import hashlib
import json
import socket
import socketserver
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cli.ssc import build_parser
from app.db.session import engine
from app.models.catalog_models import CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.scan_executors import validate_scan_config
from app.services.service_probe_text import (
    SMTP_STANDARD_PORT_POLICY_VERSION,
    SMTP_STANDARD_PORTS,
    WAVE5A_SERVICE_POLICY_VERSION,
)
from app.services.service_probes import (
    ADAPTERS,
    MAX_SERVICE_PROBE_LINE_BYTES,
    MAX_SERVICE_PROBE_LINES,
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
    MAX_SERVICE_PROBE_STAGES,
    SERVICE_PROBE_FRAMEWORK_VERSION,
    aggregate_service_probe_evaluations,
    evaluate_service_probe_response,
    evaluate_staged_service_probe_responses,
    run_service_probe,
)
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave3a_rules import WAVE3A_RULES
from app.services.wave5a_rules import WAVE5A_RULES, activate_wave5a_rules, active_wave5a_mappings


EXCHANGES = {
    "ftp": (b"220 ftp.example.test ready\r\n", b"NOOP\r\n", b"200 NOOP command successful\r\n"),
    "imap": (b"* OK IMAP service ready\r\n", b"A001 CAPABILITY\r\n", b"* CAPABILITY IMAP4rev1 IDLE\r\nA001 OK CAPABILITY completed\r\n"),
    "pop3": (b"+OK POP3 service ready\r\n", b"CAPA\r\n", b"+OK Capability list follows\r\nUSER\r\nUIDL\r\n.\r\n"),
    "smtp": (b"220 mail.example.test service ready\r\n", b"EHLO scanner.invalid\r\n", b"250-mail.example.test hello\r\n250-PIPELINING\r\n250 SIZE 1024\r\n"),
}


class _ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextmanager
def _staged_server(
    stage1: bytes,
    expected_request: bytes,
    stage2: bytes | None,
    *,
    stage1_delay: float = 0,
    stage2_delay: float = 0,
    reset_after_stage1: bool = False,
):
    received: list[bytes] = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if stage1_delay:
                time.sleep(stage1_delay)
            self.request.sendall(stage1)
            if reset_after_stage1:
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                return
            self.request.settimeout(1)
            try:
                request = self.request.recv(2048)
            except OSError:
                return
            if request:
                received.append(request)
            if request != expected_request or stage2 is None:
                return
            if stage2_delay:
                time.sleep(stage2_delay)
            try:
                self.request.sendall(stage2)
            except OSError:
                pass

    server = _ReusableServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("protocol", ["ftp", "imap", "pop3", "smtp"])
def test_two_stage_runner_matches_exact_reviewed_plaintext_exchange(protocol):
    greeting, request, response = EXCHANGES[protocol]
    with _staged_server(greeting, request, response) as (port, received):
        result = run_service_probe("127.0.0.1", port, protocol, timeout=1, response_limit=4096)
    assert result["outcome"] == "MATCH"
    assert received == [request]
    assert result["framework_version"] == "service-probe-adapter.v2"
    assert result["policy_version"] == WAVE5A_SERVICE_POLICY_VERSION
    assert result["stage_count"] == MAX_SERVICE_PROBE_STAGES == 2
    assert result["total_bytes_sent"] == len(request) <= MAX_SERVICE_PROBE_OUTBOUND_BYTES
    assert result["total_bytes_received"] == len(greeting) + len(response)
    assert result["stages"][0]["response_sha256"] == hashlib.sha256(greeting).hexdigest()
    assert result["stages"][1]["response_sha256"] == hashlib.sha256(response).hexdigest()
    serialized = json.dumps(result)
    for raw_value in (greeting.decode(), response.decode(), "IMAP4rev1", "PIPELINING"):
        assert raw_value not in serialized


def test_ftp_exact_and_multiline_boundaries():
    assert evaluate_staged_service_probe_responses(
        "ftp", [EXCHANGES["ftp"][0], EXCHANGES["ftp"][2]], port=2121,
    )["outcome"] == "MATCH"
    multiline = b"220-ftp.example.test ready\r\nmaintenance notice\r\n220 service ready\r\n"
    assert evaluate_staged_service_probe_responses(
        "ftp", [multiline, b"200 NOOP accepted\r\n"], port=21,
    )["outcome"] == "MATCH"
    assert evaluate_staged_service_probe_responses("ftp", [EXCHANGES["ftp"][0]], port=21)["outcome"] == "INDETERMINATE"
    assert evaluate_staged_service_probe_responses(
        "ftp", [EXCHANGES["ftp"][0], b"250 SMTP-style reply\r\n"], port=2121,
    )["outcome"] == "INDETERMINATE"
    malformed = b"220-first line\r\n221 wrong terminator\r\n"
    assert evaluate_staged_service_probe_responses("ftp", [malformed, b"200 OK\r\n"], port=21)["outcome"] == "INDETERMINATE"


def test_imap_exact_completion_and_malformed_boundaries():
    greeting, _, response = EXCHANGES["imap"]
    assert evaluate_staged_service_probe_responses("imap", [greeting, response], port=143)["outcome"] == "MATCH"
    for stages in (
        [greeting],
        [greeting, b"* CAPABILITY IMAP4rev1\r\n"],
        [greeting, b"A001 NO unavailable\r\n"],
        [greeting, b"* CAPABILITY IMAP4rev1\r\nA002 OK wrong tag\r\n"],
        [b"* OK bad\x00text\r\n", response],
    ):
        assert evaluate_staged_service_probe_responses("imap", stages, port=143)["outcome"] == "INDETERMINATE"


def test_pop3_exact_dot_completion_and_malformed_boundaries():
    greeting, _, response = EXCHANGES["pop3"]
    assert evaluate_staged_service_probe_responses("pop3", [greeting, response], port=110)["outcome"] == "MATCH"
    for stages in (
        [greeting],
        [greeting, b"-ERR CAPA unsupported\r\n"],
        [greeting, b"+OK follows\r\nUSER\r\n"],
        [greeting, b"+OK follows\r\nBAD\tCAP\r\n.\r\n"],
    ):
        assert evaluate_staged_service_probe_responses("pop3", stages, port=110)["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize(("port", "outcome"), [(2525, "MATCH"), (25, "NO_MATCH"), (465, "NO_MATCH"), (587, "NO_MATCH")])
def test_smtp_identity_precedes_versioned_unusual_port_policy(port, outcome):
    greeting, _, response = EXCHANGES["smtp"]
    result = evaluate_staged_service_probe_responses("smtp", [greeting, response], port=port)
    assert result["outcome"] == outcome
    assert result["port_policy_version"] == SMTP_STANDARD_PORT_POLICY_VERSION
    assert result["standard_ports"] == [25, 465, 587]


def test_smtp_greeting_ftp_and_malformed_multiline_are_not_matches():
    greeting, _, response = EXCHANGES["smtp"]
    assert evaluate_staged_service_probe_responses("smtp", [greeting], port=2525)["outcome"] == "INDETERMINATE"
    assert evaluate_staged_service_probe_responses(
        "smtp", [b"220 ftp.example.test FTP ready\r\n", b"200 NOOP successful\r\n"], port=2525,
    )["outcome"] == "INDETERMINATE"
    malformed = b"250-mail.example.test hello\r\n550 wrong-code line\r\n250 SIZE 1024\r\n"
    assert evaluate_staged_service_probe_responses("smtp", [greeting, malformed], port=2525)["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("protocol", ["ftp", "imap", "pop3", "smtp"])
def test_stage1_timeout_malformed_and_peer_close_are_indeterminate(protocol):
    greeting, request, response = EXCHANGES[protocol]
    with _staged_server(greeting, request, response, stage1_delay=0.15) as (port, _):
        timed_out = run_service_probe("127.0.0.1", port, protocol, timeout=0.05, response_limit=4096)
    assert timed_out["outcome"] == "INDETERMINATE" and timed_out["stop_reason"] == "timed_out"
    with _staged_server(b"not a protocol\r\n", request, response) as (port, received):
        malformed = run_service_probe("127.0.0.1", port, protocol, timeout=0.2, response_limit=4096)
    assert malformed["outcome"] == "INDETERMINATE" and received == []
    with _staged_server(greeting, request, None) as (port, _):
        closed = run_service_probe("127.0.0.1", port, protocol, timeout=0.2, response_limit=4096)
    assert closed["outcome"] == "INDETERMINATE" and closed["stop_reason"] == "peer_closed"


def test_stage2_timeout_reset_and_hard_total_deadline_are_indeterminate():
    greeting, request, response = EXCHANGES["ftp"]
    with _staged_server(greeting, request, response, stage2_delay=0.15) as (port, _):
        stage2_timeout = run_service_probe("127.0.0.1", port, "ftp", timeout=0.05, response_limit=4096)
    assert stage2_timeout["outcome"] == "INDETERMINATE" and stage2_timeout["stop_reason"] == "timed_out"
    with _staged_server(greeting, request, response, reset_after_stage1=True) as (port, _):
        reset = run_service_probe("127.0.0.1", port, "ftp", timeout=0.2, response_limit=4096)
    assert reset["outcome"] == "INDETERMINATE" and reset["stop_reason"] in {"write_error", "reset"}
    with _staged_server(greeting, request, response, stage1_delay=0.04, stage2_delay=0.08) as (port, _):
        started = time.monotonic()
        deadline = run_service_probe("127.0.0.1", port, "ftp", timeout=0.08, response_limit=4096)
        elapsed = time.monotonic() - started
    assert deadline["outcome"] == "INDETERMINATE" and deadline["stop_reason"] == "timed_out"
    assert elapsed < 0.2


def test_response_line_and_outbound_budgets_fail_closed(monkeypatch):
    greeting, request, _ = EXCHANGES["ftp"]
    oversized_response = b"200 " + b"x" * 80 + b"\r\n"
    with _staged_server(greeting, request, oversized_response) as (port, _):
        limited = run_service_probe("127.0.0.1", port, "ftp", timeout=0.5, response_limit=64)
    assert limited["outcome"] == "INDETERMINATE" and limited["stop_reason"] == "response_limit"

    long_line = b"220 " + b"x" * MAX_SERVICE_PROBE_LINE_BYTES + b"\r\n"
    with _staged_server(long_line, request, None) as (port, _):
        line_limited = run_service_probe("127.0.0.1", port, "ftp", timeout=0.5, response_limit=4096)
    assert line_limited["stop_reason"] == "line_length_limit"

    many_lines = b"220-first\r\n" + b"notice\r\n" * MAX_SERVICE_PROBE_LINES
    with _staged_server(many_lines, request, None) as (port, _):
        count_limited = run_service_probe("127.0.0.1", port, "ftp", timeout=0.5, response_limit=4096)
    assert count_limited["stop_reason"] == "line_count_limit"

    original = ADAPTERS["ftp"]
    monkeypatch.setitem(ADAPTERS, "ftp", replace(original, outbound_payload=b"x" * (MAX_SERVICE_PROBE_OUTBOUND_BYTES + 1)))
    with _staged_server(greeting, request, None) as (port, received):
        outbound_limited = run_service_probe("127.0.0.1", port, "ftp", timeout=0.5, response_limit=4096)
    assert outbound_limited["outcome"] == "INDETERMINATE"
    assert outbound_limited["stop_reason"] == "outbound_limit" and received == []


def test_write_failure_is_indeterminate(monkeypatch):
    class BrokenWriteSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def settimeout(self, _timeout):
            pass

        def recv(self, _size):
            return EXCHANGES["ftp"][0]

        def sendall(self, _payload):
            raise BrokenPipeError("closed")

    monkeypatch.setattr("app.services.service_probes.socket.create_connection", lambda *_args, **_kwargs: BrokenWriteSocket())
    result = run_service_probe("127.0.0.1", 21, "ftp", timeout=0.5, response_limit=4096)
    assert result["outcome"] == "INDETERMINATE" and result["stop_reason"] == "write_error"


def test_aggregation_preserves_match_negative_and_unresolved_semantics():
    smtp = EXCHANGES["smtp"]
    matched = {"issue_key": "mail_server_unusual_port", **evaluate_staged_service_probe_responses("smtp", [smtp[0], smtp[2]], port=2525)}
    negative = {"issue_key": "mail_server_unusual_port", **evaluate_staged_service_probe_responses("smtp", [smtp[0], smtp[2]], port=25)}
    unresolved = {"issue_key": "mail_server_unusual_port", **evaluate_staged_service_probe_responses("smtp", [smtp[0]], port=2526)}
    assert aggregate_service_probe_evaluations([matched, unresolved])["mail_server_unusual_port"]["outcome"] == "MATCH"
    assert aggregate_service_probe_evaluations([negative, negative])["mail_server_unusual_port"]["outcome"] == "NO_MATCH"
    assert aggregate_service_probe_evaluations([negative, unresolved])["mail_server_unusual_port"]["outcome"] == "INDETERMINATE"


def test_configuration_is_explicit_bounded_and_raw_phase_blind_evaluation_is_indeterminate():
    configured = validate_scan_config({
        "executors": ["tcp"],
        "service_probes": [
            {"protocol": "ftp", "port": 21},
            {"protocol": "imap", "port": 143},
            {"protocol": "pop3", "port": 110},
            {"protocol": "smtp", "port": 2525},
        ],
    })
    assert [item["protocol"] for item in configured["service_probes"]] == ["ftp", "imap", "pop3", "smtp"]
    assert all(item["transport"] == "tcp" for item in configured["service_probes"])
    assert evaluate_service_probe_response("ftp", b"220 mail.example.test ready\r\n")["outcome"] == "INDETERMINATE"
    assert evaluate_service_probe_response("smtp", b"220 ftp.example.test ready\r\n")["outcome"] == "INDETERMINATE"
    assert evaluate_staged_service_probe_responses(
        "smtp", EXCHANGES["smtp"][::2], port=2525, transport="udp",
    )["outcome"] == "INDETERMINATE"


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _wave5a_baseline():
    factors = {
        "network_security": {"key": "network_security", "name": "Network Security"},
        "ip_reputation": {"key": "ip_reputation", "name": "IP Reputation"},
    }
    issues = [{
        "key": spec.issue_key,
        "severity": "medium",
        "factor": "ip_reputation" if spec.issue_key == "mail_server_unusual_port" else "network_security",
        "title": spec.title,
    } for spec in WAVE5A_RULES]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-10-06T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


def test_wave5a_registry_cli_exact_activation_idempotence_and_fail_closed_risk(db):
    assert SERVICE_PROBE_FRAMEWORK_VERSION == "service-probe-adapter.v2"
    assert MAX_SERVICE_PROBE_RESPONSE_BYTES == 4096
    assert [spec.issue_key for spec in WAVE5A_RULES] == [
        "service_ftp", "service_imap", "service_pop3", "mail_server_unusual_port",
    ]
    assert len(WAVE3A_RULES) == 6
    assert SMTP_STANDARD_PORT_POLICY_VERSION == "smtp-standard-ports.v1"
    assert SMTP_STANDARD_PORTS == {25, 465, 587}
    args = build_parser().parse_args(["baseline", "activate-wave5a", "--yes"])
    assert args.baseline_command == "activate-wave5a" and args.yes is True

    import_golden_baseline(db, _wave5a_baseline(), attest_real_source=True)
    mappings = active_wave5a_mappings(db)
    assert len(mappings) == 4
    assert {item["rule_key"] for item in mappings} == {f"ssc.wave5a.{spec.issue_key}" for spec in WAVE5A_RULES}
    for mapping in mappings:
        version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert version.source_type == SourceTypeEnum.SSC_API
        assert resolve_ssc_internal_risk(mapping["issue_key"]).breach_risk == "UNKNOWN"
        assert resolve_ssc_internal_risk(mapping["issue_key"]).affects_score is False

    repeated = activate_wave5a_rules(db, commit=False)
    assert repeated["rules_created"] == 0 and repeated["rule_versions_created"] == 0
    assert repeated["rules_reused"] == 4 and repeated["unavailable"] == {}
    assert len(active_wave5a_mappings(db)) == 4
    assert db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave3a.service_vnc")) is None
