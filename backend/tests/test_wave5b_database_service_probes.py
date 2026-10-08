import hashlib
import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.cli.ssc import build_parser
from app.services.cli_scan import scan_inventory_target
from app.services.cli_setup import add_inventory_target
from app.db.session import engine
from app.models.catalog_models import CatalogIssueType, CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.scan_executors import InventoryScanTarget, TCPExecutor, validate_scan_config
from app.services.scoring_engine import ScoringDefinition
from app.models.scan_models import ScanTargetTypeEnum
from app.services.service_probe_database import (
    DATABASE_PROBE_FRAMEWORK_VERSION,
    LDAP_ROOTDSE_REQUEST,
    ORACLE_PROBE_SERVICE,
    ProbeRequestContext,
    build_oracle_connect,
    parse_ldap_response,
    parse_oracle_response,
)
from app.services.service_probes import (
    ADAPTERS,
    MAX_SERVICE_PROBES,
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
    SERVICE_PROBE_FRAMEWORK_VERSION,
    aggregate_service_probe_evaluations,
    evaluate_service_probe_response,
    run_service_probe,
)
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave5b_rules import (
    WAVE5B_ACTIVE_KEYS,
    WAVE5B_RULES,
    activate_wave5b_rules,
    active_wave5b_mappings,
)


def _ber(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        length = bytes([len(value)])
    else:
        length = b"\x81" + bytes([len(value)])
    return bytes([tag]) + length + value


def _ldap_message(operation: bytes, message_id: int = 1, controls: bytes = b"") -> bytes:
    return _ber(0x30, _ber(0x02, bytes([message_id])) + operation + controls)


def _ldap_done(code: int = 0, message_id: int = 1) -> bytes:
    result = _ber(0x0A, bytes([code])) + _ber(0x04, b"") + _ber(0x04, b"sensitive diagnostic")
    return _ldap_message(_ber(0x65, result), message_id)


def _ldap_entry() -> bytes:
    attribute = _ber(0x30, _ber(0x04, b"vendorName") + _ber(0x31, _ber(0x04, b"secret-value")))
    return _ldap_message(_ber(0x64, _ber(0x04, b"dc=secret") + _ber(0x30, attribute)))


def _tns(packet_type: int, body: bytes) -> bytes:
    length = 8 + len(body)
    return length.to_bytes(2, "big") + b"\x00\x00" + bytes([packet_type, 0]) + b"\x00\x00" + body


def _tns_accept() -> bytes:
    body = (319).to_bytes(2, "big") + b"\x00\x01" + bytes(10) + b"\x00" + bytes(9) + (8192).to_bytes(4, "big")
    return _tns(2, body)


def _tns_refuse() -> bytes:
    message = b"(DESCRIPTION=(TMP=)(ERR=12514))"
    return _tns(4, b"\x00\x00" + len(message).to_bytes(2, "big") + message)


def _tns_redirect() -> bytes:
    descriptor = b"(ADDRESS=(PROTOCOL=TCP)(HOST=redirect.invalid)(PORT=9999))"
    return _tns(5, len(descriptor).to_bytes(2, "big") + descriptor)


@pytest.mark.parametrize("code", [0, 8, 13, 50])
def test_ldap_search_result_done_legal_codes_match_without_values(code):
    response = _ldap_done(code)
    result = parse_ldap_response(response)
    assert result.outcome == "MATCH"
    assert result.correlation_result == "message_id_1_matched"
    assert result.structural_counts == {"messages": 1, "entries": 0, "references": 0, "result_code": code}
    assert "sensitive" not in repr(result)


def test_ldap_entry_then_done_matches_and_discards_directory_values():
    response = _ldap_entry() + _ldap_done()
    result = evaluate_service_probe_response("ldap", response)
    assert result["outcome"] == "MATCH"
    assert result["structural_counts"]["entries"] == 1
    assert "secret" not in json.dumps(result)


def test_ldap_reviewed_request_is_exact_and_referral_result_is_structural_only():
    assert LDAP_ROOTDSE_REQUEST.hex() == (
        "302a020101632504000a01000a01000201010201010101ff870b"
        "6f626a656374436c61737330050403312e31"
    )
    referral = _ber(0xA3, _ber(0x04, b"ldap://secret.invalid/dc=secret"))
    result_fields = _ber(0x0A, b"\x0a") + _ber(0x04, b"") + _ber(0x04, b"hidden") + referral
    result = evaluate_service_probe_response("ldap", _ldap_message(_ber(0x65, result_fields)))
    assert result["outcome"] == "MATCH"
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("response", [
    prefix
    for complete in (_ldap_done(), _ldap_entry() + _ldap_done())
    for prefix in (complete[:index] for index in range(len(complete)))
])
def test_ldap_truncation_at_every_boundary_is_indeterminate(response):
    assert evaluate_service_probe_response("ldap", response)["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("response", [
    _ldap_done(message_id=2),
    b"\x30\x80\x00\x00",
    b"arbitrary bytes",
    _ldap_entry(),
    _ldap_message(_ber(0x61, b"")),
    b"\x30\x10\x02\x01\x01",
])
def test_ldap_invalid_or_incomplete_responses_are_indeterminate(response):
    result = evaluate_service_probe_response("ldap", response)
    assert result["outcome"] == "INDETERMINATE"
    assert result["matched"] is None


def test_ldap_malformed_controls_are_indeterminate():
    controls = _ber(0xA0, _ber(0x30, _ber(0x01, b"\xff")))
    result = evaluate_service_probe_response("ldap", _ldap_message(_ber(0x65, _ber(0x0A, b"\x00") + _ber(0x04, b"") + _ber(0x04, b"")), controls=controls))
    assert result["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("response", [_tns_accept(), _tns_refuse(), _tns_redirect()])
def test_oracle_valid_identification_packets_match_without_peer_values(response):
    result = parse_oracle_response(response)
    assert result.outcome == "MATCH"
    assert result.correlation_result == "declared_endpoint_response"
    assert result.declared_response_bytes == len(response)
    assert "redirect.invalid" not in repr(result)
    assert "ERR=12514" not in repr(result)


@pytest.mark.parametrize("response", [
    b"arbitrary",
    b"\x00\x07" + bytes(6),
    _tns(6, b"data"),
    _tns(11, b"resend"),
    _tns(99, b"unknown"),
    _tns_accept()[:-1],
    _tns(4, b"\x00\x00\x00\x20short"),
    _tns(5, b"\x00\x05bad"),
])
def test_oracle_invalid_packets_are_indeterminate(response):
    result = evaluate_service_probe_response("oracle", response)
    assert result["outcome"] == "INDETERMINATE"
    assert result["matched"] is None


@pytest.mark.parametrize("response", [
    prefix
    for complete in (_tns_accept(), _tns_refuse(), _tns_redirect())
    for prefix in (complete[:index] for index in range(len(complete)))
])
def test_oracle_truncation_at_every_boundary_is_indeterminate(response):
    assert evaluate_service_probe_response("oracle", response)["outcome"] == "INDETERMINATE"


def test_oracle_endpoint_builder_is_numeric_bounded_and_contains_no_identity_data():
    built = build_oracle_connect(ProbeRequestContext("127.0.0.1", 1521, bytes(16)))
    assert len(built.payload) <= MAX_SERVICE_PROBE_OUTBOUND_BYTES
    assert int.from_bytes(built.payload[:2], "big") == len(built.payload)
    assert built.payload[4] == 1
    assert b"HOST=127.0.0.1" in built.payload and b"PORT=1521" in built.payload
    assert ORACLE_PROBE_SERVICE.encode() in built.payload
    assert b"USER=" not in built.payload and b"CID=" not in built.payload
    with pytest.raises(ValueError):
        build_oracle_connect(ProbeRequestContext("localhost", 1521, bytes(16)))
    with pytest.raises(ValueError):
        build_oracle_connect(ProbeRequestContext("127.0.0.1", 0, bytes(16)))
    with pytest.raises(ValueError):
        build_oracle_connect(ProbeRequestContext("127.0.0.1", 65536, bytes(16)))


@contextmanager
def _probe_server(response: bytes | None, *, delay: float = 0, reset: bool = False):
    state = {"requests": [], "connections": 0}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            state["connections"] += 1
            self.request.settimeout(1)
            try:
                state["requests"].append(self.request.recv(2048))
            except OSError:
                return
            if reset:
                self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                return
            if delay:
                time.sleep(delay)
            if response is not None:
                self.request.sendall(response)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ldap_and_oracle_run_through_v3_without_changing_v2():
    assert SERVICE_PROBE_FRAMEWORK_VERSION == "service-probe-adapter.v2"
    for protocol, response in (("ldap", _ldap_done()), ("oracle", _tns_refuse())):
        with _probe_server(response) as (port, state):
            result = run_service_probe("127.0.0.1", port, protocol, timeout=1, response_limit=4096)
        assert result["outcome"] == "MATCH"
        assert result["framework_version"] == DATABASE_PROBE_FRAMEWORK_VERSION
        assert result["builder_version"] and result["request_model"]
        assert result["tls_mode"] == "plaintext"
        assert result["response_sha256"] == hashlib.sha256(response).hexdigest()
        assert "response" not in result and "descriptor" not in json.dumps(result).lower()
        assert len(state["requests"]) == 1
    assert state["connections"] == 1  # REDIRECT/REFUSE is never followed.


def test_oracle_redirect_is_not_followed_or_persisted():
    with _probe_server(_tns_redirect()) as (port, state):
        result = run_service_probe("127.0.0.1", port, "oracle", timeout=1, response_limit=4096)
    assert result["outcome"] == "MATCH" and result["response_class"] == "tns_redirect"
    assert state["connections"] == 1
    assert "redirect.invalid" not in json.dumps(result)


@pytest.mark.parametrize("protocol", ["ldap", "oracle"])
def test_database_acquisition_failures_and_tls_like_bytes_are_indeterminate(protocol):
    for stop in ("timed_out", "reset", "peer_closed", "response_limit"):
        result = evaluate_service_probe_response(protocol, b"", stop_reason=stop)
        assert result["outcome"] == "INDETERMINATE"
    tls = evaluate_service_probe_response(protocol, b"\x16\x03\x03\x00\x05hello")
    assert tls["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("protocol", ["ldap", "oracle"])
def test_database_runner_timeout_reset_close_and_response_limit(protocol):
    with _probe_server(None, delay=0.15) as (port, _):
        timed_out = run_service_probe("127.0.0.1", port, protocol, timeout=0.03, response_limit=4096)
    assert timed_out["outcome"] == "INDETERMINATE" and timed_out["stop_reason"] == "timed_out"
    with _probe_server(None) as (port, _):
        closed = run_service_probe("127.0.0.1", port, protocol, timeout=0.2, response_limit=4096)
    assert closed["outcome"] == "INDETERMINATE" and closed["stop_reason"] == "peer_closed"
    oversized = (b"\x30\x82\x10\x01" if protocol == "ldap" else b"\x10\x01")
    oversized += bytes(4096 - len(oversized))
    with _probe_server(oversized) as (port, _):
        limited = run_service_probe("127.0.0.1", port, protocol, timeout=0.5, response_limit=4096)
    assert limited["outcome"] == "INDETERMINATE" and limited["stop_reason"] == "response_limit"


def test_response_limit_and_probe_cap_remain_fixed():
    assert MAX_SERVICE_PROBES == 6
    assert MAX_SERVICE_PROBE_RESPONSE_BYTES == 4096
    assert MAX_SERVICE_PROBE_OUTBOUND_BYTES == 1024
    configured = validate_scan_config({"service_probes": [
        {"protocol": "ldap", "port": 1389}, {"protocol": "oracle", "port": 1521},
    ]})
    assert len(configured["service_probes"]) == 2
    with pytest.raises(ValueError):
        validate_scan_config({"service_probes": [
            {"protocol": "ldap", "port": 1000 + index} for index in range(7)
        ]})


def test_database_aggregation_never_invents_no_match():
    matched = {"issue_key": "service_ldap", **evaluate_service_probe_response("ldap", _ldap_done())}
    unresolved = {"issue_key": "service_ldap", **evaluate_service_probe_response("ldap", b"arbitrary")}
    assert aggregate_service_probe_evaluations([matched, unresolved])["service_ldap"]["outcome"] == "MATCH"
    assert aggregate_service_probe_evaluations([unresolved])["service_ldap"]["outcome"] == "INDETERMINATE"
    assert evaluate_service_probe_response("ldap", b"RFB 003.008\n")["outcome"] == "INDETERMINATE"


def test_tcp_executor_reports_v3_attempt_and_compact_evaluation():
    target = InventoryScanTarget(
        target_type=ScanTargetTypeEnum.HOST,
        inventory_id=str(uuid4()),
        hostname="localhost",
        connect_host="127.0.0.1",
        domain_name="example.test",
        allow_sensitive_network_scan=True,
    )
    with _probe_server(_ldap_done()) as (port, _):
        evidence = TCPExecutor().collect(target, {
            "service_probes": [{"protocol": "ldap", "port": port}],
            "service_probe_timeout_seconds": 1,
        }).evidence
    assert evidence["probe_framework_version"] == DATABASE_PROBE_FRAMEWORK_VERSION
    assert evidence["probe_framework_versions"] == [DATABASE_PROBE_FRAMEWORK_VERSION]
    assert evidence["evaluations"]["service_ldap"]["outcome"] == "MATCH"


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _wave5b_baseline(*, attested_titles: bool = True):
    factors = {"network_security": {"key": "network_security", "name": "Network Security"}}
    issues = [{
        "key": spec.issue_key,
        "severity": "medium",
        "factor": "network_security",
        "title": spec.title if attested_titles else "Stale " + spec.title,
    } for spec in WAVE5B_RULES]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-10-07T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


def test_wave5b_registry_cli_activation_is_exact_idempotent_and_uncalibrated(db):
    assert [spec.issue_key for spec in WAVE5B_RULES] == ["service_ldap", "service_oracle_db"]
    assert WAVE5B_ACTIVE_KEYS == {"service_ldap"}
    assert not {"cassandra", "microsoft_sql", "mongodb", "mysql", "postgresql"} & set(ADAPTERS)
    args = build_parser().parse_args(["baseline", "activate-wave5b", "--yes"])
    assert args.baseline_command == "activate-wave5b" and args.yes
    import_golden_baseline(db, _wave5b_baseline(), attest_real_source=True)
    mappings = active_wave5b_mappings(db)
    assert len(mappings) == 1
    assert {item["rule_key"] for item in mappings} == {"ssc.wave5b.service_ldap"}
    assert db.scalar(select(RuleEngineRule).where(
        RuleEngineRule.stable_key == "ssc.wave5b.service_oracle_db",
    )) is None
    for mapping in mappings:
        version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert version.source_type == SourceTypeEnum.SSC_API
        decision = resolve_ssc_internal_risk(mapping["issue_key"])
        assert decision.breach_risk == "UNKNOWN" and decision.affects_score is False
    oracle_issue = db.scalar(select(CatalogIssueType).where(
        CatalogIssueType.stable_key == "service_oracle_db",
    ))
    legacy_oracle_rule = RuleEngineRule(
        stable_key="ssc.wave5b.service_oracle_db",
        catalog_issue_type_id=oracle_issue.id,
        is_active=True,
    )
    db.add(legacy_oracle_rule)
    db.flush()
    deactivated = activate_wave5b_rules(db, commit=False)
    assert deactivated["rules_created"] == deactivated["rule_versions_created"] == 0
    assert deactivated["rules_reused"] == 1 and deactivated["rules_deactivated"] == 1
    assert deactivated["activated"] == ["service_ldap"]
    assert deactivated["inactive"] == ["service_oracle_db"]
    assert deactivated["unavailable"] == {}
    assert legacy_oracle_rule.is_active is False
    repeated = activate_wave5b_rules(db, commit=False)
    assert repeated["rules_reused"] == 1 and repeated["rules_deactivated"] == 0


def test_active_wave5b_match_finding_is_visible_unknown_and_non_scoring(db):
    import_golden_baseline(db, _wave5b_baseline(), attest_real_source=True)
    protocol, response = "ldap", _ldap_done()
    issue_key = ADAPTERS[protocol].issue_key
    rule = db.scalar(select(RuleEngineRule).where(
        RuleEngineRule.stable_key == f"ssc.wave5b.{issue_key}",
    ))
    assert rule.current_version.catalog_issue_type_version_id == rule.catalog_issue_type.current_version_id
    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db,
        organization="Wave 5B.1 " + suffix,
        domain_name=suffix + ".test",
        hostname="localhost",
        ip="127.0.0.1",
        approved=True,
        allow_sensitive=True,
        approval_notes="Controlled local database protocol fixture",
    )
    with _probe_server(response) as (port, _):
        result = scan_inventory_target(
            db,
            name="localhost",
            organization_id=UUID(target["organization_id"]),
            scan_config={
                "executors": ["tcp"],
                "service_probes": [{"protocol": protocol, "port": port}],
                "service_probe_timeout_seconds": 1,
            },
            model=ScoringDefinition(),
            rule_keys=[rule.stable_key],
        )
    assert result.evidence[0].summary["evaluations"][issue_key]["outcome"] == "MATCH"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.ssc_issue_key == issue_key
    assert finding.breach_risk == "UNKNOWN"
    assert finding.affects_score is False
    assert finding.score_impact == 0


def test_wave5b_activation_rejects_unattested_and_stale_current_versions(db):
    import_golden_baseline(db, _wave5b_baseline(), attest_real_source=False)
    unavailable = activate_wave5b_rules(db, commit=False)["unavailable"]
    assert set(unavailable) == {"service_ldap"}
    db.rollback()
