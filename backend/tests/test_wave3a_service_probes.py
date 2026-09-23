import hashlib
import json
import socketserver
import threading
from contextlib import contextmanager
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRule
from app.models.scan_models import ScanTargetTypeEnum
from app.outputs.report import render_html
from app.services.cli_scan import scan_inventory_target
from app.services.cli_setup import add_inventory_target
from app.services.golden_baseline_importer import import_golden_baseline
from app.services.scan_executors import InventoryScanTarget, TCPExecutor, validate_scan_config
from app.services.scoring_engine import ScoringDefinition
from app.services.service_probes import (
    ADAPTERS,
    SERVICE_PROBE_FRAMEWORK_VERSION,
    SERVICE_PROBE_POLICY_VERSION,
    aggregate_service_probe_evaluations,
    evaluate_service_probe_response,
    run_service_probe,
)
from app.services.ssc_api_baseline import API_ORIGIN, FACTORS_ENDPOINT, ISSUES_ENDPOINT, normalize_api_payloads
from app.services.wave1_rules import WAVE1_RULES
from app.services.wave2_rules import WAVE2_RULES
from app.services.wave3a_rules import WAVE3A_RULES, active_wave3a_mappings


def _smb2_response() -> bytes:
    payload = bytearray(128)
    payload[0:4] = b"\xfeSMB"
    payload[4:6] = (64).to_bytes(2, "little")
    payload[12:14] = (0).to_bytes(2, "little")
    payload[14:16] = (1).to_bytes(2, "little")
    payload[16:20] = (1).to_bytes(4, "little")
    payload[64:66] = (65).to_bytes(2, "little")
    payload[66:68] = (1).to_bytes(2, "little")
    payload[68:70] = (0x0311).to_bytes(2, "little")
    return b"\x00" + len(payload).to_bytes(3, "big") + bytes(payload)


POSITIVE_FIXTURES = {
    "vnc": b"RFB 003.008\n",
    "rsync": b"@RSYNCD: 31.0 sha512 sha256\n",
    "redis": b"+PONG\r\n",
    "socks5": b"\x05\xff",
    "telnet": b"\xff\xfc\x03",
    "smb2": _smb2_response(),
}
NEGATIVE_FIXTURES = {
    "vnc": POSITIVE_FIXTURES["rsync"],
    "rsync": POSITIVE_FIXTURES["vnc"],
    "redis": POSITIVE_FIXTURES["vnc"],
    "socks5": POSITIVE_FIXTURES["vnc"],
    "telnet": POSITIVE_FIXTURES["vnc"],
    "smb2": POSITIVE_FIXTURES["vnc"],
}


@pytest.mark.parametrize("protocol", list(POSITIVE_FIXTURES))
def test_every_wave3a_adapter_has_strict_positive_negative_and_indeterminate_boundaries(protocol):
    positive = evaluate_service_probe_response(protocol, POSITIVE_FIXTURES[protocol])
    assert positive["outcome"] == "MATCH"
    assert positive["matched"] is True
    assert positive["response_class"]
    assert positive["policy_version"] == SERVICE_PROBE_POLICY_VERSION

    negative = evaluate_service_probe_response(protocol, NEGATIVE_FIXTURES[protocol])
    assert negative["outcome"] == "NO_MATCH"
    assert negative["matched"] is False
    assert negative["response_class"].startswith("foreign_")

    malformed = evaluate_service_probe_response(protocol, b"protocol response maybe\r\n", stop_reason="peer_closed")
    assert malformed["outcome"] == "INDETERMINATE"
    assert malformed["matched"] is None

    timed_out = evaluate_service_probe_response(protocol, b"", stop_reason="timed_out", error_class="TimeoutError")
    assert timed_out["outcome"] == "INDETERMINATE"
    failed = evaluate_service_probe_response(protocol, b"", stop_reason="read_error", error_class="OSError")
    assert failed["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("protocol", list(POSITIVE_FIXTURES))
def test_open_tcp_or_misleading_banner_never_identifies_a_service(protocol):
    open_only = evaluate_service_probe_response(protocol, b"", stop_reason="peer_closed")
    misleading = evaluate_service_probe_response(
        protocol,
        f"Welcome to the {protocol} service; RFB @RSYNCD Redis SOCKS Telnet SMB\r\n".encode(),
        stop_reason="peer_closed",
    )
    assert open_only["outcome"] == "INDETERMINATE"
    assert misleading["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("protocol", list(POSITIVE_FIXTURES))
def test_unsupported_transport_is_indeterminate(protocol):
    result = evaluate_service_probe_response(protocol, POSITIVE_FIXTURES[protocol], transport="udp")
    assert result["outcome"] == "INDETERMINATE"
    assert result["matched"] is None


@contextmanager
def _probe_server(response: bytes, *, server_first: bool):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if server_first:
                self.request.sendall(response)
                self.request.settimeout(0.5)
                try:
                    self.request.recv(512)
                except OSError:
                    pass
            else:
                self.request.settimeout(1)
                self.request.recv(512)
                self.request.sendall(response)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("protocol", list(POSITIVE_FIXTURES))
def test_every_adapter_runs_through_common_bounded_transport(protocol):
    with _probe_server(POSITIVE_FIXTURES[protocol], server_first=ADAPTERS[protocol].server_first) as port:
        result = run_service_probe("127.0.0.1", port, protocol, timeout=1.0, response_limit=4096)
    assert result["outcome"] == "MATCH"
    assert result["framework_version"] == SERVICE_PROBE_FRAMEWORK_VERSION
    assert result["transport"] == "tcp"
    assert result["port"] == port
    assert result["bytes_received"] == len(POSITIVE_FIXTURES[protocol])
    assert result["response_sha256"] == hashlib.sha256(POSITIVE_FIXTURES[protocol]).hexdigest()
    assert result["started_at"] and result["completed_at"]
    assert "response" not in result


def test_tcp_executor_collects_probe_evidence_without_port_inference():
    target = InventoryScanTarget(
        target_type=ScanTargetTypeEnum.HOST,
        inventory_id=str(uuid4()),
        hostname="localhost",
        connect_host="127.0.0.1",
        domain_name="example.test",
        allow_sensitive_network_scan=True,
    )
    with _probe_server(POSITIVE_FIXTURES["vnc"], server_first=True) as port:
        observation = TCPExecutor().collect(target, {
            "service_probes": [{"protocol": "vnc", "port": port}],
            "service_probe_timeout_seconds": 1.0,
        })
    evidence = observation.evidence
    assert evidence["ports"] == {}
    assert evidence["evaluations"]["service_vnc"]["outcome"] == "MATCH"
    attempt = evidence["service_probes"][0]
    assert evidence["target_hostname"] == "localhost"
    assert attempt["probe_type"] == "rfb-version-greeting"
    assert attempt["response_magic"] == "RFB"


def test_probe_configuration_is_explicit_bounded_and_preserves_unsupported_transport():
    config = validate_scan_config({
        "executors": ["tcp"],
        "service_probes": [{"protocol": "redis", "port": 6379, "transport": "udp"}],
    })
    assert config["service_probes"] == [{"protocol": "redis", "port": 6379, "transport": "udp"}]
    with pytest.raises(ValueError):
        validate_scan_config({"executors": ["tcp"], "service_probes": [
            {"protocol": protocol, "port": 1000 + index} for index, protocol in enumerate(list(ADAPTERS) + ["vnc"])
        ]})
    with pytest.raises(ValueError):
        validate_scan_config({"executors": ["tcp"], "service_probes": [{"protocol": "ssh", "port": 22}]})


def test_probe_aggregation_does_not_turn_partial_execution_into_no_match():
    attempts = []
    for stop_reason, response in (("response_complete", POSITIVE_FIXTURES["rsync"]), ("timed_out", b"")):
        attempts.append({
            "issue_key": "service_vnc",
            **evaluate_service_probe_response("vnc", response, stop_reason=stop_reason),
        })
    result = aggregate_service_probe_evaluations(attempts)["service_vnc"]
    assert result["outcome"] == "INDETERMINATE"
    assert result["matched"] is None


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _wave3a_baseline():
    factors = {"network_security": {"key": "network_security", "name": "Network Security"}}
    severities = {
        "service_socks_proxy": "low",
        **{spec.issue_key: "medium" for spec in WAVE3A_RULES if spec.issue_key != "service_socks_proxy"},
    }
    issues = [{
        "key": spec.issue_key,
        "severity": severities[spec.issue_key],
        "factor": "network_security",
        "title": spec.title,
    } for spec in WAVE3A_RULES]
    raw = {}
    for endpoint, payload in ((FACTORS_ENDPOINT, {"entries": list(factors.values())}), (ISSUES_ENDPOINT, {"entries": issues})):
        body = json.dumps(payload)
        raw[API_ORIGIN + endpoint] = {
            "body": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "captured_at": "2026-09-23T00:00:00+00:00",
        }
    return normalize_api_payloads(raw)


def test_wave3a_exact_version_activation_and_end_to_end_finding(db):
    import_golden_baseline(db, _wave3a_baseline(), attest_real_source=True)
    mappings = active_wave3a_mappings(db)
    assert len(mappings) == len(WAVE3A_RULES) == 6
    assert {item["issue_key"] for item in mappings} == {spec.issue_key for spec in WAVE3A_RULES}
    for mapping in mappings:
        issue_version = db.get(CatalogIssueTypeVersion, UUID(mapping["issue_version_id"]))
        assert issue_version.source_type == SourceTypeEnum.SSC_API
        assert mapping["primitive"] == "SERVICE_PROTOCOL_IDENTIFICATION"

    rule = db.scalar(select(RuleEngineRule).where(RuleEngineRule.stable_key == "ssc.wave3a.service_vnc"))
    assert rule.current_version.catalog_issue_type_version_id == rule.catalog_issue_type.current_version_id
    suffix = uuid4().hex[:12]
    target = add_inventory_target(
        db, organization="Wave 3A " + suffix, domain_name=suffix + ".test",
        hostname="localhost", ip="127.0.0.1", approved=True, allow_sensitive=True,
        approval_notes="Deterministic local RFB fixture",
    )
    with _probe_server(POSITIVE_FIXTURES["vnc"], server_first=True) as port:
        result = scan_inventory_target(
            db, name="localhost", organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["tcp"], "service_probes": [{"protocol": "vnc", "port": port}]},
            model=ScoringDefinition(), rule_keys=[rule.stable_key],
        )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.ssc_issue_key == "service_vnc"
    assert finding.ssc_severity == "medium"
    assert finding.breach_risk == "UNKNOWN" and finding.score_impact == 0
    assert result.evidence[0].summary["evaluations"]["service_vnc"]["outcome"] == "MATCH"
    payload = result.model_dump(mode="json")
    probe = payload["evidence"][0]["summary"]["service_probes"][0]
    assert probe["protocol"] == "vnc" and probe["transport"] == "tcp" and probe["port"] == port
    assert probe["response_sha256"] and probe["stop_reason"] == "response_complete"
    html = render_html(result)
    assert "service_vnc" in html and "rfb-version-greeting" in html

    with _probe_server(NEGATIVE_FIXTURES["vnc"], server_first=True) as negative_port:
        negative = scan_inventory_target(
            db, name="localhost", organization_id=UUID(target["organization_id"]),
            scan_config={"executors": ["tcp"], "service_probes": [{"protocol": "vnc", "port": negative_port}]},
            model=ScoringDefinition(), rule_keys=[rule.stable_key],
        )
    assert negative.findings == []
    assert negative.evidence[0].summary["evaluations"]["service_vnc"]["outcome"] == "NO_MATCH"


def test_prior_wave_registries_remain_intact():
    assert len(WAVE1_RULES) == 14
    assert len(WAVE2_RULES) == 7
    assert {spec.issue_key for spec in WAVE3A_RULES}.isdisjoint({spec.issue_key for spec in WAVE1_RULES + WAVE2_RULES})
