import json
import socket
import socketserver
import struct
import threading
import time
from contextlib import contextmanager
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.cli.ssc import build_parser
from app.db.session import engine
from app.services.scan_executors import InventoryScanTarget, TCPExecutor, validate_scan_config
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.service_probe_database import ProbeRequestContext
from app.services.service_probe_framed import (
    FRAMED_PROBE_BUILDER_VERSION,
    FRAMED_PROBE_FRAMEWORK_VERSION,
    MAX_MINECRAFT_JSON_DEPTH,
    MINECRAFT_DISCOVERY_PROTOCOL_VERSION,
    PPTP_MAGIC_COOKIE,
    PPTP_MESSAGE_BYTES,
    PPTP_START_CONTROL_CONNECTION_REQUEST,
    RDP_NEGOTIATION_REQUEST,
    WAVE5C_SERVICE_POLICY_VERSION,
    _decode_minecraft_varint,
    build_minecraft_status_request,
    encode_minecraft_varint,
    parse_minecraft_response,
    parse_pptp_response,
    parse_rdp_response,
)
from app.services.service_probes import (
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
    aggregate_service_probe_evaluations,
    evaluate_service_probe_response,
    run_service_probe,
)
from app.models.scan_models import ScanTargetTypeEnum
from app.models.catalog_models import (
    BreachRiskEnum,
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.models.rule_models import (
    RuleEngineRule,
    RuleEngineRuleVersion,
    RuleSourceTypeEnum,
    RuleTargetTypeEnum,
)
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V2,
    get_pinned_public_exposure_consumer,
)
from app.services.wave5c_rules import (
    WAVE5C_ACTIVE_KEYS,
    WAVE5C_BY_KEY,
    WAVE5C_CLOSURE_BLOCKERS,
    activate_wave5c_rules,
    active_wave5c_mappings,
)


def _minecraft_response(document: object) -> bytes:
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    body = b"\x00" + encode_minecraft_varint(len(raw)) + raw
    return encode_minecraft_varint(len(body)) + body


MINECRAFT_RESPONSE = _minecraft_response({
    "version": {"name": "fixture-secret-version", "protocol": 47},
    "description": {"text": "private motd"},
    "players": {"sample": [{"name": "private-player"}]},
    "favicon": "private-favicon",
})


def _pptp_response(
    *,
    result: int = 1,
    error: int = 0,
    protocol_version: int = 0x0100,
    cookie: int = PPTP_MAGIC_COOKIE,
    message_type: int = 1,
    control_type: int = 2,
    reserved: int = 0,
    framing: int = 3,
    bearer: int = 3,
    length: int = PPTP_MESSAGE_BYTES,
) -> bytes:
    return struct.pack(
        "!HHIHHHBBIIHH64s64s",
        length, message_type, cookie, control_type, reserved, protocol_version,
        result, error, framing, bearer, 12, 7,
        b"private-server".ljust(64, b"\x00"),
        b"private-vendor".ljust(64, b"\x00"),
    )


PPTP_RESPONSE = _pptp_response()


def _rdp_response(*, response_type: int = 2, flags: int = 0, value: int = 1) -> bytes:
    negotiation = bytes([response_type, flags]) + (8).to_bytes(2, "little") + value.to_bytes(4, "little")
    x224 = b"\x0e\xd0\x00\x00\x12\x34\x00" + negotiation
    return b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224


RDP_RESPONSE = _rdp_response()
RDP_BARE_CONFIRM = bytes.fromhex("03 00 00 0b 06 d0 00 00 12 34 00")


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _seed_pinned_wave5c_baseline(db: Session) -> dict[str, CatalogIssueType]:
    factor = CatalogFactor(code="network_security", name="Network Security")
    db.add(factor)
    db.flush()
    snapshot = CatalogSnapshot(
        name="Pinned Wave 5C baseline",
        source_type=SourceTypeEnum.SSC_API,
        content_hash=PINNED_SSC_BASELINE_HASH,
        normalized_schema_version="ssc.api.metadata.v2",
        is_real_baseline=True,
    )
    db.add(snapshot)
    db.flush()
    issues = {}
    for position, spec in enumerate(WAVE5C_BY_KEY.values()):
        issue = CatalogIssueType(stable_key=spec.issue_key, factor_id=factor.id)
        db.add(issue)
        db.flush()
        version = CatalogIssueTypeVersion(
            issue_type_id=issue.id,
            version_number=1,
            name=spec.title,
            breach_risk=BreachRiskEnum.UNKNOWN,
            ssc_severity="medium",
            affects_score=False,
            source_type=SourceTypeEnum.SSC_API,
            source_snapshot_hash=PINNED_SSC_BASELINE_HASH,
        )
        db.add(version)
        db.flush()
        issue.current_version_id = version.id
        db.add(CatalogSnapshotItem(
            catalog_snapshot_id=snapshot.id,
            issue_type_version_id=version.id,
            factor_position=0,
            issue_position=position,
        ))
        issues[spec.issue_key] = issue
    db.flush()
    return issues


@contextmanager
def _probe_server(response: bytes | None, *, one_byte_chunks: bool = False, delay: float = 0):
    state: dict[str, object] = {"request": b"", "extra": None}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            try:
                state["request"] = self.request.recv(2048)
            except OSError:
                return
            if delay:
                time.sleep(delay)
            if response is not None:
                chunks = (bytes([byte]) for byte in response) if one_byte_chunks else (response,)
                for chunk in chunks:
                    try:
                        self.request.sendall(chunk)
                    except OSError:
                        return
            self.request.settimeout(0.2)
            try:
                state["extra"] = self.request.recv(64)
            except OSError:
                state["extra"] = b""

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("value", [0, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, -1])
def test_minecraft_varint_boundaries_are_minimal_signed_32_bit(value):
    encoded = encode_minecraft_varint(value)
    decoded, width = _decode_minecraft_varint(encoded)
    assert decoded == value and width == len(encoded) <= 5
    if value == -1:
        assert encoded == bytes.fromhex("ff ff ff ff 0f")


@pytest.mark.parametrize("encoded", [b"\x80\x00", b"\xff\xff\xff\xff\x10", b"\x80\x80\x80\x80\x80\x00"])
def test_minecraft_varint_overlong_and_overflow_are_rejected(encoded):
    with pytest.raises(ValueError):
        _decode_minecraft_varint(encoded)


def test_minecraft_request_uses_exact_declared_hostname_port_and_discovery_version():
    built = build_minecraft_status_request(ProbeRequestContext(
        "127.0.0.1", 25565, bytes(16), "xn--bcher-kva.example",
    ))
    declared, width = _decode_minecraft_varint(built.payload)
    handshake = built.payload[width:width + declared]
    packet_id, cursor = _decode_minecraft_varint(handshake)
    protocol, used = _decode_minecraft_varint(handshake, cursor)
    cursor += used
    hostname_length, used = _decode_minecraft_varint(handshake, cursor)
    cursor += used
    assert packet_id == 0 and protocol == MINECRAFT_DISCOVERY_PROTOCOL_VERSION
    assert handshake[cursor:cursor + hostname_length] == b"xn--bcher-kva.example"
    cursor += hostname_length
    assert int.from_bytes(handshake[cursor:cursor + 2], "big") == 25565
    assert handshake[cursor + 2:] == b"\x01"
    assert built.payload[width + declared:] == b"\x01\x00"
    assert len(built.payload) <= MAX_SERVICE_PROBE_OUTBOUND_BYTES
    assert built.correlation_metadata == {"declared_hostname_used": True, "declared_port_used": True}


@pytest.mark.parametrize("hostname,port", [(None, 25565), ("", 25565), ("a" * 256, 25565), ("example.test", 0), ("example.test", 65536)])
def test_minecraft_request_rejects_invalid_context(hostname, port):
    with pytest.raises(ValueError):
        build_minecraft_status_request(ProbeRequestContext("127.0.0.1", port, bytes(16), hostname))


def test_minecraft_valid_status_matches_without_retaining_optional_content():
    result = parse_minecraft_response(MINECRAFT_RESPONSE)
    assert result.outcome == "MATCH"
    rendered = repr(result)
    assert "fixture-secret-version" not in rendered
    assert "private motd" not in rendered and "private-player" not in rendered and "private-favicon" not in rendered
    assert result.structural_counts["json_depth"] <= MAX_MINECRAFT_JSON_DEPTH


@pytest.mark.parametrize("response", [MINECRAFT_RESPONSE[:index] for index in range(len(MINECRAFT_RESPONSE))])
def test_minecraft_every_truncation_boundary_is_indeterminate(response):
    assert evaluate_service_probe_response("minecraft", response)["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("response", [
    b"\x80\x00",
    b"\xff\xff\xff\xff\x10",
    b"\x01\x01",
    b"\x03\x00\x02\xff",
    _minecraft_response([]),
    _minecraft_response({}),
    _minecraft_response({"version": []}),
    _minecraft_response({"version": {"name": "", "protocol": 47}}),
    _minecraft_response({"version": {"name": "ok", "protocol": True}}),
    _minecraft_response({"version": {"name": "ok", "protocol": 1.5}}),
])
def test_minecraft_malformed_or_invalid_responses_are_indeterminate(response):
    assert evaluate_service_probe_response("minecraft", response)["outcome"] == "INDETERMINATE"


def test_minecraft_json_duplicate_depth_node_and_length_limits_are_indeterminate():
    duplicate = b'{"version":{"name":"a","name":"b","protocol":47}}'
    duplicate_body = b"\x00" + encode_minecraft_varint(len(duplicate)) + duplicate
    duplicate_frame = encode_minecraft_varint(len(duplicate_body)) + duplicate_body
    nested: object = 0
    for _ in range(33):
        nested = [nested]
    cases = [
        duplicate_frame,
        _minecraft_response({"version": {"name": "ok", "protocol": 47}, "nested": nested}),
        _minecraft_response({"version": {"name": "ok", "protocol": 47}, "nodes": [0] * 513}),
        _minecraft_response({"version": {"name": "x" * 257, "protocol": 47}}),
    ]
    assert all(parse_minecraft_response(item).outcome == "INDETERMINATE" for item in cases)


def test_minecraft_valid_frame_can_fill_exact_4096_byte_response_ceiling():
    response = next(
        candidate
        for size in range(3800, 4096)
        if len(candidate := _minecraft_response({
            "version": {"name": "ok", "protocol": 47}, "padding": "x" * size,
        })) == MAX_SERVICE_PROBE_RESPONSE_BYTES
    )
    assert parse_minecraft_response(response).outcome == "MATCH"


def test_pptp_request_is_exact_fixed_identity_sccrq():
    request = PPTP_START_CONTROL_CONNECTION_REQUEST
    assert len(request) == PPTP_MESSAGE_BYTES == 156
    assert request[:16].hex() == "009c00011a2b3c4d0001000001000000"
    assert int.from_bytes(request[16:20], "big") == 3
    assert int.from_bytes(request[20:24], "big") == 3
    assert b"ssc-probe.invalid" in request and b"SSC Wave5C probe" in request


@pytest.mark.parametrize("result,error,version", [(1, 0, 0x0100), (2, 1, 0x0100), (2, 6, 0x0100), (3, 0, 0x0100), (4, 0, 0x0100), (5, 0, 0x0200)])
def test_pptp_all_legal_result_classes_match(result, error, version):
    parsed = parse_pptp_response(_pptp_response(result=result, error=error, protocol_version=version))
    assert parsed.outcome == "MATCH"
    assert "private-server" not in repr(parsed) and "private-vendor" not in repr(parsed)


@pytest.mark.parametrize("changes", [
    {"result": 2, "error": 0}, {"result": 2, "error": 7}, {"result": 1, "error": 1},
    {"result": 5, "error": 0, "protocol_version": 0}, {"result": 3, "error": 0, "protocol_version": 0x0200},
    {"cookie": 1}, {"message_type": 2}, {"control_type": 1}, {"reserved": 1},
    {"framing": 4}, {"bearer": 4}, {"result": 6}, {"length": 155},
])
def test_pptp_invalid_headers_results_versions_and_capabilities_are_indeterminate(changes):
    assert parse_pptp_response(_pptp_response(**changes)).outcome == "INDETERMINATE"


@pytest.mark.parametrize("response", [PPTP_RESPONSE[:index] for index in range(len(PPTP_RESPONSE))])
def test_pptp_every_truncation_boundary_is_indeterminate(response):
    assert evaluate_service_probe_response("pptp", response)["outcome"] == "INDETERMINATE"


def test_rdp_request_is_exact_reviewed_negotiation_request():
    assert RDP_NEGOTIATION_REQUEST.hex() == "030000130ee00000000000010008000b000000"
    assert len(RDP_NEGOTIATION_REQUEST) == 19


@pytest.mark.parametrize("selected", [1, 2, 8])
def test_rdp_legal_negotiation_responses_match(selected):
    assert parse_rdp_response(_rdp_response(value=selected)).outcome == "MATCH"


@pytest.mark.parametrize("failure", range(1, 8))
def test_rdp_all_legal_negotiation_failures_match(failure):
    assert parse_rdp_response(_rdp_response(response_type=3, value=failure)).outcome == "MATCH"


@pytest.mark.parametrize("response", [RDP_RESPONSE[:index] for index in range(len(RDP_RESPONSE))])
def test_rdp_every_truncation_boundary_is_indeterminate(response):
    assert evaluate_service_probe_response("rdp", response)["outcome"] == "INDETERMINATE"


@pytest.mark.parametrize("response", [
    RDP_BARE_CONFIRM,
    bytes.fromhex("03 00 00 0b 06 d0 00 00 12 34 00"),
    bytes.fromhex("03 00 00 13 0e e0 00 00 00 00 00 02 00 08 00 01 00 00 00"),
    _rdp_response(value=0), _rdp_response(value=4), _rdp_response(value=16),
    _rdp_response(flags=0x20), _rdp_response(response_type=3, flags=1, value=1),
    _rdp_response(response_type=3, value=0), _rdp_response(response_type=3, value=8),
    b"\x16\x03\x03\x00\x10tls-like-bytes",
    b"arbitrary bytes",
])
def test_rdp_bare_generic_malformed_foreign_and_tls_are_indeterminate(response):
    result = evaluate_service_probe_response("rdp", response)
    assert result["outcome"] == "INDETERMINATE" and result["matched"] is None


@pytest.mark.parametrize(("protocol", "response", "expected_request", "hostname"), [
    ("minecraft", MINECRAFT_RESPONSE, None, "mc.example.test"),
    ("pptp", PPTP_RESPONSE, PPTP_START_CONTROL_CONNECTION_REQUEST, "pptp.example.test"),
    ("rdp", RDP_RESPONSE, RDP_NEGOTIATION_REQUEST, "rdp.example.test"),
])
@pytest.mark.parametrize("one_byte_chunks", [False, True])
def test_v3_runner_uses_one_deadline_exact_request_compact_evidence_and_no_continuation(
    protocol, response, expected_request, hostname, one_byte_chunks,
):
    with _probe_server(response, one_byte_chunks=one_byte_chunks) as (port, state):
        result = run_service_probe(
            "127.0.0.1", port, protocol, timeout=1, response_limit=4096,
            declared_hostname=hostname,
        )
    assert result["outcome"] == "MATCH"
    assert result["framework_version"] == FRAMED_PROBE_FRAMEWORK_VERSION
    assert result["policy_version"] == WAVE5C_SERVICE_POLICY_VERSION
    assert result["builder_version"] == FRAMED_PROBE_BUILDER_VERSION
    assert result["completion_reason"] == result["stop_reason"] == "response_complete"
    assert result["response_sha256"] and result["declared_frame_length"] is not None
    if expected_request is not None:
        assert state["request"] == expected_request
    else:
        assert hostname.encode() in state["request"]
        assert bytes.fromhex("ff ff ff ff 0f") in state["request"]
    assert state["extra"] == b""
    serialized = json.dumps(result)
    for secret in ("private motd", "private-player", "private-favicon", "private-server", "private-vendor", "fixture-secret-version"):
        assert secret not in serialized
    assert "raw_request" not in serialized and "raw_response" not in serialized


@pytest.mark.parametrize("protocol", ["minecraft", "pptp", "rdp"])
def test_v3_runner_timeout_peer_close_and_response_limit_are_indeterminate(protocol):
    hostname = "fixture.example.test"
    with _probe_server(None, delay=0.08) as (port, _):
        timed_out = run_service_probe("127.0.0.1", port, protocol, timeout=0.03, response_limit=4096, declared_hostname=hostname)
    assert timed_out["outcome"] == "INDETERMINATE" and timed_out["stop_reason"] == "timed_out"
    with _probe_server(None) as (port, _):
        closed = run_service_probe("127.0.0.1", port, protocol, timeout=0.3, response_limit=4096, declared_hostname=hostname)
    assert closed["outcome"] == "INDETERMINATE" and closed["stop_reason"] == "peer_closed"
    oversized = b"\x81\x20" + bytes(4094) if protocol == "minecraft" else (
        b"\x10\x01" + bytes(4094) if protocol == "pptp" else b"\x03\x00\x10\x01" + bytes(4092)
    )
    with _probe_server(oversized) as (port, _):
        limited = run_service_probe("127.0.0.1", port, protocol, timeout=1, response_limit=4096, declared_hostname=hostname)
    assert limited["outcome"] == "INDETERMINATE" and limited["stop_reason"] == "response_limit"
    assert limited["bytes_received"] == MAX_SERVICE_PROBE_RESPONSE_BYTES


def test_wave5c_has_no_no_match_and_aggregation_remains_fail_closed():
    attempts = []
    issue_keys = {"minecraft": "minecraft_server", "pptp": "service_pptp", "rdp": "service_rdp"}
    for protocol in ("minecraft", "pptp", "rdp"):
        result = evaluate_service_probe_response(protocol, b"arbitrary")
        assert result["outcome"] == "INDETERMINATE"
        attempts.append({"issue_key": issue_keys[protocol], **result})
    evaluations = aggregate_service_probe_evaluations(attempts)
    assert all(item["outcome"] == "INDETERMINATE" for item in evaluations.values())


@pytest.mark.parametrize("stop_reason", ["connect_error", "write_error", "read_error", "reset", "peer_closed", "timed_out", "response_limit"])
@pytest.mark.parametrize("protocol", ["minecraft", "pptp", "rdp"])
def test_wave5c_all_acquisition_failures_are_indeterminate(protocol, stop_reason):
    result = evaluate_service_probe_response(protocol, b"", stop_reason=stop_reason)
    assert result["outcome"] == "INDETERMINATE" and result["matched"] is None


@pytest.mark.parametrize("issue_key", ["minecraft_server", "service_pptp", "service_rdp"])
def test_wave5c_uncalibrated_risk_fails_closed(issue_key):
    decision = resolve_ssc_internal_risk(issue_key)
    assert decision.breach_risk == "UNKNOWN" and decision.affects_score is False


def test_wave5c_config_and_executor_pass_declared_hostname(monkeypatch):
    configured = validate_scan_config({
        "executors": ["tcp"],
        "service_probes": [
            {"protocol": "minecraft", "port": 25565},
            {"protocol": "pptp", "port": 1723},
            {"protocol": "rdp", "port": 3389},
        ],
    })
    assert [item["protocol"] for item in configured["service_probes"]] == ["minecraft", "pptp", "rdp"]
    seen = []

    def fake_probe(connect_host, port, protocol, **kwargs):
        seen.append((connect_host, port, protocol, kwargs["declared_hostname"]))
        return {
            "protocol": protocol, "issue_key": {"minecraft": "minecraft_server", "pptp": "service_pptp", "rdp": "service_rdp"}[protocol],
            "framework_version": FRAMED_PROBE_FRAMEWORK_VERSION, "outcome": "INDETERMINATE", "matched": None,
            "policy_version": WAVE5C_SERVICE_POLICY_VERSION,
        }

    monkeypatch.setattr("app.services.scan_executors._pin_target", lambda target: target)
    monkeypatch.setattr("app.services.scan_executors.run_service_probe", fake_probe)
    target = InventoryScanTarget(ScanTargetTypeEnum.HOST, "id", "declared.example.test", "192.0.2.10", "example.test", False)
    TCPExecutor().collect(target, configured)
    assert all(item[3] == "declared.example.test" for item in seen)


def test_wave5c_rules_close_minecraft_and_rdp_with_exact_semantics(db):
    assert WAVE5C_ACTIVE_KEYS == frozenset({"minecraft_server", "service_rdp"})
    assert WAVE5C_CLOSURE_BLOCKERS == {"service_pptp": ("IMPLEMENTED_PENDING_INTEROP",)}
    minecraft = WAVE5C_BY_KEY["minecraft_server"]
    assert minecraft.expression == {
        "operator": "equals", "path": "tcp.evaluations.minecraft_server.matched", "value": True,
    }
    assert minecraft.evidence_schema["semantic_class"] == "PROTOCOL_IDENTITY_ONLY"
    assert "public_exposure_context" not in minecraft.evidence_schema
    rdp = WAVE5C_BY_KEY["service_rdp"]
    assert rdp.expression == {
        "operator": "equals",
        "path": "tcp.evaluations.service_rdp.exposure_context.composition.matched",
        "value": True,
    }
    assert rdp.evidence_schema["public_exposure_context"]["consumer_policy_version"] == (
        PUBLIC_EXPOSURE_CONSUMER_POLICY_V2
    )
    assert get_pinned_public_exposure_consumer("service_pptp") is not None
    args = build_parser().parse_args(["baseline", "activate-wave5c", "--yes"])
    assert args.baseline_command == "activate-wave5c" and args.yes


def test_wave5c_activation_requires_exact_baseline_is_idempotent_and_deactivates_pptp(db):
    unavailable = activate_wave5c_rules(db, commit=False)["unavailable"]
    assert set(unavailable) == {"minecraft_server", "service_rdp"}
    issues = _seed_pinned_wave5c_baseline(db)

    pptp_rule = RuleEngineRule(
        stable_key="ssc.wave5c.service_pptp",
        catalog_issue_type_id=issues["service_pptp"].id,
        is_active=True,
    )
    db.add(pptp_rule)
    db.flush()
    first = activate_wave5c_rules(db, commit=False)
    assert first["unavailable"] == {}
    assert set(first["activated"]) == {"minecraft_server", "service_rdp"}
    assert first["inactive"] == ["service_pptp"]
    assert first["rules_created"] == first["rule_versions_created"] == 2
    assert first["rules_deactivated"] == 1 and pptp_rule.is_active is False
    mappings = active_wave5c_mappings(db)
    assert {mapping["issue_key"] for mapping in mappings} == {"minecraft_server", "service_rdp"}
    assert all(UUID(mapping["issue_version_id"]) == issues[mapping["issue_key"]].current_version_id for mapping in mappings)

    version_count = db.scalar(select(func.count()).select_from(RuleEngineRuleVersion))
    repeated = activate_wave5c_rules(db, commit=False)
    assert repeated["rules_created"] == repeated["rule_versions_created"] == 0
    assert repeated["rules_reused"] == 2 and repeated["rules_deactivated"] == 0
    assert db.scalar(select(func.count()).select_from(RuleEngineRuleVersion)) == version_count


def test_wave5c_activation_rejects_stale_current_version_and_does_not_churn_other_rules(db):
    issues = _seed_pinned_wave5c_baseline(db)
    other_rules = []
    for position, issue_key in enumerate((
        "service_rsync", "service_redis", "service_socks_proxy", "service_smb", "service_soap",
        "service_ftp", "service_imap", "service_pop3", "service_ldap",
    )):
        rule = RuleEngineRule(stable_key=f"ssc.existing.{issue_key}", is_active=True)
        db.add(rule)
        db.flush()
        version = RuleEngineRuleVersion(
            rule_id=rule.id,
            version_number=2,
            name=issue_key,
            target_type=RuleTargetTypeEnum.HOST,
            rule_expression={"operator": "equals", "path": f"tcp.evaluations.{issue_key}.matched", "value": True},
            evidence_schema={"immutable_fixture": position},
            source_type=RuleSourceTypeEnum.SSC_REFERENCE,
        )
        db.add(version)
        db.flush()
        rule.current_version_id = version.id
        other_rules.append((rule.id, version.id, version.version_number, version.rule_expression, version.evidence_schema))

    initial = activate_wave5c_rules(db, commit=False)
    assert set(initial["activated"]) == {"minecraft_server", "service_rdp"}
    minecraft_rule = db.scalar(select(RuleEngineRule).where(
        RuleEngineRule.stable_key == "ssc.wave5c.minecraft_server"
    ))

    minecraft = issues["minecraft_server"]
    stale = CatalogIssueTypeVersion(
        issue_type_id=minecraft.id,
        version_number=2,
        name="Stale Minecraft definition",
        breach_risk=BreachRiskEnum.UNKNOWN,
        ssc_severity="medium",
        affects_score=False,
        source_type=SourceTypeEnum.SSC_API,
    )
    db.add(stale)
    db.flush()
    minecraft.current_version_id = stale.id
    result = activate_wave5c_rules(db, commit=False)
    assert set(result["activated"]) == {"service_rdp"}
    assert set(result["unavailable"]) == {"minecraft_server"}
    assert result["rules_deactivated"] == 1 and minecraft_rule.is_active is False
    for rule_id, version_id, number, expression, schema in other_rules:
        rule = db.get(RuleEngineRule, rule_id)
        version = db.get(RuleEngineRuleVersion, version_id)
        assert rule.current_version_id == version_id and rule.is_active
        assert (version.version_number, version.rule_expression, version.evidence_schema) == (number, expression, schema)
