import json
import os
import socket
import struct
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from uuid import UUID

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models.catalog_models import (
    BreachRiskEnum,
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.models.rule_models import RuleEngineRuleVersion
from app.models.scan_models import ScanTargetTypeEnum
from app.services import scan_executors as executors
from app.services.public_exposure import (
    AttestationSource,
    ExecutionContext,
    VantageClass,
    attach_exposure_context_for_issue,
)
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V3,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_V4,
    PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS,
    get_pinned_public_exposure_consumer,
)
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.service_probe_dns import (
    DNS_QUERY_POLICY_VERSION,
    DNS_SERVICE_QNAME,
    MAX_DNS_TCP_RESPONSE_BYTES,
    MAX_DNS_UDP_RESPONSE_BYTES,
    aggregate_dns_service_attempts,
    build_dns_service_query,
    evaluate_tcp_dns_frame,
    evaluate_udp_dns_response,
    indeterminate_dns_attempt,
)
from app.services.wave5e_rules import (
    PINNED_SERVICE_DNS_ISSUE_VERSION_ID,
    WAVE5E_BY_KEY,
    activate_wave5e_rules,
    active_wave5e_mappings,
)


def _wire_response(transaction_id=0x1234, *, rcode=dns.rcode.NOERROR, tc=False, qname=DNS_SERVICE_QNAME):
    query = dns.message.make_query(qname, dns.rdatatype.A, dns.rdataclass.IN, id=transaction_id, flags=0)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    if tc:
        response.flags |= dns.flags.TC
    return response.to_wire()


def _udp(wire, *, expected=0x1234, source=True, oversized=False):
    return evaluate_udp_dns_response(
        wire,
        expected_transaction_id=expected,
        port=53,
        source_match=source,
        elapsed_ms=1,
        observed_at="2026-10-16T00:00:00+00:00",
        oversized=oversized,
    )


def _tcp(wire, *, expected=0x1234):
    return evaluate_tcp_dns_frame(
        len(wire).to_bytes(2, "big") + wire,
        expected_transaction_id=expected,
        port=53,
        source_match=True,
        elapsed_ms=1,
        observed_at="2026-10-16T00:00:00+00:00",
    )


def _target(address="127.0.0.1", *, allow_sensitive=True, target_type=ScanTargetTypeEnum.HOST):
    return executors.InventoryScanTarget(
        target_type, "inventory-id", "approved.test", address, "example.test", allow_sensitive,
    )


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def test_fixed_query_is_exact_bounded_and_randomized_without_edns(monkeypatch):
    generated = iter((0x1234, 0x5678))
    monkeypatch.setattr("app.services.service_probe_dns.secrets.randbits", lambda _bits: next(generated))
    first, first_id = build_dns_service_query()
    second, second_id = build_dns_service_query()
    message = dns.message.from_wire(first)
    assert len(first) == 50
    assert (first_id, second_id) == (0x1234, 0x5678) and first != second
    assert message.id == first_id
    assert message.opcode() == dns.opcode.QUERY
    assert message.flags == 0
    assert len(message.question) == 1
    assert message.question[0].name == DNS_SERVICE_QNAME
    assert message.question[0].rdtype == dns.rdatatype.A
    assert message.question[0].rdclass == dns.rdataclass.IN
    assert message.edns == -1 and not message.additional
    assert DNS_QUERY_POLICY_VERSION == "ssc-wave5e-dns-query-policy.v1"


@pytest.mark.parametrize("rcode", [
    dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.REFUSED,
    dns.rcode.SERVFAIL, dns.rcode.NOTIMP, dns.rcode.FORMERR,
])
def test_reviewed_rcodes_with_exact_question_prove_dns_identity(rcode):
    result = _udp(_wire_response(rcode=rcode))
    assert (result["outcome"], result["matched"], result["rcode"]) == ("MATCH", True, rcode)


@pytest.mark.parametrize("rcode", range(6, 16))
def test_unreviewed_rcodes_are_indeterminate(rcode):
    assert _udp(_wire_response(rcode=rcode))["reason_code"] == "rcode_not_accepted_v1"


def test_formerr_without_exact_question_is_indeterminate():
    wire = struct.pack("!HHHHHH", 0x1234, dns.flags.QR | dns.rcode.FORMERR, 0, 0, 0, 0)
    assert _udp(wire)["outcome"] == "INDETERMINATE"


def test_valid_correlated_udp_tc_is_match_without_fallback():
    result = _udp(_wire_response(tc=True))
    assert result["outcome"] == "MATCH" and result["tc"] is True


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"expected": 1}, "transaction_id_mismatch"),
        ({"source": False}, "response_source_mismatch"),
    ],
)
def test_udp_correlation_failures_are_indeterminate(kwargs, reason):
    result = _udp(_wire_response(), **kwargs)
    assert result["outcome"] == "INDETERMINATE" and result["reason_code"] == reason


def test_udp_wrong_question_malformed_trailing_and_oversized_are_indeterminate():
    wrong = dns.name.from_text("other.invalid.")
    assert _udp(_wire_response(qname=wrong))["reason_code"] == "question_mismatch"
    assert _udp(b"bad")["reason_code"] == "dns_parsing_failed"
    assert _udp(_wire_response() + b"junk")["reason_code"] == "dns_parsing_failed"
    oversized = _udp(b"x" * (MAX_DNS_UDP_RESPONSE_BYTES + 1), oversized=True)
    assert oversized["reason_code"] == "udp_response_oversized"


def test_tcp_valid_frame_and_all_framing_failures_are_indeterminate():
    wire = _wire_response()
    assert _tcp(wire)["outcome"] == "MATCH"
    cases = {
        b"": "tcp_length_prefix_partial",
        b"\x00": "tcp_length_prefix_partial",
        b"\x00\x00": "tcp_length_zero",
        b"\x00\x0b" + b"x" * 11: "tcp_length_below_dns_header",
        (MAX_DNS_TCP_RESPONSE_BYTES + 1).to_bytes(2, "big"): "tcp_length_oversized",
        len(wire).to_bytes(2, "big") + wire[:-1]: "tcp_dns_body_partial",
        len(wire).to_bytes(2, "big") + wire + b"x": "tcp_frame_trailing_bytes",
    }
    for frame, reason in cases.items():
        result = evaluate_tcp_dns_frame(
            frame, expected_transaction_id=0x1234, port=53, source_match=True, elapsed_ms=1,
        )
        assert result["outcome"] == "INDETERMINATE" and result["reason_code"] == reason


def test_aggregation_stops_conceptually_at_any_match_and_never_no_match():
    failed = indeterminate_dns_attempt(transport="udp", port=53, reason_code="udp_timeout", elapsed_ms=1)
    matched = _tcp(_wire_response())
    assert aggregate_dns_service_attempts([failed, matched])["outcome"] == "MATCH"
    inconclusive = aggregate_dns_service_attempts([failed])
    assert inconclusive["outcome"] == "INDETERMINATE"
    assert "NO_MATCH" not in json.dumps(inconclusive)


def test_executor_aggregation_stops_after_first_match(monkeypatch):
    calls = []
    monkeypatch.setattr(executors, "_run_dns_udp_probe", lambda host, port, deadline: (
        calls.append(("udp", host, port)) or _udp(_wire_response())
    ))
    monkeypatch.setattr(executors, "_run_dns_tcp_probe", lambda *_args: pytest.fail("probe after match"))
    attempts = executors._collect_dns_service_attempts(_target("192.0.2.1"), [
        {"transport": "udp", "port": 53}, {"transport": "tcp", "port": 53},
    ])
    assert len(attempts) == 1 and attempts[0]["outcome"] == "MATCH"
    assert calls == [("udp", "192.0.2.1", 53)]


def test_udp_indeterminate_then_explicit_tcp_match(monkeypatch):
    monkeypatch.setattr(executors, "_run_dns_udp_probe", lambda *_args: indeterminate_dns_attempt(
        transport="udp", port=53, reason_code="udp_timeout", elapsed_ms=1,
    ))
    monkeypatch.setattr(executors, "_run_dns_tcp_probe", lambda *_args: _tcp(_wire_response()))
    attempts = executors._collect_dns_service_attempts(_target("192.0.2.1"), [
        {"transport": "udp", "port": 53}, {"transport": "tcp", "port": 53},
    ])
    assert [item["outcome"] for item in attempts] == ["INDETERMINATE", "MATCH"]
    assert aggregate_dns_service_attempts(attempts)["outcome"] == "MATCH"


def test_compact_evidence_never_retains_query_or_wire_values():
    result = _udp(_wire_response(rcode=dns.rcode.REFUSED))
    rendered = json.dumps(result)
    assert "ssc-dns-service-probe-v1.invalid" not in rendered
    assert "1234" not in rendered
    assert "raw" not in result and "answers" not in result


@pytest.mark.parametrize("bad", [
    {"dns_service_probes": "udp"},
    {"dns_service_probes": [{"transport": "UDP", "port": 53}]},
    {"dns_service_probes": [{"transport": "udp", "port": True}]},
    {"dns_service_probes": [{"transport": "udp", "port": 0}]},
    {"dns_service_probes": [{"transport": "udp", "port": 65536}]},
    {"dns_service_probes": [{"transport": "udp", "port": 53, "host": "127.0.0.1"}]},
    {"dns_service_probes": [{"transport": "udp", "port": 53, "qname": "example.com"}]},
    {"dns_service_probes": [
        {"transport": "udp", "port": 53}, {"transport": "tcp", "port": 53},
        {"transport": "udp", "port": 54},
    ]},
    {"executors": ["http"], "dns_service_probes": [{"transport": "udp", "port": 53}]},
])
def test_service_probe_configuration_rejects_unbounded_or_inconsistent_shapes(bad):
    with pytest.raises(executors.ScanExecutorError):
        executors.validate_scan_config(bad)


def test_service_probe_configuration_is_opt_in_and_deduplicated():
    assert executors.validate_scan_config({})["dns_service_probes"] == []
    configured = executors.validate_scan_config({
        "executors": ["dns"],
        "dns_service_probes": [
            {"transport": "udp", "port": 53}, {"transport": "udp", "port": 53},
            {"transport": "tcp", "port": 53},
        ],
    })
    assert configured["dns_service_probes"] == [
        {"transport": "udp", "port": 53}, {"transport": "tcp", "port": 53},
    ]


def test_domain_target_and_sensitive_unapproved_address_are_rejected_before_probe(monkeypatch):
    monkeypatch.setattr(executors, "_collect_dns_service_attempts", lambda *_args: pytest.fail("network probe"))
    config = {"dns_service_probes": [{"transport": "udp", "port": 53}]}
    with pytest.raises(executors.ScanExecutorError, match="HOST"):
        executors.DNSExecutor().collect(_target(target_type=ScanTargetTypeEnum.DOMAIN), config)
    with pytest.raises(executors.ScanExecutorError, match="sensitive"):
        executors.DNSExecutor().collect(_target(allow_sensitive=False), config)


def _dns_health_result(name):
    return {
        "name": name, "record_type": "TXT", "status": "NODATA", "records": [],
        "invalid_records": [], "answer_count": 0, "response_size": 0, "error_class": None,
    }


def _stub_dns_health(monkeypatch):
    monkeypatch.setattr(executors, "_query_spf_txt_evidence", lambda name, *_args: _dns_health_result(name))
    monkeypatch.setattr(executors, "_query_txt_evidence", lambda name, *_args: _dns_health_result(name))
    monkeypatch.setattr(executors, "analyze_spf", lambda *_args, **_kwargs: {
        "outcome": "NO_MATCH", "permanent_error": False, "valid": False,
        "error_class": "record_missing", "terminal_all": None,
    })
    monkeypatch.setattr(executors.secrets, "token_hex", lambda _count: "fixednonce")


def test_absent_probe_config_preserves_dns_health_evidence_and_creates_no_service_evaluation(monkeypatch):
    _stub_dns_health(monkeypatch)
    before = executors.DNSExecutor().collect(_target(), {}).evidence
    after = executors.DNSExecutor().collect(_target(), {"dns_service_probes": []}).evidence
    assert before == after
    assert "service_dns" not in before["evaluations"]
    assert "service_probes" not in before


def test_dns_server_host_is_resolver_only_and_never_service_destination(monkeypatch):
    _stub_dns_health(monkeypatch)
    probed = []
    monkeypatch.setattr(executors, "_collect_dns_service_attempts", lambda target, probes: (
        probed.append((target.connect_host, deepcopy(probes))) or [
            indeterminate_dns_attempt(transport="udp", port=5353, reason_code="udp_timeout", elapsed_ms=1)
        ]
    ))
    evidence = executors.DNSExecutor().collect(_target("127.0.0.1"), {
        "dns_server_host": "127.0.0.2",
        "dns_service_probes": [{"transport": "udp", "port": 5353}],
    }).evidence
    assert probed == [("127.0.0.1", [{"transport": "udp", "port": 5353}])]
    assert evidence["target_identity"]["connect_host"] == "127.0.0.1"
    assert evidence["status"] == "success"
    assert evidence["evaluations"]["service_dns"]["outcome"] == "INDETERMINATE"


def test_issue_filtered_exposure_attachment_does_not_decorate_email_evaluations():
    evidence = {"evaluations": {
        "spf_record_missing": {"outcome": "MATCH", "matched": True},
        "service_dns": {"outcome": "MATCH", "matched": True},
    }}
    context = ExecutionContext(
        VantageClass.EXTERNAL_PUBLIC, "edge", AttestationSource.DEPLOYMENT_MANIFEST,
        manifest_digest="a" * 64,
    )
    attach_exposure_context_for_issue(evidence, "8.8.8.8", context, "service_dns")
    assert "exposure_context" not in evidence["evaluations"]["spf_record_missing"]
    assert evidence["evaluations"]["service_dns"]["exposure_context"]["composition"]["matched"] is True


def test_public_exposure_registry_v4_is_strictly_additive_for_dns():
    v3 = PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS[PUBLIC_EXPOSURE_CONSUMER_POLICY_V3]
    v4 = PUBLIC_EXPOSURE_CONSUMER_REGISTRY_VERSIONS[PUBLIC_EXPOSURE_CONSUMER_POLICY_V4]
    assert v4[:-1] == v3 and v4[-1] == "service_dns"
    consumer = get_pinned_public_exposure_consumer("service_dns")
    assert (consumer.evidence_root, consumer.required_evidence_source) == ("dns", "SCANNER_DNS")


def test_service_dns_remains_unconfigured_unknown_and_non_scoring():
    decision = resolve_ssc_internal_risk("service_dns")
    assert (decision.breach_risk, decision.affects_score) == ("UNKNOWN", False)


def _seed_exact_dns_baseline(db):
    factor = CatalogFactor(code="network_security", name="Network Security")
    snapshot = CatalogSnapshot(
        name="Pinned Wave 5E baseline", source_type=SourceTypeEnum.SSC_API,
        content_hash=PINNED_SSC_BASELINE_HASH, normalized_schema_version="ssc.api.metadata.v2",
        is_real_baseline=True,
    )
    db.add_all([factor, snapshot]); db.flush()
    issue = CatalogIssueType(stable_key="service_dns", factor_id=factor.id)
    db.add(issue); db.flush()
    version = CatalogIssueTypeVersion(
        id=UUID(PINNED_SERVICE_DNS_ISSUE_VERSION_ID), issue_type_id=issue.id, version_number=1,
        name="DNS Server Accessible", breach_risk=BreachRiskEnum.UNKNOWN, ssc_severity="medium",
        affects_score=False, source_type=SourceTypeEnum.SSC_API, source_snapshot_hash=PINNED_SSC_BASELINE_HASH,
    )
    db.add(version); db.flush(); issue.current_version_id = version.id
    db.add(CatalogSnapshotItem(
        catalog_snapshot_id=snapshot.id, issue_type_version_id=version.id,
        factor_position=1, issue_position=1,
    ))
    db.flush()
    return issue


def test_exact_activation_is_idempotent_immutable_and_non_scoring(db):
    _seed_exact_dns_baseline(db)
    first = activate_wave5e_rules(db, commit=False)
    assert first["activated"] == ["service_dns"] and not first["unavailable"]
    count = db.scalar(select(func.count()).select_from(RuleEngineRuleVersion))
    second = activate_wave5e_rules(db, commit=False)
    assert second["rules_created"] == second["rule_versions_created"] == 0
    assert db.scalar(select(func.count()).select_from(RuleEngineRuleVersion)) == count
    mapping = active_wave5e_mappings(db)
    assert mapping[0]["issue_version_id"] == PINNED_SERVICE_DNS_ISSUE_VERSION_ID
    spec = WAVE5E_BY_KEY["service_dns"]
    assert spec.expression["path"] == "dns.evaluations.service_dns.exposure_context.composition.matched"


@contextmanager
def _one_shot_dns_server(transport, *, rcode=dns.rcode.REFUSED):
    family = socket.AF_INET
    sock_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    server = socket.socket(family, sock_type)
    server.bind(("127.0.0.1", 0))
    if transport == "tcp":
        server.listen(1)
    port = server.getsockname()[1]
    requests = []

    def serve():
        try:
            if transport == "udp":
                request, peer = server.recvfrom(512)
                requests.append(request)
                query = dns.message.from_wire(request)
                response = dns.message.make_response(query)
                response.set_rcode(rcode)
                server.sendto(response.to_wire(), peer)
            else:
                connection, _peer = server.accept()
                with connection:
                    prefix = connection.recv(2)
                    size = int.from_bytes(prefix, "big")
                    request = b""
                    while len(request) < size:
                        request += connection.recv(size - len(request))
                    requests.append(request)
                    query = dns.message.from_wire(request)
                    response = dns.message.make_response(query)
                    response.set_rcode(rcode)
                    wire = response.to_wire()
                    connection.sendall(len(wire).to_bytes(2, "big") + wire)
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, requests
    finally:
        thread.join(timeout=2)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_loopback_socket_acquisition_matches_refused_once(transport):
    with _one_shot_dns_server(transport) as (port, requests):
        deadline = time.monotonic() + 3
        if transport == "udp":
            result = executors._run_dns_udp_probe("127.0.0.1", port, deadline)
        else:
            result = executors._run_dns_tcp_probe("127.0.0.1", port, deadline)
    assert result["outcome"] == "MATCH" and result["rcode"] == dns.rcode.REFUSED
    assert len(requests) == 1
    query = dns.message.from_wire(requests[0])
    assert query.question[0].name == DNS_SERVICE_QNAME and not (query.flags & dns.flags.RD)


def test_real_coredns_udp_and_tcp_interoperability_when_enabled():
    raw_port = os.getenv("WAVE5E_COREDNS_PORT")
    if raw_port is None:
        pytest.skip("real CoreDNS closure fixture is explicitly enabled by the interoperability gate")
    port = int(raw_port)
    udp = executors._run_dns_udp_probe("127.0.0.1", port, time.monotonic() + 3)
    tcp = executors._run_dns_tcp_probe("127.0.0.1", port, time.monotonic() + 3)
    assert (udp["outcome"], udp["rcode"]) == ("MATCH", dns.rcode.NXDOMAIN)
    assert (tcp["outcome"], tcp["rcode"]) == ("MATCH", dns.rcode.NXDOMAIN)
