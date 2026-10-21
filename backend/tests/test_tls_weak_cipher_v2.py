import hashlib
import re
import struct
from types import SimpleNamespace
from uuid import UUID

import pytest

from app.models.catalog_models import SourceTypeEnum
from app.services import scan_executors
from app.services.internal_risk_calibration import resolve_ssc_internal_risk
from app.services.service_probe_tls_cipher import (
    CATALOG_SHA256,
    CATALOG_VERSION,
    MAX_CLIENT_HELLO_BYTES,
    MAX_HANDSHAKE_MESSAGES,
    MAX_RESPONSE_BYTES,
    MAX_TLS_RECORDS,
    METHOD_VERSION,
    POLICY_VERSION,
    PROBE_VERSION,
    SSC_WEAK_CIPHER_BY_ID,
    SSC_WEAK_CIPHER_CATALOG,
    STRONG_CONTROL_SUITES,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    TLS_FALLBACK_SCSV,
    TLS_VERSIONS,
    build_client_hello,
    build_prohibited_partitions,
    build_strong_control,
    evaluate_endpoint_observation,
    parse_tls_response,
    prohibited_suite_ids,
)
from app.services.wave2_rules import (
    GOLDEN_BASELINE_HASH,
    TLS_WEAK_CIPHER_ISSUE_VERSION_ID,
    TLS_WEAK_CIPHER_ISSUE_VERSION_NUMBER,
    WAVE2_BY_KEY,
    _required_issue_version_matches,
)


EXACT_IDS = {
    0x00A2, 0x00A3, 0xC056, 0xC057, 0xC080, 0x0096,
    0x009A, 0xC072, 0xC073, 0xC023, 0xC0A2, 0xC0A3,
}


def _is_grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _server_hello(partition, selected=None, *, version=None, compression=0, extensions=b""):
    selected = selected if selected is not None else partition.offered_suite_ids[0]
    version = version if version is not None else TLS_VERSIONS[partition.tls_version]
    body = (
        struct.pack("!H", version) + bytes(range(32)) + b"\x00"
        + struct.pack("!H", selected) + bytes([compression])
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _alert(description, *, fatal=True):
    fragment = bytes([2 if fatal else 1, description])
    return b"\x15\x03\x01" + struct.pack("!H", len(fragment)) + fragment


def _compact_attempt(partition, *, matched=None, rejected=False):
    return {
        "partition_id": partition.partition_id,
        "attempted_version": partition.tls_version,
        "suite_class": partition.suite_class,
        "matched": matched,
        "definitive_rejection": rejected,
    }


def test_frozen_catalog_exact_membership_digest_and_provider_independence(monkeypatch):
    assert len(SSC_WEAK_CIPHER_CATALOG) == 90
    assert CATALOG_SHA256 == "a4cdf405202a6492600e3c8794874b7e37f8cc64e40d9929374d8ef18991570a"
    assert CATALOG_VERSION == "ssc-tls-weak-cipher-catalog.2026-08-11.v1"
    assert EXACT_IDS <= set(SSC_WEAK_CIPHER_BY_ID)
    assert all(entry.reasons for entry in SSC_WEAK_CIPHER_CATALOG)
    assert all(
        entry.effective_strength_bits is None or entry.effective_strength_bits < 128
        for entry in SSC_WEAK_CIPHER_CATALOG
    )
    assert TLS_EMPTY_RENEGOTIATION_INFO_SCSV not in SSC_WEAK_CIPHER_BY_ID
    assert TLS_FALLBACK_SCSV not in SSC_WEAK_CIPHER_BY_ID
    assert not any(_is_grease(value) for value in SSC_WEAK_CIPHER_BY_ID)
    assert not any("TLSv1.3" in entry.tls_versions for entry in SSC_WEAK_CIPHER_CATALOG)
    # The module has no ssl/OpenSSL membership input; changing scan executor ssl
    # cannot affect the immutable catalog or its digest.
    monkeypatch.setattr(scan_executors.ssl, "OPENSSL_VERSION", "test-provider")
    assert len(SSC_WEAK_CIPHER_CATALOG) == 90
    assert CATALOG_SHA256 == "a4cdf405202a6492600e3c8794874b7e37f8cc64e40d9929374d8ef18991570a"


def test_disclosed_name_families_and_strength_facts_are_compiled():
    pattern = re.compile(r"md4|md5|rc2|rc4|rsa_export|^tls_dh_.*_export|^tls_dhe_.*_export", re.I)
    catalog_names = {entry.canonical_name for entry in SSC_WEAK_CIPHER_CATALOG}
    assert {name for name in catalog_names if pattern.search(name)}
    for entry in SSC_WEAK_CIPHER_CATALOG:
        if pattern.search(entry.canonical_name):
            assert "ssc_disclosed_name_family" in entry.reasons
        if entry.effective_strength_bits is not None:
            assert "effective_strength_below_128" in entry.reasons
    # Reviewed exclusions: these broad categories are not independently enough.
    assert 0x0007 not in SSC_WEAK_CIPHER_BY_ID  # TLS_RSA_WITH_IDEA_CBC_SHA
    assert 0x009B not in SSC_WEAK_CIPHER_BY_ID  # all-SEED would include this
    assert 0xC013 not in SSC_WEAK_CIPHER_BY_ID  # generic AES-CBC/non-AEAD
    assert 0xC09E not in SSC_WEAK_CIPHER_BY_ID  # generic CCM is not CCM8 exact entry


def test_client_hello_partitions_are_bounded_prohibited_only_and_represent_unavailable_suites():
    partitions = build_prohibited_partitions("tls.example.test")
    assert [item.tls_version for item in partitions] == list(TLS_VERSIONS)
    assert len(partitions) == 3
    for partition in partitions:
        request = partition.request_bytes
        assert len(request) <= MAX_CLIENT_HELLO_BYTES
        assert request[:3] == b"\x16\x03\x01"
        assert int.from_bytes(request[3:5], "big") == len(request) - 5
        assert request[5] == 1
        assert int.from_bytes(request[6:9], "big") == len(request) - 9
        assert request[9:11] == struct.pack("!H", TLS_VERSIONS[partition.tls_version])
        assert request[43] == 0  # empty session ID after 32-byte random
        assert set(partition.offered_suite_ids) <= set(SSC_WEAK_CIPHER_BY_ID)
        assert not (set(partition.offered_suite_ids) & set(STRONG_CONTROL_SUITES))
    tls12 = partitions[-1]
    assert {0xC080, 0x0096, 0x009A} <= set(tls12.offered_suite_ids)
    assert struct.pack("!H", 0xC080) in tls12.request_bytes
    assert struct.pack("!H", 0x0096) in tls12.request_bytes
    assert struct.pack("!H", 0x009A) in tls12.request_bytes


def test_client_hello_sni_extensions_random_and_numeric_omission():
    random_bytes = bytes(range(32))
    named = build_client_hello("TLSv1.2", prohibited_suite_ids("TLSv1.2"), "tls.example.test", random_bytes=random_bytes)
    numeric = build_client_hello("TLSv1.2", prohibited_suite_ids("TLSv1.2"), "192.0.2.10", random_bytes=random_bytes)
    assert random_bytes in named
    assert b"tls.example.test" in named
    assert b"192.0.2.10" not in numeric
    assert b"\x00\x0d" in named  # signature_algorithms extension
    assert b"\x00\x0a" in named  # supported_groups extension
    assert b"\x00\x0b" in named  # ec_point_formats extension
    assert b"h2" not in named and b"http/1.1" not in named
    with pytest.raises(ValueError):
        build_client_hello("TLSv1.2", [0xC080], "example.test", random_bytes=b"short")


def test_valid_server_hello_selection_matches_and_control_is_separate():
    partition = build_prohibited_partitions("example.test")[-1]
    result = parse_tls_response(_server_hello(partition, 0xC080), partition, eof=True)
    assert result.matched is True and result.server_hello_valid
    assert result.selected_suite_id == 0xC080
    assert result.selected_suite_class == "ssc_prohibited"
    control = build_strong_control("example.test")
    control_result = parse_tls_response(_server_hello(control, STRONG_CONTROL_SUITES[0]), control, eof=True)
    assert control_result.matched is True
    assert control_result.selected_suite_class == "strong_control"


def test_valid_prohibited_selection_matches_in_every_legacy_partition():
    for partition in build_prohibited_partitions("example.test"):
        result = parse_tls_response(_server_hello(partition), partition, eof=True)
        assert result.matched is True
        assert result.selected_suite_id in partition.offered_suite_ids


@pytest.mark.parametrize("selected", [0x1301, TLS_EMPTY_RENEGOTIATION_INFO_SCSV, 0x0A0A, 0xFEFE])
def test_unoffered_scsv_grease_and_unknown_selection_are_indeterminate(selected):
    partition = build_prohibited_partitions("example.test")[-1]
    result = parse_tls_response(_server_hello(partition, selected), partition, eof=True)
    assert result.matched is None and result.outcome == "INDETERMINATE"


def test_server_hello_strict_structure_and_fragmentation():
    partition = build_prohibited_partitions("example.test")[-1]
    extension = struct.pack("!HH", 0, 0)
    message = _server_hello(partition, extensions=extension)
    assert parse_tls_response(message, partition, eof=True).matched is True
    handshake = message[5:]
    split = 17
    fragmented = (
        b"\x16\x03\x01" + struct.pack("!H", split) + handshake[:split]
        + b"\x16\x03\x01" + struct.pack("!H", len(handshake) - split) + handshake[split:]
    )
    assert parse_tls_response(fragmented, partition, eof=True).matched is True
    assert parse_tls_response(_server_hello(partition, compression=1), partition, eof=True).matched is None
    assert parse_tls_response(_server_hello(partition, version=0x0302), partition, eof=True).matched is None
    duplicate = struct.pack("!HHHH", 0, 0, 0, 0)
    assert parse_tls_response(_server_hello(partition, extensions=duplicate), partition, eof=True).matched is None
    malformed = bytearray(message)
    malformed[-2:] = b"\xff\xff"
    assert parse_tls_response(bytes(malformed), partition, eof=True).matched is None
    assert parse_tls_response(message[:-1], partition, eof=True).matched is None


def test_response_record_and_handshake_limits_fail_closed():
    partition = build_prohibited_partitions("example.test")[-1]
    assert parse_tls_response(b"x" * (MAX_RESPONSE_BYTES + 1), partition).matched is None
    assert parse_tls_response(b"\x17\x03\x01\x00\x00", partition, eof=True).matched is None
    empty_records = b"\x16\x03\x01\x00\x00" * (MAX_TLS_RECORDS + 1)
    result = parse_tls_response(empty_records, partition, eof=True)
    assert result.reason_code == "record_limit_exceeded"
    hello_requests = (b"\x00\x00\x00\x00" * (MAX_HANDSHAKE_MESSAGES + 1))
    record = b"\x16\x03\x01" + struct.pack("!H", len(hello_requests)) + hello_requests
    result = parse_tls_response(record, partition, eof=True)
    assert result.reason_code == "handshake_message_limit_exceeded"


@pytest.mark.parametrize("description,name", [(40, "handshake_failure"), (71, "insufficient_security"), (70, "protocol_version")])
def test_reviewed_fatal_alerts_are_rejection_candidates(description, name):
    partition = build_prohibited_partitions("example.test")[0]
    result = parse_tls_response(_alert(description), partition, eof=True)
    assert result.definitive_rejection is True
    assert result.alert_class == name
    assert result.matched is False


@pytest.mark.parametrize("description", [47, 50, 80, 110])
def test_ambiguous_alerts_are_indeterminate(description):
    partition = build_prohibited_partitions("example.test")[0]
    result = parse_tls_response(_alert(description), partition, eof=True)
    assert result.definitive_rejection is False
    assert result.matched is None
    assert parse_tls_response(b"", partition, eof=True).matched is None


def test_endpoint_match_no_match_and_indeterminate_contracts():
    partitions = build_prohibited_partitions("example.test")
    rejected = [_compact_attempt(item, matched=False, rejected=True) for item in partitions]
    observation = {"attempts": rejected, "catalog_complete": True, "control": {"matched": True}}
    assert evaluate_endpoint_observation(observation) is False
    assert evaluate_endpoint_observation({**observation, "control": {"matched": None}}) is None
    assert evaluate_endpoint_observation({**observation, "attempts": rejected[:-1]}) is None
    ambiguous = [*rejected[:-1], _compact_attempt(partitions[-1], matched=None, rejected=False)]
    assert evaluate_endpoint_observation({**observation, "attempts": ambiguous}) is None
    attempts = [_compact_attempt(partitions[0], matched=True), *rejected[1:]]
    assert evaluate_endpoint_observation({**observation, "attempts": attempts}) is True


def test_collector_stops_on_match_and_caps_attempts(monkeypatch):
    calls = []

    def fake_attempt(host, port, partition, timeout):
        assert (host, port) == ("192.0.2.1", 443)
        assert 0 < timeout <= 3.0
        calls.append(partition.partition_id)
        matched = partition.partition_id == "tls11"
        return _compact_attempt(partition, matched=matched, rejected=not matched)

    monkeypatch.setattr(scan_executors, "_raw_tls_cipher_attempt", fake_attempt)
    evidence = scan_executors._collect_ssc_tls_weak_cipher_evidence("192.0.2.1", "example.test", 443, 30)
    assert calls == ["tls10", "tls11"]
    assert evidence["matched"] is True and evidence["attempt_count"] == 2
    assert evidence["attempt_count"] <= 4
    assert evidence["probe_version"] == PROBE_VERSION
    assert evidence["method_version"] == METHOD_VERSION
    assert evidence["policy_version"] == POLICY_VERSION
    assert evidence["catalog_hash"] == CATALOG_SHA256


def test_collector_uses_one_control_only_after_three_rejections(monkeypatch):
    calls = []

    def fake_attempt(host, port, partition, timeout):
        assert (host, port) == ("192.0.2.1", 443)
        assert 0 < timeout <= 3.0
        calls.append(partition.partition_id)
        if partition.suite_class == "strong_control":
            return _compact_attempt(partition, matched=True)
        return _compact_attempt(partition, matched=False, rejected=True)

    monkeypatch.setattr(scan_executors, "_raw_tls_cipher_attempt", fake_attempt)
    evidence = scan_executors._collect_ssc_tls_weak_cipher_evidence("192.0.2.1", "example.test", 443, 30)
    assert calls == ["tls10", "tls11", "tls12", "tls12_strong_control"]
    assert evidence["attempt_count"] == 4
    assert evidence["matched"] is False and evidence["outcome"] == "NO_MATCH"


def test_wave2_rule_is_v2_and_exact_golden_version_pinned():
    spec = WAVE2_BY_KEY["tls_weak_cipher"]
    assert TLS_WEAK_CIPHER_ISSUE_VERSION_ID == "013168ec-2848-49eb-8d22-0f49ac2beb56"
    assert TLS_WEAK_CIPHER_ISSUE_VERSION_NUMBER == 1
    assert GOLDEN_BASELINE_HASH == "0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8"
    assert spec.evidence_schema["schema_version"] == METHOD_VERSION
    assert spec.evidence_schema["policy_version"] == POLICY_VERSION
    exact = SimpleNamespace(
        id=UUID(TLS_WEAK_CIPHER_ISSUE_VERSION_ID),
        version_number=TLS_WEAK_CIPHER_ISSUE_VERSION_NUMBER,
        source_type=SourceTypeEnum.SSC_API,
        source_snapshot_hash=GOLDEN_BASELINE_HASH,
    )
    assert _required_issue_version_matches(spec, exact)
    assert not _required_issue_version_matches(spec, SimpleNamespace(
        **{**exact.__dict__, "id": UUID("00000000-0000-0000-0000-000000000001")}
    ))
    assert not _required_issue_version_matches(spec, SimpleNamespace(
        **{**exact.__dict__, "source_snapshot_hash": "wrong"}
    ))


def test_existing_wave2_versions_and_scoring_are_unchanged():
    for issue_key, spec in WAVE2_BY_KEY.items():
        if issue_key != "tls_weak_cipher":
            assert spec.method_version == "ssc-wave2-observation.v1"
            assert spec.evidence_schema["schema_version"] == "ssc-wave2-observation.v1"
    decision = resolve_ssc_internal_risk("tls_weak_cipher")
    assert (decision.breach_risk, decision.affects_score) == ("UNKNOWN", False)


def test_endpoint_aggregation_is_match_dominant_and_fail_closed():
    assert scan_executors._tri_aggregate([False, True, None]) is True
    assert scan_executors._tri_aggregate([False, False]) is False
    assert scan_executors._tri_aggregate([False, None]) is None
    assert scan_executors._tri_aggregate([None, None]) is None


def test_compact_attempt_evidence_contains_no_raw_or_secret_material(monkeypatch):
    partition = build_prohibited_partitions("example.test")[-1]

    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def settimeout(self, _timeout): return None
        def sendall(self, data): self.sent = data
        def recv(self, _size):
            if hasattr(self, "done"): return b""
            self.done = True
            return _server_hello(partition, 0xC080)

    monkeypatch.setattr(scan_executors.socket, "create_connection", lambda target, timeout: FakeSocket())
    attempt = scan_executors._raw_tls_cipher_attempt("192.0.2.1", 443, partition, 1.0)
    assert attempt["matched"] is True
    assert attempt["selected_suite_id"] == 0xC080
    assert set(attempt).isdisjoint({"raw_request", "raw_response", "random", "session_id", "certificate"})
    assert attempt["response_sha256"] == hashlib.sha256(_server_hello(partition, 0xC080)).hexdigest()


@pytest.mark.parametrize(
    ("error", "expected_class"),
    [(TimeoutError(), "timeout"), (ConnectionResetError(), "connection_reset"), (OSError(), "transport_error")],
)
def test_transport_failures_are_indeterminate(monkeypatch, error, expected_class):
    partition = build_prohibited_partitions("example.test")[-1]

    def fail_connection(target, timeout):
        assert target == ("192.0.2.1", 443)
        assert timeout <= 3.0
        raise error

    monkeypatch.setattr(scan_executors.socket, "create_connection", fail_connection)
    attempt = scan_executors._raw_tls_cipher_attempt("192.0.2.1", 443, partition, 3.0)
    assert attempt["matched"] is None
    assert attempt["outcome"] == "INDETERMINATE"
    assert attempt["error_class"] == expected_class
    assert attempt["definitive_rejection"] is False
