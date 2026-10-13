import hashlib
import json

import pytest

from app.services.public_exposure import (
    ADDRESS_SCOPE_POLICY_TABLE_DIGEST,
    ADDRESS_SCOPE_POLICY_VERSION,
    DEPLOYMENT_BOUNDARY_ASSERTION,
    DEPLOYMENT_BOUNDARY_VERSION,
    DEPLOYMENT_MANIFEST_SCHEMA_VERSION,
    EXPOSURE_COMPOSITION_POLICY_VERSION,
    PUBLIC_EXPOSURE_SCHEMA_VERSION,
    VANTAGE_POLICY_VERSION,
    AddressScope,
    AddressScopeResult,
    AttestationSource,
    ExecutionContext,
    ExposureOutcome,
    ProtocolOutcome,
    VantageClass,
    api_inline_execution_context,
    attach_exposure_contexts,
    build_public_exposure_context,
    classify_pinned_address,
    compose_public_exposure,
    execution_context_snapshot,
    load_worker_execution_context,
    local_cli_execution_context,
    reject_reserved_trust_keys,
    unknown_execution_context,
)
from app.services.scan_executors import ScanExecutorError, validate_scan_config
from app.models.scan_models import EvidenceSourceEnum, ScanTargetTypeEnum
from app.services import scan_executors
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    PUBLIC_EXPOSURE_CONSUMER_POLICY_VERSION,
    PUBLIC_EXPOSURE_CONSUMERS,
    PUBLIC_EXPOSURE_REQUIRED_ISSUE_KEYS,
    get_public_exposure_consumer,
)
from app.services.wave3a_rules import WAVE3A_BY_KEY
from app.services.wave3b_rules import WAVE3B_BY_KEY
from app.services.wave5a_rules import WAVE5A_BY_KEY
from app.services.wave5b_rules import WAVE5B_BY_KEY


EXPECTED_TABLE_DIGEST = "69c38afc252d8462e6771653bd9a7bc8e59e6e0ee01d9e31f4fa5ed3747057d2"
EXPECTED_PUBLIC_EXPOSURE_CONSUMERS = {
    "service_rsync": ("tcp", "SCANNER_TCP"),
    "service_redis": ("tcp", "SCANNER_TCP"),
    "service_socks_proxy": ("tcp", "SCANNER_TCP"),
    "service_smb": ("tcp", "SCANNER_TCP"),
    "service_soap": ("http", "SCANNER_HTTP"),
    "service_ftp": ("tcp", "SCANNER_TCP"),
    "service_imap": ("tcp", "SCANNER_TCP"),
    "service_pop3": ("tcp", "SCANNER_TCP"),
    "service_ldap": ("tcp", "SCANNER_TCP"),
}


def test_public_exposure_consumer_registry_is_exact_immutable_and_version_aware():
    assert PUBLIC_EXPOSURE_CONSUMER_POLICY_VERSION == "ssc-public-exposure-consumers.v1"
    assert PUBLIC_EXPOSURE_REQUIRED_ISSUE_KEYS == set(EXPECTED_PUBLIC_EXPOSURE_CONSUMERS)
    assert len(PUBLIC_EXPOSURE_CONSUMERS) == 9
    for issue_key, (root, source) in EXPECTED_PUBLIC_EXPOSURE_CONSUMERS.items():
        consumer = get_public_exposure_consumer(PINNED_SSC_BASELINE_HASH, issue_key)
        assert consumer is not None
        assert consumer.semantic_class == "PUBLIC_EXPOSURE_REQUIRED"
        assert (consumer.evidence_root, consumer.required_evidence_source) == (root, source)
        assert consumer.expression_path == (
            f"{root}.evaluations.{issue_key}.exposure_context.composition.matched"
        )
    with pytest.raises(TypeError):
        PUBLIC_EXPOSURE_CONSUMERS[(PINNED_SSC_BASELINE_HASH, "other")] = object()


def test_public_exposure_consumer_registry_fails_closed_outside_reviewed_identity():
    assert get_public_exposure_consumer("unknown-baseline", "service_rsync") is None
    assert get_public_exposure_consumer(PINNED_SSC_BASELINE_HASH, "unknown_issue") is None
    for issue_key in ("service_vnc", "service_telnet", "mail_server_unusual_port"):
        assert get_public_exposure_consumer(PINNED_SSC_BASELINE_HASH, issue_key) is None


def test_registered_rules_use_composition_paths_and_unaffected_rules_remain_identity_based():
    specs = {**WAVE3A_BY_KEY, **WAVE3B_BY_KEY, **WAVE5A_BY_KEY, **WAVE5B_BY_KEY}
    for issue_key, (root, _source) in EXPECTED_PUBLIC_EXPOSURE_CONSUMERS.items():
        spec = specs[issue_key]
        assert spec.expression == {
            "operator": "equals",
            "path": f"{root}.evaluations.{issue_key}.exposure_context.composition.matched",
            "value": True,
        }
        contract = spec.evidence_schema["public_exposure_context"]
        assert contract["consumer_policy_version"] == PUBLIC_EXPOSURE_CONSUMER_POLICY_VERSION
        assert contract["required_context"] == {
            "schema_version": PUBLIC_EXPOSURE_SCHEMA_VERSION,
            "address_scope_policy_version": ADDRESS_SCOPE_POLICY_VERSION,
            "vantage_policy_version": VANTAGE_POLICY_VERSION,
            "composition_policy_version": EXPOSURE_COMPOSITION_POLICY_VERSION,
        }
        assert spec.evidence_schema["protocol_identity_is_sufficient"] is False

    for issue_key in ("service_vnc", "service_telnet"):
        spec = WAVE3A_BY_KEY[issue_key]
        assert spec.expression["path"] == f"tcp.evaluations.{issue_key}.matched"
        assert spec.evidence_schema["schema_version"] == "ssc-wave3a-service-observation.v1"
        assert "public_exposure_context" not in spec.evidence_schema

    smtp = WAVE5A_BY_KEY["mail_server_unusual_port"]
    assert smtp.expression["path"] == "tcp.evaluations.mail_server_unusual_port.matched"
    assert smtp.evidence_schema["schema_version"] == "ssc-wave5a-staged-text-service-observation.v1"
    assert smtp.evidence_schema["port_policy"]["standard_tcp_ports"] == [25, 465, 587]
    assert "public_exposure_context" not in smtp.evidence_schema


@pytest.mark.parametrize(
    ("address", "expected", "family"),
    [
        ("8.8.8.8", AddressScope.PUBLIC_ROUTABLE, "IPv4"),
        ("10.1.2.3", AddressScope.NON_PUBLIC, "IPv4"),
        ("172.16.1.2", AddressScope.NON_PUBLIC, "IPv4"),
        ("192.168.1.2", AddressScope.NON_PUBLIC, "IPv4"),
        ("127.0.0.1", AddressScope.NON_PUBLIC, "IPv4"),
        ("169.254.2.3", AddressScope.NON_PUBLIC, "IPv4"),
        ("100.64.0.1", AddressScope.NON_PUBLIC, "IPv4"),
        ("0.0.0.0", AddressScope.NON_PUBLIC, "IPv4"),
        ("192.0.2.5", AddressScope.NON_PUBLIC, "IPv4"),
        ("198.18.0.1", AddressScope.NON_PUBLIC, "IPv4"),
        ("224.0.0.1", AddressScope.NON_PUBLIC, "IPv4"),
        ("240.0.0.1", AddressScope.NON_PUBLIC, "IPv4"),
        ("255.255.255.255", AddressScope.NON_PUBLIC, "IPv4"),
        ("2606:4700:4700::1111", AddressScope.PUBLIC_ROUTABLE, "IPv6"),
        ("fc00::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("::", AddressScope.NON_PUBLIC, "IPv6"),
        ("fe80::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("ff02::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("2001:db8::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("2001:2::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("2001:20::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("2002::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("64:ff9b:1::1", AddressScope.NON_PUBLIC, "IPv6"),
        ("::ffff:8.8.8.8", AddressScope.PUBLIC_ROUTABLE, "IPv4"),
        ("::ffff:10.0.0.1", AddressScope.NON_PUBLIC, "IPv4"),
    ],
)
def test_address_policy_golden_vectors(address, expected, family):
    result = classify_pinned_address(address)
    assert result.outcome == expected
    assert result.address_family == family
    assert result.policy_version == ADDRESS_SCOPE_POLICY_VERSION
    assert result.policy_table_digest == EXPECTED_TABLE_DIGEST


@pytest.mark.parametrize("address", ["", "not-an-ip", "example.com", "fe80::1%eth0", "127.0.0.1%lo"])
def test_invalid_or_scoped_addresses_are_indeterminate(address):
    result = classify_pinned_address(address)
    assert result.outcome == AddressScope.INDETERMINATE
    assert result.address_family == "UNKNOWN"


def test_most_specific_global_exceptions_override_special_parent_prefixes():
    assert classify_pinned_address("192.0.0.9").outcome == AddressScope.PUBLIC_ROUTABLE
    assert classify_pinned_address("192.0.0.11").outcome == AddressScope.NON_PUBLIC
    assert classify_pinned_address("2001:1::1").outcome == AddressScope.PUBLIC_ROUTABLE
    assert classify_pinned_address("2001:1::4").outcome == AddressScope.NON_PUBLIC


def test_address_policy_digest_is_frozen_and_does_not_use_is_global():
    assert ADDRESS_SCOPE_POLICY_TABLE_DIGEST == EXPECTED_TABLE_DIGEST
    # Python versions have historically treated multicast/global differently;
    # these are policy-table results, not assertions about the stdlib property.
    assert classify_pinned_address("224.0.0.1").reason_code == "multicast"
    assert classify_pinned_address("100.64.0.1").reason_code == "shared_cgnat"


def _external_context() -> ExecutionContext:
    return ExecutionContext(
        VantageClass.EXTERNAL_PUBLIC,
        "edge-bkk-01",
        AttestationSource.DEPLOYMENT_MANIFEST,
        manifest_digest="a" * 64,
    )


def _scope(address: str) -> AddressScopeResult:
    return classify_pinned_address(address)


@pytest.mark.parametrize(
    ("protocol", "address", "context", "outcome", "reason"),
    [
        (ProtocolOutcome.MATCH, "8.8.8.8", _external_context(), ExposureOutcome.MATCH,
         "public_service_observed_from_external_vantage"),
        (ProtocolOutcome.MATCH, "8.8.8.8", ExecutionContext(VantageClass.INTERNAL, "internal", AttestationSource.UNCONFIGURED),
         ExposureOutcome.INDETERMINATE, "internal_vantage_not_public_proof"),
        (ProtocolOutcome.MATCH, "8.8.8.8", unknown_execution_context(),
         ExposureOutcome.INDETERMINATE, "vantage_unknown"),
        (ProtocolOutcome.MATCH, "10.0.0.1", unknown_execution_context(),
         ExposureOutcome.INDETERMINATE, "non_public_destination_not_issue_absence"),
        (ProtocolOutcome.MATCH, "10.0.0.1", _external_context(),
         ExposureOutcome.INDETERMINATE, "non_public_destination_not_issue_absence"),
        (ProtocolOutcome.INDETERMINATE, "8.8.8.8", _external_context(),
         ExposureOutcome.INDETERMINATE, "protocol_indeterminate"),
    ],
)
def test_composition_truth_table(protocol, address, context, outcome, reason):
    result = compose_public_exposure(protocol, _scope(address), context)
    assert result.outcome == outcome
    assert result.matched is (True if outcome == ExposureOutcome.MATCH else None)
    assert result.reason_code == reason


@pytest.mark.parametrize("protocol", ["NO_MATCH", "timeout", "refused", None])
def test_no_protocol_proof_is_indeterminate(protocol):
    result = compose_public_exposure(protocol, _scope("8.8.8.8"), _external_context())
    assert result.outcome == ExposureOutcome.INDETERMINATE
    assert result.matched is None
    assert result.reason_code == "protocol_indeterminate"


def test_missing_or_unrecognized_policy_context_fails_closed():
    assert compose_public_exposure(ProtocolOutcome.MATCH, None, _external_context()).matched is None
    assert compose_public_exposure(ProtocolOutcome.MATCH, _scope("8.8.8.8"), None).matched is None
    stale_scope = AddressScopeResult("old-policy", AddressScope.PUBLIC_ROUTABLE, "IPv4", "old", EXPECTED_TABLE_DIGEST)
    assert compose_public_exposure(ProtocolOutcome.MATCH, stale_scope, _external_context()).matched is None
    stale_vantage = ExecutionContext(
        VantageClass.EXTERNAL_PUBLIC,
        "edge",
        AttestationSource.DEPLOYMENT_MANIFEST,
        attestation_policy_version="old-policy",
    )
    assert compose_public_exposure(ProtocolOutcome.MATCH, _scope("8.8.8.8"), stale_vantage).matched is None
    result = compose_public_exposure(
        ProtocolOutcome.MATCH,
        _scope("8.8.8.8"),
        _external_context(),
        composition_policy_version="old-policy",
    )
    assert result.matched is None


def test_external_class_without_manifest_source_is_not_trusted():
    spoofed = ExecutionContext(VantageClass.EXTERNAL_PUBLIC, "spoof", AttestationSource.API_INLINE)
    result = compose_public_exposure(ProtocolOutcome.MATCH, _scope("8.8.8.8"), spoofed)
    assert result.matched is None
    assert result.reason_code == "external_vantage_not_trusted"


def _manifest(vantage_id="edge-bkk-01"):
    return {
        "schema_version": DEPLOYMENT_MANIFEST_SCHEMA_VERSION,
        "vantage_id": vantage_id,
        "vantage_class": "EXTERNAL_PUBLIC",
        "deployment_boundary_assertion": DEPLOYMENT_BOUNDARY_ASSERTION,
        "deployment_boundary_version": DEPLOYMENT_BOUNDARY_VERSION,
    }


def _write_manifest(path, document):
    raw = json.dumps(document, sort_keys=True).encode()
    path.write_bytes(raw)
    path.chmod(0o400)
    return raw


def test_valid_protected_worker_manifest_attests_external_vantage(tmp_path):
    path = tmp_path / "vantage.json"
    raw = _write_manifest(path, _manifest())
    context = load_worker_execution_context(path)
    assert context.vantage_class == VantageClass.EXTERNAL_PUBLIC
    assert context.vantage_id == "edge-bkk-01"
    assert context.attestation_source == AttestationSource.DEPLOYMENT_MANIFEST
    assert context.manifest_digest == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "document",
    [
        {},
        {**_manifest(), "vantage_class": "INTERNAL"},
        {**_manifest(), "schema_version": "unknown"},
        {**_manifest(), "deployment_boundary_assertion": "self-asserted"},
        {**_manifest(), "extra": True},
        {**_manifest(), "vantage_id": "bad id"},
    ],
)
def test_malformed_or_unrecognized_manifest_fails_closed(tmp_path, document):
    path = tmp_path / "vantage.json"
    _write_manifest(path, document)
    assert load_worker_execution_context(path) == unknown_execution_context()


def test_missing_writable_or_symlink_manifest_fails_closed(tmp_path):
    assert load_worker_execution_context(tmp_path / "missing.json") == unknown_execution_context()
    path = tmp_path / "vantage.json"
    _write_manifest(path, _manifest())
    path.chmod(0o600)
    assert load_worker_execution_context(path) == unknown_execution_context()
    link = tmp_path / "link.json"
    link.symlink_to(path)
    assert load_worker_execution_context(link) == unknown_execution_context()


def test_runtime_entrypoint_context_defaults_are_explicitly_unknown():
    assert local_cli_execution_context() == ExecutionContext(
        VantageClass.UNKNOWN, None, AttestationSource.LOCAL_CLI
    )
    assert api_inline_execution_context() == ExecutionContext(
        VantageClass.UNKNOWN, None, AttestationSource.API_INLINE
    )
    assert load_worker_execution_context(None) == ExecutionContext(
        VantageClass.UNKNOWN, None, AttestationSource.UNCONFIGURED
    )


def test_manifest_change_cannot_mutate_an_existing_snapshot(tmp_path):
    path = tmp_path / "vantage.json"
    _write_manifest(path, _manifest("edge-one"))
    original = load_worker_execution_context(path)
    snapshot = execution_context_snapshot(original)
    path.chmod(0o600)  # Simulate an administrator replacing deployment configuration.
    _write_manifest(path, _manifest("edge-two"))
    replacement = load_worker_execution_context(path)
    assert snapshot["vantage"]["vantage_id"] == "edge-one"
    assert original.vantage_id == "edge-one"
    assert replacement.vantage_id == "edge-two"
    assert snapshot["vantage"]["manifest_digest"] != replacement.manifest_digest


@pytest.mark.parametrize(
    "key",
    [
        "external", "PUBLIC", "is-public", "Vantage", "vantage_class", "vantage-id",
        "exposure", "exposure_context", "public-exposure", "PUBLIC_EXPOSURE_CONTEXT",
    ],
)
def test_scan_config_cannot_spoof_reserved_trust_keys(key):
    with pytest.raises(ScanExecutorError, match="reserved"):
        validate_scan_config({key: True})


def test_unrelated_scan_config_extensions_remain_permitted():
    assert validate_scan_config({"future_extension": {"enabled": True}})["future_extension"] == {"enabled": True}


def test_manual_evidence_top_level_trust_claims_are_rejected():
    with pytest.raises(ValueError, match="reserved"):
        reject_reserved_trust_keys({"exposure_context": {"matched": True}}, field_name="evidence")


def test_manual_evidence_nested_exposure_context_is_rejected_without_broad_key_filtering():
    with pytest.raises(ValueError, match="reserved"):
        reject_reserved_trust_keys(
            {"tcp": {"evaluations": {"service": {"exposure_context": {"matched": True}}}}},
            field_name="evidence",
            recursive=True,
        )
    reject_reserved_trust_keys(
        {"service": {"public": True, "external": "ordinary-domain-field"}},
        field_name="evidence",
        recursive=True,
    )


def test_protocol_evaluations_receive_independent_context_without_result_changes():
    evidence = {
        "target_identity": {"connect_host": "8.8.8.8"},
        "evaluations": {
            "positive": {"outcome": "MATCH", "matched": True},
            "negative": {"outcome": "NO_MATCH", "matched": False},
        },
    }
    attach_exposure_contexts(evidence, "8.8.8.8", _external_context())
    positive = evidence["evaluations"]["positive"]
    negative = evidence["evaluations"]["negative"]
    assert positive["matched"] is True
    assert positive["exposure_context"]["composition"]["matched"] is True
    assert negative["matched"] is False
    assert negative["exposure_context"]["composition"]["matched"] is None
    assert negative["exposure_context"]["composition"]["reason_code"] == "protocol_indeterminate"
    assert positive["exposure_context"]["address_scope"]["pinned_address_ref"] == "target_identity.connect_host"
    assert "8.8.8.8" not in json.dumps(positive["exposure_context"])


def test_context_schema_has_independent_version_boundaries():
    context = build_public_exposure_context("8.8.8.8", _external_context(), ProtocolOutcome.MATCH)
    assert context["schema_version"] == PUBLIC_EXPOSURE_SCHEMA_VERSION
    assert context["address_scope"]["policy_version"] == ADDRESS_SCOPE_POLICY_VERSION
    assert context["vantage"]["policy_version"] == VANTAGE_POLICY_VERSION
    assert context["composition"]["policy_version"] == EXPOSURE_COMPOSITION_POLICY_VERSION


def test_scanner_plumbing_uses_runtime_context_not_scan_config(monkeypatch):
    target = scan_executors.InventoryScanTarget(
        ScanTargetTypeEnum.HOST,
        "inventory-id",
        "example.test",
        "8.8.8.8",
        "example.test",
        False,
    )

    def collect(_target, _config):
        return scan_executors.ExecutorObservation(
            EvidenceSourceEnum.SCANNER_TCP,
            {
                "target_identity": {"connect_host": "8.8.8.8"},
                "evaluations": {"service": {"outcome": "MATCH", "matched": True}},
            },
        )

    monkeypatch.setattr(scan_executors.EXECUTOR_BY_NAME["tcp"], "collect", collect)
    observation = scan_executors.collect_scanner_observations(
        target,
        {"executors": ["tcp"], "per_target_interval_seconds": 0},
        _external_context(),
    )[0]
    exposure = observation.evidence["evaluations"]["service"]["exposure_context"]
    assert exposure["composition"]["matched"] is True
    assert exposure["vantage"]["vantage_id"] == "edge-bkk-01"
