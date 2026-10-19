"""Versioned, fail-closed context for qualifying public service observations.

This module deliberately does not decide whether an SSC issue applies.  It
classifies the pinned destination, records trusted runtime provenance, and
composes those facts with one protocol evaluation.  Consumer selection is a
separate, reviewed concern.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


PUBLIC_EXPOSURE_SCHEMA_VERSION = "ssc-public-exposure-context.v1"
ADDRESS_SCOPE_POLICY_VERSION = "ssc-public-address-scope.v1"
VANTAGE_POLICY_VERSION = "ssc-scan-vantage-attestation.v1"
EXPOSURE_COMPOSITION_POLICY_VERSION = "ssc-public-exposure-composition.v1"

DEPLOYMENT_MANIFEST_SCHEMA_VERSION = "ssc-scanner-deployment-manifest.v1"
DEPLOYMENT_BOUNDARY_ASSERTION = "approved-external-public-scanner"
DEPLOYMENT_BOUNDARY_VERSION = "ssc-external-deployment-boundary.v1"

# The IANA IPv4 and IPv6 Special-Purpose Address Registries were both last
# updated on this date.  The table below is a reviewed, frozen policy derived
# from that registry snapshot plus the IP multicast blocks.  Runtime registry
# access and ipaddress.is_global are intentionally not part of the contract.
ADDRESS_POLICY_REGISTRY_SNAPSHOT = "iana-special-purpose-address-registries-2025-10-09"


class AddressScope(str, Enum):
    PUBLIC_ROUTABLE = "PUBLIC_ROUTABLE"
    NON_PUBLIC = "NON_PUBLIC"
    INDETERMINATE = "INDETERMINATE"


class VantageClass(str, Enum):
    EXTERNAL_PUBLIC = "EXTERNAL_PUBLIC"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class AttestationSource(str, Enum):
    DEPLOYMENT_MANIFEST = "DEPLOYMENT_MANIFEST"
    LOCAL_CLI = "LOCAL_CLI"
    API_INLINE = "API_INLINE"
    UNCONFIGURED = "UNCONFIGURED"


class ExposureOutcome(str, Enum):
    MATCH = "MATCH"
    INDETERMINATE = "INDETERMINATE"


class ProtocolOutcome(str, Enum):
    MATCH = "MATCH"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class _AddressPolicyEntry:
    prefix: str
    outcome: AddressScope
    reason_code: str


# Most-specific-prefix selection is mandatory.  PUBLIC_ROUTABLE entries are
# explicit exceptions inside broader special-purpose blocks.  ORCHID, Teredo,
# 6to4, SRv6 SIDs, and other special transition/identifier space remain
# NON_PUBLIC for this exposure-evidence contract even where packets may be
# forwardable in a specialized context.
_ADDRESS_POLICY_TABLE: tuple[_AddressPolicyEntry, ...] = (
    _AddressPolicyEntry("0.0.0.0/0", AddressScope.PUBLIC_ROUTABLE, "ordinary_ipv4_unicast"),
    _AddressPolicyEntry("0.0.0.0/8", AddressScope.NON_PUBLIC, "this_network"),
    _AddressPolicyEntry("0.0.0.0/32", AddressScope.NON_PUBLIC, "unspecified"),
    _AddressPolicyEntry("10.0.0.0/8", AddressScope.NON_PUBLIC, "private_use"),
    _AddressPolicyEntry("100.64.0.0/10", AddressScope.NON_PUBLIC, "shared_cgnat"),
    _AddressPolicyEntry("127.0.0.0/8", AddressScope.NON_PUBLIC, "loopback"),
    _AddressPolicyEntry("169.254.0.0/16", AddressScope.NON_PUBLIC, "link_local"),
    _AddressPolicyEntry("172.16.0.0/12", AddressScope.NON_PUBLIC, "private_use"),
    _AddressPolicyEntry("192.0.0.0/24", AddressScope.NON_PUBLIC, "ietf_protocol_assignments"),
    _AddressPolicyEntry("192.0.0.0/29", AddressScope.NON_PUBLIC, "service_continuity"),
    _AddressPolicyEntry("192.0.0.8/32", AddressScope.NON_PUBLIC, "dummy_address"),
    _AddressPolicyEntry("192.0.0.9/32", AddressScope.PUBLIC_ROUTABLE, "pcp_anycast_global_exception"),
    _AddressPolicyEntry("192.0.0.10/32", AddressScope.PUBLIC_ROUTABLE, "turn_anycast_global_exception"),
    _AddressPolicyEntry("192.0.0.170/32", AddressScope.NON_PUBLIC, "nat64_discovery"),
    _AddressPolicyEntry("192.0.0.171/32", AddressScope.NON_PUBLIC, "nat64_discovery"),
    _AddressPolicyEntry("192.0.2.0/24", AddressScope.NON_PUBLIC, "documentation_test_net_1"),
    _AddressPolicyEntry("192.31.196.0/24", AddressScope.PUBLIC_ROUTABLE, "as112_global_exception"),
    _AddressPolicyEntry("192.52.193.0/24", AddressScope.PUBLIC_ROUTABLE, "amt_global_exception"),
    _AddressPolicyEntry("192.88.99.0/24", AddressScope.NON_PUBLIC, "deprecated_6to4_relay"),
    _AddressPolicyEntry("192.88.99.2/32", AddressScope.NON_PUBLIC, "six_a_four_relay"),
    _AddressPolicyEntry("192.168.0.0/16", AddressScope.NON_PUBLIC, "private_use"),
    _AddressPolicyEntry("192.175.48.0/24", AddressScope.PUBLIC_ROUTABLE, "direct_as112_global_exception"),
    _AddressPolicyEntry("198.18.0.0/15", AddressScope.NON_PUBLIC, "benchmarking"),
    _AddressPolicyEntry("198.51.100.0/24", AddressScope.NON_PUBLIC, "documentation_test_net_2"),
    _AddressPolicyEntry("203.0.113.0/24", AddressScope.NON_PUBLIC, "documentation_test_net_3"),
    _AddressPolicyEntry("224.0.0.0/4", AddressScope.NON_PUBLIC, "multicast"),
    _AddressPolicyEntry("240.0.0.0/4", AddressScope.NON_PUBLIC, "reserved"),
    _AddressPolicyEntry("255.255.255.255/32", AddressScope.NON_PUBLIC, "limited_broadcast"),
    _AddressPolicyEntry("::/0", AddressScope.NON_PUBLIC, "not_reviewed_global_ipv6_unicast"),
    _AddressPolicyEntry("::/128", AddressScope.NON_PUBLIC, "unspecified"),
    _AddressPolicyEntry("::1/128", AddressScope.NON_PUBLIC, "loopback"),
    _AddressPolicyEntry("::ffff:0:0/96", AddressScope.NON_PUBLIC, "ipv4_mapped_container"),
    _AddressPolicyEntry("64:ff9b::/96", AddressScope.PUBLIC_ROUTABLE, "ipv4_ipv6_translation_global_exception"),
    _AddressPolicyEntry("64:ff9b:1::/48", AddressScope.NON_PUBLIC, "local_ipv4_ipv6_translation"),
    _AddressPolicyEntry("100::/64", AddressScope.NON_PUBLIC, "discard_only"),
    _AddressPolicyEntry("100:0:0:1::/64", AddressScope.NON_PUBLIC, "dummy_address"),
    _AddressPolicyEntry("2000::/3", AddressScope.PUBLIC_ROUTABLE, "ordinary_ipv6_global_unicast"),
    _AddressPolicyEntry("2001::/23", AddressScope.NON_PUBLIC, "ietf_protocol_assignments"),
    _AddressPolicyEntry("2001::/32", AddressScope.NON_PUBLIC, "teredo_transition"),
    _AddressPolicyEntry("2001:1::1/128", AddressScope.PUBLIC_ROUTABLE, "pcp_anycast_global_exception"),
    _AddressPolicyEntry("2001:1::2/128", AddressScope.PUBLIC_ROUTABLE, "turn_anycast_global_exception"),
    _AddressPolicyEntry("2001:1::3/128", AddressScope.PUBLIC_ROUTABLE, "dns_sd_anycast_global_exception"),
    _AddressPolicyEntry("2001:2::/48", AddressScope.NON_PUBLIC, "benchmarking"),
    _AddressPolicyEntry("2001:3::/32", AddressScope.PUBLIC_ROUTABLE, "amt_global_exception"),
    _AddressPolicyEntry("2001:4:112::/48", AddressScope.PUBLIC_ROUTABLE, "as112_global_exception"),
    _AddressPolicyEntry("2001:10::/28", AddressScope.NON_PUBLIC, "deprecated_orchid"),
    _AddressPolicyEntry("2001:20::/28", AddressScope.NON_PUBLIC, "orchid_v2"),
    _AddressPolicyEntry("2001:30::/28", AddressScope.PUBLIC_ROUTABLE, "det_global_exception"),
    _AddressPolicyEntry("2001:db8::/32", AddressScope.NON_PUBLIC, "documentation"),
    _AddressPolicyEntry("2002::/16", AddressScope.NON_PUBLIC, "six_to_four_transition"),
    _AddressPolicyEntry("2620:4f:8000::/48", AddressScope.PUBLIC_ROUTABLE, "direct_as112_global_exception"),
    _AddressPolicyEntry("3fff::/20", AddressScope.NON_PUBLIC, "documentation"),
    _AddressPolicyEntry("5f00::/16", AddressScope.NON_PUBLIC, "srv6_sid"),
    _AddressPolicyEntry("fc00::/7", AddressScope.NON_PUBLIC, "unique_local"),
    _AddressPolicyEntry("fe80::/10", AddressScope.NON_PUBLIC, "link_local"),
    _AddressPolicyEntry("ff00::/8", AddressScope.NON_PUBLIC, "multicast"),
)


def _policy_table_digest() -> str:
    serialized = json.dumps(
        [
            {"prefix": entry.prefix, "outcome": entry.outcome.value, "reason_code": entry.reason_code}
            for entry in _ADDRESS_POLICY_TABLE
        ],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


ADDRESS_SCOPE_POLICY_TABLE_DIGEST = _policy_table_digest()
_COMPILED_ADDRESS_POLICY = tuple(
    sorted(
        ((ipaddress.ip_network(entry.prefix), entry) for entry in _ADDRESS_POLICY_TABLE),
        key=lambda item: item[0].prefixlen,
        reverse=True,
    )
)


@dataclass(frozen=True)
class AddressScopeResult:
    policy_version: str
    outcome: AddressScope
    address_family: str
    reason_code: str
    policy_table_digest: str

    def as_evidence(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "outcome": self.outcome.value,
            "address_family": self.address_family,
            "pinned_address_ref": "target_identity.connect_host",
            "reason_code": self.reason_code,
            "policy_table_digest": self.policy_table_digest,
        }


@dataclass(frozen=True)
class ExecutionContext:
    vantage_class: VantageClass
    vantage_id: str | None
    attestation_source: AttestationSource
    attestation_policy_version: str = VANTAGE_POLICY_VERSION
    manifest_digest: str | None = None

    def as_evidence(self) -> dict[str, Any]:
        return {
            "policy_version": self.attestation_policy_version,
            "vantage_class": self.vantage_class.value,
            "vantage_id": self.vantage_id,
            "attestation_source": self.attestation_source.value,
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True)
class ExposureComposition:
    policy_version: str
    protocol_outcome: ProtocolOutcome
    outcome: ExposureOutcome
    matched: bool | None
    reason_code: str

    def as_evidence(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "protocol_outcome": self.protocol_outcome.value,
            "outcome": self.outcome.value,
            "matched": self.matched,
            "reason_code": self.reason_code,
        }


def unknown_execution_context(source: AttestationSource = AttestationSource.UNCONFIGURED) -> ExecutionContext:
    return ExecutionContext(VantageClass.UNKNOWN, None, source)


def local_cli_execution_context() -> ExecutionContext:
    return unknown_execution_context(AttestationSource.LOCAL_CLI)


def api_inline_execution_context() -> ExecutionContext:
    return unknown_execution_context(AttestationSource.API_INLINE)


def classify_pinned_address(value: str) -> AddressScopeResult:
    """Classify one numeric executor destination using the frozen table."""
    if not isinstance(value, str) or not value or "%" in value:
        return _indeterminate_address("invalid_or_scoped_address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return _indeterminate_address("invalid_or_non_numeric_address")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    family = "IPv4" if address.version == 4 else "IPv6"
    for network, entry in _COMPILED_ADDRESS_POLICY:
        if network.version == address.version and address in network:
            return AddressScopeResult(
                ADDRESS_SCOPE_POLICY_VERSION,
                entry.outcome,
                family,
                entry.reason_code,
                ADDRESS_SCOPE_POLICY_TABLE_DIGEST,
            )
    return _indeterminate_address("address_not_covered_by_policy", family)


def _indeterminate_address(reason: str, family: str = "UNKNOWN") -> AddressScopeResult:
    return AddressScopeResult(
        ADDRESS_SCOPE_POLICY_VERSION,
        AddressScope.INDETERMINATE,
        family,
        reason,
        ADDRESS_SCOPE_POLICY_TABLE_DIGEST,
    )


def compose_public_exposure(
    protocol_outcome: ProtocolOutcome | str,
    address_scope: AddressScopeResult | None,
    execution_context: ExecutionContext | None,
    *,
    composition_policy_version: str = EXPOSURE_COMPOSITION_POLICY_VERSION,
) -> ExposureComposition:
    """Compose independent facts without ever emitting a clean NO_MATCH."""
    protocol = _coerce_protocol_outcome(protocol_outcome)
    if (
        composition_policy_version != EXPOSURE_COMPOSITION_POLICY_VERSION
        or address_scope is None
        or address_scope.policy_version != ADDRESS_SCOPE_POLICY_VERSION
        or address_scope.policy_table_digest != ADDRESS_SCOPE_POLICY_TABLE_DIGEST
        or execution_context is None
        or execution_context.attestation_policy_version != VANTAGE_POLICY_VERSION
    ):
        return _indeterminate_composition(protocol, "unrecognized_or_missing_policy_context")
    if protocol != ProtocolOutcome.MATCH:
        return _indeterminate_composition(ProtocolOutcome.INDETERMINATE, "protocol_indeterminate")
    if address_scope.outcome == AddressScope.NON_PUBLIC:
        return _indeterminate_composition(protocol, "non_public_destination_not_issue_absence")
    if address_scope.outcome != AddressScope.PUBLIC_ROUTABLE:
        return _indeterminate_composition(protocol, "address_scope_indeterminate")
    if execution_context.vantage_class == VantageClass.INTERNAL:
        return _indeterminate_composition(protocol, "internal_vantage_not_public_proof")
    if execution_context.vantage_class != VantageClass.EXTERNAL_PUBLIC:
        return _indeterminate_composition(protocol, "vantage_unknown")
    if execution_context.attestation_source != AttestationSource.DEPLOYMENT_MANIFEST:
        return _indeterminate_composition(protocol, "external_vantage_not_trusted")
    return ExposureComposition(
        EXPOSURE_COMPOSITION_POLICY_VERSION,
        protocol,
        ExposureOutcome.MATCH,
        True,
        "public_service_observed_from_external_vantage",
    )


def _coerce_protocol_outcome(value: ProtocolOutcome | str) -> ProtocolOutcome:
    try:
        return ProtocolOutcome(value)
    except (TypeError, ValueError):
        return ProtocolOutcome.INDETERMINATE


def _indeterminate_composition(protocol: ProtocolOutcome, reason: str) -> ExposureComposition:
    return ExposureComposition(
        EXPOSURE_COMPOSITION_POLICY_VERSION,
        protocol,
        ExposureOutcome.INDETERMINATE,
        None,
        reason,
    )


def build_public_exposure_context(
    pinned_address: str,
    execution_context: ExecutionContext,
    protocol_outcome: ProtocolOutcome | str,
) -> dict[str, Any]:
    address_scope = classify_pinned_address(pinned_address)
    composition = compose_public_exposure(protocol_outcome, address_scope, execution_context)
    return {
        "schema_version": PUBLIC_EXPOSURE_SCHEMA_VERSION,
        "address_scope": address_scope.as_evidence(),
        "vantage": execution_context.as_evidence(),
        "composition": composition.as_evidence(),
    }


def execution_context_snapshot(execution_context: ExecutionContext) -> dict[str, Any]:
    return {
        "schema_version": PUBLIC_EXPOSURE_SCHEMA_VERSION,
        "vantage": execution_context.as_evidence(),
    }


_VANTAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MANIFEST_KEYS = {
    "schema_version",
    "vantage_id",
    "vantage_class",
    "deployment_boundary_assertion",
    "deployment_boundary_version",
}


def load_worker_execution_context(manifest_path: str | os.PathLike[str] | None) -> ExecutionContext:
    """Load a protected worker manifest once; any defect fails closed."""
    if not manifest_path:
        return unknown_execution_context()
    try:
        path = Path(manifest_path)
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            return unknown_execution_context()
        owner_is_admin = path_stat.st_uid == 0
        owner_is_read_only_runtime = (
            path_stat.st_uid == os.geteuid() and not path_stat.st_mode & stat.S_IWUSR
        )
        if (
            not (owner_is_admin or owner_is_read_only_runtime)
            or path_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return unknown_execution_context()
        raw = path.read_bytes()
        if len(raw) > 4096:
            return unknown_execution_context()
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEYS:
            return unknown_execution_context()
        vantage_id = manifest.get("vantage_id")
        if (
            manifest.get("schema_version") != DEPLOYMENT_MANIFEST_SCHEMA_VERSION
            or manifest.get("vantage_class") != VantageClass.EXTERNAL_PUBLIC.value
            or manifest.get("deployment_boundary_assertion") != DEPLOYMENT_BOUNDARY_ASSERTION
            or manifest.get("deployment_boundary_version") != DEPLOYMENT_BOUNDARY_VERSION
            or not isinstance(vantage_id, str)
            or _VANTAGE_ID_RE.fullmatch(vantage_id) is None
        ):
            return unknown_execution_context()
        digest = hashlib.sha256(raw).hexdigest()
        return ExecutionContext(
            VantageClass.EXTERNAL_PUBLIC,
            vantage_id,
            AttestationSource.DEPLOYMENT_MANIFEST,
            manifest_digest=digest,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return unknown_execution_context()


_RESERVED_TRUST_KEYS = frozenset(
    {
        "external",
        "public",
        "is_public",
        "vantage",
        "vantage_class",
        "vantage_id",
        "exposure",
        "exposure_context",
        "public_exposure",
        "public_exposure_context",
    }
)
_NESTED_RESERVED_TRUST_KEYS = frozenset(
    {
        "vantage",
        "vantage_class",
        "vantage_id",
        "exposure_context",
        "public_exposure",
        "public_exposure_context",
    }
)


def reject_reserved_trust_keys(
    value: Mapping[str, Any] | None,
    *,
    field_name: str,
    recursive: bool = False,
) -> None:
    """Reject bounded trust claims in caller-controlled JSON."""
    if value is None:
        return
    for key, child in value.items():
        normalized = str(key).strip().casefold().replace("-", "_")
        if normalized in _RESERVED_TRUST_KEYS:
            raise ValueError(f"{field_name}.{key} is reserved and cannot establish scan vantage or exposure")
        if recursive:
            _reject_nested_trust_keys(child, f"{field_name}.{key}")


def _reject_nested_trust_keys(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().casefold().replace("-", "_")
            if normalized in _NESTED_RESERVED_TRUST_KEYS:
                raise ValueError(f"{path}.{key} is reserved and cannot establish scan vantage or exposure")
            _reject_nested_trust_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_nested_trust_keys(child, f"{path}[{index}]")


def attach_exposure_contexts(
    evidence: dict[str, Any],
    pinned_address: str,
    execution_context: ExecutionContext,
) -> dict[str, Any]:
    """Attach context to each protocol evaluation without changing its result."""
    evaluations = evidence.get("evaluations")
    if not isinstance(evaluations, dict):
        return evidence
    for evaluation in evaluations.values():
        if not isinstance(evaluation, dict):
            continue
        protocol_outcome = (
            ProtocolOutcome.MATCH
            if evaluation.get("outcome") == "MATCH" and evaluation.get("matched") is True
            else ProtocolOutcome.INDETERMINATE
        )
        evaluation["exposure_context"] = build_public_exposure_context(
            pinned_address,
            execution_context,
            protocol_outcome,
        )
    return evidence


def attach_exposure_context_for_issue(
    evidence: dict[str, Any],
    pinned_address: str,
    execution_context: ExecutionContext,
    issue_key: str,
) -> dict[str, Any]:
    """Attach trusted exposure context to one explicitly reviewed evaluation."""
    evaluations = evidence.get("evaluations")
    if not isinstance(evaluations, dict):
        return evidence
    evaluation = evaluations.get(issue_key)
    if not isinstance(evaluation, dict):
        return evidence
    protocol_outcome = (
        ProtocolOutcome.MATCH
        if evaluation.get("outcome") == "MATCH" and evaluation.get("matched") is True
        else ProtocolOutcome.INDETERMINATE
    )
    evaluation["exposure_context"] = build_public_exposure_context(
        pinned_address,
        execution_context,
        protocol_outcome,
    )
    return evidence
