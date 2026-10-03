"""Reviewed Wave 4A SSH-negotiation rules and exact-version activation."""
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.catalog_models import (
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
from app.services.ssh_negotiation import (
    AEAD_CIPHER_MAC_MODES,
    AEAD_CIPHERS,
    KNOWN_NON_AEAD_CIPHERS,
    PROHIBITED_CIPHERS,
    PROHIBITED_MACS,
    SSH_AEAD_POLICY_VERSION,
    SSH_COLLECTOR_VERSION,
    SSH_CRYPTO_POLICY_VERSION,
)


METHOD_VERSION = "ssc-wave4a-ssh-observation.v1"
REFERENCE = (
    "https://api.securityscorecard.io/metadata/issue-types/{issue_key}; "
    "https://www.rfc-editor.org/rfc/rfc4253.html; "
    "https://www.iana.org/assignments/ssh-parameters"
)


@dataclass(frozen=True)
class Wave4ARuleSpec:
    issue_key: str
    title: str
    match_condition: str
    no_match_boundary: str
    indeterminate_boundary: str
    remediation: str
    primitive: str = "SSH_NEGOTIATION"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave4a.{self.issue_key}"

    @property
    def reference(self) -> str:
        return REFERENCE.format(issue_key=self.issue_key)

    @property
    def evidence_requirement(self) -> str:
        return (
            "For each explicitly declared SSH TCP port: bounded validated identification exchange and, for SSH2, "
            "a complete SSH_MSG_KEXINIT with both directional cipher and MAC lists; retain hashes and normalized "
            "algorithms only, never unrestricted banners or packets."
        )

    @property
    def logic(self) -> str:
        return f"{self.match_condition} {self.no_match_boundary} {self.indeterminate_boundary}"

    @property
    def expression(self) -> dict[str, Any]:
        return {
            "operator": "equals",
            "path": f"tcp.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        return {
            "schema_version": METHOD_VERSION,
            "collector_version": SSH_COLLECTOR_VERSION,
            "policy_version": SSH_CRYPTO_POLICY_VERSION,
            "primitive": self.primitive,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "persisted_endpoint_fields": [
                "port", "hostname", "resolved_address", "identification_protocol_version",
                "identification_sha256", "kexinit_status", "kex_algorithms",
                "server_host_key_algorithms", "encryption_algorithms_client_to_server",
                "encryption_algorithms_server_to_client", "mac_algorithms_client_to_server",
                "mac_algorithms_server_to_client", "collector_version", "crypto_policy_version",
                "aead_policy_version", "evaluations.ssh_weak_mac.direction_evaluations",
                "limits", "stop_reason", "error_class", "error_reason",
            ],
            "prohibited_ciphers": sorted(PROHIBITED_CIPHERS),
            "prohibited_macs": sorted(PROHIBITED_MACS),
            "aead_policy_version": SSH_AEAD_POLICY_VERSION,
            "aead_ciphers": sorted(AEAD_CIPHERS),
            "aead_cipher_mac_modes": dict(sorted(AEAD_CIPHER_MAC_MODES.items())),
            "known_non_aead_ciphers": sorted(KNOWN_NON_AEAD_CIPHERS),
            "policy_provenance": (
                "Immutable SSC_API issue details: ssh_weak_cipher prohibits Arcfour/CBC; "
                "ssh_weak_mac prohibits MD5; ssh_weak_protocol prohibits versions below 2. "
                "Exact spellings and AEAD/standalone-MAC applicability use RFC 4253, RFC 4345, "
                "RFC 5647 paired encryption/MAC negotiation, IANA SSH parameters, and documented "
                "MAC-ignored OpenSSH and ChaCha20-Poly1305 extensions."
            ),
            "match_condition": self.match_condition,
            "no_match_boundary": self.no_match_boundary,
            "indeterminate_boundary": self.indeterminate_boundary,
            "aggregation_boundary": (
                "MATCH wins; NO_MATCH requires every response-bearing applicable SSH endpoint to be conclusive. "
                "Unavailable and recognized non-SSH endpoints are outside that boundary but cannot alone create "
                "NO_MATCH; an ambiguous responsive SSH endpoint makes the result INDETERMINATE unless another matches."
            ),
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }


WAVE4A_RULES = (
    Wave4ARuleSpec(
        "ssh_weak_protocol",
        "SSH Software Supports Vulnerable Protocol",
        "MATCH for valid deterministic SSH-1.x identification below 2, excluding ambiguous SSH-1.99.",
        "NO_MATCH only for valid SSH-2.0 identification plus a complete valid SSH2 KEXINIT.",
        "SSH-1.99 without safe SSH1 confirmation, malformed/foreign/incomplete exchanges, transport failure, or unsupported protocol is INDETERMINATE.",
        "Disable SSH protocol version 1 compatibility and permit SSH protocol version 2 only.",
    ),
    Wave4ARuleSpec(
        "ssh_weak_cipher",
        "SSH Supports Weak Cipher",
        "MATCH when either complete KEXINIT encryption direction advertises an exact policy-prohibited Arcfour or CBC cipher.",
        "NO_MATCH only when both complete directional lists contain no exact prohibited cipher.",
        "Missing/malformed/truncated KEXINIT, a missing direction, unknown policy, transport failure, non-SSH service, or non-SSH2 state is INDETERMINATE.",
        "Disable the exact policy-prohibited Arcfour and CBC SSH ciphers and retain approved modern encryption algorithms.",
    ),
    Wave4ARuleSpec(
        "ssh_weak_mac",
        "SSH Supports Weak MAC",
        "MATCH when an exact prohibited MD5 MAC is advertised in a direction containing at least one known non-AEAD cipher, making the standalone MAC selectable.",
        "NO_MATCH only when both directions are conclusive: each has only MAC-ignored AEAD ciphers, has complete consistent RFC 5647 paired AEAD evidence, or has a complete clean MAC list applicable to a known non-AEAD cipher.",
        "Missing/malformed evidence, an empty applicable MAC list, incomplete RFC 5647 pairing, unknown cipher applicability or policy, transport failure, or a non-SSH/non-SSH2 state is INDETERMINATE.",
        "Disable the exact policy-prohibited MD5 SSH MAC algorithms and retain approved modern integrity protection.",
    ),
)

WAVE4A_BY_KEY = {spec.issue_key: spec for spec in WAVE4A_RULES}


class Wave4AActivationError(ValueError):
    pass


def activate_wave4a_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 4A only for attested exact SSC_API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE4A_RULES:
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)).scalar_one_or_none()
        if issue is None or not issue.is_active or issue.current_version_id is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            continue
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id)
        if issue_version is None or issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions:
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"
            continue
        rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=spec.rule_key, catalog_issue_type_id=issue.id, is_active=True)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave4AActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            counts["rules_reused"] += 1
            rule.is_active = True
        definition = {
            "catalog_issue_type_version_id": issue_version.id,
            "name": spec.title,
            "description": f"{spec.evidence_requirement} {spec.logic}",
            "target_type": RuleTargetTypeEnum.HOST,
            "rule_expression": spec.expression,
            "evidence_schema": spec.evidence_schema,
            "remediation": spec.remediation,
            "source_type": RuleSourceTypeEnum.SSC_REFERENCE,
            "source_reference": spec.reference,
        }
        versions = db.execute(select(RuleEngineRuleVersion).where(RuleEngineRuleVersion.rule_id == rule.id)).scalars().all()
        version = next((candidate for candidate in versions if _same_definition(candidate, definition)), None)
        if version is None:
            latest = db.execute(select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule.id)).scalar()
            version = RuleEngineRuleVersion(rule_id=rule.id, version_number=(latest or 0) + 1, **definition)
            db.add(version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = version.id
        activated.append(spec.issue_key)
    if commit:
        db.commit()
    return {**counts, "activated": activated, "unavailable": unavailable}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def active_wave4a_mappings(db: Session) -> list[dict[str, Any]]:
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    rows = db.execute(
        select(RuleEngineRule, RuleEngineRuleVersion, CatalogIssueType, CatalogIssueTypeVersion)
        .join(RuleEngineRuleVersion, RuleEngineRule.current_version_id == RuleEngineRuleVersion.id)
        .join(CatalogIssueType, RuleEngineRule.catalog_issue_type_id == CatalogIssueType.id)
        .join(CatalogIssueTypeVersion, RuleEngineRuleVersion.catalog_issue_type_version_id == CatalogIssueTypeVersion.id)
        .where(RuleEngineRule.is_active.is_(True))
    ).all()
    mappings = []
    for rule, rule_version, issue, issue_version in rows:
        spec = WAVE4A_BY_KEY.get(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key
            or issue_version.issue_type_id != issue.id
            or issue_version.source_type != SourceTypeEnum.SSC_API
            or issue_version.id not in real_versions
            or rule_version.rule_expression != spec.expression
            or rule_version.evidence_schema != spec.evidence_schema
        ):
            continue
        mappings.append({
            "issue_key": issue.stable_key,
            "issue_version_id": str(issue_version.id),
            "issue_version_number": issue_version.version_number,
            "ssc_severity": issue_version.ssc_severity,
            "rule_key": rule.stable_key,
            "rule_version_id": str(rule_version.id),
            "rule_version_number": rule_version.version_number,
            "primitive": spec.primitive,
        })
    return sorted(mappings, key=lambda item: item["issue_key"])
