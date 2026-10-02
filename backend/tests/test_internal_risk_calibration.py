from collections import Counter
from datetime import datetime, timezone

import pytest

from app.schemas.results import ResultFinding
from app.services.internal_risk_calibration import (
    SSC_SUPPORTED_INTERNAL_RISK_V1,
    resolve_ssc_internal_risk,
)
from app.services.scoring_engine import ScoringDefinition, score_result


ORIGINAL_27_DECISIONS = {
    "csp_no_policy_v2": ("LOW", True),
    "csp_too_broad_v2": ("LOW", True),
    "csp_unsafe_policy_v2": ("LOW", True),
    "domain_missing_https_v2": ("MEDIUM", True),
    "hsts_incorrect_v2": ("LOW", True),
    "insecure_https_redirect_pattern_v2": ("MEDIUM", True),
    "insecure_server_certificate_key_size": ("MEDIUM", True),
    "redirect_chain_contains_http_v2": ("MEDIUM", True),
    "x_content_type_options_incorrect_v2": ("LOW", True),
    "x_frame_options_incorrect_v2": ("LOW", True),
    "dmarc_contains_none": ("LOW", True),
    "dmarc_record_missing": ("LOW", True),
    "spf_record_missing": ("LOW", True),
    "spf_record_softfail": ("LOW", True),
    "spf_record_wildcard": ("UNKNOWN", False),
    "subdomain_dmarc_contains_none": ("LOW", True),
    "service_redis": ("LOW", True),
    "service_rsync": ("UNKNOWN", False),
    "service_smb": ("LOW", True),
    "service_socks_proxy": ("UNKNOWN", False),
    "service_telnet": ("LOW", True),
    "service_vnc": ("LOW", True),
    "tls_weak_protocol": ("MEDIUM", True),
    "tlscert_expired": ("LOW", True),
    "tlscert_no_revocation": ("UNKNOWN", False),
    "tlscert_self_signed": ("LOW", True),
    "tlscert_weak_signature": ("MEDIUM", True),
}

WAVE3B_DECISIONS = {
    "unsafe_sri_v2": ("LOW", True),
    "insecure_ftp": ("LOW", True),
    "contact_information_detected": ("UNKNOWN", False),
    "local_file_path_exposed_via_url_scheme": ("LOW", True),
    "server_error": ("UNKNOWN", False),
    "links_to_insecure_website": ("LOW", True),
    "service_soap": ("UNKNOWN", False),
}


def _finding(issue_key: str, ssc_severity: str) -> ResultFinding:
    decision = resolve_ssc_internal_risk(issue_key)
    return ResultFinding(
        id="finding-" + issue_key,
        target_id="target",
        rule_id="rule-" + issue_key,
        rule_version_id="rule-version-" + issue_key,
        catalog_issue_type_version_id="issue-version-" + issue_key,
        ssc_issue_key=issue_key,
        ssc_severity=ssc_severity,
        title="Observed issue",
        factor_code="application_security",
        factor_name="Application Security",
        breach_risk=decision.breach_risk,
        affects_score=decision.affects_score,
        status="OPEN",
        evidence_source="SCANNER_HTTP",
        evidence_summary={},
        remediation="Review",
    )


def _score(*findings: ResultFinding):
    assessments = [
        {
            "factor_code": finding.factor_code,
            "factor_name": finding.factor_name,
            "status": "evaluated",
        }
        for finding in findings
    ]
    return score_result(
        scan_run_id="run",
        generated_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        targets=[],
        findings=list(findings),
        evidence=[],
        assessments=assessments,
        model=ScoringDefinition(),
    )


def test_calibration_has_all_approved_decisions_and_counts():
    assert len(SSC_SUPPORTED_INTERNAL_RISK_V1) == 34
    counts = Counter(item.breach_risk for item in SSC_SUPPORTED_INTERNAL_RISK_V1.values())
    assert {risk: counts[risk] for risk in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")} == {
        "HIGH": 0, "MEDIUM": 6, "LOW": 21, "UNKNOWN": 7,
    }
    assert Counter(item.affects_score for item in SSC_SUPPORTED_INTERNAL_RISK_V1.values()) == {
        True: 27,
        False: 7,
    }


def test_original_27_approved_mappings_remain_unchanged():
    actual = {
        key: (decision.breach_risk, decision.affects_score)
        for key, decision in SSC_SUPPORTED_INTERNAL_RISK_V1.items()
        if key in ORIGINAL_27_DECISIONS
    }
    assert actual == ORIGINAL_27_DECISIONS


def test_wave3b_approved_counts():
    decisions = [SSC_SUPPORTED_INTERNAL_RISK_V1[key] for key in WAVE3B_DECISIONS]
    counts = Counter(item.breach_risk for item in decisions)
    assert {risk: counts[risk] for risk in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")} == {
        "HIGH": 0, "MEDIUM": 0, "LOW": 4, "UNKNOWN": 3,
    }
    assert Counter(item.affects_score for item in decisions) == {True: 4, False: 3}


@pytest.mark.parametrize(
    ("issue_key", "ssc_severity", "expected_risk", "expected_affects_score", "expected_impact"),
    [
        ("unsafe_sri_v2", "high", "LOW", True, 2),
        ("insecure_ftp", "medium", "LOW", True, 2),
        ("contact_information_detected", "low", "UNKNOWN", False, 0),
        ("local_file_path_exposed_via_url_scheme", "low", "LOW", True, 2),
        ("server_error", "low", "UNKNOWN", False, 0),
        ("links_to_insecure_website", "low", "LOW", True, 2),
        ("service_soap", "medium", "UNKNOWN", False, 0),
    ],
)
def test_wave3b_approved_mappings_and_penalties(
    issue_key, ssc_severity, expected_risk, expected_affects_score, expected_impact,
):
    decision = resolve_ssc_internal_risk(issue_key)
    assert (decision.breach_risk, decision.affects_score) == WAVE3B_DECISIONS[issue_key]
    assert decision.breach_risk == expected_risk
    assert decision.affects_score is expected_affects_score
    finding = _finding(issue_key, ssc_severity)
    result = _score(finding)
    assert finding.ssc_severity == ssc_severity
    assert result.findings[0].score_impact == expected_impact


def test_csp_unsafe_policy_match_is_low_and_deducts_two_factor_points():
    finding = _finding("csp_unsafe_policy_v2", "low")
    result = _score(finding)
    assert finding.breach_risk == "LOW"
    assert finding.affects_score is True
    assert result.findings[0].score_impact == 2
    assert result.factor_scores[0].score == 98


@pytest.mark.parametrize(
    ("issue_key", "ssc_severity", "expected_risk", "expected_impact"),
    [
        ("tls_weak_protocol", "high", "MEDIUM", 7),
        ("service_redis", "medium", "LOW", 2),
    ],
)
def test_calibrated_match_uses_internal_risk_for_penalty(
    issue_key, ssc_severity, expected_risk, expected_impact,
):
    finding = _finding(issue_key, ssc_severity)
    result = _score(finding)
    assert finding.breach_risk == expected_risk
    assert result.findings[0].score_impact == expected_impact


@pytest.mark.parametrize(
    "issue_key",
    ["spf_record_wildcard", "service_rsync", "service_socks_proxy", "tlscert_no_revocation"],
)
def test_unknown_non_scoring_match_remains_visible_with_zero_impact(issue_key):
    finding = _finding(issue_key, "high")
    result = _score(finding)
    assert [item.ssc_issue_key for item in result.findings] == [issue_key]
    assert result.findings[0].breach_risk == "UNKNOWN"
    assert result.findings[0].affects_score is False
    assert result.findings[0].score_impact == 0
    assert result.factor_scores[0].score == 100


def test_ssc_severity_difference_does_not_control_internal_score():
    finding = _finding("dmarc_contains_none", "info")
    result = _score(finding)
    assert finding.ssc_severity == "info"
    assert finding.breach_risk == "LOW"
    assert result.findings[0].score_impact == 2


def test_missing_calibration_fails_closed_without_ssc_severity_fallback():
    decision = resolve_ssc_internal_risk("future_ssc_high_issue")
    assert decision.breach_risk == "UNKNOWN"
    assert decision.affects_score is False
    finding = _finding("future_ssc_high_issue", "high")
    assert _score(finding).findings[0].score_impact == 0


def test_calibrated_findings_keep_existing_deduplication_and_cap():
    decision = resolve_ssc_internal_risk("tls_weak_protocol")
    findings = []
    for index in range(16):
        finding = _finding("tls_weak_protocol", "high").model_copy(update={
            "id": f"finding-{index}",
            "rule_id": f"rule-{index}",
            "rule_version_id": f"rule-version-{index}",
            "catalog_issue_type_version_id": "same-version" if index < 2 else f"version-{index}",
            "breach_risk": decision.breach_risk,
        })
        findings.append(finding)
    result = _score(*findings)
    assert sum(item.score_impact for item in result.findings) == 100
    assert sum(item.score_impact == 0 for item in result.findings) >= 1
    assert result.factor_scores[0].score == 0
