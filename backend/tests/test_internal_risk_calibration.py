from collections import Counter
from datetime import datetime, timezone

import pytest

from app.schemas.results import ResultFinding
from app.services.internal_risk_calibration import (
    SSC_SUPPORTED_INTERNAL_RISK_V1,
    resolve_ssc_internal_risk,
)
from app.services.scoring_engine import ScoringDefinition, score_result


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
    assert len(SSC_SUPPORTED_INTERNAL_RISK_V1) == 27
    counts = Counter(item.breach_risk for item in SSC_SUPPORTED_INTERNAL_RISK_V1.values())
    assert {risk: counts[risk] for risk in ("HIGH", "MEDIUM", "LOW", "UNKNOWN")} == {
        "HIGH": 0, "MEDIUM": 6, "LOW": 17, "UNKNOWN": 4,
    }
    assert Counter(item.affects_score for item in SSC_SUPPORTED_INTERNAL_RISK_V1.values()) == {
        True: 23,
        False: 4,
    }


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
