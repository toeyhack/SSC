from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.db.session import engine
from app.models import models as _inventory_models  # noqa: F401 - register ORM relationships
from app.models.catalog_models import (
    BreachRiskEnum,
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.outputs.report import render_html
from app.schemas.results import NormalizedResult, ResultFinding
from app.services.assessment_profiles import (
    AssessmentProfileDefinition,
    ProfileIssue,
    ResolvedAssessmentProfile,
    V1_BASELINE_CONTENT_HASH,
    V1_FACTOR_TOTALS,
    load_v1_assessment_profile,
)
from app.services.scoring_engine import ScoringDefinition, score_result
from app.services.scan_engine import _not_assessed_reason
from app.services.wave1_rules import WAVE1_BY_KEY
from app.services.wave2_rules import WAVE2_BY_KEY
from app.services.wave3a_rules import WAVE3A_BY_KEY


def _profile() -> ResolvedAssessmentProfile:
    issues = (
        ProfileIssue("app-a", "app-a-v1", "application_security", "Application Security", "low", True),
        ProfileIssue("app-b", "app-b-v1", "application_security", "Application Security", "medium", False),
        ProfileIssue("network-a", "network-a-v1", "network_security", "Network Security", "low", True),
        ProfileIssue("dns-a", "dns-a-v1", "dns_health", "DNS Health", "medium", True),
        ProfileIssue("patch-a", "patch-a-v1", "patching_cadence", "Patching Cadence", "high", False),
        ProfileIssue("v2-a", "v2-a-v1", "endpoint_security", "Endpoint Security", "high", False),
    )
    return ResolvedAssessmentProfile(AssessmentProfileDefinition(), issues)


@pytest.fixture
def db():
    with engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


def _assessment(version_id: str, outcome: str = "NO_MATCH", **changes):
    item = {
        "rule_id": "rule-" + version_id,
        "rule_version_id": "rule-version-" + version_id,
        "catalog_issue_type_version_id": version_id,
        "factor_code": "unused-by-profile",
        "factor_name": "Unused by profile",
        "target_id": "target",
        "status": "evaluated",
        "evaluation_outcome": outcome,
    }
    item.update(changes)
    return item


def _score(assessments, findings=None):
    return score_result(
        scan_run_id="run",
        generated_at=datetime(2026, 9, 23, tzinfo=timezone.utc),
        targets=[],
        findings=findings or [],
        evidence=[],
        assessments=assessments,
        model=ScoringDefinition(),
        assessment_profile=_profile(),
    )


def _all_v1_assessments():
    return [_assessment(version_id) for version_id in (
        "app-a-v1", "app-b-v1", "network-a-v1", "dns-a-v1", "patch-a-v1",
    )]


def test_single_no_match_cannot_make_incomplete_v1_assessment_complete():
    result = _score([_assessment("app-a-v1")])
    assert result.status == "incomplete"
    assert result.overall_score is None
    assert result.assessment_completeness.assessed_count == 1
    assert result.assessment_completeness.not_assessed_count == 4
    assert result.assessment_completeness.out_of_scope_count == 1
    assert {item.ssc_issue_key for item in result.issue_assessments if item.state == "NOT_ASSESSED"} == {
        "app-b", "network-a", "dns-a", "patch-a",
    }
    application = next(item for item in result.factor_scores if item.code == "application_security")
    assert application.total_issues == 2
    assert application.assessed_count == 1
    assert application.not_assessed_count == 1
    assert application.score is None


def test_v2_issues_are_out_of_scope_and_do_not_change_v1_score():
    v2_finding = ResultFinding(
        id="finding", target_id="target", rule_id="rule", rule_version_id="rule-v1",
        catalog_issue_type_version_id="v2-a-v1", ssc_issue_key="v2-a", ssc_severity="high",
        title="V2 issue", factor_code="endpoint_security", factor_name="Endpoint Security",
        breach_risk="HIGH", affects_score=True, status="OPEN", evidence_source="SCANNER_HTTP",
        evidence_summary={}, remediation="Review",
    )
    result = _score(_all_v1_assessments() + [_assessment("v2-a-v1", "MATCH")], [v2_finding])
    assert result.status == "complete"
    assert result.overall_score == 100
    assert result.findings[0].score_impact == 0
    v2 = next(item for item in result.issue_assessments if item.ssc_issue_key == "v2-a")
    assert v2.state == "OUT_OF_SCOPE"
    assert v2.reason_code == "outside_v1_profile"


@pytest.mark.parametrize("reason", [
    "insufficient_evidence", "timed_out", "evidence_error", "malformed_evidence",
])
def test_indeterminate_execution_states_are_not_assessed(reason):
    assessments = _all_v1_assessments()
    assessments[0] = _assessment(
        "app-a-v1", "INDETERMINATE", status="skipped", reason_code=reason,
    )
    result = _score(assessments)
    issue = next(item for item in result.issue_assessments if item.ssc_issue_key == "app-a")
    assert issue.state == "NOT_ASSESSED"
    assert issue.reason_code == reason
    assert result.overall_score is None


@pytest.mark.parametrize(("source", "evaluation", "expected"), [
    ({"status": "success"}, {"reason": "required scope was not declared"}, "insufficient_evidence"),
    ({"status": "error", "error": "TimeoutError"}, None, "timed_out"),
    ({"status": "error", "error": "connection_failed"}, None, "evidence_error"),
    ({"status": "success"}, {"reason": "malformed policy could not be parsed"}, "malformed_evidence"),
])
def test_scan_failures_map_to_explicit_not_assessed_reasons(source, evaluation, expected):
    assert _not_assessed_reason(source, evaluation) == expected


@pytest.mark.parametrize("outcome", ["MATCH", "NO_MATCH"])
def test_deterministic_positive_and_negative_outcomes_are_assessed(outcome):
    assessments = _all_v1_assessments()
    assessments[0] = _assessment("app-a-v1", outcome)
    result = _score(assessments)
    issue = next(item for item in result.issue_assessments if item.ssc_issue_key == "app-a")
    assert issue.state == "ASSESSED"
    assert issue.target_assessments[0].evaluator_outcome == outcome
    assert result.status == "complete"


def test_json_and_html_expose_v1_assessment_completeness():
    result = _score([_assessment("app-a-v1")])
    payload = NormalizedResult.model_validate_json(result.model_dump_json())
    assert payload.assessment_profile.name == "ssc-v1"
    assert payload.coverage["issues_not_assessed"] == 4
    document = render_html(payload)
    assert "V1 assessment completeness" in document
    assert "NOT_ASSESSED: 4" in document
    assert "OUT_OF_SCOPE: 1" in document
    assert "app-b" in document
    assert "Supported capability" in document


def test_versioned_v1_profile_resolves_exact_baseline_scope_and_capabilities(db):
    supported = sorted(set(WAVE1_BY_KEY) | set(WAVE2_BY_KEY))
    supported_by_factor = {
        "application_security": supported[:10],
        "network_security": supported[10:15] + sorted(WAVE3A_BY_KEY),
        "dns_health": supported[15:21],
        "patching_cadence": [],
    }
    rows = []
    for code, total in V1_FACTOR_TOTALS.items():
        keys = supported_by_factor[code]
        keys += [f"fixture-{code}-{index}" for index in range(total - len(keys))]
        rows += [{"factor": code, "ssc_issue_key": key, "title": key, "ssc_severity": "low"} for key in keys]
    rows += [
        {"factor": "endpoint_security", "ssc_issue_key": f"fixture-v2-{index}", "title": f"V2 {index}", "ssc_severity": "low"}
        for index in range(42)
    ]
    factors = {}
    for position, code in enumerate(dict.fromkeys(row["factor"] for row in rows)):
        factor = CatalogFactor(code=code, name=code.replace("_", " ").title(), display_order=position)
        db.add(factor)
        db.flush()
        factors[code] = factor
    snapshot = CatalogSnapshot(
        name="V1 completeness profile fixture",
        source_type=SourceTypeEnum.SSC_API,
        content_hash=V1_BASELINE_CONTENT_HASH,
        is_real_baseline=True,
        normalized_schema_version="ssc.api.metadata.v2",
    )
    db.add(snapshot)
    db.flush()
    factor_positions = {code: index for index, code in enumerate(factors)}
    issue_positions = {code: 0 for code in factors}
    for row in rows:
        issue = CatalogIssueType(stable_key=row["ssc_issue_key"], factor_id=factors[row["factor"]].id)
        db.add(issue)
        db.flush()
        version = CatalogIssueTypeVersion(
            issue_type_id=issue.id,
            version_number=1,
            name=row["title"],
            breach_risk=BreachRiskEnum.UNKNOWN,
            ssc_severity=row["ssc_severity"],
            source_type=SourceTypeEnum.SSC_API,
        )
        db.add(version)
        db.flush()
        issue.current_version_id = version.id
        db.add(CatalogSnapshotItem(
            catalog_snapshot_id=snapshot.id,
            issue_type_version_id=version.id,
            factor_position=factor_positions[row["factor"]],
            issue_position=issue_positions[row["factor"]],
        ))
        issue_positions[row["factor"]] += 1
    db.flush()

    profile = load_v1_assessment_profile(db)
    assert profile is not None
    assert len(profile.issues) == 202
    in_scope = [item for item in profile.issues if item.factor_code in profile.definition.in_scope_factor_codes]
    out_of_scope = [item for item in profile.issues if item.factor_code not in profile.definition.in_scope_factor_codes]
    assert len(in_scope) == 160
    assert len(out_of_scope) == 42
    assert sum(item.supported_capability for item in in_scope) == 27
    assert {
        code: sum(item.supported_capability for item in in_scope if item.factor_code == code)
        for code in profile.definition.in_scope_factor_codes
    } == {
        "application_security": 10,
        "network_security": 11,
        "dns_health": 6,
        "patching_cadence": 0,
    }
