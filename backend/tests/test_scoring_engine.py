from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from app.schemas.results import ResultFinding
from app.services.scoring_engine import ScoringDefinition, score_result


def finding(id="f1", **changes):
    values = dict(id=id, target_id="target", rule_id="rule", rule_version_id=id, catalog_issue_type_version_id="issue-v1",
                  title="Issue", factor_code="WEB", factor_name="Web", breach_risk="HIGH", affects_score=True,
                  status="OPEN", evidence_source="SCANNER_HTTP", evidence_summary={}, remediation="Fix it")
    values.update(changes)
    return ResultFinding(**values)


def score(findings, assessments=None, **kwargs):
    return score_result(scan_run_id="run", generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), targets=[], findings=findings,
                        evidence=[], assessments=assessments if assessments is not None else [{"factor_code": "WEB", "factor_name": "Web", "status": "evaluated"}],
                        model=kwargs.pop("model", ScoringDefinition()), **kwargs)


def test_penalties_deduplicate_catalog_version_per_target_and_cap():
    result = score([finding(), finding("duplicate"), *[finding(str(i), catalog_issue_type_version_id=str(i)) for i in range(10)]])
    assert result.overall_score == 0
    assert sum(f.score_impact for f in result.findings) == 100
    assert sum(f.overall_score_impact for f in result.findings) == 100
    assert sum(f.score_impact == 0 for f in result.findings) >= 1


def test_weighted_factors_and_informational_positive_optout_resolved():
    assessments = [{"factor_code": "WEB", "factor_name": "Web", "status": "evaluated"}, {"factor_code": "DNS", "factor_name": "DNS", "status": "evaluated"}]
    findings = [finding(), finding("dns", factor_code="DNS", breach_risk="MEDIUM", catalog_issue_type_version_id="dns"),
                finding("info", breach_risk="INFORMATIONAL"), finding("positive", breach_risk="POSITIVE"),
                finding("optout", affects_score=False), finding("resolved", status="RESOLVED")]
    result = score(findings, assessments, model=ScoringDefinition(factor_weights={"WEB": 3, "DNS": 1}))
    assert result.overall_score == 87
    assert {f.code: f.score for f in result.factor_scores} == {"DNS": 93, "WEB": 85}
    assert sum(f.overall_score_impact for f in result.findings) == 13
    assert all(f.score_impact == 0 for f in result.findings if f.id in {"info", "positive", "optout", "resolved"})


def test_missing_rules_and_skipped_rules_never_get_perfect_score():
    assert score([], []).overall_score is None
    result = score([], [{"factor_code": "WEB", "factor_name": "Web", "status": "skipped"}])
    assert result.status == "incomplete"
    assert result.factor_scores[0].score is None


def test_unknown_and_uncategorized_are_unassessed():
    assert score([finding(breach_risk="UNKNOWN")]).overall_score is None
    assert score([finding(factor_code="UNCATEGORIZED", catalog_issue_type_version_id=None, affects_score=False)]).overall_score is None


def test_definition_hash_and_determinism():
    model = ScoringDefinition()
    assert model.content_hash() == ScoringDefinition().content_hash()
    assert model.content_hash() != ScoringDefinition(version="2").content_hash()
    assert score([finding(), finding("b")]).model_dump() == score([finding("b"), finding()]).model_dump()


@pytest.mark.parametrize("values", [{"factor_weights": {"WEB": 0}}, {"factor_weights": {"WEB": float("nan")}},
                                    {"penalties": {"HIGH": -1}}, {"penalties": {"HIGH": 1, "MEDIUM": 7, "LOW": True}}])
def test_invalid_scoring_model_rejected(values):
    with pytest.raises(ValidationError):
        ScoringDefinition(**values)


def test_unversioned_linked_catalog_without_findings_is_unassessed():
    result = score([], [{"factor_code": "WEB", "factor_name": "Web", "status": "evaluated", "catalog_issue_type_version_id": None}])
    assert result.overall_score is None
    assert result.factor_scores[0].status == "unassessed"
