"""The versioned result contract shared by every output adapter."""
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ResultRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ResultTarget(ResultRecord):
    inventory_id: str
    scan_job_target_id: str
    target_type: str
    name: str


class ResultEvidence(ResultRecord):
    id: str
    target_id: str
    source: str
    status: Literal["success", "error", "skipped", "manual"]
    observed_at: datetime
    summary: dict[str, Any]


class ResultFinding(ResultRecord):
    id: str
    target_id: str
    rule_id: str
    rule_version_id: str
    catalog_issue_type_version_id: str | None = None
    ssc_issue_key: str | None = None
    ssc_severity: str | None = None
    title: str
    factor_code: str
    factor_name: str
    breach_risk: str
    affects_score: bool
    status: str
    evidence_source: str | None
    evidence_summary: dict[str, Any]
    remediation: str | None
    score_impact: float = 0
    overall_score_impact: float = 0


class AssessmentProfileSummary(ResultRecord):
    name: str
    version: str
    definition_hash: str
    baseline_content_hash: str
    scoring_model_name: str
    scoring_model_version: str
    in_scope_factor_codes: list[str]


class TargetIssueAssessment(ResultRecord):
    target_id: str
    state: Literal["ASSESSED", "NOT_ASSESSED"]
    reason_code: str
    rule_id: str | None = None
    rule_version_id: str | None = None
    evaluator_outcome: Literal["MATCH", "NO_MATCH", "INDETERMINATE"] | None = None


class IssueAssessment(ResultRecord):
    ssc_issue_key: str
    catalog_issue_type_version_id: str
    factor_code: str
    factor_name: str
    ssc_severity: str | None = None
    supported_capability: bool
    state: Literal["ASSESSED", "NOT_ASSESSED", "OUT_OF_SCOPE"]
    reason_code: str
    target_assessments: list[TargetIssueAssessment] = Field(default_factory=list)


class AssessmentCompleteness(ResultRecord):
    state: Literal["COMPLETE", "INCOMPLETE"]
    total_issues_in_profile: int
    assessed_count: int
    not_assessed_count: int
    out_of_scope_count: int


class FactorScore(ResultRecord):
    code: str
    name: str
    score: float | None = None
    weight: float
    score_impact: float = 0
    status: Literal["assessed", "incomplete", "unassessed"]
    total_issues: int = 0
    assessed_count: int = 0
    not_assessed_count: int = 0
    supported_capability_count: int = 0
    assessment_state: Literal["ASSESSED", "NOT_ASSESSED"] | None = None


class NormalizedResult(ResultRecord):
    schema_version: Literal["ssc.result.v1"] = "ssc.result.v1"
    scan_run_id: str
    generated_at: datetime
    status: Literal["complete", "incomplete"]
    scoring_model_name: str
    scoring_model_version: str
    scoring_model_hash: str
    scoring_model_definition: dict[str, Any]
    overall_score: float | None
    factor_scores: list[FactorScore]
    targets: list[ResultTarget]
    findings: list[ResultFinding]
    evidence: list[ResultEvidence]
    coverage: dict[str, int]
    assessment_profile: AssessmentProfileSummary | None = None
    assessment_completeness: AssessmentCompleteness | None = None
    issue_assessments: list[IssueAssessment] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
