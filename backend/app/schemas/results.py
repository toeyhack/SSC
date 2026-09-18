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


class FactorScore(ResultRecord):
    code: str
    name: str
    score: float | None = None
    weight: float
    score_impact: float = 0
    status: Literal["assessed", "incomplete", "unassessed"]


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
    warnings: list[str] = Field(default_factory=list)
