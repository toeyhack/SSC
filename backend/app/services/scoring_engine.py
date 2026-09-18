"""Pure, deterministic internal scoring; independent of scanner and output adapters."""
import hashlib
import json
import math
from collections import Counter
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import Field, field_validator

from app.schemas.results import FactorScore, NormalizedResult, ResultEvidence, ResultFinding, ResultRecord, ResultTarget


class ScoringDefinition(ResultRecord):
    name: str = Field(default="internal-exposure", min_length=1)
    version: str = Field(default="1.0", min_length=1)
    penalties: dict[str, float] = Field(default_factory=lambda: {"HIGH": 15, "MEDIUM": 7, "LOW": 2})
    factor_weights: dict[str, float] = Field(default_factory=dict)

    @field_validator("penalties", "factor_weights", mode="before")
    @classmethod
    def validate_numbers(cls, values, info):
        if not isinstance(values, dict):
            raise ValueError("scoring values must be an object")
        for key, value in values.items():
            if not isinstance(key, str) or not key or isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
                raise ValueError("scoring values must be finite numbers with nonempty keys")
            if (info.field_name == "factor_weights" and value <= 0) or (info.field_name == "penalties" and not 0 <= value <= 100):
                raise ValueError("weights must be positive; penalties must be between 0 and 100")
        if info.field_name == "penalties" and set(values) != {"HIGH", "MEDIUM", "LOW"}:
            raise ValueError("penalties must define exactly HIGH, MEDIUM and LOW")
        return values

    def content_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(payload.encode()).hexdigest()


def score_result(*, scan_run_id: str, generated_at: datetime, targets: list[ResultTarget],
                 findings: list[ResultFinding], evidence: list[ResultEvidence],
                 assessments: list[dict[str, Any]], model: ScoringDefinition) -> NormalizedResult:
    factors = {}
    unversioned_factors = set()
    for item in assessments:
        code = item["factor_code"]
        if "catalog_issue_type_version_id" in item and item["catalog_issue_type_version_id"] is None:
            unversioned_factors.add(code)
        factors.setdefault(code, {"name": item["factor_name"], "evaluated": 0, "skipped": 0})
        factors[code][item["status"]] += 1
    for code in model.factor_weights:
        factors.setdefault(code, {"name": code, "evaluated": 0, "skipped": 0})
    warnings = []
    penalties = Counter()
    seen = set()
    scored_findings = []
    unknown_factors = set()
    for finding in sorted(findings, key=lambda f: (f.factor_code, f.catalog_issue_type_version_id or "", f.target_id, f.rule_version_id, f.id)):
        code = finding.factor_code
        factors.setdefault(code, {"name": finding.factor_name, "evaluated": 0, "skipped": 0})
        amount = Decimal(0)
        if finding.affects_score and finding.status == "OPEN":
            if finding.breach_risk == "UNKNOWN":
                unknown_factors.add(code)
            if finding.breach_risk in model.penalties:
                identity = (finding.catalog_issue_type_version_id, finding.target_id)
                if identity not in seen:
                    seen.add(identity)
                    amount = min(Decimal(str(model.penalties[finding.breach_risk])), Decimal(100) - penalties[code])
                    penalties[code] += amount
        scored_findings.append(finding.model_copy(update={"score_impact": float(amount)}))
    factor_scores = []
    for code, state in sorted(factors.items()):
        status = "assessed"
        if not state["evaluated"] or code == "UNCATEGORIZED" or code in unversioned_factors:
            status = "unassessed"
        elif state["skipped"] or code in unknown_factors:
            status = "incomplete"
        factor_scores.append(FactorScore(code=code, name=state["name"], status=status,
                          score=float(Decimal(100) - penalties[code]) if status == "assessed" else None,
                          weight=model.factor_weights.get(code, 1), score_impact=float(penalties[code])))
    total_weight = sum(Decimal(str(f.weight)) for f in factor_scores)
    complete = bool(factor_scores) and all(f.status == "assessed" for f in factor_scores) and all(e.status in {"success", "manual"} for e in evidence)
    overall = None
    if complete:
        overall = float(round(sum(Decimal(str(f.score)) * Decimal(str(f.weight)) for f in factor_scores) / total_weight, 2))
    else:
        warnings.append("Overall score is unassessed because evidence, catalog linkage or rule coverage is incomplete.")
    if any(f.factor_code == "UNCATEGORIZED" for f in findings) or "UNCATEGORIZED" in factors:
        warnings.append("Unlinked rules are uncategorized and have no score penalty; link them to versioned catalog issues.")
    if unknown_factors:
        warnings.append("UNKNOWN breach risk requires catalog review before a factor score can be assessed.")
    weights = {f.code: Decimal(str(f.weight)) for f in factor_scores}
    scored_findings = [f.model_copy(update={"overall_score_impact": float(round(Decimal(str(f.score_impact)) * weights[f.factor_code] / total_weight, 4)) if complete else 0}) for f in scored_findings]
    coverage = {"rules_evaluated": sum(f["evaluated"] for f in factors.values()), "rules_skipped": sum(f["skipped"] for f in factors.values()),
                "evidence_collected": len(evidence), "evidence_errors": sum(e.status == "error" for e in evidence)}
    return NormalizedResult(scan_run_id=scan_run_id, generated_at=generated_at, status="complete" if complete else "incomplete",
                            scoring_model_name=model.name, scoring_model_version=model.version, scoring_model_hash=model.content_hash(),
                            scoring_model_definition=model.model_dump(), overall_score=overall, factor_scores=factor_scores,
                            targets=targets, findings=scored_findings, evidence=evidence, coverage=coverage, warnings=warnings)
