"""Pure, deterministic internal scoring; independent of scanner and output adapters."""
import hashlib
import json
import math
from collections import Counter
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import Field, field_validator

from app.schemas.results import (
    AssessmentCompleteness,
    FactorScore,
    IssueAssessment,
    NormalizedResult,
    ResultEvidence,
    ResultFinding,
    ResultRecord,
    ResultTarget,
    TargetIssueAssessment,
)
from app.services.assessment_profiles import ResolvedAssessmentProfile


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
                 assessments: list[dict[str, Any]], model: ScoringDefinition,
                 assessment_profile: ResolvedAssessmentProfile | None = None) -> NormalizedResult:
    if assessment_profile is not None:
        return _score_assessment_profile(
            scan_run_id=scan_run_id,
            generated_at=generated_at,
            targets=targets,
            findings=findings,
            evidence=evidence,
            assessments=assessments,
            model=model,
            profile=assessment_profile,
        )
    return _score_configured_scope(
        scan_run_id=scan_run_id,
        generated_at=generated_at,
        targets=targets,
        findings=findings,
        evidence=evidence,
        assessments=assessments,
        model=model,
    )


def _score_configured_scope(*, scan_run_id: str, generated_at: datetime, targets: list[ResultTarget],
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


def _score_assessment_profile(*, scan_run_id: str, generated_at: datetime, targets: list[ResultTarget],
                              findings: list[ResultFinding], evidence: list[ResultEvidence],
                              assessments: list[dict[str, Any]], model: ScoringDefinition,
                              profile: ResolvedAssessmentProfile) -> NormalizedResult:
    definition = profile.definition
    if (model.name, model.version) != (definition.scoring_model_name, definition.scoring_model_version):
        raise ValueError(
            f"Assessment profile {definition.name} v{definition.version} requires "
            f"{definition.scoring_model_name} v{definition.scoring_model_version}"
        )

    in_scope_codes = set(definition.in_scope_factor_codes)
    profile_by_version = {item.catalog_issue_type_version_id: item for item in profile.issues}
    assessments_by_version: dict[str, list[dict[str, Any]]] = {}
    for assessment in assessments:
        version_id = assessment.get("catalog_issue_type_version_id")
        if isinstance(version_id, str):
            assessments_by_version.setdefault(version_id, []).append(assessment)

    issue_assessments = []
    for issue in profile.issues:
        if issue.factor_code not in in_scope_codes:
            issue_assessments.append(IssueAssessment(
                ssc_issue_key=issue.stable_key,
                catalog_issue_type_version_id=issue.catalog_issue_type_version_id,
                factor_code=issue.factor_code,
                factor_name=issue.factor_name,
                ssc_severity=issue.ssc_severity,
                supported_capability=issue.supported_capability,
                state="OUT_OF_SCOPE",
                reason_code="outside_v1_profile",
            ))
            continue

        rows = assessments_by_version.get(issue.catalog_issue_type_version_id, [])
        target_states = _target_issue_assessments(rows)
        is_assessed = bool(target_states) and all(item.state == "ASSESSED" for item in target_states)
        if is_assessed:
            reason_code = "deterministic_evaluation"
        elif target_states:
            reason_code = next(item.reason_code for item in target_states if item.state == "NOT_ASSESSED")
        elif issue.supported_capability:
            reason_code = "not_selected_or_not_applicable"
        else:
            reason_code = "no_conclusive_evaluator"
        issue_assessments.append(IssueAssessment(
            ssc_issue_key=issue.stable_key,
            catalog_issue_type_version_id=issue.catalog_issue_type_version_id,
            factor_code=issue.factor_code,
            factor_name=issue.factor_name,
            ssc_severity=issue.ssc_severity,
            supported_capability=issue.supported_capability,
            state="ASSESSED" if is_assessed else "NOT_ASSESSED",
            reason_code=reason_code,
            target_assessments=target_states,
        ))

    in_scope_issue_assessments = [item for item in issue_assessments if item.factor_code in in_scope_codes]
    assessed_count = sum(item.state == "ASSESSED" for item in in_scope_issue_assessments)
    not_assessed_count = sum(item.state == "NOT_ASSESSED" for item in in_scope_issue_assessments)
    out_of_scope_count = sum(item.state == "OUT_OF_SCOPE" for item in issue_assessments)
    completeness = AssessmentCompleteness(
        state="COMPLETE" if not_assessed_count == 0 else "INCOMPLETE",
        total_issues_in_profile=len(in_scope_issue_assessments),
        assessed_count=assessed_count,
        not_assessed_count=not_assessed_count,
        out_of_scope_count=out_of_scope_count,
    )

    penalties = Counter()
    seen = set()
    unknown_factors = set()
    scored_findings = []
    out_of_scope_findings = False
    for finding in sorted(findings, key=lambda f: (f.factor_code, f.catalog_issue_type_version_id or "", f.target_id, f.rule_version_id, f.id)):
        profile_issue = profile_by_version.get(finding.catalog_issue_type_version_id or "")
        in_scope = profile_issue is not None and profile_issue.factor_code in in_scope_codes
        amount = Decimal(0)
        if not in_scope:
            out_of_scope_findings = True
        elif finding.affects_score and finding.status == "OPEN":
            if finding.breach_risk == "UNKNOWN":
                unknown_factors.add(finding.factor_code)
            if finding.breach_risk in model.penalties:
                identity = (finding.catalog_issue_type_version_id, finding.target_id)
                if identity not in seen:
                    seen.add(identity)
                    amount = min(
                        Decimal(str(model.penalties[finding.breach_risk])),
                        Decimal(100) - penalties[finding.factor_code],
                    )
                    penalties[finding.factor_code] += amount
        scored_findings.append(finding.model_copy(update={"score_impact": float(amount)}))

    factor_scores = []
    for code in definition.in_scope_factor_codes:
        factor_issues = [item for item in in_scope_issue_assessments if item.factor_code == code]
        factor_assessed = sum(item.state == "ASSESSED" for item in factor_issues)
        factor_not_assessed = sum(item.state == "NOT_ASSESSED" for item in factor_issues)
        factor_complete = factor_not_assessed == 0 and bool(factor_issues)
        if not factor_assessed:
            status = "unassessed"
        elif not factor_complete or code in unknown_factors:
            status = "incomplete"
        else:
            status = "assessed"
        name = factor_issues[0].factor_name if factor_issues else code
        factor_scores.append(FactorScore(
            code=code,
            name=name,
            status=status,
            score=float(Decimal(100) - penalties[code]) if status == "assessed" else None,
            weight=model.factor_weights.get(code, 1),
            score_impact=float(penalties[code]),
            total_issues=len(factor_issues),
            assessed_count=factor_assessed,
            not_assessed_count=factor_not_assessed,
            supported_capability_count=sum(item.supported_capability for item in factor_issues),
            assessment_state="ASSESSED" if factor_complete else "NOT_ASSESSED",
        ))

    total_weight = sum(Decimal(str(factor.weight)) for factor in factor_scores)
    complete = (
        completeness.state == "COMPLETE"
        and all(factor.status == "assessed" for factor in factor_scores)
        and all(item.status in {"success", "manual"} for item in evidence)
    )
    overall = None
    if complete:
        overall = float(round(sum(
            Decimal(str(factor.score)) * Decimal(str(factor.weight))
            for factor in factor_scores
        ) / total_weight, 2))

    weights = {factor.code: Decimal(str(factor.weight)) for factor in factor_scores}
    scored_findings = [finding.model_copy(update={
        "overall_score_impact": float(round(
            Decimal(str(finding.score_impact)) * weights[finding.factor_code] / total_weight, 4,
        )) if complete and finding.factor_code in weights else 0,
    }) for finding in scored_findings]

    warnings = []
    if not complete:
        warnings.append(
            "Overall V1 score is unassessed because required V1 issues remain NOT_ASSESSED "
            "or other documented scoring prerequisites are incomplete."
        )
    if unknown_factors:
        warnings.append("UNKNOWN breach risk requires catalog review before a factor score can be assessed.")
    if out_of_scope_findings:
        warnings.append("Findings outside the V1 assessment profile are reported but excluded from V1 scoring.")
    ignored_weights = sorted(set(model.factor_weights) - in_scope_codes)
    if ignored_weights:
        warnings.append("Configured weights outside the V1 profile were excluded: " + ", ".join(ignored_weights))

    coverage = {
        "rules_evaluated": sum(item.get("status") == "evaluated" for item in assessments),
        "rules_skipped": sum(item.get("status") != "evaluated" for item in assessments),
        "evidence_collected": len(evidence),
        "evidence_errors": sum(item.status == "error" for item in evidence),
        "issues_assessed": assessed_count,
        "issues_not_assessed": not_assessed_count,
        "issues_out_of_scope": out_of_scope_count,
    }
    return NormalizedResult(
        scan_run_id=scan_run_id,
        generated_at=generated_at,
        status="complete" if complete else "incomplete",
        scoring_model_name=model.name,
        scoring_model_version=model.version,
        scoring_model_hash=model.content_hash(),
        scoring_model_definition=model.model_dump(),
        overall_score=overall,
        factor_scores=factor_scores,
        targets=targets,
        findings=scored_findings,
        evidence=evidence,
        coverage=coverage,
        assessment_profile=profile.summary,
        assessment_completeness=completeness,
        issue_assessments=issue_assessments,
        warnings=warnings,
    )


def _target_issue_assessments(rows: list[dict[str, Any]]) -> list[TargetIssueAssessment]:
    by_target: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        target_id = row.get("target_id")
        if isinstance(target_id, str):
            by_target.setdefault(target_id, []).append(row)
    results = []
    for target_id, target_rows in sorted(by_target.items()):
        deterministic = next((row for row in target_rows if (
            row.get("status") == "evaluated" and row.get("evaluation_outcome") in {"MATCH", "NO_MATCH"}
        )), None)
        if deterministic is not None:
            results.append(TargetIssueAssessment(
                target_id=target_id,
                state="ASSESSED",
                reason_code="deterministic_evaluation",
                rule_id=deterministic.get("rule_id"),
                rule_version_id=deterministic.get("rule_version_id"),
                evaluator_outcome=deterministic["evaluation_outcome"],
            ))
            continue
        row = target_rows[0]
        outcome = row.get("evaluation_outcome")
        results.append(TargetIssueAssessment(
            target_id=target_id,
            state="NOT_ASSESSED",
            reason_code=row.get("reason_code") or (
                "assessment_metadata_missing" if row.get("status") == "evaluated" else "insufficient_evidence"
            ),
            rule_id=row.get("rule_id"),
            rule_version_id=row.get("rule_version_id"),
            evaluator_outcome=outcome if outcome in {"MATCH", "NO_MATCH", "INDETERMINATE"} else None,
        ))
    return results
