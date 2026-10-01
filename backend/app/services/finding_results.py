"""Normalize persisted findings using exact historical versions, without scoring or rendering."""
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.catalog_models import CatalogIssueType, CatalogIssueTypeVersion, SourceTypeEnum
from app.models.rule_models import RuleEngineRuleVersion
from app.models.scan_models import ScanFinding
from app.schemas.results import ResultFinding
from app.services.internal_risk_calibration import resolve_ssc_internal_risk


def load_result_findings(db: Session, run_id, assessments: list[dict]) -> list[ResultFinding]:
    metadata = {(a["rule_version_id"], a["target_id"]): a for a in assessments}
    results = []
    for finding in db.execute(select(ScanFinding).where(ScanFinding.scan_run_id == run_id)).scalars():
        rule = db.get(RuleEngineRuleVersion, finding.rule_version_id)
        issue = db.get(CatalogIssueTypeVersion, finding.catalog_issue_type_version_id) if finding.catalog_issue_type_version_id else None
        issue_type = db.get(CatalogIssueType, issue.issue_type_id) if issue else None
        assessment = metadata.get((str(finding.rule_version_id), str(finding.scan_job_target_id)), {})
        if issue and issue.source_type == SourceTypeEnum.SSC_API and issue_type:
            internal_risk = resolve_ssc_internal_risk(issue_type.stable_key)
            breach_risk = internal_risk.breach_risk
            affects_score = internal_risk.affects_score
        else:
            breach_risk = issue.breach_risk.value if issue else "UNKNOWN"
            affects_score = issue.affects_score if issue else False
        results.append(ResultFinding(id=str(finding.id), target_id=str(finding.scan_job_target_id), rule_id=str(finding.rule_id),
                     rule_version_id=str(finding.rule_version_id), catalog_issue_type_version_id=str(issue.id) if issue else None,
                     ssc_issue_key=issue_type.stable_key if issue_type else None,
                     ssc_severity=issue.ssc_severity if issue else None,
                     title=issue.name if issue else rule.name, factor_code=assessment.get("factor_code", "UNCATEGORIZED"),
                     factor_name=assessment.get("factor_name", "Uncategorized"), breach_risk=breach_risk,
                     affects_score=affects_score, status=finding.status.value,
                     evidence_source=finding.evidence_source.value if finding.evidence_source else None,
                     evidence_summary=finding.evidence or {}, remediation=rule.remediation))
    return results
