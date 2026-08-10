import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.models import Domain, Host, Organization
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion, RuleTargetTypeEnum
from app.models.scan_models import ScanFinding, ScanJob, ScanJobTarget, ScanRun, ScanStatusEnum, ScanTargetTypeEnum


class ScanEngineError(ValueError):
    pass


def run_scan_job(db: Session, scan_job_id: UUID) -> ScanRun:
    job = db.execute(
        select(ScanJob)
        .where(ScanJob.id == scan_job_id)
        .with_for_update()
    ).scalar_one_or_none()
    if job is None:
        raise ScanEngineError("Scan job not found")
    if job.status not in {ScanStatusEnum.QUEUED, ScanStatusEnum.FAILED}:
        raise ScanEngineError(f"Scan job cannot be run from status {job.status}")

    now = datetime.now(timezone.utc)
    job.status = ScanStatusEnum.RUNNING
    job.started_at = now
    job.completed_at = None
    job.error_message = None
    run = ScanRun(scan_job_id=job.id, status=ScanStatusEnum.RUNNING, started_at=now)
    db.add(run)
    db.flush()

    try:
        targets = db.execute(
            select(ScanJobTarget).where(ScanJobTarget.scan_job_id == job.id).order_by(ScanJobTarget.created_at)
        ).scalars().all()
        rule_stmt = (
            select(RuleEngineRule)
            .where(RuleEngineRule.is_active.is_(True), RuleEngineRule.current_version_id.is_not(None))
            .options(
                joinedload(RuleEngineRule.current_version),
                joinedload(RuleEngineRule.catalog_issue_type),
            )
            .order_by(RuleEngineRule.stable_key)
        )
        if job.selected_rule_ids:
            rule_stmt = rule_stmt.where(RuleEngineRule.id.in_(job.selected_rule_ids))
        active_rules = db.execute(rule_stmt).unique().scalars().all()

        evaluated = 0
        finding_count = 0
        for target in targets:
            evidence = target.evidence or {}
            for rule in active_rules:
                version = rule.current_version
                if version is None or not _rule_targets_match(version, target):
                    continue
                evaluated += 1
                if evaluate_rule_expression(version.rule_expression, evidence):
                    finding_count += 1
                    db.add(
                        ScanFinding(
                            scan_run_id=run.id,
                            scan_job_id=job.id,
                            scan_job_target_id=target.id,
                            target_type=target.target_type,
                            organization_id=target.organization_id,
                            domain_id=target.domain_id,
                            host_id=target.host_id,
                            rule_id=rule.id,
                            rule_version_id=version.id,
                            catalog_issue_type_id=rule.catalog_issue_type_id,
                            catalog_issue_type_version_id=(
                                rule.catalog_issue_type.current_version_id
                                if rule.catalog_issue_type is not None
                                else None
                            ),
                            evidence={
                                "target_evidence": evidence,
                                "matched_expression": version.rule_expression,
                            },
                        )
                    )

        completed_at = datetime.now(timezone.utc)
        run.status = ScanStatusEnum.COMPLETED
        run.completed_at = completed_at
        run.summary = {
            "targets": len(targets),
            "rules_evaluated": evaluated,
            "findings_created": finding_count,
        }
        job.status = ScanStatusEnum.COMPLETED
        job.completed_at = completed_at
        db.commit()
        db.refresh(run)
        return run
    except Exception as exc:
        db.rollback()
        failed_job = db.get(ScanJob, scan_job_id)
        if failed_job is not None:
            failed_job.status = ScanStatusEnum.FAILED
            failed_job.error_message = str(exc)
            failed_job.completed_at = datetime.now(timezone.utc)
            failed_run = db.get(ScanRun, run.id)
            if failed_run is not None:
                failed_run.status = ScanStatusEnum.FAILED
                failed_run.error_message = str(exc)
                failed_run.completed_at = failed_job.completed_at
            db.commit()
        raise


def process_next_scan_job(db: Session) -> ScanRun | None:
    job = db.execute(
        select(ScanJob)
        .where(ScanJob.status == ScanStatusEnum.QUEUED)
        .order_by(ScanJob.created_at)
        .limit(1)
    ).scalar_one_or_none()
    if job is None:
        return None
    return run_scan_job(db, job.id)


def validate_scan_target(db: Session, target: ScanJobTarget):
    if target.target_type == ScanTargetTypeEnum.ORGANIZATION:
        if db.get(Organization, target.organization_id) is None:
            raise ScanEngineError("Organization target not found")
    elif target.target_type == ScanTargetTypeEnum.DOMAIN:
        if db.get(Domain, target.domain_id) is None:
            raise ScanEngineError("Domain target not found")
    elif target.target_type == ScanTargetTypeEnum.HOST:
        if db.get(Host, target.host_id) is None:
            raise ScanEngineError("Host target not found")


def evaluate_rule_expression(expression: dict[str, Any], evidence: dict[str, Any]) -> bool:
    operator = expression.get("operator")
    path = expression.get("path")
    if not isinstance(operator, str):
        raise ScanEngineError("rule_expression.operator must be a string")
    if not isinstance(path, str):
        raise ScanEngineError("rule_expression.path must be a string")

    found, value = _extract_path(evidence, path)
    if operator == "exists":
        return found
    if operator == "missing":
        return not found
    if operator == "equals":
        return found and value == expression.get("value")
    if operator == "not_equals":
        return (not found) or value != expression.get("value")
    if operator == "contains":
        expected = expression.get("value")
        if isinstance(value, list):
            return expected in value
        if isinstance(value, str) and isinstance(expected, str):
            return expected in value
        return False
    if operator == "regex":
        pattern = expression.get("pattern")
        if not isinstance(value, str) or not isinstance(pattern, str):
            return False
        return re.search(pattern, value) is not None
    raise ScanEngineError(f"Unsupported rule_expression.operator: {operator}")


def _rule_targets_match(version: RuleEngineRuleVersion, target: ScanJobTarget) -> bool:
    target_type = version.target_type.value if isinstance(version.target_type, RuleTargetTypeEnum) else version.target_type
    return target_type == target.target_type.value


def _extract_path(evidence: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = evidence
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        return False, None
    return True, current
