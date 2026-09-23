from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.models import Domain, Host, Organization
from app.models.catalog_models import CatalogIssueType, CatalogIssueTypeVersion
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion, RuleTargetTypeEnum
from app.models.scan_models import (
    EvidenceSourceEnum,
    ScanFinding,
    ScanJob,
    ScanJobTarget,
    ScanObservation,
    ScanRun,
    ScanStatusEnum,
    ScanTargetTypeEnum,
)
from app.services.rule_evaluation import RuleEvaluationError, evaluate_rule_expression, _extract_path
from app.services.scan_executors import (
    ScanExecutorError,
    collect_scanner_observations,
    load_authorized_scan_target,
    validate_scan_config,
)


ScanEngineError = RuleEvaluationError  # Preserve the Phase 4 public exception contract.


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
    run_id = run.id

    try:
        targets = db.execute(
            select(ScanJobTarget).where(ScanJobTarget.scan_job_id == job.id).order_by(ScanJobTarget.created_at)
        ).scalars().all()
        rule_stmt = (
            select(RuleEngineRule)
            .where(RuleEngineRule.is_active.is_(True), RuleEngineRule.current_version_id.is_not(None))
            .options(
                joinedload(RuleEngineRule.current_version),
                joinedload(RuleEngineRule.catalog_issue_type).joinedload(CatalogIssueType.factor),
            )
            .order_by(RuleEngineRule.stable_key)
        )
        if job.selected_rule_ids:
            rule_stmt = rule_stmt.where(RuleEngineRule.id.in_(job.selected_rule_ids))
        active_rules = db.execute(rule_stmt).unique().scalars().all()

        evaluated = 0
        finding_count = 0
        skipped = 0
        assessments = []
        target_snapshots = []
        observation_count = 0
        for target in targets:
            evidence, source_by_root, created_observations = _collect_or_load_evidence(db, job, run, target)
            observation_count += created_observations
            identity = target.host or target.domain or target.organization
            target_snapshots.append({"inventory_id": str(target.host_id or target.domain_id or target.organization_id),
                                     "scan_job_target_id": str(target.id), "target_type": target.target_type.value,
                                     "name": getattr(identity, "hostname", None) or identity.name})
            for rule in active_rules:
                version = rule.current_version
                if version is None or not _rule_targets_match(version, target):
                    continue
                issue = rule.catalog_issue_type
                pinned_issue_version_id = version.catalog_issue_type_version_id
                if pinned_issue_version_id is not None:
                    pinned_issue_version = db.get(CatalogIssueTypeVersion, pinned_issue_version_id)
                    if issue is None or pinned_issue_version is None or pinned_issue_version.issue_type_id != issue.id:
                        raise ScanEngineError(f"Rule {rule.stable_key} has an invalid pinned catalog issue version")
                else:
                    pinned_issue_version_id = issue.current_version_id if issue else None
                assessment = {"rule_id": str(rule.id), "rule_version_id": str(version.id),
                              "catalog_issue_type_version_id": str(pinned_issue_version_id) if pinned_issue_version_id else None,
                              "factor_code": issue.factor.code if issue else "UNCATEGORIZED",
                              "factor_name": issue.factor.name if issue else "Uncategorized",
                              "target_id": str(target.id), "status": "evaluated"}
                assessments.append(assessment)
                root = version.rule_expression.get("path", "").split(".")[0]
                source_evidence = evidence.get(root)
                path = version.rule_expression.get("path", "")
                evaluation = _evaluation_for_expression(version.rule_expression, evidence)
                if evaluation is not None and evaluation.get("outcome") in {"MATCH", "NO_MATCH", "INDETERMINATE"}:
                    assessment["evaluation_outcome"] = evaluation["outcome"]
                if job.collect_observations and (not isinstance(source_evidence, dict) or
                    (source_evidence.get("status") != "success" and ".evaluations." not in path and not path.endswith(".endpoint_available")) or
                    (_extract_path(evidence, path)[1] is None and version.rule_expression.get("operator") != "exists")):
                    assessment["status"] = "skipped"
                    assessment["reason_code"] = _not_assessed_reason(source_evidence, evaluation)
                    skipped += 1
                    continue
                evaluated += 1
                if evaluate_rule_expression(version.rule_expression, evidence):
                    finding_count += 1
                    evidence_source = _evidence_source_for_expression(version.rule_expression, source_by_root)
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
                            catalog_issue_type_version_id=pinned_issue_version_id,
                            evidence={
                                "evidence_source": evidence_source.value if evidence_source is not None else None,
                                "target_evidence": _matched_evidence(version.rule_expression, evidence),
                                "matched_expression": version.rule_expression,
                            },
                            evidence_source=evidence_source,
                        )
                    )

        completed_at = datetime.now(timezone.utc)
        run.status = ScanStatusEnum.COMPLETED
        run.completed_at = completed_at
        run.summary = {
            "targets": len(targets),
            "observations_created": observation_count,
            "evidence_mode": "SCANNER" if job.collect_observations else "MANUAL",
            "rules_evaluated": evaluated,
            "rules_skipped": skipped,
            "rule_assessments": assessments,
            "targets_snapshot": target_snapshots,
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
            db.add(ScanRun(id=run_id, scan_job_id=scan_job_id, status=ScanStatusEnum.FAILED,
                           started_at=now, completed_at=failed_job.completed_at, error_message=str(exc)))
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


def validate_scan_target_authorized_for_scanner(db: Session, target: ScanJobTarget):
    try:
        validate_scan_config(target.scan_config)
        load_authorized_scan_target(db, target)
    except ScanExecutorError as exc:
        raise ScanEngineError(str(exc)) from exc


def _rule_targets_match(version: RuleEngineRuleVersion, target: ScanJobTarget) -> bool:
    target_type = version.target_type.value if isinstance(version.target_type, RuleTargetTypeEnum) else version.target_type
    return target_type == target.target_type.value


def _collect_or_load_evidence(
    db: Session,
    job: ScanJob,
    run: ScanRun,
    target: ScanJobTarget,
) -> tuple[dict[str, Any], dict[str, EvidenceSourceEnum], int]:
    if not job.collect_observations:
        evidence = target.evidence or {}
        if target.evidence is not None:
            db.add(
                ScanObservation(
                    scan_run_id=run.id,
                    scan_job_id=job.id,
                    scan_job_target_id=target.id,
                    evidence_source=EvidenceSourceEnum.MANUAL,
                    evidence=evidence,
                )
            )
            return evidence, {"": EvidenceSourceEnum.MANUAL}, 1
        return evidence, {"": EvidenceSourceEnum.MANUAL}, 0

    try:
        inventory_target = load_authorized_scan_target(db, target)
        observations = collect_scanner_observations(inventory_target, target.scan_config)
    except ScanExecutorError as exc:
        raise ScanEngineError(str(exc)) from exc

    evidence: dict[str, Any] = {}
    source_by_root: dict[str, EvidenceSourceEnum] = {}
    for observation in observations:
        root = _root_for_evidence_source(observation.evidence_source)
        evidence[root] = observation.evidence
        source_by_root[root] = observation.evidence_source
        db.add(
            ScanObservation(
                scan_run_id=run.id,
                scan_job_id=job.id,
                scan_job_target_id=target.id,
                evidence_source=observation.evidence_source,
                evidence=observation.evidence,
            )
        )
    return evidence, source_by_root, len(observations)


def _root_for_evidence_source(source: EvidenceSourceEnum) -> str:
    return {
        EvidenceSourceEnum.MANUAL: "",
        EvidenceSourceEnum.SCANNER_HTTP: "http",
        EvidenceSourceEnum.SCANNER_TLS: "tls",
        EvidenceSourceEnum.SCANNER_DNS: "dns",
        EvidenceSourceEnum.SCANNER_TCP: "tcp",
    }[source]


def _evidence_source_for_expression(
    expression: dict[str, Any],
    source_by_root: dict[str, EvidenceSourceEnum],
) -> EvidenceSourceEnum | None:
    path = expression.get("path")
    if not isinstance(path, str):
        return source_by_root.get("")
    root = path.split(".", 1)[0]
    return source_by_root.get(root) or source_by_root.get("")


def _evaluation_for_expression(
    expression: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any] | None:
    path = expression.get("path")
    if not isinstance(path, str) or not path.endswith(".matched"):
        return None
    found, value = _extract_path(evidence, path.rsplit(".", 1)[0])
    return value if found and isinstance(value, dict) else None


def _not_assessed_reason(
    source_evidence: Any,
    evaluation: dict[str, Any] | None,
) -> str:
    details = " ".join(str(value) for value in (
        source_evidence.get("error") if isinstance(source_evidence, dict) else None,
        evaluation.get("reason") if evaluation else None,
    ) if value).casefold()
    if "timeout" in details or "timed out" in details:
        return "timed_out"
    if any(token in details for token in ("malformed", "parse", "invalid")):
        return "malformed_evidence"
    if isinstance(source_evidence, dict) and source_evidence.get("status") == "error":
        return "evidence_error"
    return "insufficient_evidence"


def _matched_evidence(expression: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    path = expression.get("path")
    if not isinstance(path, str):
        return evidence
    found, value = _extract_path(evidence, path)
    return {"path": path, "found": found, "value": value}
