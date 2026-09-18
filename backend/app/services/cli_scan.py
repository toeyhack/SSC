"""CLI-independent orchestration over the existing inventory, scan and scoring services."""
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload
from app.models.models import Domain, Host
from app.models.rule_models import RuleEngineRule, RuleTargetTypeEnum
from app.models.scan_models import ScanJob, ScanJobTarget, ScanTargetTypeEnum
from app.services.scan_engine import run_scan_job, validate_scan_target_authorized_for_scanner
from app.services.scan_executors import _clean_host_identifier, validate_scan_config
from app.services.score_results import build_score_result
from app.services.scoring_engine import ScoringDefinition


def resolve_inventory_target(db: Session, name: str, organization_id=None) -> ScanJobTarget:
    name = _clean_host_identifier(name, "target")
    hosts = select(Host).join(Domain).where(or_(Host.hostname == name, Host.ip == name))
    domains = select(Domain).where(Domain.name == name)
    if organization_id:
        hosts = hosts.where(Domain.organization_id == organization_id)
        domains = domains.where(Domain.organization_id == organization_id)
    matches = [ScanJobTarget(target_type=ScanTargetTypeEnum.HOST, host_id=h.id) for h in db.execute(hosts).scalars()]
    matches += [ScanJobTarget(target_type=ScanTargetTypeEnum.DOMAIN, domain_id=d.id) for d in db.execute(domains).scalars()]
    if not matches:
        raise ValueError("Target is not in inventory. Register and approve it before scanning.")
    if len(matches) != 1:
        raise ValueError("Target is ambiguous in inventory. Use --organization-id or a unique inventory hostname.")
    return matches[0]


def scan_inventory_target(db: Session, *, name: str, scan_config: dict, model: ScoringDefinition,
                          organization_id=None, rule_keys: list[str] | None = None):
    config = validate_scan_config(scan_config)
    target = resolve_inventory_target(db, name, organization_id)
    target.scan_config = config
    validate_scan_target_authorized_for_scanner(db, target)
    rules_stmt = select(RuleEngineRule).where(RuleEngineRule.is_active.is_(True), RuleEngineRule.current_version_id.is_not(None)).options(joinedload(RuleEngineRule.current_version))
    if rule_keys:
        rules_stmt = rules_stmt.where(RuleEngineRule.stable_key.in_(rule_keys))
    rules = db.execute(rules_stmt).unique().scalars().all()
    rules = [r for r in rules if r.current_version.target_type == RuleTargetTypeEnum(target.target_type.value)]
    if rule_keys and set(rule_keys) != {r.stable_key for r in rules}:
        raise ValueError("A requested rule is missing, inactive or does not apply to this target type")
    if not rules:
        raise ValueError("No active rules apply to this target. Load detector definitions before scanning.")
    job = ScanJob(name=f"CLI scan {name}", requested_by="ssc CLI", collect_observations=True, selected_rule_ids=[str(r.id) for r in rules])
    db.add(job)
    db.flush()
    target.scan_job_id = job.id
    db.add(target)
    db.commit()
    run = run_scan_job(db, job.id)
    return build_score_result(db, run.id, model)
