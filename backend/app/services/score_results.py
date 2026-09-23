"""Build and persist the shared normalized result; no presentation or HTTP dependency."""
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models.score_models import ScoreResult
from app.models.scan_models import ScanObservation, ScanRun, ScanStatusEnum
from app.schemas.results import NormalizedResult, ResultEvidence, ResultTarget
from app.services.assessment_profiles import load_v1_assessment_profile
from app.services.finding_results import load_result_findings
from app.services.scoring_engine import ScoringDefinition, score_result


def build_score_result(db: Session, run_id, model: ScoringDefinition | None = None) -> NormalizedResult:
    model = model or ScoringDefinition()
    model_hash = model.content_hash()
    assessment_profile = load_v1_assessment_profile(db)
    profile_summary = assessment_profile.summary if assessment_profile is not None else None
    profile_hash = profile_summary.definition_hash if profile_summary is not None else None
    existing_stmt = select(ScoreResult).where(
        ScoreResult.scan_run_id == run_id,
        ScoreResult.scoring_model_hash == model_hash,
        ScoreResult.assessment_profile_hash == profile_hash,
    )
    existing = db.execute(existing_stmt).scalar_one_or_none()
    if existing:
        return NormalizedResult.model_validate(existing.result)
    run = db.get(ScanRun, run_id)
    if run is None or run.status != ScanStatusEnum.COMPLETED:
        raise ValueError("Scoring requires a completed scan run")
    summary = run.summary or {}
    assessments = summary.get("rule_assessments", [])
    evidence = []
    for observation in db.execute(select(ScanObservation).where(ScanObservation.scan_run_id == run.id).order_by(ScanObservation.id)).scalars():
        evidence.append(ResultEvidence(id=str(observation.id), target_id=str(observation.scan_job_target_id),
                        source=observation.evidence_source.value, status="manual" if observation.evidence_source.value == "MANUAL" else observation.evidence.get("status", "error"),
                        observed_at=observation.observed_at, summary=observation.evidence))
    result = score_result(scan_run_id=str(run.id), generated_at=datetime.now(timezone.utc),
                        targets=[ResultTarget.model_validate(t) for t in summary.get("targets_snapshot", [])],
                        findings=load_result_findings(db, run.id, assessments), evidence=evidence,
                        assessments=assessments, model=model, assessment_profile=assessment_profile)
    snapshot = ScoreResult(scan_run_id=run.id, scoring_model_name=model.name, scoring_model_version=model.version,
                           scoring_model_hash=model_hash,
                           assessment_profile_name=profile_summary.name if profile_summary else None,
                           assessment_profile_version=profile_summary.version if profile_summary else None,
                           assessment_profile_hash=profile_hash,
                           result=result.model_dump(mode="json"))
    db.add(snapshot)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.execute(existing_stmt).scalar_one_or_none()
        if existing is None:
            raise
        return NormalizedResult.model_validate(existing.result)
    return result
