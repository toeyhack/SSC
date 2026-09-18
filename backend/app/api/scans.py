from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.rule_models import RuleEngineRule
from app.models.scan_models import ScanFinding, ScanJob, ScanJobTarget, ScanObservation, ScanRun
from app.schemas.scans import ScanFindingRead, ScanJobCreate, ScanJobRead, ScanObservationRead, ScanRunRead
from app.services.scan_engine import (
    ScanEngineError,
    run_scan_job,
    validate_scan_target,
    validate_scan_target_authorized_for_scanner,
)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _commit_or_conflict(db: Session, detail: str):
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(detail) from exc


def _get_scan_job(db: Session, scan_job_id: UUID) -> ScanJob:
    stmt = select(ScanJob).where(ScanJob.id == scan_job_id).options(joinedload(ScanJob.targets))
    job = db.execute(stmt).unique().scalar_one_or_none()
    if job is None:
        raise _not_found("Scan job not found")
    return job


@router.get("/jobs", response_model=list[ScanJobRead])
def list_scan_jobs(db: Session = Depends(get_db)):
    stmt = select(ScanJob).options(joinedload(ScanJob.targets)).order_by(ScanJob.created_at.desc())
    return db.execute(stmt).unique().scalars().all()


@router.post("/jobs", response_model=ScanJobRead, status_code=status.HTTP_201_CREATED)
def create_scan_job(payload: ScanJobCreate, db: Session = Depends(get_db)):
    selected_rule_ids = [str(rule_id) for rule_id in payload.rule_ids] if payload.rule_ids else None
    if payload.rule_ids:
        existing_rule_ids = set(
            db.execute(select(RuleEngineRule.id).where(RuleEngineRule.id.in_(payload.rule_ids))).scalars().all()
        )
        missing = [str(rule_id) for rule_id in payload.rule_ids if rule_id not in existing_rule_ids]
        if missing:
            raise _bad_request(f"Rule not found: {', '.join(missing)}")

    job = ScanJob(
        name=payload.name,
        requested_by=payload.requested_by,
        notes=payload.notes,
        selected_rule_ids=selected_rule_ids,
        collect_observations=payload.collect_observations,
    )
    db.add(job)
    db.flush()

    for target_payload in payload.targets:
        target = ScanJobTarget(scan_job_id=job.id, **target_payload.model_dump())
        try:
            validate_scan_target(db, target)
            if payload.collect_observations:
                validate_scan_target_authorized_for_scanner(db, target)
        except ScanEngineError as exc:
            db.rollback()
            raise _bad_request(str(exc)) from exc
        db.add(target)

    _commit_or_conflict(db, "Scan job violates a scan-engine constraint")
    return _get_scan_job(db, job.id)


@router.get("/jobs/{scan_job_id}", response_model=ScanJobRead)
def read_scan_job(scan_job_id: UUID, db: Session = Depends(get_db)):
    return _get_scan_job(db, scan_job_id)


@router.post("/jobs/{scan_job_id}/run", response_model=ScanRunRead, status_code=status.HTTP_201_CREATED)
def run_scan_job_endpoint(scan_job_id: UUID, db: Session = Depends(get_db)):
    try:
        return run_scan_job(db, scan_job_id)
    except ScanEngineError as exc:
        raise _bad_request(str(exc)) from exc


@router.get("/runs", response_model=list[ScanRunRead])
def list_scan_runs(db: Session = Depends(get_db)):
    stmt = select(ScanRun).order_by(ScanRun.started_at.desc())
    return db.execute(stmt).scalars().all()


@router.get("/runs/{scan_run_id}/findings", response_model=list[ScanFindingRead])
def list_scan_findings(scan_run_id: UUID, db: Session = Depends(get_db)):
    stmt = (
        select(ScanFinding)
        .where(ScanFinding.scan_run_id == scan_run_id)
        .options(joinedload(ScanFinding.rule), joinedload(ScanFinding.rule_version))
        .order_by(ScanFinding.created_at)
    )
    return db.execute(stmt).unique().scalars().all()


@router.get("/runs/{scan_run_id}/observations", response_model=list[ScanObservationRead])
def list_scan_observations(scan_run_id: UUID, db: Session = Depends(get_db)):
    stmt = (
        select(ScanObservation)
        .where(ScanObservation.scan_run_id == scan_run_id)
        .order_by(ScanObservation.observed_at, ScanObservation.evidence_source)
    )
    return db.execute(stmt).scalars().all()
