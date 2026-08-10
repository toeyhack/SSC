from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.catalog_models import CatalogIssueType
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion
from app.schemas.rules import RuleCreate, RuleRead, RuleUpdate, RuleVersionCreate, RuleVersionRead

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def _conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _commit_or_conflict(db: Session, detail: str):
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict(detail) from exc


def _get_rule(db: Session, rule_id: UUID, for_update: bool = False) -> RuleEngineRule:
    stmt = select(RuleEngineRule).where(RuleEngineRule.id == rule_id)
    if for_update:
        stmt = stmt.with_for_update()
    rule = db.execute(stmt).scalar_one_or_none()
    if rule is None:
        raise _not_found("Rule not found")
    return rule


def _get_rule_version(db: Session, version_id: UUID) -> RuleEngineRuleVersion:
    version = db.get(RuleEngineRuleVersion, version_id)
    if version is None:
        raise _not_found("Rule version not found")
    return version


def _validate_catalog_issue(db: Session, catalog_issue_type_id: UUID | None):
    if catalog_issue_type_id is None:
        return
    if db.get(CatalogIssueType, catalog_issue_type_id) is None:
        raise _bad_request("Catalog issue type not found")


def _validate_current_version(db: Session, rule_id: UUID, current_version_id: UUID | None):
    if current_version_id is None:
        return
    version = _get_rule_version(db, current_version_id)
    if version.rule_id != rule_id:
        raise _bad_request("Current version must belong to the same rule")


@router.get("", response_model=list[RuleRead])
def list_rules(db: Session = Depends(get_db)):
    stmt = (
        select(RuleEngineRule)
        .options(joinedload(RuleEngineRule.catalog_issue_type), joinedload(RuleEngineRule.current_version))
        .order_by(RuleEngineRule.stable_key)
    )
    return db.execute(stmt).unique().scalars().all()


@router.post("", response_model=RuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(payload: RuleCreate, db: Session = Depends(get_db)):
    _validate_catalog_issue(db, payload.catalog_issue_type_id)
    if payload.current_version_id is not None:
        raise _bad_request("Current version cannot be set while creating a new rule")

    existing = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == payload.stable_key)).scalar_one_or_none()
    if existing is not None:
        raise _conflict("Rule stable_key already exists")

    rule = RuleEngineRule(**payload.model_dump())
    db.add(rule)
    _commit_or_conflict(db, "Rule stable_key already exists")
    return read_rule(rule.id, db)


@router.get("/{rule_id}", response_model=RuleRead)
def read_rule(rule_id: UUID, db: Session = Depends(get_db)):
    stmt = (
        select(RuleEngineRule)
        .where(RuleEngineRule.id == rule_id)
        .options(joinedload(RuleEngineRule.catalog_issue_type), joinedload(RuleEngineRule.current_version))
    )
    rule = db.execute(stmt).unique().scalar_one_or_none()
    if rule is None:
        raise _not_found("Rule not found")
    return rule


@router.patch("/{rule_id}", response_model=RuleRead)
def update_rule(rule_id: UUID, payload: RuleUpdate, db: Session = Depends(get_db)):
    rule = _get_rule(db, rule_id)
    data = payload.model_dump(exclude_unset=True)
    if "catalog_issue_type_id" in data:
        _validate_catalog_issue(db, data["catalog_issue_type_id"])
    if "current_version_id" in data:
        _validate_current_version(db, rule.id, data["current_version_id"])

    for field, value in data.items():
        setattr(rule, field, value)

    _commit_or_conflict(db, "Rule update violates a rule-engine constraint")
    return read_rule(rule.id, db)


@router.get("/{rule_id}/versions", response_model=list[RuleVersionRead])
def list_rule_versions(rule_id: UUID, db: Session = Depends(get_db)):
    _get_rule(db, rule_id)
    stmt = (
        select(RuleEngineRuleVersion)
        .where(RuleEngineRuleVersion.rule_id == rule_id)
        .order_by(RuleEngineRuleVersion.version_number)
    )
    return db.execute(stmt).scalars().all()


@router.post("/{rule_id}/versions", response_model=RuleVersionRead, status_code=status.HTTP_201_CREATED)
def create_rule_version(rule_id: UUID, payload: RuleVersionCreate, db: Session = Depends(get_db)):
    rule = _get_rule(db, rule_id, for_update=True)
    version_number = payload.version_number
    if version_number is None:
        latest = db.execute(
            select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule_id)
        ).scalar()
        version_number = (latest or 0) + 1
    else:
        existing = db.execute(
            select(RuleEngineRuleVersion).where(
                RuleEngineRuleVersion.rule_id == rule_id,
                RuleEngineRuleVersion.version_number == version_number,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise _conflict("Rule version number already exists")

    data = payload.model_dump(exclude={"make_current"}, exclude_none=True)
    data["version_number"] = version_number
    version = RuleEngineRuleVersion(rule_id=rule_id, **data)
    db.add(version)

    try:
        db.flush()
        if payload.make_current:
            rule.current_version_id = version.id
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict("Rule version number already exists") from exc

    db.refresh(version)
    return version
