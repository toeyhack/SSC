from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.catalog_models import (
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
)
from app.schemas.catalog import (
    CatalogSnapshotCreate,
    CatalogSnapshotItemCreate,
    CatalogSnapshotItemRead,
    CatalogSnapshotRead,
    FactorCreate,
    FactorRead,
    FactorUpdate,
    IssueTypeCreate,
    IssueTypeRead,
    IssueTypeUpdate,
    IssueTypeVersionCreate,
    IssueTypeVersionRead,
)

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])


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


def _get_factor(db: Session, factor_id: UUID) -> CatalogFactor:
    factor = db.get(CatalogFactor, factor_id)
    if factor is None:
        raise _not_found("Factor not found")
    return factor


def _get_issue(db: Session, issue_id: UUID, for_update: bool = False) -> CatalogIssueType:
    stmt = select(CatalogIssueType).where(CatalogIssueType.id == issue_id)
    if for_update:
        stmt = stmt.with_for_update()
    issue = db.execute(stmt).scalar_one_or_none()
    if issue is None:
        raise _not_found("Issue type not found")
    return issue


def _get_version(db: Session, version_id: UUID) -> CatalogIssueTypeVersion:
    version = db.get(CatalogIssueTypeVersion, version_id)
    if version is None:
        raise _not_found("Issue type version not found")
    return version


def _validate_current_version(db: Session, issue_id: UUID, version_id: UUID | None):
    if version_id is None:
        return
    version = _get_version(db, version_id)
    if version.issue_type_id != issue_id:
        raise _bad_request("Current version must belong to the same issue type")


@router.get("/factors", response_model=list[FactorRead])
def list_factors(db: Session = Depends(get_db)):
    stmt = select(CatalogFactor).order_by(CatalogFactor.display_order, CatalogFactor.name)
    return db.execute(stmt).scalars().all()


@router.get("/factors/{factor_id}", response_model=FactorRead)
def read_factor(factor_id: UUID, db: Session = Depends(get_db)):
    return _get_factor(db, factor_id)


@router.post("/factors", response_model=FactorRead, status_code=status.HTTP_201_CREATED)
def create_factor(payload: FactorCreate, db: Session = Depends(get_db)):
    existing = db.execute(select(CatalogFactor).where(CatalogFactor.code == payload.code)).scalar_one_or_none()
    if existing is not None:
        raise _conflict("Factor code already exists")

    factor = CatalogFactor(**payload.model_dump())
    db.add(factor)
    _commit_or_conflict(db, "Factor code already exists")
    db.refresh(factor)
    return factor


@router.patch("/factors/{factor_id}", response_model=FactorRead)
def update_factor(factor_id: UUID, payload: FactorUpdate, db: Session = Depends(get_db)):
    factor = _get_factor(db, factor_id)
    data = payload.model_dump(exclude_unset=True)
    if "code" in data and data["code"] != factor.code:
        existing = db.execute(select(CatalogFactor).where(CatalogFactor.code == data["code"])).scalar_one_or_none()
        if existing is not None:
            raise _conflict("Factor code already exists")

    for field, value in data.items():
        setattr(factor, field, value)

    _commit_or_conflict(db, "Factor update violates a catalog constraint")
    db.refresh(factor)
    return factor


@router.get("/issues", response_model=list[IssueTypeRead])
def list_issues(db: Session = Depends(get_db)):
    stmt = (
        select(CatalogIssueType)
        .options(joinedload(CatalogIssueType.factor), joinedload(CatalogIssueType.current_version))
        .order_by(CatalogIssueType.stable_key)
    )
    return db.execute(stmt).unique().scalars().all()


@router.get("/issues/{issue_id}", response_model=IssueTypeRead)
def read_issue(issue_id: UUID, db: Session = Depends(get_db)):
    stmt = (
        select(CatalogIssueType)
        .where(CatalogIssueType.id == issue_id)
        .options(joinedload(CatalogIssueType.factor), joinedload(CatalogIssueType.current_version))
    )
    issue = db.execute(stmt).unique().scalar_one_or_none()
    if issue is None:
        raise _not_found("Issue type not found")
    return issue


@router.post("/issues", response_model=IssueTypeRead, status_code=status.HTTP_201_CREATED)
def create_issue(payload: IssueTypeCreate, db: Session = Depends(get_db)):
    _get_factor(db, payload.factor_id)
    if payload.current_version_id is not None:
        raise _bad_request("Current version cannot be set while creating a new issue type")

    existing = db.execute(
        select(CatalogIssueType).where(CatalogIssueType.stable_key == payload.stable_key)
    ).scalar_one_or_none()
    if existing is not None:
        raise _conflict("Issue stable_key already exists")

    issue = CatalogIssueType(**payload.model_dump())
    db.add(issue)
    _commit_or_conflict(db, "Issue stable_key already exists")
    db.refresh(issue)
    return read_issue(issue.id, db)


@router.patch("/issues/{issue_id}", response_model=IssueTypeRead)
def update_issue(issue_id: UUID, payload: IssueTypeUpdate, db: Session = Depends(get_db)):
    issue = _get_issue(db, issue_id)
    data = payload.model_dump(exclude_unset=True)

    if "stable_key" in data and data["stable_key"] != issue.stable_key:
        existing = db.execute(
            select(CatalogIssueType).where(CatalogIssueType.stable_key == data["stable_key"])
        ).scalar_one_or_none()
        if existing is not None:
            raise _conflict("Issue stable_key already exists")

    if "factor_id" in data:
        _get_factor(db, data["factor_id"])

    if "current_version_id" in data:
        _validate_current_version(db, issue.id, data["current_version_id"])

    for field, value in data.items():
        setattr(issue, field, value)

    _commit_or_conflict(db, "Issue update violates a catalog constraint")
    return read_issue(issue.id, db)


@router.get("/issues/{issue_id}/versions", response_model=list[IssueTypeVersionRead])
def list_issue_versions(issue_id: UUID, db: Session = Depends(get_db)):
    _get_issue(db, issue_id)
    stmt = (
        select(CatalogIssueTypeVersion)
        .where(CatalogIssueTypeVersion.issue_type_id == issue_id)
        .order_by(CatalogIssueTypeVersion.version_number)
    )
    return db.execute(stmt).scalars().all()


@router.post("/issues/{issue_id}/versions", response_model=IssueTypeVersionRead, status_code=status.HTTP_201_CREATED)
def create_issue_version(issue_id: UUID, payload: IssueTypeVersionCreate, db: Session = Depends(get_db)):
    issue = _get_issue(db, issue_id, for_update=True)
    version_number = payload.version_number
    if version_number is None:
        latest = db.execute(
            select(func.max(CatalogIssueTypeVersion.version_number)).where(
                CatalogIssueTypeVersion.issue_type_id == issue_id
            )
        ).scalar()
        version_number = (latest or 0) + 1
    else:
        existing = db.execute(
            select(CatalogIssueTypeVersion).where(
                CatalogIssueTypeVersion.issue_type_id == issue_id,
                CatalogIssueTypeVersion.version_number == version_number,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise _conflict("Issue type version number already exists")

    data = payload.model_dump(exclude={"make_current"}, exclude_none=True)
    data["version_number"] = version_number
    version = CatalogIssueTypeVersion(issue_type_id=issue_id, **data)
    db.add(version)

    try:
        db.flush()
        if payload.make_current:
            issue.current_version_id = version.id
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _conflict("Issue type version number already exists") from exc

    db.refresh(version)
    return version


@router.get("/snapshots", response_model=list[CatalogSnapshotRead])
def list_snapshots(db: Session = Depends(get_db)):
    stmt = (
        select(CatalogSnapshot)
        .options(joinedload(CatalogSnapshot.items).joinedload(CatalogSnapshotItem.issue_version))
        .order_by(CatalogSnapshot.captured_at.desc(), CatalogSnapshot.name)
    )
    return db.execute(stmt).unique().scalars().all()


@router.get("/snapshots/{snapshot_id}", response_model=CatalogSnapshotRead)
def read_snapshot(snapshot_id: UUID, db: Session = Depends(get_db)):
    stmt = (
        select(CatalogSnapshot)
        .where(CatalogSnapshot.id == snapshot_id)
        .options(joinedload(CatalogSnapshot.items).joinedload(CatalogSnapshotItem.issue_version))
    )
    snapshot = db.execute(stmt).unique().scalar_one_or_none()
    if snapshot is None:
        raise _not_found("Catalog snapshot not found")
    return snapshot


@router.post("/snapshots", response_model=CatalogSnapshotRead, status_code=status.HTTP_201_CREATED)
def create_snapshot(payload: CatalogSnapshotCreate, db: Session = Depends(get_db)):
    item_version_ids = [item.issue_type_version_id for item in payload.items]
    if len(item_version_ids) != len(set(item_version_ids)):
        raise _conflict("Duplicate issue type version in snapshot payload")

    for version_id in item_version_ids:
        _get_version(db, version_id)

    data = payload.model_dump(exclude={"items"}, exclude_none=True)
    snapshot = CatalogSnapshot(**data)
    db.add(snapshot)
    db.flush()

    for item in payload.items:
        db.add(CatalogSnapshotItem(catalog_snapshot_id=snapshot.id, **item.model_dump()))

    _commit_or_conflict(db, "Duplicate issue type version in snapshot")
    return read_snapshot(snapshot.id, db)


@router.post(
    "/snapshots/{snapshot_id}/items",
    response_model=CatalogSnapshotItemRead,
    status_code=status.HTTP_201_CREATED,
)
def attach_snapshot_item(snapshot_id: UUID, payload: CatalogSnapshotItemCreate, db: Session = Depends(get_db)):
    snapshot = db.get(CatalogSnapshot, snapshot_id)
    if snapshot is None:
        raise _not_found("Catalog snapshot not found")
    _get_version(db, payload.issue_type_version_id)

    item = CatalogSnapshotItem(catalog_snapshot_id=snapshot_id, **payload.model_dump())
    db.add(item)
    _commit_or_conflict(db, "Duplicate issue type version in snapshot")
    db.refresh(item)
    return item
