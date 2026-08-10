from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.models import Domain, Host, HostGroup, HostGroupMember, Organization
from app.schemas.inventory import (
    DomainCreate,
    DomainRead,
    DomainUpdate,
    HostCreate,
    HostGroupCreate,
    HostGroupMemberCreate,
    HostGroupMemberRead,
    HostGroupRead,
    HostGroupUpdate,
    HostRead,
    HostUpdate,
    OrganizationCreate,
    OrganizationRead,
    OrganizationUpdate,
)

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


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


def _get_organization(db: Session, organization_id: UUID) -> Organization:
    organization = db.get(Organization, organization_id)
    if organization is None:
        raise _not_found("Organization not found")
    return organization


def _get_domain(db: Session, domain_id: UUID) -> Domain:
    stmt = select(Domain).where(Domain.id == domain_id).options(joinedload(Domain.organization))
    domain = db.execute(stmt).unique().scalar_one_or_none()
    if domain is None:
        raise _not_found("Domain not found")
    return domain


def _get_host(db: Session, host_id: UUID) -> Host:
    stmt = select(Host).where(Host.id == host_id).options(joinedload(Host.domain).joinedload(Domain.organization))
    host = db.execute(stmt).unique().scalar_one_or_none()
    if host is None:
        raise _not_found("Host not found")
    return host


def _get_host_group(db: Session, host_group_id: UUID) -> HostGroup:
    stmt = select(HostGroup).where(HostGroup.id == host_group_id).options(joinedload(HostGroup.organization))
    host_group = db.execute(stmt).unique().scalar_one_or_none()
    if host_group is None:
        raise _not_found("Host group not found")
    return host_group


@router.get("/organizations", response_model=list[OrganizationRead])
def list_organizations(db: Session = Depends(get_db)):
    stmt = select(Organization).order_by(Organization.name)
    return db.execute(stmt).scalars().all()


@router.post("/organizations", response_model=OrganizationRead, status_code=status.HTTP_201_CREATED)
def create_organization(payload: OrganizationCreate, db: Session = Depends(get_db)):
    organization = Organization(**payload.model_dump())
    db.add(organization)
    _commit_or_conflict(db, "Organization name already exists")
    db.refresh(organization)
    return organization


@router.get("/organizations/{organization_id}", response_model=OrganizationRead)
def read_organization(organization_id: UUID, db: Session = Depends(get_db)):
    return _get_organization(db, organization_id)


@router.patch("/organizations/{organization_id}", response_model=OrganizationRead)
def update_organization(organization_id: UUID, payload: OrganizationUpdate, db: Session = Depends(get_db)):
    organization = _get_organization(db, organization_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(organization, field, value)
    _commit_or_conflict(db, "Organization update violates an inventory constraint")
    db.refresh(organization)
    return organization


@router.get("/domains", response_model=list[DomainRead])
def list_domains(organization_id: UUID | None = Query(default=None), db: Session = Depends(get_db)):
    stmt = select(Domain).options(joinedload(Domain.organization)).order_by(Domain.name)
    if organization_id is not None:
        stmt = stmt.where(Domain.organization_id == organization_id)
    return db.execute(stmt).unique().scalars().all()


@router.post("/domains", response_model=DomainRead, status_code=status.HTTP_201_CREATED)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)):
    _get_organization(db, payload.organization_id)
    domain = Domain(**payload.model_dump())
    db.add(domain)
    _commit_or_conflict(db, "Domain name already exists for organization")
    return _get_domain(db, domain.id)


@router.patch("/domains/{domain_id}", response_model=DomainRead)
def update_domain(domain_id: UUID, payload: DomainUpdate, db: Session = Depends(get_db)):
    domain = _get_domain(db, domain_id)
    data = payload.model_dump(exclude_unset=True)
    if "organization_id" in data:
        _get_organization(db, data["organization_id"])
    for field, value in data.items():
        setattr(domain, field, value)
    _commit_or_conflict(db, "Domain update violates an inventory constraint")
    return _get_domain(db, domain.id)


@router.get("/hosts", response_model=list[HostRead])
def list_hosts(
    organization_id: UUID | None = Query(default=None),
    domain_id: UUID | None = Query(default=None),
    db: Session = Depends(get_db),
):
    stmt = (
        select(Host)
        .join(Host.domain)
        .options(joinedload(Host.domain).joinedload(Domain.organization))
        .order_by(Host.hostname)
    )
    if domain_id is not None:
        stmt = stmt.where(Host.domain_id == domain_id)
    if organization_id is not None:
        stmt = stmt.where(Domain.organization_id == organization_id)
    return db.execute(stmt).unique().scalars().all()


@router.post("/hosts", response_model=HostRead, status_code=status.HTTP_201_CREATED)
def create_host(payload: HostCreate, db: Session = Depends(get_db)):
    _get_domain(db, payload.domain_id)
    host = Host(**payload.model_dump())
    db.add(host)
    _commit_or_conflict(db, "Host name already exists for domain")
    return _get_host(db, host.id)


@router.patch("/hosts/{host_id}", response_model=HostRead)
def update_host(host_id: UUID, payload: HostUpdate, db: Session = Depends(get_db)):
    host = _get_host(db, host_id)
    data = payload.model_dump(exclude_unset=True)
    if "domain_id" in data:
        _get_domain(db, data["domain_id"])
    for field, value in data.items():
        setattr(host, field, value)
    _commit_or_conflict(db, "Host update violates an inventory constraint")
    return _get_host(db, host.id)


@router.get("/host-groups", response_model=list[HostGroupRead])
def list_host_groups(organization_id: UUID | None = Query(default=None), db: Session = Depends(get_db)):
    stmt = select(HostGroup).options(joinedload(HostGroup.organization)).order_by(HostGroup.name)
    if organization_id is not None:
        stmt = stmt.where(HostGroup.organization_id == organization_id)
    return db.execute(stmt).unique().scalars().all()


@router.post("/host-groups", response_model=HostGroupRead, status_code=status.HTTP_201_CREATED)
def create_host_group(payload: HostGroupCreate, db: Session = Depends(get_db)):
    _get_organization(db, payload.organization_id)
    host_group = HostGroup(**payload.model_dump())
    db.add(host_group)
    _commit_or_conflict(db, "Host group name already exists for organization")
    return _get_host_group(db, host_group.id)


@router.patch("/host-groups/{host_group_id}", response_model=HostGroupRead)
def update_host_group(host_group_id: UUID, payload: HostGroupUpdate, db: Session = Depends(get_db)):
    host_group = _get_host_group(db, host_group_id)
    data = payload.model_dump(exclude_unset=True)
    if "organization_id" in data:
        _get_organization(db, data["organization_id"])
    for field, value in data.items():
        setattr(host_group, field, value)
    _commit_or_conflict(db, "Host group update violates an inventory constraint")
    return _get_host_group(db, host_group.id)


@router.get("/host-groups/{host_group_id}/members", response_model=list[HostGroupMemberRead])
def list_host_group_members(host_group_id: UUID, db: Session = Depends(get_db)):
    _get_host_group(db, host_group_id)
    stmt = (
        select(HostGroupMember)
        .where(HostGroupMember.host_group_id == host_group_id)
        .options(joinedload(HostGroupMember.host).joinedload(Host.domain).joinedload(Domain.organization))
        .order_by(HostGroupMember.created_at)
    )
    return db.execute(stmt).unique().scalars().all()


@router.post(
    "/host-groups/{host_group_id}/members",
    response_model=HostGroupMemberRead,
    status_code=status.HTTP_201_CREATED,
)
def add_host_group_member(
    host_group_id: UUID,
    payload: HostGroupMemberCreate,
    db: Session = Depends(get_db),
):
    host_group = _get_host_group(db, host_group_id)
    host = _get_host(db, payload.host_id)
    if host.domain.organization_id != host_group.organization_id:
        raise _bad_request("Host must belong to the same organization as the host group")

    member = HostGroupMember(host_id=host.id, host_group_id=host_group.id)
    db.add(member)
    _commit_or_conflict(db, "Host is already in this host group")
    db.refresh(member)
    return member
