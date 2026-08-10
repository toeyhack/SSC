from copy import deepcopy
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.catalog_models import (
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.services.golden_baseline_importer import (
    GoldenBaselineImportError,
    GoldenBaselineInput,
    compute_baseline_content_hash,
    import_golden_baseline,
)


def _suffix() -> str:
    return uuid4().hex[:12]


def _baseline(*, suffix: str | None = None) -> GoldenBaselineInput:
    suffix = suffix or _suffix()
    return GoldenBaselineInput.model_validate(
        {
            "schema_version": "phase1b.ssc_licensed_ui.v1",
            "name": f"Phase 1B baseline {suffix}",
            "source_type": "SSC_LICENSED_UI",
            "source_reference": f"licensed-ui-capture-{suffix}",
            "captured_at": "2026-08-06T18:30:00Z",
            "notes": "Synthetic test baseline; not real SSC content.",
            "factors": [
                {
                    "code": f"phase1b_network_{suffix}",
                    "name": "Network Security",
                    "position": 1,
                    "issues": [
                        {
                            "stable_key": f"phase1b.network.{suffix}.tls_expired",
                            "name": "TLS certificate expired",
                            "description": "Original definition",
                            "breach_risk": "HIGH",
                            "threat_level": "HIGH",
                            "affects_score": True,
                            "position": 1,
                        },
                        {
                            "stable_key": f"phase1b.network.{suffix}.secure_tls",
                            "name": "Secure TLS observed",
                            "description": "Positive observation",
                            "breach_risk": "POSITIVE",
                            "threat_level": "POSITIVE",
                            "affects_score": False,
                            "position": 2,
                        },
                    ],
                }
            ],
        }
    )


def test_dry_run_previews_without_creating_snapshot():
    baseline = _baseline()
    content_hash = compute_baseline_content_hash(baseline)

    with SessionLocal() as db:
        result = import_golden_baseline(db, baseline, dry_run=True)
        snapshot_count = db.execute(
            select(func.count()).select_from(CatalogSnapshot).where(CatalogSnapshot.content_hash == content_hash)
        ).scalar_one()

    assert result.dry_run is True
    assert result.snapshot_action == "create"
    assert result.factors_created == 1
    assert result.issues_created == 2
    assert result.versions_created == 2
    assert result.snapshot_items == 2
    assert snapshot_count == 0


def test_import_creates_immutable_snapshot_items_and_reuses_exact_baseline():
    baseline = _baseline()
    content_hash = compute_baseline_content_hash(baseline)

    with SessionLocal() as db:
        first = import_golden_baseline(db, baseline)
        second = import_golden_baseline(db, baseline)

        snapshots = db.execute(
            select(CatalogSnapshot).where(CatalogSnapshot.content_hash == content_hash)
        ).scalars().all()
        items = db.execute(
            select(CatalogSnapshotItem)
            .where(CatalogSnapshotItem.catalog_snapshot_id == first.snapshot_id)
            .order_by(CatalogSnapshotItem.factor_position, CatalogSnapshotItem.issue_position)
        ).scalars().all()

    assert first.snapshot_action == "create"
    assert first.snapshot_id is not None
    assert first.snapshot_items == 2
    assert first.versions_created == 2
    assert second.snapshot_action == "reused_existing"
    assert second.snapshot_id == first.snapshot_id
    assert len(snapshots) == 1
    assert snapshots[0].source_type == SourceTypeEnum.SSC_LICENSED_UI
    assert [(item.factor_position, item.issue_position) for item in items] == [(1, 1), (1, 2)]


def test_changed_definition_creates_new_issue_type_version_only_once():
    suffix = _suffix()
    baseline = _baseline(suffix=suffix)
    changed_payload = baseline.model_dump(mode="json")
    changed_payload["name"] = f"Phase 1B changed baseline {suffix}"
    changed_payload["captured_at"] = "2026-08-07T18:30:00Z"
    changed_payload["factors"][0]["issues"][0]["description"] = "Changed definition"
    changed = GoldenBaselineInput.model_validate(changed_payload)

    with SessionLocal() as db:
        first = import_golden_baseline(db, baseline)
        second = import_golden_baseline(db, changed)
        third = import_golden_baseline(db, changed)

        issue = db.execute(
            select(CatalogIssueType).where(
                CatalogIssueType.stable_key == f"phase1b.network.{suffix}.tls_expired"
            )
        ).scalar_one()
        versions = db.execute(
            select(CatalogIssueTypeVersion)
            .where(CatalogIssueTypeVersion.issue_type_id == issue.id)
            .order_by(CatalogIssueTypeVersion.version_number)
        ).scalars().all()

    assert first.versions_created == 2
    assert second.snapshot_action == "create"
    assert second.versions_created == 1
    assert third.snapshot_action == "reused_existing"
    assert [version.version_number for version in versions] == [1, 2]
    assert versions[0].description == "Original definition"
    assert versions[1].description == "Changed definition"
    assert issue.current_version_id == versions[1].id


def test_ambiguous_issue_name_collision_is_rejected():
    baseline = _baseline()
    colliding_payload = deepcopy(baseline.model_dump(mode="json"))
    colliding_payload["name"] = f"Phase 1B collision {uuid4().hex[:12]}"
    colliding_payload["captured_at"] = "2026-08-08T18:30:00Z"
    colliding_payload["factors"][0]["issues"][0]["stable_key"] = (
        f"phase1b.network.{uuid4().hex[:12]}.different_key"
    )
    colliding = GoldenBaselineInput.model_validate(colliding_payload)

    with SessionLocal() as db:
        import_golden_baseline(db, baseline)
        with pytest.raises(GoldenBaselineImportError) as excinfo:
            import_golden_baseline(db, colliding, dry_run=True)

    assert "matches existing stable_key" in str(excinfo.value)


def test_baseline_schema_rejects_invalid_source_ordering_and_threat_level():
    payload = _baseline().model_dump(mode="json")
    payload["source_type"] = "SSC_PUBLIC_WEB"
    with pytest.raises(ValidationError):
        GoldenBaselineInput.model_validate(payload)

    payload = _baseline().model_dump(mode="json")
    payload["factors"][0]["issues"][0]["threat_level"] = "CRITICAL"
    with pytest.raises(ValidationError):
        GoldenBaselineInput.model_validate(payload)

    payload = _baseline().model_dump(mode="json")
    payload["factors"][0]["issues"][0]["position"] = 3
    with pytest.raises(ValidationError):
        GoldenBaselineInput.model_validate(payload)
