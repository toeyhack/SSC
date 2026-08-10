from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _baseline_payload():
    suffix = uuid4().hex[:12]
    return {
        "schema_version": "phase1b.ssc_licensed_ui.v1",
        "name": f"Phase 1C admin baseline {suffix}",
        "source_type": "SSC_LICENSED_UI",
        "source_reference": f"phase1c-admin-{suffix}",
        "captured_at": "2026-08-10T03:00:00Z",
        "notes": "Synthetic admin API fixture; not real SSC content.",
        "factors": [
            {
                "code": f"phase1c_admin_factor_{suffix}",
                "name": "Phase 1C Admin Factor",
                "position": 1,
                "issues": [
                    {
                        "stable_key": f"phase1c.admin.{suffix}.issue",
                        "name": "Phase 1C admin issue",
                        "description": "Synthetic admin review issue.",
                        "breach_risk": "LOW",
                        "threat_level": "LOW",
                        "affects_score": True,
                        "position": 1,
                    }
                ],
            }
        ],
    }


def test_golden_baseline_preview_and_import_endpoints_are_idempotent():
    payload = _baseline_payload()

    preview = client.post("/api/v1/catalog/golden-baseline/preview", json=payload)
    assert preview.status_code == 200
    preview_body = preview.json()
    assert preview_body["dry_run"] is True
    assert preview_body["snapshot_action"] == "create"
    assert preview_body["factors_created"] == 1
    assert preview_body["issues_created"] == 1
    assert preview_body["versions_created"] == 1

    created = client.post("/api/v1/catalog/golden-baseline/import", json=payload)
    assert created.status_code == 201
    created_body = created.json()
    assert created_body["dry_run"] is False
    assert created_body["snapshot_action"] == "create"
    assert created_body["snapshot_id"] is not None
    assert created_body["content_hash"] == preview_body["content_hash"]

    repeated = client.post("/api/v1/catalog/golden-baseline/import", json=payload)
    assert repeated.status_code == 200
    repeated_body = repeated.json()
    assert repeated_body["snapshot_action"] == "reused_existing"
    assert repeated_body["snapshot_id"] == created_body["snapshot_id"]


def test_golden_baseline_preview_rejects_ambiguous_issue_name():
    payload = _baseline_payload()
    created = client.post("/api/v1/catalog/golden-baseline/import", json=payload)
    assert created.status_code == 201

    payload["name"] = f"Phase 1C collision {uuid4().hex[:12]}"
    payload["captured_at"] = "2026-08-11T03:00:00Z"
    payload["factors"][0]["issues"][0]["stable_key"] = f"phase1c.admin.{uuid4().hex[:12]}.different"

    preview = client.post("/api/v1/catalog/golden-baseline/preview", json=payload)
    assert preview.status_code == 400
    assert "matches existing stable_key" in str(preview.json()["detail"])
