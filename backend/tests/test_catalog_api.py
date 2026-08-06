from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _suffix() -> str:
    return uuid4().hex[:12]


def test_factor_create_list_read_and_duplicate_code():
    suffix = _suffix()
    payload = {
        "code": f"factor-{suffix}",
        "name": "Application Security",
        "description": "Internal test factor",
        "display_order": 10,
    }

    created = client.post("/api/v1/catalog/factors", json=payload)
    assert created.status_code == 201
    factor = created.json()
    assert factor["code"] == payload["code"]
    assert factor["is_active"] is True

    listed = client.get("/api/v1/catalog/factors")
    assert listed.status_code == 200
    assert any(item["id"] == factor["id"] for item in listed.json())

    read = client.get(f"/api/v1/catalog/factors/{factor['id']}")
    assert read.status_code == 200
    assert read.json()["name"] == payload["name"]

    duplicate = client.post("/api/v1/catalog/factors", json=payload)
    assert duplicate.status_code == 409


def test_issue_catalog_version_history_snapshots_and_validation_errors():
    suffix = _suffix()
    factor = client.post(
        "/api/v1/catalog/factors",
        json={"code": f"network-{suffix}", "name": "Network Security", "display_order": 20},
    ).json()

    issue_payload = {"stable_key": f"tls-expiry-{suffix}", "factor_id": factor["id"]}
    created_issue = client.post("/api/v1/catalog/issues", json=issue_payload)
    assert created_issue.status_code == 201
    issue = created_issue.json()
    assert issue["stable_key"] == issue_payload["stable_key"]
    assert issue["current_version_id"] is None

    duplicate_issue = client.post("/api/v1/catalog/issues", json=issue_payload)
    assert duplicate_issue.status_code == 409

    invalid_parent = client.post(
        f"/api/v1/catalog/issues/{uuid4()}/versions",
        json={
            "name": "Invalid parent",
            "breach_risk": "HIGH",
            "affects_score": True,
            "source_type": "MANUAL",
        },
    )
    assert invalid_parent.status_code == 404

    first_version_payload = {
        "name": "Certificate expires soon",
        "description": "Original definition",
        "breach_risk": "HIGH",
        "threat_level": "HIGH",
        "affects_score": True,
        "source_type": "MANUAL",
        "source_reference": "phase1a-test",
        "make_current": True,
    }
    first_version = client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json=first_version_payload,
    )
    assert first_version.status_code == 201
    v1 = first_version.json()
    assert v1["version_number"] == 1
    assert v1["breach_risk"] == "HIGH"

    second_version_payload = {
        "name": "Certificate expires within policy window",
        "description": "Updated definition",
        "breach_risk": "MEDIUM",
        "threat_level": "MEDIUM",
        "affects_score": True,
        "source_type": "MANUAL",
        "make_current": True,
    }
    second_version = client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json=second_version_payload,
    )
    assert second_version.status_code == 201
    v2 = second_version.json()
    assert v2["version_number"] == 2

    duplicate_version = client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json={**second_version_payload, "version_number": 2},
    )
    assert duplicate_version.status_code == 409

    versions = client.get(f"/api/v1/catalog/issues/{issue['id']}/versions")
    assert versions.status_code == 200
    history = versions.json()
    assert [item["version_number"] for item in history] == [1, 2]
    assert history[0]["name"] == first_version_payload["name"]
    assert history[0]["description"] == "Original definition"

    current_issue = client.get(f"/api/v1/catalog/issues/{issue['id']}")
    assert current_issue.status_code == 200
    assert current_issue.json()["current_version_id"] == v2["id"]
    assert current_issue.json()["current_version"]["name"] == second_version_payload["name"]

    informational = client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json={
            "name": "Certificate transparency observed",
            "breach_risk": "INFORMATIONAL",
            "affects_score": False,
            "source_type": "MANUAL",
        },
    )
    assert informational.status_code == 201
    assert informational.json()["breach_risk"] == "INFORMATIONAL"

    positive = client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json={
            "name": "Strong TLS configuration",
            "breach_risk": "POSITIVE",
            "affects_score": False,
            "source_type": "MANUAL",
        },
    )
    assert positive.status_code == 201
    assert positive.json()["breach_risk"] == "POSITIVE"

    other_issue = client.post(
        "/api/v1/catalog/issues",
        json={"stable_key": f"other-{suffix}", "factor_id": factor["id"]},
    ).json()
    other_version = client.post(
        f"/api/v1/catalog/issues/{other_issue['id']}/versions",
        json={
            "name": "Other issue version",
            "breach_risk": "LOW",
            "affects_score": True,
            "source_type": "MANUAL",
        },
    ).json()
    invalid_current = client.patch(
        f"/api/v1/catalog/issues/{issue['id']}",
        json={"current_version_id": other_version["id"]},
    )
    assert invalid_current.status_code == 400

    snapshot_payload = {
        "name": f"Phase 1A snapshot {suffix}",
        "source_type": "MANUAL",
        "content_hash": uuid4().hex,
        "notes": "Snapshot should preserve the original version reference",
        "items": [
            {
                "issue_type_version_id": v1["id"],
                "factor_position": 1,
                "issue_position": 1,
            }
        ],
    }
    created_snapshot = client.post("/api/v1/catalog/snapshots", json=snapshot_payload)
    assert created_snapshot.status_code == 201
    snapshot = created_snapshot.json()
    assert snapshot["items"][0]["issue_type_version_id"] == v1["id"]
    assert snapshot["items"][0]["issue_version"]["name"] == first_version_payload["name"]

    duplicate_item = client.post(
        f"/api/v1/catalog/snapshots/{snapshot['id']}/items",
        json={"issue_type_version_id": v1["id"]},
    )
    assert duplicate_item.status_code == 409

    read_snapshot = client.get(f"/api/v1/catalog/snapshots/{snapshot['id']}")
    assert read_snapshot.status_code == 200
    historical_item = read_snapshot.json()["items"][0]
    assert historical_item["issue_type_version_id"] == v1["id"]
    assert historical_item["issue_version"]["description"] == "Original definition"

    snapshots = client.get("/api/v1/catalog/snapshots")
    assert snapshots.status_code == 200
    assert any(item["id"] == snapshot["id"] for item in snapshots.json())


def test_catalog_list_endpoints_are_available():
    assert client.get("/api/v1/catalog/factors").status_code == 200
    assert client.get("/api/v1/catalog/issues").status_code == 200
    assert client.get("/api/v1/catalog/snapshots").status_code == 200
