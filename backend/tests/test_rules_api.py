from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _suffix() -> str:
    return uuid4().hex[:12]


def _catalog_issue(suffix: str):
    factor = client.post(
        "/api/v1/catalog/factors",
        json={"code": f"rule-factor-{suffix}", "name": "Rule Factor", "display_order": 30},
    ).json()
    issue = client.post(
        "/api/v1/catalog/issues",
        json={"stable_key": f"rule.issue.{suffix}", "factor_id": factor["id"]},
    ).json()
    client.post(
        f"/api/v1/catalog/issues/{issue['id']}/versions",
        json={
            "name": "Rule linked catalog issue",
            "breach_risk": "MEDIUM",
            "threat_level": "MEDIUM",
            "affects_score": True,
            "source_type": "MANUAL",
            "make_current": True,
        },
    )
    return issue


def test_rule_lifecycle_version_history_and_catalog_linkage():
    suffix = _suffix()
    catalog_issue = _catalog_issue(suffix)

    create_rule = client.post(
        "/api/v1/rules",
        json={
            "stable_key": f"dns.rule.{suffix}",
            "catalog_issue_type_id": catalog_issue["id"],
        },
    )
    assert create_rule.status_code == 201
    rule = create_rule.json()
    assert rule["stable_key"] == f"dns.rule.{suffix}"
    assert rule["catalog_issue_type_id"] == catalog_issue["id"]
    assert rule["current_version_id"] is None

    duplicate = client.post("/api/v1/rules", json={"stable_key": f"dns.rule.{suffix}"})
    assert duplicate.status_code == 409

    first_version = client.post(
        f"/api/v1/rules/{rule['id']}/versions",
        json={
            "name": "DNS MX record present",
            "description": "Manual rule definition only; no scanner execution.",
            "target_type": "DOMAIN",
            "rule_expression": {
                "operator": "exists",
                "path": "dns.mx.records",
            },
            "evidence_schema": {
                "required": ["domain", "records"],
            },
            "remediation": "Publish an MX record when mail handling is expected.",
            "source_type": "MANUAL",
            "make_current": True,
        },
    )
    assert first_version.status_code == 201
    v1 = first_version.json()
    assert v1["version_number"] == 1
    assert v1["rule_expression"]["operator"] == "exists"

    second_version = client.post(
        f"/api/v1/rules/{rule['id']}/versions",
        json={
            "name": "DNS MX record present",
            "description": "Definition revised without overwriting version 1.",
            "target_type": "DOMAIN",
            "rule_expression": {
                "operator": "exists",
                "path": "dns.mx.records",
                "minimum_count": 1,
            },
            "source_type": "INTERNAL",
            "make_current": True,
        },
    )
    assert second_version.status_code == 201
    v2 = second_version.json()
    assert v2["version_number"] == 2

    versions = client.get(f"/api/v1/rules/{rule['id']}/versions")
    assert versions.status_code == 200
    history = versions.json()
    assert [version["version_number"] for version in history] == [1, 2]
    assert history[0]["description"] == "Manual rule definition only; no scanner execution."

    read_rule = client.get(f"/api/v1/rules/{rule['id']}")
    assert read_rule.status_code == 200
    assert read_rule.json()["current_version_id"] == v2["id"]
    assert read_rule.json()["current_version"]["description"] == "Definition revised without overwriting version 1."


def test_rule_current_version_must_belong_to_same_rule_and_list_endpoint_available():
    suffix = _suffix()
    rule_a = client.post("/api/v1/rules", json={"stable_key": f"rule.a.{suffix}"}).json()
    rule_b = client.post("/api/v1/rules", json={"stable_key": f"rule.b.{suffix}"}).json()
    version_b = client.post(
        f"/api/v1/rules/{rule_b['id']}/versions",
        json={
            "name": "Rule B version",
            "target_type": "HOST",
            "rule_expression": {"operator": "equals", "path": "port.state", "value": "open"},
            "source_type": "MANUAL",
        },
    ).json()

    invalid_current = client.patch(f"/api/v1/rules/{rule_a['id']}", json={"current_version_id": version_b["id"]})
    assert invalid_current.status_code == 400

    listed = client.get("/api/v1/rules")
    assert listed.status_code == 200
    assert any(item["id"] == rule_a["id"] for item in listed.json())


def test_rule_validation_rejects_invalid_catalog_link_and_empty_expression():
    invalid_catalog = client.post("/api/v1/rules", json={"stable_key": f"rule.invalid.{_suffix()}", "catalog_issue_type_id": str(uuid4())})
    assert invalid_catalog.status_code == 400

    rule = client.post("/api/v1/rules", json={"stable_key": f"rule.empty-expression.{_suffix()}"}).json()
    invalid_version = client.post(
        f"/api/v1/rules/{rule['id']}/versions",
        json={
            "name": "Invalid empty expression",
            "target_type": "HOST",
            "rule_expression": {},
            "source_type": "MANUAL",
        },
    )
    assert invalid_version.status_code == 422
