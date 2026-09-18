from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.db.session import SessionLocal
from app.models.score_models import ScoreResult
from app.services.score_results import build_score_result
from app.services.scoring_engine import ScoringDefinition
from tests.test_scans_api import _host

client = TestClient(app)


def linked_rule(path="service.exposed", value=True):
    suffix = uuid4().hex[:12]
    factor = client.post("/api/v1/catalog/factors", json={"code": f"web-{suffix}", "name": "Web"}).json()
    issue = client.post("/api/v1/catalog/issues", json={"stable_key": f"issue-{suffix}", "factor_id": factor["id"]}).json()
    iv = client.post(f"/api/v1/catalog/issues/{issue['id']}/versions", json={"name": "Original finding", "breach_risk": "HIGH", "affects_score": True, "source_type": "MANUAL", "make_current": True}).json()
    rule = client.post("/api/v1/rules", json={"stable_key": f"rule-{suffix}", "catalog_issue_type_id": issue["id"]}).json()
    rv = client.post(f"/api/v1/rules/{rule['id']}/versions", json={"name": "Original rule", "target_type": "HOST", "rule_expression": {"operator": "equals", "path": path, "value": value}, "source_type": "INTERNAL", "remediation": "Original remediation", "make_current": True}).json()
    return factor, issue, iv, rule, rv


def test_score_snapshot_uses_exact_versions_and_survives_current_definition_changes():
    _, _, host = _host()
    factor, issue, iv, rule, rv = linked_rule()
    job = client.post("/api/v1/scans/jobs", json={"name": "Snapshot test", "rule_ids": [rule["id"]], "targets": [{"target_type": "HOST", "host_id": host["id"], "evidence": {"service": {"exposed": True}}}]}).json()
    run = client.post(f"/api/v1/scans/jobs/{job['id']}/run").json()
    assert run["status"] == "COMPLETED"
    # Modify current identities BEFORE normalization; historical versions and factor metadata must survive.
    client.post(f"/api/v1/catalog/issues/{issue['id']}/versions", json={"name": "New definition", "breach_risk": "LOW", "source_type": "MANUAL", "make_current": True})
    client.patch(f"/api/v1/catalog/factors/{factor['id']}", json={"code": "changed-" + uuid4().hex[:12], "name": "Changed"})
    client.post(f"/api/v1/rules/{rule['id']}/versions", json={"name": "New rule", "target_type": "HOST", "rule_expression": {"operator": "exists", "path": "something"}, "remediation": "New remediation", "make_current": True})
    with SessionLocal() as db:
        result = build_score_result(db, UUID(run["id"]))
        assert result.overall_score == 85
        assert result.findings[0].title == "Original finding"
        assert result.findings[0].remediation == "Original remediation"
        assert result.findings[0].catalog_issue_type_version_id == iv["id"]
        assert result.findings[0].rule_version_id == rv["id"]
        assert result.factor_scores[0].code == factor["code"]
        assert result.targets[0].name == host["hostname"]
        assert build_score_result(db, UUID(run["id"])).model_dump() == result.model_dump()
        snapshots = db.execute(select(ScoreResult).where(ScoreResult.scan_run_id == UUID(run["id"]))).scalars().all()
        assert len(snapshots) == 1
        new_model = ScoringDefinition(version="2", penalties={"HIGH": 20, "MEDIUM": 7, "LOW": 2})
        rescored = build_score_result(db, UUID(run["id"]), new_model)
        assert rescored.overall_score == 80
        assert rescored.scoring_model_hash != result.scoring_model_hash
