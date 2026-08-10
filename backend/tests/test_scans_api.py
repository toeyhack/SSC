from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _suffix() -> str:
    return uuid4().hex[:12]


def _host():
    suffix = _suffix()
    org = client.post("/api/v1/inventory/organizations", json={"name": f"Scan Org {suffix}"}).json()
    domain = client.post(
        "/api/v1/inventory/domains",
        json={"organization_id": org["id"], "name": f"scan-{suffix}.example.com"},
    ).json()
    host = client.post(
        "/api/v1/inventory/hosts",
        json={"domain_id": domain["id"], "hostname": f"app.scan-{suffix}.example.com"},
    ).json()
    return org, domain, host


def _rule(target_type: str = "HOST"):
    suffix = _suffix()
    rule = client.post("/api/v1/rules", json={"stable_key": f"scan.rule.{suffix}"}).json()
    version = client.post(
        f"/api/v1/rules/{rule['id']}/versions",
        json={
            "name": "Detected exposed test service",
            "target_type": target_type,
            "rule_expression": {"operator": "equals", "path": "service.exposed", "value": True},
            "evidence_schema": {"required": ["service"]},
            "source_type": "INTERNAL",
            "make_current": True,
        },
    ).json()
    return rule, version


def test_scan_job_run_creates_findings_with_exact_rule_version():
    _org, _domain, host = _host()
    rule, version = _rule()

    job_resp = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "Synthetic host scan",
            "requested_by": "pytest",
            "rule_ids": [rule["id"]],
            "targets": [
                {
                    "target_type": "HOST",
                    "host_id": host["id"],
                    "evidence": {"service": {"exposed": True}},
                }
            ],
        },
    )
    assert job_resp.status_code == 201
    job = job_resp.json()
    assert job["status"] == "QUEUED"
    assert job["selected_rule_ids"] == [rule["id"]]

    run_resp = client.post(f"/api/v1/scans/jobs/{job['id']}/run")
    assert run_resp.status_code == 201
    run = run_resp.json()
    assert run["status"] == "COMPLETED"
    assert run["summary"]["targets"] == 1
    assert run["summary"]["rules_evaluated"] == 1
    assert run["summary"]["findings_created"] == 1

    findings = client.get(f"/api/v1/scans/runs/{run['id']}/findings")
    assert findings.status_code == 200
    finding = findings.json()[0]
    assert finding["host_id"] == host["id"]
    assert finding["rule_id"] == rule["id"]
    assert finding["rule_version_id"] == version["id"]
    assert finding["status"] == "OPEN"
    assert finding["evidence"]["matched_expression"]["path"] == "service.exposed"

    rerun = client.post(f"/api/v1/scans/jobs/{job['id']}/run")
    assert rerun.status_code == 400


def test_scan_job_with_nonmatching_evidence_completes_without_findings():
    _org, _domain, host = _host()
    rule, _version = _rule()

    job = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "No finding scan",
            "rule_ids": [rule["id"]],
            "targets": [
                {
                    "target_type": "HOST",
                    "host_id": host["id"],
                    "evidence": {"service": {"exposed": False}},
                }
            ],
        },
    ).json()

    run = client.post(f"/api/v1/scans/jobs/{job['id']}/run").json()
    assert run["summary"]["findings_created"] == 0
    findings = client.get(f"/api/v1/scans/runs/{run['id']}/findings")
    assert findings.status_code == 200
    assert findings.json() == []


def test_scan_job_validation_rejects_unknown_targets_and_rules():
    unknown_host = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "Invalid target",
            "targets": [{"target_type": "HOST", "host_id": str(uuid4())}],
        },
    )
    assert unknown_host.status_code == 400

    _org, _domain, host = _host()
    unknown_rule = client.post(
        "/api/v1/scans/jobs",
        json={
            "name": "Invalid rule",
            "rule_ids": [str(uuid4())],
            "targets": [{"target_type": "HOST", "host_id": host["id"]}],
        },
    )
    assert unknown_rule.status_code == 400
