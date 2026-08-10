from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _suffix() -> str:
    return uuid4().hex[:12]


def test_inventory_organization_domain_host_lifecycle_and_duplicates():
    suffix = _suffix()

    org_resp = client.post(
        "/api/v1/inventory/organizations",
        json={"name": f"Example Org {suffix}", "description": "Inventory test org"},
    )
    assert org_resp.status_code == 201
    organization = org_resp.json()
    assert organization["active"] is True

    duplicate_org = client.post("/api/v1/inventory/organizations", json={"name": organization["name"]})
    assert duplicate_org.status_code == 409

    domain_resp = client.post(
        "/api/v1/inventory/domains",
        json={
            "organization_id": organization["id"],
            "name": f"WWW-{suffix}.Example.COM.",
            "description": "Primary domain",
        },
    )
    assert domain_resp.status_code == 201
    domain = domain_resp.json()
    assert domain["name"] == f"www-{suffix}.example.com"
    assert domain["organization"]["id"] == organization["id"]

    duplicate_domain = client.post(
        "/api/v1/inventory/domains",
        json={"organization_id": organization["id"], "name": f"www-{suffix}.example.com"},
    )
    assert duplicate_domain.status_code == 409

    host_resp = client.post(
        "/api/v1/inventory/hosts",
        json={
            "domain_id": domain["id"],
            "hostname": f"APP-{suffix}.WWW-{suffix}.Example.COM.",
            "ip": "203.0.113.10",
        },
    )
    assert host_resp.status_code == 201
    host = host_resp.json()
    assert host["hostname"] == f"app-{suffix}.www-{suffix}.example.com"
    assert host["domain"]["id"] == domain["id"]

    duplicate_host = client.post(
        "/api/v1/inventory/hosts",
        json={"domain_id": domain["id"], "hostname": host["hostname"]},
    )
    assert duplicate_host.status_code == 409

    patched = client.patch(f"/api/v1/inventory/hosts/{host['id']}", json={"active": False})
    assert patched.status_code == 200
    assert patched.json()["active"] is False

    hosts = client.get(f"/api/v1/inventory/hosts?organization_id={organization['id']}")
    assert hosts.status_code == 200
    assert any(item["id"] == host["id"] for item in hosts.json())


def test_host_group_membership_requires_same_organization_and_is_unique():
    suffix = _suffix()
    org_a = client.post("/api/v1/inventory/organizations", json={"name": f"Org A {suffix}"}).json()
    org_b = client.post("/api/v1/inventory/organizations", json={"name": f"Org B {suffix}"}).json()
    domain_a = client.post(
        "/api/v1/inventory/domains",
        json={"organization_id": org_a["id"], "name": f"a-{suffix}.example.com"},
    ).json()
    domain_b = client.post(
        "/api/v1/inventory/domains",
        json={"organization_id": org_b["id"], "name": f"b-{suffix}.example.com"},
    ).json()
    host_a = client.post(
        "/api/v1/inventory/hosts",
        json={"domain_id": domain_a["id"], "hostname": f"host-a.{domain_a['name']}"},
    ).json()
    host_b = client.post(
        "/api/v1/inventory/hosts",
        json={"domain_id": domain_b["id"], "hostname": f"host-b.{domain_b['name']}"},
    ).json()

    group = client.post(
        "/api/v1/inventory/host-groups",
        json={"organization_id": org_a["id"], "name": f"Production {suffix}"},
    ).json()

    member = client.post(f"/api/v1/inventory/host-groups/{group['id']}/members", json={"host_id": host_a["id"]})
    assert member.status_code == 201
    assert member.json()["host_id"] == host_a["id"]

    duplicate = client.post(f"/api/v1/inventory/host-groups/{group['id']}/members", json={"host_id": host_a["id"]})
    assert duplicate.status_code == 409

    cross_org = client.post(f"/api/v1/inventory/host-groups/{group['id']}/members", json={"host_id": host_b["id"]})
    assert cross_org.status_code == 400

    members = client.get(f"/api/v1/inventory/host-groups/{group['id']}/members")
    assert members.status_code == 200
    assert len(members.json()) == 1
