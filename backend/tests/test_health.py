from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["message"] == "SSC Backend - Phase 0"

def test_health_ping():
    resp = client.get("/health/ping")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
