import pytest

from helpers import open_sg
from misconfig.api import create_app


@pytest.fixture
def client(aws, store):
    app = create_app(store, session_factory=lambda: aws)
    return app.test_client()


def test_health_and_dashboard(client):
    assert client.get("/health").json == {"status": "ok"}
    assert b"<div id=\"app\"" in client.get("/").data


def test_checks_endpoint(client):
    data = client.get("/api/checks").json
    assert len(data) == 47 and any(c["auto_remediable"] for c in data)


def test_scan_flow(client, aws):
    open_sg(aws, 22)
    created = client.post("/api/scans", json={"regions": ["us-east-1"]})
    assert created.status_code == 201
    sid = created.json["id"]
    assert client.get("/api/scans").json[0]["id"] == sid
    assert client.get(f"/api/scans/{sid}").json["grade"] in "ABCDF"
    crit = client.get(f"/api/scans/{sid}/findings?severity=CRITICAL").json
    ssh = next(f for f in crit if f["check_id"] == "EC2-001")
    report = client.get(f"/api/scans/{sid}/report").json
    assert report["by_service"] and report["top_resources"] and report["trend"]

    dry = client.post(f"/api/findings/{ssh['id']}/remediate", json={}).json
    assert dry["status"] == "dry_run"
    done = client.post(f"/api/findings/{ssh['id']}/remediate", json={"dry_run": False}).json
    assert done["status"] == "remediated"
    assert client.get(f"/api/scans/{sid}/findings?status=REMEDIATED").json[0]["id"] == ssh["id"]


def test_errors(client):
    assert client.get("/api/scans/999").status_code == 404
    assert client.post("/api/findings/999/remediate").status_code == 404
    assert client.post("/api/scans", json={"regions": "us-east-1"}).status_code == 400


def test_token_required_when_configured(aws, store, monkeypatch):
    monkeypatch.setenv("API_TOKEN", "s3cret")
    c = create_app(store, session_factory=lambda: aws).test_client()
    assert c.post("/api/scans", json={}).status_code == 401
    assert c.post("/api/scans", json={}, headers={"Authorization": "Bearer s3cret"}).status_code == 201
    assert c.get("/api/scans").status_code == 200  # reads stay open
