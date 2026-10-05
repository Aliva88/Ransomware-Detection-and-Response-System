from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"


def test_config_endpoint():

    response = client.get("/api/config")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert "config" in data

    config = data["config"]

    assert "app" in config
    assert "monitoring" in config
    assert "detection" in config
    assert "scoring" in config


def test_status_endpoint():

    response = client.get("/api/status")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "active"
    assert "monitoring" in data
    assert "monitor_running" in data
    assert "system" in data


def test_incidents_endpoint():

    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"
    assert "count" in data
    assert "incidents" in data

    incidents = data["incidents"]

    assert isinstance(incidents, list)

    if len(incidents) > 0:

        incident = incidents[0]

        assert "id" in incident
        assert "incident_type" in incident
        assert "severity" in incident
        assert "description" in incident
        assert "status" in incident
        assert "timestamp" in incident


def test_dashboard_endpoint():

    response = client.get("/api/dashboard")

    assert response.status_code == 200

    data = response.json()

    assert "system" in data
    assert data["status"] == "active"

    assert "threat" in data
    assert "score" in data["threat"]
    assert "level" in data["threat"]

    assert "incident_count" in data
    assert "open_incidents" in data

    assert data["incident_count"] >= 0
    assert data["open_incidents"] >= 0