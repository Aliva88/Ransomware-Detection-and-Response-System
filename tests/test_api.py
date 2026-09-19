from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_endpoint():

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "running"


def test_config_endpoint():

    response = client.get("/api/config")

    assert response.status_code == 200

    data = response.json()

    assert "app" in data
    assert "monitoring" in data
    assert "detection" in data
    assert "scoring" in data


def test_status_endpoint():

    response = client.get("/api/status")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "active"
    assert data["simulation_mode"] is True
    assert "threat_score" in data
    assert "threat_level" in data


def test_incidents_endpoint():

    response = client.get("/api/incidents")

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)

    if len(data) > 0:
        incident = data[0]

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

    assert data["system"] == (
        "Ransomware Detection and Response System"
    )

    assert data["status"] == "active"
    assert data["simulation_mode"] is True

    assert "threat" in data
    assert "score" in data["threat"]
    assert "level" in data["threat"]

    assert "incident_count" in data
    assert "open_incidents" in data

    assert data["incident_count"] >= 0
    assert data["open_incidents"] >= 0