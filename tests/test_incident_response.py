from types import SimpleNamespace

from app.core import incident_response


TEST_SYSTEM_ID = 62


def test_critical_detection_creates_incident(monkeypatch):

    threat_result = {
        "score": 105,
        "threat_level": "Critical",
        "behaviors": {
            "rapid_encryption": True,
            "mass_rename": True,
            "high_entropy": True,
            "cpu_spike": False,
            "unknown_program": False
        }
    }

    detection_result = {
        "modified_count": 30,
        "rename_count": 15,
        "extension_changes": 10
    }

    expected_incident = SimpleNamespace(
        id=999,
        incident_type="Ransomware Activity",
        severity="Critical",
        status="open",
        threat_score=105,
        signals=str(threat_result["behaviors"])
    )

    monkeypatch.setattr(
        incident_response,
        "get_open_incident",
        lambda incident_type, system_id: None
    )

    def fake_create_incident(**kwargs):
        assert kwargs["incident_type"] == "Ransomware Activity"
        assert kwargs["severity"] == "Critical"
        assert kwargs["system_id"] == TEST_SYSTEM_ID
        assert kwargs["threat_score"] == 105
        assert "rapid_encryption" in kwargs["signals"]
        assert "mass_rename" in kwargs["signals"]

        return expected_incident

    monkeypatch.setattr(
        incident_response,
        "create_incident",
        fake_create_incident
    )

    response = incident_response.IncidentResponse(
        system_id=TEST_SYSTEM_ID
    )

    incident = response.handle_detection(
        threat_result,
        detection_result
    )

    assert incident is not None
    assert incident.incident_type == "Ransomware Activity"
    assert incident.severity == "Critical"
    assert incident.status == "open"
    assert incident.threat_score == 105
    assert "rapid_encryption" in incident.signals
    assert "mass_rename" in incident.signals


def test_non_critical_detection_does_not_create_incident():

    threat_result = {
        "score": 70,
        "threat_level": "High"
    }

    detection_result = {
        "modified_count": 25,
        "rename_count": 12,
        "extension_changes": 0
    }

    response = incident_response.IncidentResponse(
        system_id=TEST_SYSTEM_ID
    )

    incident = response.handle_detection(
        threat_result,
        detection_result
    )

    assert incident is None