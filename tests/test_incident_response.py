from app.core.incident_response import IncidentResponse


def test_critical_detection_creates_incident():

    threat_result = {
        "score": 105,
        "threat_level": "Critical"
    }

    detection_result = {
        "modified_count": 30,
        "rename_count": 15,
        "extension_changes": 10
    }

    response = IncidentResponse()

    incident = response.handle_detection(
        threat_result,
        detection_result
    )

    assert incident is not None
    assert incident.incident_type == "Ransomware Activity"
    assert incident.severity == "Critical"
    assert incident.status == "open"


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

    response = IncidentResponse()

    incident = response.handle_detection(
        threat_result,
        detection_result
    )

    assert incident is None