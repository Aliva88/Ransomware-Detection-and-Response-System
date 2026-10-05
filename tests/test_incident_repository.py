from app.core.incident_repository import create_incident


TEST_SYSTEM_ID = 62


def test_create_incident():

    incident = create_incident(
        system_id=TEST_SYSTEM_ID,
        incident_type="Ransomware Activity",
        severity="Critical",
        description="Critical ransomware-like activity detected."
    )

    assert incident.id is not None
    assert incident.incident_type == "Ransomware Activity"
    assert incident.severity == "Critical"
    assert incident.status == "open"