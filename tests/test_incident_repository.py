from app.core.incident_repository import create_incident


def test_create_incident():

    incident = create_incident(
        incident_type="Ransomware Activity",
        severity="Critical",
        description="Critical ransomware-like activity detected."
    )

    assert incident.id is not None
    assert incident.incident_type == "Ransomware Activity"
    assert incident.severity == "Critical"
    assert incident.status == "open"