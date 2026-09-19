from app.database import SessionLocal
from app.models import Incident


def create_incident(
    incident_type,
    severity,
    description
):
    """
    Create and save a new security incident.
    """

    db = SessionLocal()

    try:
        incident = Incident(
            incident_type=incident_type,
            severity=severity,
            description=description
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    finally:
        db.close()