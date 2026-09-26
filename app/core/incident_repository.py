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


def get_open_incident(incident_type="Ransomware Activity"):
    """
    Return the latest open incident of the given type.

    This is used to prevent duplicate incidents
    during the same active ransomware event.
    """

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(
                Incident.incident_type == incident_type,
                Incident.status == "open"
            )
            .order_by(Incident.id.desc())
            .first()
        )

        return incident

    finally:
        db.close()