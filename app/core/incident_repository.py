from app.database import SessionLocal
from app.models import Incident


def create_incident(
    incident_type,
    severity,
    description,
    system_id
):
    """
    Create and save a new security incident.
    """

    db = SessionLocal()

    try:
        incident = Incident(
            incident_type=incident_type,
            severity=severity,
            description=description,
            system_id=system_id
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    finally:
        db.close()


def get_open_incident(
    incident_type="Ransomware Activity",
    system_id=None
):
    """
    Return the latest open incident of the given type
    for the specified system.

    This prevents incidents from different systems
    being treated as duplicates.
    """

    db = SessionLocal()

    try:
        query = (
            db.query(Incident)
            .filter(
                Incident.incident_type == incident_type,
                Incident.status == "open"
            )
        )

        if system_id is not None:
            query = query.filter(
                Incident.system_id == system_id
            )

        incident = (
            query
            .order_by(Incident.id.desc())
            .first()
        )

        return incident

    finally:
        db.close()
