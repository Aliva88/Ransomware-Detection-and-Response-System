from fastapi import APIRouter

from app.core.config_loader import load_config
from app.database import SessionLocal
from app.models import Score, Incident


router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "running",
        "service": "Ransomware Detection and Response System"
    }


@router.get("/config")
def get_config():
    config = load_config()

    return {
        "app": config["app"],
        "monitoring": config["monitoring"],
        "detection": config["detection"],
        "scoring": config["scoring"],
        "quarantine": config["quarantine"]
    }


@router.get("/status")
def get_status():

    config = load_config()

    db = SessionLocal()

    try:
        latest_score = (
            db.query(Score)
            .order_by(Score.id.desc())
            .first()
        )

        if latest_score is None:
            threat_score = 0
            threat_level = "Low"
        else:
            threat_score = latest_score.score
            threat_level = latest_score.level

        return {
            "system": "Ransomware Detection and Response System",
            "status": "active",
            "simulation_mode": config["monitoring"]["simulation_mode"],
            "threat_score": threat_score,
            "threat_level": threat_level
        }

    finally:
        db.close()


@router.get("/incidents")
def get_incidents():

    db = SessionLocal()

    try:
        incidents = (
            db.query(Incident)
            .order_by(Incident.id.desc())
            .all()
        )

        return [
            {
                "id": incident.id,
                "incident_type": incident.incident_type,
                "severity": incident.severity,
                "description": incident.description,
                "status": incident.status,
                "timestamp": incident.timestamp
            }
            for incident in incidents
        ]

    finally:
        db.close()


@router.get("/dashboard")
def get_dashboard():

    config = load_config()

    db = SessionLocal()

    try:
        latest_score = (
            db.query(Score)
            .order_by(Score.id.desc())
            .first()
        )

        incidents = (
            db.query(Incident)
            .order_by(Incident.id.desc())
            .all()
        )

        if latest_score is None:
            threat_score = 0
            threat_level = "Low"
        else:
            threat_score = latest_score.score
            threat_level = latest_score.level

        return {
            "system": "Ransomware Detection and Response System",
            "status": "active",
            "simulation_mode": config["monitoring"]["simulation_mode"],
            "threat": {
                "score": threat_score,
                "level": threat_level
            },
            "incident_count": len(incidents),
            "open_incidents": sum(
                1
                for incident in incidents
                if incident.status == "open"
            )
        }

    finally:
        db.close()