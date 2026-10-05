from datetime import datetime
import base64
import csv
import io
import platform
import socket
import secrets

import pyotp
import qrcode

from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.core.config_loader import load_config
from app.database import SessionLocal
from app.models import (
    System,
    Event,
    Process,
    Score,
    Incident,
)
from app.detectors.file_monitor import start_monitor


router = APIRouter()

monitor_observer = None


# ============================================================
# REQUEST SCHEMAS
# ============================================================

class SystemCreate(BaseModel):
    system_name: str
    hostname: str = ""
    ip_address: str = ""
    operating_system: str = ""
    environment: str = "Workstation"


class SystemVerification(BaseModel):
    system_id: str
    code: str


class ExistingSystemAuthentication(BaseModel):
    system_id: str
    code: str


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_local_hostname():
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def get_local_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "127.0.0.1"


def get_local_os():
    try:
        return platform.platform()
    except Exception:
        return "Unknown"


def generate_system_id():
    return f"RSH-{secrets.token_hex(4).upper()}"


def generate_qr_code(provisioning_uri):
    qr = qrcode.QRCode(
        version=1,
        box_size=8,
        border=4,
    )

    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image(
        fill_color="black",
        back_color="white",
    )

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    return base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")


def system_response(system):
    return {
        "id": system.id,
        "system_id": system.system_id,
        "system_name": system.system_name,
        "hostname": system.hostname,
        "ip_address": system.ip_address,
        "operating_system": system.operating_system,
        "verified": system.verified,
        "monitoring": system.monitoring,
        "created_at": system.created_at,
        "last_seen": system.last_seen,
    }


def validate_totp_code(system, code):
    if not system.totp_secret:
        return False

    try:
        totp = pyotp.TOTP(system.totp_secret)

        return totp.verify(
            code,
            valid_window=1,
        )

    except Exception:
        return False


def get_latest_score(db, system_id=None):

    query = db.query(Score)

    if system_id:
        query = query.filter(
            Score.system_id == system_id
        )

    return query.order_by(
        Score.timestamp.desc()
    ).first()


def calculate_threat_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


# ============================================================
# HEALTH
# ============================================================

@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "RansomShield",
    }


# ============================================================
# CONFIG
# ============================================================

@router.get("/config")
def get_config():

    config = load_config()

    return {
        "status": "ok",
        "config": config,
    }


# ============================================================
# CREATE SYSTEM
# ============================================================

@router.post("/systems")
def create_system(data: SystemCreate):

    db = SessionLocal()

    try:

        hostname = (
            data.hostname.strip()
            if data.hostname
            else get_local_hostname()
        )

        ip_address = (
            data.ip_address.strip()
            if data.ip_address
            else get_local_ip()
        )

        operating_system = (
            data.operating_system.strip()
            if data.operating_system
            else get_local_os()
        )

        system_id = generate_system_id()

        totp_secret = pyotp.random_base32()

        system = System(
            system_id=system_id,
            system_name=data.system_name,
            hostname=hostname,
            ip_address=ip_address,
            operating_system=operating_system,
            totp_secret=totp_secret,
            verified=False,
            monitoring=False,
        )

        db.add(system)
        db.commit()
        db.refresh(system)

        totp = pyotp.TOTP(totp_secret)

        provisioning_uri = totp.provisioning_uri(
            name=hostname,
            issuer_name="RansomShield",
        )

        qr_code = generate_qr_code(
            provisioning_uri
        )

        return {
            "status": "created",
            "message": "System registered successfully.",
            "system": system_response(system),
            "authenticator": {
                "secret": totp_secret,
                "provisioning_uri": provisioning_uri,
                "qr_code": (
                    "data:image/png;base64,"
                    + qr_code
                ),
            },
        }

    finally:
        db.close()


# ============================================================
# VERIFY SYSTEM
# ============================================================

@router.post("/systems/verify")
def verify_system(data: SystemVerification):

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.system_id == data.system_id
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": "System not found.",
            }

        if not validate_totp_code(
            system,
            data.code,
        ):
            return {
                "status": "error",
                "message": "Invalid authenticator code.",
            }

        system.verified = True
        system.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(system)

        return {
            "status": "verified",
            "message": "System verified successfully.",
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# EXISTING SYSTEM AUTHENTICATION
# ============================================================

@router.post("/systems/authenticate")
def authenticate_existing_system(
    data: ExistingSystemAuthentication,
):

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.system_id == data.system_id
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": "System not found.",
            }

        if not validate_totp_code(
            system,
            data.code,
        ):
            return {
                "status": "error",
                "message": "Invalid authenticator code.",
            }

        system.verified = True
        system.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(system)

        return {
            "status": "authenticated",
            "message": "System authenticated successfully.",
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# REGENERATE AUTHENTICATOR
# ============================================================

@router.post(
    "/systems/{system_id}/authenticator/regenerate"
)
def regenerate_authenticator(
    system_id: str,
):

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.system_id == system_id
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": "System not found.",
            }

        new_totp_secret = pyotp.random_base32()

        system.totp_secret = new_totp_secret
        system.verified = False
        system.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(system)

        totp = pyotp.TOTP(
            new_totp_secret
        )

        provisioning_uri = totp.provisioning_uri(
            name=system.hostname,
            issuer_name="RansomShield",
        )

        qr_code = generate_qr_code(
            provisioning_uri
        )

        return {
            "status": "regenerated",
            "message": (
                "Authenticator regenerated successfully. "
                "Scan the new QR code with your "
                "authenticator application."
            ),
            "system": system_response(system),
            "authenticator": {
                "secret": new_totp_secret,
                "provisioning_uri": provisioning_uri,
                "qr_code": (
                    "data:image/png;base64,"
                    + qr_code
                ),
            },
        }

    finally:
        db.close()


# ============================================================
# GET ALL SYSTEMS
# ============================================================

@router.get("/systems")
def get_systems():

    db = SessionLocal()

    try:

        systems = (
            db.query(System)
            .order_by(
                System.created_at.desc()
            )
            .all()
        )

        return {
            "status": "ok",
            "count": len(systems),
            "systems": [
                system_response(system)
                for system in systems
            ],
        }

    finally:
        db.close()


# ============================================================
# GET SINGLE SYSTEM
# ============================================================

@router.get("/systems/{system_id}")
def get_system(system_id: str):

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.system_id == system_id
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": "System not found.",
            }

        return {
            "status": "ok",
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# PROTECTION START / STOP
# ============================================================

@router.post(
    "/systems/{system_id}/protection"
)
def set_system_protection(
    system_id: str,
    enabled: bool = True,
):

    global monitor_observer

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.system_id == system_id
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": "System not found.",
            }

        if enabled:

            if not system.verified:
                return {
                    "status": "error",
                    "message": (
                        "System must be verified "
                        "before protection can start."
                    ),
                }

            # -----------------------------------------
            # START FILE MONITOR
            # -----------------------------------------

            if (
                monitor_observer is None
                or not monitor_observer.is_alive()
            ):

                config = load_config()

                monitoring_config = config.get(
                    "monitoring",
                    {}
                )

                folders = monitoring_config.get(
                    "folders",
                    ["data/sandbox"]
                )

                if not folders:
                    return {
                        "status": "error",
                        "message": (
                            "No monitoring folder "
                            "configured."
                        ),
                    }

                '''monitor_folder = folders[0]

                monitor_observer = start_monitor(
                    monitor_folder,
                    system_id=system.id
                )'''
                monitor_observer = start_monitor(
                    folders,
                    system_id=system.id
                )

            system.monitoring = True
            system.last_seen = datetime.utcnow()

            db.commit()
            db.refresh(system)

            return {
                "status": "active",
                "message": (
                    "RansomShield protection "
                    "started successfully."
                ),
                "system": system_response(system),
            }

        # ---------------------------------------------
        # STOP PROTECTION
        # ---------------------------------------------

        system.monitoring = False
        system.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(system)

        return {
            "status": "inactive",
            "message": (
                "RansomShield protection "
                "stopped successfully."
            ),
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# GLOBAL PROTECTION START
# ============================================================

@router.post("/protection/start")
def start_protection():

    global monitor_observer

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.verified == True
            )
            .order_by(
                System.created_at.desc()
            )
            .first()
        )

        if not system:
            return {
                "status": "error",
                "message": (
                    "No verified system available."
                ),
            }

        if (
            monitor_observer is None
            or not monitor_observer.is_alive()
        ):

            config = load_config()

            monitoring_config = config.get(
                "monitoring",
                {}
            )

            folders = monitoring_config.get(
                "folders",
                ["data/sandbox"]
            )

            if not folders:
                return {
                    "status": "error",
                    "message": (
                        "No monitoring folder "
                        "configured."
                    ),
                }

            '''monitor_folder = folders[0]

            monitor_observer = start_monitor(
                monitor_folder,
                system_id=system.id
            )'''
            monitor_observer = start_monitor(
                folders,
                system_id=system.id
            )

        system.monitoring = True
        system.last_seen = datetime.utcnow()

        db.commit()
        db.refresh(system)

        return {
            "status": "active",
            "message": (
                "RansomShield protection "
                "started successfully."
            ),
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# GLOBAL PROTECTION STOP
# ============================================================

@router.post("/protection/stop")
def stop_protection():

    global monitor_observer

    db = SessionLocal()

    try:

        # -----------------------------------------
        # STOP FILE MONITOR
        # -----------------------------------------

        if (
            monitor_observer is not None
            and monitor_observer.is_alive()
        ):
            monitor_observer.stop()
            monitor_observer.join(timeout=5)

        monitor_observer = None

        # -----------------------------------------
        # UPDATE SYSTEM STATUS
        # -----------------------------------------

        systems = (
            db.query(System)
            .filter(
                System.monitoring == True
            )
            .all()
        )

        for system in systems:

            system.monitoring = False
            system.last_seen = datetime.utcnow()

        db.commit()

        return {
            "status": "inactive",
            "monitoring": False,
            "monitor_running": False,
            "message": (
                "RansomShield protection "
                "stopped successfully."
            ),
        }

    finally:
        db.close()
# ============================================================
# SYSTEM STATUS
# ============================================================

@router.get("/status")
def get_status():

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.monitoring == True
            )
            .order_by(
                System.last_seen.desc()
            )
            .first()
        )

        monitor_running = (
            monitor_observer is not None
            and monitor_observer.is_alive()
        )

        if not system:

            return {
                "status": "inactive",
                "monitoring": False,
                "monitor_running": monitor_running,
                "message": "Protection is inactive.",
            }

        return {
            "status": (
                "active"
                if system.monitoring
                else "inactive"
            ),
            "monitoring": system.monitoring,
            "monitor_running": monitor_running,
            "system": system_response(system),
        }

    finally:
        db.close()


# ============================================================
# INCIDENTS
# ============================================================

@router.get("/incidents")
def get_incidents():

    db = SessionLocal()

    try:

        # Get the currently monitored system.
        system = (
            db.query(System)
            .filter(
                System.monitoring == True
            )
            .order_by(
                System.last_seen.desc()
            )
            .first()
        )

        if not system:
            return {
                "status": "ok",
                "count": 0,
                "incidents": [],
            }

        # IMPORTANT:
        # Only return incidents belonging to the
        # currently monitored system.
        incidents = (
            db.query(Incident)
            .filter(
                Incident.system_id == system.id
            )
            .order_by(
                Incident.timestamp.desc()
            )
            .all()
        )

        data = []

        for incident in incidents:

            data.append(
                {
                    "id": incident.id,
                    "system_id": incident.system_id,
                    "incident_type": incident.incident_type,
                    "severity": incident.severity,
                    "description": incident.description,
                    "status": incident.status,
                    "threat_score": incident.threat_score,
                    "signals": incident.signals,
                    "timestamp": incident.timestamp,
                }
            )

        return {
            "status": "ok",
            "count": len(data),
            "incidents": data,
        }

    finally:
        db.close()


# ============================================================
# THREAT API
# ============================================================

@router.get("/threat")
def get_current_threat():

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .filter(
                System.monitoring == True
            )
            .order_by(
                System.last_seen.desc()
            )
            .first()
        )

        latest_score = get_latest_score(
            db,
            system.id if system else None,
        )

        score_value = (
            latest_score.score
            if latest_score
            else 0
        )

        level = (
            latest_score.level
            if latest_score
            else calculate_threat_level(
                score_value
            )
        )

        modified_count = 0
        rename_count = 0
        extension_changes = 0
        high_entropy = False

        cpu_spike = False
        combined_process_activity = False

        if system:

            recent_events = (
                db.query(Event)
                .filter(
                    Event.system_id == system.id
                )
                .order_by(
                    Event.timestamp.desc()
                )
                .limit(100)
                .all()
            )

            for event in recent_events:

                event_type = (
                    event.event_type or ""
                ).lower()

                if "modif" in event_type:
                    modified_count += 1

                if "rename" in event_type:
                    rename_count += 1

                if (
                    "extension" in event_type
                    or "ext_change" in event_type
                ):
                    extension_changes += 1

                if "entropy" in event_type:
                    high_entropy = True

            latest_process = (
                db.query(Process)
                .filter(
                    Process.system_id == system.id
                )
                .order_by(
                    Process.timestamp.desc()
                )
                .first()
            )

            if latest_process:

                cpu_spike = (
                    latest_process.cpu_percent
                    is not None
                    and latest_process.cpu_percent >= 80
                )

                combined_process_activity = (
                    cpu_spike
                    or (
                        latest_process.disk_write_bytes
                        is not None
                        and latest_process.disk_write_bytes > 0
                    )
                )

        return {
            "status": "ok",
            "system": (
                system.system_id
                if system
                else None
            ),
            "threat": {
                "score": score_value,
                "level": str(level).upper(),
                "threat_score": score_value,
                "threat_level": str(level).upper(),
                "detection": {
                    "modified_count": modified_count,
                    "rename_count": rename_count,
                    "extension_changes": extension_changes,
                    "high_entropy": high_entropy,
                },
                "process": {
                    "cpu_spike": cpu_spike,
                    "combined_process_activity": (
                        combined_process_activity
                    ),
                },
            },
        }

    finally:
        db.close()


# ============================================================
# DASHBOARD
# ============================================================

@router.get("/dashboard")
def get_dashboard():

    db = SessionLocal()

    try:

        config = load_config()

        system = (
            db.query(System)
            .filter(
                System.monitoring == True
            )
            .order_by(
                System.last_seen.desc()
            )
            .first()
        )

        latest_score = get_latest_score(
            db,
            system.id if system else None,
        )

        # ----------------------------------------------------
        # IMPORTANT:
        # Only load incidents belonging to the current system.
        # ----------------------------------------------------

        if system:

            incidents = (
                db.query(Incident)
                .filter(
                    Incident.system_id == system.id
                )
                .order_by(
                    Incident.timestamp.desc()
                )
                .all()
            )

        else:

            incidents = []

        monitor_status = (
            monitor_observer is not None
            and monitor_observer.is_alive()
        )

        if (
            not monitor_status
            or latest_score is None
        ):

            threat_score = 0
            threat_level = "LOW"

        else:

            threat_score = latest_score.score
            threat_level = latest_score.level

        incident_data = []

        for incident in incidents:

            incident_data.append(
                {
                    "id": incident.id,
                    "system_id": incident.system_id,
                    "incident_type": (
                        incident.incident_type
                    ),
                    "severity": incident.severity,
                    "description": (
                        incident.description
                    ),
                    "status": incident.status,
                    "threat_score": (
                        incident.threat_score
                    ),
                    "signals": incident.signals,
                    "timestamp": incident.timestamp,
                }
            )

        open_incidents = sum(
            1
            for incident in incidents
            if str(
                incident.status
            ).lower()
            in {
                "open",
                "active",
                "investigating",
            }
        )

        return {
            "system": (
                system.system_id
                if system
                else None
            ),
            "system_name": (
                system.system_name
                if system
                else None
            ),
            "status": (
                "active"
                if system and system.monitoring
                else "inactive"
            ),
            "monitoring": monitor_status,
            "monitor_running": monitor_status,
            "simulation_mode": (
                config["monitoring"][
                    "simulation_mode"
                ]
            ),
            "threat": {
                "score": threat_score,
                "level": threat_level,
            },
            "threat_score": threat_score,
            "threat_level": threat_level,
            "incident_count": len(incidents),
            "open_incidents": open_incidents,
            "incidents": incident_data,
        }

    finally:
        db.close()


# ============================================================
# JSON REPORT
# ============================================================

@router.get("/reports/json")
def generate_json_report():

    db = SessionLocal()

    try:

        system = (
            db.query(System)
            .order_by(
                System.created_at.desc()
            )
            .first()
        )

        scores = (
            db.query(Score)
            .order_by(
                Score.timestamp.desc()
            )
            .all()
        )

        incidents = (
            db.query(Incident)
            .order_by(
                Incident.timestamp.desc()
            )
            .all()
        )

        processes = (
            db.query(Process)
            .order_by(
                Process.timestamp.desc()
            )
            .limit(500)
            .all()
        )

        events = (
            db.query(Event)
            .order_by(
                Event.timestamp.desc()
            )
            .limit(500)
            .all()
        )

        report = {
            "report": {
                "name": (
                    "RansomShield Security Report"
                ),
                "generated_at": datetime.utcnow(),
                "system": (
                    system_response(system)
                    if system
                    else None
                ),
            },
            "scores": [
                {
                    "id": score.id,
                    "system_id": score.system_id,
                    "score": score.score,
                    "level": score.level,
                    "timestamp": score.timestamp,
                }
                for score in scores
            ],
            "incidents": [
                {
                    "id": incident.id,
                    "system_id": incident.system_id,
                    "incident_type": (
                        incident.incident_type
                    ),
                    "severity": incident.severity,
                    "description": (
                        incident.description
                    ),
                    "status": incident.status,
                    "threat_score": (
                        incident.threat_score
                    ),
                    "signals": incident.signals,
                    "timestamp": incident.timestamp,
                }
                for incident in incidents
            ],
            "processes": [
                {
                    "id": process.id,
                    "system_id": process.system_id,
                    "pid": process.pid,
                    "process_name": (
                        process.process_name
                    ),
                    "cpu_percent": (
                        process.cpu_percent
                    ),
                    "memory_percent": (
                        process.memory_percent
                    ),
                    "disk_write_bytes": (
                        process.disk_write_bytes
                    ),
                    "executable_path": (
                        process.executable_path
                    ),
                    "parent_pid": (
                        process.parent_pid
                    ),
                    "timestamp": process.timestamp,
                }
                for process in processes
            ],
            "events": [
                {
                    "id": event.id,
                    "system_id": event.system_id,
                    "event_type": event.event_type,
                    "file_path": event.file_path,
                    "timestamp": event.timestamp,
                }
                for event in events
            ],
        }

        return JSONResponse(
            content=jsonable_encoder(report)
        )

    finally:
        db.close()


# ============================================================
# CSV REPORT
# ============================================================

@router.get("/reports/csv")
def generate_csv_report():

    db = SessionLocal()

    try:

        incidents = (
            db.query(Incident)
            .order_by(
                Incident.timestamp.desc()
            )
            .all()
        )

        scores = (
            db.query(Score)
            .order_by(
                Score.timestamp.desc()
            )
            .all()
        )

        output = io.StringIO()

        writer = csv.writer(output)

        writer.writerow(
            [
                "Record Type",
                "ID",
                "System ID",
                "Type",
                "Severity",
                "Status",
                "Threat Score",
                "Level",
                "Description",
                "Timestamp",
            ]
        )

        for incident in incidents:

            writer.writerow(
                [
                    "Incident",
                    incident.id,
                    incident.system_id,
                    incident.incident_type,
                    incident.severity,
                    incident.status,
                    incident.threat_score,
                    "",
                    incident.description,
                    incident.timestamp,
                ]
            )

        for score in scores:

            writer.writerow(
                [
                    "Score",
                    score.id,
                    score.system_id,
                    "",
                    "",
                    "",
                    score.score,
                    score.level,
                    "",
                    score.timestamp,
                ]
            )

        csv_content = output.getvalue()

        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    "attachment; "
                    "filename="
                    "ransomshield-security-report.csv"
                )
            },
        )

    finally:
        db.close()
        # ============================================================
# ATTACK REPLAY
# ============================================================

@router.get("/attack-replay")
def get_attack_replay(
    system_id: int | None = None,
    limit: int = 200
):
    """
    Return recent filesystem events for Attack Replay.

    This endpoint is read-only.
    It does not modify or delete any event data.
    """

    db = SessionLocal()

    try:

        query = (
            db.query(Event)
            .order_by(
                Event.timestamp.asc()
            )
        )

        if system_id is not None:
            query = query.filter(
                Event.system_id == system_id
            )

        limit = max(
            1,
            min(limit, 1000)
        )

        events = (
            query
            .limit(limit)
            .all()
        )

        return {
            "status": "ok",
            "count": len(events),
            "events": [
                {
                    "id": event.id,
                    "system_id": event.system_id,
                    "event_type": event.event_type,
                    "file_path": event.file_path,
                    "timestamp": event.timestamp,
                }
                for event in events
            ],
        }

    finally:
        db.close()