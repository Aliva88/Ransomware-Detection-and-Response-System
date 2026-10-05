from pathlib import Path
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.logging import logger
from app.database import SessionLocal
from app.models import Event
from app.core.config_loader import load_config
from app.core.entropy import calculate_entropy
from app.core.threat_scorer import ThreatScorer
from app.core.score_repository import save_score
from app.core.incident_response import IncidentResponse
from app.detectors.detection_engine import DetectionEngine
from app.process_monitor import get_process_signals


# ------------------------------------------------------------
# Entropy settings
# ------------------------------------------------------------

# Entropy of very small files is naturally low, even when they
# are random, so tiny files are skipped.
MIN_ENTROPY_FILE_SIZE = 1024

# These formats are already compressed, so their content can
# naturally look random. Measuring them can cause false alarms.
SKIP_ENTROPY_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tgz", ".cab",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".aac",
    ".ogg", ".webm",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
    ".jar", ".apk", ".iso", ".msi", ".exe", ".dll",
}


def measure_entropy(file_path, event_type):
    """
    Return the entropy (0-8) of a file's content, or None when it
    should not be measured.
    """

    if event_type == "DELETE":
        return None

    try:
        if file_path.suffix.lower() in SKIP_ENTROPY_EXTENSIONS:
            return None

        if not file_path.is_file():
            return None

        if file_path.stat().st_size < MIN_ENTROPY_FILE_SIZE:
            return None

        return round(
            calculate_entropy(str(file_path)),
            3
        )

    except (OSError, PermissionError):
        # File was moved/locked while we were looking at it.
        return None


class RDRSEventHandler(FileSystemEventHandler):

    def __init__(
        self,
        detection_engine,
        threat_scorer,
        incident_response,
        system_id
    ):
        super().__init__()

        self.detection_engine = detection_engine
        self.threat_scorer = threat_scorer
        self.incident_response = incident_response
        self.system_id = system_id

        self.last_incident_score = 0

    def _save_event_to_database(
        self,
        event_type,
        file_path
    ):
        """
        Save a filesystem event to the events table.

        Database failure must not stop the detection engine.
        """

        db = SessionLocal()

        try:
            db_event = Event(
                system_id=self.system_id,
                event_type=event_type,
                file_path=str(file_path),
                timestamp=datetime.utcnow()
            )

            db.add(db_event)
            db.commit()

            logger.info(
                "File event saved to database: "
                f"{event_type} - {file_path}"
            )

        except Exception as e:

            db.rollback()

            logger.error(
                "Failed to save file event to database: "
                f"{e}"
            )

        finally:
            db.close()

    def _record_event(
        self,
        event_type,
        path,
        old_path=None
    ):

        file_path = Path(path)

        event_data = {
            "event_type": event_type,
            "path": str(file_path),
            "timestamp": datetime.now().isoformat(),
            "extension": file_path.suffix.lower()
        }

        if old_path:

            old_file_path = Path(old_path)

            event_data["old_path"] = str(
                old_file_path
            )

            event_data["old_extension"] = (
                old_file_path.suffix.lower()
            )

        # -----------------------------------------
        # 1. Save event to database
        # -----------------------------------------

        self._save_event_to_database(
            event_type=event_type,
            file_path=file_path
        )

        # -----------------------------------------
        # 2. Calculate entropy
        # -----------------------------------------

        entropy = measure_entropy(
            file_path,
            event_type
        )

        if entropy is not None:
            event_data["entropy"] = entropy

        logger.info(
            f"File event: {event_data}"
        )

        # -----------------------------------------
        # 3. Add file event to Detection Engine
        # -----------------------------------------

        self.detection_engine.add_event(
            event_data
        )

        # -----------------------------------------
        # 4. Analyze file activity
        # -----------------------------------------

        detection_result = (
            self.detection_engine.analyze()
        )

        logger.info(
            f"Detection result: {detection_result}"
        )

        # -----------------------------------------
        # 5. Collect current process activity
        # -----------------------------------------

        process_result = (
            get_process_signals()
        )

        logger.info(
            f"Process signals: {process_result}"
        )

        # -----------------------------------------
        # 6. Calculate combined threat score
        # -----------------------------------------

        threat_result = (
            self.threat_scorer.analyze_detection(
                detection_result,
                process_result
            )
        )

        logger.info(
            f"Combined threat result: {threat_result}"
        )

        # -----------------------------------------
        # 7. Save score when suspicious activity
        # -----------------------------------------

        if detection_result["suspicious"]:

            save_score(
                score=threat_result["score"],
                level=threat_result["threat_level"],
                system_id=self.system_id
            )

            logger.info(
                "Active threat score saved: "
                f"{threat_result['score']} "
                f"({threat_result['threat_level']})"
            )

            # -------------------------------------
            # 8. Incident Response
            # -------------------------------------

            incident = (
                self.incident_response.handle_detection(
                    threat_result,
                    detection_result
                )
            )

            if incident is not None:

                if (
                    threat_result["score"]
                    != self.last_incident_score
                ):

                    logger.warning(
                        "Security incident created or "
                        f"updated: ID={incident.id}"
                    )

                    self.last_incident_score = (
                        threat_result["score"]
                    )

        else:

            logger.debug(
                "No suspicious file activity detected. "
                f"Calculated score: "
                f"{threat_result['score']}"
            )

    def on_created(self, event):

        if not event.is_directory:

            self._record_event(
                "CREATE",
                event.src_path
            )

    def on_modified(self, event):

        if not event.is_directory:

            self._record_event(
                "MODIFY",
                event.src_path
            )

    def on_deleted(self, event):

        if not event.is_directory:

            self._record_event(
                "DELETE",
                event.src_path
            )

    def on_moved(self, event):

        if not event.is_directory:

            self._record_event(
                "RENAME",
                event.dest_path,
                event.src_path
            )


'''def start_monitor(folder, system_id):

    folder_path = Path(folder)

    # -----------------------------------------
    # Validate monitoring folder
    # -----------------------------------------

    if not folder_path.exists():

        raise FileNotFoundError(
            f"Monitoring folder does not exist: "
            f"{folder_path}"
        )

    # -----------------------------------------
    # Load configuration
    # -----------------------------------------

    config = load_config()

    monitoring_config = config["monitoring"]
    detection_config = config["detection"]
    scoring_config = config["scoring"]

    # -----------------------------------------
    # Detection Engine
    # -----------------------------------------

    detection_engine = DetectionEngine(

        window_seconds=monitoring_config[
            "sliding_window_seconds"
        ],

        modified_files_threshold=detection_config[
            "modified_files_threshold"
        ],

        rename_threshold=detection_config[
            "rename_threshold"
        ],

        extension_change_threshold=detection_config[
            "extension_change_threshold"
        ],

        entropy_threshold=detection_config.get(
            "entropy_threshold",
            7.5
        ),

        high_entropy_files_threshold=detection_config.get(
            "high_entropy_files_threshold",
            5
        )
    )

    # -----------------------------------------
    # Threat Scorer
    # -----------------------------------------

    threat_scorer = ThreatScorer(
        scoring_config
    )

    # -----------------------------------------
    # Incident Response
    # -----------------------------------------

    incident_response = IncidentResponse(
        system_id=system_id,
        critical_threshold=80
    )

    # -----------------------------------------
    # Watchdog Observer
    # -----------------------------------------

    observer = Observer()

    handler = RDRSEventHandler(
        detection_engine=detection_engine,
        threat_scorer=threat_scorer,
        incident_response=incident_response,
        system_id=system_id
    )

    observer.schedule(
        handler,
        str(folder_path),
        recursive=True
    )

    observer.start()

    logger.info(
        f"File monitoring started: {folder_path}"
    )

    return observer'''
def start_monitor(folders, system_id):
    """
    Start real-time monitoring for one or more folders.
    A single watchdog Observer can monitor multiple folders.
    """

    # -----------------------------------------
    # Normalize folder input
    # -----------------------------------------

    if isinstance(folders, (str, Path)):
        folders = [folders]

    folder_paths = [
        Path(folder).expanduser()
        for folder in folders
    ]

    # -----------------------------------------
    # Validate monitoring folders
    # -----------------------------------------

    for folder_path in folder_paths:
        if not folder_path.exists():
            raise FileNotFoundError(
                f"Monitoring folder does not exist: "
                f"{folder_path}"
            )

        if not folder_path.is_dir():
            raise NotADirectoryError(
                f"Monitoring path is not a directory: "
                f"{folder_path}"
            )

    # -----------------------------------------
    # Load configuration
    # -----------------------------------------

    config = load_config()

    monitoring_config = config["monitoring"]
    detection_config = config["detection"]
    scoring_config = config["scoring"]

    # -----------------------------------------
    # Detection Engine
    # -----------------------------------------

    detection_engine = DetectionEngine(
        window_seconds=monitoring_config["sliding_window_seconds"],
        modified_files_threshold=detection_config["modified_files_threshold"],
        rename_threshold=detection_config["rename_threshold"],
        extension_change_threshold=detection_config["extension_change_threshold"],
        entropy_threshold=detection_config.get(
            "entropy_threshold",
            7.5
        ),
        high_entropy_files_threshold=detection_config.get(
            "high_entropy_files_threshold",
            5
        )
    )

    # -----------------------------------------
    # Threat Scoring
    # -----------------------------------------

    threat_scorer = ThreatScorer(scoring_config)

    # -----------------------------------------
    # Incident Response
    # -----------------------------------------

    incident_response = IncidentResponse(
        system_id=system_id,
        critical_threshold=80
    )

    # -----------------------------------------
    # Single Observer
    # -----------------------------------------

    observer = Observer()

    handler = RDRSEventHandler(
        detection_engine=detection_engine,
        threat_scorer=threat_scorer,
        incident_response=incident_response,
        system_id=system_id
    )

    # -----------------------------------------
    # Schedule ALL folders
    # -----------------------------------------

    for folder_path in folder_paths:
        observer.schedule(
            handler,
            str(folder_path),
            recursive=True
        )

        logger.info(
            f"File monitoring scheduled: {folder_path}"
        )

    # -----------------------------------------
    # Start Observer
    # -----------------------------------------

    observer.start()

    logger.info(
        "Real-time file monitoring started for "
        f"{len(folder_paths)} folder(s)."
    )

    return observer