from pathlib import Path
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.logging import logger
from app.core.config_loader import load_config
from app.core.threat_scorer import ThreatScorer
from app.core.score_repository import save_score
from app.core.incident_response import IncidentResponse
from app.detectors.detection_engine import DetectionEngine
from app.process_monitor import get_process_signals


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

        logger.info(
            f"File event: {event_data}"
        )

        # -----------------------------------------
        # 1. Add file event to Detection Engine
        # -----------------------------------------

        self.detection_engine.add_event(
            event_data
        )

        # -----------------------------------------
        # 2. Analyze file activity
        # -----------------------------------------

        detection_result = (
            self.detection_engine.analyze()
        )

        logger.info(
            f"Detection result: {detection_result}"
        )

        # -----------------------------------------
        # 3. Collect current process activity
        # -----------------------------------------

        process_result = (
            get_process_signals()
        )

        logger.info(
            f"Process signals: {process_result}"
        )

        # -----------------------------------------
        # 4. Calculate combined threat score
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
        # 5. Save score when suspicious activity
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
            # 6. Incident Response
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


def start_monitor(folder, system_id):

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
        ]
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

    return observer