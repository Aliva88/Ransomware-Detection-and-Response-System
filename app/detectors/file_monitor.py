from pathlib import Path
from datetime import datetime

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.core.logging import logger
from app.detectors.detection_engine import DetectionEngine


class RDRSEventHandler(FileSystemEventHandler):

    def __init__(self, detection_engine):
        super().__init__()
        self.detection_engine = detection_engine

    def _record_event(self, event_type, path, old_path=None):

        file_path = Path(path)

        event_data = {
            "event_type": event_type,
            "path": str(file_path),
            "timestamp": datetime.now().isoformat(),
            "extension": file_path.suffix.lower(),
        }

        if old_path:
            old_file_path = Path(old_path)

            event_data["old_path"] = str(old_file_path)
            event_data["old_extension"] = old_file_path.suffix.lower()

        logger.info(f"File event: {event_data}")

        self.detection_engine.add_event(event_data)

        result = self.detection_engine.analyze()

        if result["suspicious"]:
            logger.warning(
                f"Suspicious activity detected: {result}"
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


def start_monitor(folder):

    folder_path = Path(folder)

    if not folder_path.exists():
        raise FileNotFoundError(
            f"Monitoring folder does not exist: {folder_path}"
        )

    detection_engine = DetectionEngine()

    observer = Observer()

    handler = RDRSEventHandler(
        detection_engine
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