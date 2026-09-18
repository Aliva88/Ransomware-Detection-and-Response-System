from collections import deque
from datetime import datetime, timedelta


class DetectionEngine:

    def __init__(
        self,
        window_seconds=60,
        modified_files_threshold=20,
        rename_threshold=10,
        extension_change_threshold=5
    ):
        self.window_seconds = window_seconds
        self.modified_files_threshold = modified_files_threshold
        self.rename_threshold = rename_threshold
        self.extension_change_threshold = extension_change_threshold

        self.events = deque()

    def add_event(self, event):
        """
        Add a new file event to the sliding window.
        """

        self.events.append(event)

        self._remove_old_events()

    def _remove_old_events(self):
        """
        Remove events older than the configured sliding window.
        """

        current_time = datetime.now()
        cutoff_time = current_time - timedelta(
            seconds=self.window_seconds
        )

        while self.events:
            event_time = datetime.fromisoformat(
                self.events[0]["timestamp"]
            )

            if event_time >= cutoff_time:
                break

            self.events.popleft()

    def analyze(self):
        """
        Analyze events currently inside the sliding window.
        """

        modified_count = sum(
            1
            for event in self.events
            if event["event_type"] == "MODIFY"
        )

        rename_count = sum(
            1
            for event in self.events
            if event["event_type"] == "RENAME"
        )

        extension_changes = self._count_extension_changes()

        suspicious_reasons = []

        if modified_count >= self.modified_files_threshold:
            suspicious_reasons.append(
                "Rapid file modifications detected"
            )

        if rename_count >= self.rename_threshold:
            suspicious_reasons.append(
                "Mass file rename activity detected"
            )

        if extension_changes >= self.extension_change_threshold:
            suspicious_reasons.append(
                "Multiple extension changes detected"
            )

        return {
            "suspicious": len(suspicious_reasons) > 0,
            "modified_count": modified_count,
            "rename_count": rename_count,
            "extension_changes": extension_changes,
            "reasons": suspicious_reasons
        }

    def _count_extension_changes(self):
        """
        Count actual file extension changes
        during the current sliding window.
        """

        count = 0

        for event in self.events:
            old_extension = event.get("old_extension")
            new_extension = event.get("extension")

            if (
                event["event_type"] == "RENAME"
                and old_extension
                and new_extension
                and old_extension != new_extension
            ):
                count += 1

        return count