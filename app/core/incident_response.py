from app.core.incident_repository import create_incident


class IncidentResponse:

    def __init__(self, critical_threshold=80):
        self.critical_threshold = critical_threshold

    def handle_detection(self, threat_result, detection_result):
        """
        Create an incident when the threat is Critical.
        """

        score = threat_result["score"]
        threat_level = threat_result["threat_level"]

        if score < self.critical_threshold:
            return None

        description = (
            f"Critical ransomware activity detected. "
            f"Threat score: {score}. "
            f"Modified files: {detection_result['modified_count']}. "
            f"Renamed files: {detection_result['rename_count']}."
        )

        incident = create_incident(
            incident_type="Ransomware Activity",
            severity=threat_level,
            description=description
        )

        return incident