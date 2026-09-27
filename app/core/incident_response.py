from app.core.incident_repository import (
    create_incident,
    get_open_incident
)


class IncidentResponse:

    def __init__(self, system_id, critical_threshold=80):
        self.system_id = system_id
        self.critical_threshold = critical_threshold

    def handle_detection(
        self,
        threat_result,
        detection_result
    ):
        """
        Create an incident when the threat is Critical.

        If an open ransomware incident already exists,
        do not create another duplicate incident.
        """

        score = threat_result["score"]
        threat_level = threat_result["threat_level"]

        # -----------------------------------------
        # Only Critical activity creates incidents
        # -----------------------------------------

        if score < self.critical_threshold:
            return None

        # -----------------------------------------
        # Check for existing open incident
        # -----------------------------------------

        existing_incident = get_open_incident(
            incident_type="Ransomware Activity"
        )

        if existing_incident is not None:

            return existing_incident

        # -----------------------------------------
        # Create new incident
        # -----------------------------------------

        description = (
            f"Critical ransomware activity detected. "
            f"Threat score: {score}. "
            f"Modified files: "
            f"{detection_result['modified_count']}. "
            f"Renamed files: "
            f"{detection_result['rename_count']}."
        )

        incident = create_incident(
            incident_type="Ransomware Activity",
            severity=threat_level,
            description=description,
            system_id=self.system_id
        )

        return incident