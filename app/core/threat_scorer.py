class ThreatScorer:
    """
    Calculates the overall ransomware threat score
    from file and process behavior.
    """

    def __init__(self, scoring_config):
        self.scores = scoring_config

    def calculate_score(self, behaviors):
        """
        Calculate total threat score from detected behaviors.
        """

        total_score = 0

        for behavior, detected in behaviors.items():

            if detected:
                total_score += self.scores.get(
                    behavior,
                    0
                )

        # Dashboard score must always stay within 0-100.
        return min(total_score, 100)

    def get_threat_level(self, score):
        """
        Convert numerical score into a threat level.
        """

        if score >= 80:
            return "Critical"

        elif score >= 60:
            return "High"

        elif score >= 30:
            return "Medium"

        return "Low"

    def analyze(self, behaviors):
        """
        Calculate score and threat level.
        """

        score = self.calculate_score(
            behaviors
        )

        threat_level = self.get_threat_level(
            score
        )

        return {
            "score": score,
            "threat_level": threat_level
        }

    def analyze_detection(
        self,
        detection_result,
        process_result=None
    ):
        """
        Convert file and process detection results
        into combined ransomware threat signals.
        """

        process_result = process_result or {}

        rapid_encryption = (
            detection_result.get(
                "modified_count",
                0
            ) >= 20
        )

        mass_rename = (
            detection_result.get(
                "rename_count",
                0
            ) >= 10
        )

        extension_change = (
            detection_result.get(
                "extension_changes",
                0
            ) >= 5
        )

        high_entropy = detection_result.get(
            "high_entropy",
            False
        )

        cpu_spike = process_result.get(
            "combined_process_activity",
            False
        )

        unknown_program = process_result.get(
            "unknown_program",
            False
        )

        behaviors = {
            "rapid_encryption": rapid_encryption,
            "mass_rename": mass_rename,
            "high_entropy": high_entropy,
            "cpu_spike": cpu_spike,
            "unknown_program": unknown_program
        }

        result = self.analyze(
            behaviors
        )

        return {
            **result,
            "behaviors": behaviors,
            "detection": detection_result,
            "process": process_result
        }