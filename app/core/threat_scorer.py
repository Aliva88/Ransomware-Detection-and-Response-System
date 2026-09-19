class ThreatScorer:
    """
    Calculates the overall ransomware threat score
    from detected suspicious behaviors.
    """

    def __init__(self, scoring_config):
        self.scores = scoring_config

    def calculate_score(self, behaviors):
        """
        Calculate total threat score.

        Example:
        {
            "rapid_encryption": True,
            "mass_rename": True,
            "high_entropy": False,
            "cpu_spike": False,
            "unknown_program": False
        }
        """

        total_score = 0

        for behavior, detected in behaviors.items():
            if detected:
                total_score += self.scores.get(behavior, 0)

        return total_score

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
        else:
            return "Low"

    def analyze(self, behaviors):
        """
        Calculate both score and threat level.
        """

        score = self.calculate_score(behaviors)
        threat_level = self.get_threat_level(score)

        return {
            "score": score,
            "threat_level": threat_level
        }

    def analyze_detection(self, detection_result):
        """
        Convert DetectionEngine output into
        threat-scoring signals.
        """

        behaviors = {
            "rapid_encryption": (
                detection_result["modified_count"] >= 20
            ),

            "mass_rename": (
                detection_result["rename_count"] >= 10
            ),

            "high_entropy": False,
            "cpu_spike": False,
            "unknown_program": False
        }

        result = self.analyze(behaviors)

        return {
            **result,
            "behaviors": behaviors,
            "detection": detection_result
        }