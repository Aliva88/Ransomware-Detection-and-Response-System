from datetime import datetime

from app.detectors.detection_engine import DetectionEngine
from app.core.config_loader import load_config
from app.core.threat_scorer import ThreatScorer


def test_detection_to_threat_score():

    config = load_config()

    detection_engine = DetectionEngine(
        window_seconds=config["monitoring"]["sliding_window_seconds"],
        modified_files_threshold=config["detection"]["modified_files_threshold"],
        rename_threshold=config["detection"]["rename_threshold"],
        extension_change_threshold=config["detection"]["extension_change_threshold"]
    )

    scorer = ThreatScorer(config["scoring"])

    # Simulate 25 file modifications
    for i in range(25):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "MODIFY"
        })

    # Simulate 12 file renames
    for i in range(12):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "RENAME"
        })

    detection_result = detection_engine.analyze()

    threat_result = scorer.analyze_detection(detection_result)

    print("\nDetection Result:")
    print(detection_result)

    print("\nThreat Result:")
    print(threat_result)

    assert detection_result["suspicious"] is True
    assert detection_result["modified_count"] == 25
    assert detection_result["rename_count"] == 12

    assert threat_result["score"] == 70
    assert threat_result["threat_level"] == "High"