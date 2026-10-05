from datetime import datetime

from app.detectors.detection_engine import DetectionEngine
from app.core.config_loader import load_config
from app.core.threat_scorer import ThreatScorer
from app.core.score_repository import save_score


TEST_SYSTEM_ID = "TEST-SYSTEM-001"


def test_full_detection_pipeline():

    # Load configuration
    config = load_config()

    # Create Detection Engine
    detection_engine = DetectionEngine(
        window_seconds=config["monitoring"]["sliding_window_seconds"],
        modified_files_threshold=config["detection"]["modified_files_threshold"],
        rename_threshold=config["detection"]["rename_threshold"],
        extension_change_threshold=config["detection"]["extension_change_threshold"]
    )

    # Create Threat Scorer
    scorer = ThreatScorer(config["scoring"])

    # Simulate ransomware-like file activity
    for i in range(25):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "MODIFY"
        })

    for i in range(12):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "RENAME"
        })

    # Step 1: Detection
    detection_result = detection_engine.analyze()

    # Step 2: Threat Scoring
    threat_result = scorer.analyze_detection(detection_result)

    # Step 3: Save score to database
    score_record = save_score(
        system_id=TEST_SYSTEM_ID,
        score=threat_result["score"],
        level=threat_result["threat_level"]
    )

    # Display results
    print("\n=== FULL RDRS PIPELINE ===")
    print("Detection:", detection_result)
    print("Threat:", threat_result)
    print("Database Record:", score_record.id)

    # Verify Detection
    assert detection_result["suspicious"] is True
    assert detection_result["modified_count"] == 25
    assert detection_result["rename_count"] == 12

    # Verify Threat Score
    assert threat_result["score"] == 70
    assert threat_result["threat_level"] == "High"

    # Verify Database
    assert score_record.id is not None
    assert score_record.score == 70
    assert score_record.level == "High"
    assert score_record.system_id == TEST_SYSTEM_ID