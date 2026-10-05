from datetime import datetime

from app.detectors.detection_engine import DetectionEngine
from app.core.config_loader import load_config
from app.core.threat_scorer import ThreatScorer
from app.core.incident_response import IncidentResponse
from app.core.evidence_manager import EvidenceManager
from app.core.quarantine_manager import QuarantineManager


TEST_SYSTEM_ID = 65


def test_incident_response_pipeline(tmp_path):

    config = load_config()

    detection_engine = DetectionEngine(
        window_seconds=config["monitoring"]["sliding_window_seconds"],
        modified_files_threshold=config["detection"]["modified_files_threshold"],
        rename_threshold=config["detection"]["rename_threshold"],
        extension_change_threshold=config["detection"]["extension_change_threshold"]
    )

    scorer = ThreatScorer(config["scoring"])

    # Simulate ransomware activity
    for _ in range(25):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "MODIFY"
        })

    for _ in range(12):
        detection_engine.add_event({
            "timestamp": datetime.now().isoformat(),
            "event_type": "RENAME"
        })

    detection_result = detection_engine.analyze()

    threat_result = scorer.analyze_detection(detection_result)

    # Simulate high entropy detection
    threat_result["behaviors"]["high_entropy"] = True

    threat_result["score"] = scorer.calculate_score(
        threat_result["behaviors"]
    )

    threat_result["threat_level"] = scorer.get_threat_level(
        threat_result["score"]
    )

    # Incident creation
    response = IncidentResponse(
        system_id=TEST_SYSTEM_ID
    )

    incident = response.handle_detection(
        threat_result,
        detection_result
    )

    assert incident is not None
    assert incident.severity == "Critical"

    # Create test suspicious file
    suspicious_file = tmp_path / "important.txt"
    suspicious_file.write_text("test ransomware evidence")

    # Evidence copy
    evidence_manager = EvidenceManager(
        evidence_directory=str(tmp_path / "evidence")
    )

    evidence = evidence_manager.copy_evidence(
        str(suspicious_file)
    )

    assert evidence is not None

    # Quarantine simulation
    quarantine_manager = QuarantineManager(
        quarantine_directory=str(tmp_path / "quarantine"),
        simulation_mode=True
    )

    quarantine_result = quarantine_manager.quarantine_file(
        evidence
    )

    assert quarantine_result["simulated"] is True

    # Original file must still exist
    assert suspicious_file.exists()