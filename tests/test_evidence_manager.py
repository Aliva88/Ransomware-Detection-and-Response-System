from pathlib import Path

from app.core.evidence_manager import EvidenceManager


def test_copy_evidence(tmp_path):

    original_file = tmp_path / "test_file.txt"
    original_file.write_text("ransomware test data")

    evidence_directory = tmp_path / "evidence"

    manager = EvidenceManager(
        evidence_directory=str(evidence_directory)
    )

    evidence_file = manager.copy_evidence(
        str(original_file)
    )

    assert evidence_file is not None
    assert Path(evidence_file).exists()

    # Original file must remain unchanged
    assert original_file.exists()
    assert original_file.read_text() == "ransomware test data"

    # Evidence must contain the same data
    assert Path(evidence_file).read_text() == "ransomware test data"