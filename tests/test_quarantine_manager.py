from pathlib import Path

from app.core.quarantine_manager import QuarantineManager


def test_quarantine_simulation(tmp_path):

    original_file = tmp_path / "suspicious.txt"
    original_file.write_text("suspicious data")

    quarantine_directory = tmp_path / "quarantine"

    manager = QuarantineManager(
        quarantine_directory=str(quarantine_directory),
        simulation_mode=True
    )

    result = manager.quarantine_file(
        str(original_file)
    )

    assert result is not None
    assert result["simulated"] is True

    # Original file must remain untouched
    assert original_file.exists()
    assert original_file.read_text() == "suspicious data"

    # Simulation mode must not create/move the file
    assert not Path(result["destination"]).exists()