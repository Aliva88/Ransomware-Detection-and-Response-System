from pathlib import Path
import shutil


class QuarantineManager:

    def __init__(
        self,
        quarantine_directory="data/quarantine",
        simulation_mode=True
    ):
        self.quarantine_directory = Path(quarantine_directory)
        self.simulation_mode = simulation_mode

        self.quarantine_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def quarantine_file(self, file_path):
        """
        Move a file to quarantine when simulation mode is disabled.
        In simulation mode, no actual file operation is performed.
        """

        source = Path(file_path)

        if not source.exists():
            return None

        destination = self.quarantine_directory / source.name

        if self.simulation_mode:
            return {
                "simulated": True,
                "source": str(source),
                "destination": str(destination)
            }

        shutil.move(str(source), str(destination))

        return {
            "simulated": False,
            "source": str(source),
            "destination": str(destination)
        }