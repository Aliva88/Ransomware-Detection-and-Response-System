from pathlib import Path
import shutil


class EvidenceManager:

    def __init__(self, evidence_directory="data/evidence"):
        self.evidence_directory = Path(evidence_directory)
        self.evidence_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def copy_evidence(self, file_path):
        """
        Copy a suspicious file as evidence.
        Original file remains unchanged.
        """

        source = Path(file_path)

        if not source.exists():
            return None

        destination = self.evidence_directory / source.name

        shutil.copy2(source, destination)

        return str(destination)