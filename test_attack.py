from pathlib import Path
import os
import time


sandbox = Path("data/sandbox")


def run_attack_simulation():
    sandbox.mkdir(parents=True, exist_ok=True)

    print("Creating safe test files...")

    test_files = []

    for i in range(50):
        file_path = sandbox / f"ransom_test_{i}.txt"

        # Remove an old test file if it exists
        if file_path.exists():
            file_path.unlink()

        locked_path = sandbox / f"ransom_test_{i}.locked"

        # Remove an old renamed test file if it exists
        if locked_path.exists():
            locked_path.unlink()

        file_path.write_text(
            "RansomShield safe detection test file.",
            encoding="utf-8"
        )

        test_files.append(file_path)

    print("50 test files created.")

    time.sleep(2)

    print("Simulating suspicious file modification...")

    for file_path in test_files:
        file_path.write_bytes(os.urandom(20000))

    print("50 files modified.")

    time.sleep(2)

    print("Simulating mass rename...")

    for file_path in test_files:
        locked_path = file_path.with_suffix(".locked")

        if locked_path.exists():
            locked_path.unlink()

        file_path.rename(locked_path)

    print("50 files renamed to .locked")

    print()
    print("SAFE TEST COMPLETE")
    print("Only data/sandbox was used.")


if __name__ == "__main__":
    run_attack_simulation()