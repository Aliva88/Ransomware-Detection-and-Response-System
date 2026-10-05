import time
from pathlib import Path

from app.detectors.file_monitor import start_monitor


SANDBOX = Path("data/sandbox")

# Test system identifier.
# The monitor only needs this value to associate
# detected activity with a system.
TEST_SYSTEM_ID = "TEST-SYSTEM-001"


def main():
    observer = start_monitor(
        SANDBOX,
        TEST_SYSTEM_ID
    )

    try:
        print("RDRS file monitor is running...")
        print("Watching:", SANDBOX.resolve())
        print("System ID:", TEST_SYSTEM_ID)
        print("Press Ctrl+C to stop.")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping monitor...")

    finally:
        observer.stop()
        observer.join()
        print("Monitor stopped safely.")


if __name__ == "__main__":
    main()