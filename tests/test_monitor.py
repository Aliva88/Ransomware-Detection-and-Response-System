import time
from pathlib import Path

from app.detectors.file_monitor import start_monitor


SANDBOX = Path("data/sandbox")


observer = start_monitor(SANDBOX)

try:
    print("RDRS file monitor is running...")
    print("Watching:", SANDBOX.resolve())
    print("Press Ctrl+C to stop.")

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopping monitor...")

finally:
    observer.stop()
    observer.join()
    print("Monitor stopped safely.")