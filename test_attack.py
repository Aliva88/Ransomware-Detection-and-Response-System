from pathlib import Path
import os
import time

sandbox = Path("data/sandbox")

sandbox.mkdir(parents=True, exist_ok=True)

print("Creating safe test files...")

test_files = []

for i in range(50):
    file_path = sandbox / f"ransom_test_{i}.txt"
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
    file_path.rename(locked_path)

print("50 files renamed to .locked")

print()
print("SAFE TEST COMPLETE")
print("Only data/sandbox was used.")