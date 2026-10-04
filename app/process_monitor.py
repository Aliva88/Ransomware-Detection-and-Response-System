import os
import time
import threading

import psutil
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import Process


# ------------------------------------------------------------
# Settings for live process signals
# ------------------------------------------------------------

# Re-use the last snapshot for this many seconds.
# Scanning every process is slow (~2 seconds on Windows),
# so doing it on every single file event blocks the file monitor.
SIGNAL_CACHE_SECONDS = 5

# A single process using at least this much CPU counts as a spike.
CPU_SPIKE_PERCENT = 70

# Bytes written by ALL processes since the previous snapshot
# that count as a disk-write spike.
DISK_WRITE_SPIKE_BYTES = 10 * 1024 * 1024

# Processes that must never be counted.
# "System Idle Process" (pid 0) reports idle time as CPU usage
# on Windows, which looks like 800-1000% CPU on an idle laptop.
# Our own process is ignored so RDRS does not detect itself.
IGNORED_PIDS = {0, os.getpid()}
IGNORED_NAMES = {"system idle process"}

_lock = threading.Lock()
_previous_writes = {}
_last_snapshot_time = 0.0
_cached_signals = None


def collect_processes():
    session = SessionLocal()

    try:
        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "cpu_percent",
                "memory_percent",
                "exe",
                "ppid"
            ]
        ):
            try:
                info = process.info

                try:
                    io_counters = process.io_counters()
                    disk_write_bytes = io_counters.write_bytes
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    disk_write_bytes = 0

                process_record = Process(
                    pid=info["pid"],
                    process_name=info["name"] or "Unknown",
                    cpu_percent=str(info["cpu_percent"] or 0),
                    memory_percent=str(info["memory_percent"] or 0),
                    disk_write_bytes=disk_write_bytes,
                    executable_path=info["exe"] or "Unknown",
                    parent_pid=info["ppid"],
                    timestamp=datetime.now(timezone.utc)
                )

                session.add(process_record)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        session.commit()

        print("Process information collected successfully!")

    except Exception as error:
        session.rollback()
        print("Error while collecting processes:", error)

    finally:
        session.close()


def get_process_signals():
    """
    Convert current process activity into ransomware-relevant signals.

    Fixes compared to the old version:
      - The idle process and RDRS itself are ignored.
      - Disk writes are measured as bytes written SINCE THE LAST
        SNAPSHOT (a delta). Before, lifetime totals were used, so
        the spike was always True.
      - Results are cached for a few seconds so file events are
        not slowed down by a full process scan every time.

    CPU alone is never treated as ransomware. It only counts
    when combined with a real burst of disk writes.
    """

    global _previous_writes, _last_snapshot_time, _cached_signals

    with _lock:
        now = time.monotonic()

        if (
            _cached_signals is not None
            and (now - _last_snapshot_time) < SIGNAL_CACHE_SECONDS
        ):
            return dict(_cached_signals)

        max_cpu = 0.0
        high_cpu_processes = 0
        total_disk_write = 0
        disk_written_since_last = 0
        current_writes = {}

        try:
            for process in psutil.process_iter(
                [
                    "pid",
                    "name",
                    "cpu_percent"
                ]
            ):
                try:
                    info = process.info

                    pid = info["pid"]
                    name = (info.get("name") or "").lower()

                    if pid in IGNORED_PIDS or name in IGNORED_NAMES:
                        continue

                    cpu = float(info.get("cpu_percent") or 0)

                    max_cpu = max(max_cpu, cpu)

                    if cpu >= CPU_SPIKE_PERCENT:
                        high_cpu_processes += 1

                    try:
                        write_bytes = int(
                            process.io_counters().write_bytes or 0
                        )
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess
                    ):
                        continue

                    total_disk_write += write_bytes
                    current_writes[pid] = write_bytes

                    previous = _previous_writes.get(pid)

                    if previous is not None and write_bytes >= previous:
                        disk_written_since_last += (
                            write_bytes - previous
                        )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    continue

        except Exception as error:
            print("Process signal collection error:", error)

        _previous_writes = current_writes

        cpu_spike = max_cpu >= CPU_SPIKE_PERCENT

        disk_write_spike = (
            disk_written_since_last >= DISK_WRITE_SPIKE_BYTES
        )

        combined_process_activity = (
            cpu_spike and disk_write_spike
        )

        signals = {
            "max_cpu": round(max_cpu, 2),
            "total_disk_write_bytes": total_disk_write,
            "disk_written_since_last_check_bytes": disk_written_since_last,
            "high_cpu_processes": high_cpu_processes,
            "cpu_spike": cpu_spike,
            "disk_write_spike": disk_write_spike,
            "combined_process_activity": combined_process_activity
        }

        _cached_signals = signals
        _last_snapshot_time = now

        return dict(signals)


if __name__ == "__main__":
    collect_processes()

    signals = get_process_signals()

    print("Current process signals:")
    print(signals)