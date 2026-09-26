import psutil
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import Process


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
    Collect current system process activity and convert it
    into ransomware-relevant behavioral signals.

    This does NOT treat normal CPU usage as ransomware.
    CPU becomes suspicious only when combined with
    significant process disk-write activity.
    """

    max_cpu = 0.0
    total_disk_write = 0
    high_cpu_processes = 0

    try:
        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "cpu_percent",
                "memory_percent"
            ]
        ):
            try:
                info = process.info

                cpu = float(info.get("cpu_percent") or 0)

                try:
                    io_counters = process.io_counters()
                    disk_write = int(
                        io_counters.write_bytes or 0
                    )
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    disk_write = 0

                max_cpu = max(max_cpu, cpu)
                total_disk_write += disk_write

                if cpu >= 70:
                    high_cpu_processes += 1

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

    except Exception as error:
        print("Process signal collection error:", error)

    cpu_spike = max_cpu >= 70

    disk_write_spike = (
        total_disk_write >= 10 * 1024 * 1024
    )

    combined_process_activity = (
        cpu_spike and disk_write_spike
    )

    return {
        "max_cpu": round(max_cpu, 2),
        "total_disk_write_bytes": total_disk_write,
        "high_cpu_processes": high_cpu_processes,
        "cpu_spike": cpu_spike,
        "disk_write_spike": disk_write_spike,
        "combined_process_activity": combined_process_activity
    }


if __name__ == "__main__":
    collect_processes()

    signals = get_process_signals()

    print("Current process signals:")
    print(signals)