import psutil
from datetime import datetime, timezone

from database import SessionLocal
from models import Process


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

                # Get disk I/O information for the process
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
                    cpu_percent=str(info["cpu_percent"]),
                    memory_percent=str(info["memory_percent"]),
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


if __name__ == "__main__":
    collect_processes()