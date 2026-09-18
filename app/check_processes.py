from database import SessionLocal
from models import Process


session = SessionLocal()

processes = (
    session.query(Process)
    .order_by(Process.id.desc())
    .limit(10)
    .all()
)

print("Latest stored process records:")

for process in processes:
    print(
        f"PID: {process.pid} | "
        f"Name: {process.process_name} | "
        f"CPU: {process.cpu_percent}% | "
        f"Memory: {process.memory_percent}% | "
        f"Disk Writes: {process.disk_write_bytes} bytes"
    )

session.close()