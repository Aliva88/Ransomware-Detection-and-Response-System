from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, index=True)
    pid = Column(Integer, nullable=False)
    process_name = Column(String, nullable=False)
    cpu_percent = Column(String)
    memory_percent = Column(String)
    disk_write_bytes = Column(Integer)
    executable_path = Column(String)
    parent_pid = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Score(Base):
    __tablename__ = "scores"

    id = Column(Integer, primary_key=True, index=True)
    score = Column(Integer, nullable=False)
    level = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String, nullable=False)
    message = Column(String)
    severity = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String)
    status = Column(String, default="open")
    timestamp = Column(DateTime, default=datetime.utcnow)