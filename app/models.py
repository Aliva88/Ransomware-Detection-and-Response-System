from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class System(Base):
    __tablename__ = "systems"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(String, unique=True, nullable=False, index=True)

    system_name = Column(String, nullable=False)

    hostname = Column(String, nullable=False)

    ip_address = Column(String)

    operating_system = Column(String)

    totp_secret = Column(String)

    verified = Column(Boolean, default=False, nullable=False)

    monitoring = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    last_seen = Column(DateTime)

    events = relationship(
        "Event",
        back_populates="system",
        cascade="all, delete-orphan"
    )

    processes = relationship(
        "Process",
        back_populates="system",
        cascade="all, delete-orphan"
    )

    scores = relationship(
        "Score",
        back_populates="system",
        cascade="all, delete-orphan"
    )

    alerts = relationship(
        "Alert",
        back_populates="system",
        cascade="all, delete-orphan"
    )

    incidents = relationship(
        "Incident",
        back_populates="system",
        cascade="all, delete-orphan"
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(
        Integer,
        ForeignKey("systems.id"),
        nullable=False,
        index=True
    )

    event_type = Column(String, nullable=False)

    file_path = Column(String, nullable=False)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    system = relationship(
        "System",
        back_populates="events"
    )


class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(
        Integer,
        ForeignKey("systems.id"),
        nullable=False,
        index=True
    )

    pid = Column(Integer, nullable=False)

    process_name = Column(String, nullable=False)

    cpu_percent = Column(Float)

    memory_percent = Column(Float)

    disk_write_bytes = Column(Integer)

    executable_path = Column(String)

    parent_pid = Column(Integer)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    system = relationship(
        "System",
        back_populates="processes"
    )


class Score(Base):
    __tablename__ = "scores"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(
        Integer,
        ForeignKey("systems.id"),
        nullable=False,
        index=True
    )

    score = Column(Integer, nullable=False)

    level = Column(String, nullable=False)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    system = relationship(
        "System",
        back_populates="scores"
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(
        Integer,
        ForeignKey("systems.id"),
        nullable=False,
        index=True
    )

    alert_type = Column(String, nullable=False)

    message = Column(String)

    severity = Column(String, nullable=False)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    system = relationship(
        "System",
        back_populates="alerts"
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    system_id = Column(
        Integer,
        ForeignKey("systems.id"),
        nullable=False,
        index=True
    )

    incident_type = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False
    )

    description = Column(String)

    status = Column(
        String,
        default="open"
    )

    threat_score = Column(Integer)

    signals = Column(String)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow
    )

    system = relationship(
        "System",
        back_populates="incidents"
    )