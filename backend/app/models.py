"""SQLAlchemy models for CyberShield AI.

Country and AttackType are deliberately NOT tables: their rows never change at
runtime, so they live as static catalogs in `geo.py` and `detection/rules.py`
and are denormalised onto AttackEvent. That keeps the hot query (timeline +
dashboard aggregation) join-free.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, enum.Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class SimulationStatus(str, enum.Enum):
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    """A monitored host/service in the lab estate — the attack destination."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    service: Mapped[str] = mapped_column(String(60))
    port: Mapped[int] = mapped_column(Integer)
    criticality: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    owner: Mapped[str] = mapped_column(String(120), default="Security Operations")
    country_code: Mapped[str] = mapped_column(String(2), default="IN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ThreatActor(Base):
    """Aggregated reputation for a source IP seen by the detection engine."""

    __tablename__ = "threat_actors"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    country_code: Mapped[str] = mapped_column(String(2), index=True)
    country_name: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(120), default="Unattributed")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetectionRule(Base):
    """Persisted, tunable copy of a rule defined in detection/rules.py."""

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(60), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    attack_type: Mapped[str] = mapped_column(String(60), index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    confidence: Mapped[float] = mapped_column(Float)
    base_score: Mapped[float] = mapped_column(Float)
    mitre_tactic: Mapped[str] = mapped_column(String(80))
    mitre_technique: Mapped[str] = mapped_column(String(120))
    recommended_action: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AttackEvent(Base):
    __tablename__ = "attack_events"
    __table_args__ = (
        Index("ix_events_detected_severity", "detected_at", "severity"),
        Index("ix_events_type_detected", "attack_type", "detected_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    attack_type: Mapped[str] = mapped_column(String(60), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    status: Mapped[EventStatus] = mapped_column(Enum(EventStatus), default=EventStatus.ACTIVE, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    threat_score: Mapped[float] = mapped_column(Float, index=True)
    recommended_action: Mapped[str] = mapped_column(Text)
    mitre_tactic: Mapped[str] = mapped_column(String(80))
    mitre_technique: Mapped[str] = mapped_column(String(120))

    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int] = mapped_column(Integer, default=0)
    source_country: Mapped[str] = mapped_column(String(2), index=True)
    source_country_name: Mapped[str] = mapped_column(String(80))
    source_lat: Mapped[float] = mapped_column(Float)
    source_lon: Mapped[float] = mapped_column(Float)

    destination_ip: Mapped[str] = mapped_column(String(45))
    destination_port: Mapped[int] = mapped_column(Integer, default=0)
    destination_country: Mapped[str] = mapped_column(String(2))
    destination_country_name: Mapped[str] = mapped_column(String(80))
    destination_lat: Mapped[float] = mapped_column(Float)
    destination_lon: Mapped[float] = mapped_column(Float)

    protocol: Mapped[str] = mapped_column(String(12))
    # BigInteger, not Integer: alert correlation folds every repeat detection in
    # a 45-second window into the open event, so a sustained flood accumulates
    # these two well past 2^31. SQLite stores any integer regardless and hid
    # this; Postgres raises NumericValueOutOfRange and takes the whole ingest
    # transaction down with it.
    packet_count: Mapped[int] = mapped_column(BigInteger, default=1)
    bytes_transferred: Mapped[int] = mapped_column(BigInteger, default=0)
    response_time_ms: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)

    raw_log: Mapped[dict] = mapped_column(JSON, default=dict)
    indicators: Mapped[list] = mapped_column(JSON, default=list)

    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("detection_rules.id"))
    threat_actor_id: Mapped[int | None] = mapped_column(ForeignKey("threat_actors.id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"))

    asset: Mapped[Asset | None] = relationship(lazy="joined")
    explanation: Mapped[AIExplanation | None] = relationship(
        back_populates="event", uselist=False, cascade="all, delete-orphan"
    )


class AIExplanation(Base):
    __tablename__ = "ai_explanations"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("attack_events.id", ondelete="CASCADE"), unique=True)
    why_detected: Mapped[str] = mapped_column(Text)
    potential_impact: Mapped[str] = mapped_column(Text)
    mitre_mapping: Mapped[str] = mapped_column(Text)
    recommended_mitigation: Mapped[str] = mapped_column(Text)
    future_prevention: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float)
    generated_by: Mapped[str] = mapped_column(String(60), default="rules-engine")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    event: Mapped[AttackEvent] = relationship(back_populates="explanation")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("attack_events.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(24), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    assigned_to: Mapped[str | None] = mapped_column(String(120))
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AttackSimulation(Base):
    __tablename__ = "attack_simulations"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_by: Mapped[str] = mapped_column(String(255))
    status: Mapped[SimulationStatus] = mapped_column(Enum(SimulationStatus), default=SimulationStatus.RUNNING)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    events_generated: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource: Mapped[str] = mapped_column(String(120))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
