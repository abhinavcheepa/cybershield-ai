"""Pydantic request/response contracts.

Every write endpoint takes a model from here, so validation happens at the
trust boundary rather than inside handlers.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import EventStatus, IncidentStatus, Role, Severity, SimulationStatus

ORM = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------- auth
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class UserOut(BaseModel):
    model_config = ORM
    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


# ------------------------------------------------------------------- events
class AssetOut(BaseModel):
    model_config = ORM
    id: int
    name: str
    hostname: str
    ip_address: str
    service: str
    port: int
    criticality: Severity
    owner: str


class AIExplanationOut(BaseModel):
    model_config = ORM
    why_detected: str
    potential_impact: str
    mitre_mapping: str
    recommended_mitigation: str
    future_prevention: list[str]
    confidence: float
    generated_by: str
    created_at: datetime


class AttackEventOut(BaseModel):
    model_config = ORM

    id: int
    uid: str
    detected_at: datetime
    attack_type: str
    name: str
    description: str
    severity: Severity
    status: EventStatus
    confidence: float
    threat_score: float
    recommended_action: str
    mitre_tactic: str
    mitre_technique: str

    source_ip: str
    source_port: int
    source_country: str
    source_country_name: str
    source_lat: float
    source_lon: float

    destination_ip: str
    destination_port: int
    destination_country: str
    destination_country_name: str
    destination_lat: float
    destination_lon: float

    protocol: str
    packet_count: int
    bytes_transferred: int
    response_time_ms: int
    blocked: bool
    simulated: bool
    indicators: list[str]
    asset: AssetOut | None = None


class AttackEventDetail(AttackEventOut):
    raw_log: dict
    explanation: AIExplanationOut | None = None


class EventPage(BaseModel):
    items: list[AttackEventOut]
    total: int
    page: int
    page_size: int


class EventStatusUpdate(BaseModel):
    status: EventStatus
    note: str = Field("", max_length=500)


# --------------------------------------------------------------- dashboard
class SeverityCount(BaseModel):
    severity: Severity
    count: int


class NamedCount(BaseModel):
    name: str
    count: int
    extra: str = ""


class CountryStat(BaseModel):
    country_code: str
    country_name: str
    latitude: float
    longitude: float
    count: int
    critical_count: int


class TimeBucket(BaseModel):
    timestamp: datetime
    count: int
    critical: int
    high: int
    blocked: int
    threat_score: float
    avg_response_ms: int


class DashboardStats(BaseModel):
    total_attacks: int
    active_attacks: int
    critical_attacks: int
    blocked_attacks: int
    threat_score: float
    attacks_last_hour: int
    attacks_previous_hour: int
    trend_pct: float
    avg_response_time_ms: int
    unique_attackers: int
    countries_involved: int
    by_severity: list[SeverityCount]
    top_attack_types: list[NamedCount]
    top_targeted_assets: list[NamedCount]
    top_attackers: list[NamedCount]
    top_targeted_services: list[NamedCount]


# ------------------------------------------------------------------- rules
class DetectionRuleOut(BaseModel):
    model_config = ORM
    id: int
    key: str
    name: str
    attack_type: str
    description: str
    severity: Severity
    confidence: float
    base_score: float
    mitre_tactic: str
    mitre_technique: str
    recommended_action: str
    enabled: bool
    hit_count: int
    updated_at: datetime


class DetectionRuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    base_score: float | None = Field(None, ge=0.0, le=100.0)


# ----------------------------------------------------------- notifications
class NotificationOut(BaseModel):
    model_config = ORM
    id: int
    event_id: int | None
    title: str
    message: str
    severity: Severity
    is_read: bool
    created_at: datetime


# --------------------------------------------------------- threat intel
class ThreatActorOut(BaseModel):
    model_config = ORM
    id: int
    ip_address: str
    country_code: str
    country_name: str
    label: str
    event_count: int
    threat_score: float
    is_blocked: bool
    tags: list[str]
    first_seen: datetime
    last_seen: datetime


class IncidentOut(BaseModel):
    model_config = ORM
    id: int
    reference: str
    title: str
    summary: str
    severity: Severity
    status: IncidentStatus
    assigned_to: str | None
    opened_at: datetime
    closed_at: datetime | None


# ---------------------------------------------------------------- simulator
class SimulationConfig(BaseModel):
    """Controls for the synthetic attack generator.

    `scenarios` empty means "all". Countries are ISO-2 codes from /api/countries.
    """

    scenarios: list[str] = Field(default_factory=list)
    source_countries: list[str] = Field(default_factory=list)
    events_per_minute: int = Field(30, ge=1, le=600)
    randomize_ips: bool = True
    repeat: bool = True

    @field_validator("scenarios")
    @classmethod
    def _known_scenarios(cls, value: list[str]) -> list[str]:
        from .simulator.scenarios import SCENARIOS

        unknown = sorted(set(value) - set(SCENARIOS))
        if unknown:
            raise ValueError(f"Unknown scenario(s): {', '.join(unknown)}")
        return value

    @field_validator("source_countries")
    @classmethod
    def _known_countries(cls, value: list[str]) -> list[str]:
        from .geo import COUNTRIES

        codes = [c.upper() for c in value]
        unknown = sorted(set(codes) - set(COUNTRIES))
        if unknown:
            raise ValueError(f"Unknown country code(s): {', '.join(unknown)}")
        return codes


class ScenarioInfo(BaseModel):
    key: str
    name: str
    description: str
    expected_detection: str


class SimulationState(BaseModel):
    status: SimulationStatus
    config: SimulationConfig
    events_generated: int
    detections: int
    started_at: datetime | None = None
    started_by: str | None = None


class SimulationRunOut(BaseModel):
    model_config = ORM
    id: int
    started_by: str
    status: SimulationStatus
    config: dict
    events_generated: int
    started_at: datetime
    stopped_at: datetime | None


# ---------------------------------------------------------------- audit
class AuditLogOut(BaseModel):
    model_config = ORM
    id: int
    actor: str
    action: str
    resource: str
    detail: dict
    ip_address: str
    created_at: datetime
