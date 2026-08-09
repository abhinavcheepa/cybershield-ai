"""Observation -> detection -> persistence.

Everything that produces security telemetry funnels through `ingest()`: the
attack simulator today, a pcap/syslog reader tomorrow. Detection, scoring,
geolocation, actor reputation, AI explanation and notification all happen here
once, so no caller can skip a step.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import bus, geo
from .ai.explain import build_explanation
from .detection.engine import Detection, engine
from .detection.rules import Observation
from .models import (
    AIExplanation,
    Asset,
    AttackEvent,
    DetectionRule,
    EventStatus,
    Notification,
    Severity,
    ThreatActor,
)

log = logging.getLogger(__name__)

#: Score at or above which the (simulated) perimeter auto-blocks the source.
AUTO_BLOCK_SCORE = 85.0

#: Only these reach the notification centre — everything is on the timeline.
NOTIFY_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

#: Repeat detections of the same rule against the same pair inside this window
#: fold into the open event instead of creating a new one. Without it a single
#: 400-packet flood would produce hundreds of identical timeline rows.
CORRELATION_WINDOW_S = 45.0


class _AlertIndex:
    """(rule_key, source_ip, destination_ip) -> the event absorbing repeats.

    In Redis when the workers have to agree on it — a flood spread across four
    workers is still one event — and a plain dict when there is only one worker.
    Expiry *is* the window in both cases.
    """

    def __init__(self) -> None:
        self._local: dict[tuple[str, str, str], tuple[int, float]] = {}

    def _key(self, key: tuple[str, str, str]) -> str:
        return "cybershield:alert:" + ":".join(key)

    def get(self, key: tuple[str, str, str]) -> int | None:
        if bus.enabled:
            found = bus.redis().get(self._key(key))
            return int(found) if found else None
        entry = self._local.get(key)
        if entry is None:
            return None
        event_id, seen_at = entry
        if time.monotonic() - seen_at > CORRELATION_WINDOW_S:
            self._local.pop(key, None)
            return None
        return event_id

    def put(self, key: tuple[str, str, str], event_id: int) -> None:
        if bus.enabled:
            bus.redis().set(self._key(key), event_id, ex=int(CORRELATION_WINDOW_S))
        else:
            self._local[key] = (event_id, time.monotonic())

    def drop(self, key: tuple[str, str, str]) -> None:
        if bus.enabled:
            bus.redis().delete(self._key(key))
        else:
            self._local.pop(key, None)

    def clear(self) -> None:
        # Nothing to clear in Redis: entries expire on their own, and a key that
        # outlives its event is dropped by `_correlate` the moment the row it
        # points at fails to load. Scanning for keys to delete would buy nothing.
        self._local.clear()


_open_alerts = _AlertIndex()


def reset_correlation() -> None:
    _open_alerts.clear()


def _correlate(db: Session, key: tuple[str, str, str], obs: Observation, score: float) -> bool:
    """Fold `obs` into an already-open alert. True if it was absorbed."""
    event_id = _open_alerts.get(key)
    if event_id is None:
        return False

    event = db.get(AttackEvent, event_id)
    if event is None:  # deleted underneath us
        _open_alerts.drop(key)
        return False

    event.packet_count += int(obs.get("packet_count", 1) or 1)
    event.bytes_transferred += int(obs.get("bytes", 0) or 0)
    event.threat_score = max(event.threat_score, score)
    event.blocked = event.blocked or event.threat_score >= AUTO_BLOCK_SCORE
    _open_alerts.put(key, event_id)
    return True


#: rule key -> DetectionRule.id. The catalog is static after seeding, so this
#: saves a lookup on every single observation.
_rule_ids: dict[str, int] = {}


def reset_caches() -> None:
    _rule_ids.clear()


def _rule_id(db: Session, key: str) -> int | None:
    if key not in _rule_ids:
        found = db.scalar(select(DetectionRule.id).where(DetectionRule.key == key))
        if found is None:
            return None
        _rule_ids[key] = found
    return _rule_ids[key]


def _asset_for(db: Session, ip: str, port: int) -> Asset | None:
    assets = db.scalars(select(Asset).where(Asset.ip_address == ip)).all()
    if not assets:
        return None
    return next((a for a in assets if a.port == port), assets[0])


def _upsert_actor(db: Session, ip: str, location: geo.GeoLocation, score: float) -> ThreatActor:
    actor = db.scalar(select(ThreatActor).where(ThreatActor.ip_address == ip))
    now = datetime.now(UTC)
    if actor is None:
        # Column `default=`s only apply at INSERT time, so a freshly constructed
        # instance has None in every defaulted field. Set them explicitly —
        # the counters below are read before the first flush.
        actor = ThreatActor(
            ip_address=ip,
            country_code=location.country_code,
            country_name=location.country_name,
            label="Unattributed",
            event_count=0,
            threat_score=0.0,
            is_blocked=False,
            tags=[],
            first_seen=now,
            last_seen=now,
        )
        db.add(actor)
    actor.last_seen = now
    actor.event_count += 1
    # Reputation is the worst thing we have seen from this address, nudged up
    # by repetition — one critical hit should not be diluted by later noise.
    actor.threat_score = round(min(100.0, max(actor.threat_score, score) + 0.5 * (actor.event_count - 1)), 1)
    actor.is_blocked = actor.is_blocked or actor.threat_score >= AUTO_BLOCK_SCORE
    return actor


def _describe(detection: Detection, obs: Observation) -> str:
    base = detection.rule.description
    target = obs.get("destination_ip", "the monitored estate")
    return f"{base} Observed against {target} from {obs.get('source_ip', 'an unknown source')}."


def ingest(
    db: Session, obs: Observation, *, simulated: bool = True, commit: bool = True
) -> AttackEvent | None:
    """Analyse one observation. Returns the stored event, or None if benign.

    None also means "absorbed into an already-open alert" — see `_correlate`.
    Pass `commit=False` to batch a whole episode into one transaction; the
    caller then owns the commit.
    """
    detection = engine.analyze(obs)
    if detection is None:
        return None

    source_ip = obs.get("source_ip", "0.0.0.0")
    destination_ip = obs.get("destination_ip", "10.0.0.1")
    # Group alerts on the same endpoint the rule counts on. A DDoS aggregates
    # by victim, so keying on the source would open a new alert per spoofed
    # packet; everything else aggregates by attacker.
    alert_key = (
        (detection.rule.key, "*", destination_ip)
        if detection.rule.correlate_by == "destination"
        else (detection.rule.key, source_ip, destination_ip)
    )
    if _correlate(db, alert_key, obs, detection.threat_score):
        return None

    source_geo = geo.lookup(source_ip)
    destination_geo = geo.lookup(destination_ip)
    asset = _asset_for(db, destination_ip, int(obs.get("destination_port", 0) or 0))
    actor = _upsert_actor(db, source_ip, source_geo, detection.threat_score)
    db.flush()  # actor.id

    event = AttackEvent(
        attack_type=detection.attack_type,
        name=detection.rule.name,
        description=_describe(detection, obs),
        severity=detection.severity,
        status=EventStatus.ACTIVE,
        confidence=detection.confidence,
        threat_score=detection.threat_score,
        recommended_action=detection.rule.recommended_action,
        mitre_tactic=detection.rule.mitre_tactic,
        mitre_technique=detection.rule.mitre_technique,
        source_ip=source_ip,
        source_port=int(obs.get("source_port", 0) or 0),
        destination_ip=destination_ip,
        destination_port=int(obs.get("destination_port", 0) or 0),
        protocol=str(obs.get("protocol", "TCP")).upper(),
        packet_count=int(obs.get("packet_count", 1) or 1),
        bytes_transferred=int(obs.get("bytes", 0) or 0),
        response_time_ms=int(obs.get("response_time_ms", 0) or 0),
        blocked=detection.threat_score >= AUTO_BLOCK_SCORE or actor.is_blocked,
        simulated=simulated,
        raw_log=dict(obs),
        indicators=detection.indicators,
        asset_id=asset.id if asset else None,
        rule_id=_rule_id(db, detection.rule.key),
        threat_actor_id=actor.id,
        **source_geo.as_source(),
        **destination_geo.as_destination(),
    )
    db.add(event)
    db.flush()  # event.id

    explanation = build_explanation(event)
    db.add(AIExplanation(event_id=event.id, **explanation.as_dict()))

    if detection.severity in NOTIFY_SEVERITIES:
        db.add(
            Notification(
                event_id=event.id,
                title=f"{detection.severity.value.upper()}: {detection.rule.name}",
                message=(
                    f"{source_ip} ({source_geo.country_name}) -> "
                    f"{destination_ip}:{event.destination_port}"
                    f" | score {event.threat_score:.0f}"
                    f"{' | auto-blocked' if event.blocked else ''}"
                ),
                severity=detection.severity,
            )
        )

    if event.rule_id is not None:
        rule = db.get(DetectionRule, event.rule_id)
        if rule:
            rule.hit_count += 1

    if commit:
        db.commit()
        db.refresh(event)
    _open_alerts.put(alert_key, event.id)
    return event


def ingest_many(
    db: Session, observations: list[Observation], *, simulated: bool = True
) -> list[AttackEvent]:
    """Run a whole attack episode as one transaction.

    Stateful rules (port scan, brute force, DDoS) only cross their thresholds
    partway through a sequence, so the whole episode has to be replayed. A
    320-packet flood is ~320 observations — committing per observation made
    seeding take minutes, so the batch commits once at the end.
    """
    events: list[AttackEvent] = []
    try:
        for obs in observations:
            event = ingest(db, obs, simulated=simulated, commit=False)
            if event is not None:
                events.append(event)
        db.commit()
    except Exception:
        db.rollback()
        # None of the episode's events landed, so every correlation key added
        # during it now points at a row that does not exist. The map is only a
        # cache, so drop it wholesale rather than tracking which keys were ours.
        reset_correlation()
        log.exception(
            "episode ingest failed (source=%s)",
            observations[0].get("source_ip") if observations else "?",
        )
        return []
    return events
