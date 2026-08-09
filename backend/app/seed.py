"""Seed data.

Idempotent: every step checks before it writes, so `python -m app.seed` is safe
to re-run. Called automatically on startup when the database is empty.
"""

from __future__ import annotations

import logging
import random
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal, init_db
from .detection.engine import engine
from .detection.rules import RULES
from .models import (
    AIExplanation,
    Asset,
    AttackEvent,
    DetectionRule,
    EventStatus,
    Notification,
    Role,
    Severity,
    ThreatActor,
    User,
)
from .pipeline import ingest_many, reset_correlation
from .security import hash_password
from .simulator.runner import DEFAULT_SOURCE_WEIGHTS
from .simulator.scenarios import SCENARIOS

log = logging.getLogger(__name__)

#: Lab credentials. Documented in the README and .env.example — change them
#: before this is reachable from anything but localhost.
DEMO_PASSWORD = "CyberShield#2026"

DEMO_USERS = [
    ("admin@cybershield.io", "Priya Raghavan", Role.ADMIN),
    ("analyst@cybershield.io", "Daniel Okafor", Role.ANALYST),
    ("viewer@cybershield.io", "Mei Tanaka", Role.VIEWER),
]

# The defended estate. Ports line up with what the scenarios target.
ASSETS = [
    ("web-prod-01", "www.cybershield.io", "10.0.0.20", "http", 443, Severity.CRITICAL, "Platform"),
    ("api-gateway-01", "api.cybershield.io", "10.0.0.21", "http", 8443, Severity.CRITICAL, "Platform"),
    ("db-primary-01", "db01.cybershield.io", "10.0.0.30", "postgres", 5432, Severity.CRITICAL, "Data"),
    ("ssh-bastion-01", "bastion.cybershield.io", "10.0.0.10", "ssh", 22, Severity.CRITICAL, "Infrastructure"),
    ("dns-resolver-01", "ns1.cybershield.io", "10.0.0.53", "dns", 53, Severity.HIGH, "Infrastructure"),
    ("mail-relay-01", "mx1.cybershield.io", "10.0.0.25", "smtp", 25, Severity.HIGH, "Infrastructure"),
    ("jenkins-ci-01", "ci.cybershield.io", "10.0.0.70", "http", 8080, Severity.HIGH, "Engineering"),
    ("file-server-01", "files.cybershield.io", "10.0.0.40", "ftp", 21, Severity.MEDIUM, "Corporate IT"),
    ("redis-cache-01", "cache01.cybershield.io", "10.0.0.60", "redis", 6379, Severity.MEDIUM, "Platform"),
    ("vdi-gateway-01", "vdi.cybershield.io", "10.0.0.100", "rdp", 3389, Severity.MEDIUM, "Corporate IT"),
]


def seed_users(db: Session) -> int:
    created = 0
    for email, name, role in DEMO_USERS:
        if db.scalar(select(User).where(User.email == email)):
            continue
        db.add(
            User(
                email=email,
                full_name=name,
                hashed_password=hash_password(DEMO_PASSWORD),
                role=role,
            )
        )
        created += 1
    db.commit()
    return created


def seed_assets(db: Session) -> int:
    created = 0
    for name, hostname, ip, service, port, criticality, owner in ASSETS:
        if db.scalar(select(Asset).where(Asset.name == name)):
            continue
        db.add(
            Asset(
                name=name,
                hostname=hostname,
                ip_address=ip,
                service=service,
                port=port,
                criticality=criticality,
                owner=owner,
            )
        )
        created += 1
    db.commit()
    return created


def seed_rules(db: Session) -> int:
    """Mirror the code-defined rule catalog into the tunable DB table."""
    created = 0
    for spec in RULES:
        row = db.scalar(select(DetectionRule).where(DetectionRule.key == spec.key))
        if row is not None:
            continue
        db.add(
            DetectionRule(
                key=spec.key,
                name=spec.name,
                attack_type=spec.attack_type,
                description=spec.description,
                severity=spec.severity,
                confidence=spec.confidence,
                base_score=spec.base_score,
                mitre_tactic=spec.mitre_tactic,
                mitre_technique=spec.mitre_technique,
                recommended_action=spec.recommended_action,
            )
        )
        created += 1
    db.commit()
    return created


def backfill_events(db: Session, target_count: int, hours: int = 24) -> int:
    """Replay simulated episodes and backdate them across the last `hours`.

    Gives the dashboard a populated trend line, country map and top-attacker
    list on first load instead of an empty state.
    """
    rng = random.Random(20260801)
    assets = list(db.scalars(select(Asset)))
    if not assets:
        return 0

    countries = list(DEFAULT_SOURCE_WEIGHTS)
    weights = [DEFAULT_SOURCE_WEIGHTS[c] for c in countries]
    scenario_keys = list(SCENARIOS)
    created: list[AttackEvent] = []

    # Every episode should yield at least one event; the budget just stops a
    # systemic ingest failure from spinning here forever.
    attempts = 0
    max_attempts = target_count * 3 + 30

    while len(created) < target_count:
        attempts += 1
        if attempts > max_attempts:
            log.error(
                "backfill gave up after %d episodes with only %d events — "
                "the ingest pipeline is rejecting everything",
                attempts, len(created),
            )
            break

        # Each episode gets clean windows so backfilled bursts stay distinct
        # events rather than correlating into one another.
        engine.reset()
        reset_correlation()

        scenario = SCENARIOS[rng.choice(scenario_keys)]
        country = rng.choices(countries, weights=weights, k=1)[0]
        from . import geo

        source_ip = geo.ip_for_country(country, rng)
        candidates = [a for a in assets if a.service == scenario.service] or assets
        asset = rng.choice(candidates)
        target = {
            "ip": asset.ip_address,
            "port": asset.port,
            "protocol": "HTTPS" if asset.port in (443, 8443) else "TCP",
            "hostname": asset.hostname,
        }
        events = ingest_many(db, scenario.build(rng, source_ip, target), simulated=True)
        if not events:
            continue
        created.extend(events)

    created = created[:target_count]

    # Spread across the window, weighted toward recent so the trend rises.
    now = datetime.now(UTC)
    for index, event in enumerate(created):
        fraction = (index / max(1, len(created) - 1)) ** 0.65
        offset = timedelta(hours=hours * (1.0 - fraction)) - timedelta(
            minutes=rng.randint(0, 25)
        )
        event.detected_at = now - offset

        # Age a slice of the older events so status counts look like a real
        # queue rather than everything sitting in ACTIVE forever.
        if fraction < 0.75:
            event.status = rng.choices(
                [
                    EventStatus.RESOLVED,
                    EventStatus.MITIGATED,
                    EventStatus.INVESTIGATING,
                    EventStatus.FALSE_POSITIVE,
                    EventStatus.ACTIVE,
                ],
                weights=[46, 24, 10, 8, 12],
                k=1,
            )[0]

        explanation = db.scalar(
            select(AIExplanation).where(AIExplanation.event_id == event.id)
        )
        if explanation:
            explanation.created_at = event.detected_at
        for note in db.scalars(select(Notification).where(Notification.event_id == event.id)):
            note.created_at = event.detected_at
            note.is_read = fraction < 0.6

    # Actor first/last seen must bracket their real events.
    for actor in db.scalars(select(ThreatActor)):
        bounds = db.execute(
            select(func.min(AttackEvent.detected_at), func.max(AttackEvent.detected_at)).where(
                AttackEvent.threat_actor_id == actor.id
            )
        ).one()
        if bounds[0] is not None:
            actor.first_seen, actor.last_seen = bounds

    db.commit()
    engine.reset()
    reset_correlation()
    return len(created)


def seed_all(force_events: bool = False) -> dict:
    init_db()
    with SessionLocal() as db:
        summary = {
            "users": seed_users(db),
            "assets": seed_assets(db),
            "rules": seed_rules(db),
            "events": 0,
        }
        existing = db.scalar(select(func.count(AttackEvent.id))) or 0
        if force_events or (existing == 0 and settings.seed_demo_events > 0):
            summary["events"] = backfill_events(db, settings.seed_demo_events)
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = seed_all()
    print(
        f"seeded: {result['users']} users, {result['assets']} assets, "
        f"{result['rules']} rules, {result['events']} events"
    )
