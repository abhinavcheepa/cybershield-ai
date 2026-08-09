"""Dashboard aggregation.

Time bucketing is done in Python rather than SQL: `date_trunc` is Postgres-only
and `strftime` is SQLite-only, and the window is at most a few thousand rows.
One portable query beats two dialect-specific ones.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import geo
from .models import Asset, AttackEvent, EventStatus, Severity, ThreatActor
from .schemas import (
    CountryStat,
    DashboardStats,
    NamedCount,
    SeverityCount,
    TimeBucket,
)

ACTIVE_STATUSES = (EventStatus.ACTIVE, EventStatus.INVESTIGATING)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; normalise so comparisons work."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _top(db: Session, column, limit: int, since: datetime) -> list[tuple]:
    return db.execute(
        select(column, func.count(AttackEvent.id).label("n"))
        .where(AttackEvent.detected_at >= since)
        .group_by(column)
        .order_by(func.count(AttackEvent.id).desc())
        .limit(limit)
    ).all()


def dashboard_stats(db: Session, hours: int = 24) -> DashboardStats:
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    in_window = AttackEvent.detected_at >= since

    total = db.scalar(select(func.count(AttackEvent.id)).where(in_window)) or 0
    active = (
        db.scalar(
            select(func.count(AttackEvent.id)).where(
                in_window, AttackEvent.status.in_(ACTIVE_STATUSES)
            )
        )
        or 0
    )
    critical = (
        db.scalar(
            select(func.count(AttackEvent.id)).where(
                in_window, AttackEvent.severity == Severity.CRITICAL
            )
        )
        or 0
    )
    blocked = (
        db.scalar(select(func.count(AttackEvent.id)).where(in_window, AttackEvent.blocked.is_(True)))
        or 0
    )

    hour_ago = now - timedelta(hours=1)
    two_hours_ago = now - timedelta(hours=2)
    last_hour = db.scalar(select(func.count(AttackEvent.id)).where(AttackEvent.detected_at >= hour_ago)) or 0
    prev_hour = (
        db.scalar(
            select(func.count(AttackEvent.id)).where(
                AttackEvent.detected_at >= two_hours_ago, AttackEvent.detected_at < hour_ago
            )
        )
        or 0
    )
    trend = ((last_hour - prev_hour) / prev_hour * 100.0) if prev_hour else (100.0 if last_hour else 0.0)

    avg_response = db.scalar(select(func.avg(AttackEvent.response_time_ms)).where(in_window)) or 0
    unique_attackers = db.scalar(select(func.count(func.distinct(AttackEvent.source_ip))).where(in_window)) or 0
    countries = db.scalar(select(func.count(func.distinct(AttackEvent.source_country))).where(in_window)) or 0

    severity_rows = dict(
        db.execute(
            select(AttackEvent.severity, func.count(AttackEvent.id))
            .where(in_window)
            .group_by(AttackEvent.severity)
        ).all()
    )
    by_severity = [
        SeverityCount(severity=level, count=severity_rows.get(level, 0))
        for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    ]

    # Overall posture: how dangerous recent traffic is, plus pressure from the
    # volume of unresolved critical findings. Capped at 100.
    avg_active_score = (
        db.scalar(
            select(func.avg(AttackEvent.threat_score)).where(
                in_window, AttackEvent.status.in_(ACTIVE_STATUSES)
            )
        )
        or 0.0
    )
    threat_score = round(min(100.0, avg_active_score * 0.6 + min(40.0, critical * 2.5)), 1)

    top_types = [NamedCount(name=name, count=n) for name, n in _top(db, AttackEvent.attack_type, 6, since)]

    asset_rows = db.execute(
        select(Asset.name, Asset.service, func.count(AttackEvent.id))
        .join(AttackEvent, AttackEvent.asset_id == Asset.id)
        .where(in_window)
        .group_by(Asset.name, Asset.service)
        .order_by(func.count(AttackEvent.id).desc())
        .limit(6)
    ).all()
    top_assets = [NamedCount(name=name, count=n, extra=service) for name, service, n in asset_rows]

    service_rows = db.execute(
        select(Asset.service, func.count(AttackEvent.id))
        .join(AttackEvent, AttackEvent.asset_id == Asset.id)
        .where(in_window)
        .group_by(Asset.service)
        .order_by(func.count(AttackEvent.id).desc())
        .limit(6)
    ).all()
    top_services = [NamedCount(name=service, count=n) for service, n in service_rows]

    attacker_rows = db.execute(
        select(
            AttackEvent.source_ip,
            AttackEvent.source_country_name,
            func.count(AttackEvent.id),
            func.max(AttackEvent.threat_score),
        )
        .where(in_window)
        .group_by(AttackEvent.source_ip, AttackEvent.source_country_name)
        .order_by(func.count(AttackEvent.id).desc())
        .limit(6)
    ).all()
    top_attackers = [
        NamedCount(name=ip, count=n, extra=f"{country} · peak {score:.0f}")
        for ip, country, n, score in attacker_rows
    ]

    return DashboardStats(
        total_attacks=total,
        active_attacks=active,
        critical_attacks=critical,
        blocked_attacks=blocked,
        threat_score=threat_score,
        attacks_last_hour=last_hour,
        attacks_previous_hour=prev_hour,
        trend_pct=round(trend, 1),
        avg_response_time_ms=int(avg_response),
        unique_attackers=unique_attackers,
        countries_involved=countries,
        by_severity=by_severity,
        top_attack_types=top_types,
        top_targeted_assets=top_assets,
        top_attackers=top_attackers,
        top_targeted_services=top_services,
    )


def timeseries(db: Session, minutes: int = 60, buckets: int = 30) -> list[TimeBucket]:
    """Evenly-spaced buckets over the last `minutes`, oldest first.

    Empty buckets are emitted as zeros so the chart keeps a continuous x-axis
    instead of collapsing quiet periods.
    """
    now = datetime.now(UTC)
    since = now - timedelta(minutes=minutes)
    width = timedelta(minutes=minutes) / buckets

    rows = db.execute(
        select(
            AttackEvent.detected_at,
            AttackEvent.severity,
            AttackEvent.threat_score,
            AttackEvent.response_time_ms,
            AttackEvent.blocked,
        ).where(AttackEvent.detected_at >= since)
    ).all()

    grouped: dict[int, list] = defaultdict(list)
    for detected_at, severity, score, response_ms, blocked in rows:
        detected_at = _aware(detected_at)
        index = int((detected_at - since) / width)
        grouped[min(max(index, 0), buckets - 1)].append((severity, score, response_ms, blocked))

    series = []
    for index in range(buckets):
        entries = grouped.get(index, [])
        scores = [s for _, s, _, _ in entries]
        responses = [r for _, _, r, _ in entries if r]
        series.append(
            TimeBucket(
                timestamp=since + width * index,
                count=len(entries),
                critical=sum(1 for sev, _, _, _ in entries if sev is Severity.CRITICAL),
                high=sum(1 for sev, _, _, _ in entries if sev is Severity.HIGH),
                blocked=sum(1 for _, _, _, b in entries if b),
                threat_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
                avg_response_ms=int(sum(responses) / len(responses)) if responses else 0,
            )
        )
    return series


def country_stats(db: Session, hours: int = 24) -> list[CountryStat]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        select(
            AttackEvent.source_country,
            AttackEvent.source_country_name,
            AttackEvent.source_lat,
            AttackEvent.source_lon,
            func.count(AttackEvent.id),
        )
        .where(AttackEvent.detected_at >= since)
        .group_by(
            AttackEvent.source_country,
            AttackEvent.source_country_name,
            AttackEvent.source_lat,
            AttackEvent.source_lon,
        )
        .order_by(func.count(AttackEvent.id).desc())
    ).all()

    critical_by_country = Counter(
        dict(
            db.execute(
                select(AttackEvent.source_country, func.count(AttackEvent.id))
                .where(AttackEvent.detected_at >= since, AttackEvent.severity == Severity.CRITICAL)
                .group_by(AttackEvent.source_country)
            ).all()
        )
    )

    return [
        CountryStat(
            country_code=code,
            country_name=name,
            latitude=lat,
            longitude=lon,
            count=count,
            critical_count=critical_by_country.get(code, 0),
        )
        for code, name, lat, lon, count in rows
    ]


def top_actors(db: Session, limit: int = 25) -> list[ThreatActor]:
    return list(
        db.scalars(
            select(ThreatActor).order_by(ThreatActor.threat_score.desc(), ThreatActor.event_count.desc()).limit(limit)
        )
    )


def known_countries() -> list[dict]:
    return geo.country_choices()
