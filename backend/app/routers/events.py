"""Attack events: search, detail, triage, timeline."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AttackEvent, EventStatus, Severity
from ..schemas import (
    AttackEventDetail,
    AttackEventOut,
    EventPage,
    EventStatusUpdate,
)
from ..security import CurrentUser, RequireAnalyst, audit
from ..ws import manager

router = APIRouter(prefix="/api", tags=["Attack Events"])

DB = Annotated[Session, Depends(get_db)]


def _get_event(db: Session, uid: str) -> AttackEvent:
    event = db.scalar(select(AttackEvent).where(AttackEvent.uid == uid))
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack event not found")
    return event


@router.get("/events", response_model=EventPage, summary="Search attack events")
def list_events(
    _: CurrentUser,
    db: DB,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    severity: Severity | None = None,
    event_status: EventStatus | None = Query(None, alias="status"),
    attack_type: str | None = None,
    country: str | None = Query(None, min_length=2, max_length=2),
    search: str | None = Query(None, max_length=100),
    hours: int = Query(24, ge=1, le=720),
) -> EventPage:
    since = datetime.now(UTC) - timedelta(hours=hours)
    filters = [AttackEvent.detected_at >= since]

    if severity is not None:
        filters.append(AttackEvent.severity == severity)
    if event_status is not None:
        filters.append(AttackEvent.status == event_status)
    if attack_type:
        filters.append(AttackEvent.attack_type == attack_type)
    if country:
        filters.append(AttackEvent.source_country == country.upper())
    if search:
        # Bound parameters throughout — no string interpolation reaches SQL.
        like = f"%{search}%"
        filters.append(
            or_(
                AttackEvent.source_ip.like(like),
                AttackEvent.destination_ip.like(like),
                AttackEvent.attack_type.like(like),
                AttackEvent.name.like(like),
                AttackEvent.source_country_name.like(like),
            )
        )

    total = db.scalar(select(func.count(AttackEvent.id)).where(*filters)) or 0
    rows = db.scalars(
        select(AttackEvent)
        .where(*filters)
        .order_by(AttackEvent.detected_at.desc(), AttackEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    return EventPage(
        items=[AttackEventOut.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/timeline", response_model=list[AttackEventOut], summary="Most recent events, newest first")
def timeline(_: CurrentUser, db: DB, limit: int = Query(50, ge=1, le=200)) -> list[AttackEvent]:
    return list(
        db.scalars(
            select(AttackEvent).order_by(AttackEvent.detected_at.desc(), AttackEvent.id.desc()).limit(limit)
        )
    )


@router.get("/events/{uid}", response_model=AttackEventDetail, summary="Full event detail")
def event_detail(uid: str, _: CurrentUser, db: DB) -> AttackEvent:
    return _get_event(db, uid)


@router.patch(
    "/events/{uid}/status",
    response_model=AttackEventDetail,
    summary="Triage an event (analyst or admin)",
)
async def update_status(
    uid: str,
    payload: EventStatusUpdate,
    user: RequireAnalyst,
    db: DB,
    request: Request,
) -> AttackEvent:
    event = _get_event(db, uid)
    previous = event.status
    event.status = payload.status
    db.commit()
    db.refresh(event)

    audit(
        db,
        user.email,
        "event.status_changed",
        f"event:{uid}",
        {"from": previous.value, "to": payload.status.value, "note": payload.note},
        request,
    )
    await manager.broadcast("event_updated", AttackEventOut.model_validate(event).model_dump(mode="json"))
    return event


@router.get("/attack-types", response_model=list[str], summary="Attack types the engine can emit")
def attack_types(_: CurrentUser) -> list[str]:
    from ..detection.rules import ATTACK_TYPES

    return sorted(set(ATTACK_TYPES))
