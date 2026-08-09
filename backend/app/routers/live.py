"""Live attack range control — governs REAL attacks against the lab target.

Analyst-gated. The client chooses which attacks, how fast, and which student to
hit; it can NEVER choose the host — that is fixed server-side in
`settings.target_base_url`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset, AttackEvent
from ..security import CurrentUser, RequireAdmin, RequireAnalyst, audit
from ..target.attack_runner import ATTACKS, live_runner
from ..target.models import SiteUser

router = APIRouter(prefix="/api/live", tags=["Live Attack Range"])

DB = Annotated[Session, Depends(get_db)]


class LiveAttackIn(BaseModel):
    attacks: list[str] = Field(default_factory=list)
    target_username: str = "all"
    attacks_per_minute: int = Field(default=40, ge=1, le=600)
    source_country: str | None = None
    repeat: bool = True


@router.get("/catalog", summary="Available real attacks + current targets")
def catalog(_: CurrentUser, db: DB) -> dict:
    students = db.scalars(select(SiteUser).order_by(SiteUser.username)).all()
    return {
        "attacks": [{"key": k, "label": v} for k, v in ATTACKS.items()],
        "targets": [
            {"username": s.username, "display_name": s.display_name,
             "is_defaced": s.is_defaced, "is_breached": s.is_breached,
             "failed_logins": s.failed_logins}
            for s in students
        ],
        "target_base_url": live_runner.state()["target_base_url"],
    }


@router.get("/state", summary="Runner state")
def state(_: CurrentUser) -> dict:
    return live_runner.state()


@router.post("/start", summary="Launch real attacks (analyst)")
async def start(payload: LiveAttackIn, user: RequireAnalyst, db: DB, request: Request) -> dict:
    result = await live_runner.start(
        attacks=payload.attacks,
        target_username=payload.target_username,
        attacks_per_minute=payload.attacks_per_minute,
        source_country=payload.source_country,
        repeat=payload.repeat,
        started_by=user.email,
    )
    audit(db, user.email, "live_attack.start", "target-site", payload.model_dump(), request)
    return result


@router.post("/pause", summary="Pause (analyst)")
async def pause(user: RequireAnalyst, db: DB, request: Request) -> dict:
    result = await live_runner.pause()
    audit(db, user.email, "live_attack.pause", "target-site", request=request)
    return result


@router.post("/resume", summary="Resume (analyst)")
async def resume(user: RequireAnalyst, db: DB, request: Request) -> dict:
    result = await live_runner.resume()
    audit(db, user.email, "live_attack.resume", "target-site", request=request)
    return result


@router.post("/stop", summary="Stop (analyst)")
async def stop(user: RequireAnalyst, db: DB, request: Request) -> dict:
    result = await live_runner.stop()
    audit(db, user.email, "live_attack.stop", "target-site", request=request)
    return result


#: The `service` every student's asset row is created with, so a purge can never
#: touch the ten seeded infrastructure assets even if a student picks a name
#: that collides with one.
STUDENT_ASSET_SERVICE = "student-site"


@router.delete("/students", summary="Remove student sites (admin)")
def purge_students(
    prefix: Annotated[str, Query(max_length=40)],
    user: RequireAdmin,
    db: DB,
    request: Request,
) -> dict:
    """Delete every student site whose username starts with `prefix`.

    Two things this is for: clearing a load test's dummy accounts, and resetting
    the class between two batches so their usernames do not collide.

    `prefix` is required. An empty value means the whole class, which is a
    legitimate thing to want — but you have to type the parameter to get it, so
    a bare call to this URL cannot wipe a class by accident.
    """
    students = db.scalars(select(SiteUser).where(SiteUser.username.startswith(prefix))).all()
    if not students:
        return {"students": 0, "assets": 0, "events_detached": 0}

    usernames = [s.username for s in students]
    asset_ids = list(
        db.scalars(
            select(Asset.id).where(
                Asset.service == STUDENT_ASSET_SERVICE, Asset.name.in_(usernames)
            )
        )
    )

    # attack_events.asset_id is a plain foreign key, so the asset rows cannot go
    # while events still point at them. Detach rather than cascade: the timeline
    # is the record of what happened in the lesson and outlives the roster.
    detached = 0
    if asset_ids:
        detached = db.execute(
            update(AttackEvent)
            .where(AttackEvent.asset_id.in_(asset_ids))
            .values(asset_id=None)
        ).rowcount or 0
        db.execute(Asset.__table__.delete().where(Asset.id.in_(asset_ids)))

    for student in students:
        db.delete(student)  # guestbook entries cascade
    db.commit()

    audit(
        db, user.email, "class.purge", "target-site",
        {"prefix": prefix, "students": len(students), "usernames": usernames[:20]}, request,
    )
    return {"students": len(students), "assets": len(asset_ids), "events_detached": detached}
