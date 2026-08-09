"""Notification centre."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Notification
from ..schemas import NotificationOut
from ..security import CurrentUser

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])

DB = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[NotificationOut], summary="List notifications, newest first")
def list_notifications(
    _: CurrentUser,
    db: DB,
    unread_only: bool = False,
    limit: int = Query(50, ge=1, le=200),
) -> list[Notification]:
    stmt = select(Notification).order_by(Notification.created_at.desc(), Notification.id.desc())
    if unread_only:
        stmt = stmt.where(Notification.is_read.is_(False))
    return list(db.scalars(stmt.limit(limit)))


@router.get("/unread-count", summary="Unread badge count")
def unread_count(_: CurrentUser, db: DB) -> dict:
    from sqlalchemy import func

    count = db.scalar(select(func.count(Notification.id)).where(Notification.is_read.is_(False))) or 0
    return {"unread": count}


@router.post("/{notification_id}/read", response_model=NotificationOut, summary="Mark one as read")
def mark_read(notification_id: int, _: CurrentUser, db: DB) -> Notification:
    notification = db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Notification not found")
    notification.is_read = True
    db.commit()
    db.refresh(notification)
    return notification


@router.post("/read-all", summary="Mark every notification as read")
def mark_all_read(_: CurrentUser, db: DB) -> dict:
    result = db.execute(
        update(Notification).where(Notification.is_read.is_(False)).values(is_read=True)
    )
    db.commit()
    return {"marked": result.rowcount or 0}
