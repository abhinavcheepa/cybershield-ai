"""AI Security Assistant endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ai.explain import generate_with_claude
from ..config import settings
from ..database import get_db
from ..models import AIExplanation, AttackEvent
from ..schemas import AIExplanationOut
from ..security import CurrentUser, RequireAnalyst, audit

router = APIRouter(prefix="/api/ai", tags=["AI Analysis"])

DB = Annotated[Session, Depends(get_db)]


def _event(db: Session, uid: str) -> AttackEvent:
    event = db.scalar(select(AttackEvent).where(AttackEvent.uid == uid))
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack event not found")
    return event


@router.get("/status", summary="Which analysis backend is active")
def ai_status(_: CurrentUser) -> dict:
    live = bool(settings.anthropic_api_key)
    return {
        "live_model_available": live,
        "model": settings.anthropic_model if live else "cybershield-analyst-v1",
        "detail": (
            "Claude-backed analysis is available on demand."
            if live
            else "Set ANTHROPIC_API_KEY to upgrade explanations from the built-in analyst templates."
        ),
    }


@router.get(
    "/explanation/{uid}",
    response_model=AIExplanationOut,
    summary="Stored explanation for an event",
)
def explanation(uid: str, _: CurrentUser, db: DB) -> AIExplanation:
    event = _event(db, uid)
    if event.explanation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No explanation stored for this event")
    return event.explanation


@router.post(
    "/analyze/{uid}",
    response_model=AIExplanationOut,
    summary="Regenerate the explanation with Claude (analyst)",
)
async def analyze(uid: str, user: RequireAnalyst, db: DB, request: Request) -> AIExplanation:
    """Re-run analysis through Claude and replace the stored explanation.

    Falls back to the built-in analyst templates when no API key is configured
    or the call fails, so this endpoint always returns a usable explanation.
    """
    event = _event(db, uid)
    result = await generate_with_claude(event)

    stored = event.explanation
    if stored is None:
        stored = AIExplanation(event_id=event.id, **result.as_dict())
        db.add(stored)
    else:
        for field, value in result.as_dict().items():
            setattr(stored, field, value)
    db.commit()
    db.refresh(stored)

    audit(db, user.email, "ai.analyze", f"event:{uid}", {"model": result.generated_by}, request)
    return stored
