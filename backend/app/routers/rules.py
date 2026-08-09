"""Detection rule management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import engine
from ..models import DetectionRule
from ..schemas import DetectionRuleOut, DetectionRuleUpdate
from ..security import CurrentUser, RequireAdmin, audit

router = APIRouter(prefix="/api/rules", tags=["Detection Rules"])

DB = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[DetectionRuleOut], summary="List detection rules")
def list_rules(_: CurrentUser, db: DB) -> list[DetectionRule]:
    return list(db.scalars(select(DetectionRule).order_by(DetectionRule.severity, DetectionRule.name)))


@router.patch("/{key}", response_model=DetectionRuleOut, summary="Tune a rule (admin)")
def update_rule(
    key: str,
    payload: DetectionRuleUpdate,
    user: RequireAdmin,
    db: DB,
    request: Request,
) -> DetectionRule:
    rule = db.scalar(select(DetectionRule).where(DetectionRule.key == key))
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection rule not found")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return rule

    for field, value in changes.items():
        setattr(rule, field, value)
    db.commit()
    db.refresh(rule)

    # The running engine holds its own enabled/disabled set — keep it in step
    # with the persisted row or a toggle only takes effect after a restart.
    if "enabled" in changes:
        engine.set_enabled(key, rule.enabled)

    audit(db, user.email, "rule.updated", f"rule:{key}", changes, request)
    return rule


def sync_engine_state(db: Session) -> None:
    """Apply persisted enable/disable flags to the in-memory engine at startup."""
    for key, enabled in db.execute(select(DetectionRule.key, DetectionRule.enabled)).all():
        try:
            engine.set_enabled(key, enabled)
        except KeyError:
            # A rule row with no matching code implementation — stale seed data.
            continue
