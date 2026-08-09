"""Authentication, identity and the audit trail."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import AuditLog, User
from ..schemas import AuditLogOut, LoginRequest, TokenResponse, UserOut
from ..security import (
    CurrentUser,
    RequireAdmin,
    audit,
    create_access_token,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

DB = Annotated[Session, Depends(get_db)]


@router.post("/login", response_model=TokenResponse, summary="Exchange credentials for a JWT")
def login(payload: LoginRequest, request: Request, db: DB) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))

    # Same response for unknown user, wrong password and disabled account —
    # anything more specific is a username-enumeration oracle.
    if user is None or not verify_password(payload.password, user.hashed_password) or not user.is_active:
        audit(db, payload.email, "login.failed", "auth", request=request)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    user.last_login_at = datetime.now(UTC)
    db.commit()
    audit(db, user.email, "login.success", "auth", {"role": user.role.value}, request)

    return TokenResponse(
        access_token=create_access_token(user),
        expires_in=settings.access_token_minutes * 60,
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut, summary="Current user")
def me(user: CurrentUser) -> User:
    return user


@router.get("/users", response_model=list[UserOut], summary="List users (admin)")
def list_users(_: RequireAdmin, db: DB) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@router.get("/audit", response_model=list[AuditLogOut], summary="Audit log (admin)")
def audit_log(_: RequireAdmin, db: DB, limit: int = 100) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(limit, 500))))
