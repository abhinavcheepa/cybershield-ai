"""JWT issuance/verification, password hashing and RBAC dependencies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import AuditLog, Role, User

bearer_scheme = HTTPBearer(auto_error=False)

# Role -> everything that role is allowed to be, cheapest possible RBAC.
_ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def create_access_token(user: User) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


def user_from_token(token: str, db: Session) -> User | None:
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        return None
    user = db.get(User, int(payload.get("sub", 0) or 0))
    return user if user and user.is_active else None


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    user = user_from_token(credentials.credentials, db)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_role(minimum: Role):
    """Dependency factory: viewer < analyst < admin."""

    def guard(user: CurrentUser) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires {minimum.value} role or higher",
            )
        return user

    return guard


RequireAnalyst = Annotated[User, Depends(require_role(Role.ANALYST))]
RequireAdmin = Annotated[User, Depends(require_role(Role.ADMIN))]


def audit(
    db: Session,
    actor: str,
    action: str,
    resource: str,
    detail: dict | None = None,
    request: Request | None = None,
) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            resource=resource,
            detail=detail or {},
            ip_address=request.client.host if request and request.client else "",
        )
    )
    db.commit()
