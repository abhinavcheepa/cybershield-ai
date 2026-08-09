"""The vulnerable target site's HTTP surface.

EVERY vulnerability below is deliberate and labelled `VULN:`. This is the
practice target — it exists to be broken so students see real consequences.
Never copy these patterns into anything real.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Asset, Severity
from ..ws import site_manager
from .models import GuestbookEntry, SiteUser
from .vuln import client_ip, observe

router = APIRouter(prefix="/site", tags=["Target Site (vulnerable lab)"])

DB = Annotated[Session, Depends(get_db)]
_bearer = HTTPBearer(auto_error=False)

# Planted files for the traversal demo. Reads are confined to the project root
# so a student can leak the planted secret and source, but not the whole disk.
_HERE = Path(__file__).resolve().parent
_FILES_DIR = _HERE / "site_files"
_PROJECT_ROOT = _HERE.parents[2]  # .../CyberShield-AI


# --------------------------------------------------------------- site tokens
def _create_token(user: SiteUser) -> str:
    return jwt.encode(
        {"sub": str(user.id), "username": user.username, "kind": "site"},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def _user_from_token(token: str, db: Session) -> SiteUser | None:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
    if payload.get("kind") != "site":
        return None
    return db.get(SiteUser, int(payload.get("sub", 0) or 0))


def current_site_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DB,
) -> SiteUser:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    user = _user_from_token(credentials.credentials, db)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid")
    return user


# ---------------------------------------------------------------- schemas
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=120)
    display_name: str = Field(min_length=1, max_length=80)
    secret_note: str = Field(default="My private note — nobody should see this.", max_length=500)


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=200)


class GuestbookIn(BaseModel):
    author: str = Field(default="guest", max_length=80)
    message: str = Field(min_length=1, max_length=2000)


def _asset_ip(user_id: int) -> str:
    return f"10.99.{user_id // 250}.{user_id % 250 + 1}"


def _utc_iso(dt: datetime) -> str:
    """SQLite drops timezone info, so naive datetimes need the UTC suffix
    added back. Without it the browser's Date parser assumes local time and
    the 'time ago' labels are off by the user's UTC offset."""
    s = dt.isoformat()
    if dt.tzinfo is None and not s.endswith("Z") and "+" not in s:
        s += "+00:00"
    return s


def _site_view(user: SiteUser) -> dict:
    return {
        "username": user.username,
        "display_name": user.display_name,
        "secret_note": user.secret_note,
        "asset_ip": user.asset_ip,
        "is_defaced": user.is_defaced,
        "is_breached": user.is_breached,
        "failed_logins": user.failed_logins,
        "guestbook": [
            {"id": e.id, "author": e.author, "message": e.message, "is_attack": e.is_attack,
             "created_at": _utc_iso(e.created_at)}
            for e in sorted(user.guestbook, key=lambda e: e.id)
        ],
    }


# ---------------------------------------------------------------- endpoints
@router.post("/register", summary="Create your site")
def register(payload: RegisterIn, db: DB):
    if db.scalar(select(SiteUser).where(SiteUser.username == payload.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "That username is taken")

    user = SiteUser(
        username=payload.username,
        password=payload.password,  # VULN: plaintext, so the SQLi dump is real
        display_name=payload.display_name,
        secret_note=payload.secret_note,
    )
    db.add(user)
    db.flush()  # user.id
    user.asset_ip = _asset_ip(user.id)

    # Register this student as an asset the SOC monitors, so attacks against
    # them show up attributed on the dashboard's "top attacked assets".
    db.add(Asset(
        name=user.username,
        hostname=f"{user.username}.studentlab.local",
        ip_address=user.asset_ip,
        service="student-site",
        port=8010,
        criticality=Severity.MEDIUM,
        owner=user.display_name,
    ))
    db.add(GuestbookEntry(site_id=user.id, author="CyberShield", message="Welcome to your new site! 🎉"))
    db.commit()
    db.refresh(user)
    return {"access_token": _create_token(user), "token_type": "bearer", "site": _site_view(user)}


@router.post("/login", summary="Sign in to your site")
async def login(payload: LoginIn, request: Request, db: DB):
    # VULN: the credentials are concatenated straight into SQL. `' OR '1'='1`
    # or `admin'--` bypass authentication entirely. This is the SQL-injection
    # surface AND (with no lockout) the brute-force surface.
    query = text(
        "SELECT id FROM site_users "
        f"WHERE username = '{payload.username}' AND password = '{payload.password}'"
    )
    try:
        row = db.execute(query).first()
    except Exception:
        row = None  # a malformed injection payload just fails the login

    if row is None:
        # Look up the account (safely) only to attribute the failure to a site.
        victim = db.scalar(select(SiteUser).where(SiteUser.username == payload.username))
        if victim:
            victim.failed_logins += 1
            db.commit()
        await observe(
            request, victim, path="/site/login",
            payload=f"{payload.username} {payload.password}",
            status_code=401, auth_failure=True,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password")

    user = db.get(SiteUser, row[0])
    # A successful login whose payload still carries injection syntax is a
    # successful *bypass* — report it and mark the account breached.
    await observe(
        request, user, path="/site/login",
        payload=f"{payload.username} {payload.password}", status_code=200,
    )
    if "'" in payload.username or "'" in payload.password:
        user.is_breached = True
        db.commit()
    return {"access_token": _create_token(user), "token_type": "bearer", "site": _site_view(user)}


@router.get("/me", summary="Your own site")
def me(user: Annotated[SiteUser, Depends(current_site_user)]):
    return _site_view(user)


# There is deliberately no endpoint that lists the class. It existed, and it was
# public: anyone holding the class link could read off every username, who was
# breached and who was defaced, without registering. Students now see only their
# own site. The operator's own list lives behind auth at /api/live/catalog, and
# the attack runner reads the table directly.


@router.get("/u/{username}", summary="View a site (public)")
async def view_site(username: str, request: Request, db: DB):
    user = db.scalar(select(SiteUser).where(SiteUser.username == username))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such site")
    await observe(request, user, path=f"/site/u/{username}")
    return _site_view(user)


@router.post("/u/{username}/guestbook", summary="Sign someone's guestbook")
async def sign_guestbook(username: str, payload: GuestbookIn, request: Request, db: DB):
    user = db.scalar(select(SiteUser).where(SiteUser.username == username))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such site")

    # VULN: the message is stored verbatim and rendered unescaped by the
    # frontend, so a <script>/<img onerror> payload actually executes on the
    # owner's page — stored XSS.
    looks_hostile = "<" in payload.message and (
        "script" in payload.message.lower()
        or "onerror" in payload.message.lower()
        or "onload" in payload.message.lower()
        or "javascript:" in payload.message.lower()
    )
    entry = GuestbookEntry(
        site_id=user.id, author=payload.author, message=payload.message, is_attack=looks_hostile
    )
    db.add(entry)
    if looks_hostile:
        user.is_defaced = True
    db.commit()

    await observe(
        request, user, path=f"/site/u/{username}/guestbook", payload=payload.message,
        extra={"body": payload.message},
    )
    return {"ok": True, "defaced": looks_hostile}


def _lab_victim(request: Request, db: Session) -> SiteUser | None:
    """Lab-only: the attack runner tags site-wide attacks (search/file) with the
    student it is targeting, so a global attack still lands on that student's
    dashboard and their live feed. Absent for organic traffic."""
    name = request.headers.get("x-lab-victim")
    return db.scalar(select(SiteUser).where(SiteUser.username == name)) if name else None


@router.get("/search", summary="Search sites by name")
async def search(request: Request, db: DB, q: str = Query("", max_length=300)):
    # VULN: `q` is concatenated into SQL. `%' UNION SELECT username, password
    # FROM site_users -- ` dumps every student's credentials.
    sql = text(f"SELECT username, display_name FROM site_users WHERE display_name LIKE '%{q}%'")
    try:
        rows = db.execute(sql).all()
        results = [{"username": r[0], "display_name": r[1]} for r in rows]
    except Exception:
        results = []

    victim = _lab_victim(request, db)
    if victim and results:
        victim.is_breached = True  # their passwords just got dumped
        db.commit()
    await observe(request, victim, path="/site/search", payload=q, extra={"query_string": f"q={q}"})
    return {"query": q, "results": results}


@router.get("/file", summary="Read a site file")
async def read_file(request: Request, db: DB, name: str = Query("welcome.txt", max_length=300)):
    # VULN: `name` is joined onto the files directory with no sanitisation, so
    # `../../<something>` escapes it. Reads are confined to the project root so
    # the demo can leak the planted secret and source — not the whole machine.
    target = (_FILES_DIR / name).resolve()
    body: str
    code = 200
    try:
        if _PROJECT_ROOT not in target.parents and target != _PROJECT_ROOT:
            raise PermissionError
        body = target.read_text(encoding="utf-8", errors="replace")[:4000]
    except (FileNotFoundError, PermissionError, OSError):
        body, code = "File not found.", 404

    victim = _lab_victim(request, db)
    if victim and code == 200 and "FLAG{" in body:
        victim.is_breached = True  # server files leaked
        db.commit()
    await observe(request, victim, path="/site/file", payload=name, status_code=code,
                  extra={"query_string": f"name={name}"})
    return {"name": name, "content": body}


# --------------------------------------------------------------- live channel
@router.websocket("/ws")
async def site_ws(websocket: WebSocket, token: str | None = Query(None)) -> None:
    """A student's live 'under attack' feed. Same JWT as /site/me, as ?token=."""
    from ..database import SessionLocal

    if not token:
        await websocket.close(code=4401, reason="Missing token")
        return
    with SessionLocal() as db:
        user = _user_from_token(token, db)
    if user is None:
        await websocket.close(code=4401, reason="Invalid token")
        return

    await site_manager.connect(user.username, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        site_manager.disconnect(user.username, websocket)
    except Exception:
        site_manager.disconnect(user.username, websocket)


__all__ = ["router", "client_ip"]
