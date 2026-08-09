"""WebSocket endpoint.

Browsers cannot set an Authorization header on a WebSocket handshake, so the
JWT arrives as a query parameter. That is the standard workaround; it is safe
here because the token is short-lived and the connection is same-origin, but it
does mean the token can land in access logs — keep `?token=` out of any proxy
log format you deploy in front of this.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from ..database import SessionLocal
from ..security import user_from_token
from ..ws import manager

router = APIRouter(tags=["WebSocket"])

WS_UNAUTHORIZED = 4401


@router.websocket("/ws")
async def realtime(websocket: WebSocket, token: str | None = Query(None)) -> None:
    if not token:
        await websocket.close(code=WS_UNAUTHORIZED, reason="Missing token")
        return

    with SessionLocal() as db:
        user = user_from_token(token, db)
    if user is None:
        await websocket.close(code=WS_UNAUTHORIZED, reason="Invalid or expired token")
        return

    await manager.connect(websocket)
    try:
        while True:
            # The client sends periodic pings; we only need to keep the socket
            # readable so disconnects surface promptly. All real traffic is
            # server -> client via manager.broadcast().
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
