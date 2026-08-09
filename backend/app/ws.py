"""WebSocket fan-out.

A socket only ever lives in the worker that accepted it, so with more than one
uvicorn worker a broadcast has to travel between workers before it can reach
every browser. Every send therefore goes out as a Redis publish and comes back
through `relay()`, which is the only thing that touches a socket. Publishers do
not deliver locally — they receive their own message from the subscription like
everyone else, so there is exactly one delivery path and no double-sends.

With no `REDIS_URL` there are no other workers, and `relay()` is called
directly. Same code path, one process.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from fastapi import WebSocket

from . import bus

log = logging.getLogger(__name__)

#: Broadcast types that carry control-plane state. Workers cache the newest of
#: each so any of them can answer `GET /api/simulation/state` without asking
#: the worker that actually owns the runner.
_SNAPSHOT_TYPES = ("simulation", "live_attack")


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode(v) for v in value]
    if hasattr(value, "value"):  # enum
        return value.value
    return value


class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    @property
    def count(self) -> int:
        """Sockets held by *this* worker."""
        return len(self._clients)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)
        await self.send(websocket, "connected", {"clients": len(self._clients)})

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    async def send(self, websocket: WebSocket, event: str, data: Any) -> None:
        await websocket.send_json({"type": event, "data": _encode(data)})

    async def broadcast(self, event: str, data: Any) -> None:
        await _dispatch({"scope": "all", "type": event, "data": _encode(data)})

    async def deliver(self, payload: dict) -> None:
        if not self._clients:
            return
        # Snapshot once — the set can be mutated by disconnects while we await.
        clients = list(self._clients)
        results = await asyncio.gather(
            *(client.send_json(payload) for client in clients),
            return_exceptions=True,
        )
        for client, result in zip(clients, results):
            if isinstance(result, Exception):
                self._clients.discard(client)


class KeyedConnectionManager:
    """Fan-out to a single named channel — one student's browser(s).

    The SOC dashboard uses the global `manager`; each student site subscribes
    here under their username so a real attack against their site pushes a live
    'under attack' event to only them.
    """

    def __init__(self) -> None:
        self._channels: dict[str, set[WebSocket]] = {}

    async def connect(self, key: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._channels.setdefault(key, set()).add(websocket)
        await websocket.send_json({"type": "connected", "data": {"channel": key}})

    def disconnect(self, key: str, websocket: WebSocket) -> None:
        sockets = self._channels.get(key)
        if sockets:
            sockets.discard(websocket)
            if not sockets:
                self._channels.pop(key, None)

    async def send_to(self, key: str, event: str, data: Any) -> None:
        await _dispatch({"scope": "site", "key": key, "type": event, "data": _encode(data)})

    async def deliver(self, key: str, payload: dict) -> None:
        sockets = self._channels.get(key)
        if not sockets:
            return
        for socket in list(sockets):
            try:
                await socket.send_json(payload)
            except Exception:
                sockets.discard(socket)


manager = ConnectionManager()
site_manager = KeyedConnectionManager()


async def _dispatch(envelope: dict) -> None:
    """Send one message to every worker — or straight to `relay` if we are alone."""
    if bus.enabled:
        await bus.publish(bus.WS_CHANNEL, envelope)
    else:
        await relay(envelope)


async def relay(envelope: dict) -> None:
    """Deliver one envelope to the sockets held by this worker."""
    payload = {"type": envelope["type"], "data": envelope["data"]}
    if envelope["type"] in _SNAPSHOT_TYPES and isinstance(envelope["data"], dict):
        bus.snapshots[envelope["type"]] = envelope["data"]
    if envelope.get("scope") == "site":
        await site_manager.deliver(envelope["key"], payload)
    else:
        await manager.deliver(payload)


bus.on(bus.WS_CHANNEL, relay)
