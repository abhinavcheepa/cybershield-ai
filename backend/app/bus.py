"""Cross-worker coordination.

Everything several uvicorn workers have to agree on lives behind this module:
WebSocket fan-out, rate-limit counters, which worker owns the simulator, and
the control-plane snapshot each worker answers `GET /state` from.

With `REDIS_URL` unset there is nothing to coordinate — every helper falls back
to the in-process object it replaced, so `uvicorn app.main:app` still needs
nothing but Python and a SQLite file. Set `REDIS_URL` and the same code spreads
across `--workers N`.

ponytail: one module, not a package. Redis is the only thing the workers share,
so one file is the entire surface — and the entire thing to delete if this ever
goes back to a single worker.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Protocol

from .config import settings

log = logging.getLogger(__name__)

#: Distinct per uvicorn worker process — the value a leader claim is stamped with.
WORKER_ID = f"{os.getpid()}-{uuid.uuid4().hex[:6]}"

WS_CHANNEL = "cybershield:ws"
CTL_CHANNEL = "cybershield:ctl"
LEADER_KEY = "cybershield:leader"

#: A leader claim dies this many seconds after its last heartbeat, so a worker
#: killed mid-class hands the simulator over instead of stranding it. Six
#: heartbeats of margin, because a busy small instance really does starve an
#: idle event loop for several seconds at a time — and the cost of the wider
#: margin is only a slower failover, which the operator absorbs by pressing
#: Start again.
LEADER_TTL = 30
LEADER_HEARTBEAT_S = 5.0

enabled = bool(settings.redis_url)

#: Latest control-plane state each worker has seen, keyed by broadcast type
#: ("simulation", "live_attack"). The runners already announce their full state
#: on every change and that announcement reaches every worker through the WS
#: channel below, so non-leader workers can answer state queries from here
#: without a single extra round trip.
snapshots: dict[str, dict] = {}

_sync_client: Any = None
_async_client: Any = None
_sub_client: Any = None
_is_leader = not enabled  # no Redis means one worker, and it owns everything
_listener: asyncio.Task | None = None
_heartbeat: asyncio.Task | None = None


# --------------------------------------------------------------------- clients
def redis() -> Any:
    """Blocking client. Detection state runs inside `asyncio.to_thread`, so it
    needs the sync client rather than the async one."""
    global _sync_client
    if _sync_client is None:
        import redis as redis_lib

        _sync_client = redis_lib.from_url(
            settings.redis_url, decode_responses=True, socket_timeout=3.0
        )
    return _sync_client


def aredis() -> Any:
    """Async client for commands. Bounded read timeout: a hung Redis must not
    hang a request."""
    global _async_client
    if _async_client is None:
        import redis.asyncio as redis_asyncio

        _async_client = redis_asyncio.from_url(
            settings.redis_url, decode_responses=True, socket_timeout=3.0
        )
    return _async_client


def asub() -> Any:
    """Async client for the subscription, which needs *no* read timeout.

    `socket_timeout` applies to the blocking read inside `pubsub.listen()`, so
    sharing the command client above meant a quiet channel looked like a dead
    connection every three seconds: the subscription was torn down and rebuilt
    on a loop, dropping whatever was published in the gap. Idling is normal
    here, so the deadline goes away and `health_check_interval` is what notices
    a peer that has actually gone.
    """
    global _sub_client
    if _sub_client is None:
        import redis.asyncio as redis_asyncio

        _sub_client = redis_asyncio.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5.0,
            health_check_interval=30,
        )
    return _sub_client


# ---------------------------------------------------------------- leadership
class Controllable(Protocol):
    """Something the leader worker runs on everyone's behalf."""

    async def handle(self, action: str, args: dict) -> None: ...


_controllables: dict[str, Controllable] = {}


def register(target: str, obj: Controllable) -> None:
    _controllables[target] = obj


def is_leader() -> bool:
    return _is_leader


async def command(target: str, action: str, args: dict | None = None) -> bool:
    """Hand a control action to whichever worker owns it.

    Returns False when *this* worker is the leader — the caller should just do
    the work itself.
    """
    if _is_leader:
        return False
    await publish(CTL_CHANNEL, {"target": target, "action": action, "args": args or {}})
    return True


async def _dispatch_command(message: dict) -> None:
    if not _is_leader:
        return
    obj = _controllables.get(message.get("target", ""))
    if obj is None:
        return
    try:
        await obj.handle(str(message.get("action", "")), dict(message.get("args") or {}))
    except Exception:
        log.exception("control command failed: %s", message)


async def _claim() -> None:
    """One pass at taking or holding the leader claim."""
    global _is_leader
    client = aredis()
    try:
        if _is_leader:
            # Only extend a claim that is still ours; a process paused past its
            # TTL can wake up to find someone else has taken over.
            if await client.get(LEADER_KEY) == WORKER_ID:
                await client.expire(LEADER_KEY, LEADER_TTL)
            else:
                _is_leader = False
                log.warning("lost control-plane leadership (%s)", WORKER_ID)
        elif await client.set(LEADER_KEY, WORKER_ID, nx=True, ex=LEADER_TTL):
            _is_leader = True
            log.info("worker %s is the control-plane leader", WORKER_ID)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.warning("leader heartbeat failed", exc_info=True)


async def _heartbeat_loop() -> None:
    """Keep the claim alive, or take it over when the holder stops refreshing.

    ponytail: if the leader dies mid-run the new leader does not resume the
    simulation — the operator presses Start again. Resuming would mean
    persisting the run's cursor, which is a lot of machinery for a lab.
    """
    while True:
        await asyncio.sleep(LEADER_HEARTBEAT_S)
        await _claim()


# -------------------------------------------------------------------- pub/sub
#: channel -> coroutine taking the decoded message. Set by `ws.py` and here.
_handlers: dict[str, Any] = {}


def on(channel: str, handler: Any) -> None:
    _handlers[channel] = handler


async def publish(channel: str, payload: dict) -> None:
    if not enabled:
        return
    try:
        await aredis().publish(channel, json.dumps(payload))
    except Exception:
        log.warning("publish to %s failed", channel, exc_info=True)


async def _listen_loop() -> None:
    backoff = 1.0
    while True:
        try:
            pubsub = asub().pubsub(ignore_subscribe_messages=True)
            await pubsub.subscribe(*_handlers)
            backoff = 1.0
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                handler = _handlers.get(message["channel"])
                if handler is None:
                    continue
                try:
                    await handler(json.loads(message["data"]))
                except Exception:
                    log.exception("bus handler for %s failed", message["channel"])
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("bus subscription dropped; retrying in %.0fs", backoff, exc_info=True)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)


# -------------------------------------------------------------- rate limiting
_hits: dict[str, deque[float]] = defaultdict(deque)


async def rate_hit(client_key: str, limit: int) -> bool:
    """Count one request. False means the caller is over `limit` per minute.

    ponytail: the Redis path is a fixed 60-second bucket, not a sliding window —
    one INCR instead of a sorted set per client, at the cost of allowing a burst
    across a bucket boundary. That distinction does not matter for a classroom.
    """
    if enabled:
        try:
            key = f"cybershield:rl:{client_key}:{int(time.time() // 60)}"
            pipe = aredis().pipeline()
            pipe.incr(key)
            pipe.expire(key, 70)
            count, _ = await pipe.execute()
            return int(count) <= limit
        except Exception:
            # Fail open. A Redis blip must not lock the whole class out.
            log.warning("rate limit check failed; allowing request", exc_info=True)
            return True

    now = time.monotonic()
    window = _hits[client_key]
    while window and now - window[0] > 60.0:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    if len(_hits) > 10_000:  # bound memory against a spoofed-source flood
        for key in [k for k, v in _hits.items() if not v][:5_000]:
            _hits.pop(key, None)
    return True


# ------------------------------------------------------------------ lifecycle
async def start() -> None:
    """Join the bus. Safe (and free) to call when Redis is not configured."""
    global _listener, _heartbeat
    if not enabled:
        return
    on(CTL_CHANNEL, _dispatch_command)
    # Settle the election before this worker serves anything. Left to the
    # heartbeat task, there would be a moment at boot where no worker considers
    # itself the leader and a control command would be published to nobody.
    await _claim()
    _listener = asyncio.create_task(_listen_loop())
    _heartbeat = asyncio.create_task(_heartbeat_loop())


async def stop() -> None:
    global _is_leader
    for task in (_listener, _heartbeat):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    if not enabled:
        return
    try:
        client = aredis()
        # Release leadership on a clean shutdown so the next worker takes over
        # immediately instead of waiting out the TTL.
        if _is_leader and await client.get(LEADER_KEY) == WORKER_ID:
            await client.delete(LEADER_KEY)
        await client.aclose()
        if _sub_client is not None:
            await _sub_client.aclose()
    except Exception:
        log.warning("bus shutdown was not clean", exc_info=True)
    _is_leader = False


if __name__ == "__main__":
    # Self-check for the in-process fallback — the path every dev machine and
    # the test suite take. The Redis path is covered by running the stack.
    async def _demo() -> None:
        if enabled:
            print("bus skipped: this checks the no-Redis fallback; unset REDIS_URL to run it")
            return
        assert is_leader(), "with no Redis the single worker must own the control plane"
        for _ in range(3):
            assert await rate_hit("10.0.0.1", 3)
        assert not await rate_hit("10.0.0.1", 3), "the fourth hit must be refused"
        assert await rate_hit("10.0.0.2", 3), "limits are per client"
        assert not await command("simulator", "start"), "the leader runs commands itself"
        print("bus ok")

    asyncio.run(_demo())
