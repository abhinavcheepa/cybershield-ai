"""Sliding-window counters backing the stateful detection rules.

Two implementations behind one five-method surface:

* `WindowState` — in-process dicts. Zero setup, correct for one worker.
* `RedisWindowState` — the same windows in Redis sorted sets, so a brute-force
  burst still trips its rule when the ten login attempts land on four different
  uvicorn workers. Selected automatically when `REDIS_URL` is set.

The Redis version keys on wall-clock time rather than `time.monotonic()`:
monotonic clocks are per-process and would not line up between workers.
"""

from __future__ import annotations

import itertools
import time
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Any

from .. import bus

# Hard cap on tracked entities so a spoofed-source flood cannot exhaust memory.
MAX_TRACKED_ENTITIES = 20_000

#: How long an untouched Redis window survives. Longer than any rule's window,
#: short enough that abandoned keys clear themselves — which is also what keeps
#: Redis memory bounded, in place of the in-process eviction below.
REDIS_KEY_TTL_S = 600


class WindowState:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._windows: dict[tuple[str, str], deque[tuple[float, Any, int]]] = defaultdict(deque)
        self._facts: dict[str, Any] = {}

    def record(self, rule: str, entity: str, value: Any = None, weight: int = 1) -> None:
        bucket = self._windows[(rule, entity)]
        bucket.append((self._clock(), value, weight))
        if len(self._windows) > MAX_TRACKED_ENTITIES:
            self._evict()

    def _prune(self, rule: str, entity: str, window: float) -> deque:
        bucket = self._windows.get((rule, entity))
        if bucket is None:
            return deque()
        cutoff = self._clock() - window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()
        if not bucket:
            self._windows.pop((rule, entity), None)
        return bucket

    def count(self, rule: str, entity: str, window: float) -> int:
        return sum(weight for _, _, weight in self._prune(rule, entity, window))

    def distinct(self, rule: str, entity: str, window: float) -> int:
        return len({value for _, value, _ in self._prune(rule, entity, window)})

    def remember(self, key: str, value: Any) -> Any | None:
        """Store `value` under `key`, returning whatever was there before."""
        previous = self._facts.get(key)
        self._facts[key] = value
        return previous

    def _evict(self) -> None:
        """Drop the oldest-touched half of the tracked entities."""
        ranked = sorted(self._windows.items(), key=lambda kv: kv[1][-1][0] if kv[1] else 0.0)
        for key, _ in ranked[: len(ranked) // 2]:
            self._windows.pop(key, None)

    def reset(self) -> None:
        self._windows.clear()
        self._facts.clear()


class RedisWindowState:
    """Same surface, backed by one sorted set per (rule, entity).

    A member encodes everything a read needs — `timestamp|seq|weight|value` —
    so `count` and `distinct` are one range read plus a parse, and the seq keeps
    two identical observations from collapsing into one set member.
    """

    def __init__(self, prefix: str = "cybershield:win") -> None:
        self._prefix = prefix
        self._clock = time.time
        self._seq = itertools.count()
        # Keys this instance has written, so reset() can delete exactly those.
        # A generation number in the key prefix would make reset O(1), but it
        # would also move this worker's windows away from everyone else's the
        # first time it reset — and sharing is the entire point of this class.
        # Seeding calls reset() once per episode, and an episode touches a
        # handful of keys, so the set stays small where it matters.
        self._written: set[str] = set()

    def _key(self, rule: str, entity: str) -> str:
        return f"{self._prefix}:w:{rule}:{entity}"

    def _track(self, key: str) -> None:
        if len(self._written) < MAX_TRACKED_ENTITIES:
            self._written.add(key)
        # Past the cap, reset() leaves the overflow to its TTL rather than
        # growing this set without bound in a long-lived worker.

    def record(self, rule: str, entity: str, value: Any = None, weight: int = 1) -> None:
        now = self._clock()
        key = self._key(rule, entity)
        member = f"{now:.6f}|{next(self._seq)}|{int(weight)}|{'' if value is None else value}"
        pipe = bus.redis().pipeline()
        pipe.zadd(key, {member: now})
        pipe.expire(key, REDIS_KEY_TTL_S)
        pipe.execute()
        self._track(key)

    def _entries(self, rule: str, entity: str, window: float) -> list[list[str]]:
        key = self._key(rule, entity)
        pipe = bus.redis().pipeline()
        pipe.zremrangebyscore(key, "-inf", f"({self._clock() - window}")
        pipe.zrange(key, 0, -1)
        _, members = pipe.execute()
        return [str(m).split("|", 3) for m in members]

    def count(self, rule: str, entity: str, window: float) -> int:
        return sum(int(parts[2]) for parts in self._entries(rule, entity, window))

    def distinct(self, rule: str, entity: str, window: float) -> int:
        return len({parts[3] for parts in self._entries(rule, entity, window)})

    def remember(self, key: str, value: Any) -> Any | None:
        full = f"{self._prefix}:f:{key}"
        self._track(full)
        return bus.redis().set(full, str(value), ex=REDIS_KEY_TTL_S, get=True)

    def reset(self) -> None:
        written, self._written = self._written, set()
        if written:
            bus.redis().delete(*written)


def new_state() -> WindowState | RedisWindowState:
    """The window store this deployment should use."""
    return RedisWindowState() if bus.enabled else WindowState()


if __name__ == "__main__":
    now = [0.0]
    state = WindowState(clock=lambda: now[0])

    for port in range(20):
        state.record("scan", "1.2.3.4", port)
    assert state.count("scan", "1.2.3.4", 60) == 20
    assert state.distinct("scan", "1.2.3.4", 60) == 20

    now[0] = 61.0
    assert state.count("scan", "1.2.3.4", 60) == 0, "expired entries must fall out of the window"

    state.record("icmp", "5.6.7.8", None, weight=250)
    assert state.count("icmp", "5.6.7.8", 10) == 250, "weights must sum, not count as one"

    assert state.remember("arp:10.0.0.1", "aa:bb") is None
    assert state.remember("arp:10.0.0.1", "cc:dd") == "aa:bb"

    # The Redis implementation has to behave identically. Skipped without a
    # REDIS_URL, because the point of the fallback is needing no Redis.
    if bus.enabled:
        shared = RedisWindowState(prefix=f"cybershield:selftest:{time.time()}")
        for port in range(20):
            shared.record("scan", "1.2.3.4", port)
        assert shared.count("scan", "1.2.3.4", 60) == 20
        assert shared.distinct("scan", "1.2.3.4", 60) == 20
        assert shared.count("scan", "1.2.3.4", 60) == 20, "a read must not consume the window"
        shared.record("icmp", "5.6.7.8", None, weight=250)
        assert shared.count("icmp", "5.6.7.8", 10) == 250
        assert shared.remember("arp:10.0.0.1", "aa:bb") is None
        assert shared.remember("arp:10.0.0.1", "cc:dd") == "aa:bb"

        # Two instances are two workers: they must see one shared window.
        other = RedisWindowState(prefix=shared._prefix)
        other.record("scan", "1.2.3.4", 99)
        assert shared.count("scan", "1.2.3.4", 60) == 21, "workers must share the window"

        # ...and must go on sharing it after one of them resets. A reset that
        # only moved this instance to a new key prefix would leave the two
        # counting separately, which is how a brute-force burst spread over
        # four workers stops tripping its rule.
        other.reset()
        shared.record("scan", "1.2.3.4", 7)
        other.record("scan", "1.2.3.4", 8)
        assert other.count("scan", "1.2.3.4", 60) == shared.count("scan", "1.2.3.4", 60), \
            "a reset must not move a worker off the shared window"
        assert other.count("scan", "1.2.3.4", 60) >= 2
        print("window state ok (in-process + redis)")
    else:
        print("window state ok (in-process; set REDIS_URL to also check the shared path)")
