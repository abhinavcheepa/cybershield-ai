"""Attack simulator.

Drives synthetic attack episodes into the same ingest pipeline real telemetry
would use, then broadcasts whatever the detection engine produced. Controls:
start / pause / resume / stop, frequency, scenario selection, source country,
and attacker-IP randomisation.

SAFETY: nothing here emits network traffic. `scenarios.py` builds log-shaped
dictionaries; this module only schedules them.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime

from sqlalchemy import select

from .. import bus, geo
from ..database import SessionLocal
from ..models import Asset, AttackSimulation, Notification, SimulationStatus
from ..pipeline import ingest_many
from ..schemas import AttackEventOut, NotificationOut, SimulationConfig, SimulationState
from ..ws import manager
from .scenarios import SCENARIOS, Scenario

log = logging.getLogger(__name__)

#: Source countries the generator favours when the operator has not pinned one.
#: Weighted to look like a real internet-facing edge rather than a uniform draw.
DEFAULT_SOURCE_WEIGHTS = {
    "RU": 14, "CN": 13, "US": 11, "IN": 6, "BR": 6, "IR": 6, "NL": 5, "VN": 5,
    "UA": 4, "KP": 4, "DE": 4, "ID": 4, "TR": 3, "NG": 3, "RO": 3, "FR": 3,
    "GB": 3, "KR": 2, "SG": 2, "PL": 2,
}


class AttackSimulator:
    def __init__(self) -> None:
        self.config = SimulationConfig()
        self.status = SimulationStatus.STOPPED
        self.events_generated = 0
        self.detections = 0
        self.started_at: datetime | None = None
        self.started_by: str | None = None
        self._run_id: int | None = None
        self._task: asyncio.Task | None = None
        self._rng = random.Random()
        # Stable attacker pool, used when randomize_ips is off so the
        # "top attackers" widget accumulates against repeat offenders.
        self._actor_pool: dict[str, str] = {}

    # ------------------------------------------------------------------ state
    def state(self) -> SimulationState:
        # Only one worker runs the loop, so the others answer from the snapshot
        # the leader's own broadcast left on the bus.
        if not bus.is_leader():
            snapshot = bus.snapshots.get("simulation")
            if snapshot:
                return SimulationState.model_validate(snapshot)
        return SimulationState(
            status=self.status,
            config=self.config,
            events_generated=self.events_generated,
            detections=self.detections,
            started_at=self.started_at,
            started_by=self.started_by,
        )

    async def _announce(self) -> None:
        await manager.broadcast("simulation", self.state().model_dump(mode="json"))

    # -------------------------------------------------------- worker routing
    async def handle(self, action: str, args: dict) -> None:
        """Run a control action forwarded by another worker. Leader only."""
        if action == "start":
            await self.start(SimulationConfig.model_validate(args["config"]), args["started_by"])
        elif action == "pause":
            await self.pause()
        elif action == "resume":
            await self.resume()
        elif action == "stop":
            await self.stop()

    # ------------------------------------------------------------- controls
    async def start(self, config: SimulationConfig, started_by: str) -> SimulationState:
        if await bus.command("simulator", "start",
                             {"config": config.model_dump(mode="json"), "started_by": started_by}):
            # Another worker owns the loop. The state it reaches comes back over
            # the WebSocket a moment later — that is what the UI renders from.
            return self.state()
        if self.status is SimulationStatus.RUNNING:
            return self.state()

        self.config = config
        self.started_by = started_by
        if self.status is SimulationStatus.PAUSED and self._task and not self._task.done():
            self.status = SimulationStatus.RUNNING
            await self._announce()
            return self.state()

        self.status = SimulationStatus.RUNNING
        self.started_at = datetime.now(UTC)
        self.events_generated = 0
        self.detections = 0
        self._run_id = await asyncio.to_thread(self._open_run, config, started_by)
        self._task = asyncio.create_task(self._loop())
        await self._announce()
        return self.state()

    async def pause(self) -> SimulationState:
        if await bus.command("simulator", "pause"):
            return self.state()
        if self.status is SimulationStatus.RUNNING:
            self.status = SimulationStatus.PAUSED
            await self._announce()
        return self.state()

    async def resume(self) -> SimulationState:
        if await bus.command("simulator", "resume"):
            return self.state()
        if self.status is SimulationStatus.PAUSED:
            self.status = SimulationStatus.RUNNING
            await self._announce()
        return self.state()

    async def stop(self) -> SimulationState:
        if await bus.command("simulator", "stop"):
            return self.state()
        await self.shutdown()
        await self._announce()
        return self.state()

    async def shutdown(self) -> None:
        """Tear down this worker's loop without touching any other worker.

        Process shutdown calls this rather than `stop()`: one worker restarting
        must not stop a simulation the leader is running.
        """
        self.status = SimulationStatus.STOPPED
        task, self._task = self._task, None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._run_id is not None:
            await asyncio.to_thread(self._close_run, self._run_id, self.events_generated)
            self._run_id = None

    # ------------------------------------------------------------------ loop
    async def _loop(self) -> None:
        try:
            while self.status is not SimulationStatus.STOPPED:
                if self.status is SimulationStatus.PAUSED:
                    await asyncio.sleep(0.25)
                    continue

                try:
                    result = await asyncio.to_thread(self._run_episode)
                except Exception:
                    log.exception("simulation episode failed")
                    await asyncio.sleep(1.0)
                    continue

                self.events_generated += result["observations"]
                self.detections += len(result["events"])

                for payload in result["events"]:
                    await manager.broadcast("attack_event", payload)
                for payload in result["notifications"]:
                    await manager.broadcast("notification", payload)
                if result["events"]:
                    await self._announce()

                if not self.config.repeat:
                    await self.stop()
                    return

                await asyncio.sleep(60.0 / max(1, self.config.events_per_minute))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("simulator loop crashed")
            self.status = SimulationStatus.STOPPED
            await self._announce()

    # ------------------------------------------------- synchronous DB helpers
    def _open_run(self, config: SimulationConfig, started_by: str) -> int:
        with SessionLocal() as db:
            run = AttackSimulation(
                started_by=started_by,
                status=SimulationStatus.RUNNING,
                config=config.model_dump(),
            )
            db.add(run)
            db.commit()
            return run.id

    def _close_run(self, run_id: int, events_generated: int) -> None:
        with SessionLocal() as db:
            run = db.get(AttackSimulation, run_id)
            if run is None:
                return
            run.status = SimulationStatus.STOPPED
            run.stopped_at = datetime.now(UTC)
            run.events_generated = events_generated
            db.commit()

    def _pick_scenario(self) -> Scenario:
        keys = self.config.scenarios or list(SCENARIOS)
        return SCENARIOS[self._rng.choice(keys)]

    def _pick_country(self) -> str:
        if self.config.source_countries:
            return self._rng.choice(self.config.source_countries)
        codes = list(DEFAULT_SOURCE_WEIGHTS)
        weights = [DEFAULT_SOURCE_WEIGHTS[c] for c in codes]
        return self._rng.choices(codes, weights=weights, k=1)[0]

    def _pick_source_ip(self, country: str) -> str:
        if self.config.randomize_ips:
            return geo.ip_for_country(country, self._rng)
        # Reuse one address per country so repeat offenders build reputation.
        if country not in self._actor_pool:
            self._actor_pool[country] = geo.ip_for_country(country, self._rng)
        return self._actor_pool[country]

    def _pick_target(self, assets: list[Asset], scenario: Scenario) -> dict:
        candidates = [a for a in assets if a.service == scenario.service] or assets
        asset = self._rng.choice(candidates)
        return {
            "ip": asset.ip_address,
            "port": asset.port,
            "protocol": "HTTPS" if asset.port in (443, 8443) else "TCP",
            "hostname": asset.hostname,
        }

    def _run_episode(self) -> dict:
        """One attack episode, start to stored events. Runs off the event loop."""
        with SessionLocal() as db:
            assets = list(db.scalars(select(Asset)))
            if not assets:
                log.warning("no assets seeded; simulator has nothing to attack")
                return {"observations": 0, "events": [], "notifications": []}

            scenario = self._pick_scenario()
            country = self._pick_country()
            source_ip = self._pick_source_ip(country)
            target = self._pick_target(assets, scenario)

            observations = scenario.build(self._rng, source_ip, target)
            events = ingest_many(db, observations, simulated=True)

            payloads = [AttackEventOut.model_validate(e).model_dump(mode="json") for e in events]
            notifications = []
            if events:
                rows = db.scalars(
                    select(Notification)
                    .where(Notification.event_id.in_([e.id for e in events]))
                    .order_by(Notification.id.desc())
                ).all()
                notifications = [
                    NotificationOut.model_validate(n).model_dump(mode="json") for n in rows
                ]

            return {
                "observations": len(observations),
                "events": payloads,
                "notifications": notifications,
            }


simulator = AttackSimulator()
bus.register("simulator", simulator)
