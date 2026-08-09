"""Attack simulator control.

Everything here generates synthetic events inside this process. No endpoint in
this router can be pointed at a third-party host — the simulator has no target
parameter, only a choice of which seeded lab asset to write logs about.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AttackSimulation
from ..schemas import ScenarioInfo, SimulationConfig, SimulationRunOut, SimulationState
from ..security import CurrentUser, RequireAnalyst, audit
from ..simulator.runner import simulator
from ..simulator.scenarios import SCENARIOS

router = APIRouter(prefix="/api/simulation", tags=["Attack Simulation"])

DB = Annotated[Session, Depends(get_db)]


@router.get("/scenarios", response_model=list[ScenarioInfo], summary="Available simulations")
def scenarios(_: CurrentUser) -> list[ScenarioInfo]:
    return [
        ScenarioInfo(
            key=s.key,
            name=s.name,
            description=s.description,
            expected_detection=s.expected_detection,
        )
        for s in SCENARIOS.values()
    ]


@router.get("/state", response_model=SimulationState, summary="Current simulator state")
def state(_: CurrentUser) -> SimulationState:
    return simulator.state()


@router.post("/start", response_model=SimulationState, summary="Start or reconfigure (analyst)")
async def start(config: SimulationConfig, user: RequireAnalyst, db: DB, request: Request) -> SimulationState:
    result = await simulator.start(config, user.email)
    audit(db, user.email, "simulation.start", "simulator", config.model_dump(), request)
    return result


@router.post("/pause", response_model=SimulationState, summary="Pause (analyst)")
async def pause(user: RequireAnalyst, db: DB, request: Request) -> SimulationState:
    result = await simulator.pause()
    audit(db, user.email, "simulation.pause", "simulator", request=request)
    return result


@router.post("/resume", response_model=SimulationState, summary="Resume (analyst)")
async def resume(user: RequireAnalyst, db: DB, request: Request) -> SimulationState:
    result = await simulator.resume()
    audit(db, user.email, "simulation.resume", "simulator", request=request)
    return result


@router.post("/stop", response_model=SimulationState, summary="Stop (analyst)")
async def stop(user: RequireAnalyst, db: DB, request: Request) -> SimulationState:
    result = await simulator.stop()
    audit(db, user.email, "simulation.stop", "simulator", request=request)
    return result


@router.get("/runs", response_model=list[SimulationRunOut], summary="Simulation run history")
def runs(_: CurrentUser, db: DB, limit: int = 25) -> list[AttackSimulation]:
    return list(
        db.scalars(
            select(AttackSimulation).order_by(AttackSimulation.started_at.desc()).limit(min(limit, 200))
        )
    )
