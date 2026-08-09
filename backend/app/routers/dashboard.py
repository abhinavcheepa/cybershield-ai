"""Dashboard statistics, charts, geography and threat intelligence."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import analytics
from ..database import get_db
from ..models import Incident, ThreatActor
from ..schemas import (
    CountryStat,
    DashboardStats,
    IncidentOut,
    ThreatActorOut,
    TimeBucket,
)
from ..security import CurrentUser

router = APIRouter(prefix="/api", tags=["Dashboard"])

DB = Annotated[Session, Depends(get_db)]


@router.get("/dashboard/stats", response_model=DashboardStats, summary="Headline metrics")
def stats(_: CurrentUser, db: DB, hours: int = Query(24, ge=1, le=720)) -> DashboardStats:
    return analytics.dashboard_stats(db, hours)


@router.get(
    "/dashboard/timeseries",
    response_model=list[TimeBucket],
    summary="Bucketed attack volume, severity mix, threat score and response time",
)
def timeseries(
    _: CurrentUser,
    db: DB,
    minutes: int = Query(60, ge=5, le=10080),
    buckets: int = Query(30, ge=5, le=120),
) -> list[TimeBucket]:
    return analytics.timeseries(db, minutes, buckets)


@router.get("/countries", response_model=list[CountryStat], summary="Attack volume by source country")
def countries(_: CurrentUser, db: DB, hours: int = Query(24, ge=1, le=720)) -> list[CountryStat]:
    return analytics.country_stats(db, hours)


@router.get("/countries/catalog", summary="Country codes and map coordinates")
def country_catalog(_: CurrentUser) -> list[dict]:
    return analytics.known_countries()


@router.get(
    "/threat-intel/actors",
    response_model=list[ThreatActorOut],
    summary="Source IPs ranked by reputation score",
)
def actors(_: CurrentUser, db: DB, limit: int = Query(25, ge=1, le=200)) -> list[ThreatActor]:
    return analytics.top_actors(db, limit)


@router.get("/incidents", response_model=list[IncidentOut], summary="Open and recent incidents")
def incidents(_: CurrentUser, db: DB, limit: int = Query(50, ge=1, le=200)) -> list[Incident]:
    return list(db.scalars(select(Incident).order_by(Incident.opened_at.desc()).limit(limit)))
