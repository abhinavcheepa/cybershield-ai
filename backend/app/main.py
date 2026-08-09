"""CyberShield AI — application entrypoint."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import bus
from .config import settings
from .database import SessionLocal, init_db, startup_lock
from .routers import ai, auth, dashboard, events, live, notifications, realtime, rules, simulation
from .target.routes import router as target_router
from .target.vuln import client_ip
from .simulator.runner import simulator
from .ws import manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("cybershield")

#: The built SPA, when there is one. Serving it from here makes a cloud deploy a
#: single service on a single origin: no CORS, and the WebSocket is same-origin.
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
SERVE_SPA = settings.serve_frontend and (FRONTEND_DIST / "index.html").is_file()

DESCRIPTION = """
Real-time cyber attack detection, analysis and visualisation.

**This platform is for education and defensive security only.** The built-in
attack simulator generates synthetic log records inside this process — it never
transmits traffic to any host. Point the detection engine at real telemetry
only on systems you are authorised to monitor.

### Roles
| Role | Can do |
|---|---|
| `viewer` | Read dashboards, events, rules, notifications |
| `analyst` | Everything a viewer can, plus triage events, run the simulator, request AI analysis |
| `admin` | Everything an analyst can, plus tune detection rules and read the audit log |

Authenticate at `POST /api/auth/login`, then send `Authorization: Bearer <token>`.
The WebSocket at `/ws` takes the same token as a `?token=` query parameter.
"""


def _prepare_database() -> dict:
    """Schema, seed data and engine state. Blocking, and slow on a first boot.

    One worker creates the schema and seeds; the rest wait on the lock and then
    find the work already done, because every seed step checks before it writes.
    """
    from .routers.rules import sync_engine_state
    from .seed import seed_all

    with startup_lock():
        init_db()
        summary = seed_all()
    with SessionLocal() as db:
        sync_engine_state(db)
    return summary


@asynccontextmanager
async def lifespan(app: FastAPI):
    if int(os.environ.get("WEB_CONCURRENCY", "1")) > 1 and not bus.enabled:
        log.error(
            "WEB_CONCURRENCY > 1 without REDIS_URL: workers will not share detection "
            "windows, rate limits or WebSocket clients. Set REDIS_URL or run one worker."
        )

    await bus.start()

    # Off the event loop: seeding 250 events takes ~15 s, and holding the loop
    # for that long lets the leader claim expire under the winner's feet — two
    # workers then briefly both believe they own the simulator.
    summary = await asyncio.to_thread(_prepare_database)
    if any(summary.values()):
        log.info(
            "seeded %s users, %s assets, %s rules, %s events",
            summary["users"], summary["assets"], summary["rules"], summary["events"],
        )

    log.info(
        "CyberShield AI ready (%s, worker %s, redis=%s)",
        settings.environment, bus.WORKER_ID, "on" if bus.enabled else "off",
    )
    yield

    from .target.attack_runner import live_runner

    # shutdown(), not stop(): one worker going down must not stop a run the
    # leader is driving for the whole class.
    await simulator.shutdown()
    await live_runner.shutdown()
    await bus.stop()


app = FastAPI(
    title=settings.app_name,
    description=DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compress JSON payloads and the SPA bundle. The dashboard's event pages and
# the 40 KB stylesheet are the difference between "instant" and "still
# loading" on a classroom connection.
app.add_middleware(GZipMiddleware, minimum_size=1000)


# ---------------------------------------------------------------- middleware
# /site is the deliberately-vulnerable target — rate-limiting it would defeat
# the brute-force demo, which is the whole point.
_RATE_EXEMPT = ("/ws", "/site", "/assets", "/api/health", "/api/docs", "/api/redoc", "/api/openapi.json")

_API_CSP = "default-src 'none'; frame-ancestors 'none'"
# Mirrors frontend/nginx.conf — the same SPA, so the same policy.
_SPA_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://*.basemaps.cartocdn.com; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def _is_api_path(path: str) -> bool:
    return path.startswith(("/api", "/site", "/ws"))


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    """Fixed-cost window per client IP, shared across workers when Redis is on.

    Behind a load balancer `request.client.host` is the proxy, which would put
    the whole class in one bucket — so this keys on the same forwarded address
    the detection pipeline attributes traffic to.

    ponytail: that address comes from `X-Forwarded-For`, so a caller who can
    reach the app directly can rotate it and get a fresh bucket each request.
    Closing that means a trusted-proxy CIDR list, which is worth adding the day
    this protects something — the lab target at `/site` is exempt on purpose.
    """
    if request.url.path.startswith(_RATE_EXEMPT):
        return await call_next(request)

    if not await bus.rate_hit(client_ip(request), settings.rate_limit_per_minute):
        return JSONResponse(
            {"detail": "Rate limit exceeded. Slow down."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "60"},
        )

    return await call_next(request)


@app.middleware("http")
async def secure_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    # The API only ever returns JSON, so it needs no script/style/image sources
    # of its own. Pages served from `frontend/dist` need the SPA's policy.
    response.headers.setdefault(
        "Content-Security-Policy",
        _API_CSP if _is_api_path(path) or not SERVE_SPA else _SPA_CSP,
    )
    # Build assets carry a content hash in their name, so they can be cached
    # forever; index.html must never be, or a client pins itself to a stale
    # bundle. This is most of why a second visit costs nothing on slow links.
    if path.startswith("/assets/"):
        response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    if request.url.scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
    return response


# ------------------------------------------------------------------- routes
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(dashboard.router)
app.include_router(rules.router)
app.include_router(simulation.router)
app.include_router(notifications.router)
app.include_router(ai.router)
app.include_router(realtime.router)
app.include_router(live.router)
app.include_router(target_router)


@app.get("/api/health", tags=["System"], summary="Liveness and runtime state")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.environment,
        # Per-worker: with several workers each holds its own share of clients.
        "websocket_clients": manager.count,
        "simulator": simulator.status.value,
        "worker": bus.WORKER_ID,
        "leader": bus.is_leader(),
        "redis": bus.enabled,
    }


if SERVE_SPA:
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{spa_path:path}", include_in_schema=False)
    def spa(spa_path: str) -> FileResponse:
        """Serve the built SPA, with unknown paths resolving to its shell."""
        # An unknown API path is a 404, not the app shell — an API client
        # should not have to parse HTML to discover it called the wrong URL.
        if _is_api_path("/" + spa_path):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
        # `spa_path` is attacker-controlled, so a real file is only served when
        # it resolves to something genuinely inside the build directory.
        candidate = (FRONTEND_DIST / spa_path).resolve()
        if spa_path and FRONTEND_DIST in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(
            FRONTEND_DIST / "index.html", headers={"Cache-Control": "no-store"}
        )

else:

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {"service": settings.app_name, "docs": "/api/docs", "health": "/api/health"}
