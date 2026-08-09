"""Turn real target-site traffic into detection telemetry.

Every request the vulnerable site handles is converted to an observation and
run through the SAME detection pipeline the SOC dashboard reads. So detections
here are produced by genuine HTTP the site actually received — not synthetic
records. Benign student traffic flows through too and simply does not trip any
rule, which is exactly what a real IDS looks like.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import Request

from ..database import SessionLocal
from ..pipeline import ingest
from ..schemas import AttackEventOut, NotificationOut
from ..ws import manager, site_manager
from .models import SiteUser

log = logging.getLogger(__name__)

# What the student sees when each attack type lands on their site. Plain,
# personal language — the point is that they feel it, not read a CVE.
_EFFECT = {
    "SQL Injection": ("data_theft", "Your private data is being stolen from the database"),
    "XSS": ("defaced", "Someone injected code into your page"),
    "Brute Force Login": ("brute_force", "Someone is trying to guess your password"),
    "SSH Brute Force": ("brute_force", "Someone is hammering your login"),
    "Directory Traversal": ("file_leak", "Someone is reading files off your server"),
    "Command Injection": ("takeover", "Someone is running commands on your server"),
    "Suspicious File Upload": ("malware", "A malicious file was uploaded to your site"),
}
_DEFAULT_EFFECT = ("attack", "Suspicious activity detected on your site")


def client_ip(request: Request) -> str:
    """Attacker-facing source IP. The attack runner sets X-Forwarded-For to a
    spoofed public address so the map lights up by country; real students come
    through as whatever the tunnel presents."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _run_ingest(obs: dict) -> dict | None:
    """Analyse one observation in its own session. Returns serialised payloads
    for broadcast, or None if the traffic was benign."""
    with SessionLocal() as db:
        event = ingest(db, obs, simulated=False)
        if event is None:
            return None
        from sqlalchemy import select

        from ..models import Notification

        payload = AttackEventOut.model_validate(event).model_dump(mode="json")
        note_row = db.scalar(
            select(Notification).where(Notification.event_id == event.id).order_by(Notification.id.desc())
        )
        note = NotificationOut.model_validate(note_row).model_dump(mode="json") if note_row else None
        return {
            "event": payload,
            "notification": note,
            "attack_type": event.attack_type,
            "severity": event.severity.value,
            "threat_score": event.threat_score,
            "source_country": event.source_country_name,
            "source_ip": event.source_ip,
        }


async def observe(
    request: Request,
    site: SiteUser | None,
    *,
    path: str,
    payload: str = "",
    status_code: int = 200,
    auth_failure: bool = False,
    extra: dict | None = None,
) -> None:
    """Feed one real request into detection, then broadcast whatever fired.

    `site` is the student whose mini-site was hit, so a detection can be pushed
    to that student's own browser and attributed to their asset on the SOC map.
    """
    obs: dict = {
        "source_ip": client_ip(request),
        "source_port": (request.client.port if request.client else 0) or 0,
        "destination_ip": site.asset_ip if site and site.asset_ip else "10.0.0.20",
        "destination_port": 8010,
        "protocol": "HTTP",
        "method": request.method,
        "path": path,
        "query_string": str(request.url.query),
        "payload": payload,
        "user_agent": request.headers.get("user-agent", ""),
        "status_code": status_code,
        "auth_failure": auth_failure,
        "raw": f"{request.method} {path} -> {status_code}",
    }
    if extra:
        obs.update(extra)

    result = await asyncio.to_thread(_run_ingest, obs)
    if result is None:
        return

    # SOC dashboard (everyone watching the projector / CyberShield UI).
    await manager.broadcast("attack_event", result["event"])
    if result["notification"]:
        await manager.broadcast("notification", result["notification"])

    # The student whose site was hit — their own live "under attack" feed.
    if site is not None:
        kind, message = _EFFECT.get(result["attack_type"], _DEFAULT_EFFECT)
        await site_manager.send_to(
            site.username,
            "under_attack",
            {
                "kind": kind,
                "message": message,
                "attack_type": result["attack_type"],
                "severity": result["severity"],
                "threat_score": result["threat_score"],
                "source_ip": result["source_ip"],
                "source_country": result["source_country"],
            },
        )
