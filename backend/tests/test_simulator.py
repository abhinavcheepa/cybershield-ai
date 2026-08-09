"""Simulator, ingest pipeline and WebSocket broadcast."""

from __future__ import annotations

import random
import time

from app.detection.engine import engine
from app.models import AttackEvent, Notification, Severity, ThreatActor
from app.pipeline import ingest, ingest_many, reset_correlation
from app.simulator.scenarios import SCENARIOS


def _session():
    from app.database import SessionLocal

    return SessionLocal()


def test_simulator_never_opens_a_socket(monkeypatch):
    """The scenarios must be pure data construction — no network, ever."""
    import socket

    def explode(*args, **kwargs):
        raise AssertionError("the attack simulator attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", explode)
    monkeypatch.setattr(socket.socket, "connect_ex", explode)
    monkeypatch.setattr(socket.socket, "sendto", explode)
    monkeypatch.setattr(socket, "create_connection", explode)

    rng = random.Random(3)
    target = {"ip": "10.0.0.20", "port": 443, "protocol": "HTTPS", "hostname": "web-prod-01"}
    for scenario in SCENARIOS.values():
        observations = scenario.build(rng, "185.220.101.9", target)
        assert observations
        assert all(isinstance(o, dict) for o in observations)


def test_every_scenario_emits_a_realistic_log_line():
    rng = random.Random(11)
    target = {"ip": "10.0.0.20", "port": 443, "protocol": "HTTPS", "hostname": "web-prod-01"}
    for key, scenario in SCENARIOS.items():
        for observation in scenario.build(rng, "185.220.101.9", target):
            assert observation["raw"], f"{key} produced an observation with no raw log"
            assert observation["source_ip"]
            assert observation["destination_ip"]


def test_ingest_stores_event_explanation_actor_and_notification(client):
    """`client` is requested so the schema exists and seed data is present."""
    reset_correlation()
    engine.reset()

    with _session() as db:
        before = db.query(AttackEvent).count()
        event = ingest(db, {
            "source_ip": "185.220.101.77",
            "source_port": 44112,
            "destination_ip": "10.0.0.20",
            "destination_port": 443,
            "protocol": "HTTPS",
            "path": "/api/v1/users?id=1' UNION ALL SELECT username,password FROM users -- ",
            "payload": "1' UNION ALL SELECT username,password FROM users -- ",
            "user_agent": "sqlmap/1.8.2#stable",
            "bytes": 1024,
            "packet_count": 3,
            "raw": "test log line",
        })

        assert event is not None
        assert db.query(AttackEvent).count() == before + 1
        assert event.attack_type == "SQL Injection"
        assert event.severity is Severity.CRITICAL
        assert event.source_country == "RU", "185.220.x must geolocate deterministically"
        assert event.source_lat and event.source_lon, "the map needs coordinates"
        assert event.asset_id is not None, "should bind to the seeded web-prod-01 asset"
        assert event.blocked is True, "a critical score must trip the auto-block policy"
        assert event.raw_log["raw"] == "test log line"

        assert event.explanation is not None
        assert "185.220.101.77" in event.explanation.why_detected

        actor = db.get(ThreatActor, event.threat_actor_id)
        assert actor.ip_address == "185.220.101.77"
        assert actor.event_count >= 1

        assert db.query(Notification).filter(Notification.event_id == event.id).count() == 1


def test_benign_observation_stores_nothing(client):
    with _session() as db:
        before = db.query(AttackEvent).count()
        assert ingest(db, {
            "source_ip": "203.0.113.44",
            "destination_ip": "10.0.0.20",
            "destination_port": 443,
            "path": "/api/v1/products?page=3",
            "user_agent": "Mozilla/5.0",
            "status_code": 200,
        }) is None
        assert db.query(AttackEvent).count() == before


def test_flood_correlates_into_one_event(client):
    """A 200-packet flood must be one timeline row, not two hundred."""
    reset_correlation()
    engine.reset()

    rng = random.Random(5)
    target = {"ip": "10.0.0.21", "port": 8443, "protocol": "HTTPS", "hostname": "api-gateway-01"}
    observations = SCENARIOS["ddos"].build(rng, "223.104.40.10", target)
    assert len(observations) > 150

    with _session() as db:
        events = ingest_many(db, observations)

    assert events, "the flood should be detected"
    assert len(events) <= 3, f"expected correlation, got {len(events)} separate events"
    assert events[0].packet_count > observations[0]["packet_count"], "absorbed packets must accumulate"


def test_correlation_window_expires(client, monkeypatch):
    reset_correlation()
    engine.reset()

    observation = {
        "source_ip": "5.160.44.200",
        "destination_ip": "10.0.0.20",
        "destination_port": 443,
        "path": "/x?id=1' OR '1'='1' -- ",
        "payload": "1' OR '1'='1' -- ",
    }

    with _session() as db:
        first = ingest(db, dict(observation))
        assert first is not None

        # Same alert again inside the window: absorbed, no new row.
        assert ingest(db, dict(observation)) is None

        # Past the window: a genuinely new event.
        real_clock = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: real_clock() + 120.0)
        second = ingest(db, dict(observation))

    assert second is not None and second.id != first.id


def test_websocket_receives_live_attack_events(client, analyst_headers, viewer_token):
    """The full spec workflow: simulator -> engine -> DB -> WebSocket -> client."""
    with client.websocket_connect(f"/ws?token={viewer_token}") as ws:
        assert ws.receive_json()["type"] == "connected"

        started = client.post(
            "/api/simulation/start",
            json={"events_per_minute": 600, "repeat": True, "randomize_ips": True},
            headers=analyst_headers,
        )
        assert started.status_code == 200
        assert started.json()["status"] == "running"

        seen = set()
        event_payload = None
        for _ in range(40):
            message = ws.receive_json()
            seen.add(message["type"])
            if message["type"] == "attack_event" and event_payload is None:
                event_payload = message["data"]
            if event_payload and "notification" in seen:
                break

        client.post("/api/simulation/stop", headers=analyst_headers)

    assert "attack_event" in seen, f"no live events broadcast; saw {seen}"
    assert event_payload["uid"]
    assert event_payload["attack_type"]
    assert event_payload["source_lat"] is not None, "the live map needs coordinates"
    assert event_payload["severity"] in ("critical", "high", "medium", "low", "info")


def test_websocket_rejects_missing_and_bad_tokens(client):
    import pytest
    from starlette.websockets import WebSocketDisconnect

    for url in ("/ws", "/ws?token=not-a-real-token"):
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect(url) as ws:
                ws.receive_json()
        assert excinfo.value.code == 4401


def test_simulator_state_and_run_history(client, analyst_headers):
    state = client.get("/api/simulation/state", headers=analyst_headers).json()
    assert state["status"] == "stopped"

    runs = client.get("/api/simulation/runs", headers=analyst_headers).json()
    assert runs, "stopping the simulator should have closed out a run record"
    assert runs[0]["stopped_at"] is not None
    assert runs[0]["started_by"] == "analyst@cybershield.io"


def test_simulation_config_rejects_unknown_scenarios(client, analyst_headers):
    response = client.post(
        "/api/simulation/start",
        json={"scenarios": ["definitely_not_a_scenario"]},
        headers=analyst_headers,
    )
    assert response.status_code == 422
    assert "definitely_not_a_scenario" in response.text


def test_simulation_config_rejects_unknown_countries(client, analyst_headers):
    response = client.post(
        "/api/simulation/start",
        json={"source_countries": ["ZZ"]},
        headers=analyst_headers,
    )
    assert response.status_code == 422
