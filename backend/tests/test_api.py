"""API contract, authentication and RBAC tests."""

from __future__ import annotations

import pytest

from app.seed import DEMO_PASSWORD


# ------------------------------------------------------------------ auth
def test_health_is_public(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"


def test_login_returns_token_and_user(client):
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@cybershield.io", "password": DEMO_PASSWORD},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "analyst"
    assert "hashed_password" not in body["user"]


@pytest.mark.parametrize(
    "email,password",
    [
        ("analyst@cybershield.io", "wrong-password"),
        ("nobody@cybershield.io", DEMO_PASSWORD),
    ],
)
def test_bad_credentials_are_indistinguishable(client, email, password):
    """Wrong password and unknown user must return the same thing."""
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_protected_routes_reject_anonymous(client):
    for path in ("/api/events", "/api/dashboard/stats", "/api/rules", "/api/notifications"):
        assert client.get(path).status_code == 401, path


def test_garbage_token_is_rejected(client):
    response = client.get("/api/events", headers={"Authorization": "Bearer not.a.jwt"})
    assert response.status_code == 401


# ------------------------------------------------------------------ RBAC
def test_viewer_cannot_run_the_simulator(client, viewer_headers):
    response = client.post("/api/simulation/start", json={}, headers=viewer_headers)
    assert response.status_code == 403
    assert "analyst" in response.json()["detail"]


def test_viewer_cannot_triage_events(client, viewer_headers):
    uid = client.get("/api/timeline?limit=1", headers=viewer_headers).json()[0]["uid"]
    response = client.patch(
        f"/api/events/{uid}/status", json={"status": "resolved"}, headers=viewer_headers
    )
    assert response.status_code == 403


def test_analyst_cannot_tune_rules_or_read_audit(client, analyst_headers):
    assert client.patch("/api/rules/xss", json={"enabled": False}, headers=analyst_headers).status_code == 403
    assert client.get("/api/auth/audit", headers=analyst_headers).status_code == 403


def test_admin_can_tune_rules(client, admin_headers):
    response = client.patch("/api/rules/xss", json={"enabled": False}, headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["enabled"] is False

    # Restore so later tests see the default rule set.
    assert client.patch("/api/rules/xss", json={"enabled": True}, headers=admin_headers).json()["enabled"]


def test_rule_changes_are_audited(client, admin_headers):
    client.patch("/api/rules/icmp_flood", json={"confidence": 0.9}, headers=admin_headers)
    entries = client.get("/api/auth/audit", headers=admin_headers).json()
    assert any(e["action"] == "rule.updated" and "icmp_flood" in e["resource"] for e in entries)


# ---------------------------------------------------------------- events
def test_events_are_paginated(client, viewer_headers):
    body = client.get("/api/events?page=1&page_size=5", headers=viewer_headers).json()
    assert len(body["items"]) <= 5
    assert body["total"] >= len(body["items"])
    assert body["page"] == 1


def test_events_filter_by_severity(client, viewer_headers):
    body = client.get("/api/events?severity=critical&page_size=50", headers=viewer_headers).json()
    assert all(item["severity"] == "critical" for item in body["items"])


def test_event_search_is_injection_safe(client, viewer_headers):
    """A SQL payload in the search box must be treated as a literal string."""
    response = client.get("/api/events?search=' OR 1=1 --", headers=viewer_headers)
    assert response.status_code == 200
    # Bound parameters mean this matches nothing, rather than returning everything.
    assert response.json()["total"] == 0

    # And the table is still there afterwards.
    assert client.get("/api/events", headers=viewer_headers).json()["total"] > 0


def test_event_detail_includes_explanation_and_raw_log(client, viewer_headers):
    uid = client.get("/api/timeline?limit=1", headers=viewer_headers).json()[0]["uid"]
    body = client.get(f"/api/events/{uid}", headers=viewer_headers).json()

    assert body["uid"] == uid
    assert body["raw_log"], "detail view must carry the raw record"
    assert body["mitre_technique"].startswith("T")

    explanation = body["explanation"]
    assert explanation is not None
    assert body["source_ip"] in explanation["why_detected"]
    assert len(explanation["future_prevention"]) >= 3


def test_unknown_event_returns_404(client, viewer_headers):
    assert client.get("/api/events/does-not-exist", headers=viewer_headers).status_code == 404


def test_analyst_can_triage_an_event(client, analyst_headers):
    uid = client.get("/api/timeline?limit=1", headers=analyst_headers).json()[0]["uid"]
    response = client.patch(
        f"/api/events/{uid}/status",
        json={"status": "investigating", "note": "picked up by day shift"},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


# ------------------------------------------------------------- dashboard
def test_dashboard_stats_are_internally_consistent(client, viewer_headers):
    stats = client.get("/api/dashboard/stats?hours=24", headers=viewer_headers).json()

    assert stats["total_attacks"] > 0
    assert stats["critical_attacks"] <= stats["total_attacks"]
    assert stats["active_attacks"] <= stats["total_attacks"]
    assert stats["blocked_attacks"] <= stats["total_attacks"]
    assert 0 <= stats["threat_score"] <= 100
    assert sum(row["count"] for row in stats["by_severity"]) == stats["total_attacks"]
    assert stats["unique_attackers"] > 0
    for widget in ("top_attack_types", "top_targeted_assets", "top_attackers", "top_targeted_services"):
        assert stats[widget], f"{widget} is empty"


def test_timeseries_has_continuous_buckets(client, viewer_headers):
    series = client.get("/api/dashboard/timeseries?minutes=120&buckets=24", headers=viewer_headers).json()
    assert len(series) == 24, "quiet periods must still emit a bucket"
    timestamps = [row["timestamp"] for row in series]
    assert timestamps == sorted(timestamps), "buckets must be oldest-first"


def test_countries_carry_map_coordinates(client, viewer_headers):
    countries = client.get("/api/countries", headers=viewer_headers).json()
    assert countries
    for row in countries:
        assert len(row["country_code"]) == 2
        assert -90 <= row["latitude"] <= 90
        assert -180 <= row["longitude"] <= 180
        assert row["critical_count"] <= row["count"]


def test_threat_actors_are_ranked(client, viewer_headers):
    actors = client.get("/api/threat-intel/actors?limit=10", headers=viewer_headers).json()
    assert actors
    scores = [a["threat_score"] for a in actors]
    assert scores == sorted(scores, reverse=True)


# ------------------------------------------------------------------ rules
def test_rule_catalog_matches_the_engine(client, viewer_headers):
    from app.detection.rules import RULES

    rules = client.get("/api/rules", headers=viewer_headers).json()
    assert {r["key"] for r in rules} == {r.key for r in RULES}


def test_unknown_rule_returns_404(client, admin_headers):
    assert client.patch("/api/rules/nope", json={"enabled": False}, headers=admin_headers).status_code == 404


def test_rule_update_validates_ranges(client, admin_headers):
    response = client.patch("/api/rules/xss", json={"confidence": 5.0}, headers=admin_headers)
    assert response.status_code == 422


# ---------------------------------------------------------- notifications
def test_notifications_and_unread_count(client, viewer_headers):
    notifications = client.get("/api/notifications?limit=5", headers=viewer_headers).json()
    assert notifications
    assert all(n["severity"] in ("critical", "high") for n in notifications)

    before = client.get("/api/notifications/unread-count", headers=viewer_headers).json()["unread"]
    unread = client.get("/api/notifications?unread_only=true&limit=1", headers=viewer_headers).json()
    if unread:
        client.post(f"/api/notifications/{unread[0]['id']}/read", headers=viewer_headers)
        after = client.get("/api/notifications/unread-count", headers=viewer_headers).json()["unread"]
        assert after == before - 1


# --------------------------------------------------------------------- ai
def test_ai_status_reports_the_template_backend(client, viewer_headers):
    body = client.get("/api/ai/status", headers=viewer_headers).json()
    assert body["live_model_available"] is False
    assert "ANTHROPIC_API_KEY" in body["detail"]


def test_analyze_falls_back_cleanly_without_an_api_key(client, analyst_headers):
    """No key configured must still yield a complete explanation, not a 500."""
    uid = client.get("/api/timeline?limit=1", headers=analyst_headers).json()[0]["uid"]
    response = client.post(f"/api/ai/analyze/{uid}", headers=analyst_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["generated_by"] == "cybershield-analyst-v1"
    assert body["recommended_mitigation"]
    assert 0.0 <= body["confidence"] <= 1.0


def test_purging_the_class_is_admin_only(client, analyst_headers):
    """Deleting a whole class is destructive; analyst must not reach it."""
    response = client.request(
        "DELETE", "/api/live/students", params={"prefix": "x"}, headers=analyst_headers
    )
    assert response.status_code == 403


def test_purge_removes_students_by_prefix_and_keeps_the_timeline(client, admin_headers):
    """Clearing dummy accounts must not take the lesson's event history with it.

    A student's asset is referenced by every attack event against them, so the
    purge detaches those events instead of cascading — the roster goes, the
    record of what happened stays.
    """
    for name in ("purgeme1", "purgeme2", "keepme1"):
        created = client.post("/site/register", json={
            "username": name, "password": "throwaway", "display_name": name})
        assert created.status_code == 200, created.text

    events_before = client.get("/api/events?page_size=1", headers=admin_headers).json()["total"]

    result = client.request(
        "DELETE", "/api/live/students", params={"prefix": "purgeme"}, headers=admin_headers
    )
    assert result.status_code == 200, result.text
    assert result.json()["students"] == 2, "only the prefixed students should go"

    targets = client.get("/api/live/catalog", headers=admin_headers).json()["targets"]
    names = {t["username"] for t in targets}
    assert "purgeme1" not in names and "purgeme2" not in names
    assert "keepme1" in names, "a student outside the prefix must survive"

    events_after = client.get("/api/events?page_size=1", headers=admin_headers).json()["total"]
    assert events_after == events_before, "purging the roster must not delete events"

    # Leave the fixture database as we found it.
    client.request("DELETE", "/api/live/students", params={"prefix": "keepme"}, headers=admin_headers)


def test_openapi_documents_every_endpoint(client):
    schema = client.get("/api/openapi.json").json()
    assert schema["info"]["title"] == "CyberShield AI"
    for path in ("/api/events", "/api/dashboard/stats", "/api/simulation/start", "/api/ai/analyze/{uid}"):
        assert path in schema["paths"], f"{path} missing from OpenAPI"
