"""Detection engine unit tests. No database, no HTTP."""

from __future__ import annotations

import pytest

from app.detection.engine import DetectionEngine
from app.detection.rules import RULES, RULES_BY_KEY
from app.detection.state import WindowState
from app.models import Severity
from app.simulator.scenarios import SCENARIOS


@pytest.fixture
def engine() -> DetectionEngine:
    return DetectionEngine()


def test_benign_traffic_produces_no_detection(engine):
    assert engine.analyze({
        "source_ip": "203.0.113.9",
        "destination_ip": "10.0.0.20",
        "destination_port": 443,
        "method": "GET",
        "path": "/api/v1/products?page=2&sort=price",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "status_code": 200,
    }) is None


@pytest.mark.parametrize(
    "payload",
    [
        "1' OR '1'='1' -- ",
        "1 UNION ALL SELECT username,password FROM users -- ",
        "'; DROP TABLE sessions; -- ",
        "1' AND (SELECT SLEEP(5)) -- ",
        # Regression: the trailing-comment pattern used to be `$`-anchored, so
        # it never matched once _text() concatenated the other fields.
        "admin'-- ",
    ],
)
def test_sql_injection_signatures(engine, payload):
    detection = engine.analyze({
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.20",
        "destination_port": 443,
        "path": f"/api/v1/users?id={payload}",
        "payload": payload,
        "user_agent": "Mozilla/5.0",
    })
    assert detection is not None, f"missed SQLi payload: {payload}"
    assert detection.rule.key == "sql_injection"
    assert detection.severity is Severity.CRITICAL


def test_port_scan_needs_to_cross_its_threshold(engine):
    base = {"source_ip": "45.9.148.2", "destination_ip": "10.0.0.20"}

    # Below threshold: reconnaissance is indistinguishable from normal traffic.
    for port in range(1, 10):
        assert engine.analyze({**base, "destination_port": port}) is None

    detection = None
    for port in range(10, 60):
        detection = engine.analyze({**base, "destination_port": port}) or detection

    assert detection is not None and detection.rule.key == "port_scan"
    assert detection.context["ports_scanned"] >= 15


def test_port_scan_is_scoped_per_source(engine):
    """One noisy source must not push an unrelated source over the threshold."""
    for port in range(1, 40):
        engine.analyze({"source_ip": "45.9.148.2", "destination_ip": "10.0.0.20", "destination_port": port})

    assert engine.analyze({
        "source_ip": "198.51.100.7", "destination_ip": "10.0.0.20", "destination_port": 443
    }) is None


def test_ssh_brute_force_beats_generic_brute_force(engine):
    detection = None
    for _ in range(8):
        detection = engine.analyze({
            "source_ip": "5.160.44.9",
            "destination_ip": "10.0.0.10",
            "destination_port": 22,
            "auth_failure": True,
            "username": "root",
        }) or detection

    assert detection is not None
    assert detection.rule.key == "ssh_brute_force", "port 22 must route to the SSH-specific rule"


def test_correlated_rules_raise_score_and_are_reported(engine):
    detection = engine.analyze({
        "source_ip": "91.209.12.3",
        "destination_ip": "10.0.0.20",
        "destination_port": 80,
        "path": "/download?file=../../etc/passwd;cat /etc/shadow",
    })

    assert detection is not None
    assert detection.correlated_rules, "traversal + command injection should correlate"
    assert any("Also matched" in i for i in detection.indicators)
    assert detection.threat_score > RULES_BY_KEY[detection.rule.key].base_score


def test_disabled_rule_stops_firing(engine):
    observation = {
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.20",
        "destination_port": 443,
        "path": "/api?id=1' OR '1'='1' -- ",
    }
    assert engine.analyze(observation) is not None

    engine.set_enabled("sql_injection", False)
    assert engine.analyze(observation) is None

    engine.set_enabled("sql_injection", True)
    assert engine.analyze(observation) is not None


def test_every_rule_carries_complete_triage_metadata():
    for rule in RULES:
        assert rule.mitre_technique.startswith("T"), f"{rule.key} has no MITRE technique"
        assert rule.mitre_tactic, f"{rule.key} has no MITRE tactic"
        assert len(rule.recommended_action) > 40, f"{rule.key} recommendation is too thin"
        assert 0.0 < rule.confidence <= 1.0
        assert 0.0 < rule.base_score <= 100.0


@pytest.mark.parametrize("key", sorted(SCENARIOS))
def test_each_scenario_triggers_its_expected_rule(key):
    import random

    scenario = SCENARIOS[key]
    engine = DetectionEngine()
    target = {"ip": "10.0.0.20", "port": 443, "protocol": "HTTPS", "hostname": "web-prod-01"}
    observations = scenario.build(random.Random(7), "185.220.101.42", target)

    detected = {d.attack_type for obs in observations if (d := engine.analyze(obs))}
    assert scenario.expected_detection in detected, f"{key} -> {detected}"


def test_window_state_expires_entries():
    clock = [0.0]
    state = WindowState(clock=lambda: clock[0])

    for port in range(20):
        state.record("scan", "1.2.3.4", port)
    assert state.count("scan", "1.2.3.4", 60) == 20

    clock[0] = 61.0
    assert state.count("scan", "1.2.3.4", 60) == 0


def test_window_state_sums_weights():
    state = WindowState()
    state.record("icmp", "5.6.7.8", None, weight=250)
    assert state.count("icmp", "5.6.7.8", 10) == 250
