"""The detection engine: one normalised observation in, at most one finding out.

Several rules can fire on the same observation (a request can be both traversal
and command injection). The highest-scoring rule owns the resulting event; the
rest are attached as correlated signals so the analyst still sees them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Severity
from .rules import RULES, RULES_BY_KEY, MatchResult, Observation, RuleSpec
from .state import new_state

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class Detection:
    rule: RuleSpec
    severity: Severity
    confidence: float
    threat_score: float
    indicators: list[str]
    context: dict = field(default_factory=dict)
    correlated_rules: list[str] = field(default_factory=list)

    @property
    def attack_type(self) -> str:
        return self.rule.attack_type


def _escalate(severity: Severity, steps: int) -> Severity:
    index = min(len(_SEVERITY_ORDER) - 1, _SEVERITY_ORDER.index(severity) + steps)
    return _SEVERITY_ORDER[index]


def score_for(rule: RuleSpec, result: MatchResult) -> float:
    """Base score, pushed toward 100 by how far past threshold the signal is."""
    headroom = 100.0 - rule.base_score
    return round(min(100.0, rule.base_score + headroom * 0.7 * result.magnitude), 1)


class DetectionEngine:
    def __init__(self, rules: list[RuleSpec] | None = None) -> None:
        self.rules = rules if rules is not None else RULES
        self.state = new_state()
        self.disabled: set[str] = set()
        self.hits: dict[str, int] = {}

    def set_enabled(self, key: str, enabled: bool) -> None:
        if key not in RULES_BY_KEY:
            raise KeyError(key)
        self.disabled.discard(key) if enabled else self.disabled.add(key)

    def analyze(self, obs: Observation) -> Detection | None:
        findings: list[tuple[float, RuleSpec, MatchResult]] = []
        for rule in self.rules:
            if rule.key in self.disabled:
                continue
            result = rule.match(obs, self.state)
            if result is None:
                continue
            findings.append((score_for(rule, result), rule, result))

        if not findings:
            return None

        findings.sort(key=lambda f: f[0], reverse=True)
        score, rule, result = findings[0]
        self.hits[rule.key] = self.hits.get(rule.key, 0) + 1

        correlated = [r.key for _, r, _ in findings[1:]]
        # Corroboration from independent rules raises both severity and score.
        if correlated:
            score = round(min(100.0, score + 4.0 * len(correlated)), 1)
        severity = rule.severity
        if score >= 92:
            severity = _escalate(severity, 1)

        confidence = round(min(0.99, rule.confidence + 0.02 * len(result.indicators[1:]) + 0.03 * len(correlated)), 2)

        indicators = list(result.indicators)
        indicators += [f"Also matched: {RULES_BY_KEY[k].name}" for k in correlated]

        return Detection(
            rule=rule,
            severity=severity,
            confidence=confidence,
            threat_score=score,
            indicators=indicators,
            context=result.context,
            correlated_rules=correlated,
        )

    def reset(self) -> None:
        self.state.reset()
        self.hits.clear()


#: Process-wide engine. Rule state is intentionally shared so windowed rules
#: (port scan, brute force, DDoS) can correlate across requests.
engine = DetectionEngine()


if __name__ == "__main__":
    e = DetectionEngine()

    sqli = e.analyze({
        "source_ip": "185.220.101.5",
        "destination_ip": "10.0.0.20",
        "destination_port": 443,
        "path": "/api/products?id=1' OR '1'='1",
        "protocol": "HTTPS",
    })
    assert sqli and sqli.rule.key == "sql_injection", sqli
    assert sqli.severity is Severity.CRITICAL

    assert e.analyze({"source_ip": "1.1.1.1", "path": "/health", "destination_port": 80}) is None

    for port in range(1, 40):
        scan = e.analyze({"source_ip": "45.9.148.2", "destination_ip": "10.0.0.20", "destination_port": port})
    assert scan and scan.rule.key == "port_scan", scan
    assert scan.threat_score > 45

    for _ in range(6):
        ssh = e.analyze({
            "source_ip": "5.160.44.9", "destination_ip": "10.0.0.30",
            "destination_port": 22, "auth_failure": True, "username": "root",
        })
    assert ssh and ssh.rule.key == "ssh_brute_force", ssh

    combo = e.analyze({
        "source_ip": "91.209.12.3", "destination_ip": "10.0.0.20", "destination_port": 80,
        "path": "/download?file=../../etc/passwd;cat /etc/shadow",
    })
    assert combo and combo.correlated_rules, "traversal + command injection should correlate"
    print("detection engine ok")
