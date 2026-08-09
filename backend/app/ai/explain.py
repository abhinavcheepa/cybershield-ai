"""AI Security Assistant.

Two tiers, both producing the same `Explanation` shape:

1. `build_explanation()` — deterministic analyst templates composed from the
   rule metadata and the concrete indicators the engine matched. No network,
   no key, runs inline in the ingest path so every event has an explanation
   the moment it lands.
2. `generate_with_claude()` — richer narrative from Claude, used on demand by
   ``POST /api/ai/analyze/{uid}`` when ANTHROPIC_API_KEY is set. Never called
   from the ingest path: an outbound HTTP call has no business sitting between
   a detection and the WebSocket broadcast.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field

from ..config import settings

log = logging.getLogger(__name__)

TEMPLATE_MODEL = "cybershield-analyst-v1"


@dataclass
class Explanation:
    why_detected: str
    potential_impact: str
    mitre_mapping: str
    recommended_mitigation: str
    future_prevention: list[str] = field(default_factory=list)
    confidence: float = 0.0
    generated_by: str = TEMPLATE_MODEL

    def as_dict(self) -> dict:
        return asdict(self)


# Impact and hardening advice per attack type. Keyed by RuleSpec.attack_type.
_PLAYBOOK: dict[str, tuple[str, list[str]]] = {
    "Port Scan": (
        "Reconnaissance itself causes no damage, but it maps which services answer and "
        "which versions they advertise. Everything the scan finds becomes the shortlist "
        "for the next stage, so treat it as the opening move rather than noise.",
        [
            "Close every port that does not need to be internet-reachable and re-scan from outside to confirm",
            "Put administrative services behind a VPN or bastion instead of exposing them directly",
            "Alert on any single source touching more than a handful of ports per minute",
        ],
    ),
    "SQL Injection": (
        "A working injection reads or modifies any data the application's database user can "
        "reach — customer records, credentials, payment data — and on a permissive database "
        "can escalate to writing files or executing commands on the host.",
        [
            "Use parameterised queries or an ORM everywhere; string concatenation into SQL is the root cause",
            "Give the application's database account only the privileges it actually needs — no DDL, no FILE",
            "Put a WAF in front of the app as a second layer, not as the primary fix",
            "Log and alert on database errors returned to users — they are how attackers calibrate",
        ],
    ),
    "XSS": (
        "Script injected into a page runs with the victim's session. That means session theft, "
        "silent actions performed as the victim, credential harvesting through injected forms, "
        "and — on an admin page — a straight path to full application takeover.",
        [
            "Context-encode on output (HTML, attribute, JavaScript, URL each need different encoding)",
            "Deploy a strict Content-Security-Policy that disallows inline script",
            "Set HttpOnly and SameSite on session cookies so stolen script cannot read them",
            "Prefer framework auto-escaping over hand-rolled sanitisation",
        ],
    ),
    "Brute Force Login": (
        "Sustained guessing eventually succeeds against reused or weak passwords. A single "
        "successful guess yields a legitimate session that looks normal in every log afterwards, "
        "which is what makes this attack so costly to detect late.",
        [
            "Enforce MFA on every account — it defeats password guessing outright",
            "Apply progressive delays and CAPTCHA after the third failure from an address",
            "Lock or step-up-challenge accounts after repeated failures, and notify the account owner",
            "Screen new passwords against known-breached password lists",
        ],
    ),
    "SSH Brute Force": (
        "SSH access is shell access. A successful guess gives the attacker code execution on "
        "the host, persistence via authorized_keys, and a pivot point into the rest of the "
        "internal network.",
        [
            "Set PasswordAuthentication no and use key-based authentication only",
            "Restrict port 22 to a VPN or jump host — do not expose it to the internet",
            "Run fail2ban (or equivalent) with an aggressive ban time",
            "Disable direct root login (PermitRootLogin no) and audit authorized_keys regularly",
        ],
    ),
    "FTP Brute Force": (
        "FTP carries credentials in plaintext and usually fronts a file store. A successful "
        "login exposes those files and, where the directory is web-served, allows an attacker "
        "to upload content that later executes.",
        [
            "Retire plaintext FTP in favour of SFTP or FTPS",
            "Restrict the service to known management addresses",
            "Disable anonymous access and ensure the upload directory is not web-served",
        ],
    ),
    "DDoS": (
        "Saturation denies service to legitimate users for as long as it lasts. Beyond the "
        "outage, floods are frequently used as cover — while the response team is occupied, "
        "a quieter intrusion runs against another asset.",
        [
            "Contract upstream scrubbing before you need it; mitigation cannot be arranged mid-attack",
            "Enable SYN cookies and connection rate limiting at the edge",
            "Design for horizontal scale so the edge can absorb bursts",
            "Watch for a second, quieter attack against other assets during the flood",
        ],
    ),
    "Directory Traversal": (
        "Escaping the web root exposes configuration files, credentials, private keys, and "
        "source code. Those secrets typically enable a second, higher-privilege attack rather "
        "than being the end goal themselves.",
        [
            "Canonicalise paths and validate against an allow-list — never against a deny-list",
            "Serve user-supplied files by opaque ID, never by a path the client controls",
            "Run the web server as an unprivileged user with no read access outside its document root",
            "Rotate any credential that lived in a file the traversal could reach",
        ],
    ),
    "Command Injection": (
        "Command injection is remote code execution. The attacker runs commands as the "
        "application's operating-system user, which means data theft, persistence, lateral "
        "movement, and — with a privilege escalation — full host compromise.",
        [
            "Never pass user input to a shell; use argument arrays and avoid shell=True",
            "Validate against a strict allow-list where an external command is unavoidable",
            "Run the application under a dedicated low-privilege account, containerised",
            "Treat any host with a confirmed hit as compromised until proven otherwise",
        ],
    ),
    "Suspicious File Upload": (
        "A server-executable file inside a web-served directory is a web shell. That is "
        "persistent remote code execution which survives password rotations and often outlives "
        "the incident response that missed it.",
        [
            "Store uploads outside the web root under generated filenames",
            "Validate by inspecting content, not by trusting the extension or Content-Type",
            "Ensure the upload directory has no execute permission at the web-server level",
            "Scan uploads with an anti-malware engine before they are retrievable",
        ],
    ),
    "Malware Upload": (
        "Known-malicious code inside the estate. Depending on the family this means data theft, "
        "ransomware staging, or a foothold for an operator. The uploaded artefact is usually the "
        "second stage of an intrusion, not the first.",
        [
            "Quarantine the artefact and image the host before cleaning — you need the forensics",
            "Rotate every credential the host could reach",
            "Hunt for the same hash across the rest of the estate before closing the incident",
            "Scan uploads at the gateway rather than after they land",
        ],
    ),
    "DNS Amplification": (
        "Your resolver becomes the weapon. Small spoofed queries produce large responses aimed "
        "at a third party, consuming your outbound bandwidth and putting your addresses on "
        "abuse blocklists.",
        [
            "Disable open recursion; answer recursive queries only for your own networks",
            "Enable Response Rate Limiting (RRL) on the resolver",
            "Apply BCP38 ingress filtering so spoofed source addresses cannot leave the network",
        ],
    ),
    "ARP Spoofing": (
        "An attacker on the local segment is positioned between hosts and the gateway. All "
        "unencrypted traffic is readable and modifiable, sessions can be hijacked, and TLS can "
        "be stripped where clients accept it.",
        [
            "Enable Dynamic ARP Inspection and DHCP snooping on managed switches",
            "Pin static ARP entries for gateways and other critical hosts",
            "Enforce HSTS and certificate pinning so interception is visible to clients",
            "Locate the offending switch port — the attacker has physical or wireless presence",
        ],
    ),
    "ICMP Flood": (
        "Echo traffic well above diagnostic levels consumes bandwidth and host resources. "
        "Impact is usually degradation rather than a hard outage, but it is often a probe to "
        "measure capacity before a larger flood.",
        [
            "Rate-limit ICMP at the edge router rather than dropping it entirely",
            "Drop echo requests from untrusted networks unless explicitly required",
            "Treat a short flood as reconnaissance for a larger one and check capacity headroom",
        ],
    ),
    "Suspicious Network Traffic": (
        "On its own this is weak signal. Correlated with anything else — a matching source, a "
        "recent alert on the same asset — it frequently marks command-and-control traffic or "
        "the reconnaissance phase of a larger intrusion.",
        [
            "Capture a full packet sample before the pattern stops",
            "Correlate with endpoint telemetry on the destination asset",
            "Block the destination if the pattern persists past a short observation window",
        ],
    ),
}

_GENERIC_IMPACT = (
    "Impact depends on whether the attempt succeeded. Treat the affected asset as suspect "
    "until the logs confirm the request was rejected."
)
_GENERIC_PREVENTION = [
    "Patch the affected service to a supported version",
    "Restrict network reachability to the clients that genuinely need it",
    "Ensure this detection routes to an on-call channel, not just the dashboard",
]

_SEVERITY_FRAMING = {
    "critical": "Treat as an active incident and begin containment now.",
    "high": "Escalate to an analyst within the hour.",
    "medium": "Queue for review during this shift.",
    "low": "Record for correlation; no immediate action required.",
    "info": "Informational only.",
}


def _severity_value(event) -> str:
    severity = getattr(event, "severity", "medium")
    return getattr(severity, "value", severity)


def build_explanation(event) -> Explanation:
    """Compose an analyst-grade explanation from rule metadata + matched indicators."""
    severity = _severity_value(event)
    indicators = list(getattr(event, "indicators", []) or [])
    impact, prevention = _PLAYBOOK.get(
        event.attack_type, (_GENERIC_IMPACT, _GENERIC_PREVENTION)
    )

    evidence = (
        "".join(f"\n  - {i}" for i in indicators)
        if indicators
        else "\n  - Signature match on the inspected request"
    )
    why = (
        f"The {event.attack_type} rule fired on traffic from {event.source_ip} "
        f"({event.source_country_name}) to {event.destination_ip}:{event.destination_port} "
        f"over {event.protocol}. Evidence:{evidence}\n"
        # The risk score is deliberately not restated here. Correlation keeps
        # absorbing later observations into an open alert and raises
        # threat_score afterwards, so a number baked into this text drifts out
        # of step with the score rendered right beside it.
        f"{_SEVERITY_FRAMING.get(severity, '')}"
    )

    mitre = (
        f"{event.mitre_technique} (tactic: {event.mitre_tactic}). "
        f"This maps the observed behaviour to the ATT&CK matrix so it can be correlated "
        f"with other activity from the same actor."
    )

    return Explanation(
        why_detected=why.strip(),
        potential_impact=impact,
        mitre_mapping=mitre,
        recommended_mitigation=event.recommended_action,
        future_prevention=prevention,
        confidence=round(float(event.confidence), 2),
        generated_by=TEMPLATE_MODEL,
    )


# --------------------------------------------------------------------------
# Claude-backed upgrade
# --------------------------------------------------------------------------
_SYSTEM_PROMPT = """You are a senior SOC analyst writing the triage note for a detected \
security event in a defensive monitoring platform. The reader is another analyst.

Be concrete and technical. Reference the specific indicators you are given rather than \
describing the attack class in the abstract. No preamble, no marketing language, no \
hedging about whether this is "potentially" malicious — the detection already fired; your \
job is to explain what it means and what to do about it.

Keep each field tight: 2-4 sentences for the prose fields, 3-5 concrete items for \
future_prevention. Every mitigation must be an action someone can take today."""

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "why_detected": {
            "type": "string",
            "description": "What in this traffic triggered the rule, citing the actual indicators.",
        },
        "potential_impact": {
            "type": "string",
            "description": "What an attacker gains if this succeeded, for this specific asset.",
        },
        "mitre_mapping": {
            "type": "string",
            "description": "The ATT&CK technique and why the observed behaviour maps to it.",
        },
        "recommended_mitigation": {
            "type": "string",
            "description": "Immediate containment and remediation steps, in priority order.",
        },
        "future_prevention": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Durable controls that stop this class of attack recurring.",
        },
        "confidence": {
            "type": "number",
            "description": "0.0-1.0 confidence that this is a genuine attack, not a false positive.",
        },
    },
    "required": [
        "why_detected",
        "potential_impact",
        "mitre_mapping",
        "recommended_mitigation",
        "future_prevention",
        "confidence",
    ],
    "additionalProperties": False,
}


def _event_brief(event) -> str:
    return json.dumps(
        {
            "attack_type": event.attack_type,
            "rule_name": event.name,
            "severity": _severity_value(event),
            "threat_score": event.threat_score,
            "engine_confidence": event.confidence,
            "indicators": list(getattr(event, "indicators", []) or []),
            "source": {
                "ip": event.source_ip,
                "port": event.source_port,
                "country": event.source_country_name,
            },
            "destination": {
                "ip": event.destination_ip,
                "port": event.destination_port,
                "asset": getattr(getattr(event, "asset", None), "name", None),
                "service": getattr(getattr(event, "asset", None), "service", None),
                "criticality": _severity_value(getattr(event, "asset", None) or event),
            },
            "protocol": event.protocol,
            "packet_count": event.packet_count,
            "bytes_transferred": event.bytes_transferred,
            "mitre_technique": event.mitre_technique,
            "mitre_tactic": event.mitre_tactic,
            "raw_log": getattr(event, "raw_log", {}),
        },
        indent=2,
        default=str,
    )


async def generate_with_claude(event) -> Explanation:
    """Upgrade the template explanation using Claude. Falls back on any failure."""
    if not settings.anthropic_api_key:
        return build_explanation(event)

    try:
        from anthropic import AsyncAnthropic
    except ImportError:
        log.warning("anthropic package not installed; using template explanation")
        return build_explanation(event)

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    try:
        response = await client.messages.create(
            model=settings.anthropic_model,
            # Thinking is on by default and shares this budget with the response,
            # so leave headroom well above the size of the JSON itself.
            max_tokens=4000,
            system=_SYSTEM_PROMPT,
            output_config={
                "effort": "low",
                "format": {"type": "json_schema", "schema": _OUTPUT_SCHEMA},
            },
            messages=[
                {
                    "role": "user",
                    "content": f"Write the triage note for this event:\n\n{_event_brief(event)}",
                }
            ],
        )
    except Exception as exc:  # network, auth, rate limit — never fail the request
        log.warning("Claude analysis failed (%s); using template explanation", exc)
        return build_explanation(event)
    finally:
        await client.close()

    # Safety classifiers can decline; content is empty or partial when they do.
    if response.stop_reason == "refusal":
        log.info("Claude declined analysis for %s; using template explanation", event.uid)
        return build_explanation(event)

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        log.warning("Claude returned unparseable output; using template explanation")
        return build_explanation(event)

    return Explanation(
        why_detected=data["why_detected"],
        potential_impact=data["potential_impact"],
        mitre_mapping=data["mitre_mapping"],
        recommended_mitigation=data["recommended_mitigation"],
        future_prevention=list(data["future_prevention"]),
        confidence=round(float(data["confidence"]), 2),
        generated_by=settings.anthropic_model,
    )


if __name__ == "__main__":
    from types import SimpleNamespace

    event = SimpleNamespace(
        uid="test", attack_type="SQL Injection", name="SQL Injection Attempt",
        severity="critical", threat_score=93.0, confidence=0.96,
        indicators=["SQL signature: \\bunion\\s+(?:all\\s+)?select\\b"],
        source_ip="185.220.101.5", source_port=51022, source_country_name="Russia",
        destination_ip="10.0.0.20", destination_port=443, protocol="HTTPS",
        packet_count=1, bytes_transferred=812,
        mitre_technique="T1190 - Exploit Public-Facing Application",
        mitre_tactic="Initial Access",
        recommended_action="Block the source and parameterise the query.",
        raw_log={}, asset=None,
    )

    result = build_explanation(event)
    assert "185.220.101.5" in result.why_detected, "must cite the actual source"
    assert "union" in result.why_detected, "must cite the matched indicator"
    assert "T1190" in result.mitre_mapping
    assert len(result.future_prevention) >= 3
    assert result.generated_by == TEMPLATE_MODEL

    unknown = build_explanation(SimpleNamespace(**{**vars(event), "attack_type": "Novel Attack"}))
    assert unknown.potential_impact == _GENERIC_IMPACT, "unknown types must still explain"
    assert set(_PLAYBOOK) >= {r.attack_type for r in __import__(
        "app.detection.rules", fromlist=["RULES"]).RULES}, "every rule needs a playbook entry"
    print(f"ai explain ok: {len(_PLAYBOOK)} playbook entries")
