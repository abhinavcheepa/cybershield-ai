"""Detection rule catalog.

A rule is metadata (severity / confidence / score / MITRE / remediation) plus a
`match` callable that inspects one normalised observation and returns the
indicators it found. Rules are pure and side-effect free apart from the shared
sliding-window state, which makes them directly unit-testable.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..models import Severity
from .state import WindowState

Observation = dict[str, Any]


@dataclass(frozen=True)
class RuleSpec:
    key: str
    name: str
    attack_type: str
    severity: Severity
    confidence: float
    base_score: float
    mitre_tactic: str
    mitre_technique: str
    description: str
    recommended_action: str
    match: Callable[[Observation, WindowState], "MatchResult | None"] = field(compare=False, repr=False)
    #: Which endpoint this rule aggregates on. Alert correlation has to group
    #: the same way the rule counts, or a distributed flood — which rotates its
    #: source by design — opens a fresh alert per packet.
    correlate_by: str = "source"


@dataclass
class MatchResult:
    indicators: list[str]
    #: 0.0-1.0 measure of how far past the threshold the signal is. Feeds the
    #: threat score so a 400-port sweep outranks a 16-port one.
    magnitude: float = 0.0
    context: dict[str, Any] = field(default_factory=dict)


def _text(obs: Observation) -> str:
    """Everything an injection payload could hide in, lowercased once."""
    parts = (
        obs.get("path", ""),
        obs.get("payload", ""),
        obs.get("query_string", ""),
        obs.get("body", ""),
        obs.get("user_agent", ""),
        obs.get("referer", ""),
    )
    return " ".join(str(p) for p in parts if p).lower()


def _hits(patterns: list[re.Pattern], haystack: str) -> list[str]:
    return [p.pattern for p in patterns if p.search(haystack)]


def _compile(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# --------------------------------------------------------------------------
# Signature sets
# --------------------------------------------------------------------------
SQLI_PATTERNS = _compile(
    r"(?:'|%27)\s*(?:or|and)\s+(?:'?\w+'?\s*=\s*'?\w+'?|\d+\s*=\s*\d+)",
    r"\bunion\s+(?:all\s+)?select\b",
    r";\s*(?:drop|truncate|alter)\s+table\b",
    r"\binformation_schema\.(?:tables|columns)\b",
    r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+",
    r"\bwaitfor\s+delay\b",
    r"\bxp_cmdshell\b",
    r"\bload_file\s*\(",
    r"\binto\s+outfile\b",
    # Quote-break immediately followed by a comment terminator ("admin'--").
    # Deliberately not `$`-anchored: _text() concatenates several fields, so an
    # end-of-string anchor would only ever match the very last one.
    r"['\")]\s*(?:--|#|/\*)",
)

XSS_PATTERNS = _compile(
    r"<\s*script\b",
    r"javascript\s*:",
    r"\bon(?:error|load|mouseover|focus|click)\s*=",
    r"<\s*(?:img|svg|iframe|body)[^>]*\bon\w+\s*=",
    r"document\s*\.\s*cookie",
    r"\b(?:eval|atob|fromcharcode)\s*\(",
    r"<\s*iframe\b",
    r"%3c\s*script",
)

TRAVERSAL_PATTERNS = _compile(
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e(?:%2f|%5c)",
    r"%252e%252e",
    r"/etc/(?:passwd|shadow|hosts)",
    r"(?:boot\.ini|win\.ini|system32)",
    r"\.\.%c0%af",
)

CMDI_PATTERNS = _compile(
    r"[;|&]{1,2}\s*(?:cat|ls|dir|whoami|id|uname|ps|netstat|ifconfig|ipconfig)\b",
    r"[;|&]{1,2}\s*(?:nc|ncat|curl|wget|bash|sh|zsh|powershell|cmd)\b",
    r"\$\(\s*\w+",
    r"`\s*\w+\s*`",
    r"\|\s*(?:base64|xxd|python|perl|ruby)\b",
    r"&&\s*\w+",
)

SCANNER_UA = _compile(
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"hydra", r"metasploit",
    r"dirbuster", r"gobuster", r"wpscan", r"acunetix", r"nessus", r"zgrab",
)

WEBSHELL_EXTENSIONS = (".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".cfm")
BINARY_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".sh", ".jar", ".msi", ".vbs")
DOUBLE_EXTENSION = re.compile(r"\.(?:jpe?g|png|gif|pdf|txt|docx?)\.(?:php|exe|js|scr|sh|aspx?)$", re.I)

# EICAR anti-malware test file — safe, universally flagged, ships no real payload.
KNOWN_MALICIOUS_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR (SHA-256)
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR (MD5)
    "e1112134b6dcc8bed54e0e34d8ac272795e73d74",  # EICAR (SHA-1)
}
EICAR_SIGNATURE = re.compile(r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR", re.I)

SUSPICIOUS_PORTS = {4444, 31337, 1337, 6667, 5555, 8888, 9001, 12345, 54321}
AUTH_FAIL_CODES = {401, 403, 407}


# --------------------------------------------------------------------------
# Rule implementations
# --------------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 60.0


def _port_scan(obs: Observation, state: WindowState) -> MatchResult | None:
    src, port = obs.get("source_ip"), obs.get("destination_port")
    if not src or not port:
        return None
    state.record("port_scan", src, port)
    ports = state.distinct("port_scan", src, PORT_SCAN_WINDOW)
    if ports < PORT_SCAN_THRESHOLD:
        return None
    return MatchResult(
        indicators=[f"{ports} distinct destination ports probed in {int(PORT_SCAN_WINDOW)}s"],
        magnitude=min(1.0, (ports - PORT_SCAN_THRESHOLD) / 200),
        context={"ports_scanned": ports},
    )


def _sql_injection(obs: Observation, state: WindowState) -> MatchResult | None:
    found = _hits(SQLI_PATTERNS, _text(obs))
    if not found:
        return None
    return MatchResult(
        indicators=[f"SQL signature: {p}" for p in found],
        magnitude=min(1.0, len(found) / 3),
    )


def _xss(obs: Observation, state: WindowState) -> MatchResult | None:
    found = _hits(XSS_PATTERNS, _text(obs))
    if not found:
        return None
    return MatchResult(
        indicators=[f"XSS signature: {p}" for p in found],
        magnitude=min(1.0, len(found) / 3),
    )


def _directory_traversal(obs: Observation, state: WindowState) -> MatchResult | None:
    found = _hits(TRAVERSAL_PATTERNS, _text(obs))
    if not found:
        return None
    return MatchResult(
        indicators=[f"Path traversal signature: {p}" for p in found],
        magnitude=min(1.0, len(found) / 2),
    )


def _command_injection(obs: Observation, state: WindowState) -> MatchResult | None:
    found = _hits(CMDI_PATTERNS, _text(obs))
    if not found:
        return None
    return MatchResult(
        indicators=[f"Command injection signature: {p}" for p in found],
        magnitude=min(1.0, len(found) / 2),
    )


BRUTE_FORCE_THRESHOLD = 8
BRUTE_FORCE_WINDOW = 120.0


def _is_auth_failure(obs: Observation) -> bool:
    return bool(
        obs.get("auth_failure")
        or obs.get("status_code") in AUTH_FAIL_CODES
        or str(obs.get("event", "")).lower() in {"failed_password", "authentication_failure", "login_failed"}
    )


def _brute_force_factory(key: str, ports: set[int] | None, threshold: int, label: str):
    def rule(obs: Observation, state: WindowState) -> MatchResult | None:
        if not _is_auth_failure(obs):
            return None
        port = obs.get("destination_port")
        if ports is not None and port not in ports:
            return None
        if ports is None and port in {21, 22}:
            return None  # handled by the protocol-specific rules
        src = obs.get("source_ip")
        if not src:
            return None
        state.record(key, src, obs.get("username", ""))
        attempts = state.count(key, src, BRUTE_FORCE_WINDOW)
        if attempts < threshold:
            return None
        users = state.distinct(key, src, BRUTE_FORCE_WINDOW)
        return MatchResult(
            indicators=[
                f"{attempts} failed {label} authentications in {int(BRUTE_FORCE_WINDOW)}s",
                f"{users} distinct username(s) attempted",
            ],
            magnitude=min(1.0, (attempts - threshold) / 50),
            context={"failed_attempts": attempts, "usernames_tried": users},
        )

    return rule


DDOS_THRESHOLD = 120
DDOS_WINDOW = 10.0


def _ddos(obs: Observation, state: WindowState) -> MatchResult | None:
    dst = obs.get("destination_ip")
    if not dst:
        return None
    state.record("ddos", dst, obs.get("source_ip", ""))
    requests = state.count("ddos", dst, DDOS_WINDOW)
    packets = int(obs.get("packet_count", 1) or 1)
    volumetric = packets >= 5000
    if requests < DDOS_THRESHOLD and not volumetric:
        return None
    sources = state.distinct("ddos", dst, DDOS_WINDOW)
    indicators = []
    if requests >= DDOS_THRESHOLD:
        indicators.append(f"{requests} requests to {dst} in {int(DDOS_WINDOW)}s from {sources} sources")
    if volumetric:
        indicators.append(f"Volumetric burst: {packets} packets in a single flow")
    return MatchResult(
        indicators=indicators,
        magnitude=min(1.0, max(requests / (DDOS_THRESHOLD * 4), packets / 60000)),
        context={"requests_in_window": requests, "distinct_sources": sources},
    )


def _suspicious_upload(obs: Observation, state: WindowState) -> MatchResult | None:
    filename = str(obs.get("filename", "")).lower()
    if not filename:
        return None
    indicators = []
    if filename.endswith(WEBSHELL_EXTENSIONS):
        indicators.append(f"Server-executable extension uploaded: {filename}")
    if filename.endswith(BINARY_EXTENSIONS):
        indicators.append(f"Binary/script payload uploaded: {filename}")
    if DOUBLE_EXTENSION.search(filename):
        indicators.append(f"Double extension masquerade: {filename}")
    if obs.get("content_type") in {"application/x-php", "application/x-msdownload"}:
        indicators.append(f"Declared content-type {obs['content_type']}")
    if not indicators:
        return None
    return MatchResult(indicators=indicators, magnitude=min(1.0, len(indicators) / 2))


def _malware_upload(obs: Observation, state: WindowState) -> MatchResult | None:
    indicators = []
    digest = str(obs.get("file_hash", "")).lower()
    if digest in KNOWN_MALICIOUS_HASHES:
        indicators.append(f"Hash matches known malware signature ({digest[:16]}…)")
    if EICAR_SIGNATURE.search(str(obs.get("payload", "")) + str(obs.get("body", ""))):
        indicators.append("EICAR anti-malware test signature present in body")
    if obs.get("av_verdict") and str(obs["av_verdict"]).lower() not in {"clean", "undetected"}:
        indicators.append(f"Scanner verdict: {obs['av_verdict']}")
    if not indicators:
        return None
    return MatchResult(indicators=indicators, magnitude=1.0, context={"file_hash": digest})


def _dns_amplification(obs: Observation, state: WindowState) -> MatchResult | None:
    if obs.get("destination_port") != 53 and obs.get("source_port") != 53:
        return None
    qtype = str(obs.get("query_type", "")).upper()
    request_size = max(int(obs.get("request_size", 0) or 0), 1)
    response_size = int(obs.get("response_size", 0) or 0)
    ratio = response_size / request_size
    indicators = []
    if qtype in {"ANY", "TXT", "DNSKEY", "RRSIG"}:
        indicators.append(f"Amplification-friendly query type: {qtype}")
    if ratio >= 10:
        indicators.append(f"Response/request amplification ratio {ratio:.1f}x")
    if obs.get("spoofed_source"):
        indicators.append("Source address appears spoofed (no matching outbound query)")
    if len(indicators) < 2:
        return None
    return MatchResult(
        indicators=indicators,
        magnitude=min(1.0, ratio / 80),
        context={"amplification_ratio": round(ratio, 2)},
    )


def _arp_spoofing(obs: Observation, state: WindowState) -> MatchResult | None:
    if str(obs.get("protocol", "")).upper() != "ARP":
        return None
    ip, mac = obs.get("announced_ip"), obs.get("mac_address")
    if not ip or not mac:
        return None
    previous = state.remember(f"arp:{ip}", mac)
    if previous is None or previous == mac:
        return None
    return MatchResult(
        indicators=[
            f"ARP reply binds {ip} to {mac}, previously {previous}",
            "Unsolicited ARP reply (gratuitous)" if obs.get("gratuitous") else "Conflicting ARP mapping",
        ],
        magnitude=1.0,
        context={"claimed_ip": ip, "new_mac": mac, "previous_mac": previous},
    )


ICMP_FLOOD_THRESHOLD = 200
ICMP_FLOOD_WINDOW = 10.0


def _icmp_flood(obs: Observation, state: WindowState) -> MatchResult | None:
    if str(obs.get("protocol", "")).upper() != "ICMP":
        return None
    src = obs.get("source_ip")
    if not src:
        return None
    packets = int(obs.get("packet_count", 1) or 1)
    state.record("icmp", src, None, weight=packets)
    total = state.count("icmp", src, ICMP_FLOOD_WINDOW)
    if total < ICMP_FLOOD_THRESHOLD:
        return None
    return MatchResult(
        indicators=[
            f"{total} ICMP echo packets in {int(ICMP_FLOOD_WINDOW)}s",
            f"Payload size {obs.get('bytes', 0)} bytes" if obs.get("bytes") else "Uniform payload size",
        ],
        magnitude=min(1.0, total / (ICMP_FLOOD_THRESHOLD * 10)),
        context={"packets_in_window": total},
    )


def _suspicious_traffic(obs: Observation, state: WindowState) -> MatchResult | None:
    indicators = []
    ua = str(obs.get("user_agent", ""))
    for pattern in _hits(SCANNER_UA, ua.lower()):
        indicators.append(f"Known offensive tooling in User-Agent: {pattern}")
    for port in (obs.get("destination_port"), obs.get("source_port")):
        if port in SUSPICIOUS_PORTS:
            indicators.append(f"Traffic on commonly abused port {port}")
    if obs.get("tor_exit_node"):
        indicators.append("Source is a known Tor exit node")
    if int(obs.get("bytes", 0) or 0) > 50_000_000:
        indicators.append(f"Unusual egress volume: {int(obs['bytes']) // 1_000_000} MB")
    if obs.get("beacon_interval_s"):
        indicators.append(f"Regular beaconing every {obs['beacon_interval_s']}s")
    if not indicators:
        return None
    return MatchResult(indicators=indicators, magnitude=min(1.0, len(indicators) / 3))


# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------
RULES: list[RuleSpec] = [
    RuleSpec(
        key="port_scan",
        name="Port Scan Detected",
        attack_type="Port Scan",
        severity=Severity.MEDIUM,
        confidence=0.88,
        base_score=45,
        mitre_tactic="Discovery",
        mitre_technique="T1046 - Network Service Discovery",
        description=(
            "A single source enumerated an unusual number of distinct destination ports in a "
            "short window, consistent with automated reconnaissance ahead of exploitation."
        ),
        recommended_action=(
            "Rate-limit or block the source at the perimeter firewall, confirm which ports "
            "answered, and close any service that should not be internet-reachable."
        ),
        match=_port_scan,
    ),
    RuleSpec(
        key="sql_injection",
        name="SQL Injection Attempt",
        attack_type="SQL Injection",
        severity=Severity.CRITICAL,
        confidence=0.94,
        base_score=88,
        mitre_tactic="Initial Access",
        mitre_technique="T1190 - Exploit Public-Facing Application",
        description=(
            "Request parameters contain SQL grammar used to break out of the intended query — "
            "tautologies, UNION SELECT, stacked statements or time-based blind probes."
        ),
        recommended_action=(
            "Block the source, replace string-concatenated SQL with parameterised queries, and "
            "audit the database for unauthorised reads on the affected tables."
        ),
        match=_sql_injection,
    ),
    RuleSpec(
        key="xss",
        name="Cross-Site Scripting Attempt",
        attack_type="XSS",
        severity=Severity.HIGH,
        confidence=0.9,
        base_score=72,
        mitre_tactic="Initial Access",
        mitre_technique="T1059.007 - Command and Scripting Interpreter: JavaScript",
        description=(
            "User-controlled input contains script tags or event handlers intended to execute "
            "in another user's browser session."
        ),
        recommended_action=(
            "Context-encode all output, enable a strict Content-Security-Policy, and set "
            "HttpOnly + SameSite on session cookies."
        ),
        match=_xss,
    ),
    RuleSpec(
        key="brute_force_login",
        name="Credential Brute Force",
        attack_type="Brute Force Login",
        severity=Severity.HIGH,
        confidence=0.91,
        base_score=70,
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001 - Brute Force: Password Guessing",
        description=(
            "Repeated failed authentications from one source against the web application "
            "within a short window, indicating automated password guessing."
        ),
        recommended_action=(
            "Lock the targeted accounts, enforce MFA, and apply progressive delays or CAPTCHA "
            "after the third failed attempt from an address."
        ),
        match=_brute_force_factory("brute_force_login", None, BRUTE_FORCE_THRESHOLD, "web"),
    ),
    RuleSpec(
        key="ssh_brute_force",
        name="SSH Brute Force",
        attack_type="SSH Brute Force",
        severity=Severity.CRITICAL,
        confidence=0.93,
        base_score=82,
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001 - Brute Force: Password Guessing",
        description=(
            "Repeated SSH authentication failures from a single source against port 22, the "
            "classic precursor to remote shell compromise."
        ),
        recommended_action=(
            "Disable password authentication in favour of keys, restrict port 22 to a VPN "
            "range, and deploy fail2ban with an aggressive ban time."
        ),
        match=_brute_force_factory("ssh_brute_force", {22}, 5, "SSH"),
    ),
    RuleSpec(
        key="ftp_brute_force",
        name="FTP Brute Force",
        attack_type="FTP Brute Force",
        severity=Severity.HIGH,
        confidence=0.89,
        base_score=68,
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001 - Brute Force: Password Guessing",
        description="Repeated FTP login failures from a single source against port 21.",
        recommended_action=(
            "Retire plaintext FTP in favour of SFTP/FTPS, and restrict the service to known "
            "management addresses."
        ),
        match=_brute_force_factory("ftp_brute_force", {21}, 5, "FTP"),
    ),
    RuleSpec(
        key="ddos",
        name="Distributed Denial of Service",
        attack_type="DDoS",
        severity=Severity.CRITICAL,
        confidence=0.87,
        base_score=90,
        mitre_tactic="Impact",
        mitre_technique="T1498 - Network Denial of Service",
        description=(
            "Request or packet volume against a single asset far exceeds its baseline, "
            "consistent with a coordinated denial-of-service attempt."
        ),
        recommended_action=(
            "Engage upstream scrubbing, enable rate limiting and SYN cookies, and scale the "
            "edge horizontally while the flood is active."
        ),
        match=_ddos,
        correlate_by="destination",
    ),
    RuleSpec(
        key="directory_traversal",
        name="Directory Traversal",
        attack_type="Directory Traversal",
        severity=Severity.HIGH,
        confidence=0.92,
        base_score=74,
        mitre_tactic="Discovery",
        mitre_technique="T1083 - File and Directory Discovery",
        description=(
            "Request path contains dot-dot sequences or encoded equivalents attempting to "
            "escape the web root and read arbitrary files."
        ),
        recommended_action=(
            "Canonicalise and validate paths against an allow-list, run the web server as an "
            "unprivileged user, and disable directory indexing."
        ),
        match=_directory_traversal,
    ),
    RuleSpec(
        key="command_injection",
        name="OS Command Injection",
        attack_type="Command Injection",
        severity=Severity.CRITICAL,
        confidence=0.93,
        base_score=91,
        mitre_tactic="Execution",
        mitre_technique="T1059 - Command and Scripting Interpreter",
        description=(
            "Input contains shell metacharacters chained to system binaries, indicating an "
            "attempt to execute operating-system commands through the application."
        ),
        recommended_action=(
            "Never pass user input to a shell; use argument arrays, drop the process to a "
            "restricted account, and isolate the host until it is confirmed clean."
        ),
        match=_command_injection,
    ),
    RuleSpec(
        key="suspicious_file_upload",
        name="Suspicious File Upload",
        attack_type="Suspicious File Upload",
        severity=Severity.HIGH,
        confidence=0.85,
        base_score=70,
        mitre_tactic="Persistence",
        mitre_technique="T1505.003 - Server Software Component: Web Shell",
        description=(
            "An uploaded file carries a server-executable or double extension, the standard "
            "route to planting a web shell."
        ),
        recommended_action=(
            "Quarantine the file, store uploads outside the web root with generated names, "
            "and validate by content type rather than extension."
        ),
        match=_suspicious_upload,
    ),
    RuleSpec(
        key="malware_upload",
        name="Malware Upload",
        attack_type="Malware Upload",
        severity=Severity.CRITICAL,
        confidence=0.97,
        base_score=95,
        mitre_tactic="Execution",
        mitre_technique="T1204.002 - User Execution: Malicious File",
        description=(
            "The uploaded object matches a known malicious hash or carries an anti-malware "
            "test signature."
        ),
        recommended_action=(
            "Delete the artefact, image the host for forensics, rotate any credentials it "
            "could have reached, and hunt for the same hash across the estate."
        ),
        match=_malware_upload,
    ),
    RuleSpec(
        key="dns_amplification",
        name="DNS Amplification",
        attack_type="DNS Amplification",
        severity=Severity.HIGH,
        confidence=0.86,
        base_score=76,
        mitre_tactic="Impact",
        mitre_technique="T1498.002 - Reflection Amplification",
        description=(
            "Small spoofed DNS queries are producing disproportionately large responses, "
            "turning the resolver into a reflector against a third party."
        ),
        recommended_action=(
            "Disable open recursion, enable response rate limiting (RRL), and apply BCP38 "
            "ingress filtering at the network edge."
        ),
        match=_dns_amplification,
    ),
    RuleSpec(
        key="arp_spoofing",
        name="ARP Spoofing / MITM",
        attack_type="ARP Spoofing",
        severity=Severity.CRITICAL,
        confidence=0.9,
        base_score=84,
        mitre_tactic="Credential Access",
        mitre_technique="T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning",
        description=(
            "A layer-2 address mapping changed unexpectedly, indicating an attacker is "
            "poisoning ARP caches to intercept traffic on the local segment."
        ),
        recommended_action=(
            "Enable Dynamic ARP Inspection and DHCP snooping on the switch, pin static ARP "
            "entries for gateways, and locate the offending port."
        ),
        match=_arp_spoofing,
    ),
    RuleSpec(
        key="icmp_flood",
        name="ICMP Flood",
        attack_type="ICMP Flood",
        severity=Severity.MEDIUM,
        confidence=0.88,
        base_score=58,
        mitre_tactic="Impact",
        mitre_technique="T1498.001 - Direct Network Flood",
        description=(
            "ICMP echo volume from one source far exceeds normal diagnostic traffic, "
            "consuming bandwidth and host resources."
        ),
        recommended_action=(
            "Rate-limit ICMP at the edge router and drop echo requests from untrusted "
            "networks unless explicitly required."
        ),
        match=_icmp_flood,
    ),
    RuleSpec(
        key="suspicious_traffic",
        name="Suspicious Network Traffic",
        attack_type="Suspicious Network Traffic",
        severity=Severity.LOW,
        confidence=0.7,
        base_score=35,
        mitre_tactic="Command and Control",
        mitre_technique="T1071 - Application Layer Protocol",
        description=(
            "Traffic carries offensive-tooling fingerprints, uses ports associated with "
            "implants, or shows beaconing regularity that ordinary clients do not."
        ),
        recommended_action=(
            "Capture a full packet sample, correlate with endpoint telemetry, and block the "
            "destination if the pattern persists."
        ),
        match=_suspicious_traffic,
    ),
]

RULES_BY_KEY: dict[str, RuleSpec] = {r.key: r for r in RULES}
ATTACK_TYPES: list[str] = [r.attack_type for r in RULES]
