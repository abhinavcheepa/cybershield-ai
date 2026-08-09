# User Guide

How to run CyberShield AI and use every screen in it.

---

## 1. Before you start

| Need | Version | Check with |
|---|---|---|
| Python | 3.12+ | `python --version` |
| Node.js | 20+ | `node --version` |
| Docker (optional) | any recent | `docker --version` |

No database to install — SQLite is used by default and is created automatically.

---

## 2. Starting the application

You need **two terminals**, both left running.

**Terminal 1 — backend**

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python -m uvicorn app.main:app --port 8010
```

Wait for `CyberShield AI ready (development)`. On the very first run it also prints how much demo
data it seeded (3 users, 10 assets, 15 rules, 250 attack events).

**Terminal 2 — frontend**

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**

> **Order matters.** Start the backend first. If the frontend loads while the backend is down, the
> login screen appears but sign-in fails.

### Docker alternative (one command)

```bash
docker compose up --build
```

Then open **http://localhost:8089**. This runs PostgreSQL instead of SQLite.

---

## 3. Signing in

Three accounts are seeded. On the login screen, **click an account card on the right** — it fills the
form for you. Do not type them by hand; browser autofill often overwrites the password field and you
get *Invalid email or password*.

| Account | Role | What it can do |
|---|---|---|
| `admin@cybershield.io` | Admin | Everything + enable/disable detection rules + read audit log |
| `analyst@cybershield.io` | Analyst | Triage events, run the simulator, request AI analysis |
| `viewer@cybershield.io` | Viewer | Read-only |

Password for all three: `CyberShield#2026`

**Use `analyst` for a demo** — it can run the simulator, which is the interesting part.

---

## 4. The screens

### 4.1 Dashboard

The landing page. Everything updates live over a WebSocket — no refresh needed.

**Top row (headline numbers)**

| Tile | Meaning |
|---|---|
| Total attacks (24h) | All detections in the window. The ▲/▼ compares this hour to the previous one |
| Active | Detections nobody has triaged yet |
| Critical | Critical-severity count; sub-line shows how many were auto-blocked |
| Threat score | Overall posture 0–100, weighted by severity and recency |

**Charts and panels**

- **Attack volume** — detections per time bucket over the last 60 minutes.
- **Severity distribution** — donut of critical/high/medium/low/info with counts and percentages.
- **Live attack map** — arcs animate from attacker country to your estate as events arrive.
- **Live activity feed** — newest detections; click any row to open it.
- **Top attack types / attacked assets / attackers / targeted services** — ranked bars. Several are
  clickable and jump to a filtered timeline.
- **Threat score trend**, **Response time**, **Attacks by country** — bottom row.
- Four summary tiles: unique attackers, countries involved, auto-blocked, average response time.

> **Empty charts on first load are normal.** Seed data is spread over 24 hours, but "Attack volume"
> only covers the last 60 minutes. Start the simulator and it fills in within seconds.

### 4.2 Live Attack Map

Full-screen version of the map, plus a country breakdown table (attacks, critical count, share %).
Markers are sized by volume; arcs are coloured by severity. Zoom with the +/− buttons or scroll.

### 4.3 Attack Timeline

Every detection in chronological order, newest first.

**Filters** (top bar):

- **Search** — matches IP, attack type or country. Typing is debounced, so it waits until you pause.
- **Severity**, **Status**, **Attack type** dropdowns.
- **Time window** — 1h / 6h / 24h / 7d.
- **Clear (n)** appears once filters are active.

**Columns**: Time · Attack · Severity · Source · Country · Target · Score · Status.
25 rows per page. A shield icon next to an attack name means it was auto-blocked.

Click any row to open its detail page.

### 4.4 Attack Detail

Everything known about one detection.

- **Header** — name, severity, status, risk score, confidence, and whether it was blocked/simulated.
- **Set status** (analyst+) — Active → Investigating → Mitigated → Resolved → False positive.
- **Connection** — source/destination IP, port, country, protocol, packet count, bytes, response
  time, and which asset was hit.
- **Detection indicators** — the literal evidence the rule matched, e.g. *"249 ICMP echo packets in
  10s"*. This is the honest answer to "why did this fire?"
- **AI security assistant** — why it was detected, potential impact, MITRE mapping, recommended
  mitigation, and prevention steps. **Re-analyse** regenerates it.
- **MITRE ATT&CK** — tactic and technique, with a link to attack.mitre.org.
- **Recommended fix** — remediation from the rule.
- **Raw log** — the exact record the engine received.

### 4.5 Detection Rules

All 15 rules as cards: severity, confidence, base score, hit count, MITRE mapping and recommended
action.

**Admin only:** the toggle enables/disables a rule. It takes effect immediately — no restart. Every
change is written to the audit log.

Try it: disable **SQL Injection**, run a SQL injection simulation, and watch nothing get detected.
Re-enable it and the detections come back. That demonstrates the engine is genuinely rule-driven.

### 4.6 Attack Simulator

Generates synthetic attack traffic. **Analyst or admin only.**

> Nothing leaves your machine. The simulator builds log records in memory and hands them to the
> detection engine. It has no target field and opens no network sockets.

**Controls**

| Control | Effect |
|---|---|
| **Start** | Begins generating with the current configuration |
| **Pause** / **Resume** | Halts generation, keeps the configuration |
| **Stop** | Ends the run and closes the run record |
| **Apply changes** | Appears while running — pushes new settings without stopping |

**Attack frequency** — Trickle (12/min), Steady (60/min), Busy (240/min), Storm (900/min), or a
custom number.

**Toggles**

- *Randomise attacker IPs* — new source address per attack instead of reusing one.
- *Repeat continuously* — keep looping; off means one pass.

**Attack scenarios** — 12 available. Select none to run all of them.

Port Scan · SQL Injection · Cross-Site Scripting · Brute Force Login · DDoS Flood · SSH Login Failure ·
Malware Upload · File Modification · Directory Traversal · ICMP Flood · DNS Amplification · ARP Spoofing

**Source countries** — pick specific origins, or select none for a weighted global mix.

The right-hand panel shows generated events streaming in, plus counters for the current run.

### 4.7 Notification centre

Bell icon in the top bar. Raises a notification for **high and critical** detections only, so it
stays useful. Badge shows the unread count. Click one to jump to the event, or **Mark all read**.

---

## 5. Common tasks

### Run your first simulation

1. Sign in as `analyst`.
2. **Attack Simulator** → leave defaults → **Start**.
3. Go to **Dashboard**. Within seconds: counters climb, arcs animate, the feed fills, the bell badge rises.
4. Click any feed row to see the full analysis.
5. Return to the simulator and press **Stop**.

### Investigate and triage an event

1. **Attack Timeline** → set Severity to `critical`.
2. Click the top row.
3. Read **Detection indicators** (what matched) and the **AI assistant** (what it means).
4. Set status to **Investigating**, then **Mitigated** once handled.
5. The timeline and dashboard counts update immediately.

### Demonstrate a specific attack type

1. **Attack Simulator** → deselect all → pick just **SQL Injection**.
2. Set frequency to **Trickle** so events are readable one at a time.
3. **Start**, then watch the timeline.

### See where attacks come from

**Live Attack Map** → the table below the map ranks every source country by volume and critical count.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| *Invalid email or password* | Browser autofilled over the demo password | Click an account card on the login page instead of typing |
| Login screen loads, sign-in fails | Backend not running | Start the backend; check http://localhost:8010/api/health |
| Charts empty on first load | Seed data is older than the 60-minute chart window | Start the simulator, or switch the timeline to 24h |
| "Attack volume" flat but timeline has rows | Same as above | Normal — not a bug |
| Feed not updating / "Reconnecting…" | WebSocket dropped | It retries automatically with backoff; refresh if it persists |
| Simulator buttons greyed out | Signed in as `viewer` | Sign in as `analyst` or `admin` |
| Rule toggle does nothing | Signed in as `analyst` | Rule tuning is admin-only |
| `429 Rate limit exceeded` | >300 requests/min from one IP | Raise `RATE_LIMIT_PER_MINUTE` in `backend/.env` |
| Port 8010 already in use | Another process took it | Run uvicorn on a free port and change the proxy target in `frontend/vite.config.ts` to match |

### Reset everything

Stop the backend, delete `backend/cybershield.db`, and restart. The database is recreated and
reseeded from scratch.

---

## 7. Stopping

Press `Ctrl+C` in both terminals. With Docker: `docker compose down` (add `-v` to wipe the database
volume too).

---

## 8. Sharing your running app

Build the frontend once (`cd frontend && npm run build`), then forward port **8010**. The backend
serves the API, the WebSocket *and* the built app on that one port, so a single tunnel is all you
need. `./share-with-class.ps1` does exactly this.

Do **not** tunnel the Vite dev server on 5173. It sends every source file separately and unminified —
hundreds of requests down one tunnel — which is why a shared dev-server link can take the better part
of a minute to open on a phone. The build is one small page plus a few cached assets.

For a link you hand out more than once, [deploy it](DEPLOY.md) instead: a stable URL, and your laptop
can be closed.

Two things to know before you share a public link:

1. **Anyone with the link can sign in**, including as `admin`, because the demo credentials are
   printed on the login page. That is fine for a demo — just be aware.
2. **Rate limiting keys on the forwarded client address**, so viewers get their own 300 req/min
   bucket rather than sharing one. Raise `RATE_LIMIT_PER_MINUTE` in `backend/.env` only if a single
   viewer is genuinely hitting the ceiling.
