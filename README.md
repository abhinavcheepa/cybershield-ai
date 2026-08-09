# CyberShield AI

Live cyber-attack detection, analysis and visualisation — a working SOC console in the shape of
Splunk / Sentinel / Elastic SIEM.

> **Educational and defensive use only.** The built-in attack simulator constructs synthetic log
> records *inside the backend process*. It has no target parameter and opens no sockets — a test
> asserts this by making `socket.connect` raise. Point the detection engine at real telemetry only on
> systems you are authorised to monitor.

---

## Quick start

Two terminals, no Docker, no database to install.

```bash
cd backend && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt && .venv/Scripts/python -m uvicorn app.main:app --port 8010
```

```bash
cd frontend && npm install && npm run dev
```

Open **http://localhost:5173**. The database is created and seeded on first start
(3 users, 10 assets, 15 rules, 250 backdated attack events).

### Ports

CyberShield deliberately avoids the ports used by the `voice flow ai` project on the same machine,
so both stacks can run side by side.

| Port | Used by | |
|---|---|---|
| **5173** | CyberShield frontend (dev) | ✅ CyberShield |
| **8010** | CyberShield API | ✅ CyberShield |
| **8089** | CyberShield frontend (Docker) | ✅ CyberShield |
| 8000 | voice flow ai — API | ⛔ do not use |
| 8001 | voice flow ai — voice engine | ⛔ do not use |
| 8080 | voice flow ai — frontend | ⛔ do not use |
| 7880 | voice flow ai — LiveKit | ⛔ do not use |

If you change the API port, change `frontend/vite.config.ts` to match — that proxy target is the
only place the frontend refers to it.

| Account | Role | Can do |
|---|---|---|
| `admin@cybershield.io` | admin | Everything, plus tune rules and read the audit log |
| `analyst@cybershield.io` | analyst | Triage events, run the simulator, request AI analysis |
| `viewer@cybershield.io` | viewer | Read-only |

Password for all three: `CyberShield#2026`

### Docker

```bash
docker compose up --build
```

Frontend on **http://localhost:8089**, API on **http://localhost:8010**. PostgreSQL, Redis and four
uvicorn workers, all internal to the compose network. Set `JWT_SECRET` and `POSTGRES_PASSWORD` in a
`.env` beside `docker-compose.yml` before exposing this anywhere.

### Deploy it

Hosting this on a server instead of a laptop takes one Dockerfile and two managed add-ons —
[docs/DEPLOY.md](docs/DEPLOY.md) has the Railway, Render and plain-Docker recipes. One service serves
the API and the built SPA together, so students get a single URL and the WebSocket is same-origin.

To share a laptop-hosted lab over the internet instead, `./share-with-class.ps1` opens a Cloudflare
tunnel to the production build.

---

## See it work

1. Sign in as the analyst.
2. **Attack Simulator** → **Start**.
3. Watch the dashboard: counters climb, arcs animate across the map, the feed fills, charts redraw,
   notifications arrive — all pushed over one WebSocket.
4. Click any event for the full forensic view: indicators, AI explanation, MITRE mapping, remediation,
   raw log.

That whole path — simulator → detection engine → database → WebSocket → dashboard — is covered by
`test_websocket_receives_live_attack_events`.

---

## What's inside

```
backend/app/
├── detection/      15 rules + sliding-window state + correlation engine
├── simulator/      8 scenarios + async runner (start/stop/pause/repeat)
├── ai/             explanation generator (templates, optional Claude)
├── routers/        auth, events, dashboard, rules, simulation, notifications, ai, ws
├── pipeline.py     observation → detection → event → notification → broadcast
├── analytics.py    dashboard aggregation queries
├── geo.py          country catalog + IP geolocation
└── models.py       SQLAlchemy schema
frontend/src/
├── pages/          Dashboard, LiveMap, Timeline, EventDetail, Simulator, Rules, Login
├── components/     Layout, AttackMap, Charts, LiveFeed, ui primitives
└── lib/            api client, auth, WebSocket provider, formatting
```

### Detection rules

Port Scan · SQL Injection · XSS · Brute Force Login · SSH Brute Force · FTP Brute Force · DDoS ·
Directory Traversal · Command Injection · Suspicious File Upload · Malware Upload · DNS Amplification ·
ARP Spoofing · ICMP Flood · Suspicious Network Traffic

Each assigns severity, confidence, threat score, MITRE tactic/technique and a recommended action.
When several rules fire on one record the highest-scoring one owns the event and the rest attach as
correlated signals, so traversal-plus-command-injection surfaces once with both named.

---

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest tests -q
```

65 tests: detection unit tests (including per-scenario round-trips), API contract, RBAC boundaries,
SQL-injection safety of the search box, alert correlation, and the live WebSocket workflow.

Two modules also carry runnable self-checks:

```bash
python -m app.detection.engine
python -m app.geo
```

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ATTACK_TYPES.md](docs/ATTACK_TYPES.md) | **All 15 attack types** — what each does, with simple examples and MITRE mapping |
| [docs/DEPLOY.md](docs/DEPLOY.md) | **Put it on a server** — Railway, Render, Docker; Postgres + Redis; sizing for a class |
| [docs/CLASSROOM.md](docs/CLASSROOM.md) | **Run the live class** — students own a site over the internet and feel it get really attacked |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Running it, every screen explained, troubleshooting |
| [docs/PRESENTATION.md](docs/PRESENTATION.md) | Demo script, design rationale, viva questions and answers |
| [docs/API.md](docs/API.md) | Every endpoint, with request/response examples |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data flow, schema, scaling limits |
| [docs/SECURITY.md](docs/SECURITY.md) | Controls implemented, and what is deliberately out of scope |
| `/api/docs` | Live OpenAPI (Swagger) once the backend is running |

---

## Deliberate simplifications

These are choices, not oversights. Each is a single-file swap when you actually need it.

| Simplified | Why | Upgrade when |
|---|---|---|
| SQLite default | Zero setup for one developer; `DATABASE_URL` switches to PostgreSQL, and Docker and every deploy already do | Never — it is the dev default, not the deployed one |
| In-process state without `REDIS_URL` | One worker needs no coordination, and the fallback keeps `uvicorn app.main:app` free of dependencies | You run more than one worker — set `REDIS_URL` and the same code shares windows, counters, sockets and the simulator |
| No Celery | Nothing here is a background job; the simulator and attack runner are asyncio loops the leader worker owns | You need work to survive a restart |
| Prefix-table GeoIP | The lat/lon table is needed for the map regardless; every IP resolves deterministically | You ingest real internet traffic — swap `geo.lookup()` for MaxMind |
| No live packet capture | Scapy/PyShark need root and real NICs; the engine consumes normalised observations, so a capture source is a new producer, not a rewrite | You have a lab span port to read |
| Template AI explanations | Complete, instant and offline; identical shape to model output | Set `ANTHROPIC_API_KEY` — the endpoint already falls back cleanly |
