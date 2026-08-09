# Architecture

## The one path that matters

```
Simulator scenario                      (app/simulator/scenarios.py)
  └─ builds N synthetic observations — plain dicts, no sockets
       ↓
Detection engine                        (app/detection/engine.py)
  └─ every enabled rule scores the observation
  └─ highest score wins; the rest attach as correlated signals
       ↓
Ingest pipeline                         (app/pipeline.py)
  ├─ alert correlation — absorb into an open alert, or open a new one
  ├─ geolocate source + destination      (app/geo.py)
  ├─ bind to the targeted asset, upsert the threat actor
  ├─ auto-block policy on critical scores
  ├─ generate the AI explanation         (app/ai/explain.py)
  └─ raise a notification for high/critical
       ↓
Database                                (app/models.py)
       ↓
WebSocket broadcast                     (app/ws.py)
       ↓
React dashboard — feed, map, charts, counters, notification centre
```

An **observation** is a normalised dict: `source_ip`, `destination_port`, `path`, `payload`,
`protocol`, `packet_count`, `raw`, and so on. That is the engine's only input contract. The
simulator is one producer of observations; a packet-capture reader or a log tailer would be another,
with no change to anything downstream.

---

## Why alert correlation exists

A 200-packet ICMP flood is *one* security event, not 200 timeline rows. `pipeline.py` keeps a short
window keyed by `(rule, entity, destination)`; a repeat detection inside it is absorbed — packet and
byte counts accumulate onto the open event and the threat score takes the max — instead of inserting
a new row.

The key mirrors how the rule itself aggregates, via `RuleSpec.correlate_by`:

- Most rules aggregate **by source** — one attacker, one alert.
- DDoS aggregates **by destination**, because a distributed flood rotates its source by design.
  Keying that on the source would open a fresh alert per spoofed packet.

`test_flood_correlates_into_one_event` pins this: 268 flood observations must produce at most 3 events.

---

## Detection rules

A rule is metadata plus a `match(observation, state)` callable returning the indicators it found and
a `magnitude` — how far past its threshold the signal is. Magnitude drives the score toward 100, so a
400-port sweep outranks a 16-port one.

Rules are pure apart from shared `WindowState`, which makes them directly unit-testable.

**Stateless** (regex over request text): SQL injection, XSS, directory traversal, command injection,
suspicious upload, malware upload.

**Stateful** (sliding window): port scan, brute force ×3, DDoS, ICMP flood, DNS amplification,
ARP spoofing (a remembered IP→MAC fact rather than a counter).

Scoring, in `engine.py`:

```
score  = base_score + (100 - base_score) × 0.7 × magnitude
score += 4 per corroborating rule
severity escalates one step at score ≥ 92
```

---

## Schema

`AttackEvent` is the hot table and denormalises country, coordinates and MITRE fields so the
timeline and dashboard aggregations stay join-free.

| Table | Holds |
|---|---|
| `attack_events` | Every detection; FKs to asset, rule, threat actor, incident |
| `detection_rules` | Tunable mirror of the code catalog — analysts toggle these |
| `ai_explanations` | 1:1 with an event, cascade-deleted |
| `threat_actors` | Rolling per-source-IP reputation |
| `assets` | The defended estate |
| `notifications` | High/critical alerts for the notification centre |
| `incidents` | Correlated groups of events |
| `attack_simulations` | Simulator run history |
| `audit_logs` | Who changed what |
| `users` | Accounts and roles |

`Country` and `AttackType` are **not** tables. Their rows never change at runtime, so they live as
static catalogs in `geo.py` and `detection/rules.py`. A table would add a join and a migration for
data that ships with the code.

---

## Frontend data flow

Two sources feed the UI and they are deliberately different:

- **React Query** owns fetched state — pagination, filters, aggregates.
- **The WebSocket** owns live state — a rolling 80-event buffer for the feed and map arcs.

A burst of live events would otherwise mean a burst of refetches, so `lib/ws.tsx` coalesces
invalidations to at most one every 2.5 s. The event buffer still updates instantly — the feed and map
never wait on a refetch.

Reconnection uses capped exponential backoff, so restarting the backend doesn't spin the tab.

---

## Scaling out

Each uvicorn worker is its own process with its own memory, so every piece of state two workers could
disagree about goes through Redis. `REDIS_URL` selects which implementation is used; unset, each one
falls back to the in-process object it replaced, and the app needs nothing but Python and a file.

| State | Where | Shared as |
|---|---|---|
| WebSocket clients | `ws.py` | Pub/sub — every send is published, and `relay()` is the only thing that touches a socket |
| Detection sliding windows | `detection/state.py` | One sorted set per `(rule, entity)`, scored by wall clock |
| Alert-correlation cache | `pipeline.py` | One key per open alert; its TTL *is* the correlation window |
| Rate-limit counters | `main.py` → `bus.py` | `INCR` on a per-minute key |
| Simulator + attack runner | `simulator/runner.py`, `target/attack_runner.py` | One leader worker holds a lock and runs the loops; the rest forward commands and read the last broadcast |

`bus.py` is the whole surface: clients, pub/sub, leader election, rate counters. It is also the whole
thing to delete if this ever goes back to one worker.

Two details that are easy to get wrong:

- The Redis windows key on `time.time()`, not `time.monotonic()`. Monotonic clocks are per-process and
  would not line up between workers.
- Nothing local delivers its own broadcast. A publisher receives its message back from the
  subscription like every other worker, so there is exactly one delivery path and no double-sends.

Memory is bounded on both paths: in-process, `WindowState` evicts at 20 000 tracked entities and the
rate limiter prunes at 10 000 client IPs; in Redis, every key carries a TTL, so an abandoned window
clears itself.

**Startup.** Four workers booting at once would race on `CREATE TABLE` and the seed inserts, so
`database.startup_lock()` takes a Postgres advisory lock — one worker does the work, the rest wait and
find it already done. On SQLite there is only ever one worker and the lock is a no-op.

The frontend scales the other way — down. Every screen is a `React.lazy` chunk, so a student opening
`/join` downloads about 110 KB gzipped instead of the 1 MB bundle that held the entire console.
Leaflet and Recharts ship with the map and dashboard chunks, and Leaflet's stylesheet is imported by
`AttackMap.tsx` rather than `index.css` so it travels with them.
