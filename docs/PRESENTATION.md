# How to Present This Project

For a viva, demo, interview or review. Includes a demo script, the reasoning behind each design
decision, and answers to the questions you are most likely to be asked.

---

## 1. The pitch

**30 seconds**

> CyberShield AI is a Security Operations Centre dashboard. It detects cyber attacks in real time,
> explains each one in plain language, and shows them on a live world map. A rule engine with 15
> detection rules analyses incoming traffic records, scores each threat, maps it to the MITRE ATT&CK
> framework, and pushes it to the dashboard over a WebSocket — so the screen updates the instant an
> attack is detected. A built-in simulator generates realistic attack traffic safely, so the whole
> system can be demonstrated without touching a real network.

**2 minutes** — add:

> There are three parts. The **detection engine** takes a normalised traffic record and runs every
> enabled rule against it — some are regex signatures like SQL injection, others are stateful and
> count events over a sliding time window, like a port scan crossing 15 distinct ports in 60 seconds.
> When several rules fire on the same record, the highest-scoring one owns the event and the rest
> attach as correlated signals.
>
> The **pipeline** takes that detection, geolocates the IPs, links it to the targeted asset, updates
> the attacker's reputation record, generates an explanation, raises a notification, saves it, and
> broadcasts it.
>
> The **frontend** is React with TypeScript. Fetched data is handled by React Query; live data comes
> off the WebSocket. Role-based access control gives Admin, Analyst and Viewer different permissions,
> enforced on the server — not just by hiding buttons.

---

## 2. Five-minute live demo script

Set up first: both terminals running, browser at `http://localhost:5173`, signed **out**.

**① Login and RBAC (30 s)**

> "Three roles — Admin, Analyst, Viewer. I'll use the Analyst account."

Click the **analyst** card → **Sign in**.

> "Access control is enforced on the server. Hiding a button isn't security — a Viewer who crafts the
> request directly still gets a 403."

**② Dashboard (60 s)**

> "This is the operations overview. 250 events seeded across the last 24 hours."

Point at: total attacks, active, critical, threat score → severity donut → map → live feed.

> "Every widget here updates in real time. Let me prove it."

**③ Start the simulator — the money shot (90 s)**

Go to **Attack Simulator**.

> "This generates synthetic attack traffic. It builds log records in memory — there's no target
> field, it never opens a socket. There's a test that makes `socket.connect` throw an exception while
> every scenario runs, so it fails if anyone ever adds real networking."

Set frequency **Busy**, press **Start**, go straight back to **Dashboard**.

> "Watch the numbers."

Let it run ~20 seconds. Counters climb, arcs animate, feed fills, notification badge rises.

> "Nothing here is polling. One WebSocket pushes each detection as it happens."

**④ Drill into one attack (90 s)**

Click a **critical** event in the live feed.

> "This is what an analyst actually needs."

Walk through:
- **Detection indicators** — *"this is the literal evidence. Not 'trust me' — this is what matched."*
- **AI assistant** — why detected, impact, MITRE mapping, mitigation, prevention.
- **MITRE ATT&CK** — *"T1190, Exploit Public-Facing Application — the industry-standard taxonomy, so
  this correlates with any other security tool."*
- **Raw log** — *"and the original record, so the analyst can verify everything above."*

**⑤ Prove the engine is real (60 s)**

This is the part that separates a working system from a mock-up.

Sign out → sign in as **admin** → **Detection Rules** → toggle **SQL Injection** off.

> "I've just disabled the SQL injection rule on the live engine — no restart."

Simulator → deselect all → select only **SQL Injection** → **Start** → open **Timeline**.

> "No SQL injection detections. The dashboard isn't playing back a recording — it's genuinely running
> these rules."

Re-enable the rule → detections reappear.

**⑥ Close (30 s)**

Stop the simulator.

> "65 automated tests cover the detection logic, the API, the role boundaries and this exact live
> workflow — simulator through to WebSocket."

---

## 3. Explaining the architecture

Draw this. It is the whole system:

```
Simulator → Detection Engine → Pipeline → Database → WebSocket → Dashboard
```

Then explain each arrow:

1. **Simulator → Engine.** The simulator produces *observations* — plain dictionaries with fields
   like source IP, destination port, request path, packet count. That is the engine's only input
   contract.
2. **Engine.** Every enabled rule scores the observation. Highest score wins; others attach as
   correlated signals.
3. **Pipeline.** Correlates repeat alerts, geolocates, links the asset, updates attacker reputation,
   applies the auto-block policy, generates the explanation, raises a notification.
4. **Database.** SQLAlchemy models; the event table denormalises country and MITRE fields so the
   dashboard queries stay join-free.
5. **WebSocket.** Broadcasts to every connected client.
6. **Dashboard.** React Query owns fetched data, the socket owns live data.

**The line that impresses:**

> "The simulator is just *one* producer of observations. A real packet-capture reader or a log tailer
> would be another producer feeding the same interface — nothing downstream changes. That's why the
> simulator being synthetic isn't a limitation of the design."

---

## 4. Design decisions worth explaining

Evaluators probe *why*, not *what*. Have these ready.

**Why is a flood one event instead of 200?**

> A 200-packet ICMP flood is one security incident. The pipeline keeps a short correlation window —
> repeat detections get absorbed into the open event, accumulating packet counts, instead of
> inserting 200 rows. Otherwise the timeline is unusable during exactly the attack you care about.

**Why does DDoS correlate differently from other rules?**

> This was an actual bug I found. Correlation originally keyed on the attacker's IP, which is right
> for most attacks — one attacker, one alert. But a distributed denial of service rotates its source
> by design, so every packet looked like a new attacker and opened a new alert. Now each rule
> declares what it aggregates on: DDoS groups by *victim*, everything else by attacker. There's a
> test that pins it — 268 flood packets must produce at most 3 events.

**Why not Redis, Celery, microservices?**

> The detection windows, correlation cache and WebSocket client set are all in-process, which is
> correct for a single worker — and the Dockerfile pins one worker deliberately. Adding Redis before
> there's a second worker would be complexity with no benefit. The state lives behind a small
> interface, so swapping it is contained. I documented exactly when it becomes necessary.

*This answer is strong because it shows judgement, not ignorance. Say when you'd change it.*

**Why SQLite?**

> Zero setup, so anyone can run this in two commands. It's one environment variable to switch to
> PostgreSQL, and the Docker Compose setup already does.

**Why no live packet capture with Scapy?**

> Packet capture needs root and a real network interface, which a demo can't assume. The engine
> consumes normalised observations, so adding a capture source is a new producer, not a rewrite. I
> chose to build the analysis layer properly rather than a fragile capture layer.

**Why isn't there CSRF protection?**

> Because there's no CSRF surface. The API takes its credential from the `Authorization` header,
> never a cookie, and a cross-origin form post cannot set that header. Adding CSRF tokens would be
> ceremony against an attack this design already excludes. If the token ever moved into a cookie,
> CSRF protection would have to be added in the same change — that's noted in the security doc.

*This is a great answer. It shows you understand the threat model rather than following a checklist.*

---

## 5. Likely viva questions

**"Is this detecting real attacks?"**

> No, and I want to be precise about that. The traffic is synthetic — generated by the simulator. The
> *detection logic* is real: the same regex signatures and threshold rules a basic IDS uses. What's
> simulated is the input, not the analysis.

**"How is this different from Snort or Suricata?"**

> Those are production IDS engines that read live packets off a NIC with thousands of community
> rules. Mine is a teaching implementation of the same idea — 15 rules, synthetic input, but with the
> analyst-facing layer built out: scoring, correlation, MITRE mapping, explanations and the SOC
> dashboard. Different scope, not a competitor.

**"How does a rule actually work?"**

> Two kinds. **Stateless** rules run regex over the request text — SQL injection looks for tautologies
> like `' OR '1'='1`, UNION SELECT, stacked statements, time-based blind probes. **Stateful** rules
> count over a sliding window — a port scan fires when one source touches 15 distinct ports in 60
> seconds. Each returns the indicators it matched plus a magnitude — how far past the threshold it
> is — which pushes the score up, so a 400-port sweep outranks a 16-port one.

**"What if two rules match the same request?"**

> Highest score owns the event; the rest attach as correlated signals and add 4 points each. A
> request containing both `../../etc/passwd` and `;cat /etc/shadow` is directory traversal *and*
> command injection — the analyst sees one event naming both, rather than two half-events.

**"How is the threat score calculated?"**

> `base_score + (100 − base_score) × 0.7 × magnitude`, plus 4 per corroborating rule. At 92+ the
> severity escalates one level. So the score always starts from the rule's inherent danger and moves
> toward 100 based on observed intensity.

**"What is MITRE ATT&CK?"**

> A globally used knowledge base of adversary tactics and techniques. Every event maps to a technique
> ID like T1190. It matters because it's a shared vocabulary — security tools from different vendors
> can correlate findings through it.

**"Is the AI actually AI?"**

> Be honest here: By default it's a template-based expert system — it composes an explanation from
> rule metadata and the matched indicators. It's deterministic, instant and works offline. The code
> also supports a real Claude API call if you set an API key, and falls back to templates cleanly if
> the key is missing or the call fails. I built the fallback first so the system is never dependent
> on an external service being up.

*Never claim it's a trained ML model. If asked "where's the machine learning?" — "There isn't any, and
that's deliberate: a rule engine is explainable and an analyst can audit exactly why something fired.
ML anomaly detection would be the natural next phase."*

**"How do you secure your own application?"**

> Passwords are bcrypt-hashed with per-password salts. Auth is JWT with role-based access enforced by
> a dependency on each route. All queries use SQLAlchemy bound parameters, so no string-built SQL.
> React escapes output by default and there's no `dangerouslySetInnerHTML` anywhere. Rate limiting,
> security headers, a CORS allowlist, and an audit log for every state change. There's a test that
> puts `' OR 1=1 --` through the search box and requires it to match zero rows.

**"How would you scale this?"**

> The single limitation is in-process state — detection windows, correlation cache, client set, rate
> limit counters. All four move to Redis, then you can run multiple workers behind a load balancer
> with the WebSocket fanned out via pub/sub. The database moves to PostgreSQL, which is already
> supported. I documented this rather than pre-building it.

**"What was the hardest part?"**

> Alert correlation. Getting a detection to fire is easy; deciding when two detections are the *same
> incident* is the real problem. My first version keyed on the attacker IP and completely failed on
> distributed floods — 268 packets became 268 alerts. The fix was making each rule declare what it
> aggregates on.

**"What would you add next?"**

> Live packet capture as a second observation producer, ML-based anomaly detection alongside the
> rules, and per-user notification state. Redis when there's a second worker.

**"Why should we believe it works?"**

> 65 automated tests. Not just unit tests — one test starts the simulator, opens a real WebSocket
> connection and asserts that live attack events arrive with map coordinates. Another makes
> `socket.connect` throw to prove the simulator never touches the network.

---

## 6. If something breaks mid-demo

Stay calm and narrate it — recovering well looks better than a flawless demo.

| Problem | Say this, then do this |
|---|---|
| Charts empty | *"Seed data is spread over 24 hours; this chart shows 60 minutes. Let me start the simulator."* |
| Feed frozen | *"WebSocket dropped — it reconnects with backoff."* Refresh. |
| Login fails | Click the account card instead of typing (autofill overwrites the password). |
| Backend crashed | *"Let me restart the API."* `Ctrl+C`, re-run uvicorn. Data persists. |
| Nothing works | Fall back to `docs/` and the test suite: `pytest tests -q` proves the logic independently of the UI. |

**Have insurance:** take screenshots of the dashboard, map and event detail beforehand, and keep them
in a folder. If the laptop misbehaves, you still have something to show.

---

## 7. Honesty guardrails

Do not claim these — you will be caught, and the project is strong enough without them:

- ❌ "It captures live network packets" — it doesn't, by design.
- ❌ "It uses machine learning" — it's a rule engine, and that's a defensible choice.
- ❌ "It's production-ready" — it's a lab tool with documented limits.
- ❌ "It detects real attacks on this machine" — the input is synthetic.

Say instead:

- ✅ "The detection logic is real; the input is synthetic and safe."
- ✅ "It's a rule engine, chosen because it's explainable and auditable."
- ✅ "Here are the limits and here's exactly when I'd change each one."

Knowing your system's boundaries is what separates an engineer from someone who assembled a demo.

---

## 8. One-page cheat sheet

| Question | One-line answer |
|---|---|
| What is it? | A real-time SOC dashboard that detects, explains and visualises cyber attacks |
| Stack | FastAPI + SQLAlchemy + WebSockets; React + TypeScript + Tailwind + Leaflet + Recharts |
| Rules | 15 — regex signature rules and stateful sliding-window rules |
| Simulator | 12 scenarios, fully synthetic, never opens a socket |
| Real-time | One WebSocket pushes events; no polling |
| Security | JWT, bcrypt, RBAC, audit log, rate limiting, bound SQL parameters, security headers |
| Tests | 65, including the full live workflow |
| Scaling limit | In-process state → Redis when a second worker is needed |
| Biggest bug fixed | DDoS correlation keyed on source instead of victim |
