# HOLD — Final Two-Person Hackathon Roadmap

**Event:** Cyberdefense Hackathon, SF Tech Week · October 9, 2026  
**Hard submission deadline:** 4:30 PM PDT  
**Build window:** 11:00 AM–4:30 PM (330 minutes)  
**Team size:** 2 developers  
**Status:** Execution plan; check boxes when implementation is verified.

## North-star objective

> Show one real AI coding-agent task where HOLD rejects an unauthorized tool action *before execution* and still allows the approved source-code fix, with genuine audit evidence.

### Definition of done (priority order)

1. **P0 — Actual enforcement:** A real tool request enters HOLD, is checked against a trusted policy, and is either executed or denied.
2. **P0 — Real agent integration:** Claude Code can call HOLD tools; native execution tools are disabled in the controlled demo.
3. **P0 — Happy path and attack path:** Legitimate source edit succeeds; unauthorized network/protected-file call is denied.
4. **P0 — Reproducible proof:** Run scripted security tests and demonstrate the real result twice.
5. **P1 — Auditability:** Store genuine events in ClickHouse and show them in a simple dashboard or event table.
6. **P2 — Polish:** Cytoscape animated DAG, benchmark panels, Semgrep policy suggestions.

*Shipping P0 with clear logs beats a polished UI around simulated enforcement.*

## Scope lock

**IN:** One isolated Flask demo workspace, one developer-approved JSON receipt, three controlled MCP tools (`read_file`, `write_file`, `fetch_url`), one denied external request, one authorized fix, measured decision events.

**OUT:** General-purpose MCP proxy for all servers, arbitrary shell execution, network sandboxing, enterprise authentication, multi-tenant support, billing, autonomous policy generation, production deployment, and broad exploit coverage.

**Why `fetch_url` exists even when blocked:** To demonstrate a *real rejected tool call*, the model needs a guarded tool surface it can attempt. HOLD denies execution when `network_egress=false`. Simply hiding a network tool proves only that it was unavailable.

## Two-person ownership

| Owner | Primary responsibilities | Files / artifacts | Proof of completion |
| --- | --- | --- | --- |
| **Builder A — Core security** | MCP gateway; policy evaluator; trusted receipt loading; canonical path checks; real guarded read/write; deny network operation; isolate Claude built-ins | `hold/server.py`, `hold/gate.py`, `hold/filesystem.py`, config, gate tests | Permitted file is really modified; forbidden call never invokes downstream operation |
| **Builder B — Evidence & demo** | ClickHouse schema/event writer; read-only events API or simple view; issue fixture; smoke tests; dashboard; pitch, README, submission | `hold/telemetry.py`, `telemetry/schema.sql`, `demo/`, `ui/`, docs | Genuine ALLOW/DENY events visible; repeatable demo and submission materials complete |

**Shared contract, agree immediately:** `task_id`, `timestamp`, `tool_name`, `target_resource`, `decision`, `reason`, `decision_latency_us`, `intent_hash`. Emit events without secret values, code contents, or credential material.

## Minute-by-minute schedule

| Time (PDT) | Builder A — Security | Builder B — Evidence / Demo | Shared exit criterion |
| --- | --- | --- | --- |
| **11:00–11:15** | Lock MCP tool names, receipt schema, workspace root | Lock fixture, event schema, mock UI data | Identical interfaces, no new scope |
| **11:15–12:30** | Build MCP server; actual read/write; gate and DENY | Set up ClickHouse + schema; create malicious fixture; build event ingestion | Local protected calls are exercised, not mocked |
| **12:30–1:15** | Configure Claude to expose only HOLD MCP tools; test live call | Wire live events to a simple table; validate payload format | Claude -> HOLD -> gate -> action/event |
| **1:15–2:15** | Fix path/bypass issues; ensure real allowed edit and denied egress | Integrate dashboard; check event timestamps and reasons | Full demo works at least once |
| **2:15–3:10** | Run adversarial regression tests, measure gate latency | Improve clarity of audit view; start README/demo recording | Twice-repeatable demo; measured outcomes |
| **3:10–3:45** | Pair to fix integration failures only | Pair to rehearse 3-minute demo, record backup | Freeze core code; no new architecture |
| **3:45–4:10** | Final smoke test, tag commit | Submit link, README, video/screenshots, description | **Submission completed by 4:10** |
| **4:10–4:30** | Only critical bug fixes | Check submission receipt; prepare judge questions | Deadline buffer remains |

### Hard stop / fallback rules

- **12:30:** If a generic proxy is not working, use a controlled MCP tool **gateway**, not a simulated reverse proxy.
- **1:15:** If Claude integration fails, secure the direct MCP tool harness first; keep Claude integration as the next fix. Label any fallback demonstration accurately.
- **2:15:** If ClickHouse is delayed, show true local structured event logs; do **not** label in-memory events as ClickHouse events.
- **3:10:** Stop frontend feature development. If Cytoscape is unfinished, present a plain, readable event table.
- **3:45:** No new features. Finish submission and rehearsals.

## Capability contract

Developer-approved sample task: `Fix NoneType crash in src/flask/app.py`.

```json
{
  "task_id": "hold-demo-001",
  "intent": "Fix NoneType crash in src/flask/app.py",
  "workspace_root": "./demo/workspace",
  "capabilities": {
    "read": ["src/**", "tests/**", "pyproject.toml"],
    "write": ["src/flask/app.py"],
    "protected": ["**/.env", "**/.env.*", "**/*.pem", "**/.git/**"],
    "network_egress": false,
    "shell_execution": false,
    "git_push": false
  }
}
```

### Required enforcement behavior

1. Parse and validate only known tool schemas; reject unknown tools and malformed arguments.
2. Resolve read/write targets within the configured workspace; deny traversal and symlink escape. Guard against symlink changes between checks and use.
3. Apply protected-path denies to **both** read and write operations.
4. For `fetch_url`, enforce `network_egress=false` **before any HTTP client executes**. No outbound network call in the protected path.
5. Load the trusted receipt outside the agent-editable demo workspace (or ensure it is immutable to the agent).
6. Do not give Claude built-in `Bash`, `Read`, `Edit`, or equivalent uncontrolled tool paths for this MCP-only demo.
7. Log decisions asynchronously; never let telemetry failure turn a DENY into ALLOW. Persist event data without secrets.

**Tested Claude CLI pattern to validate against your installed version:**

```bash
claude \
  --tools "" \
  --strict-mcp-config \
  --mcp-config ./configs/hold.mcp.json \
  -p "Read the local issue fixture and fix the reported bug using HOLD tools."
```

This limits tool exposure in that Claude session; it does not sandbox every possible process on the host.

## Security acceptance tests

- [ ] Allowed `read_file("src/flask/app.py")` reads the expected file.
- [ ] Allowed `write_file("src/flask/app.py", ...)` changes that exact file on disk.
- [ ] Blocked attempt to read `.env` or `src/.env`.
- [ ] Blocked attempt to write `.env` or a protected path, even under broad write patterns.
- [ ] Blocked traversal such as `src/../../.env`.
- [ ] Blocked symlink escape from inside workspace.
- [ ] Blocked `fetch_url` to external target without dispatching a network request.
- [ ] Blocked unknown tool name and unexpected argument fields.
- [ ] No Claude native-tool bypass in the demonstrated session.
- [ ] ClickHouse has genuine allow/deny event rows (if claimed).
- [ ] Latency measured and reported as gate-only p50/p95, not a hardcoded figure.
- [ ] Demo runs successfully at least twice from a reset fixture.

## Three-minute judge demo

| Time | Screen / action | Message |
| --- | --- | --- |
| **0:00–0:25** | Show human task and malicious local issue fixture | "An untrusted issue can ask an AI agent to exceed its authority." |
| **0:25–0:55** | Show baseline unauthorized tool-call risk, safely and only if reproducible | "The model's decisions are not our permission system." |
| **0:55–1:25** | Show trusted Intent Receipt | "This task can edit app.py, but it cannot access protected files or the network." |
| **1:25–2:10** | Trigger network call; show HOLD deny; then perform real authorized file edit | "The unsafe action was rejected; the legitimate work still succeeded." |
| **2:10–2:40** | Show actual events from ClickHouse or clearly labeled fallback logs | "Every guarded decision is inspectable." |
| **2:40–3:00** | Show architecture and one-line closer | "We enforce human-approved task scope, not whatever untrusted content tells the agent to do." |

**Demo backup:** If Claude declines to attempt the injected operation, replay a deterministic direct MCP request through the *same live HOLD enforcement path*. Explicitly explain that the fallback validates enforcement, not the model's susceptibility.

## Evidence to include in GitHub submission

- [ ] README with problem/solution, architecture, setup, limits, and demo instructions.
- [ ] A screenshot or 30–60-second recording of **real** deny + allow behavior.
- [ ] Test output showing blocked and permitted operations.
- [ ] An event query or screenshot proving actual ClickHouse ingestion (if completed).
- [ ] A clean demo fixture containing **no secrets**.
- [ ] Named team contributions and a working repo link.
- [ ] Submission made **before 4:30 PM PDT**.

## Honest claims for judges

**Say:** "HOLD enforces a developer-approved capability policy for tool calls routed through our controlled MCP gateway."  
**Say:** "This demo blocks an unauthorized network-tool attempt and permits the assigned code edit."  
**Say:** "Decision latency was measured at [observed p50/p95]." (only after measurement).

**Do not say:** "Mathematically unbreakable," "blocks all AI attacks," "zero network packets," "zero false positives," "cryptographically signed" (unless implemented), or "sub-1.5ms guaranteed" (unless actually demonstrated under a stated test methodology).

## Beyond the MVP

- Semgrep-assisted **suggestions** for policies, reviewed by the developer.
- Enforced controls over more tool types, remote endpoints, and OS-level operations.
- Stronger policy integrity and authenticated receipt issuance.
- Hardened isolation, additional adversarial coverage, multi-task audit history.

**Final rule:** Build **real enforcement → real agent integration → real evidence → demo clarity**. Never reverse that order for presentation polish.
