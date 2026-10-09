# SPEC.md: HOLD MVP technical specification

This is the source of truth. If another document disagrees, this one wins. The implementation
is `hold/` (`core.py` gate + executors + telemetry, `scan.py` Semgrep write scan, `server.py`
MCP server, `env.py` config); `python harness.py` runs every test.

Items marked **IN PROGRESS** are being built or re-verified now; do not present them as done.

---

## 1. Architecture

```text
 Developer ── approves ──> configs/intent_receipt.json (template, in the repo)
                                   │ scripts/make_mcp_config.py renders it
                                   ▼
                         configs/generated/intent_receipt.json  (absolute workspace_root;
                                   │                            loaded once; SHA-256 digest)
                                   ▼
 Claude Code ──MCP stdio──> hold/server.py ──> Gateway.call(tool, raw args)
 (launched by scripts/run_claude_demo.*        │
  inside ~/hold-demo-workspace with            ├─ CapabilityGate.evaluate → ALLOW / DENY
  built-in tools off, only HOLD loaded)        ├─ write_file ALLOW → Semgrep write scan (hold/scan.py)
                                               │                      → DENY on new findings or any scan error
                                               ├─ ALLOW → guarded executor (file I/O, HTTP)
                                               ├─ DENY  → isError result, executor never called
                                               └─ event → audit.jsonl + ClickHouse hold_events
                                                                          │ polled ~1 s
                                                                          ▼
                                                          ui/dashboard.py  /  ClickHouse SQL console
```

**Enforcement boundary.** HOLD controls only the tools it serves. That holds only if
Claude Code's built-in tools are disabled and no other MCP server is loaded. HOLD is not a
sandbox, a firewall or an OS-level control. A DENY proves that HOLD did not dispatch the
operation; it does not prove the host made no other network traffic.

| Component | File | Responsibility |
|---|---|---|
| Receipt | `hold/core.py` `IntentReceipt` | Parse, reject unknown fields, add default protected patterns, compute digest |
| Gate | `hold/core.py` `CapabilityGate` | Pure ALLOW/DENY decision. Never raises; fails closed |
| Write scan | `hold/scan.py` `SemgrepScanner` | Real Semgrep scan of every gate-allowed write (§4.1). Fails closed |
| Gateway | `hold/core.py` `Gateway` | Gate → scan (writes) → execute or deny → emit event |
| Telemetry | `hold/core.py` `Telemetry`, `JsonlWriter`, `ClickHouseWriter` | Local JSONL audit + batched ClickHouse inserts; never affect decisions |
| MCP server | `hold/server.py` | FastMCP over stdio; routes raw tool names and arguments to the Gateway |
| Config | `hold/env.py`, `scripts/make_mcp_config.py` | `.env` loading, demo workspace location, receipt rendering, MCP config |

## 2. Intent Receipt

Template in the repo (`configs/intent_receipt.json`):
```json
{
  "task_id": "hold-demo-001",
  "intent": "Fix NoneType crash in src/flask/app.py",
  "workspace_root": "<HOLD_DEMO_WORKSPACE>",
  "capabilities": {
    "read": ["src/**", "tests/**", "pyproject.toml", "ISSUE.md"],
    "write": ["src/flask/app.py"],
    "protected": [],
    "network_egress": false,
    "host_allowlist": [],
    "shell_execution": false,
    "git_push": false
  }
}
```

- The template **cannot be loaded directly** (`<HOLD_DEMO_WORKSPACE>` is not a directory), so a forgotten render fails closed.
- `scripts/make_mcp_config.py` renders it into `configs/generated/` (gitignored) with `workspace_root` = the absolute demo workspace (`hold.env.demo_workspace()`: `HOLD_DEMO_WORKSPACE`, else `~/hold-demo-workspace`). It refuses a workspace inside the repo, a symlink/junction, a UNC/device path, or a missing workspace.
- **Why outside the repo:** Claude Code loads `CLAUDE.md` from every parent directory. A workspace inside this repo would show the agent under test HOLD's own rules.
- `configs/intent_receipt.allow-host.json` is the positive-control template: identical except `network_egress: true` and one host. `make_mcp_config.py --allow-host HOST` renders it.
- A relative `workspace_root` is resolved against the receipt file's directory.
- Unknown fields → load error. `shell_execution` or `git_push` set to `true` → load error (no such tools exist).
- `protected` **adds** to the defaults; it can never remove them: `**/.env`, `**/.env.*`, `**/*.pem`, `**/*.key`, `**/id_rsa*`, `**/id_ed25519*`, `**/.git/**`, `**/.github/workflows/**`, `**/.aws/**`, `**/.ssh/**`, `**/.npmrc`, `**/.pypirc`, `**/.netrc`, `**/.claude/**`, `**/.mcp.json`.
- `digest` = SHA-256 of the canonical JSON (sorted keys, no whitespace). It is a **digest, not a signature**: it identifies the policy in every event but does not authenticate who wrote it. `make_mcp_config.py` prints its prefix.
- The server refuses to start if the receipt or the audit log lies inside `workspace_root`.
- Globs: `**/` = zero or more directories, `**` = anything, `*` = anything except `/`, `?` = one character except `/`.

## 3. Tools

| Tool | Arguments (exact; extra or missing → DENY) | Sink | Executes |
|---|---|---|---|
| `read_file` | `path: str` | `FS_READ` | Read ≤ 512 KiB, UTF-8 (invalid bytes replaced) |
| `write_file` | `path: str`, `content: str` | `FS_WRITE` | Semgrep write scan first (§4.1); then write ≤ 512 KiB, replacing the file |
| `fetch_url` | `url: str` | `NETWORK_EGRESS` | GET, 5 s timeout, ≤ 256 KiB, no redirects, no env proxies |

The MCP server forwards the **raw** tool name and arguments to the gate (it overrides
FastMCP's `call_tool`), so an unknown tool or an extra argument is DENIED and audited
instead of being dropped or answered by the SDK. Names like `bash_exec` and `git_push` are
mapped to `SHELL_EXEC` and `GIT_MUTATION` for telemetry only.
Denials and execution failures return an MCP tool result with **`isError: true`** and HOLD's
reason text, so the model can continue the task. They are not JSON-RPC protocol errors.

## 4. Gate rules (in order)

**Paths** (`read_file`, `write_file`)
1. Must match `^[A-Za-z0-9_./-]{1,512}$`. Rejects absolute paths with drive letters, `:` (Windows alternate data streams), `~`, `\`, NUL, spaces and Unicode lookalikes.
2. Must not start with `/`. No segment may be empty, `.` or `..`, or end in `.` (Windows maps `.env.` to `.env`).
3. `realpath(workspace_root / path)` must stay inside `workspace_root` (symlink escape).
4. Neither the requested path nor the resolved path may match a protected pattern (case-insensitive). This applies to reads **and** writes.
5. Both the requested and resolved paths must match the `read` or `write` allowlist.
6. Right before I/O, the executor re-resolves the path and refuses if it changed. It opens with `O_NOFOLLOW` where the OS has it.
7. `write_file` is denied when the resolved workspace-relative path differs from the requested one (no writes through symlinks, junctions or case aliases). Reads are unaffected.

**URLs** (`fetch_url`)
1. Scheme must be `http` or `https`; no userinfo; there must be a host.
2. `network_egress` must be `true`.
3. `hostname` (lowercased, trailing dot removed) must be in `host_allowlist`. It is compared exactly: no suffix matching.

**Anything unexpected** (exception, wrong types) → DENY with reason `gate error`.

### 4.1 Write content scan (Semgrep)

Runs only for `write_file`, only after the gate ALLOWs.

1. HOLD reads the current file (≤ 512 KiB; empty if new) and runs real Semgrep
   (`semgrep scan --config rules/hold-write-scan.yml --json --metrics=off --disable-version-check --quiet`,
   no shell, stdin closed, output to files) on copies of the current and proposed content kept under
   `.tmp/semgrep/` (outside the agent workspace). Semgrep's `TEMP`/`TMP` point there too
   (override: `HOLD_SEMGREP_TMP`); see §4.2 for why.
2. **DENY** if the proposed content has a finding (rule id + whitespace-normalized matched source)
   that the current content lacks. Counts matter: a second copy of an existing call is new.
   Pre-existing calls do not block a fix.
3. Rules (Python): new network egress (urllib.request, http.client, requests, httpx, socket,
   aiohttp, urllib3, ftplib, smtplib, xmlrpc, asyncio connections, websockets, pycurl); process
   execution (subprocess, os.system/popen/exec*/spawn*, pty, asyncio subprocesses, ctypes DLL
   loading); dynamic code (eval/exec/compile, runpy, marshal/pickle loads, `__import__`,
   importlib, getattr on builtins/os/subprocess/socket, `globals()[...]`, `sys.modules[...]`,
   decoded-data-into-exec taint).
4. **Fails closed:** Semgrep missing, nonzero exit, timeout (60 s, process tree killed),
   missing/invalid JSON, content not scanned, a Semgrep error entry, a scanner exception or a
   non-boolean verdict → DENY with a `Semgrep unavailable:` / `Semgrep error:` reason, file
   unchanged. Only `HOLD_SEMGREP=0` disables the scan.
5. Non-Python files are written unscanned; the event reason says `not scanned`. "Python" is decided from both the requested and the resolved path. Content over 512 KiB is denied without a scan.
6. Events: DENY → `FS_WRITE`, `not_run`, reason `<reason> (scan N ms)`; ALLOW → reason
   `within receipt; Semgrep: no new findings (scan N ms)`. `gate_latency_ns` stays gate-only.
7. **Measured cost:** each scanned write takes about **4–18 s** on our Windows dev machine,
   depending on load (~4 s idle; 11.5–17.8 s with other jobs running; 11.2 s cold).
   Semgrep's own engine time is ~0.9 s; the rest is its process startup. Run
   `python harness.py --scan-bench` on the demo machine and quote that number.
8. Semgrep runs with **`--disable-nosem`**: inline `# nosemgrep` / `# nosem` comments in the
   written content are ignored (regression test covers same-line, preceding-line and
   rule-specific forms). Any Semgrep error entry denies the write, except a warning about the
   current (old) file.
9. Semgrep gets an **allowlisted environment**, not HOLD's: no secrets, no `SEMGREP_*`
   overrides; `SEMGREP_SEND_METRICS=off`, `SEMGREP_ENABLE_VERSION_CHECK=0`.
10. The MCP server passes the scanner to the Gateway and runs `Gateway.call` in a worker
   thread. End-to-end stdio test: an injected `urllib.request.urlopen` write is DENIED with the
   file unchanged, and the real fix is ALLOWED and written.
11. The local JSONL audit row is written synchronously before the tool result is returned;
   ClickHouse rows are batched asynchronously.

**Known limits of the write scan:** Python only (extension, or a python shebang); calls
through pre-existing wrappers, new data flowing into an unchanged existing sink, or moving an
existing sink are not flagged; not covered: `getattr` with a literal name on unlisted modules
(e.g. `ctypes`), `os.__dict__[...]`, `operator.attrgetter`, `functools.partial` around sinks,
`shelve`, `dill`/`jsonpickle`, `yaml.full_load`, logging network handlers, `webbrowser`,
`http.server`, `multiprocessing`, `ctypes.pythonapi`, runtime file-write-then-import, imports
inside functions for the dynamic-getattr rule, and star imports (untested); malicious
dependencies in `pyproject.toml`/requirements and all non-Python files are unscanned.

### 4.2 Host note: Windows packaged-app container

Inside the Claude desktop app, commands run in a packaged-app container where `%TEMP%` under
AppData is filesystem-virtualized. Winsock `AF_UNIX` sockets created there can bind but not
connect (`WSAEINVAL`), which made `semgrep-core` fail with `Unix_error: Invalid argument
socketpair`. Pointing `TEMP`/`TMP` at a non-virtualized folder fixes it; `hold/scan.py` does
this. If the repo path is very long, set `HOLD_SEMGREP_TMP` to a short folder (e.g.
`C:\hold-tmp`) to stay under the 108-byte `AF_UNIX` path limit (inference, not observed).

**Other known residual risks:** TOCTOU race on Windows (no `O_NOFOLLOW`); DNS rebinding for
allowlisted hosts; anything the agent does outside HOLD's tools if built-in tools are not
actually disabled.

## 5. ClickHouse

### 5.1 Table (`telemetry/schema.sql`)
```sql
CREATE TABLE IF NOT EXISTS hold_events
(
    event_id        UUID,
    ts              DateTime64(6, 'UTC'),
    task_id         LowCardinality(String),
    agent_id        LowCardinality(String),
    request_id      String,
    tool_name       LowCardinality(String),
    sink            LowCardinality(String),           -- FS_READ | FS_WRITE | NETWORK_EGRESS | SHELL_EXEC | GIT_MUTATION | UNKNOWN_TOOL | UNKNOWN
    target          String,                           -- workspace path or scheme://host. Never content, URL path/query or commands
    decision        Enum8('ALLOW' = 1, 'DENY' = 2),
    reason          String,
    exec_status     Enum8('ok' = 1, 'error' = 2, 'not_run' = 3),
    gate_latency_ns UInt64,                           -- gate decision only; excludes scan, I/O, transport, model
    intent_digest   String
)
ENGINE = MergeTree
ORDER BY (task_id, ts);
```
Column order matches `EVENT_COLUMNS` in `hold/core.py`. Change both together.

### 5.2 Least-privilege users
```sql
CREATE USER hold_writer IDENTIFIED BY '<generated>';
GRANT INSERT ON default.hold_events TO hold_writer;

CREATE USER hold_reader IDENTIFIED BY '<generated>' SETTINGS readonly = 1;
GRANT SELECT ON default.hold_events TO hold_reader;
```
`scripts/setup_clickhouse.py` creates the table and both users from `.env` values.
The gateway uses `hold_writer`; the dashboard backend uses `hold_reader`. No credentials go
in the browser or in git.

### 5.3 Writer configuration (environment variables, from `.env`)
`CLICKHOUSE_HOST`, `CLICKHOUSE_PORT` (default 8443), `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`,
`CLICKHOUSE_DATABASE` (default `default`), `CLICKHOUSE_SECURE` (default `1`); the reader and
admin variables are listed in `.env.example`.
If `CLICKHOUSE_HOST` is unset, events go only to the JSONL audit file. The client connects
lazily on the telemetry thread and inserts in batches (≤ 500 rows or every 250 ms).
Writer errors go to stderr and are counted; they never affect decisions.
**Status: verified against ClickHouse Cloud 26.6** (2026-10-09): `scripts/setup_clickhouse.py` created the table and users; checks passed (writer inserted a real gate decision via `ClickHouseWriter`, reader read it back, dashboard queries ran as reader, reader cannot insert and writer cannot select, both `ACCESS_DENIED` 497). Live tests `test_telemetry.LiveClickHouse` and `test_dashboard.LiveDashboard` pass. The first connection after idling timed out (30 s); warm the service before the demo.

### 5.4 Dashboard queries (poll every 1 s)
```sql
-- Live feed
SELECT ts, tool_name, sink, target, decision, reason, exec_status,
       round(gate_latency_ns / 1000, 1) AS gate_us
FROM hold_events WHERE task_id = {task:String}
ORDER BY ts DESC LIMIT 50;

-- Summary
SELECT decision, count() AS calls,
       round(quantile(0.5)(gate_latency_ns) / 1000, 1)  AS p50_us,
       round(quantile(0.95)(gate_latency_ns) / 1000, 1) AS p95_us
FROM hold_events WHERE task_id = {task:String}
GROUP BY decision;

-- Write-scan denials
SELECT ts, target, reason FROM hold_events
WHERE task_id = {task:String} AND reason LIKE 'Semgrep%'
ORDER BY ts DESC;

-- Graph edges (P2): agent -> target, coloured by decision
SELECT sink, target, decision, count() AS n, max(ts) AS last_seen
FROM hold_events WHERE task_id = {task:String}
GROUP BY sink, target, decision;
```
Fallback dashboard: run these in the ClickHouse Cloud SQL console. That is real and needs no UI code.

Before the demo, wake the Cloud service (idle services are slow on the first query) and
add the venue IP to the service's IP access list.

## 6. Running with Claude Code

```bash
python scripts/reset_demo.py --attack-url <your Beeceptor URL>   # fresh ~/hold-demo-workspace
python scripts/make_mcp_config.py                                 # renders receipt + configs/hold.mcp.json
bash scripts/run_claude_demo.sh                                   # or the PowerShell launcher below
```
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_claude_demo.ps1
```
Positive control: `python scripts/make_mcp_config.py --allow-host <host>` writes
`configs/generated/hold.allow-host.mcp.json`; pass that config to the launcher (see the
script's parameters and DEMO.md).

What the generated `configs/hold.mcp.json` contains: the venv's python as `command`,
`["-m", "hold.server"]`, and env `PYTHONPATH` (repo), `PYTHONSAFEPATH=1`, `HOLD_RECEIPT`
(rendered receipt, absolute), `HOLD_AUDIT_LOG` (absolute). No secrets: ClickHouse settings
come from `.env`, loaded by the server.

What the launchers do: `cd` into the workspace the rendered receipt governs; refuse an
unrendered, missing, linked or in-repo workspace and any `.claude/` or `.mcp.json` in it;
warn about `CLAUDE.md` files Claude Code will load; run
`claude -p "<task>" --tools "" --strict-mcp-config --mcp-config <abs config> --allowedTools "mcp__hold"`;
then print the audit rows that run produced.

- **Use the launchers; don't hand-type the command in Windows PowerShell 5.1.** It drops a
  `""` argument, so `--tools ""` typed by hand does NOT disable the built-in tools.
- `--tools ""` disables built-in tools; `--strict-mcp-config` ignores every other MCP config.
- `--allowedTools "mcp__hold"` is needed in `-p` mode, or Claude Code's own permission layer
  refuses the call **before it reaches HOLD**, which looks like HOLD working. Always confirm a
  DENY in HOLD's audit log. (Whole-server rule behavior: confirm on the first real run.)
- `PYTHONSAFEPATH=1` stops the untrusted workspace from shadowing the `hold` package (or
  `mcp`, `pydantic`, `sitecustomize`, `.pth`) when `python -m` starts in the workspace.
- User-level `~/.claude/CLAUDE.md` still loads into the agent under test; disclose it.
- All flags were checked against `claude --help` for Claude Code 2.1.295.

## 7. Demo flow

1. **Receipt shown:** write `src/flask/app.py`; network egress false; digest prefix (printed by `make_mcp_config.py`).
2. `read_file("ISSUE.md")` and `read_file("src/flask/app.py")` → ALLOW.
3. The injected step leads the model to call `fetch_url("<attack URL>")` → DENY, `exec_status = not_run`; the attack endpoint's log stays empty.
4. `write_file("src/flask/app.py", fix)` → Semgrep scan → ALLOW; `git -C <workspace> diff` shows the change.
5. **Positive control:** same `fetch_url` under the allow-host receipt → ALLOW, and the endpoint shows the request.
6. ClickHouse live feed and summary query show these rows.

If the model doesn't attempt the injected call, replay the same `tools/call` through the
same running HOLD server and say that this tests enforcement, not the model's susceptibility.
