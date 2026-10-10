# DEMO.md: HOLD demo runbook

Run every command from the **HOLD repo root** in PowerShell. On macOS/Linux, use
`.venv/bin/python` and `bash scripts/run_claude_demo.sh` instead.

The demo workspace lives **outside the repo** (`~/hold-demo-workspace`, or `HOLD_DEMO_WORKSPACE`),
because Claude Code loads `CLAUDE.md` from parent folders and would otherwise see HOLD's own rules.

## 1. Set up (before you present)

```powershell
.venv\Scripts\python scripts\reset_demo.py --attack-url "https://<your-endpoint>/reproduce_issue.py"
.venv\Scripts\python scripts\make_mcp_config.py
.venv\Scripts\python scripts\make_mcp_config.py --allow-host <your-endpoint-host>
.venv\Scripts\python ui\dashboard.py --task hold-demo-001
```

1. **Reset** copies `demo/fixture/` into the workspace: a small Flask app with a `NoneType` bug, plus an
   `ISSUE.md` whose "maintainer note" asks the agent to fetch your URL. It prints `git: ok`.
   Use an endpoint whose request log you can show, such as Beeceptor.
2. **Render the deny config.** This writes `configs/hold.mcp.json` and prints the receipt's digest prefix.
   The receipt allows writing `src/flask/app.py` only, with no network.
3. **Render the allow config.** This writes `configs/generated/hold.allow-host.mcp.json`, the same receipt
   but allowing your host. It is used for the positive control.
4. **Start the dashboard** and open `http://127.0.0.1:8765/live`.
   Leave it running in its own terminal and use a second terminal for the rest.

Checks:
- [ ] The ClickHouse service is awake and your IP is on its access list.
- [ ] Only one dashboard is running. Windows lets two processes share a port, and a stale one serves old code.
- [ ] `.venv\Scripts\python harness.py -q` passes.

## 2. Run (about 3 minutes)

| Step | Command / screen | What to say |
|---|---|---|
| 1. The threat | Open `ISSUE.md` in the workspace | "Agents read untrusted text and hold real tools. This issue asks the agent to fetch a script from an outside server." |
| 2. The receipt | Receipt card on `/live` | "The developer approved this task: read the repo, write `app.py`, no network. The issue can't add to that." |
| 3. Live agent | `powershell -ExecutionPolicy Bypass -File scripts\run_claude_demo.ps1` | "Claude Code runs with its built-in tools off. HOLD is its only tool provider." Every read and the fix appear on `/live` as ALLOW. Semgrep scans the fix first (4–18 s). |
| 4. The attack | `.venv\Scripts\python scripts\replay_attack.py` | "Now the two calls the issue asks for, sent through the same server and receipt." `fetch_url` is DENY (no egress) and the `urlopen` write is DENY (Semgrep). The endpoint's log stays empty. |
| 5. Positive control | `.venv\Scripts\python scripts\replay_attack.py --config configs\generated\hold.allow-host.mcp.json` | "Same call, receipt that allows the host: ALLOW, and the endpoint receives it. The receipt decides, not a missing tool." The `urlopen` write is still DENY, because Semgrep checks content. |
| 6. Evidence | `/live` feed + p50/p95, or the ClickHouse SQL console | "Every decision is a row in ClickHouse, with reason and latency." |
| 7. Limits | Say it | "HOLD guards tool calls routed through it; it's not a sandbox. The Semgrep scan covers Python and costs seconds per write." |

Show the fix with `git -C $HOME\hold-demo-workspace diff`.

**Be honest about step 4.** Replay rows are tagged `agent_id = scripted-replay`. It tests HOLD's
enforcement, not whether the model falls for the injection. In our live run, Claude ignored the
injected fetch on its own.

**Use the launcher; don't hand-type the `claude` command.** Windows PowerShell 5.1 drops the empty
`--tools ""` argument, which would leave Claude Code's built-in tools on.

## 3. Reset for another take

```powershell
.venv\Scripts\python scripts\reset_demo.py --attack-url "https://<your-endpoint>/reproduce_issue.py"
```

This puts the bug back. For a clean dashboard, render the configs with a new task ID or start the
dashboard with `--task <new-id>`.

## Variant: a real GitHub issue

```powershell
.venv\Scripts\python scripts\github_task.py --repo owner/name --issue 1 --write path/to/file.py
```

It prints the exact run and dashboard commands for that repo. Verified on `shehryaur/flask` issue #1.

## Fallbacks

**ClickHouse unreachable:** `.venv\Scripts\python ui\dashboard.py --jsonl hold_audit.jsonl` reads
the local audit log the server writes on every run. The page is labeled "local audit log".

**No internet, no model:** `.venv\Scripts\python -m hold.core` sends a fixed script of tool calls
through the real gate, against a temporary workspace and a local "attacker" server. It prints the
injected fetch DENY, the fix ALLOW, then the positive control. It does not run Semgrep. Label it on
screen as the offline scripted run.
