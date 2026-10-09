# CLAUDE.md: working rules for this repo

HOLD is a task-scoped MCP tool gateway for AI coding agents. A developer-approved **Intent
Receipt** says which files the agent may read and write and which hosts it may contact.
HOLD checks every tool call against the receipt before executing it, scans written code with
Semgrep, and logs each ALLOW/DENY decision to a local JSONL file and to ClickHouse.

Hackathon build: Fri 2026-10-09, 11:00–16:30 PDT, 2 builders. Prize tracks: ClickHouse, Semgrep, Pi. Submit by 16:10.

## Where things are
- `SPEC.md`: source of truth for receipt schema, tools, gate rules, ClickHouse schema and queries, MCP/Claude config
- `intent.md`: scope (P0/P1/P2/out) · `ROADMAP.md`: schedule, cut rules, demo, judge Q&A, honest claims
- `PRD.md`: problem and positioning · `REVIEW.md`: audit of earlier claims · `decision.md`: every decision + build log
- `hold/core.py`: enforcement core (gate, guarded tools, telemetry) · `hold/server.py`: MCP server · `hold/env.py`: `.env` loader
- `harness.py`: runs all tests (its own + `tests/test_*.py`)

## Commands (use the project venv)
```bash
.venv/Scripts/python harness.py -q      # all tests; must pass (Windows path; .venv/bin on macOS/Linux)
.venv/Scripts/python harness.py --bench # gate-only p50/p95 on this machine
.venv/Scripts/python architecture.py    # offline end-to-end demo with a local "attacker" server
```

## Agent team (`.claude/agents/`)
The **orchestrator** plans, delegates, verifies and logs. Run it as the main session with
`claude --agent orchestrator`, or follow its protocol in any session. Specialists:
**gate-engineer**, **mcp-integrator**, **telemetry-engineer**, **demo-engineer**, **red-team**
(writes failing tests for real bypasses), **critic** (read-only, re-runs evidence, returns
VERIFIED/REJECTED/UNVERIFIED). File ownership is listed in `.claude/agents/orchestrator.md`;
**edit only files you own**. If a test owned by someone else fails, report it; don't touch it.

## Automatic checks (`.claude/hooks/check.py`, runs after every Edit/Write)
- Editing a `.py` file runs `harness.py -q`; a failure blocks until fixed.
- Public docs (README, PRD, SPEC, intent, DEMO) and `ui/` are scanned for banned claims.
- Any file except `.env*` is scanned for hard-coded secrets.
- `.claude/settings.json` denies reading `.env` and denies `git commit` / `git push`.

## Rules
1. **Working product, not simulation.** Never fake an ALLOW/DENY, a tool result, a latency figure or a ClickHouse row. Mocks may only count dispatches, and must say so. Fallbacks are labeled on screen.
2. **Evidence or it didn't happen.** Every claim in a report names the command that proves it and its output. Unproven claims are treated as false.
3. **Fail closed.** Unknown tools, malformed arguments, scanner errors and gate exceptions → DENY. Telemetry failures never change a decision.
4. **A stdio MCP server never writes to stdout.** Diagnostics go to stderr.
5. **Secrets live only in `.env`** (gitignored; template in `.env.example`). Never read, print or log them. Events never contain file contents, URL paths/queries or command lines.
6. Keep the receipt outside the agent's workspace; load it once.
7. No shell tool, no git tool, no new MCP tools without updating SPEC.md and adding tests.
8. **No commits, pushes or branches**; the humans do version control.
9. Use only the claims in ROADMAP.md › Honest claims. Stay in scope (intent.md).
