# CLAUDE.md: working rules for this repo

HOLD is a task-scoped MCP tool gateway for AI coding agents. A developer-approved **Intent
Receipt** says which files the agent may read and write and which hosts it may contact.
HOLD checks every tool call against the receipt before executing it, scans written code with
Semgrep, and logs each ALLOW/DENY decision to a local JSONL file and to ClickHouse.

## Where things are
- `README.md`: what HOLD is, setup, verified features, limits, FAQ
- `SPEC.md`: source of truth for receipt schema, tools, gate rules, ClickHouse schema and queries, Claude Code config
- `DEMO.md`: demo runbook · `decision.md`: decision and build log from the hackathon
- `hold/core.py`: gate, guarded tools, telemetry · `hold/scan.py`: Semgrep write scan · `hold/server.py`: MCP server · `hold/env.py`: `.env` loader
- `harness.py`: runs all tests (its own + `tests/test_*.py`)

## Commands (use the project venv)
```bash
.venv/Scripts/python harness.py -q      # all tests; must pass (Windows path; .venv/bin on macOS/Linux)
.venv/Scripts/python harness.py --bench # gate-only p50/p95 on this machine
.venv/Scripts/python -m hold.core       # offline scripted demo with a local "attacker" server
```

## Agent team (`.claude/agents/`)
Optional specialists from the hackathon build: **orchestrator**, **gate-engineer**,
**mcp-integrator**, **telemetry-engineer**, **demo-engineer**, **red-team** and **critic**
(read-only reviewer). File ownership is listed in `.claude/agents/orchestrator.md`.

## Automatic checks (`.claude/hooks/check.py`, runs after every Edit/Write)
- Editing a `.py` file runs `harness.py -q`; a failure blocks until fixed.
- Public docs (README, SPEC, DEMO) and `ui/` are scanned for banned claims (list below).
- Any file except `.env*` is scanned for hard-coded secrets.
- `.claude/settings.json` denies reading `.env` and denies `git commit` / `git push`.

## Honest claims
**Say:** "HOLD enforces a developer-approved, task-scoped policy on every tool call routed
through it." · "The injected request was denied before dispatch; the authorized fix
succeeded." · "Every decision is a row in ClickHouse." · Latency only from `--bench` output.

**Don't say:** zero syscalls or packets · mathematically proven or unbreakable · signed
receipts · zero false positives · blocks all prompt injection · guaranteed latency · Semgrep
writes the policy · any sponsor integration that isn't built.

## Rules
1. **Working product, not simulation.** Never fake an ALLOW/DENY, a tool result, a latency figure or a ClickHouse row. Fallbacks are labeled on screen.
2. **Evidence or it didn't happen.** Every claim names the command that proves it and its output.
3. **Fail closed.** Unknown tools, malformed arguments, scanner errors and gate exceptions → DENY. Telemetry failures never change a decision.
4. **A stdio MCP server never writes to stdout.** Diagnostics go to stderr.
5. **Secrets live only in `.env`** (gitignored; template in `.env.example`). Never read, print or log them. Events never contain file contents, URL paths/queries or command lines.
6. Keep the receipt outside the agent's workspace; load it once.
7. No shell tool, no git tool, no new MCP tools without updating SPEC.md and adding tests.
8. **No commits, pushes or branches**; the humans do version control.
