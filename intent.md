# intent.md: HOLD scope contract (hackathon MVP)

> **Build window:** 11:00–16:30 PDT, Fri 2026-10-09 (submit by 16:10). Two builders.
> **Rule of the day:** Build real enforcement → real agent integration → real evidence → demo clarity. Never reverse that order. Anything shown on screen must be real, or labeled as a fallback.

## Sprint objective
Show one Claude Code task where HOLD **denies an injected network request before it is
dispatched**, **still allows the authorized fix** to `src/flask/app.py`, and records both
decisions as **real rows in ClickHouse**.

## P0: must ship (nothing else matters until these work)
- `hold/core.py`: gate + guarded `read_file` / `write_file` / `fetch_url` (start from `architecture.py`; do not rewrite it).
- `hold/server.py`: MCP stdio server exposing those three tools through the official MCP Python SDK.
- Claude Code runs with built-in tools disabled and only HOLD's MCP server loaded (SPEC.md §6).
- `python harness.py` passes.
- ClickHouse `hold_events` table receiving real ALLOW/DENY rows.
- Positive control: the same `fetch_url` succeeds under a receipt that grants the host.

## P1: only after P0 runs end to end twice
- Plain live event table polling ClickHouse, plus one aggregate (count and p50/p95 by decision).
- Semgrep scan of `write_file` content for newly introduced network/exec sinks (addresses REVIEW.md §1.5).
- Recorded backup video.

## P2: only if P1 is done before 15:10
- Cytoscape graph (agent → resource edges, red for DENY).
- Semgrep rules that classify MCP tool handler code into sink categories, as **suggestions** for the receipt author.

## Out of scope (do not start)
- User auth, signups, JWTs, multi-tenancy, billing, pricing pages.
- LLM or embedding-based guardrails at runtime.
- A generic transparent proxy in front of arbitrary MCP servers.
- Shell or git tools, command allowlists, or blocklist matching of shell strings.
- `hold run` CLI wrappers, TypeScript rewrites, AST transformations of diffs.
- Any sponsor work outside the three tracks we enter (ClickHouse, Semgrep, Pi): no Akash, Guild AI, OpenAI, MongoDB or ElevenLabs integrations.
- Running the gateway on any remote host: it must sit next to the agent over stdio.
