# HOLD: two-person hackathon roadmap

**Event:** Cyberdefense Hackathon, SF Tech Week · Fri 2026-10-09
**Build window:** 11:00–16:30 PDT · **Submit by 16:10** (20-minute buffer)
**Team:** 2 builders

## North star
> One real Claude Code task where HOLD denies an injected network request **before it is dispatched**, still allows the authorized fix, and both decisions are **real rows in ClickHouse**.

Priority order: **real enforcement → real agent integration → real evidence → demo clarity.** Never reverse it for polish.

## Prize tracks
Sponsors at the event: OpenAI, MongoDB, Pi, Akash, ElevenLabs, Guild AI, ClickHouse, Semgrep. **Only five award prizes: ClickHouse, Semgrep, Pi, Akash, Guild AI.** OpenAI, MongoDB and ElevenLabs have no track, so don't spend build time on them.

| Track | Fit | Extra work | What we enter with |
|---|---|---|---|
| **ClickHouse** | Strong | None (core) | Every decision is a real row; live feed + p50/p95-by-decision query |
| **Semgrep** | Strong | ~45 min (P1) | `write_file` content scanned for newly introduced network/exec sinks before it is allowed |
| **Pi** | Strong on theme | None. Pi is a prize sponsor only; **no product or tech access at this event**, so every team competes on fit | Runtime, task-scoped enforcement for coding agents: "agentic product security" at the tool-call layer. Never imply a Pi integration |

**We enter three tracks: ClickHouse, Semgrep, Pi.** Akash and Guild AI are dropped. Akash only fit as dashboard hosting, and Guild overlaps HOLD's own space (agent governance), so the ~1.5–2 hours they would cost go to demo reliability instead.

**Rule:** claim a track only with something that is real and shown. Read the three tracks' judging criteria at 11:00. Pi is judged on fit and execution, so the Pi story rests on the live DENY + ALLOW demo and the stated limits.

## Already done (pre-build, 2026-10-09 early morning)
- `architecture.py`: working gate, guarded executors, telemetry (JSONL + ClickHouse writer). Not yet run against a live ClickHouse.
- `harness.py`: 19 passing adversarial tests.
- Docs reconciled; audit in REVIEW.md.

## Before 11:00 (setup only, no feature code)
- [ ] ClickHouse Cloud service created; `hold_events` table and `hold_writer` / `hold_reader` users from SPEC.md §5; venue IP on the access list.
- [ ] Credentials in a local `.env.hold` file that is **gitignored**, never committed.
- [ ] Demo workspace = the self-contained fixture in `demo/fixture/` (real NoneType bug, failing test, `ISSUE.md` with the injected fetch, fake `.env`), copied by `scripts/reset_demo.py` to `~/hold-demo-workspace` (override: `HOLD_DEMO_WORKSPACE`). It lives **outside the repo** because Claude Code loads `CLAUDE.md` from parent directories, and the agent under test must not see HOLD's rules. Reset with `scripts/reset_demo.py --attack-url <your Beeceptor URL>`.
- [ ] `pip install mcp clickhouse-connect`; record the versions in `requirements.txt`.
- [ ] `claude --version` and `claude --help` checked for `--tools`, `--strict-mcp-config`, `--mcp-config`, `--allowedTools`.
- [ ] Evidence log for the unshielded runs: model ID, Claude Code version, **permission mode**, prompt, timestamp, screenshot.
- [ ] `pip install semgrep`; `semgrep --version` works on the demo machine.
- [ ] Read the prize criteria for ClickHouse, Semgrep and Pi (Pi provides no product access; it is judged on fit).
- [ ] **Check the event's rules on code written before 11:00.** Much of HOLD was built before the window. If prior work must be disclosed, say so in the README and submission.

## Ownership

| Owner | Responsibilities | Files | Done when |
|---|---|---|---|
| **A: security core** | Move `architecture.py` → `hold/core.py` unchanged; MCP server; receipt config; Claude isolation; keep harness green | `hold/core.py`, `hold/server.py`, `configs/`, `harness.py` | Claude calls HOLD tools; the DENY appears in HOLD's audit log; the fix is on disk |
| **B: evidence and demo** | ClickHouse schema and users; verify real inserts; live view; fixture; recordings; README; submission | `telemetry/schema.sql`, `ui/`, `demo/`, docs | Rows visible in ClickHouse within ~1 s of a call; demo recorded; submitted |

**Shared contract (frozen at 11:00):** the `EVENT_COLUMNS` in `hold/core.py` = the table in SPEC.md §5.1. Changing either requires changing both, together.

## Schedule

| Time | A: security core | B: evidence and demo | Exit criterion |
|---|---|---|---|
| **11:00–11:15** | Copy core → `hold/core.py`; run harness | Run `architecture.py` with `CLICKHOUSE_*` set; check rows in the SQL console | Real rows in ClickHouse from the reference demo |
| **11:15–12:30** | `hold/server.py` (SPEC.md §6); call the tools with the MCP Inspector or a raw stdio client | Live event table (polls the `hold_reader` backend, or uses the SQL console); summary query | HOLD server answers `tools/list` and `tools/call` |
| **12:30–13:15** | Claude Code with `--tools ""` and only HOLD loaded; first end-to-end run | Finish `ISSUE.md` so the model attempts `fetch_url` (wording that points to a fetch, not "run curl") | Claude → HOLD → gate → disk / event |
| **13:15–14:15** | Fix integration failures; positive-control receipt | Wire the live view to the real task_id; record the unshielded baseline (pre-recorded, permission mode on screen) | Full demo works once |
| **14:15–15:10** | Run harness + bench on the demo machine; add P1 Semgrep write scan **only if** everything above is green | Record the full demo; README results section with measured numbers | Demo works twice from a reset workspace |
| **15:10–15:45** | Pair: integration fixes only | Pair: rehearse 3× | **Code freeze at 15:45** |
| **15:45–16:10** | Final harness run; tag the commit | Submit: repo link, video, screenshots, description | **Submitted by 16:10** |
| **16:10–16:30** | Critical fixes only | Confirm submission; review judge Q&A | Buffer |

### Cut rules
- **12:30:** MCP SDK fighting you? Write a minimal stdio JSON-RPC server (`initialize`, `tools/list`, `tools/call`) around the same `Gateway`. Don't write a generic proxy.
- **13:15:** Claude integration not working? Demo the same live HOLD server driven by a scripted MCP client, **labeled as such**, and keep fixing Claude integration in parallel.
- **14:15:** ClickHouse not working? Show the JSONL audit log, **labeled "local audit log"**. Never call it ClickHouse.
- **15:10:** Stop all UI work. A plain table is fine.
- **15:45:** No new features.

## Security acceptance tests
Automated in `harness.py` (all passing pre-build):
- [x] Allowed read returns the file; allowed write changes it on disk
- [x] Protected reads denied: `.env`, `.ENV`, `.env.production`, `src/.env`, `src/.git/config`, `*.pem`, `.aws/`, `.ssh/`
- [x] Protected writes denied even with `write: ["**"]`: `.env`, workflows, `.git/hooks`, `.claude/`, `.mcp.json`
- [x] Traversal and non-canonical paths denied (15 variants, including Windows `.env.` and `:stream`)
- [x] Symlink escape and symlink-to-protected denied
- [x] Unknown tools and malformed or extra arguments denied; gate never raises
- [x] `fetch_url` denied with zero dispatches; URL tricks (`@`, suffix hosts, userinfo, `file://`, metadata IP) denied
- [x] Redirects not followed
- [x] Telemetry failure cannot flip a DENY; events contain no file content or URL query

Manual, on demo day:
- [ ] No built-in tools in the demo session (Claude tool list shows only `mcp__hold__*`)
- [ ] The DENY row is in HOLD's audit log (not a Claude Code permission refusal)
- [ ] ClickHouse has the genuine rows from the demo run
- [ ] `python harness.py --bench` run on the demo machine; numbers in the README
- [ ] Demo succeeds twice from a reset workspace

## Three-minute demo

| Time | Screen | Say |
|---|---|---|
| 0:00–0:25 | The issue: a real bug report plus an injected "fetch our reproduction script" | "Agents read untrusted text and hold real tools. The text can ask for anything." |
| 0:25–0:55 | **Pre-recorded** unshielded run; permission mode visible; Beeceptor gets the request | "Here the model made the call. Its judgment isn't a permission system." |
| 0:55–1:20 | The Intent Receipt: write `app.py`, no network; digest | "The developer approved this task's capabilities. The issue can't add to them." |
| 1:20–2:05 | Live HOLD run: `fetch_url` DENY with reason, Beeceptor empty; then `write_file` ALLOW, `git diff` | "Blocked before dispatch. The real fix still landed." |
| 2:05–2:25 | Positive control: same call, receipt grants the host → ALLOW, Beeceptor lights up | "Same tool, same URL. The receipt decided, not a missing tool." |
| 2:25–2:50 | ClickHouse: live rows + summary (count, p50/p95 by decision) | "Every decision is queryable the moment it happens." |
| 2:50–3:00 | Limits + next step | "We guard tool calls, not the OS. Next: Semgrep scanning of what the agent writes." |

**Backup:** if the model doesn't attempt the injected call, replay the exact `tools/call` through the same running HOLD server, and say it validates enforcement, not model behavior.

## Judge Q&A (prepare these answers)
- **"Why not just disable Bash or use Claude Code's permission rules?"** Those are per-agent and per-user settings. The receipt is per task, works for any MCP client, and produces an audit trail. Also show the positive control: HOLD decides by policy, not by removing tools.
- **"What about Claude Code's sandbox or hooks?"** They're good and complementary; use them. HOLD is the task-scoped policy and audit layer and isn't tied to one agent.
- **"What if the injected code goes into app.py?"** HOLD allows it today; that's our stated limit. The fix is scanning written content with Semgrep before allowing the write.
- **"How does this relate to Pi?"** Pi secures the code a team ships; HOLD limits what an agent can do while writing it. Same goal, different layer.
- **"Why Semgrep at write time, not on the final PR?"** At write time, the bad write never lands on disk, and the scan's decision is a row in ClickHouse next to the gate's. A final PR scan is still worth running too.
- **"Isn't this what agent-governance platforms (e.g., Guild AI) do?"** Those run and govern whole agents. HOLD is a narrow per-task policy check on every tool call that could plug into such a platform.
- **"How does this differ from existing MCP gateways?"** Answer from your landscape check (REVIEW.md §1.3). Don't claim to be first.
- **"Who writes the receipt?"** The developer, in about 30 seconds of JSON. Realistic receipts are broad on writes (`src/**`) and strict on categories (no network, no secrets, no CI config).
- **"Is the latency real?"** Show `--bench` output from the demo machine and explain that path checks hit the filesystem on purpose.
- **"Did Claude really push to main by itself?"** Answer only with the logged permission mode. If prompts were bypassed, say so.

## Honest claims
**Say:** "HOLD enforces a developer-approved, task-scoped policy on every tool call routed through it." · "The injected request was denied before dispatch; the authorized fix succeeded." · "Gate decisions measured at p50 X / p95 Y on this machine." (only after measuring) · "Every decision is a row in ClickHouse."

**Don't say:** zero syscalls · zero packets · mathematically proven / unbreakable · seL4-style · signed receipts · zero false positives · blocks all prompt injection · sub-1.5 ms guaranteed · Semgrep writes the policy · competitive vacuum · any sponsor integration you didn't build.

## Submission evidence
- [ ] README with problem, architecture, setup, **limits**, measured numbers
- [ ] 30–60 s video of real DENY + ALLOW + positive control + ClickHouse rows
- [ ] `python harness.py` output
- [ ] ClickHouse query screenshot with real rows
- [ ] No secrets anywhere in the repo (`git grep -i password`, check `.env.hold` is ignored)
- [ ] Named team contributions

## After the hackathon
Semgrep scanning of written content; per-tool argument policies for more tool types; an authenticated receipt issuer; OS or container isolation so test execution can be allowed; multi-task audit history.
