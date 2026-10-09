# intent.md — Project Hold: Anti-Scope-Creep Guardrails (Hackathon MVP)

> **Build Window:** Strictly 5.5 Hours (11:00 AM – 4:30 PM PDT @ AWS Builder Loft)  
> **Rule of the Day:** If a feature does not appear on screen during our 180-second judging pitch, **IT DOES NOT EXIST.**

---

## Singular Sprint Objective
**Build and demonstrate Project Hold: a functional, sub-1.5ms MCP stdio reverse proxy that intercepts and terminates unauthorized outbound network egress from Claude Code during real GitHub issue triage, streaming the severed attack edge to ClickHouse in real time.**

---

## Strict Feature Prioritization

### ✅ P0 (Must Have — Nothing Else Matters)
* Working `proxy.py` intercepting MCP JSON-RPC `tools/call`.
* In-memory `gate.py` capability validator (< 1.5ms latency).
* Deterministic 403 block on `curl`/network tool calls.
* ClickHouse Python driver logging `ALLOW`/`DENY` events.
* Dark-mode Cytoscape DAG dashboard showing the red severed attack edge.

### 🟡 P1 (Only If Time Permits)
* Semgrep CLI script auto-generating `intent_receipt.json`.
* Summary stats cards in the dashboard (Average Latency, Total Blocked Calls).

### 🚫 THE GUILLOTINE: OUT OF SCOPE (IMMEDIATE DISQUALIFIERS)
* ❌ User authentication, signups, JWTs, or multi-tenant database schemes.
* ❌ Stripe, billing plans, or pricing pages.
* ❌ Secondary LLM guardrails or embedding-based semantic matching at runtime.
* ❌ Full TypeScript rewrite of MCP SDKs (stick to Python stdio).
* ❌ Complex AST transformations of code diffs.
