-- HOLD decision events (SPEC.md section 5.1).
-- Column order must equal EVENT_COLUMNS in hold/core.py; tests/test_telemetry.py checks
-- names, order and types against both hold/core.py and SPEC.md. Change all three together.
-- Applied by scripts/setup_clickhouse.py (idempotent). The table name is unqualified: the
-- database comes from the connection (CLICKHOUSE_DATABASE, default `default`).

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
    gate_latency_ns UInt64,                           -- gate decision only; excludes I/O, transport, model
    intent_digest   String
)
ENGINE = MergeTree
ORDER BY (task_id, ts);

-- ---------------------------------------------------------------------------------------
-- Least-privilege users (SPEC.md section 5.2). REFERENCE ONLY: every line below is a
-- comment and is never executed from this file. scripts/setup_clickhouse.py runs the
-- equivalent statements with the user names and passwords from .env
-- (CLICKHOUSE_USER / CLICKHOUSE_PASSWORD, CLICKHOUSE_READER_USER / CLICKHOUSE_READER_PASSWORD).
-- No password is stored in this file or anywhere in git.
--
-- CREATE USER IF NOT EXISTS hold_writer IDENTIFIED BY '<generated>';
-- GRANT INSERT ON default.hold_events TO hold_writer;
--
-- CREATE USER IF NOT EXISTS hold_reader IDENTIFIED BY '<generated>' SETTINGS readonly = 1;
-- GRANT SELECT ON default.hold_events TO hold_reader;
--
-- The gateway connects as hold_writer, the dashboard backend as hold_reader. Credentials
-- never go to the browser.
