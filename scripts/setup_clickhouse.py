#!/usr/bin/env python3
"""Create and verify HOLD's ClickHouse table and least-privilege users (SPEC.md 5).

    python scripts/setup_clickhouse.py          create table + users (idempotent), then run the checks
    python scripts/setup_clickhouse.py --check  run the checks only; no DDL

Settings come from the environment, after `hold.env.load_env()` has read `.env` (real
environment variables win):

    CLICKHOUSE_HOST, CLICKHOUSE_PORT (8443), CLICKHOUSE_SECURE (1), CLICKHOUSE_DATABASE (default)
    CLICKHOUSE_ADMIN_USER / CLICKHOUSE_ADMIN_PASSWORD     creates table and users; deletes probe rows
    CLICKHOUSE_USER / CLICKHOUSE_PASSWORD                 gateway writer: INSERT on hold_events only
    CLICKHOUSE_READER_USER / CLICKHOUSE_READER_PASSWORD   dashboard reader: readonly=1, SELECT only

The checks prove the real path end to end: a real Gateway decision is inserted with
`hold.core.ClickHouseWriter` as the writer, read back as the reader with the dashboard's own
queries, the reader is refused an INSERT, the writer is refused a SELECT, and the admin
deletes the probe rows. Prints what it does and never a password.

Exit codes: 0 all good, 1 a step or check failed, 2 configuration missing or invalid.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.core import EVENT_COLUMNS, ClickHouseWriter, Gateway, IntentReceipt, Telemetry  # noqa: E402
from hold.env import load_env  # noqa: E402
from telemetry import clickhouse as tch  # noqa: E402

EXIT_OK, EXIT_FAIL, EXIT_CONFIG = 0, 1, 2
REQUIRED = (
    "CLICKHOUSE_HOST",
    "CLICKHOUSE_ADMIN_USER", "CLICKHOUSE_ADMIN_PASSWORD",
    "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD",
    "CLICKHOUSE_READER_USER", "CLICKHOUSE_READER_PASSWORD",
)
# ClickHouse error codes that mean "refused for lack of rights".
READONLY, ACCESS_DENIED = 164, 497
REFUSAL_CODES = {READONLY: "READONLY", ACCESS_DENIED: "ACCESS_DENIED"}
POLL_SECONDS = 10.0


@dataclass(frozen=True)
class Config:
    endpoint: tch.Endpoint
    admin_user: str
    admin_password: str
    writer_user: str
    writer_password: str
    reader_user: str
    reader_password: str

    @property
    def table(self) -> str:
        return f"`{self.endpoint.database}`.`{tch.TABLE}`"


def load_config(environ=os.environ) -> Config:
    absent = tch.missing(REQUIRED, environ)
    if absent:
        raise tch.ConfigError("missing or blank: " + ", ".join(absent)
                              + ". Set them in .env (template: .env.example).")
    endpoint = tch.Endpoint.from_env(environ)
    admin = environ["CLICKHOUSE_ADMIN_USER"].strip()
    writer = tch.check_identifier(environ["CLICKHOUSE_USER"].strip(), "CLICKHOUSE_USER")
    reader = tch.check_identifier(environ["CLICKHOUSE_READER_USER"].strip(), "CLICKHOUSE_READER_USER")
    if len({admin, writer, reader}) != 3:
        raise tch.ConfigError("CLICKHOUSE_ADMIN_USER, CLICKHOUSE_USER and CLICKHOUSE_READER_USER "
                              "must be three different users")
    if "default" in (writer, reader):
        raise tch.ConfigError("CLICKHOUSE_USER and CLICKHOUSE_READER_USER must be dedicated users, not 'default'")
    for var in ("CLICKHOUSE_PASSWORD", "CLICKHOUSE_READER_PASSWORD"):
        if any(ord(c) < 32 or ord(c) == 127 for c in environ[var]):
            raise tch.ConfigError(f"{var} contains control characters")
    return Config(endpoint, admin, environ["CLICKHOUSE_ADMIN_PASSWORD"],
                  writer, environ["CLICKHOUSE_PASSWORD"], reader, environ["CLICKHOUSE_READER_PASSWORD"])


# --------------------------------------------------------------------------------------
# Setup (idempotent)
# --------------------------------------------------------------------------------------

def _user_exists(admin, name: str) -> bool:
    result = admin.query("SELECT count() FROM system.users WHERE name = {name:String}",
                         parameters={"name": name})
    return bool(result.result_rows[0][0])


def ensure_user(admin, name: str, password: str, *, readonly: bool, privilege: str, table: str,
                out: Callable[[str], None], redact: tch.Redactor) -> None:
    ident = f"`{name}`"  # name already validated as [A-Za-z_][A-Za-z0-9_]*
    settings = " SETTINGS readonly = 1" if readonly else ""
    note = " with readonly = 1" if readonly else ""
    # The password is bound client-side by clickhouse-connect (%(pw)s -> escaped '...' literal):
    # ClickHouse has no server-side parameters in IDENTIFIED BY.
    if not _user_exists(admin, name):
        admin.command(f"CREATE USER IF NOT EXISTS {ident} IDENTIFIED BY %(pw)s{settings}",
                      parameters={"pw": password})
        out(f"user {name}: created{note}")
    else:
        admin.command(f"ALTER USER {ident} IDENTIFIED BY %(pw)s{settings}", parameters={"pw": password})
        out(f"user {name}: already existed; password set from .env{note}")
        try:
            admin.command(f"REVOKE ALL ON *.* FROM {ident}")
            out(f"user {name}: revoked previously granted privileges")
        except Exception as exc:  # the checks below test what the user can actually do
            out(f"WARN  user {name}: could not revoke earlier privileges: {tch.describe_error(exc, redact)}")
    admin.command(f"GRANT {privilege} ON {table} TO {ident}")
    grants = admin.query(f"SHOW GRANTS FOR {ident}").result_rows
    out(f"user {name}: grants now: " + "; ".join(str(r[0]) for r in grants))


def setup(cfg: Config, admin, out: Callable[[str], None], redact: tch.Redactor) -> None:
    db = cfg.endpoint.database
    if db != "default":
        admin.command(f"CREATE DATABASE IF NOT EXISTS `{db}`")
        out(f"database {db}: ensured")
    # schema.sql names the table without a database, so bind the admin client to `db`.
    admin.database = db
    existed = admin.command(f"EXISTS TABLE {cfg.table}") == 1
    for statement in tch.sql_statements(tch.SCHEMA_PATH.read_text(encoding="utf-8")):
        admin.command(statement)
    out(f"table {db}.{tch.TABLE}: " + ("already existed (CREATE ... IF NOT EXISTS left it unchanged)"
                                       if existed else "created from telemetry/schema.sql"))
    ensure_user(admin, cfg.writer_user, cfg.writer_password, readonly=False, privilege="INSERT",
                table=cfg.table, out=out, redact=redact)
    ensure_user(admin, cfg.reader_user, cfg.reader_password, readonly=True, privilege="SELECT",
                table=cfg.table, out=out, redact=redact)


# --------------------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------------------

def gateway_probe_event(task_id: str) -> Dict[str, Any]:
    """One genuine gate decision (DENY of a tool HOLD does not offer) from a real Gateway
    with a throwaway receipt, captured in memory. Its task_id marks it as a probe."""
    captured: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "ws").mkdir()
        receipt = IntentReceipt.from_dict({
            "task_id": task_id,
            "intent": "scripts/setup_clickhouse.py check probe; the row is deleted after the check",
            "workspace_root": "ws",
            "capabilities": {"read": [], "write": []},
        }, Path(tmp))
        telemetry = Telemetry([captured.extend], flush_interval=0.01)
        Gateway(receipt, telemetry, agent_id="setup_clickhouse").call("hold_setup_probe", {},
                                                                      request_id="setup-check")
        telemetry.close()
    if len(captured) != 1:
        raise RuntimeError(f"expected 1 gateway event, got {len(captured)}")
    return captured[0]


def poll(fetch: Callable[[], Any], done: Callable[[Any], bool], timeout: float = POLL_SECONDS):
    """Re-run `fetch` until `done(result)` or timeout (a Cloud replica can lag an instant)."""
    deadline = time.monotonic() + timeout
    while True:
        result = fetch()
        if done(result) or time.monotonic() >= deadline:
            return result
        time.sleep(0.25)


def _refusal(exc: BaseException) -> str:
    """'ClickHouse <code> <NAME>' when the server refused for lack of rights, else ''."""
    code, name = tch.error_code(exc)
    if code is None:
        match = re.search(r"\bCode:\s*(\d+)", str(exc))
        code = int(match.group(1)) if match else None
    if code in REFUSAL_CODES or name in REFUSAL_CODES.values():
        return f"ClickHouse {code} {name or REFUSAL_CODES.get(code, '')}".strip()
    return ""


def run_checks(cfg: Config, admin, out: Callable[[str], None], redact: tch.Redactor) -> bool:
    results: List[bool] = []

    def record(ok: bool, message: str) -> bool:
        out(("PASS  " if ok else "FAIL  ") + message)
        results.append(ok)
        return ok

    def summary() -> bool:
        failed = results.count(False)
        out("ALL CHECKS PASSED" if not failed else f"{failed} CHECK(S) FAILED")
        return not failed

    db, table = cfg.endpoint.database, cfg.table
    out("checks:")
    if not record(admin.command(f"EXISTS TABLE {table}") == 1, f"table {db}.{tch.TABLE} exists"):
        out("      run scripts/setup_clickhouse.py without --check to create it")
        return summary()

    expected = [(n, tch.normalize_type(t)) for n, t in tch.schema_columns()]
    live = [(r[0], tch.normalize_type(r[1])) for r in admin.query(f"DESCRIBE TABLE {table}").result_rows]
    if not record(live == expected and [n for n, _ in live] == EVENT_COLUMNS,
                  f"columns (names, order, types) match telemetry/schema.sql and EVENT_COLUMNS ({len(live)} columns)"):
        for i in range(max(len(live), len(expected))):
            have = live[i] if i < len(live) else None
            want = expected[i] if i < len(expected) else None
            if have != want:
                out(f"      column {i}: live {have} != schema {want}")
        out("      the table predates the current schema; migrate it by hand (setup never drops data)")
        return summary()

    probe_task = f"hold-setup-probe-{uuid.uuid4().hex[:12]}"
    reader_task = probe_task + "-reader-insert"
    try:
        _probe_checks(cfg, admin, probe_task, reader_task, record, redact)
    finally:
        _delete_probe_rows(admin, table, (probe_task, reader_task), record, redact)
    return summary()


def _probe_checks(cfg: Config, admin, probe_task: str, reader_task: str,
                  record: Callable[[bool, str], bool], redact: tch.Redactor) -> None:
    event = gateway_probe_event(probe_task)
    try:
        ClickHouseWriter()([event])  # the gateway's own writer class, connecting as CLICKHOUSE_USER
    except Exception as exc:
        record(False, f"writer '{cfg.writer_user}' insert with hold.core.ClickHouseWriter: "
                      f"{tch.describe_error(exc, redact)}")
        return
    record(True, f"writer '{cfg.writer_user}' inserted a real gate decision with hold.core.ClickHouseWriter "
                 f"(task {probe_task}: {event['decision']} {event['tool_name']}, gate {event['gate_latency_ns']} ns)")

    reader = writer = None
    try:
        reader = tch.connect(cfg.endpoint, cfg.reader_user, cfg.reader_password, client_name="hold-setup-check")
        start = time.monotonic()
        rows = poll(lambda: reader.query(
            "SELECT toString(event_id), decision, exec_status, sink, gate_latency_ns "
            "FROM hold_events WHERE task_id = {task:String}", parameters={"task": probe_task}).result_rows,
            lambda r: len(r) > 0)
        want = [(str(event["event_id"]), event["decision"], event["exec_status"], event["sink"],
                 event["gate_latency_ns"])]
        record(list(map(tuple, rows)) == want,
               f"reader '{cfg.reader_user}' read the same row back (event_id, decision, exec_status, sink, "
               f"gate_latency_ns) after {time.monotonic() - start:.2f} s" + ("" if rows else ": no rows"))

        feed = list(reader.query(tch.LIVE_FEED_SQL, parameters={"task": probe_task}).named_results())
        summ = list(reader.query(tch.SUMMARY_SQL, parameters={"task": probe_task}).named_results())
        gate_us = feed[0]["gate_us"] if feed else None
        record(len(feed) == 1 and feed[0]["decision"] == event["decision"]
               and summ == [{"decision": event["decision"], "calls": 1, "p50_us": gate_us, "p95_us": gate_us}],
               f"dashboard queries (SPEC.md 5.4 live feed + summary) run as reader: "
               f"feed rows={len(feed)}, summary={summ}")

        bad = dict(event, event_id=uuid.uuid4(), task_id=reader_task)
        try:
            reader.insert(tch.TABLE, [[bad[c] for c in EVENT_COLUMNS]], column_names=EVENT_COLUMNS,
                          column_type_names=[t for _, t in tch.schema_columns()])
            refused = ""
        except Exception as exc:
            refused = _refusal(exc) or f"unexpected error {tch.describe_error(exc, redact)}"
        leaked = admin.query(f"SELECT count() FROM {cfg.table} WHERE task_id = {{task:String}}",
                             parameters={"task": reader_task}).result_rows[0][0]
        record(refused.startswith("ClickHouse") and leaked == 0,
               f"reader '{cfg.reader_user}' cannot insert ({refused or 'INSERT WAS ACCEPTED'}; rows written: {leaked})")

        writer = tch.connect(cfg.endpoint, cfg.writer_user, cfg.writer_password, client_name="hold-setup-check")
        try:
            writer.query("SELECT count() FROM hold_events")
            denied = ""
        except Exception as exc:
            denied = _refusal(exc) or f"unexpected error {tch.describe_error(exc, redact)}"
        record(denied.startswith("ClickHouse"),
               f"writer '{cfg.writer_user}' cannot select ({denied or 'SELECT WAS ALLOWED'})")
    finally:
        for client in (reader, writer):
            if client is not None:
                client.close()


def _delete_probe_rows(admin, table: str, tasks, record, redact: tch.Redactor) -> None:
    params = {"a": tasks[0], "b": tasks[1]}
    where = "task_id IN (%(a)s, %(b)s)"  # bound client-side to escaped string literals

    def count() -> int:
        return admin.query(f"SELECT count() FROM {table} WHERE task_id IN ({{a:String}}, {{b:String}})",
                           parameters=params).result_rows[0][0]

    try:
        try:
            admin.command(f"DELETE FROM {table} WHERE {where}", parameters=params)
        except Exception:  # servers without lightweight DELETE: synchronous mutation instead
            admin.command(f"ALTER TABLE {table} DELETE WHERE {where}", parameters=params,
                          settings={"mutations_sync": 2})
        remaining = poll(count, lambda n: n == 0)
        record(remaining == 0, f"admin deleted the probe rows ({remaining} remaining)")
    except Exception as exc:
        record(False, f"admin delete of probe rows for {tasks[0]}: {tch.describe_error(exc, redact)}")


# --------------------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="run the checks only; make no changes")
    args = parser.parse_args(argv)

    loaded = sorted(n for n in load_env() if n.startswith("CLICKHOUSE_"))
    redact = tch.Redactor()  # built after load_env so it knows every password value

    def out(message: str) -> None:
        print(redact(message), flush=True)

    def err(message: str) -> None:
        print(redact(message), file=sys.stderr, flush=True)

    out(".env: " + ("set " + ", ".join(loaded) if loaded else "no new CLICKHOUSE_* values (file absent, "
                    "or already set in the environment)"))
    try:
        cfg = load_config()
    except tch.ConfigError as exc:
        err(f"CONFIG ERROR: {exc}")
        return EXIT_CONFIG
    try:
        import clickhouse_connect  # noqa: F401
    except ImportError:
        err("CONFIG ERROR: clickhouse-connect is not installed for this Python (pip install clickhouse-connect)")
        return EXIT_CONFIG

    out(f"ClickHouse: {cfg.endpoint.describe()} | mode: {'check only' if args.check else 'setup + check'}")
    try:
        admin = tch.connect(cfg.endpoint, cfg.admin_user, cfg.admin_password, client_name="hold-setup",
                            database=None)
    except Exception as exc:
        err(f"ERROR: cannot connect as admin user '{cfg.admin_user}': {tch.describe_error(exc, redact)}")
        err("       Check CLICKHOUSE_HOST/PORT, that the Cloud service is awake, and that this machine's "
            "IP is on the service's IP access list.")
        return EXIT_FAIL
    out(f"connected as admin '{cfg.admin_user}' (ClickHouse {admin.server_version})")
    try:
        if not args.check:
            setup(cfg, admin, out, redact)
        ok = run_checks(cfg, admin, out, redact)
    except Exception as exc:
        err(f"ERROR: {tch.describe_error(exc, redact)}")
        return EXIT_FAIL
    finally:
        admin.close()
    return EXIT_OK if ok else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
