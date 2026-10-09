"""Dashboard tests (stdlib unittest; run by harness.py).

- The REAL ui/dashboard.py process, started on an ephemeral port in --jsonl mode against an
  audit log written by a REAL Gateway (tests.test_telemetry.gateway_scenario): JSON shape and
  values of /api/events, /api/summary, /api/health, the page's CSP and credential-free HTML,
  Host-header refusal, and that hostile target/reason strings are delivered as data and
  rendered with textContent only.
- The REAL process in ClickHouse mode without reader credentials: every /api/* answers 503
  with the reason; the page still loads.
- In-process with a FAKE ClickHouse client (labeled): ClickHouse rows are shaped like the
  JSONL rows, the SQL text is constant and the task travels only as a bound parameter,
  and errors are redacted.
- Live, only when .env has the reader credentials (otherwise SKIPPED): /api/health is ok.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import queue
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.env import load_env  # noqa: E402
from telemetry import clickhouse as tch  # noqa: E402
from tests.test_telemetry import (  # noqa: E402
    OTHER_TASK, PAYLOAD_PATH, PAYLOAD_TOOL, SCENARIO, SENTINEL_PASSWORD, TASK, gateway_scenario,
)
from ui import dashboard  # noqa: E402

DASHBOARD = REPO_ROOT / "ui" / "dashboard.py"
LOCAL_LABEL = "LOCAL AUDIT LOG (not ClickHouse)"
EVENT_FIELDS = {"ts", "agent_id", "tool_name", "sink", "target", "decision", "reason", "exec_status", "gate_us"}
START_TIMEOUT = 30


def _env(**overrides):
    """Process env with every CLICKHOUSE_* set explicitly, so load_env cannot add real ones."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLICKHOUSE_")}
    for name in ("HOST", "PORT", "SECURE", "DATABASE", "USER", "PASSWORD", "READER_USER", "READER_PASSWORD",
                 "ADMIN_USER", "ADMIN_PASSWORD"):
        env[f"CLICKHOUSE_{name}"] = ""
    env.update(overrides)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def request(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def get_json(port, path):
    status, headers, body = request(port, path)
    return status, headers, json.loads(body)


class DashboardProcess:
    """ui/dashboard.py as a real child process on an ephemeral port."""

    def __init__(self, args, env, workdir: Path):
        self.stderr_path = workdir / f"dashboard-{len(list(workdir.iterdir()))}.stderr"
        self._stderr = self.stderr_path.open("w", encoding="utf-8")
        self.proc = subprocess.Popen([sys.executable, str(DASHBOARD), "--port", "0", *args], cwd=str(REPO_ROOT),
                                     env=env, stdout=subprocess.PIPE, stderr=self._stderr, text=True,
                                     encoding="utf-8")
        lines: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=lambda: lines.put(self.proc.stdout.readline()), daemon=True).start()
        try:
            first = lines.get(timeout=START_TIMEOUT)
        except queue.Empty:
            self.stop()
            raise AssertionError(f"dashboard did not start within {START_TIMEOUT} s: {self.stderr()}")
        match = re.search(r"http://127\.0\.0\.1:(\d+)/", first)
        if not match:
            self.stop()
            raise AssertionError(f"unexpected first line {first!r}; stderr: {self.stderr()}")
        self.port = int(match.group(1))
        self.banner = first

    def stderr(self) -> str:
        self._stderr.flush()
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")

    def stop(self):
        if self.proc.poll() is None:
            if os.name == "nt":
                # .venv\Scripts\python.exe is a launcher whose child is the real interpreter;
                # terminate() would only end the launcher. Kill the whole tree.
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"], capture_output=True,
                               timeout=30)
            else:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self._stderr.close()
        deadline = time.monotonic() + 15  # until the interpreter is gone and the port is closed
        while hasattr(self, "port") and time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
            except OSError:
                break
            time.sleep(0.1)


def cleanup(tmp: tempfile.TemporaryDirectory):
    """Windows may hold a dead child's file handles for a moment; retry briefly."""
    for _ in range(50):
        try:
            tmp.cleanup()
            return
        except PermissionError:
            time.sleep(0.2)
    tmp.cleanup()


def _inline_hash(html: str, tag: str) -> str:
    body = re.search(rf"<{tag}>(.*?)</{tag}>", html, re.DOTALL).group(1)
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"


class JsonlModeProcess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        cls.audit, cls.events, _ = gateway_scenario(base)
        cls.lines = [json.loads(line) for line in cls.audit.read_text(encoding="utf-8").splitlines()]
        logs = base / "logs"
        logs.mkdir()
        cls.server = DashboardProcess(["--jsonl", str(cls.audit), "--task", TASK],
                                      _env(CLICKHOUSE_READER_USER="hold_reader",
                                           CLICKHOUSE_READER_PASSWORD=SENTINEL_PASSWORD), logs)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cleanup(cls._tmp)

    def expected_events(self, task=TASK):
        rows = [line for line in self.lines if line["task_id"] == task]
        return [{
            "ts": datetime.fromisoformat(r["ts"]).astimezone(timezone.utc).isoformat(),
            "agent_id": r["agent_id"],
            "tool_name": r["tool_name"], "sink": r["sink"], "target": r["target"],
            "decision": r["decision"], "reason": r["reason"], "exec_status": r["exec_status"],
            "gate_us": round(r["gate_latency_ns"] / 1000, 1),
        } for r in reversed(rows)]

    def test_banner_names_the_local_source(self):
        self.assertIn(LOCAL_LABEL, self.server.banner)

    def test_events_are_the_audit_log_newest_first(self):
        status, headers, body = get_json(self.server.port, f"/api/events?task={TASK}&limit=200")
        self.assertEqual(status, 200, body)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(body["source"], "jsonl")
        self.assertEqual(body["source_label"], LOCAL_LABEL)
        self.assertEqual((body["task"], body["limit"]), (TASK, 200))
        self.assertEqual(len(body["events"]), len(SCENARIO))
        for event in body["events"]:
            self.assertEqual(set(event), EVENT_FIELDS)
        self.assertEqual(body["events"], self.expected_events())
        self.assertEqual([e["decision"] for e in reversed(body["events"])], [d for _, _, d, _ in SCENARIO])

    def test_limit_keeps_the_newest(self):
        status, _, body = get_json(self.server.port, f"/api/events?task={TASK}&limit=3")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["events"], self.expected_events()[:3])
        status, _, body = get_json(self.server.port, f"/api/events?task={TASK}")
        self.assertEqual((status, body["limit"]), (200, 50))

    def test_bad_parameters_are_400(self):
        for query in ("limit=5", f"task={TASK}&limit=0", f"task={TASK}&limit=201", f"task={TASK}&limit=abc",
                      f"task={TASK}&limit=-1", f"task={TASK}&task=x", "task=", "task=a%01b", f"task={'x' * 201}"):
            for route in ("/api/events", "/api/summary"):
                if route == "/api/summary" and "limit" in query:
                    continue
                status, _, body = get_json(self.server.port, f"{route}?{query}")
                self.assertEqual(status, 400, (route, query, body))
                self.assertEqual(body["source_label"], LOCAL_LABEL)

    def test_summary_counts_and_percentiles_come_from_the_real_latencies(self):
        status, _, body = get_json(self.server.port, f"/api/summary?task={TASK}")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["source_label"], LOCAL_LABEL)
        by_decision = {row["decision"]: row for row in body["summary"]}
        self.assertEqual({d: r["calls"] for d, r in by_decision.items()}, {"ALLOW": 4, "DENY": 5})
        for decision, row in by_decision.items():
            ns = [line["gate_latency_ns"] for line in self.lines
                  if line["task_id"] == TASK and line["decision"] == decision]
            # Independent computation: linear interpolation at (n-1)p ("inclusive").
            p50 = statistics.quantiles(ns, n=100, method="inclusive")[49] / 1000
            p95 = statistics.quantiles(ns, n=100, method="inclusive")[94] / 1000
            self.assertAlmostEqual(row["p50_us"], p50, delta=0.051, msg=decision)
            self.assertAlmostEqual(row["p95_us"], p95, delta=0.051, msg=decision)
            self.assertLessEqual(row["p50_us"], row["p95_us"])

    def test_task_filter(self):
        _, _, body = get_json(self.server.port, f"/api/events?task={OTHER_TASK}")
        self.assertEqual(body["events"], self.expected_events(OTHER_TASK))
        self.assertEqual(len(body["events"]), 1)
        _, _, body = get_json(self.server.port, "/api/summary?task=no-such-task")
        self.assertEqual(body["summary"], [])
        _, _, body = get_json(self.server.port, "/api/events?task=no-such-task")
        self.assertEqual(body["events"], [])

    def test_health_reports_the_local_source(self):
        status, _, body = get_json(self.server.port, "/api/health")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["clickhouse"], "not_used")
        self.assertEqual(body["jsonl"], "ok")
        self.assertEqual(body["source"], "jsonl")
        self.assertEqual(body["source_label"], LOCAL_LABEL)
        self.assertEqual(body["default_task"], TASK)
        self.assertIn(f"{len(self.lines)} events, 0 unreadable lines", body["detail"])

    def test_page_has_a_strict_csp_and_no_credentials(self):
        status, headers, raw = request(self.server.port, "/")
        html = raw.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn(f"script-src {_inline_hash(html, 'script')};", csp)
        self.assertIn(f"style-src {_inline_hash(html, 'style')};", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe", csp)
        for forbidden in (SENTINEL_PASSWORD, "PASSWORD", "CLICKHOUSE_", "not-a-real-secret", PAYLOAD_PATH,
                          PAYLOAD_TOOL):
            self.assertNotIn(forbidden, html)
        self.assertNotRegex(html, r"<script[^>]*\bsrc=|<link[^>]*stylesheet")  # nothing external

    def test_page_renders_api_strings_with_textcontent_only(self):
        _, _, raw = request(self.server.port, "/")
        script = re.search(r"<script>(.*?)</script>", raw.decode("utf-8"), re.DOTALL).group(1)
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
                     "srcdoc", "DOMParser", "createContextualFragment"):
            self.assertNotIn(sink, script)
        self.assertIn("node.textContent = String(text)", script)  # the single writer of API text
        for field in ("tool_name", "sink", "target", "decision", "reason", "exec_status"):
            self.assertRegex(script, rf'make\("td", e\.{field}\b')
        self.assertEqual(len(re.findall(r"setAttribute\(", script)), 1)
        self.assertIn('setAttribute("datetime", String(e.ts))', script)

    def test_hostile_strings_arrive_verbatim_as_json_data(self):
        _, headers, body = get_json(self.server.port, f"/api/events?task={TASK}")
        targets = {e["target"] for e in body["events"]}
        self.assertIn(PAYLOAD_PATH, targets)
        self.assertIn(PAYLOAD_TOOL, targets)
        self.assertTrue(any(PAYLOAD_TOOL in e["reason"] for e in body["events"]))
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_no_response_contains_the_reader_password(self):
        for path in ("/", "/api/health", f"/api/events?task={TASK}", f"/api/summary?task={TASK}", "/nope"):
            _, headers, body = request(self.server.port, path)
            self.assertNotIn(SENTINEL_PASSWORD.encode(), body + json.dumps(headers).encode(), path)

    def test_foreign_host_header_is_refused(self):
        status, _, body = request(self.server.port, "/api/health", {"Host": "rebind.example"})
        self.assertEqual(status, 403, body)
        status, _, _ = request(self.server.port, "/", {"Host": f"localhost:{self.server.port}"})
        self.assertEqual(status, 200)

    def test_unknown_path_is_404(self):
        status, _, _ = request(self.server.port, "/api/../etc/passwd")
        self.assertEqual(status, 404)


class ClickHouseModeWithoutReaderCredentials(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.server = DashboardProcess([], _env(CLICKHOUSE_READER_PASSWORD=SENTINEL_PASSWORD), Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cleanup(cls._tmp)

    def test_api_answers_503_with_the_reason(self):
        for path in (f"/api/events?task={TASK}", f"/api/summary?task={TASK}"):
            status, _, body = get_json(self.server.port, path)
            self.assertEqual(status, 503, body)
            self.assertEqual(body["source"], "clickhouse")
            self.assertEqual(body["source_label"], "ClickHouse (reader not configured)")
            self.assertIn("not configured", body["error"])
            self.assertIn("CLICKHOUSE_HOST", body["error"])
            self.assertIn("CLICKHOUSE_READER_USER", body["error"])
            self.assertNotIn("CLICKHOUSE_READER_PASSWORD", body["error"])  # that one is set
        status, _, body = get_json(self.server.port, "/api/health")
        self.assertEqual(status, 503, body)
        self.assertEqual(body["clickhouse"], "error")
        self.assertIn("not configured", body["detail"])

    def test_page_still_loads_and_nothing_leaks(self):
        status, _, _ = request(self.server.port, "/")
        self.assertEqual(status, 200)
        for path in ("/", "/api/health", f"/api/events?task={TASK}"):
            _, _, body = request(self.server.port, path)
            self.assertNotIn(SENTINEL_PASSWORD.encode(), body)
        self.assertIn("WARNING: ClickHouse reader is not configured", self.server.stderr())
        self.assertNotIn(SENTINEL_PASSWORD, self.server.stderr() + self.server.banner)


class FakeClickHouseResult:
    def __init__(self, rows):
        self.rows = rows

    def named_results(self):
        return iter(self.rows)


class FakeClickHouseClient:
    """FAKE clickhouse-connect client: records (sql, parameters) and returns canned rows.
    Proves the dashboard's SQL text, parameter binding and JSON shaping only."""

    def __init__(self, fail_with=None):
        self.calls, self.fail_with, self.closed = [], fail_with, False

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        if self.fail_with:
            raise self.fail_with
        if sql == tch.LIVE_FEED_SQL:
            return FakeClickHouseResult([{
                "ts": datetime(2026, 10, 9, 18, 0, 1, 250000),  # naive UTC, as clickhouse-connect returns it
                "tool_name": "read_file", "sink": "FS_READ", "target": PAYLOAD_PATH, "decision": "DENY",
                "reason": "protected", "exec_status": "not_run", "gate_us": 12.3}] * 3)
        if sql == tch.SUMMARY_SQL:
            return FakeClickHouseResult([{"decision": "DENY", "calls": 3, "p50_us": 12.3, "p95_us": 12.3},
                                         {"decision": "ALLOW", "calls": 2, "p50_us": 30.0, "p95_us": 41.5}])
        return FakeClickHouseResult([{"version": "FAKE", "rows": 5}])

    def close(self):
        self.closed = True


class ClickHouseSourceWithFakeClient(unittest.TestCase):
    ENV = {"CLICKHOUSE_HOST": "fake.invalid", "CLICKHOUSE_READER_USER": "hold_reader",
           "CLICKHOUSE_READER_PASSWORD": SENTINEL_PASSWORD}

    def serve(self, client):
        self.connects = []

        def connect(endpoint, user, password, **kwargs):
            self.connects.append((endpoint, user, kwargs))
            return client

        source = dashboard.ClickHouseSource(self.ENV, connect=connect)
        server = dashboard.make_server(source, TASK, port=0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_rows_are_shaped_like_jsonl_rows_and_the_task_is_only_a_parameter(self):
        client = FakeClickHouseClient()
        port = self.serve(client)
        hostile = "x' OR 1=1 --"
        status, _, body = get_json(port, "/api/events?task=" + "x%27%20OR%201%3D1%20--" + "&limit=2")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["source"], "clickhouse")
        self.assertEqual(body["source_label"], "ClickHouse default.hold_events (read-only user)")
        self.assertEqual(body["events"], [{
            "ts": "2026-10-09T18:00:01.250000+00:00", "tool_name": "read_file", "sink": "FS_READ",
            "target": PAYLOAD_PATH, "decision": "DENY", "reason": "protected", "exec_status": "not_run",
            "gate_us": 12.3}] * 2)
        status, _, body = get_json(port, "/api/summary?task=" + "x%27%20OR%201%3D1%20--")
        self.assertEqual([r["decision"] for r in body["summary"]], ["ALLOW", "DENY"])
        self.assertEqual(client.calls, [(tch.LIVE_FEED_SQL, {"task": hostile}), (tch.SUMMARY_SQL, {"task": hostile})])
        (endpoint, user, kwargs), = self.connects  # one lazily created, reused client
        self.assertEqual((endpoint.host, endpoint.port, endpoint.secure, user), ("fake.invalid", 8443, True, "hold_reader"))
        self.assertEqual(kwargs["show_clickhouse_errors"], "scrub")

    def test_errors_are_502_redacted_and_reconnect(self):
        client = FakeClickHouseClient(fail_with=RuntimeError(f"auth failed for password {SENTINEL_PASSWORD}"))
        port = self.serve(client)
        status, _, raw = request(port, f"/api/events?task={TASK}")
        self.assertEqual(status, 502)
        self.assertNotIn(SENTINEL_PASSWORD.encode(), raw)
        self.assertIn(b"<redacted>", raw)
        self.assertTrue(client.closed)
        status, _, body = get_json(port, "/api/health")
        self.assertEqual((status, body["clickhouse"]), (502, "error"))
        self.assertEqual(len(self.connects), 2, "a failed client is dropped and the next request reconnects")


class LiveDashboard(unittest.TestCase):
    """Needs a real ClickHouse; skipped (never passed) when .env lacks the reader credentials."""

    def test_clickhouse_mode_health_is_ok(self):
        loaded = load_env()
        try:
            absent = tch.missing(tch.READER_VARS)
        finally:
            for name in loaded:
                os.environ.pop(name, None)
        if absent:
            self.skipTest("live ClickHouse reader not configured (missing or blank: " + ", ".join(absent)
                          + "); fill .env and run scripts/setup_clickhouse.py, then re-run")
        tmp = tempfile.TemporaryDirectory()
        server = DashboardProcess([], dict(os.environ), Path(tmp.name))
        try:
            status, _, body = get_json(server.port, "/api/health")
            self.assertEqual((status, body["clickhouse"]), (200, "ok"), body)
            status, _, body = get_json(server.port, f"/api/summary?task={TASK}")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["source"], "clickhouse")
        finally:
            server.stop()
            cleanup(tmp)


if __name__ == "__main__":
    unittest.main()
