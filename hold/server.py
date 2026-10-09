"""
HOLD MCP stdio server: exposes `read_file`, `write_file` and `fetch_url` through the
official MCP Python SDK (FastMCP, mcp 1.29.0) and routes every `tools/call` to
`Gateway.call` in `hold/core.py`.

    python -m hold.server          # speaks MCP on stdin/stdout

Configuration (environment; `.env` at the repo root is loaded first and never overrides
variables that are already set):
    HOLD_RECEIPT    required, absolute path to the Intent Receipt (outside the workspace)
    HOLD_AUDIT_LOG  absolute path of the JSONL audit file (default <repo>/hold_audit.jsonl)
    HOLD_AGENT_ID   agent_id written into every event (default "claude-code")
    HOLD_SEMGREP    "0" disables the Semgrep write scan (hold/scan.py); anything else keeps it on
    CLICKHOUSE_*    see SPEC.md 5.3; events also go to ClickHouse when CLICKHOUSE_HOST is set

stdout is the protocol channel. Diagnostics go to stderr, and once the stdio transport
holds the real stdout, `sys.stdout` is pointed at stderr so a stray print() cannot corrupt
the JSON-RPC stream.

How results reach the client (checked against the installed SDK source):
- Each tool returns `mcp.types.CallToolResult`. With that return annotation FastMCP builds
  no output schema and passes the object through unchanged, so `isError` is exactly
  `ToolResult.is_error` and the text is HOLD's own reason. These are tool results, not
  JSON-RPC protocol errors (SPEC.md 3).
- `HoldMCP.call_tool` sends the raw tool name and raw arguments straight to the gateway.
  FastMCP's own argument handling (which drops unknown keys and answers unknown tool names
  itself) is bypassed, so unknown tools and extra, missing or mistyped arguments are
  DENYed by the gate and audited like every other call.
- `Gateway.call` runs in a worker thread (`anyio.to_thread.run_sync`), so a slow Semgrep
  write scan does not stall the session: pings and other calls are answered meanwhile.
- If `Gateway.call` itself raises, the client gets "HOLD denied <tool>: internal error;
  failing closed", stderr gets the exception type only, and a DENY event is emitted.
"""

import os
import shutil
import sys
import uuid
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, List, Tuple

import anyio.to_thread
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from hold.core import (SINKS, UNOFFERED_SINKS, ClickHouseWriter, Gateway, IntentReceipt,
                       JsonlWriter, Telemetry)
from hold.env import REPO_ROOT, load_env

DEFAULT_AUDIT_LOG = REPO_ROOT / "hold_audit.jsonl"
DEFAULT_AGENT_ID = "claude-code"
TOOL_NAMES = ("read_file", "write_file", "fetch_url")

INSTRUCTIONS = (
    "HOLD is a task-scoped tool gateway. File paths are relative to the task workspace "
    "(for example 'src/flask/app.py'). Only the files and hosts the developer approved "
    "for this task can be used; any other call returns an error that states the reason."
)


def _log(message: str) -> None:
    print(f"[hold] {message}", file=sys.stderr, flush=True)


def _is_within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(root)
        return True
    except ValueError:
        return False


def build_gateway(receipt_path: Path, audit_log: Path, write_scanner: Any = None, *,
                  agent_id: str = DEFAULT_AGENT_ID) -> Tuple[Gateway, Telemetry]:
    """Load the receipt once and wire the gateway to its telemetry writers.

    Raises on an invalid receipt or audit-log location, so the caller can refuse to serve.
    `write_scanner` is passed to `Gateway` only when given. If the installed `Gateway` does
    not accept it, construction fails (TypeError) instead of silently running unscanned.
    """
    receipt = IntentReceipt.load(Path(receipt_path))
    audit_log = Path(audit_log)
    # The agent must not be able to reach its own policy or its audit trail.
    if _is_within(receipt_path, receipt.workspace_root):
        raise ValueError(f"the receipt must live outside workspace_root ({receipt.workspace_root})")
    if _is_within(audit_log, receipt.workspace_root):
        raise ValueError(f"the audit log must live outside workspace_root ({receipt.workspace_root})")
    if not audit_log.parent.is_dir():
        raise ValueError(f"audit log directory does not exist: {audit_log.parent}")
    with audit_log.open("a", encoding="utf-8"):  # fail now, not on the telemetry thread
        pass

    writers: List[Callable[[List[Dict[str, Any]]], None]] = [JsonlWriter(audit_log)]
    if ClickHouseWriter.configured():
        writers.append(ClickHouseWriter())
    telemetry = Telemetry(writers)
    kwargs: Dict[str, Any] = {"agent_id": agent_id}
    if write_scanner is not None:
        kwargs["write_scanner"] = write_scanner
    try:
        gateway = Gateway(receipt, telemetry, **kwargs)
    except BaseException:
        telemetry.close()
        raise
    return gateway, telemetry


@asynccontextmanager
async def _divert_stray_stdout(_app: FastMCP) -> AsyncIterator[None]:
    """FastMCP runs this lifespan inside `stdio_server()`, which has already wrapped the
    real stdout buffer for the protocol. Re-point `sys.stdout` at stderr so a stray print()
    from any code in this process cannot corrupt the JSON-RPC stream."""
    sys.stdout = sys.stderr
    yield


def _to_result(text: str, is_error: bool) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=is_error)


class HoldMCP(FastMCP):
    """FastMCP whose `tools/call` goes straight to `Gateway.call` with the raw arguments."""

    def __init__(self, gateway: Gateway, **kwargs: Any):
        with warnings.catch_warnings():
            # mcp 1.29.0 + pydantic-settings emit a cosmetic forward-reference warning here.
            warnings.filterwarnings("ignore", message="Field 'lifespan' has an incomplete definition")
            super().__init__(**kwargs)
        self.gateway = gateway

    def run_gateway(self, tool: Any, args: Any, request_id: str = "") -> CallToolResult:
        try:
            result = self.gateway.call(tool, args, request_id=request_id)
            return _to_result(result.text, result.is_error)
        except Exception as exc:  # fail closed; the message may hold content, so drop it
            name = str(tool)[:80]
            _log(f"internal error while handling {name!r}: {type(exc).__name__}; failing closed")
            self._audit_internal_error(name, type(exc).__name__, request_id)
            return _to_result(f"HOLD denied {name}: internal error; failing closed", True)

    def _audit_internal_error(self, tool: str, exc_type: str, request_id: str) -> None:
        """Best-effort DENY event for a call the gateway could not finish. Never raises.
        exec_status is "error", not "not_run": once Gateway.call has raised, HOLD cannot
        vouch for how far the call got."""
        try:
            receipt = self.gateway.receipt
            self.gateway.telemetry.emit({
                "event_id": uuid.uuid4(),
                "ts": datetime.now(timezone.utc),
                "task_id": receipt.task_id,
                "agent_id": self.gateway.agent_id,
                "request_id": str(request_id),
                "tool_name": tool,
                "sink": SINKS.get(tool) or UNOFFERED_SINKS.get(tool, "UNKNOWN_TOOL"),
                "target": "",
                "decision": "DENY",
                "reason": f"internal error ({exc_type}); failing closed",
                "exec_status": "error",
                "gate_latency_ns": 0,
                "intent_digest": receipt.digest,
            })
        except Exception:
            pass

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:  # type: ignore[override]
        try:
            request_id = self.get_context().request_id
        except Exception:
            request_id = ""
        # Blocking file and network I/O runs off the event loop. Not abandoned on cancel,
        # so the decision is always emitted before the server shuts down.
        return await anyio.to_thread.run_sync(self.run_gateway, name, arguments, request_id)


def create_server(gateway: Gateway) -> HoldMCP:
    """Register the three tools. Their signatures and docstrings become the schemas and
    descriptions in `tools/list`; calls are dispatched by `HoldMCP.call_tool`."""
    mcp = HoldMCP(gateway, name="hold", instructions=INSTRUCTIONS, log_level="WARNING",
                  lifespan=_divert_stray_stdout)

    @mcp.tool()
    def read_file(path: str) -> CallToolResult:
        """Read a UTF-8 text file from the task workspace (at most 512 KiB).

        `path` is workspace-relative with '/' separators, e.g. 'src/flask/app.py'.
        Absolute paths, '..' and backslashes are refused. Only files approved for this
        task can be read; any other path returns an error that states the reason.
        """
        return mcp.run_gateway("read_file", {"path": path})

    write_doc = (
        "Replace the entire contents of a file in the task workspace with `content`.\n\n"
        "`path` is workspace-relative with '/' separators, e.g. 'src/flask/app.py'.\n"
        "Only files approved for writing in this task can be written; any other path\n"
        "returns an error that states the reason.")
    if gateway.write_scanner is not None:
        write_doc += ("\nPython content is scanned before it is written; a write that adds\n"
                      "network, process-execution or dynamic-code calls is refused with the finding.")

    @mcp.tool(description=write_doc)
    def write_file(path: str, content: str) -> CallToolResult:
        return mcp.run_gateway("write_file", {"path": path, "content": content})

    @mcp.tool()
    def fetch_url(url: str) -> CallToolResult:
        """HTTP GET a URL and return the response body as text (5 s timeout, no redirects).

        Only hosts approved for this task can be contacted; any other URL returns an
        error that states the reason.
        """
        return mcp.run_gateway("fetch_url", {"url": url})

    return mcp


def _log_scanner(scanner: Any) -> None:
    """Static status only (no subprocess): a real probe scan takes 6-25 s and would compete
    with the agent's first write. Run `hold.scan.probe()` before a demo instead."""
    if scanner is None:
        _log("*** WARNING: HOLD_SEMGREP=0: the Semgrep write scan is DISABLED. "
             "Writes are checked by the capability gate only. ***")
        return
    binary = getattr(scanner, "semgrep_bin", None)
    rules = getattr(scanner, "rules_path", None)
    found = bool(binary) and (os.path.isfile(binary) or shutil.which(binary) is not None)
    _log(f"write scan: Semgrep ON ({type(scanner).__name__}, binary={binary or 'not found'}, "
         f"rules={rules})")
    if not found or (rules is not None and not Path(rules).is_file()):
        _log("*** WARNING: Semgrep binary or rules missing: every scanned write will be DENIED "
             "(fail closed). ***")


def _config_error(message: str) -> int:
    _log(f"cannot start: {message}")
    return 2


def main() -> int:
    protocol_stdout = sys.stdout
    sys.stdout = sys.stderr  # nothing during startup may reach the protocol channel
    loaded = load_env()

    raw_receipt = os.environ.get("HOLD_RECEIPT", "").strip()
    if not raw_receipt:
        return _config_error("HOLD_RECEIPT is not set (absolute path to the Intent Receipt)")
    receipt_path = Path(raw_receipt)
    if not receipt_path.is_absolute():
        return _config_error(f"HOLD_RECEIPT must be an absolute path, got '{raw_receipt}'")
    if not receipt_path.is_file():
        return _config_error(f"HOLD_RECEIPT does not exist: {receipt_path}")
    audit_log = Path(os.environ.get("HOLD_AUDIT_LOG", "").strip() or DEFAULT_AUDIT_LOG)
    if not audit_log.is_absolute():
        return _config_error(f"HOLD_AUDIT_LOG must be an absolute path, got '{audit_log}'")
    agent_id = os.environ.get("HOLD_AGENT_ID", "").strip()[:64] or DEFAULT_AGENT_ID

    try:
        from hold.scan import write_scanner_from_env  # None only when HOLD_SEMGREP=0
        scanner = write_scanner_from_env()
    except Exception as exc:
        return _config_error(f"write scanner: {type(exc).__name__}: {exc}")
    try:
        gateway, telemetry = build_gateway(receipt_path, audit_log, write_scanner=scanner,
                                           agent_id=agent_id)
    except Exception as exc:
        return _config_error(f"invalid configuration: {type(exc).__name__}: {exc}")

    try:
        receipt = gateway.receipt
        writers = ", ".join(type(w).__name__ for w in telemetry.writers)
        _log(f".env variables loaded: {', '.join(sorted(loaded)) or 'none'}")
        _log(f"task={receipt.task_id} agent_id={agent_id} digest={receipt.digest[:16]}... "
             f"receipt={receipt_path}")
        _log(f"workspace={receipt.workspace_root} write={list(receipt.write)} "
             f"network_egress={receipt.network_egress} hosts={list(receipt.host_allowlist)}")
        _log(f"telemetry writers: {writers}; audit log: {audit_log}")
        _log_scanner(scanner)
        server = create_server(gateway)
        # The SDK's stdio transport wraps sys.stdout.buffer when it starts, so hand it the
        # real stdout; the lifespan diverts sys.stdout to stderr again right after.
        sys.stdout = protocol_stdout
        server.run("stdio")
    finally:
        sys.stdout = sys.stderr
        telemetry.close()
        _log(f"stopped; telemetry flushed (dropped={telemetry.dropped}, "
             f"writer_errors={telemetry.writer_errors})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
