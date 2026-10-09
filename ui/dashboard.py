#!/usr/bin/env python3
"""HOLD live dashboard: a stdlib HTTP server on 127.0.0.1 that serves ui/index.html and a
small JSON API over the decision log.

    python ui/dashboard.py [--port 8765] [--task hold-demo-001]
        ClickHouse mode: connects as CLICKHOUSE_READER_USER (readonly=1, SELECT on
        hold_events only) and runs only the parameterized queries in telemetry/clickhouse.py.
    python ui/dashboard.py --jsonl hold_audit.jsonl [--port 8765]
        Fallback: reads the gateway's local JSONL audit log. Every API response and the
        page say "LOCAL AUDIT LOG (not ClickHouse)".

Endpoints:
    GET /                                       ui/index.html (static; no credentials in it)
    GET /api/events?task=<id>&limit=<1..200>    newest decisions first (default limit 50)
    GET /api/summary?task=<id>                  per decision: calls, p50_us, p95_us (gate latency)
    GET /api/health                             {"clickhouse": "ok" | "error" | "not_used", "detail": ...}

Without reader credentials the server still starts and every /api/* call answers 503 with
the reason. Credentials stay in this process; none are ever sent to the browser.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

UI_DIR = Path(__file__).resolve().parent
REPO_ROOT = UI_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.env import load_env  # noqa: E402
from telemetry import clickhouse as tch  # noqa: E402

INDEX_PATH = UI_DIR / "index.html"
DEFAULT_PORT = 8765
DEFAULT_TASK = "hold-demo-001"
DEFAULT_LIMIT = 50
MAX_LIMIT = tch.MAX_EVENTS
MAX_TASK_LEN = 200
LOCAL_LABEL = "LOCAL AUDIT LOG (not ClickHouse)"
HEALTH_SQL = "SELECT version() AS version, count() AS rows FROM hold_events"


class BadRequest(Exception):
    """Invalid query parameters (400)."""


class Unavailable(Exception):
    """The data source is not configured (503)."""


class UpstreamError(Exception):
    """The data source failed to answer (502)."""


def iso_utc(value: Any) -> str:
    """ISO-8601 UTC string. Naive datetimes from ClickHouse are UTC (the column is UTC)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def quantile(sorted_values: List[int], q: float) -> float:
    """Linear interpolation at rank (n - 1) * q. Used only for the JSONL fallback; ClickHouse
    mode uses ClickHouse's own quantile()."""
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


# --------------------------------------------------------------------------------------
# Data sources
# --------------------------------------------------------------------------------------

class JsonlSource:
    """Reads the gateway's JSONL audit log (hold.core.JsonlWriter). Re-reads the file only
    when its size or mtime changes. Lines that do not parse are skipped and counted."""

    name = "jsonl"
    label = LOCAL_LABEL
    problem: Optional[str] = None

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._key: Optional[Tuple[int, int]] = None
        self._events: List[Dict[str, Any]] = []
        self._skipped = 0

    def meta(self) -> Dict[str, Any]:
        return {"source": self.name, "source_label": self.label, "audit_log": str(self.path)}

    def _load(self) -> Tuple[List[Dict[str, Any]], int, bool]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return [], 0, False
        key = (stat.st_mtime_ns, stat.st_size)
        with self._lock:
            if key != self._key:
                events, skipped = [], 0
                with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        try:
                            raw = json.loads(line)
                            ts = datetime.fromisoformat(str(raw["ts"]))
                            events.append({
                                "seq": len(events),
                                "task_id": str(raw["task_id"]),
                                "ts": ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc),
                                "tool_name": str(raw["tool_name"]),
                                "sink": str(raw["sink"]),
                                "target": str(raw["target"]),
                                "decision": str(raw["decision"]),
                                "reason": str(raw["reason"]),
                                "exec_status": str(raw["exec_status"]),
                                "gate_latency_ns": int(raw["gate_latency_ns"]),
                            })
                        except (ValueError, KeyError, TypeError):
                            skipped += 1  # e.g. a line still being written
                self._key, self._events, self._skipped = key, events, skipped
            return self._events, self._skipped, True

    def _for_task(self, task: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        events, _, exists = self._load()
        warning = None if exists else f"audit log not found yet: {self.path}"
        return [e for e in events if e["task_id"] == task], warning

    def events(self, task: str, limit: int) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        rows, warning = self._for_task(task)
        rows.sort(key=lambda e: (e["ts"], e["seq"]), reverse=True)
        return [{
            "ts": iso_utc(e["ts"]), "tool_name": e["tool_name"], "sink": e["sink"],
            "target": e["target"], "decision": e["decision"], "reason": e["reason"],
            "exec_status": e["exec_status"], "gate_us": round(e["gate_latency_ns"] / 1000, 1),
        } for e in rows[:limit]], warning

    def summary(self, task: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        rows, warning = self._for_task(task)
        by_decision: Dict[str, List[int]] = {}
        for e in rows:
            by_decision.setdefault(e["decision"], []).append(e["gate_latency_ns"])
        out = []
        for decision in sorted(by_decision):
            ns = sorted(by_decision[decision])
            out.append({"decision": decision, "calls": len(ns),
                        "p50_us": round(quantile(ns, 0.5) / 1000, 1),
                        "p95_us": round(quantile(ns, 0.95) / 1000, 1)})
        return out, warning

    def health(self) -> Tuple[int, Dict[str, Any]]:
        events, skipped, exists = self._load()
        if not exists:
            return 200, {"clickhouse": "not_used", "jsonl": "missing",
                         "detail": f"audit log not found yet: {self.path}"}
        return 200, {"clickhouse": "not_used", "jsonl": "ok",
                     "detail": f"reading {self.path}: {len(events)} events, {skipped} unreadable lines"}


class ClickHouseSource:
    """Queries ClickHouse as the read-only reader user. One lazily created client, shared
    under a lock; any failure drops it so the next request reconnects."""

    name = "clickhouse"

    def __init__(self, environ: Mapping[str, str] = os.environ, connect: Callable[..., Any] = tch.connect):
        self._connect = connect
        self._lock = threading.Lock()
        self._client = None
        self._redact = tch.Redactor(environ)
        self.endpoint: Optional[tch.Endpoint] = None
        self.problem: Optional[str] = None
        absent = tch.missing(tch.READER_VARS, environ)
        if absent:
            self.problem = ("ClickHouse reader is not configured: missing or blank " + ", ".join(absent)
                            + " in .env. Start with --jsonl <audit log> to show the local audit log instead.")
        else:
            try:
                self.endpoint = tch.Endpoint.from_env(environ)
            except tch.ConfigError as exc:
                self.problem = f"ClickHouse reader configuration is invalid: {exc}"
        self._user = environ.get("CLICKHOUSE_READER_USER", "").strip()
        self._password = environ.get("CLICKHOUSE_READER_PASSWORD", "")
        self.label = (f"ClickHouse {self.endpoint.database}.{tch.TABLE} (read-only user)" if self.endpoint
                      else "ClickHouse (reader not configured)")

    def meta(self) -> Dict[str, Any]:
        return {"source": self.name, "source_label": self.label}

    def _query(self, sql: str, parameters: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        if self.problem:
            raise Unavailable(self.problem)
        with self._lock:
            try:
                if self._client is None:
                    self._client = self._connect(
                        self.endpoint, self._user, self._password, client_name="hold-dashboard",
                        connect_timeout=5, send_receive_timeout=10, show_clickhouse_errors="scrub")
                return list(self._client.query(sql, parameters=parameters).named_results())
            except Exception as exc:
                client, self._client = self._client, None
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
                raise UpstreamError(f"ClickHouse query failed: {tch.describe_error(exc, self._redact)}") from None

    def events(self, task: str, limit: int) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        rows = self._query(tch.LIVE_FEED_SQL, {"task": task})[:limit]
        return [{
            "ts": iso_utc(r["ts"]), "tool_name": str(r["tool_name"]), "sink": str(r["sink"]),
            "target": str(r["target"]), "decision": str(r["decision"]), "reason": str(r["reason"]),
            "exec_status": str(r["exec_status"]), "gate_us": float(r["gate_us"]),
        } for r in rows], None

    def summary(self, task: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        rows = self._query(tch.SUMMARY_SQL, {"task": task})
        return sorted(({"decision": str(r["decision"]), "calls": int(r["calls"]),
                        "p50_us": float(r["p50_us"]), "p95_us": float(r["p95_us"])} for r in rows),
                      key=lambda r: r["decision"]), None

    def health(self) -> Tuple[int, Dict[str, Any]]:
        try:
            row = self._query(HEALTH_SQL)[0]
        except Unavailable as exc:
            return 503, {"clickhouse": "error", "detail": str(exc)}
        except UpstreamError as exc:
            return 502, {"clickhouse": "error", "detail": str(exc)}
        host = self.endpoint.host if self.endpoint else "?"
        return 200, {"clickhouse": "ok",
                     "detail": f"ClickHouse {row['version']} at {host}; {tch.TABLE} has {row['rows']} rows; "
                               "queried as the read-only user"}


# --------------------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------------------

_INLINE_RE = re.compile(r"<(script|style)>(.*?)</\1>", re.DOTALL)
_LIMIT_RE = re.compile(r"[0-9]{1,3}")


def content_security_policy(html: str) -> str:
    """Allow exactly the page's own inline <script> and <style> blocks (by SHA-256) and
    same-origin fetches; nothing else."""
    hashes: Dict[str, List[str]] = {"script": [], "style": []}
    for tag, body in _INLINE_RE.findall(html):
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
        hashes[tag].append(f"'sha256-{digest}'")
    script_src = " ".join(hashes["script"]) or "'none'"
    style_src = " ".join(hashes["style"]) or "'none'"
    return (f"default-src 'none'; script-src {script_src}; style-src {style_src}; connect-src 'self'; "
            "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def parse_task(query: Dict[str, List[str]]) -> str:
    values = query.get("task", [])
    if len(values) != 1:
        raise BadRequest("give exactly one task parameter, e.g. ?task=hold-demo-001")
    task = values[0]
    if not 0 < len(task) <= MAX_TASK_LEN or any(ord(c) < 32 or ord(c) == 127 for c in task):
        raise BadRequest(f"task must be 1 to {MAX_TASK_LEN} printable characters")
    return task


def parse_limit(query: Dict[str, List[str]]) -> int:
    values = query.get("limit", [str(DEFAULT_LIMIT)])
    if len(values) != 1 or not _LIMIT_RE.fullmatch(values[0]) or not 1 <= int(values[0]) <= MAX_LIMIT:
        raise BadRequest(f"limit must be an integer from 1 to {MAX_LIMIT}")
    return int(values[0])


class DashboardApp:
    def __init__(self, source: Any, default_task: str = DEFAULT_TASK, index_path: Path = INDEX_PATH):
        self.source = source
        self.default_task = default_task
        self.index_path = index_path

    def api(self, route: str, query: Dict[str, List[str]]) -> Tuple[int, Dict[str, Any]]:
        meta = self.source.meta()
        if route == "/api/health":
            status, payload = self.source.health()
            return status, {**payload, **meta, "default_task": self.default_task}
        try:
            task = parse_task(query)
            if route == "/api/events":
                limit = parse_limit(query)
                events, warning = self.source.events(task, limit)
                payload = {**meta, "task": task, "limit": limit, "events": events}
            else:
                summary, warning = self.source.summary(task)
                payload = {**meta, "task": task, "summary": summary}
        except BadRequest as exc:
            return 400, {**meta, "error": str(exc)}
        except Unavailable as exc:
            return 503, {**meta, "error": str(exc)}
        except UpstreamError as exc:
            return 502, {**meta, "error": str(exc)}
        if warning:
            payload["warning"] = warning
        return 200, payload


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "hold-dashboard"
    sys_version = ""
    API_ROUTES = ("/api/events", "/api/summary", "/api/health")

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        app: DashboardApp = self.server.app  # type: ignore[attr-defined]
        port = self.server.server_address[1]
        host = self.headers.get("Host", "").lower()
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            # Blocks DNS-rebinding pages from reading the API through another hostname.
            self._send_json(403, {"error": f"unexpected Host header; open http://127.0.0.1:{port}/"})
            return
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            self._send_index(app)
            return
        if url.path not in self.API_ROUTES:
            self._send_json(404, {"error": "not found"})
            return
        try:
            query = parse_qs(url.query, keep_blank_values=True, max_num_fields=20)
        except ValueError:
            self._send_json(400, {"error": "too many query parameters"})
            return
        self._send_json(*app.api(url.path, query))

    def _headers(self, status: int, content_type: str, length: int, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_index(self, app: DashboardApp) -> None:
        raw = app.index_path.read_bytes()
        csp = content_security_policy(raw.decode("utf-8"))
        self._headers(200, "text/html; charset=utf-8", len(raw),
                      {"Content-Security-Policy": csp, "X-Frame-Options": "DENY"})
        self.wfile.write(raw)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        if getattr(self.server, "verbose", False):
            super().log_message(format, *args)


def make_server(source: Any, default_task: str = DEFAULT_TASK, port: int = DEFAULT_PORT,
                verbose: bool = False) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    server.daemon_threads = True
    server.app = DashboardApp(source, default_task)  # type: ignore[attr-defined]
    server.verbose = verbose  # type: ignore[attr-defined]
    return server


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port on 127.0.0.1 (0 = any free port)")
    parser.add_argument("--task", default=DEFAULT_TASK, help="task shown when the URL has no ?task=")
    parser.add_argument("--jsonl", metavar="PATH", type=Path,
                        help="read this local JSONL audit log instead of ClickHouse (labeled on the page)")
    parser.add_argument("--verbose", action="store_true", help="log every request to stderr")
    args = parser.parse_args(argv)

    if args.jsonl:
        source: Any = JsonlSource(args.jsonl)
    else:
        load_env()
        source = ClickHouseSource()
    server = make_server(source, args.task, args.port, args.verbose)
    print(f"HOLD dashboard listening on http://127.0.0.1:{server.server_address[1]}/ "
          f"| source: {source.label}", flush=True)
    if source.problem:
        print(f"WARNING: {source.problem}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
