"""Shared ClickHouse helpers for HOLD telemetry.

- Parse `telemetry/schema.sql` (and the SQL block in SPEC.md 5.1) into (column, type) pairs.
- Read connection settings from the environment with the same rules as
  `hold.core.ClickHouseWriter`, and validate them before any network call.
- The dashboard queries from SPEC.md 5.4, parameterized with `{task:String}` only.
- Redact credential values from any text before it is printed or sent to a browser.

Stdlib only at import time; `clickhouse_connect` is imported lazily by `connect()`.
Nothing here prints or logs a credential value.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence, Tuple

TELEMETRY_DIR = Path(__file__).resolve().parent
REPO_ROOT = TELEMETRY_DIR.parent
SCHEMA_PATH = TELEMETRY_DIR / "schema.sql"
SPEC_PATH = REPO_ROOT / "SPEC.md"
TABLE = "hold_events"

# --------------------------------------------------------------------------------------
# Dashboard queries (SPEC.md 5.4). The only user input is {task:String}, bound server-side
# by clickhouse-connect as an HTTP query parameter (param_task), never formatted into SQL.
# The live feed always asks for MAX_EVENTS rows; the dashboard slices to the requested
# limit in Python so the SQL text is constant.
# --------------------------------------------------------------------------------------
MAX_EVENTS = 200
LIVE_FEED_SQL = """SELECT ts, tool_name, sink, target, decision, reason, exec_status,
       round(gate_latency_ns / 1000, 1) AS gate_us
FROM hold_events WHERE task_id = {task:String}
ORDER BY ts DESC LIMIT 200"""

SUMMARY_SQL = """SELECT decision, count() AS calls,
       round(quantile(0.5)(gate_latency_ns) / 1000, 1)  AS p50_us,
       round(quantile(0.95)(gate_latency_ns) / 1000, 1) AS p95_us
FROM hold_events WHERE task_id = {task:String}
GROUP BY decision"""

# Variables each role needs. "Missing" means unset or blank (a copied .env.example has blanks).
WRITER_VARS = ("CLICKHOUSE_HOST", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
READER_VARS = ("CLICKHOUSE_HOST", "CLICKHOUSE_READER_USER", "CLICKHOUSE_READER_PASSWORD")
ADMIN_VARS = ("CLICKHOUSE_HOST", "CLICKHOUSE_ADMIN_USER", "CLICKHOUSE_ADMIN_PASSWORD")


class ConfigError(ValueError):
    """A ClickHouse setting from the environment is missing or malformed."""


# --------------------------------------------------------------------------------------
# Schema parsing
# --------------------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"--[^\n]*")
_CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>[`\w.]+)\s*\((?P<body>.*)\)\s*ENGINE",
    re.IGNORECASE | re.DOTALL,
)
_COLUMN_RE = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<type>.+?)\s*,?$")
_ENUM_ITEM_RE = re.compile(r"'((?:[^'\\]|\\.)*)'\s*=\s*(-?\d+)")


def strip_sql_comments(sql: str) -> str:
    """Remove `--` comments. The schema has no `--` inside string literals."""
    return _COMMENT_RE.sub("", sql)


def sql_statements(sql: str) -> List[str]:
    """Executable statements in `sql`: comments removed, split on `;`, blanks dropped."""
    return [s.strip() for s in strip_sql_comments(sql).split(";") if s.strip()]


def table_columns(sql: str) -> List[Tuple[str, str]]:
    """(name, type) for the first CREATE TABLE in `sql`. One column per line, as in SPEC.md."""
    for statement in sql_statements(sql):
        match = _CREATE_RE.search(statement)
        if match:
            break
    else:
        raise ValueError("no CREATE TABLE statement found")
    columns = []
    for line in match.group("body").splitlines():
        line = line.strip()
        if not line:
            continue
        col = _COLUMN_RE.match(line)
        if not col:
            raise ValueError(f"cannot parse column definition: {line!r}")
        columns.append((col.group("name"), " ".join(col.group("type").split())))
    return columns


def schema_columns(path: Path = SCHEMA_PATH) -> List[Tuple[str, str]]:
    return table_columns(path.read_text(encoding="utf-8"))


def spec_columns(path: Path = SPEC_PATH) -> List[Tuple[str, str]]:
    """Columns from the ```sql block under SPEC.md "### 5.1"."""
    text = path.read_text(encoding="utf-8")
    section = re.search(r"^### 5\.1[^\n]*\n(.*?)^### ", text, re.MULTILINE | re.DOTALL)
    if not section:
        raise ValueError("SPEC.md has no '### 5.1' section")
    block = re.search(r"```sql\n(.*?)```", section.group(1), re.DOTALL)
    if not block:
        raise ValueError("SPEC.md 5.1 has no ```sql block")
    return table_columns(block.group(1))


def normalize_type(type_str: str) -> str:
    """Drop whitespace outside quotes, so `Enum8('A' = 1)` equals `Enum8('A'=1)`."""
    out, quoted = [], False
    for ch in type_str.strip():
        if ch == "'":
            quoted = not quoted
        if ch.isspace() and not quoted:
            continue
        out.append(ch)
    return "".join(out)


def enum_names(type_str: str) -> List[str]:
    """Value names of an Enum8/Enum16 type string, in declaration order."""
    return [name for name, _ in _ENUM_ITEM_RE.findall(type_str)]


# --------------------------------------------------------------------------------------
# Connection settings
# --------------------------------------------------------------------------------------

_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def missing(names: Sequence[str], environ: Mapping[str, str] = os.environ) -> List[str]:
    """Names from `names` that are unset or blank. Never looks at more than presence."""
    return [n for n in names if not environ.get(n, "").strip()]


def check_identifier(value: str, var: str) -> str:
    if not _IDENT_RE.match(value):
        raise ConfigError(f"{var} must be a plain identifier ([A-Za-z_][A-Za-z0-9_]*, at most 64 chars)")
    return value


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    secure: bool
    database: str

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "Endpoint":
        """Same rules as hold.core.ClickHouseWriter._connect, validated up front."""
        host = environ.get("CLICKHOUSE_HOST", "").strip()
        if not host:
            raise ConfigError("CLICKHOUSE_HOST is not set")
        if not _HOST_RE.match(host):
            raise ConfigError("CLICKHOUSE_HOST must be a bare hostname such as "
                              "abc123.us-east-1.aws.clickhouse.cloud (no scheme, port or path; "
                              "the port goes in CLICKHOUSE_PORT)")
        port_raw = environ.get("CLICKHOUSE_PORT", "8443").strip()
        if not port_raw.isdigit() or not 0 < int(port_raw) < 65536:
            raise ConfigError("CLICKHOUSE_PORT must be an integer port (8443 for ClickHouse Cloud)")
        # ClickHouseWriter: secure = (CLICKHOUSE_SECURE == "1"), default "1".
        secure = environ.get("CLICKHOUSE_SECURE", "1") == "1"
        # ClickHouseWriter passes "" through, which the client treats as the user's default
        # database ("default" for users created by scripts/setup_clickhouse.py).
        database = environ.get("CLICKHOUSE_DATABASE", "").strip() or "default"
        check_identifier(database, "CLICKHOUSE_DATABASE")
        return cls(host=host, port=int(port_raw), secure=secure, database=database)

    def describe(self) -> str:
        return f"host={self.host} port={self.port} secure={int(self.secure)} database={self.database}"


def connect(endpoint: Endpoint, username: str, password: str, *, client_name: str,
            database: Optional[str] = "", connect_timeout: int = 10,
            send_receive_timeout: int = 30, **extra: Any):
    """clickhouse_connect.get_client with HOLD's settings (signature checked against
    clickhouse-connect 1.10.0). `database=""` means endpoint.database; None means none."""
    import clickhouse_connect  # lazy: only paths that talk to ClickHouse need it

    return clickhouse_connect.get_client(
        host=endpoint.host,
        port=endpoint.port,
        username=username,
        password=password,
        database=endpoint.database if database == "" else database,
        secure=endpoint.secure,
        client_name=client_name,
        connect_timeout=connect_timeout,
        send_receive_timeout=send_receive_timeout,
        autogenerate_session_id=False,  # no server session: safe to share across threads
        **extra,
    )


def error_code(exc: BaseException) -> Tuple[Optional[int], Optional[str]]:
    """(code, symbolic name) of a clickhouse-connect error, when the server sent one."""
    return getattr(exc, "code", None), getattr(exc, "name", None)


# --------------------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------------------

_SECRET_NAME_RE = re.compile(r"PASSWORD|SECRET|TOKEN|API_KEY|_KEY$", re.IGNORECASE)
_CH_ESCAPE = ("\\", "'", "`", "\t", "\n")  # clickhouse_connect.driver.binding.must_escape


def _ch_escaped(value: str) -> str:
    return "".join("\\" + c if c in _CH_ESCAPE else c for c in value)


class Redactor:
    """Replaces the values of credential-like environment variables (and the escaped
    form they take inside a SQL literal) with <redacted>."""

    def __init__(self, environ: Mapping[str, str] = os.environ):
        values = set()
        for name, value in environ.items():
            if value and len(value) >= 6 and _SECRET_NAME_RE.search(name):
                values.update({value, _ch_escaped(value)})
        self._values = sorted(values, key=len, reverse=True)

    def __call__(self, text: Any) -> str:
        text = str(text)
        for value in self._values:
            text = text.replace(value, "<redacted>")
        return text


def describe_error(exc: BaseException, redact: Redactor, limit: int = 400) -> str:
    code, name = error_code(exc)
    tag = f" [ClickHouse {code}{' ' + name if name else ''}]" if code else ""
    message = " ".join(redact(exc).split())
    if len(message) > limit:
        message = message[:limit] + "..."
    return f"{type(exc).__name__}{tag}: {message}"
