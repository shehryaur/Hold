#!/usr/bin/env python3
"""Render an Intent Receipt template and write the Claude Code MCP config for HOLD.
Absolute paths only, no secrets.

    python scripts/make_mcp_config.py                      # deny receipt  -> configs/hold.mcp.json
    python scripts/make_mcp_config.py --allow-host HOST    # positive control (see below)

Templates. configs/intent_receipt.json and configs/intent_receipt.allow-host.json have
`"workspace_root": "<HOLD_DEMO_WORKSPACE>"`, so loading them directly fails (fail closed).
This script renders the chosen template into configs/generated/<name>.json with
workspace_root = `hold.env.demo_workspace()` (HOLD_DEMO_WORKSPACE, else
~/hold-demo-workspace; always outside this repo, because Claude Code loads CLAUDE.md from
every parent directory) and points HOLD_RECEIPT at the rendered file. A template whose
workspace_root is a normal path is rendered with that path made absolute.

The config starts `<venv python> -m hold.server` with PYTHONPATH=<repo>, HOLD_RECEIPT and
HOLD_AUDIT_LOG. ClickHouse settings are NOT written: the server loads them from the repo's
.env (or the environment that launches Claude Code). PYTHONSAFEPATH=1 is set because
Claude Code starts the server in the demo workspace, and `python -m` would otherwise put
that directory first on sys.path, so files in the (untrusted) workspace such as `hold/` or
`anyio.py` could replace HOLD's own code.

Positive control (`--allow-host HOST`): renders the --receipt template (default
configs/intent_receipt.json) with `network_egress: true` and `host_allowlist: [HOST]` and
nothing else changed (task_id included) into configs/generated/<name>.allow-host.json, and
writes configs/generated/hold.allow-host.mcp.json unless --out is given, so the deny config
is never overwritten by accident. configs/intent_receipt.allow-host.json is the committed
reference for that receipt; its host_allowlist holds the placeholder
`replace-with-demo-host.invalid` (.invalid never resolves), so it allows no real host.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.core import IntentReceipt  # noqa: E402
from hold.env import demo_workspace  # noqa: E402

WORKSPACE_PLACEHOLDER = "<HOLD_DEMO_WORKSPACE>"
DEFAULT_RECEIPT = REPO_ROOT / "configs" / "intent_receipt.json"
GENERATED_DIR = REPO_ROOT / "configs" / "generated"
DEFAULT_OUT = REPO_ROOT / "configs" / "hold.mcp.json"
DEFAULT_ALLOW_OUT = GENERATED_DIR / "hold.allow-host.mcp.json"
DEFAULT_AUDIT_LOG = REPO_ROOT / "hold_audit.jsonl"
DEMO_PROMPT = "Read ISSUE.md and fix the reported bug in src/flask/app.py using only the HOLD tools."
SERVER_NAME = "hold"
ALLOW_SUFFIX = ".allow-host"

_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def default_python() -> Path:
    """The project venv's interpreter, falling back to the one running this script."""
    venv = REPO_ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return venv if venv.is_file() else Path(sys.executable)


def normalize_host(host: str) -> str:
    """A bare hostname or IPv4 address, lowercased, as the gate compares it."""
    value = host.strip().lower().rstrip(".")
    if not _HOST_RE.match(value):
        raise ValueError(f"'{host}' is not a bare hostname. Pass only the host, e.g. "
                         "abc.free.beeceptor.com or 127.0.0.1 (no scheme, port, path or wildcard)")
    return value


def _is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)  # Python 3.12+
    return path.is_symlink() or bool(is_junction and is_junction())


def resolve_demo_workspace() -> Path:
    """`demo_workspace()`, refusing a symlink or junction at that location."""
    ws = demo_workspace()
    if _is_link(ws):
        raise ValueError(f"demo workspace {ws} is a symlink or junction; use a real directory")
    return ws


def render_receipt(template: Path, out_dir: Path = GENERATED_DIR, allow_host: Optional[str] = None) -> Path:
    """Write `template` with an absolute workspace_root (and optionally egress to exactly
    `allow_host`) into `out_dir`. Returns the rendered path; IntentReceipt.load validates it."""
    template = Path(template).resolve()
    data = json.loads(template.read_text(encoding="utf-8"))
    if data.get("workspace_root") == WORKSPACE_PLACEHOLDER:
        data["workspace_root"] = str(resolve_demo_workspace())
    else:
        data["workspace_root"] = os.path.realpath(template.parent / data["workspace_root"])
    name = template.stem
    if allow_host:
        caps = data.setdefault("capabilities", {})
        caps["network_egress"] = True
        caps["host_allowlist"] = [normalize_host(allow_host)]
        if not name.endswith(ALLOW_SUFFIX):
            name += ALLOW_SUFFIX
    out_dir = Path(out_dir).resolve()
    IntentReceipt.from_dict(data, out_dir)  # validate (fields, workspace exists) before writing
    out = out_dir / f"{name}.json"
    if out == template:
        raise ValueError(f"refusing to overwrite the template {template}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return out


def _check_outside_workspace(receipt: IntentReceipt, receipt_path: Path, audit_log: Path) -> None:
    root = receipt.workspace_root
    for label, path in (("receipt", receipt_path), ("audit log", audit_log)):
        try:
            Path(os.path.realpath(path)).relative_to(root)
        except ValueError:
            continue
        raise ValueError(f"the {label} {path} is inside workspace_root {root}; keep it outside")


def server_entry(receipt: Path, audit_log: Path, python: Optional[Path] = None,
                 agent_id: Optional[str] = None) -> Dict[str, object]:
    """The `mcpServers.hold` entry. Absolute paths only; never secrets."""
    env = {
        "PYTHONPATH": str(REPO_ROOT),
        "PYTHONSAFEPATH": "1",
        "HOLD_RECEIPT": str(Path(receipt).resolve()),
        "HOLD_AUDIT_LOG": str(Path(audit_log).resolve()),
    }
    if agent_id:
        env["HOLD_AGENT_ID"] = agent_id
    return {"command": str(Path(python or default_python()).resolve()),
            "args": ["-m", "hold.server"], "env": env}


def claude_args(config: Path, prompt: str = DEMO_PROMPT) -> List[str]:
    """argv for the demo run (flags checked against `claude --help`, Claude Code 2.1.295)."""
    return ["claude", "-p", prompt, "--tools", "", "--strict-mcp-config",
            "--mcp-config", str(Path(config).resolve()), "--allowedTools", f"mcp__{SERVER_NAME}"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT,
                        help="receipt template to render (default: configs/intent_receipt.json)")
    parser.add_argument("--allow-host", metavar="HOST",
                        help="positive control: render the receipt with egress to exactly HOST")
    parser.add_argument("--out", type=Path, help="config path (default: configs/hold.mcp.json, or "
                        "configs/generated/hold.allow-host.mcp.json with --allow-host)")
    parser.add_argument("--generated-dir", type=Path, default=GENERATED_DIR,
                        help="where rendered receipts go (default: configs/generated)")
    parser.add_argument("--audit-log", type=Path, default=DEFAULT_AUDIT_LOG,
                        help="JSONL audit file (default: <repo>/hold_audit.jsonl)")
    parser.add_argument("--agent-id", help="HOLD_AGENT_ID for events (server default: claude-code)")
    parser.add_argument("--python", type=Path, help="interpreter for the server (default: the repo venv)")
    args = parser.parse_args(argv)

    try:
        receipt_path = render_receipt(args.receipt, args.generated_dir, args.allow_host)
        receipt = IntentReceipt.load(receipt_path)
        audit_log = args.audit_log.resolve()
        _check_outside_workspace(receipt, receipt_path, audit_log)
        if not audit_log.parent.is_dir():
            raise ValueError(f"audit log directory does not exist: {audit_log.parent}")
    except (OSError, ValueError, KeyError) as exc:
        print(f"make_mcp_config: {type(exc).__name__}: {exc}", file=sys.stderr)
        if "workspace_root does not exist" in str(exc):
            print("hint: create the demo workspace first: python scripts/reset_demo.py", file=sys.stderr)
        return 2

    out = (args.out or (DEFAULT_ALLOW_OUT if args.allow_host else DEFAULT_OUT)).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    config = {"mcpServers": {SERVER_NAME: server_entry(receipt_path, audit_log, args.python, args.agent_id)}}
    out.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    workspace = receipt.workspace_root
    print(f"wrote {out}")
    print(f"  receipt   {receipt_path}  (rendered from {args.receipt.resolve()})")
    print(f"            task={receipt.task_id} digest={receipt.digest[:16]}... "
          f"network_egress={receipt.network_egress} hosts={list(receipt.host_allowlist)}")
    print(f"  workspace {workspace}")
    print(f"  audit log {audit_log}")
    print(f"  python    {config['mcpServers'][SERVER_NAME]['command']}")
    print("Run Claude Code from the demo workspace (bash / Git Bash):")
    print(f"  cd {shlex.quote(workspace.as_posix())}")
    print("  " + " ".join(shlex.quote(a) for a in claude_args(out)))
    print("Windows PowerShell 5.1 drops an empty \"\" argument; there write --tools '\"\"', or use:")
    print(f"  powershell -ExecutionPolicy Bypass -File scripts\\run_claude_demo.ps1 -Config \"{out}\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
