#!/usr/bin/env python3
"""PostToolUse hook for Edit|Write. Deterministic checks that no agent can argue with.

1. Any edited .py file under the repo  -> run `harness.py -q`; failing tests block (exit 2).
2. Public-facing docs and UI           -> reject banned claims (exit 2).
3. Any edited file except .env*         -> reject things that look like committed secrets (exit 2).

Exit 2 sends stderr back to Claude, which must fix the problem. Exit 0 is silent.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The repo root is wherever this script lives; CLAUDE_PROJECT_DIR can point elsewhere
# when a session was started in another folder and moved here.
ROOT = Path(__file__).resolve().parents[2]
PUBLIC_DOCS = {"README.md", "PRD.md", "SPEC.md", "intent.md", "DEMO.md"}
BANNED = [
    r"zero (os )?syscalls?", r"zero packets", r"mathematically", r"\bsel4\b",
    r"cryptographically signed", r"signed (intent )?receipts?", r"zero false positives?",
    r"100% (blocked|of)", r"blocks? all (prompt )?injection", r"unbreakable", r"guarantee[sd]?\b",
    r"competitive vacuum", r"polic(y|ies) writes? itsel(f|ves)", r"semgrep (writes|generates) the polic",
    r"sub-1\.5\s?ms",
]
# A credential-looking name assigned a quoted literal (code, JSON, YAML), or, outside .py
# files, a bare KEY=value line (env/ini style). Group 2 is the value.
_NAME = r"\b[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)\b"
QUOTED_SECRET_RE = re.compile(rf"(?i){_NAME}['\"]?\s*[=:]\s*(['\"])([^'\"\s]{{8,}})\1")
BARE_SECRET_RE = re.compile(rf"(?i)^\s*(?:export\s+)?{_NAME}\s*=\s*()([^\s'\"#]{{8,}})\s*$")
SECRET_OK = {"not-a-real-secret", "<generated>"}


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    sys.exit(2)


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read().lstrip("﻿"))
    except Exception as exc:  # never pass silently on input we cannot read
        print(f"[hold-hook] could not parse hook input ({exc}); checks did NOT run", file=sys.stderr)
        sys.exit(1)
    raw = (payload.get("tool_input") or {}).get("file_path") or ""
    if not raw:
        return
    path = Path(raw).resolve()
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return
    if rel.parts and rel.parts[0] in (".venv", ".git"):
        return
    text = path.read_text(encoding="utf-8-sig", errors="replace") if path.is_file() else ""

    if not path.name.startswith(".env"):
        patterns = [QUOTED_SECRET_RE] if path.suffix == ".py" else [QUOTED_SECRET_RE, BARE_SECRET_RE]
        for n, line in enumerate(text.splitlines(), 1):
            for pattern in patterns:
                m = pattern.search(line)
                value = m.group(2) if m else ""
                if m and not any(ok in value for ok in SECRET_OK) and not value.startswith(("$", "{", "<")):
                    fail(f"[hold-hook] {rel}:{n} looks like a hard-coded secret. Secrets belong in .env only.")

    if path.name in PUBLIC_DOCS or (rel.parts and rel.parts[0] == "ui"):
        hits = []
        for n, line in enumerate(text.splitlines(), 1):
            for pattern in BANNED:
                if re.search(pattern, line, re.IGNORECASE):
                    hits.append(f"  {rel}:{n}: '{pattern}' -> {line.strip()[:120]}")
        if hits:
            fail("[hold-hook] Banned claim(s) in a public file. Rewrite them as measured, "
                 "evidence-backed statements (see ROADMAP.md > Honest claims):\n" + "\n".join(hits))

    if path.suffix == ".py":
        venv_py = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
        py = str(venv_py) if venv_py.exists() else sys.executable
        try:
            proc = subprocess.run([py, str(ROOT / "harness.py"), "-q"], cwd=ROOT, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=300)
        except subprocess.TimeoutExpired:
            fail("[hold-hook] harness.py timed out after 300 s.")
        if proc.returncode != 0:
            tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-40:])
            fail(f"[hold-hook] harness.py FAILED after editing {rel}. If the failing test is in a file "
                 "you own, fix it before continuing. If it belongs to another agent, do NOT edit their "
                 f"files; note it in your report and continue.\n{tail}")


if __name__ == "__main__":
    main()
