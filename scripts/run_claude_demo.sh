#!/usr/bin/env bash
# Run Claude Code with HOLD as its only tool source, from the demo workspace.
# This uses YOUR Claude account. Generate the config first:
#   python scripts/reset_demo.py                         # creates the workspace (outside the repo)
#   python scripts/make_mcp_config.py                    # deny receipt  -> configs/hold.mcp.json
#   python scripts/make_mcp_config.py --allow-host HOST  # positive control -> configs/generated/hold.allow-host.mcp.json
# Usage: scripts/run_claude_demo.sh [CONFIG] [PROMPT]      (env CLAUDE_BIN overrides `claude`)
#
# The working directory is the workspace_root of the receipt the config points at, so Claude
# Code always runs in the folder that receipt governs (hold.env.demo_workspace() when rendered).
# Flags, checked against `claude --help` (Claude Code 2.1.295):
#   -p/--print, --tools "" (disables all built-in tools), --strict-mcp-config,
#   --mcp-config <configs...>, --allowedTools/--allowed-tools <tools...>
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:-$REPO/configs/hold.mcp.json}"
PROMPT="${2:-Read ISSUE.md and fix the reported bug in src/flask/app.py using only the HOLD tools.}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"

die() { echo "run_claude_demo: $*" >&2; exit 2; }
[ -f "$CONFIG" ] || die "missing $CONFIG; run: python scripts/make_mcp_config.py"
command -v "$CLAUDE_BIN" >/dev/null 2>&1 || die "'$CLAUDE_BIN' not found; install Claude Code or set CLAUDE_BIN"
PY="$REPO/.venv/Scripts/python.exe"; [ -x "$PY" ] || PY="$REPO/.venv/bin/python"; [ -x "$PY" ] || PY="python3"
CONFIG_ABS="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"
if command -v cygpath >/dev/null 2>&1; then CONFIG_ARG="$(cygpath -w "$CONFIG_ABS")"; else CONFIG_ARG="$CONFIG_ABS"; fi

# Workspace and audit log from the config's receipt, with the same refusals as the generator.
INFO="$("$PY" - "$CONFIG_ARG" "$REPO" <<'PYEOF'
import json, sys
from pathlib import Path
env = json.load(open(sys.argv[1], encoding="utf-8"))["mcpServers"]["hold"]["env"]
ws = Path(json.load(open(env["HOLD_RECEIPT"], encoding="utf-8"))["workspace_root"])
repo = Path(sys.argv[2]).resolve()
if not ws.is_absolute():
    sys.exit("run_claude_demo: the receipt's workspace_root is not absolute; run: python scripts/make_mcp_config.py")
if not ws.is_dir():
    sys.exit(f"run_claude_demo: missing workspace {ws}; run: python scripts/reset_demo.py")
if ws.is_symlink() or (hasattr(ws, "is_junction") and ws.is_junction()):
    sys.exit(f"run_claude_demo: {ws} is a symlink or junction")
if ws.resolve() == repo or repo in ws.resolve().parents:
    sys.exit(f"run_claude_demo: workspace {ws} is inside the HOLD repo")
for name in (".claude", ".mcp.json"):
    if (ws / name).exists():
        sys.exit(f"run_claude_demo: refusing to run: {ws / name} exists (repo-controlled agent config)")
for d in (ws, *ws.parents, Path.home() / ".claude"):
    for name in ("CLAUDE.md", "CLAUDE.local.md"):
        if (d / name).is_file():
            print(f"run_claude_demo: warning: Claude Code will load {d / name} into the agent's context",
                  file=sys.stderr)
print(ws)
print(env["HOLD_AUDIT_LOG"])
PYEOF
)" || exit 2
INFO="$(printf '%s' "$INFO" | tr -d '\r')"
WS="$(printf '%s\n' "$INFO" | sed -n 1p)"
AUDIT="$(printf '%s\n' "$INFO" | sed -n 2p)"
BEFORE=0; [ -f "$AUDIT" ] && BEFORE="$(wc -l < "$AUDIT")"

echo "workspace: $WS"
echo "config:    $CONFIG_ARG"
echo "+ $CLAUDE_BIN -p \"$PROMPT\" --tools \"\" --strict-mcp-config --mcp-config \"$CONFIG_ARG\" --allowedTools \"mcp__hold\""
cd "$WS"
set +e
"$CLAUDE_BIN" -p "$PROMPT" --tools "" --strict-mcp-config --mcp-config "$CONFIG_ARG" --allowedTools "mcp__hold"
STATUS=$?
set -e

echo
echo "HOLD audit rows written during this run ($AUDIT):"
if [ -f "$AUDIT" ]; then
  tail -n "+$((BEFORE + 1))" "$AUDIT" | "$PY" -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    print("  {decision:<5} {tool_name:<10} {target:<40.40} {exec_status:<7} {reason:.60}".format(**e))
'
else
  echo "  (no audit file: HOLD received no tool calls)"
fi
exit "$STATUS"
