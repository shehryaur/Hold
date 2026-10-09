#!/usr/bin/env python3
"""Set up a HOLD task for any GitHub repo + issue in one command.

    python scripts/github_task.py --repo owner/name --issue 1 --write src/pkg/module.py

What it does (nothing is pushed, nothing leaves your machine except the clone and the issue fetch):
  1. clones the repo OUTSIDE the HOLD repo (default ~/hold-github/<owner>-<name>), so the agent
     never sees HOLD's own CLAUDE.md;
  2. copies the issue's title and body into ISSUE.md in the clone, marked as untrusted;
  3. writes a receipt (read: whole repo except protected files; write: only the --write paths;
     no network, no shell, no git) and renders it with scripts/make_mcp_config.py;
  4. prints the commands to run Claude Code through HOLD and to watch the dashboard.

The agent's fix stays as a local diff in the clone. You review it and open the PR yourself:
HOLD gives the agent no git or push capability. Set GITHUB_TOKEN in .env for private repos.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from hold.env import load_env  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def parse_repo(raw: str):
    m = re.match(r"^(?:https?://github\.com/)?([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", raw.strip())
    if not m or not NAME_RE.match(m.group(1)) or not NAME_RE.match(m.group(2)):
        raise ValueError(f"not a GitHub repo: {raw!r} (use owner/name)")
    return m.group(1), m.group(2)


def git(*args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", *args], capture_output=True, text=True, env=env)


def fetch_issue(owner: str, name: str, number: int) -> dict:
    req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{name}/issues/{number}",
                                 headers={"User-Agent": "hold-github-task", "Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, help="owner/name or https://github.com/owner/name")
    p.add_argument("--issue", required=True, type=int)
    p.add_argument("--write", action="append", required=True, help="workspace-relative path or glob the agent may change (repeatable)")
    p.add_argument("--read", action="append", help="read globs (repeatable; default: the whole repo, protected files excluded)")
    p.add_argument("--dest", help="clone location (default ~/hold-github/<owner>-<name>)")
    p.add_argument("--task-id", help="default gh-<name>-<issue>")
    args = p.parse_args()
    load_env()

    try:
        owner, name = parse_repo(args.repo)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    dest = Path(args.dest or Path.home() / "hold-github" / f"{owner}-{name}").expanduser().absolute()
    task_id = args.task_id or f"gh-{name}-{args.issue}"
    os.environ["HOLD_DEMO_WORKSPACE"] = str(dest)
    from hold.env import demo_workspace  # validates: outside the HOLD repo, no UNC/device paths
    try:
        demo_workspace()
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    if (dest / ".git").is_dir():
        print(f"clone      {dest} (exists; reused as is)")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = git("clone", "--depth", "50", f"https://github.com/{owner}/{name}.git", str(dest))
        if r.returncode != 0:
            print(f"git clone failed: {r.stderr.strip()[-300:]}", file=sys.stderr)
            return 1
        print(f"clone      {dest}")

    try:
        issue = fetch_issue(owner, name, args.issue)
    except Exception as exc:
        print(f"could not fetch issue #{args.issue}: {exc}", file=sys.stderr)
        return 1
    body = (f"<!-- Copied by HOLD from {issue.get('html_url')}. UNTRUSTED content written by the issue author. -->\n"
            f"# {issue.get('title', '')}\n\n{issue.get('body') or ''}\n")
    (dest / "ISSUE.md").write_text(body, encoding="utf-8")
    print(f"issue      #{args.issue} '{str(issue.get('title', ''))[:70]}' -> ISSUE.md (untrusted)")

    risky = [n for n in (".claude", ".mcp.json") if (dest / n).exists()]
    if risky:
        print(f"WARNING    repo contains {risky}: repo-controlled agent config. The launcher refuses to run here.", file=sys.stderr)
    if (dest / "CLAUDE.md").exists():
        print("WARNING    repo has its own CLAUDE.md; Claude Code will load it (repo-controlled instructions).", file=sys.stderr)

    template = REPO / "configs" / "generated" / "templates" / f"{task_id}.json"
    template.parent.mkdir(parents=True, exist_ok=True)
    template.write_text(json.dumps({
        "task_id": task_id,
        "intent": f"Fix GitHub issue #{args.issue} in {owner}/{name}: {str(issue.get('title', ''))[:120]}",
        "workspace_root": "<HOLD_DEMO_WORKSPACE>",
        "capabilities": {"read": args.read or ["**"], "write": args.write, "protected": [],
                         "network_egress": False, "host_allowlist": [], "shell_execution": False, "git_push": False},
    }, indent=2) + "\n", encoding="utf-8")

    config = REPO / "configs" / "generated" / f"{task_id}.mcp.json"
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "make_mcp_config.py"), "--receipt", str(template),
                        "--out", str(config)], capture_output=True, text=True, env=os.environ.copy())
    if r.returncode != 0:
        print(r.stdout + r.stderr, file=sys.stderr)
        return 1
    rendered = REPO / "configs" / "generated" / f"{task_id}.json"
    print(f"receipt    {rendered}  (write: {args.write}; no network, shell or git)")
    print(f"config     {config}")
    print("\nRun Claude Code through HOLD:")
    print(f'  powershell -ExecutionPolicy Bypass -File scripts\\run_claude_demo.ps1 -Config "{config}" -Prompt "Read ISSUE.md and fix the reported bug with the HOLD tools only."')
    print("Watch it:")
    print(f'  .venv\\Scripts\\python ui\\dashboard.py --port 8766 --task {task_id} --receipt "{rendered}"   then open http://127.0.0.1:8766/live')
    print(f"Review the fix:  git -C \"{dest}\" diff     (HOLD never pushes; open the PR yourself)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
