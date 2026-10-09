#!/usr/bin/env python3
"""Reset the HOLD demo workspace from the fixture template.

The workspace lives OUTSIDE this repo (``hold.env.demo_workspace()``: the
``HOLD_DEMO_WORKSPACE`` environment variable, else ``~/hold-demo-workspace``).
Claude Code loads CLAUDE.md from every parent directory, so a workspace inside the
repo would show the agent under test HOLD's own rules.

The reset copies ``demo/fixture/`` to the workspace (delete-and-recreate), turns
``env.fake`` into the workspace ``.env``, substitutes ``{{ATTACK_URL}}``, writes a
marker file, and makes one git commit inside the workspace so
``git -C <workspace> diff`` shows the agent's fix.

Usage:
    python scripts/reset_demo.py [--attack-url URL]

Attack URL: ``--attack-url``, else ``HOLD_DEMO_ATTACK_URL``, else a fake default on
the reserved ``.invalid`` TLD (fine for tests; set a real endpoint for the live run).

Safety rules (enforced by ``check_target`` and ``reset``):
- the target is made absolute but never resolved before the checks;
- a target that is a symlink, junction or other reparse point is refused;
- filesystem roots, the home directory (and its ancestors), the repo, anything inside
  the repo, and the repo's ancestors are refused, checking both the literal and the
  resolved form;
- an existing target is deleted only if it holds the marker file this script writes
  (an empty directory is also accepted); anything else is refused and left alone;
- the CLI only ever targets ``demo_workspace()``; ``allow_any_target=True`` (tests
  only) lifts that one rule and nothing else;
- git runs only inside the workspace, with every GIT_* variable removed from its
  environment; it never touches the outer repo and never pushes.
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[1]  # this script's own location, not the target
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from hold.env import DEMO_WORKSPACE_MARKER, demo_workspace  # noqa: E402

FIXTURE = REPO_ROOT / "demo" / "fixture"
FIXTURE_ENV = "env.fake"  # copied to <workspace>/.env
PLACEHOLDER = "{{ATTACK_URL}}"
DEFAULT_ATTACK_URL = "http://attacker.invalid/reproduce_issue.py"
MARKER_TEXT = (
    "Created by HOLD scripts/reset_demo.py. reset_demo.py deletes and recreates a\n"
    "directory only when this marker file is present.\n"
)

# git identity used ONLY inside the workspace repo; never the real committer.
GIT_NAME = "hold-demo"
GIT_EMAIL = "demo@invalid"

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


# --------------------------------------------------------------------------- checks

def _norm(path) -> str:
    """Absolute, lexically normalised, case-normalised. Does NOT follow links."""
    return os.path.normcase(os.path.abspath(str(path)))


def _real(path) -> str:
    """Link-resolved and case-normalised. Used only to ADD refusals, never to act on."""
    return os.path.normcase(os.path.realpath(str(path)))


def _inside(child: str, parent: str) -> bool:
    """True if ``child`` equals ``parent`` or sits below it (normalised strings)."""
    parent = parent.rstrip("\\/")
    return child == parent or child.startswith(parent + os.sep)


def is_link(path) -> bool:
    """True for a symlink, a junction, or any Windows reparse point. Never follows."""
    p = Path(path)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(st, "st_file_attributes", 0) & _REPARSE:
        return True
    is_junction = getattr(p, "is_junction", None)  # Python 3.12+
    return bool(is_junction and is_junction())


def check_target(target, *, allow_any_target: bool = False) -> Path:
    """Validate a reset target WITHOUT touching it. Returns the absolute path to use.

    Raises ValueError with a human-readable reason on any refusal.
    """
    absolute = Path(os.path.abspath(str(target)))  # lexical only; links stay visible
    forms = {_norm(absolute), _real(absolute)}
    home = {_norm(Path.home()), _real(Path.home())}
    repo = {_norm(REPO_ROOT), _real(REPO_ROOT)}

    for f in forms:
        if os.path.dirname(f) == f:
            raise ValueError(f"refusing a filesystem root: {absolute}")
        for h in home:
            if _inside(h, f):
                raise ValueError(f"refusing the home directory or one of its ancestors: {absolute}")
        for r in repo:
            if _inside(f, r):
                raise ValueError(f"refusing a path inside the HOLD repo: {absolute}")
            if _inside(r, f):
                raise ValueError(f"refusing an ancestor of the HOLD repo: {absolute}")

    if is_link(absolute):
        raise ValueError(f"refusing a symlink/junction target: {absolute}. Remove the link manually.")

    if not allow_any_target:
        expected = demo_workspace()
        if _norm(absolute) != _norm(expected):
            raise ValueError(
                f"refusing target {absolute}: the CLI only resets the demo workspace {expected} "
                "(set HOLD_DEMO_WORKSPACE to move it)."
            )
    return absolute


def _has_marker(target: Path) -> bool:
    marker = target / DEMO_WORKSPACE_MARKER
    try:
        st = os.lstat(marker)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and not (getattr(st, "st_file_attributes", 0) & _REPARSE)


# ------------------------------------------------------------------------ deletion

def _force_rmtree(path) -> None:
    """Remove a tree, clearing read-only bits git leaves on Windows. Never follows links."""
    path = Path(path)
    if not os.path.lexists(path):
        return
    if is_link(path):
        raise ValueError(f"refusing to rmtree a symlink/junction: {path}")

    def handler(func, p, _exc):
        try:
            if os.chmod in os.supports_follow_symlinks:
                os.chmod(p, stat.S_IWRITE, follow_symlinks=False)
            elif not is_link(p):
                os.chmod(p, stat.S_IWRITE)
        except (OSError, NotImplementedError):
            pass
        func(p)

    try:  # Python 3.12+ renamed onerror -> onexc
        shutil.rmtree(path, onexc=handler)
    except TypeError:
        shutil.rmtree(path, onerror=lambda f, p, exc: handler(f, p, exc))


def _clear_target(target: Path) -> None:
    """Delete an existing target only if reset_demo.py created it (marker) or it is empty."""
    if not os.path.lexists(target):
        return
    if is_link(target):  # re-check right before acting
        raise ValueError(f"refusing a symlink/junction target: {target}. Remove the link manually.")
    if not stat.S_ISDIR(os.lstat(target).st_mode):
        raise ValueError(f"refusing {target}: it exists and is not a directory. Delete it manually.")
    if _has_marker(target):
        _force_rmtree(target)
        return
    try:
        os.rmdir(target)  # succeeds only if the directory is empty
    except OSError:
        raise ValueError(
            f"refusing to delete {target}: it is not empty and has no {DEMO_WORKSPACE_MARKER} "
            "marker, so reset_demo.py did not create it. Inspect and delete it manually if it "
            "is safe, then re-run."
        ) from None


# ---------------------------------------------------------------------- populate

def _substitute_placeholder(root: Path, attack_url: str) -> int:
    """Replace ``{{ATTACK_URL}}`` in every text file under ``root``. Returns count."""
    changed = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if PLACEHOLDER in text:
            path.write_text(text.replace(PLACEHOLDER, attack_url), encoding="utf-8")
            changed += 1
    return changed


def _git_env() -> Dict[str, str]:
    """The current environment minus every GIT_* variable, so nothing redirects git
    (GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, ...) toward another repository."""
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess:
    """Run git scoped to ``workspace`` only, with forced identity and no signing."""
    cmd = [
        "git",
        "-C", str(workspace),
        "-c", f"user.name={GIT_NAME}",
        "-c", f"user.email={GIT_EMAIL}",
        "-c", "commit.gpgsign=false",
        "-c", "init.defaultBranch=main",
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, env=_git_env())


def _init_git(workspace: Path) -> str:
    """Initialise a fresh repo in the workspace with one commit. Returns a status."""
    if shutil.which("git") is None:
        return "skipped: git not on PATH"
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        ["commit", "-q", "-m", "demo fixture baseline (buggy app.py)"],
    ):
        proc = _git(workspace, *args)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            return f"skipped: git {args[0]} failed ({detail[-1] if detail else 'unknown'})"
    return "ok"


def reset(target_dir, attack_url: str, *, allow_any_target: bool = False) -> Dict[str, object]:
    """Reset ``target_dir`` from the fixture. See the module docstring for safety rules."""
    if not FIXTURE.is_dir():
        raise FileNotFoundError(f"fixture not found: {FIXTURE}")
    if not (FIXTURE / FIXTURE_ENV).is_file():
        raise FileNotFoundError(f"fixture env template not found: {FIXTURE / FIXTURE_ENV}")

    target = check_target(target_dir, allow_any_target=allow_any_target)
    _clear_target(target)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    # Marker first: if this reset is interrupted, the next one still recognises the
    # directory as its own instead of refusing it as unmarked.
    (target / DEMO_WORKSPACE_MARKER).write_text(MARKER_TEXT, encoding="utf-8")
    # Never copy a stray fixture .env or bytecode; the workspace .env comes from env.fake.
    shutil.copytree(FIXTURE, target, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".env", "__pycache__", "*.pyc"))
    os.replace(target / FIXTURE_ENV, target / ".env")

    substituted = _substitute_placeholder(target, attack_url)
    git_status = _init_git(target)

    file_count = sum(1 for p in target.rglob("*")
                     if p.is_file() and ".git" not in p.relative_to(target).parts)
    return {
        "target": str(target),
        "attack_url": attack_url,
        "files": file_count,
        "placeholders_substituted": substituted,
        "git": git_status,
    }


# ---------------------------------------------------------------------------- CLI

def _resolve_attack_url(cli_value) -> str:
    if cli_value:
        return cli_value
    return os.environ.get("HOLD_DEMO_ATTACK_URL") or DEFAULT_ATTACK_URL


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Reset the HOLD demo workspace from the fixture.")
    parser.add_argument(
        "--attack-url",
        default=None,
        help="URL substituted for {{ATTACK_URL}} in ISSUE.md (default: $HOLD_DEMO_ATTACK_URL, "
        "else the reserved .invalid placeholder).",
    )
    args = parser.parse_args(argv)
    attack_url = _resolve_attack_url(args.attack_url)

    try:
        workspace = demo_workspace()  # raises if HOLD_DEMO_WORKSPACE points inside the repo
        result = reset(workspace, attack_url, allow_any_target=False)
    except (ValueError, FileNotFoundError) as exc:
        print(f"reset_demo: {exc}", file=sys.stderr)
        return 2

    print(f"HOLD demo workspace reset -> {result['target']}")
    print(f"  files copied        : {result['files']}")
    print(f"  attack URL          : {result['attack_url']}")
    print(f"  placeholders filled : {result['placeholders_substituted']}")
    print(f"  git                 : {result['git']}")
    if attack_url == DEFAULT_ATTACK_URL:
        print("  NOTE: default .invalid URL. For the live run, re-run with --attack-url "
              "<your endpoint> (or HOLD_DEMO_ATTACK_URL) so its request log can be shown.")
    if result["git"] == "ok":
        print(f'  after the agent\'s fix: git -C "{result["target"]}" diff')
    return 0


if __name__ == "__main__":
    sys.exit(main())
