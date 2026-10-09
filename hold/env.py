"""Load KEY=VALUE pairs from the repo-root `.env` without overriding real environment
variables. Stdlib only; never prints values."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_WORKSPACE_MARKER = ".hold-demo-workspace"


def demo_workspace() -> Path:
    """Where the demo workspace lives: HOLD_DEMO_WORKSPACE, else ~/hold-demo-workspace.

    It is deliberately OUTSIDE this repo. Claude Code loads CLAUDE.md from every parent
    directory, so a workspace inside the repo would show the agent under test HOLD's own
    rules. The path is made absolute but NOT resolved, so a symlink or junction at that
    location stays visible to callers, which must refuse it.
    """
    raw = os.environ.get("HOLD_DEMO_WORKSPACE") or str(Path.home() / "hold-demo-workspace")
    # Device (\\?\, \\.\) and UNC (\\host\share) forms defeat prefix comparisons, so only
    # plain drive-letter paths are accepted on Windows.
    if os.name == "nt" and raw.replace("/", "\\").startswith("\\\\"):
        raise ValueError(f"demo workspace must be a plain drive path, not a UNC/device path (got {raw})")
    path = Path(raw).expanduser().absolute()
    repo = REPO_ROOT.resolve()
    if path.resolve() == repo or repo in path.resolve().parents or _same_or_inside(path, repo):
        raise ValueError(f"demo workspace must be outside the HOLD repo (got {path})")
    return path


def _same_or_inside(path: Path, repo: Path) -> bool:
    """samefile-based check on the nearest existing ancestor, so case, 8.3 names and
    links that point into the repo are caught too."""
    probe = path
    while not probe.exists():
        if probe.parent == probe:
            return False
        probe = probe.parent
    for candidate in [probe, *probe.parents]:
        try:
            if os.path.samefile(candidate, repo):
                return True
        except OSError:
            continue
    return False


def load_env(path: Path = REPO_ROOT / ".env") -> list:
    """Return the names (never the values) of variables that were set from the file."""
    if not path.is_file():
        return []
    loaded = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
