"""
HOLD write-content scan: run Semgrep on every write_file the gate has allowed, and deny
the write if the proposed content adds a risky call (network egress, process execution,
dynamic code) that the file did not already contain. Rules: rules/hold-write-scan.yml.

Fail closed: if Semgrep is missing, crashes, times out, prints no or invalid JSON, or did
not scan the content, the verdict is DENY with a reason that starts "Semgrep unavailable:"
or "Semgrep error:". Only an explicit HOLD_SEMGREP=0 turns the scan off.

This module runs inside the MCP stdio server: it never writes to stdout, and Semgrep's
stdin/stdout/stderr are redirected away from the protocol channel.

Host note (Windows): when HOLD runs inside a packaged-app container (for example under
the Claude desktop app), %TEMP% under AppData is filesystem-virtualized and semgrep-core
crashes at startup with "Unix_error: Invalid argument socketpair". The scanner therefore
gives Semgrep TEMP/TMP = a scratch directory outside AppData: <repo>/.tmp/semgrep by
default, or HOLD_SEMGREP_TMP. The old/new content files are written there too.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "rules" / "hold-write-scan.yml"
DEFAULT_SCRATCH = REPO_ROOT / ".tmp" / "semgrep"

# The rules are Python-only. Other file types are passed through as "not scanned".
SCANNED_SUFFIXES = (".py", ".pyw", ".pyi")
_OLD, _NEW = "old/target.py", "new/target.py"
_MAX_REASON = 300


@dataclass
class ScanVerdict:
    allowed: bool
    reason: str  # never contains written content: rule ids, line numbers, rule messages only
    elapsed_ms: float
    rule_ids: tuple[str, ...]  # rules with NEW findings (empty when allowed or on error)


def find_semgrep() -> Optional[str]:
    """The venv's semgrep (next to sys.executable), else the one on PATH, else None."""
    candidate = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if candidate.is_file():
        return str(candidate)
    return shutil.which("semgrep")


def default_scratch_dir() -> Path:
    raw = os.environ.get("HOLD_SEMGREP_TMP", "").strip()
    return Path(raw) if raw else DEFAULT_SCRATCH


def _clean(text: str, limit: int = _MAX_REASON) -> str:
    return " ".join(str(text).split())[:limit]


def _norm_path(p: Any) -> str:
    """'C:\\x\\new\\target.py' or 'new/target.py' -> 'new/target.py'."""
    parts = [s for s in str(p).replace("\\", "/").split("/") if s]
    return "/".join(parts[-2:])


def _looks_like_python(path: str, new: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in SCANNED_SUFFIXES:
        return True
    first = new.split("\n", 1)[0]
    return suffix == "" and first.startswith("#!") and "python" in first


# Environment passed to Semgrep: an allowlist, so secrets (e.g. CLICKHOUSE_PASSWORD) and
# SEMGREP_* settings that change results (baseline commit, extra rules, timeouts) never
# reach it. TEMP/TMP are set separately to the scratch dir.
_ENV_ALLOW = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "USERPROFILE",
              "HOMEDRIVE", "HOMEPATH", "HOME", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA",
              "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL", "LC_CTYPE",
              "TMPDIR", "USER", "LOGNAME")


def child_env(scratch: Path) -> Dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_ALLOW if k in os.environ}
    env["TEMP"] = env["TMP"] = str(scratch)
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def popen_kwargs() -> Dict[str, Any]:
    """Process-group settings so `_kill_tree` can take down Semgrep and semgrep-core."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _matched_text(result: Dict[str, Any], src: bytes) -> Optional[str]:
    """Source text of a finding, whitespace-normalized. Semgrep's own `extra.lines` says
    "requires login" without an account, so slice the file by byte offset instead."""
    start, end = result.get("start") or {}, result.get("end") or {}
    so, eo = start.get("offset"), end.get("offset")
    if isinstance(so, int) and isinstance(eo, int) and 0 <= so <= eo <= len(src):
        chunk = src[so:eo]
    else:  # fall back to whole lines (coarser, so comparisons only get stricter)
        a, b = start.get("line"), end.get("line")
        lines = src.split(b"\n")
        if not (isinstance(a, int) and isinstance(b, int) and 1 <= a <= b <= len(lines)):
            return None
        chunk = b"\n".join(lines[a - 1:b])
    return " ".join(chunk.decode("utf-8", errors="replace").split())


def _error_type(err: Dict[str, Any]) -> str:
    t = err.get("type")
    if isinstance(t, list) and t:
        t = t[0]
    t = "".join(c for c in str(t) if c.isalnum() or c in " _-")[:40]
    return t or "unknown error"


def evaluate_output(data: Any, old: bytes, new: bytes) -> Tuple[bool, str, Tuple[str, ...]]:
    """Turn Semgrep's JSON for (old/target.py, new/target.py) into a verdict.

    DENY if the content was not scanned, if Semgrep reported an error, or if `new` has a
    finding (rule id + normalized matched text) that `old` does not. Counts matter: a
    second copy of a pre-existing call is new."""
    bad = (False, "Semgrep error: unexpected JSON output", ())
    if not isinstance(data, dict):
        return bad
    results, errors, paths = data.get("results"), data.get("errors"), data.get("paths")
    if not isinstance(results, list) or not isinstance(errors, list) or not isinstance(paths, dict):
        return bad
    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or _NEW not in {_norm_path(p) for p in scanned}:
        return False, "Semgrep error: the written content was not scanned", ()
    for err in errors:
        if not isinstance(err, dict):
            return bad
        level = str(err.get("level", "error")).lower()
        # Any error can mean missing findings (e.g. a rule that timed out). The one safe
        # exception: a warning about the OLD file only makes the comparison stricter.
        if level == "error" or _norm_path(err.get("path", "")) != _OLD:
            return False, f"Semgrep error: {_error_type(err)} ({level}) while scanning", ()

    baseline: Counter = Counter()
    proposed: List[Tuple[int, str, str, Tuple[str, str]]] = []
    for r in results:
        if not isinstance(r, dict):
            return bad
        which = _norm_path(r.get("path", ""))
        if which not in (_OLD, _NEW):
            return False, "Semgrep error: finding for an unexpected path", ()
        rule = str(r.get("check_id", "")).rsplit(".", 1)[-1] or "unknown-rule"
        text = _matched_text(r, old if which == _OLD else new)
        if text is None:
            return False, "Semgrep error: finding without a usable position", ()
        if which == _OLD:
            baseline[(rule, text)] += 1
        else:
            line = (r.get("start") or {}).get("line", 0)
            message = _clean((r.get("extra") or {}).get("message", ""), 80)
            proposed.append((line if isinstance(line, int) else 0, rule, message, (rule, text)))

    remaining = Counter(baseline)
    fresh = []
    for line, rule, message, key in sorted(proposed):
        if remaining[key] > 0:
            remaining[key] -= 1
        else:
            fresh.append((line, rule, message))
    if fresh:
        ids = tuple(dict.fromkeys(rule for _, rule, _ in fresh))
        shown = "; ".join(f"{rule} line {line}: {message}" for line, rule, message in fresh[:3])
        more = f"; +{len(fresh) - 3} more" if len(fresh) > 3 else ""
        return False, f"Semgrep found {len(fresh)} new finding(s): {shown}{more}", ids
    kept = sum(baseline.values())
    note = f" ({kept} pre-existing finding(s) unchanged)" if kept else ""
    return True, f"Semgrep: no new findings{note}", ()


class SemgrepScanner:
    """Callable write scanner: scanner(rel_path, old, new) -> ScanVerdict. Never raises."""

    def __init__(self, rules_path: Path, semgrep_bin: Optional[str] = None, timeout_s: float = 60,
                 scratch_dir: Optional[Path] = None):
        self.rules_path = Path(rules_path)
        self.semgrep_bin = semgrep_bin if semgrep_bin is not None else find_semgrep()
        self.timeout_s = float(timeout_s)
        self.scratch_dir = Path(scratch_dir) if scratch_dir is not None else default_scratch_dir()
        self.last_stderr = ""   # diagnostics only (probe, harness); never put into events
        self.last_version = ""  # from Semgrep's JSON output

    def __call__(self, rel_path: str, old: str, new: str, resolved_path: Optional[str] = None) -> ScanVerdict:
        """`resolved_path`: the workspace-relative path the write will really land on (after
        symlinks). The content is scanned if EITHER path looks like a Python file."""
        start = time.perf_counter()
        try:
            allowed, reason, ids = self._scan(rel_path, old, new, resolved_path)
        except Exception as exc:  # fail closed on anything unexpected
            allowed, reason, ids = False, f"Semgrep error: {type(exc).__name__} during scan", ()
        return ScanVerdict(allowed, _clean(reason), (time.perf_counter() - start) * 1000.0, ids)

    # -- internals -------------------------------------------------------------------

    def _resolve_bin(self) -> Optional[str]:
        b = self.semgrep_bin
        if not b:
            return None
        if os.path.isfile(b):
            return b
        return shutil.which(b)

    def _scan(self, rel_path: str, old: str, new: str,
              resolved_path: Optional[str]) -> Tuple[bool, str, Tuple[str, ...]]:
        if not all(isinstance(x, str) for x in (rel_path, old, new)):
            return False, "Semgrep error: invalid scan arguments", ()
        if resolved_path is not None and not isinstance(resolved_path, str):
            return False, "Semgrep error: invalid scan arguments", ()
        paths = [rel_path] + ([resolved_path] if resolved_path is not None else [])
        if not any(_looks_like_python(p, new) for p in paths):
            return True, "not scanned: HOLD scan rules cover Python files only", ()
        exe = self._resolve_bin()
        if exe is None:
            return False, "Semgrep unavailable: semgrep executable not found", ()
        if not self.rules_path.is_file():
            return False, "Semgrep error: rules file not found", ()
        new_b = new.encode("utf-8")  # same bytes the Gateway writes; lone surrogates raise -> DENY
        old_b = old.encode("utf-8", errors="replace") if old.strip() else b""

        self.scratch_dir.mkdir(parents=True, exist_ok=True)
        # Long path, not an 8.3 short name (realpath expands ADMINI~1 on Windows).
        scratch = Path(os.path.realpath(self.scratch_dir))
        work = Path(os.path.realpath(tempfile.mkdtemp(prefix="scan-", dir=str(scratch))))
        try:
            targets = []
            if old_b:
                (work / "old").mkdir()
                (work / "old" / "target.py").write_bytes(old_b)
                targets.append(_OLD)
            (work / "new").mkdir()
            (work / "new" / "target.py").write_bytes(new_b)
            targets.append(_NEW)
            out = work / "out.json"
            # --disable-nosem: the scanned content is attacker-influenced, so inline
            # `# nosemgrep` / `# nosem: <rule>` comments must not suppress findings.
            argv = [exe, "scan", "--config", str(Path(os.path.realpath(self.rules_path))), "--json",
                    "--output", str(out), "--metrics=off", "--disable-version-check", "--quiet",
                    "--disable-nosem", *targets]
            try:
                rc = self._run(argv, work, child_env(scratch))
            except OSError as exc:
                return False, f"Semgrep unavailable: could not start semgrep ({type(exc).__name__})", ()
            if rc is None:
                return False, f"Semgrep error: timed out after {self.timeout_s:g} s", ()
            if rc != 0:
                return False, f"Semgrep error: exit code {rc}{self._hint()}", ()
            try:
                data = json.loads(out.read_bytes().decode("utf-8-sig"))
            except FileNotFoundError:
                return False, "Semgrep error: no JSON output", ()
            except ValueError:  # includes UnicodeDecodeError and JSONDecodeError
                return False, "Semgrep error: invalid JSON output", ()
            if isinstance(data, dict) and isinstance(data.get("version"), str):
                self.last_version = data["version"][:20]
            return evaluate_output(data, old_b, new_b)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _run(self, argv: List[str], work: Path, env: Dict[str, str]) -> Optional[int]:
        """Run Semgrep with stdio redirected to files (never the MCP channel, and no pipes
        a surviving grandchild could hold open). Returns the exit code, or None on timeout."""
        kwargs: Dict[str, Any] = {"cwd": str(work), "env": env, "stdin": subprocess.DEVNULL, **popen_kwargs()}
        with open(work / "stdout.txt", "wb") as fo, open(work / "stderr.txt", "wb") as fe:
            proc = subprocess.Popen(argv, stdout=fo, stderr=fe, **kwargs)
            try:
                rc: Optional[int] = proc.wait(timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                _kill_tree(proc)
                rc = None
        try:
            tail = (work / "stderr.txt").read_bytes()[-600:].decode("utf-8", errors="replace")
            self.last_stderr = _clean(tail, 600)
        except OSError:
            self.last_stderr = ""
        return rc

    def _hint(self) -> str:
        """Fixed-vocabulary hint from stderr (raw stderr never goes into a verdict)."""
        err = self.last_stderr
        if "socketpair" in err:
            return " (semgrep-core socketpair failure; set HOLD_SEMGREP_TMP to a non-virtualized dir)"
        if "semgrep-core" in err:
            return " (semgrep-core failed)"
        return ""


def _kill_tree(proc: "subprocess.Popen[bytes]") -> None:
    """Kill Semgrep and its semgrep-core child. Best effort; never raises."""
    try:
        if os.name == "nt":
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
            subprocess.run([str(taskkill), "/F", "/T", "/PID", str(proc.pid)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:
        pass


# A real, tiny scan whose correct answer is known: a new urlopen() must be flagged.
PROBE_SNIPPET = (
    "import urllib.request\n\n\n"
    "def report(data):\n"
    "    return urllib.request.urlopen('http://127.0.0.1:9/hold-probe', data)\n"
)


def probe(scanner: Any) -> Tuple[bool, str]:
    """Run one real scan of a known-bad snippet. (True, detail) only if the scanner
    produced a finding; otherwise (False, why). Never raises."""
    try:
        verdict = scanner("hold_probe.py", "", PROBE_SNIPPET)
    except Exception as exc:
        return False, f"scanner raised {type(exc).__name__}"
    version = getattr(scanner, "last_version", "") or "?"
    if not verdict.allowed and verdict.rule_ids:
        return True, (f"Semgrep {version} flagged the known-bad probe ({', '.join(verdict.rule_ids)}) "
                      f"in {verdict.elapsed_ms:.0f} ms")
    if verdict.allowed:
        return False, f"known-bad probe was NOT flagged: {verdict.reason}"
    tail = getattr(scanner, "last_stderr", "")
    return False, verdict.reason + (f" | stderr: {tail[-300:]}" if tail else "")


def write_scanner_from_env() -> Optional[SemgrepScanner]:
    """None only when HOLD_SEMGREP=0. A missing Semgrep still returns a scanner, which then
    denies every Python write ("Semgrep unavailable"), so the scan cannot silently vanish."""
    if os.environ.get("HOLD_SEMGREP", "").strip() == "0":
        return None
    return SemgrepScanner(DEFAULT_RULES, find_semgrep())
