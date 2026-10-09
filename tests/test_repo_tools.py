"""Real-repo tools: list_files, search_code, read_lines, edit_file. Real files, real Gateway."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hold.core import Gateway, IntentReceipt, JsonlWriter, Telemetry

APP = "".join(f"line {i}\n" for i in range(1, 1501)) + "def get_auth_token(environ):\n    return environ.get('A').split('Bearer ')[1]\n"
SECRET = "FAKE_TOKEN=not-a-real-secret-needle\n"


class Verdict:
    def __init__(self, allowed, reason):
        self.allowed, self.reason, self.elapsed_ms, self.rule_ids = allowed, reason, 1.0, ()


class RecordingScanner:
    """Test double for the write scanner (NOT Semgrep): records what it was asked to scan."""

    def __init__(self, allow=True):
        self.allow, self.calls = allow, []

    def __call__(self, rel_path, old, new, resolved_path=None):
        self.calls.append((rel_path, old, new))
        return Verdict(self.allow, "no new findings" if self.allow else "Semgrep found 1 new finding(s): test")


class RepoToolsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        ws = base / "workspace"
        (ws / "src" / "flask").mkdir(parents=True)
        (ws / ".git").mkdir()
        (ws / ".git" / "config").write_text("[remote] needle-in-git\n", encoding="utf-8")
        (ws / "src" / "flask" / "app.py").write_bytes(APP.encode("utf-8"))
        (ws / "src" / "flask" / "helpers.py").write_bytes(b"def helper():\n    return 'needle'\n")
        (ws / "src" / ".env").write_text(SECRET, encoding="utf-8")
        (ws / "docs.md").write_text("needle outside the read list\n", encoding="utf-8")
        self.ws, self.audit = ws, base / "audit.jsonl"
        self.receipt = IntentReceipt.from_dict({"task_id": "t", "intent": "fix", "workspace_root": "workspace",
                                                "capabilities": {"read": ["src/**"], "write": ["src/flask/app.py"]}}, base)
        self.telemetry = Telemetry([JsonlWriter(self.audit)])
        self.addCleanup(self.telemetry.close)

    def gateway(self, scanner=None):
        return Gateway(self.receipt, self.telemetry, write_scanner=scanner)

    def test_list_files_shows_only_readable_files(self):
        out = self.gateway().call("list_files", {"path": "."})
        self.assertFalse(out.is_error, out.text)
        self.assertEqual(out.text.splitlines(), ["src/flask/app.py", "src/flask/helpers.py"])
        for hidden in (".env", ".git", "docs.md"):
            self.assertNotIn(hidden, out.text)

    def test_list_files_refuses_protected_and_escaping_folders(self):
        hold = self.gateway()
        for path in (".git", "src/../..", "/etc", "src/./flask"):
            self.assertTrue(hold.call("list_files", {"path": path}).is_error, path)

    def test_search_finds_code_but_never_protected_or_unreadable_files(self):
        hold = self.gateway()
        out = hold.call("search_code", {"query": "def get_auth_token"})
        self.assertFalse(out.is_error, out.text)
        self.assertEqual(out.text, "src/flask/app.py:1501: def get_auth_token(environ):")
        needle = hold.call("search_code", {"query": "needle"}).text
        self.assertEqual(needle, "src/flask/helpers.py:2: return 'needle'")  # not .git, .env or docs.md
        self.assertTrue(hold.call("search_code", {"query": ""}).is_error)

    def test_read_lines_returns_numbered_range(self):
        out = self.gateway().call("read_lines", {"path": "src/flask/app.py", "start_line": 1500, "end_line": 1502})
        self.assertFalse(out.is_error, out.text)
        self.assertEqual(out.text.splitlines()[1:], ["1500: line 1500", "1501: def get_auth_token(environ):",
                                                     "1502:     return environ.get('A').split('Bearer ')[1]"])

    def test_read_lines_rejects_bad_ranges_types_and_protected_files(self):
        hold = self.gateway()
        for args in ({"path": "src/flask/app.py", "start_line": True, "end_line": 2},
                     {"path": "src/flask/app.py", "start_line": "1", "end_line": 2},
                     {"path": "src/.env", "start_line": 1, "end_line": 1},
                     {"path": "docs.md", "start_line": 1, "end_line": 1}):
            self.assertTrue(hold.call("read_lines", args).is_error, args)
        for start, end in ((0, 5), (5, 4), (1, 401)):
            self.assertTrue(hold.call("read_lines", {"path": "src/flask/app.py", "start_line": start, "end_line": end}).is_error)

    def test_edit_replaces_exactly_one_occurrence_and_is_scanned(self):
        scanner = RecordingScanner()
        fix = "    token = environ.get('A')\n    return token.split('Bearer ')[1] if token else None\n"
        out = self.gateway(scanner).call("edit_file", {"path": "src/flask/app.py",
                                                       "old_text": "    return environ.get('A').split('Bearer ')[1]\n",
                                                       "new_text": fix})
        self.assertFalse(out.is_error, out.text)
        on_disk = (self.ws / "src" / "flask" / "app.py").read_text(encoding="utf-8")
        self.assertTrue(on_disk.endswith(fix))
        self.assertEqual(len(scanner.calls), 1)
        self.assertEqual(scanner.calls[0][2], on_disk)  # the scanner saw exactly what was written

    def test_edit_denied_by_scanner_leaves_file_unchanged(self):
        out = self.gateway(RecordingScanner(allow=False)).call(
            "edit_file", {"path": "src/flask/app.py", "old_text": "line 7\n", "new_text": "import socket\n"})
        self.assertTrue(out.is_error)
        self.assertEqual((self.ws / "src" / "flask" / "app.py").read_bytes(), APP.encode("utf-8"))
        row = json.loads(self.audit.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual((row["tool_name"], row["decision"], row["exec_status"]), ("edit_file", "DENY", "not_run"))

    def test_edit_needs_a_unique_match_and_an_approved_file(self):
        hold = self.gateway()
        self.assertIn("found 0", hold.call("edit_file", {"path": "src/flask/app.py", "old_text": "nope", "new_text": "x"}).text)
        self.assertIn("found", hold.call("edit_file", {"path": "src/flask/app.py", "old_text": "line 1", "new_text": "x"}).text)
        for path in ("src/flask/helpers.py", "src/.env", ".git/config"):
            self.assertTrue(hold.call("edit_file", {"path": path, "old_text": "a", "new_text": "b"}).is_error, path)
        self.assertEqual((self.ws / "src" / "flask" / "app.py").read_bytes(), APP.encode("utf-8"))

    def test_edit_works_on_crlf_files(self):
        app = self.ws / "src" / "flask" / "app.py"
        app.write_bytes(b"def f(x):\r\n    return x.y\r\n")
        out = self.gateway().call("edit_file", {"path": "src/flask/app.py", "old_text": "    return x.y\n",
                                                "new_text": "    return x.y if x else None\n"})
        self.assertFalse(out.is_error, out.text)
        self.assertEqual(app.read_bytes(), b"def f(x):\r\n    return x.y if x else None\r\n")


if __name__ == "__main__":
    unittest.main()
