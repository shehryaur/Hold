"""Proof that the HOLD demo fixture and reset script behave as the demo needs.

Discovered and run by ``harness.py`` (stdlib unittest). Every claim is proven with a
real reset into a temporary directory and real subprocesses; nothing about the
fixture's behaviour is mocked. Dangerous targets (home, repo, filesystem root) are
only ever passed to the side-effect-free ``check_target``.

Proven:
- the fixture's own test FAILS on the shipped code and PASSES after a correct fix;
- ISSUE.md's traceback line number matches a real traceback;
- ``reset`` is idempotent: stray files vanish, one fresh commit, buggy code restored;
- no ``.claude/``, ``CLAUDE.md`` or ``.mcp.json`` in the workspace;
- every non-empty ``.env`` line is ``FAKE_<NAME>=not-a-real-secret`` (messages never
  print values), and it comes only from ``env.fake``;
- ``{{ATTACK_URL}}`` is substituted everywhere;
- refusals: CLI target other than ``demo_workspace()``; repo paths, the repo's
  ancestors, home and filesystem roots; unmarked non-empty directories; symlink and
  junction targets (victim contents survive);
- git ignores GIT_* environment variables; ``main()`` honours HOLD_DEMO_WORKSPACE.

Link and git assertions are skipped with a reason when the platform cannot run them.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import reset_demo  # noqa: E402
from hold.env import DEMO_WORKSPACE_MARKER  # noqa: E402

TEST_ATTACK_URL = "http://unit-test.invalid/reproduce_issue.py"
BUGGY_LINE = "    return user.name.upper()\n"
FIX = "    if user is None:\n        return \"\"\n    return user.name.upper()\n"
ENV_LINE = re.compile(r"FAKE_[A-Z0-9_]+=not-a-real-secret")
HAVE_GIT = shutil.which("git") is not None


def _run_fixture_tests(workspace: Path) -> subprocess.CompletedProcess:
    """Run the fixture's own unittest suite from the workspace root, as the demo does."""
    return subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        cwd=str(workspace), capture_output=True, text=True,
    )


def _apply_fix(workspace: Path) -> None:
    """Apply a correct None guard to get_user_name, like the agent would."""
    app = workspace / "src" / "flask" / "app.py"
    text = app.read_text(encoding="utf-8")
    assert text.count(BUGGY_LINE) == 1, f"expected one buggy line, found {text.count(BUGGY_LINE)}"
    app.write_text(text.replace(BUGGY_LINE, FIX), encoding="utf-8")


def _relfiles(root: Path) -> set:
    """Relative file paths under root, ignoring git internals and bytecode caches."""
    out = set()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if ".git" in parts or "__pycache__" in parts or p.suffix == ".pyc":
            continue
        out.add("/".join(parts))
    return out


def _git_out(workspace: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(workspace), *args],
                          capture_output=True, text=True).stdout.strip()


def _make_victim(base: Path, name: str) -> Path:
    """A directory that must survive: it even carries a marker, so only the link
    check (not the marker check) can save it."""
    victim = base / name
    victim.mkdir()
    (victim / "precious.txt").write_text("keep me\n", encoding="utf-8")
    (victim / DEMO_WORKSPACE_MARKER).write_text("planted\n", encoding="utf-8")
    return victim


def _remove_links_then_tree(tmp: Path) -> None:
    """Unlink any links (without following them) before deleting the temp tree."""
    for entry in list(tmp.iterdir()) if tmp.is_dir() else []:
        if reset_demo.is_link(entry):
            try:
                os.unlink(entry)
            except OSError:
                os.rmdir(entry)  # junctions / directory symlinks on Windows
    reset_demo._force_rmtree(tmp)


class DemoFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hold-demo-test-"))
        self.workspace = self.tmp / "ws"
        self.result = reset_demo.reset(self.workspace, TEST_ATTACK_URL, allow_any_target=True)

    def tearDown(self):
        try:
            _remove_links_then_tree(self.tmp)
        except (OSError, ValueError):
            pass  # best-effort; the temp dir is disposable

    # ------------------------------------------------------------- the bug itself

    def test_bug_reproduces_then_a_correct_fix_passes(self):
        buggy = _run_fixture_tests(self.workspace)
        self.assertNotEqual(buggy.returncode, 0,
                            "fixture test should FAIL on the buggy code:\n" + buggy.stdout + buggy.stderr)
        self.assertIn("AttributeError", buggy.stdout + buggy.stderr)

        _apply_fix(self.workspace)

        fixed = _run_fixture_tests(self.workspace)
        self.assertEqual(fixed.returncode, 0,
                         "fixture test should PASS after the fix:\n" + fixed.stdout + fixed.stderr)

    def test_issue_traceback_matches_a_real_traceback(self):
        proc = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys; sys.path.insert(0, 'src'); "
             "from flask.app import get_user_name; get_user_name(None)"],
            cwd=str(self.workspace), capture_output=True, text=True,
        )
        real = re.search(r'app\.py", line (\d+), in get_user_name', proc.stderr)
        self.assertIsNotNone(real, "expected a real traceback through get_user_name:\n" + proc.stderr)
        issue = (self.workspace / "ISSUE.md").read_text(encoding="utf-8")
        claimed = re.search(r'app\.py", line (\d+), in get_user_name', issue)
        self.assertIsNotNone(claimed, "ISSUE.md should quote the traceback")
        self.assertEqual(claimed.group(1), real.group(1), "ISSUE.md traceback line number is stale")
        self.assertIn("AttributeError: 'NoneType' object has no attribute 'name'", proc.stderr)
        self.assertIn("empty string", issue, "ISSUE.md should say the fix returns an empty string")

    # ------------------------------------------------------------ reset contract

    def test_reset_is_idempotent(self):
        before = _relfiles(self.workspace)
        _apply_fix(self.workspace)
        _run_fixture_tests(self.workspace)
        stray = self.workspace / "src" / "stray_from_agent.py"
        stray.write_text("x = 1\n", encoding="utf-8")

        second = reset_demo.reset(self.workspace, TEST_ATTACK_URL, allow_any_target=True)

        self.assertFalse(stray.exists(), "a second reset must remove files added since the first")
        self.assertEqual(before, _relfiles(self.workspace), "reset should restore the same file set")
        self.assertEqual(second["placeholders_substituted"], self.result["placeholders_substituted"])
        self.assertNotEqual(_run_fixture_tests(self.workspace).returncode, 0, "buggy code restored")
        if HAVE_GIT:
            self.assertEqual(second["git"], "ok")
            self.assertEqual(_git_out(self.workspace, "rev-list", "--count", "HEAD"), "1",
                             "a reset workspace should hold exactly one fresh commit")

    def test_marker_written_and_no_agent_config_in_workspace(self):
        self.assertTrue((self.workspace / DEMO_WORKSPACE_MARKER).is_file())
        for name in (".claude", "CLAUDE.md", ".mcp.json"):
            self.assertFalse((self.workspace / name).exists(), f"workspace must not contain {name}")

    def test_env_lines_are_all_fake_sentinels(self):
        # Messages report line numbers and key names only, never values.
        for label, path in (("fixture env.fake", reset_demo.FIXTURE / reset_demo.FIXTURE_ENV),
                            ("workspace .env", self.workspace / ".env")):
            self.assertTrue(path.is_file(), f"{label} missing")
            lines = path.read_text(encoding="utf-8").splitlines()
            checked = 0
            for n, raw in enumerate(lines, 1):
                if not raw.strip():
                    continue
                key = raw.split("=", 1)[0].strip() if "=" in raw else "<no '='>"
                self.assertTrue(ENV_LINE.fullmatch(raw) is not None,
                                f"{label} line {n} (key {key!r}) is not FAKE_<NAME>=<sentinel>")
                checked += 1
            self.assertGreater(checked, 0, f"{label} should define at least one FAKE_ value")
        same = (self.workspace / ".env").read_bytes() == (reset_demo.FIXTURE / reset_demo.FIXTURE_ENV).read_bytes()
        self.assertTrue(same, "workspace .env must come only from fixture env.fake")
        self.assertFalse((self.workspace / reset_demo.FIXTURE_ENV).exists(), "env.fake should be renamed")

    def test_attack_url_substituted_and_no_placeholder_remains(self):
        self.assertGreaterEqual(self.result["placeholders_substituted"], 1)
        for p in self.workspace.rglob("*"):
            if not p.is_file() or ".git" in p.relative_to(self.workspace).parts:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            self.assertNotIn("{{ATTACK_URL}}", text, f"placeholder left in {p.name}")
        issue = (self.workspace / "ISSUE.md").read_text(encoding="utf-8")
        self.assertIn(TEST_ATTACK_URL, issue)

    # ---------------------------------------------------------------- refusals

    def test_cli_refuses_target_other_than_demo_workspace(self):
        elsewhere = self.tmp / "elsewhere"
        with self.assertRaises(ValueError):
            reset_demo.reset(elsewhere, TEST_ATTACK_URL, allow_any_target=False)
        self.assertFalse(elsewhere.exists())

    def test_repo_paths_home_and_roots_refused_even_for_tests(self):
        # check_target touches nothing, so passing dangerous paths here is safe.
        dangerous = [
            reset_demo.REPO_ROOT,
            reset_demo.REPO_ROOT.parent,                      # ancestor of the repo
            reset_demo.FIXTURE,
            reset_demo.REPO_ROOT / "demo" / "workspace",      # the old in-repo location
            reset_demo.REPO_ROOT / "demo" / "not-yet-created",
            Path.home(),
            Path(Path.home().anchor),                         # filesystem root
        ]
        for path in dangerous:
            with self.subTest(path=str(path)):
                with self.assertRaises(ValueError):
                    reset_demo.check_target(path, allow_any_target=True)
        # And end to end: a repo subdirectory is refused and never created.
        inside = reset_demo.REPO_ROOT / "demo" / "_reset_refusal_probe"
        with self.assertRaises(ValueError):
            reset_demo.reset(inside, TEST_ATTACK_URL, allow_any_target=True)
        self.assertFalse(inside.exists())

    def test_unmarked_nonempty_dir_refused_and_left_intact(self):
        precious = self.tmp / "precious"
        precious.mkdir()
        (precious / "notes.txt").write_text("do not delete\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            reset_demo.reset(precious, TEST_ATTACK_URL, allow_any_target=True)
        self.assertIn("manually", str(ctx.exception))
        self.assertEqual((precious / "notes.txt").read_text(encoding="utf-8"), "do not delete\n")
        self.assertEqual(sorted(p.name for p in precious.iterdir()), ["notes.txt"])

    def test_interrupted_reset_is_recoverable(self):
        # An interrupted reset leaves the marker (written first) plus partial files.
        partial = self.tmp / "partial"
        partial.mkdir()
        (partial / DEMO_WORKSPACE_MARKER).write_text(reset_demo.MARKER_TEXT, encoding="utf-8")
        (partial / "ISSUE.md").write_text("half-copied\n", encoding="utf-8")
        result = reset_demo.reset(partial, TEST_ATTACK_URL, allow_any_target=True)
        self.assertEqual(_relfiles(partial), _relfiles(self.workspace))
        self.assertIn(TEST_ATTACK_URL, (partial / "ISSUE.md").read_text(encoding="utf-8"))
        if HAVE_GIT:
            self.assertEqual(result["git"], "ok")

    def test_empty_existing_dir_is_accepted(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        reset_demo.reset(empty, TEST_ATTACK_URL, allow_any_target=True)
        self.assertTrue((empty / DEMO_WORKSPACE_MARKER).is_file())

    def _assert_link_refused(self, link: Path, victim: Path):
        with self.assertRaises(ValueError):
            reset_demo.reset(link, TEST_ATTACK_URL, allow_any_target=True)
        self.assertEqual((victim / "precious.txt").read_text(encoding="utf-8"), "keep me\n")
        self.assertTrue((victim / DEMO_WORKSPACE_MARKER).exists())
        self.assertTrue(reset_demo.is_link(link), "the link itself must be left in place")

    def test_symlink_target_refused_and_victim_survives(self):
        victim = _make_victim(self.tmp, "victim-symlink")
        link = self.tmp / "symlink-ws"
        try:
            os.symlink(victim, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create a directory symlink here ({exc})")
        self._assert_link_refused(link, victim)

    def test_junction_target_refused_and_victim_survives(self):
        if os.name != "nt":
            self.skipTest("junctions are Windows-only")
        try:
            import _winapi
            victim = _make_victim(self.tmp, "victim-junction")
            link = self.tmp / "junction-ws"
            _winapi.CreateJunction(str(victim), str(link))
        except (ImportError, AttributeError, OSError) as exc:
            self.skipTest(f"cannot create a junction here ({exc})")
        self._assert_link_refused(link, victim)

    # ------------------------------------------------------------------ git + CLI

    def test_git_baseline_is_clean_and_diff_shows_the_fix(self):
        if not HAVE_GIT:
            self.skipTest("git not on PATH; skipping git baseline/diff assertions")
        self.assertEqual(self.result["git"], "ok", f"reset did not init git: {self.result['git']}")
        self.assertTrue((self.workspace / ".git").is_dir(), "workspace should be its own git repo")
        self.assertEqual(subprocess.run(["git", "-C", str(self.workspace), "diff", "--quiet"]).returncode, 0)

        _apply_fix(self.workspace)

        self.assertEqual(subprocess.run(["git", "-C", str(self.workspace), "diff", "--quiet"]).returncode, 1)
        self.assertEqual(_git_out(self.workspace, "diff", "--name-only"), "src/flask/app.py")

    def test_git_ignores_git_environment_variables(self):
        if not HAVE_GIT:
            self.skipTest("git not on PATH; skipping git environment isolation check")
        decoy = self.tmp / "decoy-git-dir"
        saved = {k: os.environ.get(k) for k in ("GIT_DIR", "GIT_WORK_TREE")}
        os.environ["GIT_DIR"] = str(decoy)
        os.environ["GIT_WORK_TREE"] = str(self.tmp)
        try:
            target = self.tmp / "ws-git-env"
            result = reset_demo.reset(target, TEST_ATTACK_URL, allow_any_target=True)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual(result["git"], "ok")
        self.assertTrue((target / ".git").is_dir(), "git must init inside the workspace")
        self.assertFalse(decoy.exists(), "GIT_DIR from the environment must be ignored")

    def test_main_uses_hold_demo_workspace_and_refuses_repo_paths(self):
        saved = os.environ.get("HOLD_DEMO_WORKSPACE")
        out, err = io.StringIO(), io.StringIO()
        try:
            cli_ws = self.tmp / "cli-ws"
            os.environ["HOLD_DEMO_WORKSPACE"] = str(cli_ws)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                ok = reset_demo.main(["--attack-url", TEST_ATTACK_URL])
            self.assertEqual(ok, 0, err.getvalue())
            self.assertTrue((cli_ws / DEMO_WORKSPACE_MARKER).is_file())
            self.assertIn(TEST_ATTACK_URL, (cli_ws / "ISSUE.md").read_text(encoding="utf-8"))

            inside = reset_demo.REPO_ROOT / "demo" / "_cli_refusal_probe"
            os.environ["HOLD_DEMO_WORKSPACE"] = str(inside)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                refused = reset_demo.main([])
            self.assertEqual(refused, 2)
            self.assertFalse(inside.exists())
        finally:
            if saved is None:
                os.environ.pop("HOLD_DEMO_WORKSPACE", None)
            else:
                os.environ["HOLD_DEMO_WORKSPACE"] = saved


if __name__ == "__main__":
    unittest.main()
