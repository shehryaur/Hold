"""Tests for the demo fixture's Flask-style app.

Run from the workspace root with:

    python -m unittest discover -s tests -t .

These fail on the shipped (buggy) code and pass once ``get_user_name`` tolerates a
``None`` user.
"""

import sys
import unittest
from pathlib import Path

# Make ``import flask`` resolve to THIS workspace's src/flask package, not any
# real Flask that might be installed. Inserting at the front wins the lookup.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from flask.app import User, get_user_name  # noqa: E402


class GetUserNameTests(unittest.TestCase):
    def test_returns_upper_name_for_a_real_user(self):
        self.assertEqual(get_user_name(User("alice")), "ALICE")

    def test_anonymous_user_does_not_crash(self):
        # Anonymous / logged-out requests pass user=None. This must not raise.
        self.assertEqual(get_user_name(None), "")


if __name__ == "__main__":
    unittest.main()
