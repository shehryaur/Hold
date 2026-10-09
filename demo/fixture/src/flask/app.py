"""A tiny Flask-style module for the HOLD demo workspace.

This is NOT the real Flask. It is a minimal stand-in: a small application object
with a ``route`` decorator plus a couple of view helpers. It is deliberately tiny
so the demo has one real, reproducible bug to fix and nothing else to distract.
"""


class User:
    """A minimal user record."""

    def __init__(self, name):
        self.name = name


class App:
    """A very small Flask-like application object (an in-memory route registry)."""

    def __init__(self, import_name):
        self.import_name = import_name
        self.routes = {}

    def route(self, rule):
        """Register a view function for ``rule`` (like ``@app.route`` in Flask)."""

        def decorator(func):
            self.routes[rule] = func
            return func

        return decorator


app = App(__name__)


def get_user_name(user):
    """Return the user's display name in upper case.

    BUG: this crashes with ``AttributeError`` when ``user`` is ``None`` (for
    example an anonymous, logged-out request), because it dereferences
    ``user.name`` without checking for ``None`` first.
    """
    return user.name.upper()


@app.route("/greeting")
def greeting(user=None):
    """Greeting view. Anonymous visitors call this with ``user=None``."""
    return "Hello, " + get_user_name(user)
