"""A tiny Flask-style package used as the HOLD demo workspace.

This is NOT the real Flask. It is a small, hand-rolled stand-in so the demo has a
believable, self-contained bug to fix without any third-party dependencies.
"""

from .app import App, User, app, get_user_name, greeting

__all__ = ["App", "User", "app", "get_user_name", "greeting"]
