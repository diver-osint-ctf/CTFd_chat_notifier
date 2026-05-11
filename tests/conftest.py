"""Test fixtures.

CTFd is a runtime dependency we don't pull in for unit tests, so we register
just enough fake modules in sys.modules to satisfy `from CTFd.utils import
get_config` and the humanize helper used by DiscordNotifier.
"""

from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock

import pytest

# Make the notifier modules importable as top-level packages. We add the
# plugin's `src/` directory to sys.path rather than the plugin root, because
# the plugin root has its own `__init__.py` (the CTFd plugin entrypoint) —
# importing `src.notifiers...` would resolve `src` through that parent
# package and execute the plugin's __init__.py, which needs CTFd installed.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)


def _ordinalize(n: int) -> str:
    # Mirrors CTFd.utils.humanize.numbers.ordinalize for the small integers
    # we exercise in tests (1st/2nd/3rd/4th/11th-13th/21st...).
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _install_ctfd_stubs() -> MagicMock:
    """Register fake CTFd modules. Returns the shared get_config mock."""
    get_config = MagicMock(return_value=None)
    set_config = MagicMock()

    ctfd = sys.modules.setdefault("CTFd", types.ModuleType("CTFd"))
    utils = types.ModuleType("CTFd.utils")
    utils.get_config = get_config
    utils.set_config = set_config

    humanize = types.ModuleType("CTFd.utils.humanize")
    numbers = types.ModuleType("CTFd.utils.humanize.numbers")
    numbers.ordinalize = _ordinalize

    sys.modules["CTFd"] = ctfd
    sys.modules["CTFd.utils"] = utils
    sys.modules["CTFd.utils.humanize"] = humanize
    sys.modules["CTFd.utils.humanize.numbers"] = numbers
    return get_config


# Install stubs at import time so test modules can `from src.notifiers...`
# at module scope.
_install_ctfd_stubs()


@pytest.fixture
def config_map(monkeypatch):
    """Drive `CTFd.utils.get_config(key)` from a plain dict.

    Lets each test set up the relevant config keys without touching globals.
    """
    store: dict[str, object] = {}

    def fake_get_config(key, default=None):
        return store.get(key, default)

    import CTFd.utils as ctfd_utils

    monkeypatch.setattr(ctfd_utils, "get_config", fake_get_config)
    # Also patch the already-bound reference inside the notifier module —
    # `from CTFd.utils import get_config` captures the symbol at import time,
    # so swapping it on the module isn't enough.
    from notifiers import discord as discord_mod

    monkeypatch.setattr(discord_mod, "get_config", fake_get_config)

    import notifiers as notifiers_pkg

    monkeypatch.setattr(notifiers_pkg, "get_config", fake_get_config)
    return store


@pytest.fixture
def requests_mock(monkeypatch):
    """Replace `requests.post` inside the discord notifier module."""
    from notifiers import discord as discord_mod

    post = MagicMock()
    monkeypatch.setattr(discord_mod.requests, "post", post)
    return post
