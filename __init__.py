from .src.admin import register_admin_blueprint
from .src.decorators import register_decorators
from .src.notifiers import (
    NOTIFIER_CLASSES,
    get_all_notifier_settings,
    get_configured_notifier,
)
from .src.notifiers.base import BaseNotifier
from .src.notifiers.discord import DiscordNotifier

__all__ = [
    "BaseNotifier",
    "DiscordNotifier",
    "NOTIFIER_CLASSES",
    "get_all_notifier_settings",
    "get_configured_notifier",
    "load",
]


def load(app):
    register_admin_blueprint(app)
    register_decorators(app)
