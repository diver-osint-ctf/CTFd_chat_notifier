from CTFd.utils import get_config

from .base import BaseNotifier
from .discord import DiscordNotifier

__all__ = [
    "NOTIFIER_CLASSES",
    "BaseNotifier",
    "DiscordNotifier",
    "get_all_notifier_settings",
    "get_configured_notifier",
]

# Global dictionary used to hold all the supported chat services. To add support
# for a new chat service, create a plugin and insert your BaseNotifier subclass
# instance into this dictionary to register it.
NOTIFIER_CLASSES = {"discord": DiscordNotifier()}


def get_configured_notifier():
    notifier_type = get_config("notifier_type")
    if not notifier_type:
        return None
    notifier = NOTIFIER_CLASSES[notifier_type]
    if not notifier.is_configured():
        return None
    return notifier


def get_all_notifier_settings():
    settings = set()
    for notifier in NOTIFIER_CLASSES.values():
        for setting in notifier.get_settings():
            if setting in settings:
                raise Exception("Notifier {0} uses duplicate setting name {1}", notifier, setting)
            settings.add(setting)
    return settings
