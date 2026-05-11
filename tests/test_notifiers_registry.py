"""Unit tests for the notifier registry in src.notifiers (the package init)."""

from __future__ import annotations

import pytest

from notifiers import (
    NOTIFIER_CLASSES,
    get_all_notifier_settings,
    get_configured_notifier,
)
from notifiers.discord import DiscordNotifier

PUBLIC_URL = "https://discord.example/api/webhooks/public/token"


def test_discord_is_registered():
    assert "discord" in NOTIFIER_CLASSES
    assert isinstance(NOTIFIER_CLASSES["discord"], DiscordNotifier)


def test_get_all_notifier_settings_includes_both_discord_urls():
    settings = get_all_notifier_settings()
    assert "notifier_discord_webhook_url" in settings
    assert "notifier_discord_admin_webhook_url" in settings


class TestGetConfiguredNotifier:
    def test_returns_none_when_type_unset(self, config_map):
        assert get_configured_notifier() is None

    def test_returns_none_when_notifier_not_configured(self, config_map):
        # discord chosen as the active notifier, but no webhook URL set.
        config_map["notifier_type"] = "discord"
        assert get_configured_notifier() is None

    def test_returns_instance_when_fully_configured(self, config_map):
        config_map["notifier_type"] = "discord"
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        notifier = get_configured_notifier()
        assert isinstance(notifier, DiscordNotifier)

    def test_unknown_notifier_type_raises(self, config_map):
        config_map["notifier_type"] = "telegram"  # not registered
        with pytest.raises(KeyError):
            get_configured_notifier()
