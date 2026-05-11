"""Unit tests for src.notifiers.discord.DiscordNotifier.

Covers in particular the optional admin webhook routing for first-blood
notifications, which is the recently-added behavior:

  - first-blood fans out to both webhooks when admin URL is set
  - first-blood goes to public only when admin URL is missing
  - second/later solves never reach the admin webhook
  - notify_message (announcements) never reach the admin webhook
"""

from __future__ import annotations

import pytest

from notifiers.discord import DiscordNotifier

PUBLIC_URL = "https://discord.example/api/webhooks/public/token"
ADMIN_URL = "https://discord.example/api/webhooks/admin/token"

FIRST_BLOOD_TITLE = "First Blood! :first_place:"
FIRST_BLOOD_COLOR = 15158332


def _solve(
    notifier,
    solve_num,
    *,
    msg="{solver} solved {challenge} ({solve_num})",
    is_team_mode=False,
    user_name="alice",
    user_url="https://ctf.example/users/1",
    team_name="team-a",
    team_url="https://ctf.example/teams/1",
    challenge_name="pwn-me",
    challenge_url="https://ctf.example/chals/1",
):
    notifier.notify_solve(
        msg,
        user_name,
        user_url,
        is_team_mode,
        team_name,
        team_url,
        challenge_name,
        challenge_url,
        solve_num,
    )


class TestSettings:
    def test_get_settings_includes_admin_webhook(self):
        notifier = DiscordNotifier()
        assert notifier.get_settings() == [
            "notifier_discord_webhook_url",
            "notifier_discord_admin_webhook_url",
        ]

    def test_is_configured_requires_public_webhook(self, config_map):
        notifier = DiscordNotifier()
        assert notifier.is_configured() is False

        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        assert notifier.is_configured() is True

    def test_is_configured_false_when_only_admin_set(self, config_map):
        # admin URL alone is not enough — the public webhook is the primary
        # channel and must be present for the notifier to engage at all.
        config_map["notifier_discord_admin_webhook_url"] = ADMIN_URL
        assert DiscordNotifier().is_configured() is False

    def test_get_admin_webhook_url_returns_configured_value(self, config_map):
        config_map["notifier_discord_admin_webhook_url"] = ADMIN_URL
        assert DiscordNotifier().get_admin_webhook_url() == ADMIN_URL


class TestFirstBloodFanOut:
    def test_first_blood_posts_to_both_webhooks(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        config_map["notifier_discord_admin_webhook_url"] = ADMIN_URL

        _solve(DiscordNotifier(), solve_num=1)

        assert requests_mock.call_count == 2
        urls = [c.args[0] for c in requests_mock.call_args_list]
        assert PUBLIC_URL in urls
        assert ADMIN_URL in urls

        # Both posts carry the same embed payload.
        payloads = [c.kwargs["json"] for c in requests_mock.call_args_list]
        assert payloads[0] == payloads[1]
        embed = payloads[0]["embeds"][0]
        assert embed["title"] == FIRST_BLOOD_TITLE
        assert embed["color"] == FIRST_BLOOD_COLOR
        assert ":drop_of_blood:" in embed["description"]

    def test_first_blood_posts_only_public_when_admin_unset(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        # notifier_discord_admin_webhook_url left absent.

        _solve(DiscordNotifier(), solve_num=1)

        assert requests_mock.call_count == 1
        assert requests_mock.call_args.args[0] == PUBLIC_URL
        assert "embeds" in requests_mock.call_args.kwargs["json"]

    @pytest.mark.parametrize("empty", ["", None])
    def test_empty_string_admin_url_is_treated_as_unset(self, config_map, requests_mock, empty):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        config_map["notifier_discord_admin_webhook_url"] = empty

        _solve(DiscordNotifier(), solve_num=1)

        assert requests_mock.call_count == 1


class TestRegularSolve:
    def test_regular_solve_posts_content_only(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL

        _solve(DiscordNotifier(), solve_num=2)

        assert requests_mock.call_count == 1
        payload = requests_mock.call_args.kwargs["json"]
        assert "embeds" not in payload
        assert "content" in payload
        # solve_num=2 → "2nd" via ordinalize
        assert "2nd" in payload["content"]

    def test_regular_solve_does_not_hit_admin_webhook(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        config_map["notifier_discord_admin_webhook_url"] = ADMIN_URL

        _solve(DiscordNotifier(), solve_num=3)

        assert requests_mock.call_count == 1
        assert requests_mock.call_args.args[0] == PUBLIC_URL


class TestSolverFormatting:
    def test_solo_mode_omits_team(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL

        _solve(
            DiscordNotifier(),
            solve_num=2,
            user_name="alice",
            user_url="https://ctf.example/u/1",
            is_team_mode=False,
            challenge_name="pwn",
            challenge_url="https://ctf.example/c/1",
        )

        content = requests_mock.call_args.kwargs["json"]["content"]
        assert "[alice](https://ctf.example/u/1)" in content
        assert "team-a" not in content
        assert "[pwn](https://ctf.example/c/1)" in content

    def test_team_mode_includes_team(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL

        _solve(
            DiscordNotifier(),
            solve_num=2,
            user_name="alice",
            user_url="https://ctf.example/u/1",
            is_team_mode=True,
            team_name="team-a",
            team_url="https://ctf.example/t/1",
        )

        content = requests_mock.call_args.kwargs["json"]["content"]
        assert "[alice](https://ctf.example/u/1)" in content
        assert "[team-a](https://ctf.example/t/1)" in content

    def test_template_placeholders_are_expanded(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL

        _solve(
            DiscordNotifier(),
            solve_num=5,
            msg="SOLVER={solver} CHAL={challenge} NTH={solve_num}",
        )

        content = requests_mock.call_args.kwargs["json"]["content"]
        for marker in ("SOLVER=", "CHAL=", "NTH=5th"):
            assert marker in content, f"missing {marker!r} in {content!r}"

    def test_first_blood_description_contains_drop_emoji_and_solver(
        self, config_map, requests_mock
    ):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL

        _solve(DiscordNotifier(), solve_num=1, user_name="alice")

        desc = requests_mock.call_args.kwargs["json"]["embeds"][0]["description"]
        assert desc.startswith(":drop_of_blood: ")
        assert "alice" in desc
        # 1st via ordinalize
        assert "1st" in desc


class TestNotifyMessage:
    def test_notify_message_posts_embed_to_public_only(self, config_map, requests_mock):
        config_map["notifier_discord_webhook_url"] = PUBLIC_URL
        config_map["notifier_discord_admin_webhook_url"] = ADMIN_URL

        DiscordNotifier().notify_message("Heads up", "fresh hint posted")

        # Announcements never fan out to the admin webhook — that channel is
        # specifically scoped to first-blood events.
        assert requests_mock.call_count == 1
        call = requests_mock.call_args
        assert call.args[0] == PUBLIC_URL
        embed = call.kwargs["json"]["embeds"][0]
        assert embed["title"] == "Heads up"
        assert embed["description"] == "fresh hint posted"
