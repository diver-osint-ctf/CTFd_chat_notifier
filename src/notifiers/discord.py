import requests
from CTFd.utils import get_config
from CTFd.utils.humanize.numbers import ordinalize

from .base import BaseNotifier


class DiscordNotifier(BaseNotifier):
    def get_settings(self):
        return [
            "notifier_discord_webhook_url",
            "notifier_discord_admin_webhook_url",
        ]

    def get_webhook_url(self):
        return get_config("notifier_discord_webhook_url")

    def get_admin_webhook_url(self):
        return get_config("notifier_discord_admin_webhook_url")

    def is_configured(self):
        return bool(self.get_webhook_url())

    def notify_solve(
        self,
        format,
        user_name,
        user_url,
        is_team_mode,
        team_name,
        team_url,
        challenge_name,
        challenge_url,
        solve_num,
    ):
        if is_team_mode:
            solver_msg = f"[{user_name}]({user_url}) ([{team_name}]({team_url}))"
        else:
            solver_msg = f"[{user_name}]({user_url})"

        markdown_msg = format.format(
            solver=solver_msg,
            challenge=f"[{challenge_name}]({challenge_url})",
            solve_num=ordinalize(solve_num),
        )

        is_first_blood = solve_num == 1
        if is_first_blood:
            markdown_msg = ":drop_of_blood: " + markdown_msg
            payload = {
                "embeds": [
                    {
                        "title": "First Blood! :first_place:",
                        "description": markdown_msg,
                        "color": 15158332,
                    }
                ]
            }
            requests.post(self.get_webhook_url(), json=payload)
            admin_webhook_url = self.get_admin_webhook_url()
            if admin_webhook_url:
                requests.post(admin_webhook_url, json=payload)
        else:
            requests.post(self.get_webhook_url(), json={"content": markdown_msg})

    def notify_message(self, title, content):
        requests.post(
            self.get_webhook_url(),
            json={
                "embeds": [
                    {
                        "title": title,
                        "description": content,
                    }
                ]
            },
        )
