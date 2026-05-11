class BaseNotifier(object):
    def get_settings(self):
        return []

    def is_configured(self):
        return True

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
        pass

    def notify_message(self, title, content):
        pass
