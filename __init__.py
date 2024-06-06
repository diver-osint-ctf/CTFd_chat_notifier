from CTFd.plugins.challenges import BaseChallenge
from CTFd.utils.modes import TEAMS_MODE, get_mode_as_word, get_model
from CTFd.utils.decorators import admins_only
from CTFd.utils.humanize.numbers import ordinalize
from CTFd.utils import get_config, set_config
from CTFd.cache import clear_config
from CTFd.models import Solves, db
from flask import (
    url_for,
    Blueprint,
    render_template,
    redirect,
    request,
    session,
    abort,
    Markup,
)
from functools import wraps
import requests


class BaseNotifier(object):
    def get_settings(self):
        return []

    def is_configured(self):
        return True

    def notify_solve(
        self, format, solver_name, solver_url, challenge_name, challenge_url, solve_num
    ):
        pass

    def notify_message(self, title, content):
        pass


class DiscordNotifier(BaseNotifier):
    def get_settings(self):
        return ["notifier_discord_webhook_url"]

    def get_webhook_url(self):
        return get_config("notifier_discord_webhook_url")

    def is_configured(self):
        return bool(self.get_webhook_url())

    def notify_solve(
        self, format, solver_name, solver_url, challenge_name, challenge_url, solve_num
    ):
        markdown_msg = format.format(
            solver="[{solver_name}]({solver_url})".format(
                solver_name=solver_name, solver_url=solver_url
            ),
            challenge="[{challenge_name}]({challenge_url})".format(
                challenge_name=challenge_name, challenge_url=challenge_url
            ),
            solve_num=ordinalize(solve_num),
        )

        is_first_blood = solve_num == 1
        if is_first_blood:
            markdown_msg = ":drop_of_blood: " + markdown_msg
            requests.post(
                self.get_webhook_url(),
                json={
                    "embeds": [
                        {
                            "title": "First Blood! :first_place:",
                            "description": markdown_msg,
                            "color": 15158332,
                        }
                    ]
                },
            )
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


"""
Global dictionary used to hold all the supported chat services. To add support for a new chat service, create a plugin and insert
your BaseNotifier subclass instance into this dictionary to register it.
"""
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
    for k, v in NOTIFIER_CLASSES.items():
        for setting in v.get_settings():
            if setting in settings:
                raise Exception(
                    "Notifier {0} uses duplicate setting name {1}", v, setting
                )
            settings.add(setting)
    return settings


def load(app):
    chat_notifier = Blueprint("chat_notifier", __name__, template_folder="templates")

    @chat_notifier.route("/admin/chat_notifier", methods=["GET", "POST"])
    @admins_only
    def chat_notifier_admin():
        clear_config()
        if request.method == "POST":
            if (
                request.form["notifier_type"]
                and request.form["notifier_type"] not in NOTIFIER_CLASSES.keys()
            ):
                abort(400)
            set_config("notifier_type", request.form["notifier_type"])
            set_config(
                "notifier_send_notifications",
                "notifier_send_notifications" in request.form,
            )
            set_config("notifier_send_solves", "notifier_send_solves" in request.form)
            set_config("notifier_solve_msg", request.form["notifier_solve_msg"])
            if request.form["notifier_solve_count"]:
                set_config(
                    "notifier_solve_count", int(request.form["notifier_solve_count"])
                )
            else:
                set_config("notifier_solve_count", None)
            for setting in get_all_notifier_settings():
                set_config(setting, request.form[setting])
            return redirect(url_for("chat_notifier.chat_notifier_admin"))
        else:
            context = {
                "nonce": session["nonce"],
                "supported_notifier_types": NOTIFIER_CLASSES.keys(),
                "notifier_type": get_config("notifier_type"),
                "notifier_send_notifications": get_config(
                    "notifier_send_notifications"
                ),
                "notifier_send_solves": get_config("notifier_send_solves"),
                "notifier_solve_msg": get_config("notifier_solve_msg"),
                "notifier_solve_count": get_config("notifier_solve_count"),
            }
            for setting in get_all_notifier_settings():
                context[setting] = get_config(setting)
            supported_notifier_settings = {}
            for k, v in NOTIFIER_CLASSES.items():
                supported_notifier_settings[k] = Markup(
                    render_template(
                        "chat_notifier/admin_notifier_settings/{}.html".format(k),
                        **context
                    )
                )
            context["supported_notifier_settings"] = supported_notifier_settings
            return render_template("chat_notifier/admin.html", **context)

    app.register_blueprint(chat_notifier)

    def chal_solve_decorator(chal_solve_func):
        @wraps(chal_solve_func)
        def wrapper(user, team, challenge, request):
            chal_solve_func(user, team, challenge, request)

            notifier = get_configured_notifier()
            if notifier and bool(get_config("notifier_send_solves")):
                if get_mode_as_word() == TEAMS_MODE:
                    solver = team
                    solver_url = url_for(
                        "teams.public", team_id=solver.account_id, _external=True
                    )
                else:
                    solver = user
                    solver_url = url_for(
                        "users.public", user_id=solver.account_id, _external=True
                    )
                challenge_url = url_for(
                    "challenges.listing",
                    _external=True,
                    _anchor="{challenge.name}-{challenge.id}".format(
                        challenge=challenge
                    ),
                )

                Model = get_model()
                solve_count = (
                    db.session.query(db.func.count(Solves.id))
                    .filter(Solves.challenge_id == challenge.id)
                    .join(Model, Solves.account_id == Model.id)
                    .filter(Model.banned == False, Model.hidden == False)
                    .scalar()
                )

                max_solves = get_config("notifier_solve_count")
                max_solves = int(max_solves) if max_solves is not None else None

                if max_solves is None or solve_count <= max_solves:
                    notifier.notify_solve(
                        get_config(
                            "notifier_solve_msg",
                            "{solver} solved {challenge} ({solve_num} solve)",
                        ),
                        solver.name,
                        solver_url,
                        challenge.name,
                        challenge_url,
                        solve_count,
                    )

        return wrapper

    BaseChallenge.solve = chal_solve_decorator(BaseChallenge.solve)

    def event_publish_decorator(event_publish_func):
        @wraps(event_publish_func)
        def wrapper(*args, **kwargs):
            event_publish_func(args, kwargs)

            if kwargs["type"] == "notification":
                notifier = get_configured_notifier()
                if notifier and bool(get_config("notifier_send_notifications")):
                    notification = kwargs["data"]
                    notifier.notify_message(
                        notification["title"], notification["content"]
                    )

        return wrapper

    app.events_manager.publish = event_publish_decorator(app.events_manager.publish)
