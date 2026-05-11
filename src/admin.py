from CTFd.utils import get_config, set_config
from CTFd.utils.decorators import admins_only
from CTFd.cache import clear_config
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

from .notifiers import NOTIFIER_CLASSES, get_all_notifier_settings


def register_admin_blueprint(app):
    chat_notifier = Blueprint(
        "chat_notifier", __name__, template_folder="../templates"
    )

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
            set_config(
                "notifier_send_solves", "notifier_send_solves" in request.form
            )
            set_config("notifier_solve_msg", request.form["notifier_solve_msg"])
            if request.form["notifier_solve_count"]:
                set_config(
                    "notifier_solve_count",
                    int(request.form["notifier_solve_count"]),
                )
            else:
                set_config("notifier_solve_count", None)
            for setting in get_all_notifier_settings():
                set_config(setting, request.form[setting])
            return redirect(url_for("chat_notifier.chat_notifier_admin"))

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
                    **context,
                )
            )
        context["supported_notifier_settings"] = supported_notifier_settings
        return render_template("chat_notifier/admin.html", **context)

    app.register_blueprint(chat_notifier)
