import logging
from functools import wraps

from CTFd.models import Solves, db
from CTFd.plugins.challenges import BaseChallenge
from CTFd.utils import get_config
from CTFd.utils.modes import TEAMS_MODE, get_model
from flask import url_for

from .notifiers import get_configured_notifier

logger = logging.getLogger(__name__)


def _send_solve_notification(user, team, challenge):
    notifier = get_configured_notifier()
    if not (notifier and bool(get_config("notifier_send_solves"))):
        return

    is_teams_mode = get_config("user_mode") == TEAMS_MODE

    user_name = user.name
    user_url = url_for("users.public", user_id=user.id, _external=True)
    team_name = team.name if is_teams_mode else None
    team_url = url_for("teams.public", team_id=team.id, _external=True) if is_teams_mode else None

    challenge_url = url_for(
        "challenges.listing",
        _external=True,
        _anchor=f"{challenge.name}-{challenge.id}",
    )

    Model = get_model()
    solve_count = (
        db.session.query(db.func.count(Solves.id))
        .filter(Solves.challenge_id == challenge.id)
        .join(Model, Solves.account_id == Model.id)
        .filter(Model.banned == False, Model.hidden == False)  # noqa: E712 — SQLAlchemy filter
        .scalar()
    )

    max_solves = get_config("notifier_solve_count")
    max_solves = int(max_solves) if max_solves is not None else None
    if max_solves is not None and solve_count > max_solves:
        return

    notifier.notify_solve(
        get_config(
            "notifier_solve_msg",
            "{solver} solved {challenge} ({solve_num} solve)",
        ),
        user_name,
        user_url,
        is_teams_mode,
        team_name,
        team_url,
        challenge.name,
        challenge_url,
        solve_count,
    )


def _chal_solve_decorator(chal_solve_func):
    @wraps(chal_solve_func)
    def wrapper(user, team, challenge, request):
        chal_solve_func(user, team, challenge, request)
        _send_solve_notification(user, team, challenge)

    return wrapper


def _geo_chal_solve_decorator(geo_solve_func):
    @wraps(geo_solve_func)
    def wrapper(cls, user, team, challenge, request):
        geo_solve_func(cls, user, team, challenge, request)
        try:
            _send_solve_notification(user, team, challenge)
        except Exception as e:
            logger.error(f"Error in geo challenge notification: {e}")

    return wrapper


def _event_publish_decorator(event_publish_func):
    @wraps(event_publish_func)
    def wrapper(*args, **kwargs):
        event_publish_func(*args, **kwargs)

        if kwargs["type"] == "notification":
            notifier = get_configured_notifier()
            if notifier and bool(get_config("notifier_send_notifications")):
                notification = kwargs["data"]
                notifier.notify_message(notification["title"], notification["content"])

    return wrapper


def _apply_challenge_decorators():
    BaseChallenge.solve = _chal_solve_decorator(BaseChallenge.solve)
    try:
        from CTFd.plugins.challenges import CHALLENGE_CLASSES

        if "geo" not in CHALLENGE_CLASSES:
            logger.info("Geo challenge type not found in CHALLENGE_CLASSES, using base decorator")
            return

        geo_challenge_class = CHALLENGE_CLASSES["geo"]
        if geo_challenge_class.solve is BaseChallenge.solve:
            return

        original_solve = geo_challenge_class.solve.__func__
        geo_challenge_class.solve = classmethod(_geo_chal_solve_decorator(original_solve))
        logger.info("Geo challenge decorator applied successfully")
    except Exception as e:
        logger.info(f"Error applying challenge decorators: {e}")


def register_decorators(app):
    app.events_manager.publish = _event_publish_decorator(app.events_manager.publish)

    @app.before_first_request
    def setup_decorators():
        _apply_challenge_decorators()
