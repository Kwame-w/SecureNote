from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlsplit

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .extensions import db, limiter
from .forms import LoginForm, MfaForm, RegisterForm
from .models import User, _now, dummy_verify
from .security import audit

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid username or password."


def _safe_next(target: str | None) -> str:
    """A01: only follow relative redirects, so ?next= can't send users to a phishing site."""
    if target:
        parts = urlsplit(target)
        if not parts.scheme and not parts.netloc and target.startswith("/") and not target.startswith("//"):
            return target
    return url_for("notes.index")


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("notes.index"))
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            form.username.errors.append("That username is taken.")
        else:
            user = User(username=username)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            audit("register", username=username)
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])  # A07: slow down online password guessing
def login():
    if current_user.is_authenticated:
        return redirect(url_for("notes.index"))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        # A03: the ORM binds parameters, so "' OR 1=1 --" is just an odd username.
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        if user is None:
            dummy_verify(form.password.data)
            audit("login_failed", username=username, reason="unknown_user")
            flash(GENERIC_LOGIN_ERROR, "error")
        elif user.is_locked():
            dummy_verify(form.password.data)
            audit("login_blocked", username=username, reason="locked")
            # Same message as a bad password, so attackers can't tell the account exists.
            flash(GENERIC_LOGIN_ERROR, "error")
        elif not user.check_password(form.password.data):
            _record_failure(user, "bad_password")
            flash(GENERIC_LOGIN_ERROR, "error")
        elif user.mfa_enabled:
            # Password is right, but the user is NOT logged in yet. Only a short-lived
            # "pending" marker goes in a fresh session until the second factor is checked.
            db.session.commit()
            session.clear()
            session["mfa_user_id"] = user.id
            session["mfa_started"] = _now().timestamp()
            session["mfa_next"] = _safe_next(request.args.get("next"))
            audit("mfa_challenge", username=username)
            return redirect(url_for("auth.mfa"))
        else:
            return _complete_login(user, _safe_next(request.args.get("next")))
    return render_template("auth/login.html", form=form)


def _record_failure(user: User, reason: str) -> None:
    """Password and MFA failures share one counter, so neither factor can be brute forced."""
    user.failed_logins += 1
    if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
        user.locked_until = _now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
        user.failed_logins = 0
        audit("account_locked", username=user.username)
    db.session.commit()
    audit("login_failed", username=user.username, reason=reason)


def _complete_login(user: User, next_url: str, notice: str | None = None):
    user.failed_logins = 0
    user.locked_until = None
    db.session.commit()
    session.clear()  # A07: new session on login prevents session fixation
    login_user(user)
    session.permanent = True
    if notice:
        flash(notice, "success")
    audit("login_success", username=user.username, mfa=user.mfa_enabled)
    return redirect(next_url)


def _pending_mfa_user() -> User | None:
    user_id, started = session.get("mfa_user_id"), session.get("mfa_started")
    if user_id is None or started is None:
        return None
    if _now().timestamp() - started > current_app.config["MFA_PENDING_SECONDS"]:
        session.clear()
        return None
    return db.session.get(User, user_id)


@bp.route("/login/mfa", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # a 6-digit code must not be guessable by brute force
def mfa():
    user = _pending_mfa_user()
    if user is None:
        flash("Please sign in again.", "error")
        return redirect(url_for("auth.login"))
    form = MfaForm()
    if form.validate_on_submit():
        if user.is_locked():
            audit("login_blocked", username=user.username, reason="locked")
            session.clear()
            flash(GENERIC_LOGIN_ERROR, "error")
            return redirect(url_for("auth.login"))
        code = form.code.data.strip()
        if user.verify_totp(code):
            return _complete_login(user, session.get("mfa_next") or url_for("notes.index"))
        if len(code.replace(" ", "")) > 6 and user.use_recovery_code(code):
            remaining = user.remaining_recovery_codes()
            audit("recovery_code_used", username=user.username, remaining=remaining)
            return _complete_login(user, session.get("mfa_next") or url_for("notes.index"),
                                   notice=f"Recovery code accepted. {remaining} left.")
        _record_failure(user, "bad_mfa_code")
        flash("Invalid or already used code.", "error")
    return render_template("auth/mfa.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout")
    logout_user()
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("auth.login"))
