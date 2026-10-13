"""Account security settings: turning two-factor authentication on and off."""

from __future__ import annotations

import segno
from flask import Blueprint, flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required

from . import totp
from .extensions import db, limiter
from .forms import DisableMfaForm, EnableMfaForm
from .security import audit

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("/security")
@login_required
def security():
    return render_template("account/security.html", disable_form=DisableMfaForm())


@bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def mfa_setup():
    if current_user.mfa_enabled:
        return redirect(url_for("account.security"))

    # The new secret lives only in the session until the user proves their app works,
    # so a half-finished setup can never lock them out.
    secret = session.get("pending_totp_secret")
    if not secret:
        secret = session["pending_totp_secret"] = totp.generate_secret()

    form = EnableMfaForm()
    if form.validate_on_submit():
        step = totp.verify(secret, form.code.data)
        if step is None:
            form.code.errors.append("That code didn't match. Check your phone's clock and try again.")
        else:
            codes = totp.generate_recovery_codes()
            current_user.totp_secret = secret
            current_user.last_totp_step = step
            current_user.mfa_enabled = True
            current_user.set_recovery_codes(codes)
            db.session.commit()
            session.pop("pending_totp_secret", None)
            audit("mfa_enabled")
            # Shown exactly once; only hashes are stored.
            return render_template("account/recovery_codes.html", codes=codes)

    uri = totp.provisioning_uri(secret, current_user.username)
    qr = segno.make(uri, error="m").svg_data_uri(scale=5, border=2)
    spaced_secret = " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))
    return render_template("account/mfa_setup.html", form=form, qr=qr, secret=spaced_secret)


@bp.route("/mfa/disable", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def mfa_disable():
    form = DisableMfaForm()
    if not form.validate_on_submit():
        flash("Enter your password and a current code.", "error")
    elif not current_user.check_password(form.password.data):
        audit("mfa_disable_failed", reason="bad_password")
        flash("Password or code incorrect.", "error")
    elif not (current_user.verify_totp(form.code.data) or current_user.use_recovery_code(form.code.data)):
        audit("mfa_disable_failed", reason="bad_code")
        flash("Password or code incorrect.", "error")
    else:
        # Turning off a security control needs both factors, so a stolen session alone can't do it.
        current_user.disable_mfa()
        db.session.commit()
        audit("mfa_disabled")
        flash("Two-factor authentication is off.", "success")
    return redirect(url_for("account.security"))
