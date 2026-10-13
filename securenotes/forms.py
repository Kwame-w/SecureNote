from __future__ import annotations

import re

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError

# A07: block the most common passwords outright. A real deployment would also check
# Have I Been Pwned's k-anonymity API; this list keeps the demo offline.
COMMON_PASSWORDS = {
    "123456789012", "password1234", "passwordpassword", "qwertyuiop12", "iloveyou1234",
    "letmein12345", "welcome12345", "administrator", "changeme1234", "password123!",
    "qwerty123456", "football1234", "1q2w3e4r5t6y", "aaaaaaaaaaaa", "abc123abc123",
}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def validate_username(form, field):
    if not USERNAME_RE.match(field.data or ""):
        raise ValidationError("Use 3-32 letters, numbers, dots, dashes or underscores.")


def strong_password(form, field):
    password = field.data or ""
    if password.lower() in COMMON_PASSWORDS:
        raise ValidationError("That password is too common.")
    username = getattr(form, "username", None)
    if username and username.data and username.data.lower() in password.lower():
        raise ValidationError("The password must not contain your username.")
    if len(set(password)) < 5:
        raise ValidationError("The password needs more variety.")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), validate_username])
    # NIST SP 800-63B: favour length over composition rules; allow long passphrases.
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128), strong_password])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", "Passwords must match.")])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=32)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])


class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=120)])
    body = TextAreaField("Note", validators=[Length(max=20000)])


class DeleteForm(FlaskForm):
    """Empty form so delete buttons carry a CSRF token."""


class MfaForm(FlaskForm):
    code = StringField("Authentication code", validators=[DataRequired(), Length(max=32)])


class EnableMfaForm(FlaskForm):
    code = StringField("Code from your app", validators=[DataRequired(), Length(min=6, max=7)])


class DisableMfaForm(FlaskForm):
    password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    code = StringField("Code from your app", validators=[DataRequired(), Length(max=32)])
