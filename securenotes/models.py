from __future__ import annotations

import secrets
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask_login import UserMixin

from . import totp
from .extensions import db, login_manager

# A02 Cryptographic Failures: Argon2id is memory-hard, salted per password, and the
# current OWASP recommendation for password storage.
_hasher = PasswordHasher()


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    # Multi-factor authentication (TOTP). last_totp_step blocks replay of a used code.
    totp_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    last_totp_step = db.Column(db.Integer, nullable=True)
    notes = db.relationship("Note", back_populates="owner", cascade="all, delete-orphan")
    recovery_codes = db.relationship("RecoveryCode", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = _hasher.hash(password)

    def check_password(self, password: str) -> bool:
        try:
            _hasher.verify(self.password_hash, password)
        except (VerificationError, InvalidHashError):
            return False
        if _hasher.check_needs_rehash(self.password_hash):
            # Transparently upgrade hashes when the cost parameters are raised.
            self.password_hash = _hasher.hash(password)
        return True

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > _now()

    def verify_totp(self, code: str) -> bool:
        if not self.totp_secret:
            return False
        step = totp.verify(self.totp_secret, code, self.last_totp_step)
        if step is None:
            return False
        self.last_totp_step = step
        return True

    def set_recovery_codes(self, codes: list[str]) -> None:
        """Recovery codes are stored hashed, like passwords, and shown to the user only once."""
        self.recovery_codes = [RecoveryCode(code_hash=_hasher.hash(c)) for c in codes]

    def use_recovery_code(self, code: str) -> bool:
        code = code.strip().lower()
        for rc in self.recovery_codes:
            if rc.used_at is None:
                try:
                    _hasher.verify(rc.code_hash, code)
                except (VerificationError, InvalidHashError):
                    continue
                rc.used_at = _now()  # single use
                return True
        return False

    def remaining_recovery_codes(self) -> int:
        return sum(1 for rc in self.recovery_codes if rc.used_at is None)

    def disable_mfa(self) -> None:
        self.mfa_enabled = False
        self.totp_secret = None
        self.last_totp_step = None
        self.recovery_codes = []


class RecoveryCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User", back_populates="recovery_codes")


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=_now, onupdate=_now)
    owner = db.relationship("User", back_populates="notes")


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


def dummy_verify(password: str) -> None:
    """Spend the same time as a real check so response timing doesn't reveal valid usernames."""
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except VerificationError:
        pass


_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))
