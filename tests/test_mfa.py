"""Multi-factor authentication (A07): TOTP per RFC 6238, recovery codes, replay and brute-force protection."""

import hashlib
import re
import time

import pytest

from securenotes import totp
from securenotes.extensions import db
from securenotes.models import User

from .conftest import STRONG, login, logout, register

# --- the TOTP algorithm itself ------------------------------------------------

# Public RFC 6238 test secret (base32 of b"12345678901234567890"), not a real credential.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # gitleaks:allow


@pytest.mark.parametrize("unix_time,expected", [
    # RFC 6238 Appendix B test vectors (SHA-1, 8 digits).
    (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130"),
])
def test_rfc6238_vectors(unix_time, expected):
    key = b"12345678901234567890"
    assert totp.hotp(key, unix_time // 30, digits=8, digest=hashlib.sha1) == expected


def test_verify_accepts_adjacent_steps_and_blocks_replay():
    now = 1_700_000_000
    code = totp.code_at(RFC_SECRET, now)
    step = totp.verify(RFC_SECRET, code, now=now)
    assert step == totp.current_step(now)
    assert totp.verify(RFC_SECRET, code, now=now + 30) == step          # clock drift tolerated
    assert totp.verify(RFC_SECRET, code, now=now + 90) is None          # too old
    assert totp.verify(RFC_SECRET, code, last_used_step=step, now=now) is None  # replay
    assert totp.verify(RFC_SECRET, "abcdef", now=now) is None
    assert totp.verify(RFC_SECRET, "12345", now=now) is None


def test_provisioning_uri_and_recovery_codes():
    uri = totp.provisioning_uri("ABC", "alice")
    assert uri.startswith("otpauth://totp/SecureNotes%3Aalice?") and "secret=ABC" in uri
    codes = totp.generate_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    assert all(re.fullmatch(r"[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}", c) for c in codes)


# --- the web flow -------------------------------------------------------------

def _enable_mfa(app, client):
    register(client)
    login(client)
    page = client.get("/account/mfa/setup").data
    assert b"data:image/svg+xml" in page  # QR code rendered inline (allowed by CSP img-src data:)
    with client.session_transaction() as sess:
        secret = sess["pending_totp_secret"]
    resp = client.post("/account/mfa/setup", data={"code": totp.code_at(secret)})
    codes = re.findall(rb"<code>([a-z2-9-]{14})</code>", resp.data)
    assert len(codes) == 10
    logout(client)
    return secret, [c.decode() for c in codes]


def _next_step_code(secret):
    """A code for the next time step, so it isn't rejected as a replay of the setup code."""
    return totp.code_at(secret, time.time() + 30)


def test_setup_requires_a_valid_code(client):
    register(client)
    login(client)
    client.get("/account/mfa/setup")
    resp = client.post("/account/mfa/setup", data={"code": "000000"})
    assert b"didn&#39;t match" in resp.data
    assert b"Two-factor authentication is on" not in resp.data


def test_secrets_and_recovery_codes_are_not_stored_in_plaintext(app, client):
    secret, codes = _enable_mfa(app, client)
    with app.app_context():
        user = db.session.execute(db.select(User)).scalar_one()
        assert user.mfa_enabled
        assert all(rc.code_hash.startswith("$argon2id$") for rc in user.recovery_codes)
        assert not any(c in rc.code_hash for rc in user.recovery_codes for c in codes)


def test_password_alone_no_longer_logs_in(app, client):
    _enable_mfa(app, client)
    resp = login(client)
    assert b"Enter the 6-digit code" in resp.data
    assert client.get("/").status_code == 302  # notes still need a full login


def test_login_with_totp(app, client):
    secret, _ = _enable_mfa(app, client)
    login(client)
    resp = client.post("/login/mfa", data={"code": _next_step_code(secret)}, follow_redirects=True)
    assert b"My notes" in resp.data


def test_totp_code_cannot_be_replayed(app, client):
    secret, _ = _enable_mfa(app, client)
    code = _next_step_code(secret)
    login(client)
    client.post("/login/mfa", data={"code": code})
    logout(client)
    login(client)
    resp = client.post("/login/mfa", data={"code": code}, follow_redirects=True)
    assert b"Invalid or already used code" in resp.data


def test_recovery_code_works_once(app, client):
    _, codes = _enable_mfa(app, client)
    login(client)
    resp = client.post("/login/mfa", data={"code": codes[0]}, follow_redirects=True)
    assert b"Recovery code accepted. 9 left." in resp.data
    logout(client)
    login(client)
    resp = client.post("/login/mfa", data={"code": codes[0]}, follow_redirects=True)
    assert b"Invalid or already used code" in resp.data


def test_wrong_codes_lock_the_account(app, client):
    secret, _ = _enable_mfa(app, client)
    login(client)
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        client.post("/login/mfa", data={"code": "000000"})
    # Locked: even a valid code is refused now.
    resp = client.post("/login/mfa", data={"code": _next_step_code(secret)}, follow_redirects=True)
    assert b"My notes" not in resp.data


def test_mfa_step_without_password_is_refused(client):
    resp = client.post("/login/mfa", data={"code": "123456"}, follow_redirects=True)
    assert b"Please sign in again" in resp.data


def test_pending_mfa_expires(make_app):
    app = make_app(MFA_PENDING_SECONDS=-1)
    client = app.test_client()
    secret, _ = _enable_mfa(app, client)
    login(client)
    resp = client.post("/login/mfa", data={"code": _next_step_code(secret)}, follow_redirects=True)
    assert b"Please sign in again" in resp.data


def test_mfa_rate_limited(make_app):
    app = make_app(RATELIMIT_ENABLED=True, MAX_FAILED_LOGINS=100)
    client = app.test_client()
    _enable_mfa(app, client)
    login(client)
    codes = [client.post("/login/mfa", data={"code": "000000"}).status_code for _ in range(6)]
    assert codes[-1] == 429


def test_disable_needs_password_and_code(app, client):
    secret, codes = _enable_mfa(app, client)
    login(client)
    client.post("/login/mfa", data={"code": _next_step_code(secret)})
    bad = client.post("/account/mfa/disable", data={"password": STRONG, "code": "000000"}, follow_redirects=True)
    assert b"Password or code incorrect" in bad.data
    wrong_pw = client.post("/account/mfa/disable", data={"password": "nope nope nope", "code": codes[0]},
                           follow_redirects=True)
    assert b"Password or code incorrect" in wrong_pw.data
    good = client.post("/account/mfa/disable", data={"password": STRONG, "code": codes[0]}, follow_redirects=True)
    assert b"Two-factor authentication is off" in good.data
