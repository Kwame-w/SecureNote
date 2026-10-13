"""A07 Identification and Authentication Failures, A02 Cryptographic Failures."""

from securenotes.extensions import db
from securenotes.models import User

from .conftest import STRONG, login, logout, register


def test_register_and_login(client):
    assert b"Account created" in register(client).data
    resp = login(client)
    assert b"My notes" in resp.data


def test_passwords_are_hashed_with_argon2id(app, client):
    register(client)
    with app.app_context():
        user = db.session.execute(db.select(User)).scalar_one()
        assert user.password_hash.startswith("$argon2id$")
        assert STRONG not in user.password_hash


def test_password_policy(client):
    assert b"between 12 and 128 characters" in register(client, password="short").data
    assert b"too common" in register(client, password="password1234").data
    assert b"must not contain your username" in register(client, username="jordan", password="jordan-is-great-2026").data
    assert b"must match" in register(client, password=STRONG, confirm=STRONG + "x").data


def test_username_validation(client):
    resp = register(client, username="<script>")
    assert b"Use 3-32 letters" in resp.data


def test_duplicate_username(client):
    register(client)
    assert b"That username is taken" in register(client).data


def test_login_errors_do_not_reveal_which_part_was_wrong(client):
    register(client)
    wrong_password = login(client, password="not the right password").data
    unknown_user = login(client, username="nobody").data
    assert b"Invalid username or password." in wrong_password
    assert b"Invalid username or password." in unknown_user


def test_account_lockout_after_repeated_failures(app, client):
    register(client)
    for _ in range(app.config["MAX_FAILED_LOGINS"]):
        login(client, password="wrong password!!")
    # Even the correct password is refused while locked, with the same generic message.
    resp = login(client)
    assert b"Invalid username or password." in resp.data
    assert b"My notes" not in resp.data


def test_sql_injection_in_login_is_harmless(client):
    register(client)
    resp = login(client, username="alice' OR '1'='1' --", password="anything at all")
    assert b"Invalid username or password." in resp.data


def test_session_is_rotated_on_login(client):
    register(client)
    client.get("/login")
    with client.session_transaction() as sess:
        sess["planted"] = "attacker-value"
    login(client)
    with client.session_transaction() as sess:
        assert "planted" not in sess


def test_logout_requires_post(client):
    register(client)
    login(client)
    assert client.get("/logout").status_code == 405
    assert b"Signed out" in logout(client).data
    assert client.get("/").status_code == 302


def test_open_redirect_blocked(client):
    register(client)
    resp = client.post("/login?next=https://evil.example/phish", data={"username": "alice", "password": STRONG})
    assert resp.headers["Location"] == "/"
    client.post("/logout")
    resp2 = client.post("/login?next=//evil.example", data={"username": "alice", "password": STRONG})
    assert resp2.headers["Location"] == "/"


def test_safe_next_is_followed(client):
    register(client)
    resp = client.post("/login?next=/notes/new", data={"username": "alice", "password": STRONG})
    assert resp.headers["Location"] == "/notes/new"
