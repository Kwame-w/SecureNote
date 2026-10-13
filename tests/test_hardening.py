"""A05 Security Misconfiguration: headers, CSRF, rate limiting, cookies, errors."""

import pytest

from securenotes import create_app

from .conftest import STRONG, csrf_token, register


def test_security_headers(client):
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in resp.headers  # only sent in production over HTTPS


def test_hsts_and_secure_cookies_in_production(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 64)
    app = create_app("production", SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")
    resp = app.test_client().get("/login")
    assert "max-age=63072000" in resp.headers["Strict-Transport-Security"]
    assert app.config["SESSION_COOKIE_SECURE"] and app.config["SESSION_COOKIE_HTTPONLY"]
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-session"


def test_production_refuses_to_start_without_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production", SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")


def test_csrf_blocks_forged_posts(make_app):
    app = make_app(WTF_CSRF_ENABLED=True)
    client = app.test_client()
    forged = client.post("/register", data={"username": "bob", "password": STRONG, "confirm": STRONG})
    assert forged.status_code == 400

    token = csrf_token(client.get("/register").data)
    ok = client.post("/register", data={"username": "bob", "password": STRONG, "confirm": STRONG,
                                        "csrf_token": token})
    assert ok.status_code == 302


def test_login_rate_limit(make_app):
    app = make_app(RATELIMIT_ENABLED=True)
    client = app.test_client()
    codes = [client.post("/login", data={"username": "x", "password": "y"}).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10
    assert codes[-1] == 429


def test_errors_do_not_leak_internals(client):
    resp = client.get("/definitely-not-here")
    assert resp.status_code == 404
    assert b"Traceback" not in resp.data and b"werkzeug" not in resp.data.lower()


def test_debug_is_off(app):
    assert not app.debug


def test_register_page_has_no_inline_script(client):
    register(client)
    assert b"<script" not in client.get("/register").data
