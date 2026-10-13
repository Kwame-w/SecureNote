import re

import pytest

from securenotes import create_app
from securenotes.extensions import db

STRONG = "correct horse battery staple"


@pytest.fixture
def make_app():
    apps = []

    def _make(**overrides):
        # CSRF is off for most tests to keep them short; test_hardening turns it on to prove it works.
        overrides.setdefault("WTF_CSRF_ENABLED", False)
        app = create_app("testing", **overrides)
        apps.append(app)
        return app

    yield _make
    for app in apps:
        with app.app_context():
            db.drop_all()


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()


def register(client, username="alice", password=STRONG, confirm=None):
    return client.post("/register", data={
        "username": username, "password": password, "confirm": confirm or password,
    }, follow_redirects=True)


def login(client, username="alice", password=STRONG):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def logout(client):
    return client.post("/logout", follow_redirects=True)


def create_note(client, title="My note", body="secret stuff"):
    resp = client.post("/notes/new", data={"title": title, "body": body})
    assert resp.status_code == 302
    return int(re.search(r"/notes/(\d+)", resp.headers["Location"]).group(1))


def csrf_token(html: bytes) -> str:
    return re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', html).group(1).decode()
