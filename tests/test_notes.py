"""A01 Broken Access Control and A03 Injection (XSS)."""

from .conftest import create_note, login, logout, register


def test_requires_login(client):
    resp = client.get("/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_crud(client):
    register(client)
    login(client)
    note_id = create_note(client, "Groceries", "eggs\nmilk")
    assert b"Groceries" in client.get("/").data
    client.post(f"/notes/{note_id}/edit", data={"title": "Groceries v2", "body": "eggs"})
    assert b"Groceries v2" in client.get(f"/notes/{note_id}").data
    client.post(f"/notes/{note_id}/delete")
    assert client.get(f"/notes/{note_id}").status_code == 404


def test_idor_other_users_notes_are_invisible(client, caplog):
    register(client, "alice")
    login(client, "alice")
    note_id = create_note(client, "Alice's diary", "private")
    logout(client)

    register(client, "mallory")
    login(client, "mallory")
    caplog.set_level("INFO", logger="securenotes.audit")
    assert client.get(f"/notes/{note_id}").status_code == 404
    assert client.get(f"/notes/{note_id}/edit").status_code == 404
    assert client.post(f"/notes/{note_id}/edit", data={"title": "pwned", "body": ""}).status_code == 404
    assert client.post(f"/notes/{note_id}/delete").status_code == 404
    assert b"Alice&#39;s diary" not in client.get("/").data
    assert "event=idor_attempt" in caplog.text

    logout(client)
    login(client, "alice")
    assert b"Alice&#39;s diary" in client.get(f"/notes/{note_id}").data


def test_stored_xss_is_escaped(client):
    register(client)
    login(client)
    payload = '<script>alert(document.cookie)</script><img src=x onerror=alert(1)>'
    note_id = create_note(client, payload, payload)
    for page in (client.get("/").data, client.get(f"/notes/{note_id}").data):
        assert b"<script>alert" not in page
        assert b"<img src=x" not in page
        assert b"&lt;script&gt;alert" in page


def test_delete_is_post_only(client):
    register(client)
    login(client)
    note_id = create_note(client)
    assert client.get(f"/notes/{note_id}/delete").status_code == 405


def test_input_length_limits(client):
    register(client)
    login(client)
    resp = client.post("/notes/new", data={"title": "x" * 500, "body": ""})
    assert resp.status_code == 200 and b"Field cannot be longer than 120" in resp.data
    huge = client.post("/notes/new", data={"title": "t", "body": "x" * 100_000})
    assert huge.status_code == 413
