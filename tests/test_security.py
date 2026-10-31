"""Tests qui tentent de vraies attaques et vérifient qu'elles échouent.
Lancer :  ./venv/bin/pytest -v
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import db  # noqa: E402
from app import create_app  # noqa: E402

PWD = "un-mot-de-passe-long"


def make_app(tmp_path, **extra):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "t.sqlite"),
                      "WTF_CSRF_ENABLED": False, "RATELIMIT_ENABLED": False, **extra})
    with app.app_context():
        db.init_db()
    return app


@pytest.fixture
def client(tmp_path):
    return make_app(tmp_path).test_client()


def register_and_login(c, name):
    c.post("/register", data={"username": name, "password": PWD, "confirm": PWD})
    return c.post("/login", data={"username": name, "password": PWD})


def test_password_is_hashed(tmp_path):
    app = make_app(tmp_path)
    register_and_login(app.test_client(), "alice")
    with app.app_context():
        h = db.get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert PWD not in h and h.startswith("$argon2id$")


def test_sql_injection_login_fails(client):
    register_and_login(client, "alice")
    client.post("/logout")
    r = client.post("/login", data={"username": "alice' --", "password": "x"})
    assert b"Identifiants invalides" in r.data
    assert client.get("/notes").status_code == 302  # toujours pas connecté


def test_xss_is_escaped(client):
    register_and_login(client, "alice")
    client.post("/notes/new", data={"title": "t", "body": "<script>alert(1)</script>"})
    r = client.get("/notes/1")
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_idor_other_users_note(tmp_path):
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register_and_login(alice, "alice")
    alice.post("/notes/new", data={"title": "secret", "body": "à alice"})
    register_and_login(bob, "bob")
    assert bob.get("/notes/1").status_code == 404
    assert bob.post("/notes/1/edit", data={"title": "pwn", "body": "x"}).status_code == 404
    assert bob.post("/notes/1/delete").status_code == 404
    assert b"secret" in alice.get("/notes/1").data  # intacte


def test_requires_login(client):
    assert client.get("/notes").status_code == 302
    assert client.get("/notes/1").status_code == 302


def test_csrf_rejected(tmp_path):
    c = make_app(tmp_path, WTF_CSRF_ENABLED=True).test_client()
    r = c.post("/register", data={"username": "eve", "password": PWD, "confirm": PWD})
    assert r.status_code == 400


def test_csrf_with_token_works(tmp_path):
    c = make_app(tmp_path, WTF_CSRF_ENABLED=True).test_client()
    token = re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"',
                      c.get("/register").data).group(1).decode()
    r = c.post("/register", data={"csrf_token": token, "username": "eve",
                                  "password": PWD, "confirm": PWD})
    assert r.status_code == 302


def test_login_rate_limited(tmp_path):
    c = make_app(tmp_path, RATELIMIT_ENABLED=True).test_client()
    codes = [c.post("/login", data={"username": "x", "password": "y"}).status_code
             for _ in range(7)]
    assert codes[-1] == 429


def test_short_password_refused(client):
    client.post("/register", data={"username": "bob", "password": "123", "confirm": "123"})
    assert b"Identifiants invalides" in client.post(
        "/login", data={"username": "bob", "password": "123"}).data


def test_session_cookie_flags(client):
    r = register_and_login(client, "alice")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
