"""Suppression de compte.  ./venv/bin/pytest -v"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import db  # noqa: E402
from test_security import PWD, make_app, register_and_login  # noqa: E402
from test_twofa import code_at, enable_2fa  # noqa: E402

SECRET_NOTE = "MON-SECRET-TRES-PRIVE-42"


def count(app, table):
    with app.app_context():
        return db.get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # nosec B608 - nom de table fixe


def test_delete_requires_password(tmp_path):
    app = make_app(tmp_path)
    victim, thief = app.test_client(), app.test_client()
    register_and_login(victim, "alice")
    # Un voleur de session ne connaît pas le mot de passe
    thief.set_cookie("session", victim.get_cookie("session").value)
    thief.post("/security/delete", data={"delete-password": "je-devine-un-truc"})
    assert count(app, "users") == 1
    assert victim.get("/notes").status_code == 200


def test_delete_removes_user_and_notes(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/notes/new", data={"title": "t", "body": SECRET_NOTE})
    r = c.post("/security/delete", data={"delete-password": PWD})
    assert r.headers["Location"].endswith("/login")
    assert count(app, "users") == 0
    assert count(app, "notes") == 0                 # ON DELETE CASCADE
    assert c.get("/notes").status_code == 302       # déconnecté
    assert b"Identifiants invalides" in c.post(
        "/login", data={"username": "alice", "password": PWD}).data


def test_deleted_note_not_recoverable_from_file(tmp_path):
    """Forensique : `strings notes.sqlite` ne doit pas retrouver la note."""
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/notes/new", data={"title": "t", "body": SECRET_NOTE})
    raw = (tmp_path / "t.sqlite").read_bytes()
    assert SECRET_NOTE.encode() in raw              # présente avant…
    c.post("/security/delete", data={"delete-password": PWD})
    raw = (tmp_path / "t.sqlite").read_bytes()
    assert SECRET_NOTE.encode() not in raw          # …effacée après (secure_delete)


def test_secure_delete_enabled(tmp_path):
    app = make_app(tmp_path)
    with app.app_context():
        assert db.get_db().execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_delete_requires_2fa_when_enabled(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0]})
    c.post("/security/delete", data={"delete-password": PWD})                       # sans code
    c.post("/security/delete", data={"delete-password": PWD, "delete-code": "000000"})     # mauvais code
    assert count(app, "users") == 1
    c.post("/security/delete", data={"delete-password": PWD, "delete-code": code_at(secret, 1)})
    assert count(app, "users") == 0
    assert count(app, "recovery_codes") == 0                                  # CASCADE


def test_other_devices_logged_out(tmp_path):
    app = make_app(tmp_path)
    laptop, phone = app.test_client(), app.test_client()
    register_and_login(laptop, "alice")
    register_and_login(phone, "alice")
    phone.post("/security/delete", data={"delete-password": PWD})
    assert laptop.get("/notes").status_code == 302


def test_other_users_untouched(tmp_path):
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register_and_login(alice, "alice")
    register_and_login(bob, "bob")
    bob.post("/notes/new", data={"title": "b", "body": "note de bob"})
    alice.post("/security/delete", data={"delete-password": PWD})
    assert count(app, "users") == 1 and count(app, "notes") == 1
    assert bob.get("/notes").status_code == 200


def test_delete_requires_post(tmp_path):
    client = make_app(tmp_path).test_client()
    register_and_login(client, "alice")
    assert client.get("/security/delete").status_code == 405  # pas de suppression via un lien
