"""Tests de la double authentification.  ./venv/bin/pytest -v"""
import re
import sqlite3
import sys
import time
from pathlib import Path

import pyotp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import db  # noqa: E402
from test_security import PWD, make_app, register_and_login  # noqa: E402


def secret_of(app, name, col="totp_secret"):
    with app.app_context():
        return db.get_db().execute(f"SELECT {col} FROM users WHERE username = ?",
                                   (name,)).fetchone()[0]


def code_at(secret, offset):
    """Code TOTP du créneau courant + offset (offset=1 → prochain créneau)."""
    step = int(time.time()) // 30 + offset
    return pyotp.TOTP(secret).at(step * 30)


def enable_2fa(app, c, name="alice"):
    register_and_login(c, name)
    c.get("/security/2fa/setup")
    secret = secret_of(app, name, "totp_pending_secret")
    r = c.post("/security/2fa/setup", data={"code": code_at(secret, 0)})
    codes = re.findall(rb"<code>([A-Z2-7]{5}-[A-Z2-7]{5})</code>", r.data)
    assert len(codes) == 10
    c.post("/logout")
    return secret, [x.decode() for x in codes]


def test_setup_requires_valid_code(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.get("/security/2fa/setup")
    c.post("/security/2fa/setup", data={"code": "000000"})
    assert secret_of(app, "alice") is None  # pas activée sans preuve


def test_qr_code_served_as_svg(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    assert c.get("/security/2fa/qr.svg").status_code == 404  # pas encore de clé
    c.get("/security/2fa/setup")
    r = c.get("/security/2fa/qr.svg")
    assert r.status_code == 200 and r.mimetype == "image/svg+xml"
    assert b"<script" not in r.data


def test_password_alone_is_not_enough(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    enable_2fa(app, c)
    r = c.post("/login", data={"username": "alice", "password": PWD})
    assert r.headers["Location"].endswith("/login/2fa")
    assert c.get("/notes").status_code == 302          # contournement impossible
    assert c.get("/security").status_code == 302


def test_wrong_then_good_code(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, _ = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    assert b"Code invalide" in c.post("/login/2fa", data={"code": "123456"},
                                      follow_redirects=True).data
    c.post("/login/2fa", data={"code": code_at(secret, 1)})
    assert c.get("/notes").status_code == 200


def test_totp_replay_rejected(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, _ = enable_2fa(app, c)
    code = code_at(secret, 1)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": code})
    c.post("/logout")
    # Un attaquant qui a intercepté le code essaie de le réutiliser
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": code})
    assert c.get("/notes").status_code == 302


def test_recovery_code_single_use(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    _, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0].lower()})  # insensible à la casse
    assert c.get("/notes").status_code == 200
    assert b"9 / 10" in c.get("/security").data
    c.post("/logout")
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0]})
    assert c.get("/notes").status_code == 302


def test_recovery_codes_stored_hashed(tmp_path):
    app = make_app(tmp_path)
    _, codes = enable_2fa(app, app.test_client())
    with app.app_context():
        stored = [r[0] for r in db.get_db().execute("SELECT code_hash FROM recovery_codes")]
    assert not any(c.replace("-", "") in s for c in codes for s in stored)


def test_too_many_2fa_failures_reset_login(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, _ = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    for _ in range(5):
        c.post("/login/2fa", data={"code": "000000"})
    # Même avec le bon code, il faut recommencer depuis le mot de passe
    r = c.post("/login/2fa", data={"code": code_at(secret, 1)})
    assert r.headers["Location"].endswith("/login")
    assert c.get("/notes").status_code == 302


def test_2fa_rate_limited(tmp_path):
    app = make_app(tmp_path, RATELIMIT_ENABLED=True)
    c = app.test_client()
    with c.session_transaction() as s:
        s["2fa_user_id"], s["2fa_started"] = 1, int(time.time())
    codes = [c.post("/login/2fa", data={"code": "000000"}).status_code for _ in range(7)]
    assert 429 in codes


def test_disable_requires_password_and_code(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0]})
    c.post("/security/2fa/disable", data={"disable-password": "mauvais-mdp-xx", "disable-code": code_at(secret, 1)})
    assert secret_of(app, "alice") is not None
    c.post("/security/2fa/disable", data={"disable-password": PWD, "disable-code": code_at(secret, 1)})
    assert secret_of(app, "alice") is None


def test_migrate_existing_db(tmp_path):
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    conn.execute("INSERT INTO users (username, password_hash) VALUES ('old', 'h')")
    conn.commit(); conn.close()
    app = make_app(tmp_path)
    app.config["DATABASE"] = str(path)
    with app.app_context():
        assert "totp_secret" in db.migrate_db()
        assert db.get_db().execute("SELECT username FROM users").fetchone()[0] == "old"
