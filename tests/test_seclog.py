"""Journal de sécurité.  ./venv/bin/pytest -v"""
import json
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import db  # noqa: E402
import seclog  # noqa: E402
from test_security import PWD, make_app, register_and_login  # noqa: E402
from test_twofa import code_at, enable_2fa  # noqa: E402

WRONG = "mauvais-mot-de-passe-123"


def read_log(tmp_path):
    """Chaque ligne DOIT être un JSON valide (sinon le test plante)."""
    text = (tmp_path / "security.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def events(tmp_path):
    return [r["event"] for r in read_log(tmp_path)]


def test_login_events_logged(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/login", data={"username": "alice", "password": WRONG})
    log = read_log(tmp_path)
    assert [r["event"] for r in log] == ["register", "login_success", "login_failed"]
    assert log[-1]["username"] == "alice" and log[-1]["ip"] == "127.0.0.1"


def test_no_secrets_in_logs(tmp_path):
    """Ni mot de passe, ni code 2FA, ni clé TOTP, ni code de secours."""
    app = make_app(tmp_path)
    c = app.test_client()
    secret, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": WRONG})
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": "123456"})
    c.post("/login/2fa", data={"code": codes[0]})
    with app.app_context():
        rows = db.get_db().execute("SELECT * FROM security_events").fetchall()
    everything = (tmp_path / "security.log").read_text() + repr([tuple(r) for r in rows])
    for s in [PWD, WRONG, secret, "123456", *codes, codes[0].replace("-", "")]:
        assert s not in everything, f"secret trouvé dans les logs : {s}"


def test_log_injection_cwe117(tmp_path):
    """Un nom contenant un saut de ligne ne doit pas créer une fausse ligne."""
    app = make_app(tmp_path)
    c = app.test_client()
    evil = 'x\n{"event":"login_success"}'
    c.post("/login", data={"username": evil, "password": WRONG})
    log = read_log(tmp_path)                     # chaque ligne est du JSON valide
    assert len(log) == 1
    assert log[0]["event"] == "login_failed"
    assert log[0]["username"] == evil            # conservé tel quel, en texte
    assert "login_success" not in events(tmp_path)


def test_unknown_user_in_file_only(tmp_path):
    app = make_app(tmp_path)
    app.test_client().post("/login", data={"username": "fantome", "password": WRONG})
    assert read_log(tmp_path)[0]["username"] == "fantome"
    with app.app_context():
        assert db.get_db().execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_lock_and_recovery_logged(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    _, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0]})
    assert "recovery_code_used" in events(tmp_path)
    c.post("/logout")
    for _ in range(6):
        c.post("/login", data={"username": "alice", "password": WRONG})
    ev = events(tmp_path)
    assert ev.count("account_locked") == 1 and "login_blocked" in ev
    assert [r for r in read_log(tmp_path) if r["event"] == "account_locked"][0]["duration"] == 60


def test_activity_page_only_shows_own_events(tmp_path):
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register_and_login(alice, "alice")
    register_and_login(bob, "bob")
    bob.post("/login", data={"username": "alice", "password": WRONG})  # bob attaque alice
    register_and_login(bob, "bob")
    page_alice = alice.get("/security/activity").data.decode()
    page_bob = bob.get("/security/activity").data.decode()
    assert "Échec de connexion" in page_alice     # alice voit l'attaque
    assert "Échec de connexion" not in page_bob   # bob ne voit pas le journal d'alice
    assert page_bob.count("Connexion réussie") == 2


def test_user_agent_xss_escaped(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    c.post("/register", data={"username": "alice", "password": PWD, "confirm": PWD})
    c.post("/login", data={"username": "alice", "password": PWD},
           headers={"User-Agent": "<script>alert(1)</script>"})
    page = c.get("/security/activity").data
    assert b"<script>alert(1)</script>" not in page
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_retention_90_days(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    with app.app_context():
        conn = db.get_db()
        old = int(time.time()) - 91 * 86400
        conn.execute("INSERT INTO security_events (user_id, event, created_at) "
                     "VALUES (1, 'login_success', ?)", (old,))
        conn.commit()
    c.post("/security/logout-all")                 # nouvel événement → ménage
    with app.app_context():
        dates = [r[0] for r in db.get_db().execute("SELECT created_at FROM security_events")]
    assert min(dates) > int(time.time()) - seclog.RETENTION_DAYS * 86400


def test_log_file_private(tmp_path):
    make_app(tmp_path).test_client().post("/login", data={"username": "a", "password": WRONG})
    mode = stat.S_IMODE((tmp_path / "security.log").stat().st_mode)
    assert mode == 0o600


def test_account_deleted_kept_in_file(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/security/delete", data={"delete-password": PWD})
    assert events(tmp_path)[-1] == "account_deleted"
    with app.app_context():
        assert db.get_db().execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_sensitive_actions_logged(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, _ = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": code_at(secret, 1)})
    c.post("/security/password", data={"current": WRONG, "new": "x" * 14, "confirm": "x" * 14})
    c.post("/security/password", data={"current": PWD, "new": "y" * 14, "confirm": "y" * 14})
    ev = events(tmp_path)
    for e in ["2fa_enabled", "password_change_failed", "password_changed"]:
        assert e in ev
    assert [r for r in read_log(tmp_path) if r["event"] == "login_success"][-1]["method"] == "password+totp"
