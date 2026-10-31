"""Régénération des codes de secours.  ./venv/bin/pytest -v"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_security import PWD, make_app, register_and_login  # noqa: E402
from test_seclog import events  # noqa: E402
from test_twofa import code_at, enable_2fa  # noqa: E402

CODE_RE = rb"<code>([A-Z2-7]{5}-[A-Z2-7]{5})</code>"


def logged_in_with_2fa(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, codes = enable_2fa(app, c)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": code_at(secret, 1)})
    return app, c, secret, codes


def regen(c, password, code):
    return c.post("/security/2fa/recovery-codes",
                  data={"regen-password": password, "regen-code": code})


def login_with_code(app, code):
    c = app.test_client()
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": code})
    return c.get("/notes").status_code == 200


def test_regenerate_replaces_all_old_codes(tmp_path):
    app, c, secret, old = logged_in_with_2fa(tmp_path)
    r = regen(c, PWD, old[0])                       # code de secours accepté
    new = [x.decode() for x in re.findall(CODE_RE, r.data)]
    assert len(new) == 10 and not set(new) & set(old)
    assert "Tes anciens codes ne fonctionnent plus" in r.data.decode()
    assert not login_with_code(app, old[1])         # ancienne liste inutilisable
    assert login_with_code(app, new[0])             # nouvelle liste OK


def test_regenerate_with_totp_code(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    secret, codes = enable_2fa(app, c)
    # Connexion avec un code de secours : le créneau TOTP +1 reste libre.
    # (Le créneau +2 serait hors fenêtre ±30 s, et un créneau déjà utilisé
    # serait refusé par l'anti-rejeu.)
    c.post("/login", data={"username": "alice", "password": PWD})
    c.post("/login/2fa", data={"code": codes[0]})
    r = regen(c, PWD, code_at(secret, 1))
    assert len(re.findall(CODE_RE, r.data)) == 10


def test_regenerate_rejects_replayed_totp(tmp_path):
    app, c, secret, _ = logged_in_with_2fa(tmp_path)
    r = regen(c, PWD, code_at(secret, 1))           # déjà utilisé pour se connecter
    assert not re.findall(CODE_RE, r.data)


def test_regenerate_requires_password_and_code(tmp_path):
    app, c, secret, old = logged_in_with_2fa(tmp_path)
    for pwd, code in [("mauvais-mot-de-passe", old[0]), (PWD, "000000"), (PWD, "")]:
        r = regen(c, pwd, code)
        assert r.status_code == 302 and not re.findall(CODE_RE, r.data)
    assert login_with_code(app, old[1])             # anciens codes toujours valides
    assert events(tmp_path).count("recovery_codes_regen_failed") == 3


def test_session_thief_cannot_regenerate(tmp_path):
    app, victim, secret, old = logged_in_with_2fa(tmp_path)
    thief = app.test_client()
    thief.set_cookie("session", victim.get_cookie("session").value)
    r = regen(thief, "je-ne-connais-pas-le-mdp", "123456")
    assert not re.findall(CODE_RE, r.data)


def test_not_available_without_2fa(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    r = regen(c, PWD, "123456")
    assert r.headers["Location"].endswith("/security")
    assert "recovery_codes_regenerated" not in events(tmp_path)


def test_low_codes_warning(tmp_path):
    app, c, secret, old = logged_in_with_2fa(tmp_path)
    assert "génère-en de nouveaux" not in c.get("/security").data.decode()
    for code in old[:7]:                            # il en reste 3
        login_with_code(app, code)
    assert "génère-en de nouveaux" in c.get("/security").data.decode()


def test_regeneration_logged_without_codes(tmp_path):
    app, c, secret, old = logged_in_with_2fa(tmp_path)
    r = regen(c, PWD, old[0])
    new = [x.decode() for x in re.findall(CODE_RE, r.data)]
    assert "recovery_codes_regenerated" in events(tmp_path)
    log = (tmp_path / "security.log").read_text()
    assert not any(code in log for code in new)     # jamais de secret dans le journal


def test_no_duplicate_ids_on_security_page(tmp_path):
    app, c, *_ = logged_in_with_2fa(tmp_path)
    ids = re.findall(rb'id="([^"]+)"', c.get("/security").data)
    assert b"regen-password" in ids
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes
