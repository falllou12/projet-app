"""Changement de mot de passe et révocation des sessions.  ./venv/bin/pytest -v"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_security import PWD, make_app, register_and_login  # noqa: E402
from test_twofa import code_at, enable_2fa  # noqa: E402

NEW = "nouveau-mot-de-passe-solide"


def change(c, current=PWD, new=NEW, confirm=None):
    return c.post("/security/password", data={
        "current": current, "new": new, "confirm": confirm or new})


def test_stolen_cookie_revoked_by_password_change(tmp_path):
    app = make_app(tmp_path)
    victim, attacker = app.test_client(), app.test_client()
    register_and_login(victim, "alice")

    # L'attaquant vole le cookie de session (XSS sur un autre site, wifi public…)
    attacker.set_cookie("session", victim.get_cookie("session").value)
    assert attacker.get("/notes").status_code == 200  # le vol fonctionne…

    change(victim)                                      # …la victime réagit
    assert attacker.get("/notes").status_code == 302   # cookie volé inutilisable
    assert victim.get("/notes").status_code == 200     # la victime reste connectée


def test_old_password_stops_working(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    change(c)
    c.post("/logout")
    assert b"Identifiants invalides" in c.post(
        "/login", data={"username": "alice", "password": PWD}).data
    c.post("/login", data={"username": "alice", "password": NEW})
    assert c.get("/notes").status_code == 200


def test_wrong_current_password_changes_nothing(tmp_path):
    app = make_app(tmp_path)
    c, other = app.test_client(), app.test_client()
    register_and_login(c, "alice")
    register_and_login(other, "alice")
    r = change(c, current="pas-le-bon-mdp")
    assert b"incorrect" in c.get(r.headers["Location"]).data
    assert other.get("/notes").status_code == 200  # personne n'a été déconnecté


def test_same_or_mismatched_password_refused(tmp_path):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    change(c, new=PWD)
    change(c, new=NEW, confirm="autre-chose-different")
    change(c, new="court")
    c.post("/logout")
    c.post("/login", data={"username": "alice", "password": PWD})
    assert c.get("/notes").status_code == 200  # l'ancien mot de passe marche toujours


def test_logout_all_other_devices(tmp_path):
    app = make_app(tmp_path)
    laptop, phone = app.test_client(), app.test_client()
    register_and_login(laptop, "alice")
    register_and_login(phone, "alice")
    phone.post("/security/logout-all")
    assert laptop.get("/notes").status_code == 302
    assert phone.get("/notes").status_code == 200


def test_pending_2fa_invalidated_by_password_change(tmp_path):
    app = make_app(tmp_path)
    attacker, victim = app.test_client(), app.test_client()
    secret, codes = enable_2fa(app, victim)
    # L'attaquant connaît l'ancien mot de passe et attend à l'étape 2FA
    attacker.post("/login", data={"username": "alice", "password": PWD})
    # La victime se connecte et change son mot de passe
    victim.post("/login", data={"username": "alice", "password": PWD})
    victim.post("/login/2fa", data={"code": codes[0]})
    change(victim)
    # Même avec un code valide, la session en attente de l'attaquant est refusée
    attacker.post("/login/2fa", data={"code": code_at(secret, 1)})
    assert attacker.get("/notes").status_code == 302


def test_other_users_unaffected(tmp_path):
    app = make_app(tmp_path)
    alice, bob = app.test_client(), app.test_client()
    register_and_login(alice, "alice")
    register_and_login(bob, "bob")
    alice.post("/security/logout-all")
    assert bob.get("/notes").status_code == 200
