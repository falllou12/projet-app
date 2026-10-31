"""Verrouillage progressif par compte.  ./venv/bin/pytest -v"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import lockout  # noqa: E402
from test_security import PWD, make_app, register_and_login  # noqa: E402
from test_twofa import code_at, enable_2fa  # noqa: E402


class Clock:
    """Fausse horloge : permet d'avancer le temps dans les tests."""
    def __init__(self):
        self.t = 1_000_000

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(lockout, "now", c)
    return c


def login(c, name="alice", pwd=PWD):
    return c.post("/login", data={"username": name, "password": pwd})


def fail(c, n, name="alice"):
    return [login(c, name, "mauvais-mot-de-passe").status_code for _ in range(n)]


def test_lock_durations():
    assert [lockout.lock_duration(n) for n in range(4, 13)] == \
        [0, 60, 120, 240, 480, 960, 1920, 3600, 3600]  # plafond 1 h
    assert lockout.lock_duration(10**9) == 3600         # pas de calcul géant


def test_locked_after_5_failures_even_with_good_password(tmp_path, clock):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/logout")
    assert fail(c, 5) == [200] * 5
    r = login(c)                                   # BON mot de passe…
    assert r.status_code == 429                    # …refusé : compte bloqué
    assert b"Trop de tentatives" in r.data
    assert c.get("/notes").status_code == 302


def test_unlock_after_delay_and_reset(tmp_path, clock):
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/logout")
    fail(c, 5)
    clock.t += 61                                  # 1 min plus tard
    login(c)
    assert c.get("/notes").status_code == 200
    c.post("/logout")
    assert fail(c, 4) == [200] * 4                 # compteur bien remis à zéro


def test_lock_doubles(tmp_path, clock):
    app = make_app(tmp_path)
    c = app.test_client()
    fail(c, 5)                                     # bloqué 60 s
    clock.t += 61
    fail(c, 1)                                     # 6e échec → bloqué 120 s
    clock.t += 61
    assert login(c).status_code == 429             # encore bloqué
    clock.t += 60
    assert login(c).status_code == 200             # débloqué


def test_no_user_enumeration(tmp_path, clock):
    """Un compte existant et un nom inventé se comportent exactement pareil."""
    app = make_app(tmp_path)
    c = app.test_client()
    register_and_login(c, "alice")
    c.post("/logout")
    real = [login(c, "alice", "faux-mdp-xxxx") for _ in range(6)]
    fake = [login(c, "personne", "faux-mdp-xxxx") for _ in range(6)]
    assert [r.status_code for r in real] == [r.status_code for r in fake]
    assert real[-1].data.count(b"Trop de tentatives") == fake[-1].data.count(b"Trop de tentatives") == 1


def test_other_accounts_not_affected(tmp_path, clock):
    app = make_app(tmp_path)
    attacker, bob = app.test_client(), app.test_client()
    register_and_login(bob, "bob")
    bob.post("/logout")
    fail(attacker, 10, "alice")
    login(bob, "bob")
    assert bob.get("/notes").status_code == 200


def test_distributed_attack_many_ips_still_locked(tmp_path, clock):
    """Chaque tentative depuis un client (IP) différent : bloqué quand même."""
    app = make_app(tmp_path)
    register_and_login(app.test_client(), "alice")
    for i in range(5):
        app.test_client().post("/login", data={"username": "alice", "password": "x" * 12},
                               environ_base={"REMOTE_ADDR": f"10.0.0.{i}"})
    r = app.test_client().post("/login", data={"username": "alice", "password": PWD},
                               environ_base={"REMOTE_ADDR": "10.0.0.99"})
    assert r.status_code == 429


def test_2fa_bruteforce_with_known_password_gets_locked(tmp_path, clock):
    """L'attaquant connaît le mot de passe et alterne : mdp OK → 4 codes faux →
    nouvelle session. Le compteur ne doit PAS être remis à zéro par le mdp."""
    app = make_app(tmp_path)
    secret, _ = enable_2fa(app, app.test_client())
    for _ in range(2):                             # 2 rounds × 4 codes = 8 essais
        c = app.test_client()
        login(c)
        for _ in range(4):
            c.post("/login/2fa", data={"code": "000000"})
    c = app.test_client()
    r = login(c)
    assert r.status_code == 429                    # bloqué, même avec le bon mdp


def test_2fa_step_refused_when_locked_meanwhile(tmp_path, clock):
    app = make_app(tmp_path)
    secret, _ = enable_2fa(app, app.test_client())
    victim = app.test_client()
    login(victim)                                  # mdp OK, en attente du code
    fail(app.test_client(), 5)                     # un attaquant bloque le compte
    r = victim.post("/login/2fa", data={"code": code_at(secret, 1)})
    assert r.headers["Location"].endswith("/login")
    assert victim.get("/notes").status_code == 302


def test_old_failures_forgotten_after_24h(tmp_path, clock):
    app = make_app(tmp_path)
    c = app.test_client()
    fail(c, 4)
    clock.t += 86400 + 1
    fail(c, 1, "autre")                            # déclenche le ménage
    assert fail(c, 4) == [200] * 4                 # compteur d'alice oublié
