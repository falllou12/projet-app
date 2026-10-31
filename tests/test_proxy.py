"""Comportement derrière nginx (ProxyFix).  ./venv/bin/pytest -v"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_security import make_app  # noqa: E402

BAD = {"username": "alice", "password": "mauvais-mot-de-passe"}


def last_ip(tmp_path):
    lines = (tmp_path / "security.log").read_text().splitlines()
    return json.loads(lines[-1])["ip"]


def test_without_proxy_forwarded_header_ignored(tmp_path):
    """Sans proxy, X-Forwarded-For est envoyé par le CLIENT → falsifiable → ignoré."""
    c = make_app(tmp_path).test_client()
    c.post("/login", data=BAD, headers={"X-Forwarded-For": "6.6.6.6"})
    assert last_ip(tmp_path) == "127.0.0.1"


def test_behind_proxy_real_ip_logged(tmp_path):
    c = make_app(tmp_path, BEHIND_PROXY=True).test_client()
    c.post("/login", data=BAD, headers={"X-Forwarded-For": "203.0.113.7"})
    assert last_ip(tmp_path) == "203.0.113.7"


def test_behind_proxy_only_last_hop_trusted(tmp_path):
    """Si le client ajoute sa propre IP inventée devant, seule la dernière
    (celle écrite par NOTRE nginx) est utilisée."""
    c = make_app(tmp_path, BEHIND_PROXY=True).test_client()
    c.post("/login", data=BAD, headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.7"})
    assert last_ip(tmp_path) == "203.0.113.7"


def test_rate_limit_cannot_be_bypassed_with_fake_ips(tmp_path):
    """L'attaquant change l'IP « inventée » à chaque essai : toujours limité."""
    c = make_app(tmp_path, BEHIND_PROXY=True, RATELIMIT_ENABLED=True).test_client()
    codes = [c.post("/login", data={"username": f"u{i}", "password": "x" * 12},
                    headers={"X-Forwarded-For": f"6.6.6.{i}, 203.0.113.7"}).status_code
             for i in range(7)]
    assert codes[-1] == 429


def test_rate_limit_is_per_real_client(tmp_path):
    """Deux vrais clients différents derrière nginx : comptés séparément."""
    c = make_app(tmp_path, BEHIND_PROXY=True, RATELIMIT_ENABLED=True).test_client()
    for _ in range(5):
        c.post("/login", data={"username": "a", "password": "x" * 12},
               headers={"X-Forwarded-For": "203.0.113.1"})
    r = c.post("/login", data={"username": "b", "password": "x" * 12},
               headers={"X-Forwarded-For": "203.0.113.2"})
    assert r.status_code != 429


def scheme_seen(app, headers):
    """Ajoute une route de test qui renvoie le schéma vu par Flask."""
    from flask import request
    if "_scheme" not in app.view_functions:
        app.add_url_rule("/_scheme", "_scheme", lambda: request.scheme)
    return app.test_client().get("/_scheme", headers=headers).data.decode()


def test_https_scheme_from_proxy(tmp_path):
    """nginx fait le HTTPS puis parle en HTTP à gunicorn : Flask doit
    quand même savoir que le client est en HTTPS (cookies Secure, redirections)."""
    behind = make_app(tmp_path, BEHIND_PROXY=True)
    assert scheme_seen(behind, {"X-Forwarded-Proto": "https"}) == "https"
    (tmp_path / "direct").mkdir()
    direct = make_app(tmp_path / "direct")
    assert scheme_seen(direct, {"X-Forwarded-Proto": "https"}) == "http"  # ignoré


def test_hsts_toggle(tmp_path):
    off = make_app(tmp_path).test_client().get("/login")
    assert "Strict-Transport-Security" not in off.headers
    (tmp_path / "b").mkdir()
    on = make_app(tmp_path / "b", HSTS=True).test_client().get("/login")
    assert "max-age=" in on.headers["Strict-Transport-Security"]


def csrf_login(app, host, referer):
    import re
    c = app.test_client()
    hdr = {"Host": host, "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7"}
    page = c.get("/login", headers=hdr)
    if page.status_code != 200:
        return page.status_code
    tok = re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"', page.data).group(1).decode()
    return c.post("/login", headers={**hdr, "Referer": referer},
                  data={"csrf_token": tok, "username": "x", "password": "y" * 12}).status_code


def test_csrf_works_behind_proxy_with_port(tmp_path):
    """Régression trouvée en testant le vrai déploiement Docker : nginx doit
    transmettre le port dans Host, sinon tous les formulaires HTTPS sont refusés."""
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True, BEHIND_PROXY=True)
    assert csrf_login(app, "localhost:8443", "https://localhost:8443/login") == 200
    assert csrf_login(app, "localhost", "https://localhost:8443/login") == 400  # l'ancien bug


def test_untrusted_host_rejected(tmp_path):
    app = make_app(tmp_path, BEHIND_PROXY=True, TRUSTED_HOSTS=["localhost", "127.0.0.1"])
    c = app.test_client()
    assert c.get("/login", headers={"Host": "localhost:8443"}).status_code == 200
    assert c.get("/login", headers={"Host": "site-pirate.com"}).status_code == 400
