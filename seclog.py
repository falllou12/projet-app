"""Journal de sécurité.

Deux destinations :
  1. instance/security.log : TOUS les événements, une ligne JSON par
     événement (lisible avec grep/jq, importable dans un SIEM).
  2. table security_events : les événements d'un compte existant, montrés
     à l'utilisateur sur la page « Activité récente ».

Règles :
  - JAMAIS de secret dans le journal (mot de passe, code 2FA, cookie, jeton).
  - JSON = protection contre l'injection de logs (CWE-117) : un « \\n » saisi
    par l'attaquant devient le texte « \\n », pas une nouvelle ligne.
  - Les IP sont des données personnelles → gardées 90 jours maximum.
"""
import json
import logging
import os
import time
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler

from flask import current_app, has_request_context, request

import db

RETENTION_DAYS = 90

# Libellés affichés à l'utilisateur. « alert » = événement à surveiller.
EVENTS = {
    "register":               ("Compte créé", False),
    "login_success":          ("Connexion réussie", False),
    "login_failed":           ("Échec de connexion (mauvais mot de passe)", True),
    "login_blocked":          ("Tentative pendant un blocage", True),
    "account_locked":         ("Compte bloqué temporairement", True),
    "2fa_failed":             ("Code 2FA invalide", True),
    "recovery_code_used":     ("Code de secours utilisé", True),
    "2fa_enabled":            ("Double authentification activée", False),
    "recovery_codes_regenerated": ("Nouveaux codes de secours générés", False),
    "recovery_codes_regen_failed": ("Échec de génération des codes de secours", True),
    "2fa_disabled":           ("Double authentification désactivée", True),
    "2fa_disable_failed":     ("Échec de désactivation de la 2FA", True),
    "password_changed":       ("Mot de passe changé", False),
    "password_change_failed": ("Échec de changement de mot de passe", True),
    "sessions_revoked":       ("Autres appareils déconnectés", False),
    "account_delete_failed":  ("Échec de suppression du compte", True),
    "logout":                 ("Déconnexion", False),
}


class PrivateFileHandler(TimedRotatingFileHandler):
    """Fichier de log en 600 (lisible seulement par toi), y compris
    chaque nouveau fichier créé à minuit lors de la rotation."""
    def _open(self):
        stream = super()._open()
        os.chmod(self.baseFilename, 0o600)
        return stream


def init_app(app):
    path = app.config.setdefault("SECURITY_LOG",
                                 os.path.join(app.instance_path, "security.log"))
    # Un logger propre à cette app (pas logging.getLogger global) : évite
    # d'empiler des handlers quand on crée plusieurs apps (tests).
    logger = logging.Logger("security")
    handler = PrivateFileHandler(path, when="midnight", backupCount=RETENTION_DAYS,
                                 encoding="utf-8", utc=True)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    app.extensions["seclog"] = logger

    @app.template_filter("datetime")
    def fmt_datetime(ts):
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    @app.template_filter("event_label")
    def event_label(code):
        return EVENTS.get(code, (code, False))[0]

    @app.template_filter("event_alert")
    def event_alert(code):
        return EVENTS.get(code, (code, False))[1]


def _clip(value, n):
    """Tronque : un attaquant ne doit pas pouvoir remplir le disque."""
    return None if value is None else str(value)[:n]


def log_event(event: str, user_id=None, username=None, **details):
    ip = request.remote_addr if has_request_context() else None
    ua = _clip(request.user_agent.string, 200) if has_request_context() else None

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "user_id": user_id,
        "username": _clip(username, 64),
        "ip": ip,
        "ua": ua,
        **details,
    }
    # json.dumps échappe \n, \r, guillemets… → toujours UNE ligne par événement
    current_app.extensions["seclog"].info(json.dumps(record, ensure_ascii=False))

    if user_id is not None:
        conn = db.get_db()
        t = int(time.time())
        conn.execute("DELETE FROM security_events WHERE created_at < ?",
                     (t - RETENTION_DAYS * 86400,))
        conn.execute(
            "INSERT INTO security_events (user_id, event, ip, user_agent, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, event, ip, ua, t),
        )
        conn.commit()
