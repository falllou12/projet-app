"""Gestionnaire de notes sécurisé — Flask + SQLite.

Lancer :  flask --app app init-db   (une seule fois)
          flask --app app run
"""
import functools
import os
import secrets
import time
from datetime import timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import (Flask, abort, flash, g, redirect, render_template,
                   session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

import db
import twofa
from forms import (ChangePasswordForm, DisableTotpForm, EmptyForm, LoginForm,
                   NoteForm, RegisterForm, TotpForm)

PENDING_2FA_TTL = 300    # 5 min pour saisir le code après le mot de passe
MAX_2FA_ATTEMPTS = 5     # au-delà, il faut retaper le mot de passe

ph = PasswordHasher()  # Argon2id avec des paramètres par défaut sûrs
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# Hash « bidon » : quand l'utilisateur n'existe pas, on vérifie quand même
# un mot de passe. Le temps de réponse est alors le même que pour un vrai
# compte, et un attaquant ne peut pas deviner quels noms existent
# (énumération par timing).
DUMMY_HASH = ph.hash("mot-de-passe-bidon-pour-le-timing")


def load_secret_key(instance_path: str) -> str:
    """La clé secrète signe les cookies de session. Si elle fuite, n'importe
    qui peut forger une session. On la lit dans une variable d'environnement,
    sinon on la génère une fois dans instance/ (fichier jamais commité)."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    key_file = Path(instance_path) / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)  # lisible uniquement par toi
    return key_file.read_text().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.update(
        SECRET_KEY=load_secret_key(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "notes.sqlite"),
        # --- Cookies de session ---
        SESSION_COOKIE_HTTPONLY=True,   # JavaScript ne peut pas lire le cookie (limite le vol par XSS)
        SESSION_COOKIE_SAMESITE="Lax",  # cookie non envoyé par les requêtes POST venant d'autres sites
        # Secure = cookie envoyé uniquement en HTTPS. Désactivé par défaut pour
        # pouvoir tester sur http://localhost ; mets HTTPS_ONLY=1 en production.
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=64 * 1024,   # refuse les requêtes > 64 Ko
    )
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    register_routes(app)
    register_security(app)
    return app


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped


def get_own_note(note_id: int):
    """Récupère une note SEULEMENT si elle appartient à l'utilisateur connecté.

    Le filtre `AND user_id = ?` empêche l'IDOR (Insecure Direct Object
    Reference) : changer /notes/5 en /notes/6 dans l'URL ne donne pas
    accès à la note de quelqu'un d'autre. On renvoie 404 (et non 403) pour
    ne même pas révéler que la note existe.
    """
    note = db.get_db().execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, g.user["id"]),
    ).fetchone()
    if note is None:
        abort(404)
    return note


def start_session(user_id: int, version: int):
    """Ouvre une session « pleinement connectée ».

    session.clear() → nouvelle session (anti-fixation).
    sv = session_version : copiée dans le cookie, comparée à chaque requête.
    """
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["sv"] = version


def revoke_other_sessions(conn, user_id: int):
    """Incrémente la version : TOUS les cookies existants deviennent invalides.
    On réécrit ensuite le cookie courant avec la nouvelle version, pour
    garder cet appareil connecté."""
    conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?",
                 (user_id,))
    conn.commit()
    new_version = conn.execute("SELECT session_version FROM users WHERE id = ?",
                               (user_id,)).fetchone()[0]
    start_session(user_id, new_version)


def register_routes(app):

    @app.before_request
    def load_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            user = db.get_db().execute(
                "SELECT id, username, session_version FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            # Cookie d'une ancienne « génération » (mot de passe changé,
            # déconnexion globale) ou compte supprimé → session rejetée.
            if user is None or session.get("sv") != user["session_version"]:
                session.clear()
            else:
                g.user = user

    @app.context_processor
    def inject_logout_form():
        # Formulaire de déconnexion (avec jeton CSRF) disponible dans tous les templates
        return {"logout_form": EmptyForm()}

    @app.route("/")
    def index():
        return redirect(url_for("notes_list" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            conn = db.get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (form.username.data, ph.hash(form.password.data)),
                )
                conn.commit()
            except conn.IntegrityError:  # contrainte UNIQUE sur username
                form.username.errors.append("Ce nom est déjà pris.")
            else:
                flash("Compte créé. Tu peux te connecter.", "success")
                return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])  # anti brute-force
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            conn = db.get_db()
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (form.username.data,)
            ).fetchone()

            stored_hash = user["password_hash"] if user else DUMMY_HASH
            try:
                ph.verify(stored_hash, form.password.data)
                ok = user is not None
            except (VerificationError, InvalidHashError):
                ok = False

            if ok:
                # Si les paramètres Argon2 ont été renforcés depuis, on re-hache
                if ph.check_needs_rehash(stored_hash):
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                 (ph.hash(form.password.data), user["id"]))
                    conn.commit()
                # session.clear() empêche la « fixation de session » : on
                # repart d'une session neuve au moment de la connexion.
                session.clear()
                if user["totp_secret"]:
                    # Mot de passe OK mais 2FA active : on NE met PAS user_id.
                    # La session est dans un état « à moitié connecté ».
                    session["2fa_user_id"] = user["id"]
                    session["2fa_sv"] = user["session_version"]
                    session["2fa_started"] = int(time.time())
                    session["2fa_fails"] = 0
                    return redirect(url_for("login_2fa"))
                start_session(user["id"], user["session_version"])
                return redirect(url_for("notes_list"))

            # Message volontairement vague : on ne dit pas si c'est le nom
            # ou le mot de passe qui est faux.
            flash("Identifiants invalides.", "error")
        return render_template("login.html", form=form)

    @app.route("/logout", methods=["POST"])  # POST + CSRF : un lien piégé ne peut pas te déconnecter
    def logout():
        if EmptyForm().validate_on_submit():
            session.clear()
        return redirect(url_for("login"))

    # -----------------------------------------------------------------------
    # Double authentification
    # -----------------------------------------------------------------------
    @app.route("/login/2fa", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])  # 10^6 codes possibles : on freine le brute-force
    def login_2fa():
        user_id = session.get("2fa_user_id")
        started = session.get("2fa_started", 0)
        if user_id is None or time.time() - started > PENDING_2FA_TTL:
            session.clear()
            flash("Session expirée, reconnecte-toi.", "error")
            return redirect(url_for("login"))

        form = TotpForm()
        if form.validate_on_submit():
            conn = db.get_db()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user is None or session.get("2fa_sv") != user["session_version"]:
                # Le mot de passe a changé entre-temps : l'ancien ne doit plus servir
                session.clear()
                flash("Session expirée, reconnecte-toi.", "error")
                return redirect(url_for("login"))
            if user["totp_secret"] and twofa.check_second_factor(conn, user, form.code.data):
                start_session(user["id"], user["session_version"])
                return redirect(url_for("notes_list"))

            # Le rate limit est par IP. Ce compteur limite aussi par session :
            # après 5 échecs, il faut recommencer depuis le mot de passe.
            session["2fa_fails"] = session.get("2fa_fails", 0) + 1
            if session["2fa_fails"] >= MAX_2FA_ATTEMPTS:
                session.clear()
                flash("Trop d'échecs, reconnecte-toi.", "error")
                return redirect(url_for("login"))
            flash("Code invalide.", "error")
        return render_template("login_2fa.html", form=form)

    def current_user_full():
        return db.get_db().execute("SELECT * FROM users WHERE id = ?",
                                   (g.user["id"],)).fetchone()

    @app.route("/security")
    @login_required
    def security():
        user = current_user_full()
        remaining = db.get_db().execute(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used = 0",
            (user["id"],)).fetchone()[0]
        return render_template("security.html", enabled=bool(user["totp_secret"]),
                               remaining=remaining, disable_form=DisableTotpForm(),
                               password_form=ChangePasswordForm(),
                               logout_all_form=EmptyForm())

    @app.route("/security/password", methods=["POST"])
    @login_required
    @limiter.limit("5 per minute")  # sinon on pourrait deviner le mot de passe actuel ici
    def change_password():
        form = ChangePasswordForm()
        conn = db.get_db()
        user = current_user_full()
        if not form.validate_on_submit():
            for errors in form.errors.values():
                for err in errors:
                    flash(err, "error")
            return redirect(url_for("security"))
        try:
            ph.verify(user["password_hash"], form.current.data)
        except (VerificationError, InvalidHashError):
            flash("Mot de passe actuel incorrect.", "error")
            return redirect(url_for("security"))
        if form.new.data == form.current.data:
            flash("Le nouveau mot de passe doit être différent.", "error")
            return redirect(url_for("security"))

        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (ph.hash(form.new.data), user["id"]))
        # Mot de passe changé = peut-être volé → on éjecte les autres appareils
        revoke_other_sessions(conn, user["id"])
        flash("Mot de passe changé. Tes autres appareils ont été déconnectés.", "success")
        return redirect(url_for("security"))

    @app.route("/security/logout-all", methods=["POST"])
    @login_required
    def logout_all():
        if EmptyForm().validate_on_submit():
            revoke_other_sessions(db.get_db(), g.user["id"])
            flash("Tous tes autres appareils ont été déconnectés.", "success")
        return redirect(url_for("security"))

    @app.route("/security/2fa/setup", methods=["GET", "POST"])
    @login_required
    def twofa_setup():
        conn = db.get_db()
        user = current_user_full()
        if user["totp_secret"]:
            return redirect(url_for("security"))

        secret = user["totp_pending_secret"]
        if not secret:  # générée une fois, côté serveur (pas dans le cookie)
            secret = twofa.new_secret()
            conn.execute("UPDATE users SET totp_pending_secret = ? WHERE id = ?",
                         (secret, user["id"]))
            conn.commit()

        form = TotpForm()
        if form.validate_on_submit():
            # On n'active QUE si l'utilisateur prouve qu'il a bien scanné la clé
            step = twofa.verify_totp(secret, form.code.data, 0)
            if step is not None:
                conn.execute(
                    "UPDATE users SET totp_secret = ?, totp_pending_secret = NULL, "
                    "totp_last_step = ? WHERE id = ?", (secret, step, user["id"]))
                codes = twofa.store_recovery_codes(conn, user["id"])
                conn.commit()
                # Affichés UNE SEULE FOIS (rendu direct, pas de redirection)
                return render_template("recovery_codes.html", codes=codes)
            flash("Code invalide. Vérifie l'heure de ton téléphone.", "error")

        return render_template("twofa_setup.html", form=form, secret=secret)

    @app.route("/security/2fa/qr.svg")
    @login_required
    def twofa_qr():
        secret = current_user_full()["totp_pending_secret"]
        if not secret:
            abort(404)
        svg = twofa.qr_svg(twofa.provisioning_uri(secret, g.user["username"]))
        return svg, 200, {"Content-Type": "image/svg+xml", "Cache-Control": "no-store"}

    @app.route("/security/2fa/disable", methods=["POST"])
    @login_required
    @limiter.limit("5 per minute")
    def twofa_disable():
        form = DisableTotpForm()
        conn = db.get_db()
        user = current_user_full()
        if form.validate_on_submit() and user["totp_secret"]:
            try:
                ph.verify(user["password_hash"], form.password.data)
                pwd_ok = True
            except (VerificationError, InvalidHashError):
                pwd_ok = False
            if pwd_ok and twofa.check_second_factor(conn, user, form.code.data):
                conn.execute("UPDATE users SET totp_secret = NULL, totp_last_step = 0 "
                             "WHERE id = ?", (user["id"],))
                conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
                conn.commit()
                flash("Double authentification désactivée.", "success")
                return redirect(url_for("security"))
        flash("Mot de passe ou code invalide.", "error")
        return redirect(url_for("security"))

    # -----------------------------------------------------------------------
    # Notes (CRUD)
    # -----------------------------------------------------------------------
    @app.route("/notes")
    @login_required
    def notes_list():
        notes = db.get_db().execute(
            "SELECT id, title, updated_at FROM notes WHERE user_id = ? "
            "ORDER BY updated_at DESC",
            (g.user["id"],),
        ).fetchall()
        return render_template("notes_list.html", notes=notes)

    @app.route("/notes/new", methods=["GET", "POST"])
    @login_required
    def note_new():
        form = NoteForm()
        if form.validate_on_submit():
            conn = db.get_db()
            conn.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                (g.user["id"], form.title.data, form.body.data),
            )
            conn.commit()
            flash("Note créée.", "success")
            return redirect(url_for("notes_list"))
        return render_template("note_form.html", form=form, action="Créer")

    @app.route("/notes/<int:note_id>")
    @login_required
    def note_view(note_id):
        return render_template("note_view.html", note=get_own_note(note_id),
                               delete_form=EmptyForm())

    @app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
    @login_required
    def note_edit(note_id):
        note = get_own_note(note_id)
        form = NoteForm(data={"title": note["title"], "body": note["body"]})
        if form.validate_on_submit():
            conn = db.get_db()
            conn.execute(
                "UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP "
                "WHERE id = ? AND user_id = ?",
                (form.title.data, form.body.data, note_id, g.user["id"]),
            )
            conn.commit()
            flash("Note modifiée.", "success")
            return redirect(url_for("note_view", note_id=note_id))
        return render_template("note_form.html", form=form, action="Enregistrer")

    @app.route("/notes/<int:note_id>/delete", methods=["POST"])
    @login_required
    def note_delete(note_id):
        get_own_note(note_id)  # 404 si ce n'est pas ta note
        if EmptyForm().validate_on_submit():
            conn = db.get_db()
            conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?",
                         (note_id, g.user["id"]))
            conn.commit()
            flash("Note supprimée.", "success")
        return redirect(url_for("notes_list"))


# ---------------------------------------------------------------------------
# En-têtes de sécurité et gestion des erreurs
# ---------------------------------------------------------------------------
def register_security(app):

    @app.after_request
    def security_headers(resp):
        # CSP : le navigateur ne charge scripts, styles et images que depuis
        # notre propre domaine. Même si du HTML était injecté, un <script>
        # inline ou externe serait bloqué. C'est la 2e ligne de défense contre le XSS.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"   # pas de devinette de type MIME
        resp.headers["X-Frame-Options"] = "DENY"             # anti clickjacking (vieux navigateurs)
        resp.headers["Referrer-Policy"] = "same-origin"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Les pages connectées ne doivent pas rester dans le cache du navigateur
        if g.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        return render_template("error.html", code=400,
                               message="Jeton de sécurité invalide ou expiré. Recharge la page."), 400

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="Page introuvable."), 404

    @app.errorhandler(429)
    def too_many(e):
        return render_template("error.html", code=429,
                               message="Trop de tentatives. Réessaie dans une minute."), 429


app = create_app()
