"""Accès à la base SQLite.

Règle d'or contre l'injection SQL : on ne construit JAMAIS une requête
avec des f-strings ou des +. On utilise des paramètres « ? » et sqlite3
se charge d'échapper les valeurs.

    MAUVAIS : db.execute(f"SELECT * FROM users WHERE username = '{nom}'")
    BON     : db.execute("SELECT * FROM users WHERE username = ?", (nom,))
"""
import sqlite3
from pathlib import Path

import click
from flask import current_app, g


def get_db():
    """Retourne une connexion par requête HTTP (stockée dans g)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row          # accès par nom : row["title"]
        g.db.execute("PRAGMA foreign_keys = ON")  # active les clés étrangères (CASCADE)
        # Écrase avec des zéros les données supprimées. Sans ça, une note
        # « supprimée » reste lisible dans le fichier (strings notes.sqlite).
        # Explicite : ne pas dépendre de la façon dont SQLite a été compilé.
        g.db.execute("PRAGMA secure_delete = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
    get_db().executescript(schema)


def migrate_db():
    """Met à jour une base existante sans effacer les données."""
    conn = get_db()
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    added = []
    for name, ddl in [
        ("totp_secret", "TEXT"),
        ("totp_pending_secret", "TEXT"),
        ("totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
        ("session_version", "INTEGER NOT NULL DEFAULT 0"),
    ]:
        if name not in cols:
            # Noms de colonnes fixés dans le code (pas d'entrée utilisateur) :
            # c'est le seul endroit où on peut construire du SQL avec une f-string.
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
            added.append(name)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            code_hash TEXT    NOT NULL,
            used      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes (user_id);
        CREATE TABLE IF NOT EXISTS login_failures (
            username     TEXT    PRIMARY KEY,
            failures     INTEGER NOT NULL DEFAULT 0,
            last_failure INTEGER NOT NULL,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            event      TEXT    NOT NULL,
            ip         TEXT,
            user_agent TEXT,
            created_at INTEGER NOT NULL,   -- timestamp Unix (UTC)
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_events_user ON security_events (user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_events_date ON security_events (created_at);
    """)
    conn.commit()
    return added


@click.command("migrate-db")
def migrate_db_command():
    """Ajoute les colonnes 2FA à une base existante : `flask --app app migrate-db`."""
    added = migrate_db()
    click.echo(f"Migration OK. Colonnes ajoutées : {', '.join(added) or 'aucune'}")


@click.command("init-db")
def init_db_command():
    """Crée (ou réinitialise) les tables : `flask --app app init-db`."""
    init_db()
    click.echo("Base de données initialisée.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(migrate_db_command)
