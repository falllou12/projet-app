-- Schéma de la base SQLite
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS login_failures;
DROP TABLE IF EXISTS recovery_codes;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    -- On ne stocke JAMAIS le mot de passe, seulement son hash Argon2
    -- (qui contient lui-même le sel et les paramètres).
    password_hash TEXT    NOT NULL,
    -- Double authentification (TOTP). NULL = désactivée.
    totp_secret         TEXT,
    -- Clé en cours de configuration (pas encore confirmée par un code)
    totp_pending_secret TEXT,
    -- Dernier créneau de 30 s accepté : empêche de réutiliser un code (rejeu)
    totp_last_step      INTEGER NOT NULL DEFAULT 0,
    -- Incrémentée pour invalider toutes les sessions existantes (révocation)
    session_version     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_notes_user ON notes (user_id);

-- Codes de secours : stockés hachés (SHA-256), utilisables une seule fois
CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    code_hash TEXT    NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_recovery_user ON recovery_codes (user_id);

-- Échecs de connexion par NOM saisi (même s'il n'existe pas : anti-énumération).
-- Pas de clé étrangère vers users, justement pour suivre les noms inexistants.
CREATE TABLE login_failures (
    username     TEXT    PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    last_failure INTEGER NOT NULL,          -- timestamp Unix
    locked_until INTEGER NOT NULL DEFAULT 0 -- timestamp Unix, 0 = pas bloqué
);

-- Journal de sécurité visible par l'utilisateur (événements de SON compte).
-- Gardé 90 jours (une IP est une donnée personnelle : nLPD / RGPD).
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
