"""Verrouillage progressif par compte (anti brute-force distribué).

Le rate limit par IP (@limiter.limit) ne suffit pas : un attaquant avec
1000 IP (botnet, proxys) peut tester 5000 mots de passe par minute.
Ici on compte les échecs par NOM d'utilisateur, quelle que soit l'IP.

Politique : après 5 échecs → bloqué 1 min, puis 2, 4, 8… plafonné à 1 h.
Le compteur est effacé après une connexion complète réussie, ou après
24 h sans échec.
"""
import math
import time

THRESHOLD = 5         # échecs avant le premier blocage
BASE_LOCK = 60        # premier blocage : 60 s
MAX_LOCK = 3600       # jamais plus d'1 h (limite le DoS contre la victime)
FORGET_AFTER = 86400  # 24 h sans échec → compteur oublié


def now() -> int:
    """Isolé dans une fonction pour que les tests puissent « avancer le temps »."""
    return int(time.time())


def lock_remaining(conn, username: str) -> int:
    """Secondes de blocage restantes (0 = pas bloqué)."""
    row = conn.execute("SELECT locked_until FROM login_failures WHERE username = ?",
                       (username,)).fetchone()
    return max(0, row[0] - now()) if row else 0


def lock_duration(failures: int) -> int:
    if failures < THRESHOLD:
        return 0
    exponent = min(failures - THRESHOLD, 10)  # évite de calculer 2**1000000
    return min(BASE_LOCK * 2 ** exponent, MAX_LOCK)


def record_failure(conn, username: str) -> int:
    """Enregistre un échec. Retourne la durée du blocage déclenché (0 = aucun)."""
    t = now()
    # Ménage : oublie les vieux échecs (sinon la table grossit sans fin,
    # un attaquant pouvant essayer des millions de noms différents).
    conn.execute("DELETE FROM login_failures WHERE last_failure < ? AND locked_until < ?",
                 (t - FORGET_AFTER, t))
    # UPSERT atomique : « failures + 1 » est calculé PAR SQLite, en une seule
    # opération. Pas de lecture-puis-écriture → pas de race condition.
    conn.execute(
        "INSERT INTO login_failures (username, failures, last_failure) VALUES (?, 1, ?) "
        "ON CONFLICT(username) DO UPDATE SET failures = failures + 1, "
        "last_failure = excluded.last_failure",
        (username, t),
    )
    failures = conn.execute("SELECT failures FROM login_failures WHERE username = ?",
                            (username,)).fetchone()[0]
    duration = lock_duration(failures)
    if duration:
        conn.execute("UPDATE login_failures SET locked_until = ? WHERE username = ?",
                     (t + duration, username))
    conn.commit()
    return duration


def reset(conn, username: str) -> None:
    conn.execute("DELETE FROM login_failures WHERE username = ?", (username,))
    conn.commit()


def lock_message(remaining: int) -> str:
    # Même message que le compte existe ou non : aucune info pour l'attaquant
    minutes = math.ceil(remaining / 60)
    return f"Trop de tentatives. Réessaie dans {minutes} minute{'s' if minutes > 1 else ''}."
