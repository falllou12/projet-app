"""Double authentification TOTP (RFC 6238) + codes de secours.

Principe du TOTP : le serveur et ton téléphone partagent une clé secrète.
Toutes les 30 secondes, chacun calcule HMAC-SHA1(clé, numéro du créneau)
et en tire 6 chiffres. Si les deux résultats sont égaux, tu possèdes la clé.
"""
import hashlib
import hmac
import secrets
import time

import pyotp
import qrcode
import qrcode.image.svg

ISSUER = "Mes notes"
STEP = 30          # durée d'un code, en secondes
VALID_WINDOW = 1   # accepte le créneau précédent/suivant (horloge décalée)
RECOVERY_COUNT = 10
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # sans 0/1/8/9 → pas de confusion O/0, I/1


def new_secret() -> str:
    return pyotp.random_base32()  # 160 bits aléatoires, via le module secrets


def provisioning_uri(secret: str, username: str) -> str:
    """URI otpauth:// que les applis (Aegis, Google Authenticator…) comprennent."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg(uri: str) -> bytes:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    return img.to_string()


def verify_totp(secret: str, code: str, last_step: int):
    """Retourne le numéro de créneau accepté, ou None si le code est refusé.

    - compare_digest : comparaison à temps constant (pas de fuite par timing)
    - step > last_step : un code déjà utilisé ne peut pas être rejoué
    """
    code = code.strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // STEP
    for step in range(now_step - VALID_WINDOW, now_step + VALID_WINDOW + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * STEP), code):
            return step
    return None


def normalize_recovery(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def hash_recovery(code: str) -> str:
    # Code aléatoire de 50 bits → SHA-256 suffit (pas besoin d'un hash lent).
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()


def new_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(B32) for _ in range(10))  # 10 × 5 bits = 50 bits
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def store_recovery_codes(conn, user_id: int) -> list[str]:
    """Remplace les anciens codes par 10 nouveaux et les retourne EN CLAIR
    (une seule fois : ensuite seuls les hashs existent)."""
    codes = new_recovery_codes()
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    conn.executemany(
        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
        [(user_id, hash_recovery(c)) for c in codes],
    )
    return codes


def use_recovery_code(conn, user_id: int, code: str) -> bool:
    """Consomme un code de secours. L'UPDATE ... AND used = 0 est atomique :
    même deux requêtes simultanées ne peuvent pas utiliser le même code."""
    if len(normalize_recovery(code)) != 10:
        return False
    cur = conn.execute(
        "UPDATE recovery_codes SET used = 1 "
        "WHERE user_id = ? AND code_hash = ? AND used = 0",
        (user_id, hash_recovery(code)),
    )
    return cur.rowcount == 1


def check_second_factor(conn, user, code: str) -> str | None:
    """Vérifie un code TOTP ou un code de secours, et enregistre son usage.
    Retourne "totp", "recovery" (valeurs vraies) ou None si refusé."""
    step = verify_totp(user["totp_secret"], code, user["totp_last_step"])
    if step is not None:
        conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?",
                     (step, user["id"]))
        conn.commit()
        return "totp"
    if use_recovery_code(conn, user["id"], code):
        conn.commit()
        return "recovery"
    return None
