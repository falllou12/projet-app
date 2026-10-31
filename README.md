# Gestionnaire de notes sécurisé

Application web Flask + SQLite : inscription, connexion, et des notes privées
(créer, lire, modifier, supprimer).

## Lancer

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/flask --app app init-db     # une seule fois (EFFACE la base)
./venv/bin/flask --app app migrate-db  # base existante : ajoute la 2FA sans rien effacer
./venv/bin/flask --app app run         # http://127.0.0.1:5000
```

## Vérifier avant chaque commit

```bash
./venv/bin/pip install -r requirements-dev.txt   # une seule fois
./check.sh
```

`check.sh` lance trois contrôles et s'arrête au premier échec :

| Outil | Ce qu'il vérifie |
|---|---|
| `pytest` | Les tests d'attaque (SQLi, XSS, IDOR, CSRF, 2FA, sessions…) échouent bien |
| `bandit` | Motifs dangereux dans le code (SQL en f-string, `shell=True`, `debug=True`, secrets en dur…) |
| `pip-audit` | CVE connues dans les dépendances |

`bandit` cherche des motifs, il ne comprend pas le code. Par exemple, il ne voit pas
un `ALTER TABLE` construit avec une f-string. « 0 problème » ne veut donc pas dire « code sûr ».

## Ce qui protège l'application

| Attaque | Protection | Où |
|---|---|---|
| Vol de la base → mots de passe | Hachage Argon2id avec sel | `app.py` `ph.hash` |
| Injection SQL | Requêtes paramétrées `?` | `db.py`, `app.py` |
| XSS | Échappement Jinja + Content-Security-Policy | templates, `security_headers` |
| CSRF | Jeton dans chaque formulaire (Flask-WTF), déconnexion et suppression en POST | `forms.py` |
| IDOR (voir la note d'un autre) | `WHERE id = ? AND user_id = ?` puis 404 | `get_own_note` |
| Brute-force | 5 tentatives de connexion par minute et par IP | `@limiter.limit` |
| Énumération des comptes | Message d'erreur générique + hash bidon (temps constant) | `login` |
| Fixation de session | `session.clear()` à la connexion | `login` |
| Vol de cookie | `HttpOnly`, `SameSite=Lax`, `Secure` en HTTPS | `create_app` |
| Mot de passe volé | Double authentification TOTP optionnelle (page « Sécurité ») | `twofa.py` |
| Rejeu d'un code TOTP intercepté | `totp_last_step` : un créneau ne sert qu'une fois | `verify_totp` |
| Brute-force du code 2FA | 5 essais/min par IP + 5 échecs max par session | `login_2fa` |
| Contournement de la 2FA | Pas de `user_id` en session avant le code ; état en attente expirant après 5 min | `login`, `login_2fa` |
| Perte du téléphone | 10 codes de secours à usage unique, stockés hachés | `store_recovery_codes` |
| Cookie de session volé | `session_version` en base, comparée à chaque requête ; changer de mot de passe ou « Déconnecter les autres appareils » l'incrémente | `load_user`, `revoke_other_sessions` |
| Changement de mot de passe par un voleur de session | Ancien mot de passe redemandé, 5 essais/min | `change_password` |
| Suppression du compte par un voleur de session | Mot de passe + code 2FA redemandés, POST + CSRF, 5 essais/min | `delete_account` |
| Notes « supprimées » lisibles dans le fichier (forensique) | `PRAGMA secure_delete = ON` : données écrasées par des zéros | `db.py` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options` | `security_headers` |

## En production (pas en local)

- Ne pas utiliser `flask run` : prendre `gunicorn` derrière nginx avec HTTPS.
- `export HTTPS_ONLY=1` (cookie `Secure` + HSTS) et `export SECRET_KEY=...`.
- Stockage Redis pour le rate limiting (la mémoire se vide à chaque redémarrage).
- `instance/` contient la clé secrète et la base : ne jamais la commiter.
- La clé TOTP est stockée en clair dans la base (comme sur la plupart des sites). Pour aller plus loin, la chiffrer avec une clé hors de la base.
