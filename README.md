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
| Brute-force distribué (botnet, beaucoup d'IP) | Blocage progressif **par compte** : 1, 2, 4… min, max 1 h ; échecs 2FA comptés aussi | `lockout.py` |
| Énumération via le blocage | Échecs suivis par nom saisi, même inexistant ; message identique | `record_failure` |
| Énumération des comptes | Message d'erreur générique + hash bidon (temps constant) | `login` |
| Fixation de session | `session.clear()` à la connexion | `login` |
| Vol de cookie | `HttpOnly`, `SameSite=Lax`, `Secure` en HTTPS | `create_app` |
| Mot de passe volé | Double authentification TOTP optionnelle (page « Sécurité ») | `twofa.py` |
| Rejeu d'un code TOTP intercepté | `totp_last_step` : un créneau ne sert qu'une fois | `verify_totp` |
| Brute-force du code 2FA | 5 essais/min par IP + 5 échecs max par session | `login_2fa` |
| Contournement de la 2FA | Pas de `user_id` en session avant le code ; état en attente expirant après 5 min | `login`, `login_2fa` |
| Perte du téléphone | 10 codes de secours à usage unique, stockés hachés | `store_recovery_codes` |
| Liste de codes de secours fuitée | Régénération (mot de passe + code 2FA) qui invalide TOUS les anciens codes ; alerte à ≤ 3 codes | `regenerate_recovery_codes` |
| Cookie de session volé | `session_version` en base, comparée à chaque requête ; changer de mot de passe ou « Déconnecter les autres appareils » l'incrémente | `load_user`, `revoke_other_sessions` |
| Changement de mot de passe par un voleur de session | Ancien mot de passe redemandé, 5 essais/min | `change_password` |
| Suppression du compte par un voleur de session | Mot de passe + code 2FA redemandés, POST + CSRF, 5 essais/min | `delete_account` |
| Notes « supprimées » lisibles dans le fichier (forensique) | `PRAGMA secure_delete = ON` : données écrasées par des zéros | `db.py` |
| Attaque passée inaperçue | Journal de sécurité : `instance/security.log` (JSON, 90 jours, droits 600) + page « Activité récente » par utilisateur | `seclog.py` |
| Injection de logs (CWE-117) | Une ligne JSON par événement : un `\n` saisi reste du texte | `log_event` |
| Secrets dans les logs | Jamais de mot de passe, code 2FA ou clé journalisé (vérifié par test) | `test_no_secrets_in_logs` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options` | `security_headers` |

## Lire le journal de sécurité

```bash
tail -f instance/security.log                                 # en direct
grep '"login_failed"' instance/security.log | wc -l           # nombre d'échecs
jq -r 'select(.event=="login_failed") | .ip' instance/security.log | sort | uniq -c | sort -rn   # IP les plus actives
```

## Déploiement (Docker : nginx + gunicorn + redis)

```bash
./deploy/gen-cert.sh                 # certificat HTTPS de test (une fois)
docker compose up -d --build         # construit et lance les 3 conteneurs
docker compose ps                    # état (healthy = OK)
docker compose logs -f app           # journaux de l'application
docker compose down                  # arrêter (les données restent dans le volume)
docker compose exec nginx nginx -s reload   # après avoir modifié deploy/nginx.conf
```

Ouvrir **https://localhost:8443** (avertissement du navigateur : certificat auto-signé, normal en local).

```
Navigateur ─HTTPS─▶ nginx ─HTTP─▶ app (gunicorn) ─▶ redis
                   réseau front   réseau back (interne, sans Internet)
```

| Mesure | Pourquoi |
|---|---|
| Ports publiés sur `127.0.0.1` uniquement | Docker contourne `ufw` : sans ça, le port est ouvert à tout le réseau |
| Réseau `back` en `internal: true` | App compromise = pas d'exfiltration, pas de téléchargement d'outils |
| `read_only`, `cap_drop: ALL`, `no-new-privileges`, utilisateurs non-root | Limite ce qu'un attaquant peut faire dans un conteneur |
| nginx **écrase** `X-Forwarded-For` ; Flask ne lit qu'1 niveau (`ProxyFix x_for=1`) | Empêche de falsifier son IP pour contourner le rate limit |
| Rate limit dans redis | Partagé entre les workers gunicorn (sinon limite × nombre de workers) |
| TLS 1.2/1.3, délais courts, `server_tokens off` | HTTPS moderne, anti-Slowloris, version de nginx cachée |
| nginx transmet `Host` avec le port ; Flask n'accepte que `TRUSTED_HOSTS` | Sans le port, Flask-WTF refusait tous les formulaires ; la liste blanche bloque l'injection d'en-tête Host |
| `HSTS: "0"` en local | HSTS sur `localhost` forcerait le HTTPS pour tous les ports de localhost |

### Sur un vrai serveur, en plus
- Certificat **Let's Encrypt** (certbot) à la place du certificat auto-signé, et `HSTS: "1"`.
- Ports `80:8080` et `443:8443` (sans `127.0.0.1`), et pare-feu configuré.
- SSH par clé uniquement, mises à jour automatiques (`unattended-upgrades`).
- Sauvegarde régulière du volume `instance` (base + clé secrète).
- La clé TOTP est stockée en clair dans la base : la chiffrer avec une clé hors de la base.
