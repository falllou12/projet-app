#!/usr/bin/env bash
# Génère un certificat HTTPS AUTO-SIGNÉ pour https://localhost (tests locaux).
# Le navigateur affichera un avertissement : normal, aucune autorité de
# certification ne l'a signé. En production : Let's Encrypt (certbot).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs

if [ -f certs/cert.pem ]; then
    echo "Certificat déjà présent (deploy/certs/). Supprime-le pour en regénérer un."
    exit 0
fi

# Clé ECDSA P-256 (moderne, rapide) ; SAN obligatoire pour les navigateurs actuels
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 365 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout certs/key.pem -out certs/cert.pem 2>/dev/null

# nginx tourne dans le conteneur sous un autre utilisateur (uid 101) : il doit
# pouvoir lire la clé. Acceptable ici : certificat de TEST, et ton dossier
# personnel (drwxr-x---) n'est pas accessible aux autres comptes du PC.
chmod 644 certs/cert.pem certs/key.pem

echo "Certificat créé :"
openssl x509 -in certs/cert.pem -noout -subject -enddate
