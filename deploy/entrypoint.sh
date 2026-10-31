#!/bin/sh
# Prépare la base au démarrage du conteneur, puis lance gunicorn.
set -eu
umask 077   # fichiers créés (base, clé, logs) : lisibles par l'utilisateur seulement

if [ ! -f /app/instance/notes.sqlite ]; then
    echo "Première exécution : création de la base"
    flask --app app init-db
else
    # Base existante : n'ajoute que ce qui manque, sans rien effacer
    flask --app app migrate-db
fi

# exec : gunicorn remplace le shell → il reçoit directement les signaux
# d'arrêt de Docker (arrêt propre avec docker compose down)
exec "$@"
