#!/usr/bin/env bash
# Vérifications à lancer avant chaque commit : ./check.sh
# set -e : le script s'arrête au premier échec
set -euo pipefail
cd "$(dirname "$0")"
VENV=./venv/bin

echo "== 1/3 Tests de sécurité (pytest) =="
"$VENV/pytest" -q

echo "== 2/3 Analyse statique du code (bandit) =="
# -ll : sévérité moyenne et haute ; tests exclus (les assert sont normaux)
"$VENV/bandit" -r . -x ./venv,./tests -ll -q

echo "== 3/3 Dépendances vulnérables (pip-audit) =="
"$VENV/pip-audit" -r requirements.txt

echo "✔ Tout est OK"
