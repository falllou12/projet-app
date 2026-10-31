# ---- Image de l'application (gunicorn + Flask) ----
# Version précise : une reconstruction donne la même base.
FROM python:3.14-slim

# Pas de fichiers .pyc, logs Python affichés immédiatement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur sans privilèges (uid fixe → droits prévisibles sur le volume)
RUN groupadd --gid 10001 app && \
    useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

# 1) Dépendances d'abord : couche mise en cache tant que requirements.txt ne change pas
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# 2) Puis le code (seulement ce qui est utile, voir .dockerignore)
COPY --chown=root:root . .

# instance/ = base SQLite + clé secrète + journal : SEUL dossier inscriptible,
# monté comme volume (les données survivent à la reconstruction de l'image)
RUN mkdir -p /app/instance && chown app:app /app/instance && chmod 700 /app/instance \
    && chmod 755 /app/deploy/entrypoint.sh

USER app

EXPOSE 8000

# Docker vérifie toutes les 30 s que l'application répond
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=4)" || exit 1

ENTRYPOINT ["/app/deploy/entrypoint.sh"]
CMD ["gunicorn", "--config", "deploy/gunicorn.conf.py", "app:app"]
