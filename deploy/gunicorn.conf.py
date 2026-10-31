"""Configuration gunicorn (serveur de production)."""
import multiprocessing

bind = "0.0.0.0:8000"          # écoute dans le conteneur ; seul nginx y accède
workers = min(4, multiprocessing.cpu_count() * 2 + 1)
timeout = 30                   # une requête bloquée plus de 30 s est tuée
graceful_timeout = 20
max_requests = 1000            # redémarre un worker toutes les ~1000 requêtes
max_requests_jitter = 100      # (limite l'impact d'une éventuelle fuite mémoire)
limit_request_line = 4094      # refuse les URL géantes
limit_request_fields = 50      # et les requêtes avec trop d'en-têtes
accesslog = "-"                # journaux d'accès sur la sortie standard
errorlog = "-"                 # → visibles avec « docker compose logs app »
# Interface d'administration de gunicorn : inutile ici → désactivée
# (moins de surface d'attaque, et rien à écrire sur un disque en lecture seule)
control_socket_disable = True
