#!/bin/bash
# Métriques llmauth pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR L'HÔTE.
#
# Deux sources :
#
# 1. Le /metrics NATIF du service (llm_auth_requests_total,
#    llm_auth_validate_seconds), relayé tel quel. Prometheus ne peut pas le
#    scraper directement : le port n'est publié que sur 127.0.0.1, et l'ouvrir
#    exposerait du même coup /admin/* et /validate, servis par le même
#    listener. Seules les séries `llm_auth_*` sont relayées : les séries go_* /
#    process_* entreraient en collision avec celles d'un autre service relayé
#    par le même svcprobe, et une famille de métriques déclarée deux fois fait
#    rejeter le scrape ENTIER — toutes les sondes de l'hôte disparaîtraient.
#    Noms conservés à l'identique de main.go : ce qu'on cherche dans Grafana
#    est ce qu'on trouve dans le code.
#
# 2. La base SQLite, lue en lecture seule : nombre de clés ACTIVES. C'est l'état
#    dégradé que la sonde `service_up` ne voit pas : à 0, le service répond
#    parfaitement à /healthz et nginx rejette pourtant 100 % des requêtes
#    (base recréée vide, volume mal monté après une migration, révocation en
#    masse). Aucun endpoint ne liste les clés, d'où la lecture directe.
#
# Usage : llmauth-metrics.sh [base_url] [chemin_base_sqlite]

set -uo pipefail

BASE="${1:-http://127.0.0.1:19080}"
DB="${2:-/opt/llmauth/data/keys.sqlite}"

# ── 1. Relai des séries natives ─────────────────────────────────────────────
NATIVE_UP=0
NATIVE=$(curl -fsS -m 5 "${BASE}/metrics" 2>/dev/null)
if [ $? -eq 0 ] && [ -n "${NATIVE}" ]; then
  NATIVE_UP=1
  # `|| true` : avant la première requête, les CounterVec n'ont aucune série
  # et grep ne trouve rien — ce n'est pas une erreur, et un code de retour non
  # nul ferait jeter par svcprobe TOUTE la sortie du collecteur.
  printf '%s\n' "${NATIVE}" | grep -E '^(# (HELP|TYPE) )?llm_auth_' || true
fi

# ── 2. Clés de la base ──────────────────────────────────────────────────────
# python3 plutôt que le client sqlite3 : présent sur tout le parc (svcprobe
# lui-même en dépend), sans paquet de plus à installer. `mode=ro` : le
# collecteur ne doit jamais pouvoir créer ni modifier la base.
COUNTS=$(python3 -I - "${DB}" 2>/dev/null <<'PY'
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True, timeout=2)
enabled, total = db.execute(
    "SELECT COALESCE(SUM(enabled = 1), 0), COUNT(*) FROM api_keys").fetchone()
print(enabled, total - enabled)
PY
)
RC=$?

echo "# HELP llmauth_native_metrics_up 1 si le /metrics natif du service a pu être relayé."
echo "# TYPE llmauth_native_metrics_up gauge"
echo "llmauth_native_metrics_up ${NATIVE_UP}"

echo "# HELP llmauth_db_readable 1 si la base des clés a pu être lue."
echo "# TYPE llmauth_db_readable gauge"
if [ "${RC}" -eq 0 ] && [ -n "${COUNTS}" ]; then
  read -r ENABLED REVOKED <<<"${COUNTS}"
  echo "llmauth_db_readable 1"
  echo "# HELP llmauth_keys Clés API dans la base, par état. enabled=0 : toute requête est rejetée."
  echo "# TYPE llmauth_keys gauge"
  echo "llmauth_keys{state=\"enabled\"} ${ENABLED}"
  echo "llmauth_keys{state=\"revoked\"} ${REVOKED}"
else
  # Pas de `llmauth_keys` du tout plutôt qu'un 0 inventé : une base illisible
  # n'est pas une base vide, et les deux appellent des gestes différents.
  echo "llmauth_db_readable 0"
fi
