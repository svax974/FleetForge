#!/bin/bash
# Métriques StarNet pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR
# L'HÔTE.
#
# `service_up` dit seulement que /api/health répond 200. Deux états lui
# échappent :
#   • DÉGRADÉ : après une boucle de crash, le sidecar reste en écoute mais
#     répond 503 avec la raison (disjoncteur process-fault) — `up` vaut 0
#     comme pour un service arrêté, le code HTTP distingue les deux ;
#   • SATURÉ : un seul process Node porte l'UI, les flux SSE et toutes les
#     boucles d'agents. Une boucle d'événements bloquée se voit à la latence
#     de /api/health bien avant le timeout.
# /api/health est le seul point d'entrée sans jeton (sidecar/apiauth.js).
#
# Usage : starnet-metrics.sh [base_url]

set -uo pipefail

BASE="${1:-http://127.0.0.1:8787}"

OUT=$(curl -s -o /dev/null -m 10 -w '%{http_code} %{time_total}' "${BASE}/api/health" 2>/dev/null)
CODE=${OUT%% *}
TIME=${OUT##* }
# curl rend « 000 » sans réponse ; une ligne vide ou non numérique ferait
# rejeter TOUTE la page de métriques de l'hôte par Prometheus.
[[ "${CODE}" =~ ^[0-9]+$ ]] || CODE=0
[[ "${TIME}" =~ ^[0-9.]+$ ]] || TIME=0

echo "# HELP starnet_health_status_code Code HTTP de /api/health (200 sain, 503 dégradé, 0 injoignable)."
echo "# TYPE starnet_health_status_code gauge"
echo "starnet_health_status_code $((10#${CODE}))"
echo "# HELP starnet_health_latency_seconds Temps de réponse de /api/health (saturation de la boucle d'événements)."
echo "# TYPE starnet_health_latency_seconds gauge"
echo "starnet_health_latency_seconds ${TIME}"
