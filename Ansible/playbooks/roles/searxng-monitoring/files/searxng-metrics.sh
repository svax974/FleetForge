#!/bin/bash
# Métriques SearXNG pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR L'HÔTE.
#
# Pourquoi ce collecteur, alors que la sonde `service_up` existe déjà : elle ne
# dit qu'une chose, « le conteneur répond ». Or la panne caractéristique d'un
# métamoteur n'est pas l'arrêt, c'est la stérilité — les moteurs amont
# finissent par bloquer l'IP de l'instance, chaque requête revient VIDE, et
# l'application qui s'en sert ne reçoit plus rien alors que tous les voyants
# sont au vert. Aucune sonde binaire ne peut voir cet état.
#
# Une requête RÉELLE est nécessaire pour le savoir. Elle n'est donc pas jouée à
# chaque scrape mais au plus une fois par INTERVAL (défaut 300 s), le résultat
# étant servi depuis un cache entre deux : à 15 s de scrape, une requête par
# scrape ferait près de 6 000 recherches par jour vers les moteurs amont, soit
# exactement le comportement qui déclenche le blocage qu'on cherche à détecter.
#
# Usage : searxng-metrics.sh [base_url] [requête] [intervalle_secondes]

set -uo pipefail

BASE="${1:-http://127.0.0.1:8888}"
QUERY="${2:-open source}"
INTERVAL="${3:-300}"
CACHE_DIR=/var/lib/svcprobe
CACHE="${CACHE_DIR}/searxng.prom"

mkdir -p "${CACHE_DIR}"

NOW=$(date +%s)
if [ -f "${CACHE}" ]; then
  AGE=$(( NOW - $(stat -c %Y "${CACHE}") ))
  if [ "${AGE}" -lt "${INTERVAL}" ]; then
    cat "${CACHE}"
    exit 0
  fi
fi

START=$(date +%s.%N)
BODY=$(curl -sS -m 25 -G "${BASE}/search" \
         --data-urlencode "q=${QUERY}" \
         --data-urlencode "format=json" 2>/dev/null)
RC=$?
END=$(date +%s.%N)
DURATION=$(awk -v a="${START}" -v b="${END}" 'BEGIN { printf "%.3f", b - a }')

SUCCESS=0
RESULTS=0
UNRESPONSIVE=0

# `jq -e .` valide le JSON : un 403 (format JSON désactivé) ou une page
# d'erreur HTML renvoient un corps non vide qu'un simple test de code de retour
# prendrait pour une réussite.
if [ "${RC}" -eq 0 ] && printf '%s' "${BODY}" | jq -e . >/dev/null 2>&1; then
  SUCCESS=1
  # `// []` sur chaque champ : une réponse JSON valide mais d'une autre forme
  # (message d'erreur applicatif) ferait échouer jq, et la variable vide
  # produirait une ligne de métrique tronquée — que Prometheus rejette en
  # bloc, faisant disparaître TOUTES les métriques de l'hôte, pas seulement
  # celles-ci.
  RESULTS=$(printf '%s' "${BODY}" | jq '(.results // []) | length')
  # Moteurs qui n'ont pas répondu à CETTE requête. Quelques-uns est normal ;
  # leur montée continue précède la stérilité complète, c'est le signal
  # précoce que la sonde de disponibilité ne donnera jamais.
  UNRESPONSIVE=$(printf '%s' "${BODY}" | jq '(.unresponsive_engines // []) | length')
  [ -n "${RESULTS}" ] || RESULTS=0
  [ -n "${UNRESPONSIVE}" ] || UNRESPONSIVE=0
fi

{
  echo "# HELP searxng_query_success 1 si la requête de contrôle a renvoyé du JSON exploitable."
  echo "# TYPE searxng_query_success gauge"
  echo "searxng_query_success ${SUCCESS}"
  echo "# HELP searxng_query_results Nombre de résultats renvoyés par la requête de contrôle."
  echo "# TYPE searxng_query_results gauge"
  echo "searxng_query_results ${RESULTS}"
  echo "# HELP searxng_query_unresponsive_engines Moteurs amont sans réponse sur la requête de contrôle."
  echo "# TYPE searxng_query_unresponsive_engines gauge"
  echo "searxng_query_unresponsive_engines ${UNRESPONSIVE}"
  echo "# HELP searxng_query_duration_seconds Durée de la requête de contrôle."
  echo "# TYPE searxng_query_duration_seconds gauge"
  echo "searxng_query_duration_seconds ${DURATION}"
  echo "# HELP searxng_query_last_check_timestamp_seconds Date de la dernière requête de contrôle réellement jouée."
  echo "# TYPE searxng_query_last_check_timestamp_seconds gauge"
  echo "searxng_query_last_check_timestamp_seconds ${NOW}"
} > "${CACHE}.tmp" && mv "${CACHE}.tmp" "${CACHE}"

cat "${CACHE}"
