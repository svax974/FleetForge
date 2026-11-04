#!/bin/bash
# Métriques d'un nœud Grass pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR
# L'HÔTE.
#
# Grass n'a pas d'API de nœud : on ne voit que l'extérieur du conteneur. Ces séries
# ciblent les états qui rendent le nœud INUTILE sans l'arrêter (`service_up` reste à 1) :
#   • IP publique classée centre de données / proxy → 0 % de qualité réseau, 0 point ;
#   • application lancée mais sans aucune connexion sortante ;
#   • version de l'application en retard sur la publication officielle (« outdated
#     versions can lose their connection silently, showing Connected while
#     contributing nothing » — grass.io/learn).
# Rien n'est émis pour une mesure impossible (un 0 se lirait « tout va bien »). Chaque
# valeur passe par `num` : une valeur vide ferait rejeter TOUTE la page de l'hôte.
#
# Appels externes (mis en cache, un par heure et par type) : ip-api.com (IP de
# l'hôte) et files.grass.io (manifeste de version).
#
# Usage : grass-metrics.sh <conteneur> <url manifeste> <url contrôle IP>

set -uo pipefail

CONTAINER="${1:-grass}"
MANIFEST_URL="${2:-}"
IP_URL="${3:-}"
CACHE_DIR="${GRASS_CACHE_DIR:-/run/grass-metrics}"
CACHE_TTL="${GRASS_CACHE_TTL:-3600}"
mkdir -p "${CACHE_DIR}" 2>/dev/null

num() { [[ "${1:-}" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && echo "$1" || echo 0; }

metric() { # nom type aide valeur [labels]
  echo "# HELP $1 $3"
  echo "# TYPE $1 $2"
  echo "$1${5:-} $4"
}

# Réponse en cache si fraîche, sinon appel réel ; en cas d'échec, l'ancienne valeur
# reste valable (jusqu'à 24 h) plutôt que de faire disparaître la série.
cached_get() { # nom url
  local f="${CACHE_DIR}/$1" now age out
  now=$(date +%s)
  if [ -s "$f" ]; then
    age=$(( now - $(stat -c %Y "$f" 2>/dev/null || echo 0) ))
    [ "${age}" -lt "${CACHE_TTL}" ] && { cat "$f"; return 0; }
  fi
  if out=$(curl -sS -m 10 "$2" 2>/dev/null) && [ -n "${out}" ]; then
    printf '%s' "${out}" > "$f"; printf '%s' "${out}"; return 0
  fi
  if [ -s "$f" ]; then
    age=$(( now - $(stat -c %Y "$f" 2>/dev/null || echo 0) ))
    [ "${age}" -lt 86400 ] && { cat "$f"; return 0; }
  fi
  return 1
}

# ── Processus de l'application dans le conteneur ───────────────────────────
APP=0
if docker exec "${CONTAINER}" pgrep -x grass-desktop >/dev/null 2>&1; then APP=1; fi
metric grass_app_process_up gauge "1 si grass-desktop tourne dans le conteneur." "${APP}"

# ── Connexions sortantes établies (hors boucle locale) ─────────────────────
# /proc/net/tcp{,6} du conteneur : état 01 = ESTABLISHED ; l'adresse distante de la
# boucle locale (127.0.0.1 = 0100007F, ::1) est exclue.
if NET=$(docker exec "${CONTAINER}" sh -c 'cat /proc/net/tcp /proc/net/tcp6' 2>/dev/null); then
  CONNS=$(printf '%s\n' "${NET}" | awk '
    $4 == "01" && $3 !~ /^0100007F:/ && $3 !~ /^00000000000000000000000001000000:/ && $3 !~ /^0000000000000000FFFF00000100007F:/ { n++ }
    END { print n + 0 }')
  metric grass_established_connections gauge "Connexions TCP sortantes établies du conteneur (hors boucle locale)." "$(num "${CONNS}")"
fi

# ── Version installée et version officielle ────────────────────────────────
INSTALLED=$(docker exec "${CONTAINER}" dpkg-query -W -f='${Version}' grass-desktop 2>/dev/null | head -n1)
if [[ "${INSTALLED}" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]]; then
  metric grass_version_info gauge "Version de l'application Grass installée dans le conteneur." 1 "{version=\"${INSTALLED}\"}"
  if [ -n "${MANIFEST_URL}" ] && MAN=$(cached_get manifest.json "${MANIFEST_URL}"); then
    LATEST=$(printf '%s' "${MAN}" | jq -r '.version // empty' 2>/dev/null | sed 's/^v//')
    if [[ "${LATEST}" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]]; then
      OUT=0; [ "${LATEST}" != "${INSTALLED}" ] && OUT=1
      metric grass_version_outdated gauge "1 si la version installée diffère de la dernière publiée par Grass." "${OUT}"
    fi
  fi
fi

# ── IP publique : centre de données / proxy ? ──────────────────────────────
OK=0; HOSTING=0; PROXY=0
if [ -n "${IP_URL}" ] && IPJ=$(cached_get ip.json "${IP_URL}") \
   && [ "$(printf '%s' "${IPJ}" | jq -r '.status // empty' 2>/dev/null)" = "success" ]; then
  OK=1
  [ "$(printf '%s' "${IPJ}" | jq -r '.hosting // false' 2>/dev/null)" = "true" ] && HOSTING=1
  [ "$(printf '%s' "${IPJ}" | jq -r '.proxy // false' 2>/dev/null)" = "true" ] && PROXY=1
fi
metric grass_public_ip_lookup_ok gauge "1 si l'IP publique de l'hôte a pu être classée." "${OK}"
if [ "${OK}" = 1 ]; then
  metric grass_public_ip_hosting gauge "1 si l'IP publique est classée centre de données (Grass : 0 % de qualité)." "${HOSTING}"
  metric grass_public_ip_proxy gauge "1 si l'IP publique est classée proxy / VPN (Grass : 0 % de qualité)." "${PROXY}"
fi
