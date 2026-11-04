#!/bin/bash
# Métriques d'un nœud Monero pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR L'HÔTE.
#
# Source : le RPC local de monerod (127.0.0.1:18081) — `get_info` et
# `get_last_block_header`. Ces séries couvrent ce que `service_up` ne voit pas : un démon
# qui tourne mais n'avance plus, n'a plus de pairs, manque de disque, ou a pris du retard
# sur la dernière version (un hard fork rend un nœud périmé inutilisable).
#
# Rien n'est émis si le RPC ne répond pas (`service_up` porte alors l'information : un 0
# se lirait « hauteur zéro » ou « aucun pair »). Chaque valeur passe par `num` : une valeur
# vide ferait rejeter TOUTE la page de métriques de l'hôte par Prometheus.
#
# Usage : monero-metrics.sh <port RPC> <url de hashes.txt>

set -uo pipefail

RPC_PORT="${1:-18081}"
RELEASE_URL="${2:-}"
CACHE_DIR="${MONERO_CACHE_DIR:-/run/monero-metrics}"
mkdir -p "${CACHE_DIR}" 2>/dev/null

INFO=$(curl -sS -m 8 "http://127.0.0.1:${RPC_PORT}/get_info" 2>/dev/null) || exit 0
printf '%s' "${INFO}" | jq -e 'type == "object" and has("height")' >/dev/null 2>&1 || exit 0

num() { [[ "${1:-}" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && echo "$1" || echo 0; }
ij() { printf '%s' "${INFO}" | jq -r "$1" 2>/dev/null; }
b2i() { [ "${1:-}" = "true" ] && echo 1 || echo 0; }

metric() { # nom type aide valeur [labels]
  echo "# HELP $1 $3"
  echo "# TYPE $1 $2"
  echo "$1${5:-} $4"
}

HEIGHT=$(num "$(ij '.height')")
TARGET=$(num "$(ij '.target_height')")
# `target_height` vaut 0 une fois synchronisé : le retard n'existe que s'il est supérieur.
LAG=0; [ "${TARGET%.*}" -gt "${HEIGHT%.*}" ] && LAG=$(( ${TARGET%.*} - ${HEIGHT%.*} ))

metric monero_height gauge "Hauteur de la chaîne du nœud." "${HEIGHT}"
metric monero_sync_lag_blocks gauge "Blocs de retard sur la cible des pairs (0 si synchronisé)." "${LAG}"
metric monero_synchronized gauge "1 si le nœud se dit synchronisé." "$(b2i "$(ij '.synchronized')")"
metric monero_busy_syncing gauge "1 si le nœud est en cours de synchronisation." "$(b2i "$(ij '.busy_syncing')")"
metric monero_outgoing_connections gauge "Connexions P2P sortantes." "$(num "$(ij '.outgoing_connections_count')")"
metric monero_incoming_connections gauge "Connexions P2P entrantes (0 en permanence : port P2P non joignable)." "$(num "$(ij '.incoming_connections_count')")"
metric monero_tx_pool_size gauge "Transactions en attente dans le pool." "$(num "$(ij '.tx_pool_size')")"
metric monero_database_size_bytes gauge "Taille de la base de la chaîne." "$(num "$(ij '.database_size')")"
metric monero_free_space_bytes gauge "Espace libre sur le disque de la chaîne." "$(num "$(ij '.free_space')")"
metric monero_offline gauge "1 si le démon est en mode hors ligne." "$(b2i "$(ij '.offline')")"

# Âge du dernier bloc : un bloc toutes les ~2 minutes, une demi-heure sans bloc sur un nœud
# synchronisé n'est pas du hasard. (GNU date : l'horodatage est déjà en secondes.)
TS=$(curl -sS -m 8 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_last_block_header"}' \
  "http://127.0.0.1:${RPC_PORT}/json_rpc" 2>/dev/null | jq -r '.result.block_header.timestamp // empty' 2>/dev/null)
if [[ "${TS}" =~ ^[0-9]+$ ]]; then
  metric monero_last_block_age_seconds gauge "Secondes depuis l'horodatage du dernier bloc connu." "$(( $(date +%s) - TS ))"
fi

# ── Version installée vs dernière version signée ───────────────────────────
INSTALLED=$(ij '.version' | sed -E 's/-.*$//')
if [[ "${INSTALLED}" =~ ^[0-9]+([.][0-9]+)+$ ]]; then
  metric monero_version_info gauge "Version de monerod." 1 "{version=\"${INSTALLED}\"}"
  F="${CACHE_DIR}/hashes.txt"
  # Une fois toutes les 6 h ; en cas d'échec l'ancienne copie reste valable 24 h.
  AGE=999999; [ -s "${F}" ] && AGE=$(( $(date +%s) - $(stat -c %Y "${F}" 2>/dev/null || echo 0) ))
  if [ -n "${RELEASE_URL}" ] && [ "${AGE}" -gt 21600 ]; then
    curl -sS -m 15 "${RELEASE_URL}" -o "${F}.new" 2>/dev/null && [ -s "${F}.new" ] && mv "${F}.new" "${F}"
  fi
  if [ -s "${F}" ] && [ "$(( $(date +%s) - $(stat -c %Y "${F}" 2>/dev/null || echo 0) ))" -lt 86400 ]; then
    LATEST=$(grep -oE 'monero-linux-x64-v[0-9.]+[.]tar[.]bz2' "${F}" | head -n1 | sed -E 's/^monero-linux-x64-v//; s/[.]tar[.]bz2$//')
    if [[ "${LATEST}" =~ ^[0-9]+([.][0-9]+)+$ ]]; then
      OUT=0; [ "${LATEST}" != "${INSTALLED}" ] && OUT=1
      metric monero_version_outdated gauge "1 si la version installée diffère de la dernière publiée (hashes.txt)." "${OUT}"
    fi
  fi
fi
