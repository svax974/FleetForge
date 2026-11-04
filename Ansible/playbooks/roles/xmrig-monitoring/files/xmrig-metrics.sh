#!/bin/bash
# Métriques d'un mineur XMRig pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR L'HÔTE.
#
# Source : API HTTP locale de XMRig (`GET /2/summary`, jeton Bearer lu dans un fichier
# root 0600 — lancé par svcprobe, donc en root). Ces séries couvrent ce que `service_up` ne
# voit pas : un mineur qui tourne mais ne mine plus (hashrate nul), a perdu son pool, ou voit
# ses partages rejetés — il consomme alors la machine sans rien gagner.
#
# Rien n'est émis si l'API ne répond pas (`service_up` porte l'information). Chaque valeur passe
# par `num` : une valeur vide ferait rejeter TOUTE la page de métriques de l'hôte.
#
# Usage : xmrig-metrics.sh <port API> <fichier du jeton> <url de la dernière version>

set -uo pipefail

PORT="${1:-18088}"
TOKEN_FILE="${2:-/etc/xmrig/api-token}"
RELEASE_URL="${3:-}"
CACHE_DIR="${XMRIG_CACHE_DIR:-/run/xmrig-metrics}"
mkdir -p "${CACHE_DIR}" 2>/dev/null

TOKEN=$(tr -d '[:space:]' < "${TOKEN_FILE}" 2>/dev/null) || exit 0
[ -n "${TOKEN}" ] || exit 0
SUM=$(curl -sS -m 8 -H "Authorization: Bearer ${TOKEN}" "http://127.0.0.1:${PORT}/2/summary" 2>/dev/null) || exit 0
printf '%s' "${SUM}" | jq -e 'type == "object" and has("uptime")' >/dev/null 2>&1 || exit 0

num() { [[ "${1:-}" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && echo "$1" || echo 0; }
sj() { printf '%s' "${SUM}" | jq -r "$1" 2>/dev/null; }

metric() { # nom type aide valeur [labels]
  echo "# HELP $1 $3"
  echo "# TYPE $1 $2"
  echo "$1${5:-} $4"
}
sample() { echo "$1${3:-} $2"; }

metric xmrig_uptime_seconds gauge "Secondes depuis le démarrage du mineur." "$(num "$(sj '.uptime')")"

# Hashrate : [10 s, 60 s, 15 min] ; `null` tant que la fenêtre n'est pas remplie — on ne
# publie alors RIEN pour cette fenêtre (un 0 se lirait « le mineur ne mine pas »).
echo "# HELP xmrig_hashrate_hps Hashrate du mineur (hashes par seconde) par fenêtre."
echo "# TYPE xmrig_hashrate_hps gauge"
i=0
for w in 10s 60s 15m; do
  v=$(sj ".hashrate.total[${i}] // empty")
  [ -n "${v}" ] && sample xmrig_hashrate_hps "$(num "${v}")" "{window=\"${w}\"}"
  i=$((i + 1))
done
H=$(sj '.hashrate.highest // empty')
[ -n "${H}" ] && metric xmrig_hashrate_highest_hps gauge "Hashrate le plus haut observé depuis le démarrage." "$(num "${H}")"

# Connexion au pool (ou au nœud en solo) et partages. `uptime` vaut 0 sans connexion.
CUP=$(num "$(sj '.connection.uptime')")
CONN=0; [ "${CUP%.*}" -gt 0 ] && CONN=1
metric xmrig_pool_connected gauge "1 si le mineur est connecté à son pool ou à son nœud." "${CONN}"
metric xmrig_pool_uptime_seconds gauge "Durée de la connexion actuelle." "${CUP}"
metric xmrig_pool_failures gauge "Échecs de connexion consécutifs." "$(num "$(sj '.connection.failures')")"
metric xmrig_pool_ping_ms gauge "Latence vers le pool." "$(num "$(sj '.connection.ping')")"
metric xmrig_shares_accepted_total counter "Partages acceptés depuis le démarrage." "$(num "$(sj '.connection.accepted')")"
metric xmrig_shares_rejected_total counter "Partages rejetés depuis le démarrage." "$(num "$(sj '.connection.rejected')")"

# ── Version installée vs dernière version publiée ──────────────────────────
INSTALLED=$(sj '.version')
if [[ "${INSTALLED}" =~ ^[0-9]+([.][0-9]+)+$ ]]; then
  metric xmrig_version_info gauge "Version de XMRig." 1 "{version=\"${INSTALLED}\"}"
  F="${CACHE_DIR}/latest.json"
  # Une fois toutes les 6 h (l'API GitHub non authentifiée est limitée à 60 appels/h) ;
  # l'ancienne copie reste valable 24 h en cas d'échec.
  AGE=999999; [ -s "${F}" ] && AGE=$(( $(date +%s) - $(stat -c %Y "${F}" 2>/dev/null || echo 0) ))
  if [ -n "${RELEASE_URL}" ] && [ "${AGE}" -gt 21600 ]; then
    curl -sS -m 15 "${RELEASE_URL}" -o "${F}.new" 2>/dev/null && jq -e '.tag_name' "${F}.new" >/dev/null 2>&1 && mv "${F}.new" "${F}"
  fi
  if [ -s "${F}" ] && [ "$(( $(date +%s) - $(stat -c %Y "${F}" 2>/dev/null || echo 0) ))" -lt 86400 ]; then
    LATEST=$(jq -r '.tag_name // empty' "${F}" 2>/dev/null | sed 's/^v//')
    if [[ "${LATEST}" =~ ^[0-9]+([.][0-9]+)+$ ]]; then
      OUT=0; [ "${LATEST}" != "${INSTALLED}" ] && OUT=1
      metric xmrig_version_outdated gauge "1 si la version installée diffère de la dernière publiée." "${OUT}"
    fi
  fi
fi
