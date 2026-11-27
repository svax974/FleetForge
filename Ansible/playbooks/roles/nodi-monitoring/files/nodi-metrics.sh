#!/bin/bash
# Métriques NOD-I Revival pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR
# L'HÔTE.
#
# Lit /api/status du cockpit (agrégat bitcoind + mineur + machine). Une réponse
# illisible publie nodi_bitcoin_up 0 et RIEN d'autre : jamais une valeur inventée,
# et jamais une ligne tronquée (Prometheus rejetterait l'exposition entière, donc les
# métriques de tous les services de l'hôte).
#
# Usage : nodi-metrics.sh [base_url] [datadir]

set -uo pipefail

BASE="${1:-http://127.0.0.1:4740}"
DATADIR="${2:-/mnt/bitcoin}"

BODY=$(curl -sS -m 10 "${BASE}/api/status" 2>/dev/null) || BODY=""

emit() { # nom aide type valeur
  echo "# HELP $1 $2"
  echo "# TYPE $1 $3"
  echo "$1 $4"
}

# `// 0` : un champ absent ou null (température inconnue) ne doit pas produire une
# ligne vide.
val() { printf '%s' "${BODY}" | jq -r "$1 // 0" 2>/dev/null; }
num() { local v; v=$(val "$1"); [[ "${v}" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && echo "${v}" || echo 0; }

if ! printf '%s' "${BODY}" | jq -e '.bitcoin.status' >/dev/null 2>&1; then
  emit nodi_bitcoin_up "1 si bitcoind répond au cockpit (RPC), 0 sinon ou si le cockpit ne répond pas." gauge 0
  exit 0
fi

STATUS=$(printf '%s' "${BODY}" | jq -r '.bitcoin.status')
UP=0; [ "${STATUS}" != "offline" ] && UP=1

emit nodi_bitcoin_up "1 si bitcoind répond au cockpit (RPC), 0 sinon." gauge "${UP}"
emit nodi_bitcoin_syncing "1 tant que le nœud rattrape la chaîne (synchronisation initiale ou retard)." gauge "$([ "${STATUS}" = syncing ] && echo 1 || echo 0)"
emit nodi_bitcoin_blocks "Hauteur du dernier bloc validé." gauge "$(num '.bitcoin.blocks')"
emit nodi_bitcoin_headers "Hauteur des en-têtes connus (le retard sur les blocs révèle un nœud qui décroche)." gauge "$(num '.bitcoin.headers')"
# Le cockpit donne un POURCENTAGE ; Prometheus préfère un ratio.
emit nodi_bitcoin_verification_progress_ratio "Avancement de la vérification de la chaîne (0 à 1)." gauge "$(printf '%s' "${BODY}" | jq -r '((.bitcoin.progress // 0) / 100)')"
emit nodi_bitcoin_peers "Nombre de pairs connectés." gauge "$(num '.bitcoin.peers')"
emit nodi_bitcoin_pruned "1 si le nœud est élagué (prune), 0 si archive." gauge "$(printf '%s' "${BODY}" | jq -r 'if .bitcoin.pruned then 1 else 0 end')"
emit nodi_bitcoin_size_on_disk_bytes "Taille de la chaîne sur disque." gauge "$(num '.bitcoin.sizeOnDisk')"
# Mesuré ICI par df sur le datadir réel, PAS lu dans /api/status : `device.dataFreeBytes` est l'espace
# du volume du magasin DANS le conteneur de l'API, donc de l'eMMC (4,7 Go le 24/11/2026), pas du SSD.
FREE=$(df -B1 --output=avail "${DATADIR}" 2>/dev/null | tail -n 1 | tr -d ' ')
[[ "${FREE}" =~ ^[0-9]+$ ]] || FREE=0
emit nodi_data_free_bytes "Espace libre du SSD qui porte la chaîne (df sur le datadir). 0 si illisible." gauge "${FREE}"
emit nodi_device_temperature_celsius "Température du SoC (0 si inconnue)." gauge "$(num '.device.temperatureC')"
emit nodi_miner_enabled "1 si le mineur loterie est demandé." gauge "$(printf '%s' "${BODY}" | jq -r 'if .miner.enabled then 1 else 0 end')"
emit nodi_miner_running "1 si le mineur tourne." gauge "$(printf '%s' "${BODY}" | jq -r 'if .miner.status == "running" then 1 else 0 end')"
emit nodi_miner_thermal_stop "1 si le mineur est arrêté par la limite thermique." gauge "$(printf '%s' "${BODY}" | jq -r 'if .miner.status == "thermal-stop" then 1 else 0 end')"
