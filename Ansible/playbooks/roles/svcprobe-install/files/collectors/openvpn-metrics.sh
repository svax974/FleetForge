#!/usr/bin/env bash
# Collecteur OpenVPN pour svcprobe — déployé par `svcprobe-install`.
#
# Usage : openvpn-metrics.sh <fichier_status> <préfixe>
#
# Le fichier de statut d'OpenVPN est la seule source de vérité sur les clients
# connectés : l'unité systemd reste `active` avec zéro client, état qui n'a
# aucun symptôme et qui est pourtant la panne (certificats expirés, règle de
# pare-feu, routage cassé).
set -uo pipefail

STATUS_FILE="${1:?fichier de statut manquant}"
PREFIX="${2:?préfixe manquant}"

emit() {
  [ -n "$2" ] || return 0
  printf '# HELP %s %s\n# TYPE %s gauge\n%s %s\n' "$1" "$3" "$1" "$1" "$2"
}

if [ ! -r "${STATUS_FILE}" ]; then
  emit "${PREFIX}_status_file_readable" 0 "1 si le fichier de statut est lisible."
  exit 0
fi
emit "${PREFIX}_status_file_readable" 1 "1 si le fichier de statut est lisible."

# Format « CLIENT_LIST » (status-version 2/3) ou tableau classique : les deux
# cohabitent selon la configuration, on compte donc les deux formes.
CLIENTS="$(grep -c '^CLIENT_LIST' "${STATUS_FILE}" 2>/dev/null || echo 0)"
if [ "${CLIENTS}" -eq 0 ]; then
  CLIENTS="$(awk '/^ROUTING TABLE/{exit} /^Virtual Address|^Common Name/{next} /,/{c++} END{print c+0}' \
             "${STATUS_FILE}" 2>/dev/null || echo 0)"
fi
emit "${PREFIX}_connected_clients" "${CLIENTS}" "Clients VPN connectés."

# Un fichier de statut qui cesse d'être réécrit signale un OpenVPN figé, alors
# que l'unité reste `active`.
MTIME="$(stat -c %Y "${STATUS_FILE}" 2>/dev/null)"
[ -n "${MTIME}" ] && emit "${PREFIX}_status_age_seconds" "$(( $(date +%s) - MTIME ))" \
  "Ancienneté du fichier de statut."

BYTES_IN="$(awk -F, '/^CLIENT_LIST/ {s+=$6} END {print s+0}' "${STATUS_FILE}" 2>/dev/null)"
BYTES_OUT="$(awk -F, '/^CLIENT_LIST/ {s+=$7} END {print s+0}' "${STATUS_FILE}" 2>/dev/null)"
emit "${PREFIX}_bytes_received" "${BYTES_IN}" "Octets reçus, tous clients."
emit "${PREFIX}_bytes_sent" "${BYTES_OUT}" "Octets émis, tous clients."
