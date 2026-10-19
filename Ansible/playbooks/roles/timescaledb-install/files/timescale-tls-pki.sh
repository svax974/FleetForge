#!/usr/bin/env bash
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
# timescale-tls-pki.sh — AC privée + certificat serveur de la base d'indicateurs TimescaleDB
# (lien PapangMetrics → TimescaleDB, deux VPS joints par Internet).
#
# Tout est écrit sur le POSTE DE CONTRÔLE, hors dépôt, dans <dir> (défaut ~/.secrets/papang/timescale-ca, 0700) :
#   ca.key      clé de l'AC (0600) — ne quitte JAMAIS ce poste
#   ca.crt      certificat de l'AC — déployé chez le CLIENT (PapangMetrics, METRICS_DB_SSL_CA_PATH)
#   server.key  clé du serveur (0600) — déployée sur l'hôte TimescaleDB seulement
#   server.crt  certificat du serveur, SAN = l'adresse que le client utilise (IP de l'inventaire) + nom DNS
# Rien de secret n'est affiché : seulement les sujets, SAN, dates d'expiration et empreintes.
#
# Le client (node-postgres, rejectUnauthorized + ca) vérifie la chaîne ET le nom : METRICS_DB_HOST étant une IP,
# le SAN doit contenir cette IP (équivalent de sslmode=verify-full).
#
# Usage :
#   timescale-tls-pki.sh --ip 194.163.180.236 [--dns timescale.papanglabs.com] [--dir DIR]
#       Crée l'AC si absente, puis le certificat serveur s'il est absent.
#   timescale-tls-pki.sh --renew-server --ip … [--dns …]
#       Nouveau couple serveur signé par la MÊME AC (renouvellement, changement d'IP) : l'ancien est archivé
#       en .bak. Aucun changement côté client.
#   timescale-tls-pki.sh --new-ca --ip … [--dns …]
#       Nouvelle AC (compromission de ca.key) : impose de redéployer ca.crt chez le client AVANT le serveur.

set -euo pipefail
umask 077

DIR="${HOME}/.secrets/papang/timescale-ca"
IP=""
DNS=""
RENEW_SERVER=0
NEW_CA=0
CA_DAYS=3650
SERVER_DAYS=730

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --dns) DNS="$2"; shift 2 ;;
    --renew-server) RENEW_SERVER=1; shift ;;
    --new-ca) NEW_CA=1; RENEW_SERVER=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
done

[[ "${IP}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "--ip <IPv4 utilisée par le client> est obligatoire." >&2; exit 2; }

mkdir -p "${DIR}"
chmod 700 "${DIR}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

archive() {
  for f in "$@"; do [[ -f "${DIR}/${f}" ]] && mv "${DIR}/${f}" "${DIR}/${f}.${stamp}.bak"; done
  return 0
}

describe() {
  openssl x509 -in "$1" -noout -subject -enddate -fingerprint -sha256 -ext subjectAltName 2>/dev/null | sed 's/^/  /'
}

if [[ "${NEW_CA}" -eq 1 ]]; then archive ca.key ca.crt; fi
if [[ ! -f "${DIR}/ca.key" ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${DIR}/ca.key" 2>/dev/null
  chmod 600 "${DIR}/ca.key"
  openssl req -x509 -new -key "${DIR}/ca.key" -sha256 -days "${CA_DAYS}" \
    -subj "/O=PapangLabs/CN=PapangLabs TimescaleDB CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "${DIR}/ca.crt" 2>/dev/null
  chmod 644 "${DIR}/ca.crt"
  echo "AC créée :"; describe "${DIR}/ca.crt"
else
  echo "AC existante conservée :"; describe "${DIR}/ca.crt"
fi

if [[ "${RENEW_SERVER}" -eq 1 ]]; then archive server.key server.crt; fi
if [[ ! -f "${DIR}/server.crt" ]]; then
  san="IP:${IP},IP:127.0.0.1,DNS:localhost"
  [[ -n "${DNS}" ]] && san="DNS:${DNS},${san}"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${DIR}/server.key" 2>/dev/null
  chmod 600 "${DIR}/server.key"
  ext="$(mktemp "${DIR}/ext.XXXXXX")"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "${san}" > "${ext}"
  openssl req -new -key "${DIR}/server.key" -subj "/O=PapangLabs/CN=${DNS:-${IP}}" 2>/dev/null \
    | openssl x509 -req -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -CAcreateserial -sha256 \
        -days "${SERVER_DAYS}" -extfile "${ext}" -out "${DIR}/server.crt" 2>/dev/null
  rm -f "${ext}"
  chmod 644 "${DIR}/server.crt"
  echo "Certificat serveur créé :"; describe "${DIR}/server.crt"
else
  echo "Certificat serveur existant conservé :"; describe "${DIR}/server.crt"
fi

openssl verify -CAfile "${DIR}/ca.crt" "${DIR}/server.crt" >/dev/null && echo "Chaîne vérifiée (server.crt signé par ca.crt)."
openssl x509 -in "${DIR}/server.crt" -noout -checkip "${IP}" | sed 's/^/  /'
