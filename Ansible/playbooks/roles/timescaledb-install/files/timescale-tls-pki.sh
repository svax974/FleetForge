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
#   server.crt  certificat du serveur, SAN = l'adresse que le client utilise (IP de l'inventaire) + noms DNS
# Avec --name <hôte>, le couple serveur vit dans <dir>/servers/<hôte>/ (la MÊME AC signe tous les serveurs) :
# un second serveur TimescaleDB n'écrase pas le certificat du premier.
# Rien de secret n'est affiché : seulement les sujets, SAN, dates d'expiration et empreintes.
#
# Le client (node-postgres, rejectUnauthorized + ca) vérifie la chaîne ET le nom : METRICS_DB_HOST étant une IP,
# le SAN doit contenir cette IP (équivalent de sslmode=verify-full).
#
# Usage :
#   timescale-tls-pki.sh --ip 194.163.180.236 [--dns timescale.papanglabs.com] [--dir DIR]
#       Crée l'AC si absente, puis le certificat serveur s'il est absent.
#   timescale-tls-pki.sh --name timescale1 --ip <IP de timescale1> --dns timescale.<domaine> --dns timescale1.<domaine>
#       Certificat d'un SECOND serveur, signé par la même AC. --dns est répétable : le premier nom devient le CN,
#       tous entrent dans le SAN. Y mettre le nom de SERVICE que visent les clients (timescale.<domaine>, un CNAME
#       qui peut changer de cible) ET le nom de la machine.
#   timescale-tls-pki.sh --renew-server --ip … [--dns …]
#       Nouveau couple serveur signé par la MÊME AC (renouvellement, changement d'IP) : l'ancien est archivé
#       en .bak. Aucun changement côté client.
#   timescale-tls-pki.sh --new-ca --ip … [--dns …]
#       Nouvelle AC (compromission de ca.key) : impose de redéployer ca.crt chez le client AVANT le serveur.

set -euo pipefail
umask 077

DIR="${HOME}/.secrets/papang/timescale-ca"
IP=""
DNS=()
NAME=""
RENEW_SERVER=0
NEW_CA=0
CA_DAYS=3650
SERVER_DAYS=730

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --dns) DNS+=("$2"); shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --renew-server) RENEW_SERVER=1; shift ;;
    --new-ca) NEW_CA=1; RENEW_SERVER=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
done

[[ "${IP}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "--ip <IPv4 utilisée par le client> est obligatoire." >&2; exit 2; }

mkdir -p "${DIR}"
chmod 700 "${DIR}"
# Couple serveur : à la racine (premier serveur, historique) ou dans servers/<nom>/.
SDIR="${DIR}"
if [[ -n "${NAME}" ]]; then
  [[ "${NAME}" =~ ^[a-zA-Z0-9._-]+$ ]] || { echo "--name : lettres, chiffres, . _ - uniquement." >&2; exit 2; }
  SDIR="${DIR}/servers/${NAME}"
  mkdir -p "${SDIR}"
  chmod 700 "${DIR}/servers" "${SDIR}"
fi
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

archive() {
  local d="$1"; shift
  for f in "$@"; do [[ -f "${d}/${f}" ]] && mv "${d}/${f}" "${d}/${f}.${stamp}.bak"; done
  return 0
}

describe() {
  openssl x509 -in "$1" -noout -subject -enddate -fingerprint -sha256 -ext subjectAltName 2>/dev/null | sed 's/^/  /'
}

if [[ "${NEW_CA}" -eq 1 ]]; then archive "${DIR}" ca.key ca.crt; fi
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

if [[ "${RENEW_SERVER}" -eq 1 ]]; then archive "${SDIR}" server.key server.crt; fi
if [[ ! -f "${SDIR}/server.crt" ]]; then
  san="IP:${IP},IP:127.0.0.1,DNS:localhost"
  for d in "${DNS[@]:-}"; do [[ -n "${d}" ]] && san="DNS:${d},${san}"; done
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${SDIR}/server.key" 2>/dev/null
  chmod 600 "${SDIR}/server.key"
  ext="$(mktemp "${SDIR}/ext.XXXXXX")"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "${san}" > "${ext}"
  openssl req -new -key "${SDIR}/server.key" -subj "/O=PapangLabs/CN=${DNS[0]:-${IP}}" 2>/dev/null \
    | openssl x509 -req -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -CAcreateserial -sha256 \
        -days "${SERVER_DAYS}" -extfile "${ext}" -out "${SDIR}/server.crt" 2>/dev/null
  rm -f "${ext}"
  chmod 644 "${SDIR}/server.crt"
  echo "Certificat serveur créé :"; describe "${SDIR}/server.crt"
else
  echo "Certificat serveur existant conservé :"; describe "${SDIR}/server.crt"
fi

openssl verify -CAfile "${DIR}/ca.crt" "${SDIR}/server.crt" >/dev/null && echo "Chaîne vérifiée (server.crt signé par ca.crt)."
openssl x509 -in "${SDIR}/server.crt" -noout -checkip "${IP}" | sed 's/^/  /'
