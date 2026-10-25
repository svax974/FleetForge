#!/usr/bin/env bash
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
# probe_fleet.sh <parc> [--ansible-dir Ansible] — relève l'état OBSERVÉ de chaque machine du parc
# (ports en écoute, conteneurs, services applicatifs, crons) pour le comparer au déclaré
# (infra_facts.py). Lecture seule. Une machine injoignable est SIGNALÉE, jamais contournée :
# pas de StrictHostKeyChecking=no — une clé d'hôte inconnue de ce poste est un fait à rapporter.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
PARC="${1:?usage: probe_fleet.sh <parc> [--ansible-dir Ansible]}"; shift || true
ANSIBLE_DIR="Ansible"
[ "${1:-}" = "--ansible-dir" ] && ANSIBLE_DIR="$2"

python3 "$DIR/infra_facts.py" "$PARC" --format json --ansible-dir "$ANSIBLE_DIR" \
| python3 -c '
import json, sys
f = json.load(sys.stdin)
for ip, names in f["machines"].items():
    ports = {f["hosts"][n]["ssh_port"] for n in names if f["hosts"][n]["ssh_port"]}
    print(ip, (sorted(ports) or [""])[0], ",".join(names))
' | while read -r ip port names; do
  echo "######## ${ip} (${names})"
  case "$ip" in *[!0-9.]*) echo "ADRESSE_NON_RENSEIGNEE"; continue ;; esac
  ssh -p "${port:-16138}" -o BatchMode=yes -o ConnectTimeout=8 "srvc@${ip}" 'bash -s' < "$DIR/probe_machine.sh" 2>&1 | cut -c1-420 || true
done
