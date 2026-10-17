#!/bin/bash
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
# Sonde principale du serveur d'IA pour svcprobe — déployé par Ansible
# (aiserver-monitoring), NE PAS ÉDITER SUR L'HÔTE.
#
# Usage : aiserver-health.sh <timeout_s> <conteneur>=<url> [<conteneur>=<url>…]
#
# Rend 0 si CHAQUE conteneur tourne ET répond 200 sur son URL de santé, 1
# sinon. Un conteneur en marche ne suffit pas : llama.cpp tourne bien avant
# d'avoir chargé son modèle (503 sur /health), et ComfyUI peut rester bloqué au
# chargement de ses nœuds. Le service n'est « up » que s'il SERT.
# Le premier échec est écrit sur stderr (journal de svcprobe).
set -uo pipefail

TIMEOUT="${1:?timeout}"
shift

for pair in "$@"; do
  container="${pair%%=*}"
  url="${pair#*=}"
  running=$(docker inspect -f '{{.State.Running}}' "${container}" 2>/dev/null || true)
  if [ "${running}" != "true" ]; then
    echo "aiserver: ${container} not running" >&2
    exit 1
  fi
  if ! curl -fsS -o /dev/null --max-time "${TIMEOUT}" "${url}"; then
    echo "aiserver: ${container} unhealthy (${url})" >&2
    exit 1
  fi
done
exit 0
