#!/bin/bash
# Métriques FreeLLMAPI pour svcprobe — déployé par Ansible, NE PAS ÉDITER SUR
# L'HÔTE.
#
# La sonde `up` (/api/ping) dit seulement que le conteneur répond. Un proxy
# LLM sans aucune clé fournisseur importée répond tout aussi bien mais ne sert
# plus aucune requête réelle — c'est /v1/models qui le révèle : la liste des
# modèles exposés reflète directement les clés fournisseur configurées. Pas de
# mise en cache ici, contrairement au collecteur SearXNG : cet appel ne fait
# qu'énumérer la configuration locale, il ne part vers aucun service tiers.
#
# Usage : freellm-metrics.sh [base_url]

set -uo pipefail

BASE="${1:-http://127.0.0.1:3001}"

BODY=$(curl -sS -m 10 "${BASE}/v1/models" 2>/dev/null)
RC=$?

COUNT=0
if [ "${RC}" -eq 0 ] && printf '%s' "${BODY}" | jq -e . >/dev/null 2>&1; then
  # `// []` : une réponse JSON valide mais d'une autre forme (message d'erreur
  # applicatif) ferait échouer jq, et la variable vide produirait une ligne de
  # métrique tronquée — que Prometheus rejette en bloc, faisant disparaître
  # TOUTES les métriques de l'hôte, pas seulement celle-ci.
  COUNT=$(printf '%s' "${BODY}" | jq '(.data // []) | length')
  [ -n "${COUNT}" ] || COUNT=0
fi

echo "# HELP freellm_configured_models Nombre de modèles exposés par /v1/models (reflète les clés fournisseur importées)."
echo "# TYPE freellm_configured_models gauge"
echo "freellm_configured_models ${COUNT}"
