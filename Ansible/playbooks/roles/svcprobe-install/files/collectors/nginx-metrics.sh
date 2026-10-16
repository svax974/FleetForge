#!/usr/bin/env bash
# Collecteur nginx pour svcprobe — déployé par `svcprobe-install`.
#
# Usage : nginx-metrics.sh <url_stub_status> <préfixe> [répertoire_certificats]
#
# Deux sources, deux pannes différentes :
#   • stub_status donne la charge (connexions, requêtes) ;
#   • l'expiration des certificats est LA panne annoncée des semaines à
#     l'avance et découverte le jour J. Un renouvellement certbot qui cesse de
#     fonctionner ne produit aucun symptôme jusqu'à l'expiration.
set -uo pipefail

STATUS_URL="${1:?url manquante}"
PREFIX="${2:?préfixe manquant}"
CERT_DIR="${3:-/etc/letsencrypt/live}"

# La valeur est VÉRIFIÉE numérique avant d'être écrite. Prometheus rejette le
# scrape ENTIER sur une seule ligne malformée : une valeur inattendue ici ne
# dégrade pas les métriques nginx, elle fait disparaître TOUTES celles de
# l'hôte — `service_up` des autres services sondés compris.
emit() {
  [ -n "$2" ] || return 0
  case "$2" in
    *[!0-9.-]*) return 0 ;;
  esac
  printf '# HELP %s %s\n# TYPE %s gauge\n%s %s\n' "$1" "$3" "$1" "$1" "$2"
}

# `curl -sf` ne suffit pas à qualifier la réponse : quand stub_status n'est pas
# activé, l'URL tombe sur le vhost par défaut, qui répond 200 avec du HTML. Le
# corps est non vide, et l'awk en tirait « <body> » comme valeur de compteur.
# Constaté le 13/08/2026 sur proxy1 : ligne `nginx_connections_accepted_total
# <body>`, et plus AUCUNE métrique de l'hôte côté Prometheus — les certificats
# compris, alors que le collecteur les produisait correctement plus bas.
BODY="$(curl -sf -m 5 "${STATUS_URL}" 2>/dev/null || true)"
case "${BODY}" in
  *"Active connections"*) ;;
  *) BODY="" ;;
esac
if [ -n "${BODY}" ]; then
  emit "${PREFIX}_connections_active" \
       "$(echo "${BODY}" | awk '/^Active connections/ {print $3}')" \
       "Connexions actives."
  # `accepts handled requests` : si handled < accepts, nginx a REFUSÉ des
  # connexions — plafond worker_connections atteint. Invisible autrement.
  read -r ACCEPTS HANDLED REQUESTS <<<"$(echo "${BODY}" | awk 'NR==3 {print $1, $2, $3}')"
  emit "${PREFIX}_connections_accepted_total" "${ACCEPTS:-}" "Connexions acceptées."
  emit "${PREFIX}_connections_handled_total"  "${HANDLED:-}" "Connexions traitées."
  emit "${PREFIX}_requests_total"             "${REQUESTS:-}" "Requêtes servies."
  emit "${PREFIX}_connections_waiting" \
       "$(echo "${BODY}" | awk '/^Reading/ {print $6}')" \
       "Connexions en attente (keep-alive)."
else
  emit "${PREFIX}_stub_status_available" 0 "1 si stub_status répond."
fi

# ── Certificats ────────────────────────────────────────────────────────────
if [ -d "${CERT_DIR}" ]; then
  NOW="$(date +%s)"
  printf '# HELP %s_certificate_expiry_seconds Temps restant avant expiration du certificat.\n' "${PREFIX}"
  printf '# TYPE %s_certificate_expiry_seconds gauge\n' "${PREFIX}"
  for cert in "${CERT_DIR}"/*/fullchain.pem; do
    [ -e "${cert}" ] || continue
    domain="$(basename "$(dirname "${cert}")")"
    end="$(openssl x509 -enddate -noout -in "${cert}" 2>/dev/null | cut -d= -f2)"
    [ -n "${end}" ] || continue
    end_ts="$(date -d "${end}" +%s 2>/dev/null)" || continue
    printf '%s_certificate_expiry_seconds{domain="%s"} %s\n' \
           "${PREFIX}" "${domain}" "$(( end_ts - NOW ))"
  done
fi
