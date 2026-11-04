#!/bin/bash
# Métriques d'un nœud Storj pour svcprobe — déployé par Ansible, NE PAS ÉDITER
# SUR L'HÔTE.
#
# Source : API JSON du tableau de bord local (127.0.0.1:14002, jamais exposé).
#   /api/sno/              espace disque, bande passante, dernier ping, version, QUIC
#   /api/sno/satellite/ID  scores d'audit, de suspension et de disponibilité
#
# Ces séries existent pour l'état que `service_up` manque : un nœud peut tourner
# et répondre en local tout en étant injoignable des satellites, en train de
# perdre ses audits ou déjà suspendu. La disqualification est IRRÉVERSIBLE.
#
# Rien n'est émis si le tableau de bord ne répond pas : `service_up` porte alors
# l'information, et une série à 0 se lirait « disque vide, aucun audit raté ».
# Chaque valeur passe par `num` : une valeur vide ou non numérique ferait rejeter
# TOUTE la page de métriques de l'hôte par Prometheus, pas seulement celle-ci.
#
# Usage : storj-metrics.sh [url du tableau de bord]

set -uo pipefail

BASE="${1:-http://127.0.0.1:14002}"

DASH=$(curl -sS -m 8 "${BASE}/api/sno/" 2>/dev/null) || exit 0
printf '%s' "${DASH}" | jq -e 'type == "object" and has("nodeID")' >/dev/null 2>&1 || exit 0

num() { [[ "${1:-}" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && echo "$1" || echo 0; }
dj() { printf '%s' "${DASH}" | jq -r "$1" 2>/dev/null; }

# Âge d'un horodatage RFC 3339 (fractions et décalages compris : GNU date).
# Date zéro de Go (« 0001-01-01… ») = jamais pingué : l'âge devient énorme,
# ce qui est exactement ce que l'alerte doit voir.
age() {
  local ts="${1:-}" epoch
  [ -n "${ts}" ] && [ "${ts}" != "null" ] || { echo 0; return; }
  epoch=$(date -d "${ts}" +%s 2>/dev/null) || { echo 0; return; }
  echo $(( $(date +%s) - epoch ))
}

metric() { # nom type aide valeur [labels]
  echo "# HELP $1 $3"
  echo "# TYPE $1 $2"
  echo "$1${5:-} $4"
}

metric storj_disk_used_bytes gauge "Espace occupé par les pièces du nœud." "$(num "$(dj '.diskSpace.used')")"
metric storj_disk_allocated_bytes gauge "Espace alloué au nœud (STORAGE)." "$(num "$(dj '.diskSpace.allocated')")"
metric storj_disk_available_bytes gauge "Espace encore disponible dans l'allocation." "$(num "$(dj '.diskSpace.available')")"
metric storj_disk_trash_bytes gauge "Espace occupé par la corbeille." "$(num "$(dj '.diskSpace.trash')")"
metric storj_disk_overused_bytes gauge "Dépassement de l'allocation (0 en régime normal)." "$(num "$(dj '.diskSpace.overused')")"
metric storj_bandwidth_used_bytes gauge "Bande passante utilisée ce mois-ci." "$(num "$(dj '.bandwidth.used')")"
metric storj_last_pinged_age_seconds gauge "Secondes depuis le dernier ping d'un satellite." "$(age "$(dj '.lastPinged')")"
metric storj_uptime_seconds gauge "Secondes depuis le démarrage du nœud." "$(age "$(dj '.startedAt')")"
metric storj_up_to_date gauge "1 si le nœud est à une version autorisée." "$([ "$(dj '.upToDate')" = "true" ] && echo 1 || echo 0)"
metric storj_quic_ok gauge "1 si le satellite joint le nœud en QUIC (UDP)." "$([ "$(dj '.quicStatus')" = "OK" ] && echo 1 || echo 0)"
metric storj_satellites gauge "Nombre de satellites de confiance." "$(num "$(dj '.satellites | length')")"

# Une série par satellite. Les en-têtes HELP/TYPE ne sont émis qu'une fois.
help_of() {
  case "$1" in
    storj_satellite_audit_score) echo "Score d'audit (disqualification sous 0,96)." ;;
    storj_satellite_suspension_score) echo "Score de suspension (suspension sous 0,6)." ;;
    storj_satellite_online_score) echo "Score de disponibilité (suspension sous 0,6)." ;;
    storj_satellite_disqualified) echo "1 si le nœud est disqualifié par ce satellite." ;;
    storj_satellite_suspended) echo "1 si le nœud est suspendu par ce satellite." ;;
    storj_satellite_vetted) echo "1 si le nœud a fini sa période de vérification." ;;
  esac
}
LINES=""
while IFS=$'\t' read -r ID URL DQ SUSP VETTED; do
  [ -n "${ID}" ] || continue
  # Étiquette : adresse du satellite, jamais une valeur libre — seule la forme
  # attendue passe, le reste ferait un fichier d'exposition invalide.
  [[ "${URL}" =~ ^[A-Za-z0-9._:@-]+$ ]] || URL="${ID:0:12}"
  L="{satellite=\"${URL}\"}"
  LINES+="storj_satellite_disqualified${L} $([ "${DQ}" != "null" ] && echo 1 || echo 0)"$'\n'
  LINES+="storj_satellite_suspended${L} $([ "${SUSP}" != "null" ] && echo 1 || echo 0)"$'\n'
  LINES+="storj_satellite_vetted${L} $([ "${VETTED}" != "null" ] && echo 1 || echo 0)"$'\n'
  SAT=$(curl -sS -m 8 "${BASE}/api/sno/satellite/${ID}" 2>/dev/null) || continue
  A=$(printf '%s' "${SAT}" | jq -r '.audits.auditScore // empty' 2>/dev/null)
  S=$(printf '%s' "${SAT}" | jq -r '.audits.suspensionScore // empty' 2>/dev/null)
  O=$(printf '%s' "${SAT}" | jq -r '.audits.onlineScore // empty' 2>/dev/null)
  # Score absent (satellite sans audit encore) : ne rien émettre plutôt qu'un 0,
  # qui déclencherait StorjAuditScoreLow sur un nœud neuf.
  [ -n "${A}" ] && LINES+="storj_satellite_audit_score${L} $(num "${A}")"$'\n'
  [ -n "${S}" ] && LINES+="storj_satellite_suspension_score${L} $(num "${S}")"$'\n'
  [ -n "${O}" ] && LINES+="storj_satellite_online_score${L} $(num "${O}")"$'\n'
done < <(printf '%s' "${DASH}" | jq -r '.satellites[]? | [.id, (.url // ""), (.disqualified // "null" | tostring), (.suspended // "null" | tostring), (.vettedAt // "null" | tostring)] | @tsv' 2>/dev/null)

for name in storj_satellite_audit_score storj_satellite_suspension_score storj_satellite_online_score \
            storj_satellite_disqualified storj_satellite_suspended storj_satellite_vetted; do
  grep -q "^${name}{" <<<"${LINES}" || continue
  echo "# HELP ${name} $(help_of "${name}")"
  echo "# TYPE ${name} gauge"
  grep "^${name}{" <<<"${LINES}"
done
