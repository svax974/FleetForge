#!/bin/bash
# Métriques mémoire/CPU du collator Astar pour svcprobe — déployé par Ansible,
# NE PAS ÉDITER SUR L'HÔTE.
#
# L'endpoint Prometheus natif du nœud (9615) ne publie AUCUNE série `process_*`
# (constaté le 21/10/2026 sur hub) : la consommation du processus n'est donc
# visible nulle part dans Prometheus. Or c'est précisément l'état dégradé que
# `service_up` et `substrate_block_height` manquent — un nœud peut finaliser
# normalement tout en dérivant lentement vers l'OOM :
#   • 15/08/2026 : RSS 14,8 Go sur 15,7 Go, OOM toutes les ~18 min ;
#   • 21/10/2026 : 6,7 Go de RSS + 11,7 Go en swap après 39 jours, sans qu'une
#     seule alerte ne parte. node_exporter ne voit que la machine entière, pas
#     la part du collator.
# `swap` est la série à regarder en premier : une RSS plafonnée par `MemoryHigh`
# reste basse pendant que le surplus part en swap.
#
# Lancé par svcprobe (root) : /proc/<pid>/status et le cgroup sont lisibles.
# Usage : astar-metrics.sh [unité systemd]

set -uo pipefail

UNIT="${1:-astar}"

PID=$(systemctl show "${UNIT}" -p MainPID --value 2>/dev/null)
# MainPID vaut 0 quand le service est arrêté ; ne rien émettre plutôt qu'un 0,
# qui se lirait comme « le nœud ne consomme rien ». svcprobe n'appelle ce
# script que si la sonde principale passe, ce garde-fou couvre la fenêtre de
# redémarrage entre les deux.
[[ "${PID}" =~ ^[0-9]+$ ]] && [ "${PID}" -gt 0 ] && [ -r "/proc/${PID}/status" ] || exit 0

# Une valeur vide ou non numérique ferait rejeter TOUTE la page de métriques de
# l'hôte par Prometheus : tout passe par ce filtre.
num() { [[ "${1:-}" =~ ^[0-9]+$ ]] && echo "$1" || echo 0; }

status() { awk -v k="$1:" '$1 == k { print $2 }' "/proc/${PID}/status"; }

# VmRSS/RssAnon/VmSwap sont en kio.
RSS=$(( $(num "$(status VmRSS)") * 1024 ))
ANON=$(( $(num "$(status RssAnon)") * 1024 ))
SWAP=$(( $(num "$(status VmSwap)") * 1024 ))
THREADS=$(num "$(status Threads)")

# utime + stime : champs 14 et 15 de /proc/<pid>/stat, comptés APRÈS la
# parenthèse fermante du nom (qui peut contenir des espaces).
TICKS=$(sed -E 's/^.*\) //' "/proc/${PID}/stat" | awk '{ print $12 + $13 }')
HZ=$(num "$(getconf CLK_TCK)")
[ "${HZ}" -gt 0 ] || HZ=100
CPU=$(awk -v t="$(num "${TICKS%.*}")" -v h="${HZ}" 'BEGIN { printf "%.2f", t / h }')

metric() { # nom type aide valeur
  echo "# HELP $1 $3"
  echo "# TYPE $1 $2"
  echo "$1 $4"
}

metric astar_process_resident_memory_bytes gauge "Mémoire résidente du collator (VmRSS)." "${RSS}"
metric astar_process_anon_memory_bytes gauge "Part anonyme de la RSS (tas, hors fichiers mappés)." "${ANON}"
metric astar_process_swap_bytes gauge "Mémoire du collator envoyée en swap (VmSwap)." "${SWAP}"
metric astar_process_threads gauge "Nombre de threads du collator." "${THREADS}"
metric astar_process_cpu_seconds_total counter "Temps CPU cumulé (utilisateur + système) du collator." "${CPU}"

# Comptabilité du cgroup : inclut le cache de fichiers, donc ce qui est
# comparé à `MemoryHigh`. Absente hors cgroup v2 : on n'émet alors rien.
CG="/sys/fs/cgroup/system.slice/${UNIT}.service"
if [ -r "${CG}/memory.current" ]; then
  metric astar_cgroup_memory_bytes gauge "Mémoire du cgroup du service (memory.current), cache compris." \
    "$(num "$(cat "${CG}/memory.current")")"
  HIGH=$(cat "${CG}/memory.high" 2>/dev/null)
  # « max » = aucune limite : omettre la série, un 0 signifierait « limite nulle ».
  if [[ "${HIGH}" =~ ^[0-9]+$ ]]; then
    metric astar_cgroup_memory_high_bytes gauge "Seuil MemoryHigh du service (au-delà, le noyau récupère puis swappe)." "${HIGH}"
  fi
fi
