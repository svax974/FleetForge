#!/bin/bash
# Réglages ROOT posés autour du mineur — déployé par Ansible, NE PAS ÉDITER SUR L'HÔTE.
# Appelé par le service (`ExecStartPre=+` / `ExecStopPost=+`, donc en root même quand le mineur
# lui-même ne l'est pas), jamais à la main.
#
#   xmrig-tune.sh start <gouverneur 0|1> <pages de 1 Gio (0 = aucune)> <msr 0|1>
#   xmrig-tune.sh stop
#
# start : gouverneur CPU `performance` (l'ancien est mémorisé), réservation des pages de 1 Gio,
#         module noyau `msr`. stop : tout est rendu (gouverneur d'origine, RAM des pages de 1 Gio).
# Aucune erreur ne doit empêcher de miner : chaque échec est écrit au journal et le script
# sort toujours en 0 — le mineur démarre alors avec un peu moins d'optimisations, et les
# métriques de supervision (pages obtenues, MSR) le disent.
#
# XMRIG_SYS_ROOT / XMRIG_TUNE_STATE : racines de remplacement pour les tests.

set -u
ROOT="${XMRIG_SYS_ROOT:-}"
STATE="${XMRIG_TUNE_STATE:-/run/xmrig-tune}"
CPU="${ROOT}/sys/devices/system/cpu"
HP1G="${ROOT}/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"

log() { echo "xmrig-tune: $*"; }

case "${1:-}" in
  start)
    GOV="${2:-0}"; N1G="${3:-0}"; MSR="${4:-0}"
    mkdir -p "${STATE}" 2>/dev/null || { log "impossible de créer ${STATE}"; exit 0; }

    if [ "${GOV}" = 1 ]; then
      done_n=0
      for f in "${CPU}"/cpu[0-9]*/cpufreq/scaling_governor; do
        [ -w "${f}" ] || continue
        c=$(basename "$(dirname "$(dirname "${f}")")")
        # Mémorisé UNE fois : un redémarrage sans arrêt propre ne doit pas figer `performance`
        # comme « ancien » gouverneur.
        [ -e "${STATE}/gov.${c}" ] || cat "${f}" > "${STATE}/gov.${c}" 2>/dev/null
        echo performance > "${f}" 2>/dev/null && done_n=$((done_n + 1))
      done
      if [ "${done_n}" -gt 0 ]; then log "gouverneur performance sur ${done_n} cœurs"
      else log "gouverneur CPU non pilotable ici (pas de cpufreq) — ignoré"; fi
    fi

    if [ "${N1G}" -gt 0 ] 2>/dev/null; then
      if [ -w "${HP1G}" ]; then
        [ -e "${STATE}/hp1g" ] || cat "${HP1G}" > "${STATE}/hp1g" 2>/dev/null
        echo "${N1G}" > "${HP1G}" 2>/dev/null
        got=$(cat "${HP1G}" 2>/dev/null || echo 0)
        if [ "${got}" -ge "${N1G}" ] 2>/dev/null; then log "${got} pages de 1 Gio réservées"
        else log "ATTENTION : ${got}/${N1G} pages de 1 Gio obtenues (mémoire trop fragmentée : à réserver au démarrage du noyau, hugepagesz=1G hugepages=${N1G}) — XMRig se rabat sur les pages de 2 Mio"; fi
      else
        log "pages de 1 Gio non réservables ici — ignoré"
      fi
    fi

    if [ "${MSR}" = 1 ]; then
      modprobe msr 2>/dev/null || log "module msr indisponible : le gain MSR sera perdu"
    fi
    ;;

  stop)
    for f in "${STATE}"/gov.*; do
      [ -e "${f}" ] || continue
      c=${f##*/gov.}
      t="${CPU}/${c}/cpufreq/scaling_governor"
      [ -w "${t}" ] && cat "${f}" > "${t}" 2>/dev/null
    done
    [ -e "${STATE}/hp1g" ] && [ -w "${HP1G}" ] && cat "${STATE}/hp1g" > "${HP1G}" 2>/dev/null
    rm -f "${STATE}"/gov.* "${STATE}/hp1g" 2>/dev/null
    log "réglages rendus"
    ;;

  *)
    log "usage : xmrig-tune.sh start <gouverneur 0|1> <pages 1 Gio> <msr 0|1> | stop"
    ;;
esac
exit 0
