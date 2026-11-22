#!/usr/bin/env bash
# Collecteur TradeKong pour svcprobe — déployé par `tradekong-monitoring`.
#
# Usage : tradekong-metrics.sh <conteneur> <utilisateur> <base> <préfixe>
#
# 1. les métriques PostgreSQL génériques (`postgres-metrics.sh`, collecteur
#    partagé : mêmes arguments, mêmes séries qu'avant) ;
# 2. `tradekong_mcp_legacy_mark_done` : 1 quand l'ENREGISTREMENT « une seule
#    fois » du marquage des clés trade larges d'avant le déploiement existe.
#
# Pourquoi un état en base plutôt qu'une métrique de l'application : le back
# n'expose pas /metrics, et l'échec visé (le marquage échoue au démarrage de
# TOUTES les répliques, les clés larges d'avant restent refusées) n'écrit rien :
# l'enregistrement reste ABSENT tant qu'un démarrage ne réussit pas. Il vit dans
# la table `mcp_boot_record` (nom = clé de l'enregistrement) ; la première version
# du marquage l'écrivait dans `config` : tant que le back n'a pas redémarré sur la
# nouvelle version, c'est cette ligne qui compte (sans quoi une base déjà
# marquée sonnerait entre le dépôt de ce collecteur et le déploiement du back).
# CONTRAT avec TradeKong : `back/src/modules/mcp/access/legacyTradeKeyMark.ts`
# (`LEGACY_MARK_GUARD_ROW`, `BOOT_RECORD_TABLE`).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER="${1:?conteneur manquant}"
USER="${2:?utilisateur manquant}"
DB="${3:?base manquante}"

RECORD="mcp_legacyTradeIpAllowMarked"

# Le collecteur partagé d'abord : sa panne ne doit pas masquer la série
# ci-dessous (ni l'inverse) — chacun n'émet rien plutôt qu'une valeur fausse.
"${HERE}/postgres-metrics.sh" "$@" || true

q() { docker exec "${CONTAINER}" psql -U "${USER}" -d "${DB}" -tAc "$1" 2>/dev/null; }

has_record_table="$(q "SELECT to_regclass('mcp_boot_record') IS NOT NULL;")"
has_config_table="$(q "SELECT to_regclass('config') IS NOT NULL;")"

# Une requête en échec rend une valeur vide : on n'émet RIEN (un 0 ferait
# sonner l'alerte sur une panne du collecteur ; son absence relève de
# `TradeKongMarkMetricMissing`).
[ -n "${has_record_table}" ] && [ -n "${has_config_table}" ] || exit 0

count=0
if [ "${has_record_table}" = "t" ]; then
  count="$(q "SELECT count(*) FROM mcp_boot_record WHERE name = '${RECORD}';")"
  [ -n "${count}" ] || exit 0
fi
if [ "${count}" = "0" ] && [ "${has_config_table}" = "t" ]; then
  count="$(q "SELECT count(*) FROM config WHERE name = '${RECORD}';")"
  [ -n "${count}" ] || exit 0
fi

mark_done=0
[ "${count}" != "0" ] && mark_done=1
printf '# HELP tradekong_mcp_legacy_mark_done %s\n# TYPE tradekong_mcp_legacy_mark_done gauge\ntradekong_mcp_legacy_mark_done %s\n' \
  "1 si le marquage des clés trade larges d'avant le déploiement a été enregistré (0 : échec ou pas encore passé, ces clés sont refusées)." \
  "${mark_done}"
