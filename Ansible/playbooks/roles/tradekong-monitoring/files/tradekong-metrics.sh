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
# du marquage l'écrivait dans `config` ; la nouvelle version la COPIE et la laisse en
# place (retour arrière sûr). Les deux emplacements comptent : sans cela une base déjà
# marquée sonnerait entre le dépôt de ce collecteur et le déploiement du back.
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

# Lecture seule, bornée : le collecteur tourne toutes les 10 s au pire et ne doit ni écrire,
# ni tenir un verrou, ni peser sur la base de production.
q() {
  docker exec -e PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=5s -c lock_timeout=2s' \
    "${CONTAINER}" psql -U "${USER}" -d "${DB}" -tAc "$1" 2>/dev/null
}

# UNE requête, sûre quand `mcp_boot_record` est absente : un SELECT direct sur une table
# inexistante échoue à l'analyse, même dans une branche CASE jamais prise. `query_to_xml`
# n'analyse sa requête qu'à l'exécution, donc seulement si `to_regclass` a trouvé la table.
# Réponse : `t` (enregistrement présent, dans `mcp_boot_record` ou encore dans `config`),
# `f` (absent) ; vide si la requête échoue.
DONE_SQL="
SELECT (
  COALESCE(CASE WHEN to_regclass('mcp_boot_record') IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml('SELECT count(*) AS c FROM mcp_boot_record WHERE name = ''${RECORD}''', true, true, '')))[1]::text::int
  END, 0)
  + COALESCE(CASE WHEN to_regclass('config') IS NOT NULL THEN
    (xpath('/row/c/text()', query_to_xml('SELECT count(*) AS c FROM config WHERE name = ''${RECORD}''', true, true, '')))[1]::text::int
  END, 0)
) > 0;"

result="$(q "${DONE_SQL}")"

# Une requête en échec rend une valeur vide : on n'émet RIEN (un 0 ferait sonner l'alerte sur
# une panne du collecteur ; son absence relève de `TradeKongMarkMetricMissing`).
case "${result}" in
  t) mark_done=1 ;;
  f) mark_done=0 ;;
  *) exit 0 ;;
esac

printf '# HELP tradekong_mcp_legacy_mark_done %s\n# TYPE tradekong_mcp_legacy_mark_done gauge\ntradekong_mcp_legacy_mark_done %s\n' \
  "1 si le marquage des clés trade larges d'avant le déploiement a été enregistré (0 : échec ou pas encore passé, ces clés sont refusées)." \
  "${mark_done}"
