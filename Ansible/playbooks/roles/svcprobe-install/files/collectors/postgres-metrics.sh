#!/usr/bin/env bash
# Collecteur PostgreSQL pour svcprobe — déployé par `svcprobe-install`.
#
# Partagé par tous les rôles `-monitoring` d'une base PostgreSQL
# (timescaledb, db, dbfront) : le même code recopié dans trois rôles serait
# corrigé dans un seul le jour où il faudra le corriger.
#
# Usage : postgres-metrics.sh <conteneur> <utilisateur> <base> <préfixe>
#
# N'est appelé que si la sonde principale du service est passée (voir
# svcprobe.py) : inutile de prévoir le cas d'une base arrêtée.
set -uo pipefail

CONTAINER="${1:?conteneur manquant}"
USER="${2:?utilisateur manquant}"
DB="${3:?base manquante}"
PREFIX="${4:?préfixe manquant}"

q() { docker exec "${CONTAINER}" psql -U "${USER}" -d "${DB}" -tAc "$1" 2>/dev/null; }

emit() {
  # Une valeur vide signifie que la requête a échoué : on n'émet RIEN plutôt
  # qu'un zéro. Un zéro serait une donnée fausse, et une alerte bâtie dessus
  # se déclencherait sur une panne du collecteur en croyant voir une panne du
  # service.
  [ -n "$2" ] || return 0
  printf '# HELP %s %s\n# TYPE %s gauge\n%s %s\n' "$1" "$3" "$1" "$1" "$2"
}

emit "${PREFIX}_database_size_bytes" \
     "$(q "SELECT pg_database_size(current_database());")" \
     "Taille de la base."

emit "${PREFIX}_connections" \
     "$(q "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database();")" \
     "Connexions ouvertes sur la base."

# Le rapport connexions/plafond est la panne qui arrive sans prévenir : la base
# répond parfaitement jusqu'au moment où elle refuse toute nouvelle connexion.
emit "${PREFIX}_max_connections" \
     "$(q "SHOW max_connections;")" \
     "Plafond de connexions du moteur."

emit "${PREFIX}_deadlocks" \
     "$(q "SELECT deadlocks FROM pg_stat_database WHERE datname = current_database();")" \
     "Interblocages depuis la dernière remise à zéro des compteurs."

# Une transaction ouverte depuis des heures empêche le VACUUM et fait gonfler
# la base sans que rien d'autre ne le signale.
emit "${PREFIX}_longest_transaction_seconds" \
     "$(q "SELECT COALESCE(EXTRACT(EPOCH FROM max(now() - xact_start)), 0)::bigint FROM pg_stat_activity WHERE state <> 'idle' AND xact_start IS NOT NULL;")" \
     "Durée de la plus ancienne transaction en cours."

# ── TimescaleDB ────────────────────────────────────────────────────────────
# Silencieux si l'extension est absente : le même collecteur sert des bases
# PostgreSQL ordinaires.
HAS_TS="$(q "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb';")"
if [ "${HAS_TS}" = "1" ]; then
  emit "${PREFIX}_chunks_total" \
       "$(q "SELECT count(*) FROM timescaledb_information.chunks;")" \
       "Chunks des hypertables."
  emit "${PREFIX}_chunks_compressed" \
       "$(q "SELECT count(*) FROM timescaledb_information.chunks WHERE is_compressed;")" \
       "Chunks compressés."
fi

# ── Réplication ────────────────────────────────────────────────────────────
IS_REPLICA="$(q "SELECT pg_is_in_recovery();")"
if [ "${IS_REPLICA}" = "t" ]; then
  emit "${PREFIX}_replication_lag_seconds" \
       "$(q "SELECT COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()), 0)::bigint;")" \
       "Retard de rejeu du réplica."
  emit "${PREFIX}_is_replica" 1 "1 si l'instance est un réplica."
else
  emit "${PREFIX}_is_replica" 0 "1 si l'instance est un réplica."
  # Un slot de réplication inactif retient les WAL indéfiniment et finit par
  # remplir le disque du maître — panne classique et lente.
  emit "${PREFIX}_inactive_replication_slots" \
       "$(q "SELECT count(*) FROM pg_replication_slots WHERE NOT active;")" \
       "Slots de réplication inactifs (rétention de WAL)."
fi
