#!/usr/bin/env bash
# disk-watchdog.sh — compress uncompressed TimescaleDB chunks if THIS host's
# local disk gets critically low. Runs every 2 minutes via cron. Lock file
# prevents concurrent runs (compress_chunk can take a while).
set -euo pipefail

THRESHOLD_GB={{ tsdb_watchdog_threshold_gb }}
LOG=/tmp/disk-watchdog.log
LOCK=/tmp/disk-watchdog.lock

if [ -f "$LOCK" ]; then
  exit 0
fi
touch "$LOCK"
trap 'rm -f "$LOCK"' EXIT

FREE_KB=$(df / | awk 'NR==2 {print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))

if (( FREE_GB >= THRESHOLD_GB )); then
  exit 0
fi

# Un réplica est en lecture seule : compress_chunk y échouerait, et son disque suit celui du
# primaire (le WAL rejoué). Alerter ici ne servirait à rien : c'est la supervision qui prévient.
IN_RECOVERY=$(docker exec papangmetrics-timescaledb psql -U "{{ tsdb_user }}" -d "{{ tsdb_db }}" \
  -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "f")
if [ "${IN_RECOVERY}" = "t" ]; then
  echo "$(date -Iseconds) [WARN] Free disk ${FREE_GB}GB < ${THRESHOLD_GB}GB on a replica — no compression possible" | tee -a "$LOG"
  exit 0
fi

echo "$(date -Iseconds) [WARN] Free disk ${FREE_GB}GB < ${THRESHOLD_GB}GB — compressing chunks" | tee -a "$LOG"

COMPRESSED=$(docker exec papangmetrics-timescaledb psql -U "{{ tsdb_user }}" -d "{{ tsdb_db }}" \
  -tAc "SELECT COUNT(compress_chunk(c, if_not_compressed => true)) FROM show_chunks('metric_point') AS c;" 2>&1)
echo "$(date -Iseconds) [INFO] Compressed ${COMPRESSED} chunks" | tee -a "$LOG"

FREE_AFTER_KB=$(df / | awk 'NR==2 {print $4}')
FREE_AFTER_GB=$(( FREE_AFTER_KB / 1024 / 1024 ))
echo "$(date -Iseconds) [INFO] Free disk after compression: ${FREE_AFTER_GB}GB" | tee -a "$LOG"

if (( FREE_AFTER_GB < THRESHOLD_GB )); then
  echo "$(date -Iseconds) [ERROR] Still below threshold after compression (${FREE_AFTER_GB}GB free). Manual intervention required." | tee -a "$LOG"
fi
