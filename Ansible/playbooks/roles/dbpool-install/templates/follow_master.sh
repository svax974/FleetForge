#!/bin/bash

# Paramètres passés par PGPool-II
NODE_ID=$1
HOSTNAME=$2
PORT=$3
DATABASE=$4
OLD_PRIMARY=$5
NEW_MASTER_HOST=$6
NEW_MASTER_PORT=$7

# Fichier de log
LOGFILE="/var/log/pgpool/follow_master.log"

echo "$(date): Follow master triggered. New master: $NEW_MASTER_HOST:$NEW_MASTER_PORT" >> $LOGFILE

# Reconfiguration du standby pour suivre le nouveau master
if [ "$HOSTNAME" != "$NEW_MASTER_HOST" ]; then
    echo "$(date): Reconfiguring standby $HOSTNAME to follow new master." >> $LOGFILE
    PGPASSWORD="{{ postgres_replication_pw }}" pg_basebackup -h "$NEW_MASTER_HOST" -D /var/lib/postgresql/{{ pgversion }}/main -U replication_user -Fp -Xs -P -R >> $LOGFILE 2>&1
fi

exit 0
