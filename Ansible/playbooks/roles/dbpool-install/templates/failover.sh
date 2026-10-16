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
LOGFILE="/var/log/pgpool/failover.log"

echo "$(date): Failover triggered. Failed node ID: $NODE_ID, Host: $HOSTNAME" >> $LOGFILE

# Promotion du standby en tant que nouveau master
if [ "$NEW_MASTER_HOST" != "" ]; then
    echo "$(date): Promoting standby $NEW_MASTER_HOST to primary." >> $LOGFILE
    PGPASSWORD="{{ postgres_replication_pw }}" psql -h "$NEW_MASTER_HOST" -U replication_user -c "SELECT pg_promote();" >> $LOGFILE 2>&1
else
    echo "$(date): No standby available to promote. Manual intervention required." >> $LOGFILE
fi

exit 0
