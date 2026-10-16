#!/bin/bash
set -e

# Ensure the data dir is empty for the first run so we initialize the backup only on first launch
if [ "$(ls -A /var/lib/postgresql/data)" ]; then
    echo "The data directory is not empty, skipping initialization."
else
    echo "Initializing replication from master..."
    su postgres -c 'PGPASSWORD="{{ postgres_replication_pw }}" /usr/local/bin/pg_basebackup -h {{ hostvars["dbmaster"].ansible_host }} -p {{ postgres_port }} -U replication_user -D /var/lib/postgresql/data -Fp -Xs -P'
    su postgres -c "touch /var/lib/postgresql/data/standby.signal"
    echo "primary_conninfo = 'host={{ hostvars['dbmaster'].ansible_host }} port={{ postgres_port }} user=replication_user password={{ postgres_replication_pw }} application_name=slave'" >> /var/lib/postgresql/data/postgresql.auto.conf
fi

echo "Starting main service..."
su postgres -c postgres
