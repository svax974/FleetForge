-- Create a replication user
CREATE USER {{ postgres_replication_user }} WITH REPLICATION ENCRYPTED PASSWORD '{{ postgres_replication_pw }}';
--CREATE ROLE {{ postgres_replication_user }} WITH REPLICATION LOGIN PASSWORD '{{ postgres_replication_pw }}';

-- Enable access for replication
ALTER SYSTEM SET wal_level = 'replica';
ALTER SYSTEM SET max_wal_senders = 10;
ALTER SYSTEM SET max_replication_slots = 10;
ALTER SYSTEM SET wal_keep_size = '64MB';
ALTER SYSTEM SET password_encryption = md5;

-- Allow connections from the slave
ALTER SYSTEM SET listen_addresses = '*';
