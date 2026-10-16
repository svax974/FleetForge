-- Create a replication user
CREATE USER {{ postgres_replication_user }} WITH REPLICATION ENCRYPTED PASSWORD '{{ postgres_replication_pw }}';
CREATE ROLE {{ postgres_replication_user }} WITH REPLICATION LOGIN PASSWORD '{{ postgres_replication_pw }}';

-- Allow connections from the slave
ALTER SYSTEM SET listen_addresses = '*';
ALTER SYSTEM SET password_encryption = md5;
