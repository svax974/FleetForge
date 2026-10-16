-- Runs once, on first container init, against POSTGRES_DB ({{ tsdb_db }}).
-- The PapangMetrics app migration (npm run migration:run) creates the tables,
-- hypertable, compression and continuous aggregates; here we only enable the
-- extension so those statements work.
CREATE EXTENSION IF NOT EXISTS timescaledb;
