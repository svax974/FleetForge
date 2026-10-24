-- Schéma de la base du serveur de messagerie (mailserver-setup).
-- Idempotent : rejoué à chaque déploiement.
CREATE TABLE IF NOT EXISTS domains (
  name TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS users (
  address  TEXT PRIMARY KEY,
  domain   TEXT NOT NULL,
  password TEXT NOT NULL,
  quota    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aliases (
  source      TEXT NOT NULL,
  destination TEXT NOT NULL,
  PRIMARY KEY (source, destination)
);
