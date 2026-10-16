/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Emplacements locaux de l'application, et reprise de ceux de l'ancien nom.
//!
//! Le projet s'appelait InfraManager : ses données vivaient sous
//! `<données locales>/infra-manager` (base SQLite, journaux, comptes
//! fournisseurs) et ses fichiers d'opérateur sous `~/.config/infra-manager`
//! (mot de passe du vault, clés Theta, clé FreeLLM). Sans reprise, la première
//! ouverture sous le nouveau nom repartirait d'une base vide et Ansible ne
//! trouverait plus le vault — sans que rien ne dise pourquoi.
//!
//! La reprise est un simple renommage de répertoire, fait une fois par
//! processus au premier accès, et seulement si la nouvelle destination
//! n'existe pas encore : deux arborescences ne sont jamais fusionnées.

use std::path::{Path, PathBuf};
use std::sync::Once;

const APP_DIR: &str = "fleetforge";
const LEGACY_DIR: &str = "infra-manager";

static MIGRATE: Once = Once::new();

/// Répertoire de données de l'application (base, journaux, comptes).
pub fn data_dir() -> PathBuf {
    migrate_legacy();
    data_root().join(APP_DIR)
}

/// `~/.config/fleetforge` — chemin littéral partagé avec `Ansible/ansible.cfg`
/// et les rôles, qui l'écrivent `~/.config/...` sur macOS comme sur Linux.
pub fn config_dir() -> PathBuf {
    migrate_legacy();
    config_root().join(APP_DIR)
}

fn data_root() -> PathBuf {
    dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn config_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
}

/// Renomme les répertoires de l'ancien nom. Idempotent, silencieux en cas
/// d'échec : l'application doit démarrer même si l'ancien répertoire est
/// verrouillé — elle repartira alors du nouveau, vide.
pub fn migrate_legacy() {
    MIGRATE.call_once(|| {
        for root in [data_root(), config_root()] {
            let _ = rename_if_absent(&root.join(LEGACY_DIR), &root.join(APP_DIR));
        }
    });
}

fn rename_if_absent(from: &Path, to: &Path) -> std::io::Result<bool> {
    if !from.is_dir() || to.exists() {
        return Ok(false);
    }
    std::fs::rename(from, to)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fleetforge-paths-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_legacy_directory_is_taken_over_with_its_content() {
        let root = scratch("takeover");
        let old = root.join(LEGACY_DIR);
        std::fs::create_dir(&old).unwrap();
        std::fs::write(old.join("database.db"), b"x").unwrap();

        let new = root.join(APP_DIR);
        assert!(rename_if_absent(&old, &new).unwrap());
        assert!(new.join("database.db").exists());
        assert!(!old.exists());
    }

    #[test]
    fn an_existing_destination_is_never_overwritten() {
        let root = scratch("keep");
        let old = root.join(LEGACY_DIR);
        let new = root.join(APP_DIR);
        std::fs::create_dir(&old).unwrap();
        std::fs::create_dir(&new).unwrap();
        std::fs::write(new.join("database.db"), b"new").unwrap();

        assert!(!rename_if_absent(&old, &new).unwrap());
        assert_eq!(std::fs::read(new.join("database.db")).unwrap(), b"new");
        assert!(old.exists());
    }
}
