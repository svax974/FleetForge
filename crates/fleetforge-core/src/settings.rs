/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Réglages persistés, nommés.
//!
//! Les clés étaient des chaînes littérales répétées dans une trentaine de
//! commandes : une faute de frappe y créait silencieusement un réglage neuf,
//! vide, sans que rien ne le signale.

use crate::database::Database;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKey {
    InventoriesPath,
    PlaybooksPath,
    SelectedInventory,
    PrometheusUrl,
    PrometheusUser,
    PrometheusPassword,
}

impl SettingKey {
    pub fn as_str(self) -> &'static str {
        match self {
            SettingKey::InventoriesPath => "inventories_path",
            SettingKey::PlaybooksPath => "playbooks_path",
            SettingKey::SelectedInventory => "selected_inventory",
            SettingKey::PrometheusUrl => "prometheus_url",
            SettingKey::PrometheusUser => "prometheus_user",
            SettingKey::PrometheusPassword => "prometheus_password",
        }
    }

    /// Clé propre à un parc.
    ///
    /// Chaque parc a SA supervision — `prometheus_host` vaut `prometheus1` sur
    /// papanglabs et `monitor` sur web3c. Un réglage unique pour les deux fait
    /// interroger la mauvaise instance dès qu'on change d'inventaire, et
    /// comme les noms d'hôtes se répètent d'un parc à l'autre (`proxy1`,
    /// `mail`), le résultat n'est pas vide mais FAUX — ce qui est pire.
    pub fn scoped(self, organization: &str) -> String {
        format!("{}@{organization}", self.as_str())
    }
}

/// Réglages qui ne dépendent pas du parc.
///
/// La supervision n'y figure PAS : elle est propre à chaque parc et se lit par
/// [`SettingKey::scoped`]. Une valeur unique ici ferait interroger la mauvaise
/// instance dès qu'on change d'inventaire.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    pub inventories_path: String,
    pub playbooks_path: String,
    pub selected_inventory: String,
}

impl Settings {
    pub fn load(db: &Database) -> Result<Settings> {
        let get = |k: SettingKey| -> Result<String> {
            Ok(db.get_setting(k.as_str())?.unwrap_or_default())
        };
        Ok(Settings {
            inventories_path: get(SettingKey::InventoriesPath)?,
            playbooks_path: get(SettingKey::PlaybooksPath)?,
            selected_inventory: get(SettingKey::SelectedInventory)?,
        })
    }

    /// Racine du dépôt Ansible, déduite du chemin des playbooks.
    ///
    /// C'est le `cwd` que `play.sh` supposent : tous leurs
    /// chemins sont relatifs, et l'ancien runner l'ignorait.
    pub fn ansible_root(&self) -> Option<std::path::PathBuf> {
        std::path::Path::new(&self.playbooks_path)
            .parent()
            .map(|p| p.to_path_buf())
    }
}
