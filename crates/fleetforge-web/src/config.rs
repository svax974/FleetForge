/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Configuration du serveur, lue dans l'environnement.
//!
//! Aucune valeur n'est écrite dans la base : le serveur doit pouvoir démarrer
//! sur une machine neuve, avant toute configuration applicative.

use anyhow::{bail, Result};
use fleetforge_core::ro_gate::RoGateConfig;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// Port applicatif par défaut. Inscrit au registre des ports de CLAUDE.md :
/// 9750, `/metrics` sur le même port (exposition Prometheus native).
pub const DEFAULT_PORT: u16 = 9750;

pub struct Config {
    pub addr: SocketAddr,
    /// Racine des fichiers statiques (le `dist/` produit par `vite build`).
    pub static_dir: PathBuf,
    /// Comptes admis. Vide : aucune authentification — boucle locale seule.
    pub accounts: Vec<Account>,
    /// Diagnostic en lecture seule (`ssh_diagnose`).
    pub ro_gate: RoGateConfig,
}

/// Ce qu'un compte a le droit de faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// L'opérateur : toute l'application.
    Operator,
    /// Un appelant programmatique (AgentHub) : la seule API d'automatisation
    /// (`auth::AUTOMATION_COMMANDS`), entrées validées strictement, sorties
    /// caviardées, et un run réel seulement après son `--check`.
    Automation,
}

pub struct Account {
    pub user: String,
    pub secret: Secret,
    pub role: Role,
}

/// Ce que le serveur détient pour vérifier un mot de passe.
///
/// En production c'est une EMPREINTE : le mot de passe en clair vit dans le
/// vault Ansible, et rien sur la machine ne permet de le reconstituer. Le clair
/// reste accepté pour le développement local, où il n'y a ni vault ni rôle
/// pour poser l'empreinte.
pub enum Secret {
    /// Empreinte PHC argon2id, posée par `fleetforge-install`.
    Hash(String),
    /// Mot de passe en clair — développement uniquement.
    Plain(String),
}

impl Config {
    /// Lit `FLEETFORGE_WEB_*`, `FLEETFORGE_API_*` et `FLEETFORGE_RO_*`.
    /// Échoue plutôt que de démarrer dans un état qui exposerait le pilotage
    /// du parc sans authentification.
    pub fn from_env() -> Result<Self> {
        let bind: IpAddr = env("FLEETFORGE_WEB_BIND")
            .unwrap_or_else(|| "127.0.0.1".to_string())
            .parse()?;
        let port: u16 = match env("FLEETFORGE_WEB_PORT") {
            Some(p) => p.parse()?,
            None => DEFAULT_PORT,
        };

        let static_dir = env("FLEETFORGE_WEB_STATIC")
            .map(PathBuf::from)
            .unwrap_or_else(default_static_dir);

        let mut accounts = Vec::new();
        if let (Some(user), Some(secret)) = (env("FLEETFORGE_WEB_USER"), secret_of("FLEETFORGE_WEB")) {
            accounts.push(Account { user, secret, role: Role::Operator });
        }

        // Compte d'automatisation (AgentHub). À moitié renseigné, c'est une
        // erreur de déploiement : la taire laisserait AgentHub en 401 sans que
        // rien n'en désigne la cause.
        match (env("FLEETFORGE_API_USER"), secret_of("FLEETFORGE_API")) {
            (Some(user), Some(secret)) => {
                if accounts.iter().any(|a| a.user == user) {
                    bail!("FLEETFORGE_API_USER doit différer de FLEETFORGE_WEB_USER ({user})");
                }
                accounts.push(Account { user, secret, role: Role::Automation });
            }
            (None, None) => {}
            _ => bail!(
                "compte d'automatisation incomplet : FLEETFORGE_API_USER et \
                 FLEETFORGE_API_PASSWORD_HASH vont ensemble"
            ),
        }

        // Cette application lance des playbooks Ansible sur tout le parc, avec
        // les clés SSH de la machine. Sur une interface autre que la boucle
        // locale, l'absence d'authentification n'est pas un réglage permissif :
        // c'est un accès administrateur ouvert. Le refus est donc au démarrage,
        // pas au premier appel — un serveur qui démarre est un serveur qu'on
        // croit configuré.
        if accounts.is_empty() && !bind.is_loopback() {
            bail!(
                "FLEETFORGE_WEB_USER et FLEETFORGE_WEB_PASSWORD_HASH sont obligatoires pour \
                 écouter sur {bind} : sans eux, n'importe qui joignant ce port pilote \
                 le parc. Écouter sur 127.0.0.1 est la seule exception (accès par \
                 tunnel SSH)."
            );
        }

        Ok(Self {
            addr: SocketAddr::new(bind, port),
            static_dir,
            accounts,
            ro_gate: ro_gate_from_env()?,
        })
    }
}

/// Secret d'un compte : `<PRÉFIXE>_PASSWORD_HASH`, à défaut `<PRÉFIXE>_PASSWORD`.
///
/// L'empreinte prime : quand les deux sont posées, c'est la variable héritée
/// d'un déploiement plus ancien qu'on ignore, pas la neuve.
fn secret_of(prefix: &str) -> Option<Secret> {
    env(&format!("{prefix}_PASSWORD_HASH"))
        .map(Secret::Hash)
        .or_else(|| env(&format!("{prefix}_PASSWORD")).map(Secret::Plain))
}

/// Réglages du diagnostic lecture seule. La clé n'est pas exigée au
/// démarrage : sans elle, `ssh_diagnose` répond `not_configured` et le reste
/// de l'application fonctionne.
fn ro_gate_from_env() -> Result<RoGateConfig> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let timeout = match env("FLEETFORGE_RO_TIMEOUT_SECS") {
        Some(t) => t.parse::<u64>()?.clamp(5, 600),
        None => 60,
    };
    Ok(RoGateConfig {
        key: env("FLEETFORGE_RO_SSH_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".ssh/id_fleetforge_ro")),
        user: env("FLEETFORGE_RO_SSH_USER").unwrap_or_else(|| "openclaw-ro".to_string()),
        known_hosts: env("FLEETFORGE_RO_KNOWN_HOSTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".ssh/known_hosts_fleetforge_ro")),
        timeout: Duration::from_secs(timeout),
    })
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Défaut commode en développement : le `dist/` du dépôt, relatif au binaire.
/// En production le rôle Ansible pose `FLEETFORGE_WEB_STATIC` explicitement.
fn default_static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/gui/dist")
}
