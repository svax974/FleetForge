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
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Port applicatif par défaut. Inscrit au registre des ports de CLAUDE.md :
/// 9750, `/metrics` sur le même port (exposition Prometheus native).
pub const DEFAULT_PORT: u16 = 9750;

pub struct Config {
    pub addr: SocketAddr,
    /// Racine des fichiers statiques (le `dist/` produit par `vite build`).
    pub static_dir: PathBuf,
    pub auth: Option<BasicAuth>,
}

pub struct BasicAuth {
    pub user: String,
    pub secret: Secret,
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
    /// Lit `FLEETFORGE_WEB_*`. Échoue plutôt que de démarrer dans un état qui
    /// exposerait le pilotage du parc sans authentification.
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

        // L'empreinte prime : quand les deux sont posées, c'est la variable
        // héritée d'un déploiement plus ancien qu'on ignore, pas la neuve.
        let secret = env("FLEETFORGE_WEB_PASSWORD_HASH")
            .map(Secret::Hash)
            .or_else(|| env("FLEETFORGE_WEB_PASSWORD").map(Secret::Plain));

        let auth = match (env("FLEETFORGE_WEB_USER"), secret) {
            (Some(user), Some(secret)) => Some(BasicAuth { user, secret }),
            _ => None,
        };

        // Cette application lance des playbooks Ansible sur tout le parc, avec
        // les clés SSH de la machine. Sur une interface autre que la boucle
        // locale, l'absence d'authentification n'est pas un réglage permissif :
        // c'est un accès administrateur ouvert. Le refus est donc au démarrage,
        // pas au premier appel — un serveur qui démarre est un serveur qu'on
        // croit configuré.
        if auth.is_none() && !bind.is_loopback() {
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
            auth,
        })
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Défaut commode en développement : le `dist/` du dépôt, relatif au binaire.
/// En production le rôle Ansible pose `FLEETFORGE_WEB_STATIC` explicitement.
fn default_static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/gui/dist")
}
