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

use anyhow::{bail, Context, Result};
use argon2::password_hash::PasswordHash;
use fleetforge_core::ansible_git::{GitTreeConfig, DEFAULT_KEEP};
use fleetforge_core::ro_gate::RoGateConfig;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    /// Arbre Ansible servi depuis git (`FLEETFORGE_ANSIBLE_SOURCE=git`). `None` :
    /// l'arbre livré par rsync (`FLEETFORGE_ANSIBLE_DIR`).
    pub git_tree: Option<GitTreeConfig>,
    /// Fichiers de l'arbre portant une donnée de parc, jamais lus par
    /// `read_tree` (`FLEETFORGE_TREE_PRIVATE_FILES`, séparés par des virgules).
    pub private_tree_files: Vec<String>,
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

/// Lecture seule ou pilotage : ce qu'un compte d'automatisation peut lancer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// `auth::READ_COMMANDS` : inventaire, playbooks, alertes, Prometheus,
    /// diagnostic lecture seule.
    Read,
    /// Tout `auth::AUTOMATION_COMMANDS` : la lecture, plus les runs de
    /// playbook (`run_ansible_playbook`, `run_status`, flux d'un run).
    Run,
}

/// Périmètre d'un compte : les parcs qu'il atteint et son mode.
///
/// Tenu à l'identique par l'API REST et le serveur MCP : un parc hors
/// périmètre, un hôte qui n'est dans aucun parc du périmètre, un run d'un
/// autre parc répondent `403 forbidden`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// `None` : tous les parcs de la machine — l'opérateur, et le compte
    /// hérité `FLEETFORGE_API_USER` (sur une machine qui ne reçoit que les
    /// données de son parc, ce parc seul).
    pub parcs: Option<BTreeSet<String>>,
    pub mode: Mode,
    /// Motifs (`*`, `?`) des noms de playbooks que `run_ansible_playbook`
    /// refuse à ce compte (`forbidden_playbook`) — y compris ceux qu'un
    /// playbook importe.
    pub deny_playbooks: Vec<String>,
    /// Hôtes au plus visés par un run de ce compte (`too_many_hosts`) ; `limit`
    /// devient obligatoire et `no_limit` refusé. `None` : pas de borne.
    pub max_hosts: Option<usize>,
}

impl Scope {
    /// Tout : l'opérateur, le compte hérité, l'absence d'authentification.
    pub fn everything() -> Self {
        Self { parcs: None, mode: Mode::Run, deny_playbooks: Vec::new(), max_hosts: None }
    }

    /// Rien : une requête qui n'est pas passée par l'authentification.
    pub fn nothing() -> Self {
        Self { parcs: Some(BTreeSet::new()), mode: Mode::Read, deny_playbooks: Vec::new(), max_hosts: None }
    }

    /// Ce playbook (nom de fichier) est-il interdit à ce compte ?
    ///
    /// `x.yaml` et `x.yml` sont un même playbook pour Ansible : un motif en
    /// `.yml` couvre aussi la forme `.yaml`, et inversement.
    pub fn denies(&self, playbook: &str) -> bool {
        let other = match (playbook.strip_suffix(".yaml"), playbook.strip_suffix(".yml")) {
            (Some(stem), _) => Some(format!("{stem}.yml")),
            (_, Some(stem)) => Some(format!("{stem}.yaml")),
            _ => None,
        };
        self.deny_playbooks.iter().any(|p| {
            fleetforge_core::automation::glob_match(p, playbook)
                || other.as_deref().is_some_and(|o| fleetforge_core::automation::glob_match(p, o))
        })
    }

    pub fn covers(&self, parc: &str) -> bool {
        self.parcs.as_ref().is_none_or(|parcs| parcs.contains(parc))
    }

    /// Commande (ou outil MCP) que ce mode permet.
    pub fn may(&self, command: &str) -> bool {
        crate::auth::commands(self.mode).contains(&command)
    }
}

pub struct Account {
    pub user: String,
    pub secret: Secret,
    pub role: Role,
    pub scope: Arc<Scope>,
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
    /// Lit `FLEETFORGE_WEB_*`, `FLEETFORGE_API_*` (dont le fichier des
    /// comptes bornés, `FLEETFORGE_API_ACCOUNTS_FILE`) et `FLEETFORGE_RO_*`.
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
            accounts.push(Account { user, secret, role: Role::Operator, scope: Arc::new(Scope::everything()) });
        }

        // Compte d'automatisation hérité (AgentHub) : pilotage, tous les
        // parcs de la machine. À moitié renseigné, c'est une erreur de
        // déploiement : la taire laisserait AgentHub en 401 sans que rien
        // n'en désigne la cause.
        match (env("FLEETFORGE_API_USER"), secret_of("FLEETFORGE_API")) {
            (Some(user), Some(secret)) => {
                if accounts.iter().any(|a| a.user == user) {
                    bail!("FLEETFORGE_API_USER doit différer de FLEETFORGE_WEB_USER ({user})");
                }
                accounts.push(Account {
                    user,
                    secret,
                    role: Role::Automation,
                    scope: Arc::new(Scope::everything()),
                });
            }
            (None, None) => {}
            _ => bail!(
                "compte d'automatisation incomplet : FLEETFORGE_API_USER et \
                 FLEETFORGE_API_PASSWORD_HASH vont ensemble"
            ),
        }

        // Comptes bornés (un par client : AgentHub, OpenClaw…).
        if let Some(path) = env("FLEETFORGE_API_ACCOUNTS_FILE") {
            for account in accounts_from_file(Path::new(&path))? {
                if accounts.iter().any(|a| a.user == account.user) {
                    bail!("{path} : compte {} déclaré deux fois (ou homonyme d'un autre compte)", account.user);
                }
                accounts.push(account);
            }
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
            git_tree: git_tree_from_env()?,
            private_tree_files: env("FLEETFORGE_TREE_PRIVATE_FILES")
                .map(|v| v.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
                .unwrap_or_default(),
        })
    }
}

/// Une entrée du fichier des comptes bornés.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountEntry {
    user: String,
    /// Empreinte argon2id (PHC), jamais le mot de passe.
    password_hash: String,
    parcs: Vec<String>,
    mode: Mode,
    /// Motifs de noms de playbooks interdits (`*-fleetforge.yml`).
    #[serde(default)]
    deny_playbooks: Vec<String>,
    /// Hôtes au plus visés par un run.
    #[serde(default)]
    max_hosts: Option<usize>,
}

/// Comptes bornés, lus dans un fichier JSON (`FLEETFORGE_API_ACCOUNTS_FILE`,
/// posé par `fleetforge-install`) :
///
/// ```json
/// [{ "user": "agenthub", "password_hash": "$argon2id$…", "parcs": ["web3c"], "mode": "read" },
///  { "user": "autonomous", "password_hash": "$argon2id$…", "parcs": ["web3c"], "mode": "run",
///    "deny_playbooks": ["*-fleetforge.yml"], "max_hosts": 3 }]
/// ```
///
/// Tout défaut refuse le démarrage plutôt qu'un compte : un fichier ignoré
/// laisserait ses clients en 401 sans que rien n'en désigne la cause, et un
/// compte dont le périmètre se perdrait à la lecture serait plus large que
/// voulu.
fn accounts_from_file(path: &Path) -> Result<Vec<Account>> {
    let shown = path.display();
    // Une empreinte se casse hors ligne : lisible par d'autres comptes de la
    // machine, le fichier exposerait les mots de passe.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).with_context(|| format!("{shown}"))?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("{shown} est lisible par d'autres comptes (mode {:o}) : 0600 attendu", mode & 0o777);
        }
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("{shown}"))?;
    let entries: Vec<AccountEntry> =
        serde_json::from_str(&text).with_context(|| format!("{shown} : comptes illisibles"))?;
    entries
        .into_iter()
        .map(|e| {
            if e.user.is_empty() || e.user.contains(':') {
                bail!("{shown} : nom de compte invalide {:?}", e.user);
            }
            if PasswordHash::new(&e.password_hash).is_err() {
                bail!("{shown} : empreinte invalide pour {} (format PHC argon2id attendu)", e.user);
            }
            if e.parcs.is_empty() {
                bail!("{shown} : {} ne couvre aucun parc", e.user);
            }
            for parc in &e.parcs {
                fleetforge_core::automation::validate_parc_name(parc)
                    .with_context(|| format!("{shown} : compte {}", e.user))?;
            }
            for pattern in &e.deny_playbooks {
                fleetforge_core::automation::validate_glob(pattern)
                    .with_context(|| format!("{shown} : compte {}", e.user))?;
            }
            if e.max_hosts.is_some_and(|n| !(1..=1000).contains(&n)) {
                bail!("{shown} : max_hosts de {} hors de 1..=1000", e.user);
            }
            Ok(Account {
                user: e.user,
                secret: Secret::Hash(e.password_hash),
                role: Role::Automation,
                scope: Arc::new(Scope {
                    parcs: Some(e.parcs.into_iter().collect()),
                    mode: e.mode,
                    deny_playbooks: e.deny_playbooks,
                    max_hosts: e.max_hosts,
                }),
            })
        })
        .collect()
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

/// Arbre Ansible servi depuis git : `FLEETFORGE_ANSIBLE_SOURCE=git` (défaut
/// `rsync`, rien ne change) puis `FLEETFORGE_ANSIBLE_GIT_DIR` (le clone),
/// `FLEETFORGE_ANSIBLE_DATA_DIR` (les données du parc),
/// `FLEETFORGE_ANSIBLE_TREES_DIR` (un arbre d'exécution par commit), et
/// facultativement `FLEETFORGE_ANSIBLE_BRANCH` (`main`),
/// `FLEETFORGE_ANSIBLE_DEPLOY_KEY`, `FLEETFORGE_ANSIBLE_KNOWN_HOSTS`,
/// `FLEETFORGE_ANSIBLE_CACHE_KEEP` (5). Un réglage à moitié posé refuse le
/// démarrage : l'application montrerait sinon un parc vide.
fn git_tree_from_env() -> Result<Option<GitTreeConfig>> {
    match env("FLEETFORGE_ANSIBLE_SOURCE").as_deref() {
        None | Some("rsync") => return Ok(None),
        Some("git") => {}
        Some(other) => bail!("FLEETFORGE_ANSIBLE_SOURCE : « {other} » inconnu (git ou rsync)"),
    }
    let required = |key: &str| -> Result<PathBuf> {
        env(key)
            .map(PathBuf::from)
            .with_context(|| format!("{key} est obligatoire avec FLEETFORGE_ANSIBLE_SOURCE=git"))
    };
    let mut cfg = GitTreeConfig::new(
        required("FLEETFORGE_ANSIBLE_GIT_DIR")?,
        required("FLEETFORGE_ANSIBLE_DATA_DIR")?,
        required("FLEETFORGE_ANSIBLE_TREES_DIR")?,
        &env("FLEETFORGE_ANSIBLE_BRANCH").unwrap_or_else(|| "main".to_string()),
    );
    cfg.deploy_key = env("FLEETFORGE_ANSIBLE_DEPLOY_KEY").map(PathBuf::from);
    cfg.known_hosts = env("FLEETFORGE_ANSIBLE_KNOWN_HOSTS").map(PathBuf::from);
    cfg.keep = match env("FLEETFORGE_ANSIBLE_CACHE_KEEP") {
        Some(n) => n.parse::<usize>().ok().filter(|n| (1..=50).contains(n)).with_context(|| {
            format!("FLEETFORGE_ANSIBLE_CACHE_KEEP : « {n} » hors de 1..=50")
        })?,
        None => DEFAULT_KEEP,
    };
    Ok(Some(cfg))
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Défaut commode en développement : le `dist/` du dépôt, relatif au binaire.
/// En production le rôle Ansible pose `FLEETFORGE_WEB_STATIC` explicitement.
fn default_static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/gui/dist")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded(deny: &[&str], max_hosts: Option<usize>) -> Scope {
        Scope {
            parcs: Some(["web3c".to_string()].into()),
            mode: Mode::Run,
            deny_playbooks: deny.iter().map(|s| s.to_string()).collect(),
            max_hosts,
        }
    }

    #[test]
    fn denied_playbooks_match_by_glob_in_both_extensions() {
        let scope = bounded(&["*-fleetforge.yml", "setup-server.yml"], Some(3));
        assert!(scope.denies("deploy-fleetforge.yml"));
        assert!(scope.denies("deploy-fleetforge.yaml"), "même playbook pour Ansible");
        assert!(scope.denies("setup-server.yml") && scope.denies("setup-server.yaml"));
        assert!(!scope.denies("deploy-agenthub.yml") && !scope.denies("setup-servers.yml"));
        assert!(!Scope::everything().denies("deploy-fleetforge.yml"));
        assert!(!bounded(&[], None).denies("anything.yml"));
        assert!(bounded(&["setup-server.yaml"], None).denies("setup-server.yml"));
    }
}
