/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Abstraction commune aux hébergeurs.
//!
//! Trois corrections structurelles par rapport au prototype Python :
//!
//! 1. **[`InstanceRef`] porte la zone.** C'est `start_instance(id)` — un
//!    identifiant nu — qui condamnait GCP à la lecture seule : l'API exige la
//!    zone, et la signature ne la transportait pas. Le problème disparaît par
//!    construction, il n'y a rien à « implémenter plus tard ».
//! 2. **[`Capabilities`] déclarées.** La matrice de `FEATURES.md` annonçait
//!    l'arrêt gracieux sur OVH et Contabo alors que le code ignorait le drapeau.
//!    Une capacité déclarée absente fait griser l'action, au lieu de promettre
//!    ce qui ne sera pas tenu.
//! 3. **`custom` est un provider à part entière** — machines physiques, SSH
//!    seul. Absent de la spec, alors qu'il est dans la liste fermée et dans les
//!    inventaires.

use async_trait::async_trait;
use fleetforge_core::model::ProviderKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("non connecté à {0}")]
    NotConnected(ProviderKind),
    #[error("{action} n'est pas disponible chez {provider}")]
    Unsupported {
        provider: ProviderKind,
        action: &'static str,
    },
    #[error("outil `{tool}` introuvable — {install}")]
    MissingCli { tool: String, install: String },
    #[error("authentification refusée : {0}")]
    Auth(String),
    #[error("{0}")]
    Api(String),
}

pub type Result<T> = std::result::Result<T, ProviderError>;

/// Un compte chez un hébergeur.
///
/// Un même hébergeur porte plusieurs comptes : deux tenancies Oracle, deux
/// profils AWS, deux projets GCP. Tout ce qui était indexé sur le seul
/// `ProviderKind` — le magasin d'identifiants, les connexions ouvertes — l'est
/// désormais sur ce couple.
///
/// Sans lui, connecter une seconde tenancy ÉCRASAIT la première : même clé de
/// trousseau, même entrée dans la table des connexions. Le parc réparti sur
/// plusieurs comptes ne pouvait donc jamais être rapproché en entier, et les
/// machines de la tenancy absente apparaissaient « sans instance » en
/// permanence — ce qui ressemble à un inventaire faux.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId {
    pub provider: ProviderKind,
    /// Nom court choisi par l'opérateur : `default`, `acme`, `perso`.
    pub name: String,
}

/// Nom du compte créé quand l'opérateur n'en désigne aucun, et nom sous lequel
/// les identifiants d'une version antérieure sont repris.
pub const DEFAULT_ACCOUNT: &str = "default";

impl AccountId {
    pub fn new(provider: ProviderKind, name: &str) -> AccountId {
        AccountId {
            provider,
            name: normalize_account_name(name),
        }
    }

    pub fn default_for(provider: ProviderKind) -> AccountId {
        AccountId::new(provider, DEFAULT_ACCOUNT)
    }

    /// Clé de stockage. Le `:` ne peut pas apparaître dans un nom normalisé,
    /// la clé est donc sans ambiguïté.
    pub fn storage_key(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.name)
    }

    pub fn parse_storage_key(key: &str) -> Option<AccountId> {
        let (provider, name) = key.split_once(':')?;
        let provider = ProviderKind::ALL
            .into_iter()
            .find(|p| p.as_str() == provider)?;
        Some(AccountId {
            provider,
            name: name.to_string(),
        })
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} · {}", self.provider, self.name)
    }
}

/// Réduit un nom saisi à ce qui peut servir de clé.
///
/// Les noms viennent d'un formulaire : « Acme Prod », « acme prod » et
/// « ACME-PROD » désigneraient trois comptes distincts là où l'opérateur n'en
/// voit qu'un. Un nom vide retombe sur `default` plutôt que de produire une
/// clé qui ne se rattache à rien.
pub fn normalize_account_name(raw: &str) -> String {
    let slug: String = raw
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();

    let slug = slug.trim_matches('-').to_string();
    // Les séparateurs consécutifs viennent des espaces multiples.
    let mut out = String::with_capacity(slug.len());
    let mut previous_dash = false;
    for c in slug.chars() {
        if c == '-' {
            if !previous_dash {
                out.push(c);
            }
            previous_dash = true;
        } else {
            out.push(c);
            previous_dash = false;
        }
    }

    if out.is_empty() {
        DEFAULT_ACCOUNT.to_string()
    } else {
        out
    }
}

/// Désignation complète d'une instance chez son hébergeur.
///
/// La `zone` est ce qui manquait au prototype. Elle est `Option` parce que tous
/// les hébergeurs n'en ont pas — OVH et Contabo raisonnent par région.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceRef {
    pub provider: ProviderKind,
    /// Compte d'où vient l'instance. Posé par le hub après listage : un
    /// provider ne sait pas sous quel nom on l'a enregistré, et le lui faire
    /// porter obligerait les six implémentations à s'en souvenir.
    ///
    /// C'est ce qui permet de router une action d'alimentation vers LA bonne
    /// connexion quand deux tenancies sont ouvertes.
    #[serde(default = "default_account_name")]
    pub account: String,
    pub id: String,
    pub zone: Option<String>,
    pub region: String,
}

fn default_account_name() -> String {
    DEFAULT_ACCOUNT.to_string()
}

impl InstanceRef {
    pub fn account_id(&self) -> AccountId {
        AccountId {
            provider: self.provider,
            name: self.account.clone(),
        }
    }
}

/// État d'alimentation, normalisé. Les libellés bruts diffèrent d'un hébergeur
/// à l'autre (`RUNNING`, `running`, `ACTIVE`, `provisioning`…) et les comparer
/// tels quels dans l'UI reviendrait à y remettre la logique de chacun.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PowerState {
    Running,
    Stopped,
    /// Transitoire : démarrage, arrêt, provisionnement.
    Transitioning,
    Unknown,
}

impl PowerState {
    /// Normalise un état brut. Tout ce qui n'est pas reconnu reste `Unknown`
    /// plutôt que d'être rangé arbitrairement : un état inconnu affiché comme
    /// « arrêté » ferait relancer une machine qui tourne.
    pub fn parse(raw: &str) -> PowerState {
        match raw.trim().to_ascii_uppercase().as_str() {
            "RUNNING" | "ACTIVE" | "STARTED" | "OK" => PowerState::Running,
            "STOPPED" | "SHUTOFF" | "TERMINATED" | "SUSPENDED" | "OFF" => PowerState::Stopped,
            "PROVISIONING" | "STARTING" | "STOPPING" | "STAGING" | "PENDING"
            | "SHUTTING-DOWN" | "REBOOTING" | "INSTALLING" | "BUILD" => PowerState::Transitioning,
            _ => PowerState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub reference: InstanceRef,
    pub name: String,
    pub state: PowerState,
    /// Libellé brut de l'hébergeur, conservé pour l'affichage détaillé.
    pub raw_state: String,
    /// Gabarit : `VM.Standard.E4.Flex`, `t3.micro`, `e2-medium`, `V5`…
    pub shape: String,
    /// Adresses connues. Le rapprochement avec l'inventaire se fait dessus,
    /// une machine pouvant exposer une IP publique et une privée.
    pub addresses: Vec<String>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl Instance {
    /// L'instance porte-t-elle cette adresse ? Base de la jointure
    /// `(provider, adresse)` entre le cloud et l'inventaire Ansible.
    pub fn has_address(&self, address: &str) -> bool {
        self.addresses.iter().any(|a| a == address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerAction {
    Start,
    Stop { graceful: bool },
    Reboot { graceful: bool },
}

impl PowerAction {
    pub fn label(self) -> &'static str {
        match self {
            PowerAction::Start => "démarrage",
            PowerAction::Stop { graceful: false } => "arrêt forcé",
            PowerAction::Stop { graceful: true } => "arrêt gracieux",
            PowerAction::Reboot { graceful: false } => "redémarrage forcé",
            PowerAction::Reboot { graceful: true } => "redémarrage gracieux",
        }
    }
}

/// Ce qu'un hébergeur sait réellement faire.
///
/// Déclaré, jamais supposé : l'UI grise ce qui n'existe pas plutôt que de
/// proposer une action qui échouera ou, pire, en réalisera une autre. OVH et
/// Contabo n'ont qu'un `/stop` et qu'un `/reboot` — annoncer l'arrêt gracieux
/// chez eux, comme le faisait la matrice de `FEATURES.md`, était faux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub list: bool,
    pub describe: bool,
    pub start: bool,
    pub stop: bool,
    pub stop_graceful: bool,
    pub reboot: bool,
    pub reboot_graceful: bool,
}

impl Capabilities {
    /// Aucune capacité — le cas de `custom`, qui n'a pas d'API.
    pub const NONE: Capabilities = Capabilities {
        list: false,
        describe: false,
        start: false,
        stop: false,
        stop_graceful: false,
        reboot: false,
        reboot_graceful: false,
    };

    /// Alimentation complète, arrêt et redémarrage gracieux compris.
    pub const FULL: Capabilities = Capabilities {
        list: true,
        describe: true,
        start: true,
        stop: true,
        stop_graceful: true,
        reboot: true,
        reboot_graceful: true,
    };

    /// Alimentation sans variante gracieuse — un seul `/stop`, un seul
    /// `/reboot`.
    pub const HARD_ONLY: Capabilities = Capabilities {
        list: true,
        describe: true,
        start: true,
        stop: true,
        stop_graceful: false,
        reboot: true,
        reboot_graceful: false,
    };

    pub fn allows(&self, action: PowerAction) -> bool {
        match action {
            PowerAction::Start => self.start,
            PowerAction::Stop { graceful: false } => self.stop,
            PowerAction::Stop { graceful: true } => self.stop_graceful,
            PowerAction::Reboot { graceful: false } => self.reboot,
            PowerAction::Reboot { graceful: true } => self.reboot_graceful,
        }
    }
}

/// Méthode d'authentification retenue et ses champs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    pub method: String,
    pub fields: HashMap<String, String>,
}

/// Champ posé par une reconnexion AUTOMATIQUE (lancement d'une façade) : la
/// tentative ne doit jamais ouvrir de navigateur. Jamais enregistré.
pub const NO_BROWSER: &str = "FLEETFORGE_NO_BROWSER";

impl Credentials {
    /// Ces identifiants servent à une reconnexion silencieuse : un fournisseur
    /// qui devrait ouvrir un navigateur pour aboutir renonce à la place.
    pub fn without_browser(mut self) -> Credentials {
        self.fields.insert(NO_BROWSER.to_string(), "1".to_string());
        self
    }

    pub fn forbids_browser(&self) -> bool {
        self.fields.contains_key(NO_BROWSER)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str).filter(|s| !s.is_empty())
    }

    pub fn require(&self, key: &str) -> Result<&str> {
        self.get(key)
            .ok_or_else(|| ProviderError::Auth(format!("champ `{key}` manquant")))
    }
}

/// Une méthode d'authentification proposée par un hébergeur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    pub name: String,
    pub label: String,
    pub fields: Vec<AuthField>,
    /// Détectée sur cette machine (fichier de configuration présent, variables
    /// d'environnement définies, CLI installé).
    pub detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthField {
    pub key: String,
    pub label: String,
    /// Masqué à la saisie et jamais réaffiché.
    pub secret: bool,
    /// Où trouver la valeur, ou quelle forme elle prend. Vide = rien à dire.
    ///
    /// L'indication vit ICI et non dans chaque façade : le GUI, le serveur web
    /// et le TUI affichent le même formulaire, et une aide recopiée trois fois
    /// n'est corrigée qu'une fois sur trois. C'est aussi le seul endroit qui
    /// sait vraiment ce que le provider attend.
    #[serde(default)]
    pub hint: String,
    /// Le champ peut rester vide — l'hébergeur a un défaut utilisable.
    #[serde(default)]
    pub optional: bool,
}

impl AuthField {
    pub fn new(key: &str, label: &str) -> AuthField {
        // Le prototype décidait du masquage en cherchant PASSWORD/SECRET/KEY
        // dans le nom du champ ; un champ nommé autrement s'affichait en clair.
        AuthField {
            key: key.to_string(),
            label: label.to_string(),
            secret: false,
            hint: String::new(),
            optional: false,
        }
    }

    pub fn secret(key: &str, label: &str) -> AuthField {
        AuthField {
            key: key.to_string(),
            label: label.to_string(),
            secret: true,
            hint: String::new(),
            optional: false,
        }
    }

    pub fn hint(mut self, hint: &str) -> AuthField {
        self.hint = hint.to_string();
        self
    }

    /// Facultatif : le formulaire le signale et n'en bloque pas l'envoi.
    pub fn optional(mut self) -> AuthField {
        self.optional = true;
        self
    }
}

/// Une commande de session qu'un hébergeur propose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAction {
    pub name: String,
    pub label: String,
    /// Ce que l'action fait, et quand elle ne peut plus rien.
    pub hint: String,
    /// Exige un navigateur SUR LA MACHINE QUI EXÉCUTE.
    ///
    /// `oci session authenticate` ouvre un navigateur et attend la redirection
    /// OAuth sur `http://localhost:8181` : le processus et le navigateur
    /// doivent être sur la même machine. Une façade servie à distance — ou un
    /// TUI joint en SSH — ouvrirait ce navigateur sur le SERVEUR et attendrait
    /// une personne que personne ne peut être.
    ///
    /// C'est donc à chaque façade de décider si elle l'offre ; le cœur se
    /// contente de dire ce qu'elle exige.
    #[serde(default)]
    pub needs_local_browser: bool,
}

impl SessionAction {
    pub fn new(name: &str, label: &str, hint: &str) -> SessionAction {
        SessionAction {
            name: name.to_string(),
            label: label.to_string(),
            hint: hint.to_string(),
            needs_local_browser: false,
        }
    }

    pub fn needing_browser(mut self) -> SessionAction {
        self.needs_local_browser = true;
        self
    }
}

/// Le processus courant peut-il ouvrir un navigateur utile à l'opérateur ?
///
/// Faux dès qu'on est arrivé par SSH : le navigateur s'ouvrirait sur la machine
/// distante, et la redirection OAuth viserait le `localhost` de CETTE machine,
/// pas celui du poste devant lequel se trouve l'opérateur.
///
/// Vit dans le cœur plutôt que dans le TUI : le serveur web s'en sert aussi,
/// et deux définitions de « suis-je local ? » finiraient par diverger.
pub fn has_local_browser() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .all(|k| std::env::var(k).is_err())
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn kind(&self) -> ProviderKind;

    fn capabilities(&self) -> Capabilities;

    /// Méthodes d'authentification, dans l'ordre de préférence.
    ///
    /// L'ordre est explicite : le prototype prenait `methods[0]`, si bien que
    /// l'ordre de détection décidait en silence quelle identité était utilisée.
    fn auth_methods(&self) -> Vec<AuthMethod>;

    async fn connect(&mut self, credentials: &Credentials) -> Result<()>;

    fn is_connected(&self) -> bool;

    fn disconnect(&mut self);

    async fn list_instances(&self) -> Result<Vec<Instance>>;

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance>;

    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()>;

    /// Requête légère qui empêche l'expiration de session.
    async fn keepalive(&self) -> Result<()> {
        Ok(())
    }

    /// Commandes de session proposées. Vide par défaut : la plupart des
    /// hébergeurs s'authentifient par clé, qui n'expire pas d'elle-même.
    fn session_actions(&self) -> Vec<SessionAction> {
        Vec::new()
    }

    /// Exécute l'une d'elles. Rend ce qu'il faut afficher à l'opérateur.
    async fn run_session_action(&self, name: &str) -> Result<String> {
        Err(ProviderError::Unsupported {
            provider: self.kind(),
            action: "commande de session",
        })
        .map_err(|e: ProviderError| {
            ProviderError::Api(format!("{e} : « {name} » inconnue"))
        })
    }

    /// Vérifie la capacité AVANT d'appeler l'API. Sans ce garde-fou, un
    /// `Stop { graceful: true }` chez OVH partirait en arrêt brutal.
    fn ensure_allows(&self, action: PowerAction) -> Result<()> {
        if self.capabilities().allows(action) {
            Ok(())
        } else {
            Err(ProviderError::Unsupported {
                provider: self.kind(),
                action: action.label(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_power_state_is_not_guessed() {
        // Ranger un état inconnu dans « arrêté » ferait relancer une machine
        // qui tourne déjà.
        assert_eq!(PowerState::parse("RUNNING"), PowerState::Running);
        assert_eq!(PowerState::parse("running"), PowerState::Running);
        assert_eq!(PowerState::parse("STOPPED"), PowerState::Stopped);
        assert_eq!(PowerState::parse("PROVISIONING"), PowerState::Transitioning);
        assert_eq!(PowerState::parse("bizarre"), PowerState::Unknown);
    }

    #[test]
    fn hard_only_refuses_the_graceful_variants() {
        let c = Capabilities::HARD_ONLY;
        assert!(c.allows(PowerAction::Stop { graceful: false }));
        assert!(!c.allows(PowerAction::Stop { graceful: true }));
        assert!(c.allows(PowerAction::Reboot { graceful: false }));
        assert!(!c.allows(PowerAction::Reboot { graceful: true }));
    }

    #[test]
    fn no_capability_allows_nothing() {
        for action in [
            PowerAction::Start,
            PowerAction::Stop { graceful: false },
            PowerAction::Reboot { graceful: true },
        ] {
            assert!(!Capabilities::NONE.allows(action));
        }
    }

    #[test]
    fn an_instance_matches_any_of_its_addresses() {
        let i = Instance {
            reference: InstanceRef {
                account: "default".into(),
                provider: ProviderKind::Contabo,
                id: "1".into(),
                zone: None,
                region: "EU".into(),
            },
            name: "n".into(),
            state: PowerState::Running,
            raw_state: "running".into(),
            shape: "V5".into(),
            addresses: vec!["203.0.113.10".into(), "10.0.0.1".into()],
            tags: HashMap::new(),
        };
        assert!(i.has_address("10.0.0.1"));
        assert!(!i.has_address("1.2.3.4"));
    }

    #[test]
    fn a_missing_credential_field_is_named() {
        let c = Credentials::default();
        let err = c.require("CONTABO_CLIENT_ID").unwrap_err();
        assert!(err.to_string().contains("CONTABO_CLIENT_ID"));
    }
}
