/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Hébergeurs pilotés par leur CLI officiel — AWS, GCP, Oracle.
//!
//! Ces trois-là exigent respectivement SigV4, un JWT de compte de service et la
//! signature RSA-SHA256 d'OCI. Les réimplémenter représenterait plusieurs
//! centaines de lignes de code cryptographique impossible à valider sans
//! identifiants réels, alors que leur CLI officiel gère déjà l'authentification,
//! le SSO, les jetons de session et leur rafraîchissement.
//!
//! On délègue donc, et l'absence du binaire devient une CAPACITÉ manquante,
//! visible dans l'UI, plutôt qu'une erreur au premier appel.

use crate::provider::*;
use async_trait::async_trait;
use fleetforge_core::model::ProviderKind;
use serde_json::Value;
use std::collections::HashMap;
use std::process::{Command, Stdio};

pub fn which(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extrait d'un flux d'erreur ce qui désigne VRAIMENT la cause.
///
/// Les CLI d'hébergeur sont des programmes Python, et Python écrit ses
/// avertissements de compilation sur stderr, avant toute exécution :
///
/// ```text
/// …/oci_cli_compute/compute_cli_extended.py:25: SyntaxWarning: "\." is an
///   INSTANCE_CONSOLE_CONNECTION_STRING_INTERMEDIATE_HOST_REGEX = "(…)"
/// ERROR: The config file at ~/.oci/config is invalid: user missing
/// ```
///
/// Rendre stderr tel quel mettait ces deux lignes EN TÊTE du message. Dans une
/// barre d'état, la cause réelle passait hors de l'écran — on lisait un chemin
/// vers du code Python, ce qui envoie chercher le défaut dans l'outil plutôt
/// que dans sa configuration.
///
/// `PYTHONWARNINGS=ignore` les supprime à la source ; ce filtre reste pour les
/// avertissements qu'un CLI émet lui-même, hors du mécanisme de Python.
fn meaningful_error(stderr: &str) -> String {
    let kept: Vec<&str> = stderr
        .lines()
        .map(str::trim_end)
        .filter(|line| !is_noise(line))
        .collect();

    // Rien d'autre que du bruit : mieux vaut tout rendre que rien.
    if kept.iter().all(|l| l.trim().is_empty()) {
        return stderr.trim().to_string();
    }

    kept.join("\n").trim().to_string()
}

fn is_noise(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    // « fichier.py:25: SyntaxWarning: … », et la ligne de source qui la suit,
    // qui commence par un retrait.
    if trimmed.contains("Warning:") && (trimmed.contains(".py:") || trimmed.starts_with("/")) {
        return true;
    }
    // Ligne de code recopiée sous l'avertissement : indentée dans l'original.
    line.starts_with("  ") && !trimmed.starts_with("ERROR") && trimmed.ends_with("# noqa: W605")
}

/// Exécute une commande et rend sa sortie JSON.
fn run_json(tool: &str, args: &[&str], install: &str) -> Result<Value> {
    if !which(tool) {
        return Err(ProviderError::MissingCli {
            tool: tool.to_string(),
            install: install.to_string(),
        });
    }

    let out = Command::new(tool)
        .args(args)
        // Entrée standard FERMÉE. Sans cela le processus hérite du terminal —
        // qui, sous le TUI, est en mode brut : un CLI qui pose une question
        // (« session expirée, se ré-authentifier ? [Y/n] ») consommerait les
        // frappes destinées à l'interface, ou attendrait indéfiniment une
        // réponse que personne ne peut voir qu'il demande. Avec /dev/null il
        // reçoit EOF et rend la main tout de suite.
        .stdin(Stdio::null())
        // Les CLI d'hébergeur sont écrits en Python et leurs avertissements de
        // compilation partent sur stderr, où nous lisons la cause de l'échec.
        .env("PYTHONWARNINGS", "ignore")
        .output()
        .map_err(|e| ProviderError::Api(format!("{tool} : {e}")))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);

        // La COMMANDE et son stderr INTÉGRAL vont au journal. C'est ce qui
        // manquait : une barre d'état tronque, et le message assaini ci-dessous
        // écarte volontairement des lignes qui peuvent se révéler utiles quand
        // on cherche vraiment. Les arguments ne portent pas de secret — les
        // identifiants des CLI vivent dans leurs propres fichiers de
        // configuration, jamais sur la ligne de commande.
        fleetforge_core::logging::error(
            tool,
            format!(
                "`{tool} {}` → code {} ; stderr : {}",
                args.join(" "),
                out.status.code().unwrap_or(-1),
                stderr.trim()
            ),
        );

        let msg = meaningful_error(&stderr);
        let msg = msg.as_str();
        // Distinguer un refus d'authentification d'une panne d'API : le premier
        // se corrige en se reconnectant, le second non.
        let lowered = msg.to_ascii_lowercase();
        if lowered.contains("credential")
            || lowered.contains("not logged in")
            || lowered.contains("expired")
            || lowered.contains("unauthorized")
            || lowered.contains("authentication")
        {
            return Err(ProviderError::Auth(msg.to_string()));
        }
        if msg.is_empty() {
            return Err(ProviderError::Api(format!(
                "{tool} a échoué sans message (code {})",
                out.status.code().unwrap_or(-1)
            )));
        }
        return Err(ProviderError::Api(format!("{tool} a échoué : {msg}")));
    }

    if out.stdout.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&out.stdout).map_err(|e| {
        // Une sortie illisible est presque toujours du texte là où on attendait
        // du JSON — un avertissement, une bannière de connexion. Sans le début
        // de cette sortie au journal, le message ne dit que « illisible ».
        fleetforge_core::logging::error(
            tool,
            format!(
                "sortie non JSON de `{tool} {}` : {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout).chars().take(400).collect::<String>()
            ),
        );
        ProviderError::Api(format!("sortie de {tool} illisible : {e}"))
    })
}

fn run_ok(tool: &str, args: &[&str], install: &str) -> Result<()> {
    run_json(tool, args, install).map(|_| ())
}

/// Comme `run_json`, mais pour une commande qui ne rend PAS de JSON.
///
/// `oci session refresh` écrit un compte rendu en clair sur stderr et ne
/// produit rien sur stdout : le passer à `run_json` échouerait sur « sortie
/// illisible » alors que la commande a parfaitement fonctionné.
fn run_text(tool: &str, args: &[&str], install: &str) -> Result<String> {
    if !which(tool) {
        return Err(ProviderError::MissingCli {
            tool: tool.to_string(),
            install: install.to_string(),
        });
    }

    let out = Command::new(tool)
        .args(args)
        .stdin(Stdio::null())
        .env("PYTHONWARNINGS", "ignore")
        .output()
        .map_err(|e| ProviderError::Api(format!("{tool} : {e}")))?;

    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        fleetforge_core::logging::error(
            tool,
            format!(
                "`{tool} {}` → code {} ; stderr : {}",
                args.join(" "),
                out.status.code().unwrap_or(-1),
                stderr.trim()
            ),
        );
        return Err(ProviderError::Api(format!(
            "{tool} a échoué : {}",
            meaningful_error(&stderr)
        )));
    }

    fleetforge_core::logging::info(tool, format!("`{tool} {}` → ok", args.join(" ")));
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ============================ AWS ============================

/// EC2 : arrêt à deux variantes (`--force` ou non), redémarrage à une seule,
/// propre. Nommée pour être confrontée au `match` de `power` par un test, que
/// le CLI `aws` soit installé ou non sur la machine qui le joue.
pub const AWS_CAPS: Capabilities = Capabilities {
    list: true,
    describe: true,
    start: true,
    stop: true,
    stop_graceful: true,
    reboot: false,
    reboot_graceful: true,
};

/// Compute Engine : une variante de chaque, et ce ne sont pas les mêmes —
/// `stop` est propre, `reset` est une coupure.
pub const GCP_CAPS: Capabilities = Capabilities {
    list: true,
    describe: true,
    start: true,
    stop: false,
    stop_graceful: true,
    reboot: true,
    reboot_graceful: false,
};

pub struct AwsProvider {
    region: Option<String>,
    connected: bool,
}

const AWS_INSTALL: &str = "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html";

impl Default for AwsProvider {
    fn default() -> Self {
        Self { region: None, connected: false }
    }
}

impl AwsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    fn base_args<'a>(&'a self, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args: Vec<&str> = vec!["ec2"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--output", "json"]);
        if let Some(r) = &self.region {
            args.extend_from_slice(&["--region", r.as_str()]);
        }
        args
    }
}

fn aws_instance(inst: &Value, region: &str) -> Instance {
    let raw_state = inst
        .get("State")
        .and_then(|s| s.get("Name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let tags: HashMap<String, String> = inst
        .get("Tags")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    Some((
                        t.get("Key")?.as_str()?.to_string(),
                        t.get("Value")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let id = inst
        .get("InstanceId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let mut addresses = Vec::new();
    for key in ["PublicIpAddress", "PrivateIpAddress"] {
        if let Some(ip) = inst.get(key).and_then(|v| v.as_str()) {
            addresses.push(ip.to_string());
        }
    }

    // La zone porte la région en préfixe (`eu-west-3a`) ; elle est nécessaire
    // pour tout ce qui suit et doit donc voyager dans la référence.
    let zone = inst
        .get("Placement")
        .and_then(|p| p.get("AvailabilityZone"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Instance {
        reference: InstanceRef {
            // Posé par le hub après listage, qui seul connaît le compte.
            account: crate::provider::DEFAULT_ACCOUNT.to_string(),
            provider: ProviderKind::Aws,
            id: id.clone(),
            zone,
            region: region.to_string(),
        },
        name: tags.get("Name").cloned().unwrap_or_else(|| id.clone()),
        state: PowerState::parse(&raw_state),
        raw_state,
        shape: inst
            .get("InstanceType")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        addresses,
        tags,
    }
}

#[async_trait]
impl Provider for AwsProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Aws
    }

    /// EC2 distingue l'arrêt forcé (`--force`) de l'arrêt ordinaire, qui laisse
    /// l'OS s'éteindre — la variante gracieuse existe donc réellement.
    ///
    /// Le redémarrage, lui, n'en a qu'une : `reboot-instances` demande un
    /// redémarrage propre à l'OS. Déclarer `reboot` (la variante brutale)
    /// promettrait une coupure qui n'aurait pas lieu.
    fn capabilities(&self) -> Capabilities {
        if which("aws") {
            AWS_CAPS
        } else {
            Capabilities::NONE
        }
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        let home = dirs_home();
        vec![
            AuthMethod {
                name: "cli".into(),
                label: "Configuration AWS CLI (profil, SSO)".into(),
                detected: which("aws")
                    && (home.join(".aws/credentials").exists()
                        || home.join(".aws/config").exists()),
                fields: vec![
                    AuthField::new("AWS_PROFILE", "Profil")
                        .hint("Un profil de ~/.aws/credentials. Vide = `default`.")
                        .optional(),
                    AuthField::new("AWS_REGION", "Région")
                        .hint("ex. eu-west-3. AWS liste par région : sans elle, les instances des autres régions restent invisibles."),
                ],
            },
            AuthMethod {
                name: "env".into(),
                label: "Clés d'accès IAM".into(),
                detected: std::env::var("AWS_ACCESS_KEY_ID").is_ok(),
                fields: vec![
                    AuthField::new("AWS_ACCESS_KEY_ID", "Access key ID")
                        .hint("Console IAM → Utilisateurs → Security credentials → Create access key. Commence par AKIA."),
                    AuthField::secret("AWS_SECRET_ACCESS_KEY", "Secret access key")
                        .hint("Montré UNE seule fois, à la création de la clé. Perdu, il faut en créer une autre."),
                    AuthField::new("AWS_REGION", "Région")
                        .hint("ex. eu-west-3."),
                ],
            },
        ]
    }

    async fn connect(&mut self, credentials: &Credentials) -> Result<()> {
        if !which("aws") {
            return Err(ProviderError::MissingCli {
                tool: "aws".into(),
                install: AWS_INSTALL.into(),
            });
        }
        // AWS liste par région : sans région, l'appel porterait sur celle du
        // profil par défaut, qui n'est pas forcément celle qu'on regarde.
        self.region = credentials
            .get("AWS_REGION")
            .map(String::from)
            .or_else(|| std::env::var("AWS_REGION").ok().filter(|v| !v.is_empty()));

        // Un appel réel vaut mieux qu'une présomption : `sts get-caller-identity`
        // échoue immédiatement si l'identité n'est pas utilisable.
        run_json("aws", &["sts", "get-caller-identity", "--output", "json"], AWS_INSTALL)?;
        self.connected = true;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }

    async fn list_instances(&self) -> Result<Vec<Instance>> {
        let region = self.region.clone().unwrap_or_default();
        let body = run_json("aws", &self.base_args(&["describe-instances"]), AWS_INSTALL)?;

        Ok(body
            .get("Reservations")
            .and_then(|r| r.as_array())
            .map(|res| {
                res.iter()
                    .filter_map(|r| r.get("Instances").and_then(|i| i.as_array()))
                    .flatten()
                    .map(|i| aws_instance(i, &region))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance> {
        let body = run_json(
            "aws",
            &self.base_args(&["describe-instances", "--instance-ids", &reference.id]),
            AWS_INSTALL,
        )?;
        body.get("Reservations")
            .and_then(|r| r.as_array())
            .and_then(|res| res.first())
            .and_then(|r| r.get("Instances"))
            .and_then(|i| i.as_array())
            .and_then(|a| a.first())
            .map(|i| aws_instance(i, &reference.region))
            .ok_or_else(|| ProviderError::Api(format!("instance {} introuvable", reference.id)))
    }

    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        self.ensure_allows(action)?;
        let id = reference.id.as_str();
        match action {
            PowerAction::Start => run_ok(
                "aws",
                &self.base_args(&["start-instances", "--instance-ids", id]),
                AWS_INSTALL,
            ),
            PowerAction::Stop { graceful } => {
                let mut args = self.base_args(&["stop-instances", "--instance-ids", id]);
                if !graceful {
                    args.push("--force");
                }
                run_ok("aws", &args, AWS_INSTALL)
            }
            // EC2 n'a qu'un `reboot-instances`, qui est un redémarrage propre.
            PowerAction::Reboot { .. } => run_ok(
                "aws",
                &self.base_args(&["reboot-instances", "--instance-ids", id]),
                AWS_INSTALL,
            ),
        }
    }

    async fn keepalive(&self) -> Result<()> {
        run_ok("aws", &["sts", "get-caller-identity", "--output", "json"], AWS_INSTALL)
    }
}

// ============================ GCP ============================

pub struct GcpProvider {
    project: Option<String>,
    connected: bool,
}

const GCLOUD_INSTALL: &str = "https://cloud.google.com/sdk/docs/install";

impl Default for GcpProvider {
    fn default() -> Self {
        Self { project: None, connected: false }
    }
}

impl GcpProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

fn gcp_instance(inst: &Value) -> Instance {
    let raw_state = inst
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // `zone` est une URL complète ; seul le dernier segment est utilisable.
    let zone = inst
        .get("zone")
        .and_then(|v| v.as_str())
        .and_then(|z| z.rsplit('/').next())
        .map(String::from);

    // La région se déduit de la zone : `europe-west1-b` → `europe-west1`.
    let region = zone
        .as_deref()
        .and_then(|z| z.rsplit_once('-').map(|(head, _)| head.to_string()))
        .unwrap_or_default();

    let mut addresses = Vec::new();
    if let Some(nics) = inst.get("networkInterfaces").and_then(|v| v.as_array()) {
        for nic in nics {
            if let Some(ip) = nic.get("networkIP").and_then(|v| v.as_str()) {
                addresses.push(ip.to_string());
            }
            if let Some(configs) = nic.get("accessConfigs").and_then(|v| v.as_array()) {
                for c in configs {
                    if let Some(ip) = c.get("natIP").and_then(|v| v.as_str()) {
                        addresses.push(ip.to_string());
                    }
                }
            }
        }
    }

    let tags: HashMap<String, String> = inst
        .get("labels")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default();

    Instance {
        reference: InstanceRef {
            // Posé par le hub après listage, qui seul connaît le compte.
            account: crate::provider::DEFAULT_ACCOUNT.to_string(),
            provider: ProviderKind::Gcp,
            id: inst
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            // LA correction : sans la zone, `start`/`stop`/`reboot` étaient
            // impossibles et GCP restait en lecture seule.
            zone,
            region,
        },
        name: inst
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        state: PowerState::parse(&raw_state),
        raw_state,
        shape: inst
            .get("machineType")
            .and_then(|v| v.as_str())
            .and_then(|m| m.rsplit('/').next())
            .unwrap_or("unknown")
            .to_string(),
        addresses,
        tags,
    }
}

impl GcpProvider {
    fn zone_of(reference: &InstanceRef) -> Result<&str> {
        reference.zone.as_deref().ok_or_else(|| {
            ProviderError::Api(format!(
                "zone inconnue pour {} — l'action GCP l'exige",
                reference.id
            ))
        })
    }
}

#[async_trait]
impl Provider for GcpProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Gcp
    }

    /// Compute Engine a exactement une variante de chaque : `stop` éteint
    /// proprement, `reset` coupe l'alimentation. Il n'y a NI arrêt brutal, NI
    /// redémarrage propre atomique.
    ///
    /// La déclaration précédente annonçait les quatre. `reboot_graceful` était
    /// donc accepté par `ensure_allows` et retombait sur `reset` : l'interface
    /// envoie `graceful` dès que la capacité est déclarée, si bien qu'un clic
    /// sur « redémarrer » coupait le courant sous une machine qu'on croyait
    /// redémarrer proprement — écritures disque non vidées comprises.
    fn capabilities(&self) -> Capabilities {
        if which("gcloud") {
            GCP_CAPS
        } else {
            Capabilities::NONE
        }
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        let home = dirs_home();
        vec![
            AuthMethod {
                name: "gcloud".into(),
                label: "Session gcloud".into(),
                detected: which("gcloud") && home.join(".config/gcloud").exists(),
                fields: vec![AuthField::new("GCP_PROJECT", "Projet")
                    .hint("L'ID du projet, pas son nom d'affichage — `gcloud projects list` donne les deux.")],
            },
            AuthMethod {
                name: "service_account".into(),
                label: "Compte de service (fichier JSON)".into(),
                detected: std::env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok(),
                fields: vec![
                    AuthField::new("GOOGLE_APPLICATION_CREDENTIALS", "Chemin de la clé JSON")
                        .hint("Chemin ABSOLU sur cette machine. IAM → Comptes de service → Clés → Ajouter une clé (JSON)."),
                    AuthField::new("GCP_PROJECT", "Projet")
                        .hint("L'ID du projet, pas son nom d'affichage."),
                ],
            },
        ]
    }

    async fn connect(&mut self, credentials: &Credentials) -> Result<()> {
        if !which("gcloud") {
            return Err(ProviderError::MissingCli {
                tool: "gcloud".into(),
                install: GCLOUD_INSTALL.into(),
            });
        }
        self.project = credentials
            .get("GCP_PROJECT")
            .map(String::from)
            .or_else(|| std::env::var("GCP_PROJECT").ok().filter(|v| !v.is_empty()));

        run_json(
            "gcloud",
            &["auth", "list", "--format=json"],
            GCLOUD_INSTALL,
        )?;
        self.connected = true;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }

    async fn list_instances(&self) -> Result<Vec<Instance>> {
        let mut args: Vec<&str> = vec!["compute", "instances", "list", "--format=json"];
        if let Some(p) = &self.project {
            args.push("--project");
            args.push(p);
        }
        let body = run_json("gcloud", &args, GCLOUD_INSTALL)?;
        Ok(body
            .as_array()
            .map(|arr| arr.iter().map(gcp_instance).collect())
            .unwrap_or_default())
    }

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance> {
        let zone = Self::zone_of(reference)?;
        let body = run_json(
            "gcloud",
            &[
                "compute",
                "instances",
                "describe",
                &reference.id,
                "--zone",
                zone,
                "--format=json",
            ],
            GCLOUD_INSTALL,
        )?;
        Ok(gcp_instance(&body))
    }

    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        self.ensure_allows(action)?;
        let zone = Self::zone_of(reference)?;
        // `ensure_allows` a déjà écarté `Stop { graceful: false }` et
        // `Reboot { graceful: true }`, que Compute Engine ne sait pas faire.
        let verb = match action {
            PowerAction::Start => "start",
            PowerAction::Stop { .. } => "stop",
            PowerAction::Reboot { .. } => "reset",
        };
        run_ok(
            "gcloud",
            &[
                "compute",
                "instances",
                verb,
                &reference.id,
                "--zone",
                zone,
                "--format=json",
                "--quiet",
            ],
            GCLOUD_INSTALL,
        )
    }
}

// ============================ Oracle ============================

pub struct OracleProvider {
    compartment: Option<String>,
    profile: Option<String>,
    /// Comment ce profil s'authentifie, lu dans `~/.oci/config`.
    session: bool,
    connected: bool,
}

const OCI_INSTALL: &str = "https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm";

impl Default for OracleProvider {
    fn default() -> Self {
        Self {
            compartment: None,
            profile: None,
            session: false,
            connected: false,
        }
    }
}

/// Un profil de `~/.oci/config` s'authentifie-t-il par JETON DE SESSION ?
///
/// Les deux modes coexistent et ne se pilotent pas pareil :
///
/// - **clé d'API** — le profil porte `user`, `fingerprint`, `key_file` ;
/// - **session** (`oci session authenticate`) — il porte `security_token_file`
///   et PAS de `user`. Le CLI exige alors `--auth security_token`.
///
/// Sans ce drapeau, le CLI retombe sur le mode par clé et se plaint que `user`
/// manque — ce qui envoie ajouter à la main un champ qu'une session n'a pas, et
/// n'a donc aucune chance d'aboutir.
fn oci_profile_uses_session(profile: &str) -> bool {
    oci_profile_key(profile, "security_token_file").is_some()
}

/// Lit une clé d'un profil de `~/.oci/config`.
///
/// `region` sert à relancer une session : `oci session authenticate` l'exige,
/// et la redemander à l'opérateur alors qu'elle est écrite là serait lui faire
/// ressaisir ce que la machine sait déjà.
fn oci_profile_key(profile: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(dirs_home().join(".oci/config")).ok()?;
    let wanted = if profile.trim().is_empty() { "DEFAULT" } else { profile.trim() };
    let mut in_section = false;

    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = name.trim() == wanted;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                return (!v.is_empty()).then(|| v.to_string());
            }
        }
    }
    None
}

impl OracleProvider {
    pub fn new() -> Self {
        Self::default()
    }

    fn profile_name(&self) -> &str {
        self.profile.as_deref().unwrap_or("DEFAULT")
    }

    fn oci_refresh(&self) -> Result<String> {
        // `--auth security_token` n'est PAS passé : `session refresh` agit sur
        // le profil, pas sur une requête authentifiée, et le drapeau le ferait
        // échouer.
        let mut args: Vec<&str> = vec!["session", "refresh"];
        if let Some(p) = &self.profile {
            args.extend_from_slice(&["--profile", p.as_str()]);
        }

        // La sortie utile part sur stderr et le code de retour suffit à
        // trancher : `run_json` attendrait du JSON là où il n'y en a pas.
        run_text("oci", &args, OCI_INSTALL)
            .map(|_| "session renouvelée".to_string())
            .map_err(|e| oci_auth_error(e, true))
    }

    /// Ouvre une session neuve, par le navigateur.
    ///
    /// La commande ouvre une page de connexion et ATTEND la redirection OAuth
    /// sur `http://localhost:8181` — donc sur la machine qui l'exécute. C'est
    /// ce qui la réserve aux façades locales, et pourquoi elle se déclare
    /// `needs_local_browser`.
    ///
    /// La région vient du profil : `oci session authenticate` l'exige, et la
    /// redemander alors qu'elle est écrite dans `~/.oci/config` ferait ressaisir
    /// ce que la machine sait déjà.
    ///
    /// `--no-browser` est volontairement absent : il emprunte un autre chemin,
    /// qui valide le profil par CLÉ D'API et échoue donc sur une configuration
    /// de session — « user missing », erreur qui ne désigne pas sa cause.
    async fn oci_authenticate(&self) -> Result<String> {
        let profile = self.profile_name().to_string();
        let region = oci_profile_key(&profile, "region").ok_or_else(|| {
            ProviderError::Auth(format!(
                "aucune `region` dans le profil [{profile}] de ~/.oci/config : \
                 `oci session authenticate` ne peut pas savoir où se connecter"
            ))
        })?;

        // Sur un fil dédié : la commande attend que l'opérateur se connecte
        // dans son navigateur, ce qui prend le temps qu'il faut. La laisser sur
        // l'exécuteur asynchrone y bloquerait un fil et figerait l'interface.
        tokio::task::spawn_blocking(move || {
            run_text(
                "oci",
                &[
                    "session",
                    "authenticate",
                    "--region",
                    &region,
                    "--profile-name",
                    &profile,
                ],
                OCI_INSTALL,
            )
            .map(|_| "session ouverte".to_string())
        })
        .await
        .map_err(|e| ProviderError::Api(format!("authentification interrompue : {e}")))?
    }

    /// Arguments communs à tout appel `oci` : le profil demandé et, pour une
    /// session, le mode d'authentification.
    fn base_args<'a>(&'a self, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args: Vec<&str> = Vec::new();
        args.extend_from_slice(extra);
        if let Some(p) = &self.profile {
            args.extend_from_slice(&["--profile", p.as_str()]);
        }
        if self.session {
            args.extend_from_slice(&["--auth", "security_token"]);
        }
        args
    }
}

fn oci_instance(inst: &Value) -> Instance {
    let raw_state = inst
        .get("lifecycle-state")
        .or_else(|| inst.get("lifecycleState"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let zone = inst
        .get("availability-domain")
        .or_else(|| inst.get("availabilityDomain"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Instance {
        reference: InstanceRef {
            // Posé par le hub après listage, qui seul connaît le compte.
            account: crate::provider::DEFAULT_ACCOUNT.to_string(),
            provider: ProviderKind::Oracle,
            id: inst.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            zone,
            region: inst
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        },
        name: inst
            .get("display-name")
            .or_else(|| inst.get("displayName"))
            .and_then(|v| v.as_str())
            .unwrap_or("sans nom")
            .to_string(),
        state: PowerState::parse(&raw_state),
        raw_state,
        shape: inst
            .get("shape")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        addresses: Vec::new(),
        tags: HashMap::new(),
    }
}

/// Traduit un échec du CLI `oci` en quelque chose d'actionnable.
///
/// Une session expire — une heure par défaut. Le CLI le signale en proposant
/// de se ré-authentifier, question à laquelle personne ne peut répondre depuis
/// un sous-processus : il rend alors « Abort: », qui ne désigne rien.
fn oci_auth_error(error: ProviderError, session: bool) -> ProviderError {
    let text = error.to_string();
    let lowered = text.to_ascii_lowercase();

    // « cannot be refreshed » : la fenêtre de renouvellement est passée, seule
    // une session neuve rouvrira l'accès. Le CLI le dit déjà, mais derrière une
    // ligne de progression (« Attempting to refresh token from … ») qui occupe
    // la barre d'état et repousse la consigne hors de l'écran.
    if session
        && (lowered.contains("expired")
            || lowered.contains("cannot be refreshed")
            || lowered.trim_end().ends_with("abort:"))
    {
        return ProviderError::Auth(
            // Ne PAS renvoyer vers `oci session refresh` : l'application le fait
            // elle-même, et si ce message apparaît c'est qu'il vient d'échouer.
            // Ne PAS renvoyer vers un terminal non plus : l'application ouvre
            // elle-même le navigateur sur la page de connexion, et le compte
            // garde cette commande justement parce que sa session est refusée.
            // Le message tient dans la barre d'état, qui tronque le reste.
            "session OCI expirée : ouvrir une session neuve (`s` dans le TUI, \
             « Session » dans l'interface)."
                .into(),
        );
    }

    if lowered.contains("user") && lowered.contains("missing") {
        return ProviderError::Auth(
            "profil OCI incomplet : `user` manque. Un profil par CLÉ D'API exige user + \
             fingerprint + key_file ; un profil de SESSION exige `security_token_file` \
             et se crée par `oci session authenticate`."
                .into(),
        );
    }

    error
}

#[async_trait]
impl Provider for OracleProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Oracle
    }

    fn capabilities(&self) -> Capabilities {
        if which("oci") {
            Capabilities::FULL
        } else {
            Capabilities::NONE
        }
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        let home = dirs_home();
        vec![AuthMethod {
            name: "config".into(),
            label: "Fichier ~/.oci/config".into(),
            detected: which("oci") && home.join(".oci/config").exists(),
            fields: vec![
                AuthField::new("OCI_PROFILE", "Profil")
                    .hint("Une section de ~/.oci/config. Vide = DEFAULT.")
                    .optional(),
                AuthField::new("OCI_COMPARTMENT", "Compartiment (OCID)")
                    .hint("ocid1.compartment.oc1..… — Console → Identité → Compartiments. Sans lui, seules les instances de la racine de la tenancy seraient listées."),
            ],
        }]
    }

    async fn connect(&mut self, credentials: &Credentials) -> Result<()> {
        if !which("oci") {
            return Err(ProviderError::MissingCli {
                tool: "oci".into(),
                install: OCI_INSTALL.into(),
            });
        }
        // Le prototype listait la seule racine de la tenancy : les instances
        // des sous-compartiments étaient invisibles. Le compartiment est donc
        // un paramètre explicite.
        self.compartment = credentials
            .get("OCI_COMPARTMENT")
            .map(String::from)
            .or_else(|| std::env::var("OCI_COMPARTMENT").ok().filter(|v| !v.is_empty()));

        if self.compartment.is_none() {
            return Err(ProviderError::Auth(
                "compartiment OCI requis : sans lui, seules les instances de la racine seraient listées".into(),
            ));
        }

        // `OCI_PROFILE` était collecté par le formulaire et n'était jamais
        // transmis au CLI : choisir un profil ne changeait rien.
        self.profile = credentials
            .get("OCI_PROFILE")
            .map(str::to_string)
            .or_else(|| std::env::var("OCI_PROFILE").ok().filter(|v| !v.is_empty()));

        self.session = oci_profile_uses_session(self.profile.as_deref().unwrap_or("DEFAULT"));

        // Vérifier MAINTENANT plutôt que de se déclarer connecté et d'échouer
        // au premier listage : l'erreur porterait alors sur « lister les
        // instances » et non sur l'authentification qui l'a causée.
        self.connected = true;
        if let Err(e) = run_json("oci", &self.base_args(&["iam", "region", "list"]), OCI_INSTALL) {
            self.connected = false;
            return Err(oci_auth_error(e, self.session));
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }

    async fn list_instances(&self) -> Result<Vec<Instance>> {
        let compartment = self
            .compartment
            .as_deref()
            .ok_or(ProviderError::NotConnected(ProviderKind::Oracle))?;

        let body = run_json(
            "oci",
            &self.base_args(&[
                "compute",
                "instance",
                "list",
                "--compartment-id",
                compartment,
                "--all",
            ]),
            OCI_INSTALL,
        )
        .map_err(|e| oci_auth_error(e, self.session))?;

        Ok(body
            .get("data")
            .and_then(|d| d.as_array())
            .map(|arr| arr.iter().map(oci_instance).collect())
            .unwrap_or_default())
    }

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance> {
        let body = run_json(
            "oci",
            &self.base_args(&["compute", "instance", "get", "--instance-id", &reference.id]),
            OCI_INSTALL,
        )
        .map_err(|e| oci_auth_error(e, self.session))?;
        body.get("data")
            .map(oci_instance)
            .ok_or_else(|| ProviderError::Api(format!("instance {} introuvable", reference.id)))
    }

    /// Deux commandes, pour un profil de SESSION seulement — un profil par clé
    /// d'API n'a rien à renouveler.
    fn session_actions(&self) -> Vec<SessionAction> {
        if !self.session {
            return Vec::new();
        }
        vec![
            SessionAction::new(
                "refresh",
                "Renouveler la session",
                "Prolonge le jeton courant, sans rien demander. Sans effet une fois la fenêtre de renouvellement passée.",
            ),
            SessionAction::new(
                "authenticate",
                "Ouvrir une session neuve",
                "Ouvre le navigateur sur la page de connexion Oracle. À utiliser quand le renouvellement n'est plus possible.",
            )
            .needing_browser(),
        ]
    }

    async fn run_session_action(&self, name: &str) -> Result<String> {
        match name {
            "refresh" => self.oci_refresh(),
            "authenticate" => self.oci_authenticate().await,
            other => Err(ProviderError::Api(format!(
                "commande de session inconnue : {other}"
            ))),
        }
    }


    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        self.ensure_allows(action)?;
        // OCI distingue explicitement les variantes douces des brutales.
        let verb = match action {
            PowerAction::Start => "START",
            PowerAction::Stop { graceful: true } => "SOFTSTOP",
            PowerAction::Stop { graceful: false } => "STOP",
            PowerAction::Reboot { graceful: true } => "SOFTRESET",
            PowerAction::Reboot { graceful: false } => "RESET",
        };
        run_ok(
            "oci",
            &self.base_args(&[
                "compute",
                "instance",
                "action",
                "--instance-id",
                &reference.id,
                "--action",
                verb,
            ]),
            OCI_INSTALL,
        )
        .map_err(|e| oci_auth_error(e, self.session))
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gcp_zone_is_extracted_from_its_url() {
        let v = json!({
            "name": "avs-1",
            "status": "RUNNING",
            "zone": "https://www.googleapis.com/compute/v1/projects/nodeinfo/zones/europe-west1-b",
            "machineType": "https://www.googleapis.com/compute/v1/projects/nodeinfo/zones/europe-west1-b/machineTypes/e2-medium",
            "networkInterfaces": [
                { "networkIP": "10.0.0.2", "accessConfigs": [{ "natIP": "34.1.2.3" }] }
            ]
        });
        let i = gcp_instance(&v);
        // C'est précisément ce que le prototype ne transportait pas, et qui le
        // condamnait à la lecture seule sur GCP.
        assert_eq!(i.reference.zone.as_deref(), Some("europe-west1-b"));
        assert_eq!(i.reference.region, "europe-west1");
        assert_eq!(i.shape, "e2-medium");
        assert!(i.has_address("34.1.2.3"));
        assert!(i.has_address("10.0.0.2"));
    }

    #[test]
    fn a_gcp_action_without_a_zone_fails_loudly() {
        let r = InstanceRef {
            account: "default".into(),
            provider: ProviderKind::Gcp,
            id: "x".into(),
            zone: None,
            region: "europe-west1".into(),
        };
        assert!(GcpProvider::zone_of(&r).is_err());
    }

    #[test]
    fn aws_name_comes_from_the_name_tag() {
        let v = json!({
            "InstanceId": "i-123",
            "InstanceType": "t3.micro",
            "State": { "Name": "running" },
            "PublicIpAddress": "1.2.3.4",
            "Placement": { "AvailabilityZone": "eu-west-3a" },
            "Tags": [{ "Key": "Name", "Value": "front1" }]
        });
        let i = aws_instance(&v, "eu-west-3");
        assert_eq!(i.name, "front1");
        assert_eq!(i.reference.zone.as_deref(), Some("eu-west-3a"));
        assert_eq!(i.state, PowerState::Running);
    }

    #[test]
    fn aws_without_a_name_tag_falls_back_to_its_id() {
        let v = json!({ "InstanceId": "i-999", "State": { "Name": "stopped" } });
        let i = aws_instance(&v, "eu-west-3");
        assert_eq!(i.name, "i-999");
    }

    #[test]
    fn oci_reads_both_kebab_and_camel_case() {
        // Le CLI rend du kebab-case, l'API du camelCase.
        let kebab = json!({ "id": "ocid1", "display-name": "small1", "lifecycle-state": "RUNNING", "shape": "VM.Standard.E4.Flex" });
        let camel = json!({ "id": "ocid1", "displayName": "small1", "lifecycleState": "RUNNING", "shape": "VM.Standard.E4.Flex" });
        assert_eq!(oci_instance(&kebab).name, "small1");
        assert_eq!(oci_instance(&camel).name, "small1");
        assert_eq!(oci_instance(&camel).state, PowerState::Running);
    }

    #[test]
    fn a_provider_without_its_cli_declares_no_capability() {
        // L'UI grise alors le provider au lieu de proposer une action qui
        // échouerait au premier appel.
        if !which("definitely-not-a-real-cli") {
            let caps = Capabilities::NONE;
            assert!(!caps.list);
            assert!(!caps.allows(PowerAction::Start));
        }
    }

    #[test]
    fn python_warnings_never_hide_the_real_error() {
        // Exactement ce que rend `oci` sous Python 3.14 : deux lignes de bruit
        // AVANT la cause. Rendues telles quelles, elles poussaient la cause
        // hors d'une barre d'état, et on lisait un chemin vers du code Python.
        let stderr = "/opt/homebrew/Cellar/oci-cli/3.92.0/libexec/lib/python3.14/site-packages/services/core/src/oci_cli_compute/compute_cli_extended.py:25: SyntaxWarning: \"\\.\" is an invalid escape sequence.\n  INSTANCE_CONSOLE_CONNECTION_STRING_INTERMEDIATE_HOST_REGEX = \"(x)\"  # noqa: W605\nERROR: The config file at ~/.oci/config is invalid: user missing\n";
        let msg = meaningful_error(stderr);
        assert!(msg.starts_with("ERROR:"), "message obtenu : {msg}");
        assert!(!msg.contains("SyntaxWarning"));
        assert!(!msg.contains("site-packages"));
    }

    #[test]
    fn an_error_made_only_of_noise_is_not_emptied() {
        // Mieux vaut un message obscur que pas de message : sans cela un échec
        // se présenterait comme une réussite silencieuse.
        let stderr = "/x/y.py:1: DeprecationWarning: quelque chose\n";
        assert!(!meaningful_error(stderr).is_empty());
    }

    #[test]
    fn an_expired_session_points_at_the_app_not_at_a_terminal() {
        // Le CLI rend « Abort: » quand il voulait poser une question et que
        // l'entrée standard est fermée : cela ne désigne rien tout seul.
        let raw = ProviderError::Api("oci a échoué : Abort:".into());
        let translated = oci_auth_error(raw, true);
        let text = translated.to_string();
        assert!(text.contains("session"), "{text}");
        // Le message a longtemps renvoyé vers `oci session authenticate` dans
        // un terminal. L'application lance elle-même cette commande et ouvre le
        // navigateur : y renvoyer serait demander à la main ce qu'elle fait.
        assert!(!text.contains("terminal"), "{text}");
        assert!(!text.contains("oci session"), "{text}");
        assert!(matches!(translated, ProviderError::Auth(_)));
    }

    #[test]
    fn a_missing_user_field_explains_both_oci_auth_modes() {
        let raw = ProviderError::Api("oci a échoué : ERROR: config invalid: user missing".into());
        let text = oci_auth_error(raw, false).to_string();
        assert!(text.contains("security_token_file"), "{text}");
        assert!(text.contains("key_file"), "{text}");
    }

    #[test]
    fn a_session_profile_is_recognised_as_such() {
        // On ne lit pas le vrai ~/.oci/config : le test doit valoir sur une
        // machine qui n'en a pas.
        assert!(!oci_profile_uses_session("profil-qui-n-existe-pas"));
    }

    #[test]
    fn gcp_does_not_promise_a_graceful_reboot() {
        // `power` fait tomber tout redémarrage sur `reset`, qui coupe
        // l'alimentation. Déclarer `reboot_graceful` laissait `ensure_allows`
        // passer, et l'interface envoie `graceful` dès que la capacité est
        // annoncée : un clic sur « redémarrer » coupait le courant.
        assert!(!GCP_CAPS.allows(PowerAction::Reboot { graceful: true }));
        assert!(GCP_CAPS.allows(PowerAction::Reboot { graceful: false }));
    }

    #[test]
    fn gcp_does_not_promise_a_forced_stop() {
        // `gcloud compute instances stop` éteint proprement ; il n'existe pas
        // de coupure côté arrêt.
        assert!(!GCP_CAPS.allows(PowerAction::Stop { graceful: false }));
        assert!(GCP_CAPS.allows(PowerAction::Stop { graceful: true }));
    }

    #[test]
    fn aws_does_not_promise_a_forced_reboot() {
        // `reboot-instances` demande un redémarrage propre à l'OS ; EC2 n'a
        // pas d'équivalent brutal.
        assert!(!AWS_CAPS.allows(PowerAction::Reboot { graceful: false }));
        assert!(AWS_CAPS.allows(PowerAction::Reboot { graceful: true }));
        // L'arrêt, lui, a bien ses deux variantes (`--force`).
        assert!(AWS_CAPS.allows(PowerAction::Stop { graceful: true }));
        assert!(AWS_CAPS.allows(PowerAction::Stop { graceful: false }));
    }
}
