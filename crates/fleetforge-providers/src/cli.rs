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
    run_text_within(tool, args, install, None)
}

/// PID de la connexion `oci session authenticate` que CETTE application a
/// lancée, 0 si aucune : de quoi l'arrêter à la fermeture.
static LOGIN_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Attend la fin de `child` au plus `limit`, puis le tue. `None` = a expiré.
fn wait_within(child: std::process::Child, limit: std::time::Duration) -> std::io::Result<Option<std::process::Output>> {
    use std::io::Read;
    let mut child = child;
    let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
    // Lire en parallèle : un tube plein bloquerait le processus avant la fin.
    let read = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let out_t = read(out.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let err_t = read(err.take().map(|p| Box::new(p) as Box<dyn Read + Send>));

    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() >= limit {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let stdout = out_t.join().unwrap_or_default();
    let stderr = err_t.join().unwrap_or_default();
    Ok(status.map(|status| std::process::Output { status, stdout, stderr }))
}

/// `run_text` avec une durée maximale. Une commande qui attend une personne
/// (connexion par navigateur) ne doit pas survivre à l'abandon de celle-ci :
/// elle garderait son port indéfiniment.
fn run_text_within(
    tool: &str,
    args: &[&str],
    install: &str,
    limit: Option<std::time::Duration>,
) -> Result<String> {
    if !which(tool) {
        return Err(ProviderError::MissingCli {
            tool: tool.to_string(),
            install: install.to_string(),
        });
    }

    let mut cmd = Command::new(tool);
    cmd.args(args).stdin(Stdio::null()).env("PYTHONWARNINGS", "ignore");
    let io_err = |e: std::io::Error| ProviderError::Api(format!("{tool} : {e}"));
    let out = match limit {
        None => cmd.output().map_err(io_err)?,
        Some(limit) => {
            let child = cmd
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(io_err)?;
            let pid = child.id();
            LOGIN_PID.store(pid, std::sync::atomic::Ordering::SeqCst);
            let done = wait_within(child, limit).map_err(io_err);
            let _ = LOGIN_PID.compare_exchange(pid, 0, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst);
            done?.ok_or_else(|| {
                ProviderError::Auth(format!(
                    "{tool} : aucune connexion reçue en {} min, commande arrêtée",
                    limit.as_secs() / 60
                ))
            })?
        }
    };

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
        // Certains outils écrivent leur erreur sur la sortie standard : sans ce
        // repli, `oci session authenticate` échouait sur « oci a échoué : »
        // suivi de rien, et le journal ne disait pas pourquoi.
        let detail = match meaningful_error(&stderr) {
            msg if msg.trim().is_empty() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            msg => msg,
        };
        return Err(ProviderError::Api(format!(
            "{tool} a échoué : {}",
            if detail.is_empty() { format!("code {}", out.status.code().unwrap_or(-1)) } else { detail }
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

/// Tenancy à laquelle le profil est connecté, telle que l'écrit `oci session
/// authenticate`. Sert à l'AFFICHER : l'application ne l'écrit jamais.
pub fn oci_profile_tenancy(profile: &str) -> Option<String> {
    oci_profile_key(profile, "tenancy")
}

/// Région actuelle du profil dans `~/.oci/config`, pour l'AFFICHER : le champ
/// « Région » du formulaire est un ordre, il ne montre pas ce que le fichier dit.
pub fn oci_profile_region(profile: &str) -> Option<String> {
    oci_profile_key(profile, "region")
}

/// Le profil a-t-il une section dans `~/.oci/config` ?
fn profile_section_exists(config: &str, profile: &str) -> bool {
    let wanted = if profile.trim().is_empty() { "DEFAULT" } else { profile.trim() };
    config.lines().any(|line| {
        line.trim()
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
            .is_some_and(|name| name.trim() == wanted)
    })
}

/// `config` avec `region` du profil réglée sur `region`. `None` si elle y est
/// déjà ou si le profil n'a pas de section. Seule cette ligne change : le reste
/// du fichier (autres profils, commentaires, ordre) reste tel quel.
fn with_profile_region(config: &str, profile: &str, region: &str) -> Option<String> {
    let wanted = if profile.trim().is_empty() { "DEFAULT" } else { profile.trim() };
    let mut lines: Vec<String> = config.lines().map(String::from).collect();
    let header = lines.iter().position(|l| {
        l.trim()
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
            .is_some_and(|n| n.trim() == wanted)
    })?;
    let end = lines[header + 1..]
        .iter()
        .position(|l| l.trim().starts_with('['))
        .map_or(lines.len(), |i| header + 1 + i);
    let existing = (header + 1..end).find(|&i| {
        lines[i].split_once('=').is_some_and(|(k, _)| k.trim() == "region")
    });
    match existing {
        Some(i) => {
            if lines[i].split_once('=').is_some_and(|(_, v)| v.trim() == region) {
                return None;
            }
            lines[i] = format!("region={region}");
        }
        None => lines.insert(header + 1, format!("region={region}")),
    }
    Some(lines.join("\n") + "\n")
}

/// Applique la région saisie à un profil qui existe déjà. Sans cela, la corriger
/// dans le formulaire n'avait aucun effet : seul un profil neuf la lisait.
fn apply_profile_region(profile: &str, region: &str) {
    let path = dirs_home().join(".oci/config");
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Some(updated) = with_profile_region(&text, profile, region) else { return };
    match std::fs::write(&path, updated) {
        Ok(()) => fleetforge_core::logging::info(
            "oci",
            format!("région du profil [{profile}] réglée sur {region}"),
        ),
        Err(e) => fleetforge_core::logging::warn("oci", format!("région non écrite dans ~/.oci/config : {e}")),
    }
}

fn oci_profile_exists(profile: &str) -> bool {
    std::fs::read_to_string(dirs_home().join(".oci/config"))
        .map(|text| profile_section_exists(&text, profile))
        .unwrap_or(false)
}

/// Région où créer un profil neuf : celle saisie, sinon celle de `DEFAULT`.
/// `oci session authenticate` l'exige, et un second compte est presque toujours
/// dans la même région que le premier.
fn creation_region(typed: Option<&str>, default_profile: Option<String>) -> Option<String> {
    typed
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(String::from)
        .or(default_profile)
}

/// Ouvre une session — et, si le profil n'existe pas, le CRÉE : c'est
/// `oci session authenticate` qui écrit la section dans `~/.oci/config`.
///
/// Sur un fil dédié : la commande attend que l'opérateur se connecte dans son
/// navigateur, ce qui prend le temps qu'il faut. La laisser sur l'exécuteur
/// asynchrone y bloquerait un fil et figerait l'interface.
/// Port où `oci session authenticate` attend la redirection OAuth du navigateur.
const OCI_LOGIN_PORT: u16 = 8181;

/// Quelqu'un écoute-t-il déjà sur ce port, en local ?
fn port_in_use(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
}

/// Attente maximale d'une connexion par navigateur.
const OCI_LOGIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

/// Arrête la connexion lancée par cette application, s'il en reste une.
/// À appeler à la fermeture : le processus Python survivrait au parent.
pub fn stop_login() {
    let pid = LOGIN_PID.swap(0, std::sync::atomic::Ordering::SeqCst);
    if pid != 0 {
        kill_pid(pid);
    }
}

fn kill_pid(pid: u32) {
    let _ = Command::new("kill").arg(pid.to_string()).output();
}

/// Qui écoute sur le port de connexion : PID et ligne de commande.
fn login_port_holder() -> Option<(u32, String)> {
    let out = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{OCI_LOGIN_PORT}"), "-sTCP:LISTEN", "-t"])
        .output()
        .ok()?;
    let pid: u32 = String::from_utf8_lossy(&out.stdout).lines().next()?.trim().parse().ok()?;
    let cmd = Command::new("ps").args(["-o", "command=", "-p", &pid.to_string()]).output().ok()?;
    Some((pid, String::from_utf8_lossy(&cmd.stdout).trim().to_string()))
}

/// Une connexion `oci session authenticate`, et rien d'autre : on n'arrête
/// jamais un processus qu'on ne sait pas nommer.
fn is_oci_login(command: &str) -> bool {
    command.contains("oci") && command.contains("session") && command.contains("authenticate")
}

/// Libère le port de connexion si c'est une connexion `oci` en attente.
fn free_login_port() -> Result<String> {
    match login_port_holder() {
        None => Ok("le port est déjà libre".to_string()),
        Some((pid, cmd)) if is_oci_login(&cmd) => {
            kill_pid(pid);
            fleetforge_core::logging::info("oci", format!("connexion en attente arrêtée (pid {pid})"));
            Ok(format!("connexion en attente arrêtée (pid {pid})"))
        }
        Some((pid, _)) => Err(ProviderError::Auth(format!(
            "le port {OCI_LOGIN_PORT} est tenu par le processus {pid}, qui n'est pas une connexion oci :              je n'y touche pas"
        ))),
    }
}

async fn oci_session_login(profile: String, region: String) -> Result<String> {
    // Une autre connexion en attente (lancée dans un terminal, ou restée là
    // après un navigateur fermé) tient le port : la nouvelle échoue en une
    // fraction de seconde, SANS message — indiscernable d'une panne d'Oracle.
    if port_in_use(OCI_LOGIN_PORT) {
        let who = match login_port_holder() {
            Some((pid, cmd)) if is_oci_login(&cmd) => format!(
                "une `oci session authenticate` (pid {pid}) attend sa connexion. L'arrêter \
                 (menu session › « Libérer le port »), ou Ctrl-C dans son terminal"
            ),
            Some((pid, _)) => format!("le processus {pid} l'occupe (ce n'est pas une connexion oci)"),
            None => "un processus l'occupe".to_string(),
        };
        return Err(ProviderError::Auth(format!(
            "le port {OCI_LOGIN_PORT} est déjà utilisé : {who}, puis recommencer."
        )));
    }
    fleetforge_core::logging::info(
        "oci",
        format!("ouverture d'une session pour le profil [{profile}] ({region})"),
    );
    tokio::task::spawn_blocking(move || {
        run_text_within(
            "oci",
            &["session", "authenticate", "--region", &region, "--profile-name", &profile],
            OCI_INSTALL,
            Some(OCI_LOGIN_LIMIT),
        )
        .map(|_| "session ouverte".to_string())
    })
    .await
    .map_err(|e| ProviderError::Api(format!("authentification interrompue : {e}")))?
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

        oci_session_login(profile, region).await
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

/// Adresses (publiques et privées) lues dans la réponse de `list-vnics`.
fn oci_vnic_addresses(body: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for vnic in body.get("data").and_then(|d| d.as_array()).into_iter().flatten() {
        for key in ["public-ip", "private-ip"] {
            if let Some(ip) = vnic.get(key).and_then(|v| v.as_str()).filter(|v| !v.is_empty()) {
                if !out.iter().any(|a| a == ip) {
                    out.push(ip.to_string());
                }
            }
        }
    }
    out
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

/// `NotAuthorizedOrNotFound` : OCI ne distingue volontairement pas « n'existe
/// pas » de « tu n'as pas le droit » (pour ne pas révéler l'existence d'une
/// ressource). Le brut — un JSON de plusieurs lignes dont la barre d'état ne
/// montre que le début — ne dit rien de ce qu'il faut vérifier.
fn oci_compartment_error(error: ProviderError, compartment: &str) -> ProviderError {
    let text = error.to_string();
    if !text.contains("NotAuthorized") {
        return error;
    }
    ProviderError::Api(format!(
        "compartiment OCI introuvable ou accès refusé ({compartment}) : vérifier l'OCID, que \
         le profil est authentifié sur CETTE tenancy, et que la politique IAM autorise \
         « read instances » dessus."
    ))
}

/// Fin d'un OCID, assez pour distinguer deux tenancies dans une barre d'état.
fn ocid_tail(ocid: &str) -> &str {
    &ocid[ocid.len().saturating_sub(8)..]
}

/// Le compartiment visé est la RACINE d'une tenancy (son OCID est celui de la
/// tenancy) mais le profil est authentifié sur une AUTRE.
///
/// Une session ne vaut que pour une tenancy. Deux comptes qui partagent le
/// profil `DEFAULT` n'en atteignent donc qu'une, et l'autre répond
/// `NotAuthorizedOrNotFound` — indiscernable d'une politique IAM manquante, ce
/// qui envoie chercher au mauvais endroit. Le profil écrit sa tenancy : on la
/// compare avant d'interroger Oracle.
fn oci_tenancy_mismatch(
    compartment: &str,
    profile: &str,
    profile_tenancy: Option<&str>,
) -> Option<ProviderError> {
    let tenancy = profile_tenancy?;
    if !compartment.starts_with("ocid1.tenancy.") || compartment == tenancy {
        return None;
    }
    Some(ProviderError::Auth(format!(
        "le profil [{profile}] est authentifié sur la tenancy …{} mais ce compte vise …{} : \
         une session ne vaut que pour une tenancy. Donner à ce compte son propre profil \
         (champ « Profil ») : s'il n'existe pas, il est créé et le navigateur s'ouvre.",
        ocid_tail(tenancy),
        ocid_tail(compartment),
    )))
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
                    .hint("Une section de ~/.oci/config. Vide = DEFAULT. Un profil qui n'existe pas est CRÉÉ : le navigateur s'ouvre pour se connecter à la tenancy du compte.")
                    .optional(),
                AuthField::new("OCI_REGION", "Région")
                    .hint("eu-paris-1… Écrite dans le profil de ~/.oci/config (créé si absent). Vide = région du profil, ou celle de DEFAULT pour un profil neuf.")
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

        // Un profil absent n'a rien à quoi se connecter : plutôt que d'échouer
        // sur « config invalide » et de renvoyer vers un terminal, on le crée.
        // Même chemin à l'ajout d'un compte et à la modification de son profil.
        let wanted = self.profile_name().to_string();
        if !oci_profile_exists(&wanted) {
            // Créer le profil, c'est ouvrir le navigateur : un lancement
            // d'application n'a pas à en ouvrir un de lui-même.
            if credentials.forbids_browser() {
                return Err(ProviderError::Auth(format!(
                    "le profil [{wanted}] n'existe pas : le créer ouvre le navigateur, \
                     non fait au lancement (menu session, ou C pour le créer)"
                )));
            }
            let region = creation_region(
                credentials.get("OCI_REGION"),
                oci_profile_key("DEFAULT", "region"),
            )
            .ok_or_else(|| {
                ProviderError::Auth(format!(
                    "le profil [{wanted}] n'existe pas et sa région est inconnue : renseigner \
                     « Région » (ex. eu-paris-1) pour que l'application le crée"
                ))
            })?;
            oci_session_login(wanted.clone(), region).await?;
            if !oci_profile_exists(&wanted) {
                return Err(ProviderError::Auth(format!(
                    "le profil [{wanted}] n'a pas été créé : la connexion dans le navigateur n'a pas abouti"
                )));
            }
        } else if let Some(region) = credentials.get("OCI_REGION").map(str::trim).filter(|r| !r.is_empty()) {
            apply_profile_region(&wanted, region);
        }

        self.session = oci_profile_uses_session(self.profile.as_deref().unwrap_or("DEFAULT"));

        // Vérifier MAINTENANT plutôt que de se déclarer connecté et d'échouer
        // au premier listage : l'erreur porterait alors sur « lister les
        // instances » et non sur l'authentification qui l'a causée.
        self.connected = true;
        if let Err(e) = run_json("oci", &self.base_args(&["iam", "region", "list"]), OCI_INSTALL) {
            self.connected = false;
            return Err(oci_auth_error(e, self.session));
        }

        // `iam region list` aboutit avec n'importe quels identifiants valides :
        // il ne dit rien du COMPARTIMENT. Un OCID erroné, ou une politique IAM
        // qui n'accorde pas la lecture des instances, ne se découvrait qu'au
        // premier listage — le compte était déjà vert, et l'erreur tombait
        // ensuite dans la barre d'état. On touche donc le compartiment ici.
        let compartment = self.compartment.clone().unwrap_or_default();
        if let Some(mismatch) = oci_tenancy_mismatch(
            &compartment,
            self.profile_name(),
            oci_profile_key(self.profile_name(), "tenancy").as_deref(),
        ) {
            self.connected = false;
            return Err(mismatch);
        }
        if let Err(e) = run_json(
            "oci",
            &self.base_args(&[
                "compute", "instance", "list", "--compartment-id", &compartment, "--limit", "1",
            ]),
            OCI_INSTALL,
        ) {
            self.connected = false;
            return Err(oci_compartment_error(oci_auth_error(e, self.session), &compartment));
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
        .map_err(|e| oci_compartment_error(oci_auth_error(e, self.session), compartment))?;

        let mut instances: Vec<Instance> = body
            .get("data")
            .and_then(|d| d.as_array())
            .map(|arr| arr.iter().map(oci_instance).collect())
            .unwrap_or_default();

        // `instance list` ne rend AUCUNE adresse : elles vivent sur les cartes
        // réseau virtuelles. Sans elles, le rapprochement avec l'inventaire
        // (par adresse) ne pouvait jamais aboutir — toutes les machines Oracle
        // restaient « non rapprochées ». Un appel par instance, en parallèle.
        let base: Vec<String> = self.base_args(&[]).into_iter().map(String::from).collect();
        std::thread::scope(|scope| {
            let jobs: Vec<_> = instances
                .iter()
                .filter(|i| !matches!(i.raw_state.as_str(), "TERMINATED" | "TERMINATING"))
                .map(|i| {
                    let id = i.reference.id.clone();
                    let base = &base;
                    scope.spawn(move || {
                        let mut args: Vec<&str> = vec!["compute", "instance", "list-vnics", "--instance-id", &id];
                        args.extend(base.iter().map(String::as_str));
                        let found = run_json("oci", &args, OCI_INSTALL)
                            .map(|v| oci_vnic_addresses(&v))
                            .map_err(|e| {
                                fleetforge_core::logging::warn(
                                    "oci",
                                    format!("adresses de l'instance {id} illisibles : {e}"),
                                )
                            })
                            .unwrap_or_default();
                        (id, found)
                    })
                })
                .collect();
            for job in jobs {
                if let Ok((id, found)) = job.join() {
                    if let Some(inst) = instances.iter_mut().find(|i| i.reference.id == id) {
                        inst.addresses = found;
                    }
                }
            }
        });

        Ok(instances)
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
        let mut actions = vec![
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
        ];
        // Proposée seulement quand elle sert : une entrée permanente laisserait
        // croire qu'on peut tuer n'importe quoi.
        if login_port_holder().is_some_and(|(_, cmd)| is_oci_login(&cmd)) {
            actions.push(SessionAction::new(
                "free_port",
                "Libérer le port 8181",
                "Arrête la connexion `oci session authenticate` restée en attente et qui bloque une nouvelle ouverture.",
            ));
        }
        actions
    }

    async fn run_session_action(&self, name: &str) -> Result<String> {
        match name {
            "refresh" => self.oci_refresh(),
            "authenticate" => self.oci_authenticate().await,
            "free_port" => free_login_port(),
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
    /// `connect` écrit la région saisie dans ~/.oci/config, qu'il aboutisse ou non.
    /// Joue le vrai `connect` avec un faux `oci` et un HOME jetable ; l'environnement
    /// étant global au processus, un verrou sérialise ce seul test.
    #[cfg(unix)]
    #[tokio::test]
    async fn typed_region_reaches_the_config_file_whatever_the_outcome() {
        use std::os::unix::fs::PermissionsExt;
        static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!("ff-oci-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".oci")).unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let fake = dir.join("bin/oci");
        // Succès pour la région, refus pour tout le reste : le compartiment est
        // rejeté, la connexion échoue APRÈS l'écriture de la région.
        std::fs::write(&fake, "#!/bin/sh\ncase \"$*\" in *\"region list\"*) echo '{\"data\":[]}';; *) echo 'NotAuthorizedOrNotFound' >&2; exit 1;; esac\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = dir.join(".oci/config");
        std::fs::write(
            &config,
            "[DEFAULT]\nregion=eu-paris-1\n\n[acme]\ntenancy=ocid1.tenancy.oc1..aaaaexample1\nregion=us-ashburn-1\nsecurity_token_file=/x/token\n",
        )
        .unwrap();

        let (old_home, old_path) = (std::env::var("HOME"), std::env::var("PATH"));
        std::env::set_var("HOME", &dir);
        std::env::set_var("PATH", format!("{}:{}", dir.join("bin").display(), old_path.clone().unwrap_or_default()));

        let mut creds = Credentials { method: "config".into(), ..Default::default() };
        for (k, v) in [
            ("OCI_PROFILE", "acme"),
            ("OCI_REGION", "eu-frankfurt-1"),
            ("OCI_COMPARTMENT", "ocid1.tenancy.oc1..aaaaexample1"),
        ] {
            creds.fields.insert(k.into(), v.into());
        }
        let mut provider = OracleProvider::new();
        let outcome = provider.connect(&creds).await;
        let written = std::fs::read_to_string(&config).unwrap();

        match old_home { Ok(v) => std::env::set_var("HOME", v), Err(_) => std::env::remove_var("HOME") }
        match old_path { Ok(v) => std::env::set_var("PATH", v), Err(_) => std::env::remove_var("PATH") }
        let _ = std::fs::remove_dir_all(&dir);

        assert!(outcome.is_err(), "le faux compartiment est refusé");
        assert!(written.contains("[acme]\ntenancy=ocid1.tenancy.oc1..aaaaexample1\nregion=eu-frankfurt-1"), "{written}");
        assert!(written.contains("[DEFAULT]\nregion=eu-paris-1"), "DEFAULT intact : {written}");
    }

    #[test]
    fn vnic_addresses_keep_public_and_private_without_duplicates() {
        let body: Value = serde_json::json!({"data": [
            {"public-ip": "203.0.113.10", "private-ip": "10.0.0.5", "is-primary": true},
            {"public-ip": null, "private-ip": "10.0.0.5"},
            {"private-ip": "10.0.0.6"}
        ]});
        assert_eq!(oci_vnic_addresses(&body), vec!["203.0.113.10", "10.0.0.5", "10.0.0.6"]);
        assert!(oci_vnic_addresses(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn a_profile_region_is_rewritten_alone() {
        let cfg = "[DEFAULT]\nregion=eu-paris-1\ntenancy=t1\n\n[acme]\ntenancy=t2\nregion = us-ashburn-1\n";
        let out = with_profile_region(cfg, "acme", "eu-frankfurt-1").unwrap();
        assert!(out.contains("[DEFAULT]\nregion=eu-paris-1\ntenancy=t1"));
        assert!(out.contains("[acme]\ntenancy=t2\nregion=eu-frankfurt-1\n"));
        assert!(with_profile_region(cfg, "acme", "us-ashburn-1").is_none(), "déjà réglée");
        assert!(with_profile_region(cfg, "absent", "x").is_none());
        let bare = with_profile_region("[p]\ntenancy=t\n", "p", "eu-paris-1").unwrap();
        assert!(bare.contains("[p]\nregion=eu-paris-1\ntenancy=t"));
    }

    #[test]
    fn only_an_oci_login_may_be_stopped() {
        assert!(is_oci_login("/usr/bin/python3 /opt/bin/oci session authenticate --region eu-paris-1"));
        assert!(!is_oci_login("node server.js --port 8181"));
        assert!(!is_oci_login("oci compute instance list"));
    }

    #[cfg(unix)]
    #[test]
    fn a_waiting_command_is_stopped_at_the_limit() {
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let done = wait_within(child, std::time::Duration::from_millis(300)).unwrap();
        assert!(done.is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

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
    fn a_denied_compartment_says_what_to_check_instead_of_dumping_the_service_error() {
        let raw = ProviderError::Api(
            "oci a échoué : ServiceError:\n{ \"code\": \"NotAuthorizedOrNotFound\" }".into(),
        );
        let text = oci_compartment_error(raw, "ocid1.compartment.oc1..aaa").to_string();
        assert!(text.contains("ocid1.compartment.oc1..aaa"), "{text}");
        assert!(text.contains("IAM"), "{text}");
        assert!(!text.contains("ServiceError"), "{text}");
    }

    #[test]
    fn a_listening_port_is_reported_busy() {
        // Pas de contre-épreuve « port libre » : un port rendu peut être repris
        // à l'instant par un autre test, et le test deviendrait aléatoire.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(port_in_use(listener.local_addr().unwrap().port()));
    }

    #[test]
    fn a_profile_is_found_by_its_section_only() {
        let config = "[DEFAULT]\nregion=eu-paris-1\n\n[ extra ]\ntenancy=x\n";
        assert!(profile_section_exists(config, "DEFAULT"));
        assert!(profile_section_exists(config, "extra"));
        assert!(profile_section_exists(config, ""), "vide = DEFAULT");
        assert!(!profile_section_exists(config, "autre"));
        // Un nom présent comme VALEUR n'est pas une section.
        assert!(!profile_section_exists("[DEFAULT]\nprofile=autre\n", "autre"));
    }

    #[test]
    fn a_new_profile_takes_the_typed_region_then_the_default_one() {
        assert_eq!(creation_region(Some(" us-ashburn-1 "), Some("eu-paris-1".into())).as_deref(), Some("us-ashburn-1"));
        assert_eq!(creation_region(Some(""), Some("eu-paris-1".into())).as_deref(), Some("eu-paris-1"));
        assert_eq!(creation_region(None, Some("eu-paris-1".into())).as_deref(), Some("eu-paris-1"));
        assert_eq!(creation_region(None, None), None);
    }

    #[test]
    fn a_profile_authenticated_on_another_tenancy_is_named_as_the_cause() {
        let err = oci_tenancy_mismatch(
            "ocid1.tenancy.oc1..aaaaaaaaexample1",
            "DEFAULT",
            Some("ocid1.tenancy.oc1..aaaaaaaaexample2"),
        )
        .expect("deux tenancies différentes");
        let text = err.to_string();
        assert!(text.contains("DEFAULT") && text.contains("example2"), "{text}");
        assert!(text.contains("example1"), "{text}");
        assert!(matches!(err, ProviderError::Auth(_)));
    }

    #[test]
    fn the_same_tenancy_or_a_sub_compartment_is_not_flagged() {
        let t = "ocid1.tenancy.oc1..aaaa";
        assert!(oci_tenancy_mismatch(t, "DEFAULT", Some(t)).is_none());
        // Un sous-compartiment ne dit rien de sa tenancy : on ne peut pas conclure.
        assert!(oci_tenancy_mismatch("ocid1.compartment.oc1..bbbb", "DEFAULT", Some(t)).is_none());
        // Profil sans tenancy lisible : on laisse Oracle répondre.
        assert!(oci_tenancy_mismatch(t, "DEFAULT", None).is_none());
    }

    #[test]
    fn an_unrelated_oci_error_passes_through_untouched() {
        let raw = ProviderError::Api("oci a échoué : timeout".into());
        assert_eq!(oci_compartment_error(raw, "x").to_string(), "oci a échoué : timeout");
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
