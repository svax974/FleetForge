/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Diagnostic en LECTURE SEULE d'une machine du parc, par la passerelle
//! `ro-gate` du compte `openclaw-ro` (`readonly-user-install`).
//!
//! La clé employée ici n'ouvre aucun shell : elle est liée à la passerelle
//! par une commande forcée (`restrict,command=…`) et, pour celle de
//! FleetForge, restreinte à l'adresse de la machine qui l'héberge (`from=`).
//! La passerelle valide elle-même chaque demande ; la grammaire ci-dessous en
//! est la COPIE, volontairement redondante : une demande hors grammaire n'est
//! pas même envoyée. Les deux doivent évoluer ensemble
//! (`readonly-user-install/files/ro-gate.py`, `USAGE`).
//!
//! Jamais de shell, jamais de commande libre : `ssh` est lancé directement,
//! avec `-F /dev/null` (aucune configuration utilisateur, donc aucun
//! `ProxyCommand` hérité) et `--` avant l'hôte.

use crate::fault::{fail, Fault, FaultKind};
use crate::models::AnsibleHost;
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Verbes de la passerelle, tous en lecture. Liste FERMÉE.
pub const VERBS: &[&str] = &[
    "logs",
    "status",
    "containers",
    "stats",
    "firewall",
    "system",
    "disk",
    "ports",
    "http",
];

/// Plafond de la sortie conservée. La passerelle plafonne déjà (80 lignes,
/// 60 pour `disk`, 16 Kio en HTTP) ; ce second plafond protège d'une passerelle d'une autre
/// version, ou d'un hôte qui ne serait pas celui qu'on croit.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Réglages du diagnostic, posés par le déploiement (`fleetforge-install`).
#[derive(Debug, Clone)]
pub struct RoGateConfig {
    /// Clé privée DÉDIÉE au diagnostic (jamais la clé de pilotage).
    pub key: PathBuf,
    /// Compte lecture seule — `readonly_user_name` côté Ansible.
    pub user: String,
    /// Fichier `known_hosts` propre à ce compte.
    pub known_hosts: PathBuf,
    pub timeout: Duration,
}

/// Résultat d'un diagnostic, sortie de la passerelle telle quelle (déjà
/// caviardée par elle).
#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    pub host: String,
    pub verb: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub output: String,
    pub truncated: bool,
}

// === Grammaire (copie de ro-gate.py) ===

/// `NAME` de ro-gate : `^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$`.
fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && s.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.@:-".contains(c))
}

/// `DURATION` de ro-gate : 1 à 4 chiffres puis `m`, `h` ou `d`.
fn is_duration(s: &str) -> bool {
    let Some(digits) = s.strip_suffix(['m', 'h', 'd']) else {
        return false;
    };
    (1..=4).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `URL_PATH` de ro-gate : `^/[A-Za-z0-9._~/%?&=+,-]{0,200}$`.
fn is_url_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 201
        && s[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~/%?&=+,-".contains(c))
}

fn is_port(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>().is_ok_and(|p| (1..65536).contains(&p))
}

fn refuse<T>(verb: &str, why: &str) -> Result<T> {
    fail(
        FaultKind::InvalidArgument,
        format!("arguments refusés pour « {verb} » : {why}"),
    )
}

/// `[DURÉE] [all]` après la cible d'un `logs`, dans n'importe quel ordre.
fn check_log_tail(rest: &[String]) -> Result<()> {
    let durations = rest.iter().filter(|a| is_duration(a)).count();
    let alls = rest.iter().filter(|a| *a == "all").count();
    if rest.len() > 2 || durations > 1 || alls > 1 || durations + alls != rest.len() {
        return refuse("logs", "attendu [DURÉE] [all], DURÉE = 30m, 2h, 1d");
    }
    Ok(())
}

/// Valide un verbe et ses arguments contre la grammaire de la passerelle.
pub fn validate(verb: &str, args: &[String]) -> Result<()> {
    if !VERBS.contains(&verb) {
        return fail(
            FaultKind::InvalidArgument,
            format!("verbe inconnu : « {verb} ». Verbes : {}", VERBS.join(", ")),
        );
    }
    match verb {
        "logs" => match args.first().map(String::as_str) {
            Some("journal") => check_log_tail(&args[1..]),
            Some("unit" | "docker") => {
                if !args.get(1).is_some_and(|t| is_name(t)) {
                    return refuse(verb, "nom d'unité ou de conteneur attendu");
                }
                check_log_tail(&args[2..])
            }
            _ => refuse(verb, "journal | unit NOM | docker NOM attendu"),
        },
        "status" if args.len() == 1 && is_name(&args[0]) => Ok(()),
        "status" => refuse(verb, "un nom d'unité systemd attendu"),
        "http" => match args {
            [port] if is_port(port) => Ok(()),
            [port, path] if is_port(port) && is_url_path(path) => Ok(()),
            _ => refuse(verb, "PORT [CHEMIN] attendu, CHEMIN commençant par /"),
        },
        _ if args.is_empty() => Ok(()),
        _ => refuse(verb, "ce verbe ne prend aucun argument"),
    }
}

/// Adresse SSH d'une entrée : IP ou nom DNS, rien qui puisse passer pour une
/// option (`-oProxyCommand=…`) ni pour plusieurs mots.
fn ssh_address(host: &AnsibleHost) -> Result<String> {
    let address = host.ansible_host.trim();
    let valid = !address.is_empty()
        && !address.starts_with('-')
        && address.len() <= 253
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:-".contains(c));
    if !valid {
        return fail(
            FaultKind::InvalidArgument,
            format!("{} : adresse inutilisable pour SSH ({address:?})", host.name),
        );
    }
    Ok(address.to_string())
}

/// Ligne de commande `ssh` complète, sans shell. Isolée pour être testée.
pub fn ssh_args(
    config: &RoGateConfig,
    host: &AnsibleHost,
    verb: &str,
    args: &[String],
) -> Result<Vec<String>> {
    validate(verb, args)?;
    let address = ssh_address(host)?;
    let port = host.ansible_port.unwrap_or(22).to_string();
    let mut out: Vec<String> = vec![
        "-F".into(),
        "/dev/null".into(),
        "-T".into(),
        "-a".into(),
        "-x".into(),
        "-i".into(),
        config.key.display().to_string(),
        "-l".into(),
        config.user.clone(),
        "-p".into(),
        port,
    ];
    for option in [
        "IdentitiesOnly=yes".to_string(),
        "BatchMode=yes".to_string(),
        "ConnectTimeout=10".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        format!("UserKnownHostsFile={}", config.known_hosts.display()),
        "LogLevel=ERROR".to_string(),
    ] {
        out.push("-o".into());
        out.push(option);
    }
    out.push("--".into());
    out.push(address);
    out.push(verb.to_string());
    out.extend(args.iter().cloned());
    Ok(out)
}

/// Lance le diagnostic. Le code 255 est celui de `ssh` lui-même (connexion,
/// authentification) : c'est une panne d'accès, pas une réponse de la
/// passerelle, et elle est rendue comme telle.
pub async fn diagnose(
    config: &RoGateConfig,
    host: &AnsibleHost,
    verb: &str,
    args: &[String],
) -> Result<Diagnosis> {
    if !config.key.is_file() {
        return fail(
            FaultKind::NotConfigured,
            format!(
                "clé de diagnostic absente ({}) : déployer avec ff_ro_diagnostics=true",
                config.key.display()
            ),
        );
    }
    let argv = ssh_args(config, host, verb, args)?;
    let mut child = tokio::process::Command::new("ssh")
        .args(&argv)
        // L'agent de la machine porte la clé de PILOTAGE : elle n'a pas à
        // être proposée au compte lecture seule, même pour y être refusée.
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Fault::new(FaultKind::Upstream, format!("ssh introuvable : {e}")))?;

    let stdout = child.stdout.take().expect("stdout capturé");
    let stderr = child.stderr.take().expect("stderr capturé");
    let collect = async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(MAX_OUTPUT_BYTES as u64 + 1);
        let mut stderr = stderr.take(16 * 1024);
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a?;
        b?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out, err))
    };
    let (status, out, err) = match tokio::time::timeout(config.timeout, collect).await {
        Ok(result) => result.map_err(|e| Fault::new(FaultKind::Upstream, format!("ssh : {e}")))?,
        Err(_) => {
            return fail(
                FaultKind::Timeout,
                format!("{} {verb} : pas de réponse en {} s", host.name, config.timeout.as_secs()),
            )
        }
    };

    let code = status.code();
    if code == Some(255) {
        let reason = String::from_utf8_lossy(&err);
        let reason = reason.lines().last().unwrap_or("échec de connexion").trim().to_string();
        return fail(FaultKind::Upstream, format!("ssh {} : {reason}", host.name));
    }
    let truncated = out.len() > MAX_OUTPUT_BYTES;
    let output = String::from_utf8_lossy(&out[..out.len().min(MAX_OUTPUT_BYTES)]).into_owned();
    Ok(Diagnosis {
        host: host.name.clone(),
        verb: verb.to_string(),
        args: args.to_vec(),
        exit_code: code,
        output,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn host(address: &str) -> AnsibleHost {
        AnsibleHost {
            name: "proxy1".into(),
            ansible_host: address.into(),
            ansible_port: Some(2222),
            ansible_user: None,
            hostname: None,
            server_type: None,
            provider: None,
            ansible_roles: vec![],
            alert_exclude: vec![],
            svcprobe_port: None,
            monitor_port: None,
            groups: vec![],
            vars: Default::default(),
        }
    }

    fn config() -> RoGateConfig {
        RoGateConfig {
            key: "/k/id_ro".into(),
            user: "openclaw-ro".into(),
            known_hosts: "/k/known".into(),
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_gate_grammar_is_mirrored() {
        for (verb, args) in [
            ("logs", v(&["journal"])),
            ("logs", v(&["journal", "1d", "all"])),
            ("logs", v(&["unit", "fleetforge.service", "30m"])),
            ("logs", v(&["docker", "searxng", "all", "2h"])),
            ("status", v(&["nginx"])),
            ("containers", v(&[])),
            ("system", v(&[])),
            ("disk", v(&[])),
            ("http", v(&["9750"])),
            ("http", v(&["9750", "/metrics?x=1"])),
        ] {
            assert!(validate(verb, &args).is_ok(), "{verb} {args:?} devrait passer");
        }
    }

    #[test]
    fn anything_outside_the_grammar_is_refused_before_ssh() {
        for (verb, args) in [
            ("rm", v(&["-rf", "/"])),
            ("logs", v(&[])),
            ("logs", v(&["unit"])),
            ("logs", v(&["unit", "-oProxyCommand=x"])),
            ("logs", v(&["journal", "2h", "3h"])),
            ("logs", v(&["journal", "yesterday"])),
            ("status", v(&["a;b"])),
            ("status", v(&["a b"])),
            ("containers", v(&["--no-trunc"])),
            ("disk", v(&["/"])),
            ("disk", v(&["--prune"])),
            ("http", v(&["0"])),
            ("http", v(&["70000"])),
            ("http", v(&["80", "relative"])),
            ("http", v(&["80", "/a b"])),
            ("http", v(&["80", "/$(id)"])),
        ] {
            let err = validate(verb, &args).unwrap_err();
            assert_eq!(
                crate::fault::kind_of(&err),
                Some(FaultKind::InvalidArgument),
                "{verb} {args:?}"
            );
        }
    }

    #[test]
    fn the_command_line_is_closed_and_ends_with_the_request() {
        let argv = ssh_args(&config(), &host("10.0.0.5"), "logs", &v(&["journal", "1h"])).unwrap();
        assert_eq!(&argv[..2], &["-F", "/dev/null"]);
        let dashdash = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&argv[dashdash + 1..], &["10.0.0.5", "logs", "journal", "1h"]);
        assert!(argv.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(argv.windows(2).any(|w| w == ["-l", "openclaw-ro"]));
        assert!(argv.iter().any(|a| a == "BatchMode=yes"));
    }

    #[test]
    fn an_address_that_could_be_an_option_is_refused() {
        for bad in ["-oProxyCommand=id", "", "a b", "xxx;id", "h$(id)"] {
            assert!(ssh_args(&config(), &host(bad), "system", &[]).is_err(), "{bad:?}");
        }
        assert!(ssh_args(&config(), &host("fe80::1"), "system", &[]).is_ok());
        assert!(ssh_args(&config(), &host("proxy1.example.org"), "system", &[]).is_ok());
    }
}
