/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! API d'automatisation : ce qu'un appelant programmatique (AgentHub, poste
//! « Infrastructure Manager ») lit et lance.
//!
//! Chaque entrée est VALIDÉE contre ce que le dépôt déclare réellement — un
//! parc par son nom, un hôte par l'inventaire, un playbook par le dossier des
//! playbooks, une variable par une grammaire fermée. Rien de ce qui arrive ici
//! ne rejoint une ligne de commande sans être passé par l'une de ces portes.

use crate::fault::{fail, Fault, FaultKind};
use crate::model::Fleet;
use crate::models::{AnsibleGroup, AnsiblePlaybook};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

// === Hôtes ===

/// Un hôte tel que l'API d'automatisation le décrit.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostSummary {
    pub name: String,
    /// `ansible_host` — vide quand l'entrée n'en déclare pas.
    pub ip: String,
    /// Port SSH (`ansible_port`), `None` = 22.
    pub port: Option<u16>,
    /// Groupes d'inventaire de l'entrée, tous parents confondus.
    pub groups: Vec<String>,
    /// Familles de rôles (`ansible_roles`).
    pub roles: Vec<String>,
    /// Hébergeur (`provider`), `None` quand l'entrée l'a oublié.
    pub provider: Option<String>,
}

/// Groupes qui contiennent chaque hôte, chemin d'ancêtres compris.
fn memberships(groups: &[AnsibleGroup]) -> HashMap<String, Vec<String>> {
    fn walk(groups: &[AnsibleGroup], path: &mut Vec<String>, out: &mut HashMap<String, Vec<String>>) {
        for group in groups {
            path.push(group.name.clone());
            for host in &group.hosts {
                let entry = out.entry(host.name.clone()).or_default();
                for name in path.iter() {
                    if !entry.contains(name) && name != "all" && name != "ungrouped" {
                        entry.push(name.clone());
                    }
                }
            }
            walk(&group.children, path, out);
            path.pop();
        }
    }
    let mut out = HashMap::new();
    walk(groups, &mut Vec::new(), &mut out);
    out
}

pub fn host_summaries(fleet: &Fleet) -> Vec<HostSummary> {
    let groups = memberships(&fleet.groups);
    fleet
        .hosts
        .iter()
        .map(|h| {
            // Le chemin d'ancêtres que porte l'entrée d'abord : le lecteur
            // statique y range l'organisation (`web3c`), qui n'est pas un
            // nœud de l'arbre. Puis les autres groupes où elle figure.
            let mut all: Vec<String> = Vec::new();
            for name in h.groups.iter().chain(groups.get(&h.name).into_iter().flatten()) {
                if !all.contains(name) && name != "all" && name != "ungrouped" {
                    all.push(name.clone());
                }
            }
            HostSummary {
                name: h.name.clone(),
                ip: h.ansible_host.clone(),
                port: h.ansible_port,
                groups: all,
                roles: h.ansible_roles.clone(),
                provider: h.provider.clone(),
            }
        })
        .collect()
}

/// Noms de groupes d'un parc, `all` compris (motif `--limit` légitime).
fn group_names(groups: &[AnsibleGroup], out: &mut BTreeSet<String>) {
    for group in groups {
        out.insert(group.name.clone());
        group_names(&group.children, out);
    }
}

/// `--limit` : chaque élément doit être un hôte ou un groupe du parc.
///
/// Les motifs d'Ansible (`web*`, `!proxy1`, `a:&b`, `a,b`) sont refusés :
/// une cible se nomme, elle ne se devine pas.
pub fn validate_limit(fleet: &Fleet, limit: &[String]) -> Result<()> {
    let mut known: BTreeSet<String> = fleet.hosts.iter().map(|h| h.name.clone()).collect();
    known.extend(fleet.hosts.iter().flat_map(|h| h.groups.iter().cloned()));
    known.insert("all".to_string());
    group_names(&fleet.groups, &mut known);
    let unknown: Vec<&String> = limit.iter().filter(|l| !known.contains(*l)).collect();
    if !unknown.is_empty() {
        return fail(
            FaultKind::UnknownHost,
            format!(
                "--limit hors inventaire du parc {} : {}",
                fleet.inventory_path,
                unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
        );
    }
    Ok(())
}

// === Identifiants ===

fn is_token(s: &str, max: usize, extra: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && s.len() <= max
        && chars.all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// Un NOM de parc — jamais un chemin de fichier. Le contournement par
/// chemin (`parc::resolve`) reste réservé à l'opérateur.
pub fn validate_parc_name(name: &str) -> Result<()> {
    if !is_token(name, 64, "_.-") {
        return fail(FaultKind::InvalidArgument, format!("nom de parc invalide : {name:?}"));
    }
    Ok(())
}

/// Identifiant de run : il nomme un flux SSE et une entrée du registre.
pub fn validate_run_id(id: &str) -> Result<()> {
    if !is_token(id, 128, "_.:-") {
        return fail(
            FaultKind::InvalidArgument,
            format!("identifiant de run invalide : {id:?} (lettres, chiffres, _ . : -)"),
        );
    }
    Ok(())
}

/// Variables `-e`.
///
/// Toujours : un nom de variable Ansible valide. En mode `strict` (compte
/// d'automatisation), en plus :
///   • aucune `ansible_*` — elles redéfinissent la connexion et l'élévation
///     (`ansible_ssh_common_args=-o ProxyCommand=…` exécute une commande sur
///     CETTE machine) ;
///   • aucun délimiteur Jinja — une valeur d'extra-var est rendue par Ansible,
///     `{{ lookup('pipe', …) }}` y exécuterait une commande locale.
pub fn validate_extra_vars(vars: &HashMap<String, String>, strict: bool) -> Result<()> {
    for (key, value) in vars {
        let identifier = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.len() <= 128
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !identifier {
            return fail(FaultKind::InvalidArgument, format!("nom de variable invalide : {key:?}"));
        }
        if !strict {
            continue;
        }
        if key.to_ascii_lowercase().starts_with("ansible_") {
            return fail(
                FaultKind::InvalidArgument,
                format!("variable réservée à l'opérateur : {key}"),
            );
        }
        if ["{{", "{%", "{#", "\0"].iter().any(|d| value.contains(d)) || value.len() > 4096 {
            return fail(
                FaultKind::InvalidArgument,
                format!("valeur refusée pour {key} (gabarit Jinja ou trop longue)"),
            );
        }
    }
    Ok(())
}

// === Playbooks ===

/// Catégorie d'un playbook, lue dans son nom.
///
/// Ordre des règles : le DESTRUCTIF d'abord (`purge-prometheus` est une purge,
/// pas de la supervision), puis les thèmes transverses, puis le verbe.
pub fn playbook_family(stem: &str) -> &'static str {
    let starts = |p: &str| stem.starts_with(p);
    let has = |p: &str| stem.contains(p);
    if starts("remove-") {
        "remove"
    } else if starts("purge-") {
        "purge"
    } else if has("security") || has("ufw") || has("sshd") {
        "security"
    } else if has("monitoring") || has("prometheus-alerts") || has("exporter") {
        "monitoring"
    } else if has("backup") || starts("restore-") {
        "backup"
    } else if starts("deploy-") || starts("install-") {
        "deploy"
    } else if starts("update-") {
        "update"
    } else if starts("setup-") {
        "setup"
    } else if starts("migrate-") || starts("switch-") || starts("duplicate-") {
        "migrate"
    } else {
        "other"
    }
}

/// Famille de SERVICE (CLAUDE.md § 2) : ce qui suit le verbe du nom.
fn service_of(stem: &str) -> Option<String> {
    let (_, rest) = stem.split_once('-')?;
    (!rest.is_empty()).then(|| rest.to_string())
}

/// Un playbook tel que l'API d'automatisation le décrit.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PlaybookSummary {
    /// Chemin RELATIF au dossier des playbooks — ce qu'on renvoie à
    /// `run_ansible_playbook`, stable d'une machine à l'autre.
    pub path: String,
    pub family: String,
    pub service: Option<String>,
    pub label: String,
    pub description: String,
}

/// Fichiers temporaires que le runner compose à côté des playbooks.
fn is_transient(stem: &str) -> bool {
    stem.starts_with("fleetforge_playbook_")
}

pub fn playbook_summaries(playbooks: &[AnsiblePlaybook]) -> Vec<PlaybookSummary> {
    let mut out: Vec<PlaybookSummary> = playbooks
        .iter()
        .filter(|p| !is_transient(&p.name))
        .filter_map(|p| {
            let file = Path::new(&p.path).file_name()?.to_str()?.to_string();
            Some(PlaybookSummary {
                path: file,
                family: playbook_family(&p.name).to_string(),
                service: service_of(&p.name),
                label: p.label.clone(),
                description: p.description.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Résout une référence de playbook : nom relatif (`deploy-x.yml`) ou chemin
/// absolu. Le fichier doit être un `.yml`/`.yaml` DIRECTEMENT dans le dossier
/// des playbooks, une fois les liens symboliques et les `..` résolus.
pub fn resolve_playbook(playbooks_dir: &str, reference: &str) -> Result<PathBuf> {
    let reference = reference.trim();
    if playbooks_dir.trim().is_empty() {
        return fail(FaultKind::NotConfigured, "dossier des playbooks non configuré");
    }
    if reference.is_empty() || reference.contains('\0') {
        return fail(FaultKind::InvalidArgument, "playbook manquant");
    }
    let dir = Path::new(playbooks_dir)
        .canonicalize()
        .map_err(|e| Fault::new(FaultKind::NotConfigured, format!("dossier des playbooks : {e}")))?;
    let candidate = if Path::new(reference).is_absolute() {
        PathBuf::from(reference)
    } else {
        dir.join(reference.strip_prefix("playbooks/").unwrap_or(reference))
    };
    let unknown = || Fault::new(FaultKind::UnknownPlaybook, format!("playbook inconnu : {reference}"));
    let resolved = candidate.canonicalize().map_err(|_| unknown())?;
    let stem = resolved.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let yaml = resolved
        .extension()
        .is_some_and(|e| e == "yml" || e == "yaml");
    if resolved.parent() != Some(dir.as_path()) || !resolved.is_file() || !yaml || is_transient(stem) {
        return Err(unknown().into());
    }
    Ok(resolved)
}

/// Chemin relatif d'un playbook résolu, pour les empreintes et l'affichage.
pub fn playbook_name(resolved: &Path) -> String {
    resolved
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string()
}

// === Alertmanager ===

/// Lit une variable SIMPLE de `group_vars/<groupe>.yml` : une chaîne ou un
/// nombre en clair. Une valeur chiffrée (`!vault`) ou templatée (`{{ … }}`)
/// n'est pas résoluble ici et compte comme absente.
fn plain_group_var(playbooks_dir: &str, group: &str, key: &str) -> Option<String> {
    let path = Path::new(playbooks_dir).join("group_vars").join(format!("{group}.yml"));
    let yaml: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    let value = match yaml.get(key)? {
        serde_yaml::Value::String(s) => s.trim().to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    (!value.is_empty() && !value.contains("{{")).then_some(value)
}

/// URL d'Alertmanager d'un parc.
///
/// Dans l'ordre :
///   1. `alertmanager_url` en clair dans `group_vars/<organisation>.yml` ;
///   2. `alertmanager_host` (entrée d'inventaire) et `alertmanager_port`
///      (défaut 9093) du même fichier — la convention des deux parcs ;
///   3. la première entrée qui porte la famille `alertmanager`, comme le fait
///      `fleet-watch` d'OpenClaw.
///
/// Pas de valeur globale de repli : comme pour Prometheus, interroger
/// l'Alertmanager d'un autre parc ne rendrait pas une liste vide mais FAUSSE.
pub fn alertmanager_url(playbooks_dir: &str, fleet: &Fleet) -> Result<String> {
    let group = &fleet.organization;
    if let Some(url) = plain_group_var(playbooks_dir, group, "alertmanager_url") {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return fail(FaultKind::NotConfigured, format!("alertmanager_url invalide : {url}"));
        }
        return Ok(url.trim_end_matches('/').to_string());
    }
    let port = plain_group_var(playbooks_dir, group, "alertmanager_port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9093);
    let entry = plain_group_var(playbooks_dir, group, "alertmanager_host")
        .and_then(|name| fleet.host(&name).cloned())
        .or_else(|| {
            fleet
                .hosts
                .iter()
                .find(|h| h.ansible_roles.iter().any(|r| r == "alertmanager"))
                .cloned()
        });
    match entry {
        Some(h) if !h.ansible_host.trim().is_empty() => {
            Ok(format!("http://{}:{port}", h.ansible_host.trim()))
        }
        _ => fail(
            FaultKind::NotConfigured,
            format!(
                "aucun Alertmanager pour le parc {} : renseigner alertmanager_url ou \
                 alertmanager_host dans group_vars/{group}.yml",
                fleet.inventory_path
            ),
        ),
    }
}

/// Alertes actives, non silencieuses et non inhibées — ce qui part aussi par
/// e-mail et par le webhook. Le JSON de l'API v2 est rendu TEL QUEL.
pub async fn fetch_alerts(base_url: &str) -> Result<serde_json::Value> {
    let url = format!("{base_url}/api/v2/alerts");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = http
        .get(&url)
        .query(&[("active", "true"), ("silenced", "false"), ("inhibited", "false")])
        .send()
        .await
        .map_err(|e| Fault::new(FaultKind::Upstream, format!("Alertmanager injoignable ({base_url}) : {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return fail(FaultKind::Upstream, format!("Alertmanager a répondu {status} ({base_url})"));
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| Fault::new(FaultKind::Upstream, format!("réponse d'Alertmanager illisible : {e}")))?;
    if !body.is_array() {
        return fail(FaultKind::Upstream, "réponse d'Alertmanager inattendue (liste attendue)");
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::kind_of;
    use crate::models::AnsibleHost;

    fn host(name: &str, ip: &str, roles: &[&str]) -> AnsibleHost {
        AnsibleHost {
            name: name.into(),
            ansible_host: ip.into(),
            ansible_port: None,
            ansible_user: None,
            hostname: None,
            server_type: None,
            provider: Some("contabo".into()),
            ansible_roles: roles.iter().map(|s| s.to_string()).collect(),
            alert_exclude: vec![],
            svcprobe_port: None,
            monitor_port: None,
            groups: vec![],
            vars: Default::default(),
        }
    }

    fn fleet() -> Fleet {
        let groups = vec![AnsibleGroup {
            name: "web3c".into(),
            hosts: vec![],
            children: vec![
                AnsibleGroup {
                    name: "proxies".into(),
                    hosts: vec![host("proxy1", "10.0.0.1", &["proxy"])],
                    children: vec![],
                },
                AnsibleGroup {
                    name: "monitoring".into(),
                    hosts: vec![
                        host("monitor", "10.0.0.2", &["monitoring"]),
                        host("alertmanager1", "10.0.0.2", &["alertmanager"]),
                    ],
                    children: vec![],
                },
            ],
        }];
        Fleet::build("web3c", "web3c", groups)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ff-automation-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("group_vars")).unwrap();
        dir
    }

    #[test]
    fn hosts_carry_every_group_on_their_path() {
        let hosts = host_summaries(&fleet());
        let proxy = hosts.iter().find(|h| h.name == "proxy1").unwrap();
        assert_eq!(proxy.groups, vec!["web3c", "proxies"]);
        assert_eq!(proxy.roles, vec!["proxy"]);
        assert_eq!(proxy.ip, "10.0.0.1");
        assert_eq!(proxy.provider.as_deref(), Some("contabo"));
    }

    #[test]
    fn limits_must_name_hosts_or_groups_of_the_parc() {
        let f = fleet();
        assert!(validate_limit(&f, &["proxy1".into(), "monitoring".into(), "all".into()]).is_ok());
        for bad in ["proxy*", "!proxy1", "proxy1,monitor", "ghost", "proxies:&monitoring"] {
            let err = validate_limit(&f, &[bad.to_string()]).unwrap_err();
            assert_eq!(kind_of(&err), Some(FaultKind::UnknownHost), "{bad}");
        }
    }

    #[test]
    fn identifiers_have_a_closed_grammar() {
        assert!(validate_parc_name("web3c").is_ok());
        for bad in ["", "../etc", "/abs/web3c_inventory.yml", "-x", "a b"] {
            assert!(validate_parc_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_run_id("agenthub-1729:check").is_ok());
        let long = "a".repeat(129);
        for bad in ["", "a/b", "x y", "-x", long.as_str()] {
            assert!(validate_run_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn extra_vars_are_strict_for_automation_only() {
        let vars = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
        assert!(validate_extra_vars(&vars("ollama_model_name", "llama3"), true).is_ok());
        assert!(validate_extra_vars(&vars("bad-name", "x"), false).is_err());
        assert!(validate_extra_vars(&vars("ansible_ssh_common_args", "-o x"), false).is_ok());
        assert!(validate_extra_vars(&vars("ansible_ssh_common_args", "-o x"), true).is_err());
        assert!(validate_extra_vars(&vars("ANSIBLE_BECOME", "x"), true).is_err());
        assert!(validate_extra_vars(&vars("x", "{{ lookup('pipe','id') }}"), true).is_err());
        assert!(validate_extra_vars(&vars("x", "{% if %}"), true).is_err());
    }

    #[test]
    fn playbook_families_come_from_the_name() {
        for (name, family) in [
            ("deploy-fleetforge", "deploy"),
            ("remove-prometheus", "remove"),
            ("purge-monitoring", "purge"),
            ("update-security-ssh", "security"),
            ("update-ufw-all", "security"),
            ("update-prometheus-alerts", "monitoring"),
            ("deploy-exporter-sys", "monitoring"),
            ("check-monitoring", "monitoring"),
            ("deploy-backup", "backup"),
            ("restore-brk", "backup"),
            ("retarget-backups", "backup"),
            ("update-proxy", "update"),
            ("setup-server", "setup"),
            ("migrate-timescale", "migrate"),
            ("temp", "other"),
        ] {
            assert_eq!(playbook_family(name), family, "{name}");
        }
        assert_eq!(service_of("deploy-sync-server").as_deref(), Some("sync-server"));
        assert_eq!(service_of("temp"), None);
    }

    #[test]
    fn a_playbook_must_live_directly_in_the_playbooks_folder() {
        let dir = scratch("playbooks");
        std::fs::write(dir.join("deploy-x.yml"), "---\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        std::fs::write(dir.join("fleetforge_playbook_1.yml"), "---\n").unwrap();
        std::fs::create_dir_all(dir.join("roles/r/tasks")).unwrap();
        std::fs::write(dir.join("roles/r/tasks/main.yml"), "---\n").unwrap();
        let d = dir.to_str().unwrap();

        let ok = resolve_playbook(d, "deploy-x.yml").unwrap();
        assert_eq!(playbook_name(&ok), "deploy-x.yml");
        assert_eq!(resolve_playbook(d, ok.to_str().unwrap()).unwrap(), ok);
        assert_eq!(resolve_playbook(d, "playbooks/deploy-x.yml").unwrap(), ok);

        for bad in [
            "../deploy-x.yml",
            "roles/r/tasks/main.yml",
            "notes.txt",
            "missing.yml",
            "fleetforge_playbook_1.yml",
            "/etc/hosts",
            "",
        ] {
            let err = resolve_playbook(d, bad).unwrap_err();
            assert!(
                matches!(kind_of(&err), Some(FaultKind::UnknownPlaybook | FaultKind::InvalidArgument)),
                "{bad:?} : {err}"
            );
        }
    }

    #[test]
    fn the_alertmanager_url_follows_the_parc_group_vars() {
        let f = fleet();
        let dir = scratch("am");
        let d = dir.to_str().unwrap();
        let gv = dir.join("group_vars/web3c.yml");

        std::fs::write(&gv, "alertmanager_host: alertmanager1\nalertmanager_port: 9094\n").unwrap();
        assert_eq!(alertmanager_url(d, &f).unwrap(), "http://10.0.0.2:9094");

        std::fs::write(&gv, "alertmanager_url: https://am.example.org/\n").unwrap();
        assert_eq!(alertmanager_url(d, &f).unwrap(), "https://am.example.org");

        // Valeur chiffrée : non résoluble, on retombe sur la famille.
        std::fs::write(&gv, "alertmanager_url: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\n").unwrap();
        assert_eq!(alertmanager_url(d, &f).unwrap(), "http://10.0.0.2:9093");

        let mut lonely = fleet();
        lonely.hosts.retain(|h| h.name == "proxy1");
        std::fs::write(&gv, "parc_name: web3c\n").unwrap();
        let err = alertmanager_url(d, &lonely).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::NotConfigured));
    }
}
