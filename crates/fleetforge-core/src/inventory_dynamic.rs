/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Lecture d'inventaire par `ansible-inventory --list`.
//!
//! Le lecteur `serde_yaml` ne voit que ce que le fichier contient littéralement.
//! Il lui échappe donc :
//!
//! - **les inventaires dynamiques** — `gcp.yml` est une configuration de plugin
//!   `gcp_compute` sans `all.children` ; le lecteur statique y trouve zéro
//!   groupe et le dit en renvoyant une liste vide. Les hôtes GCP étaient
//!   invisibles, sans le moindre message ;
//! - **la précédence des `group_vars`** — `prometheus_host`, `ansible_port`,
//!   `ansible_user` vivent dans `group_vars/<org>.yml`, jamais sur l'hôte ;
//! - **le Jinja** — `hostname: proxy1.{{ domain_name }}` restait brut.
//!
//! Ansible est le seul à savoir résoudre tout cela. On lui délègue, et on
//! retombe sur le lecteur statique s'il n'est pas installé.

use crate::models::{AnsibleGroup, AnsibleHost};
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;

/// Où trouver de quoi résoudre un inventaire.
#[derive(Debug, Clone, Default)]
pub struct ResolveContext {
    /// Racine du dépôt Ansible — le `cwd` que supposent les wrappers.
    pub root: Option<PathBuf>,
    /// Dossier des playbooks. Sans lui, `group_vars/` n'est pas chargé : il vit
    /// sous `playbooks/`, et non à côté des inventaires.
    pub playbook_dir: Option<PathBuf>,
}

pub fn is_available() -> bool {
    Command::new("ansible-inventory")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Résout un parc — un ou plusieurs inventaires, quel qu'en soit le type.
pub fn resolve(files: &[String], ctx: &ResolveContext) -> Result<Vec<AnsibleGroup>> {
    let json = run_ansible_inventory(files, ctx)?;
    parse_inventory_json(&json)
}

fn run_ansible_inventory(files: &[String], ctx: &ResolveContext) -> Result<Value> {
    let mut cmd = Command::new("ansible-inventory");
    if let Some(root) = &ctx.root {
        if root.is_dir() {
            cmd.current_dir(root);
        }
    }
    // Même correctif que pour le runner : sans cela les workers forkés
    // d'Ansible meurent sur macOS.
    #[cfg(target_os = "macos")]
    cmd.env("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES");

    // Un `-i` par fichier : `-i a,b` serait lu comme une liste d'HÔTES.
    for file in files {
        cmd.arg("-i").arg(file);
    }
    if let Some(dir) = &ctx.playbook_dir {
        if dir.is_dir() {
            cmd.arg("--playbook-dir").arg(dir);
        }
    }
    cmd.arg("--list");

    let out = cmd
        .output()
        .with_context(|| "ansible-inventory introuvable".to_string())?;

    if !out.status.success() {
        // stderr porte aussi de simples avertissements ; ne le remonter qu'en
        // cas d'échec réel, sinon chaque lecture ressemblerait à une panne.
        return Err(anyhow!(
            "ansible-inventory a échoué sur {} : {}",
            files.join(", "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    serde_json::from_slice(&out.stdout).context("sortie de ansible-inventory illisible")
}

/// Reconstruit l'arbre de groupes depuis la sortie `--list`.
///
/// Forme : `{"_meta": {"hostvars": {...}}, "all": {"children": [...]},
/// "<groupe>": {"hosts": [...], "children": [...]}}`.
pub fn parse_inventory_json(json: &Value) -> Result<Vec<AnsibleGroup>> {
    let obj = json
        .as_object()
        .ok_or_else(|| anyhow!("inventaire résolu : objet attendu"))?;

    let hostvars = json
        .get("_meta")
        .and_then(|m| m.get("hostvars"))
        .and_then(|h| h.as_object())
        .cloned()
        .unwrap_or_default();

    // `all.children` porte le niveau org. `ungrouped` est un artefact d'Ansible
    // — un groupe vide qui n'apprend rien et alourdirait chaque arbre.
    let roots: Vec<String> = obj
        .get("all")
        .and_then(|a| a.get("children"))
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|n| *n != "ungrouped")
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let mut groups = Vec::new();
    for root in &roots {
        // Le niveau org est l'ancêtre commun ; ses enfants sont les groupes
        // que les interfaces affichent, comme avec le lecteur statique.
        let ancestry = vec![root.clone()];
        for child in children_of(obj, root) {
            groups.push(build_group(
                obj,
                &hostvars,
                &child,
                &ancestry,
                &mut HashSet::new(),
            ));
        }
        // Un org qui porte directement des hôtes (sans sous-groupe) ne doit pas
        // disparaître de l'arbre.
        let direct = hosts_of(obj, root);
        if !direct.is_empty() {
            groups.push(build_group(obj, &hostvars, root, &[], &mut HashSet::new()));
        }
    }

    groups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(groups)
}

fn children_of(obj: &serde_json::Map<String, Value>, group: &str) -> Vec<String> {
    obj.get(group)
        .and_then(|g| g.get("children"))
        .and_then(|c| c.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default()
}

fn hosts_of(obj: &serde_json::Map<String, Value>, group: &str) -> Vec<String> {
    obj.get(group)
        .and_then(|g| g.get("hosts"))
        .and_then(|h| h.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default()
}

fn build_group(
    obj: &serde_json::Map<String, Value>,
    hostvars: &serde_json::Map<String, Value>,
    name: &str,
    ancestry: &[String],
    // Un groupe peut être l'enfant de plusieurs parents ; sans garde, une
    // boucle d'inventaire ferait tourner la reconstruction indéfiniment.
    visiting: &mut HashSet<String>,
) -> AnsibleGroup {
    let mut path = ancestry.to_vec();
    path.push(name.to_string());

    let hosts = hosts_of(obj, name)
        .into_iter()
        .map(|h| {
            let vars = hostvars.get(&h).cloned().unwrap_or(Value::Null);
            host_from_vars(&h, &vars, &path)
        })
        .collect();

    let children = if visiting.insert(name.to_string()) {
        let kids = children_of(obj, name)
            .into_iter()
            .map(|c| build_group(obj, hostvars, &c, &path, visiting))
            .collect();
        visiting.remove(name);
        kids
    } else {
        Vec::new()
    };

    AnsibleGroup {
        name: name.to_string(),
        hosts,
        children,
    }
}

fn host_from_vars(name: &str, vars: &Value, groups: &[String]) -> AnsibleHost {
    let map = vars.as_object().cloned().unwrap_or_default();

    let string_of = |k: &str| map.get(k).and_then(|v| v.as_str()).map(String::from);
    let port_of = |k: &str| {
        map.get(k).and_then(|v| {
            // Ansible rend parfois les ports en chaîne (`ansible_port: "22"`).
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .map(|n| n as u16)
        })
    };

    // `ansible_roles`, `alert_exclude` : liste par convention, chaîne
    // « a, b » tolérée en lecture.
    let list_of = |k: &str| -> Vec<String> {
        map.get(k)
            .map(|v| match v {
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect(),
                Value::String(s) => s
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default()
    };

    const PROMOTED: [&str; 10] = [
        "ansible_host",
        "ansible_port",
        "ansible_user",
        "hostname",
        "server_type",
        "provider",
        "ansible_roles",
        "alert_exclude",
        "svcprobe_port",
        "monitor_port",
    ];

    // `ansible-inventory --list` ne déchiffre pas : une valeur vaultée arrive
    // sous la forme `{"__ansible_vault": "$ANSIBLE_VAULT;..."}`. On la remplace
    // par un marqueur — recracher le cryptogramme dans l'UI n'apprend rien et
    // invite à le coller ailleurs.
    let rest: HashMap<String, Value> = map
        .iter()
        .filter(|(k, _)| !PROMOTED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), redact_vault(v)))
        .collect();

    AnsibleHost {
        name: name.to_string(),
        ansible_host: string_of("ansible_host").unwrap_or_default(),
        ansible_port: port_of("ansible_port"),
        ansible_user: string_of("ansible_user"),
        hostname: string_of("hostname"),
        server_type: string_of("server_type"),
        provider: string_of("provider"),
        ansible_roles: list_of("ansible_roles"),
        alert_exclude: list_of("alert_exclude"),
        svcprobe_port: port_of("svcprobe_port"),
        monitor_port: port_of("monitor_port"),
        groups: groups.to_vec(),
        vars: rest,
    }
}

/// Remplace récursivement les valeurs chiffrées par un marqueur.
fn redact_vault(value: &Value) -> Value {
    match value {
        Value::Object(map) if map.contains_key("__ansible_vault") => {
            Value::String("(chiffré — Ansible Vault)".to_string())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_vault(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_vault).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_vaulted_value_never_reaches_the_interface_as_ciphertext() {
        let v = json!({
            "_meta": { "hostvars": { "h": {
                "ansible_host": "10.0.0.1",
                "ansible_become_password": { "__ansible_vault": "$ANSIBLE_VAULT;1.1;AES256\n3562..." }
            }}},
            "all": { "children": ["org"] },
            "org": { "children": ["g"] },
            "g": { "hosts": ["h"] }
        });
        let groups = parse_inventory_json(&v).unwrap();
        let secret = &groups[0].hosts[0].vars["ansible_become_password"];
        assert_eq!(secret, "(chiffré — Ansible Vault)");
        assert!(!secret.to_string().contains("ANSIBLE_VAULT;"));
    }

    #[test]
    fn redaction_reaches_nested_values() {
        let nested = json!({
            "creds": [{ "pw": { "__ansible_vault": "$ANSIBLE_VAULT;x" } }]
        });
        let out = redact_vault(&nested).to_string();
        assert!(!out.contains("ANSIBLE_VAULT"));
    }

    fn sample() -> Value {
        json!({
            "_meta": { "hostvars": {
                "proxy1": {
                    "ansible_host": "203.0.113.10",
                    "ansible_port": 16138,
                    "provider": "contabo",
                    "ansible_roles": ["proxy", "nginx"],
                    "app_port": 9741
                },
                "rpcbtc1": {
                    "ansible_host": "203.0.113.30",
                    "provider": "contabo",
                    "ansible_roles": ["rpcbtc"]
                }
            }},
            "all": { "children": ["ungrouped", "papanglabs"] },
            "papanglabs": { "children": ["proxies", "nodes"] },
            "proxies": { "hosts": ["proxy1"] },
            "nodes": { "children": ["rpcsbtc"] },
            "rpcsbtc": { "hosts": ["rpcbtc1"] }
        })
    }

    #[test]
    fn rebuilds_the_group_tree_below_the_org() {
        let groups = parse_inventory_json(&sample()).unwrap();
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, vec!["nodes", "proxies"]);
    }

    #[test]
    fn ungrouped_is_dropped() {
        let groups = parse_inventory_json(&sample()).unwrap();
        assert!(!groups.iter().any(|g| g.name == "ungrouped"));
    }

    #[test]
    fn promotes_the_typed_fields_and_keeps_the_rest() {
        let groups = parse_inventory_json(&sample()).unwrap();
        let proxies = groups.iter().find(|g| g.name == "proxies").unwrap();
        let h = &proxies.hosts[0];
        assert_eq!(h.ansible_host, "203.0.113.10");
        assert_eq!(h.ansible_port, Some(16138));
        assert_eq!(h.ansible_roles, vec!["proxy", "nginx"]);
        // Les variables non promues restent accessibles, sans être perdues.
        assert!(h.vars.contains_key("app_port"));
        assert!(!h.vars.contains_key("ansible_roles"));
    }

    #[test]
    fn ancestry_starts_at_the_org_and_follows_nesting() {
        let groups = parse_inventory_json(&sample()).unwrap();
        let nodes = groups.iter().find(|g| g.name == "nodes").unwrap();
        let rpcsbtc = &nodes.children[0];
        assert_eq!(
            rpcsbtc.hosts[0].groups,
            vec!["papanglabs", "nodes", "rpcsbtc"]
        );
    }

    #[test]
    fn a_group_cycle_does_not_loop_forever() {
        let looped = json!({
            "_meta": { "hostvars": {} },
            "all": { "children": ["org"] },
            "org": { "children": ["a"] },
            "a": { "children": ["b"] },
            "b": { "children": ["a"] }
        });
        let groups = parse_inventory_json(&looped).unwrap();
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn a_port_given_as_a_string_is_still_a_port() {
        let v = json!({
            "_meta": { "hostvars": { "h": { "ansible_port": "22" } } },
            "all": { "children": ["org"] },
            "org": { "children": ["g"] },
            "g": { "hosts": ["h"] }
        });
        let groups = parse_inventory_json(&v).unwrap();
        assert_eq!(groups[0].hosts[0].ansible_port, Some(22));
    }
}
