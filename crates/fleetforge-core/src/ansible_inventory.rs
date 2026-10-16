/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

use crate::models::*;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

/// List all .yml inventory files in the inventories directory
pub fn list_inventories(inventories_path: &str) -> Result<Vec<AnsibleInventoryInfo>> {
    let inventories_dir = Path::new(inventories_path);
    if !inventories_dir.exists() {
        return Ok(vec![]);
    }

    let mut inventories = Vec::new();

    for entry in std::fs::read_dir(&inventories_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yml" || ext == "yaml" {
                    let file_path = path.to_string_lossy().to_string();
                    let name = path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    // Determine organization name by peeking at YAML content
                    let organization = extract_org_name(&file_path).unwrap_or_default();

                    inventories.push(AnsibleInventoryInfo {
                        name,
                        files: vec![file_path.clone()],
                        file_path,
                        organization,
                    });
                }
            }
        }
    }

    inventories.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(inventories)
}

/// Lecture statique d'un PARC : les groupes de chaque fichier, fusionnés par
/// nom. Deux fichiers d'un même parc rangent leurs hôtes sous les mêmes
/// groupes (`web3c` → `proxies`…) : sans fusion, l'arbre afficherait deux fois
/// le même groupe, chacun incomplet.
pub fn parse_inventories(files: &[String]) -> Result<Vec<AnsibleGroup>> {
    let mut merged: Vec<AnsibleGroup> = Vec::new();
    for file in files {
        merge_groups(&mut merged, parse_inventory(file)?);
    }
    merged.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(merged)
}

fn merge_groups(into: &mut Vec<AnsibleGroup>, groups: Vec<AnsibleGroup>) {
    for group in groups {
        match into.iter_mut().find(|g| g.name == group.name) {
            Some(existing) => {
                for host in group.hosts {
                    if !existing.hosts.iter().any(|h| h.name == host.name) {
                        existing.hosts.push(host);
                    }
                }
                merge_groups(&mut existing.children, group.children);
            }
            None => into.push(group),
        }
    }
}

/// Parse an inventory file and return top-level groups (below the org level)
pub fn parse_inventory(file_path: &str) -> Result<Vec<AnsibleGroup>> {
    let content = std::fs::read_to_string(file_path)?;
    if content.trim().is_empty() {
        return Ok(vec![]);
    }

    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;

    // Navigate: all -> children -> <org> -> children -> groups
    let all_children = match yaml
        .get("all")
        .and_then(|v| v.get("children"))
        .and_then(|v| v.as_mapping())
    {
        Some(m) => m,
        None => return Ok(vec![]),
    };

    // The first key under all.children is the org
    let org_value = match all_children.values().next() {
        Some(v) => v,
        None => return Ok(vec![]),
    };

    // org -> children -> actual groups
    let group_map = match org_value
        .get("children")
        .and_then(|v| v.as_mapping())
    {
        Some(m) => m,
        None => return Ok(vec![]),
    };

    // Le niveau org (`papanglabs`, `web3c`) est l'ancêtre commun de tous les
    // groupes : c'est lui qui nomme le fichier `group_vars/<org>.yml` où vivent
    // `prometheus_host`, `ansible_port` et le reste des variables de parc.
    let org_name = all_children
        .keys()
        .next()
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .to_string();

    let mut groups = Vec::new();
    for (key, value) in group_map {
        let group_name = key.as_str().unwrap_or_default().to_string();
        let group = parse_group(&group_name, value, &[org_name.clone()]);
        groups.push(group);
    }

    groups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(groups)
}

/// Recursively parse a group YAML node into an AnsibleGroup.
///
/// `ancestry` porte les groupes traversés : chaque hôte en garde une copie, ce
/// qui évite aux deux interfaces de re-parcourir l'arbre pour savoir d'où vient
/// un hôte qu'elles affichent à plat.
fn parse_group(name: &str, value: &serde_yaml::Value, ancestry: &[String]) -> AnsibleGroup {
    let mut hosts = Vec::new();
    let mut children = Vec::new();

    let mut path = ancestry.to_vec();
    path.push(name.to_string());

    // Parse direct hosts
    if let Some(hosts_map) = value.get("hosts").and_then(|v| v.as_mapping()) {
        for (host_key, host_vars) in hosts_map {
            let host_name = host_key.as_str().unwrap_or_default().to_string();
            let mut host = parse_host(&host_name, host_vars);
            host.groups = path.clone();
            hosts.push(host);
        }
    }

    // Parse nested children recursively
    if let Some(children_map) = value.get("children").and_then(|v| v.as_mapping()) {
        for (child_key, child_value) in children_map {
            let child_name = child_key.as_str().unwrap_or_default().to_string();
            let child_group = parse_group(&child_name, child_value, &path);
            children.push(child_group);
        }
    }

    AnsibleGroup {
        name: name.to_string(),
        hosts,
        children,
    }
}

/// Aplatit l'arbre de groupes en liste d'hôtes, dédupliquée par nom.
///
/// Repris de `ServicesView.tsx::flattenHosts` et de la logique « tout
/// sélectionner » des deux modals, qui en portaient chacun leur variante.
pub fn flatten_hosts(groups: &[AnsibleGroup]) -> Vec<AnsibleHost> {
    let mut out: Vec<AnsibleHost> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    fn walk(
        groups: &[AnsibleGroup],
        out: &mut Vec<AnsibleHost>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        for group in groups {
            for host in &group.hosts {
                if seen.insert(host.name.clone()) {
                    out.push(host.clone());
                }
            }
            walk(&group.children, out, seen);
        }
    }

    walk(groups, &mut out, &mut seen);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Parse a single host YAML node into an AnsibleHost
fn parse_host(name: &str, value: &serde_yaml::Value) -> AnsibleHost {
    let mut ansible_host = String::new();
    let mut ansible_port: Option<u16> = None;
    let mut ansible_user: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut server_type: Option<String> = None;
    let mut provider: Option<String> = None;
    let mut ansible_roles: Vec<String> = Vec::new();
    let mut svcprobe_port: Option<u16> = None;
    let mut monitor_port: Option<u16> = None;
    let mut vars: HashMap<String, serde_json::Value> = HashMap::new();

    if let Some(mapping) = value.as_mapping() {
        for (k, v) in mapping {
            let key = k.as_str().unwrap_or_default();
            match key {
                "ansible_host" => {
                    ansible_host = v.as_str().unwrap_or_default().to_string();
                }
                "ansible_port" => {
                    ansible_port = v.as_u64().map(|n| n as u16);
                }
                "ansible_user" => {
                    ansible_user = v.as_str().map(|s| s.to_string());
                }
                "hostname" => {
                    hostname = v.as_str().map(|s| s.to_string());
                }
                "server_type" => {
                    server_type = v.as_str().map(|s| s.to_string());
                }
                "provider" => {
                    provider = v.as_str().map(|s| s.to_string());
                }
                "ansible_roles" => {
                    ansible_roles = parse_role_families(v);
                }
                "svcprobe_port" => {
                    svcprobe_port = v.as_u64().map(|n| n as u16);
                }
                "monitor_port" => {
                    monitor_port = v.as_u64().map(|n| n as u16);
                }
                other => {
                    let json_val = yaml_to_json(v);
                    vars.insert(other.to_string(), json_val);
                }
            }
        }
    }

    AnsibleHost {
        name: name.to_string(),
        ansible_host,
        ansible_port,
        ansible_user,
        hostname,
        server_type,
        provider,
        ansible_roles,
        svcprobe_port,
        monitor_port,
        groups: Vec::new(),
        vars,
    }
}

/// `ansible_roles` est toujours une liste par convention, mais un inventaire
/// tiers ou une saisie à la main peut y mettre une chaîne. On accepte les deux
/// en lecture — le consommateur écrit `'brk' in ansible_roles` sans tester le
/// type — et le diagnostic signalera la forme non conforme.
fn parse_role_families(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        serde_yaml::Value::String(s) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

/// Convert a serde_yaml::Value to serde_json::Value
fn yaml_to_json(value: &serde_yaml::Value) -> serde_json::Value {
    match value {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::json!(f)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
        serde_yaml::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = k.as_str().unwrap_or_default().to_string();
                obj.insert(key, yaml_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        serde_yaml::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

/// Extract the organization name from the first key under all.children
fn extract_org_name(file_path: &str) -> Result<String> {
    let content = std::fs::read_to_string(file_path)?;
    if content.trim().is_empty() {
        return Ok(String::new());
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let org = yaml
        .get("all")
        .and_then(|v| v.get("children"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.keys().next())
        .and_then(|k| k.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(org)
}
