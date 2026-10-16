/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

use anyhow::Result;
use std::path::Path;

/// List all .yml/.yaml files in {playbooks_path}/group_vars/
pub fn list_group_vars_files(playbooks_path: &str) -> Result<Vec<String>> {
    let dir = Path::new(playbooks_path).join("group_vars");
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "yml" || ext == "yaml" {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    files.push(name);
                }
            }
        }
    }

    files.sort();
    Ok(files)
}

/// Read a group_vars YAML file and return it as a list of {key, value, type} entries.
/// Preserves original YAML ordering and represents values as strings for the UI.
pub fn read_group_vars_file(playbooks_path: &str, filename: &str) -> Result<Vec<GroupVarEntry>> {
    let path = Path::new(playbooks_path)
        .join("group_vars")
        .join(filename);
    let content = std::fs::read_to_string(&path)?;
    if content.trim().is_empty() {
        return Ok(vec![]);
    }

    let yaml: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let mapping = match yaml.as_mapping() {
        Some(m) => m,
        None => return Ok(vec![]),
    };

    let mut entries = Vec::new();
    for (k, v) in mapping {
        let key = k.as_str().unwrap_or_default().to_string();
        let (value_str, value_type) = yaml_value_to_string(v);
        entries.push(GroupVarEntry {
            key,
            value: value_str,
            value_type,
        });
    }

    Ok(entries)
}

/// Type des valeurs chiffrées par Ansible Vault. Lecture seule : la valeur
/// n'est jamais déchiffrée pour l'affichage, et jamais réécrite.
pub const VAULT_TYPE: &str = "vault";

/// Écrit les entrées modifiées, en préservant tout le reste du fichier.
///
/// L'implémentation précédente reconstruisait le fichier depuis une `Mapping` :
/// elle effaçait les commentaires — nombreux et porteurs de sens ici — et,
/// depuis le passage au vault, aurait remplacé les blocs `!vault` par leur
/// représentation aplatie, détruisant le chiffrement sans rien signaler.
///
/// On édite donc les lignes visées et rien d'autre, et on refuse de toucher à
/// une valeur chiffrée.
pub fn write_group_vars_file(
    playbooks_path: &str,
    filename: &str,
    entries: &[GroupVarEntry],
) -> Result<()> {
    let path = Path::new(playbooks_path)
        .join("group_vars")
        .join(filename);
    let content = std::fs::read_to_string(&path)?;

    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    for entry in entries {
        if entry.value_type == VAULT_TYPE {
            continue; // chiffré : hors de portée de l'éditeur
        }
        set_key(&mut lines, entry)?;
    }

    let mut updated = lines.join("\n");
    if content.ends_with('\n') && !updated.ends_with('\n') {
        updated.push('\n');
    }

    // Un group_vars cassé ne se voit qu'au prochain déploiement, trop tard.
    serde_yaml::from_str::<serde_yaml::Value>(&updated)
        .map_err(|e| anyhow::anyhow!("l'écriture produirait un YAML invalide : {e}"))?;

    std::fs::write(&path, updated)?;
    Ok(())
}

/// Remplace (ou ajoute) une clé de premier niveau.
fn set_key(lines: &mut Vec<String>, entry: &GroupVarEntry) -> Result<()> {
    let rendered = render_entry(entry);

    match find_key(lines, &entry.key) {
        Some(start) => {
            // Refuser d'écraser une valeur chiffrée, même si l'appelant a
            // perdu le type en route : c'est le fichier qui fait foi.
            if lines
                .get(start)
                .is_some_and(|l| l.contains("!vault"))
            {
                return Ok(());
            }
            let end = block_end(lines, start);
            lines.splice(start..end, rendered);
        }
        None => {
            // Nouvelle clé : à la fin, sans s'insérer au milieu d'un bloc.
            if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.extend(rendered);
        }
    }
    Ok(())
}

fn render_entry(entry: &GroupVarEntry) -> Vec<String> {
    match entry.value_type.as_str() {
        "list" | "map" => {
            let mut out = vec![format!("{}:", entry.key)];
            for line in entry.value.lines() {
                out.push(format!("  {line}"));
            }
            out
        }
        "null" => vec![format!("{}:", entry.key)],
        _ => vec![format!("{}: {}", entry.key, entry.value)],
    }
}

/// Ligne d'une clé de premier niveau, commentaires exclus.
fn find_key(lines: &[String], key: &str) -> Option<usize> {
    let prefix = format!("{key}:");
    lines
        .iter()
        .position(|l| !l.starts_with('#') && l.starts_with(&prefix))
}

/// Fin du bloc d'une clé : la prochaine clé de premier niveau.
///
/// Les commentaires qui PRÉCÈDENT la clé suivante lui appartiennent — ils la
/// documentent — et doivent donc rester hors du bloc remplacé.
fn block_end(lines: &[String], start: usize) -> usize {
    let mut end = lines.len();
    let mut pending_comment: Option<usize> = None;

    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            pending_comment.get_or_insert(i);
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            end = pending_comment.unwrap_or(i);
            break;
        }
        pending_comment = None;
    }
    end
}

/// Convert a YAML value to a display string and its type identifier
fn yaml_value_to_string(value: &serde_yaml::Value) -> (String, String) {
    match value {
        serde_yaml::Value::Null => ("".to_string(), "null".to_string()),
        serde_yaml::Value::Bool(b) => (b.to_string(), "bool".to_string()),
        serde_yaml::Value::Number(n) => (n.to_string(), "number".to_string()),
        serde_yaml::Value::String(s) => (s.clone(), "string".to_string()),
        serde_yaml::Value::Sequence(_) | serde_yaml::Value::Mapping(_) => {
            // For complex types, serialize as YAML string
            let s = serde_yaml::to_string(value).unwrap_or_default();
            // Remove the leading "---\n" that serde_yaml adds
            let s = s.strip_prefix("---\n").unwrap_or(&s).trim().to_string();
            let type_name = if value.is_sequence() { "list" } else { "map" };
            (s, type_name.to_string())
        }
        // `!vault` : ne jamais rendre le cryptogramme. L'afficher n'apprend
        // rien, encombre la vue, et invite à le coller ailleurs.
        serde_yaml::Value::Tagged(tagged) if tagged.tag == "!vault" => {
            (String::new(), VAULT_TYPE.to_string())
        }
        serde_yaml::Value::Tagged(tagged) => yaml_value_to_string(&tagged.value),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupVarEntry {
    pub key: String,
    pub value: String,
    pub value_type: String,
}
