/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Écriture d'inventaire préservant les commentaires.
//!
//! Réécrire ces fichiers par `serde_yaml` les détruirait. Ce n'est pas un
//! détail cosmétique : les inventaires portent en commentaires les conventions
//! du parc et leurs justifications — pourquoi `provider` n'a pas de défaut,
//! pourquoi `brk1` et `rpcbtc1` sont deux noms pour une machine, quelles
//! entrées sont volontairement mises de côté. S'y ajoutent de gros blocs
//! d'hôtes commentés, prêts à être réactivés.
//!
//! On édite donc les lignes visées et rien d'autre. La contrepartie est que ce
//! module ne sait pas tout faire : il modifie et ajoute des variables d'hôte,
//! ce qui couvre ce que les interfaces proposent.

use anyhow::{anyhow, Result};
use std::path::Path;

/// Une modification à appliquer à une entrée d'hôte.
#[derive(Debug, Clone)]
pub struct HostVarEdit {
    pub host: String,
    pub key: String,
    /// `None` retire la variable. Utile pour `provider`, dont l'absence est
    /// significative — il n'a volontairement aucun défaut.
    pub value: Option<String>,
}

/// Applique des modifications à un contenu d'inventaire.
///
/// Travaille sur une chaîne pour rester testable sans toucher au disque.
pub fn apply_edits(content: &str, edits: &[HostVarEdit]) -> Result<String> {
    let mut lines: Vec<String> = content.lines().map(String::from).collect();

    for edit in edits {
        apply_one(&mut lines, edit)?;
    }

    let mut out = lines.join("\n");
    // Préserver la présence ou l'absence du saut de ligne final : le modifier
    // ferait un diff sur un fichier par ailleurs inchangé.
    if content.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn apply_one(lines: &mut Vec<String>, edit: &HostVarEdit) -> Result<()> {
    let (start, indent) = find_host_block(lines, &edit.host)
        .ok_or_else(|| anyhow!("hôte `{}` introuvable dans l'inventaire", edit.host))?;

    let var_indent = format!("{indent}  ");
    let end = block_end(lines, start, &var_indent);

    // La variable existe-t-elle déjà dans le bloc ?
    let existing = (start + 1..end).find(|&i| {
        line_key(&lines[i])
            .map(|(ind, key)| ind == var_indent && key == edit.key)
            .unwrap_or(false)
    });

    match (existing, &edit.value) {
        (Some(i), Some(value)) => {
            lines[i] = format!("{var_indent}{}: {value}", edit.key);
        }
        (Some(i), None) => {
            lines.remove(i);
        }
        (None, Some(value)) => {
            // Insérer à la fin du bloc, avant les lignes vides finales : les
            // coller après séparerait l'entrée de son groupe.
            let mut at = end;
            while at > start + 1 && lines[at - 1].trim().is_empty() {
                at -= 1;
            }
            lines.insert(at, format!("{var_indent}{}: {value}", edit.key));
        }
        (None, None) => {}
    }

    Ok(())
}

/// Repère l'entrée d'un hôte : une clé nue (sans valeur) dont le nom correspond.
///
/// Une ligne commentée n'est jamais retenue — les inventaires en contiennent de
/// gros blocs, et écrire dedans réactiverait silencieusement une entrée mise de
/// côté, avec une adresse peut-être réattribuée depuis.
///
/// La clé doit relever directement d'un `hosts:` : un GROUPE homonyme d'un hôte
/// serait sinon édité à sa place, sans erreur.
fn find_host_block(lines: &[String], host: &str) -> Option<(usize, String)> {
    lines.iter().enumerate().find_map(|(i, line)| {
        if line.trim_start().starts_with('#') {
            return None;
        }
        let (indent, key) = line_key(line)?;
        let is_bare = line.trim_end().ends_with(':');
        (is_bare && key == host && parent_key(lines, i, indent.len()).as_deref() == Some("hosts"))
            .then_some((i, indent))
    })
}

/// Clé de la première ligne significative moins indentée que la ligne `at`.
fn parent_key(lines: &[String], at: usize, indent: usize) -> Option<String> {
    lines[..at].iter().rev().find_map(|l| {
        let (ind, key) = line_key(l)?;
        (ind.len() < indent).then_some(key)
    })
}

/// Fin du bloc : la première ligne moins indentée que ses variables.
fn block_end(lines: &[String], start: usize, var_indent: &str) -> usize {
    let mut end = start + 1;
    while end < lines.len() {
        let line = &lines[end];
        // Les lignes vides et les commentaires appartiennent au bloc tant
        // qu'une ligne significative moins indentée n'est pas rencontrée.
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            end += 1;
            continue;
        }
        if !line.starts_with(var_indent) {
            break;
        }
        end += 1;
    }
    end
}

/// `("  ", "ansible_host")` pour `  ansible_host: 1.2.3.4`.
fn line_key(line: &str) -> Option<(String, String)> {
    let indent: String = line.chars().take_while(|c| *c == ' ').collect();
    let rest = &line[indent.len()..];
    if rest.starts_with('#') || rest.is_empty() {
        return None;
    }
    let key = rest.split(':').next()?.trim();
    (!key.is_empty() && !key.contains(' ')).then(|| (indent, key.to_string()))
}

/// Écrit un inventaire modifié, en refusant de produire un fichier illisible.
pub fn write_edits(inventory_path: &Path, edits: &[HostVarEdit]) -> Result<()> {
    let content = std::fs::read_to_string(inventory_path)?;
    let updated = apply_edits(&content, edits)?;

    // Garde-fou : un inventaire cassé ne se voit qu'au prochain déploiement,
    // c'est-à-dire trop tard.
    serde_yaml::from_str::<serde_yaml::Value>(&updated)
        .map_err(|e| anyhow!("l'écriture produirait un YAML invalide : {e}"))?;

    std::fs::write(inventory_path, updated)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_group_named_like_a_host_is_never_edited_in_its_place() {
        let content = "all:\n  children:\n    web3c:\n      children:\n        ollama:\n          hosts:\n            ollama:\n              ansible_host: 1.2.3.4\n";
        let out = apply_edits(
            content,
            &[HostVarEdit { host: "ollama".into(), key: "app_port".into(), value: Some("11434".into()) }],
        )
        .unwrap();
        assert!(out.lines().any(|l| l == "              app_port: 11434"), "{out}");
        assert!(!out.lines().any(|l| l == "          app_port: 11434"), "écrit sous le groupe : {out}");
    }

    const SAMPLE: &str = r#"# En-tête portant une convention.
all:
  vars:
    ansible_roles: []
  children:
    papanglabs:
      children:
        proxies:
          hosts:
            proxy1:
              hostname: proxy1.{{ domain_name }}
              ansible_host: 203.0.113.10
              provider: contabo
              ansible_roles: [proxy, nginx, cert]
            #vpn2:
            #  ansible_host: 203.0.113.99
        misc:
          hosts:
            mail:
              ansible_host: 203.0.113.10
              provider: contabo
"#;

    fn edit(host: &str, key: &str, value: Option<&str>) -> HostVarEdit {
        HostVarEdit {
            host: host.into(),
            key: key.into(),
            value: value.map(String::from),
        }
    }

    #[test]
    fn no_edits_leaves_the_file_byte_identical() {
        assert_eq!(apply_edits(SAMPLE, &[]).unwrap(), SAMPLE);
    }

    #[test]
    fn changing_a_value_touches_only_that_line() {
        let out = apply_edits(SAMPLE, &[edit("proxy1", "provider", Some("ovh"))]).unwrap();
        assert!(out.contains("              provider: ovh"));
        // Tout le reste est intact, commentaires compris.
        assert!(out.contains("# En-tête portant une convention."));
        assert!(out.contains("            #vpn2:"));
        assert!(out.contains("              ansible_host: 203.0.113.10"));
        assert_eq!(out.lines().count(), SAMPLE.lines().count());
    }

    #[test]
    fn a_new_variable_lands_inside_its_host_block() {
        let out = apply_edits(SAMPLE, &[edit("mail", "svcprobe_port", Some("9111"))]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let mail = lines.iter().position(|l| l.trim() == "mail:").unwrap();
        let added = lines
            .iter()
            .position(|l| l.contains("svcprobe_port: 9111"))
            .unwrap();
        assert!(added > mail, "la variable doit suivre son hôte");
        assert_eq!(lines[added], "              svcprobe_port: 9111");
    }

    #[test]
    fn removing_a_variable_removes_exactly_one_line() {
        let out = apply_edits(SAMPLE, &[edit("proxy1", "provider", None)]).unwrap();
        assert_eq!(out.lines().count(), SAMPLE.lines().count() - 1);
        // Celui de `mail` est resté.
        assert!(out.contains("              provider: contabo"));
    }

    #[test]
    fn a_commented_out_host_is_never_written_into() {
        // Réactiver `vpn2` en écrivant dedans remettrait en service une entrée
        // volontairement écartée, sur une adresse peut-être réattribuée.
        let err = apply_edits(SAMPLE, &[edit("vpn2", "provider", Some("contabo"))]);
        assert!(err.is_err());
    }

    #[test]
    fn an_unknown_host_is_refused_rather_than_appended_anywhere() {
        assert!(apply_edits(SAMPLE, &[edit("nope", "provider", Some("ovh"))]).is_err());
    }

    #[test]
    fn edits_do_not_leak_into_the_next_host_block() {
        let out = apply_edits(SAMPLE, &[edit("proxy1", "server_type", Some("proxy"))]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let added = lines
            .iter()
            .position(|l| l.contains("server_type: proxy"))
            .unwrap();
        let misc = lines.iter().position(|l| l.trim() == "misc:").unwrap();
        assert!(added < misc, "la variable a débordé sur le groupe suivant");
    }

    #[test]
    fn the_result_is_still_valid_yaml() {
        let out = apply_edits(
            SAMPLE,
            &[
                edit("proxy1", "provider", Some("ovh")),
                edit("mail", "svcprobe_port", Some("9111")),
            ],
        )
        .unwrap();
        serde_yaml::from_str::<serde_yaml::Value>(&out).expect("YAML invalide");
    }

    #[test]
    fn a_file_without_a_trailing_newline_keeps_not_having_one() {
        let trimmed = SAMPLE.trim_end();
        let out = apply_edits(trimmed, &[]).unwrap();
        assert!(!out.ends_with('\n'));
    }
}
