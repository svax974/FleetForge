/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Parc : l'UNION des inventaires `<parc>_*.yml` (plus `<parc>.yml`).
//!
//! Même règle que `Ansible/play.sh` (CLAUDE.md, « Parc et play.sh ») : le nom
//! du parc est le nom du fichier jusqu'au premier `_`, un fichier sans `_`
//! forme son propre parc (`gcp.yml` → `gcp`). Ansible reçoit un `-i` par
//! fichier — jamais `-i a,b`, qu'il lirait comme une liste d'HÔTES.
//!
//! Une référence d'inventaire est soit un nom de parc, soit le chemin d'un
//! fichier existant : le second reste le contournement d'un parc douteux, et
//! la forme que les réglages enregistraient avant l'introduction des parcs.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parc {
    /// Nom du parc — ou chemin du fichier pour un parc à un seul fichier
    /// désigné explicitement. C'est la RÉFÉRENCE qu'on persiste et qu'on
    /// renvoie au cœur.
    pub name: String,
    /// Organisation : premier groupe sous `all.children` des fichiers
    /// statiques, à défaut le nom du parc. Clé des réglages Prometheus.
    pub organization: String,
    /// Fichiers d'inventaire, triés. Jamais vide.
    pub files: Vec<String>,
}

/// Nom du parc d'un fichier d'inventaire : `web3c_oracle.yml` → `web3c`.
pub fn parc_name_of(file: &Path) -> Option<String> {
    let stem = file.file_stem()?.to_str()?;
    let name = stem.split('_').next().unwrap_or(stem);
    (!name.is_empty()).then(|| name.to_string())
}

fn is_inventory_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .map(|e| e == "yml" || e == "yaml")
            .unwrap_or(false)
}

/// Tous les parcs d'un répertoire d'inventaires, triés par nom.
pub fn list_parcs(inventories_dir: &str) -> Result<Vec<Parc>> {
    let dir = Path::new(inventories_dir);
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if !is_inventory_file(&path) {
            continue;
        }
        if let Some(name) = parc_name_of(&path) {
            by_name
                .entry(name)
                .or_default()
                .push(path.to_string_lossy().to_string());
        }
    }
    Ok(by_name
        .into_iter()
        .map(|(name, mut files)| {
            files.sort();
            let organization = organization_of(&files).unwrap_or_else(|| name.clone());
            Parc { name, organization, files }
        })
        .collect())
}

/// Résout une référence : chemin d'un fichier existant, ou nom de parc.
pub fn resolve(inventories_dir: &str, reference: &str) -> Result<Parc> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Err(anyhow!("aucun parc ni inventaire indiqué"));
    }
    let as_file = Path::new(reference);
    if is_inventory_file(as_file) {
        let files = vec![reference.to_string()];
        let organization = organization_of(&files)
            .or_else(|| parc_name_of(as_file))
            .unwrap_or_default();
        return Ok(Parc { name: reference.to_string(), organization, files });
    }
    list_parcs(inventories_dir)?
        .into_iter()
        .find(|p| p.name == reference)
        .ok_or_else(|| anyhow!("parc ou inventaire inconnu : {reference}"))
}

/// Organisation déclarée par le premier fichier statique qui en porte une.
/// Un inventaire de plugin (`plugin: gcp_compute`) n'a pas d'`all.children`.
fn organization_of(files: &[String]) -> Option<String> {
    files.iter().find_map(|f| {
        let yaml = read_yaml(f)?;
        yaml.get("all")?
            .get("children")?
            .as_mapping()?
            .keys()
            .next()?
            .as_str()
            .map(String::from)
            .filter(|s| !s.is_empty())
    })
}

fn read_yaml(file: &str) -> Option<serde_yaml::Value> {
    let content = std::fs::read_to_string(file).ok()?;
    serde_yaml::from_str(&content).ok()
}

/// Vrai si `host` est déclaré sous une clé `hosts:` de cet inventaire.
pub fn declares_host(yaml: &serde_yaml::Value, host: &str) -> bool {
    let Some(map) = yaml.as_mapping() else {
        return false;
    };
    map.iter().any(|(key, value)| {
        let declared_here = key.as_str() == Some("hosts")
            && value
                .as_mapping()
                .map(|hosts| hosts.keys().any(|k| k.as_str() == Some(host)))
                .unwrap_or(false);
        declared_here || declares_host(value, host)
    })
}

/// Variables propres d'une entrée : la valeur de `host` sous une clé `hosts:`.
pub fn host_entry<'a>(yaml: &'a serde_yaml::Value, host: &str) -> Option<&'a serde_yaml::Value> {
    let map = yaml.as_mapping()?;
    map.iter().find_map(|(key, value)| {
        let here = (key.as_str() == Some("hosts"))
            .then(|| value.as_mapping()?.iter().find(|(k, _)| k.as_str() == Some(host)).map(|(_, v)| v))
            .flatten();
        here.or_else(|| host_entry(value, host))
    })
}

/// Fichiers du parc qui déclarent `host`.
pub fn files_declaring(parc: &Parc, host: &str) -> Vec<String> {
    parc.files
        .iter()
        .filter(|f| read_yaml(f).map(|y| declares_host(&y, host)).unwrap_or(false))
        .cloned()
        .collect()
}

/// LE fichier qui déclare `host`, seul endroit où l'on peut l'éditer.
///
/// Aucun : l'hôte vient d'un plugin (gcp) et n'existe pas sous forme écrite.
/// Plusieurs : Ansible fusionne en silence, écrire dans l'un laisserait
/// l'autre l'emporter — on refuse plutôt que de choisir au hasard.
pub fn owning_file(parc: &Parc, host: &str) -> Result<String> {
    let mut files = files_declaring(parc, host);
    match files.len() {
        1 => Ok(files.remove(0)),
        0 => Err(anyhow!(
            "l'hôte `{host}` n'est déclaré dans aucun fichier écrit du parc {} \
             (inventaire de plugin ?) : modification impossible",
            parc.name
        )),
        _ => Err(anyhow!(
            "l'hôte `{host}` est déclaré dans plusieurs fichiers du parc {} ({}) : \
             Ansible n'en retient qu'un, à corriger avant toute écriture",
            parc.name,
            files.join(", ")
        )),
    }
}

/// Hôtes déclarés dans plus d'un fichier du parc : nom → fichiers.
pub fn duplicate_hosts(parc: &Parc) -> BTreeMap<String, Vec<String>> {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in &parc.files {
        let Some(yaml) = read_yaml(file) else { continue };
        let mut hosts = Vec::new();
        collect_hosts(&yaml, &mut hosts);
        hosts.sort();
        hosts.dedup();
        for h in hosts {
            seen.entry(h).or_default().push(file.clone());
        }
    }
    seen.retain(|_, files| files.len() > 1);
    seen
}

fn collect_hosts(yaml: &serde_yaml::Value, out: &mut Vec<String>) {
    let Some(map) = yaml.as_mapping() else { return };
    for (key, value) in map {
        if key.as_str() == Some("hosts") {
            if let Some(hosts) = value.as_mapping() {
                out.extend(hosts.keys().filter_map(|k| k.as_str().map(String::from)));
            }
        }
        collect_hosts(value, out);
    }
}

/// Fichiers statiques dont l'organisation n'est pas celle du parc : leurs
/// hôtes ne reçoivent pas `group_vars/<parc>.yml`.
pub fn misfiled(parc: &Parc) -> Vec<(String, String)> {
    parc.files
        .iter()
        .filter_map(|f| {
            let org = organization_of(std::slice::from_ref(f))?;
            (org != parc.organization).then(|| (f.clone(), org))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parc::testutil::dir_with;


    const A: &str = "all:\n  children:\n    web3c:\n      children:\n        g:\n          hosts:\n            h1:\n              ansible_host: 1.1.1.1\n";
    const B: &str = "all:\n  children:\n    web3c:\n      hosts:\n        h2:\n          ansible_host: 2.2.2.2\n";
    const PLUGIN: &str = "plugin: gcp_compute\nprojects: [x]\n";

    #[test]
    fn files_sharing_a_prefix_form_one_parc() {
        let d = dir_with(&[("web3c_inventory.yml", A), ("web3c_oracle.yml", B), ("gcp.yml", PLUGIN)]);
        let parcs = list_parcs(d.path().to_str().unwrap()).unwrap();
        let names: Vec<_> = parcs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["gcp", "web3c"]);
        let web3c = &parcs[1];
        assert_eq!(web3c.files.len(), 2);
        assert!(web3c.files[0].ends_with("web3c_inventory.yml"));
        assert_eq!(web3c.organization, "web3c");
        // Un inventaire de plugin n'a pas d'organisation écrite : le nom du parc en tient lieu.
        assert_eq!(parcs[0].organization, "gcp");
    }

    #[test]
    fn a_reference_is_a_parc_name_or_an_existing_file() {
        let d = dir_with(&[("web3c_inventory.yml", A), ("web3c_oracle.yml", B)]);
        let dir = d.path().to_str().unwrap();
        assert_eq!(resolve(dir, "web3c").unwrap().files.len(), 2);
        let file = d.path().join("web3c_oracle.yml").to_string_lossy().to_string();
        let single = resolve(dir, &file).unwrap();
        assert_eq!(single.files, vec![file.clone()]);
        assert_eq!(single.name, file);
        assert_eq!(single.organization, "web3c");
        assert!(resolve(dir, "nope").is_err());
        assert!(resolve(dir, "").is_err());
    }

    #[test]
    fn the_owning_file_is_the_one_declaring_the_host() {
        let d = dir_with(&[("web3c_inventory.yml", A), ("web3c_oracle.yml", B)]);
        let parc = resolve(d.path().to_str().unwrap(), "web3c").unwrap();
        assert!(owning_file(&parc, "h1").unwrap().ends_with("web3c_inventory.yml"));
        assert!(owning_file(&parc, "h2").unwrap().ends_with("web3c_oracle.yml"));
        assert!(owning_file(&parc, "absent").is_err());
        // Le nom d'un GROUPE n'est pas un hôte.
        assert!(owning_file(&parc, "g").is_err());
    }

    #[test]
    fn a_host_declared_twice_is_refused_and_reported() {
        let d = dir_with(&[("web3c_inventory.yml", A), ("web3c_dup.yml", A)]);
        let parc = resolve(d.path().to_str().unwrap(), "web3c").unwrap();
        assert!(owning_file(&parc, "h1").is_err());
        assert_eq!(duplicate_hosts(&parc).keys().collect::<Vec<_>>(), vec!["h1"]);
    }

    #[test]
    fn a_file_filed_under_another_organization_is_reported() {
        let other = "all:\n  children:\n    papanglabs:\n      hosts:\n        x: {}\n";
        let d = dir_with(&[("web3c_inventory.yml", A), ("web3c_wrong.yml", other)]);
        let parc = resolve(d.path().to_str().unwrap(), "web3c").unwrap();
        let bad = misfiled(&parc);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].1, "papanglabs");
    }
}

/// Répertoires d'inventaires jetables pour les tests du crate.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::Path;

    /// Répertoire jetable, supprimé à la fin du test.
    pub(crate) struct Dir(std::path::PathBuf);
    impl Dir {
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) fn dir_with(files: &[(&str, &str)]) -> Dir {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "infra-parc-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            std::fs::write(dir.join(name), content).unwrap();
        }
        Dir(dir)
    }
}
