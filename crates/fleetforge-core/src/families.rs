/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Inscription automatique d'une famille dans `ansible_roles` au déploiement.
//!
//! Règles (CLAUDE.md § 2) :
//! - la famille est le suffixe du `deploy-<famille>.yml` qui la déploie ; un
//!   rôle `<famille>-install` n'en désigne une que si ce playbook existe ;
//! - socle, transverses, modèles et orchestrations n'en portent pas ;
//! - une famille déjà portée par une AUTRE entrée de la même machine (entrée
//!   dédiée d'un service publié) n'est pas recopiée sur l'entrée ciblée ;
//! - l'écriture se fait dans le fichier du parc qui déclare l'hôte, en
//!   préservant ses commentaires (`inventory_writer`).
//!
//! Inscrite AVANT le run — un playbook peut sauter les hôtes qui ne portent
//! pas sa famille — et RETIRÉE s'il échoue : l'inventaire décrit ce qui est
//! installé, pas ce qu'on a tenté.

use crate::inventory_writer::{write_edits, HostVarEdit};
use crate::model::{Fleet, MachineKey};
use crate::parc::{self, Parc};
use std::path::Path;

/// `deploy-*` qui ne déploient pas une famille de service.
pub const NOT_FAMILIES: &[&str] = &[
    // socle et transverses
    "exporter-sys",
    "copyfail-patch",
    "install-cert",
    "readonly-user",
    // artefacts posés sur un service existant
    "llamacpp-model",
    "ollama-model",
    // orchestrations de plusieurs playbooks
    "btc-pipeline",
    "dbs",
    // ancienne installation inline, concurrente de deploy-mailserver.yml
    "mail-server-complete",
];

fn is_family(playbooks_dir: &str, family: &str) -> bool {
    !family.is_empty()
        && !NOT_FAMILIES.contains(&family)
        && Path::new(playbooks_dir)
            .join(format!("deploy-{family}.yml"))
            .is_file()
}

/// `…/deploy-ollama.yml` → `ollama`.
pub fn family_of_playbook(playbooks_dir: &str, playbook_path: &str) -> Option<String> {
    let stem = Path::new(playbook_path).file_stem()?.to_str()?;
    let family = stem.strip_prefix("deploy-")?;
    is_family(playbooks_dir, family).then(|| family.to_string())
}

/// `ollama-install` → `ollama` ; `ollama-security`, `ollama-model-install` → rien.
pub fn family_of_role(playbooks_dir: &str, role: &str) -> Option<String> {
    let family = role.strip_suffix("-install")?;
    is_family(playbooks_dir, family).then(|| family.to_string())
}

/// Une inscription réalisée, de quoi l'annuler à l'identique.
#[derive(Debug, Clone)]
pub struct FamilyEdit {
    pub host: String,
    pub family: String,
    pub file: String,
    /// Liste PROPRE à l'entrée avant l'ajout ; `None` : la clé était absente
    /// (le défaut `[]` de `all.vars` s'appliquait).
    pub previous: Option<Vec<String>>,
}

fn flow_list(items: &[String]) -> String {
    format!("[{}]", items.join(", "))
}

/// `ansible_roles` déclaré sur l'entrée elle-même, hors héritage.
fn own_families(file: &str, host: &str) -> Option<Vec<String>> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
    let vars = parc::host_entry(&yaml, host)?;
    let list = vars.get("ansible_roles")?.as_sequence()?;
    Some(list.iter().filter_map(|v| v.as_str().map(String::from)).collect())
}

/// Inscrit `family` sur chaque hôte qui ne la porte pas. Renvoie les
/// inscriptions faites et une ligne d'explication par hôte écarté.
pub fn inscribe(parc: &Parc, fleet: &Fleet, family: &str, hosts: &[String]) -> (Vec<FamilyEdit>, Vec<String>) {
    let mut done = Vec::new();
    let mut notes = Vec::new();
    for name in hosts {
        let Some(host) = fleet.host(name) else {
            notes.push(format!("`{name}` n'est pas un hôte du parc {} : `{family}` non inscrite", parc.name));
            continue;
        };
        if host.ansible_roles.iter().any(|f| f == family) {
            continue;
        }
        let key = MachineKey::of(host);
        if let Some(other) = fleet
            .hosts
            .iter()
            .find(|h| h.name != host.name && MachineKey::of(h) == key && h.ansible_roles.iter().any(|f| f == family))
        {
            notes.push(format!(
                "`{family}` est portée par l'entrée dédiée `{}` de la même machine : non recopiée sur `{name}`",
                other.name
            ));
            continue;
        }
        let file = match parc::owning_file(parc, name) {
            Ok(f) => f,
            Err(e) => {
                notes.push(format!("`{family}` non inscrite sur `{name}` : {e}"));
                continue;
            }
        };
        let previous = own_families(&file, name);
        let mut next = previous.clone().unwrap_or_default();
        next.push(family.to_string());
        let edit = HostVarEdit { host: name.clone(), key: "ansible_roles".into(), value: Some(flow_list(&next)) };
        match write_edits(Path::new(&file), &[edit]) {
            Ok(()) => {
                notes.push(format!("`{family}` inscrite dans ansible_roles de `{name}` ({file})"));
                done.push(FamilyEdit { host: name.clone(), family: family.to_string(), file, previous });
            }
            Err(e) => notes.push(format!("`{family}` non inscrite sur `{name}` : {e}")),
        }
    }
    (done, notes)
}

/// Annule des inscriptions, dans l'ordre inverse.
pub fn revert(edits: &[FamilyEdit]) -> Vec<String> {
    edits
        .iter()
        .rev()
        .map(|e| {
            let edit = HostVarEdit {
                host: e.host.clone(),
                key: "ansible_roles".into(),
                value: e.previous.as_deref().map(flow_list),
            };
            match write_edits(Path::new(&e.file), &[edit]) {
                Ok(()) => format!("run en échec : `{}` retirée de ansible_roles de `{}`", e.family, e.host),
                Err(err) => format!("run en échec : `{}` N'A PAS PU être retirée de `{}` : {err}", e.family, e.host),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Fleet;

    fn playbooks() -> String {
        format!("{}/../../Ansible/playbooks", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn the_family_is_the_deploy_playbook_suffix() {
        let p = playbooks();
        assert_eq!(family_of_playbook(&p, "deploy-ollama.yml").as_deref(), Some("ollama"));
        assert_eq!(family_of_playbook(&p, "/x/playbooks/deploy-theta-edge.yml").as_deref(), Some("theta-edge"));
        assert_eq!(family_of_playbook(&p, "deploy-ollama-model.yml"), None);
        assert_eq!(family_of_playbook(&p, "deploy-exporter-sys.yml"), None);
        assert_eq!(family_of_playbook(&p, "remove-ollama.yml"), None);
        assert_eq!(family_of_playbook(&p, "deploy-nope.yml"), None);
    }

    const INV: &str = "# convention en tête : doit survivre\nall:\n  vars:\n    ansible_roles: []\n  children:\n    web3c:\n      children:\n        home:\n          hosts:\n            hub:\n              ansible_host: 9.9.9.9\n              svcprobe_port: 9111\n              ansible_roles: [astar]\n            ollama:\n              ansible_host: 9.9.9.9\n              svcprobe_port: 9111\n              ansible_roles: [ollama]\n            nuc:\n              ansible_host: 9.9.9.9\n              svcprobe_port: 9112\n";

    fn setup() -> (crate::parc::testutil::Dir, Parc, Fleet) {
        let d = crate::parc::testutil::dir_with(&[("web3c_inventory.yml", INV)]);
        let parc = crate::parc::resolve(d.path().to_str().unwrap(), "web3c").unwrap();
        let groups = crate::ansible_inventory::parse_inventories(&parc.files).unwrap();
        let fleet = Fleet::build(&parc.organization, &parc.name, groups);
        (d, parc, fleet)
    }

    #[test]
    fn a_family_is_inscribed_then_reverted_to_the_exact_original() {
        let (d, parc, fleet) = setup();
        let file = d.path().join("web3c_inventory.yml");
        let (edits, _) = inscribe(&parc, &fleet, "theta-edge", &["hub".into(), "nuc".into()]);
        assert_eq!(edits.len(), 2);
        let written = std::fs::read_to_string(&file).unwrap();
        assert!(written.contains("ansible_roles: [astar, theta-edge]"));
        assert!(written.contains("ansible_roles: [theta-edge]"), "nuc n'avait pas de clé : créée");
        assert!(written.starts_with("# convention en tête"), "commentaires préservés");
        revert(&edits);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), INV, "annulation à l'identique");
    }

    #[test]
    fn a_family_carried_by_a_dedicated_entry_is_not_copied_to_its_machine() {
        let (d, parc, fleet) = setup();
        let (edits, notes) = inscribe(&parc, &fleet, "ollama", &["hub".into(), "nuc".into(), "absent".into()]);
        // hub : même machine que l'entrée `ollama` → écarté ; nuc : autre machine → inscrit.
        assert_eq!(edits.iter().map(|e| e.host.as_str()).collect::<Vec<_>>(), vec!["nuc"]);
        assert!(notes.iter().any(|n| n.contains("entrée dédiée `ollama`")));
        assert!(notes.iter().any(|n| n.contains("`absent` n'est pas un hôte")));
        drop(d);
    }

    #[test]
    fn only_an_install_role_with_its_playbook_designates_a_family() {
        let p = playbooks();
        assert_eq!(family_of_role(&p, "ollama-install").as_deref(), Some("ollama"));
        assert_eq!(family_of_role(&p, "ollama-security"), None);
        assert_eq!(family_of_role(&p, "ollama-model-install"), None);
        assert_eq!(family_of_role(&p, "docker-install"), None);
    }
}
