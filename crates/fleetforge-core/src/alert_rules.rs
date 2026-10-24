/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Règles d'alerte Prometheus et exemptions par hôte (`alert_exclude`).
//!
//! Les règles vivent dans un gabarit unique, partagé par les parcs
//! (`prometheus-alerts-update/templates/alerts.yml.j2`), découpé en groupes
//! `{% if '<groupe>' in prom_alert_groups %}`. Un parc ne charge que les
//! groupes de son `prom_alert_groups` (group_vars) : une exemption sur une
//! règle non chargée serait décorative, le rôle Ansible la refuse, et on la
//! refuse ici de la même façon.
//!
//! Une exemption s'écrit sur l'entrée d'inventaire elle-même,
//! `alert_exclude: [DiskWillFillSoon]`, en préservant les commentaires du
//! fichier (`inventory_writer`, même chemin que `families`). Elle ne prend effet
//! qu'au rendu suivant des règles (`update-prometheus-alerts.yml`).

use crate::inventory_writer::{write_edits, HostVarEdit};
use crate::parc::{self, Parc};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Clé d'inventaire portant les exemptions d'une entrée.
pub const ALERT_EXCLUDE_KEY: &str = "alert_exclude";

const TEMPLATE: &str = "roles/prometheus-alerts-update/templates/alerts.yml.j2";
const ROLE_DEFAULTS: &str = "roles/prometheus-alerts-update/defaults/main.yml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    /// Groupe du gabarit (`availability`, `resources`, …).
    pub group: String,
    /// Le groupe figure dans `prom_alert_groups` du parc.
    pub loaded: bool,
}

/// Règles du gabarit, une par nom (une même alerte peut avoir plusieurs
/// règles, `BackupStale` par exemple), dans l'ordre du fichier.
pub fn parse_rules(template: &str) -> Vec<(String, String)> {
    let mut group = String::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for line in template.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("{% if '") {
            if let Some((name, tail)) = rest.split_once('\'') {
                if tail.trim_start().starts_with("in prom_alert_groups") {
                    group = name.to_string();
                }
            }
        } else if let Some(name) = trimmed.strip_prefix("- alert:") {
            let name = name.trim().to_string();
            if !name.is_empty() && !out.iter().any(|(n, _)| *n == name) {
                out.push((name, group.clone()));
            }
        }
    }
    out
}

/// `prom_alert_groups` du parc : group_vars du parc, sinon défaut du rôle.
fn loaded_groups(playbooks_dir: &str, parc: &str) -> Vec<String> {
    let read = |path: &Path| -> Option<Vec<String>> {
        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        let list = yaml.get("prom_alert_groups")?.as_sequence()?;
        Some(
            list.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        )
    };
    let dir = Path::new(playbooks_dir);
    read(&dir.join("group_vars").join(format!("{parc}.yml")))
        .or_else(|| read(&dir.join(ROLE_DEFAULTS)))
        .unwrap_or_default()
}

/// Règles connues pour un parc, celles qu'il charge en premier.
pub fn list_alert_rules(playbooks_dir: &str, parc: &str) -> Result<Vec<AlertRule>> {
    let path = Path::new(playbooks_dir).join(TEMPLATE);
    let template =
        std::fs::read_to_string(&path).map_err(|e| anyhow!("{} : {e}", path.display()))?;
    let loaded = loaded_groups(playbooks_dir, parc);
    let mut rules: Vec<AlertRule> = parse_rules(&template)
        .into_iter()
        .map(|(name, group)| AlertRule {
            loaded: loaded.contains(&group),
            name,
            group,
        })
        .collect();
    rules.sort_by_key(|r| !r.loaded);
    Ok(rules)
}

/// `alert_exclude` déclaré sur l'entrée elle-même, hors héritage.
pub fn own_exclusions(file: &str, host: &str) -> Option<Vec<String>> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
    let list = parc::host_entry(&yaml, host)?
        .get(ALERT_EXCLUDE_KEY)?
        .as_sequence()?;
    Some(
        list.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
    )
}

/// Remplace les exemptions d'une entrée. Liste vide : la clé est retirée.
/// Refuse une alerte que le parc ne charge pas — elle ne serait jamais
/// appliquée — et un nom d'entrée inutilisable dans la regex PromQL du rôle.
pub fn set_alert_exclusions(
    playbooks_dir: &str,
    parc: &Parc,
    host: &str,
    alerts: &[String],
) -> Result<()> {
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(anyhow!(
            "`{host}` : nom d'entrée inutilisable dans une regex PromQL ([A-Za-z0-9_-])"
        ));
    }
    let rules = list_alert_rules(playbooks_dir, &parc.name)?;
    let mut next: Vec<String> = Vec::new();
    for alert in alerts.iter().map(|a| a.trim()).filter(|a| !a.is_empty()) {
        match rules.iter().find(|r| r.name == alert) {
            Some(r) if r.loaded => {}
            Some(r) => {
                return Err(anyhow!(
                    "`{alert}` appartient au groupe `{}`, que le parc {} ne charge pas (prom_alert_groups)",
                    r.group,
                    parc.name
                ))
            }
            None => return Err(anyhow!("`{alert}` : aucune règle d'alerte de ce nom")),
        }
        if !next.iter().any(|a| a == alert) {
            next.push(alert.to_string());
        }
    }
    let file = parc::owning_file(parc, host)?;
    let value = (!next.is_empty()).then(|| format!("[{}]", next.join(", ")));
    let edit = HostVarEdit {
        host: host.to_string(),
        key: ALERT_EXCLUDE_KEY.into(),
        value,
    };
    write_edits(Path::new(&file), &[edit])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn playbooks() -> String {
        format!("{}/../../Ansible/playbooks", env!("CARGO_MANIFEST_DIR"))
    }

    const TPL: &str = "groups:\n{% if 'availability' in prom_alert_groups %}\n  - name: availability\n    rules:\n      - alert: TargetDown\n{% endif %}\n{% if 'backups' in prom_alert_groups %}\n      - alert: BackupStale\n      - alert: BackupStale\n{% for x in y %}\n{% endfor %}\n{% endif %}\n";

    #[test]
    fn rules_are_read_with_their_group_once_per_name() {
        assert_eq!(
            parse_rules(TPL),
            vec![
                ("TargetDown".into(), "availability".into()),
                ("BackupStale".into(), "backups".into())
            ]
        );
    }

    #[test]
    fn the_real_template_yields_named_and_grouped_rules() {
        let tpl = std::fs::read_to_string(Path::new(&playbooks()).join(TEMPLATE)).unwrap();
        let rules = parse_rules(&tpl);
        assert!(rules
            .iter()
            .any(|(n, g)| n == "TargetDown" && g == "availability"));
        assert!(rules
            .iter()
            .any(|(n, g)| n == "OpenClawModelUnavailable" && g == "openclaw"));
        assert!(
            rules.iter().all(|(_, g)| !g.is_empty()),
            "toute règle est dans un groupe"
        );
    }

    const INV: &str = "# en tête\nall:\n  vars:\n    ansible_roles: []\n  children:\n    web3c:\n      children:\n        home:\n          hosts:\n            nuc:\n              ansible_host: 9.9.9.9\n              svcprobe_port: 9112\n";

    fn setup() -> (crate::parc::testutil::Dir, Parc) {
        let d = crate::parc::testutil::dir_with(&[("web3c_inventory.yml", INV)]);
        let parc = crate::parc::resolve(d.path().to_str().unwrap(), "web3c").unwrap();
        (d, parc)
    }

    /// Dossier de playbooks minimal : le gabarit et le group_vars du parc.
    fn playbooks_with(groups: &str) -> crate::parc::testutil::Dir {
        let d = crate::parc::testutil::dir_with(&[] as &[(&str, &str)]);
        let tpl = d.path().join(TEMPLATE);
        std::fs::create_dir_all(tpl.parent().unwrap()).unwrap();
        std::fs::write(&tpl, TPL).unwrap();
        std::fs::create_dir_all(d.path().join("group_vars")).unwrap();
        std::fs::write(
            d.path().join("group_vars/web3c.yml"),
            format!("prom_alert_groups: [{groups}]\n"),
        )
        .unwrap();
        d
    }

    #[test]
    fn an_exemption_is_written_then_removed_to_the_exact_original() {
        let (d, parc) = setup();
        let pb = playbooks_with("availability");
        let pb = pb.path().to_str().unwrap();
        let file = d.path().join("web3c_inventory.yml");
        set_alert_exclusions(
            pb,
            &parc,
            "nuc",
            &["TargetDown".into(), "TargetDown".into()],
        )
        .unwrap();
        let written = std::fs::read_to_string(&file).unwrap();
        assert!(
            written.contains("alert_exclude: [TargetDown]"),
            "doublon écarté"
        );
        assert!(written.starts_with("# en tête"), "commentaires préservés");
        assert_eq!(
            own_exclusions(file.to_str().unwrap(), "nuc").unwrap(),
            vec!["TargetDown"]
        );
        set_alert_exclusions(pb, &parc, "nuc", &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            INV,
            "liste vide : clé retirée"
        );
    }

    #[test]
    fn unknown_or_unloaded_alerts_are_refused() {
        let (d, parc) = setup();
        let pb = playbooks_with("availability");
        let pb = pb.path().to_str().unwrap();
        let err = set_alert_exclusions(pb, &parc, "nuc", &["Nope".into()]).unwrap_err();
        assert!(err.to_string().contains("aucune règle"));
        let err = set_alert_exclusions(pb, &parc, "nuc", &["BackupStale".into()]).unwrap_err();
        assert!(err.to_string().contains("ne charge pas"));
        assert_eq!(
            std::fs::read_to_string(d.path().join("web3c_inventory.yml")).unwrap(),
            INV
        );
    }

    #[test]
    fn loaded_rules_come_first() {
        let pb = playbooks_with("backups");
        let rules = list_alert_rules(pb.path().to_str().unwrap(), "web3c").unwrap();
        assert_eq!(rules[0].name, "BackupStale");
        assert!(rules[0].loaded && !rules[1].loaded);
    }
}
