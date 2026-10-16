/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Le modèle de domaine : `Fleet` → `Server` → `Host` → `Service`.
//!
//! L'application ne connaissait que l'entrée d'inventaire. Or plusieurs entrées
//! décrivent une même MACHINE — huit sur `203.0.113.10`, sept sur
//! `203.0.113.11` — et c'est la machine qu'on démarre, qu'on scrape et qu'on
//! facture. Ce module introduit ce niveau, dérivé et jamais stocké.

use crate::metrics::{Probe, SVCPROBE_DEFAULT_PORT};
use crate::models::{AnsibleGroup, AnsibleHost};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Hébergeur de la machine. Liste fermée, alignée sur `preflight_providers`
/// (rôle `host-preflight`) : `contabo` et `Contabo` feraient deux parcs là où
/// il n'y en a qu'un.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Gcp,
    Aws,
    Contabo,
    Ovh,
    Oracle,
    /// Machines physiques : pas d'API, SSH seul.
    Custom,
}

impl ProviderKind {
    pub const ALL: [ProviderKind; 6] = [
        ProviderKind::Gcp,
        ProviderKind::Aws,
        ProviderKind::Contabo,
        ProviderKind::Ovh,
        ProviderKind::Oracle,
        ProviderKind::Custom,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Gcp => "gcp",
            ProviderKind::Aws => "aws",
            ProviderKind::Contabo => "contabo",
            ProviderKind::Ovh => "ovh",
            ProviderKind::Oracle => "oracle",
            ProviderKind::Custom => "custom",
        }
    }

    /// Libellé d'affichage, partagé par les deux interfaces.
    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::Gcp => "Google Cloud",
            ProviderKind::Aws => "Amazon AWS",
            ProviderKind::Contabo => "Contabo",
            ProviderKind::Ovh => "OVHcloud",
            ProviderKind::Oracle => "Oracle Cloud",
            ProviderKind::Custom => "Machine physique",
        }
    }

    /// Un provider `custom` n'a pas d'API : ni instances à lister, ni
    /// alimentation à piloter.
    pub fn has_cloud_api(self) -> bool {
        !matches!(self, ProviderKind::Custom)
    }

    /// Analyse stricte : la casse compte, faute de quoi l'invariant « une seule
    /// écriture par parc » ne vaut plus rien.
    pub fn parse(raw: &str) -> Option<ProviderKind> {
        ProviderKind::ALL.into_iter().find(|p| p.as_str() == raw)
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identité d'une MACHINE.
///
/// L'adresse seule ne suffit pas : sur `198.51.100.20` (NAT domestique web3c),
/// `hub` et `nuc` sont deux machines physiquement distinctes, séparées par leur
/// port SSH (1220/1221) et par leurs ports d'exporter (9101/9102, 9111/9112).
/// Les regrouper sur l'IP les fusionnerait.
///
/// On retient `(adresse, port svcprobe)` parce que c'est déjà, de fait, la clé
/// machine du parc : `svcprobe-install` cherche sur l'hôte Prometheus une cible
/// contenant `"{{ ansible_host }}:{{ svcprobe_port }}"` et saute
/// l'enregistrement s'il la trouve — « une seule cible par MACHINE, pas par
/// entrée d'inventaire ». On ne réinvente pas une identité, on remonte celle
/// que les rôles appliquent déjà.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MachineKey {
    pub address: String,
    pub svcprobe_port: u16,
}

impl MachineKey {
    pub fn of(host: &AnsibleHost) -> MachineKey {
        MachineKey {
            address: host.ansible_host.clone(),
            svcprobe_port: host.svcprobe_port.unwrap_or(SVCPROBE_DEFAULT_PORT),
        }
    }
}

impl fmt::Display for MachineKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Le port n'est montré que lorsqu'il distingue réellement deux machines,
        // sinon il alourdit l'affichage de tout un parc sans rien apprendre.
        if self.svcprobe_port == SVCPROBE_DEFAULT_PORT {
            f.write_str(&self.address)
        } else {
            write!(f, "{}:{}", self.address, self.svcprobe_port)
        }
    }
}

/// Santé agrégée d'une machine, telle que les sondes la rapportent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    /// Toutes les sondes connues répondent.
    Up,
    /// Une partie des sondes est tombée.
    Degraded,
    /// Aucune sonde ne répond.
    Down,
    /// Aucune sonde n'est enregistrée — indiscernable d'un service sain tant
    /// qu'on ne le dit pas. C'est précisément le défaut que la supervision
    /// existe pour éviter, il ne doit donc jamais s'afficher comme « vert ».
    Unknown,
}

/// Une MACHINE : l'unité qu'on allume, qu'on scrape et qu'on paie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub key: MachineKey,
    /// `None` quand aucune entrée ne le déclare, `Some` sinon. Une divergence
    /// entre entrées d'une même machine est signalée par `diagnostics`, pas
    /// arbitrée ici.
    pub provider: Option<ProviderKind>,
    /// Noms d'hôtes d'inventaire hébergés, triés.
    pub hosts: Vec<String>,
    /// Ports SSH distincts observés — plus d'un est le signe que la clé
    /// machine et le découpage par port SSH ne s'accordent pas.
    pub ssh_ports: Vec<u16>,
    pub health: Health,
}

impl Server {
    /// Familles de rôles portées par la machine, tous hôtes confondus.
    pub fn role_families(&self, fleet: &Fleet) -> Vec<String> {
        let mut families: Vec<String> = self
            .hosts
            .iter()
            .filter_map(|h| fleet.host(h))
            .flat_map(|h| h.ansible_roles.iter().cloned())
            .collect();
        families.sort();
        families.dedup();
        families
    }
}

/// Un parc : l'union de ses fichiers d'inventaire (`parc::Parc`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fleet {
    /// Nom de l'organisation — première clé sous `all.children`.
    pub organization: String,
    /// Référence du parc (nom, ou chemin d'un fichier isolé).
    pub inventory_path: String,
    pub groups: Vec<AnsibleGroup>,
    pub hosts: Vec<AnsibleHost>,
    pub servers: Vec<Server>,
}

impl Fleet {
    /// Construit le parc à partir de l'arbre de groupes : aplatit les hôtes,
    /// puis les regroupe en machines.
    pub fn build(organization: &str, inventory_path: &str, groups: Vec<AnsibleGroup>) -> Fleet {
        let hosts = crate::ansible_inventory::flatten_hosts(&groups);
        let servers = group_into_servers(&hosts);
        Fleet {
            organization: organization.to_string(),
            inventory_path: inventory_path.to_string(),
            groups,
            hosts,
            servers,
        }
    }

    pub fn host(&self, name: &str) -> Option<&AnsibleHost> {
        self.hosts.iter().find(|h| h.name == name)
    }

    pub fn server(&self, key: &MachineKey) -> Option<&Server> {
        self.servers.iter().find(|s| &s.key == key)
    }

    /// La machine qui héberge un hôte donné.
    pub fn server_of(&self, host_name: &str) -> Option<&Server> {
        let host = self.host(host_name)?;
        self.server(&MachineKey::of(host))
    }

    /// Applique les sondes Prometheus aux machines.
    ///
    /// Une sonde se rattache par son ADRESSE, pas par son port : une machine
    /// expose plusieurs cibles (node_exporter, svcprobe, exporters de service)
    /// sur des ports différents, et elles décrivent toutes le même matériel.
    pub fn apply_probes(&mut self, probes: &[Probe]) {
        for server in &mut self.servers {
            let mine: Vec<&Probe> = probes
                .iter()
                .filter(|p| p.address() == server.key.address)
                .collect();
            server.health = match (mine.len(), mine.iter().filter(|p| p.up).count()) {
                (0, _) => Health::Unknown,
                (total, up) if up == total => Health::Up,
                (_, 0) => Health::Down,
                _ => Health::Degraded,
            };
        }
    }
}

/// Regroupe des entrées d'inventaire en machines.
///
/// Les hôtes sans adresse sont ignorés : ils ne désignent aucune machine.
fn group_into_servers(hosts: &[AnsibleHost]) -> Vec<Server> {
    let mut buckets: BTreeMap<MachineKey, Vec<&AnsibleHost>> = BTreeMap::new();
    for host in hosts.iter().filter(|h| !h.ansible_host.trim().is_empty()) {
        buckets.entry(MachineKey::of(host)).or_default().push(host);
    }

    buckets
        .into_iter()
        .map(|(key, entries)| {
            // On ne choisit pas entre deux providers divergents : on retient le
            // premier déclaré et `diagnostics` lève le désaccord. Trancher ici
            // masquerait exactement la faute qu'on veut voir.
            let provider = entries
                .iter()
                .find_map(|h| h.provider.as_deref().and_then(ProviderKind::parse));

            let mut ssh_ports: Vec<u16> =
                entries.iter().filter_map(|h| h.ansible_port).collect();
            ssh_ports.sort_unstable();
            ssh_ports.dedup();

            let mut host_names: Vec<String> =
                entries.iter().map(|h| h.name.clone()).collect();
            host_names.sort();

            Server {
                key,
                provider,
                hosts: host_names,
                ssh_ports,
                health: Health::Unknown,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn host(name: &str, addr: &str, port: Option<u16>, svcprobe: Option<u16>) -> AnsibleHost {
        AnsibleHost {
            name: name.to_string(),
            ansible_host: addr.to_string(),
            ansible_port: port,
            ansible_user: None,
            hostname: None,
            server_type: None,
            provider: Some("contabo".to_string()),
            ansible_roles: vec![],
            svcprobe_port: svcprobe,
            monitor_port: None,
            groups: vec![],
            vars: HashMap::new(),
        }
    }

    #[test]
    fn entries_sharing_an_address_are_one_machine() {
        let hosts = vec![
            host("proxy1", "203.0.113.10", None, None),
            host("prometheus1", "203.0.113.10", None, None),
            host("mail", "203.0.113.10", None, None),
        ];
        let servers = group_into_servers(&hosts);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].hosts.len(), 3);
    }

    #[test]
    fn distinct_svcprobe_ports_behind_one_nat_are_distinct_machines() {
        // hub et nuc : deux machines physiques derrière 198.51.100.20.
        // Les fusionner sur l'IP serait le bug que cette clé existe pour éviter.
        let hosts = vec![
            host("hub", "198.51.100.20", Some(1220), Some(9111)),
            host("nuc", "198.51.100.20", Some(1221), Some(9112)),
        ];
        let servers = group_into_servers(&hosts);
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn hosts_without_an_address_designate_no_machine() {
        let hosts = vec![host("ghost", "", None, None)];
        assert!(group_into_servers(&hosts).is_empty());
    }

    #[test]
    fn provider_parsing_is_case_sensitive() {
        assert_eq!(ProviderKind::parse("contabo"), Some(ProviderKind::Contabo));
        assert_eq!(ProviderKind::parse("Contabo"), None);
    }

    #[test]
    fn custom_provider_has_no_cloud_api() {
        assert!(!ProviderKind::Custom.has_cloud_api());
        assert!(ProviderKind::Gcp.has_cloud_api());
    }

    #[test]
    fn a_machine_without_probes_is_unknown_not_healthy() {
        let hosts = vec![host("proxy1", "10.0.0.1", None, None)];
        let mut fleet = Fleet {
            organization: "t".into(),
            inventory_path: String::new(),
            groups: vec![],
            servers: group_into_servers(&hosts),
            hosts,
        };
        fleet.apply_probes(&[]);
        assert_eq!(fleet.servers[0].health, Health::Unknown);
    }

    #[test]
    fn probes_attach_by_address_across_ports() {
        let hosts = vec![host("proxy1", "10.0.0.1", None, None)];
        let mut fleet = Fleet {
            organization: "t".into(),
            inventory_path: String::new(),
            groups: vec![],
            servers: group_into_servers(&hosts),
            hosts,
        };
        fleet.apply_probes(&[
            Probe { instance: "10.0.0.1:9100".into(), job: "exporter".into(), up: true },
            Probe { instance: "10.0.0.1:9110".into(), job: "svcprobe".into(), up: false },
        ]);
        assert_eq!(fleet.servers[0].health, Health::Degraded);
    }
}
