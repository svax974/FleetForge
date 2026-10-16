/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Moteur de cohérence.
//!
//! Chaque règle ici correspond à une panne silencieuse déjà payée et consignée
//! dans `CLAUDE.md` : Prometheus installé après les services et ses `file_sd`
//! restés vides, web3c huit semaines sans `rule_files` ni Alertmanager, le job
//! `node-btc` vide depuis toujours. Le point commun de ces pannes est qu'un
//! parc en défaut ressemble exactement à un parc sain. Ce module fait la
//! différence, et les deux interfaces la rendent à l'identique.

use crate::metrics::Probe;
use crate::model::{Fleet, ProviderKind};
use crate::models::AnsibleRole;
use crate::parc::{self, Parc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Rompt un invariant : deux parcs là où il n'y en a qu'un, une machine
    /// comptée deux fois, une supervision qui ne surveille rien.
    Error,
    /// Fonctionne aujourd'hui, mais une obligation de convention n'est pas
    /// tenue — c'est ainsi que naissent les pannes muettes.
    Warning,
    /// Information utile, sans action requise.
    Info,
}

/// Ce que la règle vise. Permet aux interfaces de rattacher un constat à
/// l'élément affiché, plutôt que de dresser une liste à plat illisible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum Subject {
    Host(String),
    Server(String),
    RoleFamily(String),
    Fleet(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub subject: Subject,
    /// Identifiant stable de la règle, pour filtrer ou taire un constat.
    pub rule: &'static str,
    pub message: String,
}

/// Contexte d'analyse. Tout est optionnel sauf le parc : un diagnostic doit
/// pouvoir tourner sans Prometheus joignable, en disant simplement moins.
pub struct Context<'a> {
    pub fleet: &'a Fleet,
    pub roles: &'a [AnsibleRole],
    pub probes: &'a [Probe],
    /// `true` quand la supervision a répondu. Sans cela, on ne conclut rien
    /// sur les cibles : une supervision injoignable ferait passer tout le parc
    /// pour non supervisé.
    pub prometheus_reachable: bool,
    /// `false` quand ce parc n'a aucune URL de supervision enregistrée.
    /// Distinct de « injoignable » : là il n'y a rien à joindre, et le taire
    /// reviendrait à présenter comme sain un parc que personne ne surveille.
    pub prometheus_configured: bool,
}

/// Actions dont l'obligation est prescrite par CLAUDE.md § 2 pour toute
/// famille de rôles qui déploie un service.
const REQUIRED_ACTIONS: [&str; 3] = ["remove", "purge", "monitoring"];

/// Familles qui relèvent du socle appliqué partout, et sont explicitement
/// exclues de `ansible_roles` — donc jamais analysées comme des services.
const BASE_FAMILIES: [&str; 8] = [
    "install-tools",
    "install-python",
    "install-docker",
    "install-scripts",
    "exporter-sys",
    "host-preflight",
    "set-hostname",
    "svcprobe",
];

pub fn analyze(ctx: &Context<'_>) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_provider_declared(ctx, &mut findings);
    check_provider_consistent_per_address(ctx, &mut findings);
    check_machine_key_agrees_with_ssh_port(ctx, &mut findings);
    check_address_is_plausible(ctx, &mut findings);
    check_role_families_have_required_actions(ctx, &mut findings);
    check_prometheus_is_configured(ctx, &mut findings);
    check_machines_are_scraped(ctx, &mut findings);
    check_no_orphan_targets(ctx, &mut findings);

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.rule.cmp(b.rule)));
    findings
}

/// Constats propres à un PARC multi-fichiers (CLAUDE.md, « Parc et play.sh ») :
/// ils portent sur les fichiers, que le `Fleet` fusionné ne voit plus.
pub fn analyze_parc(parc: &Parc) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Ansible fusionne en silence : la dernière définition gagne, et
    // l'application refuse ensuite d'écrire dans l'un ou l'autre fichier.
    for (host, files) in parc::duplicate_hosts(parc) {
        findings.push(Finding {
            severity: Severity::Error,
            subject: Subject::Host(host.clone()),
            rule: "parc.duplicate_host",
            message: format!(
                "`{host}` est déclaré dans plusieurs fichiers du parc {} ({}) : Ansible n'en retient qu'un, sans le signaler.",
                parc.name,
                files.join(", ")
            ),
        });
    }
    for (file, org) in parc::misfiled(parc) {
        findings.push(Finding {
            severity: Severity::Error,
            subject: Subject::Fleet(parc.name.clone()),
            rule: "parc.misfiled",
            message: format!(
                "{file} range ses hôtes sous `{org}` et non `{}` : group_vars/{}.yml ne s'applique pas à eux.",
                parc.organization, parc.organization
            ),
        });
    }
    findings
}

/// `provider` est MANDATORY et volontairement sans défaut : c'est l'absence qui
/// doit se voir. Un défaut ferait passer pour « contabo » toute machine ajoutée
/// sans y penser, ce qui est pire que pas de variable.
fn check_provider_declared(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    for host in &ctx.fleet.hosts {
        match host.provider.as_deref() {
            None => out.push(Finding {
                severity: Severity::Error,
                subject: Subject::Host(host.name.clone()),
                rule: "provider.missing",
                message: format!("{} ne déclare pas de `provider`.", host.name),
            }),
            Some(raw) if ProviderKind::parse(raw).is_none() => out.push(Finding {
                severity: Severity::Error,
                subject: Subject::Host(host.name.clone()),
                rule: "provider.unknown",
                message: format!(
                    "{} porte `provider: {raw}`, hors liste fermée ({}).",
                    host.name,
                    ProviderKind::ALL
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }),
            Some(_) => {}
        }
    }
}

/// « Même adresse = même machine = même valeur. » Deux valeurs sur une adresse
/// font deux parcs là où il n'y en a qu'un.
fn check_provider_consistent_per_address(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    let mut by_address: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for host in &ctx.fleet.hosts {
        if host.ansible_host.trim().is_empty() {
            continue;
        }
        if let Some(p) = host.provider.as_deref() {
            by_address
                .entry(host.ansible_host.as_str())
                .or_default()
                .insert(p);
        }
    }

    for (address, providers) in by_address {
        if providers.len() > 1 {
            out.push(Finding {
                severity: Severity::Error,
                subject: Subject::Server(address.to_string()),
                rule: "provider.inconsistent",
                message: format!(
                    "{address} porte plusieurs `provider` ({}) : la même machine est comptée deux fois.",
                    providers.into_iter().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
}

/// L'identité machine repose sur `(adresse, port svcprobe)`. Le port SSH est le
/// second découpage possible. Quand les deux ne s'accordent pas, on le dit —
/// trancher en silence choisirait à la place de l'opérateur.
fn check_machine_key_agrees_with_ssh_port(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    for server in &ctx.fleet.servers {
        if server.ssh_ports.len() > 1 {
            out.push(Finding {
                severity: Severity::Warning,
                subject: Subject::Server(server.key.to_string()),
                rule: "machine.ambiguous",
                message: format!(
                    "{} regroupe des hôtes aux ports SSH distincts ({}) : \
                     s'agit-il vraiment d'une seule machine ? Distinguer par `svcprobe_port`.",
                    server.key,
                    server
                        .ssh_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }
}

/// Une adresse de remplacement laissée dans l'inventaire ne se voit jamais
/// tant qu'aucun playbook ne cible l'hôte.
fn check_address_is_plausible(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    for host in &ctx.fleet.hosts {
        let addr = host.ansible_host.trim();
        if addr.is_empty() {
            out.push(Finding {
                severity: Severity::Warning,
                subject: Subject::Host(host.name.clone()),
                rule: "address.missing",
                message: format!("{} n'a pas d'`ansible_host`.", host.name),
            });
            continue;
        }
        let resolvable = addr
            .split('.')
            .all(|part| part.parse::<u8>().is_ok())
            || addr.chars().any(|c| c.is_ascii_alphabetic() && c != 'x');
        if !resolvable {
            out.push(Finding {
                severity: Severity::Error,
                subject: Subject::Host(host.name.clone()),
                rule: "address.placeholder",
                message: format!(
                    "{} porte `ansible_host: {addr}`, qui n'est pas une adresse.",
                    host.name
                ),
            });
        }
    }
}

/// Toute famille qui déploie un SERVICE doit avoir ses contreparties.
/// Un service sans sonde est un service dont personne ne saura qu'il est tombé,
/// et c'est indiscernable d'un service en bonne santé.
fn check_role_families_have_required_actions(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    if ctx.roles.is_empty() {
        return; // catalogue non chargé : on ne conclut rien.
    }
    let known: BTreeSet<&str> = ctx.roles.iter().map(|r| r.name.as_str()).collect();

    let mut families: BTreeSet<&str> = BTreeSet::new();
    for host in &ctx.fleet.hosts {
        for f in &host.ansible_roles {
            if !BASE_FAMILIES.contains(&f.as_str()) {
                families.insert(f.as_str());
            }
        }
    }

    for family in families {
        // Une famille qui n'a AUCUN rôle n'est pas un service déployé par ce
        // dépôt : ne rien exiger d'elle. On ne cherche pas un `-install`
        // précis — `dbfront` s'installe par `dbfront-install-master`, `back`
        // n'a que `back-security` — ce qui faisait passer pour inconnues des
        // familles parfaitement réelles.
        let prefix = format!("{family}-");
        let has_any_role = known.iter().any(|r| r.starts_with(&prefix));
        if !has_any_role {
            out.push(Finding {
                severity: Severity::Warning,
                subject: Subject::RoleFamily(family.to_string()),
                rule: "family.unknown",
                message: format!(
                    "La famille `{family}` est déclarée dans `ansible_roles` mais aucun rôle `{family}-install` n'existe."
                ),
            });
            continue;
        }

        for action in REQUIRED_ACTIONS {
            // `monitoring-monitoring` : la famille porte déjà le nom de
            // l'action. Le rôle `monitoring-install` EST la supervision, il n'y
            // a rien à superviser de plus.
            if family == action {
                continue;
            }
            if !known.contains(format!("{family}-{action}").as_str()) {
                let (severity, why) = match action {
                    "monitoring" => (
                        Severity::Error,
                        "un service sans sonde est indiscernable d'un service sain",
                    ),
                    _ => (
                        Severity::Warning,
                        "obligation de convention (CLAUDE.md § 2)",
                    ),
                };
                out.push(Finding {
                    severity,
                    subject: Subject::RoleFamily(family.to_string()),
                    rule: "family.missing_action",
                    message: format!("`{family}` n'a pas de rôle `{family}-{action}` — {why}."),
                });
            }
        }
    }
}

/// Une machine sans aucune cible de scrape n'est pas supervisée. `ufw` fermé,
/// `file_sd` vide ou cible jamais posée : le symptôme est le même, l'absence.
/// Un parc sans supervision déclarée.
///
/// Depuis que chaque parc porte SA supervision, ne rien renseigner est
/// possible — et serait le pire des cas : aucune alerte, aucun constat, et un
/// parc qui a l'air parfaitement sain. C'est exactement le mode de panne que
/// tout ce module existe pour rendre visible.
fn check_prometheus_is_configured(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    if ctx.prometheus_configured || ctx.fleet.servers.is_empty() {
        return;
    }
    out.push(Finding {
        severity: Severity::Error,
        subject: Subject::Fleet(ctx.fleet.organization.clone()),
        rule: "monitoring.not_configured",
        message: format!(
            "Le parc `{}` n'a aucune URL Prometheus enregistrée : ses {} machines ne sont \
             surveillées par rien, et rien ne le signalerait.",
            ctx.fleet.organization,
            ctx.fleet.servers.len()
        ),
    });
}

fn check_machines_are_scraped(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    if !ctx.prometheus_reachable {
        return;
    }
    let scraped = scraped_identities(ctx.probes);

    let unscraped: Vec<&crate::model::Server> = ctx
        .fleet
        .servers
        .iter()
        .filter(|s| !is_scraped(s, &scraped))
        .collect();

    // Prometheus scrute des cibles, mais AUCUNE du parc : ce n'est pas un parc
    // entier tombé, c'est presque sûrement la mauvaise supervision.
    // `prometheus_host` vaut `prometheus1` sur papanglabs et `monitor` sur
    // web3c ; un seul réglage d'URL pour deux parcs les confond. Un constat
    // juste vaut mieux que treize faux.
    //
    // Un Prometheus qui ne scrute RIEN est un autre problème — il n'est pas
    // « celui d'un autre parc », il est vide — et chaque machine mérite alors
    // son propre constat.
    let scrutes_something = !ctx.probes.is_empty();
    if scrutes_something && !ctx.fleet.servers.is_empty() && unscraped.len() == ctx.fleet.servers.len()
    {
        out.push(Finding {
            severity: Severity::Error,
            subject: Subject::Fleet(ctx.fleet.organization.clone()),
            rule: "monitoring.wrong_prometheus",
            message: format!(
                "Aucune des {} machines de `{}` n'est scrutée alors que Prometheus répond : \
                 l'URL configurée est probablement celle d'un autre parc.",
                ctx.fleet.servers.len(),
                ctx.fleet.organization
            ),
        });
        return;
    }

    for server in unscraped {
        out.push(Finding {
            severity: Severity::Error,
            subject: Subject::Server(server.key.to_string()),
            rule: "monitoring.unscraped",
            message: format!(
                "{} n'a aucune cible Prometheus ({} hôte(s) concerné(s)). \
                 Réarmer : `--tags monitoring`.",
                server.key,
                server.hosts.len()
            ),
        });
    }
}

/// Identités portées par les cibles de scrape.
///
/// Le label `instance` ne contient PAS toujours une adresse : les modèles de
/// cible du parc l'écrasent avec `inventory_hostname`
/// (`"labels": {"instance": "{{ inventory_hostname }}"}`). Ne comparer que des
/// adresses faisait donc passer pour non supervisée toute machine correctement
/// enregistrée.
fn scraped_identities(probes: &[Probe]) -> BTreeSet<String> {
    probes
        .iter()
        .flat_map(|p| [p.address().to_string(), p.instance.clone()])
        .collect()
}

fn is_scraped(server: &crate::model::Server, scraped: &BTreeSet<String>) -> bool {
    scraped.contains(&server.key.address)
        || server.hosts.iter().any(|h| scraped.contains(h))
}

/// La cible désigne-t-elle un CONTENEUR hébergé par une machine connue ?
///
/// La découverte Docker nomme ses cibles d'après le conteneur, en y intercalant
/// l'adresse de l'hôte avec des tirets :
/// `ctdapi-back-203-0-113-20-back-1`. Ce n'est pas une machine orpheline,
/// c'est un service qui tourne sur une machine du parc — les signaler
/// noierait les vraies cibles restées après une purge.
fn runs_on_a_known_machine(instance: &str, known: &BTreeSet<&str>) -> bool {
    known.iter().any(|candidate| {
        candidate.split('.').count() == 4
            && candidate.split('.').all(|p| p.parse::<u8>().is_ok())
            && instance.contains(&candidate.replace('.', "-"))
    })
}

/// Une cible restée en place après une purge publie `up=0` indéfiniment et fait
/// sonner une alerte sur un service volontairement désinstallé.
fn check_no_orphan_targets(ctx: &Context<'_>, out: &mut Vec<Finding>) {
    if !ctx.prometheus_reachable {
        return;
    }
    // Une cible peut être nommée par son adresse OU par son nom d'inventaire :
    // les deux valent reconnaissance, sinon toute machine correctement
    // enregistrée passerait pour orpheline.
    let mut known: BTreeSet<&str> = BTreeSet::new();
    for server in &ctx.fleet.servers {
        known.insert(server.key.address.as_str());
        for host in &server.hosts {
            known.insert(host.as_str());
        }
    }

    let mut orphans: BTreeSet<&str> = BTreeSet::new();
    for probe in ctx.probes {
        let addr = probe.address();
        // Une cible locale à Prometheus (auto-scrape, bridge Docker) ne décrit
        // pas une machine du parc.
        let local = addr == "localhost"
            || addr.starts_with("127.")
            || addr.starts_with("172.17.")
            || addr.starts_with("172.18.");
        let recognised = known.contains(addr)
            || known.contains(probe.instance.as_str())
            || runs_on_a_known_machine(&probe.instance, &known);
        if !local && !recognised {
            orphans.insert(addr);
        }
    }

    for addr in orphans {
        out.push(Finding {
            severity: Severity::Warning,
            subject: Subject::Server(addr.to_string()),
            rule: "monitoring.orphan_target",
            message: format!(
                "Prometheus scrute {addr}, absente de l'inventaire : cible orpheline ou machine non gérée."
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AnsibleHost, AnsibleRole};
    use std::collections::HashMap;

    fn host(name: &str, addr: &str, provider: Option<&str>, families: &[&str]) -> AnsibleHost {
        AnsibleHost {
            name: name.into(),
            ansible_host: addr.into(),
            ansible_port: None,
            ansible_user: None,
            hostname: None,
            server_type: None,
            provider: provider.map(|s| s.to_string()),
            ansible_roles: families.iter().map(|s| s.to_string()).collect(),
            svcprobe_port: None,
            monitor_port: None,
            groups: vec![],
            vars: HashMap::new(),
        }
    }

    fn role(name: &str) -> AnsibleRole {
        AnsibleRole {
            name: name.into(),
            label: name.into(),
            category: "T".into(),
            description: String::new(),
            path: String::new(),
            has_tasks: true,
            has_templates: false,
            has_handlers: false,
        }
    }

    fn fleet(hosts: Vec<AnsibleHost>) -> Fleet {
        Fleet::build("test", "inv.yml", vec![crate::models::AnsibleGroup {
            name: "g".into(),
            hosts,
            children: vec![],
        }])
    }

    fn analyze_with(f: &Fleet, roles: &[AnsibleRole], probes: &[Probe], reachable: bool) -> Vec<Finding> {
        analyze(&Context {
            fleet: f,
            roles,
            probes,
            prometheus_reachable: reachable,
            // Les cas de test qui n'en parlent pas supposent une supervision
            // renseignée : c'est `not_configured` qui a son propre test.
            prometheus_configured: true,
        })
    }

    #[test]
    fn a_missing_provider_is_an_error() {
        let f = fleet(vec![host("h1", "10.0.0.1", None, &[])]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(found.iter().any(|x| x.rule == "provider.missing"));
    }

    #[test]
    fn a_miscased_provider_is_rejected_not_normalised() {
        let f = fleet(vec![host("h1", "10.0.0.1", Some("Contabo"), &[])]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(found.iter().any(|x| x.rule == "provider.unknown"));
    }

    #[test]
    fn two_providers_on_one_address_is_an_error() {
        let f = fleet(vec![
            host("h1", "10.0.0.1", Some("contabo"), &[]),
            host("h2", "10.0.0.1", Some("ovh"), &[]),
        ]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(found.iter().any(|x| x.rule == "provider.inconsistent"));
    }

    #[test]
    fn placeholder_address_is_caught() {
        // Cas réel : docker-repo porte `xxx.xxx.xxx.xxx`.
        let f = fleet(vec![host("docker-repo", "xxx.xxx.xxx.xxx", Some("contabo"), &[])]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(found.iter().any(|x| x.rule == "address.placeholder"));
    }

    #[test]
    fn a_real_ip_is_not_flagged() {
        let f = fleet(vec![host("h1", "203.0.113.10", Some("contabo"), &[])]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(!found.iter().any(|x| x.rule.starts_with("address.")));
    }

    #[test]
    fn a_family_without_monitoring_is_an_error() {
        // Cas réel : papangmetrics n'a pas de rôle -monitoring.
        let f = fleet(vec![host("pm1", "10.0.0.1", Some("contabo"), &["papangmetrics"])]);
        let roles = vec![
            role("papangmetrics-deploy"),
            role("papangmetrics-purge"),
            role("papangmetrics-remove"),
        ];
        let found = analyze_with(&f, &roles, &[], false);
        assert!(found
            .iter()
            .any(|x| x.rule == "family.missing_action" && x.message.contains("monitoring")));
    }

    #[test]
    fn a_complete_family_raises_nothing() {
        let f = fleet(vec![host("b1", "10.0.0.1", Some("contabo"), &["brk"])]);
        let roles = vec![
            role("brk-install"),
            role("brk-remove"),
            role("brk-purge"),
            role("brk-monitoring"),
        ];
        let found = analyze_with(&f, &roles, &[], false);
        assert!(!found.iter().any(|x| x.rule.starts_with("family.")));
    }

    #[test]
    fn base_families_are_not_treated_as_services() {
        let f = fleet(vec![host("h1", "10.0.0.1", Some("contabo"), &["exporter-sys"])]);
        let found = analyze_with(&f, &[role("exporter-sys-install")], &[], false);
        assert!(!found.iter().any(|x| x.rule.starts_with("family.")));
    }

    #[test]
    fn an_unscraped_machine_is_reported_only_when_prometheus_answered() {
        let f = fleet(vec![host("h1", "10.0.0.1", Some("contabo"), &[])]);

        // Supervision injoignable : on ne conclut rien, sinon tout le parc
        // passerait pour non supervisé à la moindre coupure réseau.
        assert!(!analyze_with(&f, &[], &[], false)
            .iter()
            .any(|x| x.rule == "monitoring.unscraped"));

        assert!(analyze_with(&f, &[], &[], true)
            .iter()
            .any(|x| x.rule == "monitoring.unscraped"));
    }

    #[test]
    fn a_target_outside_the_inventory_is_an_orphan() {
        let f = fleet(vec![host("h1", "10.0.0.1", Some("contabo"), &[])]);
        let probes = vec![
            Probe { instance: "10.0.0.1:9100".into(), job: "exporter".into(), up: true },
            Probe { instance: "10.0.0.99:9100".into(), job: "exporter".into(), up: false },
        ];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(found
            .iter()
            .any(|x| x.rule == "monitoring.orphan_target" && x.message.contains("10.0.0.99")));
    }

    #[test]
    fn a_target_named_by_inventory_hostname_counts_as_scraped() {
        // Les modèles de cible du parc écrasent `instance` avec
        // `inventory_hostname` : ne comparer que des adresses faisait passer
        // pour non supervisée toute machine correctement enregistrée.
        let f = fleet(vec![host("proxy1", "203.0.113.10", Some("contabo"), &[])]);
        let probes = vec![Probe {
            instance: "proxy1".into(),
            job: "svcprobe".into(),
            up: true,
        }];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(!found.iter().any(|x| x.rule == "monitoring.unscraped"));
        assert!(!found.iter().any(|x| x.rule == "monitoring.orphan_target"));
    }

    #[test]
    fn a_fleet_without_any_prometheus_says_so_loudly() {
        // Depuis que chaque parc porte SA supervision, ne rien renseigner est
        // possible — et serait le pire des cas : un parc que personne ne
        // surveille, et qui a l'air parfaitement sain.
        let f = fleet(vec![host("a", "10.0.0.1", Some("contabo"), &[])]);
        let found = analyze(&Context {
            fleet: &f,
            roles: &[],
            probes: &[],
            prometheus_reachable: false,
            prometheus_configured: false,
        });
        assert!(found.iter().any(|x| x.rule == "monitoring.not_configured"));
    }

    #[test]
    fn a_configured_fleet_does_not_get_the_not_configured_finding() {
        let f = fleet(vec![host("a", "10.0.0.1", Some("contabo"), &[])]);
        let found = analyze_with(&f, &[], &[], false);
        assert!(!found.iter().any(|x| x.rule == "monitoring.not_configured"));
    }

    #[test]
    fn a_whole_fleet_unscraped_points_at_the_wrong_prometheus() {
        // Treize « machine non supervisée » quand c'est l'URL qui est celle
        // d'un autre parc : un constat juste vaut mieux que treize faux.
        let f = fleet(vec![
            host("a", "10.0.0.1", Some("contabo"), &[]),
            host("b", "10.0.0.2", Some("contabo"), &[]),
        ]);
        let probes = vec![Probe {
            instance: "autre-parc".into(),
            job: "exporter".into(),
            up: true,
        }];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(found.iter().any(|x| x.rule == "monitoring.wrong_prometheus"));
        assert!(
            !found.iter().any(|x| x.rule == "monitoring.unscraped"),
            "les constats par machine doivent laisser place au constat global"
        );
    }

    #[test]
    fn one_unscraped_machine_among_others_stays_a_per_machine_finding() {
        let f = fleet(vec![
            host("a", "10.0.0.1", Some("contabo"), &[]),
            host("b", "10.0.0.2", Some("contabo"), &[]),
        ]);
        let probes = vec![Probe {
            instance: "10.0.0.1:9100".into(),
            job: "exporter".into(),
            up: true,
        }];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(!found.iter().any(|x| x.rule == "monitoring.wrong_prometheus"));
        assert_eq!(
            found.iter().filter(|x| x.rule == "monitoring.unscraped").count(),
            1
        );
    }

    #[test]
    fn a_family_whose_install_role_is_named_differently_is_still_known() {
        // Cas réels : `dbfront` s'installe par `dbfront-install-master`,
        // `back` n'a que `back-security`. Exiger un `<famille>-install` exact
        // les faisait passer pour des familles inconnues.
        let f = fleet(vec![host("h", "10.0.0.1", Some("contabo"), &["dbfront", "back"])]);
        let roles = vec![role("dbfront-install-master"), role("back-security")];
        let found = analyze_with(&f, &roles, &[], false);
        assert!(
            !found.iter().any(|x| x.rule == "family.unknown"),
            "familles signalées à tort : {:?}",
            found.iter().filter(|x| x.rule == "family.unknown").collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_family_with_no_role_at_all_is_still_reported() {
        let f = fleet(vec![host("h", "10.0.0.1", Some("contabo"), &["fantome"])]);
        let found = analyze_with(&f, &[role("brk-install")], &[], false);
        assert!(found.iter().any(|x| x.rule == "family.unknown"));
    }

    #[test]
    fn a_docker_container_target_is_not_an_orphan_machine() {
        // La découverte Docker intercale l'adresse de l'hôte avec des tirets.
        let f = fleet(vec![host("ctdapi", "203.0.113.20", Some("contabo"), &[])]);
        let probes = vec![Probe {
            instance: "ctdapi-back-203-0-113-20-back-worker-1".into(),
            job: "exporter".into(),
            up: true,
        }];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(!found.iter().any(|x| x.rule == "monitoring.orphan_target"));
    }

    #[test]
    fn a_container_on_an_unknown_machine_is_still_an_orphan() {
        let f = fleet(vec![host("a", "10.0.0.1", Some("contabo"), &[])]);
        let probes = vec![
            Probe { instance: "10.0.0.1:9100".into(), job: "exporter".into(), up: true },
            Probe { instance: "svc-back-203-0-113-9-back-1".into(), job: "exporter".into(), up: true },
        ];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(found.iter().any(|x| x.rule == "monitoring.orphan_target"));
    }

    #[test]
    fn a_family_named_after_its_action_is_not_asked_to_monitor_itself() {
        // `monitoring-monitoring` : le rôle `monitoring-install` EST la
        // supervision, il n'y a rien à superviser de plus.
        let f = fleet(vec![host("m", "10.0.0.1", Some("contabo"), &["monitoring"])]);
        let roles = vec![
            role("monitoring-install"),
            role("monitoring-remove"),
            role("monitoring-purge"),
        ];
        let found = analyze_with(&f, &roles, &[], false);
        assert!(
            !found.iter().any(|x| x.message.contains("monitoring-monitoring")),
            "constat absurde conservé"
        );
    }

    #[test]
    fn prometheus_local_targets_are_not_orphans() {
        let f = fleet(vec![host("h1", "10.0.0.1", Some("contabo"), &[])]);
        let probes = vec![
            Probe { instance: "10.0.0.1:9100".into(), job: "exporter".into(), up: true },
            Probe { instance: "localhost:9090".into(), job: "prometheus".into(), up: true },
            Probe { instance: "172.17.0.1:9100".into(), job: "exporter".into(), up: true },
        ];
        let found = analyze_with(&f, &[], &probes, true);
        assert!(!found.iter().any(|x| x.rule == "monitoring.orphan_target"));
    }
}
