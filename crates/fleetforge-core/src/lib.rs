/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Cœur métier de FleetForge, partagé par le GUI (Tauri) et le TUI.
//!
//! Aucune dépendance d'interface n'entre ici. C'est la seule garantie que les
//! deux façades voient le même parc : toute logique qui remonterait dans l'une
//! d'elles finirait par diverger de l'autre en silence.
//!
//! Point d'entrée : [`Core`].

pub mod alert_rules;
pub mod ansible_group_vars;
pub mod ansible_inventory;
pub mod ansible_playbooks;
pub mod ansible_roles;
pub mod ansible_runner;
pub mod database;
pub mod deploy;
pub mod diagnostics;
pub mod families;
pub mod inventory_dynamic;
pub mod inventory_writer;
pub mod logging;
pub mod metrics;
pub mod model;
pub mod models;
pub mod parc;
pub mod paths;
pub mod service_tracker;
pub mod services_catalog;
pub mod settings;
pub mod style;

use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

pub use ansible_group_vars::GroupVarEntry;
pub use database::Database;
pub use deploy::{DeployRequest, PlaybookRequest, RunHandle, RunRegistry};
pub use metrics::{Probe, ProbeScope, PrometheusClient, PrometheusConfig};
pub use model::{Fleet, Health, MachineKey, ProviderKind, Server};
pub use models::*;
pub use services_catalog::CatalogService;
pub use settings::{SettingKey, Settings};

/// Premier candidat qui existe réellement au catalogue.
///
/// `candidate_roles` propose du plus sûr au plus spéculatif ; c'est le
/// catalogue qui tranche, parce que toutes les familles n'ont pas leur `-purge`.
fn resolve_role(roles: &[AnsibleRole], service_name: &str, action: &str) -> Option<AnsibleRole> {
    service_tracker::candidate_roles(service_name, action)
        .into_iter()
        .find_map(|c| roles.iter().find(|r| r.name == c).cloned())
}

/// Façade du cœur. Les deux interfaces n'en connaissent qu'elle.
///
/// Le GUI l'enveloppe dans un `tauri::State` et ses commandes deviennent des
/// adaptateurs de quelques lignes ; le TUI l'appelle directement.
pub struct Core {
    db: Mutex<Database>,
    runs: RunRegistry,
}

impl Core {
    pub fn new() -> Result<Self> {
        let db = Database::new()?;
        Ok(Self {
            db: Mutex::new(db),
            runs: RunRegistry::new(),
        })
    }

    /// Accès brut à la base, pour les rares appels qui n'ont pas de méthode
    /// dédiée. Le verrou est volontairement court : le lock ne doit jamais
    /// être tenu pendant un run Ansible, qui dure des minutes.
    pub fn with_db<T>(&self, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow!("state de la base empoisonné"))?;
        f(&db)
    }

    pub fn runs(&self) -> &RunRegistry {
        &self.runs
    }

    // === Réglages ===

    pub fn settings(&self) -> Result<Settings> {
        self.with_db(Settings::load)
    }

    pub fn get_setting(&self, key: SettingKey) -> Result<String> {
        self.with_db(|db| Ok(db.get_setting(key.as_str())?.unwrap_or_default()))
    }

    pub fn set_setting(&self, key: SettingKey, value: &str) -> Result<()> {
        self.with_db(|db| {
            db.set_setting(key.as_str(), value)?;
            Ok(())
        })
    }

    fn inventories_path(&self) -> Result<String> {
        self.get_setting(SettingKey::InventoriesPath)
    }

    fn playbooks_path(&self) -> Result<String> {
        self.get_setting(SettingKey::PlaybooksPath)
    }

    // === Inventaires ===

    /// Les PARCS : un par préfixe `<parc>_*.yml` (CLAUDE.md, « Parc et
    /// play.sh »). `file_path` y porte le nom du parc, c'est la référence que
    /// les façades renvoient ensuite au cœur.
    pub fn list_inventories(&self) -> Result<Vec<AnsibleInventoryInfo>> {
        Ok(self
            .list_parcs()?
            .into_iter()
            .map(|p| AnsibleInventoryInfo {
                name: p.name.clone(),
                file_path: p.name,
                organization: p.organization,
                files: p.files,
            })
            .collect())
    }

    pub fn list_parcs(&self) -> Result<Vec<parc::Parc>> {
        let path = self.inventories_path()?;
        if path.is_empty() {
            return Ok(vec![]);
        }
        parc::list_parcs(&path)
    }

    /// Résout une référence d'inventaire — nom de parc, ou chemin d'un
    /// fichier existant (contournement, et forme héritée des réglages).
    pub fn resolve_inventory(&self, reference: &str) -> Result<parc::Parc> {
        parc::resolve(&self.inventories_path()?, reference)
    }

    /// Contexte de résolution : racine du dépôt et dossier des playbooks, sans
    /// lequel `group_vars/` n'est pas chargé (il vit sous `playbooks/`, pas à
    /// côté des inventaires).
    fn resolve_context(&self) -> Result<inventory_dynamic::ResolveContext> {
        let settings = self.settings()?;
        let playbook_dir = (!settings.playbooks_path.is_empty())
            .then(|| std::path::PathBuf::from(&settings.playbooks_path));
        Ok(inventory_dynamic::ResolveContext {
            root: settings.ansible_root(),
            playbook_dir,
        })
    }

    /// Groupes d'un inventaire.
    ///
    /// Passe par `ansible-inventory`, seul capable de résoudre les inventaires
    /// dynamiques (`gcp.yml`), la précédence des `group_vars` et le Jinja. Le
    /// lecteur `serde_yaml` sert de repli quand Ansible n'est pas installé :
    /// mieux vaut un arbre partiel qu'un écran vide.
    pub fn inventory_groups(&self, inventory_path: &str) -> Result<Vec<AnsibleGroup>> {
        let parc = self.resolve_inventory(inventory_path)?;
        if let Ok(ctx) = self.resolve_context() {
            match inventory_dynamic::resolve(&parc.files, &ctx) {
                Ok(groups) if !groups.is_empty() => return Ok(groups),
                // Un inventaire réellement vide comme un Ansible absent
                // retombent sur le lecteur statique : il ne peut pas faire pire.
                _ => {}
            }
        }
        ansible_inventory::parse_inventories(&parc.files)
    }

    /// Le parc complet : hôtes aplatis et regroupés en machines.
    pub fn fleet(&self, inventory_path: &str) -> Result<Fleet> {
        let parc = self.resolve_inventory(inventory_path)?;
        let groups = self.inventory_groups(inventory_path)?;
        Ok(Fleet::build(&parc.organization, inventory_path, groups))
    }

    /// L'inventaire retenu, en écartant une valeur devenue obsolète.
    ///
    /// Le réglage persistait un chemin qui pouvait ne plus exister ; c'est le
    /// frontal qui s'en apercevait et le remettait à zéro. Le cœur se soigne
    /// désormais lui-même, sinon le TUI hériterait du même défaut.
    ///
    /// Avant les parcs, le réglage portait le CHEMIN d'un fichier : il est
    /// converti une fois pour toutes en nom de parc, le nom du fichier en
    /// donnant le préfixe.
    pub fn selected_inventory(&self) -> Result<Option<AnsibleInventoryInfo>> {
        let selected = self.get_setting(SettingKey::SelectedInventory)?;
        if selected.is_empty() {
            return Ok(None);
        }
        let available = self.list_inventories()?;
        if let Some(found) = available.iter().find(|i| i.file_path == selected) {
            return Ok(Some(found.clone()));
        }
        let legacy = std::path::Path::new(&selected);
        let migrated = legacy
            .extension()
            .is_some()
            .then(|| parc::parc_name_of(legacy))
            .flatten()
            .and_then(|name| available.into_iter().find(|i| i.file_path == name));
        self.set_setting(
            SettingKey::SelectedInventory,
            migrated.as_ref().map(|i| i.file_path.as_str()).unwrap_or(""),
        )?;
        Ok(migrated)
    }

    // === Catalogues ===

    pub fn list_playbooks(&self) -> Result<Vec<AnsiblePlaybook>> {
        let path = self.playbooks_path()?;
        if path.is_empty() {
            return Ok(vec![]);
        }
        ansible_playbooks::list_playbooks(&path)
    }

    pub fn list_roles(&self) -> Result<Vec<AnsibleRole>> {
        let path = self.playbooks_path()?;
        if path.is_empty() {
            return Ok(vec![]);
        }
        ansible_roles::list_roles(&path)
    }

    pub fn services_catalog(&self) -> Result<Vec<CatalogService>> {
        services_catalog::build_services_catalog(&self.playbooks_path()?)
    }

    pub fn service_names(&self) -> Result<Vec<String>> {
        services_catalog::get_service_names(&self.playbooks_path()?)
    }

    /// Le rôle de désinstallation d'un service, s'il existe.
    ///
    /// Vivait dans `ServicesView.tsx` avec un commentaire décrivant le défaut :
    /// `service_tracker::parse_role` renomme certains services (« nginx-proxy »)
    /// et l'inverse ne retombait pas sur un nom de rôle réel. La résolution est
    /// désormais faite ici, contre le catalogue.
    pub fn uninstall_role(&self, service_name: &str, action: &str) -> Result<Option<AnsibleRole>> {
        // Le catalogue fait foi : `candidate_roles` propose, il ne garantit pas
        // que le rôle existe — toutes les familles n'ont pas leur `-purge`.
        let roles = self.list_roles()?;
        Ok(resolve_role(&roles, service_name, action))
    }

    /// Rôles de désinstallation pour un lot de services, en un seul aller.
    ///
    /// Le frontal en a besoin par ligne de tableau ; les résoudre un par un
    /// ferait autant d'allers-retours que de services affichés.
    pub fn uninstall_roles(
        &self,
        service_names: &[String],
        actions: &[String],
    ) -> Result<std::collections::HashMap<String, std::collections::HashMap<String, AnsibleRole>>>
    {
        let roles = self.list_roles()?;
        let mut out = std::collections::HashMap::new();
        for service in service_names {
            let mut per_action = std::collections::HashMap::new();
            for action in actions {
                if let Some(role) = resolve_role(&roles, service, action) {
                    per_action.insert(action.clone(), role);
                }
            }
            out.insert(service.clone(), per_action);
        }
        Ok(out)
    }

    // === Group vars ===

    pub fn list_group_vars_files(&self) -> Result<Vec<String>> {
        let path = self.playbooks_path()?;
        if path.is_empty() {
            return Ok(vec![]);
        }
        ansible_group_vars::list_group_vars_files(&path)
    }

    pub fn read_group_vars(&self, filename: &str) -> Result<Vec<GroupVarEntry>> {
        let path = self.playbooks_path()?;
        if path.is_empty() {
            return Err(anyhow!("Playbooks path not configured"));
        }
        ansible_group_vars::read_group_vars_file(&path, filename)
    }

    pub fn write_group_vars(&self, filename: &str, entries: &[GroupVarEntry]) -> Result<()> {
        let path = self.playbooks_path()?;
        if path.is_empty() {
            return Err(anyhow!("Playbooks path not configured"));
        }
        ansible_group_vars::write_group_vars_file(&path, filename, entries)
    }

    // === Exemptions d'alertes ===

    /// Règles d'alerte connues, celles que le parc charge en premier.
    pub fn list_alert_rules(&self, inventory_path: &str) -> Result<Vec<alert_rules::AlertRule>> {
        let parc = self.resolve_inventory(inventory_path)?;
        alert_rules::list_alert_rules(&self.playbooks_path()?, &parc.name)
    }

    /// Remplace les exemptions d'une entrée (`alert_exclude`). Effet au
    /// prochain `update-prometheus-alerts.yml`.
    pub fn set_alert_exclusions(&self, inventory_path: &str, host: &str, alerts: &[String]) -> Result<()> {
        let parc = self.resolve_inventory(inventory_path)?;
        alert_rules::set_alert_exclusions(&self.playbooks_path()?, &parc, host, alerts)
    }

    // === Prometheus ===

    /// Réglages de supervision D'UN PARC.
    ///
    /// Il n'y a PAS de valeur globale. Chaque parc a sa propre machine de
    /// supervision — `prometheus_host` vaut `prometheus1` sur papanglabs et
    /// `monitor` sur web3c — et une cascade « global puis surcharge » obligeait
    /// à se demander laquelle s'appliquait. Un parc ajouté sans y penser
    /// héritait en silence de la supervision d'un autre, et comme les noms
    /// d'hôtes se répètent (`proxy1`, `mail`), le résultat n'était pas vide
    /// mais FAUX. Une valeur, un parc.
    pub fn prometheus_config_for(&self, organization: &str) -> Result<PrometheusConfig> {
        if organization.is_empty() {
            return Ok(PrometheusConfig::default());
        }
        let read = |key: SettingKey| -> Result<String> {
            Ok(self
                .with_db(|db| Ok(db.get_setting(&key.scoped(organization))?))?
                .unwrap_or_default())
        };
        Ok(PrometheusConfig {
            url: read(SettingKey::PrometheusUrl)?,
            user: read(SettingKey::PrometheusUser)?,
            password: read(SettingKey::PrometheusPassword)?,
        })
    }

    pub fn prometheus_for(&self, organization: &str) -> Result<PrometheusClient> {
        PrometheusClient::new(self.prometheus_config_for(organization)?)
    }

    /// Supervision du parc actuellement sélectionné.
    pub fn prometheus(&self) -> Result<PrometheusClient> {
        self.prometheus_for(&self.current_organization()?)
    }

    /// Organisation du parc sélectionné, vide si aucun.
    pub fn current_organization(&self) -> Result<String> {
        Ok(self
            .selected_inventory()?
            .map(|i| i.organization)
            .unwrap_or_default())
    }

    pub fn set_prometheus_for(
        &self,
        organization: &str,
        key: SettingKey,
        value: &str,
    ) -> Result<()> {
        self.with_db(|db| {
            db.set_setting(&key.scoped(organization), value)?;
            Ok(())
        })
    }

    pub async fn query_prometheus(&self, query: &str) -> Result<Vec<PrometheusMetric>> {
        self.prometheus()?.query(query).await
    }

    pub async fn probes(&self, scope: ProbeScope) -> Result<Vec<Probe>> {
        self.prometheus()?.probes(scope).await
    }

    /// Le parc, sondes appliquées. C'est la vue qu'affichent les deux
    /// interfaces en page d'accueil.
    pub async fn fleet_with_health(&self, inventory_path: &str) -> Result<Fleet> {
        let mut fleet = self.fleet(inventory_path)?;
        // Une supervision injoignable ne doit pas empêcher d'afficher le parc :
        // les machines restent en `Unknown`, ce qui est la vérité.
        if let Ok(probes) = self.fleet_probes(&fleet.organization).await {
            fleet.apply_probes(&probes);
        }
        Ok(fleet)
    }

    /// Sondes de LA supervision de ce parc.
    async fn fleet_probes(&self, organization: &str) -> Result<Vec<Probe>> {
        self.prometheus_for(organization)?
            .probes(ProbeScope::All)
            .await
    }

    // === Historique ===

    pub fn ansible_runs(&self) -> Result<Vec<AnsibleRun>> {
        self.with_db(|db| db.get_ansible_runs())
    }

    pub fn ansible_run_output(&self, run_id: i64) -> Result<String> {
        self.with_db(|db| Ok(db.get_ansible_run_by_id(run_id)?.output))
    }

    pub fn current_services(&self, server_id: Option<i64>) -> Result<Vec<ServerServiceState>> {
        self.with_db(|db| db.get_server_current_services(server_id))
    }

    pub fn server_services(
        &self,
        server_id: Option<i64>,
        service_name: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<ServerService>> {
        self.with_db(|db| db.get_server_services(server_id, service_name, status))
    }

    pub fn add_manual_service(
        &self,
        server_name: &str,
        service_name: &str,
        action: &str,
        notes: Option<String>,
    ) -> Result<ServerService> {
        self.with_db(|db| {
            db.add_server_service(ServerService {
                id: None,
                server_id: 0,
                server_name: server_name.to_string(),
                service_name: service_name.to_string(),
                action: action.to_string(),
                source: "manual".to_string(),
                role_name: None,
                ansible_run_id: None,
                status: "success".to_string(),
                executed_at: chrono::Utc::now().to_rfc3339(),
                notes,
            })
        })
    }

    // === Diagnostics ===

    /// Constats de cohérence sur un parc. Chaque règle correspond à une panne
    /// silencieuse déjà payée : voir [`diagnostics`].
    pub async fn diagnose(&self, inventory_path: &str) -> Result<Vec<diagnostics::Finding>> {
        let fleet = self.fleet(inventory_path)?;
        let roles = self.list_roles().unwrap_or_default();
        let configured = self
            .prometheus_config_for(&fleet.organization)?
            .is_configured();
        let (probes, reachable) = match self.fleet_probes(&fleet.organization).await {
            Ok(p) => (p, true),
            Err(_) => (vec![], false),
        };
        let mut findings = diagnostics::analyze(&diagnostics::Context {
            fleet: &fleet,
            roles: &roles,
            probes: &probes,
            prometheus_reachable: reachable,
            prometheus_configured: configured,
        });
        findings.extend(diagnostics::analyze_parc(&self.resolve_inventory(inventory_path)?));
        findings.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.rule.cmp(b.rule)));
        Ok(findings)
    }

    // === Exécution ===

    pub fn ansible_available(&self) -> bool {
        ansible_runner::check_ansible_installed()
    }

    fn ansible_env(&self) -> Result<ansible_runner::AnsibleEnv> {
        Ok(ansible_runner::AnsibleEnv::at_root(
            self.settings()?.ansible_root(),
        ))
    }

    /// Déploie des rôles. `on_line` reçoit chaque ligne en direct ; le registre
    /// est alimenté en parallèle, de sorte qu'une interface qui rejoint le run
    /// en cours de route retrouve la sortie déjà produite.
    pub fn run_deploy<F>(&self, req: DeployRequest, on_line: F) -> Result<AnsibleRun>
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        req.validate()?;
        let playbooks_path = self.playbooks_path()?;
        if playbooks_path.is_empty() {
            return Err(anyhow!("Playbooks path not configured"));
        }
        // Avant `runs.start` : une référence inconnue ne doit pas laisser un
        // run « en cours » à jamais dans le registre.
        let parc = self.resolve_inventory(&req.inventory_path)?;

        self.runs.start(
            &req.id,
            &req.label,
            deploy::RunKind::Role,
            &req.roles,
            &req.hosts,
        );

        let env = self.ansible_env()?;
        let extra = (!req.extra_vars.is_empty()).then(|| req.extra_vars.clone());
        let sink = Arc::new(deploy::line_sink(&self.runs, &req.id, on_line));

        let mut families: Vec<String> = req
            .roles
            .iter()
            .filter_map(|r| families::family_of_role(&playbooks_path, r))
            .collect();
        families.dedup();
        let inscribed = self.inscribe_families(&parc, &families, &req.hosts, &*sink);

        let run = ansible_runner::run_playbook_streaming(
            &playbooks_path,
            &parc,
            &req.roles,
            &req.hosts,
            extra,
            &env,
            { let s = sink.clone(); move |l: String| s(l) },
        )?;
        if run.status != "success" {
            families::revert(&inscribed).into_iter().for_each(|n| sink(format!("[fleetforge] {n}")));
        }

        self.runs
            .finish(&req.id, deploy::RunStatus::from_str(&run.status));

        let saved = self.with_db(|db| {
            let saved = db.add_ansible_run(run)?;
            deploy::record_deploy(db, &saved, &req.roles, &req.hosts);
            Ok(saved)
        })?;
        Ok(saved)
    }

    /// Inscrit chaque famille sur les hôtes qui ne la portent pas encore
    /// (`families`). Ne fait jamais échouer le déploiement : une inscription
    /// impossible est expliquée dans la sortie du run.
    fn inscribe_families(
        &self,
        parc: &parc::Parc,
        wanted: &[String],
        hosts: &[String],
        say: &dyn Fn(String),
    ) -> Vec<families::FamilyEdit> {
        if wanted.is_empty() || hosts.is_empty() {
            return vec![];
        }
        let fleet = match self.inventory_groups(&parc.name) {
            Ok(groups) => Fleet::build(&parc.organization, &parc.name, groups),
            Err(e) => {
                say(format!("[fleetforge] ansible_roles non mis à jour : {e}"));
                return vec![];
            }
        };
        let mut done = Vec::new();
        for family in wanted {
            let (edits, notes) = families::inscribe(parc, &fleet, family, hosts);
            notes.into_iter().for_each(|n| say(format!("[fleetforge] {n}")));
            done.extend(edits);
        }
        done
    }

    /// Exécute un playbook existant.
    pub fn run_playbook<F>(&self, req: PlaybookRequest, on_line: F) -> Result<AnsibleRun>
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        let parc = self.resolve_inventory(&req.inventory_path)?;
        let display_hosts = req.limit_hosts.clone().unwrap_or_default();
        self.runs.start(
            &req.id,
            &req.label,
            deploy::RunKind::Playbook,
            &[],
            &display_hosts,
        );

        let env = self.ansible_env()?;
        let extra = (!req.extra_vars.is_empty()).then(|| req.extra_vars.clone());
        let sink = Arc::new(deploy::line_sink(&self.runs, &req.id, on_line));

        // Seuls les hôtes NOMMÉS par `--limit` sont inscrits : sans limite, le
        // playbook vise ses propres entrées, qui déclarent déjà leur famille —
        // et certains plays agissent sur l'entrée canonique de la machine
        // (`deploy-rotki.yml` → `ctdapi`), qui ne doit pas la recevoir.
        let family = families::family_of_playbook(&self.playbooks_path()?, &req.playbook_path);
        let inscribed = match (&family, &req.limit_hosts) {
            (Some(f), Some(hosts)) => self.inscribe_families(&parc, std::slice::from_ref(f), hosts, &*sink),
            _ => vec![],
        };

        let run = ansible_runner::run_existing_playbook_streaming(
            &req.playbook_path,
            &parc,
            req.limit_hosts.clone(),
            extra,
            &env,
            { let s = sink.clone(); move |l: String| s(l) },
        )?;
        if run.status != "success" {
            families::revert(&inscribed).into_iter().for_each(|n| sink(format!("[fleetforge] {n}")));
        }

        self.runs
            .finish(&req.id, deploy::RunStatus::from_str(&run.status));

        let saved = self.with_db(|db| {
            let saved = db.add_ansible_run(run)?;
            let hosts = req.limit_hosts.clone().unwrap_or_else(|| saved.hosts.clone());
            deploy::record_playbook(db, &saved, &req.playbook_path, &hosts);
            Ok(saved)
        })?;
        Ok(saved)
    }
}
