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

pub mod actions;
pub mod alert_rules;
pub mod ansible_describe;
pub mod ansible_git;
pub mod ansible_group_vars;
pub mod ansible_inventory;
pub mod ansible_output;
pub mod ansible_playbooks;
pub mod ansible_roles;
pub mod ansible_runner;
pub mod ansible_tree;
pub mod automation;
pub mod database;
pub mod deploy;
pub mod diagnostics;
pub mod families;
pub mod fault;
pub mod inventory_dynamic;
pub mod inventory_writer;
pub mod logging;
pub mod metrics;
pub mod model;
pub mod models;
pub mod parc;
pub mod paths;
pub mod proc;
pub mod redact;
pub mod ro_gate;
pub mod service_tracker;
pub mod services_catalog;
pub mod settings;
pub mod style;

use anyhow::{anyhow, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

pub use ansible_group_vars::GroupVarEntry;
pub use database::Database;
pub use deploy::{DeployRequest, PlaybookRequest, RunGuard, RunHandle, RunOptions, RunRegistry, RunSelection};
pub use fault::{Fault, FaultKind};
pub use metrics::{Probe, ProbeScope, PrometheusClient, PrometheusConfig};
pub use model::{Fleet, Health, MachineKey, ProviderKind, Server};
pub use models::*;
pub use services_catalog::CatalogService;
pub use settings::{SettingKey, Settings};

/// Premier candidat qui existe réellement au catalogue.
///
/// `candidate_roles` propose du plus sûr au plus spéculatif ; c'est le
/// catalogue qui tranche, parce que toutes les familles n'ont pas leur `-purge`.
pub fn resolve_role(roles: &[AnsibleRole], service_name: &str, action: &str) -> Option<AnsibleRole> {
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
    /// Un run à la fois par parc (`deploy::RunLock`).
    locks: deploy::RunLocks,
    /// Arbre Ansible servi depuis git (`ff_ansible_source: git`). Absent :
    /// l'arbre livré par rsync, dont les chemins sont des réglages.
    git: OnceLock<Arc<ansible_git::GitTree>>,
    /// Fichiers de l'arbre livrés avec une donnée de parc, à ne jamais lire
    /// par `read_tree` (`ff_ansible_extra_files`).
    private_files: OnceLock<Vec<String>>,
}

/// L'arbre Ansible sur lequel opère un appel : celui d'un commit (arbre git)
/// ou l'arbre livré. Garde le commit retenu (hors du nettoyage du cache) tant
/// qu'elle vit.
pub struct TreeView {
    /// Commit complet ; `None` pour l'arbre livré par rsync.
    pub commit: Option<String>,
    pub root: PathBuf,
    pub playbooks: PathBuf,
    _pin: Option<ansible_git::PinGuard>,
}

impl TreeView {
    fn playbooks_str(&self) -> String {
        self.playbooks.to_string_lossy().to_string()
    }
}

/// `tree_status`.
#[derive(Debug, Clone, Serialize)]
pub struct TreeStatus {
    /// `git` ou `rsync`.
    pub source: &'static str,
    pub branch: Option<String>,
    pub head: Option<String>,
    pub synced_at: Option<String>,
    pub commits_cached: usize,
}

/// Réponse de `describe_playbook`.
#[derive(Debug, Clone, Serialize)]
pub struct DescribeAnswer {
    pub commit: Option<String>,
    #[serde(flatten)]
    pub description: ansible_describe::Description,
}

/// Réponse de `read_tree`.
#[derive(Debug, Clone, Serialize)]
pub struct ReadAnswer {
    pub commit: Option<String>,
    #[serde(flatten)]
    pub read: ansible_tree::TreeRead,
}

/// Réponse de `search_tree`.
#[derive(Debug, Clone, Serialize)]
pub struct SearchAnswer {
    pub commit: Option<String>,
    pub hits: Vec<ansible_tree::Hit>,
    pub truncated: bool,
}

/// Réponse de `syntax_check`.
#[derive(Debug, Clone, Serialize)]
pub struct SyntaxAnswer {
    pub commit: Option<String>,
    pub playbook: String,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// Sortie d'Ansible, bornée, NON caviardée (la façade le fait).
    pub output: String,
    pub failures: Vec<ansible_output::TaskFailure>,
}

/// Sortie d'un contrôle de syntaxe rendue au plus, en caractères.
pub const SYNTAX_OUTPUT_CHARS: usize = 8000;

/// Que faire quand un run occupe déjà le parc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPolicy {
    /// Attendre, en le disant dans la sortie du run — les interfaces humaines.
    Wait,
    /// Refuser tout de suite (`FaultKind::RunBusy`) — l'API d'automatisation,
    /// dont l'appelant décide lui-même de réessayer.
    Try,
}

/// Run de playbook validé et inscrit au registre, prêt à s'exécuter.
///
/// Séparé de l'exécution pour que l'API puisse répondre « lancé » (ou
/// « occupé ») avant de confier le run à un fil d'exécution : le run est déjà
/// visible dans le registre quand la réponse part.
pub struct PreparedRun {
    req: PlaybookRequest,
    parc: parc::Parc,
    options: RunOptions,
    selection: RunSelection,
    /// Arbre du commit exécuté (ou arbre livré).
    view: TreeView,
    guard: Option<RunGuard>,
}

impl PreparedRun {
    pub fn id(&self) -> &str {
        &self.req.id
    }
}

impl Core {
    pub fn new() -> Result<Self> {
        let db = Database::new()?;
        Ok(Self {
            db: Mutex::new(db),
            runs: RunRegistry::new(),
            locks: deploy::RunLocks::default(),
            git: OnceLock::new(),
            private_files: OnceLock::new(),
        })
    }

    /// Passe l'arbre Ansible en mode git. Une fois, au démarrage.
    pub fn attach_git_tree(&self, tree: Arc<ansible_git::GitTree>) {
        let _ = self.git.set(tree);
    }

    pub fn git_tree(&self) -> Option<&Arc<ansible_git::GitTree>> {
        self.git.get()
    }

    /// Nettoyage périodique de l'arbre git (références `infra/*` orphelines,
    /// arbres au-delà du cache). `None` : arbre rsync, rien à nettoyer.
    pub fn prune_git(&self) -> Option<Result<ansible_git::PruneReport>> {
        self.git.get().map(|git| git.prune_orphans())
    }

    /// Fichiers de l'arbre que `read_tree` / `search_tree` / `describe_playbook`
    /// ne lisent jamais (chemins relatifs à `Ansible/`).
    pub fn set_private_tree_files(&self, files: Vec<String>) {
        let _ = self.private_files.set(files);
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
        let mut settings = self.with_db(Settings::load)?;
        if self.git.get().is_some() {
            settings.inventories_path = self.get_setting(SettingKey::InventoriesPath)?;
            settings.playbooks_path = self.get_setting(SettingKey::PlaybooksPath)?;
        }
        Ok(settings)
    }

    /// Un réglage. En mode git, les deux chemins de l'arbre ne sont pas des
    /// réglages : les inventaires sont les données du parc, les playbooks
    /// l'arbre de la tête synchronisée (vides si le clone est indisponible —
    /// l'application montre alors un parc vide et le dit au journal).
    pub fn get_setting(&self, key: SettingKey) -> Result<String> {
        if let Some(git) = self.git.get() {
            match key {
                SettingKey::InventoriesPath => return Ok(git.inventories_dir().to_string_lossy().to_string()),
                SettingKey::PlaybooksPath => {
                    return Ok(match self.tree_view(None, None) {
                        Ok(view) => view.playbooks_str(),
                        Err(e) => {
                            logging::warn("core", format!("arbre git indisponible : {e}"));
                            String::new()
                        }
                    })
                }
                _ => {}
            }
        }
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

    /// Services suivis sur les hôtes du parc, et d'eux seuls.
    ///
    /// Le journal est indexé par NOM d'hôte, sans parc : `proxy1` ou `mail`
    /// existent dans plusieurs parcs, et `current_services(None)` mélangeait
    /// leurs services. Le parc courant fait foi sur ce qui lui appartient.
    pub fn fleet_services(&self, inventory_path: &str) -> Result<Vec<ServerServiceState>> {
        let fleet = self.fleet(inventory_path)?;
        let all = self.current_services(None)?;
        Ok(all
            .into_iter()
            .filter(|s| fleet.host(&s.server_name).is_some())
            .collect())
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

        if self.runs.is_running(&req.id) {
            return fault::fail(FaultKind::RunIdInUse, format!("un run en cours porte déjà l'identifiant {}", req.id));
        }
        automation::validate_extra_vars(&req.extra_vars, false)?;

        self.runs.start(
            &req.id,
            &req.label,
            deploy::RunKind::Role,
            &req.roles,
            &req.hosts,
        );
        let sink = Arc::new(deploy::line_sink(&self.runs, &req.id, on_line));
        let _guard = self.wait_for_lock(&parc.name, &*sink);
        let result = self.deploy_locked(&req, &parc, &playbooks_path, sink);
        self.settle_run(&req.id, &result);
        result
    }

    /// Corps de [`Core::run_deploy`], verrou du parc tenu.
    fn deploy_locked<S>(
        &self,
        req: &DeployRequest,
        parc: &parc::Parc,
        playbooks_path: &str,
        sink: Arc<S>,
    ) -> Result<AnsibleRun>
    where
        S: Fn(String) + Send + Sync + 'static,
    {
        let env = self.ansible_env()?;
        let extra = (!req.extra_vars.is_empty()).then(|| req.extra_vars.clone());

        let mut families: Vec<String> = req
            .roles
            .iter()
            .filter_map(|r| families::family_of_role(playbooks_path, r))
            .collect();
        families.dedup();
        let inscribed = self.inscribe_families(parc, &families, &req.hosts, &*sink);

        let run = ansible_runner::run_playbook_streaming(
            playbooks_path,
            parc,
            &req.roles,
            &req.hosts,
            extra,
            &env,
            { let s = sink.clone(); move |l: String| s(l) },
        )?;
        if run.status != "success" {
            families::revert(&inscribed).into_iter().for_each(|n| sink(format!("[fleetforge] {n}")));
        }

        let saved = self.with_db(|db| {
            let saved = db.add_ansible_run(run)?;
            deploy::record_deploy(db, &saved, &req.roles, &req.hosts);
            Ok(saved)
        })?;
        Ok(saved)
    }

    /// Prend le verrou du parc ; s'il est tenu, le dit dans la sortie du run
    /// avant d'attendre — sans quoi un run en attente ressemblerait à un run
    /// figé.
    fn wait_for_lock(&self, parc: &str, say: &dyn Fn(String)) -> RunGuard {
        let lock = self.locks.of(parc);
        lock.try_acquire().unwrap_or_else(|| {
            say(format!(
                "[fleetforge] un autre run est en cours sur le parc {parc} : attente de sa fin…"
            ));
            lock.acquire()
        })
    }

    /// Clôt l'entrée du registre, quelle que soit l'issue : une erreur levée
    /// après `runs.start` laissait sinon un run « en cours » à jamais.
    fn settle_run(&self, id: &str, result: &Result<AnsibleRun>) {
        match result {
            Ok(run) => self.runs.finish_with(
                id,
                deploy::RunStatus::from_str(&run.status),
                run.exit_code,
            ),
            Err(_) => self.runs.finish(id, deploy::RunStatus::Failed),
        }
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

    /// Exécute un playbook existant (interfaces humaines : attend le verrou).
    pub fn run_playbook<F>(&self, req: PlaybookRequest, on_line: F) -> Result<AnsibleRun>
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        let prepared = self.prepare_playbook(req, RunOptions::default(), LockPolicy::Wait)?;
        self.execute_playbook(prepared, on_line)
    }

    /// Valide un run de playbook et l'inscrit au registre.
    ///
    /// Refusé AVANT l'inscription : identifiant mal formé ou déjà en cours,
    /// playbook hors du dossier des playbooks, `--limit` hors inventaire,
    /// variable mal nommée, parc occupé (`LockPolicy::Try`).
    pub fn prepare_playbook(
        &self,
        req: PlaybookRequest,
        options: RunOptions,
        lock: LockPolicy,
    ) -> Result<PreparedRun> {
        self.prepare_playbook_with(req, options, RunSelection::default(), lock)
    }

    /// [`Self::prepare_playbook`] avec une sélection : étiquettes et commit.
    ///
    /// En mode git, le playbook est cherché dans l'arbre du commit
    /// (`selection.commit`, sinon la tête synchronisée), que le run retient
    /// jusqu'à sa fin ; le commit exécuté est consigné au registre.
    pub fn prepare_playbook_with(
        &self,
        mut req: PlaybookRequest,
        options: RunOptions,
        mut selection: RunSelection,
        lock: LockPolicy,
    ) -> Result<PreparedRun> {
        automation::validate_run_id(&req.id)?;
        if self.runs.is_running(&req.id) {
            return fault::fail(FaultKind::RunIdInUse, format!("un run en cours porte déjà l'identifiant {}", req.id));
        }
        automation::validate_extra_vars(&req.extra_vars, false)?;
        selection.tags = automation::validate_tags(&selection.tags, "tags")?;
        selection.skip_tags = automation::validate_tags(&selection.skip_tags, "skip_tags")?;
        if selection.no_limit && req.limit_hosts.as_ref().is_some_and(|l| !l.is_empty()) {
            return fault::fail(FaultKind::InvalidArgument, "no_limit et limit s'excluent");
        }
        let parc = self.resolve_inventory(&req.inventory_path)?;
        let view = self.tree_view(Some(&parc.name), selection.commit.as_deref())?;
        selection.commit = view.commit.clone();
        let resolved = automation::resolve_playbook(&view.playbooks_str(), &req.playbook_path)?;
        req.playbook_path = resolved.to_string_lossy().to_string();
        if let Some(limit) = req.limit_hosts.as_ref().filter(|l| !l.is_empty()) {
            automation::validate_limit(&self.fleet(&parc.name)?, limit)?;
        }

        let guard = match lock {
            LockPolicy::Wait => None,
            LockPolicy::Try => Some(self.locks.of(&parc.name).try_acquire().ok_or_else(|| {
                Fault::new(
                    FaultKind::RunBusy,
                    format!("un run est déjà en cours sur le parc {}", parc.name),
                )
            })?),
        };

        let label = if options.check { format!("[check] {}", req.label) } else { req.label.clone() };
        let display_hosts = req.limit_hosts.clone().unwrap_or_default();
        self.runs.start_with(
            &req.id,
            &label,
            deploy::RunKind::Playbook,
            &[],
            &display_hosts,
            options,
        );
        self.runs.annotate(&req.id, &selection);
        Ok(PreparedRun { req, parc, options, selection, view, guard })
    }

    /// Exécute un run préparé. Bloque le temps du playbook.
    pub fn execute_playbook<F>(&self, prepared: PreparedRun, on_line: F) -> Result<AnsibleRun>
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        let PreparedRun { req, parc, options, selection, view, guard } = prepared;
        let sink = Arc::new(deploy::line_sink(&self.runs, &req.id, on_line));
        let _guard = guard.unwrap_or_else(|| self.wait_for_lock(&parc.name, &*sink));
        if let Some(commit) = &view.commit {
            // 16 caractères : le sha entier serait caviardé comme un secret
            // hexadécimal dans la sortie rendue au compte d'automatisation.
            sink(format!("[fleetforge] arbre git : commit {}", &commit[..16.min(commit.len())]));
        }
        let result = self.playbook_locked(&req, &parc, options, &selection, &view, sink);
        self.settle_run(&req.id, &result);
        result
    }

    /// Corps d'un run de playbook, verrou du parc tenu.
    fn playbook_locked<S>(
        &self,
        req: &PlaybookRequest,
        parc: &parc::Parc,
        options: RunOptions,
        selection: &RunSelection,
        view: &TreeView,
        sink: Arc<S>,
    ) -> Result<AnsibleRun>
    where
        S: Fn(String) + Send + Sync + 'static,
    {
        // L'arbre de CE run : celui du commit demandé, pas forcément la tête.
        let env = ansible_runner::AnsibleEnv::at_root(Some(view.root.clone()));
        let extra = (!req.extra_vars.is_empty()).then(|| req.extra_vars.clone());

        // Seuls les hôtes NOMMÉS par `--limit` sont inscrits : sans limite, le
        // playbook vise ses propres entrées, qui déclarent déjà leur famille —
        // et certains plays agissent sur l'entrée canonique de la machine
        // (`deploy-rotki.yml` → `ctdapi`), qui ne doit pas la recevoir.
        // En `--check`, rien n'est installé : l'inventaire ne doit pas le
        // prétendre.
        let family = (!options.check)
            .then(|| families::family_of_playbook(&view.playbooks_str(), &req.playbook_path))
            .flatten();
        let inscribed = match (&family, &req.limit_hosts) {
            (Some(f), Some(hosts)) => self.inscribe_families(parc, std::slice::from_ref(f), hosts, &*sink),
            _ => vec![],
        };
        if options.check {
            sink("[fleetforge] mode vérification (--check) : aucune modification des hôtes ni de l'inventaire".to_string());
        }

        let mut run = ansible_runner::run_existing_playbook_streaming(
            &req.playbook_path,
            parc,
            req.limit_hosts.clone(),
            extra,
            options,
            selection,
            &env,
            { let s = sink.clone(); move |l: String| s(l) },
        )?;
        if run.status != "success" {
            families::revert(&inscribed).into_iter().for_each(|n| sink(format!("[fleetforge] {n}")));
        }
        if options.check {
            run.roles = run.roles.iter().map(|r| format!("{r} --check")).collect();
        }

        let saved = self.with_db(|db| {
            let saved = db.add_ansible_run(run)?;
            // Un `--check` n'a rien installé : rien à consigner au suivi.
            if !options.check {
                let hosts = req.limit_hosts.clone().unwrap_or_else(|| saved.hosts.clone());
                deploy::record_playbook(db, &saved, &req.playbook_path, &hosts);
            }
            Ok(saved)
        })?;
        Ok(saved)
    }

    // === API d'automatisation ===

    /// Un parc désigné par son NOM (jamais un chemin de fichier).
    pub fn parc_by_name(&self, name: &str) -> Result<parc::Parc> {
        automation::validate_parc_name(name)?;
        self.list_parcs()?
            .into_iter()
            .find(|p| p.name == name)
            .ok_or_else(|| Fault::new(FaultKind::UnknownParc, format!("parc inconnu : {name}")).into())
    }

    /// Requête instantanée sur LA supervision du parc nommé — réglages
    /// Prometheus de son organisation (URL, identifiants), jamais ceux du
    /// parc sélectionné dans l'interface ni ceux de l'appelant.
    pub async fn query_prometheus_in(
        &self,
        parc: &str,
        query: &str,
        time: Option<&str>,
    ) -> Result<automation::PrometheusAnswer> {
        let parc = self.parc_by_name(parc)?;
        automation::validate_promql(query)?;
        if let Some(t) = time {
            automation::validate_prom_time(t)?;
        }
        let series = self
            .prometheus_for(&parc.organization)?
            .query_at(query, time)
            .await?;
        let (result, truncated) = automation::cap_series(series, automation::MAX_SERIES);
        Ok(automation::PrometheusAnswer { parc: parc.name, result, truncated })
    }

    pub fn list_hosts(&self, parc: &str) -> Result<Vec<automation::HostSummary>> {
        let parc = self.parc_by_name(parc)?;
        Ok(automation::host_summaries(&self.fleet(&parc.name)?))
    }

    pub fn list_playbook_summaries(&self) -> Result<Vec<automation::PlaybookSummary>> {
        Ok(automation::playbook_summaries(&self.list_playbooks()?))
    }

    /// Alertes actives de l'Alertmanager du parc (JSON de l'API v2, tel quel).
    pub async fn alertmanager_alerts(&self, parc: &str) -> Result<serde_json::Value> {
        let parc = self.parc_by_name(parc)?;
        let fleet = self.fleet(&parc.name)?;
        let url = automation::alertmanager_url(&self.playbooks_path()?, &fleet)?;
        automation::fetch_alerts(&url).await
    }

    // === Arbre Ansible : lecture, description, contrôle de syntaxe, synchronisation ===

    /// L'arbre d'un appel. Arbre git : `commit` (`HEAD`, sha complet, ou rien
    /// pour la tête synchronisée) est résolu, vérifié atteignable d'une
    /// référence permise de `parc`, construit au besoin et retenu. Arbre
    /// rsync : aucun commit n'existe, en demander un est une erreur.
    pub fn tree_view(&self, parc: Option<&str>, commit: Option<&str>) -> Result<TreeView> {
        let Some(git) = self.git.get() else {
            if commit.is_some() {
                return fault::fail(
                    FaultKind::NotConfigured,
                    "cet arbre Ansible n'est pas servi depuis git (ff_ansible_source: rsync) : pas de commit",
                );
            }
            let playbooks = self.get_setting(SettingKey::PlaybooksPath)?;
            if playbooks.is_empty() {
                return fault::fail(FaultKind::NotConfigured, "dossier des playbooks non configuré");
            }
            let playbooks = PathBuf::from(playbooks);
            let root = playbooks.parent().map(PathBuf::from).unwrap_or_else(|| playbooks.clone());
            return Ok(TreeView { commit: None, root, playbooks, _pin: None });
        };
        let spec = commit.map(ansible_git::parse_commit).transpose()?;
        // La tête n'a pas besoin du parc ; un sha se résout pour LE parc de
        // l'appel (branches `infra/<parc>/*`), donc exige un nom de parc valide.
        let parc = match (&spec, parc) {
            (Some(ansible_git::CommitSpec::Sha(_)), None) => {
                return fault::fail(FaultKind::InvalidArgument, "un commit se résout pour un parc : `parc` manquant")
            }
            (Some(ansible_git::CommitSpec::Sha(_)), Some(parc)) => {
                automation::validate_parc_name(parc)?;
                parc
            }
            _ => "",
        };
        let sha = git.resolve_commit(parc, spec.as_ref())?;
        let pin = git.pin(&sha);
        let tree = git.exec_tree(&sha)?;
        Ok(TreeView { commit: Some(sha), root: tree.root, playbooks: tree.playbooks, _pin: Some(pin) })
    }

    /// Commit que lancera un appel qui n'en précise pas, ou qu'il a précisé :
    /// sha complet en mode git, `None` en mode rsync (où en demander un est une
    /// erreur). Sert à l'empreinte de la porte du check, AVANT toute
    /// construction d'arbre.
    pub fn resolve_commit(&self, parc: &str, commit: Option<&str>) -> Result<Option<String>> {
        let Some(git) = self.git.get() else {
            if commit.is_some() {
                return fault::fail(
                    FaultKind::NotConfigured,
                    "cet arbre Ansible n'est pas servi depuis git (ff_ansible_source: rsync) : pas de commit",
                );
            }
            return Ok(None);
        };
        automation::validate_parc_name(parc)?;
        let spec = commit.map(ansible_git::parse_commit).transpose()?;
        git.resolve_commit(parc, spec.as_ref()).map(Some)
    }

    fn tree_reader(&self, view: &TreeView) -> Result<ansible_tree::TreeReader> {
        let private = self.private_files.get().cloned().unwrap_or_default();
        ansible_tree::TreeReader::new(&view.root, &private)
    }

    pub fn tree_status(&self, parc: &str) -> Result<TreeStatus> {
        self.parc_by_name(parc)?;
        match self.git.get() {
            None => Ok(TreeStatus { source: "rsync", branch: None, head: None, synced_at: None, commits_cached: 0 }),
            Some(git) => {
                let status = git.status()?;
                Ok(TreeStatus {
                    source: "git",
                    branch: Some(status.branch),
                    head: Some(status.head),
                    synced_at: status.synced_at,
                    commits_cached: status.commits_cached,
                })
            }
        }
    }

    pub fn read_tree(&self, parc: &str, path: &str, commit: Option<&str>) -> Result<ReadAnswer> {
        let parc = self.parc_by_name(parc)?;
        let view = self.tree_view(Some(&parc.name), commit)?;
        let read = self.tree_reader(&view)?.read(path)?;
        Ok(ReadAnswer { commit: view.commit.clone(), read })
    }

    pub fn search_tree(&self, parc: &str, pattern: &str, commit: Option<&str>) -> Result<SearchAnswer> {
        let parc = self.parc_by_name(parc)?;
        let view = self.tree_view(Some(&parc.name), commit)?;
        let (hits, truncated) = self.tree_reader(&view)?.search(pattern)?;
        Ok(SearchAnswer { commit: view.commit.clone(), hits, truncated })
    }

    pub fn describe_playbook(&self, parc: &str, playbook: &str, commit: Option<&str>) -> Result<DescribeAnswer> {
        let parc = self.parc_by_name(parc)?;
        let view = self.tree_view(Some(&parc.name), commit)?;
        let resolved = automation::resolve_playbook(&view.playbooks_str(), playbook)?;
        let description = ansible_describe::describe(&self.tree_reader(&view)?, &automation::playbook_name(&resolved))?;
        Ok(DescribeAnswer { commit: view.commit.clone(), description })
    }

    /// Le playbook et ceux qu'il importe (`import_playbook`, transitivement),
    /// par nom de fichier : de quoi appliquer `deny_playbooks` à ce qu'un
    /// playbook inoffensif ferait jouer par ricochet.
    pub fn playbook_chain(&self, parc: &str, playbook: &str, commit: Option<&str>) -> Result<Vec<String>> {
        let parc = self.parc_by_name(parc)?;
        let view = self.tree_view(Some(&parc.name), commit)?;
        let resolved = automation::resolve_playbook(&view.playbooks_str(), playbook)?;
        let name = automation::playbook_name(&resolved);
        let mut chain = vec![name.clone()];
        chain.extend(ansible_describe::imported_playbooks(&self.tree_reader(&view)?, &name));
        Ok(chain)
    }

    /// Hôtes que viserait ce `--limit` (validé d'abord) : de quoi appliquer
    /// `max_hosts`.
    pub fn count_limit_hosts(&self, parc: &str, limit: &[String]) -> Result<usize> {
        let parc = self.parc_by_name(parc)?;
        let fleet = self.fleet(&parc.name)?;
        automation::validate_limit(&fleet, limit)?;
        Ok(automation::count_limit_hosts(&fleet, limit))
    }

    /// `ansible-playbook --syntax-check` depuis l'arbre d'un commit.
    pub fn syntax_check(&self, parc: &str, playbook: &str, commit: Option<&str>) -> Result<SyntaxAnswer> {
        let parc = self.parc_by_name(parc)?;
        let view = self.tree_view(Some(&parc.name), commit)?;
        let resolved = automation::resolve_playbook(&view.playbooks_str(), playbook)?;
        let env = ansible_runner::AnsibleEnv::at_root(Some(view.root.clone()));
        let verdict = ansible_runner::syntax_check(&resolved.to_string_lossy(), &parc, &env)?;
        let report = ansible_output::parse(verdict.output.lines());
        let output: String = verdict.output.chars().take(SYNTAX_OUTPUT_CHARS).collect();
        Ok(SyntaxAnswer {
            commit: view.commit.clone(),
            playbook: automation::playbook_name(&resolved),
            ok: verdict.ok,
            exit_code: verdict.exit_code,
            timed_out: verdict.timed_out,
            output,
            failures: report.failures,
        })
    }

    /// `sync_tree` : `git fetch` d'une référence permise, avance rapide de la
    /// branche suivie, commit rendu. Arbre rsync : rien à synchroniser.
    pub fn sync_tree(&self, parc: &str, commit: Option<&str>, reference: Option<&str>) -> Result<ansible_git::SyncOutcome> {
        let parc = self.parc_by_name(parc)?;
        let Some(git) = self.git.get() else {
            return fault::fail(
                FaultKind::NotConfigured,
                "cet arbre Ansible n'est pas servi depuis git (ff_ansible_source: rsync) : rien à synchroniser",
            );
        };
        let spec = commit.map(ansible_git::parse_commit).transpose()?;
        git.sync(&parc.name, spec.as_ref(), reference)
    }

    /// Entrée d'inventaire visée par un diagnostic.
    ///
    /// Sans `parc`, l'entrée est cherchée dans tous les parcs ; un nom présent
    /// dans plusieurs (`proxy1`, `mail`) est refusé plutôt que deviné.
    pub fn find_host(&self, parc: Option<&str>, host: &str) -> Result<(String, AnsibleHost)> {
        let parcs = match parc {
            Some(name) => vec![self.parc_by_name(name)?],
            None => self.list_parcs()?,
        };
        self.find_host_among(parcs, host)
    }

    /// [`Self::find_host`] sans `parc`, borné aux parcs nommés : ceux que
    /// couvre un compte d'automatisation. Un nom absent de la machine n'y
    /// ajoute rien.
    pub fn find_host_in(&self, names: &[String], host: &str) -> Result<(String, AnsibleHost)> {
        let parcs = self.list_parcs()?.into_iter().filter(|p| names.contains(&p.name)).collect();
        self.find_host_among(parcs, host)
    }

    fn find_host_among(&self, parcs: Vec<parc::Parc>, host: &str) -> Result<(String, AnsibleHost)> {
        let mut found: Vec<(String, AnsibleHost)> = Vec::new();
        for p in parcs {
            if let Ok(fleet) = self.fleet(&p.name) {
                if let Some(h) = fleet.host(host) {
                    found.push((p.name.clone(), h.clone()));
                }
            }
        }
        match found.len() {
            0 => fault::fail(FaultKind::UnknownHost, format!("hôte inconnu : {host}")),
            1 => Ok(found.remove(0)),
            _ => fault::fail(
                FaultKind::AmbiguousHost,
                format!(
                    "{host} existe dans plusieurs parcs ({}) : préciser `parc`",
                    found.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>().join(", ")
                ),
            ),
        }
    }
}
