/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Orchestration d'un déploiement et registre des runs en cours.
//!
//! Le registre vivait en mémoire React : le backend n'avait aucune notion de
//! « run en cours », il n'existait pas de `get_active_runs`, et un déploiement
//! lancé depuis une interface était invisible depuis l'autre. Il vit ici.

use crate::database::Database;
use crate::models::{AnsibleRun, ServerService};
use crate::service_tracker;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};

/// Rôle qui exige un nom de modèle en variable supplémentaire.
///
/// Politique portée par `AnsibleDeployModal.tsx` : le TUI l'aurait sinon
/// réinventée, ou pire, oubliée — le rôle échoue alors au milieu du playbook.
pub const OLLAMA_MODEL_ROLE: &str = "ollama-model-install";
pub const OLLAMA_MODEL_VAR: &str = "ollama_model_name";

/// Déploiement d'un ensemble de rôles sur un ensemble d'hôtes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub id: String,
    pub label: String,
    pub inventory_path: String,
    pub roles: Vec<String>,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub extra_vars: HashMap<String, String>,
}

impl DeployRequest {
    /// Vérifie ce qui rendrait le run inutile avant de le lancer.
    pub fn validate(&self) -> Result<()> {
        if self.roles.is_empty() {
            anyhow::bail!("aucun rôle sélectionné");
        }
        if self.hosts.is_empty() {
            anyhow::bail!("aucun hôte sélectionné");
        }
        if self.roles.iter().any(|r| r == OLLAMA_MODEL_ROLE)
            && !self.extra_vars.contains_key(OLLAMA_MODEL_VAR)
        {
            anyhow::bail!("{OLLAMA_MODEL_ROLE} exige la variable {OLLAMA_MODEL_VAR}");
        }
        Ok(())
    }
}

/// Exécution d'un playbook existant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRequest {
    pub id: String,
    pub label: String,
    pub playbook_path: String,
    pub inventory_path: String,
    /// `None` = pas de `--limit`, donc tous les hôtes que cible le playbook.
    pub limit_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub extra_vars: HashMap<String, String>,
}

/// Mode d'exécution d'un playbook. Hors de [`PlaybookRequest`] : les façades
/// de bureau et le TUI construisent la requête champ par champ et n'ont pas à
/// connaître ces options, qui ne servent qu'à l'API d'automatisation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunOptions {
    /// `--check` : rien n'est modifié sur les hôtes. Le run n'inscrit alors
    /// aucune famille dans l'inventaire et ne consigne aucun service.
    pub check: bool,
    /// `--diff` : montre les différences de fichiers.
    pub diff: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Running,
    Success,
    Failed,
}

impl RunStatus {
    pub fn from_str(s: &str) -> RunStatus {
        match s {
            "success" => RunStatus::Success,
            "failed" => RunStatus::Failed,
            _ => RunStatus::Running,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunKind {
    Role,
    Playbook,
}

/// Un run vivant, tel que les deux interfaces l'affichent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHandle {
    pub id: String,
    pub label: String,
    pub kind: RunKind,
    pub roles: Vec<String>,
    pub hosts: Vec<String>,
    pub status: RunStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// Sortie accumulée. Le frontal la reconstituait ligne à ligne depuis un
    /// événement ; elle est désormais lisible à tout moment, ce qui permet à
    /// une interface de rejoindre un run déjà commencé.
    pub output: Vec<String>,
    /// Code de sortie d'`ansible-playbook`, une fois le run terminé. `None`
    /// tant qu'il tourne, ou quand Ansible n'a pas pu être lancé.
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub options: RunOptions,
}

impl RunHandle {
    pub fn is_running(&self) -> bool {
        self.status == RunStatus::Running
    }
}

/// Registre des runs de ce processus.
#[derive(Clone, Default)]
pub struct RunRegistry {
    runs: Arc<RwLock<Vec<RunHandle>>>,
}

impl RunRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&self, id: &str, label: &str, kind: RunKind, roles: &[String], hosts: &[String]) {
        self.start_with(id, label, kind, roles, hosts, RunOptions::default());
    }

    pub fn start_with(
        &self,
        id: &str,
        label: &str,
        kind: RunKind,
        roles: &[String],
        hosts: &[String],
        options: RunOptions,
    ) {
        let handle = RunHandle {
            id: id.to_string(),
            label: label.to_string(),
            kind,
            roles: roles.to_vec(),
            hosts: hosts.to_vec(),
            status: RunStatus::Running,
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: None,
            output: Vec::new(),
            exit_code: None,
            options,
        };
        let mut runs = self.runs.write().unwrap();
        runs.retain(|r| r.id != id);
        runs.push(handle);
    }

    /// Vrai si un run EN COURS porte cet identifiant. Le relancer sous le même
    /// nom remplacerait son entrée : le run continuerait, invisible.
    pub fn is_running(&self, id: &str) -> bool {
        self.runs
            .read()
            .unwrap()
            .iter()
            .any(|r| r.id == id && r.is_running())
    }

    pub fn push_line(&self, id: &str, line: String) {
        if let Some(run) = self
            .runs
            .write()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == id)
        {
            run.output.push(line);
        }
    }

    pub fn finish(&self, id: &str, status: RunStatus) {
        self.finish_with(id, status, None);
    }

    pub fn finish_with(&self, id: &str, status: RunStatus, exit_code: Option<i32>) {
        if let Some(run) = self
            .runs
            .write()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == id)
        {
            run.status = status;
            run.finished_at = Some(chrono::Utc::now().to_rfc3339());
            run.exit_code = exit_code;
        }
    }

    pub fn get(&self, id: &str) -> Option<RunHandle> {
        self.runs.read().unwrap().iter().find(|r| r.id == id).cloned()
    }

    pub fn all(&self) -> Vec<RunHandle> {
        self.runs.read().unwrap().clone()
    }

    pub fn active(&self) -> Vec<RunHandle> {
        self.runs
            .read()
            .unwrap()
            .iter()
            .filter(|r| r.is_running())
            .cloned()
            .collect()
    }

    /// Oublie les runs terminés. Les runs en cours ne sont jamais retirés.
    pub fn clear_finished(&self) {
        self.runs.write().unwrap().retain(|r| r.is_running());
    }
}

/// Consigne ce qu'un run réussi a changé sur le parc.
///
/// Le journal est en ajout seul : c'est la projection (`get_server_current_services`)
/// qui en déduit l'état courant. Un run échoué n'écrit rien — il n'a rien changé
/// de sûr, et l'inscrire ferait passer pour installé un service qui ne l'est pas.
pub fn record_deploy(db: &Database, run: &AnsibleRun, roles: &[String], hosts: &[String]) {
    if run.status != "success" {
        return;
    }
    for role in roles {
        let parsed = service_tracker::parse_role(role);
        for host in hosts {
            let (server_id, server_name) = service_tracker::resolve_host_to_server(db, host);
            let _ = db.add_server_service(ServerService {
                id: None,
                server_id,
                server_name,
                service_name: parsed.service_name.clone(),
                action: parsed.action.clone(),
                source: "ansible".to_string(),
                role_name: Some(role.clone()),
                ansible_run_id: run.id,
                status: "success".to_string(),
                executed_at: chrono::Utc::now().to_rfc3339(),
                notes: None,
            });
        }
    }
}

/// Idem pour un playbook : le nom du fichier fait office de nom de service.
pub fn record_playbook(db: &Database, run: &AnsibleRun, playbook_path: &str, hosts: &[String]) {
    if run.status != "success" {
        return;
    }
    let stem = std::path::Path::new(playbook_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(playbook_path)
        .to_string();

    for host in hosts {
        let (server_id, server_name) = service_tracker::resolve_host_to_server(db, host);
        let _ = db.add_server_service(ServerService {
            id: None,
            server_id,
            server_name,
            service_name: stem.clone(),
            action: "install".to_string(),
            source: "ansible".to_string(),
            role_name: Some(stem.clone()),
            ansible_run_id: run.id,
            status: "success".to_string(),
            executed_at: chrono::Utc::now().to_rfc3339(),
            notes: None,
        });
    }
}

/// Diffuseur de lignes : alimente le registre ET la façade (fenêtre Tauri ou
/// canal TUI). Le registre est ainsi toujours à jour, quelle que soit
/// l'interface qui a lancé le run.
pub fn line_sink<F>(registry: &RunRegistry, id: &str, forward: F) -> impl Fn(String) + Send + Sync + 'static
where
    F: Fn(String) + Send + Sync + 'static,
{
    let registry = registry.clone();
    let id = id.to_string();
    let forward = Arc::new(forward);
    move |line: String| {
        registry.push_line(&id, line.clone());
        forward(line);
    }
}

/// Verrou de sérialisation : deux `ansible-playbook` simultanés sur le même
/// parc se marchent dessus (fichier de playbook temporaire, `known_hosts`,
/// verrous apt sur l'hôte cible).
///
/// Le jeton rendu ([`RunGuard`]) est POSSÉDÉ et transférable d'un fil à
/// l'autre : l'API d'automatisation le prend dans la requête HTTP — pour
/// répondre « occupé » tout de suite — puis le confie au fil qui exécute le
/// run, qui le relâche en se terminant.
#[derive(Clone, Default)]
pub struct RunLock(Arc<(Mutex<bool>, Condvar)>);

/// Détention du verrou ; le relâche en disparaissant.
pub struct RunGuard(RunLock);

impl RunLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attend que le verrou se libère.
    pub fn acquire(&self) -> RunGuard {
        let (busy, freed) = &*self.0;
        let mut busy = busy.lock().unwrap_or_else(|e| e.into_inner());
        while *busy {
            busy = freed.wait(busy).unwrap_or_else(|e| e.into_inner());
        }
        *busy = true;
        RunGuard(self.clone())
    }

    /// Prend le verrou s'il est libre, sans attendre.
    pub fn try_acquire(&self) -> Option<RunGuard> {
        let mut busy = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        if *busy {
            return None;
        }
        *busy = true;
        Some(RunGuard(self.clone()))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let (busy, freed) = &*self.0 .0;
        *busy.lock().unwrap_or_else(|e| e.into_inner()) = false;
        freed.notify_one();
    }
}

/// Un verrou par parc : deux parcs n'ont aucun hôte en commun.
#[derive(Clone, Default)]
pub struct RunLocks(Arc<Mutex<HashMap<String, RunLock>>>);

impl RunLocks {
    pub fn of(&self, parc: &str) -> RunLock {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(parc.to_string())
            .or_default()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(roles: &[&str], hosts: &[&str]) -> DeployRequest {
        DeployRequest {
            id: "x".into(),
            label: "x".into(),
            inventory_path: "inv.yml".into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            extra_vars: HashMap::new(),
        }
    }

    #[test]
    fn a_deploy_without_hosts_is_refused_before_spawning_ansible() {
        assert!(req(&["brk-install"], &[]).validate().is_err());
        assert!(req(&[], &["brk1"]).validate().is_err());
        assert!(req(&["brk-install"], &["brk1"]).validate().is_ok());
    }

    #[test]
    fn ollama_model_role_requires_its_variable() {
        let mut r = req(&[OLLAMA_MODEL_ROLE], &["hub"]);
        assert!(r.validate().is_err());
        r.extra_vars
            .insert(OLLAMA_MODEL_VAR.into(), "llama3".into());
        assert!(r.validate().is_ok());
    }

    #[test]
    fn registry_tracks_a_run_from_start_to_finish() {
        let reg = RunRegistry::new();
        reg.start("r1", "BRK", RunKind::Role, &["brk-install".into()], &["brk1".into()]);
        assert_eq!(reg.active().len(), 1);

        reg.push_line("r1", "TASK [brk-install]".into());
        reg.finish("r1", RunStatus::Success);

        let run = reg.get("r1").unwrap();
        assert_eq!(run.status, RunStatus::Success);
        assert_eq!(run.output.len(), 1);
        assert!(run.finished_at.is_some());
        assert!(reg.active().is_empty());
    }

    #[test]
    fn clearing_finished_runs_keeps_the_running_ones() {
        let reg = RunRegistry::new();
        reg.start("done", "a", RunKind::Role, &[], &[]);
        reg.start("live", "b", RunKind::Role, &[], &[]);
        reg.finish("done", RunStatus::Failed);

        reg.clear_finished();
        let all = reg.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "live");
    }

    #[test]
    fn the_exit_code_is_kept_with_the_final_status() {
        let reg = RunRegistry::new();
        let check = RunOptions { check: true, diff: false };
        reg.start_with("r1", "x", RunKind::Playbook, &[], &[], check);
        assert!(reg.is_running("r1"));
        reg.finish_with("r1", RunStatus::Failed, Some(2));

        let run = reg.get("r1").unwrap();
        assert_eq!((run.status, run.exit_code), (RunStatus::Failed, Some(2)));
        assert!(run.options.check);
        assert!(!reg.is_running("r1"));
    }

    #[test]
    fn the_run_lock_is_exclusive_until_released() {
        let locks = RunLocks::default();
        let guard = locks.of("web3c").try_acquire().expect("libre");
        assert!(locks.of("web3c").try_acquire().is_none(), "déjà pris");
        assert!(locks.of("papanglabs").try_acquire().is_some(), "autre parc");
        drop(guard);
        assert!(locks.of("web3c").try_acquire().is_some(), "relâché");
    }

    #[test]
    fn a_waiting_run_starts_when_the_lock_is_released() {
        let lock = RunLock::new();
        let guard = lock.try_acquire().unwrap();
        let waiter = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let _g = lock.acquire();
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "doit attendre");
        drop(guard);
        waiter.join().unwrap();
        assert!(lock.try_acquire().is_some());
    }
}
