/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Arbre Ansible servi depuis git (`ff_ansible_source: git`).
//!
//! Trois répertoires, tous posés par `fleetforge-install` :
//!   • `clone_dir` — clone git du dépôt (clé de déploiement en LECTURE
//!     seule), jamais de copie de travail : on n'y lit que des objets ;
//!   • `data_dir` — les données du parc (inventaires, `keys/<parc>/`,
//!     `parcs/<parc>/`, group_vars et host_vars), livrées comme avant par
//!     `ansible-tree.yml` mais à part du code ;
//!   • `trees_dir` — un ARBRE D'EXÉCUTION par commit : `git archive` du
//!     sous-dossier `Ansible/` puis des liens vers `data_dir`, comme
//!     `link-private.sh` le fait avec `.private`. Les N derniers servis sont
//!     gardés (les runs en cours, et la tête, jamais retirés).
//!
//! Tout ce qui touche à git passe par `Command` aux arguments séparés — jamais
//! un shell —, avec des références et des commits validés par une grammaire
//! fermée AVANT d'atteindre une ligne de commande. Un commit ne s'exécute que
//! s'il est atteignable depuis une référence PERMISE : la branche suivie
//! (avancée en avance rapide seulement) ou `infra/<parc>/*` (branches de
//! correctifs du hub).

use crate::fault::{fail, Fault, FaultKind};
use crate::proc::{run_bounded, Captured};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Sous-dossier du dépôt qui porte l'arbre Ansible.
pub const SUBDIR: &str = "Ansible";
/// Arbres d'exécution gardés par défaut.
pub const DEFAULT_KEEP: usize = 5;
/// Longueur du nom de dossier d'un arbre : un sha complet (40 hexadécimaux)
/// serait pris pour un secret par le caviardage (`redact`) dans les chemins
/// que cite la sortie d'Ansible.
const DIR_NAME_LEN: usize = 16;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(180);
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(300);
const GIT_MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct GitTreeConfig {
    pub clone_dir: PathBuf,
    pub data_dir: PathBuf,
    pub trees_dir: PathBuf,
    /// Branche suivie (`main`).
    pub branch: String,
    /// Clé de déploiement en lecture seule. Absente : git sans clé (dépôt
    /// public, ou chemin local).
    pub deploy_key: Option<PathBuf>,
    pub known_hosts: Option<PathBuf>,
    pub keep: usize,
    /// Exécutable git.
    pub git: String,
}

impl GitTreeConfig {
    pub fn new(clone_dir: PathBuf, data_dir: PathBuf, trees_dir: PathBuf, branch: &str) -> Self {
        Self {
            clone_dir,
            data_dir,
            trees_dir,
            branch: branch.to_string(),
            deploy_key: None,
            known_hosts: None,
            keep: DEFAULT_KEEP,
            git: "git".to_string(),
        }
    }
}

// === Grammaires ===

/// Commit demandé : la tête synchronisée, ou un sha complet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitSpec {
    Head,
    Sha(String),
}

/// `HEAD`, ou un sha COMPLET (40 hexadécimaux, 64 pour un dépôt sha256), mis
/// en minuscules. Jamais un nom de branche, un sha abrégé ni une expression
/// (`HEAD~3`, `a..b`) : le commit est ce qui sera exécuté, il se désigne
/// sans ambiguïté.
pub fn parse_commit(spec: &str) -> Result<CommitSpec> {
    if spec == "HEAD" {
        return Ok(CommitSpec::Head);
    }
    let hex = (spec.len() == 40 || spec.len() == 64) && spec.chars().all(|c| c.is_ascii_hexdigit());
    if !hex {
        return fail(
            FaultKind::InvalidArgument,
            format!("commit invalide {spec:?} : HEAD ou un sha complet (40 hexadécimaux)"),
        );
    }
    Ok(CommitSpec::Sha(spec.to_ascii_lowercase()))
}

/// Nom de branche suivie : segments `[A-Za-z0-9._-]` séparés par `/`, sans
/// `..`, sans segment vide ni commençant par `.` ou `-`, sans `.lock` final.
pub fn validate_branch_name(name: &str) -> Result<()> {
    let segment = |s: &str| {
        !s.is_empty()
            && !s.starts_with(['.', '-'])
            && !s.ends_with(".lock")
            && !s.ends_with('.')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    if name.len() > 100 || name.contains("..") || !name.split('/').all(segment) {
        return fail(FaultKind::InvalidArgument, format!("nom de branche invalide : {name:?}"));
    }
    Ok(())
}

/// Référence que `sync_tree` accepte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeRef {
    /// La branche suivie.
    Branch,
    /// `infra/<parc>/<nom>` : branche de correctif du hub.
    Infra(String),
}

/// `ref` de `sync_tree` : exactement la branche suivie, ou
/// `infra/<parc>/<nom>` pour LE parc de l'appel (un compte d'un parc ne
/// touche pas aux branches d'un autre). `<nom>` : un seul segment.
pub fn parse_ref(reference: &str, parc: &str, branch: &str) -> Result<TreeRef> {
    if reference == branch {
        return Ok(TreeRef::Branch);
    }
    let refused = || {
        Fault::new(
            FaultKind::RefRefused,
            format!("référence refusée {reference:?} : la branche suivie ({branch}) ou infra/{parc}/<nom>"),
        )
    };
    let name = reference
        .strip_prefix("infra/")
        .and_then(|r| r.strip_prefix(parc))
        .and_then(|r| r.strip_prefix('/'))
        .ok_or_else(refused)?;
    let valid = (1..=64).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && !name.ends_with(['.'])
        && !name.ends_with(".lock")
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !valid {
        return Err(refused().into());
    }
    Ok(TreeRef::Infra(name.to_string()))
}

/// Une valeur insérée dans `GIT_SSH_COMMAND` (lu par un shell) : pas de
/// guillemet ni de caractère de contrôle.
fn shell_safe(path: &Path) -> Result<String> {
    let text = path.to_string_lossy().to_string();
    if text.is_empty() || text.chars().any(|c| c == '\'' || c.is_control()) {
        return fail(FaultKind::NotConfigured, format!("chemin inutilisable pour git : {text:?}"));
    }
    Ok(text)
}

// === L'arbre ===

/// Arbre d'exécution d'un commit.
#[derive(Debug, Clone)]
pub struct ExecTree {
    pub commit: String,
    /// Racine : le `cwd` d'Ansible (`ansible.cfg`, `playbooks/`).
    pub root: PathBuf,
    pub playbooks: PathBuf,
}

/// Retenue d'un arbre : tant qu'elle vit, le nettoyage ne le retire pas.
pub struct PinGuard {
    pins: Arc<Mutex<HashMap<String, usize>>>,
    commit: String,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        let mut pins = self.pins.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = pins.get_mut(&self.commit) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                pins.remove(&self.commit);
            }
        }
    }
}

/// Ce que `sync_tree` rend.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Le commit demandé, sinon la pointe de la référence synchronisée.
    pub commit: String,
    /// Tête synchronisée de la branche suivie, après l'opération.
    pub head: String,
    pub reference: String,
}

/// Ce qu'un nettoyage (`prune_orphans`) a retiré.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct PruneReport {
    /// Références `infra/*` locales qui n'existent plus sur le dépôt distant.
    pub refs_removed: Vec<String>,
    /// Arbres d'exécution retirés du cache (au-delà de `keep`).
    pub trees_removed: usize,
    /// Pourquoi les références n'ont pas pu être comparées (dépôt injoignable) :
    /// rien n'est alors retiré de ce côté.
    pub refs_error: Option<String>,
}

/// État de l'arbre git.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GitStatus {
    pub branch: String,
    pub head: String,
    pub synced_at: Option<String>,
    pub commits_cached: usize,
}

pub struct GitTree {
    cfg: GitTreeConfig,
    /// Une synchronisation à la fois.
    sync_lock: Mutex<()>,
    /// Une construction d'arbre (ou un nettoyage) à la fois.
    tree_lock: Mutex<()>,
    pins: Arc<Mutex<HashMap<String, usize>>>,
}

impl GitTree {
    pub fn new(cfg: GitTreeConfig) -> Result<Arc<Self>> {
        validate_branch_name(&cfg.branch)?;
        if cfg.keep == 0 {
            return fail(FaultKind::NotConfigured, "le cache d'arbres doit garder au moins un commit");
        }
        if let Some(key) = &cfg.deploy_key {
            shell_safe(key)?;
        }
        if let Some(known) = &cfg.known_hosts {
            shell_safe(known)?;
        }
        Ok(Arc::new(Self {
            cfg,
            sync_lock: Mutex::new(()),
            tree_lock: Mutex::new(()),
            pins: Arc::default(),
        }))
    }

    pub fn config(&self) -> &GitTreeConfig {
        &self.cfg
    }

    pub fn branch(&self) -> &str {
        &self.cfg.branch
    }

    pub fn inventories_dir(&self) -> PathBuf {
        self.cfg.data_dir.join("inventories")
    }

    // --- git ---

    fn command(&self, network: bool) -> Result<Command> {
        let mut cmd = Command::new(&self.cfg.git);
        cmd.arg("-C").arg(&self.cfg.clone_dir);
        cmd.env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", "file:ssh:https")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("LC_ALL", "C");
        if network {
            if let Some(key) = &self.cfg.deploy_key {
                let mut ssh = format!(
                    "ssh -i '{}' -o IdentitiesOnly=yes -o BatchMode=yes",
                    shell_safe(key)?
                );
                match &self.cfg.known_hosts {
                    Some(known) => ssh.push_str(&format!(
                        " -o 'UserKnownHostsFile={}' -o StrictHostKeyChecking=yes",
                        shell_safe(known)?
                    )),
                    None => ssh.push_str(" -o StrictHostKeyChecking=accept-new"),
                }
                cmd.env("GIT_SSH_COMMAND", ssh);
            }
        } else {
            // Un commit absent du clone se dit « inconnu » ; il ne se va pas
            // chercher sur le réseau.
            cmd.env("GIT_NO_LAZY_FETCH", "1");
        }
        Ok(cmd)
    }

    fn run(&self, args: &[&str], network: bool, timeout: Duration) -> Result<Captured> {
        if !self.cfg.clone_dir.is_dir() {
            return fail(
                FaultKind::NotConfigured,
                format!("clone git absent : {} (ff_ansible_source: git, tags ansible)", self.cfg.clone_dir.display()),
            );
        }
        let mut cmd = self.command(network)?;
        cmd.args(args);
        run_bounded(cmd, timeout, GIT_MAX_BYTES)
    }

    /// Sortie standard d'un git qui doit réussir.
    fn ok(&self, args: &[&str], network: bool, timeout: Duration) -> Result<String> {
        let got = self.run(args, network, timeout)?;
        if got.timed_out {
            return fail(FaultKind::Timeout, format!("git {} : délai dépassé", args.first().unwrap_or(&"")));
        }
        if !got.success() {
            let kind = if network { FaultKind::Upstream } else { FaultKind::NotConfigured };
            return fail(
                kind,
                format!("git {} a échoué : {}", args.first().unwrap_or(&""), got.stderr.trim()),
            );
        }
        Ok(got.stdout.trim().to_string())
    }

    /// Tête synchronisée : la branche locale suivie, relue du clone — elle
    /// survit donc à un redémarrage.
    pub fn head(&self) -> Result<String> {
        let reference = format!("refs/heads/{}^{{commit}}", self.cfg.branch);
        let got = self.run(&["rev-parse", "--verify", "--quiet", &reference], false, LOCAL_TIMEOUT)?;
        if !got.success() || got.stdout.trim().is_empty() {
            return fail(
                FaultKind::NotConfigured,
                format!("le clone n'a pas de branche {} : synchroniser (sync_tree) ou redéployer", self.cfg.branch),
            );
        }
        Ok(got.stdout.trim().to_string())
    }

    /// Dernière synchronisation : date de `FETCH_HEAD`.
    pub fn synced_at(&self) -> Option<String> {
        [self.cfg.clone_dir.join(".git/FETCH_HEAD"), self.cfg.clone_dir.join("FETCH_HEAD")]
            .iter()
            .find_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
    }

    pub fn status(&self) -> Result<GitStatus> {
        Ok(GitStatus {
            branch: self.cfg.branch.clone(),
            head: self.head()?,
            synced_at: self.synced_at(),
            commits_cached: self.cached().len(),
        })
    }

    fn has_commit(&self, sha: &str) -> Result<bool> {
        let object = format!("{sha}^{{commit}}");
        Ok(self.run(&["cat-file", "-e", &object], false, LOCAL_TIMEOUT)?.success())
    }

    /// Le commit est-il atteignable depuis une référence permise : la tête
    /// synchronisée, ou une branche `infra/<parc>/*` déjà récupérée ?
    /// (Pas du suivi distant de la branche : un historique réécrit côté
    /// serveur n'a pas été accepté en avance rapide.)
    fn allowed(&self, parc: &str, sha: &str) -> Result<bool> {
        let local = format!("refs/heads/{}", self.cfg.branch);
        let infra = format!("refs/remotes/origin/infra/{parc}");
        let out = self.ok(
            &["for-each-ref", "--contains", sha, "--format=%(refname)", &local, &infra],
            false,
            LOCAL_TIMEOUT,
        )?;
        Ok(!out.is_empty())
    }

    /// Commit à exécuter : `None`/`HEAD` = la tête synchronisée ; un sha doit
    /// être connu du clone ET atteignable d'une référence permise de CE parc.
    pub fn resolve_commit(&self, parc: &str, spec: Option<&CommitSpec>) -> Result<String> {
        match spec {
            None | Some(CommitSpec::Head) => self.head(),
            Some(CommitSpec::Sha(sha)) => {
                if !self.has_commit(sha)? {
                    return fail(
                        FaultKind::UnknownCommit,
                        format!("commit inconnu du clone : {sha} (le récupérer d'abord avec sync_tree)"),
                    );
                }
                if !self.allowed(parc, sha)? {
                    return fail(
                        FaultKind::UnknownCommit,
                        format!(
                            "commit {sha} hors des références permises ({} ou infra/{parc}/*)",
                            self.cfg.branch
                        ),
                    );
                }
                Ok(sha.clone())
            }
        }
    }

    // --- synchronisation ---

    /// `git fetch` d'une référence permise, avance rapide de la branche
    /// suivie seulement. Rend le commit (celui demandé, vérifié atteignable ;
    /// sinon la pointe de la référence).
    pub fn sync(&self, parc: &str, commit: Option<&CommitSpec>, reference: Option<&str>) -> Result<SyncOutcome> {
        crate::automation::validate_parc_name(parc)?;
        let kind = match reference {
            Some(r) => parse_ref(r, parc, &self.cfg.branch)?,
            None => TreeRef::Branch,
        };
        let _one_at_a_time = self.sync_lock.lock().unwrap_or_else(|e| e.into_inner());
        let branch = self.cfg.branch.clone();

        let (shown, tip) = match &kind {
            TreeRef::Branch => {
                let spec = format!("+refs/heads/{branch}:refs/remotes/origin/{branch}");
                self.ok(&["fetch", "--no-tags", "origin", &spec], true, FETCH_TIMEOUT)?;
                self.fast_forward()?;
                (branch.clone(), self.head()?)
            }
            TreeRef::Infra(name) => {
                // Toutes les branches de correctif du parc, élaguées : ce qui
                // a été supprimé côté serveur cesse d'être une référence
                // permise ici.
                let spec = format!("+refs/heads/infra/{parc}/*:refs/remotes/origin/infra/{parc}/*");
                self.ok(&["fetch", "--no-tags", "--prune", "origin", &spec], true, FETCH_TIMEOUT)?;
                let tracked = format!("refs/remotes/origin/infra/{parc}/{name}^{{commit}}");
                let got = self.run(&["rev-parse", "--verify", "--quiet", &tracked], false, LOCAL_TIMEOUT)?;
                if !got.success() {
                    return fail(
                        FaultKind::UnknownCommit,
                        format!("la branche infra/{parc}/{name} n'existe pas sur le dépôt"),
                    );
                }
                (format!("infra/{parc}/{name}"), got.stdout.trim().to_string())
            }
        };

        let commit = match commit {
            None | Some(CommitSpec::Head) => tip,
            Some(CommitSpec::Sha(sha)) => {
                if !self.has_commit(sha)? || !self.allowed(parc, sha)? {
                    return fail(
                        FaultKind::UnknownCommit,
                        format!("commit {sha} introuvable depuis {shown} ni depuis une référence permise"),
                    );
                }
                sha.clone()
            }
        };
        Ok(SyncOutcome { commit, head: self.head()?, reference: shown })
    }

    /// Avance la branche locale suivie sur son suivi distant, en avance rapide
    /// SEULEMENT et par échange conditionnel (`update-ref <nouveau> <ancien>`).
    fn fast_forward(&self) -> Result<()> {
        let branch = &self.cfg.branch;
        let tracked_ref = format!("refs/remotes/origin/{branch}^{{commit}}");
        let new = self.ok(&["rev-parse", "--verify", &tracked_ref], false, LOCAL_TIMEOUT)?;
        let local_ref = format!("refs/heads/{branch}");
        let old = match self.head() {
            Ok(old) => old,
            Err(_) => {
                // Premier passage (clone sans branche locale) : on la crée.
                self.ok(&["update-ref", &local_ref, &new, &"0".repeat(new.len())], false, LOCAL_TIMEOUT)?;
                return Ok(());
            }
        };
        if old == new {
            return Ok(());
        }
        let ancestor = self.run(&["merge-base", "--is-ancestor", &old, &new], false, LOCAL_TIMEOUT)?;
        match ancestor.code {
            Some(0) => {
                self.ok(&["update-ref", &local_ref, &new, &old], false, LOCAL_TIMEOUT)?;
                Ok(())
            }
            Some(1) => fail(
                FaultKind::NotFastForward,
                format!(
                    "{branch} a divergé de la tête synchronisée ({old}) : pas d'avance rapide, \
                     intervention humaine requise (git -C {} update-ref {local_ref} <commit>)",
                    self.cfg.clone_dir.display()
                ),
            ),
            _ => fail(FaultKind::Upstream, format!("git merge-base a échoué : {}", ancestor.stderr.trim())),
        }
    }

    // --- arbres d'exécution ---

    fn dir_name(sha: &str) -> &str {
        &sha[..DIR_NAME_LEN.min(sha.len())]
    }

    fn tree_path(&self, sha: &str) -> PathBuf {
        self.cfg.trees_dir.join(Self::dir_name(sha))
    }

    /// Commits dont l'arbre est en cache.
    pub fn cached(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.cfg.trees_dir) else { return vec![] };
        entries
            .filter_map(|e| e.ok())
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| std::fs::read_to_string(e.path().join(".commit")).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Retient l'arbre d'un commit le temps d'un run.
    pub fn pin(&self, commit: &str) -> PinGuard {
        *self.pins.lock().unwrap_or_else(|e| e.into_inner()).entry(commit.to_string()).or_default() += 1;
        PinGuard { pins: self.pins.clone(), commit: commit.to_string() }
    }

    /// Arbre d'exécution d'un commit DÉJÀ résolu (`resolve_commit`) : construit
    /// au besoin, liens vers les données du parc remis à jour, nettoyage du
    /// cache.
    pub fn exec_tree(&self, commit: &str) -> Result<ExecTree> {
        let hex = commit.len() >= 40 && commit.chars().all(|c| c.is_ascii_hexdigit());
        if !hex {
            return fail(FaultKind::InvalidArgument, format!("commit invalide : {commit:?}"));
        }
        let _build = self.tree_lock.lock().unwrap_or_else(|e| e.into_inner());
        let dir = self.tree_path(commit);
        let marker = dir.join(".commit");
        if dir.join("playbooks").is_dir() {
            match std::fs::read_to_string(&marker) {
                Ok(found) if found.trim() == commit => {}
                _ => {
                    return fail(
                        FaultKind::NotConfigured,
                        format!("{} appartient à un autre commit (collision de nom)", dir.display()),
                    )
                }
            }
        } else {
            self.build_tree(commit, &dir)?;
        }
        let _ = std::fs::write(dir.join(".last_used"), chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default().to_string());
        link_data(&dir, &self.cfg.data_dir)?;
        self.prune(Some(commit));
        Ok(ExecTree { commit: commit.to_string(), root: dir.clone(), playbooks: dir.join("playbooks") })
    }

    fn build_tree(&self, commit: &str, dest: &Path) -> Result<()> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::fs::create_dir_all(&self.cfg.trees_dir)
            .with_context(|| format!("création de {}", self.cfg.trees_dir.display()))?;
        let tmp = self.cfg.trees_dir.join(format!(
            ".tmp-{}-{}-{}",
            Self::dir_name(commit),
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("tree"))?;
        let built = self.extract_into(commit, &tmp);
        let result = built.and_then(|()| {
            let tree = tmp.join("tree");
            if !tree.join("playbooks").is_dir() {
                return fail(
                    FaultKind::NotConfigured,
                    format!("le commit {commit} n'a pas de {SUBDIR}/playbooks"),
                );
            }
            remove_escaping_links(&tree)?;
            std::fs::write(tree.join(".commit"), commit)?;
            if dest.exists() {
                // Reste d'une construction interrompue.
                std::fs::remove_dir_all(dest)?;
            }
            std::fs::rename(&tree, dest).with_context(|| format!("installation de {}", dest.display()))
        });
        let _ = std::fs::remove_dir_all(&tmp);
        result
    }

    fn extract_into(&self, commit: &str, tmp: &Path) -> Result<()> {
        let archive = tmp.join("archive.tar");
        let output = format!("--output={}", archive.display());
        // `archive` lit les blobs du commit ; dans un clone partiel, il les
        // demande au serveur (clé de déploiement, donc `network`).
        self.ok(&["archive", "--format=tar", &output, commit, SUBDIR], true, ARCHIVE_TIMEOUT)?;
        let mut tar = Command::new("tar");
        tar.arg("-x")
            .arg("-f")
            .arg(&archive)
            .arg("-C")
            .arg(tmp.join("tree"))
            .arg("--strip-components=1")
            .arg("--no-same-owner");
        let got = run_bounded(tar, ARCHIVE_TIMEOUT, GIT_MAX_BYTES)?;
        if !got.success() {
            return fail(FaultKind::Upstream, format!("tar a échoué : {}", got.stderr.trim()));
        }
        Ok(())
    }

    /// Retire les arbres au-delà de `keep`, du moins récemment servi au plus
    /// ancien ; jamais la tête, le commit demandé ni un arbre retenu. Rend le
    /// nombre d'arbres retirés.
    fn prune(&self, current: Option<&str>) -> usize {
        let mut removed = 0;
        let Ok(entries) = std::fs::read_dir(&self.cfg.trees_dir) else { return 0 };
        let head = self.head().unwrap_or_default();
        let pinned: Vec<String> = self.pins.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();
        let mut trees: Vec<(u128, PathBuf, String)> = Vec::new();
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(".tmp-") {
                // Construction abandonnée (processus tué) : plus d'une heure.
                let old = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(3600));
                if old {
                    let _ = std::fs::remove_dir_all(&path);
                }
                continue;
            }
            if name.starts_with('.') || !path.is_dir() {
                continue;
            }
            let commit = std::fs::read_to_string(path.join(".commit")).unwrap_or_default().trim().to_string();
            let used = std::fs::read_to_string(path.join(".last_used"))
                .ok()
                .and_then(|s| s.trim().parse::<u128>().ok())
                .unwrap_or(0);
            trees.push((used, path, commit));
        }
        trees.sort_by(|a, b| b.0.cmp(&a.0));
        let mut kept = 0;
        for (_, path, commit) in trees {
            let keep_it = current == Some(commit.as_str()) || commit == head || pinned.contains(&commit);
            if keep_it || kept < self.cfg.keep {
                kept += 1;
                continue;
            }
            // `remove_dir_all` ne suit pas les liens : les données du parc,
            // où ils pointent, ne sont jamais touchées.
            if std::fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    // --- nettoyage ---

    /// Nettoyage de ce que FleetForge garde en local : les arbres d'exécution
    /// au-delà du cache, et les références `infra/*` (suivis distants
    /// `refs/remotes/origin/infra/…`, et branches locales de même nom) que le
    /// dépôt distant n'a plus — une branche de correctif fusionnée puis
    /// supprimée par le fournisseur (GitLab « supprimer la branche source »,
    /// GitHub « delete branch ») ne reste ainsi pas permise indéfiniment.
    ///
    /// Appelé au démarrage puis toutes les heures ; `sync` n'élague que le parc
    /// de l'appelant, et seulement quand il récupère une `infra/<parc>/*`.
    ///
    /// La liste des branches distantes vient de `git ls-remote` : aucun objet
    /// n'est téléchargé, donc rien d'un autre parc n'entre dans le clone. Si
    /// elle ne peut pas être lue (réseau, clé), AUCUNE référence n'est retirée.
    pub fn prune_orphans(&self) -> Result<PruneReport> {
        if !self.cfg.clone_dir.is_dir() {
            return fail(
                FaultKind::NotConfigured,
                format!("clone git absent : {}", self.cfg.clone_dir.display()),
            );
        }
        let mut report = PruneReport::default();
        {
            let _build = self.tree_lock.lock().unwrap_or_else(|e| e.into_inner());
            report.trees_removed = self.prune(None);
        }
        let _one_at_a_time = self.sync_lock.lock().unwrap_or_else(|e| e.into_inner());
        match self.orphan_refs() {
            Ok(orphans) => {
                for reference in orphans {
                    // `update-ref -d` : la référence seule ; les objets restent
                    // au clone jusqu'à son prochain `git gc`.
                    if self.ok(&["update-ref", "-d", &reference], false, LOCAL_TIMEOUT).is_ok() {
                        report.refs_removed.push(reference);
                    }
                }
            }
            Err(e) => report.refs_error = Some(e.to_string()),
        }
        Ok(report)
    }

    /// Références locales `infra/*` absentes du dépôt distant.
    fn orphan_refs(&self) -> Result<Vec<String>> {
        let remote = self.ok(&["ls-remote", "--heads", "origin", "refs/heads/infra/*"], true, FETCH_TIMEOUT)?;
        let on_remote: std::collections::HashSet<&str> = remote
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .filter_map(|(_, name)| name.strip_prefix("refs/heads/"))
            .filter(|name| name.starts_with("infra/"))
            .collect();
        let local = self.ok(
            &["for-each-ref", "--format=%(refname)", "refs/remotes/origin/infra", "refs/heads/infra"],
            false,
            LOCAL_TIMEOUT,
        )?;
        Ok(local
            .lines()
            .filter(|reference| {
                let short = reference
                    .strip_prefix("refs/remotes/origin/")
                    .or_else(|| reference.strip_prefix("refs/heads/"))
                    .unwrap_or_default();
                short.starts_with("infra/") && !on_remote.contains(short)
            })
            .map(String::from)
            .collect())
    }
}

// === Liens vers les données du parc ===

/// Entrées sous lesquelles un SOUS-DOSSIER de données se lie en entier
/// (`parcs/<parc>/`, `keys/<parc>/`), comme `link-private.sh`.
const WHOLE_DIRS: &[&str] = &["parcs", "keys"];

/// Lie les données du parc dans l'arbre, à l'image de `link-private.sh` :
/// `parcs/<parc>/` et `keys/<parc>/` en entier, tout autre fichier de données
/// (inventaires, group_vars, host_vars, fichiers de rôle livrés à la demande)
/// fichier par fichier au même chemin. Idempotent ; rejoué à chaque usage de
/// l'arbre, pour qu'une donnée livrée depuis (`--tags ansible`) y paraisse.
///
/// Un fichier ou dossier ORDINAIRE déjà présent dans l'arbre n'est jamais
/// remplacé : le code du dépôt prime sur la donnée.
pub fn link_data(tree: &Path, data: &Path) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    if !data.is_dir() {
        notes.push(format!("pas de données de parc dans {}", data.display()));
        return Ok(notes);
    }
    let data = data.canonicalize()?;
    fn walk(tree: &Path, data: &Path, rel: &Path, notes: &mut Vec<String>) -> Result<()> {
        for entry in std::fs::read_dir(data.join(rel))? {
            let entry = entry?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            if name_text.starts_with('.') {
                continue;
            }
            let child = rel.join(&name);
            let source = data.join(&child);
            let meta = std::fs::symlink_metadata(&source)?;
            let whole = meta.is_dir()
                && rel.components().count() == 1
                && WHOLE_DIRS.contains(&rel.to_string_lossy().as_ref());
            if meta.is_dir() && !whole {
                walk(tree, data, &child, notes)?;
            } else {
                link_one(&tree.join(&child), &source, notes)?;
            }
        }
        Ok(())
    }
    walk(tree, &data, Path::new(""), &mut notes)?;

    // Liens devenus orphelins : donnée retirée depuis.
    for dir in ["inventories", "keys", "parcs", "playbooks/group_vars", "playbooks/host_vars"] {
        let Ok(entries) = std::fs::read_dir(tree.join(dir)) else { continue };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Ok(target) = std::fs::read_link(&path) {
                if target.starts_with(&data) && !path.exists() {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
    Ok(notes)
}

fn link_one(dest: &Path, source: &Path, notes: &mut Vec<String>) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            if std::fs::read_link(dest).is_ok_and(|t| t == source) {
                return Ok(());
            }
            std::fs::remove_file(dest)?;
        } else {
            if dest.file_name().is_some_and(|n| n != "README.md") {
                notes.push(format!("{} existe dans le code : donnée de parc non liée", dest.display()));
            }
            return Ok(());
        }
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(source, dest).with_context(|| format!("lien {}", dest.display()))?;
    #[cfg(not(unix))]
    return fail(FaultKind::NotConfigured, "l'arbre git n'est pris en charge que sous unix");
    Ok(())
}

/// Retire de l'arbre extrait tout lien symbolique qui en sortirait (cible
/// absolue ou `..` au-delà de la racine) : un commit n'a pas à pointer hors
/// de lui-même, et les lecteurs de l'arbre (`read_tree`) n'ont pas à s'en
/// défendre seuls.
fn remove_escaping_links(root: &Path) -> Result<usize> {
    fn walk(root: &Path, dir: &Path, removed: &mut usize) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path)?;
                if escapes(root, &path, &target) {
                    std::fs::remove_file(&path)?;
                    *removed += 1;
                }
            } else if meta.is_dir() {
                walk(root, &path, removed)?;
            }
        }
        Ok(())
    }
    let mut removed = 0;
    walk(root, root, &mut removed)?;
    Ok(removed)
}

/// La cible d'un lien, lue littéralement, sort-elle de `root` ?
fn escapes(root: &Path, link: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return true;
    }
    let mut depth = link
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .map(|p| p.components().count() as i64)
        .unwrap_or(0);
    for component in target.components() {
        match component {
            std::path::Component::ParentDir => depth -= 1,
            std::path::Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::kind_of;

    fn scratch(name: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ff-git-{}-{name}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `git` avec une identité fixe et sans réglage de l'utilisateur.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.org")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.org")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?} : {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Dépôt « serveur » avec un premier commit, et clone de `fleetforge`.
    struct Fixture {
        root: PathBuf,
        origin: PathBuf,
        tree: Arc<GitTree>,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = scratch(name);
            let origin = root.join("origin");
            std::fs::create_dir_all(&origin).unwrap();
            git(&origin, &["init", "-q", "-b", "main"]);
            write(&origin.join("Ansible/playbooks/deploy-x.yml"), "---\n- hosts: all\n  tasks: []\n");
            write(&origin.join("Ansible/ansible.cfg"), "[defaults]\n");
            write(&origin.join("README.md"), "hors de Ansible/\n");
            git(&origin, &["add", "-A"]);
            git(&origin, &["commit", "-q", "-m", "first"]);

            let clone = root.join("ansible-git");
            let out = Command::new("git")
                .args(["clone", "-q", "--no-checkout", "--branch", "main"])
                .arg(&origin)
                .arg(&clone)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

            let data = root.join("ansible-data");
            write(&data.join("inventories/web3c_inventory.yml"), "all: {}\n");
            write(&data.join("playbooks/group_vars/web3c.yml"), "parc_name: web3c\n");
            write(&data.join("parcs/web3c/nginx/site.conf"), "x\n");
            write(&data.join("keys/web3c/control/id.pub"), "k\n");
            write(&data.join("keys/README.md"), "doc\n");

            let mut cfg = GitTreeConfig::new(clone, data, root.join("ansible-trees"), "main");
            cfg.keep = 2;
            let tree = GitTree::new(cfg).unwrap();
            Self { root, origin, tree }
        }

        fn commit_on_origin(&self, file: &str, content: &str) -> String {
            write(&self.origin.join(file), content);
            git(&self.origin, &["add", "-A"]);
            git(&self.origin, &["commit", "-q", "-m", "change"]);
            git(&self.origin, &["rev-parse", "HEAD"])
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn commits_are_head_or_a_full_sha() {
        assert_eq!(parse_commit("HEAD").unwrap(), CommitSpec::Head);
        let sha = "0123456789ABCDEF0123456789abcdef01234567";
        assert_eq!(parse_commit(sha).unwrap(), CommitSpec::Sha(sha.to_ascii_lowercase()));
        assert!(parse_commit(&"a".repeat(64)).is_ok(), "dépôt sha256");
        for bad in [
            "", "head", "HEAD~1", "main", "abc1234", "-x", "--help", &"a".repeat(41), &"g".repeat(40),
            "0123456789abcdef0123456789abcdef01234567 ", "a..b", "0123456789abcdef0123456789abcdef0123456\n",
        ] {
            assert!(parse_commit(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refs_are_the_followed_branch_or_the_parc_fix_branches() {
        assert_eq!(parse_ref("main", "web3c", "main").unwrap(), TreeRef::Branch);
        assert_eq!(
            parse_ref("infra/web3c/fix-1.a", "web3c", "main").unwrap(),
            TreeRef::Infra("fix-1.a".into())
        );
        for bad in [
            "dev", "origin/main", "refs/heads/main", "HEAD", "infra/papanglabs/x", "infra/web3c", "infra/web3c/",
            "infra/web3c/a/b", "infra/web3c/..", "infra/web3c/a..b", "infra/web3c/-x", "infra/web3c/.x",
            "infra/web3c/x.lock", "infra/web3c/x.", "infra/web3c/x y", "infra/web3c/x;id", "infra/web3cc/x",
            "infra/web3c/*", "", "-x", "main ", "--upload-pack=x",
        ] {
            let err = parse_ref(bad, "web3c", "main").unwrap_err();
            assert_eq!(kind_of(&err), Some(FaultKind::RefRefused), "{bad:?}");
        }
        assert!(parse_ref(&format!("infra/web3c/{}", "a".repeat(65)), "web3c", "main").is_err());
    }

    #[test]
    fn branch_names_have_a_closed_grammar() {
        for ok in ["main", "release/1.2", "a-b_c"] {
            assert!(validate_branch_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "a..b", "a//b", "/a", "a/", ".x", "x.lock", "a b", "a;b", "a/.b", &"a".repeat(101)] {
            assert!(validate_branch_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_literal_symlink_is_judged_by_where_it_points() {
        let root = Path::new("/t");
        let at = |link: &str, target: &str| escapes(root, &root.join(link), Path::new(target));
        assert!(at("a", "/etc/passwd"));
        assert!(at("a", "../x"));
        assert!(at("p/a", "../../x"));
        assert!(!at("p/a", "../x"));
        assert!(!at("p/a", "b/c"));
        assert!(at("p/a", "b/../../../x"));
    }

    #[test]
    fn the_head_comes_from_the_clone_and_survives_a_restart() {
        let fx = Fixture::new("head");
        let first = git(&fx.origin, &["rev-parse", "HEAD"]);
        assert_eq!(fx.tree.head().unwrap(), first);
        let again = GitTree::new(fx.tree.config().clone()).unwrap();
        assert_eq!(again.head().unwrap(), first);
        let status = again.status().unwrap();
        assert_eq!((status.branch.as_str(), status.head.as_str(), status.commits_cached), ("main", first.as_str(), 0));
    }

    #[test]
    fn sync_fast_forwards_the_followed_branch_and_returns_the_commit() {
        let fx = Fixture::new("sync");
        let second = fx.commit_on_origin("Ansible/playbooks/deploy-y.yml", "---\n");
        let out = fx.tree.sync("web3c", None, None).unwrap();
        assert_eq!((out.commit.as_str(), out.head.as_str(), out.reference.as_str()), (second.as_str(), second.as_str(), "main"));
        assert_eq!(fx.tree.head().unwrap(), second);
        assert!(fx.tree.synced_at().is_some());

        // Rien de neuf : même commit, sans erreur.
        assert_eq!(fx.tree.sync("web3c", Some(&CommitSpec::Head), Some("main")).unwrap().commit, second);
        // Un commit explicite atteignable est rendu tel quel.
        assert_eq!(fx.tree.sync("web3c", Some(&CommitSpec::Sha(second.clone())), None).unwrap().commit, second);
    }

    #[test]
    fn a_history_rewritten_on_the_server_is_not_followed() {
        let fx = Fixture::new("rewrite");
        let first = fx.tree.head().unwrap();
        fx.commit_on_origin("Ansible/playbooks/deploy-y.yml", "---\n");
        fx.tree.sync("web3c", None, None).unwrap();
        let synced = fx.tree.head().unwrap();
        // Le serveur réécrit : retour au premier commit puis un autre commit.
        git(&fx.origin, &["reset", "-q", "--hard", &first]);
        fx.commit_on_origin("Ansible/playbooks/deploy-z.yml", "---\n");
        let err = fx.tree.sync("web3c", None, None).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::NotFastForward), "{err}");
        assert_eq!(fx.tree.head().unwrap(), synced, "la tête n'a pas bougé");
    }

    #[test]
    fn only_allowed_refs_are_fetched_and_only_their_commits_run() {
        let fx = Fixture::new("refs");
        let main_head = fx.tree.head().unwrap();
        // Branche de correctif du parc, et branche étrangère.
        git(&fx.origin, &["checkout", "-q", "-b", "infra/web3c/fix1"]);
        let fix = fx.commit_on_origin("Ansible/playbooks/deploy-fix.yml", "---\n");
        git(&fx.origin, &["checkout", "-q", "-b", "feature/other", &main_head]);
        let other = fx.commit_on_origin("Ansible/playbooks/deploy-other.yml", "---\n");
        git(&fx.origin, &["checkout", "-q", "main"]);

        // Avant récupération : inconnu.
        let sha = |s: &str| CommitSpec::Sha(s.to_string());
        let err = fx.tree.resolve_commit("web3c", Some(&sha(&fix))).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::UnknownCommit));

        let out = fx.tree.sync("web3c", None, Some("infra/web3c/fix1")).unwrap();
        assert_eq!((out.commit.as_str(), out.reference.as_str()), (fix.as_str(), "infra/web3c/fix1"));
        assert_eq!(out.head, main_head, "la branche suivie n'a pas bougé");
        assert_eq!(fx.tree.resolve_commit("web3c", Some(&sha(&fix))).unwrap(), fix);
        // Mais pas pour un autre parc.
        assert!(fx.tree.resolve_commit("papanglabs", Some(&sha(&fix))).is_err());

        // Références refusées : branche étrangère, infra d'un autre parc.
        for bad in ["feature/other", "infra/papanglabs/x"] {
            let err = fx.tree.sync("web3c", None, Some(bad)).unwrap_err();
            assert_eq!(kind_of(&err), Some(FaultKind::RefRefused), "{bad}");
        }
        // Un commit hors des références permises est refusé, même demandé par sha.
        let err = fx.tree.sync("web3c", Some(&sha(&other)), None).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::UnknownCommit), "{err}");
        assert!(fx.tree.resolve_commit("web3c", Some(&sha(&other))).is_err());
        // Branche de correctif absente du serveur.
        let err = fx.tree.sync("web3c", None, Some("infra/web3c/ghost")).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::UnknownCommit));

        // La branche supprimée côté serveur cesse d'être permise (élagage).
        git(&fx.origin, &["branch", "-q", "-D", "infra/web3c/fix1"]);
        let _ = fx.tree.sync("web3c", None, Some("infra/web3c/ghost"));
        assert!(fx.tree.resolve_commit("web3c", Some(&sha(&fix))).is_err());
    }

    #[test]
    fn an_execution_tree_is_the_commit_plus_links_to_the_parc_data() {
        let fx = Fixture::new("exec");
        let head = fx.tree.head().unwrap();
        let tree = fx.tree.exec_tree(&head).unwrap();
        assert_eq!(tree.commit, head);
        assert!(tree.playbooks.join("deploy-x.yml").is_file());
        assert!(tree.root.join("ansible.cfg").is_file());
        assert!(!tree.root.join("README.md").exists(), "seulement Ansible/");
        assert_eq!(
            tree.root.file_name().unwrap().to_string_lossy().len(),
            DIR_NAME_LEN,
            "nom court : un sha de 40 caractères est caviardé dans les chemins"
        );

        let data = fx.tree.config().data_dir.canonicalize().unwrap();
        let is_link_to = |rel: &str, target: &Path| {
            std::fs::read_link(tree.root.join(rel)).is_ok_and(|t| t == target)
        };
        assert!(is_link_to("inventories/web3c_inventory.yml", &data.join("inventories/web3c_inventory.yml")));
        assert!(is_link_to("playbooks/group_vars/web3c.yml", &data.join("playbooks/group_vars/web3c.yml")));
        assert!(is_link_to("parcs/web3c", &data.join("parcs/web3c")), "dossier lié en entier");
        assert!(is_link_to("keys/web3c", &data.join("keys/web3c")));
        assert!(tree.root.join("parcs/web3c/nginx/site.conf").is_file(), "lisible à travers le lien");

        // Une donnée livrée depuis paraît au prochain usage ; une retirée disparaît.
        write(&data.join("playbooks/host_vars/infra1.yml"), "x: 1\n");
        std::fs::remove_file(data.join("playbooks/group_vars/web3c.yml")).unwrap();
        fx.tree.exec_tree(&head).unwrap();
        assert!(tree.root.join("playbooks/host_vars/infra1.yml").is_file());
        assert!(std::fs::symlink_metadata(tree.root.join("playbooks/group_vars/web3c.yml")).is_err());
    }

    #[test]
    fn code_files_win_over_data_files_at_the_same_path() {
        let fx = Fixture::new("conflict");
        write(&fx.tree.config().data_dir.join("ansible.cfg"), "[defaults]\nevil = 1\n");
        let tree = fx.tree.exec_tree(&fx.tree.head().unwrap()).unwrap();
        assert_eq!(std::fs::read_to_string(tree.root.join("ansible.cfg")).unwrap(), "[defaults]\n");
    }

    #[test]
    fn symlinks_leaving_the_commit_are_dropped_at_extraction() {
        let fx = Fixture::new("escape");
        let outside = fx.root.join("secret.txt");
        write(&outside, "secret");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, fx.origin.join("Ansible/playbooks/abs")).unwrap();
            std::os::unix::fs::symlink("../../../secret.txt", fx.origin.join("Ansible/playbooks/rel")).unwrap();
            std::os::unix::fs::symlink("deploy-x.yml", fx.origin.join("Ansible/playbooks/inner")).unwrap();
        }
        git(&fx.origin, &["add", "-A"]);
        git(&fx.origin, &["commit", "-q", "-m", "links"]);
        fx.tree.sync("web3c", None, None).unwrap();
        let tree = fx.tree.exec_tree(&fx.tree.head().unwrap()).unwrap();
        assert!(std::fs::symlink_metadata(tree.playbooks.join("abs")).is_err());
        assert!(std::fs::symlink_metadata(tree.playbooks.join("rel")).is_err());
        assert!(tree.playbooks.join("inner").is_symlink(), "un lien interne reste");
    }

    #[test]
    fn the_cache_keeps_n_trees_but_never_the_head_or_a_pinned_one() {
        let fx = Fixture::new("prune");
        let mut shas = vec![fx.tree.head().unwrap()];
        for i in 0..4 {
            shas.push(fx.commit_on_origin(&format!("Ansible/playbooks/deploy-{i}.yml"), "---\n"));
        }
        fx.tree.sync("web3c", None, None).unwrap();
        let head = fx.tree.head().unwrap();
        assert_eq!(&head, shas.last().unwrap());

        let pin = fx.tree.pin(&shas[0]);
        for sha in &shas {
            fx.tree.exec_tree(sha).unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        let cached = fx.tree.cached();
        assert!(cached.contains(&head), "la tête reste");
        assert!(cached.contains(&shas[0]), "un arbre retenu reste : {cached:?}");
        assert!(cached.len() <= 2 + 2, "keep=2, plus la tête et l'arbre retenu : {cached:?}");
        assert!(cached.len() < shas.len(), "le cache a été nettoyé : {cached:?}");
        drop(pin);
        fx.tree.exec_tree(&head).unwrap();
        assert!(fx.tree.cached().len() <= 2, "{:?}", fx.tree.cached());
        // Les données du parc n'ont pas été touchées par les nettoyages.
        assert!(fx.tree.config().data_dir.join("parcs/web3c/nginx/site.conf").is_file());
    }

    #[test]
    fn an_unknown_commit_is_refused_without_touching_the_network() {
        let fx = Fixture::new("unknown");
        let ghost = CommitSpec::Sha("0".repeat(40));
        let err = fx.tree.resolve_commit("web3c", Some(&ghost)).unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::UnknownCommit));
        let err = fx.tree.exec_tree("nope").unwrap_err();
        assert_eq!(kind_of(&err), Some(FaultKind::InvalidArgument));
    }

    #[test]
    fn a_missing_clone_is_a_configuration_fault() {
        let root = scratch("noclone");
        let cfg = GitTreeConfig::new(root.join("none"), root.join("data"), root.join("trees"), "main");
        let tree = GitTree::new(cfg).unwrap();
        assert_eq!(kind_of(&tree.head().unwrap_err()), Some(FaultKind::NotConfigured));
        assert_eq!(kind_of(&tree.sync("web3c", None, None).unwrap_err()), Some(FaultKind::NotConfigured));
    }

    #[test]
    fn key_paths_cannot_smuggle_shell_syntax() {
        let mut cfg = GitTreeConfig::new("c".into(), "d".into(), "t".into(), "main");
        cfg.deploy_key = Some("/k/it's".into());
        assert!(GitTree::new(cfg.clone()).is_err());
        cfg.deploy_key = Some("/k/id; rm -rf x\n".into());
        assert!(GitTree::new(cfg).is_err());
    }

    // --- dépôt distant NU (comme un projet GitLab ou GitHub) ---

    /// Dépôt distant nu, copie de travail pour y pousser, et clone de FleetForge.
    struct Remote {
        root: PathBuf,
        bare: PathBuf,
        work: PathBuf,
        tree: Arc<GitTree>,
    }

    impl Remote {
        fn new(name: &str, keep: usize) -> Self {
            let root = scratch(name);
            let bare = root.join("remote.git");
            std::fs::create_dir_all(&bare).unwrap();
            git(&bare, &["init", "-q", "--bare", "-b", "main"]);

            let work = root.join("work");
            let out = Command::new("git")
                .args(["clone", "-q"])
                .arg(&bare)
                .arg(&work)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            git(&work, &["checkout", "-q", "-b", "main"]);
            write(&work.join("Ansible/playbooks/deploy-x.yml"), "---\n- hosts: all\n  tasks: []\n");
            write(&work.join("Ansible/ansible.cfg"), "[defaults]\n");
            git(&work, &["add", "-A"]);
            git(&work, &["commit", "-q", "-m", "first"]);
            git(&work, &["push", "-q", "origin", "main"]);

            let clone = root.join("ansible-git");
            let out = Command::new("git")
                .args(["clone", "-q", "--no-checkout", "--branch", "main"])
                .arg(&bare)
                .arg(&clone)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            let data = root.join("ansible-data");
            write(&data.join("inventories/web3c_inventory.yml"), "all: {}\n");
            let mut cfg = GitTreeConfig::new(clone, data, root.join("ansible-trees"), "main");
            cfg.keep = keep;
            let tree = GitTree::new(cfg).unwrap();
            Self { root, bare, work, tree }
        }

        /// Commit sur la branche donnée de la copie de travail, poussé.
        fn commit(&self, branch: &str, file: &str) -> String {
            git(&self.work, &["checkout", "-q", branch]);
            write(&self.work.join(file), "---\n");
            git(&self.work, &["add", "-A"]);
            git(&self.work, &["commit", "-q", "-m", file]);
            git(&self.work, &["push", "-q", "origin", branch]);
            git(&self.work, &["rev-parse", "HEAD"])
        }

        /// Nouvelle branche issue de `main`, avec un commit, poussée.
        fn branch(&self, name: &str, file: &str) -> String {
            git(&self.work, &["checkout", "-q", "-b", name, "main"]);
            git(&self.work, &["push", "-q", "origin", name]);
            self.commit(name, file)
        }

        fn delete_remote_branch(&self, name: &str) {
            git(&self.work, &["push", "-q", "origin", "--delete", name]);
        }

        fn local_infra_refs(&self) -> Vec<String> {
            let out = git(
                &self.tree.config().clone_dir,
                &["for-each-ref", "--format=%(refname)", "refs/remotes/origin/infra", "refs/heads/infra"],
            );
            out.lines().map(String::from).collect()
        }
    }

    impl Drop for Remote {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn a_merge_commit_on_the_followed_branch_is_a_plain_fast_forward() {
        // GitLab (méthode de fusion « commit de fusion ») crée un commit de
        // fusion à chaque merge request : la tête de la branche suivie avance
        // vers un descendant de l'ancienne, exactement comme une avance rapide.
        let rm = Remote::new("merge-commit", 5);
        let sha = |s: &str| CommitSpec::Sha(s.to_string());
        let fix = rm.branch("infra/web3c/fix1", "Ansible/playbooks/deploy-fix.yml");
        // `main` avance entre-temps : la fusion est une vraie fusion à deux parents.
        let main2 = rm.commit("main", "Ansible/playbooks/deploy-main2.yml");
        let synced = rm.tree.sync("web3c", None, None).unwrap();
        assert_eq!(synced.head, main2);
        let out = rm.tree.sync("web3c", None, Some("infra/web3c/fix1")).unwrap();
        assert_eq!(out.commit, fix);
        assert_eq!(out.head, main2, "la branche suivie n'a pas bougé");

        // La fusion, puis suppression de la branche source (option GitLab).
        git(&rm.work, &["checkout", "-q", "main"]);
        git(&rm.work, &["merge", "-q", "--no-ff", "-m", "Merge branch infra/web3c/fix1", "infra/web3c/fix1"]);
        git(&rm.work, &["push", "-q", "origin", "main"]);
        rm.delete_remote_branch("infra/web3c/fix1");
        let merge = git(&rm.work, &["rev-parse", "HEAD"]);
        assert_eq!(git(&rm.work, &["rev-list", "--parents", "-n1", &merge]).split(' ').count(), 3, "deux parents");

        // `sync_tree` sur la branche suivie : tête = commit de fusion, sans erreur.
        let out = rm.tree.sync("web3c", None, None).unwrap();
        assert_eq!((out.commit.as_str(), out.head.as_str()), (merge.as_str(), merge.as_str()));
        assert_eq!(rm.tree.head().unwrap(), merge);
        // Rejouer ne change rien.
        assert_eq!(rm.tree.sync("web3c", None, None).unwrap().head, merge);

        // Le commit du correctif reste exécutable : il est désormais atteignable
        // de la branche suivie, la branche source étant supprimée.
        assert_eq!(rm.tree.resolve_commit("web3c", Some(&sha(&fix))).unwrap(), fix);
        let tree = rm.tree.exec_tree(&merge).unwrap();
        assert!(tree.playbooks.join("deploy-fix.yml").is_file());
        assert!(tree.playbooks.join("deploy-main2.yml").is_file());

        // La référence orpheline part au nettoyage, sans toucher à la permission
        // acquise par la fusion.
        let report = rm.tree.prune_orphans().unwrap();
        assert_eq!(report.refs_removed, vec!["refs/remotes/origin/infra/web3c/fix1".to_string()]);
        assert!(rm.local_infra_refs().is_empty());
        assert_eq!(rm.tree.resolve_commit("web3c", Some(&sha(&fix))).unwrap(), fix);
    }

    #[test]
    fn a_squash_or_rebase_merge_is_a_fast_forward_too() {
        let rm = Remote::new("squash", 5);
        let first = rm.tree.head().unwrap();
        rm.branch("infra/web3c/fix2", "Ansible/playbooks/deploy-fix.yml");
        // Fusion « squash » : un seul commit sur main, sans lien avec la branche.
        let squashed = rm.commit("main", "Ansible/playbooks/deploy-fix.yml");
        let out = rm.tree.sync("web3c", None, None).unwrap();
        assert_eq!(out.head, squashed);
        assert_ne!(out.head, first);
    }

    #[test]
    fn orphan_infra_refs_are_pruned_and_only_those() {
        let rm = Remote::new("orphans", 5);
        let keep = rm.branch("infra/web3c/keep", "Ansible/playbooks/deploy-keep.yml");
        let gone = rm.branch("infra/web3c/gone", "Ansible/playbooks/deploy-gone.yml");
        let other = rm.branch("infra/papanglabs/x", "Ansible/playbooks/deploy-other.yml");
        git(&rm.work, &["checkout", "-q", "main"]);

        rm.tree.sync("web3c", None, Some("infra/web3c/keep")).unwrap();
        rm.tree.sync("web3c", None, Some("infra/web3c/gone")).unwrap();
        // Une branche locale de même famille, laissée par un geste manuel.
        let clone = rm.tree.config().clone_dir.clone();
        git(&clone, &["update-ref", "refs/heads/infra/web3c/manual", &keep]);
        assert_eq!(rm.local_infra_refs().len(), 3);

        assert_eq!(
            rm.tree.prune_orphans().unwrap().refs_removed,
            vec!["refs/heads/infra/web3c/manual".to_string()],
            "la branche locale sans équivalent distant est la seule orpheline"
        );
        rm.delete_remote_branch("infra/web3c/gone");
        let report = rm.tree.prune_orphans().unwrap();
        assert_eq!(report.refs_removed, vec!["refs/remotes/origin/infra/web3c/gone".to_string()]);
        assert_eq!(report.refs_error, None);
        assert_eq!(rm.local_infra_refs(), vec!["refs/remotes/origin/infra/web3c/keep".to_string()]);

        // La branche supprimée n'est plus permise ; celle qui reste l'est.
        let sha = |s: &String| CommitSpec::Sha(s.clone());
        assert!(rm.tree.resolve_commit("web3c", Some(&sha(&gone))).is_err());
        assert_eq!(rm.tree.resolve_commit("web3c", Some(&sha(&keep))).unwrap(), keep);

        // Le nettoyage ne télécharge rien : la branche d'un autre parc, jamais
        // récupérée ici, n'est pas entrée dans le clone.
        assert!(!rm.tree.has_commit(&other).unwrap());
        // Ni la branche suivie ni sa tête ne bougent.
        assert_eq!(rm.tree.head().unwrap(), git(&rm.bare, &["rev-parse", "main"]));
    }

    #[test]
    fn nothing_is_pruned_when_the_remote_cannot_be_read() {
        let rm = Remote::new("unreachable", 5);
        rm.branch("infra/web3c/keep", "Ansible/playbooks/deploy-keep.yml");
        rm.tree.sync("web3c", None, Some("infra/web3c/keep")).unwrap();
        let clone = rm.tree.config().clone_dir.clone();
        git(&clone, &["remote", "set-url", "origin", rm.root.join("absent.git").to_str().unwrap()]);

        let report = rm.tree.prune_orphans().unwrap();
        assert!(report.refs_removed.is_empty(), "{report:?}");
        assert!(report.refs_error.is_some(), "l'échec est rapporté");
        assert_eq!(rm.local_infra_refs(), vec!["refs/remotes/origin/infra/web3c/keep".to_string()]);
    }

    #[test]
    fn the_cleanup_trims_the_tree_cache_down_to_its_size() {
        let rm = Remote::new("trees", 5);
        let mut shas = vec![rm.tree.head().unwrap()];
        for i in 0..4 {
            shas.push(rm.commit("main", &format!("Ansible/playbooks/deploy-{i}.yml")));
        }
        rm.tree.sync("web3c", None, None).unwrap();
        for sha in &shas {
            rm.tree.exec_tree(sha).unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(rm.tree.cached().len(), 5);

        // Le même clone, relu avec un cache plus petit (réglage changé, redémarrage).
        let mut cfg = rm.tree.config().clone();
        cfg.keep = 2;
        let smaller = GitTree::new(cfg).unwrap();
        let pin = smaller.pin(&shas[0]);
        let report = smaller.prune_orphans().unwrap();
        let cached = smaller.cached();
        assert!(cached.contains(shas.last().unwrap()), "la tête reste : {cached:?}");
        assert!(cached.contains(&shas[0]), "un arbre retenu reste : {cached:?}");
        assert_eq!(report.trees_removed, 5 - cached.len());
        assert!(cached.len() <= 3, "keep=2 plus l'arbre retenu : {cached:?}");
        drop(pin);
        // Les données du parc ne sont pas touchées.
        assert!(smaller.config().data_dir.join("inventories/web3c_inventory.yml").is_file());
    }

    #[test]
    fn the_cleanup_without_a_clone_is_a_configuration_fault() {
        let root = scratch("prune-noclone");
        let cfg = GitTreeConfig::new(root.join("none"), root.join("data"), root.join("trees"), "main");
        let tree = GitTree::new(cfg).unwrap();
        assert_eq!(kind_of(&tree.prune_orphans().unwrap_err()), Some(FaultKind::NotConfigured));
    }

    #[test]
    fn ssh_uses_the_pinned_known_hosts_and_never_trusts_a_new_key() {
        // Fournisseur quelconque (GitHub, gitlab.com, GitLab auto-hébergé, port
        // personnalisé) : la clé d'hôte attendue est celle du fichier posé par le
        // rôle ; le port, lui, vient de l'URL du dépôt, pas d'ici.
        let mut cfg = GitTreeConfig::new("c".into(), "d".into(), "t".into(), "main");
        cfg.deploy_key = Some("/k/id".into());
        cfg.known_hosts = Some("/k/known".into());
        let tree = GitTree::new(cfg).unwrap();
        let cmd = tree.command(true).unwrap();
        let ssh = cmd
            .get_envs()
            .find(|(k, _)| *k == "GIT_SSH_COMMAND")
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().to_string()))
            .expect("GIT_SSH_COMMAND");
        assert!(ssh.contains("-i '/k/id'") && ssh.contains("IdentitiesOnly=yes") && ssh.contains("BatchMode=yes"));
        assert!(ssh.contains("UserKnownHostsFile=/k/known") && ssh.contains("StrictHostKeyChecking=yes"), "{ssh}");
        assert!(!ssh.contains("accept-new"));
        // Hors réseau, pas de ssh du tout.
        assert!(tree.command(false).unwrap().get_envs().all(|(k, _)| k != "GIT_SSH_COMMAND"));
    }
}
