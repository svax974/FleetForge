/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Lecture du CODE de l'arbre Ansible (`read_tree`, `search_tree`,
//! `describe_playbook`) — jamais des données de parc.
//!
//! Ces lectures partent chez le fournisseur d'un modèle. Une seule
//! règle les gouverne : ce qui est lu est du code public du dépôt, sous
//! `playbooks/`. Tout le reste est refusé, et le refus se décide sur le chemin
//! RÉEL (canonique) du fichier, pas sur celui qu'on a demandé :
//!   • la demande est une chaîne relative, sans `..`, sans `/` initial, sans
//!     composante cachée ;
//!   • aucune composante (du chemin demandé comme du chemin réel) ne porte le
//!     nom d'un dossier de données — `inventories`, `group_vars`, `host_vars`,
//!     `keys`, `parcs`, `.private`, `.git` ;
//!   • le chemin réel reste SOUS `playbooks/` de l'arbre : un lien qui
//!     sortirait (vers `.private`, vers `ansible-data/`, vers `/etc`) est
//!     refusé ;
//!   • un fichier chiffré par ansible-vault (`$ANSIBLE_VAULT`), un fichier de
//!     clé ou de certificat (extension, nom), un fichier livré à la demande
//!     parce qu'il porte une donnée de parc (`private_files`) sont refusés ;
//!   • un fichier lu fait au plus [`MAX_FILE_BYTES`], en UTF-8.
//! Les listes et les recherches OMETTENT ces entrées sans le dire : on ne
//! confirme pas leur existence.

use crate::fault::{fail, FaultKind};
use anyhow::Result;
use serde::Serialize;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// Taille maximale d'un fichier rendu par `read_tree`.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;
/// Entrées rendues au plus pour un dossier.
pub const MAX_ENTRIES: usize = 500;
/// Résultats de `search_tree`.
pub const MAX_HITS: usize = 100;
/// Longueur d'une ligne de résultat de recherche, en caractères.
pub const MAX_HIT_CHARS: usize = 300;
/// Longueur du motif de recherche.
pub const MAX_PATTERN: usize = 200;
/// Un fichier plus gros n'est pas parcouru par la recherche ni par l'analyse.
pub const MAX_SCAN_BYTES: u64 = 1024 * 1024;
const MAX_SCAN_FILES: usize = 20_000;
const MAX_SCAN_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_DEPTH: usize = 24;

/// Noms de dossiers de données : refusés à tout niveau.
const DATA_NAMES: &[&str] = &["inventories", "group_vars", "host_vars", "keys", "parcs", ".private", ".git"];
/// Extensions de fichiers de clés, de certificats privés, de coffres.
const SECRET_EXTENSIONS: &[&str] =
    &["pem", "key", "p12", "pfx", "jks", "kdbx", "gpg", "age", "vault", "dump", "keystore", "ppk"];
/// Noms de fichiers de secrets usuels.
const SECRET_NAMES: &[&str] = &["htpasswd", "vault-pass", "vault_pass", "authorized_keys", "known_hosts"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    /// Octets, pour un fichier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Ce que `read_tree` rend.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TreeRead {
    File {
        path: String,
        size: u64,
        content: String,
    },
    Dir {
        path: String,
        entries: Vec<DirEntry>,
        /// Plus d'entrées que [`MAX_ENTRIES`].
        truncated: bool,
    },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hit {
    pub path: String,
    pub line: usize,
    pub text: String,
}

/// Lecteur de l'arbre : une racine, et ce qu'il refuse d'y lire.
#[derive(Debug, Clone)]
pub struct TreeReader {
    /// Racine canonique de l'arbre Ansible.
    root: PathBuf,
    /// `<racine>/playbooks`, canonique.
    playbooks: PathBuf,
    /// Chemins (relatifs à la racine) de fichiers livrés avec l'arbre mais
    /// qui portent des données de parc (`ff_ansible_extra_files`).
    private: Vec<PathBuf>,
}

fn component_is_data(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    DATA_NAMES.contains(&lower.as_str())
}

fn file_name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SECRET_NAMES.contains(&lower.as_str()) || lower.starts_with("id_") || lower.starts_with("vault-pass") {
        return true;
    }
    Path::new(&lower)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SECRET_EXTENSIONS.contains(&e))
}

/// Début d'un fichier chiffré par ansible-vault.
fn has_vault_header(path: &Path) -> bool {
    let mut head = [0u8; 15];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| &head == b"$ANSIBLE_VAULT;")
}

fn refused(message: impl Into<String>) -> anyhow::Error {
    crate::fault::Fault::new(FaultKind::PathRefused, message).into()
}

fn unknown(path: &str) -> anyhow::Error {
    crate::fault::Fault::new(FaultKind::UnknownPath, format!("chemin absent de l'arbre : {path}")).into()
}

/// Valide la FORME d'un chemin demandé et le rend sous forme de composantes
/// relatives à `playbooks/`. `playbooks/…` et `…` sont équivalents ; `""`,
/// `.` et `playbooks` désignent le dossier lui-même.
pub fn validate_request(path: &str) -> Result<Vec<String>> {
    if path.len() > 512 || path.chars().any(|c| c.is_control() || c == '\\') {
        return Err(refused("chemin invalide"));
    }
    if path.starts_with('/') || path.starts_with('~') {
        return Err(refused("chemin absolu refusé : un chemin relatif à playbooks/ est attendu"));
    }
    let mut parts: Vec<String> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => return Err(refused("`..` refusé")),
            p if p.starts_with('.') => return Err(refused(format!("composante cachée refusée : {p}"))),
            p if component_is_data(p) => {
                return Err(refused(format!("`{p}` est une donnée de parc : hors de ce que cet outil lit")))
            }
            p => parts.push(p.to_string()),
        }
    }
    if parts.first().is_some_and(|p| p == "playbooks") {
        parts.remove(0);
    }
    Ok(parts)
}

impl TreeReader {
    /// `root` : racine de l'arbre Ansible (le dossier qui porte `playbooks/`).
    /// `private_files` : chemins relatifs à `root` à ne jamais lire.
    pub fn new(root: &Path, private_files: &[String]) -> Result<Self> {
        let root = root.canonicalize().map_err(|e| {
            crate::fault::Fault::new(FaultKind::NotConfigured, format!("arbre Ansible illisible ({}) : {e}", root.display()))
        })?;
        let playbooks = root.join("playbooks").canonicalize().map_err(|_| {
            crate::fault::Fault::new(FaultKind::NotConfigured, "l'arbre Ansible n'a pas de dossier playbooks/")
        })?;
        let private = private_files
            .iter()
            .map(|p| p.trim().trim_start_matches("./"))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .collect();
        Ok(Self { root, playbooks, private })
    }

    pub fn playbooks_dir(&self) -> &Path {
        &self.playbooks
    }

    /// Chemin réel d'un chemin DÉJÀ validé, et contrôle de ce qu'il est.
    fn resolve(&self, parts: &[String], shown: &str) -> Result<PathBuf> {
        let candidate = parts.iter().fold(self.playbooks.clone(), |p, c| p.join(c));
        let real = candidate.canonicalize().map_err(|_| unknown(shown))?;
        self.check_real(&real, shown)?;
        Ok(real)
    }

    /// Le chemin RÉEL est-il lisible ?
    fn check_real(&self, real: &Path, shown: &str) -> Result<()> {
        let Ok(relative) = real.strip_prefix(&self.playbooks) else {
            return Err(refused(format!("{shown} : hors de l'arbre playbooks/ (lien sortant)")));
        };
        for component in relative.components() {
            let Component::Normal(name) = component else { return Err(refused(format!("{shown} : chemin invalide"))) };
            let name = name.to_string_lossy();
            if name.starts_with('.') || component_is_data(&name) {
                return Err(refused(format!("{shown} : donnée de parc ou fichier caché")));
            }
        }
        if let Ok(from_root) = real.strip_prefix(&self.root) {
            if self.private.iter().any(|p| p == from_root) {
                return Err(refused(format!("{shown} : fichier livré avec une donnée de parc")));
            }
        }
        if real.is_file() {
            if real.file_name().is_some_and(|n| file_name_is_secret(&n.to_string_lossy())) {
                return Err(refused(format!("{shown} : fichier de secret ou de clé")));
            }
            if has_vault_header(real) {
                return Err(refused(format!("{shown} : fichier chiffré (ansible-vault)")));
            }
        }
        Ok(())
    }

    /// Le chemin d'une entrée de l'arbre (déjà réel) relatif à `playbooks/`,
    /// pour l'affichage.
    fn shown(&self, real: &Path) -> String {
        real.strip_prefix(&self.playbooks)
            .map(|p| format!("playbooks/{}", p.to_string_lossy()))
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_string()
    }

    /// `read_tree` : un fichier (≤ 64 Kio, UTF-8) ou un dossier.
    pub fn read(&self, path: &str) -> Result<TreeRead> {
        let parts = validate_request(path)?;
        let real = self.resolve(&parts, path)?;
        let shown = self.shown(&real);
        let shown = if shown.is_empty() { "playbooks".to_string() } else { shown };
        if real.is_dir() {
            let (entries, truncated) = self.list(&real);
            return Ok(TreeRead::Dir { path: shown, entries, truncated });
        }
        let size = std::fs::metadata(&real).map(|m| m.len()).map_err(|_| unknown(path))?;
        if size > MAX_FILE_BYTES {
            return fail(
                FaultKind::InvalidArgument,
                format!("{shown} : {size} octets, au-delà de {MAX_FILE_BYTES} (non lisible par cet outil)"),
            );
        }
        let bytes = std::fs::read(&real).map_err(|_| unknown(path))?;
        let content = String::from_utf8(bytes)
            .ok()
            .filter(|t| !t.contains('\0'))
            .ok_or_else(|| refused(format!("{shown} : fichier binaire")))?;
        Ok(TreeRead::File { path: shown, size, content })
    }

    /// Entrées lisibles d'un dossier réel ; les autres sont omises.
    fn list(&self, dir: &Path) -> (Vec<DirEntry>, bool) {
        let mut entries = Vec::new();
        let Ok(read) = std::fs::read_dir(dir) else { return (entries, false) };
        let mut names: Vec<PathBuf> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        names.sort();
        let mut truncated = false;
        for path in names {
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else { continue };
            // Le chemin RÉEL de l'entrée (un lien se juge sur sa cible).
            let Ok(real) = path.canonicalize() else { continue };
            if name.starts_with('.') || component_is_data(&name) || self.check_real(&real, &name).is_err() {
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                truncated = true;
                break;
            }
            if real.is_dir() {
                entries.push(DirEntry { name, kind: EntryKind::Dir, size: None });
            } else if real.is_file() {
                let size = std::fs::metadata(&real).map(|m| m.len()).ok();
                entries.push(DirEntry { name, kind: EntryKind::File, size });
            }
        }
        (entries, truncated)
    }

    /// Fichier texte lisible, jusqu'à `max` octets, pour l'analyse interne
    /// (`describe_playbook`) : mêmes refus que `read`, sans la borne de 64 Kio
    /// du rendu. `None` quand il est refusé, absent, trop gros ou binaire.
    pub fn read_text(&self, relative_to_playbooks: &Path, max: u64) -> Option<String> {
        let parts: Vec<String> = relative_to_playbooks
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => Some(n.to_string_lossy().to_string()),
                _ => None,
            })
            .collect();
        let candidate = parts.iter().fold(self.playbooks.clone(), |p, c| p.join(c));
        let real = candidate.canonicalize().ok()?;
        self.check_real(&real, "").ok()?;
        if !real.is_file() || std::fs::metadata(&real).ok()?.len() > max {
            return None;
        }
        String::from_utf8(std::fs::read(real).ok()?).ok().filter(|t| !t.contains('\0'))
    }

    /// NOMS des variables que les group_vars / host_vars de l'arbre déclarent
    /// (clés de premier niveau) — jamais leurs valeurs, qui ne sortent pas de
    /// ce module. Un fichier chiffré en entier n'en donne aucun.
    pub fn parc_var_names(&self) -> std::collections::BTreeSet<String> {
        fn keys_of(path: &Path, out: &mut std::collections::BTreeSet<String>) {
            let Ok(meta) = std::fs::metadata(path) else { return };
            if !meta.is_file() || meta.len() > MAX_SCAN_BYTES || has_vault_header(path) {
                return;
            }
            let Ok(text) = std::fs::read_to_string(path) else { return };
            if let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
                out.extend(map.keys().filter_map(|k| k.as_str().map(String::from)));
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for kind in ["group_vars", "host_vars"] {
            let Ok(read) = std::fs::read_dir(self.playbooks.join(kind)) else { continue };
            for entry in read.filter_map(|e| e.ok()).take(500) {
                let path = entry.path();
                if path.is_dir() {
                    if let Ok(inner) = std::fs::read_dir(&path) {
                        inner.filter_map(|e| e.ok()).take(50).for_each(|e| keys_of(&e.path(), &mut names));
                    }
                } else {
                    keys_of(&path, &mut names);
                }
            }
        }
        names
    }

    /// Un dossier existe-t-il (et se lit-il) sous `playbooks/` ?
    pub fn dir_exists(&self, relative_to_playbooks: &Path) -> bool {
        let candidate = self.playbooks.join(relative_to_playbooks);
        candidate.canonicalize().is_ok_and(|real| real.is_dir() && self.check_real(&real, "").is_ok())
    }

    /// `search_tree` : texte FIXE (sensible à la casse), au plus
    /// [`MAX_HITS`] résultats, sur les fichiers lisibles de `playbooks/`.
    /// Rend aussi `true` quand la limite (de résultats, de fichiers ou
    /// d'octets parcourus) a coupé la recherche.
    pub fn search(&self, pattern: &str) -> Result<(Vec<Hit>, bool)> {
        if pattern.is_empty() || pattern.chars().count() > MAX_PATTERN || pattern.chars().any(|c| c == '\0' || c == '\n' || c == '\r') {
            return fail(
                FaultKind::InvalidArgument,
                format!("motif de recherche invalide : 1 à {MAX_PATTERN} caractères, sur une ligne"),
            );
        }
        let mut hits = Vec::new();
        let mut budget = Budget { files: 0, bytes: 0, cut: false };
        self.search_dir(&self.playbooks.clone(), pattern, &mut hits, &mut budget, 0);
        let truncated = budget.cut || hits.len() >= MAX_HITS;
        Ok((hits, truncated))
    }

    fn search_dir(&self, dir: &Path, pattern: &str, hits: &mut Vec<Hit>, budget: &mut Budget, depth: usize) {
        if depth > MAX_DEPTH || budget.cut || hits.len() >= MAX_HITS {
            return;
        }
        let Ok(read) = std::fs::read_dir(dir) else { return };
        let mut paths: Vec<PathBuf> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        paths.sort();
        for path in paths {
            if budget.cut || hits.len() >= MAX_HITS {
                return;
            }
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else { continue };
            if name.starts_with('.') || component_is_data(&name) {
                continue;
            }
            // Un lien de dossier n'est jamais suivi (pas de boucle, pas de
            // sortie) ; un lien de fichier se juge sur sa cible.
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() && path.is_dir() {
                continue;
            }
            if meta.is_dir() {
                self.search_dir(&path, pattern, hits, budget, depth + 1);
                continue;
            }
            let Ok(real) = path.canonicalize() else { continue };
            if self.check_real(&real, &name).is_err() {
                continue;
            }
            let Ok(size) = std::fs::metadata(&real).map(|m| m.len()) else { continue };
            if size > MAX_SCAN_BYTES {
                continue;
            }
            budget.files += 1;
            budget.bytes += size;
            if budget.files > MAX_SCAN_FILES || budget.bytes > MAX_SCAN_TOTAL {
                budget.cut = true;
                return;
            }
            let Ok(bytes) = std::fs::read(&real) else { continue };
            let Ok(text) = String::from_utf8(bytes) else { continue };
            if text.contains('\0') {
                continue;
            }
            let shown = self.shown(&real);
            for (index, line) in text.lines().enumerate() {
                if line.contains(pattern) {
                    hits.push(Hit {
                        path: shown.clone(),
                        line: index + 1,
                        text: line.trim().chars().take(MAX_HIT_CHARS).collect(),
                    });
                    if hits.len() >= MAX_HITS {
                        return;
                    }
                }
            }
        }
    }
}

struct Budget {
    files: usize,
    bytes: u64,
    cut: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::kind_of;

    fn scratch(name: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ff-tree-{}-{name}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    /// Arbre factice : du code, des données, et des pièges.
    fn fixture(name: &str) -> (PathBuf, TreeReader) {
        let root = scratch(name);
        write(&root.join("ansible.cfg"), "[defaults]\nvault_password_file = ~/.config/fleetforge/vault-pass\n");
        write(&root.join("playbooks/deploy-x.yml"), "---\n- hosts: web\n  roles: [x-install]\n");
        write(&root.join("playbooks/roles/x-install/tasks/main.yml"), "---\n- name: Hello\n  debug: msg=needle\n");
        write(&root.join("playbooks/roles/x-install/files/keys/deploy.pub"), "ssh-ed25519 AAAA\n");
        write(&root.join("playbooks/roles/x-install/files/tls.key"), "-----BEGIN PRIVATE KEY-----\n");
        write(&root.join("playbooks/roles/x-install/files/id_ed25519"), "secret\n");
        write(&root.join("playbooks/roles/x-install/files/app.json"), "{\"secret\": \"s3cr3t\"}\n");
        write(&root.join("playbooks/group_vars/web3c.yml"), "needle: secret\n");
        write(&root.join("playbooks/host_vars/infra1.yml"), "needle: secret\n");
        write(&root.join("playbooks/.hidden.yml"), "needle\n");
        write(&root.join("inventories/web3c_inventory.yml"), "needle: inventory\n");
        write(&root.join("keys/web3c/id.pub"), "needle\n");
        write(&root.join("parcs/web3c/nginx.conf"), "needle\n");
        write(&root.join("playbooks/roles/vaulted/vars/main.yml"), "$ANSIBLE_VAULT;1.1;AES256\n6162\n");
        write(&root.join("playbooks/roles/vaulted/tasks/main.yml"), "---\n- debug: msg=needle\n");
        write(&root.join("playbooks/big.yml"), &format!("# {}\n", "x".repeat(70_000)));
        std::fs::write(root.join("playbooks/blob.bin"), [0u8, 159, 146, 150]).unwrap();
        write(&root.join("outside/secret.txt"), "needle outside\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(root.join("outside/secret.txt"), root.join("playbooks/abs-link")).unwrap();
            symlink("../outside/secret.txt", root.join("playbooks/rel-link")).unwrap();
            symlink("../../../playbooks/group_vars/web3c.yml", root.join("playbooks/roles/x-install/files/to-gv")).unwrap();
            symlink("../inventories", root.join("playbooks/inv-dir")).unwrap();
            symlink("deploy-x.yml", root.join("playbooks/alias.yml")).unwrap();
            symlink("../keys/web3c", root.join("playbooks/roles/x-install/files/linked-keys")).unwrap();
            symlink("..", root.join("playbooks/roles/x-install/loop")).unwrap();
        }
        let reader = TreeReader::new(&root, &["playbooks/roles/x-install/files/app.json".to_string()]).unwrap();
        (root, reader)
    }

    fn kind(e: anyhow::Error) -> Option<FaultKind> {
        kind_of(&e)
    }

    #[test]
    fn request_paths_are_relative_clean_and_visible() {
        assert_eq!(validate_request("playbooks/roles/x/tasks/main.yml").unwrap(), ["roles", "x", "tasks", "main.yml"]);
        assert_eq!(validate_request("roles/x").unwrap(), ["roles", "x"]);
        assert!(validate_request("").unwrap().is_empty());
        assert!(validate_request(".").unwrap().is_empty());
        assert!(validate_request("playbooks").unwrap().is_empty());
        assert_eq!(validate_request("./playbooks//deploy-x.yml").unwrap(), ["deploy-x.yml"]);
        for bad in [
            "..", "../x", "playbooks/../inventories", "roles/../../x", "/etc/passwd", "/playbooks/x", "~/x",
            "playbooks/group_vars/web3c.yml", "playbooks/host_vars", "inventories/web3c.yml", "keys", "parcs/web3c",
            "playbooks/GROUP_VARS/x.yml", "playbooks/roles/x/keys/id", ".private/x", "playbooks/.git/config",
            "playbooks/.hidden.yml", "a\\b", "a\0b", "a\nb", &"a/".repeat(300),
        ] {
            let err = validate_request(bad).unwrap_err();
            assert_eq!(kind(err), Some(FaultKind::PathRefused), "{bad:?}");
        }
    }

    #[test]
    fn a_code_file_and_a_directory_are_read() {
        let (_root, reader) = fixture("read");
        match reader.read("playbooks/deploy-x.yml").unwrap() {
            TreeRead::File { path, content, size } => {
                assert_eq!(path, "playbooks/deploy-x.yml");
                assert!(content.contains("x-install"));
                assert_eq!(size as usize, content.len());
            }
            other => panic!("{other:?}"),
        }
        // Avec ou sans le préfixe, même résultat.
        assert_eq!(reader.read("roles/x-install/tasks/main.yml").unwrap(), reader.read("playbooks/roles/x-install/tasks/main.yml").unwrap());
        match reader.read("").unwrap() {
            TreeRead::Dir { path, entries, truncated } => {
                assert_eq!(path, "playbooks");
                assert!(!truncated);
                let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
                assert!(names.contains(&"deploy-x.yml") && names.contains(&"roles"), "{names:?}");
                for hidden in ["group_vars", "host_vars", ".hidden.yml", "abs-link", "rel-link", "inv-dir", "big.yml", "blob.bin"] {
                    if hidden == "big.yml" || hidden == "blob.bin" {
                        continue; // listés (lisibles à la taille et au type près), refusés à la lecture
                    }
                    assert!(!names.contains(&hidden), "{hidden} ne doit pas apparaître : {names:?}");
                }
                assert!(names.contains(&"alias.yml"), "un lien interne se liste : {names:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_directory_listing_omits_secrets_without_saying_so() {
        let (_root, reader) = fixture("list");
        let TreeRead::Dir { entries, .. } = reader.read("roles/x-install/files").unwrap() else { panic!() };
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.is_empty(), "keys/, tls.key, id_ed25519, app.json (privé), liens sortants : {names:?}");
        let TreeRead::Dir { entries, .. } = reader.read("roles/vaulted").unwrap() else { panic!() };
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["tasks", "vars"], "`vars/` est listé, son fichier vault non");
        let TreeRead::Dir { entries, .. } = reader.read("roles/vaulted/vars").unwrap() else { panic!() };
        assert!(entries.is_empty(), "le fichier vault est omis");
    }

    #[test]
    fn symlinks_are_judged_on_their_real_target() {
        let (_root, reader) = fixture("links");
        for bad in [
            "abs-link", "rel-link", "roles/x-install/files/to-gv", "inv-dir", "inv-dir/web3c_inventory.yml",
            "roles/x-install/files/linked-keys", "roles/x-install/files/linked-keys/id.pub",
        ] {
            let err = reader.read(bad).unwrap_err();
            assert!(
                matches!(kind(err), Some(FaultKind::PathRefused | FaultKind::UnknownPath)),
                "{bad} doit être refusé"
            );
        }
        // Un lien interne à playbooks/ reste lisible.
        assert!(matches!(reader.read("alias.yml").unwrap(), TreeRead::File { .. }));
        // Un lien qui boucle sur son dossier : listé sans fin ni sortie.
        assert!(reader.read("roles/x-install/loop").is_ok());
    }

    #[test]
    fn vaults_secrets_private_files_and_binaries_are_refused() {
        let (_root, reader) = fixture("secrets");
        for (path, expected) in [
            ("roles/vaulted/vars/main.yml", FaultKind::PathRefused),
            ("roles/x-install/files/tls.key", FaultKind::PathRefused),
            ("roles/x-install/files/id_ed25519", FaultKind::PathRefused),
            ("roles/x-install/files/app.json", FaultKind::PathRefused),
            ("roles/x-install/files/keys/deploy.pub", FaultKind::PathRefused),
            ("blob.bin", FaultKind::PathRefused),
            ("big.yml", FaultKind::InvalidArgument),
            ("missing.yml", FaultKind::UnknownPath),
        ] {
            let err = reader.read(path).unwrap_err();
            assert_eq!(kind(err), Some(expected), "{path}");
        }
    }

    #[test]
    fn search_finds_fixed_text_in_readable_code_only() {
        let (_root, reader) = fixture("search");
        let (hits, truncated) = reader.search("needle").unwrap();
        assert!(!truncated);
        let paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        assert!(paths.contains(&"playbooks/roles/x-install/tasks/main.yml"), "{paths:?}");
        assert!(paths.contains(&"playbooks/roles/vaulted/tasks/main.yml"), "{paths:?}");
        for leak in ["group_vars", "host_vars", "inventories", "keys", "parcs", "outside", ".hidden", "abs-link", "rel-link"] {
            assert!(!paths.iter().any(|p| p.contains(leak)), "{leak} : {paths:?}");
        }
        assert_eq!(hits.iter().find(|h| h.path.ends_with("x-install/tasks/main.yml")).unwrap().line, 3);
        // Texte fixe : `.` et `*` ne sont pas des motifs.
        assert!(reader.search("need.e").unwrap().0.is_empty());
        for bad in ["", "a\nb", &"x".repeat(MAX_PATTERN + 1)] {
            assert_eq!(kind(reader.search(bad).unwrap_err()), Some(FaultKind::InvalidArgument), "{bad:?}");
        }
    }

    #[test]
    fn search_results_are_bounded() {
        let root = scratch("bounded");
        write(&root.join("playbooks/a.yml"), "x\n");
        let many: String = (0..300).map(|i| format!("hit {i} {}\n", "y".repeat(400))).collect();
        write(&root.join("playbooks/many.yml"), &many);
        let reader = TreeReader::new(&root, &[]).unwrap();
        let (hits, truncated) = reader.search("hit").unwrap();
        assert_eq!(hits.len(), MAX_HITS);
        assert!(truncated);
        assert!(hits.iter().all(|h| h.text.chars().count() <= MAX_HIT_CHARS));
    }

    #[test]
    fn internal_reads_follow_the_same_refusals() {
        let (_root, reader) = fixture("internal");
        assert!(reader.read_text(Path::new("deploy-x.yml"), MAX_SCAN_BYTES).is_some());
        assert!(reader.read_text(Path::new("big.yml"), 1000).is_none(), "borne de taille");
        for bad in ["group_vars/web3c.yml", "../inventories/web3c_inventory.yml", "abs-link", "roles/vaulted/vars/main.yml"] {
            assert!(reader.read_text(Path::new(bad), MAX_SCAN_BYTES).is_none(), "{bad}");
        }
        assert!(reader.dir_exists(Path::new("roles/x-install")));
        assert!(!reader.dir_exists(Path::new("group_vars")));
        assert!(!reader.dir_exists(Path::new("../keys")));
    }

    #[test]
    fn an_arbre_without_playbooks_is_not_configured() {
        let root = scratch("empty");
        assert_eq!(kind(TreeReader::new(&root, &[]).unwrap_err()), Some(FaultKind::NotConfigured));
        assert_eq!(kind(TreeReader::new(&root.join("nowhere"), &[]).unwrap_err()), Some(FaultKind::NotConfigured));
    }
}
