/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! `describe_playbook` : ce qu'un playbook fait, lu SANS l'exécuter.
//!
//! Analyse STATIQUE et au mieux du YAML du dépôt (jamais d'Ansible, jamais de
//! Jinja évalué), par le lecteur de l'arbre (`ansible_tree::TreeReader`) donc
//! sous ses refus : rien hors de `playbooks/`, aucune donnée de parc.
//!
//! Ce qui est résolu : les plays (y compris ceux d'un `import_playbook` de
//! nom statique), leurs rôles et les dépendances de rôles (`meta/main.yml`),
//! `include_role` / `import_role` / `include_tasks` / `import_tasks` dont le
//! nom ne contient pas de gabarit, les `tags` de chaque niveau (play, rôle
//! appelé, tâche, bloc, `apply:`). Ce qui ne l'est pas — un nom construit par
//! `{{ … }}` — est dit dans `notes`.
//!
//! `vars` : variables RÉFÉRENCÉES (`{{ x }}`, `when: x …`) sans `| default`,
//! que ni un défaut de rôle, ni un `vars:`/`register:`/`set_fact:`, ni une clé
//! de group_vars/host_vars de l'arbre (NOMS seulement, jamais les valeurs) ne
//! définit : ce que l'appelant devra probablement passer en `extra_vars`. Les
//! gabarits `.j2` ne sont pas lus. Une liste d'indices, pas une garantie.
//!
//! `needs_no_limit` : vrai quand un play vise des hôtes qu'un `--limit` sur
//! les cibles habituelles écarterait. Cibles habituelles = les motifs du
//! premier play qui n'est ni local (`localhost`, `connection: local`) ni
//! `run_once` ; un play suivant dont un motif positif (hors `localhost`,
//! `all`, `*` ou un motif construit par `{{ }}`) n'y figure pas est ignoré par
//! un `--limit` sur ces cibles (`deploy-fleetforge.yml` : `infras`, puis
//! `proxies` et `prometheus1:monitor`). Si les cibles habituelles sont `all`,
//! il n'y a rien à exclure : faux.

use crate::ansible_tree::{TreeReader, MAX_SCAN_BYTES};
use crate::fault::{fail, FaultKind};
use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use serde_yaml::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const MAX_FILES: usize = 400;
const MAX_DEPTH: usize = 12;
const MAX_VARS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PlayInfo {
    pub name: String,
    pub hosts: String,
    pub roles: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Description {
    pub plays: Vec<PlayInfo>,
    /// Union des étiquettes du playbook et des rôles qu'il appelle.
    pub tags: Vec<String>,
    pub vars: Vec<String>,
    pub needs_no_limit: bool,
    /// Playbooks importés (`import_playbook`), transitivement.
    pub imports: Vec<String>,
    /// Ce que l'analyse n'a pas pu résoudre.
    pub notes: Vec<String>,
}

#[derive(Default, Clone)]
struct Acc {
    tags: BTreeSet<String>,
    required: BTreeSet<String>,
    defined: BTreeSet<String>,
}

impl Acc {
    fn merge(&mut self, other: &Acc) {
        self.tags.extend(other.tags.iter().cloned());
        self.required.extend(other.required.iter().cloned());
        self.defined.extend(other.defined.iter().cloned());
    }
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("motif valide"))
}

fn jinja_block() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"(?s)\{\{(.*?)\}\}")
}

fn jinja_set() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"\{%-?\s*(?:set\s+([A-Za-z_]\w*)|for\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+in)\b")
}

const KEYWORDS: &[&str] = &[
    "and", "or", "not", "in", "is", "if", "else", "elif", "for", "true", "false", "none", "True", "False", "None",
    "defined", "undefined", "string", "number", "mapping", "iterable", "sequence", "boolean", "integer", "float",
    "callable", "sameas", "divisibleby", "equalto", "even", "odd", "lower", "upper", "match", "search", "regex",
    "contains", "subset", "superset", "success", "succeeded", "failed", "failure", "changed", "skipped", "skip",
    "reachable", "unreachable", "finished", "started", "version", "truthy", "falsy", "abs", "file", "directory",
    "link", "exists",
];

const MAGIC: &[&str] = &[
    "item", "loop", "omit", "hostvars", "groups", "group_names", "inventory_hostname", "inventory_hostname_short",
    "play_hosts", "playbook_dir", "role_path", "role_name", "inventory_dir", "inventory_file", "environment", "vars",
    "lookup", "query", "q", "now", "range", "dict", "lipsum", "cycler", "joiner", "namespace", "self", "caller",
    "varargs", "kwargs", "ansible_check_mode", "ansible_diff_mode", "ansible_play_hosts", "ansible_play_batch",
    "ansible_facts", "ansible_version", "ansible_loop", "ansible_loop_var", "ansible_index_var", "ansible_run_tags",
    "ansible_skip_tags", "ansible_limit",
];

/// Identificateurs de premier niveau d'une expression Jinja, avec : `Some(true)`
/// quand un `| default(…)` les suit (variable optionnelle), `Some(false)`
/// quand `is defined` / `is not defined` les suit (variable gardée).
fn expression_vars(expr: &str) -> Vec<(String, Option<bool>)> {
    // Chaînes littérales masquées : rien de ce qu'elles contiennent n'est une
    // variable.
    let mut masked = String::with_capacity(expr.len());
    let mut quote: Option<char> = None;
    for c in expr.chars() {
        match (quote, c) {
            (None, '\'' | '"') => {
                quote = Some(c);
                masked.push(' ');
            }
            (Some(q), c) if c == q => {
                quote = None;
                masked.push(' ');
            }
            (Some(_), _) => masked.push(' '),
            (None, c) => masked.push(c),
        }
    }
    let chars: Vec<char> = masked.chars().collect();
    let mut found = Vec::new();
    let (mut i, mut prev_word, mut prev_prev) = (0, String::new(), String::new());
    while i < chars.len() {
        let c = chars[i];
        if !(c.is_ascii_alphabetic() || c == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
            i += 1;
        }
        let ident: String = chars[start..i].iter().collect();
        let before = chars[..start].iter().rev().find(|c| !c.is_whitespace()).copied();
        let rest: String = chars[i..].iter().collect();
        let next = rest.trim_start().chars().next();
        let is_test = prev_word == "is" || (prev_word == "not" && prev_prev == "is");
        prev_prev = std::mem::replace(&mut prev_word, ident.clone());
        // Un chiffre précédent (`1e5`) ou un attribut (`a.b`) n'est pas une variable.
        if start > 0 && (chars[start - 1].is_ascii_digit() || chars[start - 1] == '.') {
            continue;
        }
        let keyword_arg = next == Some('=') && !rest.trim_start().starts_with("==");
        if before == Some('.')
            || before == Some('|')
            || next == Some('(')
            || is_test
            || keyword_arg
            || KEYWORDS.contains(&ident.as_str())
            || MAGIC.contains(&ident.as_str())
            || ident.starts_with("ansible_")
        {
            continue;
        }
        // Accesseurs puis filtre : `x.y['z'] | default(…)`.
        let after: String = rest
            .chars()
            .skip_while(|c| c.is_ascii_alphanumeric() || " ._[]".contains(*c))
            .collect();
        let verdict = if after.trim_start().starts_with('|') {
            let filter = after.trim_start()[1..].trim_start();
            (filter.starts_with("default") || filter.starts_with("d(")).then_some(true)
        } else {
            None
        };
        let guarded = {
            let t = rest.trim_start();
            let accessor_free = t.strip_prefix("is").map(str::trim_start);
            accessor_free.is_some_and(|r| r.starts_with("defined") || r.strip_prefix("not").is_some_and(|n| n.trim_start().starts_with("defined")))
        };
        found.push((ident, if guarded { Some(false) } else { verdict }));
    }
    found
}

/// Variables d'un texte : blocs `{{ … }}`, ou le texte entier quand c'est une
/// expression nue (`when:`, `assert.that`). `require_defined` : une garde
/// `is defined` y compte comme une EXIGENCE (assert).
fn collect_refs(text: &str, bare: bool, require_defined: bool, acc: &mut Acc) {
    for caps in jinja_set().captures_iter(text) {
        for g in [caps.get(1), caps.get(2)].into_iter().flatten() {
            acc.defined.extend(g.as_str().split(',').map(|s| s.trim().to_string()));
        }
    }
    let mut take = |expr: &str| {
        for (name, verdict) in expression_vars(expr) {
            match verdict {
                Some(true) => {}
                Some(false) if !require_defined => {}
                _ => {
                    acc.required.insert(name);
                }
            }
        }
    };
    if bare {
        take(text);
    }
    for caps in jinja_block().captures_iter(text) {
        take(&caps[1]);
    }
}

/// Texte d'un scalaire, quelle que soit sa forme YAML.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `tags:` d'un nœud : chaîne (éventuellement séparée par des virgules) ou
/// liste ; un nom construit par gabarit est ignoré.
fn tags_of(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: &str| {
        let s = s.trim();
        if !s.is_empty() && !s.contains("{{") && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
            out.push(s.to_string());
        }
    };
    match v {
        Value::String(s) => s.split(',').for_each(&mut push),
        Value::Sequence(items) => items.iter().filter_map(scalar).for_each(|s| s.split(',').for_each(&mut push)),
        _ => {}
    }
    out
}

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key)
}

/// Premier des noms `key` / `ansible.builtin.key` présent dans la tâche.
fn module<'a>(task: &'a Value, key: &str) -> Option<&'a Value> {
    get(task, key).or_else(|| get(task, &format!("ansible.builtin.{key}")))
}

fn is_static(name: &str) -> bool {
    !name.is_empty() && !name.contains("{{") && !name.contains("{%")
}

fn valid_role_name(name: &str) -> bool {
    is_static(name) && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) && !name.starts_with('.')
}

/// Chemin relatif simple (`a/b.yml`), sans `..` ni composante vide.
fn simple_relative(path: &str) -> Option<PathBuf> {
    if !is_static(path) || path.starts_with('/') || path.contains('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if !out.pop() {
                    return None;
                }
            }
            p => out.push(p),
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

struct Walker<'a> {
    reader: &'a TreeReader,
    files: usize,
    notes: BTreeSet<String>,
    stack: Vec<String>,
    cache: HashMap<String, Acc>,
    imports: Vec<String>,
}

impl<'a> Walker<'a> {
    fn load(&mut self, rel: &Path) -> Option<Value> {
        if self.files >= MAX_FILES {
            self.notes.insert("analyse interrompue : trop de fichiers".to_string());
            return None;
        }
        let text = self.reader.read_text(rel, MAX_SCAN_BYTES)?;
        self.files += 1;
        serde_yaml::from_str(&text).ok()
    }

    /// Premier de `candidates` qui existe et se lit comme du YAML.
    fn load_any(&mut self, candidates: &[PathBuf]) -> Option<(PathBuf, Value)> {
        for rel in candidates {
            if let Some(v) = self.load(rel) {
                return Some((rel.clone(), v));
            }
        }
        None
    }

    fn scan_tasks(&mut self, tasks: &Value, dir: &Path, role: Option<&str>, acc: &mut Acc, depth: usize) {
        let Value::Sequence(list) = tasks else { return };
        if depth > MAX_DEPTH {
            self.notes.insert("analyse interrompue : imbrication trop profonde".to_string());
            return;
        }
        for task in list {
            if matches!(task, Value::Mapping(_)) {
                self.scan_task(task, dir, role, acc, depth);
            }
        }
    }

    fn scan_task(&mut self, task: &Value, dir: &Path, role: Option<&str>, acc: &mut Acc, depth: usize) {
        if let Some(t) = get(task, "tags") {
            acc.tags.extend(tags_of(t));
        }
        for key in ["block", "rescue", "always"] {
            if let Some(inner) = get(task, key) {
                self.scan_tasks(inner, dir, role, acc, depth + 1);
            }
        }
        if let Some(Value::String(name)) = get(task, "register") {
            acc.defined.insert(name.clone());
        }
        if let Some(Value::Mapping(facts)) = module(task, "set_fact") {
            acc.defined.extend(facts.keys().filter_map(scalar).filter(|k| k != "cacheable"));
        }
        if let Some(Value::Mapping(vars)) = get(task, "vars") {
            acc.defined.extend(vars.keys().filter_map(scalar));
        }
        if let Some(Value::String(var)) = get(task, "loop_control").and_then(|c| get(c, "loop_var")) {
            acc.defined.insert(var.clone());
        }
        if let Value::Mapping(map) = task {
            if map.keys().filter_map(scalar).any(|k| k == "loop" || k.starts_with("with_")) {
                acc.defined.insert("item".to_string());
            }
        }

        // Inclusions de fichiers de tâches.
        for key in ["import_tasks", "include_tasks"] {
            let Some(target) = module(task, key) else { continue };
            let file = match target {
                Value::String(s) => Some(s.clone()),
                Value::Mapping(_) => get(target, "file").or_else(|| get(target, "_raw_params")).and_then(scalar),
                _ => None,
            };
            if let Some(apply) = get(target, "apply").and_then(|a| get(a, "tags")) {
                acc.tags.extend(tags_of(apply));
            }
            match file.as_deref().and_then(simple_relative) {
                Some(rel) => self.include_file(&rel, dir, role, acc, depth),
                None => {
                    self.notes.insert(format!("{key} non résolu (nom construit par gabarit ou chemin invalide)"));
                }
            }
        }
        // Inclusions de rôles.
        for key in ["import_role", "include_role"] {
            let Some(target) = module(task, key) else { continue };
            let name = get(target, "name").or_else(|| get(target, "role")).and_then(scalar);
            let from = get(target, "tasks_from").and_then(scalar).unwrap_or_else(|| "main".to_string());
            if let Some(apply) = get(target, "apply").and_then(|a| get(a, "tags")) {
                acc.tags.extend(tags_of(apply));
            }
            match name {
                Some(n) if valid_role_name(&n) && valid_role_name(&from) => self.scan_role(&n, &from, acc, depth + 1),
                _ => {
                    self.notes.insert(format!("{key} non résolu (nom construit par gabarit)"));
                }
            }
        }

        // Variables référencées : toutes les chaînes de la tâche.
        Self::scan_values(task, false, acc);
    }

    /// Fichier de tâches inclus : relatif au fichier courant, sinon aux
    /// tâches du rôle.
    fn include_file(&mut self, rel: &Path, dir: &Path, role: Option<&str>, acc: &mut Acc, depth: usize) {
        let mut candidates = vec![dir.join(rel)];
        if let Some(role) = role {
            candidates.push(Path::new("roles").join(role).join("tasks").join(rel));
        }
        let key = candidates[0].to_string_lossy().to_string();
        if self.stack.contains(&key) {
            return;
        }
        match self.load_any(&candidates) {
            Some((found, tasks)) => {
                self.stack.push(key);
                let parent = found.parent().unwrap_or(Path::new("")).to_path_buf();
                self.scan_tasks(&tasks, &parent, role, acc, depth + 1);
                self.stack.pop();
            }
            None => {
                self.notes.insert(format!("fichier de tâches introuvable : {}", rel.display()));
            }
        }
    }

    fn scan_values(value: &Value, bare: bool, acc: &mut Acc) {
        match value {
            Value::String(s) => collect_refs(s, bare, false, acc),
            Value::Sequence(items) => items.iter().for_each(|v| Self::scan_values(v, bare, acc)),
            Value::Mapping(map) => {
                for (k, v) in map {
                    let key = scalar(k).unwrap_or_default();
                    match key.as_str() {
                        "when" | "failed_when" | "changed_when" | "until" => Self::scan_bare(v, false, acc),
                        "that" => Self::scan_bare(v, true, acc),
                        // Ces clés portent des sous-tâches, déjà parcourues.
                        "block" | "rescue" | "always" | "tags" => {}
                        _ => Self::scan_values(v, bare, acc),
                    }
                }
            }
            _ => {}
        }
    }

    fn scan_bare(value: &Value, require_defined: bool, acc: &mut Acc) {
        match value {
            Value::String(s) => collect_refs(s, true, require_defined, acc),
            Value::Sequence(items) => items.iter().for_each(|v| Self::scan_bare(v, require_defined, acc)),
            _ => {}
        }
    }

    /// Un rôle : dépendances, défauts, tâches. Mémoïsé.
    fn scan_role(&mut self, name: &str, tasks_from: &str, acc: &mut Acc, depth: usize) {
        let key = format!("{name}:{tasks_from}");
        if let Some(done) = self.cache.get(&key) {
            let done = done.clone();
            acc.merge(&done);
            return;
        }
        if self.stack.contains(&key) || depth > MAX_DEPTH {
            return;
        }
        let base = Path::new("roles").join(name);
        if !self.reader.dir_exists(&base) {
            self.notes.insert(format!("rôle introuvable : {name}"));
            return;
        }
        self.stack.push(key.clone());
        let mut role_acc = Acc::default();

        if let Some((_, meta)) = self.load_any(&[base.join("meta/main.yml"), base.join("meta/main.yaml")]) {
            if let Some(Value::Sequence(deps)) = get(&meta, "dependencies") {
                for dep in deps {
                    let dep_name = match dep {
                        Value::String(s) => Some(s.clone()),
                        Value::Mapping(_) => get(dep, "role").or_else(|| get(dep, "name")).and_then(scalar),
                        _ => None,
                    };
                    if let Some(t) = get(dep, "tags") {
                        role_acc.tags.extend(tags_of(t));
                    }
                    match dep_name {
                        Some(n) if valid_role_name(&n) => self.scan_role(&n, "main", &mut role_acc, depth + 1),
                        _ => {
                            self.notes.insert(format!("dépendance non résolue du rôle {name}"));
                        }
                    }
                }
            }
        }
        for file in ["defaults", "vars"] {
            let found = self.load_any(&[base.join(file).join("main.yml"), base.join(file).join("main.yaml")]);
            if let Some((_, Value::Mapping(map))) = found {
                role_acc.defined.extend(map.keys().filter_map(scalar));
            }
        }
        let tasks = self.load_any(&[
            base.join("tasks").join(format!("{tasks_from}.yml")),
            base.join("tasks").join(format!("{tasks_from}.yaml")),
        ]);
        match tasks {
            Some((found, tasks)) => {
                let dir = found.parent().unwrap_or(Path::new("")).to_path_buf();
                self.scan_tasks(&tasks, &dir, Some(name), &mut role_acc, depth + 1);
            }
            None => {
                self.notes.insert(format!("rôle {name} : pas de tasks/{tasks_from}.yml"));
            }
        }
        self.stack.pop();
        acc.merge(&role_acc);
        self.cache.insert(key, role_acc);
    }

    /// Un play : ses rôles, ses tâches, ses étiquettes.
    fn scan_play(&mut self, play: &Value, acc: &mut Acc) -> Vec<String> {
        if let Some(t) = get(play, "tags") {
            acc.tags.extend(tags_of(t));
        }
        if let Some(Value::Mapping(vars)) = get(play, "vars") {
            acc.defined.extend(vars.keys().filter_map(scalar));
        }
        if let Some(Value::Sequence(prompts)) = get(play, "vars_prompt") {
            acc.defined.extend(prompts.iter().filter_map(|p| get(p, "name").and_then(scalar)));
        }
        if get(play, "vars_files").is_some() {
            self.notes.insert("vars_files : variables de ces fichiers non analysées".to_string());
        }
        let mut role_names = Vec::new();
        if let Some(Value::Sequence(roles)) = get(play, "roles") {
            for entry in roles {
                let name = match entry {
                    Value::String(s) => Some(s.clone()),
                    Value::Mapping(map) => {
                        let reserved = ["role", "name", "tags", "when", "vars"];
                        acc.defined.extend(map.keys().filter_map(scalar).filter(|k| !reserved.contains(&k.as_str())));
                        if let Some(Value::Mapping(vars)) = get(entry, "vars") {
                            acc.defined.extend(vars.keys().filter_map(scalar));
                        }
                        if let Some(t) = get(entry, "tags") {
                            acc.tags.extend(tags_of(t));
                        }
                        get(entry, "role").or_else(|| get(entry, "name")).and_then(scalar)
                    }
                    _ => None,
                };
                match name {
                    Some(n) if valid_role_name(&n) => {
                        role_names.push(n.clone());
                        self.scan_role(&n, "main", acc, 0);
                    }
                    Some(n) => {
                        role_names.push(n);
                        self.notes.insert("rôle construit par gabarit : non résolu".to_string());
                    }
                    None => {}
                }
            }
        }
        for key in ["pre_tasks", "tasks", "post_tasks", "handlers"] {
            if let Some(tasks) = get(play, key) {
                self.scan_tasks(tasks, Path::new(""), None, acc, 0);
            }
        }
        role_names
    }

    fn walk_playbook(&mut self, rel: &Path, plays: &mut Vec<(PlayInfo, Acc, bool)>, depth: usize) {
        if depth > 5 {
            self.notes.insert("import_playbook trop profond".to_string());
            return;
        }
        let Some(Value::Sequence(items)) = self.load(rel) else {
            self.notes.insert(format!("playbook illisible : {}", rel.display()));
            return;
        };
        for item in &items {
            let import = module(item, "import_playbook").and_then(scalar);
            if let Some(target) = import {
                match simple_relative(&target) {
                    Some(sub) => {
                        let resolved = rel.parent().unwrap_or(Path::new("")).join(sub);
                        let shown = resolved.to_string_lossy().to_string();
                        if !self.imports.contains(&shown) {
                            self.imports.push(shown);
                            self.walk_playbook(&resolved, plays, depth + 1);
                        }
                    }
                    None => {
                        self.notes.insert("import_playbook non résolu (nom construit par gabarit)".to_string());
                    }
                }
                continue;
            }
            if !matches!(item, Value::Mapping(_)) {
                continue;
            }
            let mut acc = Acc::default();
            let roles = self.scan_play(item, &mut acc);
            let hosts = match get(item, "hosts") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Sequence(l)) => l.iter().filter_map(scalar).collect::<Vec<_>>().join(":"),
                _ => String::new(),
            };
            let local = hosts.trim() == "localhost"
                || get(item, "connection").and_then(scalar).as_deref() == Some("local")
                || get(item, "run_once").and_then(|v| v.as_bool()) == Some(true);
            let name = get(item, "name").and_then(scalar).unwrap_or_default();
            plays.push((
                PlayInfo { name, hosts, roles, tags: acc.tags.iter().cloned().collect() },
                acc,
                local,
            ));
        }
    }
}

/// Motifs positifs d'un `hosts:` (`a:b`, `a,b`) : sans exclusion `!x` ni
/// intersection `&x`, `*` et `all` écartés, un motif construit par gabarit
/// aussi. `None` : le play vise « tout » (`all`, `*`).
fn host_targets(hosts: &str) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for token in hosts.split([':', ',']) {
        let token = token.trim();
        if token.is_empty() || token.starts_with('!') || token.starts_with('&') || token.contains("{{") {
            continue;
        }
        if token == "all" || token == "*" {
            return None;
        }
        out.insert(token.to_string());
    }
    Some(out)
}

fn needs_no_limit(plays: &[(PlayInfo, Acc, bool)]) -> bool {
    let mut usual: Option<BTreeSet<String>> = None;
    let mut first = true;
    for (play, _, local) in plays {
        if *local {
            continue;
        }
        let Some(targets) = host_targets(&play.hosts) else {
            // `all` : un play qui vise tout n'est écarté par aucun `--limit`
            // plus qu'un autre ; s'il est le premier, il EST la cible habituelle.
            if first {
                return false;
            }
            continue;
        };
        if first {
            usual = Some(targets);
            first = false;
            continue;
        }
        let usual = usual.as_ref().expect("fixé au premier play");
        if targets.iter().any(|t| t != "localhost" && !usual.contains(t)) {
            return true;
        }
    }
    false
}

fn builtin(name: &str) -> bool {
    MAGIC.contains(&name) || KEYWORDS.contains(&name) || name.starts_with("ansible_")
}

/// Playbooks importés (`import_playbook` de nom statique) par `playbook`,
/// transitivement — sans analyser ses rôles.
pub fn imported_playbooks(reader: &TreeReader, playbook: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut queue = vec![PathBuf::from(playbook)];
    let mut read = 0;
    while let Some(current) = queue.pop() {
        read += 1;
        if read > 50 {
            break;
        }
        let Some(text) = reader.read_text(&current, MAX_SCAN_BYTES) else { continue };
        let Ok(Value::Sequence(items)) = serde_yaml::from_str::<Value>(&text) else { continue };
        for item in &items {
            let Some(target) = module(item, "import_playbook").and_then(scalar) else { continue };
            let Some(sub) = simple_relative(&target) else { continue };
            let resolved = current.parent().unwrap_or(Path::new("")).join(sub);
            let shown = resolved.to_string_lossy().to_string();
            if !found.contains(&shown) {
                found.push(shown);
                queue.push(resolved);
            }
        }
    }
    found
}

/// Décrit `playbook` (nom d'un fichier directement sous `playbooks/`).
pub fn describe(reader: &TreeReader, playbook: &str) -> Result<Description> {
    if playbook.contains('/') || playbook.starts_with('.') || playbook.is_empty() {
        return fail(FaultKind::InvalidArgument, format!("nom de playbook invalide : {playbook:?}"));
    }
    let mut walker = Walker {
        reader,
        files: 0,
        notes: BTreeSet::new(),
        stack: Vec::new(),
        cache: HashMap::new(),
        imports: Vec::new(),
    };
    let mut plays = Vec::new();
    walker.walk_playbook(Path::new(playbook), &mut plays, 0);
    if plays.is_empty() && walker.files == 0 {
        return fail(FaultKind::UnknownPlaybook, format!("playbook illisible : {playbook}"));
    }

    let mut all = Acc::default();
    for (_, acc, _) in &plays {
        all.merge(acc);
    }
    let parc_vars = reader.parc_var_names();
    let vars: Vec<String> = all
        .required
        .iter()
        .filter(|v| !all.defined.contains(*v) && !parc_vars.contains(*v) && !builtin(v))
        .take(MAX_VARS)
        .cloned()
        .collect();
    let needs = needs_no_limit(&plays);
    Ok(Description {
        plays: plays.into_iter().map(|(p, _, _)| p).collect(),
        tags: all.tags.into_iter().collect(),
        vars,
        needs_no_limit: needs,
        imports: walker.imports,
        notes: walker.notes.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ff-describe-{}-{name}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn names(vars: &[(String, Option<bool>)]) -> Vec<(&str, Option<bool>)> {
        vars.iter().map(|(n, v)| (n.as_str(), *v)).collect()
    }

    #[test]
    fn jinja_expressions_yield_their_variables() {
        let v = expression_vars(" ollama_model_name ");
        assert_eq!(names(&v), [("ollama_model_name", None)]);
        let v = expression_vars(" app_port | default(9750) ");
        assert_eq!(names(&v), [("app_port", Some(true))]);
        let v = expression_vars(" cfg.items['a'] | default({}) | length ");
        assert_eq!(names(&v), [("cfg", Some(true))]);
        let v = expression_vars(" 'x' if flag is defined else other | upper ");
        assert_eq!(names(&v), [("flag", Some(false)), ("other", None)]);
        let v = expression_vars(" lookup('env', 'HOME') ~ playbook_dir ~ x.attr ");
        assert_eq!(names(&v), [("x", None)]);
        let v = expression_vars(" a is not defined and b == 'c d' and not c ");
        assert_eq!(names(&v), [("a", Some(false)), ("b", None), ("c", None)]);
        let v = expression_vars(" item.name ~ ansible_hostname ~ inventory_hostname ");
        assert!(v.is_empty(), "{v:?}");
        let v = expression_vars(" x | regex_replace('a', b) ");
        assert_eq!(names(&v), [("x", None), ("b", None)]);
        let v = expression_vars(" lookup('password', '/dev/null length=40', seed=thing) ");
        assert_eq!(names(&v), [("thing", None)], "un argument nommé n'est pas une variable");
    }

    #[test]
    fn globs_and_patterns_pick_the_usual_targets() {
        let play = |hosts: &str, local: bool| (PlayInfo { name: String::new(), hosts: hosts.into(), roles: vec![], tags: vec![] }, Acc::default(), local);
        assert!(needs_no_limit(&[play("infras", false), play("proxies", false)]));
        assert!(needs_no_limit(&[play("infras", false), play("prometheus1:monitor", false)]));
        assert!(!needs_no_limit(&[play("infras", false), play("infras", false)]));
        assert!(!needs_no_limit(&[play("proxies:infras", false), play("infras", false)]));
        assert!(!needs_no_limit(&[play("localhost", true), play("infras", false), play("localhost", false)]));
        assert!(!needs_no_limit(&[play("all", false), play("proxies", false)]), "cibles habituelles : tout");
        assert!(!needs_no_limit(&[play("infras", false), play("all", false)]));
        assert!(!needs_no_limit(&[play("infras", false), play("{{ x }}", false)]), "motif construit : ignoré");
        assert!(!needs_no_limit(&[play("infras", false), play("infras:!proxies", false)]));
        assert!(!needs_no_limit(&[]));
    }

    fn fixture(name: &str) -> (PathBuf, TreeReader) {
        let root = scratch(name);
        write(&root, "playbooks/deploy-demo.yml", "\
---
- name: Preflight
  hosts: demo
  run_once: true
  roles: [host-preflight]
- name: Deploy demo
  hosts: demo
  tags: [play-tag]
  vars:
    from_play: 1
  roles:
    - demo-install
    - { role: other-role, tags: [other] }
  tasks:
    - name: Use things
      ansible.builtin.debug:
        msg: \"{{ needed_var }} {{ from_play }} {{ optional | default('x') }} {{ role_default }} {{ group_known }} {{ never_seen }}\"
      tags: [late]
    - ansible.builtin.import_role:
        name: dyn-role
      vars: { k: 1 }
    - ansible.builtin.include_role:
        name: \"{{ computed }}\"
- name: Vhost on the proxies
  hosts: proxies
  roles: [proxy-vhost]
- import_playbook: deploy-sub.yml
");
        write(&root, "playbooks/deploy-sub.yml", "---\n- name: Sub\n  hosts: subs\n  roles: [sub-install]\n");
        write(&root, "playbooks/roles/host-preflight/tasks/main.yml", "---\n- name: p\n  debug: msg=ok\n  tags: [preflight]\n");
        write(&root, "playbooks/roles/demo-install/meta/main.yml", "---\ndependencies:\n  - role: dep-role\n    tags: [dep]\n  - common\n");
        write(&root, "playbooks/roles/demo-install/defaults/main.yml", "---\nrole_default: 1\n");
        write(&root, "playbooks/roles/demo-install/tasks/main.yml", "\
---
- name: Include a file
  ansible.builtin.include_tasks:
    file: more.yml
    apply:
      tags: [applied]
  tags: [code]
- name: Block
  block:
    - name: inner
      command: \"echo {{ inner_var }}\"
      register: result
      tags: [inner]
    - name: after
      debug: msg=\"{{ result.stdout }}\"
  when: gate_var is defined
- name: Require
  ansible.builtin.assert:
    that:
      - must_have is defined
- name: Loop
  debug: msg=\"{{ item }}\"
  loop: \"{{ things }}\"
");
        write(&root, "playbooks/roles/demo-install/tasks/more.yml", "---\n- name: More\n  debug: msg=\"{{ more_var }}\"\n  tags: [more]\n");
        write(&root, "playbooks/roles/dep-role/tasks/main.yml", "---\n- debug: msg=dep\n  tags: [from-dep]\n");
        write(&root, "playbooks/roles/common/tasks/main.yml", "---\n- debug: msg=common\n");
        write(&root, "playbooks/roles/other-role/tasks/main.yml", "---\n- debug: msg=other\n");
        write(&root, "playbooks/roles/dyn-role/tasks/main.yml", "---\n- debug: msg=\"{{ k }}\"\n  tags: [dyn]\n");
        write(&root, "playbooks/roles/proxy-vhost/tasks/main.yml", "---\n- debug: msg=vhost\n  tags: [proxy-conf]\n");
        write(&root, "playbooks/roles/sub-install/tasks/main.yml", "---\n- debug: msg=sub\n  tags: [sub]\n");
        write(&root, "playbooks/group_vars/web3c.yml", "group_known: 1\nsecret_thing: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\n");
        write(&root, "playbooks/group_vars/vaulted.yml", "$ANSIBLE_VAULT;1.1;AES256\n6162\n");
        let reader = TreeReader::new(&root, &[]).unwrap();
        (root, reader)
    }

    #[test]
    fn plays_roles_tags_and_vars_are_read_statically() {
        let (_root, reader) = fixture("static");
        let d = describe(&reader, "deploy-demo.yml").unwrap();

        let plays: Vec<(&str, &str, Vec<&str>)> = d
            .plays
            .iter()
            .map(|p| (p.name.as_str(), p.hosts.as_str(), p.roles.iter().map(String::as_str).collect()))
            .collect();
        assert_eq!(plays[0], ("Preflight", "demo", vec!["host-preflight"]));
        assert_eq!(plays[1], ("Deploy demo", "demo", vec!["demo-install", "other-role"]));
        assert_eq!(plays[2], ("Vhost on the proxies", "proxies", vec!["proxy-vhost"]));
        assert_eq!(plays[3], ("Sub", "subs", vec!["sub-install"]), "import_playbook déplié");
        assert_eq!(d.imports, ["deploy-sub.yml"]);

        // Étiquettes : play, rôle appelé (et ses dépendances), tâches, apply.
        for tag in [
            "play-tag", "other", "late", "code", "applied", "more", "inner", "dep", "from-dep", "dyn", "proxy-conf",
            "preflight", "sub",
        ] {
            assert!(d.tags.contains(&tag.to_string()), "{tag} manque : {:?}", d.tags);
        }
        let deploy = &d.plays[1];
        assert!(deploy.tags.contains(&"inner".to_string()) && deploy.tags.contains(&"dyn".to_string()));
        assert!(!d.plays[0].tags.contains(&"proxy-conf".to_string()), "les étiquettes restent par play");
        assert!(d.tags.windows(2).all(|w| w[0] < w[1]), "triées, sans doublon");

        assert!(d.needs_no_limit, "play `proxies` hors des cibles `demo`");
        // Variables : attendues, hors défaut/définition/groupe/garde.
        for expected in ["needed_var", "inner_var", "more_var", "must_have", "things", "never_seen"] {
            assert!(d.vars.contains(&expected.to_string()), "{expected} manque : {:?}", d.vars);
        }
        for unexpected in ["from_play", "optional", "role_default", "group_known", "result", "item", "gate_var", "k"] {
            assert!(!d.vars.contains(&unexpected.to_string()), "{unexpected} en trop : {:?}", d.vars);
        }
        assert!(d.notes.iter().any(|n| n.contains("include_role non résolu")), "{:?}", d.notes);
    }

    #[test]
    fn unreadable_or_unknown_playbooks_are_refused() {
        let (_root, reader) = fixture("refused");
        for bad in ["nothing.yml", "", "a/b.yml", ".hidden.yml", "../x.yml"] {
            assert!(describe(&reader, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn inclusions_cannot_read_outside_the_playbooks_tree() {
        let (root, reader) = fixture("escape");
        write(&root, "outside/evil.yml", "---\n- debug: msg=\"{{ leaked_var }}\"\n  tags: [leaked]\n");
        write(&root, "playbooks/evil.yml", "\
---
- hosts: demo
  tasks:
    - include_tasks: ../../outside/evil.yml
    - include_tasks: /etc/hosts
    - include_tasks: group_vars/web3c.yml
    - import_role:
        name: ../../outside
");
        let d = describe(&reader, "evil.yml").unwrap();
        assert!(!d.tags.contains(&"leaked".to_string()) && !d.vars.contains(&"leaked_var".to_string()));
        assert!(!d.notes.is_empty());
    }

    #[test]
    fn a_role_cycle_does_not_loop() {
        let root = scratch("cycle");
        write(&root, "playbooks/p.yml", "---\n- hosts: demo\n  roles: [a]\n");
        write(&root, "playbooks/roles/a/meta/main.yml", "---\ndependencies: [b]\n");
        write(&root, "playbooks/roles/b/meta/main.yml", "---\ndependencies: [a]\n");
        write(&root, "playbooks/roles/a/tasks/main.yml", "---\n- include_tasks: main.yml\n  tags: [a]\n");
        write(&root, "playbooks/roles/b/tasks/main.yml", "---\n- debug: msg=b\n  tags: [b]\n");
        let reader = TreeReader::new(&root, &[]).unwrap();
        let d = describe(&reader, "p.yml").unwrap();
        assert!(d.tags.contains(&"a".to_string()) && d.tags.contains(&"b".to_string()), "{:?}", d.tags);
    }

    #[test]
    fn the_real_fleetforge_playbook_needs_no_limit() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ansible");
        let reader = TreeReader::new(&root, &[]).unwrap();
        let d = describe(&reader, "deploy-fleetforge.yml").unwrap();
        assert!(d.needs_no_limit, "plays : {:?}", d.plays);
        for tag in ["proxy-conf", "alerts", "monitoring", "authorize", "code", "config", "secrets", "ansible", "dns"] {
            assert!(d.tags.contains(&tag.to_string()), "{tag} manque : {:?}", d.tags);
        }
        let roles: Vec<&str> = d.plays.iter().flat_map(|p| p.roles.iter().map(String::as_str)).collect();
        assert!(roles.contains(&"fleetforge-install") && roles.contains(&"host-preflight"), "{roles:?}");
        // Pas de donnée de parc dans la description.
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("$ANSIBLE_VAULT"));
    }

    #[test]
    fn a_few_real_playbooks_are_described_without_error() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ansible");
        let reader = TreeReader::new(&root, &[]).unwrap();
        let ollama = describe(&reader, "deploy-ollama-model.yml");
        if let Ok(d) = ollama {
            assert!(d.vars.contains(&"ollama_model_name".to_string()), "{:?}", d.vars);
        }
        for name in ["update-ufw-all.yml", "deploy-agenthub.yml", "deploy-openclaw.yml", "setup-server.yml"] {
            let d = describe(&reader, name).unwrap_or_else(|e| panic!("{name} : {e}"));
            assert!(!d.plays.is_empty(), "{name}");
        }
        let openclaw = describe(&reader, "deploy-openclaw.yml").unwrap();
        assert_eq!(openclaw.imports, ["deploy-llamacpp.yml"], "import_playbook déplié");
        let agenthub = describe(&reader, "deploy-agenthub.yml").unwrap();
        assert!(agenthub.needs_no_limit, "vhost sur les proxies : {:?}", agenthub.plays.iter().map(|p| &p.hosts).collect::<Vec<_>>());
        let ufw = describe(&reader, "update-ufw-all.yml").unwrap();
        assert!(!ufw.needs_no_limit, "{:?}", ufw.plays.iter().map(|p| &p.hosts).collect::<Vec<_>>());
    }
}
