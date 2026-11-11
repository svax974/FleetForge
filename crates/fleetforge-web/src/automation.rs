/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Commandes de l'API d'automatisation (AgentHub, poste « Infrastructure
//! Manager ») et lancement des runs de playbook.
//!
//! Servies par le même `POST /api/{commande}` que le frontal, et en outils par
//! le serveur MCP (`/mcp`, toujours sous les règles de l'automatisation), à
//! cette différence près que le compte d'automatisation ([`Role::Automation`])
//! y est tenu plus court que l'opérateur :
//!   • un parc se désigne par son NOM, jamais par un chemin de fichier ;
//!   • aucune variable `ansible_*`, aucun gabarit Jinja dans une valeur ;
//!   • un run réel exige le `--check` du même lancement, fait par le même
//!     compte ou par un compte qu'il accepte (`state::CheckLedger`) ;
//!   • un compte `check` ne lance QUE des `--check` ([`run_options`]) ;
//!   • un parc occupé répond `run_busy` au lieu d'attendre ;
//!   • les sorties rendues sont caviardées (`fleetforge_core::redact`).
//!
//! Ces commandes ne sont servies QUE par le web : un appelant distant n'a pas
//! d'équivalent dans l'application de bureau (voir CLAUDE.md § 3).

use anyhow::anyhow;
use fleetforge_core::ansible_output;
use fleetforge_core::automation::{validate_extra_vars, validate_run_id, validate_tags};
use fleetforge_core::redact::redact_text;
use fleetforge_core::{ro_gate, AnsibleRun, Fault, FaultKind, LockPolicy, PlaybookRequest, PreparedRun, RunOptions, RunSelection};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::api::{ok, ApiError, ApiResult, Params};
use crate::config::{Role, Scope};
use crate::state::AppState;

/// Lignes de sortie rendues par défaut par `run_status`.
const DEFAULT_TAIL_LINES: usize = 50;
const MAX_TAIL_LINES: usize = 500;

/// Une commande de l'API d'automatisation (`auth::AUTOMATION_COMMANDS`).
///
/// Seule porte vers ces commandes, pour `POST /api/{commande}` comme pour les
/// outils du serveur MCP (`mcp.rs`) : ce qui est validé, refusé ou caviardé
/// l'est à l'identique par les deux voies.
///
/// Le périmètre du compte ([`Scope`]) y est tenu : une commande hors de son
/// mode, un parc, un hôte ou un run hors de ses parcs répondent
/// `403 forbidden` — avant toute lecture d'inventaire, et sans dire si le
/// parc ou l'hôte refusé existe.
pub async fn serve(state: &AppState, role: Role, scope: &Scope, command: &str, p: &Params) -> ApiResult {
    if !scope.may(command) {
        return Err(ApiError::forbidden(format!("{command} : hors du mode du compte ({})", scope.mode.describe())));
    }
    match command {
        "list_hosts" => list_hosts(state, scope, p).await,
        "list_playbooks" => list_playbooks(state),
        "alertmanager_alerts" => alertmanager_alerts(state, scope, p).await,
        "query_prometheus" => query_prometheus(state, role, scope, p).await,
        "ssh_diagnose" => ssh_diagnose(state, role, scope, p).await,
        "run_ansible_playbook" => run_playbook(state, role, scope, p).await,
        "run_status" => run_status(state, role, scope, p),
        "describe_playbook" => describe_playbook(state, scope, p).await,
        "read_tree" => read_tree(state, scope, p).await,
        "search_tree" => search_tree(state, scope, p).await,
        "tree_status" => tree_status(state, scope, p).await,
        "syntax_check" => syntax_check(state, scope, p).await,
        "sync_tree" => sync_tree(state, scope, p).await,
        other => Err(ApiError::invalid(format!("commande inconnue : {other}"))),
    }
}

/// Le parc nommé est-il dans le périmètre du compte ?
fn within(scope: &Scope, parc: &str) -> Result<(), ApiError> {
    if scope.covers(parc) {
        return Ok(());
    }
    Err(ApiError::forbidden(format!("parc hors du périmètre du compte : {parc}")))
}

async fn list_hosts(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let core = state.core.clone();
    // `ansible-inventory` est un sous-processus : hors du fil asynchrone.
    ok(tokio::task::spawn_blocking(move || core.list_hosts(&parc)).await??)
}

fn list_playbooks(state: &AppState) -> ApiResult {
    ok(state.core.list_playbook_summaries()?)
}

async fn alertmanager_alerts(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    ok(state.core.alertmanager_alerts(&parc).await?)
}

/// `query_prometheus`, deux formes :
///   • `{ query }` (frontal) : supervision du parc SÉLECTIONNÉ, liste de séries ;
///   • `{ parc, query, time? }` : supervision du parc nommé, réponse
///     `{ parc, result, truncated }`. Seule forme admise pour l'automatisation.
async fn query_prometheus(state: &AppState, role: Role, scope: &Scope, p: &Params) -> ApiResult {
    let query: String = p.get("query")?;
    let Some(parc) = p.opt::<String>("parc")? else {
        if role == Role::Automation {
            return Err(anyhow!(Fault::invalid("argument manquant : parc")).into());
        }
        return ok(state.core.query_prometheus(&query).await?);
    };
    within(scope, &parc)?;
    // Horodatage en nombre ou en chaîne : transmis tel qu'écrit, validé.
    let time = match p.opt::<serde_json::Value>("time")? {
        None => None,
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::String(s)) => Some(s),
        Some(_) => return Err(anyhow!(Fault::invalid("argument time invalide")).into()),
    };
    ok(state.core.query_prometheus_in(&parc, &query, time.as_deref()).await?)
}

/// `{ host, verb, args?, parc? }`. Sans `args`, `verb` peut porter la demande
/// entière (« logs docker searxng 1h ») : elle est découpée sur les espaces,
/// puis validée comme le reste.
///
/// Sans `parc`, l'hôte n'est cherché que dans les parcs du périmètre ; absent
/// de tous, la réponse est `forbidden` pour un compte borné — `unknown_host`
/// dirait qu'il existe ailleurs.
async fn ssh_diagnose(state: &AppState, role: Role, scope: &Scope, p: &Params) -> ApiResult {
    let host: String = p.get("host")?;
    let parc: Option<String> = p.opt("parc")?;
    let raw_verb: String = p.get("verb")?;
    let (verb, args) = match p.opt::<Vec<String>>("args")? {
        Some(args) => (raw_verb.trim().to_string(), args),
        None => {
            let mut words = raw_verb.split_whitespace().map(String::from);
            (words.next().unwrap_or_default(), words.collect())
        }
    };
    // La grammaire d'abord : une demande hors liste ne coûte pas même une
    // lecture d'inventaire.
    ro_gate::validate(&verb, &args)?;

    if let Some(parc) = &parc {
        within(scope, parc)?;
    }
    let core = state.core.clone();
    let bounded: Option<Vec<String>> = scope.parcs.as_ref().map(|parcs| parcs.iter().cloned().collect());
    let lookup = tokio::task::spawn_blocking(move || match (parc, bounded) {
        (None, Some(parcs)) => core.find_host_in(&parcs, &host).map_err(|e| match fleetforge_core::fault::kind_of(&e) {
            Some(FaultKind::UnknownHost) => {
                ApiError::forbidden(format!("hôte hors du périmètre du compte : {host}"))
            }
            _ => e.into(),
        }),
        (parc, _) => core.find_host(parc.as_deref(), &host).map_err(ApiError::from),
    });
    let (parc, entry) = lookup.await??;
    let mut diagnosis = ro_gate::diagnose(&state.ro_gate, &entry, &verb, &args).await?;
    if role == Role::Automation {
        // ro-gate caviarde déjà sur l'hôte ; une passerelle d'une autre version
        // ne doit pas suffire à faire sortir un secret.
        diagnosis.output = redact_text(&diagnosis.output);
    }
    let mut value = serde_json::to_value(diagnosis)?;
    value["parc"] = json!(parc);
    ok(value)
}

/// `{ run_id }` (ou `runId`) → état d'un run du registre.
fn run_status(state: &AppState, role: Role, scope: &Scope, p: &Params) -> ApiResult {
    let id: String = p.first(&["run_id", "runId"])?;
    validate_run_id(&id)?;
    let run = state
        .core
        .runs()
        .get(&id)
        .ok_or_else(|| ApiError::from(anyhow!(Fault::new(FaultKind::UnknownRun, format!("run inconnu : {id}")))))?;
    run_within(state, scope, &id)?;
    let wanted = p
        .opt::<usize>("tail_lines")?
        .unwrap_or(DEFAULT_TAIL_LINES)
        .clamp(1, MAX_TAIL_LINES);
    let tail = run.output[run.output.len().saturating_sub(wanted)..].join("\n");
    let tail = if role == Role::Automation { redact_text(&tail) } else { tail };
    // Bilan par hôte et tâches en échec, lus de la sortie ENTIÈRE du run (pas
    // de sa fin seule) : un run en cours n'a pas encore de bilan, mais montre
    // déjà ses échecs.
    let report = ansible_output::parse(run.output.iter().map(String::as_str));
    let failures: Vec<_> = report
        .failures
        .into_iter()
        .map(|mut f| {
            f.task = f.task.map(|t| redact_text(&t));
            f
        })
        .collect();
    ok(json!({
        "run_id": run.id,
        "state": run.status,
        "exit_code": run.exit_code,
        "started_at": run.started_at,
        "ended_at": run.finished_at,
        "output_tail": tail,
        "label": run.label,
        "check": run.options.check,
        "diff": run.options.diff,
        "commit": run.commit,
        "tags": run.tags,
        "skip_tags": run.skip_tags,
        "recap": report.recap,
        "failures": failures,
    }))
}

/// Un run n'est visible d'un compte borné (`run_status`, flux SSE) que s'il a
/// été lancé sur l'un de ses parcs.
pub fn run_within(state: &AppState, scope: &Scope, run_id: &str) -> Result<(), ApiError> {
    if scope.parcs.is_none() {
        return Ok(());
    }
    match state.run_parcs.parc_of(run_id) {
        Some(parc) if scope.covers(&parc) => Ok(()),
        _ => Err(ApiError::forbidden(format!("run hors du périmètre du compte : {run_id}"))),
    }
}

/// Identifiant de run fabriqué quand l'appelant n'en fournit pas.
fn generated_run_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "api-{}-{}",
        chrono::Utc::now().timestamp_millis(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Empreinte d'un lancement : ce qui doit être identique entre le `--check` et
/// le run réel qu'il autorise. `--diff` n'en fait pas partie — il ne change
/// que l'affichage. En revanche le COMMIT RÉSOLU en fait partie : un check du
/// commit A n'autorise pas le même playbook sur le commit B.
#[allow(clippy::too_many_arguments)]
fn fingerprint(
    parc: &str,
    playbook: &str,
    limit: &Option<Vec<String>>,
    extra: &HashMap<String, String>,
    tags: &[String],
    skip_tags: &[String],
    commit: &Option<String>,
    no_limit: bool,
) -> String {
    let sorted = |list: &[String]| {
        let mut v: Vec<String> = list.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    };
    let limit = sorted(limit.as_deref().unwrap_or_default());
    let extra: std::collections::BTreeMap<&String, &String> = extra.iter().collect();
    json!([parc, playbook, limit, extra, sorted(tags), sorted(skip_tags), commit, no_limit]).to_string()
}

/// `run_ansible_playbook`.
///
/// Arguments (forme du frontal, alias de l'API d'automatisation) :
/// `playbookPath`|`playbook`, `inventoryPath`|`parc`, `limitHosts`|`limit`,
/// `extraVars`|`extra_vars`, `deployId`|`run_id` (facultatif : fabriqué sinon),
/// `label`, `check`, `diff`, `detach`, et `tags`, `skip_tags`, `commit`
/// (`HEAD` ou sha complet ; défaut : la tête synchronisée de l'arbre git),
/// `no_limit` (aucun `--limit` ; exclusif avec `limit`, refusé aux comptes
/// bornés par `max_hosts`).
///
/// Pour le compte d'automatisation, en plus : `deny_playbooks` (le playbook et
/// ceux qu'il importe) et `max_hosts` (`limit` obligatoire, groupes développés)
/// de son périmètre sont appliqués avant tout. Un compte `check` est toujours
/// tenu à ces règles strictes, et ne lance que des `--check` ([`run_options`]).
///
/// `run_id` et `label` sont ceux de l'appelant quand il les donne (une
/// passerelle impose ainsi les siens) : `run_id_in_use` tant qu'un run EN
/// COURS porte cet identifiant ; celui d'un run terminé est réutilisable, et
/// le nouveau run remplace l'ancien au registre.
///
/// `detach: true` rend la main dès le run inscrit (`{ run_id, state }`) ; sans
/// lui, la réponse attend la fin du run (comportement du frontal). Dans les
/// deux cas le run se termine et se clôt même si le client se déconnecte.
async fn run_playbook(state: &AppState, role: Role, scope: &Scope, p: &Params) -> ApiResult {
    let strict = role == Role::Automation || scope.check_only();
    let playbook: String = p.first(&["playbookPath", "playbook"])?;
    let inventory: String = p.first(&["inventoryPath", "parc"])?;
    let limit: Option<Vec<String>> = p.first_opt(&["limitHosts", "limit"])?;
    let tags: Vec<String> = p.opt("tags")?.unwrap_or_default();
    let skip_tags: Vec<String> = p.opt("skip_tags")?.unwrap_or_default();
    let commit: Option<String> = p.opt("commit")?;
    let no_limit: bool = p.opt("no_limit")?.unwrap_or(false);
    let extra: HashMap<String, String> = p.first_opt(&["extraVars", "extra_vars"])?.unwrap_or_default();
    let id: String = p.first_opt(&["deployId", "run_id"])?.unwrap_or_else(generated_run_id);
    let options = run_options(scope, p)?;
    let detach: bool = p.opt("detach")?.unwrap_or(false);
    let label: String = p.opt("label")?.unwrap_or_else(|| playbook.clone());

    let core = state.core.clone();
    let mut print = None;
    let (mut tags, mut skip_tags, mut commit) = (tags, skip_tags, commit);
    let mut playbook = playbook;
    if strict {
        within(scope, &inventory)?;
        // Un NOM de parc, jamais un chemin de fichier d'inventaire.
        core.parc_by_name(&inventory)?;
        validate_extra_vars(&extra, true)?;
        tags = validate_tags(&tags, "tags")?;
        skip_tags = validate_tags(&skip_tags, "skip_tags")?;
        let limited = limit.as_ref().is_some_and(|l| !l.is_empty());
        if no_limit && limited {
            return Err(anyhow!(Fault::invalid("no_limit et limit s'excluent")).into());
        }
        if let Some(max) = scope.max_hosts {
            enforce_max_hosts(state, &inventory, limit.as_deref().filter(|l| !l.is_empty()), no_limit, max).await?;
        }
        // Commit RÉSOLU d'abord (sha complet, atteignable d'une référence
        // permise) : il entre dans l'empreinte, et c'est lui — pas une tête
        // qui aurait avancé entre le check et le run — qui sera exécuté.
        let (parc, wanted) = (inventory.clone(), commit.clone());
        let c = core.clone();
        commit = tokio::task::spawn_blocking(move || c.resolve_commit(&parc, wanted.as_deref())).await??;
        // Le playbook et ceux qu'il importe, dans l'arbre de ce commit.
        let (parc, wanted, name) = (inventory.clone(), commit.clone(), playbook.clone());
        let c = core.clone();
        let chain = tokio::task::spawn_blocking(move || c.playbook_chain(&parc, &name, wanted.as_deref())).await??;
        if let Some(denied) = chain.iter().find(|n| scope.denies(base_name(n))) {
            return Err(anyhow!(Fault::new(
                FaultKind::ForbiddenPlaybook,
                format!("playbook interdit à ce compte : {denied}"),
            ))
            .into());
        }
        playbook = chain.first().cloned().unwrap_or(playbook);
        let fp = fingerprint(&inventory, &playbook, &limit, &extra, &tags, &skip_tags, &commit, no_limit);
        if !options.check && !state.checks.is_fresh(scope.check_owners(), &fp) {
            return Err(anyhow!(Fault::new(
                FaultKind::CheckRequired,
                "run réel refusé : lancer d'abord le même playbook avec check: true \
                 (même parc, même limit, mêmes variables, mêmes tags, même commit), il y a moins d'une heure, \
                 sous ce compte (ou un compte de son accept_checks_from)",
            ))
            .into());
        }
        print = options.check.then(|| (scope.owner.clone(), fp));
    }

    // Dernière barrière avant l'inscription et le lancement, indépendante de
    // la façon dont `options` a été calculé plus haut.
    ensure_check_only(scope, options)?;
    let run_parc = inventory.clone();
    let req = PlaybookRequest {
        id,
        label,
        playbook_path: playbook,
        inventory_path: inventory,
        limit_hosts: limit,
        extra_vars: extra,
    };
    let lock = if strict { LockPolicy::Try } else { LockPolicy::Wait };
    // Validation complète (inventaire, `--limit`) et inscription au registre
    // — sous-processus possibles, hors du fil asynchrone —, puis lancement.
    // Le tout dans une tâche à part : un client qui se déconnecte entre les
    // deux laisserait sinon un run inscrit « en cours » que rien n'exécute.
    let shared = state.clone();
    let selection = RunSelection { tags, skip_tags, no_limit, commit };
    let (run_id, running) = tokio::spawn(async move {
        let prepared = tokio::task::spawn_blocking(move || core.prepare_playbook_with(req, options, selection, lock))
            .await??;
        let run_id = prepared.id().to_string();
        // Avant le lancement : un `run_status` immédiat doit déjà le trouver.
        shared.run_parcs.record(&run_id, &run_parc);
        Ok::<_, anyhow::Error>((run_id, launch(shared, prepared, print)))
    })
    .await??;

    if detach {
        let commit = state.core.runs().get(&run_id).and_then(|r| r.commit);
        return ok(json!({
            "run_id": run_id,
            "state": "running",
            "check": options.check,
            "diff": options.diff,
            "commit": commit,
        }));
    }
    let run = running.await??;
    let mut value = serde_json::to_value(&run)?;
    if strict {
        value["output"] = json!(redact_text(&run.output));
    }
    value["run_id"] = json!(run_id);
    value["commit"] = json!(state.core.runs().get(&run_id).and_then(|r| r.commit));
    ok(value)
}

/// `check` et `diff` d'un lancement.
///
/// Un compte `check` ne lance QUE des `--check` : `check` absent vaut `true` ;
/// `check: false` est refusé (`403 forbidden`) plutôt que ramené en silence à
/// un check — l'appelant qui demandait un run réel doit savoir qu'il n'a pas
/// eu lieu. Les variables qui pourraient désarmer `--check` (`ansible_*`,
/// dont `ansible_check_mode`) sont refusées par la validation stricte, à
/// laquelle ce compte est toujours tenu.
fn run_options(scope: &Scope, p: &Params) -> Result<RunOptions, ApiError> {
    let check: Option<bool> = p.opt("check")?;
    let diff: bool = p.opt("diff")?.unwrap_or(false);
    if !scope.check_only() {
        return Ok(RunOptions { check: check.unwrap_or(false), diff });
    }
    if check == Some(false) {
        return Err(ApiError::forbidden(
            "run réel refusé : ce compte ne lance que des --check (check: false interdit)".to_string(),
        ));
    }
    Ok(RunOptions { check: true, diff })
}

/// Un compte `check` n'inscrit jamais un run sans `--check`, quel que soit le
/// chemin suivi jusque-là : seconde barrière, juste avant le lancement.
fn ensure_check_only(scope: &Scope, options: RunOptions) -> Result<(), ApiError> {
    if scope.check_only() && !options.check {
        return Err(ApiError::forbidden("run réel refusé : ce compte ne lance que des --check".to_string()));
    }
    Ok(())
}

/// Nom de fichier d'un playbook (`sub/x.yml` → `x.yml`).
fn base_name(playbook: &str) -> &str {
    playbook.rsplit('/').next().unwrap_or(playbook)
}

/// `max_hosts` : `limit` est obligatoire (un run sans limite vise tout ce que
/// cible le playbook, donc un nombre inconnu), `no_limit` refusé, et les
/// groupes sont développés par l'inventaire pour compter les hôtes.
async fn enforce_max_hosts(
    state: &AppState,
    parc: &str,
    limit: Option<&[String]>,
    no_limit: bool,
    max: usize,
) -> Result<(), ApiError> {
    let too_many = |message: String| ApiError::from(anyhow!(Fault::new(FaultKind::TooManyHosts, message)));
    if no_limit {
        return Err(too_many(format!("no_limit refusé à ce compte (au plus {max} hôtes)")));
    }
    let Some(limit) = limit else {
        return Err(too_many(format!("limit obligatoire pour ce compte (au plus {max} hôtes)")));
    };
    let (core, parc, names) = (state.core.clone(), parc.to_string(), limit.to_vec());
    let hosts = tokio::task::spawn_blocking(move || core.count_limit_hosts(&parc, &names)).await??;
    if hosts > max {
        return Err(too_many(format!("{hosts} hôtes visés, ce compte en admet {max} au plus")));
    }
    Ok(())
}

// === Lecture de l'arbre Ansible, contrôle de syntaxe, synchronisation ===

/// Chaînes d'une valeur JSON, caviardées de bout en bout : ce qui sort part
/// chez le fournisseur d'un modèle. Sauf `commit` : un sha complet y serait pris
/// pour un secret hexadécimal, et c'est un identifiant que l'appelant doit
/// pouvoir réutiliser tel quel.
fn redacted(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => Value::String(redact_text(&s)),
        Value::Array(items) => Value::Array(items.into_iter().map(redacted).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| if k == "commit" { (k, v) } else { (k, redacted(v)) })
                .collect(),
        ),
        other => other,
    }
}

/// `{ parc, playbook, commit? }` → plays, étiquettes, variables attendues,
/// `needs_no_limit` (voir `fleetforge_core::ansible_describe`).
async fn describe_playbook(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let playbook: String = p.first(&["playbook", "playbookPath"])?;
    let commit: Option<String> = p.opt("commit")?;
    let core = state.core.clone();
    let answer = tokio::task::spawn_blocking(move || core.describe_playbook(&parc, &playbook, commit.as_deref())).await??;
    ok(redacted(serde_json::to_value(answer)?))
}

/// `{ parc, path, commit? }` → un fichier de `playbooks/` (≤ 64 Kio, caviardé ;
/// `redacted: true` quand le caviardage a changé le texte) ou la liste d'un
/// dossier.
async fn read_tree(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let path: String = p.opt("path")?.unwrap_or_default();
    let commit: Option<String> = p.opt("commit")?;
    let core = state.core.clone();
    let answer = tokio::task::spawn_blocking(move || core.read_tree(&parc, &path, commit.as_deref())).await??;
    let mut value = serde_json::to_value(&answer)?;
    if let Some(content) = value.get("content").and_then(|c| c.as_str()).map(String::from) {
        let masked = redact_text(&content);
        // `redact_text` rend les lignes jointes par `\n` : le saut final et la
        // casse des fins de ligne ne sont pas un caviardage.
        let plain = content.lines().collect::<Vec<_>>().join("\n");
        value["redacted"] = json!(masked != plain);
        let trailing = if content.ends_with('\n') { "\n" } else { "" };
        value["content"] = json!(format!("{masked}{trailing}"));
    }
    ok(redacted_names(value))
}

/// Chemins et noms d'un résultat de lecture : caviardés comme le reste.
fn redacted_names(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(entries) = value.get_mut("entries").and_then(|e| e.as_array_mut()) {
        for entry in entries {
            if let Some(name) = entry.get("name").and_then(|n| n.as_str()).map(redact_text) {
                entry["name"] = json!(name);
            }
        }
    }
    value
}

/// `{ parc, pattern, commit? }` → au plus 100 occurrences du texte fixe.
async fn search_tree(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let pattern: String = p.get("pattern")?;
    let commit: Option<String> = p.opt("commit")?;
    let core = state.core.clone();
    let answer = tokio::task::spawn_blocking(move || core.search_tree(&parc, &pattern, commit.as_deref())).await??;
    ok(redacted(serde_json::to_value(answer)?))
}

/// `{ parc }` → `{ source, branch, head, synced_at, commits_cached }`.
async fn tree_status(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let core = state.core.clone();
    ok(tokio::task::spawn_blocking(move || core.tree_status(&parc)).await??)
}

/// `{ parc, playbook, commit? }` → `ansible-playbook --syntax-check` depuis
/// l'arbre du commit : verdict, code, sortie bornée et caviardée.
async fn syntax_check(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let playbook: String = p.first(&["playbook", "playbookPath"])?;
    let commit: Option<String> = p.opt("commit")?;
    let core = state.core.clone();
    let answer = tokio::task::spawn_blocking(move || core.syntax_check(&parc, &playbook, commit.as_deref())).await??;
    ok(redacted(serde_json::to_value(answer)?))
}

/// `{ parc, commit?, ref? }` → `{ commit, head, reference }` : `git fetch` d'une
/// référence permise (la branche suivie, avancée en avance rapide, ou
/// `infra/<parc>/<nom>`), le commit demandé étant refusé s'il n'est atteignable
/// d'aucune.
async fn sync_tree(state: &AppState, scope: &Scope, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    within(scope, &parc)?;
    let commit: Option<String> = p.opt("commit")?;
    let reference: Option<String> = p.opt("ref")?;
    let core = state.core.clone();
    ok(tokio::task::spawn_blocking(move || core.sync_tree(&parc, commit.as_deref(), reference.as_deref())).await??)
}

/// Exécute un run préparé sur un fil dédié, puis le clôt : flux SSE fermé,
/// compteurs, et `--check` consigné — au nom du compte qui l'a lancé
/// (`check_print` : compte, empreinte) — quand il a réellement tourné.
///
/// Tâche détachée et non `await` dans la requête : un client qui se
/// déconnecte ne doit pas laisser un flux ouvert sur un run terminé.
fn launch(
    state: AppState,
    prepared: PreparedRun,
    check_print: Option<(String, String)>,
) -> tokio::task::JoinHandle<anyhow::Result<AnsibleRun>> {
    tokio::spawn(async move {
        let id = prepared.id().to_string();
        let sink = state.events.sink(&id);
        let core = state.core.clone();
        let outcome = tokio::task::spawn_blocking(move || core.execute_playbook(prepared, sink))
            .await
            .unwrap_or_else(|e| Err(anyhow!("run interrompu : {e}")));
        if let (Some((owner, print)), Ok(run)) = (&check_print, &outcome) {
            // Ansible a tourné jusqu'au bout (code connu) : le résultat du
            // check, bon ou mauvais, est sous les yeux de l'humain qui choisit.
            if run.exit_code.is_some() {
                state.checks.record(owner, print);
            }
        }
        crate::api::settle(&state, &id, outcome)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(
        limit: Option<&[&str]>,
        extra: &[(&str, &str)],
        tags: &[&str],
        skip: &[&str],
        commit: Option<&str>,
        no_limit: bool,
    ) -> String {
        let own = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        fingerprint(
            "web3c",
            "deploy-x.yml",
            &limit.map(own),
            &extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            &own(tags),
            &own(skip),
            &commit.map(String::from),
            no_limit,
        )
    }

    #[test]
    fn a_launch_fingerprint_ignores_order_but_not_content() {
        let a = fp(Some(&["b", "a"]), &[("k", "v"), ("j", "w")], &["t2", "t1"], &["s"], Some("c1"), false);
        let b = fp(Some(&["a", "b", "a"]), &[("j", "w"), ("k", "v")], &["t1", "t2", "t1"], &["s"], Some("c1"), false);
        assert_eq!(a, b);
        assert_ne!(a, fp(Some(&["a"]), &[], &[], &[], None, false));
        assert_eq!(
            fp(None, &[], &[], &[], None, false),
            fp(Some(&[]), &[], &[], &[], None, false),
            "sans limite = liste vide"
        );
    }

    #[test]
    fn every_field_of_the_launch_changes_the_fingerprint() {
        let base = fp(Some(&["a"]), &[("k", "v")], &["t"], &["s"], Some("c1"), false);
        for (name, other) in [
            ("limit", fp(Some(&["b"]), &[("k", "v")], &["t"], &["s"], Some("c1"), false)),
            ("extra_vars", fp(Some(&["a"]), &[("k", "w")], &["t"], &["s"], Some("c1"), false)),
            ("tags", fp(Some(&["a"]), &[("k", "v")], &["u"], &["s"], Some("c1"), false)),
            ("skip_tags", fp(Some(&["a"]), &[("k", "v")], &["t"], &["u"], Some("c1"), false)),
            ("commit", fp(Some(&["a"]), &[("k", "v")], &["t"], &["s"], Some("c2"), false)),
            ("commit absent", fp(Some(&["a"]), &[("k", "v")], &["t"], &["s"], None, false)),
            ("no_limit", fp(Some(&["a"]), &[("k", "v")], &["t"], &["s"], Some("c1"), true)),
        ] {
            assert_ne!(base, other, "{name} doit compter dans l'empreinte");
        }
        // Tags et skip-tags ne se confondent pas.
        assert_ne!(
            fp(None, &[], &["a"], &[], None, false),
            fp(None, &[], &[], &["a"], None, false)
        );
        // Un check sans limite n'autorise pas un run `no_limit`.
        assert_ne!(fp(None, &[], &[], &[], None, false), fp(None, &[], &[], &[], None, true));
    }

    #[test]
    fn nested_playbooks_are_judged_by_their_file_name() {
        assert_eq!(base_name("sub/deploy-fleetforge.yml"), "deploy-fleetforge.yml");
        assert_eq!(base_name("deploy-x.yml"), "deploy-x.yml");
    }

    #[test]
    fn read_results_are_redacted_string_by_string() {
        let v = redacted(json!({ "a": ["password=hunter2", { "b": "ok" }], "n": 3 }));
        assert_eq!(v, json!({ "a": ["password=[REDACTED]", { "b": "ok" }], "n": 3 }));
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(redacted(json!({ "commit": sha, "x": sha })), json!({ "commit": sha, "x": "[REDACTED-HEX]" }));
    }

    fn options(scope: &Scope, body: serde_json::Value) -> Result<RunOptions, &'static str> {
        run_options(scope, &Params::new(body)).map_err(|e| e.code())
    }

    #[test]
    fn a_check_account_always_runs_with_check_and_never_without() {
        let check = Scope { mode: crate::config::Mode::Check, ..Scope::everything() };
        let forced = RunOptions { check: true, diff: false };
        assert_eq!(options(&check, json!({})), Ok(forced), "check absent : imposé");
        assert_eq!(options(&check, json!({ "check": null })), Ok(forced));
        assert_eq!(options(&check, json!({ "check": true })), Ok(forced));
        assert_eq!(options(&check, json!({ "check": true, "diff": true })), Ok(RunOptions { check: true, diff: true }));
        assert_eq!(options(&check, json!({ "check": false })), Err("forbidden"), "refusé, pas ignoré");
        assert_eq!(options(&check, json!({ "check": "false" })), Err("invalid_argument"));
        assert_eq!(options(&check, json!({ "check": 0 })), Err("invalid_argument"));
        // Seconde barrière : quelles que soient les options, pas de run sans --check.
        assert!(ensure_check_only(&check, forced).is_ok());
        assert_eq!(ensure_check_only(&check, RunOptions::default()).map_err(|e| e.code()), Err("forbidden"));
    }

    #[test]
    fn other_accounts_keep_their_run_options() {
        for scope in [Scope::everything(), Scope { mode: crate::config::Mode::Read, ..Scope::everything() }] {
            assert_eq!(options(&scope, json!({})), Ok(RunOptions::default()), "run réel par défaut, comme avant");
            assert_eq!(options(&scope, json!({ "check": false })), Ok(RunOptions::default()));
            assert_eq!(options(&scope, json!({ "check": true })), Ok(RunOptions { check: true, diff: false }));
            assert!(ensure_check_only(&scope, RunOptions::default()).is_ok());
        }
    }

    #[test]
    fn generated_run_ids_are_valid_and_distinct() {
        let (a, b) = (generated_run_id(), generated_run_id());
        assert_ne!(a, b);
        assert!(validate_run_id(&a).is_ok());
    }
}
