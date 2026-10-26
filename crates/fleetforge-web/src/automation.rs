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
//!   • un run réel exige le `--check` du même lancement (`state::CheckLedger`) ;
//!   • un parc occupé répond `run_busy` au lieu d'attendre ;
//!   • les sorties rendues sont caviardées (`fleetforge_core::redact`).
//!
//! Ces commandes ne sont servies QUE par le web : un appelant distant n'a pas
//! d'équivalent dans l'application de bureau (voir CLAUDE.md § 3).

use anyhow::anyhow;
use fleetforge_core::automation::{self, validate_extra_vars, validate_run_id};
use fleetforge_core::redact::redact_text;
use fleetforge_core::{ro_gate, AnsibleRun, Fault, FaultKind, LockPolicy, PlaybookRequest, PreparedRun, RunOptions, SettingKey};
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
        return Err(ApiError::forbidden(format!("{command} : hors du mode du compte (lecture seule)")));
    }
    match command {
        "list_hosts" => list_hosts(state, scope, p).await,
        "list_playbooks" => list_playbooks(state),
        "alertmanager_alerts" => alertmanager_alerts(state, scope, p).await,
        "query_prometheus" => query_prometheus(state, role, scope, p).await,
        "ssh_diagnose" => ssh_diagnose(state, role, scope, p).await,
        "run_ansible_playbook" => run_playbook(state, role, scope, p).await,
        "run_status" => run_status(state, role, scope, p),
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
/// que l'affichage.
fn fingerprint(parc: &str, playbook: &str, limit: &Option<Vec<String>>, extra: &HashMap<String, String>) -> String {
    let mut limit: Vec<&str> = limit.iter().flatten().map(String::as_str).collect();
    limit.sort_unstable();
    limit.dedup();
    let extra: std::collections::BTreeMap<&String, &String> = extra.iter().collect();
    json!([parc, playbook, limit, extra]).to_string()
}

/// `run_ansible_playbook`.
///
/// Arguments (forme du frontal, alias de l'API d'automatisation) :
/// `playbookPath`|`playbook`, `inventoryPath`|`parc`, `limitHosts`|`limit`,
/// `extraVars`|`extra_vars`, `deployId`|`run_id` (facultatif : fabriqué sinon),
/// `label`, `check`, `diff`, `detach`.
///
/// `detach: true` rend la main dès le run inscrit (`{ run_id, state }`) ; sans
/// lui, la réponse attend la fin du run (comportement du frontal). Dans les
/// deux cas le run se termine et se clôt même si le client se déconnecte.
async fn run_playbook(state: &AppState, role: Role, scope: &Scope, p: &Params) -> ApiResult {
    let strict = role == Role::Automation;
    let playbook: String = p.first(&["playbookPath", "playbook"])?;
    let inventory: String = p.first(&["inventoryPath", "parc"])?;
    let limit: Option<Vec<String>> = p.first_opt(&["limitHosts", "limit"])?;
    let extra: HashMap<String, String> = p.first_opt(&["extraVars", "extra_vars"])?.unwrap_or_default();
    let id: String = p.first_opt(&["deployId", "run_id"])?.unwrap_or_else(generated_run_id);
    let options = RunOptions {
        check: p.opt("check")?.unwrap_or(false),
        diff: p.opt("diff")?.unwrap_or(false),
    };
    let detach: bool = p.opt("detach")?.unwrap_or(false);
    let label: String = p.opt("label")?.unwrap_or_else(|| playbook.clone());

    let core = state.core.clone();
    let mut print = None;
    if strict {
        within(scope, &inventory)?;
        // Un NOM de parc, jamais un chemin de fichier d'inventaire.
        core.parc_by_name(&inventory)?;
        validate_extra_vars(&extra, true)?;
        let resolved = automation::resolve_playbook(&core.get_setting(SettingKey::PlaybooksPath)?, &playbook)?;
        let fp = fingerprint(&inventory, &automation::playbook_name(&resolved), &limit, &extra);
        if !options.check && !state.checks.is_fresh(&fp) {
            return Err(anyhow!(Fault::new(
                FaultKind::CheckRequired,
                "run réel refusé : lancer d'abord le même playbook avec check: true \
                 (même parc, même limit, mêmes variables), il y a moins d'une heure",
            ))
            .into());
        }
        print = options.check.then_some(fp);
    }

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
    let (run_id, running) = tokio::spawn(async move {
        let prepared =
            tokio::task::spawn_blocking(move || core.prepare_playbook(req, options, lock)).await??;
        let run_id = prepared.id().to_string();
        // Avant le lancement : un `run_status` immédiat doit déjà le trouver.
        shared.run_parcs.record(&run_id, &run_parc);
        Ok::<_, anyhow::Error>((run_id, launch(shared, prepared, print)))
    })
    .await??;

    if detach {
        return ok(json!({
            "run_id": run_id,
            "state": "running",
            "check": options.check,
            "diff": options.diff,
        }));
    }
    let run = running.await??;
    let mut value = serde_json::to_value(&run)?;
    if strict {
        value["output"] = json!(redact_text(&run.output));
    }
    value["run_id"] = json!(run_id);
    ok(value)
}

/// Exécute un run préparé sur un fil dédié, puis le clôt : flux SSE fermé,
/// compteurs, et `--check` consigné quand il a réellement tourné.
///
/// Tâche détachée et non `await` dans la requête : un client qui se
/// déconnecte ne doit pas laisser un flux ouvert sur un run terminé.
fn launch(
    state: AppState,
    prepared: PreparedRun,
    check_print: Option<String>,
) -> tokio::task::JoinHandle<anyhow::Result<AnsibleRun>> {
    tokio::spawn(async move {
        let id = prepared.id().to_string();
        let sink = state.events.sink(&id);
        let core = state.core.clone();
        let outcome = tokio::task::spawn_blocking(move || core.execute_playbook(prepared, sink))
            .await
            .unwrap_or_else(|e| Err(anyhow!("run interrompu : {e}")));
        if let (Some(print), Ok(run)) = (&check_print, &outcome) {
            // Ansible a tourné jusqu'au bout (code connu) : le résultat du
            // check, bon ou mauvais, est sous les yeux de l'humain qui choisit.
            if run.exit_code.is_some() {
                state.checks.record(print);
            }
        }
        crate::api::settle(&state, &id, outcome)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_launch_fingerprint_ignores_order_but_not_content() {
        let a = fingerprint(
            "web3c",
            "deploy-x.yml",
            &Some(vec!["b".into(), "a".into()]),
            &HashMap::from([("k".into(), "v".into()), ("j".into(), "w".into())]),
        );
        let b = fingerprint(
            "web3c",
            "deploy-x.yml",
            &Some(vec!["a".into(), "b".into(), "a".into()]),
            &HashMap::from([("j".into(), "w".into()), ("k".into(), "v".into())]),
        );
        assert_eq!(a, b);
        let other = fingerprint("web3c", "deploy-x.yml", &Some(vec!["a".into()]), &HashMap::new());
        assert_ne!(a, other);
        let no_limit = fingerprint("web3c", "deploy-x.yml", &None, &HashMap::new());
        let empty_limit = fingerprint("web3c", "deploy-x.yml", &Some(vec![]), &HashMap::new());
        assert_eq!(no_limit, empty_limit, "sans limite = liste vide");
    }

    #[test]
    fn generated_run_ids_are_valid_and_distinct() {
        let (a, b) = (generated_run_id(), generated_run_id());
        assert_ne!(a, b);
        assert!(validate_run_id(&a).is_ok());
    }
}
