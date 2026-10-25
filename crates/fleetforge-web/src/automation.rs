/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Commandes de l'API d'automatisation (AgentHub, poste « Infrastructure
//! Manager ») et lancement des runs de playbook.
//!
//! Servies par le même `POST /api/{commande}` que le frontal, à cette
//! différence près que le compte d'automatisation ([`Role::Automation`]) y est
//! tenu plus court que l'opérateur :
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
use crate::config::Role;
use crate::state::AppState;

/// Lignes de sortie rendues par défaut par `run_status`.
const DEFAULT_TAIL_LINES: usize = 50;
const MAX_TAIL_LINES: usize = 500;

pub async fn list_hosts(state: &AppState, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    let core = state.core.clone();
    // `ansible-inventory` est un sous-processus : hors du fil asynchrone.
    ok(tokio::task::spawn_blocking(move || core.list_hosts(&parc)).await??)
}

pub fn list_playbooks(state: &AppState) -> ApiResult {
    ok(state.core.list_playbook_summaries()?)
}

pub async fn alertmanager_alerts(state: &AppState, p: &Params) -> ApiResult {
    let parc: String = p.get("parc")?;
    ok(state.core.alertmanager_alerts(&parc).await?)
}

/// `{ host, verb, args?, parc? }`. Sans `args`, `verb` peut porter la demande
/// entière (« logs docker searxng 1h ») : elle est découpée sur les espaces,
/// puis validée comme le reste.
pub async fn ssh_diagnose(state: &AppState, role: Role, p: &Params) -> ApiResult {
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

    let core = state.core.clone();
    let (parc, entry) =
        tokio::task::spawn_blocking(move || core.find_host(parc.as_deref(), &host)).await??;
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
pub fn run_status(state: &AppState, role: Role, p: &Params) -> ApiResult {
    let id: String = p.first(&["run_id", "runId"])?;
    validate_run_id(&id)?;
    let run = state
        .core
        .runs()
        .get(&id)
        .ok_or_else(|| ApiError::from(anyhow!(Fault::new(FaultKind::UnknownRun, format!("run inconnu : {id}")))))?;
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
pub async fn run_playbook(state: &AppState, role: Role, p: &Params) -> ApiResult {
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
