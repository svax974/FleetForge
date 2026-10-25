/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Traduction HTTP des commandes du cœur.
//!
//! Une seule route — `POST /api/{commande}` — dont le corps porte exactement
//! les arguments que `invoke()` envoie côté Tauri, dans la même casse. C'est ce
//! qui permet au frontal de n'avoir qu'un aiguillage de transport à changer, et
//! non trente-quatre appels : les deux façades exposent la MÊME surface.
//!
//! Aucune règle métier ici, comme dans la façade Tauri.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use fleetforge_core::{DeployRequest, Fault, FaultKind, GroupVarEntry, Model, ProbeScope, SettingKey};
use fleetforge_providers::{AccountId, Credentials, InstanceRef, PowerAction};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::automation;
use crate::config::Role;
use crate::state::AppState;

/// Erreur rendue au client : `{ "error": <message>, "code": <code stable> }`.
///
/// Le frontal n'affiche que le message — c'est déjà ce que fait la façade
/// Tauri, qui aplatit tout en `String`. Un appelant programmatique lit le
/// code (`fleetforge_core::FaultKind::code`, `failed` pour une erreur non
/// qualifiée) et le statut HTTP.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    /// Refus métier non qualifié. 400 et non 500 : la quasi-totalité de ces
    /// erreurs sont des refus (rôle sans hôte, inventaire absent, hébergeur
    /// inconnu), pas des pannes du serveur.
    fn failed(message: String) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: "failed", message }
    }

    fn invalid(message: String) -> Self {
        Self::from_fault(&Fault::invalid(message))
    }

    fn from_fault(fault: &Fault) -> Self {
        let status = match fault.kind {
            FaultKind::InvalidArgument | FaultKind::AmbiguousHost => StatusCode::BAD_REQUEST,
            FaultKind::UnknownParc
            | FaultKind::UnknownHost
            | FaultKind::UnknownPlaybook
            | FaultKind::UnknownRun => StatusCode::NOT_FOUND,
            FaultKind::RunBusy | FaultKind::RunIdInUse | FaultKind::CheckRequired => StatusCode::CONFLICT,
            FaultKind::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            FaultKind::Upstream => StatusCode::BAD_GATEWAY,
            FaultKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        };
        Self { status, code: fault.kind.code(), message: fault.message.clone() }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast_ref::<Fault>() {
            Some(fault) => Self::from_fault(fault),
            None => Self::failed(e.to_string()),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::invalid(format!("corps JSON invalide : {e}"))
    }
}

// Une conversion générique `impl<E: Display> From<E>` serait refusée par la
// cohérence des traits (elle chevaucherait `From<T> for T`). Les sources
// d'erreur qui traversent réellement cette couche sont donc écrites une à une.
macro_rules! from_error {
    ($($ty:ty),* $(,)?) => {
        $(impl From<$ty> for ApiError {
            fn from(e: $ty) -> Self {
                ApiError::failed(e.to_string())
            }
        })*
    };
}

from_error!(tokio::task::JoinError, fleetforge_providers::ProviderError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message, "code": self.code }))).into_response()
    }
}

pub type ApiResult = Result<Json<Value>, ApiError>;

/// Arguments d'un appel, tels que le frontal les envoie.
pub struct Params(Value);

impl Params {
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T, ApiError> {
        self.opt(key)?
            .ok_or_else(|| ApiError::invalid(format!("argument manquant : {key}")))
    }

    /// Argument facultatif. Absent et `null` sont traités pareil : le frontal
    /// envoie l'un ou l'autre selon les appels (`serviceName: name ?? null`).
    pub fn opt<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, ApiError> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(raw) => serde_json::from_value(raw.clone())
                .map(Some)
                .map_err(|e| ApiError::invalid(format!("argument {key} invalide : {e}"))),
        }
    }

    fn opt_or_default<T: DeserializeOwned + Default>(&self, key: &str) -> Result<T, ApiError> {
        Ok(self.opt(key)?.unwrap_or_default())
    }

    /// Premier des noms présents — le frontal et l'API d'automatisation
    /// nomment certains arguments différemment (`inventoryPath` / `parc`).
    pub fn first_opt<T: DeserializeOwned>(&self, keys: &[&str]) -> Result<Option<T>, ApiError> {
        for key in keys {
            if let Some(value) = self.opt(key)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub fn first<T: DeserializeOwned>(&self, keys: &[&str]) -> Result<T, ApiError> {
        self.first_opt(keys)?
            .ok_or_else(|| ApiError::invalid(format!("argument manquant : {}", keys.join(" ou "))))
    }
}

pub fn ok<T: serde::Serialize>(value: T) -> ApiResult {
    Ok(Json(serde_json::to_value(value).map_err(|e| ApiError::failed(e.to_string()))?))
}

/// Compte visé par un appel : `provider` obligatoire, `account` facultatif.
///
/// Facultatif pour que les appels d'avant les comptes nommés continuent de
/// fonctionner — ils visent alors `default`, qui est précisément le compte sous
/// lequel les identifiants d'une version antérieure sont repris.
fn account_id(p: &Params) -> Result<AccountId, ApiError> {
    let kind = provider_kind(&p.get::<String>("provider")?)?;
    let name = p.opt::<String>("account")?.unwrap_or_default();
    Ok(if name.trim().is_empty() {
        AccountId::default_for(kind)
    } else {
        AccountId::new(kind, &name)
    })
}

fn provider_kind(name: &str) -> Result<fleetforge_core::model::ProviderKind, ApiError> {
    fleetforge_core::model::ProviderKind::parse(name)
        .ok_or_else(|| ApiError::invalid(format!("provider inconnu : {name}")))
}

pub async fn dispatch(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(command): Path<String>,
    body: String,
) -> ApiResult {
    // Rôle absent = requête qui n'est pas passée par l'authentification :
    // traitée comme la moins privilégiée.
    let role = role.map_or(Role::Automation, |Extension(r)| r);
    // Corps lu en texte plutôt que par l'extracteur `Json` : une commande sans
    // argument est appelée avec un corps vide, que `Json` rejetterait avant
    // même d'arriver ici — l'erreur parlerait alors de désérialisation là où le
    // frontal n'a rien fait de mal.
    let p = Params(if body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body)?
    });
    let core = state.core.clone();
    let hub = state.hub.clone();

    match command.as_str() {
        // === Réglages ===
        "get_inventories_path" => ok(core.get_setting(SettingKey::InventoriesPath)?),
        "set_inventories_path" => ok(core.set_setting(SettingKey::InventoriesPath, &p.get::<String>("path")?)?),
        "get_playbooks_path" => ok(core.get_setting(SettingKey::PlaybooksPath)?),
        "set_playbooks_path" => ok(core.set_setting(SettingKey::PlaybooksPath, &p.get::<String>("path")?)?),

        "get_selected_inventory" => ok(core
            .selected_inventory()?
            .map(|i| i.file_path)
            .unwrap_or_default()),
        "set_selected_inventory" => ok(core.set_setting(
            SettingKey::SelectedInventory,
            &p.get::<String>("inventoryPath")?,
        )?),

        // Supervision du parc SÉLECTIONNÉ. Pas de valeur globale de repli :
        // les noms d'hôtes se répètent d'un parc à l'autre, interroger la
        // mauvaise instance ne rend pas un résultat vide mais FAUX.
        "get_prometheus_url" => ok(fleet_prometheus(&core, SettingKey::PrometheusUrl)?),
        "get_prometheus_user" => ok(fleet_prometheus(&core, SettingKey::PrometheusUser)?),
        "get_prometheus_password" => ok(fleet_prometheus(&core, SettingKey::PrometheusPassword)?),
        "set_prometheus_url" => ok(set_fleet_prometheus(&core, SettingKey::PrometheusUrl, &p.get::<String>("url")?)?),
        "set_prometheus_user" => ok(set_fleet_prometheus(&core, SettingKey::PrometheusUser, &p.get::<String>("user")?)?),
        "set_prometheus_password" => ok(set_fleet_prometheus(&core, SettingKey::PrometheusPassword, &p.get::<String>("password")?)?),

        "get_fleet_prometheus" => {
            let org: String = p.get("organization")?;
            let mut out = HashMap::new();
            for (name, key) in [
                ("url", SettingKey::PrometheusUrl),
                ("user", SettingKey::PrometheusUser),
                ("password", SettingKey::PrometheusPassword),
            ] {
                let value = core
                    .with_db(|db| Ok(db.get_setting(&key.scoped(&org))?))?
                    .unwrap_or_default();
                out.insert(name.to_string(), value);
            }
            ok(out)
        }
        "set_fleet_prometheus" => {
            let org: String = p.get("organization")?;
            for (key, value) in [
                (SettingKey::PrometheusUrl, p.get::<String>("url")?),
                (SettingKey::PrometheusUser, p.get::<String>("user")?),
                (SettingKey::PrometheusPassword, p.get::<String>("password")?),
            ] {
                core.set_prometheus_for(&org, key, &value)?;
            }
            ok(())
        }

        // === Inventaire et parc ===
        "list_ansible_inventories" => ok(core.list_inventories()?),
        "get_inventory_groups" => ok(core.inventory_groups(&p.get::<String>("inventoryPath")?)?),
        "get_fleet" => ok(core.fleet_with_health(&p.get::<String>("inventoryPath")?).await?),
        "get_diagnostics" => ok(core.diagnose(&p.get::<String>("inventoryPath")?).await?),

        // === Catalogues ===
        "list_ansible_playbooks" => ok(core.list_playbooks()?),
        "list_ansible_roles" => ok(core.list_roles()?),
        "get_services_catalog" => ok(core.services_catalog()?),
        "get_available_service_names" => ok(core.service_names()?),
        "get_uninstall_role" => ok(core.uninstall_role(
            &p.get::<String>("serviceName")?,
            &p.get::<String>("action")?,
        )?),
        "get_uninstall_roles" => ok(core.uninstall_roles(
            &p.get::<Vec<String>>("serviceNames")?,
            &p.get::<Vec<String>>("actions")?,
        )?),

        // === Group vars ===
        "list_group_vars_files" => ok(core.list_group_vars_files()?),
        "read_group_vars_file" => ok(core.read_group_vars(&p.get::<String>("filename")?)?),
        "write_group_vars_file" => ok(core.write_group_vars(
            &p.get::<String>("filename")?,
            &p.get::<Vec<GroupVarEntry>>("entries")?,
        )?),

        // === Exemptions d'alertes ===
        "list_alert_rules" => ok(core.list_alert_rules(&p.get::<String>("inventoryPath")?)?),
        "set_host_alert_exclusions" => ok(core.set_alert_exclusions(
            &p.get::<String>("inventoryPath")?,
            &p.get::<String>("host")?,
            &p.get::<Vec<String>>("alerts")?,
        )?),

        // === Supervision ===
        // Avec `parc` : supervision de ce parc (forme de l'automatisation).
        "query_prometheus" => automation::query_prometheus(&state, role, &p).await,
        "get_probes" => {
            let scope = match p.opt::<String>("scope")?.unwrap_or_default().as_str() {
                "system" => ProbeScope::System,
                "service" => ProbeScope::Service,
                _ => ProbeScope::All,
            };
            ok(core.probes(scope).await?)
        }

        // === Exécution ===
        "check_ansible_available" => ok(core.ansible_available()),
        "run_ansible_deploy" => {
            let id: String = p.get("deployId")?;
            let roles: Vec<String> = p.get("roles")?;
            let req = DeployRequest {
                label: p.opt("label")?.unwrap_or_else(|| roles.join(", ")),
                id: id.clone(),
                inventory_path: p.get("inventoryPath")?,
                roles,
                hosts: p.get("hosts")?,
                extra_vars: p.opt_or_default("extraVars")?,
            };
            let sink = state.events.sink(&id);
            // `run_deploy` bloque le temps du playbook — des minutes. Le tenir
            // sur un fil d'exécution asynchrone gèlerait tout le serveur, y
            // compris le flux SSE qui rend justement compte de ce run.
            let run = tokio::task::spawn_blocking(move || core.run_deploy(req, sink)).await?;
            ok(settle(&state, &id, run)?)
        }
        // `check`, `diff`, `detach` ; validation stricte et `--check` exigé
        // pour le compte d'automatisation (voir `automation.rs`).
        "run_ansible_playbook" => automation::run_playbook(&state, role, &p).await,
        "get_active_runs" => ok(core.runs().active()),
        "get_run_handle" => ok(core.runs().get(&p.get::<String>("runId")?)),
        "clear_finished_runs" => ok(core.runs().clear_finished()),

        // === Historique et services ===
        "get_ansible_runs" => ok(core.ansible_runs()?),
        "get_ansible_run_output" => ok(core.ansible_run_output(p.get::<i64>("runId")?)?),
        "get_server_services" => ok(core.server_services(
            p.opt("serverId")?,
            p.opt::<String>("serviceName")?.as_deref(),
            p.opt::<String>("statusFilter")?.as_deref(),
        )?),
        "get_server_current_services" => ok(core.current_services(p.opt("serverId")?)?),
        "add_manual_service" => ok(core.add_manual_service(
            &p.get::<String>("serverName")?,
            &p.get::<String>("serviceName")?,
            &p.get::<String>("action")?,
            p.opt("notes")?,
        )?),

        // === Hébergeurs ===
        "list_providers" => ok(hub.statuses().await),
        "connect_provider" => {
            let account = account_id(&p)?;
            let credentials = Credentials {
                method: p.get("method")?,
                fields: p.get("fields")?,
            };
            ok(hub.connect(&account, &credentials).await?)
        }
        "reconnect_provider" => {
            let account = account_id(&p)?;
            ok(hub.reconnect(&account).await?)
        }
        "disconnect_provider" => {
            let account = account_id(&p)?;
            ok(hub.disconnect(&account).await)
        }
        "forget_provider" => {
            let account = account_id(&p)?;
            ok(hub.forget(&account).await?)
        }
        "list_instances" => {
            let kind = provider_kind(&p.get::<String>("provider")?)?;
            // Sans `account`, les instances de TOUS les comptes connectés de
            // cet hébergeur. C'est ce que la vue veut par défaut : n'en montrer
            // qu'un ferait passer les machines des autres pour absentes.
            match p.opt::<String>("account")? {
                Some(name) => {
                    ok(hub.list_instances(&AccountId::new(kind, &name)).await?)
                }
                None => {
                    let (instances, failures) = hub.list_instances_everywhere(kind).await;
                    // Un compte injoignable ne doit pas vider la liste des
                    // autres, mais se taire le ferait passer pour vide.
                    if instances.is_empty() {
                        if let Some((account, error)) = failures.into_iter().next() {
                            return Err(ApiError::failed(format!("{account} : {error}")));
                        }
                    }
                    ok(instances)
                }
            }
        }
        "run_session_action" => {
            let account = account_id(&p)?;
            let name: String = p.get("action")?;
            ok(hub.run_session_action(&account, &name).await?)
        }
        "reconnect_provider_accounts" => {
            let kind = provider_kind(&p.get::<String>("provider")?)?;
            let results: Vec<(String, Option<String>)> = hub
                .reconnect_all(kind)
                .await
                .into_iter()
                .map(|(account, result)| (account.name, result.err().map(|e| e.to_string())))
                .collect();
            ok(results)
        }
        "power_instance" => {
            let reference: InstanceRef = p.get("reference")?;
            let graceful: bool = p.opt("graceful")?.unwrap_or(false);
            let action = match p.get::<String>("action")?.as_str() {
                "start" => PowerAction::Start,
                "stop" => PowerAction::Stop { graceful },
                "reboot" => PowerAction::Reboot { graceful },
                other => return Err(ApiError::invalid(format!("action inconnue : {other}"))),
            };
            ok(hub.power(&reference, action).await?)
        }
        "reconcile_fleet" => {
            let fleet = core.fleet(&p.get::<String>("inventoryPath")?)?;
            let pairs: Vec<(String, fleetforge_providers::Reconciliation)> = hub
                .reconcile_fleet(&fleet)
                .await
                .into_iter()
                .map(|(kind, rec)| (kind.as_str().to_string(), rec))
                .collect();
            ok(pairs)
        }

        "machine_controls" => {
            let fleet = core.fleet(&p.get::<String>("inventoryPath")?)?;
            ok(hub.machine_controls(&fleet).await)
        }

        // === Modèles (catalogue Ollama) ===
        "get_models" => ok(core.with_db(|db| db.get_models())?),
        "add_model" => {
            let model: Model = p.get("model")?;
            ok(core.with_db(|db| db.add_model(model))?)
        }
        "update_model" => {
            let model: Model = p.get("model")?;
            ok(core.with_db(|db| db.update_model(model))?)
        }
        "delete_model" => {
            let id: i64 = p.get("id")?;
            ok(core.with_db(|db| db.delete_model(id))?)
        }

        // === API d'automatisation (AgentHub) — web seulement ===
        "list_hosts" => automation::list_hosts(&state, &p).await,
        "list_playbooks" => automation::list_playbooks(&state),
        "alertmanager_alerts" => automation::alertmanager_alerts(&state, &p).await,
        "ssh_diagnose" => automation::ssh_diagnose(&state, role, &p).await,
        "run_status" => automation::run_status(&state, role, &p),

        other => Err(ApiError::invalid(format!("commande inconnue : {other}"))),
    }
}

/// Clôt le flux du run et consigne son issue, quel que soit le verdict.
///
/// Les deux commandes d'exécution partagent ces trois gestes ; les recopier
/// laisserait un jour un flux SSE ouvert sur un run terminé, que le navigateur
/// rouvrirait indéfiniment.
pub fn settle(
    state: &AppState,
    run_id: &str,
    outcome: anyhow::Result<fleetforge_core::AnsibleRun>,
) -> anyhow::Result<fleetforge_core::AnsibleRun> {
    state.events.finish(run_id);
    state.record_run(
        outcome
            .as_ref()
            .is_ok_and(|run| run.status == "success"),
    );
    outcome
}

fn fleet_prometheus(core: &fleetforge_core::Core, key: SettingKey) -> anyhow::Result<String> {
    let org = core.current_organization()?;
    Ok(core.prometheus_config_for(&org)?.field(key))
}

fn set_fleet_prometheus(
    core: &fleetforge_core::Core,
    key: SettingKey,
    value: &str,
) -> anyhow::Result<()> {
    let org = core.current_organization()?;
    if org.is_empty() {
        anyhow::bail!("sélectionner un inventaire avant de configurer sa supervision");
    }
    core.set_prometheus_for(&org, key, value)
}

/// Commandes servies. Sert à la fois de sommaire lisible et de garde-fou : le
/// test `command_parity` la confronte aux bras du `match` ci-dessus ET aux
/// appels réellement écrits dans `api.ts`.
///
/// Inutilisée par le code — elle est lue depuis la SOURCE par le test, un
/// binaire n'exposant rien à un test d'intégration. C'est aussi ce qui la rend
/// fiable : elle est vérifiée telle qu'elle est écrite.
#[allow(dead_code)]
pub const COMMANDS: &[&str] = &[
    "get_inventories_path",
    "set_inventories_path",
    "get_playbooks_path",
    "set_playbooks_path",
    "get_selected_inventory",
    "set_selected_inventory",
    "get_prometheus_url",
    "set_prometheus_url",
    "get_prometheus_user",
    "set_prometheus_user",
    "get_prometheus_password",
    "set_prometheus_password",
    "get_fleet_prometheus",
    "set_fleet_prometheus",
    "list_ansible_inventories",
    "get_inventory_groups",
    "get_fleet",
    "get_diagnostics",
    "list_ansible_playbooks",
    "list_ansible_roles",
    "get_services_catalog",
    "get_available_service_names",
    "get_uninstall_role",
    "get_uninstall_roles",
    "list_group_vars_files",
    "read_group_vars_file",
    "write_group_vars_file",
    "list_alert_rules",
    "set_host_alert_exclusions",
    "query_prometheus",
    "get_probes",
    "check_ansible_available",
    "run_ansible_deploy",
    "run_ansible_playbook",
    "get_active_runs",
    "get_run_handle",
    "clear_finished_runs",
    "get_ansible_runs",
    "get_ansible_run_output",
    "get_server_services",
    "get_server_current_services",
    "add_manual_service",
    "list_providers",
    "connect_provider",
    "reconnect_provider",
    "disconnect_provider",
    "forget_provider",
    "reconnect_provider_accounts",
    "run_session_action",
    "list_instances",
    "power_instance",
    "reconcile_fleet",
    "machine_controls",
    "get_models",
    "add_model",
    "update_model",
    "delete_model",
    // API d'automatisation — web seulement, sans équivalent Tauri.
    "list_hosts",
    "list_playbooks",
    "alertmanager_alerts",
    "ssh_diagnose",
    "run_status",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qualified_fault_keeps_its_code_and_status() {
        let err: ApiError = anyhow::Error::from(Fault::new(FaultKind::RunBusy, "occupé")).into();
        assert_eq!((err.status, err.code), (StatusCode::CONFLICT, "run_busy"));
        let err: ApiError = anyhow::anyhow!("autre chose").into();
        assert_eq!((err.status, err.code), (StatusCode::BAD_REQUEST, "failed"));
        let err = Params(json!({})).get::<String>("parc").unwrap_err();
        assert_eq!((err.status, err.code), (StatusCode::BAD_REQUEST, "invalid_argument"));
    }

    #[test]
    fn aliases_are_read_in_order() {
        let p = Params(json!({ "parc": "web3c", "inventoryPath": null }));
        assert_eq!(p.first::<String>(&["inventoryPath", "parc"]).unwrap(), "web3c");
        let err = Params(json!({})).first::<String>(&["playbookPath", "playbook"]).unwrap_err();
        assert!(err.message.contains("playbookPath ou playbook"), "{}", err.message);
    }

    #[test]
    fn every_automation_command_is_served() {
        for command in crate::auth::AUTOMATION_COMMANDS {
            assert!(COMMANDS.contains(command), "{command} absente de COMMANDS");
        }
    }

    #[test]
    fn optional_arguments_accept_absent_and_null_alike() {
        // Le frontal envoie `serviceName: name ?? null` ici et rien du tout
        // là : les deux formes doivent signifier « pas de filtre », faute de
        // quoi la vue Services remonte une erreur au lieu d'une liste.
        let present = Params(json!({ "serviceName": "brk" }));
        let explicit_null = Params(json!({ "serviceName": null }));
        let absent = Params(json!({}));

        assert_eq!(
            present.opt::<String>("serviceName").unwrap().as_deref(),
            Some("brk")
        );
        assert_eq!(explicit_null.opt::<String>("serviceName").unwrap(), None);
        assert_eq!(absent.opt::<String>("serviceName").unwrap(), None);
    }

    #[test]
    fn a_missing_required_argument_names_itself() {
        let err = Params(json!({})).get::<String>("inventoryPath").unwrap_err();
        assert!(err.message.contains("inventoryPath"), "message : {}", err.message);
    }

    #[test]
    fn the_command_list_has_no_duplicate() {
        let mut sorted = COMMANDS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "commande déclarée deux fois");
    }
}
