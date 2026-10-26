// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Façade Tauri du cœur `fleetforge-core`.
//!
//! Chaque commande est un adaptateur : elle traduit les arguments venus du
//! frontal, délègue, et convertit l'erreur en `String`. Aucune règle métier ne
//! doit apparaître ici — ce qui s'y glisserait serait invisible au TUI.

use fleetforge_core::deploy::RunHandle;
use fleetforge_providers::{AccountId, ProviderHub, ProviderStatus};
use fleetforge_core::diagnostics::Finding;
use fleetforge_core::model::Fleet;
use fleetforge_core::{
    ansible_group_vars::GroupVarEntry, services_catalog::CatalogService, AnsibleGroup,
    AnsibleInventoryInfo, AnsiblePlaybook, AnsibleRole, AnsibleRun, Core, DeployRequest,
    PlaybookRequest, ProbeScope, PrometheusMetric, ServerService, ServerServiceState, SettingKey,
};
use std::collections::HashMap;
use tauri::State;

/// Traduit une erreur du cœur en message affichable.
fn err(e: anyhow::Error) -> String {
    e.to_string()
}

// === Réglages ===

macro_rules! setting_commands {
    ($($get:ident, $set:ident, $key:expr, $arg:ident);* $(;)?) => {
        $(
            #[tauri::command]
            async fn $get(core: State<'_, Core>) -> Result<String, String> {
                core.get_setting($key).map_err(err)
            }

            #[tauri::command]
            async fn $set(core: State<'_, Core>, $arg: String) -> Result<(), String> {
                core.set_setting($key, &$arg).map_err(err)
            }
        )*
    };
}

setting_commands! {
    get_inventories_path,   set_inventories_path,   SettingKey::InventoriesPath,    path;
    get_playbooks_path,     set_playbooks_path,     SettingKey::PlaybooksPath,      path;
}

/// Réglages de supervision — toujours ceux du parc SÉLECTIONNÉ.
///
/// Il n'existe plus de valeur globale : chaque parc a sa machine de
/// supervision, et une cascade obligeait à se demander laquelle s'appliquait.
macro_rules! fleet_prometheus_commands {
    ($($get:ident, $set:ident, $key:expr, $arg:ident);* $(;)?) => {
        $(
            #[tauri::command]
            async fn $get(core: State<'_, Core>) -> Result<String, String> {
                let org = core.current_organization().map_err(err)?;
                Ok(core.prometheus_config_for(&org).map_err(err)?.field($key))
            }

            #[tauri::command]
            async fn $set(core: State<'_, Core>, $arg: String) -> Result<(), String> {
                let org = core.current_organization().map_err(err)?;
                if org.is_empty() {
                    return Err(
                        "sélectionner un inventaire avant de configurer sa supervision".into(),
                    );
                }
                core.set_prometheus_for(&org, $key, &$arg).map_err(err)
            }
        )*
    };
}

fleet_prometheus_commands! {
    get_prometheus_url,      set_prometheus_url,      SettingKey::PrometheusUrl,      url;
    get_prometheus_user,     set_prometheus_user,     SettingKey::PrometheusUser,     user;
    get_prometheus_password, set_prometheus_password, SettingKey::PrometheusPassword, password;
}

#[tauri::command]
async fn get_selected_inventory(core: State<'_, Core>) -> Result<String, String> {
    // Passe par le cœur, qui écarte une valeur devenue obsolète : le frontal
    // s'en chargeait, le TUI aurait hérité du défaut.
    Ok(core
        .selected_inventory()
        .map_err(err)?
        .map(|i| i.file_path)
        .unwrap_or_default())
}

#[tauri::command]
async fn set_selected_inventory(
    core: State<'_, Core>,
    inventory_path: String,
) -> Result<(), String> {
    core.set_setting(SettingKey::SelectedInventory, &inventory_path)
        .map_err(err)
}

// === Inventaires et parc ===

#[tauri::command]
async fn list_ansible_inventories(
    core: State<'_, Core>,
) -> Result<Vec<AnsibleInventoryInfo>, String> {
    core.list_inventories().map_err(err)
}

#[tauri::command]
async fn get_inventory_groups(
    core: State<'_, Core>,
    inventory_path: String,
) -> Result<Vec<AnsibleGroup>, String> {
    core.inventory_groups(&inventory_path).map_err(err)
}

/// Le parc regroupé en MACHINES — ce que la vue Serveurs affiche.
#[tauri::command]
async fn get_fleet(core: State<'_, Core>, inventory_path: String) -> Result<Fleet, String> {
    core.fleet_with_health(&inventory_path).await.map_err(err)
}

#[tauri::command]
async fn get_diagnostics(
    core: State<'_, Core>,
    inventory_path: String,
) -> Result<Vec<Finding>, String> {
    core.diagnose(&inventory_path).await.map_err(err)
}

// === Catalogues ===

#[tauri::command]
async fn list_ansible_playbooks(core: State<'_, Core>) -> Result<Vec<AnsiblePlaybook>, String> {
    core.list_playbooks().map_err(err)
}

#[tauri::command]
async fn list_ansible_roles(core: State<'_, Core>) -> Result<Vec<AnsibleRole>, String> {
    core.list_roles().map_err(err)
}

#[tauri::command]
async fn get_services_catalog(core: State<'_, Core>) -> Result<Vec<CatalogService>, String> {
    core.services_catalog().map_err(err)
}

#[tauri::command]
async fn get_available_service_names(core: State<'_, Core>) -> Result<Vec<String>, String> {
    core.service_names().map_err(err)
}

#[tauri::command]
async fn get_uninstall_role(
    core: State<'_, Core>,
    service_name: String,
    action: String,
) -> Result<Option<AnsibleRole>, String> {
    core.uninstall_role(&service_name, &action).map_err(err)
}

/// Résolution en lot : une ligne de tableau par service, un seul aller-retour.
#[tauri::command]
async fn get_uninstall_roles(
    core: State<'_, Core>,
    service_names: Vec<String>,
    actions: Vec<String>,
) -> Result<HashMap<String, HashMap<String, AnsibleRole>>, String> {
    core.uninstall_roles(&service_names, &actions).map_err(err)
}

// === Group vars ===

#[tauri::command]
async fn list_group_vars_files(core: State<'_, Core>) -> Result<Vec<String>, String> {
    core.list_group_vars_files().map_err(err)
}

#[tauri::command]
async fn read_group_vars_file(
    core: State<'_, Core>,
    filename: String,
) -> Result<Vec<GroupVarEntry>, String> {
    core.read_group_vars(&filename).map_err(err)
}

#[tauri::command]
async fn write_group_vars_file(
    core: State<'_, Core>,
    filename: String,
    entries: Vec<GroupVarEntry>,
) -> Result<(), String> {
    core.write_group_vars(&filename, &entries).map_err(err)
}

// === Exemptions d'alertes ===

#[tauri::command]
async fn list_alert_rules(
    core: State<'_, Core>,
    inventory_path: String,
) -> Result<Vec<fleetforge_core::alert_rules::AlertRule>, String> {
    core.list_alert_rules(&inventory_path).map_err(err)
}

#[tauri::command]
async fn set_host_alert_exclusions(
    core: State<'_, Core>,
    inventory_path: String,
    host: String,
    alerts: Vec<String>,
) -> Result<(), String> {
    core.set_alert_exclusions(&inventory_path, &host, &alerts).map_err(err)
}

// === Prometheus ===

#[tauri::command]
async fn query_prometheus(
    core: State<'_, Core>,
    query: String,
) -> Result<Vec<PrometheusMetric>, String> {
    core.query_prometheus(&query).await.map_err(err)
}

/// Supervision propre à un parc. Le réglage global reste le défaut : une
/// configuration existante continue de fonctionner sans rien changer.
#[tauri::command]
async fn get_fleet_prometheus(
    core: State<'_, Core>,
    organization: String,
) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for (name, key) in [
        ("url", SettingKey::PrometheusUrl),
        ("user", SettingKey::PrometheusUser),
        ("password", SettingKey::PrometheusPassword),
    ] {
        let value = core
            .with_db(|db| Ok(db.get_setting(&key.scoped(&organization))?))
            .map_err(err)?
            .unwrap_or_default();
        out.insert(name.to_string(), value);
    }
    Ok(out)
}

#[tauri::command]
async fn set_fleet_prometheus(
    core: State<'_, Core>,
    organization: String,
    url: String,
    user: String,
    password: String,
) -> Result<(), String> {
    for (key, value) in [
        (SettingKey::PrometheusUrl, url),
        (SettingKey::PrometheusUser, user),
        (SettingKey::PrometheusPassword, password),
    ] {
        core.set_prometheus_for(&organization, key, &value)
            .map_err(err)?;
    }
    Ok(())
}

#[tauri::command]
async fn get_probes(
    core: State<'_, Core>,
    scope: String,
) -> Result<Vec<fleetforge_core::Probe>, String> {
    let scope = match scope.as_str() {
        "system" => ProbeScope::System,
        "service" => ProbeScope::Service,
        _ => ProbeScope::All,
    };
    core.probes(scope).await.map_err(err)
}

// === Exécution ===

#[tauri::command]
async fn check_ansible_available(core: State<'_, Core>) -> Result<bool, String> {
    Ok(core.ansible_available())
}

#[tauri::command]
async fn run_ansible_deploy(
    window: tauri::Window,
    core: State<'_, Core>,
    deploy_id: String,
    label: Option<String>,
    inventory_path: String,
    roles: Vec<String>,
    hosts: Vec<String>,
    extra_vars: Option<HashMap<String, String>>,
) -> Result<AnsibleRun, String> {
    let event = format!("ansible_output_{deploy_id}");
    let req = DeployRequest {
        id: deploy_id,
        label: label.unwrap_or_else(|| roles.join(", ")),
        inventory_path,
        roles,
        hosts,
        extra_vars: extra_vars.unwrap_or_default(),
    };
    core.run_deploy(req, move |line| {
        let _ = window.emit(&event, line);
    })
    .map_err(err)
}

#[tauri::command]
async fn run_ansible_playbook(
    window: tauri::Window,
    core: State<'_, Core>,
    deploy_id: String,
    label: Option<String>,
    playbook_path: String,
    inventory_path: String,
    limit_hosts: Option<Vec<String>>,
    extra_vars: Option<HashMap<String, String>>,
) -> Result<AnsibleRun, String> {
    let event = format!("ansible_output_{deploy_id}");
    let req = PlaybookRequest {
        id: deploy_id,
        label: label.unwrap_or_else(|| playbook_path.clone()),
        playbook_path,
        inventory_path,
        limit_hosts,
        extra_vars: extra_vars.unwrap_or_default(),
    };
    core.run_playbook(req, move |line| {
        let _ = window.emit(&event, line);
    })
    .map_err(err)
}

/// Runs en cours. Le registre vivait en mémoire React : une interface qui
/// rouvrait ne voyait plus le déploiement lancé par l'autre.
#[tauri::command]
async fn get_active_runs(core: State<'_, Core>) -> Result<Vec<RunHandle>, String> {
    Ok(core.runs().active())
}

#[tauri::command]
async fn get_run_handle(core: State<'_, Core>, run_id: String) -> Result<Option<RunHandle>, String> {
    Ok(core.runs().get(&run_id))
}

#[tauri::command]
async fn clear_finished_runs(core: State<'_, Core>) -> Result<(), String> {
    core.runs().clear_finished();
    Ok(())
}

// === Historique et services ===

#[tauri::command]
async fn get_ansible_runs(core: State<'_, Core>) -> Result<Vec<AnsibleRun>, String> {
    core.ansible_runs().map_err(err)
}

#[tauri::command]
async fn get_ansible_run_output(core: State<'_, Core>, run_id: i64) -> Result<String, String> {
    core.ansible_run_output(run_id).map_err(err)
}

#[tauri::command]
async fn get_server_services(
    core: State<'_, Core>,
    server_id: Option<i64>,
    service_name: Option<String>,
    status_filter: Option<String>,
) -> Result<Vec<ServerService>, String> {
    core.server_services(server_id, service_name.as_deref(), status_filter.as_deref())
        .map_err(err)
}

#[tauri::command]
async fn get_server_current_services(
    core: State<'_, Core>,
    server_id: Option<i64>,
) -> Result<Vec<ServerServiceState>, String> {
    core.current_services(server_id).map_err(err)
}

#[tauri::command]
async fn get_fleet_services(
    core: State<'_, Core>,
    inventory_path: String,
) -> Result<Vec<ServerServiceState>, String> {
    core.fleet_services(&inventory_path).map_err(err)
}

#[tauri::command]
fn list_actions(
    subject: fleetforge_core::actions::Subject,
    context: fleetforge_core::actions::ActionContext,
) -> Vec<fleetforge_core::actions::ItemAction> {
    fleetforge_core::actions::actions_for(subject, &context)
}

#[tauri::command]
async fn add_manual_service(
    core: State<'_, Core>,
    server_name: String,
    service_name: String,
    action: String,
    notes: Option<String>,
) -> Result<ServerService, String> {
    core.add_manual_service(&server_name, &service_name, &action, notes)
        .map_err(err)
}

// === Hébergeurs ===

/// Ce qu'on sait d'un hébergeur AVANT toute connexion : capacités réelles,
/// méthodes d'authentification détectées, outil manquant le cas échéant.
#[tauri::command]
async fn list_providers(hub: State<'_, ProviderHub>) -> Result<Vec<ProviderStatus>, String> {
    Ok(hub.statuses().await)
}

/// Compte visé : `provider` obligatoire, `account` facultatif.
///
/// Facultatif pour que les appels d'avant les comptes nommés continuent de
/// fonctionner — ils visent `default`, qui est le compte sous lequel les
/// identifiants d'une version antérieure sont repris.
fn account_of(provider: &str, account: Option<String>) -> Result<AccountId, String> {
    let kind = fleetforge_core::model::ProviderKind::parse(provider)
        .ok_or_else(|| format!("provider inconnu : {provider}"))?;
    let name = account.unwrap_or_default();
    Ok(if name.trim().is_empty() {
        AccountId::default_for(kind)
    } else {
        AccountId::new(kind, &name)
    })
}

#[tauri::command]
async fn connect_provider(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
    method: String,
    fields: HashMap<String, String>,
) -> Result<(), String> {
    let id = account_of(&provider, account)?;
    hub.connect(&id, &fleetforge_providers::Credentials { method, fields })
        .await
        .map_err(|e| e.to_string())
}

/// Reconnecte depuis les identifiants enregistrés, sans redemander de secret.
#[tauri::command]
async fn reconnect_provider(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
) -> Result<(), String> {
    let id = account_of(&provider, account)?;
    hub.reconnect(&id).await.map_err(|e| e.to_string())
}

/// Rouvre TOUS les comptes enregistrés d'un hébergeur. Rend, par compte,
/// l'erreur éventuelle : une tenancy expirée ne doit pas empêcher les autres.
#[tauri::command]
async fn reconnect_provider_accounts(
    hub: State<'_, ProviderHub>,
    provider: String,
) -> Result<Vec<(String, Option<String>)>, String> {
    let kind = fleetforge_core::model::ProviderKind::parse(&provider)
        .ok_or_else(|| format!("provider inconnu : {provider}"))?;
    Ok(hub
        .reconnect_all(kind)
        .await
        .into_iter()
        .map(|(account, result)| (account.name, result.err().map(|e| e.to_string())))
        .collect())
}

/// Exécute une commande de session (renouvellement de jeton, par exemple).
/// Ne sont proposées que celles que l'application mène à bien SEULE.
#[tauri::command]
async fn run_session_action(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
    action: String,
) -> Result<String, String> {
    let id = account_of(&provider, account)?;
    hub.run_session_action(&id, &action)
        .await
        .map_err(|e| e.to_string())
}

/// Ferme la session. Les identifiants restent enregistrés — les effacer serait
/// `forget_provider`, et confondre les deux rendait la déconnexion destructive.
#[tauri::command]
async fn disconnect_provider(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
) -> Result<(), String> {
    let id = account_of(&provider, account)?;
    hub.disconnect(&id).await;
    Ok(())
}

#[tauri::command]
async fn forget_provider(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
) -> Result<(), String> {
    let id = account_of(&provider, account)?;
    hub.forget(&id).await.map_err(|e| e.to_string())
}

/// Sans `account`, les instances de TOUS les comptes connectés de cet
/// hébergeur : n'en montrer qu'un ferait passer les machines des autres pour
/// absentes.
#[tauri::command]
async fn list_instances(
    hub: State<'_, ProviderHub>,
    provider: String,
    account: Option<String>,
) -> Result<Vec<fleetforge_providers::Instance>, String> {
    let kind = fleetforge_core::model::ProviderKind::parse(&provider)
        .ok_or_else(|| format!("provider inconnu : {provider}"))?;

    match account.filter(|a| !a.trim().is_empty()) {
        Some(name) => hub
            .list_instances(&AccountId::new(kind, &name))
            .await
            .map_err(|e| e.to_string()),
        None => {
            let (instances, failures) = hub.list_instances_everywhere(kind).await;
            // Se taire sur un échec ferait passer une liste vide pour un
            // hébergeur sans instance.
            if instances.is_empty() {
                if let Some((account, error)) = failures.into_iter().next() {
                    return Err(format!("{account} : {error}"));
                }
            }
            Ok(instances)
        }
    }
}

#[tauri::command]
async fn power_instance(
    hub: State<'_, ProviderHub>,
    reference: fleetforge_providers::InstanceRef,
    action: String,
    graceful: bool,
) -> Result<(), String> {
    use fleetforge_providers::PowerAction;
    let action = match action.as_str() {
        "start" => PowerAction::Start,
        "stop" => PowerAction::Stop { graceful },
        "reboot" => PowerAction::Reboot { graceful },
        other => return Err(format!("action inconnue : {other}")),
    };
    hub.power(&reference, action).await.map_err(|e| e.to_string())
}

/// Rapprochement instances ↔ machines d'inventaire, sur `(provider, adresse)`.
/// C'est le lien que la fusion des deux outils existe pour établir.
#[tauri::command]
async fn reconcile_fleet(
    core: State<'_, Core>,
    hub: State<'_, ProviderHub>,
    inventory_path: String,
) -> Result<Vec<(String, fleetforge_providers::Reconciliation)>, String> {
    let fleet = core.fleet(&inventory_path).map_err(err)?;
    Ok(hub
        .reconcile_fleet(&fleet)
        .await
        .into_iter()
        .map(|(kind, rec)| (kind.as_str().to_string(), rec))
        .collect())
}

/// Ce que chaque machine d'inventaire permet de piloter chez son hébergeur.
///
/// Les écrans Serveurs et Hôtes ne pouvaient qu'AFFICHER le parc : pour
/// éteindre une machine il fallait passer par l'écran Providers et y refaire
/// à la main le rapprochement que le cœur sait faire.
#[tauri::command]
async fn machine_controls(
    core: State<'_, Core>,
    hub: State<'_, ProviderHub>,
    inventory_path: String,
) -> Result<Vec<fleetforge_providers::MachineControl>, String> {
    let fleet = core.fleet(&inventory_path).map_err(err)?;
    Ok(hub.machine_controls(&fleet).await)
}

// === Modèles (catalogue Ollama) ===

#[tauri::command]
async fn get_models(core: State<'_, Core>) -> Result<Vec<fleetforge_core::Model>, String> {
    core.with_db(|db| db.get_models()).map_err(err)
}

#[tauri::command]
async fn add_model(
    core: State<'_, Core>,
    model: fleetforge_core::Model,
) -> Result<fleetforge_core::Model, String> {
    core.with_db(|db| db.add_model(model)).map_err(err)
}

#[tauri::command]
async fn update_model(core: State<'_, Core>, model: fleetforge_core::Model) -> Result<(), String> {
    core.with_db(|db| db.update_model(model)).map_err(err)
}

#[tauri::command]
async fn delete_model(core: State<'_, Core>, id: i64) -> Result<(), String> {
    core.with_db(|db| db.delete_model(id)).map_err(err)
}

fn main() {
    // L'application de bureau n'a PAS de terminal : un `eprintln!` y part dans
    // le vide, et le bandeau d'erreur de l'interface disparaît au rechargement
    // suivant. Le journal est le seul endroit où un incident reste lisible.
    fleetforge_core::logging::init("gui");

    let core = Core::new().expect("Failed to initialize core");
    core.with_db(|db| db.seed_predefined_models())
        .expect("Failed to seed predefined models");

    // Un run laissé « en cours » d'une session précédente n'existe plus : le
    // processus qui le portait est mort. Le registre repart donc vide.
    tauri::Builder::default()
        .manage(core)
        .manage(ProviderHub::new())
        .invoke_handler(tauri::generate_handler![
            // réglages
            get_inventories_path,
            set_inventories_path,
            get_playbooks_path,
            set_playbooks_path,
            get_selected_inventory,
            set_selected_inventory,
            get_prometheus_url,
            set_prometheus_url,
            get_prometheus_user,
            set_prometheus_user,
            get_prometheus_password,
            set_prometheus_password,
            // inventaire et parc
            list_ansible_inventories,
            get_inventory_groups,
            get_fleet,
            get_diagnostics,
            // catalogues
            list_ansible_playbooks,
            list_ansible_roles,
            get_services_catalog,
            get_available_service_names,
            get_uninstall_role,
            get_uninstall_roles,
            // group vars
            list_group_vars_files,
            read_group_vars_file,
            write_group_vars_file,
            // exemptions d'alertes
            list_alert_rules,
            set_host_alert_exclusions,
            // prometheus
            query_prometheus,
            get_probes,
            list_providers,
            connect_provider,
            reconnect_provider,
            disconnect_provider,
            forget_provider,
            reconnect_provider_accounts,
            run_session_action,
            list_instances,
            power_instance,
            reconcile_fleet,
            machine_controls,
            get_fleet_prometheus,
            set_fleet_prometheus,
            // exécution
            check_ansible_available,
            run_ansible_deploy,
            run_ansible_playbook,
            get_active_runs,
            get_run_handle,
            clear_finished_runs,
            // historique et services
            get_ansible_runs,
            get_ansible_run_output,
            get_server_services,
            get_server_current_services,
            get_fleet_services,
            list_actions,
            add_manual_service,
            // modèles
            get_models,
            add_model,
            update_model,
            delete_model,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
