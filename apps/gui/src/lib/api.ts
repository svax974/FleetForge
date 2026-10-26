/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/**
 * Seule porte vers le backend. Chaque fonction est un appel nu : la logique vit
 * dans `fleetforge-core`, partagée avec le TUI et le serveur web. Ce qui s'ajouterait
 * ici serait invisible aux autres interfaces.
 *
 * `call` masque le transport — IPC Tauri dans l'application de bureau, HTTP
 * dans le navigateur. Aucune fonction ci-dessous n'a à savoir laquelle des deux
 * la sert : les deux façades exposent la même surface, dans la même casse.
 */

import { call } from './transport'
import {
  Model, AnsibleInventoryInfo, AnsibleGroup, AnsiblePlaybook, AnsibleRole, AnsibleRun,
  GroupVarEntry, ServerService, ServerServiceState, PrometheusMetric, CatalogService,
  Fleet, Finding, Probe, ProbeScopeName, RunHandle,
  ProviderStatus, ServerProvider, Instance, InstanceRef, Reconciliation, MachineControl, AlertRule,
  ActionSubject, ActionContext, ItemAction,
} from '../types'

// === Modèles ===
export const getModels = async (): Promise<Model[]> => call('get_models')
export const addModel = async (model: Model): Promise<Model> => call('add_model', { model })
export const updateModel = async (model: Model): Promise<void> => call('update_model', { model })
export const deleteModel = async (id: number): Promise<void> => call('delete_model', { id })

// === Réglages ===
export const getInventoriesPath = async (): Promise<string> => call('get_inventories_path')
export const setInventoriesPath = async (path: string): Promise<void> => call('set_inventories_path', { path })
export const getPlaybooksPath = async (): Promise<string> => call('get_playbooks_path')
export const setPlaybooksPath = async (path: string): Promise<void> => call('set_playbooks_path', { path })

/** Le cœur écarte lui-même un inventaire devenu introuvable : cette valeur est
 *  donc toujours vide ou valide, le frontal n'a plus à s'en assurer. */
export const getSelectedInventory = async (): Promise<string> => call('get_selected_inventory')
export const setSelectedInventory = async (inventoryPath: string): Promise<void> =>
  call('set_selected_inventory', { inventoryPath })

// === Inventaire et parc ===
export const listAnsibleInventories = async (): Promise<AnsibleInventoryInfo[]> =>
  call('list_ansible_inventories')

export const getInventoryGroups = async (inventoryPath: string): Promise<AnsibleGroup[]> =>
  call('get_inventory_groups', { inventoryPath })

/** Le parc regroupé en MACHINES, sondes appliquées. Vue Serveurs. */
export const getFleet = async (inventoryPath: string): Promise<Fleet> =>
  call('get_fleet', { inventoryPath })

export const getDiagnostics = async (inventoryPath: string): Promise<Finding[]> =>
  call('get_diagnostics', { inventoryPath })

// === Catalogues ===
export const listAnsiblePlaybooks = async (): Promise<AnsiblePlaybook[]> => call('list_ansible_playbooks')
export const listAnsibleRoles = async (): Promise<AnsibleRole[]> => call('list_ansible_roles')
export const getServicesCatalog = async (): Promise<CatalogService[]> => call('get_services_catalog')
export const getAvailableServiceNames = async (): Promise<string[]> => call('get_available_service_names')

/** Le rôle qui réalise cette action sur ce service, s'il existe.
 *  La résolution vit dans le cœur : reconstruire `<service>-<action>` ici
 *  échouait sur tout service renommé (« nginx-proxy » n'est aucun rôle). */
export const getUninstallRole = async (serviceName: string, action: string): Promise<AnsibleRole | null> =>
  call('get_uninstall_role', { serviceName, action })

/** Résolution en lot — une ligne de tableau par service, un seul aller-retour. */
export const getUninstallRoles = async (
  serviceNames: string[],
  actions: string[],
): Promise<Record<string, Record<string, AnsibleRole>>> =>
  call('get_uninstall_roles', { serviceNames, actions })

// === Group vars ===
export const listGroupVarsFiles = async (): Promise<string[]> => call('list_group_vars_files')
export const readGroupVarsFile = async (filename: string): Promise<GroupVarEntry[]> =>
  call('read_group_vars_file', { filename })
export const writeGroupVarsFile = async (filename: string, entries: GroupVarEntry[]): Promise<void> =>
  call('write_group_vars_file', { filename, entries })

// === Exemptions d'alertes ===
export const listAlertRules = async (inventoryPath: string): Promise<AlertRule[]> =>
  call('list_alert_rules', { inventoryPath })

/** Remplace les exemptions de l'entrée ; effet au prochain update-prometheus-alerts.yml. */
export const setHostAlertExclusions = async (inventoryPath: string, host: string, alerts: string[]): Promise<void> =>
  call('set_host_alert_exclusions', { inventoryPath, host, alerts })

// === Services suivis ===
export const getServerServices = async (
  serverId?: number,
  serviceName?: string,
  statusFilter?: string,
): Promise<ServerService[]> =>
  call('get_server_services', {
    serverId: serverId ?? null,
    serviceName: serviceName ?? null,
    statusFilter: statusFilter ?? null,
  })

/** Services suivis sur les hôtes du parc, et d'eux seuls : le journal les
 *  indexe par nom d'hôte, et ces noms se répètent d'un parc à l'autre. */
export const getFleetServices = async (inventoryPath: string): Promise<ServerServiceState[]> =>
  call('get_fleet_services', { inventoryPath })

/** Ce qu'on peut faire sur un élément, et pourquoi pas — décidé par le cœur,
 *  comme dans le TUI. */
export const listActions = async (subject: ActionSubject, context: ActionContext): Promise<ItemAction[]> =>
  call('list_actions', { subject, context })

export const getServerCurrentServices = async (serverId?: number): Promise<ServerServiceState[]> =>
  call('get_server_current_services', { serverId: serverId ?? null })

export const addManualService = async (
  serverName: string,
  serviceName: string,
  action: string,
  notes?: string,
): Promise<ServerService> =>
  call('add_manual_service', { serverName, serviceName, action, notes: notes ?? null })

// === Prometheus ===
export const getPrometheusUrl = async (): Promise<string> => call('get_prometheus_url')
export const setPrometheusUrl = async (url: string): Promise<void> => call('set_prometheus_url', { url })
export const getPrometheusUser = async (): Promise<string> => call('get_prometheus_user')
export const setPrometheusUser = async (user: string): Promise<void> => call('set_prometheus_user', { user })
export const getPrometheusPassword = async (): Promise<string> => call('get_prometheus_password')
export const setPrometheusPassword = async (password: string): Promise<void> =>
  call('set_prometheus_password', { password })

export const queryPrometheus = async (query: string): Promise<PrometheusMetric[]> =>
  call('query_prometheus', { query })

/** Sondes `up`, triées en panne d'abord. Les PromQL vivent dans le cœur —
 *  deux interfaces qui écriraient chacune les leurs finiraient par ne plus
 *  afficher le même parc. */
export const getProbes = async (scope: ProbeScopeName = 'all'): Promise<Probe[]> =>
  call('get_probes', { scope })

// === Exécution ===
export const checkAnsibleAvailable = async (): Promise<boolean> => call('check_ansible_available')

export const runAnsibleDeploy = async (
  deployId: string,
  inventoryPath: string,
  roles: string[],
  hosts: string[],
  extraVars?: Record<string, string>,
  label?: string,
): Promise<AnsibleRun> =>
  call('run_ansible_deploy', { deployId, label: label ?? null, inventoryPath, roles, hosts, extraVars })

export const runAnsiblePlaybook = async (
  deployId: string,
  playbookPath: string,
  inventoryPath: string,
  limitHosts: string[] | null,
  extraVars?: Record<string, string>,
  label?: string,
): Promise<AnsibleRun> =>
  call('run_ansible_playbook', { deployId, label: label ?? null, playbookPath, inventoryPath, limitHosts, extraVars })

/** Runs en cours, tenus par le cœur : survivent au démontage d'une vue. */
export const getActiveRuns = async (): Promise<RunHandle[]> => call('get_active_runs')
export const getRunHandle = async (runId: string): Promise<RunHandle | null> =>
  call('get_run_handle', { runId })
export const clearFinishedRuns = async (): Promise<void> => call('clear_finished_runs')

// === Hébergeurs ===

/** Capacités RÉELLES et méthodes détectées, avant toute connexion. */
export const listProviders = async (): Promise<ProviderStatus[]> => call('list_providers')

export const connectProvider = async (
  provider: ServerProvider,
  account: string,
  method: string,
  fields: Record<string, string>,
): Promise<void> => call('connect_provider', { provider, account, method, fields })

/** Reconnecte depuis le trousseau, sans redemander de secret. */
export const reconnectProvider = async (
  provider: ServerProvider,
  account: string,
): Promise<void> => call('reconnect_provider', { provider, account })

/** Rouvre TOUS les comptes enregistrés. Rend, par compte, l'erreur éventuelle :
 *  une tenancy expirée ne doit pas empêcher les autres de s'ouvrir. */
export const reconnectProviderAccounts = async (
  provider: ServerProvider,
): Promise<[string, string | null][]> =>
  call('reconnect_provider_accounts', { provider })

/** Exécute une commande de session (renouvellement de jeton…). Rend le compte
 *  rendu à afficher. */
export const runSessionAction = async (
  provider: ServerProvider,
  account: string,
  action: string,
): Promise<string> => call('run_session_action', { provider, account, action })

/** Ferme la session ; les identifiants restent enregistrés. */
export const disconnectProvider = async (
  provider: ServerProvider,
  account: string,
): Promise<void> => call('disconnect_provider', { provider, account })

/** Oublie les identifiants — distinct de la déconnexion, et irréversible. */
export const forgetProvider = async (
  provider: ServerProvider,
  account: string,
): Promise<void> => call('forget_provider', { provider, account })

/** Renomme un compte : identifiants et session suivent, rien n'est recréé. */
export const renameProvider = async (
  provider: ServerProvider,
  account: string,
  newName: string,
): Promise<string> => call('rename_provider', { provider, account, newName })

/** Sans `account`, les instances de TOUS les comptes connectés : n'en montrer
 *  qu'un ferait passer les machines des autres pour absentes. */
export const listInstances = async (
  provider: ServerProvider,
  account?: string,
): Promise<Instance[]> => call('list_instances', { provider, account })

export const powerInstance = async (
  reference: InstanceRef,
  action: 'start' | 'stop' | 'reboot',
  graceful: boolean,
): Promise<void> => call('power_instance', { reference, action, graceful })

/** Rapprochement instances ↔ inventaire : le lien que la fusion établit. */
export const reconcileFleet = async (
  inventoryPath: string,
): Promise<[string, Reconciliation][]> => call('reconcile_fleet', { inventoryPath })

/** Ce que chaque machine du parc permet de piloter chez son hébergeur.
 *  Vide tant qu'aucun hébergeur n'est connecté : le rapprochement n'a alors
 *  rien à quoi rapprocher. */
export const machineControls = async (
  inventoryPath: string,
): Promise<MachineControl[]> => call('machine_controls', { inventoryPath })

// === Supervision par parc ===

/** Chaque parc a SA supervision : `prometheus_host` vaut `prometheus1` sur
 *  papanglabs et `monitor` sur web3c. Un réglage unique interrogeait la
 *  mauvaise instance, et comme les noms d'hôtes se répètent d'un parc à
 *  l'autre, le résultat n'était pas vide mais faux. */
export const getFleetPrometheus = async (
  organization: string,
): Promise<Record<string, string>> => call('get_fleet_prometheus', { organization })

export const setFleetPrometheus = async (
  organization: string,
  url: string,
  user: string,
  password: string,
): Promise<void> => call('set_fleet_prometheus', { organization, url, user, password })

// === Historique ===
export const getAnsibleRuns = async (): Promise<AnsibleRun[]> => call('get_ansible_runs')
export const getAnsibleRunOutput = async (runId: number): Promise<string> =>
  call('get_ansible_run_output', { runId })
