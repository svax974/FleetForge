export interface Model {
  id?: number
  name: string
  ollama_name: string
  description?: string
  size_gb?: number
  parameters?: string
  context_window?: number
  is_predefined: boolean
  category?: string
  requires_auth: boolean
  icon?: string
  created_at?: string
  updated_at?: string
}

/** Un parc : l'union des inventaires `<parc>_*.yml`. */
export interface AnsibleInventoryInfo {
  name: string
  /** Référence renvoyée au cœur : le nom du parc (historiquement un chemin). */
  file_path: string
  organization: string
  /** Fichiers d'inventaire qui composent le parc. */
  files: string[]
}

export interface AnsibleGroup {
  name: string
  hosts: AnsibleHost[]
  children: AnsibleGroup[]
}

/** Hébergeur de la machine. Liste fermée, alignée sur `preflight_providers`
 *  (rôle host-preflight) : la même valeur écrite différemment ferait deux parcs. */
export type ServerProvider = 'gcp' | 'aws' | 'contabo' | 'ovh' | 'oracle' | 'custom'

export interface AnsibleHost {
  name: string
  ansible_host: string
  ansible_port?: number
  ansible_user?: string
  hostname?: string
  server_type?: string
  provider?: ServerProvider
  /** Familles de rôles applicables, sans suffixe d'action. Toujours une liste. */
  ansible_roles: string[]
  /** Alertes Prometheus dont l'entrée est exemptée (`alert_exclude`). */
  alert_exclude: string[]
  /** Composante de l'identité machine — cf. `MachineKey` côté cœur. */
  svcprobe_port?: number
  monitor_port?: number
  /** Groupes traversés, du niveau org au plus spécifique. */
  groups: string[]
  vars: Record<string, unknown>
}

/** Santé agrégée d'une machine. `unknown` n'est JAMAIS rendu comme sain :
 *  l'absence de sonde est le défaut que la supervision existe pour éviter. */
export type Health = 'up' | 'degraded' | 'down' | 'unknown'

/** Une MACHINE physique. Plusieurs entrées d'inventaire y cohabitent : huit
 *  sur 203.0.113.10. L'identité est `(adresse, port svcprobe)` — l'adresse
 *  seule fusionnerait `hub` et `nuc`, deux machines derrière un même NAT. */
export interface Server {
  key: { address: string; svcprobe_port: number }
  provider?: ServerProvider
  hosts: string[]
  ssh_ports: number[]
  health: Health
}

export interface Fleet {
  organization: string
  inventory_path: string
  groups: AnsibleGroup[]
  hosts: AnsibleHost[]
  servers: Server[]
}

export type Severity = 'error' | 'warning' | 'info'

export type FindingSubject =
  | { kind: 'host'; id: string }
  | { kind: 'server'; id: string }
  | { kind: 'rolefamily'; id: string }
  | { kind: 'fleet'; id: string }

/** Constat de cohérence. Chaque règle correspond à une panne silencieuse
 *  déjà payée et consignée dans CLAUDE.md. */
export interface Finding {
  severity: Severity
  subject: FindingSubject
  rule: string
  message: string
}

/** Une cible de scrape et son état. */
export interface Probe {
  instance: string
  job: string
  up: boolean
}

export type ProbeScopeName = 'system' | 'service' | 'all'

/** Ce qu'un hébergeur sait RÉELLEMENT faire. Déclaré, jamais supposé :
 *  l'UI grise ce qui n'existe pas au lieu de promettre ce qui échouera. */
export interface Capabilities {
  list: boolean
  describe: boolean
  start: boolean
  stop: boolean
  stop_graceful: boolean
  reboot: boolean
  reboot_graceful: boolean
}

export interface AuthField {
  key: string
  label: string
  secret: boolean
  /** Où trouver la valeur. Déclaré par le cœur : les trois façades affichent
   *  la même aide, une seule version à corriger. */
  hint: string
  /** Peut rester vide — l'hébergeur a un défaut utilisable. */
  optional: boolean
}

export interface AuthMethod {
  name: string
  label: string
  fields: AuthField[]
  /** Détectée sur cette machine (fichier de config, variables, CLI installé). */
  detected: boolean
}

/** Un compte chez un hébergeur, et l'état de sa session.
 *
 *  Un même hébergeur en porte plusieurs : deux tenancies Oracle, deux profils
 *  AWS, deux projets GCP. */
/** Une commande de session que l'application mène à bien SEULE.
 *  `oci session authenticate` n'en est pas : il ouvre un navigateur et attend
 *  quelqu'un devant l'écran — sur l'application servie à distance, ce
 *  navigateur s'ouvrirait sur le serveur. */
export interface SessionAction {
  name: string
  label: string
  hint: string
  /** Ouvrira un navigateur SUR LA MACHINE QUI EXÉCUTE l'application. Le cœur
   *  retire ces actions quand ce n'est pas le poste de l'opérateur ; celles
   *  qui arrivent ici sont donc lançables. */
  needs_local_browser: boolean
}

export interface AccountStatus {
  name: string
  connected: boolean
  has_saved_credentials: boolean
  /** Disponibles même sur un compte NON connecté dont la session vient d'être
   *  refusée — c'est là qu'elles servent. Vides tant que le compte n'a jamais
   *  été construit : elles dépendent de sa méthode d'authentification. */
  session_actions: SessionAction[]
}

export interface ProviderStatus {
  kind: ServerProvider
  label: string
  capabilities: Capabilities
  auth_methods: AuthMethod[]
  /** Outil requis et absent — affiché plutôt que découvert au premier clic. */
  missing_tool?: string | null
  /** Au moins un compte connecté. */
  connected: boolean
  /** Au moins un compte enregistré. */
  has_saved_credentials: boolean
  accounts: AccountStatus[]
}

export type PowerState = 'running' | 'stopped' | 'transitioning' | 'unknown'

export interface InstanceRef {
  provider: ServerProvider
  /** Compte d'où vient l'instance — ce qui route l'action d'alimentation vers
   *  la bonne connexion quand deux tenancies sont ouvertes. */
  account: string
  id: string
  /** Sans elle, les actions GCP sont impossibles — c'est ce qui manquait. */
  zone?: string | null
  region: string
}

export interface Instance {
  reference: InstanceRef
  name: string
  state: PowerState
  raw_state: string
  shape: string
  addresses: string[]
  tags: Record<string, string>
}

/** Rapprochement instances cloud ↔ machines d'inventaire, sur (provider, adresse). */
export interface Reconciliation {
  matched: { server: Server; instance: Instance }[]
  /** Instances qu'aucune entrée d'inventaire ne décrit — payées, non gérées. */
  unmanaged: Instance[]
  /** Machines d'inventaire sans instance : adresse morte ou provider déconnecté. */
  unmatched: Server[]
  /** Adresses revendiquées par plusieurs comptes. Le rapprochement retient le
   *  premier par ordre alphabétique, ce qui n'a aucune raison d'être juste. */
  ambiguous: { server: Server; accounts: string[] }[]
}

/** Ce qu'une MACHINE d'inventaire permet de piloter chez son hébergeur.
 *
 *  Porte l'état ET les capacités : sans les deux, l'écran ne peut pas décider
 *  seul quoi proposer. Une machine dont l'adresse est revendiquée par deux
 *  comptes en est absente — agir dessus depuis une liste où rien ne dit
 *  laquelle des deux tenancies répond serait piloter au hasard. */
export interface MachineControl {
  key: { address: string; svcprobe_port: number }
  hosts: string[]
  instance: InstanceRef
  /** Nom chez l'hébergeur, qui n'est pas celui de l'inventaire. */
  name: string
  state: PowerState
  raw_state: string
  capabilities: Capabilities
}

export interface AnsiblePlaybook {
  name: string
  label: string
  category: string
  description: string
  path: string
  hosts: string
  roles: string[]
}

export interface AnsibleRole {
  name: string
  label: string
  category: string
  description: string
  path: string
  has_tasks: boolean
  has_templates: boolean
  has_handlers: boolean
}

export interface AnsibleRun {
  id?: number
  inventory: string
  roles: string[]
  hosts: string[]
  status: 'running' | 'success' | 'failed'
  output: string
  started_at: string
  finished_at?: string
}

export interface GroupVarEntry {
  key: string
  value: string
  value_type: string
}

export interface ServerService {
  id?: number
  server_id: number
  server_name: string
  service_name: string
  action: 'install' | 'remove' | 'purge' | 'update' | 'security'
  source: 'ansible' | 'manual'
  role_name?: string
  ansible_run_id?: number
  status: 'success' | 'failed'
  executed_at: string
  notes?: string
}

export interface PrometheusMetric {
  metric: Record<string, string>
  timestamp: number
  value: string
}

export interface OllamaRegistryModel {
  name: string
  modified_at?: string
  size?: number
  digest?: string
  details?: {
    parent_model?: string
    format?: string
    family?: string
    families?: string[]
    parameter_size?: string
    quantization_level?: string
  }
}

/** Un run vivant, tel que le registre du cœur le tient.
 *  Remplace l'ancien `ActiveDeployment`, qui n'existait qu'en mémoire React :
 *  un déploiement lancé depuis une interface était invisible depuis l'autre. */
export interface RunHandle {
  id: string
  label: string
  kind: 'role' | 'playbook'
  roles: string[]
  hosts: string[]
  status: 'running' | 'success' | 'failed'
  started_at: string
  finished_at?: string
  output: string[]
}

export interface DeployLaunchConfig {
  id: string
  label: string
  inventoryPath: string
  roles: string[]
  hosts: string[]
  extraVars?: Record<string, string>
}

/** Règle d'alerte du gabarit partagé ; `loaded` : le parc charge son groupe. */
export interface AlertRule {
  name: string
  group: string
  loaded: boolean
}

export interface PlaybookLaunchConfig {
  id: string
  label: string
  playbookPath: string
  inventoryPath: string
  limitHosts: string[] | null
  displayHosts: string[]
  extraVars?: Record<string, string>
}

export interface ServerServiceState {
  server_id: number
  server_name: string
  service_name: string
  last_action: string
  last_source: string
  last_role_name?: string
  last_ansible_run_id?: number
  installed_at: string
}

export interface CatalogService {
  service_name: string
  label: string
  description: string
  category: string
  actions: string[]
  playbooks: string[]
}
