use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub id: Option<i64>,
    pub name: String,
    pub ollama_name: String,
    pub description: Option<String>,
    pub size_gb: Option<f64>,
    pub parameters: Option<String>,
    pub context_window: Option<i64>,
    pub is_predefined: bool,
    pub category: Option<String>,
    pub requires_auth: bool,
    pub icon: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleInventoryInfo {
    pub name: String,
    /// RÉFÉRENCE transmise au cœur : le nom du parc pour une entrée de
    /// `Core::list_inventories`, le chemin pour un fichier isolé. Le nom de
    /// champ date d'avant les parcs ; il est conservé pour ne pas casser les
    /// façades, qui ne font que le renvoyer tel quel.
    pub file_path: String,
    pub organization: String,
    /// Fichiers d'inventaire qui composent ce parc (un seul pour un fichier).
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleGroup {
    pub name: String,
    pub hosts: Vec<AnsibleHost>,
    pub children: Vec<AnsibleGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleHost {
    pub name: String,
    pub ansible_host: String,
    pub ansible_port: Option<u16>,
    pub ansible_user: Option<String>,
    pub hostname: Option<String>,
    pub server_type: Option<String>,
    /// Hébergeur de la machine — gcp, aws, contabo, ovh, oracle, custom.
    /// `Option` bien que la variable soit obligatoire côté Ansible : c'est
    /// justement l'oubli qu'on veut voir remonter dans l'UI, pas une valeur
    /// de repli qui le masquerait.
    pub provider: Option<String>,
    /// Familles de rôles applicables, sans le suffixe d'action
    /// (`mailrelay` → `mailrelay-install`, `-setup`, `-security`, …).
    /// MANDATORY côté Ansible (CLAUDE.md § 2) et jusqu'ici noyée dans `vars`,
    /// donc l'application ne savait pas répondre « quels rôles s'appliquent
    /// ici ». Toujours une liste : `[]` quand l'hôte ne reçoit que le socle.
    #[serde(default)]
    pub ansible_roles: Vec<String>,
    /// Alertes Prometheus dont l'entrée est exemptée, par nom de règle
    /// (`alert_exclude: [DiskWillFillSoon]`), appliquées au rendu des règles
    /// par `prometheus-alerts-update`. Voir `alert_rules`.
    #[serde(default)]
    pub alert_exclude: Vec<String>,
    /// Port de la sonde `svcprobe`. Composante de l'identité machine : deux
    /// entrées qui partagent une adresse mais pas ce port sont deux machines
    /// distinctes derrière un même NAT (cf. `hub`/`nuc` sur web3c).
    pub svcprobe_port: Option<u16>,
    /// Port de node_exporter, redéfini sur les machines à NAT partagé.
    pub monitor_port: Option<u16>,
    /// Groupes d'inventaire auxquels l'hôte appartient, du plus général au
    /// plus spécifique. Rempli à l'aplatissement de l'arbre.
    #[serde(default)]
    pub groups: Vec<String>,
    pub vars: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleRole {
    pub name: String,
    pub label: String,
    pub category: String,
    pub description: String,
    pub path: String,
    pub has_tasks: bool,
    pub has_templates: bool,
    pub has_handlers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleRun {
    pub id: Option<i64>,
    pub inventory: String,
    pub roles: Vec<String>,
    pub hosts: Vec<String>,
    pub status: String,
    pub output: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// Code de sortie d'`ansible-playbook` du run qui vient de s'achever. Non
    /// persisté : `None` pour un run relu en base.
    #[serde(default)]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsiblePlaybook {
    pub name: String,
    pub label: String,
    pub category: String,
    pub description: String,
    pub path: String,
    pub hosts: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerService {
    pub id: Option<i64>,
    pub server_id: i64,
    pub server_name: String,
    pub service_name: String,
    pub action: String,         // "install"|"remove"|"purge"|"update"|"security"
    pub source: String,         // "ansible"|"ssh"
    pub role_name: Option<String>,
    pub ansible_run_id: Option<i64>,
    pub status: String,         // "success"|"failed"
    pub executed_at: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusMetric {
    pub metric: std::collections::HashMap<String, String>,
    pub timestamp: f64,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerServiceState {
    pub server_id: i64,
    pub server_name: String,
    pub service_name: String,
    pub last_action: String,
    pub last_source: String,
    pub last_role_name: Option<String>,
    pub last_ansible_run_id: Option<i64>,
    pub installed_at: String,
}
