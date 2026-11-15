/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

// Service tracker — parse Ansible role names into (service_name, action) pairs
// and provide French labels for known service names.

use crate::database::Database;


/// Parsed representation of an Ansible role name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRole {
    pub service_name: String,
    pub action: String,
    /// Rôle d'origine. Sans lui, la correspondance était à sens unique : le
    /// frontal reconstruisait `<service>-<action>` et tombait à côté dès que
    /// le service avait été renommé (`proxy-install` → « nginx-proxy », dont
    /// aucun rôle ne porte le nom). Voir [`role_for`].
    pub role_name: String,
}

/// Map a role name to its (service_name, action) pair.
///
/// Convention (from CLAUDE.md):
///   `-install`          → action = "install"
///   `-remove`           → action = "remove"
///   `-purge`            → action = "purge"
///   `-security`         → action = "security"
///   `-setup` / `-update` → action = "update"
///
/// Known ambiguous roles are resolved via a hardcoded lookup table first.
pub fn parse_role(role_name: &str) -> ParsedRole {
    let (service_name, action) = classify(role_name);
    ParsedRole {
        service_name,
        action,
        role_name: role_name.to_string(),
    }
}

/// Table de désambiguïsation : rôle → (service, action).
///
/// Plusieurs rôles retombent volontairement sur un même service (les quatre
/// `proxy-*` sont « nginx-proxy »), la correspondance n'est donc pas injective.
/// C'est [`role_for`] qui en fournit l'inverse retenu.
fn disambiguation_table() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("db-install-master",       "postgresql",       "install"),
        ("db-install-backup",       "postgresql",       "install"),
        ("dbfront-install-master",  "postgresql-front", "install"),
        ("dbfront-install-backup",  "postgresql-front", "install"),
        ("dbpool-install",          "pgpool",           "install"),
        ("proxy-install",           "nginx-proxy",      "install"),
        ("proxy-update",            "nginx-proxy",      "update"),
        ("proxy-security",          "nginx-proxy",      "security"),
        ("proxy-certs-bind9",       "ssl-certs",        "update"),
        ("nginx-install",           "nginx",            "install"),
        ("vpn-install",             "vpn",              "install"),
        ("vpn-setup",               "vpn",              "update"),
        ("vpn-security",            "vpn",              "security"),
        ("vpn-routes-install",      "vpn",              "update"),
        ("mail-install",            "mail",             "install"),
        ("mail-setup",              "mail",             "update"),
        ("mail-remove",             "mail",             "remove"),
        ("mail-security",           "mail",             "security"),
        // Les rôles `monitor-prometheus-*` n'existent plus (déplacés dans
        // `old/`) : les laisser ici faisait déduire la famille « monitor-prometheus »
        // pour le service « prometheus », et l'inverse pointait sur des rôles
        // absents alors que `prometheus-install` est juste là.
        ("monitor-grafana-install", "grafana",          "install"),
        ("monitoring-install",      "monitoring",       "install"),
        ("monitoring-security",     "monitoring",       "security"),
        ("exporter-sys-install",    "node-exporter",    "install"),
        ("svcprobe-install",        "svcprobe",         "install"),
        // `<service>-monitoring` est l'ACTION de supervision d'un service, pas
        // un service de plus. Ces deux entrées le classaient comme
        // l'installation d'un « bitcoin-exporter » / « astar-exporter »
        // distinct : le journal d'audit comptait alors deux services là où il
        // n'y en a qu'un, et superviser `rpcbtc1` n'apparaissait jamais comme
        // une action portant sur le nœud Bitcoin.
        ("rpcbtc-monitoring",       "bitcoin-node",     "monitoring"),
        ("astar-monitoring",        "astar-node",       "monitoring"),
        ("docker-install",          "docker",           "install"),
        ("docker-repo-install",     "docker-registry",  "install"),
        ("docker-repo-security",    "docker-registry",  "security"),
        ("rpcbtc-install",          "bitcoin-node",     "install"),
        ("rpcbtc-setup",            "bitcoin-node",     "update"),
        ("rpcbtc-security",         "bitcoin-node",     "security"),
        ("rpcbtc-rpcauth",          "bitcoin-node",     "update"),
        ("astar-install",           "astar-node",       "install"),
        ("astar-security",          "astar-node",       "security"),
        ("astar-remove",            "astar-node",       "remove"),
        ("astar-purge",             "astar-node",       "purge"),
        ("deploy-astar",            "astar-node",       "install"),
        ("ollama-install",          "ollama",           "install"),
        ("ollama-security",         "ollama",           "security"),
        ("ollama-remove",           "ollama",           "remove"),
        ("ollama-purge",            "ollama",           "purge"),
        ("deploy-ollama",           "ollama",           "install"),
        ("ollama-model-remove",     "ollama-model",     "remove"),
        ("remove-ollama-model",     "ollama-model",     "remove"),
        ("ollama-model-install",    "ollama-model",     "install"),
        ("deploy-ollama-model",     "ollama-model",     "install"),
        ("install-ollama",          "ollama",           "install"),
        ("llamacpp-install",        "llamacpp",         "install"),
        ("llamacpp-security",       "llamacpp",         "security"),
        ("llamacpp-remove",         "llamacpp",         "remove"),
        ("llamacpp-purge",          "llamacpp",         "purge"),
        ("deploy-llamacpp",         "llamacpp",         "install"),
        ("llamacpp-model-install",  "llamacpp-model",   "install"),
        ("deploy-llamacpp-model",   "llamacpp-model",   "install"),
        ("wordpress-install",       "wordpress",        "install"),
        ("wordpress-backup",        "wordpress",        "update"),
        ("wordpress-restore",       "wordpress",        "update"),
        ("cert-install",            "ssl-certs",        "install"),
        ("install-cert",            "ssl-certs",        "install"),
        ("python-install",          "python",           "install"),
        ("tools-install",           "tools",            "install"),
        ("scripts-install",         "scripts",          "install"),
        ("set-hostname",            "hostname",         "update"),
        ("create-user-install",     "users",            "install"),
        ("ssh-security",            "ssh",              "security"),
        ("ssh-security-update",     "ssh",              "security"),
        ("firewall-security",       "firewall",         "security"),
        ("back-security",           "backend",          "security"),
        ("db-security",             "postgresql",       "security"),
        ("dbpool-security",         "pgpool",           "security"),
        ("front-security",          "frontend",         "security"),
    ]
}

fn classify(role_name: &str) -> (String, String) {
    let hardcoded = disambiguation_table();

    if let Some(&(_, svc, act)) = hardcoded.iter().find(|&&(r, _, _)| r == role_name) {
        return (svc.to_string(), act.to_string());
    }

    // --- Suffix-based heuristic ---
    // `-monitoring` manquait : `brk-monitoring` était donc classé comme le
    // service « brk-monitoring » installé, et non comme l'action de supervision
    // du service « brk ». Le journal d'audit comptait ainsi deux services là où
    // il n'y en a qu'un, et la vue Services affichait un doublon par famille.
    let suffixes: &[(&str, &str)] = &[
        ("-monitoring", "monitoring"),
        ("-purge",    "purge"),
        ("-remove",   "remove"),
        ("-security", "security"),
        ("-install",  "install"),
        ("-restore",  "restore"),
        ("-backup",   "backup"),
        ("-deploy",   "install"),
        ("-setup",    "update"),
        ("-update",   "update"),
    ];

    for &(suffix, action) in suffixes {
        if role_name.ends_with(suffix) {
            let svc = &role_name[..role_name.len() - suffix.len()];
            return (svc.to_string(), action.to_string());
        }
        // Also handle compound like "proxy-update" → already in hardcoded, but
        // for unknown patterns, strip the last dash-segment if it matches a suffix keyword
        if let Some(pos) = role_name.rfind(&suffix[1..]) {
            if pos > 0 && role_name.as_bytes()[pos - 1] == b'-' {
                let action_word = &role_name[pos..];
                let svc_part = &role_name[..pos - 1];
                if ["install", "remove", "purge", "security", "setup", "update"]
                    .contains(&action_word)
                {
                    let act = match action_word {
                        "setup" => "update",
                        other => other,
                    };
                    return (svc_part.to_string(), act.to_string());
                }
            }
        }
    }

    // Fallback: treat the whole name as service, action = install
    (role_name.to_string(), "install".to_string())
}

/// Inverse de [`parse_role`] : quel rôle réalise cette action sur ce service ?
///
/// C'est la moitié qui manquait. `ServicesView.tsx` reconstruisait
/// `<service>-<action>` à la main et ne trouvait rien dès que le service avait
/// été renommé par la table de désambiguïsation — le bouton « désinstaller »
/// disparaissait alors sans explication sur les services concernés.
///
/// La table étant many-to-one, on cherche d'abord un rôle qui porte exactement
/// l'action demandée pour ce service ; à défaut, on retombe sur la convention
/// `<famille>-<action>`, en repartant de la famille d'origine et non du nom de
/// service affiché.
/// Candidats, du plus sûr au plus spéculatif. C'est au CATALOGUE de trancher :
/// l'inverse est authentiquement ambigu (plusieurs rôles produisent un même
/// service, certains rôles n'ont pas de suffixe d'action du tout), et prétendre
/// le contraire est exactement ce qui faisait disparaître le bouton
/// « désinstaller » sans explication.
pub fn candidate_roles(service_name: &str, action: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |c: String| {
        if !out.contains(&c) {
            out.push(c);
        }
    };

    // 1. Un rôle déclare-t-il exactement ce couple ?
    for &(role, svc, act) in disambiguation_table() {
        if svc == service_name && act == action {
            push(role.to_string());
        }
    }

    // Certaines actions sont TRADUITES à l'analyse : `-setup` et `-deploy` ne
    // survivent pas au passage. L'inverse doit donc réessayer les suffixes
    // d'origine, faute de quoi `mailrelay-setup` ou `papangmetrics-deploy` ne
    // se retrouvent jamais eux-mêmes.
    let suffixes: Vec<&str> = match action {
        "update" => vec!["update", "setup"],
        "install" => vec!["install", "deploy"],
        other => vec![other],
    };

    // 2. La FAMILLE de rôles qui produit ce service, suffixée par convention.
    //    C'est ce qui rattrape « nginx-proxy » + « remove » → `proxy-remove`.
    if let Some(family) = family_of(service_name) {
        for s in &suffixes {
            push(format!("{family}-{s}"));
        }
    }

    // 3. Service jamais renommé : la convention nue.
    for s in suffixes {
        push(format!("{service_name}-{s}"));
    }

    // 4. Rôles sans suffixe d'action (`terraform`, `security-restrict`,
    //    `docker-repo`) : le nom du service EST le nom du rôle.
    if action == "install" {
        push(service_name.to_string());
    }

    out
}

/// Le premier candidat. Pratique quand aucun catalogue n'est disponible ;
/// préférer [`candidate_roles`] partout où il l'est.
pub fn role_for(service_name: &str, action: &str) -> Option<String> {
    candidate_roles(service_name, action).into_iter().next()
}

/// Famille de rôles dont provient un nom de service renommé.
///
/// Déduite de la table : on prend le préfixe commun des rôles qui produisent ce
/// service, ce qui évite d'entretenir une seconde liste à la main — deux listes
/// finiraient par diverger, et c'est précisément le défaut qu'on corrige.
fn family_of(service_name: &str) -> Option<String> {
    let mut families: Vec<&str> = disambiguation_table()
        .iter()
        .filter(|&&(_, svc, _)| svc == service_name)
        .filter_map(|&(role, _, act)| {
            // `proxy-install` → « proxy » ; `proxy-security` → « proxy ».
            role.find(&format!("-{act}"))
                .map(|pos| &role[..pos])
                .or_else(|| {
                    // Actions traduites (`-setup` → « update ») : retomber sur
                    // le premier segment, qui est la famille par convention.
                    role.split_once('-').map(|(head, _)| head)
                })
        })
        .collect();

    families.sort_unstable();
    families.dedup();

    // Une seule famille : l'inverse est déterminé. Plusieurs : on ne devine pas.
    match families.as_slice() {
        [only] => Some((*only).to_string()),
        _ => None,
    }
}

/// French label and one-sentence description for a known service name.
pub fn get_service_label(service_name: &str) -> (String, String) {
    match service_name {
        "ollama"           => ("Ollama (IA)".into(),         "Runtime de serving de modèles IA.".into()),
        "ollama-model"     => ("Modèle Ollama".into(),       "Modèle IA déployé via Ollama.".into()),
        "llamacpp"         => ("llama.cpp (IA)".into(),      "Moteur d'inférence LLM llama.cpp (llama-server).".into()),
        "llamacpp-model"   => ("Modèle llama.cpp".into(),    "Modèle GGUF déployé via llama.cpp.".into()),
        "fleetforge"    => ("FleetForge (web)".into(), "L'application de gestion du parc elle-même, servie en HTTP. La machine qui la porte est un nœud de contrôle Ansible.".into()),
        "monitoring"       => ("Monitoring".into(),          "Stack Prometheus + Grafana (Docker).".into()),
        "prometheus"       => ("Prometheus".into(),          "Collecte et stockage de métriques.".into()),
        "alertmanager"     => ("Alertmanager".into(),        "Routage et notification par e-mail des alertes Prometheus.".into()),
        "grafana"          => ("Grafana".into(),             "Visualisation des métriques.".into()),
        "node-exporter"    => ("Exporteur système".into(),   "Collecte métriques système (node_exporter).".into()),
        "bitcoin-exporter" => ("Exporteur Bitcoin".into(),   "Exporteur de métriques Bitcoin pour Prometheus.".into()),
        "astar-exporter"   => ("Exporteur Astar".into(),     "Exporteur de métriques Astar pour Prometheus.".into()),
        "nginx-proxy"      => ("Proxy Nginx".into(),         "Reverse proxy avec terminaison SSL.".into()),
        "nginx"            => ("Nginx".into(),               "Serveur web Nginx.".into()),
        "postgresql"       => ("PostgreSQL".into(),          "Base de données relationnelle.".into()),
        "postgresql-front" => ("PostgreSQL (frontend)".into(),"Instance PostgreSQL dédiée au frontend.".into()),
        "pgpool"           => ("PgPool".into(),              "Connection pooling PostgreSQL.".into()),
        "docker"           => ("Docker".into(),              "Moteur de conteneurs Docker CE.".into()),
        "docker-registry"  => ("Registre Docker".into(),     "Registre Docker privé.".into()),
        "vpn"              => ("VPN".into(),                 "Infrastructure VPN.".into()),
        "mail"             => ("Serveur Mail".into(),        "Stack mail (Postfix/Dovecot).".into()),
        "bitcoin-node"     => ("Nœud Bitcoin".into(),        "Nœud Bitcoin Core (RPC).".into()),
        "astar-node"       => ("Nœud Astar".into(),         "Nœud blockchain Astar.".into()),
        "ssl-certs"        => ("Certificats SSL".into(),     "Certificats Let's Encrypt.".into()),
        "wordpress"        => ("WordPress".into(),           "CMS WordPress.".into()),
        "ssh"              => ("Sécurité SSH".into(),        "Durcissement de la configuration SSH.".into()),
        "firewall"         => ("Pare-feu".into(),            "Règles de pare-feu (UFW/iptables).".into()),
        "backend"          => ("Backend".into(),             "Paramètres de sécurité backend.".into()),
        "frontend"         => ("Frontend".into(),            "Paramètres de sécurité frontend.".into()),
        "python"           => ("Python".into(),              "Runtime Python.".into()),
        "tools"            => ("Outils".into(),              "Outils généraux (git, curl, etc.).".into()),
        "scripts"          => ("Scripts".into(),             "Scripts utilitaires.".into()),
        "hostname"         => ("Hostname".into(),            "Configuration du nom d'hôte.".into()),
        "users"            => ("Utilisateurs".into(),        "Création de comptes utilisateurs.".into()),
        other => {
            let label = {
                let mut chars = other.chars();
                match chars.next() {
                    None => String::new(),
                    Some(c) => c.to_uppercase().to_string() + &chars.as_str().replace('-', " "),
                }
            };
            (label, format!("Service {}.", other))
        }
    }
}

/// Resolve an Ansible hostname to a (server_id, server_name) pair.
/// All hosts come from the Ansible inventory — server_id is always 0.
pub fn resolve_host_to_server(_db: &Database, host: &str) -> (i64, String) {
    (0, host.to_string())
}
