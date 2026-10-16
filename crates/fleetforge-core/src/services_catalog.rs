/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

/// Services catalog — build a dynamic list of available services
/// by scanning deploy-*.yml playbooks.
/// Service names are derived from playbook filenames (deploy-<service>.yml)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A service entry in the catalog
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogService {
    pub service_name: String,
    pub label: String,
    pub description: String,
    pub category: String,
    pub playbooks: Vec<String>, // playbook names that deploy this service
}

/// Scan deploy-*.yml playbooks and build a catalog of available services.
/// Service names are derived from playbook filenames.
pub fn build_services_catalog(playbooks_path: &str) -> anyhow::Result<Vec<CatalogService>> {
    let dir = resolve_playbooks_path(playbooks_path)?;
    let dir = Path::new(&dir);

    if !dir.exists() || !dir.is_dir() {
        return Ok(vec![]);
    }

    let mut services: HashMap<String, CatalogServiceBuilder> = HashMap::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Only process deploy-*.yml files
        if !name.starts_with("deploy-") {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        // Extract service name from filename: "deploy-<service>" -> "<service>"
        let service_name = name.strip_prefix("deploy-")
            .unwrap_or(&name)
            .to_string();

        let entry = services
            .entry(service_name.clone())
            .or_insert_with(CatalogServiceBuilder::new);

        entry.add_playbook(&name);
    }

    // Convert builders to final catalog entries
    let mut catalog: Vec<CatalogService> = services
        .into_iter()
        .map(|(name, builder)| {
            let (label, description) = get_service_label(&name);
            CatalogService {
                service_name: name.clone(),
                label,
                description,
                category: categorize_service(&name),
                playbooks: builder.playbooks,
            }
        })
        .collect();

    // Sort by service name
    catalog.sort_by(|a, b| a.service_name.cmp(&b.service_name));

    Ok(catalog)
}

/// Resolve playbooks path, with auto-detection fallback
fn resolve_playbooks_path(playbooks_path: &str) -> anyhow::Result<String> {
    // If path is provided and exists, use it
    if !playbooks_path.is_empty() {
        let path = Path::new(playbooks_path);
        if path.is_absolute() && path.exists() {
            return Ok(playbooks_path.to_string());
        } else if path.exists() {
            let abs_path = std::env::current_dir()?.join(path);
            return Ok(abs_path.to_string_lossy().to_string());
        }
    }

    // Try to auto-detect based on common project structures
    let candidates = [
        "Ansible/playbooks",
        "../Ansible/playbooks",
        "../../Ansible/playbooks",
        "./Ansible/playbooks",
    ];

    for candidate in &candidates {
        let path = Path::new(candidate);
        if path.is_dir() {
            let abs_path = std::env::current_dir()?.join(path);
            return Ok(abs_path.to_string_lossy().to_string());
        }
    }

    // Last resort: try to find it relative to the executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let relative = exe_dir.join("../Ansible/playbooks");
            if relative.is_dir() {
                return Ok(relative.to_string_lossy().to_string());
            }
        }
    }

    Ok(String::new())
}

/// Builder pattern for accumulating service data.
///
/// Le nom du service n'est pas repris ici : c'est déjà la clé de la table qui
/// porte le builder, l'y dupliquer laissait deux sources pour une seule vérité.
struct CatalogServiceBuilder {
    playbooks: Vec<String>,
}

impl CatalogServiceBuilder {
    fn new() -> Self {
        Self {
            playbooks: Vec::new(),
        }
    }

    fn add_playbook(&mut self, playbook: &str) {
        if !self.playbooks.contains(&playbook.to_string()) {
            self.playbooks.push(playbook.to_string());
        }
    }
}

/// French label and description for a known service name
fn get_service_label(service_name: &str) -> (String, String) {
    // Capitalize first letter
    let label = service_name.chars().next().map(|c| {
        c.to_uppercase().to_string() + &service_name.chars().skip(1).collect::<String>()
    }).unwrap_or_else(|| service_name.to_string());

    let description = match service_name {
        "monitoring" => "Supervision Prometheus du parc web3c (Docker).",
        "prometheus" => "Collecte des métriques et évaluation des règles d'alerte.",
        "alertmanager" => "Routage et notification par e-mail des alertes Prometheus.",
        "proxy" => "Reverse proxy avec terminaison SSL.",
        "back" => "Services backend.",
        "front" => "Services frontend.",
        "dbs" => "Cluster PostgreSQL avec réplication.",
        "db-single" => "Instance PostgreSQL standalone.",
        "dbfront" => "Base de données frontend.",
        "pgpool" => "Connection pooling PostgreSQL.",
        "vpn" => "Infrastructure VPN Pritunl.",
        "mailserver" => "Relai SMTP multi-domaines.",
        "rpcbtc" => "Nœud Bitcoin Core (RPC).",
        "bitcoin-exporter" => "Exporteur de métriques du nœud Bitcoin (rpcbtc-monitoring).",
        "svcprobe" => "Sonde de disponibilité partagée des services de l'hôte.",
        "docker-repo" => "Registre Docker privé.",
        "install-cert" => "Certificats Let's Encrypt.",
        "backup" => "Sauvegardes off-host (BRK, TimescaleDB, PostgreSQL, SQLite).",
        "wordpress" => "CMS WordPress.",
        "ollama" => "Runtime de serving de modèles IA.",
        "llamacpp" => "Moteur d'inférence LLM llama.cpp (llama-server).",
        "astar" => "Nœud blockchain Astar.",
        "theta-edge" => "Nœud Theta Edge.",
        _ => "Service déployable via Ansible.",
    };

    (label, description.to_string())
}

/// Categorize a service based on its name
fn categorize_service(service_name: &str) -> String {
    match service_name {
        s if s.contains("monitor")
            || s.contains("exporter")
            || s.contains("prometheus")
            || s.contains("alertmanager")
            || s.contains("grafana") =>
        {
            "Monitoring".to_string()
        }
        s if s.contains("proxy") || s.contains("nginx") || s.contains("cert") => {
            "Proxy / SSL".to_string()
        }
        s if s.contains("db") || s.contains("pgpool") || s.contains("postgresql") => {
            "Base de données".to_string()
        }
        s if s.contains("vpn") => "VPN".to_string(),
        s if s.contains("mail") => "Mail".to_string(),
        s if s.contains("btc") || s.contains("bitcoin") || s.contains("astar") || s.contains("theta") || s.contains("blockchain") => {
            "Blockchain".to_string()
        }
        s if s.contains("docker") => "Docker".to_string(),
        s if s.contains("wordpress") => "WordPress".to_string(),
        s if s.contains("ollama") || s.contains("llamacpp") => "IA / LLM".to_string(),
        s if s.contains("front") => "Frontend".to_string(),
        s if s.contains("back") => "Backend".to_string(),
        s if s.contains("ssh") || s.contains("firewall") || s.contains("security") => {
            "Sécurité".to_string()
        }
        _ => "Autre".to_string(),
    }
}

/// Get a simple list of service names from playbooks (for autocomplete)
pub fn get_service_names(playbooks_path: &str) -> anyhow::Result<Vec<String>> {
    let catalog = build_services_catalog(playbooks_path)?;
    let mut names: Vec<String> = catalog.into_iter().map(|s| s.service_name).collect();
    names.sort();
    Ok(names)
}
