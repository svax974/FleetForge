/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Client Prometheus et sémantique des sondes.
//!
//! La sémantique vivait jusqu'ici dans le TSX (`MonitoringView`, `DashboardView`
//! construisaient leurs PromQL à la main) et le backend n'était qu'un passe-plat.
//! Deux interfaces qui écriraient chacune leurs requêtes finiraient par ne plus
//! afficher le même parc : les requêtes sont donc ici, nommées, une seule fois.

use crate::fault::{fail, Fault, FaultKind};
use crate::models::PrometheusMetric;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::time::Duration;

/// Plafond du corps d'une réponse Prometheus lu par le serveur.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;

/// Job des exporters système (node_exporter). Défini par `prometheus_sd_jobs`
/// dans le rôle `prometheus-install`.
pub const SYSTEM_JOB: &str = "exporter";

/// Job d'auto-scrape de Prometheus, exclu des vues de service : il ne décrit
/// pas le parc mais le superviseur lui-même.
pub const SELF_JOB: &str = "prometheus";

/// Sonde `svcprobe` partagée — un exporter par MACHINE, pas par service.
pub const SVCPROBE_JOB: &str = "svcprobe";

/// Port par défaut de `svcprobe` (`svcprobe-install/defaults/main.yml`).
/// Sert de composante par défaut de l'identité machine, cf. [`crate::model::MachineKey`].
pub const SVCPROBE_DEFAULT_PORT: u16 = 9110;

/// Port par défaut de node_exporter.
pub const NODE_EXPORTER_DEFAULT_PORT: u16 = 9100;

/// Ce qu'on interroge. Les deux interfaces partagent ces requêtes plutôt que
/// d'en réécrire chacune une variante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeScope {
    /// Exporters système, tous hôtes confondus.
    System,
    /// Exporters de service : tout sauf le système et l'auto-scrape.
    Service,
    /// Les deux.
    All,
}

impl ProbeScope {
    pub fn promql(self) -> String {
        match self {
            ProbeScope::System => format!("up{{job=\"{SYSTEM_JOB}\"}}"),
            ProbeScope::Service => {
                format!("up{{job!=\"{SYSTEM_JOB}\",job!=\"{SELF_JOB}\"}}")
            }
            ProbeScope::All => "up".to_string(),
        }
    }
}

/// Une cible de scrape et son état. `up` est le seul signal qui prouve la
/// chaîne complète : une règle d'alerte peut être `health=ok` et n'interroger
/// aucune série (cf. CLAUDE.md, « vérifier une alerte par ses séries »).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Probe {
    pub instance: String,
    pub job: String,
    pub up: bool,
}

impl Probe {
    /// Adresse de la cible sans le port — c'est elle qui rattache une sonde à
    /// une machine quand l'`instance` est un couple `hôte:port`.
    pub fn address(&self) -> &str {
        self.instance.split(':').next().unwrap_or(&self.instance)
    }

    pub fn port(&self) -> Option<u16> {
        self.instance.split(':').nth(1)?.parse().ok()
    }
}

/// Projette des séries `up` brutes en sondes exploitables.
///
/// La valeur Prometheus est une chaîne (`"1"` / `"0"`) : le TSX la comparait à
/// `'1'`, ce qui traitait `"1.0"` comme un service tombé. On la lit en nombre.
pub fn parse_probes(metrics: &[PrometheusMetric]) -> Vec<Probe> {
    metrics
        .iter()
        .filter_map(|m| {
            let instance = m.metric.get("instance")?.clone();
            let job = m.metric.get("job").cloned().unwrap_or_default();
            let up = m.value.parse::<f64>().map(|v| v != 0.0).unwrap_or(false);
            Some(Probe { instance, job, up })
        })
        .collect()
}

/// Client Prometheus. Instantané uniquement (`/api/v1/query`) — c'est tout ce
/// que le parc expose derrière son authentification basique.
#[derive(Debug, Clone, Default)]
pub struct PrometheusConfig {
    pub url: String,
    pub user: String,
    pub password: String,
}

impl PrometheusConfig {
    pub fn is_configured(&self) -> bool {
        !self.url.trim().is_empty()
    }

    /// Accès par clé, pour les adaptateurs d'interface.
    pub fn field(&self, key: crate::settings::SettingKey) -> String {
        use crate::settings::SettingKey;
        match key {
            SettingKey::PrometheusUrl => self.url.clone(),
            SettingKey::PrometheusUser => self.user.clone(),
            SettingKey::PrometheusPassword => self.password.clone(),
            _ => String::new(),
        }
    }
}

pub struct PrometheusClient {
    config: PrometheusConfig,
    http: reqwest::Client,
}

impl PrometheusClient {
    pub fn new(config: PrometheusConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { config, http })
    }

    pub async fn query(&self, query: &str) -> Result<Vec<PrometheusMetric>> {
        self.query_at(query, None).await
    }

    /// Requête instantanée (`/api/v1/query`), à l'instant `time` (horodatage
    /// Unix ou RFC 3339) ou maintenant. Les identifiants partent d'ici, jamais
    /// de l'appelant. Corps lu par morceaux et plafonné
    /// ([`MAX_RESPONSE_BYTES`]) : une requête trop large ne doit pas faire
    /// tenir des centaines de mégaoctets au serveur.
    ///
    /// Seul un vecteur instantané est rendu ; une plage (`up[5m]`), un scalaire
    /// ou une chaîne sont refusés plutôt que rendus vides.
    pub async fn query_at(&self, query: &str, time: Option<&str>) -> Result<Vec<PrometheusMetric>> {
        if !self.config.is_configured() {
            return fail(FaultKind::NotConfigured, "Prometheus URL not configured");
        }
        let url = format!(
            "{}/api/v1/query",
            self.config.url.trim_end_matches('/')
        );
        let mut params = vec![("query", query)];
        if let Some(t) = time {
            params.push(("time", t));
        }
        let mut request = self.http.get(&url).query(&params);
        if !self.config.user.is_empty() {
            request = request.basic_auth(
                &self.config.user,
                if self.config.password.is_empty() {
                    None
                } else {
                    Some(&self.config.password)
                },
            );
        }

        let mut resp = request
            .send()
            .await
            .map_err(|e| Fault::new(FaultKind::Upstream, format!("Prometheus unreachable: {e}")))?;
        let too_big = || Fault::new(
            FaultKind::Upstream,
            format!("réponse de Prometheus trop volumineuse (> {} Mio) : restreindre la requête", MAX_RESPONSE_BYTES >> 20),
        );
        if resp.content_length().is_some_and(|n| n as usize > MAX_RESPONSE_BYTES) {
            return Err(too_big().into());
        }
        let mut raw = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| Fault::new(FaultKind::Upstream, format!("Prometheus unreachable: {e}")))?
        {
            if raw.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(too_big().into());
            }
            raw.extend_from_slice(&chunk);
        }
        let body: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| Fault::new(FaultKind::Upstream, format!("Invalid Prometheus response format: {e}")))?;

        if body.get("status").and_then(|s| s.as_str()) != Some("success") {
            let err = body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Unknown Prometheus error");
            // `bad_data` : la requête elle-même est fautive, pas Prometheus.
            let kind = if body.get("errorType").and_then(|t| t.as_str()) == Some("bad_data") {
                FaultKind::InvalidArgument
            } else {
                FaultKind::Upstream
            };
            return fail(kind, format!("Prometheus error: {err}"));
        }

        let result_type = body["data"]["resultType"].as_str().unwrap_or("vector");
        if result_type != "vector" {
            return fail(
                FaultKind::InvalidArgument,
                format!("résultat « {result_type} » : seule une requête rendant un vecteur instantané est servie"),
            );
        }
        let results = body["data"]["result"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid Prometheus response format"))?;

        Ok(results
            .iter()
            .filter_map(|item| {
                let metric: HashMap<String, String> = item["metric"]
                    .as_object()?
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect();
                let value_arr = item["value"].as_array()?;
                let timestamp = value_arr.first()?.as_f64().unwrap_or(0.0);
                let value = value_arr.get(1)?.as_str().unwrap_or("").to_string();
                Some(PrometheusMetric {
                    metric,
                    timestamp,
                    value,
                })
            })
            .collect())
    }

    /// Sondes d'une portée donnée, triées « en panne d'abord » — l'ordre que
    /// les deux interfaces doivent présenter, un parc sain n'ayant rien à dire.
    pub async fn probes(&self, scope: ProbeScope) -> Result<Vec<Probe>> {
        let metrics = self.query(&scope.promql()).await?;
        let mut probes = parse_probes(&metrics);
        probes.sort_by(|a, b| {
            a.up.cmp(&b.up)
                .then_with(|| a.instance.cmp(&b.instance))
        });
        Ok(probes)
    }

    /// Nombre de séries d'une métrique. Le contrôle prescrit par CLAUDE.md
    /// après tout déploiement de supervision : `count(<métrique>)` non nul,
    /// sinon l'alerte associée est décorative.
    pub async fn series_count(&self, metric: &str) -> Result<u64> {
        let res = self.query(&format!("count({metric})")).await?;
        Ok(res
            .first()
            .and_then(|m| m.value.parse::<f64>().ok())
            .unwrap_or(0.0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(instance: &str, job: &str, value: &str) -> PrometheusMetric {
        let mut m = HashMap::new();
        m.insert("instance".to_string(), instance.to_string());
        m.insert("job".to_string(), job.to_string());
        PrometheusMetric {
            metric: m,
            timestamp: 0.0,
            value: value.to_string(),
        }
    }

    #[test]
    fn scope_promql_excludes_self_scrape_from_services() {
        let q = ProbeScope::Service.promql();
        assert!(q.contains("job!=\"exporter\""));
        assert!(q.contains("job!=\"prometheus\""));
    }

    #[test]
    fn probe_value_is_read_as_a_number_not_a_string() {
        // Le TSX comparait à `'1'` : "1.0" y passait pour un service tombé.
        let probes = parse_probes(&[
            metric("10.0.0.1:9100", "exporter", "1.0"),
            metric("10.0.0.2:9100", "exporter", "0"),
        ]);
        assert!(probes[0].up);
        assert!(!probes[1].up);
    }

    #[test]
    fn probe_splits_instance_into_address_and_port() {
        let p = parse_probes(&[metric("203.0.113.10:9110", "svcprobe", "1")]);
        assert_eq!(p[0].address(), "203.0.113.10");
        assert_eq!(p[0].port(), Some(9110));
    }

    #[test]
    fn probe_without_port_keeps_full_instance_as_address() {
        let p = parse_probes(&[metric("prometheus1", "exporter", "1")]);
        assert_eq!(p[0].address(), "prometheus1");
        assert_eq!(p[0].port(), None);
    }
}
