/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Contabo — REST direct.
//!
//! L'authentification est un `password grant` OAuth2 et l'API est un REST
//! ordinaire : quarante lignes suffisent, aucun CLI n'est requis. C'est
//! l'hébergeur de la quasi-totalité du parc papanglabs.

use crate::provider::*;
use async_trait::async_trait;
use fleetforge_core::model::ProviderKind;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

const TOKEN_URL: &str =
    "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token";
const API_URL: &str = "https://api.contabo.com/v1";

pub struct ContaboProvider {
    http: reqwest::Client,
    token: Option<String>,
}

impl Default for ContaboProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ContaboProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("client HTTP"),
            token: None,
        }
    }

    fn token(&self) -> Result<&str> {
        self.token
            .as_deref()
            .ok_or(ProviderError::NotConnected(ProviderKind::Contabo))
    }

    async fn get(&self, endpoint: &str) -> Result<Value> {
        let resp = self
            .http
            .get(format!("{API_URL}{endpoint}"))
            .bearer_auth(self.token()?)
            .header("x-request-id", request_id())
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("Contabo injoignable : {e}")))?;

        if !resp.status().is_success() {
            return Err(ProviderError::Api(format!(
                "Contabo {endpoint} : HTTP {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| ProviderError::Api(format!("réponse Contabo illisible : {e}")))
    }

    async fn action(&self, instance_id: &str, action: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API_URL}/compute/instances/{instance_id}/actions/{action}"))
            .bearer_auth(self.token()?)
            .header("x-request-id", request_id())
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("Contabo injoignable : {e}")))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ProviderError::Api(format!(
                "Contabo {action} refusé : HTTP {}",
                resp.status()
            )))
        }
    }
}

/// L'API Contabo exige un `x-request-id` par appel. Un identifiant fixe ferait
/// prendre deux actions distinctes pour un doublon et la seconde serait ignorée.
fn request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("fleetforge-{nanos}")
}

fn instance_from_json(inst: &Value) -> Instance {
    let id = inst
        .get("instanceId")
        .map(|v| v.to_string().trim_matches('"').to_string())
        .unwrap_or_default();

    let raw_state = inst
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let addresses = inst
        .get("ipConfig")
        .and_then(|c| c.get("v4"))
        .and_then(|v| v.get("ip"))
        .and_then(|v| v.as_str())
        .into_iter()
        .map(String::from)
        .collect();

    let region = inst
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    Instance {
        reference: InstanceRef {
            // Posé par le hub après listage, qui seul connaît le compte.
            account: crate::provider::DEFAULT_ACCOUNT.to_string(),
            provider: ProviderKind::Contabo,
            id: id.clone(),
            zone: None,
            region: region.clone(),
        },
        name: inst
            .get("displayName")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| inst.get("name").and_then(|v| v.as_str()))
            .unwrap_or(&id)
            .to_string(),
        state: PowerState::parse(&raw_state),
        raw_state,
        shape: inst
            .get("productName")
            .or_else(|| inst.get("productId"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        addresses,
        tags: HashMap::new(),
    }
}

#[async_trait]
impl Provider for ContaboProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Contabo
    }

    /// Contabo n'expose qu'un `/stop` et qu'un `/reboot` : pas de variante
    /// gracieuse, contrairement à ce qu'annonçait la matrice de `FEATURES.md`.
    fn capabilities(&self) -> Capabilities {
        Capabilities::HARD_ONLY
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        let detected = ["CONTABO_CLIENT_ID", "CONTABO_CLIENT_SECRET", "CONTABO_USER", "CONTABO_PASSWORD"]
            .iter()
            .all(|k| std::env::var(k).is_ok_and(|v| !v.is_empty()));

        vec![AuthMethod {
            name: "oauth2".into(),
            label: "OAuth2 (client + utilisateur API)".into(),
            detected,
            fields: vec![
                AuthField::new("CONTABO_CLIENT_ID", "Client ID")
                    .hint("Panneau client → API → « Client ID ». Ce n'est PAS l'identifiant du compte."),
                AuthField::secret("CONTABO_CLIENT_SECRET", "Client secret")
                    .hint("Même écran, juste sous le Client ID."),
                AuthField::new("CONTABO_USER", "Utilisateur API")
                    .hint("L'adresse e-mail du compte Contabo."),
                AuthField::secret("CONTABO_PASSWORD", "Mot de passe API")
                    .hint("Le mot de passe API, à générer dans le panneau — distinct de celui du compte."),
            ],
        }]
    }

    async fn connect(&mut self, credentials: &Credentials) -> Result<()> {
        // Les identifiants saisis l'emportent sur l'environnement : c'est un
        // choix explicite de l'opérateur, il doit gagner.
        let field = |k: &str| -> Result<String> {
            credentials
                .get(k)
                .map(String::from)
                .or_else(|| std::env::var(k).ok().filter(|v| !v.is_empty()))
                .ok_or_else(|| ProviderError::Auth(format!("champ `{k}` manquant")))
        };

        let params = [
            ("grant_type".to_string(), "password".to_string()),
            ("client_id".to_string(), field("CONTABO_CLIENT_ID")?),
            ("client_secret".to_string(), field("CONTABO_CLIENT_SECRET")?),
            ("username".to_string(), field("CONTABO_USER")?),
            ("password".to_string(), field("CONTABO_PASSWORD")?),
        ];

        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&params)
            .send()
            .await
            .map_err(|e| ProviderError::Auth(format!("Contabo injoignable : {e}")))?;

        if !resp.status().is_success() {
            return Err(ProviderError::Auth(format!(
                "Contabo a refusé les identifiants (HTTP {})",
                resp.status()
            )));
        }

        let body: Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Auth(format!("réponse illisible : {e}")))?;

        self.token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from);

        self.token
            .is_some()
            .then_some(())
            .ok_or_else(|| ProviderError::Auth("aucun jeton dans la réponse".into()))
    }

    fn is_connected(&self) -> bool {
        self.token.is_some()
    }

    fn disconnect(&mut self) {
        // On oublie le jeton, PAS les identifiants : le prototype effaçait le
        // fichier de credentials à la déconnexion, rendant l'action destructive
        // pour la configuration et non seulement pour la session.
        self.token = None;
    }

    async fn list_instances(&self) -> Result<Vec<Instance>> {
        let body = self.get("/compute/instances?size=100").await?;
        Ok(body
            .get("data")
            .and_then(|d| d.as_array())
            .map(|arr| arr.iter().map(instance_from_json).collect())
            .unwrap_or_default())
    }

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance> {
        let body = self
            .get(&format!("/compute/instances/{}", reference.id))
            .await?;
        body.get("data")
            .and_then(|d| d.as_array())
            .and_then(|a| a.first())
            .map(instance_from_json)
            .ok_or_else(|| ProviderError::Api(format!("instance {} introuvable", reference.id)))
    }

    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        self.ensure_allows(action)?;
        let verb = match action {
            PowerAction::Start => "start",
            PowerAction::Stop { .. } => "stop",
            PowerAction::Reboot { .. } => "restart",
        };
        self.action(&reference.id, verb).await
    }

    async fn keepalive(&self) -> Result<()> {
        self.get("/compute/instances?page=1&size=1").await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_an_instance_payload() {
        let v = json!({
            "instanceId": 12345,
            "displayName": "rpcbtc1",
            "status": "running",
            "productName": "VPS 4 SSD",
            "region": "EU",
            "ipConfig": { "v4": { "ip": "203.0.113.30" } }
        });
        let i = instance_from_json(&v);
        assert_eq!(i.reference.id, "12345");
        assert_eq!(i.name, "rpcbtc1");
        assert_eq!(i.state, PowerState::Running);
        assert!(i.has_address("203.0.113.30"));
        // Contabo n'a pas de zone : le champ reste vide plutôt que d'être inventé.
        assert!(i.reference.zone.is_none());
    }

    #[test]
    fn falls_back_to_the_id_when_no_name_is_given() {
        let v = json!({ "instanceId": 42, "status": "stopped" });
        let i = instance_from_json(&v);
        assert_eq!(i.name, "42");
        assert_eq!(i.state, PowerState::Stopped);
    }

    #[test]
    fn graceful_stop_is_refused_before_reaching_the_api() {
        // Sans ce garde-fou, la demande partirait en arrêt BRUTAL.
        let p = ContaboProvider::new();
        assert!(p.ensure_allows(PowerAction::Stop { graceful: true }).is_err());
        assert!(p.ensure_allows(PowerAction::Stop { graceful: false }).is_ok());
    }

    #[test]
    fn request_ids_are_distinct() {
        assert_ne!(request_id(), request_id());
    }

    #[test]
    fn calls_without_a_token_are_refused_locally() {
        let p = ContaboProvider::new();
        assert!(!p.is_connected());
        assert!(p.token().is_err());
    }
}
