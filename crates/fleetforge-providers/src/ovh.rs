/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! OVHcloud — REST direct.
//!
//! La signature OVH est un simple SHA-1 sur une chaîne concaténée : aucune
//! bibliothèque de crypto n'est nécessaire, l'implémentation tient en quelques
//! dizaines de lignes.

use crate::provider::*;
use async_trait::async_trait;
use fleetforge_core::model::ProviderKind;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

/// Points d'entrée régionaux. Chez OVH, ce n'est pas une « région » au sens des
/// autres hébergeurs mais le domaine d'API auquel on s'adresse.
pub const ENDPOINTS: [(&str, &str); 3] = [
    ("ovh-eu", "https://eu.api.ovh.com/1.0"),
    ("ovh-us", "https://api.us.ovhcloud.com/1.0"),
    ("ovh-ca", "https://ca.api.ovh.com/1.0"),
];

fn endpoint_url(name: &str) -> &'static str {
    ENDPOINTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, u)| *u)
        .unwrap_or(ENDPOINTS[0].1)
}

pub struct OvhProvider {
    http: reqwest::Client,
    base: &'static str,
    app_key: String,
    app_secret: String,
    consumer_key: String,
    project: Option<String>,
    /// Décalage avec l'horloge d'OVH. La signature intègre un horodatage ; une
    /// machine désynchronisée verrait tous ses appels refusés sans que rien
    /// n'indique pourquoi.
    time_delta: i64,
    connected: bool,
}

impl Default for OvhProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OvhProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("client HTTP"),
            base: ENDPOINTS[0].1,
            app_key: String::new(),
            app_secret: String::new(),
            consumer_key: String::new(),
            project: None,
            time_delta: 0,
            connected: false,
        }
    }

    fn now(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            + self.time_delta
    }

    /// `$1$` + SHA1(secret+consumer+METHOD+url+body+timestamp).
    fn signature(&self, method: &str, url: &str, body: &str, ts: i64) -> String {
        let raw = format!(
            "{}+{}+{}+{}+{}+{}",
            self.app_secret, self.consumer_key, method, url, body, ts
        );
        format!("$1${}", sha1_hex(raw.as_bytes()))
    }

    async fn request(&self, method: &str, path: &str) -> Result<Value> {
        self.request_body(method, path, None).await
    }

    /// Appel signé, avec corps optionnel.
    ///
    /// Le corps doit être passé ici et NON ajouté au `RequestBuilder` par
    /// l'appelant : il entre dans le calcul de la signature OVH. Une requête
    /// dont le corps ne serait pas celui qui a été signé est rejetée en 403,
    /// ce qui ressemble à un problème d'identifiants.
    async fn request_body(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value> {
        if !self.connected {
            return Err(ProviderError::NotConnected(ProviderKind::Ovh));
        }
        let url = format!("{}{path}", self.base);
        let ts = self.now();
        let sig = self.signature(method, &url, body.unwrap_or(""), ts);

        let builder = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            _ => return Err(ProviderError::Api(format!("méthode {method} non gérée"))),
        };
        let builder = match body {
            Some(b) => builder.body(b.to_string()),
            None => builder,
        };

        let resp = builder
            .header("X-Ovh-Application", &self.app_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Timestamp", ts.to_string())
            .header("X-Ovh-Signature", sig)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("OVH injoignable : {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(ProviderError::Auth(format!("OVH a refusé l'appel (HTTP {status})")));
        }
        if !status.is_success() {
            return Err(ProviderError::Api(format!("OVH {path} : HTTP {status}")));
        }
        // Certaines actions répondent 200 sans corps.
        let text = resp.text().await.unwrap_or_default();
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text)
            .map_err(|e| ProviderError::Api(format!("réponse OVH illisible : {e}")))
    }

    fn project(&self) -> Result<&str> {
        self.project
            .as_deref()
            .ok_or_else(|| ProviderError::Auth("projet Public Cloud non renseigné".into()))
    }
}

fn ovh_instance(inst: &Value, region_fallback: &str) -> Instance {
    let raw_state = inst
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let addresses = inst
        .get("ipAddresses")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("ip").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let region = inst
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap_or(region_fallback)
        .to_string();

    Instance {
        reference: InstanceRef {
            // Posé par le hub après listage, qui seul connaît le compte.
            account: crate::provider::DEFAULT_ACCOUNT.to_string(),
            provider: ProviderKind::Ovh,
            id: inst.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            zone: None,
            region,
        },
        name: inst
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("sans nom")
            .to_string(),
        state: PowerState::parse(&raw_state),
        raw_state,
        shape: inst
            .get("flavor")
            .and_then(|f| f.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| inst.get("planCode").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string(),
        addresses,
        tags: HashMap::new(),
    }
}

#[async_trait]
impl Provider for OvhProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Ovh
    }

    /// Relevé sur le schéma vivant (`eu.api.ovh.com/1.0/cloud.json`) :
    ///
    /// - `POST …/reboot` exige un corps `{"type": "soft"|"hard"}` (`required:
    ///   true`) — les DEUX variantes existent donc réellement ;
    /// - `POST …/start` et `POST …/stop` ne prennent aucun paramètre : il n'y
    ///   a qu'un arrêt, dont l'API ne laisse pas choisir la brutalité.
    ///
    /// `HARD_ONLY` déclarait l'inverse sur le redémarrage, et le corps
    /// obligatoire n'était pas envoyé : tout `/reboot` partait en HTTP 400.
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            list: true,
            describe: true,
            start: true,
            stop: true,
            stop_graceful: false,
            reboot: true,
            reboot_graceful: true,
        }
    }

    fn auth_methods(&self) -> Vec<AuthMethod> {
        let detected = ["OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY"]
            .iter()
            .all(|k| std::env::var(k).is_ok_and(|v| !v.is_empty()));

        vec![AuthMethod {
            name: "api_keys".into(),
            label: "Clés d'API OVH".into(),
            detected,
            fields: vec![
                AuthField::new("OVH_ENDPOINT", "Point d'entrée")
                    .hint("ovh-eu, ovh-us, ovh-ca, kimsufi-eu, soyoustart-eu. Vide = ovh-eu.")
                    .optional(),
                AuthField::new("OVH_APPLICATION_KEY", "Application key")
                    .hint("Les trois clés viennent d'un seul passage sur eu.api.ovh.com/createToken/ — y demander GET et POST sur /cloud/*."),
                AuthField::secret("OVH_APPLICATION_SECRET", "Application secret")
                    .hint("Délivré par createToken en même temps que l'application key."),
                AuthField::secret("OVH_CONSUMER_KEY", "Consumer key")
                    .hint("Troisième valeur de createToken. C'est elle qui porte les droits demandés."),
                AuthField::new("OVH_CLOUD_PROJECT_SERVICE", "Projet Public Cloud")
                    .hint("L'ID du projet (32 caractères), visible dans l'URL du manager Public Cloud."),
            ],
        }]
    }

    async fn connect(&mut self, credentials: &Credentials) -> Result<()> {
        let field = |k: &str| -> Option<String> {
            credentials
                .get(k)
                .map(String::from)
                .or_else(|| std::env::var(k).ok().filter(|v| !v.is_empty()))
        };

        self.base = endpoint_url(&field("OVH_ENDPOINT").unwrap_or_else(|| "ovh-eu".into()));
        self.app_key = field("OVH_APPLICATION_KEY")
            .ok_or_else(|| ProviderError::Auth("OVH_APPLICATION_KEY manquant".into()))?;
        self.app_secret = field("OVH_APPLICATION_SECRET")
            .ok_or_else(|| ProviderError::Auth("OVH_APPLICATION_SECRET manquant".into()))?;
        self.consumer_key = field("OVH_CONSUMER_KEY")
            .ok_or_else(|| ProviderError::Auth("OVH_CONSUMER_KEY manquant".into()))?;
        self.project = field("OVH_CLOUD_PROJECT_SERVICE");

        // Aligner l'horloge AVANT toute signature. Sans cela, une machine
        // désynchronisée voit tous ses appels refusés sans indication de cause.
        if let Ok(resp) = self.http.get(format!("{}/auth/time", self.base)).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(server) = text.trim().parse::<i64>() {
                    use std::time::{SystemTime, UNIX_EPOCH};
                    let local = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    self.time_delta = server - local;
                }
            }
        }

        self.connected = true;
        // Un appel réel valide les clés ; sans cela « connecté » ne veut rien dire.
        match self.request("GET", "/auth/currentCredential").await {
            Ok(_) => Ok(()),
            Err(e) => {
                self.connected = false;
                Err(e)
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn disconnect(&mut self) {
        self.connected = false;
        self.app_secret.clear();
        self.consumer_key.clear();
    }

    async fn list_instances(&self) -> Result<Vec<Instance>> {
        let project = self.project()?;
        let body = self
            .request("GET", &format!("/cloud/project/{project}/instance"))
            .await?;
        Ok(body
            .as_array()
            .map(|arr| arr.iter().map(|i| ovh_instance(i, "")).collect())
            .unwrap_or_default())
    }

    async fn get_instance(&self, reference: &InstanceRef) -> Result<Instance> {
        let project = self.project()?;
        let body = self
            .request(
                "GET",
                &format!("/cloud/project/{project}/instance/{}", reference.id),
            )
            .await?;
        Ok(ovh_instance(&body, &reference.region))
    }

    async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        self.ensure_allows(action)?;
        let project = self.project()?;
        let id = &reference.id;
        let (path, body) = match action {
            PowerAction::Start => (format!("/cloud/project/{project}/instance/{id}/start"), None),
            PowerAction::Stop { .. } => {
                (format!("/cloud/project/{project}/instance/{id}/stop"), None)
            }
            // `type` est obligatoire. Sans lui l'API répond 400, et c'est ce
            // qui rendait le redémarrage OVH inopérant depuis toujours.
            PowerAction::Reboot { graceful } => (
                format!("/cloud/project/{project}/instance/{id}/reboot"),
                Some(reboot_body(graceful)),
            ),
        };
        self.request_body("POST", &path, body).await.map(|_| ())
    }

    async fn keepalive(&self) -> Result<()> {
        self.request("GET", "/auth/currentCredential").await.map(|_| ())
    }
}

/// Corps obligatoire de `POST …/instance/{id}/reboot`.
///
/// `cloud.ProjectInstanceRebootCreation.type` est `required: true` et son
/// énumération vaut exactement `["hard", "soft"]`.
fn reboot_body(graceful: bool) -> &'static str {
    if graceful {
        r#"{"type":"soft"}"#
    } else {
        r#"{"type":"hard"}"#
    }
}

/// SHA-1, implémenté ici pour ne pas tirer une dépendance de plus pour la seule
/// signature OVH. L'algorithme est figé depuis 1995 et tient en trente lignes.
fn sha1_hex(data: &[u8]) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;

    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sha1_matches_the_reference_vectors() {
        // Sans ces vecteurs, une signature fausse ne se verrait qu'à l'appel,
        // sous la forme d'un 403 sans explication.
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
        // Franchit la limite de bloc de 64 octets.
        assert_eq!(
            sha1_hex(&[b'a'; 1000]),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn the_signature_has_the_expected_shape() {
        let mut p = OvhProvider::new();
        p.app_secret = "secret".into();
        p.consumer_key = "consumer".into();
        let sig = p.signature("GET", "https://eu.api.ovh.com/1.0/auth/time", "", 1234567890);
        assert!(sig.starts_with("$1$"));
        assert_eq!(sig.len(), 3 + 40);
    }

    #[test]
    fn an_unknown_endpoint_falls_back_to_europe() {
        assert_eq!(endpoint_url("ovh-us"), "https://api.us.ovhcloud.com/1.0");
        assert_eq!(endpoint_url("n-importe-quoi"), ENDPOINTS[0].1);
    }

    #[test]
    fn parses_an_instance_payload() {
        let v = json!({
            "id": "abc-123",
            "name": "vpn1",
            "status": "ACTIVE",
            "region": "GRA7",
            "flavor": { "name": "b2-30" },
            "ipAddresses": [{ "ip": "198.51.100.51" }, { "ip": "10.0.0.5" }]
        });
        let i = ovh_instance(&v, "");
        assert_eq!(i.name, "vpn1");
        assert_eq!(i.state, PowerState::Running);
        assert_eq!(i.shape, "b2-30");
        assert!(i.has_address("198.51.100.51"));
    }

    #[test]
    fn both_reboot_variants_are_allowed_but_no_graceful_stop() {
        // Relevé sur eu.api.ovh.com/1.0/cloud.json : `/reboot` prend
        // `type: soft|hard`, `/stop` ne prend aucun paramètre.
        let p = OvhProvider::new();
        assert!(p.ensure_allows(PowerAction::Reboot { graceful: true }).is_ok());
        assert!(p.ensure_allows(PowerAction::Reboot { graceful: false }).is_ok());
        assert!(p.ensure_allows(PowerAction::Stop { graceful: true }).is_err());
        assert!(p.ensure_allows(PowerAction::Stop { graceful: false }).is_ok());
    }

    #[test]
    fn the_reboot_body_carries_the_required_type() {
        // Sans ce corps l'API répond 400 — c'est ce qui rendait le
        // redémarrage OVH inopérant, sans que rien ne le distingue d'une
        // instance récalcitrante.
        assert_eq!(reboot_body(true), r#"{"type":"soft"}"#);
        assert_eq!(reboot_body(false), r#"{"type":"hard"}"#);
    }

    #[test]
    fn the_body_is_part_of_what_gets_signed() {
        // Si le corps n'entrait pas dans la signature, OVH répondrait 403 et
        // l'erreur désignerait les identifiants plutôt que l'appel.
        let mut p = OvhProvider::new();
        p.app_secret = "secret".into();
        p.consumer_key = "consumer".into();
        let url = "https://eu.api.ovh.com/1.0/cloud/project/p/instance/i/reboot";
        assert_ne!(
            p.signature("POST", url, reboot_body(true), 1234567890),
            p.signature("POST", url, "", 1234567890)
        );
    }
}
