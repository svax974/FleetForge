/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Authentification basique.
//!
//! Deuxième barrière, derrière le filtrage réseau : le vhost nginx et ufw
//! n'autorisent que la whitelist, mais une whitelist est une liste d'ADRESSES —
//! elle ne dit rien de qui est derrière. Et le parc a déjà connu des règles de
//! filtrage entièrement décoratives (ufw sur un port publié par Docker) sans
//! que rien ne le signale.
//!
//! Deux comptes possibles : l'opérateur (tout) et l'automatisation (AgentHub),
//! cantonnée à [`AUTOMATION_COMMANDS`] et au flux d'un run. Le rôle reconnu
//! est déposé dans les extensions de la requête ([`Role`]).
//!
//! `/metrics` et `/healthz` en sont exemptés : ils sont scrapés par Prometheus,
//! qui n'a pas d'identifiants ici, et restreints par ufw à sa seule adresse.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use base64::Engine;
use serde_json::json;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::config::{Account, Role, Secret};

/// Commandes ouvertes au compte d'automatisation. Tout le reste — réglages,
/// group_vars, hébergeurs, alimentation des machines, sorties brutes des runs
/// (`get_run_handle`) — reste à l'opérateur. `query_prometheus` n'y est admis
/// que sous sa forme `{ parc, query }` (lecture seule, voir `automation.rs`).
pub const AUTOMATION_COMMANDS: &[&str] = &[
    "list_hosts",
    "list_playbooks",
    "alertmanager_alerts",
    "query_prometheus",
    "ssh_diagnose",
    "run_ansible_playbook",
    "run_status",
];

/// Chemins servis sans authentification.
fn is_public(path: &str) -> bool {
    path == "/metrics" || path == "/healthz"
}

/// Le serveur MCP. Ses outils sont les commandes de la liste : le tri se fait
/// outil par outil, dans `mcp.rs`, pas à l'entrée.
pub fn is_mcp(path: &str) -> bool {
    path == "/mcp" || path.starts_with("/mcp/")
}

/// Ce que le compte d'automatisation peut atteindre : une commande de la
/// liste, le flux SSE d'un run, ou le serveur MCP.
fn automation_may(method: &Method, path: &str) -> bool {
    if is_mcp(path) {
        return true;
    }
    if method == Method::POST {
        if let Some(command) = path.strip_prefix("/api/") {
            return AUTOMATION_COMMANDS.contains(&command);
        }
    }
    method == Method::GET
        && path
            .strip_prefix("/api/events/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

fn refusal(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = (status, Json(json!({ "error": message, "code": code }))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static(r#"Basic realm="FleetForge""#),
        );
    }
    response
}

pub async fn middleware(
    State(accounts): State<Arc<Vec<Account>>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if accounts.is_empty() {
        // Pas d'authentification configurée : le seul cas autorisé est
        // l'écoute sur la boucle locale, refusée au démarrage sinon.
        request.extensions_mut().insert(Role::Operator);
        return next.run(request).await;
    }

    if is_public(request.uri().path()) {
        return next.run(request).await;
    }

    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|v| String::from_utf8(v).ok());

    let Some(role) = presented.and_then(|c| identify(&c, &accounts)) else {
        return refusal(StatusCode::UNAUTHORIZED, "unauthorized", "authentification requise");
    };

    if role == Role::Automation && !automation_may(request.method(), request.uri().path()) {
        return refusal(
            StatusCode::FORBIDDEN,
            "forbidden",
            "commande réservée à l'opérateur",
        );
    }

    request.extensions_mut().insert(role);
    next.run(request).await
}

/// Rôle du compte dont le couple présenté est exact.
///
/// TOUS les comptes sont vérifiés, même après une correspondance : s'arrêter
/// au premier renseignerait, par la seule durée de la réponse, sur le compte
/// visé.
fn identify(presented: &str, accounts: &[Account]) -> Option<Role> {
    let mut found = None;
    for account in accounts {
        if matches(presented, account) && found.is_none() {
            found = Some(account.role);
        }
    }
    found
}

/// Vérifie le couple présenté.
///
/// Les deux moitiés sont TOUJOURS évaluées, même quand la première a déjà
/// échoué : court-circuiter sur l'utilisateur renseignerait sur son existence
/// par la seule durée de la réponse.
fn matches(presented: &str, expected: &Account) -> bool {
    let Some((user, password)) = presented.split_once(':') else {
        return false;
    };
    let user_ok: bool = user.as_bytes().ct_eq(expected.user.as_bytes()).into();
    let pass_ok = verify(password, &expected.secret);
    user_ok & pass_ok
}

fn verify(presented: &str, secret: &Secret) -> bool {
    match secret {
        // argon2 compare lui-même à temps constant, et le sel rend l'empreinte
        // inutilisable ailleurs : le fichier volé sur la machine ne rejoue rien.
        Secret::Hash(hash) => PasswordHash::new(hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(presented.as_bytes(), &parsed)
                .is_ok()
        }),
        // `==` s'arrêterait au premier octet différent : la durée de la réponse
        // renseignerait sur le préfixe correct.
        Secret::Plain(clear) => presented.as_bytes().ct_eq(clear.as_bytes()).into(),
    }
}

/// Empreinte argon2id d'un mot de passe, au format PHC.
///
/// Produite sur la MACHINE par `fleetforge-web hash-password`, à partir du clair que
/// le vault détient. C'est ce qui permet au serveur de vérifier un mot de passe
/// sans jamais le stocker : le fichier d'environnement ne contient plus rien de
/// rejouable, ni ici ni ailleurs.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};

    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("empreinte du mot de passe : {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(user: &str, secret: Secret, role: Role) -> Account {
        Account { user: user.into(), secret, role }
    }

    fn creds() -> Account {
        account("steph", Secret::Plain("correct horse".into()), Role::Operator)
    }

    #[test]
    fn only_the_exact_pair_is_accepted() {
        assert!(matches("steph:correct horse", &creds()));
        assert!(!matches("steph:correct", &creds()));
        assert!(!matches("steph:correct horse ", &creds()));
        assert!(!matches("root:correct horse", &creds()));
        // Un mot de passe contenant « : » ne doit pas être tronqué au premier.
        assert!(!matches("steph", &creds()));
    }

    #[test]
    fn a_password_may_contain_a_colon() {
        let c = account("u", Secret::Plain("a:b".into()), Role::Operator);
        assert!(matches("u:a:b", &c));
    }

    #[test]
    fn a_hashed_secret_accepts_the_password_it_was_made_from() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"), "format PHC attendu : {hash}");

        let expected = account("steph", Secret::Hash(hash), Role::Operator);
        assert!(matches("steph:correct horse", &expected));
        assert!(!matches("steph:correct horses", &expected));
        assert!(!matches("root:correct horse", &expected));
    }

    #[test]
    fn two_hashes_of_the_same_password_differ() {
        // Le sel est ce qui rend l'empreinte inutilisable ailleurs : sans lui,
        // le fichier d'environnement d'une machine vaudrait pour toutes.
        assert_ne!(hash_password("x").unwrap(), hash_password("x").unwrap());
    }

    #[test]
    fn a_malformed_hash_refuses_everything_rather_than_accepting_anything() {
        // Une empreinte tronquée par une copie ratée ne doit pas dégénérer en
        // « pas de mot de passe » : elle doit tout refuser.
        let expected = account("steph", Secret::Hash("pas une empreinte".into()), Role::Operator);
        assert!(!matches("steph:", &expected));
        assert!(!matches("steph:correct horse", &expected));
    }

    #[test]
    fn the_scrape_endpoints_stay_reachable_without_credentials() {
        // Prometheus n'a pas d'identifiants pour cette application : si
        // /metrics tombait derrière l'authentification, la cible passerait
        // `down` en 401 et ferait sonner TargetDown en permanence.
        assert!(is_public("/metrics"));
        assert!(is_public("/healthz"));
        assert!(!is_public("/api/get_fleet"));
        assert!(!is_public("/"));
    }

    #[test]
    fn each_account_gets_its_own_role() {
        let accounts = vec![
            creds(),
            account("agenthub", Secret::Plain("other".into()), Role::Automation),
        ];
        assert_eq!(identify("steph:correct horse", &accounts), Some(Role::Operator));
        assert_eq!(identify("agenthub:other", &accounts), Some(Role::Automation));
        assert_eq!(identify("agenthub:correct horse", &accounts), None);
        assert_eq!(identify("steph:other", &accounts), None);
    }

    #[test]
    fn automation_reaches_only_its_commands_and_run_streams() {
        assert!(automation_may(&Method::POST, "/api/list_hosts"));
        assert!(automation_may(&Method::POST, "/api/run_ansible_playbook"));
        assert!(automation_may(&Method::POST, "/api/run_status"));
        assert!(automation_may(&Method::POST, "/api/query_prometheus"));
        assert!(automation_may(&Method::GET, "/api/events/run-1"));

        for (method, path) in [
            (Method::POST, "/api/write_group_vars_file"),
            (Method::POST, "/api/set_inventories_path"),
            (Method::POST, "/api/power_instance"),
            (Method::POST, "/api/get_run_handle"),
            (Method::POST, "/api/run_ansible_deploy"),
            (Method::GET, "/api/list_hosts"),
            (Method::GET, "/"),
            (Method::GET, "/api/events/"),
            (Method::GET, "/api/events/a/b"),
        ] {
            assert!(!automation_may(&method, path), "{method} {path}");
        }
    }
}
