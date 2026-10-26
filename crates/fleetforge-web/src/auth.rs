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
//! Deux sortes de comptes : l'opérateur (tout) et l'automatisation (AgentHub,
//! OpenClaw…), cantonnée à [`AUTOMATION_COMMANDS`] et au flux d'un run, et
//! bornée par son périmètre ([`Scope`] : ses parcs, lecture ou pilotage). Le
//! rôle et le périmètre reconnus sont déposés dans les extensions de la
//! requête ([`Role`], `Arc<Scope>`), où les lisent l'API et le serveur MCP.
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
use std::sync::{Arc, LazyLock};
use subtle::ConstantTimeEq;

use crate::config::{Account, Mode, Role, Scope, Secret};

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

/// Commandes d'un compte en LECTURE (`mode: read`) : ni run, ni état de run,
/// ni flux. `ssh_diagnose` en est : la passerelle ro-gate n'a que des verbes
/// de lecture.
pub const READ_COMMANDS: &[&str] = &[
    "list_hosts",
    "list_playbooks",
    "alertmanager_alerts",
    "query_prometheus",
    "ssh_diagnose",
];

pub fn commands(mode: Mode) -> &'static [&'static str] {
    match mode {
        Mode::Read => READ_COMMANDS,
        Mode::Run => AUTOMATION_COMMANDS,
    }
}

/// Chemins servis sans authentification.
fn is_public(path: &str) -> bool {
    path == "/metrics" || path == "/healthz"
}

/// Le serveur MCP. Ses outils sont les commandes de la liste : le tri se fait
/// outil par outil, dans `mcp.rs`, pas à l'entrée.
pub fn is_mcp(path: &str) -> bool {
    path == "/mcp" || path.starts_with("/mcp/")
}

/// Ce qu'un compte d'automatisation peut atteindre : une commande de son mode,
/// le flux SSE d'un run (pilotage seulement), ou le serveur MCP.
fn automation_may(method: &Method, path: &str, mode: Mode) -> bool {
    if is_mcp(path) {
        return true;
    }
    if method == Method::POST {
        if let Some(command) = path.strip_prefix("/api/") {
            return commands(mode).contains(&command);
        }
    }
    mode == Mode::Run
        && method == Method::GET
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
        request.extensions_mut().insert(Arc::new(Scope::everything()));
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

    let Some(account) = presented.and_then(|c| identify(&c, &accounts)) else {
        return refusal(StatusCode::UNAUTHORIZED, "unauthorized", "authentification requise");
    };

    if account.role == Role::Automation
        && !automation_may(request.method(), request.uri().path(), account.scope.mode)
    {
        return refusal(
            StatusCode::FORBIDDEN,
            "forbidden",
            match account.scope.mode {
                Mode::Run => "commande réservée à l'opérateur",
                Mode::Read => "commande hors du mode du compte (lecture seule)",
            },
        );
    }

    request.extensions_mut().insert(account.role);
    request.extensions_mut().insert(account.scope.clone());
    next.run(request).await
}

/// Compte dont le couple présenté est exact.
///
/// Toujours UNE vérification de mot de passe, et une seule : celle du compte
/// dont le nom correspond (comparé à temps constant, à tous les comptes), ou
/// celle d'une empreinte factice quand aucun ne correspond. La durée de la
/// réponse ne renseigne donc ni sur l'existence d'un nom, ni sur le compte
/// visé — et elle ne croît pas avec le nombre de comptes, ce que ferait une
/// vérification argon2 par compte.
fn identify<'a>(presented: &str, accounts: &'a [Account]) -> Option<&'a Account> {
    let (user, password) = presented.split_once(':')?;
    let mut candidate = None;
    for account in accounts {
        let same: bool = user.as_bytes().ct_eq(account.user.as_bytes()).into();
        if same && candidate.is_none() {
            candidate = Some(account);
        }
    }
    match candidate {
        Some(account) => verify(password, &account.secret).then_some(account),
        None => {
            verify(password, &DECOY);
            None
        }
    }
}

/// Empreinte sans mot de passe connu, vérifiée quand aucun compte ne porte le
/// nom présenté.
static DECOY: LazyLock<Secret> =
    LazyLock::new(|| Secret::Hash(hash_password("fleetforge-decoy").unwrap_or_default()));

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
        Account { user: user.into(), secret, role, scope: Arc::new(Scope::everything()) }
    }

    /// Le couple présenté ouvre-t-il ce compte ?
    fn matches(presented: &str, expected: &Account) -> bool {
        identify(presented, std::slice::from_ref(expected)).is_some()
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
        let role = |presented: &str| identify(presented, &accounts).map(|a| a.role);
        assert_eq!(role("steph:correct horse"), Some(Role::Operator));
        assert_eq!(role("agenthub:other"), Some(Role::Automation));
        assert_eq!(role("agenthub:correct horse"), None);
        assert_eq!(role("steph:other"), None);
        assert_eq!(role("nobody:other"), None);
    }

    #[test]
    fn automation_reaches_only_its_commands_and_run_streams() {
        for mode in [Mode::Read, Mode::Run] {
            assert!(automation_may(&Method::POST, "/api/list_hosts", mode));
            assert!(automation_may(&Method::POST, "/api/query_prometheus", mode));
            assert!(automation_may(&Method::POST, "/api/ssh_diagnose", mode));
            assert!(automation_may(&Method::POST, "/mcp", mode), "le tri des outils se fait dans mcp.rs");
        }
        assert!(automation_may(&Method::POST, "/api/run_ansible_playbook", Mode::Run));
        assert!(automation_may(&Method::POST, "/api/run_status", Mode::Run));
        assert!(automation_may(&Method::GET, "/api/events/run-1", Mode::Run));

        for (method, path, mode) in [
            (Method::POST, "/api/write_group_vars_file", Mode::Run),
            (Method::POST, "/api/set_inventories_path", Mode::Run),
            (Method::POST, "/api/power_instance", Mode::Run),
            (Method::POST, "/api/get_run_handle", Mode::Run),
            (Method::POST, "/api/run_ansible_deploy", Mode::Run),
            (Method::GET, "/api/list_hosts", Mode::Run),
            (Method::GET, "/", Mode::Run),
            (Method::GET, "/api/events/", Mode::Run),
            (Method::GET, "/api/events/a/b", Mode::Run),
            (Method::POST, "/api/run_ansible_playbook", Mode::Read),
            (Method::POST, "/api/run_status", Mode::Read),
            (Method::GET, "/api/events/run-1", Mode::Read),
        ] {
            assert!(!automation_may(&method, path, mode), "{method} {path} {mode:?}");
        }
    }

    #[test]
    fn the_read_commands_are_the_automation_commands_without_runs() {
        let mut runs: Vec<&str> = AUTOMATION_COMMANDS.iter().copied().filter(|c| !READ_COMMANDS.contains(c)).collect();
        runs.sort_unstable();
        assert_eq!(runs, ["run_ansible_playbook", "run_status"]);
    }
}
