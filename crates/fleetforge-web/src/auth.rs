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
//! `/metrics` et `/healthz` en sont exemptés : ils sont scrapés par Prometheus,
//! qui n'a pas d'identifiants ici, et restreints par ufw à sa seule adresse.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use base64::Engine;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::config::{BasicAuth, Secret};

/// Chemins servis sans authentification.
fn is_public(path: &str) -> bool {
    path == "/metrics" || path == "/healthz"
}

pub async fn middleware(
    State(auth): State<Arc<Option<BasicAuth>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = auth.as_ref() else {
        // Pas d'authentification configurée : le seul cas autorisé est
        // l'écoute sur la boucle locale, refusée au démarrage sinon.
        return next.run(request).await;
    };

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

    if presented.is_some_and(|c| matches(&c, expected)) {
        return next.run(request).await;
    }

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="FleetForge""#)
        .body(Body::from("authentification requise"))
        .expect("réponse 401 constante")
}

/// Vérifie le couple présenté.
///
/// Les deux moitiés sont TOUJOURS évaluées, même quand la première a déjà
/// échoué : court-circuiter sur l'utilisateur renseignerait sur son existence
/// par la seule durée de la réponse.
fn matches(presented: &str, expected: &BasicAuth) -> bool {
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

    fn creds() -> BasicAuth {
        BasicAuth {
            user: "steph".into(),
            secret: Secret::Plain("correct horse".into()),
        }
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
        let c = BasicAuth {
            user: "u".into(),
            secret: Secret::Plain("a:b".into()),
        };
        assert!(matches("u:a:b", &c));
    }

    #[test]
    fn a_hashed_secret_accepts_the_password_it_was_made_from() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"), "format PHC attendu : {hash}");

        let expected = BasicAuth {
            user: "steph".into(),
            secret: Secret::Hash(hash),
        };
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
        let expected = BasicAuth {
            user: "steph".into(),
            secret: Secret::Hash("pas une empreinte".into()),
        };
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
}
