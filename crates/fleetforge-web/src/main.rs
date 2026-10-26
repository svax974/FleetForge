/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! FleetForge servi dans un navigateur.
//!
//! Troisième façade du cœur, à parité avec le GUI Tauri et le TUI : elle sert
//! le MÊME frontal React, qui ne fait qu'aiguiller son transport (`invoke` vers
//! Tauri, `fetch` vers ici). Le paquetage en application de bureau reste
//! possible — `npm run tauri:build` — et n'a rien perdu au passage.

mod api;
mod auth;
mod automation;
mod config;
mod events;
mod mcp;
mod metrics;
mod state;
mod stream;

use anyhow::{Context, Result};
use axum::routing::{get, post};
use axum::Router;
use config::Config;
use fleetforge_core::{Core, SettingKey};
use state::AppState;
use std::path::Path;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};

fn env_path(variable: &str) -> Option<String> {
    std::env::var(variable)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Chemins imposés par l'environnement : chacun par sa variable, à défaut
/// dérivé de `FLEETFORGE_ANSIBLE_DIR` (`<dossier>/inventories`,
/// `<dossier>/playbooks`) — l'arbre Ansible peut vivre ailleurs que dans le
/// code livré.
fn deployed_paths() -> Vec<(SettingKey, &'static str, String)> {
    let root = env_path("FLEETFORGE_ANSIBLE_DIR");
    [
        (SettingKey::InventoriesPath, "FLEETFORGE_INVENTORIES_PATH", "inventories"),
        (SettingKey::PlaybooksPath, "FLEETFORGE_PLAYBOOKS_PATH", "playbooks"),
    ]
    .into_iter()
    .filter_map(|(key, variable, sub)| {
        env_path(variable)
            .or_else(|| {
                root.as_ref()
                    .map(|r| Path::new(r).join(sub).to_string_lossy().to_string())
            })
            .map(|value| (key, variable, value))
    })
    .collect()
}

/// Impose les chemins livrés par le déploiement, quand il en fournit.
///
/// Sur un poste, ces chemins se règlent dans la vue Configuration et le
/// réglage stocké fait foi. Sur un serveur, c'est l'inverse : le rôle Ansible
/// sait où il a déposé l'arbre, et un réglage stocké qui en diffère est
/// forcément périmé — répertoire déplacé, base restaurée d'une autre machine.
/// L'application démarrerait alors sur un inventaire vide, ce qui ressemble
/// beaucoup à un parc vide.
fn adopt_deployed_paths(core: &Core) -> Result<()> {
    for (key, variable, value) in deployed_paths() {
        core.set_setting(key, &value)
            .with_context(|| format!("réglage {variable}"))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Sous-commande unique, hors serveur : produire l'empreinte du mot de passe
    // d'accès. Elle est appelée par `fleetforge-install` sur la MACHINE,
    // pour que le clair — qui vit dans le vault Ansible — n'ait jamais à y être
    // écrit. Le mot de passe arrive par l'entrée standard et non en argument :
    // `ps` rend les arguments de commande lisibles par tout le monde.
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        return hash_password_from_stdin();
    }

    let log_path = fleetforge_core::logging::init("web");

    // Le serveur web n'ouvre JAMAIS de navigateur pour l'opérateur : le sien
    // s'ouvrirait sur la machine qui héberge l'application, et la redirection
    // OAuth viserait le `localhost` de CETTE machine. Même servi sur la boucle
    // locale, rien ne garantit que le navigateur y soit — un tunnel SSH suffit
    // à les séparer, et c'est le mode d'accès nominal ici.
    std::env::set_var("FLEETFORGE_NO_LOCAL_BROWSER", "1");

    let config = Config::from_env()?;

    let core = Core::new().context("initialisation du cœur")?;
    core.with_db(|db| db.seed_predefined_models())
        .context("catalogue de modèles")?;
    adopt_deployed_paths(&core)?;

    let state = AppState::new(core, config.ro_gate.clone());

    // Le frontal est une application à page unique : toute route inconnue doit
    // rendre `index.html`, faute de quoi un rechargement (F5) sur une vue
    // interne renverrait 404 alors que la navigation interne fonctionne.
    let index = config.static_dir.join("index.html");
    if !index.exists() {
        anyhow::bail!(
            "frontal introuvable : {} n'existe pas. Construire avec `npm run build` \
             dans apps/gui, ou renseigner FLEETFORGE_WEB_STATIC.",
            index.display()
        );
    }
    let statics = ServeDir::new(&config.static_dir).fallback(ServeFile::new(&index));
    let mcp = mcp::service(state.clone(), !config.accounts.is_empty());

    let app = Router::new()
        .route("/api/{command}", post(api::dispatch))
        .route("/api/events/{run_id}", get(stream::sse))
        // Serveur MCP : les commandes d'automatisation en outils, derrière la
        // même authentification que le reste (`auth::middleware`).
        .nest_service("/mcp", mcp)
        .route("/metrics", get(metrics::handler))
        .route("/healthz", get(|| async { "ok" }))
        .fallback_service(statics)
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(config.accounts),
            auth::middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .with_context(|| format!("écoute sur {}", config.addr))?;

    // Sur la sortie d'erreur ET dans le journal : sous systemd la première va
    // au journal du système, mais le service peut aussi être lancé à la main.
    eprintln!(
        "FleetForge — http://{} (statique : {}) — journal {}",
        config.addr,
        config.static_dir.display(),
        log_path.display()
    );
    fleetforge_core::logging::info(
        "web",
        format!("écoute sur {} (statique : {})", config.addr, config.static_dir.display()),
    );

    axum::serve(listener, app).await.context("serveur HTTP")
}

fn hash_password_from_stdin() -> Result<()> {
    use std::io::Read;

    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .context("lecture du mot de passe sur l'entrée standard")?;

    // Un saut de ligne final est presque toujours un artefact du transport
    // (`echo`, heredoc, `stdin:` d'Ansible), jamais une intention. L'inclure
    // produirait une empreinte que le mot de passe saisi ne vérifie pas.
    let password = password.trim_end_matches(['\n', '\r']);
    if password.is_empty() {
        anyhow::bail!("mot de passe vide sur l'entrée standard");
    }

    println!("{}", auth::hash_password(password)?);
    Ok(())
}
