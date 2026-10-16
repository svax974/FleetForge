/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Exposition Prometheus native, sur le port applicatif.
//!
//! Convention du parc (CLAUDE.md) : quand un service expose déjà Prometheus, on
//! l'active et on enregistre sa cible — svcprobe n'est là que pour ceux qui
//! n'exposent rien. C'est le meilleur des trois cas, parce qu'un exporter
//! externe ne saurait rien dire de l'état INTERNE.
//!
//! Les métriques répondent aux deux exigences de la convention :
//!   1. `fleetforge_up`, sonde binaire ;
//!   2. des séries qui révèlent un état DÉGRADÉ que la sonde binaire manquerait.
//!      C'est le point qui compte ici : cette application répond parfaitement
//!      en HTTP alors même qu'elle ne peut plus rien piloter — `ansible-playbook`
//!      absent du PATH, arbre Ansible non livré, chemins non configurés. Le
//!      service est alors « up » et inutile, et rien d'autre ne le dirait.

use crate::state::AppState;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use std::fmt::Write;

pub async fn handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = tokio::task::spawn_blocking(move || render(&state))
        .await
        .unwrap_or_else(|e| format!("# collecte impossible : {e}\n"));

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

fn render(state: &AppState) -> String {
    let mut out = String::with_capacity(2048);

    gauge(
        &mut out,
        "fleetforge_up",
        "1 quand le serveur répond. Toujours 1 s'il a pu servir cette page.",
        1,
    );
    gauge(
        &mut out,
        "fleetforge_uptime_seconds",
        "Temps écoulé depuis le démarrage du processus.",
        state.started.elapsed().as_secs(),
    );

    let _ = writeln!(
        out,
        "# HELP fleetforge_build_info Version du binaire.\n# TYPE fleetforge_build_info gauge\nfleetforge_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    // ── État dégradé ───────────────────────────────────────────────────────
    gauge(
        &mut out,
        "fleetforge_ansible_available",
        "1 si ansible-playbook est exécutable. À 0, l'application répond mais ne peut plus rien déployer.",
        u64::from(state.core.ansible_available()),
    );

    let inventories = state.core.list_inventories().unwrap_or_default();
    gauge(
        &mut out,
        "fleetforge_inventories",
        "Inventaires visibles. À 0, les chemins sont mal configurés ou l'arbre Ansible n'est pas livré.",
        inventories.len() as u64,
    );

    gauge(
        &mut out,
        "fleetforge_roles",
        "Rôles au catalogue. À 0 alors que des inventaires existent, l'arbre des playbooks est incomplet.",
        state.core.list_roles().map(|r| r.len()).unwrap_or(0) as u64,
    );

    // ── Parc sélectionné ───────────────────────────────────────────────────
    // Seulement le parc courant : dérouler tous les inventaires appellerait
    // `ansible-inventory` autant de fois à chaque scrape, pour une information
    // que personne ne regarde.
    if let Ok(Some(inventory)) = state.core.selected_inventory() {
        if let Ok(fleet) = state.core.fleet(&inventory.file_path) {
            let org = escape(&inventory.organization);
            labelled(
                &mut out,
                "fleetforge_fleet_machines",
                "Machines distinctes du parc sélectionné.",
                &org,
                fleet.servers.len() as u64,
            );
            labelled(
                &mut out,
                "fleetforge_fleet_hosts",
                "Entrées d'inventaire du parc sélectionné.",
                &org,
                fleet.hosts.len() as u64,
            );
        }
    }

    // ── Runs ───────────────────────────────────────────────────────────────
    gauge(
        &mut out,
        "fleetforge_runs_active",
        "Déploiements en cours dans ce processus.",
        state.core.runs().active().len() as u64,
    );
    counter(
        &mut out,
        "fleetforge_runs_started_total",
        "Déploiements lancés depuis le démarrage.",
        state.runs_started(),
    );
    counter(
        &mut out,
        "fleetforge_runs_failed_total",
        "Déploiements terminés en échec, refus avant lancement compris.",
        state.runs_failed(),
    );

    out
}

fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
    );
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
    );
}

fn labelled(out: &mut String, name: &str, help: &str, fleet: &str, value: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} gauge\n{name}{{fleet=\"{fleet}\"}} {value}"
    );
}

/// Échappement des valeurs d'étiquette, tel que l'exige le format d'exposition.
///
/// Le nom d'organisation vient d'un nom de fichier : un guillemet ou un
/// antislash y rendrait TOUTE la page inanalysable, et la cible passerait
/// `down` sans que rien ne désigne la cause.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape(r#"we"b3c"#), r#"we\"b3c"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), r"a\nb");
    }

    #[test]
    fn every_series_declares_its_type_before_its_value() {
        let mut out = String::new();
        gauge(&mut out, "x_up", "aide", 1);
        assert_eq!(out, "# HELP x_up aide\n# TYPE x_up gauge\nx_up 1\n");
    }
}
