/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Aller-retour rôle → service → rôle, sur le catalogue RÉEL.
//!
//! `ServicesView.tsx` reconstruisait `<service>-<action>` à la main et n'y
//! retombait pas dès qu'un service avait été renommé ; le bouton
//! « désinstaller » disparaissait alors sans explication. Ce test tient
//! l'invariant sur les ~190 rôles du dépôt, pas sur trois exemples choisis.

use fleetforge_core::ansible_roles::list_roles;
use fleetforge_core::service_tracker::{candidate_roles, parse_role, role_for};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn playbooks_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ansible/playbooks")
}

fn catalog() -> Vec<String> {
    let roles = list_roles(playbooks_path().to_str().unwrap()).expect("catalogue de rôles illisible");
    assert!(
        roles.len() > 100,
        "catalogue anormalement petit ({}) — chemin des playbooks erroné ?",
        roles.len()
    );
    roles.into_iter().map(|r| r.name).collect()
}

#[test]
fn every_real_role_maps_back_to_an_existing_role() {
    let names = catalog();
    let known: BTreeSet<&str> = names.iter().map(String::as_str).collect();

    let mut broken: Vec<String> = Vec::new();
    for role in &names {
        let parsed = parse_role(role);
        let candidates = candidate_roles(&parsed.service_name, &parsed.action);
        if !candidates.iter().any(|c| known.contains(c.as_str())) {
            broken.push(format!(
                "{role} → ({}, {}) → aucun candidat existant parmi {candidates:?}",
                parsed.service_name, parsed.action
            ));
        }
    }

    assert!(
        broken.is_empty(),
        "{} rôle(s) ne reviennent pas sur un rôle existant :\n  {}",
        broken.len(),
        broken.join("\n  ")
    );
}

#[test]
fn parse_role_keeps_its_provenance() {
    let parsed = parse_role("proxy-install");
    assert_eq!(parsed.service_name, "nginx-proxy");
    assert_eq!(parsed.action, "install");
    // Sans cette provenance, l'inverse était condamné à deviner.
    assert_eq!(parsed.role_name, "proxy-install");
}

#[test]
fn a_renamed_service_still_finds_its_removal_role() {
    // Le cas qui cassait : « nginx-proxy » n'est le nom d'aucun rôle, et
    // `nginx-proxy-remove` n'existe pas — c'est `proxy-remove` qu'il faut.
    let known: BTreeSet<String> = catalog().into_iter().collect();
    assert!(known.contains("proxy-remove"), "prérequis du test absent");

    let back = role_for("nginx-proxy", "remove").expect("aucun rôle proposé");
    assert_eq!(back, "proxy-remove");
    assert!(known.contains(&back));
}

#[test]
fn monitoring_is_an_action_not_a_service_of_its_own() {
    // `<service>-monitoring` supervise un service ; ce n'est pas un service de
    // plus. Le classer en `install` faisait compter deux services par famille
    // dans le journal d'audit.
    for role in [
        "brk-monitoring",
        "searxng-monitoring",
        "rpcbtc-monitoring",
        "astar-monitoring",
        "alertmanager-monitoring",
    ] {
        let parsed = parse_role(role);
        assert_eq!(
            parsed.action, "monitoring",
            "{role} classé en `{}` au lieu de `monitoring`",
            parsed.action
        );
        assert!(
            !parsed.service_name.ends_with("-monitoring"),
            "{role} a produit le service `{}`",
            parsed.service_name
        );
    }
}

#[test]
fn monitoring_a_service_stays_attached_to_that_service() {
    // Superviser rpcbtc1 doit apparaître comme une action portant sur le nœud
    // Bitcoin, pas sur un « bitcoin-exporter » qui n'existe nulle part ailleurs.
    assert_eq!(parse_role("rpcbtc-install").service_name, "bitcoin-node");
    assert_eq!(parse_role("rpcbtc-monitoring").service_name, "bitcoin-node");
    assert_eq!(parse_role("astar-install").service_name, "astar-node");
    assert_eq!(parse_role("astar-monitoring").service_name, "astar-node");
}

#[test]
fn a_service_never_renamed_follows_the_plain_convention() {
    assert_eq!(role_for("brk", "purge").as_deref(), Some("brk-purge"));
    assert_eq!(
        role_for("searxng", "monitoring").as_deref(),
        Some("searxng-monitoring")
    );
}

#[test]
fn proposing_a_role_does_not_assert_that_it_exists() {
    // Toutes les familles n'ont pas leur `-purge` : `role_for` propose, c'est
    // au catalogue de trancher. La distinction évite d'afficher un bouton
    // « purger » qui lancerait un rôle inexistant.
    let known: BTreeSet<String> = catalog().into_iter().collect();
    let proposed = role_for("frontend", "purge").expect("une proposition attendue");
    assert!(
        !known.contains(&proposed),
        "ce test suppose que {proposed} n'existe pas"
    );
}
