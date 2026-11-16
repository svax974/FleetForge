/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Famille `backup`, sans aucun hôte (`Ansible/scripts/test_backup_family.py`) : la passerelle
//! `backup-gate` de la destination (verbes fermés, répertoire de la seule source, rétention fixée par
//! la commande forcée, contenu contrôlé avant d'être rendu visible), les scripts PostgreSQL rendus et
//! joués sur des doublures (dump chiffré sans repli en clair, clé de l'opérateur sur l'entrée
//! standard, base jamais supprimée avant une relecture complète), le script SQLite rendu, et les
//! règles BackupStale/BackupMissing.
//! PRÉREQUIS : le Python d'Ansible (`FLEETFORGE_ANSIBLE_PYTHON`, celui d'`ansible`, ou `python3`),
//! `bash`, `gzip`, `ansible-playbook`. Sans eux le test ÉCHOUE ; `FLEETFORGE_ANSIBLE_TESTS=skip`
//! l'écarte explicitement (machine sans Ansible).

use std::path::PathBuf;
use std::process::Command;

fn ansible_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ansible")
}

/// Même recherche que `gateway_isolation.rs` : `FLEETFORGE_ANSIBLE_PYTHON`, celui d'`ansible`, `python3`.
fn python() -> Option<String> {
    let mut candidates: Vec<String> = std::env::var("FLEETFORGE_ANSIBLE_PYTHON").into_iter().collect();
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let shebang = std::fs::read_to_string(dir.join("ansible")).ok().and_then(|s| {
                s.lines().next().and_then(|l| l.strip_prefix("#!")).map(|l| l.trim().to_string())
            });
            candidates.extend(shebang.filter(|s| !s.contains(' ')));
        }
    }
    candidates.push("python3".into());
    candidates.into_iter().find(|py| {
        Command::new(py).args(["-I", "-c", "import yaml, jinja2"]).output().is_ok_and(|o| o.status.success())
    })
}

#[test]
fn the_backup_family_holds_without_any_host() {
    let skip = std::env::var("FLEETFORGE_ANSIBLE_TESTS").as_deref() == Ok("skip");
    let Some(python) = python() else {
        if skip {
            eprintln!("FLEETFORGE_ANSIBLE_TESTS=skip : tests de la famille backup NON exécutés");
            return;
        }
        panic!(
            "PyYAML et Jinja2 introuvables : les tests de la famille backup ne peuvent pas tourner. \
             Désigner un Python qui les a (FLEETFORGE_ANSIBLE_PYTHON) ou, en connaissance de cause, \
             FLEETFORGE_ANSIBLE_TESTS=skip"
        );
    };
    let out = Command::new(&python)
        .arg("-I")
        .arg(ansible_dir().join("scripts").join("test_backup_family.py"))
        .output()
        .expect("python");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "tests de la famille backup :\n{text}");
    // Un test SAUTÉ (ansible-playbook absent) n'a rien prouvé : échec, sauf choix explicite.
    let skipped = text.lines().any(|l| l.contains("skipped=") || l.trim_end().ends_with("skipped"));
    assert!(
        !skipped || skip,
        "tests de la famille backup SAUTÉS (ansible-playbook absent) :\n{text}\n\
         installer Ansible, ou, en connaissance de cause, FLEETFORGE_ANSIBLE_TESTS=skip"
    );
}
