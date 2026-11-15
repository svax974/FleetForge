/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Isolation de la passerelle MCP de FleetForge, entrée `webapp` DURCIE
//! (`Ansible/scripts/webapp_hardening_check.py`) : seule la garde vise `fleetforge_gateways`, la
//! passerelle est déployée par l'import de deploy-webapp.yml (jamais par un play `infras`), les
//! rôles `webapp-*` ne créent aucun conteneur, les proxies admis écartent les adresses VPN, le vhost
//! générique limite `/mcp` à sa liste nommée (+ whitelist de test filtrée) puis `deny all`, les
//! gardes sans connexion refusent un profil invalide, et un compose non durci (montages de l'hôte,
//! driver_opts, volumes_from, cap_add, unconfined, ports publics, compte, read_only, cap_drop,
//! limites, réseau, relais à adresse fixe, Redis sans mot de passe) est refusé — composes piégés
//! des revues compris.
//! Le contrôle est en Python (PyYAML, Jinja2 : ceux d'Ansible). PRÉREQUIS : un tel interpréteur
//! (`FLEETFORGE_ANSIBLE_PYTHON`, celui d'`ansible`, ou `python3`). Sans lui le test ÉCHOUE — un
//! contrôle de sécurité qui passerait sans rien vérifier serait pire que pas de contrôle ;
//! `FLEETFORGE_ANSIBLE_TESTS=skip` l'écarte explicitement (machine sans Ansible).

use std::path::{Path, PathBuf};
use std::process::Command;

fn ansible_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ansible")
}

/// Même recherche que `ansible_quoting.rs` : `FLEETFORGE_ANSIBLE_PYTHON`, celui d'`ansible`, `python3`.
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

fn run(python: &str, script: &Path, args: &[&Path]) -> (bool, String) {
    let out = Command::new(python).arg("-I").arg(script).args(args).output().expect("python");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[test]
fn the_gateway_stays_isolated_from_the_control_node() {
    let Some(python) = python() else {
        if std::env::var("FLEETFORGE_ANSIBLE_TESTS").as_deref() == Ok("skip") {
            eprintln!("FLEETFORGE_ANSIBLE_TESTS=skip : contrôle d'isolation de la passerelle NON exécuté");
            return;
        }
        panic!(
            "PyYAML et Jinja2 introuvables : le contrôle d'isolation de la passerelle ne peut pas tourner. \
             Désigner un Python qui les a (FLEETFORGE_ANSIBLE_PYTHON) ou, en connaissance de cause, \
             FLEETFORGE_ANSIBLE_TESTS=skip"
        );
    };
    let scripts = ansible_dir().join("scripts");
    let (ok, out) = run(&python, &scripts.join("test_webapp_hardening_check.py"), &[]);
    assert!(ok, "tests du contrôle d'isolation :\n{out}");
    let (ok, out) = run(
        &python,
        &scripts.join("webapp_hardening_check.py"),
        &[Path::new("playbook"), &ansible_dir().join("playbooks")],
    );
    assert!(ok, "isolation de la passerelle dans les playbooks et rôles :\n{out}");
}
