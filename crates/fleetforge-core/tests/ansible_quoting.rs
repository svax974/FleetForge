/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Aucune tâche qu'un `--check` exécute pour de vrai (`check_mode: false`) n'interpole
//! une variable réglable sans `| quote` (`Ansible/scripts/unquoted_check_mode.py`).
//!
//! Un compte d'automatisation passe des `extra_vars`, qui l'emportent sur toute autre
//! définition : une interpolation nue dans un `shell:` y devient une commande, en root,
//! dès le check — avant tout humain. Le scanner est en Python (PyYAML, Jinja2 : ceux
//! d'Ansible) ; sans interpréteur qui les ait, ce test s'efface en le disant.

use std::path::{Path, PathBuf};
use std::process::Command;

fn ansible_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ansible")
}

/// Un Python qui a PyYAML et Jinja2 : `FLEETFORGE_ANSIBLE_PYTHON`, celui d'`ansible`
/// (sa ligne `#!`), sinon `python3`.
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
fn no_check_mode_false_task_interpolates_an_unquoted_variable() {
    let Some(python) = python() else {
        eprintln!("PyYAML et Jinja2 introuvables (FLEETFORGE_ANSIBLE_PYTHON) : test ignoré");
        return;
    };
    let scripts = ansible_dir().join("scripts");
    let (ok, out) = run(&python, &scripts.join("test_unquoted_check_mode.py"), &[]);
    assert!(ok, "tests du scanner :\n{out}");
    let (ok, out) = run(&python, &scripts.join("unquoted_check_mode.py"), &[&ansible_dir().join("playbooks")]);
    assert!(ok, "interpolations non protégées (`| quote`, ou `# unquoted-ok: `variable` raison`) :\n{out}");
}
