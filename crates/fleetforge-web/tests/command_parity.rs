/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Parité entre les deux façades.
//!
//! Le frontal est le MÊME dans l'application de bureau et dans le navigateur :
//! il appelle les commandes par leur nom, et seul le transport change. Une
//! commande servie par Tauri mais pas par le serveur web échoue donc uniquement
//! dans le navigateur, à l'exécution, sur un écran précis — c'est-à-dire au
//! pire endroit et au pire moment.
//!
//! Ce test lit les noms là où ils sont écrits, plutôt que d'entretenir une
//! troisième liste à la main.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} illisible : {e}", path.display()))
}

/// Noms passés à `call(...)` dans la couche d'API du frontal.
fn called_by_frontend() -> BTreeSet<String> {
    let source = read("../../apps/gui/src/lib/api.ts");
    let mut names = BTreeSet::new();

    for (index, _) in source.match_indices("call(") {
        // Écarte `recall(`, `install(`… : le caractère précédent doit clore un
        // mot.
        if index > 0 {
            let previous = source.as_bytes()[index - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                continue;
            }
        }
        let rest = &source[index + "call(".len()..];
        if let Some(name) = rest.strip_prefix('\'').and_then(|r| r.split('\'').next()) {
            names.insert(name.to_string());
        }
    }

    assert!(
        names.len() > 40,
        "extraction anormalement pauvre ({}) — la forme des appels a changé ?",
        names.len()
    );
    names
}

/// Noms réellement traités par le `match` du serveur.
fn dispatched_by_server() -> BTreeSet<String> {
    let source = read("src/api.rs");
    let mut names = BTreeSet::new();

    // Indentation exacte du `match command.as_str()`. Les bras imbriqués —
    // « start », « stop », « system » — sont plus profonds : ce sont des
    // valeurs d'argument, pas des commandes, et les compter ferait échouer le
    // test sur une parité qui, elle, est bonne.
    const ARM_INDENT: &str = "        ";

    for line in source.lines() {
        let Some(rest) = line.strip_prefix(ARM_INDENT) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        let Some((name, tail)) = rest.split_once('"') else {
            continue;
        };
        // Un bras du `match`, et non une entrée de la liste `COMMANDS`.
        if tail.trim_start().starts_with("=>") {
            names.insert(name.to_string());
        }
    }
    names
}

#[test]
fn the_server_answers_every_command_the_frontend_calls() {
    let served = fleetforge_web_commands();
    let called = called_by_frontend();
    let missing: Vec<&String> = called.difference(&served).collect();

    assert!(
        missing.is_empty(),
        "commande(s) appelées par le frontal et absentes du serveur web : {missing:?}"
    );
}

#[test]
fn the_declared_list_matches_the_dispatcher() {
    // La liste sert de sommaire lisible ; si elle dérive du `match`, elle ment.
    let declared = fleetforge_web_commands();
    let dispatched = dispatched_by_server();

    let undeclared: Vec<&String> = dispatched.difference(&declared).collect();
    let unserved: Vec<&String> = declared.difference(&dispatched).collect();

    assert!(undeclared.is_empty(), "traitées mais non déclarées : {undeclared:?}");
    assert!(unserved.is_empty(), "déclarées mais non traitées : {unserved:?}");
}

/// La liste déclarée par le serveur, lue depuis sa source.
///
/// Le binaire n'est pas une bibliothèque : ses constantes ne sont pas
/// importables depuis un test d'intégration. On lit donc le fichier, ce qui a
/// l'avantage de vérifier la liste TELLE QU'ELLE EST ÉCRITE.
fn fleetforge_web_commands() -> BTreeSet<String> {
    let source = read("src/api.rs");
    let start = source
        .find("pub const COMMANDS")
        .expect("constante COMMANDS introuvable");
    let body = &source[start..];
    let end = body.find("];").expect("liste COMMANDS non terminée");

    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix('"')?
                .split_once('"')
                .filter(|(_, tail)| tail.trim() == ",")
                .map(|(name, _)| name.to_string())
        })
        .collect()
}
