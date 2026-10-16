/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Journal de bord, partagé par les trois façades.
//!
//! Il existe parce qu'une erreur affichée ne se rattrape pas : la barre d'état
//! du TUI a montré `oci a échoué : /opt/homebrew/…/compute_cli_extended.py:25`
//! tronqué au bord de l'écran, et la cause réelle — trois lignes plus loin dans
//! stderr — n'était consultable nulle part. Le GUI a le même défaut sous une
//! autre forme : le message tient dans un bandeau, puis disparaît au
//! rechargement suivant.
//!
//! Choix de conception :
//!
//! - **Un fichier par FAÇADE**, pas par exécution. Les trois peuvent tourner en
//!   même temps sur le même poste ; un fichier unique mêlerait leurs lignes, et
//!   un fichier par lancement en sèmerait des centaines.
//! - **Rotation par taille**, à l'ouverture. Un journal qui grossit sans fin
//!   finit par remplir le disque d'un serveur — et c'est la supervision qui
//!   tombe en premier.
//! - **Jamais d'échec propagé.** Un journal qu'on ne peut pas écrire (disque
//!   plein, droits) ne doit pas empêcher l'application de démarrer : elle
//!   fonctionnait très bien sans lui hier.
//! - **Rien de secret.** Les valeurs d'identifiants ne passent JAMAIS par ici ;
//!   seuls y figurent le nom de l'hébergeur, la commande et le message d'erreur.

use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Au-delà, le fichier courant est basculé en `.1` et un neuf est ouvert.
const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Nombre de fichiers tournants conservés, en plus du courant.
const KEEP: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }
}

struct Logger {
    file: Mutex<Option<File>>,
    path: PathBuf,
    min: Level,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

/// Répertoire des journaux. `FLEETFORGE_LOG_DIR` l'emporte — le déploiement peut
/// vouloir les ranger ailleurs que dans le répertoire de données de l'utilisateur.
pub fn log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("FLEETFORGE_LOG_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir.trim());
        }
    }
    crate::paths::data_dir().join("logs")
}

/// Ouvre le journal de cette façade. Appelé UNE fois au démarrage.
///
/// `facade` nomme le fichier : `tui.log`, `web.log`, `gui.log`. Un second
/// appel est sans effet — la première ouverture fait foi, et deux façades dans
/// le même processus n'existent pas.
pub fn init(facade: &str) -> &'static Path {
    let logger = LOGGER.get_or_init(|| {
        let dir = log_dir();
        let path = dir.join(format!("{facade}.log"));
        let _ = std::fs::create_dir_all(&dir);
        rotate_if_needed(&path);

        let file = OpenOptions::new().create(true).append(true).open(&path).ok();

        Logger {
            file: Mutex::new(file),
            path,
            min: min_level(),
        }
    });

    log(
        Level::Info,
        facade,
        &format!("démarrage — journal {}", logger.path.display()),
    );
    &logger.path
}

/// Chemin du journal courant, une fois `init` appelé.
pub fn current_path() -> Option<&'static Path> {
    LOGGER.get().map(|l| l.path.as_path())
}

/// `FLEETFORGE_LOG_LEVEL` = debug | info | warn | error. Défaut : info.
fn min_level() -> Level {
    match std::env::var("FLEETFORGE_LOG_LEVEL")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "debug" | "trace" => Level::Debug,
        "warn" | "warning" => Level::Warn,
        "error" => Level::Error,
        _ => Level::Info,
    }
}

/// Fait tourner les fichiers si le courant est trop gros.
///
/// À l'OUVERTURE et non à chaque écriture : vérifier la taille à chaque ligne
/// coûterait un `stat` par ligne, et une session qui dépasse le seuil en cours
/// de route peut très bien attendre le prochain démarrage.
fn rotate_if_needed(path: &Path) {
    let too_big = std::fs::metadata(path).map(|m| m.len() >= MAX_BYTES).unwrap_or(false);
    if !too_big {
        return;
    }

    // Le plus ancien part en premier, sinon on écraserait en cascade.
    let numbered = |n: usize| path.with_extension(format!("log.{n}"));
    let _ = std::fs::remove_file(numbered(KEEP));
    for n in (1..KEEP).rev() {
        let _ = std::fs::rename(numbered(n), numbered(n + 1));
    }
    let _ = std::fs::rename(path, numbered(1));
}

/// Écrit une ligne. Sans `init` préalable, ne fait rien — c'est le cas des
/// tests, qui ne doivent pas semer de fichiers.
pub fn log(level: Level, scope: &str, message: &str) {
    let Some(logger) = LOGGER.get() else { return };
    if level < logger.min {
        return;
    }

    let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    // Une ligne par événement, et les retours à la ligne du message sont
    // remplacés : un message multi-lignes — une trace Python, typiquement —
    // casserait sinon tout filtrage par `grep`.
    let flat = message.replace('\n', " ⏎ ");
    let line = format!("{stamp} {} [{scope}] {flat}\n", level.label());

    if let Ok(mut guard) = logger.file.lock() {
        if let Some(file) = guard.as_mut() {
            // L'échec d'écriture est ignoré volontairement : le journal est un
            // confort, pas une dépendance de l'application.
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

pub fn debug(scope: &str, message: impl Display) {
    log(Level::Debug, scope, &message.to_string());
}

pub fn info(scope: &str, message: impl Display) {
    log(Level::Info, scope, &message.to_string());
}

pub fn warn(scope: &str, message: impl Display) {
    log(Level::Warn, scope, &message.to_string());
}

pub fn error(scope: &str, message: impl Display) {
    log(Level::Error, scope, &message.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_ordered_from_debug_to_error() {
        assert!(Level::Debug < Level::Info);
        assert!(Level::Info < Level::Warn);
        assert!(Level::Warn < Level::Error);
    }

    #[test]
    fn logging_without_init_is_a_no_op() {
        // Les tests n'appellent pas `init` : écrire ici sèmerait un fichier
        // dans le répertoire de données de qui joue la suite.
        log(Level::Error, "test", "ne doit rien écrire");
    }

    #[test]
    fn the_log_directory_follows_the_environment() {
        // Sans quoi un déploiement ne pourrait pas ranger ses journaux avec
        // ceux du service, là où l'exploitant va les chercher.
        std::env::set_var("FLEETFORGE_LOG_DIR", "/tmp/infra-logs-test");
        assert_eq!(log_dir(), PathBuf::from("/tmp/infra-logs-test"));
        std::env::remove_var("FLEETFORGE_LOG_DIR");
    }

    #[test]
    fn rotation_leaves_a_missing_file_alone() {
        // Au premier démarrage il n'y a rien à faire tourner.
        rotate_if_needed(Path::new("/tmp/infra-logs-test/absent.log"));
    }
}
