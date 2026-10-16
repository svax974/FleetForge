/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Jetons sémantiques de statut, définis une fois pour les deux interfaces.
//!
//! Le GUI les mappe vers des classes Tailwind, le TUI vers des `ratatui::Style`.
//! Ce qui compte est qu'un même état ne se rende jamais « vert » d'un côté et
//! « ambre » de l'autre : c'est la cohérence visuelle qui rend les deux vues
//! superposables.

use crate::model::Health;
use serde::{Deserialize, Serialize};

/// Ton sémantique. Volontairement peu nombreux : au-delà, le code appelant
/// choisit une couleur au lieu de nommer un état.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tone {
    /// Nominal.
    Ok,
    /// Fonctionne, mais dégradé — mérite un regard, pas une astreinte.
    Warn,
    /// En panne.
    Danger,
    /// Rien de connu. JAMAIS rendu comme `Ok` : c'est tout l'enjeu d'une
    /// supervision, l'absence de signal n'est pas une bonne nouvelle.
    Unknown,
    /// Information neutre.
    Info,
}

impl Tone {
    /// Glyphe d'état. Utilisable en TUI comme en GUI — un rond plein se lit
    /// dans un terminal comme dans une carte.
    pub fn glyph(self) -> &'static str {
        match self {
            Tone::Ok => "●",
            Tone::Warn => "◐",
            Tone::Danger => "○",
            Tone::Unknown => "·",
            Tone::Info => "◦",
        }
    }

    /// Identifiant stable, consommé côté GUI pour choisir une classe Tailwind
    /// et côté TUI pour choisir une couleur.
    pub fn token(self) -> &'static str {
        match self {
            Tone::Ok => "ok",
            Tone::Warn => "warn",
            Tone::Danger => "danger",
            Tone::Unknown => "unknown",
            Tone::Info => "info",
        }
    }
}

impl From<Health> for Tone {
    fn from(h: Health) -> Tone {
        match h {
            Health::Up => Tone::Ok,
            Health::Degraded => Tone::Warn,
            Health::Down => Tone::Danger,
            Health::Unknown => Tone::Unknown,
        }
    }
}
