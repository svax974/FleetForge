/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Traduction des jetons sémantiques du cœur en styles ratatui.
//!
//! Les jetons sont définis une seule fois, dans `fleetforge_core::style` ; le GUI les
//! mappe vers Tailwind, le TUI vers `ratatui::Style`. Un même état ne peut donc
//! pas se rendre « vert » d'un côté et « ambre » de l'autre, ce qui est la
//! condition pour que les deux vues soient superposables.

use fleetforge_core::diagnostics::Severity;
use fleetforge_core::model::Health;
use fleetforge_core::style::Tone;
use ratatui::style::{Color, Modifier, Style};

/// Accent de l'application. Aligné sur la teinte `primary` (sky) du GUI.
pub const ACCENT: Color = Color::Rgb(56, 189, 248);
pub const DIM: Color = Color::Rgb(107, 114, 128);
pub const TEXT: Color = Color::Rgb(229, 231, 235);
pub const PANEL_BORDER: Color = Color::Rgb(55, 65, 81);

pub fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Ok => Color::Rgb(74, 222, 128),
        Tone::Warn => Color::Rgb(251, 191, 36),
        Tone::Danger => Color::Rgb(248, 113, 113),
        // Gris, jamais vert : l'absence de signal n'est pas une bonne nouvelle.
        Tone::Unknown => DIM,
        Tone::Info => ACCENT,
    }
}

pub fn tone_style(tone: Tone) -> Style {
    Style::default().fg(tone_color(tone))
}

pub fn health_style(health: Health) -> Style {
    tone_style(Tone::from(health))
}

pub fn health_glyph(health: Health) -> &'static str {
    Tone::from(health).glyph()
}

pub fn severity_tone(severity: Severity) -> Tone {
    match severity {
        Severity::Error => Tone::Danger,
        Severity::Warning => Tone::Warn,
        Severity::Info => Tone::Info,
    }
}

pub fn severity_style(severity: Severity) -> Style {
    tone_style(severity_tone(severity))
}

pub fn severity_glyph(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "✖",
        Severity::Warning => "▲",
        Severity::Info => "•",
    }
}

pub fn title_style() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn dim_style() -> Style {
    Style::default().fg(DIM)
}

pub fn text_style() -> Style {
    Style::default().fg(TEXT)
}

/// Ligne sélectionnée. Le fond plutôt que la couleur du texte : la teinte du
/// texte porte déjà l'état de santé, la surcharger la ferait disparaître.
pub fn selected_style() -> Style {
    Style::default()
        .bg(Color::Rgb(30, 41, 59))
        .add_modifier(Modifier::BOLD)
}

/// Ligne sélectionnée dans un panneau qui N'A PAS le focus.
///
/// Le fond disparaît, le gras reste : deux lignes également surlignées dans
/// deux panneaux ne disent plus laquelle répond aux touches, et c'est
/// exactement ce que le curseur sert à dire.
pub fn selected_elsewhere_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Panneau ayant le focus, par opposition à son voisin.
pub fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(PANEL_BORDER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_health_is_never_green() {
        // Tout l'enjeu de la supervision : une machine dont on ne sait rien ne
        // doit jamais se présenter comme saine.
        assert_eq!(tone_color(Tone::Unknown), DIM);
        assert_ne!(tone_color(Tone::Unknown), tone_color(Tone::Ok));
        assert_eq!(health_style(Health::Unknown).fg, Some(DIM));
    }

    #[test]
    fn every_health_maps_to_a_distinct_colour() {
        let colours: Vec<Color> = [Health::Up, Health::Degraded, Health::Down, Health::Unknown]
            .into_iter()
            .map(|h| tone_color(Tone::from(h)))
            .collect();
        let mut unique = colours.clone();
        unique.dedup();
        assert_eq!(colours.len(), unique.len());
    }

    #[test]
    fn severities_keep_the_shared_tone_mapping() {
        assert_eq!(severity_tone(Severity::Error), Tone::Danger);
        assert_eq!(severity_tone(Severity::Warning), Tone::Warn);
    }
}
