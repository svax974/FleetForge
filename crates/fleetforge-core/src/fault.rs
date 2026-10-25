/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Refus QUALIFIÉS du cœur.
//!
//! Le frontal n'affiche qu'un message ; un appelant programmatique (AgentHub)
//! doit, lui, distinguer « ce run n'existe pas » de « un run occupe déjà le
//! parc » sans lire une phrase en français. Le cœur reste ignorant de HTTP :
//! il qualifie l'erreur, la façade web en déduit le statut.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Argument absent, mal formé ou hors de la grammaire admise.
    InvalidArgument,
    UnknownParc,
    UnknownHost,
    /// Nom d'hôte présent dans plusieurs parcs : préciser `parc`.
    AmbiguousHost,
    UnknownPlaybook,
    UnknownRun,
    /// Un run occupe déjà ce parc (verrou de run).
    RunBusy,
    /// Un run EN COURS porte déjà cet identifiant.
    RunIdInUse,
    /// Un run réel exige un `--check` préalable du même lancement.
    CheckRequired,
    /// Réglage absent côté serveur (clé de diagnostic, Alertmanager…).
    NotConfigured,
    /// Service tiers injoignable ou réponse invalide (Alertmanager, ssh).
    Upstream,
    Timeout,
}

impl FaultKind {
    /// Code stable, celui que lit un appelant programmatique.
    pub fn code(self) -> &'static str {
        match self {
            FaultKind::InvalidArgument => "invalid_argument",
            FaultKind::UnknownParc => "unknown_parc",
            FaultKind::UnknownHost => "unknown_host",
            FaultKind::AmbiguousHost => "ambiguous_host",
            FaultKind::UnknownPlaybook => "unknown_playbook",
            FaultKind::UnknownRun => "unknown_run",
            FaultKind::RunBusy => "run_busy",
            FaultKind::RunIdInUse => "run_id_in_use",
            FaultKind::CheckRequired => "check_required",
            FaultKind::NotConfigured => "not_configured",
            FaultKind::Upstream => "upstream_error",
            FaultKind::Timeout => "timeout",
        }
    }
}

/// Erreur qualifiée. Circule dans un `anyhow::Error` ; la façade la retrouve
/// par `downcast_ref`.
#[derive(Debug, Clone)]
pub struct Fault {
    pub kind: FaultKind,
    pub message: String,
}

impl Fault {
    pub fn new(kind: FaultKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(FaultKind::InvalidArgument, message)
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Fault {}

/// `Err(Fault)` dans un `anyhow::Result`, en une expression.
pub fn fail<T>(kind: FaultKind, message: impl Into<String>) -> anyhow::Result<T> {
    Err(Fault::new(kind, message).into())
}

/// La qualification d'une erreur, si elle en porte une.
pub fn kind_of(error: &anyhow::Error) -> Option<FaultKind> {
    error.downcast_ref::<Fault>().map(|f| f.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fault_survives_the_trip_through_anyhow() {
        let err: anyhow::Error = Fault::new(FaultKind::RunBusy, "occupé").into();
        assert_eq!(kind_of(&err), Some(FaultKind::RunBusy));
        assert_eq!(err.to_string(), "occupé");
    }

    #[test]
    fn a_plain_error_has_no_kind() {
        assert_eq!(kind_of(&anyhow::anyhow!("x")), None);
    }
}
