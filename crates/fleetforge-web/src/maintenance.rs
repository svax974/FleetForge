/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Entretien périodique de l'arbre git (`ff_ansible_source: git`).
//!
//! Les références `infra/<parc>/*` ne sont élaguées par `sync_tree` que pour le
//! parc de l'appelant et seulement quand il récupère une branche de correctif :
//! une branche fusionnée puis supprimée côté fournisseur (GitLab, GitHub)
//! resterait sinon une référence permise, et ses arbres d'exécution au cache.
//! Ce module rejoue le nettoyage du cœur au démarrage puis toutes les heures.

use fleetforge_core::Core;
use std::sync::Arc;
use std::time::Duration;

/// Période du nettoyage.
pub const PRUNE_EVERY: Duration = Duration::from_secs(3600);

/// Lance `job` tout de suite puis toutes les `period`, sur un fil bloquant (git
/// est synchrone). Le premier passage est celui du démarrage. Un passage lent
/// retarde le suivant sans les cumuler.
pub fn every<F>(period: Duration, job: F) -> tokio::task::JoinHandle<()>
where
    F: Fn() + Send + Sync + 'static,
{
    let job = Arc::new(job);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let job = job.clone();
            let _ = tokio::task::spawn_blocking(move || job()).await;
        }
    })
}

/// Nettoyage de l'arbre git du cœur : au démarrage, puis toutes les heures.
pub fn spawn_git_prune(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    every(PRUNE_EVERY, move || match core.prune_git() {
        None => {}
        Some(Ok(report)) => {
            if !report.refs_removed.is_empty() || report.trees_removed > 0 {
                fleetforge_core::logging::info(
                    "web",
                    format!(
                        "arbre git : {} référence(s) infra/* orpheline(s) retirée(s) ({}), {} arbre(s) d'exécution retiré(s)",
                        report.refs_removed.len(),
                        report.refs_removed.join(", "),
                        report.trees_removed
                    ),
                );
            }
            if let Some(why) = report.refs_error {
                fleetforge_core::logging::warn(
                    "web",
                    format!("arbre git : références infra/* non comparées au dépôt ({why})"),
                );
            }
        }
        Some(Err(e)) => fleetforge_core::logging::warn("web", format!("arbre git : nettoyage impossible ({e})")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn the_job_runs_at_start_then_on_every_period() {
        let runs = Arc::new(AtomicUsize::new(0));
        let seen = runs.clone();
        let handle = every(Duration::from_millis(30), move || {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(250)).await;
        handle.abort();
        let n = runs.load(Ordering::SeqCst);
        assert!(n >= 3, "au moins le démarrage et deux périodes, obtenu {n}");
        assert!(n <= 10, "pas de rafale : {n}");
    }

    #[test]
    fn the_period_is_hourly() {
        assert_eq!(PRUNE_EVERY, Duration::from_secs(3600));
    }
}
