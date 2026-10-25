/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! État partagé par les routes. L'équivalent des `manage()` de Tauri.

use fleetforge_core::ro_gate::RoGateConfig;
use fleetforge_core::Core;
use fleetforge_providers::ProviderHub;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::events::EventHub;

#[derive(Clone)]
pub struct AppState {
    pub core: Arc<Core>,
    pub hub: Arc<ProviderHub>,
    pub events: EventHub,
    pub started: Instant,
    /// Diagnostic lecture seule (`ssh_diagnose`).
    pub ro_gate: Arc<RoGateConfig>,
    /// `--check` récents du compte d'automatisation.
    pub checks: CheckLedger,
    /// Compteurs de runs. Le registre ne peut pas en tenir lieu : il oublie les
    /// runs terminés (`clear_finished`), or un compteur Prometheus ne doit
    /// jamais décroître — un `rate()` sur une série qui recule rend n'importe
    /// quoi.
    counters: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    started: AtomicU64,
    failed: AtomicU64,
}

impl AppState {
    pub fn new(core: Core, ro_gate: RoGateConfig) -> Self {
        Self {
            core: Arc::new(core),
            hub: Arc::new(ProviderHub::new()),
            events: EventHub::new(),
            started: Instant::now(),
            ro_gate: Arc::new(ro_gate),
            checks: CheckLedger::default(),
            counters: Arc::new(Counters::default()),
        }
    }

    /// Consigne l'issue d'un run pour l'exposition Prometheus.
    ///
    /// Un run refusé AVANT le lancement d'Ansible (rôle sans hôte, variable
    /// manquante) compte comme un échec : c'est bien un déploiement demandé qui
    /// n'a pas eu lieu, et l'opérateur qui regarde la courbe cherche cela.
    pub fn record_run(&self, succeeded: bool) {
        self.counters.started.fetch_add(1, Ordering::Relaxed);
        if !succeeded {
            self.counters.failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn runs_started(&self) -> u64 {
        self.counters.started.load(Ordering::Relaxed)
    }

    pub fn runs_failed(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }
}

/// Durée pendant laquelle un `--check` autorise le run réel correspondant.
pub const CHECK_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// `--check` récents du compte d'automatisation, par empreinte de lancement
/// (parc, playbook, `--limit`, variables).
///
/// Décision D9 d'AgentHub, tenue ICI et pas seulement chez l'appelant : un
/// run réel lancé par l'automatisation exige le `--check` du MÊME lancement,
/// achevé depuis moins de [`CHECK_VALIDITY`]. Un modèle qui sauterait l'étape
/// — consigne mal suivie, injection dans une alerte — est arrêté à la porte
/// d'exécution, là où il ne peut pas la contourner.
#[derive(Clone, Default)]
pub struct CheckLedger(Arc<Mutex<HashMap<String, Instant>>>);

impl CheckLedger {
    pub fn record(&self, fingerprint: &str) {
        let mut done = self.0.lock().unwrap_or_else(|e| e.into_inner());
        done.retain(|_, at| at.elapsed() < CHECK_VALIDITY);
        done.insert(fingerprint.to_string(), Instant::now());
    }

    pub fn is_fresh(&self, fingerprint: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(fingerprint)
            .is_some_and(|at| at.elapsed() < CHECK_VALIDITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_unlocks_only_its_own_launch() {
        let ledger = CheckLedger::default();
        assert!(!ledger.is_fresh("web3c|deploy-x.yml"));
        ledger.record("web3c|deploy-x.yml");
        assert!(ledger.is_fresh("web3c|deploy-x.yml"));
        assert!(!ledger.is_fresh("web3c|deploy-y.yml"));
    }
}
