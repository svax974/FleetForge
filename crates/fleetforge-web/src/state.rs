/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! État partagé par les routes. L'équivalent des `manage()` de Tauri.

use fleetforge_core::Core;
use fleetforge_providers::ProviderHub;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::events::EventHub;

#[derive(Clone)]
pub struct AppState {
    pub core: Arc<Core>,
    pub hub: Arc<ProviderHub>,
    pub events: EventHub,
    pub started: Instant,
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
    pub fn new(core: Core) -> Self {
        Self {
            core: Arc::new(core),
            hub: Arc::new(ProviderHub::new()),
            events: EventHub::new(),
            started: Instant::now(),
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
