/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Diffusion en direct de la sortie des runs, équivalent HTTP de
//! `window.emit()` côté Tauri.
//!
//! Une différence assumée avec Tauri : chaque ligne porte son RANG. Le
//! navigateur ouvre son flux après avoir lancé le run — parfois plusieurs
//! centaines de millisecondes après —, et ce sont justement les premières
//! lignes qui portent les échecs de connexion SSH. Le flux rejoue donc ce que
//! le registre a déjà accumulé, puis ne laisse passer que les lignes de rang
//! supérieur : ni trou, ni doublon, quel que soit l'instant du raccordement.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Rang réservé à la fin de run. Le client ferme son `EventSource` dessus :
/// sans cela le navigateur le rouvrirait indéfiniment, et chaque réouverture
/// rejouerait toute la sortie.
pub const END: usize = usize::MAX;

#[derive(Clone, Debug)]
pub struct Line {
    pub index: usize,
    pub text: String,
}

impl Line {
    pub fn is_end(&self) -> bool {
        self.index == END
    }
}

/// Un canal par run. La capacité borne le retard tolérable d'un client lent ;
/// au-delà, `recv` rend `Lagged` — le flux saute, mais ne se ferme pas.
const CAPACITY: usize = 1024;

#[derive(Clone, Default)]
pub struct EventHub {
    channels: Arc<Mutex<HashMap<String, broadcast::Sender<Line>>>>,
}

impl EventHub {
    pub fn new() -> Self {
        Self::default()
    }

    fn sender(&self, run_id: &str) -> broadcast::Sender<Line> {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels
            .entry(run_id.to_string())
            .or_insert_with(|| broadcast::channel(CAPACITY).0)
            .clone()
    }

    pub fn subscribe(&self, run_id: &str) -> broadcast::Receiver<Line> {
        self.sender(run_id).subscribe()
    }

    /// Diffuseur à brancher sur `Core::run_deploy` : il numérote les lignes.
    ///
    /// Le rang vient d'un compteur propre au run, et non de la longueur du
    /// registre : la lire imposerait de prendre son verrou en écriture à
    /// chaque ligne, sur le chemin chaud d'un `ansible-playbook` bavard.
    pub fn sink(&self, run_id: &str) -> impl Fn(String) + Send + Sync + 'static {
        let sender = self.sender(run_id);
        let next = AtomicUsize::new(0);
        move |text: String| {
            let index = next.fetch_add(1, Ordering::Relaxed);
            // `send` échoue quand plus personne n'écoute : c'est le cas normal
            // d'un run lancé puis suivi depuis une autre interface.
            let _ = sender.send(Line { index, text });
        }
    }

    /// Clôt le flux d'un run et libère son canal.
    pub fn finish(&self, run_id: &str) {
        let sender = {
            let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
            channels.remove(run_id)
        };
        if let Some(sender) = sender {
            let _ = sender.send(Line {
                index: END,
                text: String::new(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lines_are_numbered_from_zero() {
        let hub = EventHub::new();
        let mut rx = hub.subscribe("r1");
        let sink = hub.sink("r1");

        sink("PLAY".into());
        sink("TASK".into());

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!((first.index, first.text.as_str()), (0, "PLAY"));
        assert_eq!((second.index, second.text.as_str()), (1, "TASK"));
    }

    #[tokio::test]
    async fn finishing_closes_the_stream_once() {
        let hub = EventHub::new();
        let mut rx = hub.subscribe("r1");
        hub.finish("r1");

        assert!(rx.recv().await.unwrap().is_end());
        // Canal retiré : plus aucun émetteur, le flux se termine.
        assert!(rx.recv().await.is_err());
    }

    #[tokio::test]
    async fn a_late_subscriber_relies_on_the_rank_not_on_the_channel() {
        // Le canal ne conserve rien pour un abonné tardif : c'est le REGISTRE
        // qui rejoue, et le rang qui évite le doublon. Ce test fige la moitié
        // qui appartient au hub : ne rien livrer d'antérieur à l'abonnement.
        let hub = EventHub::new();
        let sink = hub.sink("r1");
        sink("perdue pour le canal".into());

        let mut rx = hub.subscribe("r1");
        sink("vue".into());

        let line = rx.recv().await.unwrap();
        assert_eq!(line.index, 1, "le rang doit survivre à l'abonnement tardif");
        assert_eq!(line.text, "vue");
    }
}
