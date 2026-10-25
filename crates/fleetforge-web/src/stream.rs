/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Flux de la sortie d'un run (Server-Sent Events).
//!
//! Le raccordement se fait en trois temps, et l'ORDRE compte :
//!   1. abonnement au canal du run — avant tout le reste, sinon les lignes
//!      produites pendant l'étape 2 seraient perdues ;
//!   2. relecture de ce que le registre a déjà accumulé ;
//!   3. reprise du direct, en n'acceptant que les rangs postérieurs à la
//!      relecture — ce qui écarte les lignes vues deux fois.
//!
//! Sans ce dispositif, un navigateur qui ouvre son flux 200 ms après avoir
//! lancé le run manquerait les premières lignes : justement celles qui portent
//! les échecs de connexion SSH.
//!
//! Pour le compte d'automatisation, chaque ligne passe par le caviardage
//! (`fleetforge_core::redact`) : elle part chez le fournisseur d'un modèle.

use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Extension;
use fleetforge_core::redact::Redactor;
use futures_util::future::ready;
use futures_util::stream::{self, Stream, StreamExt};
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

use crate::config::Role;
use crate::events::Line;
use crate::state::AppState;

/// Ce que le flux transporte, avant mise en forme SSE.
enum Item {
    Line(String),
    End,
}

pub async fn sse(
    State(state): State<AppState>,
    role: Option<Extension<Role>>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    let receiver = state.events.subscribe(&run_id);

    let handle = state.core.runs().get(&run_id);

    // Un run déjà terminé n'émettra plus rien : on rejoue et on clôt, sinon le
    // navigateur garderait un `EventSource` ouvert sur un flux mort et le
    // rouvrirait à chaque expiration.
    //
    // Un run INCONNU, lui, n'est pas un run terminé : c'est le cas NORMAL au
    // raccordement, le frontal ouvrant son flux avant de lancer le run — sans
    // quoi il perdrait les premières lignes. Le confondre avec un run fini
    // fermait le flux aussitôt, et l'interface restait muette de bout en bout.
    let finished = handle.as_ref().is_some_and(|h| !h.is_running());
    let replay = handle.map(|h| h.output).unwrap_or_default();
    let replayed = replay.len();

    let head = stream::iter(replay.into_iter().map(Item::Line));
    let items = head.chain(live(receiver, replayed, finished));

    // Rôle absent = requête qui n'est pas passée par l'authentification :
    // traitée comme la moins privilégiée.
    let redact = role.map_or(true, |Extension(r)| r == Role::Automation);
    let events = items
        .scan(Redactor::new(), move |redactor, item| {
            let event = match item {
                Item::End => Some(end()),
                Item::Line(text) if redact => redactor.line(&text).map(|l| data(&l)),
                Item::Line(text) => Some(data(&text)),
            };
            ready(Some(event))
        })
        .filter_map(|event| ready(event.map(Ok::<_, Infallible>)));

    Sse::new(events).keep_alive(
        // Un déploiement peut rester silencieux plusieurs minutes (attente
        // d'un `apt`, d'une compilation). Sans battement, un intermédiaire —
        // nginx ici — coupe une connexion inactive, et l'interface donne le run
        // pour interrompu alors qu'il se déroule normalement.
        KeepAlive::new().interval(Duration::from_secs(15)),
    )
}

fn data(line: &str) -> Event {
    Event::default().data(line)
}

/// Événement de fin. Le client ferme son `EventSource` dessus : un flux SSE
/// simplement terminé côté serveur est rouvert par le navigateur, qui
/// rejouerait alors toute la sortie, indéfiniment.
fn end() -> Event {
    Event::default().event("end").data("")
}

fn live(
    receiver: tokio::sync::broadcast::Receiver<Line>,
    replayed: usize,
    finished: bool,
) -> impl Stream<Item = Item> {
    // État : (canal, rangs déjà rejoués, run fini au raccordement, fin émise).
    stream::unfold(
        (receiver, replayed, finished, false),
        |(mut rx, replayed, finished, ended)| async move {
            if ended {
                return None;
            }
            // Run déjà terminé : la relecture a tout rendu, reste à clore —
            // par l'événement de fin, sans quoi le client rouvrirait le flux.
            if finished {
                return Some((Item::End, (rx, replayed, finished, true)));
            }
            loop {
                match rx.recv().await {
                    Ok(line) if line.is_end() => return Some((Item::End, (rx, replayed, false, true))),
                    // Déjà servie par la relecture.
                    Ok(line) if line.index < replayed => continue,
                    Ok(line) => return Some((Item::Line(line.text), (rx, replayed, false, false))),
                    // Client trop lent : des lignes sont perdues. Le flux
                    // continue — l'historique complet reste lisible dans le
                    // registre et en base, la sortie en direct n'est pas la
                    // source de vérité.
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => return Some((Item::End, (rx, replayed, false, true))),
                }
            }
        },
    )
}
