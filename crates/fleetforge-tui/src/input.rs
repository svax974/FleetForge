/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Clavier.
//!
//! Le prototype ne définissait qu'UNE touche (Échap) et se pilotait à la
//! souris, son menu contextuel n'étant même pas câblé. Tout le modèle
//! d'interaction est ici : navigation vim, palette `:`, filtre `/`, aide `?`.

use crate::app::{
    ActionMenu, ActionTarget, App, Confirm, ConfirmedAction, CredentialsForm, MenuEntry, Msg,
    Overlay, PickItem, PickPurpose, Picker, ProviderFocus, RenameForm, Screen, Section,
    SessionMenu,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use fleetforge_core::actions::{actions_for, ActionContext, ActionId, Subject};
use fleetforge_core::deploy::{DeployRequest, PlaybookRequest};
use fleetforge_providers::PowerAction;
use fleetforge_core::SettingKey;
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;

pub fn handle_key(app: &mut App, key: KeyEvent, tx: &UnboundedSender<Msg>) {
    // Sous Windows, chaque touche produit un Press ET un Release : sans ce
    // filtre, tout serait fait deux fois.
    if key.kind != KeyEventKind::Press {
        return;
    }

    // Ctrl-C sort toujours, quelle que soit la superposition ouverte.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    match app.overlay.clone() {
        Some(Overlay::Filter) => handle_filter(app, key),
        Some(Overlay::Palette) => handle_palette(app, key, tx),
        Some(Overlay::Confirm(c)) => handle_confirm(app, key, c, tx),
        Some(Overlay::Credentials(form)) => handle_credentials(app, key, *form, tx),
        Some(Overlay::SessionMenu(menu)) => handle_session_menu(app, key, menu, tx),
        Some(Overlay::Picker(picker)) => handle_picker(app, key, *picker, tx),
        Some(Overlay::Rename(form)) => handle_rename(app, key, form, tx),
        Some(Overlay::Actions(menu)) => handle_actions(app, key, *menu),
        // Fermée par une touche voulue, pas par n'importe laquelle : une
        // frappe en cours quand l'erreur arrive la ferait disparaître sans
        // avoir été lue.
        Some(Overlay::Message(_)) => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ')) {
                app.overlay = None;
                app.status.clear();
            }
        }
        Some(Overlay::Help) => {
            // N'importe quelle touche referme l'aide : y chercher la bonne
            // serait absurde.
            app.overlay = None;
        }
        None => handle_normal(app, key, tx),
    }
}

fn handle_filter(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.filter.clear();
            app.overlay = None;
        }
        // Le filtre reste appliqué : c'est le but.
        KeyCode::Enter => app.overlay = None,
        KeyCode::Backspace => {
            app.filter.pop();
            app.set_cursor(app.cursor());
        }
        KeyCode::Char(c) => {
            app.filter.push(c);
            // Le curseur peut désigner une ligne que le filtre vient d'exclure.
            app.set_cursor(app.cursor());
        }
        _ => {}
    }
}

fn handle_palette(app: &mut App, key: KeyEvent, tx: &UnboundedSender<Msg>) {
    match key.code {
        KeyCode::Esc => {
            app.palette_input.clear();
            app.overlay = None;
        }
        KeyCode::Backspace => {
            app.palette_input.pop();
        }
        KeyCode::Char(c) => app.palette_input.push(c),
        KeyCode::Enter => {
            let input = app.palette_input.clone();
            app.palette_input.clear();
            app.overlay = None;
            run_command(app, input.trim(), tx);
        }
        _ => {}
    }
}

/// Saisie des identifiants.
///
/// L'édition est volontairement élémentaire — ajout et effacement en fin de
/// champ, comme le filtre et la palette. Un curseur déplaçable dans le texte
/// supposerait de gérer la sélection et le collage, pour des valeurs qu'on
/// colle d'un bloc et qu'on refait plutôt qu'on ne corrige.
fn handle_credentials(
    app: &mut App,
    key: KeyEvent,
    mut form: CredentialsForm,
    tx: &UnboundedSender<Msg>,
) {
    match key.code {
        KeyCode::Esc => {
            app.overlay = None;
            return;
        }
        KeyCode::Tab | KeyCode::Down => form.move_field(1),
        KeyCode::BackTab | KeyCode::Up => form.move_field(-1),
        // Les flèches horizontales sont libres : l'édition n'a pas de curseur
        // à déplacer dans le champ.
        KeyCode::Left => form.move_method(-1),
        KeyCode::Right => form.move_method(1),
        KeyCode::Backspace => form.backspace(),
        KeyCode::Enter => {
            let missing = form.missing();
            if !missing.is_empty() {
                form.error = Some(format!("champ(s) requis : {}", missing.join(", ")));
            } else if let Some((_, credentials)) = form.credentials() {
                let account = form.account_id();
                let renamed_from = form.original_id().filter(|from| *from != account);
                let hub = app.hub.clone();
                let tx = tx.clone();
                // Un profil Oracle absent est créé par la connexion : le navigateur
                // s'ouvre et la commande attend qu'on s'y soit connecté.
                app.status = if form.kind == fleetforge_core::model::ProviderKind::Oracle {
                    format!("connexion à {account}… (le navigateur peut s'ouvrir pour créer le profil)")
                } else {
                    format!("connexion à {account}…")
                };

                if renamed_from.is_some() {
                    // La liste des comptes va changer : le focus désignait l'ancien nom.
                    app.reset_focus();
                }

                tokio::spawn(async move {
                    // Renommer d'abord : les identifiants suivent, puis la
                    // connexion s'ouvre sous le nouveau nom avec les valeurs saisies.
                    if let Some(from) = renamed_from {
                        if let Err(e) = hub.rename(&from, &account.name).await {
                            let _ = tx.send(Msg::Error(e.to_string()));
                            return;
                        }
                    }
                    connect_and_list(hub, account, Some(credentials), tx).await;
                });

                app.overlay = None;
                return;
            }
        }
        KeyCode::Char(c) => form.push(c),
        _ => {}
    }
    app.overlay = Some(Overlay::Credentials(Box::new(form)));
}

/// Connecte un compte puis recharge ce que l'écran affiche.
///
/// `credentials` absent = reconnexion depuis l'enregistré.
///
/// Le rechargement des hébergeurs est indispensable : les comptes et l'état de
/// leur session vivent dans `ProviderStatus`, et sans ce renvoi la vignette
/// resterait sur « non connecté » après une connexion réussie.
///
/// Les instances sont relues pour TOUS les comptes ouverts de l'hébergeur —
/// n'en lister qu'un les ferait disparaître de l'écran dès qu'on en connecte
/// un second.
async fn connect_and_list(
    hub: std::sync::Arc<fleetforge_providers::ProviderHub>,
    account: fleetforge_providers::AccountId,
    credentials: Option<fleetforge_providers::Credentials>,
    tx: UnboundedSender<Msg>,
) {
    let outcome = match &credentials {
        Some(c) => hub.connect(&account, c).await,
        None => hub.reconnect(&account).await,
    };

    if let Err(e) = outcome {
        let _ = tx.send(Msg::Error(e.to_string()));
        return;
    }

    let _ = tx.send(Msg::Status(format!("{account} connecté")));
    let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));

    let (instances, failures) = hub.list_instances_everywhere(account.provider).await;
    let _ = tx.send(Msg::InstancesLoaded(account.provider, instances));
    // Les machines du parc deviennent pilotables depuis les écrans Serveurs et
    // Hôtes : c'est maintenant qu'il faut le leur dire.
    let _ = tx.send(Msg::ReloadControls);
    for (failed, error) in failures {
        let _ = tx.send(Msg::Error(format!("{failed} : {error}")));
    }
}

fn handle_confirm(app: &mut App, key: KeyEvent, confirm: Confirm, tx: &UnboundedSender<Msg>) {
    match key.code {
        // `o` pour oui, et `y` parce que les doigts la connaissent.
        KeyCode::Char('o') | KeyCode::Char('y') => {
            app.overlay = None;
            perform(app, confirm.action, tx);
        }
        _ => app.overlay = None,
    }
}

fn handle_normal(app: &mut App, key: KeyEvent, tx: &UnboundedSender<Msg>) {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') => app.overlay = Some(Overlay::Help),
        // `/` ouvre la palette : c'est le préfixe de commande auquel on
        // s'attend aujourd'hui. `:` reste accepté en alias — la mémoire des
        // doigts d'un habitué de vim n'a pas à être rééduquée pour ça.
        KeyCode::Char('/') | KeyCode::Char(':') => {
            app.palette_input.clear();
            app.overlay = Some(Overlay::Palette);
        }
        // Le filtre a donc changé de touche. `f` pour filtrer : la seule libre
        // qui se retienne, `s` et `r` étant déjà prises.
        KeyCode::Char('f') => {
            app.filter.clear();
            app.overlay = Some(Overlay::Filter);
        }

        // Échap dégrade par étapes plutôt que de tout jeter d'un coup : on
        // remonte d'un niveau (comptes), puis on efface le filtre, puis on
        // remonte dans le parc, et c'est tout en haut seulement qu'il efface
        // les marques.
        KeyCode::Esc => {
            // Le message de la barre d'état reste jusqu'au suivant : sans cela
            // une erreur lue y demeurait indéfiniment. `⎋` l'efface EN PLUS de
            // son action, pour ne pas coûter une frappe de plus.
            app.status.clear();
            if app.screen == Screen::Providers && app.focus_shallower() {
                // Remonté d'un niveau dans l'arborescence des comptes.
            } else if !app.filter.is_empty() {
                app.filter.clear();
                app.set_cursor(app.cursor());
            } else if app.ascend() {
                // Remonté d'un cran dans le fil d'Ariane du parc.
            } else {
                app.clear_marks();
            }
        }

        KeyCode::Tab => {
            let next = app.section().next();
            app.go_section(next);
        }
        KeyCode::BackTab => {
            let prev = app.section().previous();
            app.go_section(prev);
        }
        KeyCode::Char(c @ '1'..='5') => {
            if let Some(section) = Section::from_digit(c) {
                app.go_section(section);
            }
        }
        // ← → : descendre / remonter dans le parc, comme ↵ et ⎋ ; entre Rôles
        // et Playbooks, passer de l'un à l'autre.
        KeyCode::Right => match app.section() {
            Section::Parc => {
                app.descend();
            }
            Section::Ansible => app.toggle_ansible_view(),
            _ => {}
        },
        KeyCode::Left => match app.section() {
            Section::Parc => {
                app.ascend();
            }
            Section::Ansible => app.toggle_ansible_view(),
            _ => {}
        },
        KeyCode::Char('P') => open_parc_picker(app),

        KeyCode::Char('j') | KeyCode::Down => move_down(app, 1),
        KeyCode::Char('k') | KeyCode::Up => move_down(app, -1),
        KeyCode::PageDown => app.move_cursor(10),
        KeyCode::PageUp => app.move_cursor(-10),
        KeyCode::Char('g') | KeyCode::Home => app.cursor_home(),
        KeyCode::Char('G') | KeyCode::End => app.cursor_end(),

        KeyCode::Char(' ') => open_actions(app),
        KeyCode::Char('m') => app.toggle_mark(),

        KeyCode::Char('r') => {
            app.loading = true;
            app.status = "rechargement…".into();
            crate::reload_all(app, tx.clone());
        }

        KeyCode::Enter => drill_in(app, tx),
        KeyCode::Char('d') => request_deploy(app),
        KeyCode::Char('p') => request_playbook(app),
        KeyCode::Char('e') => request_exemption(app),
        KeyCode::Char('c') => connect_provider(app, tx),
        KeyCode::Char('C') => configure_provider(app),
        KeyCode::Char('a') => add_account(app),
        KeyCode::Char('n') => request_rename(app),
        // Sur Services, `x`/`X` retirent / purgent le service ; sur Providers,
        // ils ferment la session / effacent les identifiants. Même gravité
        // croissante, même confirmation.
        KeyCode::Char('x') => match app.screen {
            Screen::Services => request_uninstall(app, "remove"),
            _ => disconnect_provider(app, tx),
        },
        // Majuscule, et derrière confirmation : `x` ferme une session, `X`
        // efface des identifiants. La distinction doit se payer d'une touche
        // plus difficile à atteindre par accident.
        KeyCode::Char('X') => match app.screen {
            Screen::Services => request_uninstall(app, "purge"),
            _ => forget_account(app),
        },
        // `s` comme session. Sans confirmation : renouveler un jeton ne
        // détruit rien, et l'échec se lit dans la barre d'état.
        KeyCode::Char('s') => run_session_action(app, tx),

        // Alimentation. En MAJUSCULES, et derrière une confirmation : `r`
        // recharge le parc, `R` redémarre une machine — une frappe de trop ne
        // doit pas couper un serveur.
        KeyCode::Char('S') => request_power(app, PowerKind::Start),
        KeyCode::Char('A') => request_power(app, PowerKind::Stop),
        KeyCode::Char('R') => request_power(app, PowerKind::Reboot),

        _ => {}
    }
}

/// Déplace le curseur qui a le focus. Sur l'écran Providers, une fois
/// descendu dans les instances, `j`/`k` y restent plutôt que de changer
/// d'hébergeur sous les pieds de l'utilisateur.
fn move_down(app: &mut App, delta: isize) {
    if app.screen == Screen::Providers && app.focus != ProviderFocus::Providers {
        app.move_focus_cursor(delta);
    } else {
        // Changer d'hébergeur invalide le focus descendu : il désignerait un
        // compte ou une instance qui ne sont plus affichés.
        app.reset_focus();
        app.move_cursor(delta);
    }
}

/// Quelle action d'alimentation la touche demande. La variante gracieuse
/// n'est pas choisie ici : elle dépend de ce que l'hébergeur sait faire.
#[derive(Debug, Clone, Copy)]
enum PowerKind {
    Start,
    Stop,
    Reboot,
}

/// Prépare une action d'alimentation sur l'instance désignée.
///
/// La variante douce est retenue dès que l'hébergeur la déclare — c'est la
/// même règle que dans le GUI. `capabilities.stop` désigne l'arrêt BRUTAL et
/// `stop_graceful` l'arrêt propre : plusieurs hébergeurs n'ont que l'un des
/// deux, tester le premier seul refuserait l'action chez GCP.
fn request_power(app: &mut App, kind: PowerKind) {
    if !matches!(
        app.screen,
        Screen::Providers | Screen::Servers | Screen::Hosts | Screen::Services
    ) {
        return;
    }

    let Some((reference, name, caps, _)) = app.power_target() else {
        app.status = match app.screen {
            Screen::Providers => {
                "aucune instance désignée — ↵ pour descendre dans la liste".into()
            }
            // Trois causes possibles, et les distinguer évite de chercher au
            // mauvais endroit : hébergeur non connecté, machine sans instance
            // correspondante, ou adresse revendiquée par deux comptes.
            _ => "machine non rapprochée d'une instance — connecter son hébergeur (écran 9)"
                .to_string(),
        };
        return;
    };
    let label = reference.provider.label().to_string();

    let action = match kind {
        PowerKind::Start => PowerAction::Start,
        PowerKind::Stop => PowerAction::Stop {
            graceful: caps.stop_graceful,
        },
        PowerKind::Reboot => PowerAction::Reboot {
            graceful: caps.reboot_graceful,
        },
    };

    // Le garde-fou du cœur refuserait de toute façon, mais l'annoncer ici
    // évite une confirmation pour une action qui ne partira pas.
    if !caps.allows(action) {
        app.status = format!("{} ne sait pas faire : {}", label, action.label());
        return;
    }

    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("{} sur {} ? (o/n)", action.label(), name),
        action: ConfirmedAction::Power {
            reference,
            action,
            name,
        },
    }));
}

/// `↵` : descendre d'un niveau, ou exécuter ce que l'écran propose.
fn drill_in(app: &mut App, tx: &UnboundedSender<Msg>) {
    match app.screen {
        Screen::Servers | Screen::Hosts => {
            app.descend();
        }
        // Au bas de l'arbre, il n'y a plus où descendre : `↵` offre ce qu'on
        // peut faire du service.
        Screen::Services => open_actions(app),
        Screen::Roles => {
            if let Some(role) = app.selected_role_name() {
                deploy_role_on_targets(app, role);
            }
        }
        Screen::Playbooks => request_run_playbook(app),
        Screen::Diagnostics => {
            // Aller à l'élément que le constat désigne : un diagnostic sans
            // chemin vers son sujet oblige à le chercher à la main.
            use fleetforge_core::diagnostics::Subject as Target;
            let subject = app
                .visible_findings()
                .get(app.cursor())
                .map(|f| f.subject.clone());
            match subject {
                Some(Target::Host(name)) => app.reveal_host(&name),
                Some(Target::Server(id)) => app.reveal_server(&id),
                Some(Target::RoleFamily(family)) => {
                    app.go(Screen::Roles);
                    app.filter = family;
                    app.cursor_home();
                }
                _ => {}
            }
        }
        // ↵ descend d'un niveau : hébergeur → comptes → instances. Au plus
        // bas, ou quand il n'y a rien où descendre, il connecte — ce qui est
        // précisément ce qui fera apparaître le niveau suivant.
        Screen::Providers => {
            if !app.focus_deeper() {
                connect_provider(app, tx);
            }
        }
        Screen::Runs => {}
    }
}

// === Sélecteur ===

/// Ouvre le choix du parc — la liste déroulante du GUI. Lit les inventaires
/// au moment de l'ouverture : la liste ne dépend pas du parc courant.
pub fn open_parc_picker(app: &mut App) {
    let available = match app.core.list_inventories() {
        Ok(list) => list,
        Err(e) => {
            app.status = format!("\u{26a0} inventaires illisibles : {e}");
            return;
        }
    };
    if available.is_empty() {
        app.status = "aucun inventaire — renseigner le chemin des inventaires".into();
        return;
    }
    let items: Vec<PickItem> = available
        .iter()
        .map(|i| PickItem {
            label: i.name.clone(),
            detail: format!(
                "{}{}",
                if i.file_path == app.inventory_path { "● courant · " } else { "" },
                i.organization
            ),
            value: i.name.clone(),
        })
        .collect();
    let mut picker = Picker::new("Parc", PickPurpose::Parc, items);
    // Le curseur part sur le parc courant : on le voit, et `↵` ne change rien.
    picker.cursor = available
        .iter()
        .position(|i| i.file_path == app.inventory_path)
        .unwrap_or(0);
    app.overlay = Some(Overlay::Picker(Box::new(picker)));
}

fn handle_picker(app: &mut App, key: KeyEvent, mut picker: Picker, tx: &UnboundedSender<Msg>) {
    match key.code {
        KeyCode::Esc => {
            app.overlay = None;
            return;
        }
        KeyCode::Up => picker.move_cursor(-1),
        KeyCode::Down => picker.move_cursor(1),
        KeyCode::Backspace => {
            picker.query.pop();
            picker.retarget();
        }
        // Tout caractère filtre — `j`/`k` compris : c'est une liste où l'on
        // TAPE le nom, les flèches suffisent à s'y déplacer.
        KeyCode::Char(c) => {
            picker.query.push(c);
            picker.retarget();
        }
        KeyCode::Enter => {
            let Some(item) = picker.selected().cloned() else { return };
            app.overlay = None;
            choose(app, picker.purpose, item, tx);
            return;
        }
        _ => {}
    }
    app.overlay = Some(Overlay::Picker(Box::new(picker)));
}

/// Suite donnée à un choix, selon ce qu'on choisissait.
fn choose(app: &mut App, purpose: PickPurpose, item: PickItem, tx: &UnboundedSender<Msg>) {
    match purpose {
        PickPurpose::Parc => switch_inventory(app, Some(&item.value), tx),
        PickPurpose::Role { hosts } => confirm_deploy(app, item.value, hosts),
        PickPurpose::HostFor { role } => confirm_deploy(app, role, vec![item.value]),
        PickPurpose::Playbook { hosts } => confirm_playbook(app, item.label, item.value, hosts),
        PickPurpose::Alert { host } => toggle_exemption(app, &host, &item.value, tx),
    }
}

// === Menu d'actions ===

/// Ce que le cœur a besoin de savoir pour décider des actions possibles.
fn action_context(app: &App, target: &ActionTarget) -> ActionContext {
    let mut ctx = ActionContext {
        has_roles: !app.roles.is_empty(),
        has_playbooks: !app.playbooks.is_empty(),
        power: app.power_state(),
        ..Default::default()
    };
    match target {
        ActionTarget::Machine(key) => {
            let hosts = app
                .visible_servers()
                .iter()
                .find(|s| &s.key == key)
                .map(|s| s.hosts.clone())
                .unwrap_or_default();
            ctx.findings = app.findings_touching(&key.to_string(), &hosts).len();
        }
        ActionTarget::Host(name) => {
            ctx.findings = app.findings_touching("", std::slice::from_ref(name)).len();
        }
        ActionTarget::Service { name, .. } => {
            ctx.can_remove = fleetforge_core::resolve_role(&app.roles, name, "remove").is_some();
            ctx.can_purge = fleetforge_core::resolve_role(&app.roles, name, "purge").is_some();
        }
    }
    ctx
}

/// `espace` : les actions de l'élément désigné, avec leur raison quand l'une
/// n'est pas disponible.
fn open_actions(app: &mut App) {
    let (subject, target, title) = match app.screen {
        Screen::Servers => {
            let Some(key) = app.selected_server_key() else { return };
            let title = key.to_string();
            (Subject::Machine, ActionTarget::Machine(key), title)
        }
        Screen::Hosts => {
            let Some(name) = app.selected_host_name() else { return };
            (Subject::Host, ActionTarget::Host(name.clone()), name)
        }
        Screen::Services => {
            let Some((name, host)) = app
                .visible_services()
                .get(app.cursor())
                .map(|s| (s.service_name.clone(), s.server_name.clone()))
            else {
                return;
            };
            let title = format!("{name} @ {host}");
            (Subject::Service, ActionTarget::Service { name, host }, title)
        }
        _ => return,
    };

    let entries = actions_for(subject, &action_context(app, &target));
    // Le curseur part sur la première action disponible : `↵` fait alors
    // quelque chose plutôt que de répondre « indisponible ».
    let cursor = entries.iter().position(|a| a.enabled).unwrap_or(0);
    app.overlay = Some(Overlay::Actions(Box::new(ActionMenu {
        title,
        entries,
        cursor,
    })));
}

fn handle_actions(app: &mut App, key: KeyEvent, mut menu: ActionMenu) {
    let chosen = match key.code {
        KeyCode::Esc => {
            app.overlay = None;
            return;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            menu.move_cursor(1);
            None
        }
        KeyCode::Char('k') | KeyCode::Up => {
            menu.move_cursor(-1);
            None
        }
        KeyCode::Enter => menu.selected().cloned(),
        // Le raccourci direct de l'entrée, pour qui le connaît déjà.
        KeyCode::Char(c) => menu
            .entries
            .iter()
            .find(|a| a.key.as_deref() == Some(c.to_string().as_str()))
            .cloned(),
        _ => None,
    };

    let Some(action) = chosen else {
        app.overlay = Some(Overlay::Actions(Box::new(menu)));
        return;
    };

    if !action.enabled {
        // Le menu reste ouvert : l'indisponibilité s'explique, elle ne ferme pas.
        app.status = format!(
            "{} : {}",
            action.label.trim_end_matches('…'),
            action.reason.clone().unwrap_or_default()
        );
        app.overlay = Some(Overlay::Actions(Box::new(menu)));
        return;
    }

    app.overlay = None;
    execute_action(app, action.id);
}

/// Exécute l'action choisie sur la sélection courante — l'écran n'a pas
/// bougé depuis l'ouverture du menu, les helpers lisent donc la même ligne.
fn execute_action(app: &mut App, id: ActionId) {
    match id {
        ActionId::Start => request_power(app, PowerKind::Start),
        ActionId::Stop => request_power(app, PowerKind::Stop),
        ActionId::Reboot => request_power(app, PowerKind::Reboot),
        ActionId::DeployRole => request_deploy(app),
        ActionId::RunPlaybook => request_playbook(app),
        ActionId::ExemptAlert => request_exemption(app),
        ActionId::ViewHosts | ActionId::ViewServices => {
            app.descend();
        }
        ActionId::ViewFindings => {
            let name = match app.screen {
                Screen::Servers => app.selected_server_key().map(|k| k.address),
                Screen::Hosts => app.selected_host_name(),
                _ => None,
            };
            if let Some(name) = name {
                app.go(Screen::Diagnostics);
                app.filter = name;
                app.cursor_home();
            }
        }
        ActionId::Remove => request_uninstall(app, "remove"),
        ActionId::Purge => request_uninstall(app, "purge"),
        // Ces deux-là n'existent que dans le catalogue partagé : le TUI les
        // porte par `↵` sur Rôles et Playbooks, sans menu.
        ActionId::DeployOn | ActionId::Run => {}
    }
}

// === Déployer, lancer, retirer ===

/// `d` : sur une machine, un hôte ou un service, choisir le rôle à y déployer ;
/// sur un rôle, choisir où.
fn request_deploy(app: &mut App) {
    match app.screen {
        Screen::Roles => {
            if let Some(role) = app.selected_role_name() {
                deploy_role_on_targets(app, role);
            }
        }
        Screen::Servers | Screen::Hosts | Screen::Services => {
            let hosts = app.target_hosts();
            if hosts.is_empty() {
                app.status = "aucun hôte désigné".into();
                return;
            }
            if app.roles.is_empty() {
                app.status = "aucun rôle dans le catalogue — renseigner le chemin des playbooks".into();
                return;
            }
            // Les rôles de la famille de l'hôte d'abord : c'est eux qu'on vient
            // chercher, les cinquante autres restent à portée de frappe.
            let families: Vec<String> = app
                .fleet
                .as_ref()
                .map(|f| {
                    hosts
                        .iter()
                        .filter_map(|h| f.host(h))
                        .flat_map(|h| h.ansible_roles.clone())
                        .collect()
                })
                .unwrap_or_default();
            let relevant = |name: &str| families.iter().any(|f| name.starts_with(&format!("{f}-")));
            let mut roles: Vec<&fleetforge_core::AnsibleRole> = app.roles.iter().collect();
            roles.sort_by_key(|r| !relevant(&r.name));
            let items = roles
                .into_iter()
                .map(|r| PickItem {
                    label: r.name.clone(),
                    detail: if relevant(&r.name) {
                        format!("● famille de l'hôte · {}", r.category)
                    } else {
                        r.category.clone()
                    },
                    value: r.name.clone(),
                })
                .collect();
            let title = format!("Déployer un rôle sur {} hôte(s)", hosts.len());
            app.overlay = Some(Overlay::Picker(Box::new(Picker::new(
                &title,
                PickPurpose::Role { hosts },
                items,
            ))));
        }
        _ => app.status = "sélectionner une machine, un hôte ou un rôle pour déployer".into(),
    }
}

/// Déploie `role` sur les hôtes marqués, sinon demande où.
fn deploy_role_on_targets(app: &mut App, role: String) {
    if !app.marked_hosts.is_empty() {
        let hosts = app.target_hosts();
        confirm_deploy(app, role, hosts);
        return;
    }
    let Some(fleet) = &app.fleet else {
        app.status = "parc non chargé".into();
        return;
    };
    let items = fleet
        .hosts
        .iter()
        .map(|h| PickItem {
            label: h.name.clone(),
            detail: h.ansible_host.clone(),
            value: h.name.clone(),
        })
        .collect();
    let title = format!("Déployer `{role}` sur…");
    app.overlay = Some(Overlay::Picker(Box::new(Picker::new(
        &title,
        PickPurpose::HostFor { role },
        items,
    ))));
}

fn confirm_deploy(app: &mut App, role: String, hosts: Vec<String>) {
    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("Déployer `{role}` sur {} hôte(s) : {} ?", hosts.len(), hosts.join(", ")),
        action: ConfirmedAction::Deploy { role, hosts },
    }));
}

/// `p` : choisir un playbook à lancer, limité à la sélection.
fn request_playbook(app: &mut App) {
    if !matches!(app.screen, Screen::Servers | Screen::Hosts | Screen::Services) {
        app.status = "sélectionner une machine ou un hôte pour lancer un playbook".into();
        return;
    }
    let hosts = app.target_hosts();
    if hosts.is_empty() {
        app.status = "aucun hôte désigné".into();
        return;
    }
    if app.playbooks.is_empty() {
        app.status = "aucun playbook dans le catalogue — renseigner le chemin des playbooks".into();
        return;
    }
    let items = app
        .playbooks
        .iter()
        .map(|p| PickItem {
            label: p.label.clone(),
            detail: p.name.clone(),
            value: p.path.clone(),
        })
        .collect();
    let title = format!("Lancer un playbook sur {} hôte(s)", hosts.len());
    app.overlay = Some(Overlay::Picker(Box::new(Picker::new(
        &title,
        PickPurpose::Playbook { hosts },
        items,
    ))));
}

/// `↵` sur Playbooks : lance le playbook désigné, sur les hôtes marqués s'il y
/// en a, sinon sur tout ce qu'il cible.
fn request_run_playbook(app: &mut App) {
    let Some((label, path)) = app
        .visible_playbooks()
        .get(app.cursor())
        .map(|p| (p.label.clone(), p.path.clone()))
    else {
        return;
    };
    let hosts = if app.marked_hosts.is_empty() {
        Vec::new()
    } else {
        app.target_hosts()
    };
    confirm_playbook(app, label, path, hosts);
}

fn confirm_playbook(app: &mut App, label: String, path: String, hosts: Vec<String>) {
    let scope = if hosts.is_empty() {
        "tout le parc (sans --limit)".to_string()
    } else {
        format!("{} hôte(s) : {}", hosts.len(), hosts.join(", "))
    };
    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("Lancer `{label}` sur {scope} ?"),
        action: ConfirmedAction::RunPlaybook { label, path, hosts },
    }));
}

/// `x` / `X` sur Services : retire (binaire + service) ou purge (données et
/// configuration) le service désigné, par son rôle `-remove` / `-purge`.
fn request_uninstall(app: &mut App, action: &str) {
    let Some((service, host)) = app
        .visible_services()
        .get(app.cursor())
        .map(|s| (s.service_name.clone(), s.server_name.clone()))
    else {
        return;
    };
    let Some(role) = fleetforge_core::resolve_role(&app.roles, &service, action) else {
        app.status = format!("pas de rôle -{action} pour {service}");
        return;
    };
    let verb = if action == "purge" { "Purger" } else { "Retirer" };
    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("{verb} {service} de {host} (rôle {}) ? (o/n)", role.name),
        action: ConfirmedAction::Deploy {
            role: role.name,
            hosts: vec![host],
        },
    }));
}

/// `e` : choisir une alerte dont on bascule l'exemption sur l'hôte désigné.
fn request_exemption(app: &mut App) {
    if app.screen != Screen::Hosts {
        app.status = "sélectionner un hôte pour gérer ses exemptions".into();
        return;
    }
    let Some(host) = app.visible_hosts().get(app.cursor()).map(|h| (*h).clone()) else { return };
    let rules = match app.core.list_alert_rules(&app.inventory_path) {
        Ok(rules) => rules,
        Err(e) => {
            app.status = format!("\u{26a0} {e}");
            return;
        }
    };
    let items: Vec<PickItem> = rules
        .iter()
        .filter(|r| r.loaded)
        .map(|r| PickItem {
            label: r.name.clone(),
            detail: if host.alert_exclude.contains(&r.name) {
                format!("● exemptée · {}", r.group)
            } else {
                r.group.clone()
            },
            value: r.name.clone(),
        })
        .collect();
    if items.is_empty() {
        app.status = "aucune règle d'alerte chargée sur ce parc".into();
        return;
    }
    let title = format!("Exemptions de {} — ↵ bascule", host.name);
    app.overlay = Some(Overlay::Picker(Box::new(Picker::new(
        &title,
        PickPurpose::Alert { host: host.name },
        items,
    ))));
}

fn perform(app: &mut App, action: ConfirmedAction, tx: &UnboundedSender<Msg>) {
    match action {
        ConfirmedAction::Deploy { role, hosts } => {
            let core = app.core.clone();
            let inventory = app.inventory_path.clone();
            let tx = tx.clone();
            let label = role.clone();

            app.status = format!("déploiement de {role}…");
            app.go(Screen::Runs);

            // `spawn_blocking` : le run est un processus qui dure des minutes,
            // il ne doit pas occuper un fil de l'exécuteur asynchrone.
            tokio::task::spawn_blocking(move || {
                let request = DeployRequest {
                    id: format!("tui-{}", now_millis()),
                    label,
                    inventory_path: inventory,
                    roles: vec![role],
                    hosts,
                    extra_vars: HashMap::new(),
                };
                // La sortie est accumulée par le registre du cœur ; la boucle
                // de rendu l'y relit. Rien à transmettre ligne à ligne.
                match core.run_deploy(request, |_| {}) {
                    Ok(run) => {
                        let _ = tx.send(Msg::Status(format!("run terminé : {}", run.status)));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        ConfirmedAction::RunPlaybook { label, path, hosts } => {
            let core = app.core.clone();
            let inventory = app.inventory_path.clone();
            let tx = tx.clone();
            app.status = format!("{label}…");
            app.go(Screen::Runs);
            tokio::task::spawn_blocking(move || {
                let request = PlaybookRequest {
                    id: format!("tui-{}", now_millis()),
                    label,
                    playbook_path: path,
                    inventory_path: inventory,
                    limit_hosts: (!hosts.is_empty()).then_some(hosts),
                    extra_vars: HashMap::new(),
                };
                match core.run_playbook(request, |_| {}) {
                    Ok(run) => {
                        let _ = tx.send(Msg::Status(format!("run terminé : {}", run.status)));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
        ConfirmedAction::ForgetAccount { account } => {
            let hub = app.hub.clone();
            let tx = tx.clone();
            let kind = account.provider;
            app.status = format!("oubli de {account}…");
            // Le focus désignait ce compte : il va disparaître de la liste.
            app.reset_focus();

            tokio::spawn(async move {
                match hub.forget(&account).await {
                    Ok(()) => {
                        let _ = tx.send(Msg::Status(format!("{account} oublié")));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
                let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
                let (instances, _) = hub.list_instances_everywhere(kind).await;
                let _ = tx.send(Msg::InstancesLoaded(kind, instances));
            });
        }
        ConfirmedAction::Power {
            reference,
            action,
            name,
        } => {
            let hub = app.hub.clone();
            let tx = tx.clone();
            let kind = reference.provider;
            app.status = format!("{} sur {name}…", action.label());

            tokio::spawn(async move {
                match hub.power(&reference, action).await {
                    Ok(()) => {
                        let _ = tx.send(Msg::Status(format!("{} demandé sur {name}", action.label())));
                        // L'état ne bascule pas instantanément côté hébergeur.
                        // Relister tout de suite montrerait l'état d'avant et
                        // ferait croire que rien n'a pris.
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        // Tous les comptes : la liste affichée les mêle, n'en
                        // relire qu'un ferait disparaître les autres.
                        let (instances, _) = hub.list_instances_everywhere(kind).await;
                        let _ = tx.send(Msg::InstancesLoaded(kind, instances));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
            });
        }
    }
}

/// Vérifie qu'un hébergeur peut être configuré, et dit pourquoi sinon.
fn usable_provider(app: &mut App) -> Option<fleetforge_providers::ProviderInfo> {
    if app.screen != Screen::Providers {
        return None;
    }
    let status = app.selected_provider()?;
    let info = status.info.clone();

    if let Some(tool) = &info.missing_tool {
        app.status = format!("⚠ `{tool}` n'est pas installé");
        return None;
    }
    if !info.capabilities.list {
        app.status = format!("{} n'a pas d'API — machines physiques", info.label);
        return None;
    }
    if info.auth_methods.is_empty() {
        app.status = format!("{} ne demande aucun identifiant", info.label);
        return None;
    }
    Some(info)
}

/// Ouvre le formulaire d'identifiants du COMPTE désigné.
///
/// Toujours disponible, y compris connecté : une clé se révoque, un projet
/// change. Sans ce chemin, des identifiants enregistrés ne pouvaient plus être
/// remplacés depuis le TUI — `c` se contente de rejouer ceux qui sont là.
fn configure_provider(app: &mut App) {
    let Some(info) = usable_provider(app) else { return };

    // Aucun compte désigné : celui du curseur si le focus y est descendu,
    // sinon le premier — il y en a toujours au moins un, `default`.
    let name = app
        .selected_account()
        .map(|a| a.name)
        .or_else(|| app.provider_accounts().first().map(|a| a.name.clone()))
        .unwrap_or_else(|| fleetforge_providers::DEFAULT_ACCOUNT.to_string());

    let saved = app
        .hub
        .saved_credentials(&fleetforge_providers::AccountId::new(info.kind, &name));
    let form = CredentialsForm::new(&info, &name, saved.as_ref());
    app.overlay = Some(Overlay::Credentials(Box::new(form)));
}

/// `n` : renommer le compte désigné. Ses identifiants et sa session le suivent ;
/// rien n'est recréé, contrairement à un nom changé dans le formulaire.
fn request_rename(app: &mut App) {
    if app.screen != Screen::Providers {
        return;
    }
    let Some(account) = app.selected_account_id() else {
        app.status = "aucun compte désigné — ↵ pour descendre dans la liste".into();
        return;
    };
    if !app.hub.has_credentials(&account) {
        app.status = format!("{account} : aucun identifiant enregistré, rien à renommer");
        return;
    }
    app.overlay = Some(Overlay::Rename(RenameForm {
        input: account.name.clone(),
        account,
    }));
}

fn handle_rename(app: &mut App, key: KeyEvent, mut form: RenameForm, tx: &UnboundedSender<Msg>) {
    match key.code {
        KeyCode::Esc => {
            app.overlay = None;
            return;
        }
        KeyCode::Backspace => {
            form.input.pop();
        }
        KeyCode::Char(c) => form.input.push(c),
        KeyCode::Enter => {
            let hub = app.hub.clone();
            let tx = tx.clone();
            let account = form.account.clone();
            let wanted = form.input.clone();
            let kind = account.provider;
            app.status = format!("renommage de {account}…");
            // La liste des comptes va changer : le focus désignait l'ancien nom.
            app.reset_focus();
            app.overlay = None;

            tokio::spawn(async move {
                match hub.rename(&account, &wanted).await {
                    Ok(renamed) => {
                        let _ = tx.send(Msg::Status(format!("{account} renommé en {}", renamed.name)));
                    }
                    Err(e) => {
                        let _ = tx.send(Msg::Error(e.to_string()));
                    }
                }
                let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
                // Les instances déjà listées portent l'ancien nom de compte.
                let (instances, _) = hub.list_instances_everywhere(kind).await;
                let _ = tx.send(Msg::InstancesLoaded(kind, instances));
                let _ = tx.send(Msg::ReloadControls);
            });
            return;
        }
        _ => {}
    }
    app.overlay = Some(Overlay::Rename(form));
}

/// Ouvre le formulaire pour un compte NEUF : le nom est à saisir.
///
/// C'est par là qu'on ajoute une seconde tenancy. Sans ce chemin, configurer
/// l'hébergeur ne pouvait que remplacer le compte existant.
fn add_account(app: &mut App) {
    let Some(info) = usable_provider(app) else { return };
    let form = CredentialsForm::new(&info, "", None);
    app.overlay = Some(Overlay::Credentials(Box::new(form)));
}

fn handle_session_menu(
    app: &mut App,
    key: KeyEvent,
    mut menu: SessionMenu,
    tx: &UnboundedSender<Msg>,
) {
    match key.code {
        KeyCode::Esc => {
            app.overlay = None;
            return;
        }
        KeyCode::Char('j') | KeyCode::Down => menu.move_cursor(1),
        KeyCode::Char('k') | KeyCode::Up => menu.move_cursor(-1),
        KeyCode::Enter => {
            if let Some(entry) = menu.selected().cloned() {
                app.overlay = None;
                launch_session_action(app, menu.account.clone(), entry, tx);
                return;
            }
        }
        _ => {}
    }
    app.overlay = Some(Overlay::SessionMenu(menu));
}

/// Lance une commande de session et rend la main tout de suite.
///
/// `authenticate` attend que l'opérateur se connecte dans son navigateur : la
/// tâche peut donc vivre une minute. L'interface reste utilisable pendant ce
/// temps, et le résultat arrive par message.
fn launch_session_action(
    app: &mut App,
    account: fleetforge_providers::AccountId,
    entry: MenuEntry,
    tx: &UnboundedSender<Msg>,
) {
    let hub = app.hub.clone();
    let tx = tx.clone();
    app.status = format!("{} sur {account}…", entry.label);

    tokio::spawn(async move {
        match hub.run_session_action(&account, &entry.name).await {
            // Le compte rendu est AFFICHÉ : un renouvellement peut aboutir
            // sans rien changer d'utile, et un message muet laisserait croire
            // que c'est réglé.
            Ok(message) => {
                let _ = tx.send(Msg::Status(format!("{account} : {message}")));
                // Une session neuve ne sert à rien tant que la connexion
                // porte l'ancienne : on la rouvre dans la foulée.
                let _ = hub.reconnect(&account).await;
                let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
                let (instances, _) = hub.list_instances_everywhere(account.provider).await;
                let _ = tx.send(Msg::InstancesLoaded(account.provider, instances));
            }
            Err(e) => {
                let _ = tx.send(Msg::Error(format!("{account} : {e}")));
            }
        }
    });
}

/// Exécute la commande de session du compte désigné.
///
/// Les commandes sont DÉCLARÉES par le provider, et seulement celles que
/// l'application mène à bien seule — `oci session authenticate` en est exclu,
/// il attend un navigateur et quelqu'un devant.
///
/// Une seule aujourd'hui (le renouvellement OCI) : elle est donc lancée
/// directement plutôt que derrière un menu qui n'offrirait qu'un choix.
fn run_session_action(app: &mut App, tx: &UnboundedSender<Msg>) {
    if app.screen != Screen::Providers {
        return;
    }
    let Some(account) = app.selected_account_id() else {
        app.status = "aucun compte désigné — ↵ pour descendre dans la liste".into();
        return;
    };
    let Some(status) = app.selected_account() else { return };

    let entries: Vec<MenuEntry> = status
        .session_actions
        .iter()
        .map(|a| MenuEntry {
            name: a.name.clone(),
            label: a.label.clone(),
            hint: a.hint.clone(),
        })
        .collect();

    if entries.is_empty() {
        // Le compte n'a pas encore été CONSTRUIT dans cette exécution : ses
        // commandes ne sont pas connues, ce qui n'est pas la même chose que
        // « il n'y en a pas ». Le cœur le construit, au besoin en tentant la
        // connexion — dont l'échec est justement ce qui rend ces commandes
        // utiles.
        let hub = app.hub.clone();
        let tx = tx.clone();
        app.status = format!("{account} : commandes de session…");
        tokio::spawn(async move {
            let actions = hub.ensure_session_actions(&account).await;
            let _ = tx.send(Msg::SessionActions(account, actions));
            let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
        });
        return;
    }

    offer(app, account, entries, tx);
}

/// Propose les commandes rapportées : menu à partir de deux, lancement direct
/// s'il n'y en a qu'une.
pub fn offer_session_actions(
    app: &mut App,
    account: fleetforge_providers::AccountId,
    actions: Vec<fleetforge_providers::SessionAction>,
    tx: &UnboundedSender<Msg>,
) {
    let entries: Vec<MenuEntry> = actions
        .into_iter()
        .map(|a| MenuEntry { name: a.name, label: a.label, hint: a.hint })
        .collect();
    offer(app, account, entries, tx);
}

fn offer(
    app: &mut App,
    account: fleetforge_providers::AccountId,
    entries: Vec<MenuEntry>,
    tx: &UnboundedSender<Msg>,
) {
    match entries.len() {
        0 => {
            app.status =
                format!("{account} : aucune commande de session (ce compte s'authentifie par clé)")
        }
        // Un menu à un seul choix ne demande qu'une frappe de plus pour rien.
        1 => launch_session_action(app, account, entries[0].clone(), tx),
        _ => {
            app.overlay = Some(Overlay::SessionMenu(SessionMenu {
                account,
                actions: entries,
                cursor: 0,
            }))
        }
    }
}

/// Oublie le compte désigné, après confirmation : ses identifiants sont
/// effacés, pas seulement sa session.
fn forget_account(app: &mut App) {
    if app.screen != Screen::Providers {
        return;
    }
    let Some(account) = app.selected_account_id() else {
        app.status = "aucun compte désigné — ↵ pour descendre dans la liste".into();
        return;
    };

    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("oublier les identifiants de {account} ? (o/n)"),
        action: ConfirmedAction::ForgetAccount { account },
    }));
}

/// `c` : ouvre la session du compte désigné, ou de TOUS les comptes
/// enregistrés quand le focus est resté sur l'hébergeur.
fn connect_provider(app: &mut App, tx: &UnboundedSender<Msg>) {
    let Some(info) = usable_provider(app) else { return };
    let hub = app.hub.clone();
    let tx_clone = tx.clone();

    // Un compte précis est désigné.
    if let Some(account) = app.selected_account_id() {
        // Rien d'enregistré : on ouvre le formulaire au lieu de refuser.
        //
        // `reconnect` répondait « authentification refusée : aucun identifiant
        // enregistré », ce qui désigne les identifiants comme mauvais alors
        // qu'il n'y en a simplement aucun.
        if !app.hub.has_credentials(&account) {
            configure_provider(app);
            return;
        }
        app.status = format!("connexion à {account}…");
        tokio::spawn(async move {
            connect_and_list(hub, account, None, tx_clone).await;
        });
        return;
    }

    // Focus sur l'hébergeur : on rouvre tout ce qui est enregistré. C'est ce
    // qui permet d'avoir plusieurs tenancies ouvertes en une frappe.
    let kind = info.kind;
    let has_any = app
        .hub
        .accounts(kind)
        .iter()
        .any(|a| app.hub.has_credentials(a));

    if !has_any {
        configure_provider(app);
        return;
    }

    app.status = format!("connexion à {}…", info.label);
    tokio::spawn(async move {
        for (account, result) in hub.reconnect_all(kind).await {
            match result {
                Ok(()) => {
                    let _ = tx_clone.send(Msg::Status(format!("{account} connecté")));
                }
                // Un compte qui échoue ne doit pas empêcher les autres : c'est
                // toute la raison d'avoir plusieurs comptes ouverts.
                Err(e) => {
                    let _ = tx_clone.send(Msg::Error(format!("{account} : {e}")));
                }
            }
        }
        let _ = tx_clone.send(Msg::ProvidersLoaded(hub.statuses().await));
        let (instances, _) = hub.list_instances_everywhere(kind).await;
        let _ = tx_clone.send(Msg::InstancesLoaded(kind, instances));
    });
}

/// `x` : ferme la session du compte désigné, ou de tous ceux de l'hébergeur.
/// Les identifiants restent enregistrés — les effacer, c'est `X`.
fn disconnect_provider(app: &mut App, tx: &UnboundedSender<Msg>) {
    if app.screen != Screen::Providers {
        return;
    }
    let Some(status) = app.selected_provider() else { return };
    let kind = status.info.kind;
    let targets: Vec<fleetforge_providers::AccountId> = match app.selected_account_id() {
        Some(account) => vec![account],
        None => status
            .accounts
            .iter()
            .map(|a| fleetforge_providers::AccountId {
                provider: kind,
                name: a.name.clone(),
            })
            .collect(),
    };

    let hub = app.hub.clone();
    let tx = tx.clone();

    tokio::spawn(async move {
        for account in &targets {
            hub.disconnect(account).await;
        }
        let _ = tx.send(Msg::Status(match targets.as_slice() {
            [one] => format!("{one} déconnecté"),
            many => format!("{} compte(s) {kind} déconnectés", many.len()),
        }));
        let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
        // Les instances affichées venaient de sessions qu'on vient de fermer.
        let (instances, _) = hub.list_instances_everywhere(kind).await;
        let _ = tx.send(Msg::InstancesLoaded(kind, instances));
    });
}

/// Bascule d'inventaire — l'équivalent de la liste déroulante du GUI.
///
/// Sans argument, la commande énumère ce qui est disponible plutôt que
/// d'échouer : l'utilisateur qui tape `:inventory` cherche justement à savoir
/// entre quoi choisir. Le choix est écrit dans le même réglage que celui du
/// GUI, donc les deux interfaces restent sur le même parc.
fn switch_inventory(app: &mut App, wanted: Option<&str>, tx: &UnboundedSender<Msg>) {
    let available = match app.core.list_inventories() {
        Ok(list) => list,
        Err(e) => {
            app.status = format!("\u{26a0} inventaires illisibles : {e}");
            return;
        }
    };

    let Some(wanted) = wanted else {
        open_parc_picker(app);
        return;
    };

    // Sur le nom du parc OU son organisation (`:inventory web3c`).
    let found = available.iter().find(|i| {
        i.name.eq_ignore_ascii_case(wanted) || i.organization.eq_ignore_ascii_case(wanted)
    });
    let Some(found) = found else {
        let names: Vec<&str> = available.iter().map(|i| i.name.as_str()).collect();
        app.status = format!("\u{26a0} parc inconnu : {wanted} (parmi {})", names.join(", "));
        return;
    };

    if let Err(e) = app
        .core
        .set_setting(SettingKey::SelectedInventory, &found.file_path)
    {
        app.status = format!("\u{26a0} choix non enregistr\u{e9} : {e}");
        return;
    }

    app.inventory_path = found.file_path.clone();
    app.organization = found.organization.clone();
    // Le parc change entièrement : les marques et le filtre portaient sur des
    // hôtes de l'ancien inventaire, les garder déploierait sur des noms qui
    // n'existent plus ici.
    app.clear_marks();
    app.scope.clear();
    app.go(Screen::Servers);
    app.status = format!("inventaire : {}", found.name);
    app.loading = true;
    crate::reload_all(app, tx.clone());
}

fn run_command(app: &mut App, input: &str, tx: &UnboundedSender<Msg>) {
    let mut parts = input.split_whitespace();
    let Some(command) = parts.next() else { return };

    match command {
        // Liste à plat : la palette saute le fil d'Ariane.
        "servers" | "hosts" | "services" => {
            app.scope.clear();
            app.go(match command {
                "servers" => Screen::Servers,
                "hosts" => Screen::Hosts,
                _ => Screen::Services,
            });
        }
        "roles" => app.go(Screen::Roles),
        "playbooks" => app.go(Screen::Playbooks),
        "runs" => app.go(Screen::Runs),
        "diagnostics" => app.go(Screen::Diagnostics),
        "providers" => app.go(Screen::Providers),
        "reload" => {
            app.loading = true;
            crate::reload_all(app, tx.clone());
        }
        "clear-marks" => app.clear_marks(),
        "inventory" => switch_inventory(app, parts.next(), tx),
        "exempt" => edit_exemption(app, parts.next(), true, tx),
        "unexempt" => edit_exemption(app, parts.next(), false, tx),
        "apply-alerts" => request_apply_alerts(app),
        "connect" => connect_provider(app, tx),
        "disconnect" => disconnect_provider(app, tx),
        "quit" | "q" => app.should_quit = true,
        other => app.status = format!("⚠ commande inconnue : {other}"),
    }
}

/// `:exempt <alerte>` / `:unexempt <alerte>` sur l'hôte courant
/// (`alert_exclude` dans l'inventaire). Effet au prochain `:apply-alerts`.
fn edit_exemption(app: &mut App, alert: Option<&str>, add: bool, tx: &UnboundedSender<Msg>) {
    if app.screen != Screen::Hosts {
        app.status = "sélectionner un hôte (Parc › Hôtes) pour gérer ses exemptions".into();
        return;
    }
    let Some(host) = app.visible_hosts().get(app.cursor()).map(|h| (*h).clone()) else { return };
    let Some(alert) = alert else {
        app.status = format!(
            ":{} <alerte> — exemptions de {} : {}",
            if add { "exempt" } else { "unexempt" },
            host.name,
            if host.alert_exclude.is_empty() { "aucune".to_string() } else { host.alert_exclude.join(", ") }
        );
        return;
    };
    let exempt = host.alert_exclude.iter().any(|a| a == alert);
    if add && exempt {
        app.status = format!("{} est déjà exempté de {alert}", host.name);
    } else if !add && !exempt {
        app.status = format!("{} n'est pas exempté de {alert}", host.name);
    } else {
        toggle_exemption(app, &host.name, alert, tx);
    }
}

/// Bascule l'exemption de `alert` sur `host` : la pose si absente, la retire
/// sinon. Partagé par `:exempt`, `:unexempt` et le sélecteur de `e`.
fn toggle_exemption(app: &mut App, host: &str, alert: &str, tx: &UnboundedSender<Msg>) {
    let Some(current) = app
        .fleet
        .as_ref()
        .and_then(|f| f.host(host))
        .map(|h| h.alert_exclude.clone())
    else {
        return;
    };
    let mut next = current.clone();
    let added = !next.iter().any(|a| a == alert);
    if added {
        next.push(alert.to_string());
    } else {
        next.retain(|a| a != alert);
    }
    match app.core.set_alert_exclusions(&app.inventory_path, host, &next) {
        Ok(()) => {
            app.status = format!(
                "{host} : {alert} {} — :apply-alerts pour l'appliquer",
                if added { "exemptée" } else { "réactivée" }
            );
            app.loading = true;
            crate::reload_all(app, tx.clone());
        }
        Err(e) => app.status = format!("\u{26a0} {e}"),
    }
}

const APPLY_ALERTS_PLAYBOOK: &str = "update-prometheus-alerts";

fn request_apply_alerts(app: &mut App) {
    let Some(playbook) = app.playbooks.iter().find(|p| p.name == APPLY_ALERTS_PLAYBOOK) else {
        app.status = format!("\u{26a0} playbook {APPLY_ALERTS_PLAYBOOK}.yml introuvable");
        return;
    };
    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("Rendre les règles d'alerte du parc ({APPLY_ALERTS_PLAYBOOK}.yml) ? (o/n)"),
        action: ConfirmedAction::RunPlaybook {
            label: playbook.label.clone(),
            path: playbook.path.clone(),
            hosts: Vec::new(),
        },
    }));
}

fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
