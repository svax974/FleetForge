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
    App, Confirm, ConfirmedAction, CredentialsForm, MenuEntry, Msg, Overlay, ProviderFocus,
    Screen, SessionMenu,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use fleetforge_core::deploy::DeployRequest;
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
                let hub = app.hub.clone();
                let tx = tx.clone();
                app.status = format!("connexion à {account}…");

                tokio::spawn(async move {
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
        // efface d'abord le filtre, puis les marques.
        KeyCode::Esc => {
            if app.screen == Screen::Providers && app.focus_shallower() {
                // Remonté d'un niveau dans l'arborescence des comptes.
            } else if !app.filter.is_empty() {
                app.filter.clear();
                app.set_cursor(app.cursor());
            } else {
                app.clear_marks();
            }
        }

        KeyCode::Tab => {
            let next = app.screen.next();
            app.go(next);
        }
        KeyCode::BackTab => {
            let prev = app.screen.previous();
            app.go(prev);
        }
        KeyCode::Char(c @ '1'..='9') => {
            if let Some(screen) = Screen::from_digit(c) {
                app.go(screen);
            }
        }

        KeyCode::Char('j') | KeyCode::Down => move_down(app, 1),
        KeyCode::Char('k') | KeyCode::Up => move_down(app, -1),
        KeyCode::PageDown => app.move_cursor(10),
        KeyCode::PageUp => app.move_cursor(-10),
        KeyCode::Char('g') | KeyCode::Home => app.cursor_home(),
        KeyCode::Char('G') | KeyCode::End => app.cursor_end(),

        KeyCode::Char(' ') => app.toggle_mark(),

        KeyCode::Char('r') => {
            app.loading = true;
            app.status = "rechargement…".into();
            crate::reload_all(app, tx.clone());
        }

        KeyCode::Enter => drill_in(app, tx),
        KeyCode::Char('d') => request_deploy(app),
        KeyCode::Char('c') => connect_provider(app, tx),
        KeyCode::Char('C') => configure_provider(app),
        KeyCode::Char('a') => add_account(app),
        KeyCode::Char('x') => disconnect_provider(app, tx),
        // Majuscule, et derrière confirmation : `x` ferme une session, `X`
        // efface des identifiants. La distinction doit se payer d'une touche
        // plus difficile à atteindre par accident.
        KeyCode::Char('X') => forget_account(app),
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
    if !matches!(app.screen, Screen::Providers | Screen::Servers | Screen::Hosts) {
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
        Screen::Inventories => {
            let wanted = app
                .visible_inventories()
                .get(app.cursor())
                .map(|i| i.name.clone());
            if let Some(name) = wanted {
                switch_inventory(app, Some(&name), tx);
                app.go(Screen::Servers);
            }
        }
        // Depuis une machine, on va voir ses hôtes — filtrés sur son adresse,
        // ce qui reproduit le « clic pour ouvrir » du GUI.
        Screen::Servers => {
            if let Some(key) = app.selected_server_key() {
                app.go(Screen::Hosts);
                app.filter = key.address.clone();
                app.cursor_home();
            }
        }
        Screen::Hosts => {
            if let Some(name) = app.selected_host_name() {
                app.go(Screen::Services);
                app.filter = name;
                app.cursor_home();
            }
        }
        Screen::Diagnostics => {
            // Aller à l'élément que le constat désigne : un diagnostic sans
            // chemin vers son sujet oblige à le chercher à la main.
            use fleetforge_core::diagnostics::Subject;
            let subject = app
                .visible_findings()
                .get(app.cursor())
                .map(|f| f.subject.clone());
            match subject {
                Some(Subject::Host(name)) => {
                    app.go(Screen::Hosts);
                    app.filter = name;
                    app.cursor_home();
                }
                Some(Subject::Server(id)) => {
                    app.go(Screen::Servers);
                    // La clé affichée peut porter un port ; l'adresse suffit.
                    app.filter = id.split(':').next().unwrap_or(&id).to_string();
                    app.cursor_home();
                }
                Some(Subject::RoleFamily(family)) => {
                    app.go(Screen::Roles);
                    app.filter = family;
                    app.cursor_home();
                }
                _ => {}
            }
        }
        // Instances déjà chargées : ↵ descend dedans pour pouvoir agir sur
        // l'une d'elles. Sinon il connecte, ce qui les charge.
        // ↵ descend d'un niveau : hébergeur → comptes → instances. Au plus
        // bas, ou quand il n'y a rien où descendre, il connecte — ce qui est
        // précisément ce qui fera apparaître le niveau suivant.
        Screen::Providers => {
            if !app.focus_deeper() {
                connect_provider(app, tx);
            }
        }
        _ => {}
    }
}

fn request_deploy(app: &mut App) {
    if app.screen != Screen::Roles {
        app.status = "sélectionner un rôle (écran 4) pour déployer".into();
        return;
    }
    let Some(role) = app.selected_role_name() else { return };
    let hosts = app.target_hosts();

    if hosts.is_empty() {
        // Refuser tôt et dire pourquoi : le cœur refuserait aussi, mais après
        // avoir laissé croire que le déploiement partait.
        app.status = "aucun hôte ciblé — marquer des hôtes avec espace".into();
        return;
    }

    app.overlay = Some(Overlay::Confirm(Confirm {
        prompt: format!("Déployer `{role}` sur {} hôte(s) : {} ?", hosts.len(), hosts.join(", ")),
        action: ConfirmedAction::Deploy { role, hosts },
    }));
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
        let names: Vec<&str> = available.iter().map(|i| i.name.as_str()).collect();
        app.status = if names.is_empty() {
            "aucun inventaire — renseigner le chemin des inventaires".to_string()
        } else {
            format!(":inventory <parc> parmi {}", names.join(", "))
        };
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
    app.filter.clear();
    app.status = format!("inventaire : {}", found.name);
    app.loading = true;
    crate::reload_all(app, tx.clone());
}

fn run_command(app: &mut App, input: &str, tx: &UnboundedSender<Msg>) {
    let mut parts = input.split_whitespace();
    let Some(command) = parts.next() else { return };

    match command {
        "servers" => app.go(Screen::Servers),
        "hosts" => app.go(Screen::Hosts),
        "services" => app.go(Screen::Services),
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
        "connect" => connect_provider(app, tx),
        "disconnect" => disconnect_provider(app, tx),
        "quit" | "q" => app.should_quit = true,
        other => app.status = format!("⚠ commande inconnue : {other}"),
    }
}

fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
