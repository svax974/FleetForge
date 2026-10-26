/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Rendu.
//!
//! Disposition constante : en-tête, corps en deux panneaux (liste à gauche,
//! détail à droite), barre d'aide. Le détail suit la sélection — c'est
//! l'équivalent clavier du survol dans le GUI.

use crate::app::{
    ActionMenu, App, CredentialsForm, Overlay, Picker, ProviderFocus, RenameForm, Screen, Scope,
    Section, SessionMenu,
};
use crate::theme::*;
use fleetforge_core::model::Health;
use fleetforge_core::style::Tone;
use fleetforge_providers::PowerState;
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_body(frame, app, chunks[1]);
    draw_footer(frame, app, chunks[2]);

    match &app.overlay {
        Some(Overlay::Help) => draw_help(frame),
        Some(Overlay::Palette) => draw_palette(frame, app),
        Some(Overlay::Filter) => draw_filter(frame, app),
        Some(Overlay::Confirm(c)) => draw_confirm(frame, &c.prompt),
        Some(Overlay::Credentials(form)) => draw_credentials(frame, form),
        Some(Overlay::SessionMenu(menu)) => draw_session_menu(frame, menu),
        Some(Overlay::Picker(picker)) => draw_picker(frame, picker),
        Some(Overlay::Actions(menu)) => draw_actions(frame, menu),
        Some(Overlay::Message(text)) => draw_message(frame, text),
        Some(Overlay::Rename(form)) => draw_rename(frame, form),
        None => {}
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(area);

    let mut left = vec![
        Span::styled(" infra ", title_style()),
        Span::styled("│ ", dim_style()),
    ];

    // Sections : le numéro est le raccourci, montré plutôt qu'à retenir.
    for section in Section::ALL {
        let active = section == app.section();
        left.push(Span::styled(
            format!("{}", section.index() + 1),
            if active { title_style() } else { dim_style() },
        ));
        left.push(Span::styled(
            format!(" {} ", section.title()),
            if active {
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
            } else {
                dim_style()
            },
        ));
    }

    let (errors, warnings) = app.finding_counts();
    let mut right: Vec<Span> = Vec::new();
    if let Some(fleet) = &app.fleet {
        right.push(Span::styled(
            format!("{} srv · {} hôtes ", fleet.servers.len(), fleet.hosts.len()),
            dim_style(),
        ));
    }
    if errors > 0 {
        right.push(Span::styled(format!("· {errors} ✖ "), tone_style(Tone::Danger)));
    }
    if warnings > 0 {
        right.push(Span::styled(format!("· {warnings} ▲ "), tone_style(Tone::Warn)));
    }

    let right_width: usize = right.iter().map(|s| s.content.chars().count()).sum();
    let left_width: usize = left.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(left_width + right_width);

    let mut spans = left;
    spans.push(Span::raw(" ".repeat(pad)));
    spans.extend(right);

    frame.render_widget(Paragraph::new(Line::from(spans)), rows[0]);
    frame.render_widget(Paragraph::new(Line::from(breadcrumb(app))), rows[1]);
}

/// Où l'on est : le parc, puis chaque cran de la descente, puis la liste.
///
/// C'est la seule trace de ce chemin — sans elle, `⎋` remonte vers un endroit
/// qu'on ne voit pas.
fn breadcrumb(app: &App) -> Vec<Span<'static>> {
    let sep = || Span::styled(" › ", dim_style());
    let current = |text: &str| {
        Span::styled(text.to_string(), Style::default().fg(TEXT).add_modifier(Modifier::BOLD))
    };
    let mut out = vec![Span::raw(" ")];

    match app.section() {
        Section::Parc => {
            if app.organization.is_empty() {
                out.push(Span::styled("aucun parc — P pour en choisir un", tone_style(Tone::Warn)));
                return out;
            }
            out.push(Span::styled(app.organization.clone(), title_style()));
            for scope in &app.scope {
                out.push(sep());
                out.push(Span::styled(
                    match scope {
                        Scope::Machine(key) => key.to_string(),
                        Scope::Host(name) => name.clone(),
                    },
                    text_style(),
                ));
            }
            out.push(sep());
            out.push(current(app.screen.title()));
        }
        Section::Ansible => {
            out.push(Span::styled("Ansible", title_style()));
            out.push(sep());
            for (i, screen) in [Screen::Roles, Screen::Playbooks].into_iter().enumerate() {
                if i > 0 {
                    out.push(Span::styled(" │ ", dim_style()));
                }
                if screen == app.screen {
                    out.push(current(screen.title()));
                } else {
                    out.push(Span::styled(screen.title().to_string(), dim_style()));
                }
            }
            out.push(Span::styled("   ← → pour changer", dim_style()));
        }
        Section::Providers => {
            out.push(Span::styled("Providers", title_style()));
            if let Some(provider) = app.selected_provider() {
                out.push(sep());
                out.push(Span::styled(provider.info.label.clone(), text_style()));
                if let Some(account) = app.selected_account().filter(|_| app.focus != ProviderFocus::Providers) {
                    out.push(sep());
                    out.push(Span::styled(account.name, text_style()));
                }
                if app.focus.instance().is_some() {
                    out.push(sep());
                    out.push(current("Instances"));
                }
            }
        }
        Section::Runs | Section::Diagnostics => {
            out.push(current(app.screen.title()));
        }
    }
    out
}

/// Complément du titre de liste. Dans le parc, la liste est bornée par le fil
/// d'Ariane : le dire dans le titre évite de croire qu'elle est complète.
fn list_hint(app: &App) -> Option<String> {
    (!app.scope.is_empty() && app.section() == Section::Parc)
        .then(|| "bornée par le fil d'Ariane".to_string())
}

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    // Deux tiers / un tiers : la liste porte l'essentiel, le détail complète.
    let cols = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);

    let (items, detail) = match app.screen {
        Screen::Servers => (servers_rows(app), server_detail(app)),
        Screen::Hosts => (hosts_rows(app), host_detail(app)),
        Screen::Services => (services_rows(app), services_detail(app)),
        Screen::Roles => (roles_rows(app), role_detail(app)),
        Screen::Playbooks => (playbooks_rows(app), playbook_detail(app)),
        Screen::Runs => (runs_rows(app), run_detail(app, cols[1].height)),
        Screen::Diagnostics => (diagnostics_rows(app), finding_detail(app)),
        Screen::Providers => (providers_rows(app), provider_detail(app)),
    };

    let mut title = format!(" {} ", app.screen.title());
    if !app.filter.is_empty() {
        title = format!(" {} · filtre {} ", app.screen.title(), app.filter);
    }
    if !app.marked_hosts.is_empty() {
        title = format!("{title}· {} marqué(s) ", app.marked_hosts.len());
    }
    if let Some(label) = &list_hint(app) {
        title = format!("{title}· {label} ");
    }

    // Sur Providers, `↵` fait passer le curseur dans le panneau de DROITE :
    // ce sont les comptes, puis les instances, que les touches visent alors.
    // Rien ne le montrait — les deux cadres gardaient la même bordure et le
    // même surlignage — si bien qu'on agissait sur la droite en regardant la
    // gauche. Le focus se déplace donc aussi à l'écran.
    let detail_focused =
        app.screen == Screen::Providers && app.focus != ProviderFocus::Providers;

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(border_style(!detail_focused))
                .title(Span::styled(
                    title,
                    if detail_focused { dim_style() } else { title_style() },
                )),
        )
        .highlight_style(if detail_focused {
            selected_elsewhere_style()
        } else {
            selected_style()
        });

    let mut state = ListState::default();
    if app.row_count() > 0 {
        state.select(Some(app.cursor()));
    }
    frame.render_stateful_widget(list, cols[0], &mut state);

    // Le titre nomme le NIVEAU : « Comptes » et « Instances » disent où l'on
    // est descendu, ce que « Détail » ne disait pas.
    let detail_title = match (detail_focused, app.focus) {
        (true, ProviderFocus::Instances { .. }) => " Instances ",
        (true, _) => " Comptes ",
        _ => " Détail ",
    };

    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style(detail_focused))
        .title(Span::styled(
            detail_title,
            if detail_focused { title_style() } else { dim_style() },
        ));

    frame.render_widget(
        Paragraph::new(detail)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        cols[1],
    );
}

/// Où un raccourci agit.
///
/// Sert au CONTRÔLE, pas au rendu : la barre du bas est composée par
/// `screen_hints`, dont le libellé dépend du contexte. Cette table dit
/// seulement quelle touche existe et sur quels écrans — de quoi vérifier que
/// la barre les annonce toutes, et n'en annonce aucune de morte.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScope {
    /// Annoncé sur tous les écrans, en fin de ligne.
    Everywhere,
    /// Annoncé sur ces écrans seulement.
    On(&'static [Screen]),
    /// Documenté par `?` uniquement. Les déplacements sont là : les annoncer
    /// partout remplirait la ligne de `j k g G ⇞ ⇟ ⇥` au détriment des touches
    /// qui AGISSENT, qui sont celles qu'on ne devine pas.
    HelpOnly,
}

/// Toutes les touches que `handle_normal` traite, et où elles agissent.
///
/// Un test relit `input.rs` et échoue si une touche y est liée sans figurer
/// ici, ou si une touche figure ici sans y être liée. Une barre qui annonce
/// des raccourcis incomplets est pire qu'une barre vide : on croit avoir fait
/// le tour.
#[cfg(test)]
pub const KEYS: &[(&str, KeyScope)] = &[
    ("q", KeyScope::Everywhere),
    ("?", KeyScope::Everywhere),
    ("/", KeyScope::Everywhere),
    ("f", KeyScope::Everywhere),
    ("r", KeyScope::Everywhere),
    ("P", KeyScope::Everywhere),
    // Alias de `/` pour les doigts venus de vim : l'annoncer doublerait
    // l'entrée sans rien apprendre.
    (":", KeyScope::HelpOnly),
    // Sur Services, `↵` ouvre les mêmes actions que `espace` : une seule
    // des deux est annoncée.
    ("↵", KeyScope::On(&[
        Screen::Servers,
        Screen::Hosts,
        Screen::Roles,
        Screen::Playbooks,
        Screen::Diagnostics,
        Screen::Providers,
    ])),
    ("espace", KeyScope::On(&[Screen::Servers, Screen::Hosts, Screen::Services])),
    ("m", KeyScope::On(&[Screen::Servers, Screen::Hosts])),
    ("d", KeyScope::On(&[Screen::Servers, Screen::Hosts, Screen::Services])),
    ("p", KeyScope::On(&[Screen::Servers, Screen::Hosts, Screen::Services])),
    ("e", KeyScope::On(&[Screen::Hosts])),
    // Ailleurs, `⎋` efface le filtre ou les marques — qu'on vient de poser
    // soi-même. Dans le parc et sur Providers il REMONTE d'un niveau, ce qui
    // ne se devine pas.
    ("⎋", KeyScope::On(&[Screen::Hosts, Screen::Services, Screen::Providers])),
    ("c", KeyScope::On(&[Screen::Providers])),
    ("C", KeyScope::On(&[Screen::Providers])),
    ("a", KeyScope::On(&[Screen::Providers])),
    ("n", KeyScope::On(&[Screen::Providers])),
    ("x", KeyScope::On(&[Screen::Services, Screen::Providers])),
    ("X", KeyScope::On(&[Screen::Services, Screen::Providers])),
    ("s", KeyScope::On(&[Screen::Providers])),
    ("S", KeyScope::On(&[Screen::Providers, Screen::Servers, Screen::Hosts, Screen::Services])),
    ("A", KeyScope::On(&[Screen::Providers, Screen::Servers, Screen::Hosts, Screen::Services])),
    ("R", KeyScope::On(&[Screen::Providers, Screen::Servers, Screen::Hosts, Screen::Services])),
    ("j", KeyScope::HelpOnly),
    ("k", KeyScope::HelpOnly),
    ("g", KeyScope::HelpOnly),
    ("G", KeyScope::HelpOnly),
    ("↑", KeyScope::HelpOnly),
    ("↓", KeyScope::HelpOnly),
    ("←", KeyScope::HelpOnly),
    ("→", KeyScope::HelpOnly),
    ("⇞", KeyScope::HelpOnly),
    ("⇟", KeyScope::HelpOnly),
    ("⇥", KeyScope::HelpOnly),
    ("⇧⇥", KeyScope::HelpOnly),
    ("1-5", KeyScope::HelpOnly),
];

/// Ce que la barre du bas doit savoir de l'ÉLÉMENT désigné.
///
/// Annoncer « A arrêter » sur une machine déjà éteinte, ou « x déconnecter »
/// sur un compte qui ne l'a jamais été, apprend une touche qui refusera. Le
/// même raisonnement que le GUI, qui masque ces boutons plutôt que de les
/// rendre cliquables pour rien — sauf qu'ici il faut aussi que la ligne reste
/// courte, et une entrée qui ne sert pas prend la place d'une qui sert.
///
/// Structure plate et sans emprunt : elle se construit dans les tests sans
/// monter un `App` complet, ce qui suppose un cœur et une connexion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HintContext {
    /// Machines / Hôtes : la ligne désignée est marquée.
    pub marked: bool,
    /// Il y a quelque chose sous le curseur.
    pub has_row: bool,
    /// Services : le catalogue offre un rôle `-remove` / `-purge` au service.
    pub can_remove: bool,
    pub can_purge: bool,
    /// Diagnostics : le constat désigné mène à un écran. Un constat de parc
    /// n'a pas de sujet où aller.
    pub navigable: bool,
    /// Providers, niveau hébergeur : au moins un compte connecté / enregistré.
    pub any_connected: bool,
    pub any_saved: bool,
    /// Providers : l'hébergeur désigné a des comptes où descendre.
    pub has_accounts: bool,
    /// Providers : il n'y en a qu'UN, donc il est désigné sans descendre et
    /// les touches de compte agissent depuis le niveau hébergeur.
    pub single_account: bool,
    /// Providers, niveau compte.
    pub account_connected: bool,
    pub account_saved: bool,
    /// Le compte a des instances chargées, donc un niveau au-dessous.
    pub has_instances: bool,
    /// Providers, niveau instance — capacité de l'hébergeur ET état de la
    /// machine, comme les boutons du GUI.
    pub can_start: bool,
    pub can_stop: bool,
    pub can_reboot: bool,
}

impl HintContext {
    /// Lit l'état courant. Tout ce qui est absent laisse le drapeau à `false`,
    /// donc l'entrée non annoncée : mieux vaut taire une action possible que
    /// d'en promettre une qui refusera.
    pub fn of(app: &App) -> Self {
        let mut ctx = HintContext {
            has_row: app.row_count() > 0,
            ..Default::default()
        };

        match app.screen {
            Screen::Servers | Screen::Hosts | Screen::Services => {
                ctx.marked = match app.screen {
                    Screen::Servers => {
                        let hosts = app
                            .visible_servers()
                            .get(app.cursor())
                            .map(|s| s.hosts.clone())
                            .unwrap_or_default();
                        !hosts.is_empty() && hosts.iter().all(|h| app.marked_hosts.contains(h))
                    }
                    Screen::Services => false,
                    _ => app
                        .selected_host_name()
                        .is_some_and(|n| app.marked_hosts.contains(&n)),
                };
                // Rien tant que l'hébergeur n'est pas connecté : la machine
                // n'est alors rapprochée d'aucune instance, et les touches
                // d'alimentation n'ont rien à viser.
                if let Some(power) = app.power_state() {
                    ctx.can_start = power.can_start;
                    ctx.can_stop = power.can_stop;
                    ctx.can_reboot = power.can_reboot;
                }
                if app.screen == Screen::Services {
                    if let Some(service) = app.visible_services().get(app.cursor()) {
                        let name = &service.service_name;
                        ctx.can_remove =
                            fleetforge_core::resolve_role(&app.roles, name, "remove").is_some();
                        ctx.can_purge =
                            fleetforge_core::resolve_role(&app.roles, name, "purge").is_some();
                    }
                }
            }
            Screen::Diagnostics => {
                use fleetforge_core::diagnostics::Subject;
                ctx.navigable = app.visible_findings().get(app.cursor()).is_some_and(|f| {
                    matches!(
                        f.subject,
                        Subject::Host(_) | Subject::Server(_) | Subject::RoleFamily(_)
                    )
                });
            }
            Screen::Providers => {
                if let Some(status) = app.selected_provider() {
                    ctx.any_connected = status.accounts.iter().any(|a| a.connected);
                    ctx.any_saved = status.accounts.iter().any(|a| a.has_saved_credentials);
                    ctx.has_accounts = !status.accounts.is_empty();
                    ctx.single_account = status.accounts.len() == 1;

                    if let Some(account) = app.selected_account() {
                        ctx.account_connected = account.connected;
                        ctx.account_saved = account.has_saved_credentials;
                    }
                    ctx.has_instances = !app.account_instances().is_empty();

                    let caps = status.info.capabilities;
                    if let Some(instance) = app.selected_instance() {
                        // `stop` est l'arrêt BRUTAL et `stop_graceful` l'arrêt
                        // propre : plusieurs hébergeurs n'ont que l'un des
                        // deux. Ne tester que le premier effacerait l'entrée
                        // chez GCP, qui ne sait que l'autre.
                        ctx.can_start = caps.start && instance.state != PowerState::Running;
                        ctx.can_stop = (caps.stop || caps.stop_graceful)
                            && instance.state != PowerState::Stopped;
                        ctx.can_reboot = caps.reboot || caps.reboot_graceful;
                    }
                }
            }
            _ => {}
        }
        ctx
    }
}

/// Raccourcis propres à l'écran courant, dans l'ordre d'affichage.
///
/// Le libellé dépend du CONTEXTE : `↵` bascule de parc sur Inventaires et
/// descend dans les comptes sur Providers. C'est pourquoi il n'est pas porté
/// par `KEYS`, qui ne dit que l'existence.
pub fn screen_hints(
    screen: Screen,
    focus: ProviderFocus,
    ctx: HintContext,
) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let mut add = |key: &'static str, what: &str| out.push((key, what.to_string()));

    match screen {
        Screen::Servers | Screen::Hosts | Screen::Services => {
            if ctx.has_row {
                match screen {
                    Screen::Servers => add("↵", "hôtes"),
                    Screen::Hosts => add("↵", "services"),
                    _ => {}
                }
                add("espace", "actions");
                if screen != Screen::Services {
                    add("m", if ctx.marked { "démarquer" } else { "marquer" });
                }
                add("d", "déployer");
                add("p", "playbook");
                if screen == Screen::Hosts {
                    add("e", "exemptions");
                }
                if screen == Screen::Services && ctx.can_remove {
                    add("x", "retirer");
                }
                if screen == Screen::Services && ctx.can_purge {
                    add("X", "purger");
                }
                // Piloter la machine là où on la regarde. Absent tant qu'elle
                // n'est rapprochée d'aucune instance — hébergeur non connecté,
                // machine sans API, ou adresse revendiquée par deux comptes.
                if ctx.can_start {
                    add("S", "démarrer");
                }
                if ctx.can_stop {
                    add("A", "arrêter");
                }
                if ctx.can_reboot {
                    add("R", "redémarrer");
                }
            }
            // Dans le parc `⎋` remonte toujours : d'un cran, ou vers Machines
            // quand la liste a été ouverte à plat par la palette.
            if screen != Screen::Servers {
                add("⎋", "remonter");
            }
        }
        Screen::Roles => {
            if ctx.has_row {
                add("↵", "déployer sur…");
            }
        }
        Screen::Playbooks => {
            if ctx.has_row {
                add("↵", "lancer");
            }
        }
        Screen::Diagnostics => {
            if ctx.navigable {
                add("↵", "aller au sujet");
            }
        }
        Screen::Runs => {}
        Screen::Providers => match focus {
            ProviderFocus::Providers => {
                // Avec un seul compte, ce niveau EST le niveau compte : les
                // touches y agissent déjà, la ligne doit donc les annoncer.
                if ctx.single_account {
                    if ctx.has_instances {
                        add("↵", "instances");
                    }
                    if ctx.account_saved && !ctx.account_connected {
                        add("c", "connecter");
                    }
                    add("C", "identifiants");
                    if ctx.account_saved {
                        add("s", "session");
                        add("n", "renommer");
                    }
                    if ctx.account_connected {
                        add("x", "déconnecter");
                    }
                    add("a", "ajouter un compte");
                    if ctx.account_saved {
                        add("X", "oublier");
                    }
                    return out;
                }

                if ctx.has_accounts {
                    add("↵", "comptes");
                }
                // `c` connecte TOUS les comptes enregistrés : sans identifiant
                // enregistré il n'a rien à ouvrir.
                if ctx.any_saved {
                    add("c", "tout connecter");
                }
                add("a", "ajouter un compte");
                if ctx.any_connected {
                    add("x", "déconnecter");
                }
            }
            ProviderFocus::Accounts(_) => {
                // `↵` descend s'il y a des instances, sinon il CONNECTE — ce
                // qui est précisément ce qui les fera apparaître.
                if ctx.has_instances {
                    add("↵", "instances");
                } else if ctx.account_saved && !ctx.account_connected {
                    add("↵", "connecter");
                }
                if ctx.account_saved && !ctx.account_connected {
                    add("c", "connecter");
                }
                add("C", "identifiants");
                if ctx.account_saved {
                    add("s", "session");
                    add("n", "renommer");
                }
                if ctx.account_connected {
                    add("x", "déconnecter");
                }
                if ctx.account_saved {
                    add("X", "oublier");
                }
                add("⎋", "remonter");
            }
            ProviderFocus::Instances { .. } => {
                if ctx.can_start {
                    add("S", "démarrer");
                }
                if ctx.can_stop {
                    add("A", "arrêter");
                }
                if ctx.can_reboot {
                    add("R", "redémarrer");
                }
                add("⎋", "remonter");
            }
        },
    }
    out
}

/// Raccourcis valables partout, annoncés après ceux de l'écran.
/// `? aide` n'y est pas : il est rendu à part, et jamais retiré.
const EVERYWHERE: &[(&str, &str)] = &[
    ("P", "parc"),
    ("r", "recharger"),
    ("f", "filtrer"),
    ("/", "commande"),
    ("q", "quitter"),
];

const HELP_HINT: (&str, &str) = ("?", "aide");

fn hint_text(pairs: &[(&'static str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, what)| format!("{k} {what}"))
        .collect::<Vec<_>>()
        .join("  ")
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mut right: Vec<Span> = Vec::new();
    if app.loading {
        right.push(Span::styled("chargement… ", tone_style(Tone::Info)));
    }
    let active = app.active_run_count();
    if active > 0 {
        right.push(Span::styled(
            format!("▶ {active} run(s) "),
            tone_style(Tone::Info),
        ));
    }
    if !app.status.is_empty() {
        let tone = if app.status.starts_with('⚠') { Tone::Danger } else { Tone::Ok };
        right.push(Span::styled(format!("{} ", app.status), tone_style(tone)));
    }
    let right_width: usize = right.iter().map(|s| s.content.chars().count()).sum();
    let width = area.width as usize;

    // `? aide` est réservé AVANT tout le reste : c'est lui qui redonne les
    // raccourcis qu'on n'a pas la place d'afficher, le retirer fermerait la
    // seule porte de sortie.
    let pinned = hint_text(&[(HELP_HINT.0, HELP_HINT.1.to_string())]);
    let room = width
        .saturating_sub(right_width)
        .saturating_sub(pinned.chars().count() + 3);

    let mut pairs = screen_hints(app.screen, app.focus, HintContext::of(app));
    pairs.extend(EVERYWHERE.iter().map(|(k, w)| (*k, w.to_string())));

    // Des ENTIERS sont retirés par la fin plutôt que de couper un libellé au
    // milieu : « x déconn » ne veut rien dire, alors qu'une entrée absente se
    // retrouve par `?`.
    while !pairs.is_empty() && hint_text(&pairs).chars().count() > room {
        pairs.pop();
    }
    pairs.push((HELP_HINT.0, HELP_HINT.1.to_string()));

    let hints = hint_text(&pairs);
    let mut spans = vec![Span::styled(format!(" {hints}"), dim_style())];
    let left_width = hints.chars().count() + 1;

    // Si le message déborde encore, la coupe est SIGNALÉE : tronqué en
    // silence, il se lit comme un message complet qui ne dit pas tout.
    let remaining = width.saturating_sub(left_width);
    if right_width > remaining {
        right = elide(right, remaining);
    }
    let right_width: usize = right.iter().map(|s| s.content.chars().count()).sum();

    spans.push(Span::raw(
        " ".repeat(width.saturating_sub(left_width + right_width)),
    ));
    spans.extend(right);

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Réduit une suite de fragments à `room` colonnes, en marquant la coupe.
fn elide(spans: Vec<Span<'static>>, room: usize) -> Vec<Span<'static>> {
    const MARK: &str = "…";
    if room <= MARK.chars().count() {
        return Vec::new();
    }
    let keep = room - MARK.chars().count();

    let mut out: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for span in spans {
        let len = span.content.chars().count();
        if used + len <= keep {
            used += len;
            out.push(span);
            continue;
        }
        let cut: String = span.content.chars().take(keep - used).collect();
        let style = span.style;
        out.push(Span::styled(cut, style));
        out.push(Span::styled(MARK.to_string(), style));
        return out;
    }
    out
}

// === Lignes par écran ===

fn servers_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_servers()
        .into_iter()
        .map(|s| {
            let marked = !s.hosts.is_empty() && s.hosts.iter().all(|h| app.marked_hosts.contains(h));
            let provider = s.provider.map(|p| p.as_str()).unwrap_or("?");
            let host_count = s.hosts.len();

            ListItem::new(Line::from(vec![
                Span::raw(if marked { " ▪ " } else { "   " }),
                Span::styled(health_glyph(s.health).to_string(), health_style(s.health)),
                Span::raw(" "),
                Span::styled(format!("{:<24}", s.key.to_string()), text_style()),
                Span::styled(format!("{provider:<9}"), dim_style()),
                Span::styled(
                    format!("{host_count} hôte{}", if host_count > 1 { "s" } else { "" }),
                    dim_style(),
                ),
            ]))
        })
        .collect()
}

fn hosts_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_hosts()
        .into_iter()
        .map(|h| {
            let marked = app.marked_hosts.contains(&h.name);
            let families = if h.ansible_roles.is_empty() {
                "socle".to_string()
            } else {
                h.ansible_roles.join(" ")
            };
            // Un `provider` absent est une faute, pas un blanc : il se voit.
            let (provider, provider_style) = match &h.provider {
                Some(p) => (p.clone(), dim_style()),
                None => ("provider ?".to_string(), tone_style(Tone::Danger)),
            };

            ListItem::new(Line::from(vec![
                Span::raw(if marked { " ▪ " } else { "   " }),
                Span::styled(format!("{:<22}", h.name), text_style()),
                Span::styled(format!("{:<17}", h.ansible_host), dim_style()),
                Span::styled(format!("{provider:<10}"), provider_style),
                Span::styled(families, tone_style(Tone::Info)),
            ]))
        })
        .collect()
}

fn services_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_services()
        .into_iter()
        .map(|s| {
            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(format!("{:<24}", s.service_name), text_style()),
                Span::styled(format!("{:<20}", s.server_name), dim_style()),
                Span::styled(s.last_action.clone(), tone_style(Tone::Info)),
            ]))
        })
        .collect()
}

fn roles_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_roles()
        .into_iter()
        .map(|r| {
            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(format!("{:<34}", r.name), text_style()),
                Span::styled(r.category.clone(), dim_style()),
            ]))
        })
        .collect()
}

fn playbooks_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_playbooks()
        .into_iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(format!("{:<34}", p.name), text_style()),
                Span::styled(p.category.clone(), dim_style()),
            ]))
        })
        .collect()
}

fn runs_rows(app: &App) -> Vec<ListItem<'static>> {
    use fleetforge_core::deploy::RunStatus;
    app.runs
        .iter()
        .map(|r| {
            let tone = match r.status {
                RunStatus::Running => Tone::Info,
                RunStatus::Success => Tone::Ok,
                RunStatus::Failed => Tone::Danger,
            };
            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(tone.glyph().to_string(), tone_style(tone)),
                Span::raw(" "),
                Span::styled(format!("{:<30}", r.label), text_style()),
                Span::styled(format!("{} hôte(s)", r.hosts.len()), dim_style()),
            ]))
        })
        .collect()
}

fn diagnostics_rows(app: &App) -> Vec<ListItem<'static>> {
    app.visible_findings()
        .into_iter()
        .map(|f| {
            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(severity_glyph(f.severity).to_string(), severity_style(f.severity)),
                Span::raw(" "),
                Span::styled(format!("{:<26}", f.rule), dim_style()),
                Span::styled(f.message.clone(), text_style()),
            ]))
        })
        .collect()
}

fn providers_rows(app: &App) -> Vec<ListItem<'static>> {
    app.providers
        .iter()
        .map(|p| {
            let open = p.accounts.iter().filter(|a| a.connected).count();
            let known = p.accounts.iter().filter(|a| a.has_saved_credentials).count();

            let (glyph, tone, note) = if let Some(tool) = &p.info.missing_tool {
                ("○", Tone::Warn, format!("`{tool}` absent"))
            } else if !p.info.capabilities.list {
                // `custom` : machines physiques, pas d'API. Ce n'est pas une panne.
                ("·", Tone::Unknown, "pas d'API — SSH seul".to_string())
            } else if open > 0 {
                // Le NOMBRE de comptes ouverts, pas un simple « connecté » :
                // avec plusieurs tenancies, savoir qu'une seule répond est
                // exactement ce qu'on a besoin de voir d'un coup d'œil.
                ("●", Tone::Ok, format!("{open}/{known} compte(s) connecté(s)"))
            } else if known > 0 {
                ("○", Tone::Warn, format!("{known} compte(s) enregistré(s)"))
            } else {
                ("○", Tone::Unknown, "aucun compte".to_string())
            };

            ListItem::new(Line::from(vec![
                Span::raw("   "),
                Span::styled(glyph.to_string(), tone_style(tone)),
                Span::raw(" "),
                Span::styled(format!("{:<18}", p.info.label), text_style()),
                Span::styled(note, dim_style()),
            ]))
        })
        .collect()
}

// === Panneaux de détail ===

fn kv(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<12}"), dim_style()),
        Span::styled(value, text_style()),
    ])
}

fn heading(text: String) -> Line<'static> {
    Line::from(Span::styled(text, title_style()))
}

fn server_detail(app: &App) -> Vec<Line<'static>> {
    let servers = app.visible_servers();
    let Some(server) = servers.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucune machine", dim_style()))];
    };
    let Some(fleet) = &app.fleet else { return Vec::new() };

    let mut lines = vec![
        heading(server.key.to_string()),
        Line::from(""),
        kv(
            "provider",
            server.provider.map(|p| p.label().to_string()).unwrap_or_else(|| "non déclaré".into()),
        ),
        Line::from(vec![
            Span::styled(format!("{:<12}", "santé"), dim_style()),
            Span::styled(
                match server.health {
                    Health::Up => "toutes les sondes répondent",
                    Health::Degraded => "sondes partiellement en panne",
                    Health::Down => "aucune sonde ne répond",
                    Health::Unknown => "aucune sonde enregistrée",
                }
                .to_string(),
                health_style(server.health),
            ),
        ]),
    ];

    if server.ssh_ports.len() > 1 {
        lines.push(kv(
            "ports SSH",
            server
                .ssh_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    lines.push(Line::from(""));
    lines.push(heading(format!("Hôtes ({})", server.hosts.len())));
    for name in &server.hosts {
        let families = fleet
            .host(name)
            .map(|h| h.ansible_roles.join(" "))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(format!("  {name:<18}"), text_style()),
            Span::styled(families, tone_style(Tone::Info)),
        ]));
    }

    // Constats rattachés à cette machine — le détail répond « pourquoi ce
    // serveur est-il en ambre ? » sans changer d'écran.
    let related = app.findings_touching(&server.key.to_string(), &server.hosts);

    if !related.is_empty() {
        lines.push(Line::from(""));
        lines.push(heading(format!("Constats ({})", related.len())));
        for f in related {
            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", severity_glyph(f.severity)), severity_style(f.severity)),
                Span::styled(f.message.clone(), text_style()),
            ]));
        }
    }

    lines
}

fn host_detail(app: &App) -> Vec<Line<'static>> {
    let hosts = app.visible_hosts();
    let Some(host) = hosts.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucun hôte", dim_style()))];
    };

    let mut lines = vec![
        heading(host.name.clone()),
        Line::from(""),
        kv("adresse", host.ansible_host.clone()),
    ];

    match &host.provider {
        Some(p) => lines.push(kv("provider", p.clone())),
        None => lines.push(Line::from(vec![
            Span::styled(format!("{:<12}", "provider"), dim_style()),
            Span::styled("non déclaré — obligatoire".to_string(), tone_style(Tone::Danger)),
        ])),
    }

    if let Some(port) = host.ansible_port {
        lines.push(kv("port SSH", port.to_string()));
    }
    if let Some(t) = &host.server_type {
        lines.push(kv("type", t.clone()));
    }
    if let Some(h) = &host.hostname {
        lines.push(kv("nom", h.clone()));
    }
    if !host.groups.is_empty() {
        lines.push(kv("groupes", host.groups.join(" › ")));
    }

    lines.push(Line::from(""));
    lines.push(heading("Familles de rôles".into()));
    if host.ansible_roles.is_empty() {
        lines.push(Line::from(Span::styled(
            "  socle uniquement".to_string(),
            dim_style(),
        )));
    } else {
        for family in &host.ansible_roles {
            lines.push(Line::from(Span::styled(
                format!("  {family}"),
                tone_style(Tone::Info),
            )));
        }
    }

    if !host.alert_exclude.is_empty() {
        lines.push(Line::from(""));
        lines.push(heading("Exemptions d'alertes".into()));
        for alert in &host.alert_exclude {
            lines.push(Line::from(Span::styled(format!("  {alert}"), tone_style(Tone::Warn))));
        }
    }

    // Services suivis sur cet hôte.
    let tracked: Vec<&fleetforge_core::ServerServiceState> = app
        .services
        .iter()
        .filter(|s| s.server_name == host.name)
        .collect();
    if !tracked.is_empty() {
        lines.push(Line::from(""));
        lines.push(heading(format!("Services installés ({})", tracked.len())));
        for s in tracked {
            lines.push(Line::from(Span::styled(
                format!("  {}", s.service_name),
                text_style(),
            )));
        }
    }

    lines
}

fn services_detail(app: &App) -> Vec<Line<'static>> {
    let services = app.visible_services();
    let Some(s) = services.get(app.cursor()) else {
        return vec![
            Line::from(Span::styled("aucun service suivi", dim_style())),
            Line::from(Span::styled(
                "le journal ne connaît que ce que FleetForge a déployé",
                dim_style(),
            )),
        ];
    };
    vec![
        heading(s.service_name.clone()),
        Line::from(""),
        kv("hôte", s.server_name.clone()),
        kv("action", s.last_action.clone()),
        kv("source", s.last_source.clone()),
        kv("depuis", s.installed_at.clone()),
        kv(
            "rôle",
            s.last_role_name.clone().unwrap_or_else(|| "—".into()),
        ),
    ]
}

fn role_detail(app: &App) -> Vec<Line<'static>> {
    let roles = app.visible_roles();
    let Some(r) = roles.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucun rôle", dim_style()))];
    };
    let targets = app.target_hosts();
    let mut lines = vec![
        heading(r.label.clone()),
        Line::from(""),
        kv("rôle", r.name.clone()),
        kv("catégorie", r.category.clone()),
        Line::from(""),
        Line::from(Span::styled(r.description.clone(), text_style())),
        Line::from(""),
    ];

    if targets.is_empty() {
        lines.push(Line::from(Span::styled(
            "Aucun hôte ciblé — marquer des hôtes (espace) avant `d`.".to_string(),
            tone_style(Tone::Warn),
        )));
    } else {
        lines.push(heading(format!("Cible ({})", targets.len())));
        for host in targets.iter().take(12) {
            lines.push(Line::from(Span::styled(format!("  {host}"), text_style())));
        }
        if targets.len() > 12 {
            lines.push(Line::from(Span::styled(
                format!("  … et {} de plus", targets.len() - 12),
                dim_style(),
            )));
        }
    }
    lines
}

fn playbook_detail(app: &App) -> Vec<Line<'static>> {
    let playbooks = app.visible_playbooks();
    let Some(p) = playbooks.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucun playbook", dim_style()))];
    };
    let mut lines = vec![
        heading(p.label.clone()),
        Line::from(""),
        kv("fichier", p.name.clone()),
        kv("catégorie", p.category.clone()),
        kv("hôtes", p.hosts.clone()),
        Line::from(""),
        Line::from(Span::styled(p.description.clone(), text_style())),
    ];
    if !p.roles.is_empty() {
        lines.push(Line::from(""));
        lines.push(heading(format!("Rôles ({})", p.roles.len())));
        for role in &p.roles {
            lines.push(Line::from(Span::styled(format!("  {role}"), dim_style())));
        }
    }
    lines
}

fn run_detail(app: &App, height: u16) -> Vec<Line<'static>> {
    let Some(run) = app.runs.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucun run", dim_style()))];
    };
    let mut lines = vec![
        heading(run.label.clone()),
        Line::from(""),
        kv("hôtes", run.hosts.join(", ")),
        kv("démarré", run.started_at.clone()),
        Line::from(""),
    ];
    // Les dernières lignes seulement : un run Ansible en produit des milliers,
    // et ce sont les dernières qui portent l'échec. Autant que le panneau en
    // contient — au-delà, c'est la FIN qui débordait, donc justement ce qu'on
    // venait lire.
    let room = (height as usize).saturating_sub(2 + lines.len()).max(3);
    let tail = run.output.iter().rev().take(room).rev();
    for line in tail {
        lines.push(Line::from(Span::styled(line.clone(), dim_style())));
    }
    lines
}

fn finding_detail(app: &App) -> Vec<Line<'static>> {
    let findings = app.visible_findings();
    let Some(f) = findings.get(app.cursor()) else {
        return vec![Line::from(Span::styled(
            "aucun constat — le parc est cohérent".to_string(),
            tone_style(Tone::Ok),
        ))];
    };
    use fleetforge_core::diagnostics::Subject;
    let subject = match &f.subject {
        Subject::Host(id) => format!("hôte {id}"),
        Subject::Server(id) => format!("machine {id}"),
        Subject::RoleFamily(id) => format!("famille {id}"),
        Subject::Fleet(id) => format!("parc {id}"),
    };
    vec![
        Line::from(Span::styled(f.rule.to_string(), severity_style(f.severity))),
        Line::from(""),
        kv("porte sur", subject),
        Line::from(""),
        Line::from(Span::styled(f.message.clone(), text_style())),
    ]
}

fn provider_detail(app: &App) -> Vec<Line<'static>> {
    let Some(p) = app.providers.get(app.cursor()) else {
        return vec![Line::from(Span::styled("aucun provider", dim_style()))];
    };

    let mut lines = vec![heading(p.info.label.clone()), Line::from("")];

    if let Some(tool) = &p.info.missing_tool {
        lines.push(Line::from(Span::styled(
            format!("L'outil `{tool}` n'est pas installé."),
            tone_style(Tone::Warn),
        )));
        lines.push(Line::from(""));
    }

    // ── Comptes ────────────────────────────────────────────────────────────
    // En tête du détail, avant les capacités : c'est ce qu'on vient chercher
    // ici dès qu'on en a plus d'un, et c'est ce sur quoi portent les touches.
    if p.info.capabilities.list {
        lines.push(heading(format!("Comptes ({})", p.accounts.len())));
        let focused = app.focus.account();

        for (index, account) in p.accounts.iter().enumerate() {
            let here = focused == Some(index);
            let (glyph, tone, note) = if account.connected {
                let count = app
                    .provider_instances()
                    .iter()
                    .filter(|i| i.reference.account == account.name)
                    .count();
                ("●", Tone::Ok, format!("{count} instance(s)"))
            } else if account.has_saved_credentials {
                ("○", Tone::Warn, "non connecté".to_string())
            } else {
                // Le compte `default` proposé d'office sur un hébergeur jamais
                // configuré : une ligne à remplir, pas une anomalie.
                ("·", Tone::Unknown, "à configurer".to_string())
            };

            lines.push(Line::from(vec![
                Span::styled(
                    if here { " ▸ " } else { "   " }.to_string(),
                    tone_style(Tone::Ok),
                ),
                Span::styled(format!("{glyph} "), tone_style(tone)),
                Span::styled(
                    format!("{:<14}", account.name),
                    if here { selected_style() } else { text_style() },
                ),
                Span::styled(note, dim_style()),
                // Signale qu'une commande de session existe ICI : elles
                // dépendent du compte, pas de l'hébergeur, et `s` ne ferait
                // rien sur un profil authentifié par clé.
                Span::styled(
                    if account.session_actions.is_empty() { "" } else { "  ⟳ s" }.to_string(),
                    tone_style(Tone::Info),
                ),
            ]));
        }
        lines.push(Line::from(""));
    }

    // ── Instances du compte désigné ────────────────────────────────────────
    let account_instances = app.account_instances();
    if let Some(account) = app.selected_account() {
        if !account_instances.is_empty() {
            lines.push(heading(format!(
                "Instances de {} ({})",
                account.name,
                account_instances.len()
            )));
            let focused = app.focus.instance();

            for (index, inst) in account_instances.iter().enumerate().take(15) {
                let tone = match inst.state {
                    fleetforge_providers::PowerState::Running => Tone::Ok,
                    fleetforge_providers::PowerState::Stopped => Tone::Danger,
                    fleetforge_providers::PowerState::Transitioning => Tone::Warn,
                    fleetforge_providers::PowerState::Unknown => Tone::Unknown,
                };
                let here = focused == Some(index);
                lines.push(Line::from(vec![
                    Span::styled(
                        if here { " ▸ " } else { "   " }.to_string(),
                        tone_style(Tone::Ok),
                    ),
                    Span::styled(format!("{} ", tone.glyph()), tone_style(tone)),
                    Span::styled(
                        format!("{:<20}", inst.name),
                        if here { selected_style() } else { text_style() },
                    ),
                    Span::styled(inst.addresses.join(" "), dim_style()),
                ]));
            }

            if account_instances.len() > 15 {
                lines.push(Line::from(Span::styled(
                    format!("   … {} de plus", account_instances.len() - 15),
                    dim_style(),
                )));
            }
            lines.push(Line::from(""));
        }
    }

    lines.push(heading("Capacités".into()));
    for (label, allowed) in [
        ("lister", p.info.capabilities.list),
        ("détailler", p.info.capabilities.describe),
        ("démarrer", p.info.capabilities.start),
        ("arrêter", p.info.capabilities.stop),
        ("arrêt gracieux", p.info.capabilities.stop_graceful),
        ("redémarrer", p.info.capabilities.reboot),
        ("redémarrage gracieux", p.info.capabilities.reboot_graceful),
    ] {
        let (glyph, tone) = if allowed { ("✓", Tone::Ok) } else { ("·", Tone::Unknown) };
        lines.push(Line::from(vec![
            Span::styled(format!("  {glyph} "), tone_style(tone)),
            Span::styled(
                label.to_string(),
                if allowed { text_style() } else { dim_style() },
            ),
        ]));
    }

    if !p.info.auth_methods.is_empty() {
        lines.push(Line::from(""));
        lines.push(heading("Authentification".into()));
        for method in &p.info.auth_methods {
            let (glyph, tone) = if method.detected {
                ("●", Tone::Ok)
            } else {
                ("○", Tone::Unknown)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {glyph} "), tone_style(tone)),
                Span::styled(method.label.clone(), text_style()),
            ]));
        }
    }

    lines
}

// === Superpositions ===

/// Fenêtre centrée, en pourcentage : reste lisible d'un terminal étroit à un
/// écran large.
fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let v = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(v[1])[1]
}

/// Cadre centré d'une hauteur EXACTE en lignes. `centered` raisonne en
/// pourcentage, ce qui convient à un panneau dont le contenu s'adapte, pas à
/// une liste fixe qu'il faut montrer entière.
fn centered_rows(area: Rect, percent_x: u16, rows: u16) -> Rect {
    let margin = area.height.saturating_sub(rows) / 2;
    let v = Layout::vertical([
        Constraint::Length(margin),
        Constraint::Length(rows),
        Constraint::Min(0),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(v[1])[1]
}

fn overlay_block(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(format!(" {title} "), title_style()))
}

/// Aide complète. La colonne de gauche est faite de TOUCHES séparées par des
/// espaces, et rien d'autre : un test la relit ainsi pour vérifier qu'aucune
/// entrée de `KEYS` n'y manque. Écrire « (ou : ) » ou « Maj-Tab » y casserait
/// la correspondance sans que rien ne le dise.
const HELP: &[(&str, &str)] = &[
    ("1-5", "aller à une section"),
    ("⇥ ⇧⇥", "section suivante / précédente"),
    ("← →", "remonter / descendre dans le parc ; Rôles ↔ Playbooks"),
    ("j k ↑ ↓", "se déplacer"),
    ("⇞ ⇟ g G", "page précédente / suivante, début / fin de liste"),
    ("espace", "actions de l'élément désigné (menu)"),
    ("m", "marquer un hôte ou une machine entière"),
    ("⎋", "remonter d'un niveau, effacer le filtre ou les marques"),
    ("/ :", "palette de commandes"),
    ("f", "filtrer la liste courante"),
    ("P", "choisir le parc"),
    ("d p e", "déployer un rôle / lancer un playbook / exemptions d'alertes"),
    ("↵", "descendre d'un niveau, ou exécuter ce que l'écran propose"),
    ("c x", "connecter / déconnecter un provider ; x retire un service"),
    ("C", "saisir les identifiants du compte désigné"),
    ("a X n", "ajouter / oublier / renommer un compte ; X purge un service"),
    ("s", "commande de session du compte (renouveler un jeton)"),
    ("S A R", "démarrer / arrêter / redémarrer la machine désignée"),
    ("r", "recharger"),
    ("?", "cette aide"),
    ("q", "quitter"),
];


/// Choix d'une commande de session.
fn draw_session_menu(frame: &mut Frame, menu: &SessionMenu) {
    let mut lines: Vec<Line> = Vec::new();

    for (index, entry) in menu.actions.iter().enumerate() {
        let here = index == menu.cursor;
        lines.push(Line::from(vec![
            Span::styled(
                if here { " ▸ " } else { "   " }.to_string(),
                tone_style(Tone::Ok),
            ),
            Span::styled(
                entry.label.clone(),
                if here { selected_style() } else { text_style() },
            ),
        ]));
    }

    // L'explication de la seule ligne désignée : les afficher toutes ferait un
    // pavé où l'on ne distingue plus laquelle est choisie.
    if let Some(entry) = menu.selected() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("   {}", entry.hint),
            dim_style(),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "   j k choisir   ↵ lancer   ⎋ annuler".to_string(),
        dim_style(),
    )));

    let wanted = lines.len() as u16 + 2;
    let area = centered_rows(frame.area(), 64, wanted.min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style(true))
                    .title(Span::styled(
                        format!(" Session · {} ", menu.account),
                        title_style(),
                    )),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_rename(frame: &mut Frame, form: &RenameForm) {
    let area = centered_rows(frame.area(), 56, 6.min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  nom ", tone_style(Tone::Info)),
                Span::styled(form.input.clone(), text_style()),
                Span::styled("▏", tone_style(Tone::Info)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  ↵ valider   ⎋ annuler   (minuscules et tirets)",
                dim_style(),
            )),
        ])
        .block(overlay_block(&format!("Renommer {}", form.account))),
        area,
    );
}

/// Lignes qu'occupe `text` une fois replié sur `width` colonnes.
///
/// Repli GLOUTON PAR MOTS, comme celui du `Paragraph` : diviser la longueur par
/// la largeur sous-compte dès qu'un mot ne tient pas en fin de ligne, et le
/// pied de la fenêtre (« ⎋ pour fermer ») sortait alors du cadre.
fn wrapped_rows(text: &str, width: usize) -> usize {
    let width = width.max(1);
    text.split('\n')
        .map(|line| {
            let mut rows = 1;
            let mut used = 0;
            for word in line.split_whitespace() {
                // Un mot plus long que la ligne se coupe, il occupe plusieurs rangées.
                let len = word.chars().count();
                let extra = len.saturating_sub(1) / width;
                if used == 0 {
                    used = len % width.max(1);
                    rows += extra;
                } else if used + 1 + len <= width {
                    used += 1 + len;
                } else {
                    rows += 1 + extra;
                    used = len % width;
                }
            }
            rows
        })
        .sum()
}

/// Erreur lue en entier. Le texte vient tel que l'outil l'a rendu : le replier
/// à la largeur de la fenêtre le garde lisible sans le réécrire.
fn draw_message(frame: &mut Frame, text: &str) {
    let width = (frame.area().width as usize * 70 / 100).max(30);
    // Deux colonnes de bordure, deux de marge à gauche.
    let inner = width.saturating_sub(4);
    // Ligne vide, texte, ligne vide, pied, plus les deux bordures.
    let rows = (wrapped_rows(text, inner) + 5).min(frame.area().height as usize);
    let area = centered_rows(frame.area(), 70, rows as u16);

    let mut lines: Vec<Line> = vec![Line::from("")];
    for line in text.split('\n') {
        lines.push(Line::from(Span::styled(format!("  {line}"), text_style())));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  ⎋ ou ↵ pour fermer".to_string(),
        dim_style(),
    )));

    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(tone_style(Tone::Danger))
                    .title(Span::styled(" Erreur ", tone_style(Tone::Danger))),
            ),
        area,
    );
}

/// Fenêtre de `max` lignes qui garde `cursor` visible.
fn window(len: usize, cursor: usize, max: usize) -> std::ops::Range<usize> {
    if len <= max {
        return 0..len;
    }
    let start = cursor.saturating_sub(max / 2).min(len - max);
    start..start + max
}

/// Choix filtrable : parc, rôle, playbook, hôte, alerte.
fn draw_picker(frame: &mut Frame, picker: &Picker) {
    let visible = picker.visible();
    let max_rows = (frame.area().height as usize).saturating_sub(8).clamp(3, 14);
    let span = window(visible.len(), picker.cursor, max_rows);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  ▸ ", tone_style(Tone::Info)),
            Span::styled(picker.query.clone(), text_style()),
            Span::styled("▏", tone_style(Tone::Info)),
        ]),
        Line::from(""),
    ];
    if visible.is_empty() {
        lines.push(Line::from(Span::styled("  aucun résultat", dim_style())));
    }
    for index in span.clone() {
        let item = visible[index];
        let here = index == picker.cursor;
        lines.push(Line::from(vec![
            Span::styled(if here { " ▸ " } else { "   " }.to_string(), tone_style(Tone::Ok)),
            Span::styled(
                format!("{:<34}", item.label),
                if here { selected_style() } else { text_style() },
            ),
            Span::styled(item.detail.clone(), dim_style()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "   {}/{}   ↑↓ choisir   ↵ valider   ⎋ annuler   taper pour filtrer",
            visible.len().min(picker.cursor + 1),
            visible.len()
        ),
        dim_style(),
    )));

    let wanted = lines.len() as u16 + 2;
    let area = centered_rows(frame.area(), 72, wanted.min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(overlay_block(&picker.title)),
        area,
    );
}

/// Actions de l'élément désigné. Une action indisponible reste LISTÉE et dit
/// pourquoi : une entrée absente ne distingue pas « n'existe pas » de
/// « une condition manque ».
fn draw_actions(frame: &mut Frame, menu: &ActionMenu) {
    let mut lines: Vec<Line> = Vec::new();
    for (index, action) in menu.entries.iter().enumerate() {
        let here = index == menu.cursor;
        let style = if !action.enabled {
            dim_style()
        } else if here {
            selected_style()
        } else if action.destructive {
            tone_style(Tone::Warn)
        } else {
            text_style()
        };
        lines.push(Line::from(vec![
            Span::styled(if here { " ▸ " } else { "   " }.to_string(), tone_style(Tone::Ok)),
            Span::styled(format!("{:<38}", action.label), style),
            Span::styled(action.key.clone().unwrap_or_default(), tone_style(Tone::Info)),
        ]));
    }

    // La raison de la seule ligne désignée, comme le menu de session.
    if let Some(reason) = menu.selected().and_then(|a| a.reason.as_ref()) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(format!("   {reason}"), tone_style(Tone::Warn))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "   j k choisir   ↵ lancer   ⎋ fermer".to_string(),
        dim_style(),
    )));

    let wanted = lines.len() as u16 + 2;
    let area = centered_rows(frame.area(), 64, wanted.min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(overlay_block(&menu.title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Formulaire d'identifiants.
///
/// Montre l'indication du champ QUI A LE FOCUS, et elle seule : les afficher
/// toutes ferait un pavé de six lignes d'aide au milieu des six champs, où
/// plus rien ne se lit.
fn draw_credentials(frame: &mut Frame, form: &CredentialsForm) {
    let Some(method) = form.current() else { return };

    let mut lines: Vec<Line> = Vec::new();

    // Sélecteur de méthode, seulement s'il y a un choix à faire.
    if form.methods.len() > 1 {
        let mut spans = vec![Span::styled("  ‹ ".to_string(), dim_style())];
        spans.push(Span::styled(method.label.clone(), selected_style()));
        if method.detected {
            spans.push(Span::styled("  détectée".to_string(), tone_style(Tone::Ok)));
        }
        spans.push(Span::styled(
            format!("  › ({}/{})", form.method + 1, form.methods.len()),
            dim_style(),
        ));
        lines.push(Line::from(spans));
        lines.push(Line::from(""));
    }

    // Nom du compte, en premier : à la création il distingue « ajouter une
    // tenancy » de « corriger celle-ci » ; sur un compte existant, le changer
    // le renomme.
    {
        let here = form.on_account_field();
        lines.push(Line::from(vec![
            Span::styled(
                if here { " ▸ " } else { "   " }.to_string(),
                tone_style(Tone::Ok),
            ),
            Span::styled(
                format!("{:<26}", "Nom du compte"),
                if here { selected_style() } else { text_style() },
            ),
            Span::styled(form.account.clone(), text_style()),
            Span::styled(if here { "▁" } else { "" }.to_string(), tone_style(Tone::Info)),
        ]));
        lines.push(Line::from(Span::styled(
            if form.original.is_some() {
                "     modifier le nom renomme le compte (identifiants et session suivent).".to_string()
            } else {
                "     court et stable : acme, perso, client-x. Vide = default.".to_string()
            },
            dim_style(),
        )));
    }

    let offset = 1;
    for (index, field) in method.fields.iter().enumerate() {
        let here = index + offset == form.field;
        // Un secret n'est jamais rendu en clair, même pendant la frappe : le
        // TUI tourne le plus souvent dans un terminal partagé ou enregistré.
        let shown = if field.secret {
            "•".repeat(field.value.chars().count())
        } else {
            field.value.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(
                if here { " ▸ " } else { "   " }.to_string(),
                tone_style(Tone::Ok),
            ),
            Span::styled(
                format!("{:<26}", field.label),
                if here { selected_style() } else { text_style() },
            ),
            Span::styled(shown, text_style()),
            Span::styled(if here { "▁" } else { "" }.to_string(), tone_style(Tone::Info)),
            Span::styled(
                if field.optional { "  facultatif" } else { "" }.to_string(),
                dim_style(),
            ),
        ]));
    }

    // Lecture seule : la tenancy du profil est celle du compte Oracle auquel il
    // est connecté, écrite par le CLI. Elle se compare au compartiment saisi,
    // qui doit être cette tenancy ou l'un de ses compartiments.
    let mut tenancy_rows = 0;
    if form.kind == fleetforge_core::model::ProviderKind::Oracle {
        let profile = method
            .fields
            .iter()
            .find(|f| f.key == "OCI_PROFILE")
            .map(|f| f.value.trim())
            .filter(|v| !v.is_empty())
            .unwrap_or("DEFAULT");
        let tenancy = fleetforge_providers::cli::oci_profile_tenancy(profile);
        let compartment = method
            .fields
            .iter()
            .find(|f| f.key == "OCI_COMPARTMENT")
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default();
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!("   {:<26}", "Tenancy du profil"), dim_style()),
            Span::styled(format!("[{profile}] · lecture seule"), dim_style()),
        ]));
        match tenancy {
            Some(t) => {
                let same = !compartment.is_empty() && compartment == t;
                lines.push(Line::from(vec![
                    Span::styled(format!("   {t}"), text_style()),
                    Span::styled(if same { "  = racine" } else { "" }.to_string(), tone_style(Tone::Ok)),
                ]));
                tenancy_rows = 2;
            }
            None => {
                lines.push(Line::from(Span::styled(
                    "   profil absent de ~/.oci/config : il sera créé à la connexion".to_string(),
                    dim_style(),
                )));
                tenancy_rows = 1;
            }
        }
    }

    if let Some(field) = form.current_field() {
        if !field.hint.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(format!("   {}", field.hint), dim_style())));
        }
    }

    if let Some(error) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("   {error}"),
            tone_style(Tone::Danger),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if form.methods.len() > 1 {
            "   ⇥ champ suivant  ← → méthode  ↵ connecter  ⎋ annuler"
        } else {
            "   ⇥ champ suivant  ↵ connecter  ⎋ annuler"
        }
        .to_string(),
        dim_style(),
    )));

    // Le titre dit LEQUEL des deux gestes est en cours.
    let title = if form.original.is_some() {
        format!(" Identifiants · {} · {} ", form.provider_label, form.account)
    } else {
        format!(" Nouveau compte · {} ", form.provider_label)
    };

    // Hauteur demandée par le contenu, comme l'aide : un cadre en pourcentage
    // tronque le pied de page sur un terminal de 24 lignes, et c'est lui qui
    // dit comment sortir.
    let wanted = lines.len() as u16 + 2 + tenancy_rows;
    let area = centered_rows(frame.area(), 72, wanted.min(frame.area().height));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style(true))
                    .title(Span::styled(title, title_style())),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_help(frame: &mut Frame) {
    // Hauteur DEMANDÉE par le contenu, pas un pourcentage de l'écran : à 70 %
    // d'un terminal de 24 lignes le cadre en fait 16, et les deux dernières
    // entrées — dont `q`, quitter — tombaient hors champ sans le moindre
    // indice de troncature. Une aide qui cache la sortie est pire que pas
    // d'aide. Le `min` garde le cadre dans l'écran sur un terminal minuscule.
    let wanted = HELP.len() as u16 + 2;
    let area = centered_rows(frame.area(), 56, wanted.min(frame.area().height));
    frame.render_widget(Clear, area);

    let lines: Vec<Line> = HELP
        .iter()
        .map(|(keys, what)| {
            Line::from(vec![
                Span::styled(format!("  {keys:<16}"), tone_style(Tone::Info)),
                Span::styled(what.to_string(), text_style()),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines).block(overlay_block("Raccourcis")),
        area,
    );
}

/// Commandes de la palette. Tout ce que la souris fait dans le GUI se tape ici.
pub const COMMANDS: &[(&str, &str)] = &[
    ("servers", "aller aux machines"),
    ("hosts", "tous les hôtes, à plat"),
    ("services", "tous les services, à plat"),
    ("roles", "aller aux rôles"),
    ("playbooks", "aller aux playbooks"),
    ("runs", "aller aux runs"),
    ("diagnostics", "aller aux diagnostics"),
    ("providers", "aller aux providers"),
    ("inventory", "changer de parc (sans argument : le sélecteur)"),
    ("reload", "tout recharger"),
    ("clear-marks", "effacer la sélection d'hôtes"),
    ("exempt", "exempter l'hôte courant d'une alerte (:exempt <alerte>)"),
    ("unexempt", "retirer une exemption de l'hôte courant"),
    ("apply-alerts", "rendre les règles d'alerte du parc (update-prometheus-alerts.yml)"),
    ("connect", "connecter le provider courant"),
    ("disconnect", "déconnecter le provider courant"),
    ("quit", "quitter"),
];

fn draw_palette(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 56, 50);
    frame.render_widget(Clear, area);

    let needle = app.palette_input.to_lowercase();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("  / ", tone_style(Tone::Info)),
            Span::styled(app.palette_input.clone(), text_style()),
            Span::styled("▏", tone_style(Tone::Info)),
        ]),
        Line::from(""),
    ];

    for (name, what) in COMMANDS.iter().filter(|(n, _)| n.contains(&needle)) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {name:<14}"), text_style()),
            Span::styled(what.to_string(), dim_style()),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines).block(overlay_block("Commande")),
        area,
    );
}

fn draw_filter(frame: &mut Frame, app: &App) {
    let area = centered(frame.area(), 50, 16);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  filtre ", tone_style(Tone::Info)),
            Span::styled(app.filter.clone(), text_style()),
            Span::styled("▏", tone_style(Tone::Info)),
        ]))
        .block(overlay_block(&format!(
            "Filtre — {} résultat(s)",
            app.row_count()
        ))),
        area,
    );
}

fn draw_confirm(frame: &mut Frame, prompt: &str) {
    let area = centered(frame.area(), 56, 24);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(format!("  {prompt}"), text_style())),
            Line::from(""),
            Line::from(vec![
                Span::styled("  o".to_string(), tone_style(Tone::Ok)),
                Span::styled(" confirmer     ", dim_style()),
                Span::styled("Échap".to_string(), tone_style(Tone::Danger)),
                Span::styled(" annuler", dim_style()),
            ]),
        ])
        .wrap(Wrap { trim: false })
        .block(overlay_block("Confirmation")),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(spans: &[Span<'static>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn a_message_that_fits_is_left_intact() {
        let spans = vec![Span::raw("session expirée".to_string())];
        assert_eq!(text(&elide(spans, 40)), "session expirée");
    }

    #[test]
    fn a_message_too_long_is_cut_visibly() {
        // Tronquer en silence donne un message qui se lit comme complet alors
        // qu'il a perdu sa consigne — c'est exactement ce que faisait la barre
        // d'état sur un refus d'authentification.
        let spans = vec![Span::raw("session expirée : ouvrir une session neuve".to_string())];
        let cut = text(&elide(spans, 12));
        assert_eq!(cut.chars().count(), 12);
        assert!(cut.ends_with('…'), "{cut}");
    }

    #[test]
    fn the_cut_spans_several_fragments_without_losing_the_first() {
        let spans = vec![
            Span::raw("▶ 2 run(s) ".to_string()),
            Span::raw("connexion refusée".to_string()),
        ];
        let cut = text(&elide(spans, 16));
        assert!(cut.starts_with("▶ 2 run(s) "), "{cut}");
        assert_eq!(cut.chars().count(), 16);
    }

    #[test]
    fn a_footer_too_narrow_for_anything_renders_nothing_rather_than_a_lone_ellipsis() {
        assert!(elide(vec![Span::raw("x".to_string())], 1).is_empty());
    }

    /// Touches que `handle_normal` lie réellement, lues dans la SOURCE.
    ///
    /// Même procédé que `command_parity` côté web : le contrôle porte sur le
    /// code qui s'exécute, pas sur une liste tenue à côté et qui se démode.
    fn keys_bound_in_input() -> Vec<String> {
        let source = include_str!("input.rs");
        let body = source
            .split("fn handle_normal")
            .nth(1)
            .expect("handle_normal introuvable");
        // Le corps s'arrête à la fonction suivante, à la colonne zéro.
        let body = body.split("\n}\n").next().unwrap_or(body);

        let mut out: Vec<String> = Vec::new();
        for (i, _) in body.match_indices("KeyCode::") {
            let rest = &body[i + "KeyCode::".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            let token = match name.as_str() {
                "Char" => {
                    // `Char('x')` ; `Char(c @ '1'..='9')` couvre les chiffres.
                    match rest.strip_prefix("Char('").and_then(|r| r.chars().next()) {
                        Some(c) => c.to_string(),
                        None if rest.starts_with("Char(c @ '1'..='5')") => "1-5".into(),
                        None => continue,
                    }
                }
                "Enter" => "↵".into(),
                "Esc" => "⎋".into(),
                "Tab" => "⇥".into(),
                "BackTab" => "⇧⇥".into(),
                "Left" => "←".into(),
                "Right" => "→".into(),
                "Up" => "↑".into(),
                "Down" => "↓".into(),
                "PageUp" => "⇞".into(),
                "PageDown" => "⇟".into(),
                "Home" => "g".into(),
                "End" => "G".into(),
                _ => continue,
            };
            let token = if token == " " { "espace".to_string() } else { token };
            if !out.contains(&token) {
                out.push(token);
            }
        }
        out
    }

    #[test]
    fn every_key_the_dispatcher_binds_is_declared() {
        // Lier une touche sans la déclarer la rend invisible : elle n'apparaît
        // ni dans la barre du bas, ni dans `?`. Elle existe pour celui qui a
        // écrit le code, et pour personne d'autre.
        let declared: Vec<&str> = KEYS.iter().map(|(k, _)| *k).collect();
        let bound = keys_bound_in_input();
        assert!(!bound.is_empty(), "lecture de input.rs ratée");

        for key in &bound {
            assert!(
                declared.contains(&key.as_str()),
                "`{key}` est liée dans handle_normal mais absente de KEYS"
            );
        }
    }

    #[test]
    fn nothing_is_declared_that_the_dispatcher_ignores() {
        // L'inverse compte autant : annoncer une touche morte envoie appuyer
        // sur quelque chose qui ne fait rien.
        let bound = keys_bound_in_input();
        for (key, _) in KEYS {
            assert!(
                bound.contains(&key.to_string()),
                "`{key}` est annoncée mais n'est liée à rien"
            );
        }
    }

    const LEVELS: [ProviderFocus; 3] = [
        ProviderFocus::Providers,
        ProviderFocus::Accounts(0),
        ProviderFocus::Instances { account: 0, instance: 0 },
    ];

    /// Tous les états d'élément qui changent ce que la barre annonce.
    ///
    /// Le tout-à-vrai n'existe pas en vrai — un compte n'est pas à la fois
    /// connecté et déconnecté — d'où une LISTE : chaque entrée est un état
    /// atteignable, et la réunion de ce qu'elles annoncent doit couvrir
    /// l'écran.
    fn reachable_contexts() -> Vec<HintContext> {
        let base = HintContext { has_row: true, ..Default::default() };
        vec![
            base,
            HintContext { marked: true, ..base },
            HintContext { can_remove: true, can_purge: true, ..base },
            HintContext { navigable: true, ..base },
            // Hébergeur : rien d'enregistré, puis enregistré non connecté,
            // puis connecté.
            HintContext { has_accounts: true, ..base },
            HintContext { has_accounts: true, any_saved: true, account_saved: true, ..base },
            // Compte unique : le niveau hébergeur EST le niveau compte.
            HintContext {
                has_accounts: true,
                single_account: true,
                any_saved: true,
                account_saved: true,
                ..base
            },
            HintContext {
                has_accounts: true,
                single_account: true,
                any_saved: true,
                any_connected: true,
                account_saved: true,
                account_connected: true,
                has_instances: true,
                ..base
            },
            HintContext {
                has_accounts: true,
                any_saved: true,
                any_connected: true,
                account_saved: true,
                account_connected: true,
                has_instances: true,
                ..base
            },
            // Instance : arrêtée (démarrable), puis allumée (arrêtable).
            HintContext { can_start: true, can_reboot: true, ..base },
            HintContext { can_stop: true, can_reboot: true, ..base },
        ]
    }

    /// Tout ce que la barre du bas peut annoncer sur un écran, tous niveaux et
    /// tous états d'élément réunis.
    fn footer_keys(screen: Screen) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for ctx in reachable_contexts() {
            for focus in LEVELS {
                for (k, _) in screen_hints(screen, focus, ctx) {
                    if !out.contains(&k) {
                        out.push(k);
                    }
                }
            }
        }
        out.extend(EVERYWHERE.iter().map(|(k, _)| *k));
        out.push(HELP_HINT.0);
        out
    }

    #[test]
    fn every_key_active_on_a_screen_is_announced_there() {
        // C'est la garantie demandée : sur chaque écran, la dernière ligne
        // annonce tout ce qui y agit. Les déplacements en sont exclus
        // explicitement — `KeyScope::HelpOnly` — et `?` les redonne.
        for screen in Screen::ALL {
            let announced = footer_keys(screen);
            for (key, scope) in KEYS {
                let active = match scope {
                    KeyScope::Everywhere => true,
                    KeyScope::On(screens) => screens.contains(&screen),
                    KeyScope::HelpOnly => false,
                };
                assert!(
                    !active || announced.contains(key),
                    "`{key}` agit sur {} mais la barre du bas ne l'annonce pas",
                    screen.title()
                );
            }
        }
    }

    #[test]
    fn the_footer_announces_nothing_that_does_not_act_there() {
        // « ↵ exécuter » est resté des mois sur l'écran Playbooks, où ↵ n'est
        // lié à rien : le TUI ne sait pas lancer de playbook.
        for screen in Screen::ALL {
            for ctx in reachable_contexts() {
            for focus in LEVELS {
                for (key, _) in screen_hints(screen, focus, ctx) {
                    let scope = KEYS
                        .iter()
                        .find(|(k, _)| *k == key)
                        .map(|(_, s)| *s)
                        .unwrap_or_else(|| panic!("`{key}` annoncée mais absente de KEYS"));
                    let active = match scope {
                        KeyScope::Everywhere => true,
                        KeyScope::On(screens) => screens.contains(&screen),
                        KeyScope::HelpOnly => false,
                    };
                    assert!(active, "`{key}` annoncée sur {} sans y agir", screen.title());
                }
            }
            }
        }
    }

    #[test]
    fn the_help_covers_every_key() {
        let documented: Vec<&str> = HELP
            .iter()
            .flat_map(|(keys, _)| keys.split_whitespace())
            .collect();
        for (key, _) in KEYS {
            assert!(documented.contains(key), "`{key}` absente de l'aide `?`");
        }
    }

    fn keys_at(screen: Screen, focus: ProviderFocus, ctx: HintContext) -> Vec<&'static str> {
        screen_hints(screen, focus, ctx).into_iter().map(|(k, _)| k).collect()
    }

    #[test]
    fn a_stopped_machine_is_not_offered_a_stop() {
        let ctx = HintContext { has_row: true, can_start: true, can_reboot: true, ..Default::default() };
        let keys = keys_at(Screen::Providers, LEVELS[2], ctx);
        assert!(keys.contains(&"S"), "{keys:?}");
        assert!(!keys.contains(&"A"), "arrêt annoncé sur une machine éteinte : {keys:?}");
    }

    #[test]
    fn a_running_machine_is_not_offered_a_start() {
        let ctx = HintContext { has_row: true, can_stop: true, can_reboot: true, ..Default::default() };
        let keys = keys_at(Screen::Providers, LEVELS[2], ctx);
        assert!(keys.contains(&"A"), "{keys:?}");
        assert!(!keys.contains(&"S"), "démarrage annoncé sur une machine allumée : {keys:?}");
    }

    #[test]
    fn a_provider_without_the_capability_announces_neither() {
        // `custom` n'a aucune API : la ligne ne doit proposer que de remonter.
        let ctx = HintContext { has_row: true, ..Default::default() };
        let keys = keys_at(Screen::Providers, LEVELS[2], ctx);
        assert_eq!(keys, vec!["⎋"], "{keys:?}");
    }

    #[test]
    fn a_disconnected_account_is_offered_a_connection_not_a_disconnection() {
        let ctx = HintContext { has_row: true, account_saved: true, ..Default::default() };
        let keys = keys_at(Screen::Providers, LEVELS[1], ctx);
        assert!(keys.contains(&"c"), "{keys:?}");
        assert!(!keys.contains(&"x"), "déconnexion annoncée sur un compte fermé : {keys:?}");
        // `↵` connecte tant qu'il n'y a pas d'instance où descendre.
        assert!(keys.contains(&"↵"), "{keys:?}");
    }

    #[test]
    fn an_account_with_nothing_saved_is_offered_neither_session_nor_forget() {
        // Rien à renouveler, rien à oublier : il reste à saisir des
        // identifiants, et c'est la seule chose annoncée avec la remontée.
        let ctx = HintContext { has_row: true, ..Default::default() };
        let keys = keys_at(Screen::Providers, LEVELS[1], ctx);
        assert_eq!(keys, vec!["C", "⎋"], "{keys:?}");
    }

    #[test]
    fn a_connected_account_is_offered_its_instances_and_a_disconnection() {
        let ctx = HintContext {
            has_row: true,
            account_saved: true,
            account_connected: true,
            has_instances: true,
            ..Default::default()
        };
        let keys = keys_at(Screen::Providers, LEVELS[1], ctx);
        assert!(keys.contains(&"x"), "{keys:?}");
        assert!(!keys.contains(&"c"), "connexion annoncée sur un compte ouvert : {keys:?}");
    }

    #[test]
    fn a_marked_row_is_offered_the_unmarking() {
        let ctx = HintContext { has_row: true, marked: true, ..Default::default() };
        let hints = screen_hints(Screen::Hosts, LEVELS[0], ctx);
        let mark = hints.iter().find(|(k, _)| *k == "m").expect("m absent");
        assert_eq!(mark.1, "démarquer");
    }

    #[test]
    fn a_role_is_deployable_from_its_row_without_marking_anything() {
        // Le déploiement ne dépend plus de marques posées AILLEURS : `↵` sur le
        // rôle demande où le poser.
        let some = HintContext { has_row: true, ..Default::default() };
        let hints = screen_hints(Screen::Roles, LEVELS[0], some);
        assert_eq!(hints[0], ("↵", "déployer sur…".to_string()));
        assert!(keys_at(Screen::Roles, LEVELS[0], HintContext::default()).is_empty());
    }

    #[test]
    fn a_service_is_offered_removal_only_when_the_catalogue_has_the_role() {
        let none = HintContext { has_row: true, ..Default::default() };
        let keys = keys_at(Screen::Services, LEVELS[0], none);
        assert!(!keys.contains(&"x") && !keys.contains(&"X"), "{keys:?}");

        let both = HintContext { has_row: true, can_remove: true, can_purge: true, ..Default::default() };
        let keys = keys_at(Screen::Services, LEVELS[0], both);
        assert!(keys.contains(&"x") && keys.contains(&"X"), "{keys:?}");
    }

    #[test]
    fn the_parc_levels_below_the_root_announce_the_way_up() {
        let ctx = HintContext::default();
        assert!(keys_at(Screen::Hosts, LEVELS[0], ctx).contains(&"⎋"));
        assert!(keys_at(Screen::Services, LEVELS[0], ctx).contains(&"⎋"));
        assert!(!keys_at(Screen::Servers, LEVELS[0], ctx).contains(&"⎋"));
    }

    #[test]
    fn a_long_message_is_wrapped_to_the_rows_it_needs() {
        assert_eq!(wrapped_rows("court", 40), 1);
        assert_eq!(wrapped_rows(&"x".repeat(100), 40), 3);
        // Un mot qui ne tient pas en fin de ligne passe à la suivante.
        assert_eq!(wrapped_rows("aaaa bbbb cccc", 9), 2);
        // Un saut de ligne compte, même sur une ligne vide.
        assert_eq!(wrapped_rows("a\n\nb", 40), 3);
        assert_eq!(wrapped_rows("", 40), 1);
    }

    #[test]
    fn a_long_error_is_shown_whole_in_its_window() {
        let text = "le profil [DEFAULT] est authentifié sur la tenancy …example2 mais ce compte \
                    vise …example1 : une session ne vaut que pour une tenancy. Donner à ce \
                    compte son propre profil (champ « Profil »).";
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_message(f, text)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        // Le texte est replié : on cherche ses mots, pas la phrase d'un bloc.
        for word in ["DEFAULT", "example2", "Profil", "Erreur", "fermer"] {
            assert!(screen.contains(word), "« {word} » absent de la fenêtre");
        }
    }

    #[test]
    fn the_message_window_stays_inside_a_small_terminal() {
        let area = Rect::new(0, 0, 80, 24);
        let rows = (wrapped_rows(&"x".repeat(5000), 50) + 5).min(area.height as usize);
        let frame = centered_rows(area, 70, rows as u16);
        assert!(frame.bottom() <= area.bottom());
    }

    #[test]
    fn a_picker_window_keeps_the_cursor_in_view() {
        assert_eq!(window(5, 4, 14), 0..5);
        let span = window(100, 99, 14);
        assert!(span.contains(&99) && span.len() == 14);
        let span = window(100, 0, 14);
        assert!(span.contains(&0) && span.len() == 14);
    }

    #[test]
    fn an_empty_list_offers_nothing_to_act_on() {
        // Curseur sur une liste vide : `↵` et `espace` ne désignent rien.
        let empty = HintContext::default();
        for screen in [Screen::Servers, Screen::Hosts, Screen::Services] {
            // `⎋` remonte même sur une liste vide : ce n'est pas une action sur
            // une ligne.
            let acting: Vec<&str> = keys_at(screen, LEVELS[0], empty)
                .into_iter()
                .filter(|k| *k != "⎋")
                .collect();
            assert!(
                acting.is_empty(),
                "{} annonce des actions sur une liste vide",
                screen.title()
            );
        }
    }

    #[test]
    fn a_lone_account_needs_no_descent_to_be_acted_on() {
        // `↵` n'offrirait aucun choix : les touches de compte agissent depuis
        // le niveau hébergeur, la ligne doit donc les y annoncer.
        let ctx = HintContext {
            has_row: true,
            has_accounts: true,
            single_account: true,
            any_saved: true,
            account_saved: true,
            ..Default::default()
        };
        let keys = keys_at(Screen::Providers, LEVELS[0], ctx);
        for expected in ["c", "C", "s", "X"] {
            assert!(keys.contains(&expected), "`{expected}` absente : {keys:?}");
        }
        // Rien à descendre tant qu'aucune instance n'est chargée.
        assert!(!keys.contains(&"↵"), "{keys:?}");
    }

    #[test]
    fn two_accounts_still_have_to_be_chosen() {
        // Là, `↵` porte un vrai choix : `X` sans compte désigné ne saurait pas
        // lequel oublier.
        let ctx = HintContext {
            has_row: true,
            has_accounts: true,
            any_saved: true,
            account_saved: true,
            ..Default::default()
        };
        let keys = keys_at(Screen::Providers, LEVELS[0], ctx);
        assert!(keys.contains(&"↵"), "{keys:?}");
        assert!(!keys.contains(&"X"), "oubli annoncé sans compte désigné : {keys:?}");
    }

    #[test]
    fn a_machine_is_pilotable_from_the_list_that_shows_it() {
        // Une liste qu'on ne peut que regarder ne sert qu'à regarder : il
        // fallait passer par l'écran Providers et y refaire à la main le
        // rapprochement que le cœur a déjà fait.
        let ctx = HintContext {
            has_row: true,
            can_stop: true,
            can_reboot: true,
            ..Default::default()
        };
        for screen in [Screen::Servers, Screen::Hosts] {
            let keys = keys_at(screen, LEVELS[0], ctx);
            assert!(keys.contains(&"A"), "{} : {keys:?}", screen.title());
            assert!(keys.contains(&"R"), "{} : {keys:?}", screen.title());
        }
    }

    #[test]
    fn a_machine_without_a_matching_instance_is_offered_nothing() {
        // Hébergeur non connecté, machine sans API (`custom`), ou adresse
        // revendiquée par deux comptes : dans les trois cas il n'y a rien à
        // viser, et l'annoncer enverrait appuyer dans le vide.
        let ctx = HintContext { has_row: true, ..Default::default() };
        for screen in [Screen::Servers, Screen::Hosts] {
            let keys = keys_at(screen, LEVELS[0], ctx);
            for key in ["S", "A", "R"] {
                assert!(!keys.contains(&key), "{} : {keys:?}", screen.title());
            }
        }
    }

    #[test]
    fn a_narrow_footer_keeps_the_way_out() {
        // Sur un terminal étroit, des entrées disparaissent — mais jamais `?`,
        // qui est ce qui permet de retrouver celles qui manquent.
        let ctx = HintContext {
            has_row: true,
            account_saved: true,
            account_connected: true,
            has_instances: true,
            ..Default::default()
        };
        let mut pairs = screen_hints(Screen::Providers, ProviderFocus::Accounts(0), ctx);
        pairs.extend(EVERYWHERE.iter().map(|(k, w)| (*k, w.to_string())));
        while !pairs.is_empty() && hint_text(&pairs).chars().count() > 10 {
            pairs.pop();
        }
        pairs.push((HELP_HINT.0, HELP_HINT.1.to_string()));
        assert!(hint_text(&pairs).contains("? aide"));
    }

    #[test]
    fn the_centered_rect_stays_inside_its_area() {
        let area = Rect::new(0, 0, 100, 40);
        let r = centered(area, 60, 50);
        assert!(r.x >= area.x && r.y >= area.y);
        assert!(r.right() <= area.right());
        assert!(r.bottom() <= area.bottom());
    }

    #[test]
    fn centering_survives_a_tiny_terminal() {
        // Un terminal minuscule ne doit pas produire de rectangle invalide.
        let r = centered(Rect::new(0, 0, 10, 4), 60, 50);
        assert!(r.width <= 10 && r.height <= 4);
    }

    #[test]
    fn every_palette_command_is_documented() {
        for (name, what) in COMMANDS {
            assert!(!name.is_empty());
            assert!(!what.is_empty(), "commande `{name}` sans description");
        }
    }

    /// L'aide annonçait `p` pour l'alimentation, touche qui n'était liée à
    /// rien : la promesse tenait par l'aide seule. Les touches annoncées ici
    /// doivent être celles que `handle_key` traite réellement.
    #[test]
    fn the_help_announces_the_power_keys_that_exist() {
        let entry = HELP
            .iter()
            .find(|(_, what)| what.contains("démarrer"))
            .expect("aucune entrée d'alimentation dans l'aide");
        for key in ["S", "A", "R"] {
            assert!(entry.0.contains(key), "`{key}` absent de « {} »", entry.0);
        }
        assert!(
            !HELP.iter().any(|(keys, _)| *keys == "p"),
            "`p` n'est liée à aucune action"
        );
    }

    /// Figurer dans `HELP` ne suffit pas : l'aide était cadrée à 70 % de la
    /// hauteur, donc tronquée sans avertissement sur un terminal de 24 lignes,
    /// et `q` — la dernière entrée — n'y apparaissait jamais.
    #[test]
    fn the_help_frame_shows_every_entry_on_a_small_terminal() {
        let screen = Rect::new(0, 0, 80, 24);
        let frame = centered_rows(screen, 56, HELP.len() as u16 + 2);
        assert!(
            frame.height >= HELP.len() as u16 + 2,
            "cadre de {} lignes pour {} entrées + bordures",
            frame.height,
            HELP.len()
        );
        assert!(frame.bottom() <= screen.bottom(), "cadre débordant de l'écran");
    }

    /// `/` a pris la place de `:` comme préfixe de commande, et le filtre
    /// celle de `f`. Une aide restée sur l'ancienne convention enverrait
    /// l'utilisateur ouvrir un filtre en croyant taper une commande.
    #[test]
    fn the_help_announces_the_current_prefixes() {
        let entry = |k: &str| HELP.iter().find(|(keys, _)| keys.starts_with(k)).copied();

        let (_, palette) = entry("/").expect("`/` absent de l'aide");
        assert!(palette.contains("commande"), "`/` annoncé comme : {palette}");

        let (_, filter) = entry("f").expect("`f` absent de l'aide");
        assert!(filter.contains("filtr"), "`f` annoncé comme : {filter}");
    }

    /// Le TUI ne peut pas choisir son parc si la commande n'est pas annoncée :
    /// aucun écran ne porte la bascule d'inventaire, la palette est le seul
    /// chemin.
    #[test]
    fn the_palette_offers_the_inventory_switch() {
        assert!(COMMANDS.iter().any(|(name, _)| *name == "inventory"));
    }
}
