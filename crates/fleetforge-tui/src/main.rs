/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! `fleetforge` — interface en mode texte de FleetForge.
//!
//! Même couverture que l'interface graphique, même cœur : tout ce qui est
//! affiché ici vient de `fleetforge_core`. Les requêtes tournent en tâches de fond
//! et parlent à la boucle de rendu par un canal — le prototype Python appelait
//! les SDK sur le fil de l'UI et gelait à chaque aller-retour.

mod app;
mod input;
mod theme;
mod ui;

use anyhow::{Context, Result};
use app::{App, Msg};
use crossterm::event::{Event, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use fleetforge_core::Core;
use fleetforge_providers::ProviderHub;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Intervalle de keepalive des sessions provider — cinq minutes, comme le
/// prototype, faute de quoi les jetons expirent en cours de session.
const KEEPALIVE: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    // Avant toute chose : le TUI prend le terminal en mode brut, et tout ce
    // qui s'y affiche ensuite disparaît au rafraîchissement suivant. Sans
    // journal, une erreur tronquée en barre d'état n'est consultable nulle part.
    let log_path = fleetforge_core::logging::init("tui");

    // `--where-logs` répond à « où sont les journaux ? » sans lancer
    // l'interface, ce qui est la première chose à savoir quand elle ne démarre pas.
    if std::env::args().any(|a| a == "--where-logs") {
        println!("{}", log_path.display());
        return Ok(());
    }

    let core = Arc::new(Core::new().context("initialisation du cœur")?);
    let hub = Arc::new(ProviderHub::new());

    // `--check` rend le parc en texte, sans terminal interactif. C'est le
    // contrôle de parité avec l'interface graphique : les deux doivent
    // annoncer les mêmes chiffres, et il est scriptable.
    if std::env::args().any(|a| a == "--check") {
        return check(core).await;
    }

    let mut terminal = setup_terminal().context(
        "impossible de passer le terminal en mode brut — \
         lancer `fleetforge` depuis un vrai terminal, ou `fleetforge --check` sinon",
    )?;
    // Quoi qu'il arrive ensuite, le terminal doit être rendu à l'utilisateur :
    // un panic en mode brut laisse un shell inutilisable.
    let result = run(&mut terminal, core, hub).await;
    restore_terminal(&mut terminal)?;
    result
}

/// Résumé non interactif du parc.
async fn check(core: Arc<Core>) -> Result<()> {
    let Some(info) = core.selected_inventory()? else {
        println!("aucun inventaire sélectionné");
        return Ok(());
    };
    println!("inventaire  {} ({})", info.name, info.organization);

    let fleet = core.fleet_with_health(&info.file_path).await?;
    println!(
        "parc        {} machines · {} hôtes",
        fleet.servers.len(),
        fleet.hosts.len()
    );

    for server in &fleet.servers {
        println!(
            "  {} {:<24} {:<9} {} hôte(s)  [{}]",
            fleetforge_core::style::Tone::from(server.health).glyph(),
            server.key.to_string(),
            server.provider.map(|p| p.as_str()).unwrap_or("?"),
            server.hosts.len(),
            server.hosts.join(", ")
        );
    }

    let findings = core.diagnose(&info.file_path).await?;
    use fleetforge_core::diagnostics::Severity;
    let errors = findings.iter().filter(|f| f.severity == Severity::Error).count();
    let warnings = findings.iter().filter(|f| f.severity == Severity::Warning).count();
    println!("diagnostics {errors} erreur(s), {warnings} avertissement(s)");
    for f in findings.iter().take(30) {
        println!("  [{:?}] {} — {}", f.severity, f.rule, f.message);
    }

    Ok(())
}

type Term = Terminal<CrosstermBackend<std::io::Stdout>>;

/// La capture de la souris n'est PAS activée, et c'est délibéré.
///
/// Un terminal qui la capture reçoit les clics et les glissés à la place de
/// l'émulateur : la sélection native disparaît, et avec elle le copier-coller
/// de ce qui est à l'écran — une adresse, un OCID, un message d'erreur. Le
/// TUI ne lisait aucun événement souris : cette capture ne coûtait que sa
/// perte.
///
/// Sans elle, glisser sélectionne et ⌘C copie, dans Terminal.app comme dans
/// iTerm2, sur l'écran secondaire compris. Les rares émulateurs qui n'en sont
/// pas capables le font toujours avec ⇧ enfoncée.
fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

async fn run(terminal: &mut Term, core: Arc<Core>, hub: Arc<ProviderHub>) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Msg>();
    let mut app = App::new(core.clone(), hub.clone());

    // Inventaire retenu. Le cœur écarte lui-même une valeur devenue obsolète.
    match core.selected_inventory() {
        Ok(Some(info)) => {
            app.inventory_path = info.file_path;
            app.organization = info.organization;
        }
        Ok(None) => {
            // Ouvrir sur l'écran des inventaires plutôt que sur un parc vide :
            // les huit autres écrans n'ont rien à montrer tant que le choix
            // n'est pas fait, et un tableau vide ne dit pas quoi faire.
            app.status = "choisir un parc : ↵ sur la ligne voulue".into();
            input::open_parc_picker(&mut app);
        }
        Err(e) => app.status = format!("⚠ {e}"),
    }

    reload_all(&app, tx.clone());
    reconnect_saved(&app, tx.clone());

    let mut events = EventStream::new();
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await; // le premier tick est immédiat

    // Rafraîchit les runs en cours : leur sortie arrive par le registre du
    // cœur, alimenté par le thread qui lit la sortie d'Ansible.
    let mut run_poll = tokio::time::interval(Duration::from_millis(400));

    loop {
        terminal.draw(|frame| ui::draw(frame, &app))?;

        tokio::select! {
            Some(Ok(event)) = events.next() => {
                if let Event::Key(key) = event {
                    input::handle_key(&mut app, key, &tx);
                }
            }
            Some(msg) = rx.recv() => {
                deliver(&mut app, msg, &tx);
                // Vider la file avant de redessiner : plusieurs chargements
                // arrivent souvent ensemble, un rendu par message ferait
                // clignoter l'écran.
                while let Ok(next) = rx.try_recv() {
                    deliver(&mut app, next, &tx);
                }
            }
            _ = run_poll.tick() => {
                let runs = core.runs().all();
                if runs.len() != app.runs.len()
                    || runs.iter().zip(&app.runs).any(|(a, b)| a.status != b.status || a.output.len() != b.output.len())
                {
                    app.runs = runs;
                }
            }
            _ = keepalive.tick() => {
                let hub = hub.clone();
                tokio::spawn(async move { hub.keepalive_all().await });
            }
        }

        if app.should_quit {
            fleetforge_providers::cli::stop_login();
            return Ok(());
        }
    }
}

/// Recharge tout le parc en parallèle.
/// Achemine un message. Presque tous vont à `App::apply`, qui ne fait que
/// ranger des données. Celui des commandes de session doit OUVRIR un menu ou
/// en lancer une : cela relève de `input`, pas de la réduction d'état.
fn deliver(app: &mut App, msg: Msg, tx: &mpsc::UnboundedSender<Msg>) {
    match msg {
        Msg::SessionActions(account, actions) => {
            input::offer_session_actions(app, account, actions, tx)
        }
        Msg::ReloadControls => {
            let core = app.core.clone();
            let hub = app.hub.clone();
            let inventory = app.inventory_path.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(fleet) = core.fleet(&inventory) {
                    let _ = tx.send(Msg::ControlsLoaded(hub.machine_controls(&fleet).await));
                }
            });
        }
        other => app.apply(other),
    }
}

/// Au lancement, rouvre TOUS les comptes enregistrés, qu'ils aient été
/// connectés ou non à la dernière fermeture : l'état « connecté » ne survit pas
/// au processus, et le rouvrir à la main à chaque lancement n'apporte rien.
///
/// Un échec ne s'affiche PAS en fenêtre : le compte reste jaune, la ligne
/// d'état le dit, et `c` réessaie. Un jeton expiré à chaque lancement ouvrirait
/// sinon une fenêtre d'erreur avant même qu'on ait regardé quoi que ce soit.
/// Le détail reste dans le journal.
fn reconnect_saved(app: &App, tx: mpsc::UnboundedSender<Msg>) {
    let hub = app.hub.clone();
    tokio::spawn(async move {
        let _ = tx.send(Msg::Status("reconnexion des comptes…".to_string()));
        let results = hub.reconnect_saved().await;

        let mut failed: Vec<String> = Vec::new();
        let mut kinds = Vec::new();
        for (account, result) in results {
            match result {
                Ok(()) if !kinds.contains(&account.provider) => kinds.push(account.provider),
                Ok(()) => {}
                Err(_) => failed.push(account.to_string()),
            }
        }
        let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
        for kind in kinds {
            let (instances, _) = hub.list_instances_everywhere(kind).await;
            let _ = tx.send(Msg::InstancesLoaded(kind, instances));
        }
        let _ = tx.send(Msg::ReloadControls);
        let _ = tx.send(Msg::Status(if failed.is_empty() {
            String::new()
        } else {
            format!("⚠ non connecté : {} — c pour réessayer, détail dans le journal", failed.join(", "))
        }));
    });
}

pub fn reload_all(app: &App, tx: mpsc::UnboundedSender<Msg>) {
    let core = app.core.clone();
    let inventory = app.inventory_path.clone();

    // Les catalogues ne dépendent pas de l'inventaire : les charger toujours.
    {
        let core = core.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(roles) = core.list_roles() {
                let _ = tx.send(Msg::RolesLoaded(roles));
            }
            if let Ok(playbooks) = core.list_playbooks() {
                let _ = tx.send(Msg::PlaybooksLoaded(playbooks));
            }
        });
    }

    // `statuses()` prend le verrou des connexions : tâche asynchrone et non
    // `spawn_blocking`, qui ne peut pas attendre un verrou async.
    {
        let tx = tx.clone();
        let hub = app.hub.clone();
        tokio::spawn(async move {
            let _ = tx.send(Msg::ProvidersLoaded(hub.statuses().await));
        });
    }

    if inventory.is_empty() {
        // Sans parc, aucun service n'est « du parc » : liste vide plutôt que
        // les services de tous les parcs mélangés.
        let _ = tx.send(Msg::ServicesLoaded(Vec::new()));
        return;
    }

    // Les services suivis ne sont connus que par nom d'hôte, et ces noms se
    // répètent d'un parc à l'autre : le cœur ne garde que ceux du parc courant.
    {
        let core = core.clone();
        let inventory = inventory.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(services) = core.fleet_services(&inventory) {
                let _ = tx.send(Msg::ServicesLoaded(services));
            }
        });
    }

    // Ce que chaque machine permet de piloter. Interroge les API des
    // hébergeurs CONNECTÉS : vide au démarrage, et rempli dès la première
    // connexion — c'est `connect_and_list` qui le redemande alors.
    {
        let core = core.clone();
        let hub = app.hub.clone();
        let inventory = inventory.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(fleet) = core.fleet(&inventory) {
                let _ = tx.send(Msg::ControlsLoaded(hub.machine_controls(&fleet).await));
            }
        });
    }

    // Le parc et les diagnostics interrogent Prometheus : ils sont asynchrones
    // et ne doivent pas retarder l'affichage du reste.
    {
        let core = core.clone();
        let inventory = inventory.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            match core.fleet_with_health(&inventory).await {
                Ok(fleet) => {
                    let _ = tx.send(Msg::FleetLoaded(Box::new(fleet)));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Error(e.to_string()));
                }
            }
        });
    }

    tokio::spawn(async move {
        match core.diagnose(&inventory).await {
            Ok(findings) => {
                let _ = tx.send(Msg::DiagnosticsLoaded(findings));
            }
            Err(e) => {
                let _ = tx.send(Msg::Error(e.to_string()));
            }
        }
    });
}
