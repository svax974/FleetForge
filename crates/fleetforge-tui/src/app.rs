/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! État de l'application et réduction des événements.
//!
//! Tout ce qui touche au parc passe par `fleetforge_core` : ce module ne décide de
//! rien qui ne soit déjà décidé côté cœur. C'est ce qui garantit que le TUI et
//! le GUI comptent les mêmes machines.

use fleetforge_core::actions::{ItemAction, PowerState as PowerAvailability};
use fleetforge_core::deploy::RunHandle;
use fleetforge_core::diagnostics::Finding;
use fleetforge_core::model::{Fleet, MachineKey, ProviderKind};
use fleetforge_core::{
    AnsiblePlaybook, AnsibleRole, Core, ServerServiceState,
};
use fleetforge_providers::{
    AccountId, AccountStatus, Capabilities, Credentials, Instance, InstanceRef, MachineControl,
    PowerAction, PowerState, ProviderInfo, ProviderStatus, SessionAction,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Sections de l'en-tête : ce qu'on choisit avec `1`-`5` ou `⇥`.
///
/// Huit listes à plat faisaient des onglets pairs de ce qui est une
/// HIÉRARCHIE (machine → hôte → service) ou un couple (rôles / playbooks).
/// Les sections regroupent ; les `Screen` restent les listes elles-mêmes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Parc,
    Ansible,
    Runs,
    Diagnostics,
    Providers,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::Parc,
        Section::Ansible,
        Section::Runs,
        Section::Diagnostics,
        Section::Providers,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Section::Parc => "Parc",
            Section::Ansible => "Ansible",
            Section::Runs => "Runs",
            Section::Diagnostics => "Diagnostics",
            Section::Providers => "Providers",
        }
    }

    pub fn index(self) -> usize {
        Section::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn next(self) -> Section {
        Section::ALL[(self.index() + 1) % Section::ALL.len()]
    }

    pub fn previous(self) -> Section {
        Section::ALL[(self.index() + Section::ALL.len() - 1) % Section::ALL.len()]
    }

    pub fn from_digit(d: char) -> Option<Section> {
        d.to_digit(10)
            .and_then(|n| (n >= 1).then(|| n as usize - 1))
            .and_then(|i| Section::ALL.get(i).copied())
    }
}

/// Listes. Le choix du parc n'en est plus une : c'est un réglage, qui se
/// choisit dans un sélecteur (`P`) comme la liste déroulante du GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Servers,
    Hosts,
    Services,
    Roles,
    Playbooks,
    Runs,
    Diagnostics,
    Providers,
}

impl Screen {
    /// Une seule source pour le nombre d'écrans : le tableau des curseurs
    /// s'indexe par `Screen::index()`, un écran ajouté sans l'agrandir
    /// paniquerait hors bornes au premier affichage.
    pub const COUNT: usize = 8;

    pub const ALL: [Screen; Screen::COUNT] = [
        Screen::Servers,
        Screen::Hosts,
        Screen::Services,
        Screen::Roles,
        Screen::Playbooks,
        Screen::Runs,
        Screen::Diagnostics,
        Screen::Providers,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Servers => "Machines",
            Screen::Hosts => "Hôtes",
            Screen::Services => "Services",
            Screen::Roles => "Rôles",
            Screen::Playbooks => "Playbooks",
            Screen::Runs => "Runs",
            Screen::Diagnostics => "Diagnostics",
            Screen::Providers => "Providers",
        }
    }

    pub fn index(self) -> usize {
        Screen::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    pub fn section(self) -> Section {
        match self {
            Screen::Servers | Screen::Hosts | Screen::Services => Section::Parc,
            Screen::Roles | Screen::Playbooks => Section::Ansible,
            Screen::Runs => Section::Runs,
            Screen::Diagnostics => Section::Diagnostics,
            Screen::Providers => Section::Providers,
        }
    }
}

/// Un cran de descente dans le parc. La pile de ces crans EST le fil
/// d'Ariane : `↵` en pousse un, `⎋` en retire un. Il remplace le filtre texte
/// que le drill-down posait à la place de l'utilisateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Machine(MachineKey),
    Host(String),
}

/// Superpositions modales. Une seule à la fois : les empiler rendrait `Esc`
/// imprévisible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Overlay {
    Help,
    /// Palette de commandes — l'équivalent clavier de ce que la souris fait
    /// dans le GUI.
    Palette,
    /// Filtre flou sur la liste courante.
    Filter,
    /// Confirmation d'une action irréversible.
    Confirm(Confirm),
    /// Choix d'une commande de session, quand le compte en propose plusieurs.
    SessionMenu(SessionMenu),
    /// Saisie des identifiants d'un hébergeur.
    ///
    /// Le TUI ne savait pas en saisir : « c'est le GUI qui porte le
    /// formulaire ». Sur un serveur atteint en SSH — précisément là où le TUI
    /// sert — il n'y a pas de GUI, et `c` échouait sur « aucun identifiant
    /// enregistré » sans offrir d'en poser.
    Credentials(Box<CredentialsForm>),
    /// Choix dans une liste filtrable : parc, rôle, playbook, hôte, alerte.
    Picker(Box<Picker>),
    /// Actions possibles sur l'élément désigné (`espace`).
    Actions(Box<ActionMenu>),
    /// Erreur trop longue pour la barre d'état : lue en entier, puis fermée.
    Message(String),
    /// Nouveau nom d'un compte d'hébergeur.
    Rename(RenameForm),
}

/// Saisie du nouveau nom d'un compte. Le nom est normalisé (minuscules,
/// tirets) par le cœur au moment d'en faire une clé, pas à la frappe :
/// corriger une faute deviendrait sinon impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameForm {
    pub account: AccountId,
    pub input: String,
}

/// Au-delà, une erreur ne tient pas sur la ligne d'état — qui la tronque — et
/// s'affiche dans une fenêtre. En deçà, elle reste en bas : une fenêtre pour
/// « machine non rapprochée » serait plus lourde que le mal.
pub const LONG_ERROR: usize = 72;

/// À quoi sert le choix en cours : ce qui se passe quand on valide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickPurpose {
    Parc,
    /// Rôle à déployer sur ces hôtes.
    Role { hosts: Vec<String> },
    /// Playbook à lancer, limité à ces hôtes.
    Playbook { hosts: Vec<String> },
    /// Hôte où déployer ce rôle.
    HostFor { role: String },
    /// Alerte dont on bascule l'exemption sur cet hôte.
    Alert { host: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickItem {
    /// Ce qui est tapé pour filtrer et affiché en premier.
    pub label: String,
    pub detail: String,
    /// Ce que le choix transmet (nom de parc, de rôle, chemin de playbook…).
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picker {
    pub title: String,
    pub purpose: PickPurpose,
    pub items: Vec<PickItem>,
    pub query: String,
    pub cursor: usize,
}

impl Picker {
    pub fn new(title: &str, purpose: PickPurpose, items: Vec<PickItem>) -> Picker {
        Picker {
            title: title.to_string(),
            purpose,
            items,
            query: String::new(),
            cursor: 0,
        }
    }

    pub fn visible(&self) -> Vec<&PickItem> {
        let needle = self.query.to_lowercase();
        self.items
            .iter()
            .filter(|i| {
                needle.is_empty()
                    || i.label.to_lowercase().contains(&needle)
                    || i.detail.to_lowercase().contains(&needle)
            })
            .collect()
    }

    pub fn selected(&self) -> Option<&PickItem> {
        self.visible().get(self.cursor).copied()
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let count = self.visible().len();
        if count == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = (self.cursor as isize + delta).clamp(0, count as isize - 1) as usize;
    }

    /// Le filtre a changé : le curseur peut désigner une ligne exclue.
    pub fn retarget(&mut self) {
        self.cursor = self.cursor.min(self.visible().len().saturating_sub(1));
    }
}

/// L'élément sur lequel le menu agit — ce qu'il faut pour exécuter, pas pour
/// décrire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionTarget {
    Machine(MachineKey),
    Host(String),
    Service { name: String, host: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionMenu {
    pub title: String,
    pub entries: Vec<ItemAction>,
    pub cursor: usize,
}

impl ActionMenu {
    pub fn move_cursor(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        let next = (self.cursor as isize + delta).rem_euclid(self.entries.len() as isize);
        self.cursor = next as usize;
    }

    pub fn selected(&self) -> Option<&ItemAction> {
        self.entries.get(self.cursor)
    }
}

/// Où se trouve le focus sur l'écran Providers.
///
/// Trois niveaux, parce qu'il y en a trois : un hébergeur porte plusieurs
/// COMPTES (deux tenancies Oracle), et un compte porte des instances. Deux
/// curseurs indépendants laissaient exprimable un état qui n'a pas de sens —
/// une instance désignée sans compte — et c'est le genre d'état qui finit par
/// arriver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFocus {
    Providers,
    Accounts(usize),
    Instances { account: usize, instance: usize },
}

impl ProviderFocus {
    pub fn account(self) -> Option<usize> {
        match self {
            ProviderFocus::Providers => None,
            ProviderFocus::Accounts(a) => Some(a),
            ProviderFocus::Instances { account, .. } => Some(account),
        }
    }

    pub fn instance(self) -> Option<usize> {
        match self {
            ProviderFocus::Instances { instance, .. } => Some(instance),
            _ => None,
        }
    }
}

/// Sélecteur de commande de session.
///
/// N'apparaît qu'à partir de DEUX commandes : avec une seule, un menu à un
/// choix ne demande qu'une frappe de plus pour rien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMenu {
    pub account: AccountId,
    pub actions: Vec<MenuEntry>,
    pub cursor: usize,
}

/// `SessionAction` ne dérive ni `PartialEq` ni `Eq`, que `Overlay` exige.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuEntry {
    pub name: String,
    pub label: String,
    pub hint: String,
}

impl SessionMenu {
    pub fn move_cursor(&mut self, delta: isize) {
        if self.actions.is_empty() {
            return;
        }
        let next = (self.cursor as isize + delta).rem_euclid(self.actions.len() as isize);
        self.cursor = next as usize;
    }

    pub fn selected(&self) -> Option<&MenuEntry> {
        self.actions.get(self.cursor)
    }
}

/// Formulaire d'identifiants du TUI.
///
/// Les méthodes et les champs viennent du cœur, comme dans le GUI : c'est lui
/// qui sait ce que chaque hébergeur attend, quels champs sont des secrets et
/// où l'on trouve leur valeur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialsForm {
    pub kind: ProviderKind,
    pub provider_label: String,
    /// Nom du compte. Éditable comme les autres champs — c'est ainsi qu'on
    /// ajoute une seconde tenancy : même formulaire, autre nom.
    pub account: String,
    /// Nom du compte à l'ouverture, quand il existe déjà. Le modifier dans le
    /// formulaire RENOMME le compte (identifiants et session suivent) au lieu
    /// d'en créer un second.
    pub original: Option<String>,
    pub methods: Vec<FormMethod>,
    /// Méthode retenue. Présélectionnée sur celle que le cœur détecte.
    pub method: usize,
    /// Champ qui a le focus, index dans les champs de la méthode courante.
    pub field: usize,
    pub error: Option<String>,
}

/// Une méthode et ce qui y a été saisi. `AuthMethod` ne dérive ni `PartialEq`
/// ni `Eq`, que `Overlay` exige ; on ne garde de toute façon que ce que le
/// formulaire affiche.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormMethod {
    pub name: String,
    pub label: String,
    pub detected: bool,
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    pub key: String,
    pub label: String,
    pub hint: String,
    pub secret: bool,
    pub optional: bool,
    pub value: String,
}

impl CredentialsForm {
    /// Construit le formulaire pour un hébergeur, en pré-remplissant ce qui
    /// est déjà enregistré.
    ///
    /// Les secrets ne sont PAS repris : les réafficher, même masqués, les
    /// renverrait tels quels si l'utilisateur ne touche qu'un autre champ,
    /// et une clé révoquée resterait ainsi en place sans qu'on le voie.
    /// `account` vide = création d'un nouveau compte, dont le nom est à saisir.
    pub fn new(
        info: &ProviderInfo,
        account: &str,
        saved: Option<&Credentials>,
    ) -> CredentialsForm {
        let methods: Vec<FormMethod> = info
            .auth_methods
            .iter()
            .map(|m| FormMethod {
                name: m.name.clone(),
                label: m.label.clone(),
                detected: m.detected,
                fields: m
                    .fields
                    .iter()
                    .map(|f| FormField {
                        key: f.key.clone(),
                        label: f.label.clone(),
                        hint: f.hint.clone(),
                        secret: f.secret,
                        optional: f.optional,
                        value: match saved {
                            Some(c) if !f.secret => c.get(&f.key).unwrap_or_default().to_string(),
                            _ => String::new(),
                        },
                    })
                    .collect(),
            })
            .collect();

        let method = methods.iter().position(|m| m.detected).unwrap_or(0);

        CredentialsForm {
            kind: info.kind,
            provider_label: info.label.clone(),
            account: account.to_string(),
            original: (!account.is_empty()).then(|| account.to_string()),
            methods,
            method,
            // Un compte existant s'ouvre sur ses identifiants : c'est eux qu'on
            // vient corriger, le nom est une ligne au-dessus.
            field: usize::from(!account.is_empty()),
            error: None,
        }
    }

    /// Le nom du compte est-il le champ qui a le focus ?
    ///
    /// Il précède les champs d'identifiants : `field == 0` désigne le nom, et
    /// les champs sont décalés d'un rang.
    pub fn on_account_field(&self) -> bool {
        self.field == 0
    }

    /// Compte d'origine, quand le formulaire en modifie un.
    pub fn original_id(&self) -> Option<AccountId> {
        self.original.as_deref().map(|n| AccountId::new(self.kind, n))
    }

    /// Le nom saisi n'est plus celui du compte ouvert.
    pub fn is_rename(&self) -> bool {
        self.original_id().is_some_and(|from| from != self.account_id())
    }

    /// Index du champ d'identifiants visé, le nom du compte déduit.
    fn credential_index(&self) -> Option<usize> {
        self.field.checked_sub(1)
    }

    /// Nombre de lignes navigables : les champs, plus le nom à la création.
    fn row_count(&self) -> usize {
        let fields = self.current().map_or(0, |m| m.fields.len());
        fields + 1
    }

    pub fn current(&self) -> Option<&FormMethod> {
        self.methods.get(self.method)
    }

    pub fn current_field(&self) -> Option<&FormField> {
        self.current()?.fields.get(self.credential_index()?)
    }

    pub fn push(&mut self, c: char) {
        self.error = None;
        if self.on_account_field() {
            self.account.push(c);
            return;
        }
        let Some(index) = self.credential_index() else { return };
        if let Some(f) = self
            .methods
            .get_mut(self.method)
            .and_then(|m| m.fields.get_mut(index))
        {
            f.value.push(c);
        }
    }

    pub fn backspace(&mut self) {
        self.error = None;
        if self.on_account_field() {
            self.account.pop();
            return;
        }
        let Some(index) = self.credential_index() else { return };
        if let Some(f) = self
            .methods
            .get_mut(self.method)
            .and_then(|m| m.fields.get_mut(index))
        {
            f.value.pop();
        }
    }

    pub fn move_field(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        // On boucle ici, contrairement aux listes : un formulaire court se
        // parcourt en rond sans jamais perdre de vue où l'on est.
        let next = (self.field as isize + delta).rem_euclid(count as isize);
        self.field = next as usize;
    }

    /// Change de méthode. Le focus repart du premier champ : l'index courant
    /// pourrait dépasser le nombre de champs de la nouvelle.
    pub fn move_method(&mut self, delta: isize) {
        let count = self.methods.len();
        if count <= 1 {
            return;
        }
        let next = (self.method as isize + delta).rem_euclid(count as isize);
        self.method = next as usize;
        self.field = 0;
        self.error = None;
    }

    /// Champs obligatoires restés vides.
    pub fn missing(&self) -> Vec<&str> {
        self.current()
            .map(|m| {
                m.fields
                    .iter()
                    .filter(|f| !f.optional && f.value.trim().is_empty())
                    .map(|f| f.label.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ce qui part au cœur. Les champs facultatifs vides sont OMIS plutôt
    /// qu'envoyés vides : `Credentials::get` filtre déjà les chaînes vides,
    /// mais les transmettre les ferait enregistrer comme des valeurs choisies.
    /// Compte visé par ce formulaire, nom normalisé.
    pub fn account_id(&self) -> AccountId {
        AccountId::new(self.kind, &self.account)
    }

    pub fn credentials(&self) -> Option<(String, Credentials)> {
        let m = self.current()?;
        let fields = m
            .fields
            .iter()
            .filter(|f| !f.value.trim().is_empty())
            .map(|f| (f.key.clone(), f.value.trim().to_string()))
            .collect();
        Some((
            m.name.clone(),
            Credentials {
                method: m.name.clone(),
                fields,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub prompt: String,
    pub action: ConfirmedAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedAction {
    Deploy {
        role: String,
        hosts: Vec<String>,
    },
    /// Lance un playbook. `hosts` vide = sans `--limit`, donc tout ce que le
    /// playbook cible.
    RunPlaybook {
        label: String,
        path: String,
        hosts: Vec<String>,
    },
    /// Efface les identifiants d'un compte — pas seulement sa session.
    ForgetAccount { account: AccountId },
    /// Porte la désignation complète et l'action typée, pas leur description.
    /// Un `action: String` perdait la variante gracieuse en route — c'est
    /// précisément ce qui distingue un arrêt propre d'une coupure.
    Power {
        reference: InstanceRef,
        action: PowerAction,
        /// Uniquement pour le message de confirmation.
        name: String,
    },
}

/// Messages venus des tâches de fond. Le rendu ne bloque jamais sur une
/// requête : le prototype Python appelait les SDK sur le fil de l'UI et gelait
/// à chaque aller-retour.
#[derive(Debug)]
pub enum Msg {
    FleetLoaded(Box<Fleet>),
    DiagnosticsLoaded(Vec<Finding>),
    RolesLoaded(Vec<AnsibleRole>),
    PlaybooksLoaded(Vec<AnsiblePlaybook>),
    ServicesLoaded(Vec<ServerServiceState>),
    ProvidersLoaded(Vec<ProviderStatus>),
    InstancesLoaded(ProviderKind, Vec<Instance>),
    /// Ce que chaque machine du parc permet de piloter chez son hébergeur.
    /// Vide tant qu'aucun hébergeur n'est connecté.
    ControlsLoaded(Vec<MachineControl>),
    /// Redemande le rapprochement. Émis après une connexion : les machines
    /// deviennent alors pilotables, et l'écran Serveurs doit le refléter sans
    /// qu'on ait à recharger tout le parc.
    ReloadControls,
    RunsUpdated(Vec<RunHandle>),
    /// Commandes de session d'un compte, rapportées par le cœur après l'avoir
    /// construit au besoin. Elles arrivent par message parce que les obtenir
    /// peut demander une connexion, donc du réseau.
    SessionActions(AccountId, Vec<SessionAction>),
    Status(String),
    Error(String),
}

pub struct App {
    pub core: Arc<Core>,
    pub hub: Arc<fleetforge_providers::ProviderHub>,

    pub screen: Screen,
    pub overlay: Option<Overlay>,
    pub should_quit: bool,

    pub inventory_path: String,
    pub organization: String,

    pub fleet: Option<Fleet>,
    pub findings: Vec<Finding>,
    pub roles: Vec<AnsibleRole>,
    pub playbooks: Vec<AnsiblePlaybook>,
    pub services: Vec<ServerServiceState>,
    /// `ProviderStatus` et non `ProviderInfo` : il porte en plus les COMPTES
    /// et l'état de leur session, que l'écran doit rendre.
    pub providers: Vec<ProviderStatus>,
    pub instances: Vec<(ProviderKind, Vec<Instance>)>,
    /// Rapprochement machine d'inventaire ↔ instance, tel que le cœur le fait.
    /// C'est lui qui rend les écrans Serveurs et Hôtes actionnables.
    pub controls: Vec<MachineControl>,
    pub runs: Vec<RunHandle>,

    /// Un curseur par écran : revenir sur un écran doit rendre la position
    /// qu'on y avait laissée.
    cursors: [usize; Screen::COUNT],
    /// Sélection multiple d'hôtes, pour déployer sur N machines d'un coup.
    pub marked_hosts: HashSet<String>,

    /// Écran Providers : à quel niveau de l'arborescence on se trouve.
    pub focus: ProviderFocus,

    /// Descente dans le parc : machine, puis hôte. Vide = liste à plat.
    pub scope: Vec<Scope>,
    /// Dernière liste vue dans chaque section à plusieurs listes : revenir sur
    /// « Parc » rend la liste qu'on y avait laissée.
    parc_view: Screen,
    ansible_view: Screen,

    pub filter: String,
    pub palette_input: String,
    pub status: String,
    pub loading: bool,
}

impl App {
    pub fn new(core: Arc<Core>, hub: Arc<fleetforge_providers::ProviderHub>) -> App {
        App {
            core,
            hub,
            screen: Screen::Servers,
            overlay: None,
            should_quit: false,
            inventory_path: String::new(),
            organization: String::new(),
            fleet: None,
            findings: Vec::new(),
            roles: Vec::new(),
            playbooks: Vec::new(),
            services: Vec::new(),
            providers: Vec::new(),
            instances: Vec::new(),
            controls: Vec::new(),
            runs: Vec::new(),
            cursors: [0; Screen::COUNT],
            marked_hosts: HashSet::new(),
            focus: ProviderFocus::Providers,
            scope: Vec::new(),
            parc_view: Screen::Servers,
            ansible_view: Screen::Roles,
            filter: String::new(),
            palette_input: String::new(),
            status: String::new(),
            loading: false,
        }
    }

    // === Curseur ===

    pub fn cursor(&self) -> usize {
        self.cursors[self.screen.index()]
    }

    pub fn set_cursor(&mut self, value: usize) {
        let max = self.row_count().saturating_sub(1);
        self.cursors[self.screen.index()] = value.min(max);
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        let current = self.cursor() as isize;
        // On borne au lieu de boucler : dépasser la fin d'une liste de trente
        // machines pour se retrouver au début surprend plus qu'il n'aide.
        let next = (current + delta).clamp(0, count as isize - 1);
        self.cursors[self.screen.index()] = next as usize;
    }

    pub fn cursor_home(&mut self) {
        self.cursors[self.screen.index()] = 0;
    }

    pub fn cursor_end(&mut self) {
        self.cursors[self.screen.index()] = self.row_count().saturating_sub(1);
    }

    pub fn go(&mut self, screen: Screen) {
        self.screen = screen;
        match screen.section() {
            Section::Parc => self.parc_view = screen,
            Section::Ansible => self.ansible_view = screen,
            _ => {}
        }
        // Le filtre est propre à une liste ; le garder d'un écran à l'autre
        // ferait apparaître le suivant vide sans raison visible.
        self.filter.clear();
    }

    pub fn section(&self) -> Section {
        self.screen.section()
    }

    /// Va à une section, sur la liste qu'on y avait laissée.
    pub fn go_section(&mut self, section: Section) {
        let screen = match section {
            Section::Parc => self.parc_view,
            Section::Ansible => self.ansible_view,
            Section::Runs => Screen::Runs,
            Section::Diagnostics => Screen::Diagnostics,
            Section::Providers => Screen::Providers,
        };
        self.go(screen);
    }

    /// Passe de Rôles à Playbooks et inversement.
    pub fn toggle_ansible_view(&mut self) {
        let other = match self.ansible_view {
            Screen::Roles => Screen::Playbooks,
            _ => Screen::Roles,
        };
        self.go(other);
    }

    fn machine_scope(&self) -> Option<&MachineKey> {
        self.scope.iter().find_map(|s| match s {
            Scope::Machine(key) => Some(key),
            Scope::Host(_) => None,
        })
    }

    fn host_scope(&self) -> Option<&str> {
        self.scope.iter().find_map(|s| match s {
            Scope::Host(name) => Some(name.as_str()),
            Scope::Machine(_) => None,
        })
    }

    /// Descend d'un cran dans le parc : machine → hôtes → services.
    /// Rend faux quand il n'y a rien où descendre.
    pub fn descend(&mut self) -> bool {
        match self.screen {
            Screen::Servers => {
                let Some(key) = self.selected_server_key() else { return false };
                self.scope = vec![Scope::Machine(key)];
                self.enter(Screen::Hosts)
            }
            Screen::Hosts => {
                let Some(name) = self.selected_host_name() else { return false };
                self.scope.retain(|s| matches!(s, Scope::Machine(_)));
                self.scope.push(Scope::Host(name));
                self.enter(Screen::Services)
            }
            _ => false,
        }
    }

    fn enter(&mut self, screen: Screen) -> bool {
        self.go(screen);
        self.cursor_home();
        true
    }

    /// Remonte d'un cran. Rend faux en haut, pour qu'`Esc` continue vers ce
    /// qu'il fait d'habitude (effacer les marques).
    ///
    /// Le curseur de la liste retrouvée n'est PAS réinitialisé : on revient
    /// sur la ligne d'où l'on était parti.
    pub fn ascend(&mut self) -> bool {
        if self.screen.section() != Section::Parc {
            return false;
        }
        let target = match self.scope.pop() {
            Some(Scope::Host(_)) => Screen::Hosts,
            Some(Scope::Machine(_)) => Screen::Servers,
            // Liste à plat atteinte par la palette : la racine est Machines.
            None if self.screen != Screen::Servers => Screen::Servers,
            None => return false,
        };
        self.go(target);
        true
    }

    /// Montre un hôte dans sa machine. Sert à Diagnostics : le constat
    /// désigne un sujet, on y va sans toucher au filtre de l'utilisateur.
    pub fn reveal_host(&mut self, name: &str) {
        let Some(key) = self
            .fleet
            .as_ref()
            .and_then(|f| f.host(name))
            .map(MachineKey::of)
        else {
            return;
        };
        self.scope = vec![Scope::Machine(key)];
        self.go(Screen::Hosts);
        let index = self.visible_hosts().iter().position(|h| h.name == name);
        self.set_cursor(index.unwrap_or(0));
    }

    pub fn reveal_server(&mut self, id: &str) {
        self.scope.clear();
        self.go(Screen::Servers);
        // La clé affichée peut porter un port ; à défaut, l'adresse suffit.
        let address = id.split(':').next().unwrap_or(id);
        let servers = self.visible_servers();
        let index = servers
            .iter()
            .position(|s| s.key.to_string() == id)
            .or_else(|| servers.iter().position(|s| s.key.address == address));
        self.set_cursor(index.unwrap_or(0));
    }

    /// Constats rattachés à une machine et à ses hôtes.
    pub fn findings_touching(&self, server_key: &str, hosts: &[String]) -> Vec<&Finding> {
        use fleetforge_core::diagnostics::Subject;
        self.findings
            .iter()
            .filter(|f| match &f.subject {
                Subject::Server(id) => id == server_key,
                Subject::Host(name) => hosts.contains(name),
                _ => false,
            })
            .collect()
    }

    // === Données filtrées ===

    fn matches(&self, haystack: &str) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_lowercase();
        haystack.to_lowercase().contains(&needle)
    }

    pub fn visible_servers(&self) -> Vec<&fleetforge_core::model::Server> {
        let Some(fleet) = &self.fleet else { return Vec::new() };
        fleet
            .servers
            .iter()
            .filter(|s| {
                self.matches(&s.key.address)
                    || s.hosts.iter().any(|h| self.matches(h))
                    || s.provider.is_some_and(|p| self.matches(p.as_str()))
            })
            .collect()
    }

    pub fn visible_hosts(&self) -> Vec<&fleetforge_core::AnsibleHost> {
        let Some(fleet) = &self.fleet else { return Vec::new() };
        let machine = self.machine_scope();
        fleet
            .hosts
            .iter()
            .filter(|h| machine.map_or(true, |key| &MachineKey::of(h) == key))
            .filter(|h| {
                self.matches(&h.name)
                    || self.matches(&h.ansible_host)
                    || h.ansible_roles.iter().any(|r| self.matches(r))
            })
            .collect()
    }

    pub fn visible_roles(&self) -> Vec<&AnsibleRole> {
        self.roles
            .iter()
            .filter(|r| self.matches(&r.name) || self.matches(&r.label) || self.matches(&r.category))
            .collect()
    }

    pub fn visible_playbooks(&self) -> Vec<&AnsiblePlaybook> {
        self.playbooks
            .iter()
            .filter(|p| self.matches(&p.name) || self.matches(&p.label))
            .collect()
    }

    pub fn visible_services(&self) -> Vec<&ServerServiceState> {
        let host = self.host_scope();
        // Sans hôte désigné, la machine du fil d'Ariane borne la liste.
        let machine_hosts: Option<&Vec<String>> = match (host, self.machine_scope(), &self.fleet) {
            (None, Some(key), Some(fleet)) => fleet.server(key).map(|s| &s.hosts),
            _ => None,
        };
        self.services
            .iter()
            .filter(|s| host.map_or(true, |name| s.server_name == name))
            .filter(|s| machine_hosts.map_or(true, |hosts| hosts.contains(&s.server_name)))
            .filter(|s| self.matches(&s.service_name) || self.matches(&s.server_name))
            .collect()
    }

    pub fn visible_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| self.matches(&f.message) || self.matches(f.rule))
            .collect()
    }

    pub fn row_count(&self) -> usize {
        match self.screen {
            Screen::Servers => self.visible_servers().len(),
            Screen::Hosts => self.visible_hosts().len(),
            Screen::Services => self.visible_services().len(),
            Screen::Roles => self.visible_roles().len(),
            Screen::Playbooks => self.visible_playbooks().len(),
            Screen::Runs => self.runs.len(),
            Screen::Diagnostics => self.visible_findings().len(),
            Screen::Providers => self.providers.len(),
        }
    }

    // === Écran Providers ===

    /// Hébergeur sous le curseur de gauche.
    pub fn selected_provider(&self) -> Option<&ProviderStatus> {
        self.providers.get(self.cursor())
    }

    /// Comptes de l'hébergeur sous le curseur.
    pub fn provider_accounts(&self) -> Vec<AccountStatus> {
        self.selected_provider()
            .map(|p| p.accounts.clone())
            .unwrap_or_default()
    }

    /// Compte désigné.
    ///
    /// Un hébergeur à compte UNIQUE le désigne sans qu'on descende : `↵` n'y
    /// offrirait aucun choix, et imposer une frappe pour passer d'une liste à
    /// un élément quand la liste en a un seul est un pas qui n'apprend rien.
    /// C'est le cas courant — `default`, sur cinq hébergeurs sur six.
    ///
    /// Le niveau garde tout son sens dès qu'il y a deux tenancies : là, il
    /// FAUT choisir, et `c` ou `X` sans choix explicite agiraient sur l'une
    /// des deux sans dire laquelle.
    pub fn selected_account(&self) -> Option<AccountStatus> {
        let accounts = self.provider_accounts();
        match self.focus.account() {
            Some(index) => accounts.into_iter().nth(index),
            None if accounts.len() == 1 => accounts.into_iter().next(),
            None => None,
        }
    }

    pub fn selected_account_id(&self) -> Option<AccountId> {
        let provider = self.selected_provider()?.info.kind;
        let account = self.selected_account()?;
        Some(AccountId {
            provider,
            name: account.name,
        })
    }

    /// Instances de l'hébergeur sous le curseur, tous comptes confondus. Vide
    /// tant que `c` n'a pas connecté puis listé : le TUI n'interroge jamais
    /// une API sans qu'on le lui demande.
    pub fn provider_instances(&self) -> &[Instance] {
        let Some(p) = self.selected_provider() else {
            return &[];
        };
        self.instances
            .iter()
            .find(|(k, _)| *k == p.info.kind)
            .map_or(&[], |(_, list)| list.as_slice())
    }

    /// Instances du COMPTE désigné. C'est sur elles que porte le curseur —
    /// mélanger les comptes ferait agir `S` sur une instance d'un autre.
    pub fn account_instances(&self) -> Vec<&Instance> {
        let Some(account) = self.selected_account() else {
            return Vec::new();
        };
        self.provider_instances()
            .iter()
            .filter(|i| i.reference.account == account.name)
            .collect()
    }

    /// Ce que la machine sous le curseur permet de piloter.
    ///
    /// C'est ce qui rend les écrans Serveurs et Hôtes actionnables : sans lui,
    /// éteindre `proxy1` imposait d'aller dans Providers y retrouver la bonne
    /// tenancy, puis l'instance — refaire à la main le rapprochement que le
    /// cœur a déjà fait.
    pub fn selected_control(&self) -> Option<&MachineControl> {
        let key = match self.screen {
            Screen::Servers => self.selected_server_key()?,
            // L'action porte sur la MACHINE, pas sur l'entrée d'inventaire :
            // huit entrées partagent 203.0.113.10, les éteindre une par une
            // n'aurait aucun sens.
            Screen::Hosts | Screen::Services => {
                let name = match self.screen {
                    Screen::Services => self.selected_service_host()?,
                    _ => self.selected_host_name()?,
                };
                let fleet = self.fleet.as_ref()?;
                MachineKey::of(fleet.hosts.iter().find(|h| h.name == name)?)
            }
            _ => return None,
        };
        self.controls.iter().find(|c| c.key == key)
    }

    /// Instance à piloter, d'où qu'on la désigne : par son instance sur
    /// l'écran Providers, par sa machine sur Serveurs et Hôtes.
    ///
    /// Rend aussi les CAPACITÉS, qui ne se déduisent pas de la référence : un
    /// écran ne peut pas décider seul ce qu'il propose.
    pub fn power_target(&self) -> Option<(InstanceRef, String, Capabilities, PowerState)> {
        if self.screen == Screen::Providers {
            let caps = self.selected_provider()?.info.capabilities;
            let instance = self.selected_instance()?;
            return Some((
                instance.reference.clone(),
                instance.name.clone(),
                caps,
                instance.state,
            ));
        }
        let control = self.selected_control()?;
        Some((
            control.instance.clone(),
            control.name.clone(),
            control.capabilities,
            control.state,
        ))
    }

    /// Ce que l'hébergeur permet sur l'élément désigné, dans les termes du
    /// catalogue d'actions. `None` : rien à piloter (machine non rapprochée).
    ///
    /// `stop` est l'arrêt BRUTAL et `stop_graceful` l'arrêt propre : plusieurs
    /// hébergeurs n'ont que l'un des deux, tester le premier seul effacerait
    /// l'entrée chez GCP, qui ne sait que l'autre.
    pub fn power_state(&self) -> Option<PowerAvailability> {
        let (_, _, caps, state) = self.power_target()?;
        Some(PowerAvailability {
            can_start: caps.start && state != PowerState::Running,
            can_stop: (caps.stop || caps.stop_graceful) && state != PowerState::Stopped,
            can_reboot: caps.reboot || caps.reboot_graceful,
        })
    }

    /// Instance désignée, seulement quand le focus est descendu dessus.
    pub fn selected_instance(&self) -> Option<&Instance> {
        let index = self.focus.instance()?;
        self.account_instances().into_iter().nth(index)
    }

    /// Descend d'un niveau. Rend faux quand il n'y a rien où descendre : un
    /// focus sur une liste vide n'afficherait rien et laisserait les touches
    /// d'alimentation porter sur un néant.
    pub fn focus_deeper(&mut self) -> bool {
        match self.focus {
            ProviderFocus::Providers => {
                if self.provider_accounts().is_empty() {
                    return false;
                }
                self.focus = ProviderFocus::Accounts(0);
                true
            }
            ProviderFocus::Accounts(account) => {
                if self.account_instances().is_empty() {
                    return false;
                }
                self.focus = ProviderFocus::Instances {
                    account,
                    instance: 0,
                };
                true
            }
            ProviderFocus::Instances { .. } => false,
        }
    }

    /// Remonte d'un niveau. Rend faux en haut, pour qu'`Esc` continue vers ce
    /// qu'il fait d'habitude (effacer le filtre, puis les marques).
    pub fn focus_shallower(&mut self) -> bool {
        self.focus = match self.focus {
            ProviderFocus::Providers => return false,
            ProviderFocus::Accounts(_) => ProviderFocus::Providers,
            ProviderFocus::Instances { account, .. } => ProviderFocus::Accounts(account),
        };
        true
    }

    pub fn reset_focus(&mut self) {
        self.focus = ProviderFocus::Providers;
    }

    pub fn move_focus_cursor(&mut self, delta: isize) {
        let shift = |current: usize, count: usize| -> usize {
            if count == 0 {
                return 0;
            }
            (current as isize + delta).clamp(0, count as isize - 1) as usize
        };

        self.focus = match self.focus {
            ProviderFocus::Providers => return,
            ProviderFocus::Accounts(a) => {
                ProviderFocus::Accounts(shift(a, self.provider_accounts().len()))
            }
            ProviderFocus::Instances { account, instance } => ProviderFocus::Instances {
                account,
                instance: shift(instance, self.account_instances().len()),
            },
        };
    }

    /// Machine sous le curseur, si l'écran en désigne une.
    pub fn selected_server_key(&self) -> Option<MachineKey> {
        self.visible_servers().get(self.cursor()).map(|s| s.key.clone())
    }

    pub fn selected_host_name(&self) -> Option<String> {
        self.visible_hosts().get(self.cursor()).map(|h| h.name.clone())
    }

    /// Hôte du service désigné.
    pub fn selected_service_host(&self) -> Option<String> {
        self.visible_services()
            .get(self.cursor())
            .map(|s| s.server_name.clone())
    }

    pub fn selected_role_name(&self) -> Option<String> {
        self.visible_roles().get(self.cursor()).map(|r| r.name.clone())
    }

    /// Hôtes ciblés par une action : la sélection multiple si elle existe,
    /// sinon la ligne courante. Éviter à l'opérateur de marquer un seul hôte
    /// pour agir dessus.
    pub fn target_hosts(&self) -> Vec<String> {
        if !self.marked_hosts.is_empty() {
            let mut v: Vec<String> = self.marked_hosts.iter().cloned().collect();
            v.sort();
            return v;
        }
        match self.screen {
            Screen::Hosts => self.selected_host_name().into_iter().collect(),
            Screen::Services => self.selected_service_host().into_iter().collect(),
            Screen::Servers => self
                .visible_servers()
                .get(self.cursor())
                .map(|s| s.hosts.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub fn toggle_mark(&mut self) {
        let names: Vec<String> = match self.screen {
            Screen::Hosts => self.selected_host_name().into_iter().collect(),
            Screen::Servers => self
                .visible_servers()
                .get(self.cursor())
                .map(|s| s.hosts.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        if names.is_empty() {
            return;
        }
        // Une machine se marque en bloc : on ne veut pas d'un serveur à moitié
        // sélectionné, dont on ne saurait plus s'il est ciblé ou non.
        let all_marked = names.iter().all(|n| self.marked_hosts.contains(n));
        for n in names {
            if all_marked {
                self.marked_hosts.remove(&n);
            } else {
                self.marked_hosts.insert(n);
            }
        }
    }

    pub fn clear_marks(&mut self) {
        self.marked_hosts.clear();
    }

    /// Nombre de constats par gravité, pour l'en-tête.
    pub fn finding_counts(&self) -> (usize, usize) {
        use fleetforge_core::diagnostics::Severity;
        let errors = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        (errors, warnings)
    }

    pub fn active_run_count(&self) -> usize {
        self.runs.iter().filter(|r| r.is_running()).count()
    }

    pub fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::FleetLoaded(fleet) => {
                self.organization = fleet.organization.clone();
                self.fleet = Some(*fleet);
                self.loading = false;
                // Le curseur peut désigner une ligne qui n'existe plus.
                self.clamp_cursors();
            }
            Msg::DiagnosticsLoaded(f) => {
                self.findings = f;
                self.clamp_cursors();
            }
            Msg::RolesLoaded(r) => {
                self.roles = r;
                self.clamp_cursors();
            }
            Msg::PlaybooksLoaded(p) => {
                self.playbooks = p;
                self.clamp_cursors();
            }
            Msg::ServicesLoaded(s) => {
                self.services = s;
                self.clamp_cursors();
            }
            Msg::ProvidersLoaded(p) => {
                self.providers = p;
                self.clamp_cursors();
            }
            Msg::InstancesLoaded(kind, list) => {
                self.instances.retain(|(k, _)| *k != kind);
                self.instances.push((kind, list));
            }
            Msg::ControlsLoaded(list) => self.controls = list,
            // Traité par `main::deliver`, qui a le cœur et le hub sous la main.
            Msg::ReloadControls => {}
            Msg::RunsUpdated(r) => self.runs = r,
            // Le choix de la commande est fait par `input`, qui sait ouvrir le
            // menu ou lancer directement. `apply` ne fait que transmettre.
            Msg::SessionActions(..) => {}
            Msg::Status(s) => self.status = s,
            Msg::Error(e) => {
                self.loading = false;
                self.status = format!("⚠ {e}");
                if e.chars().count() > LONG_ERROR {
                    match &mut self.overlay {
                        // Plusieurs échecs d'affilée (un compte par échec) :
                        // ils s'empilent dans la même fenêtre plutôt que de
                        // s'écraser, le premier se lisant sinon jamais.
                        Some(Overlay::Message(text)) => {
                            text.push_str("\n\n");
                            text.push_str(&e);
                        }
                        // Jamais par-dessus une saisie en cours : un formulaire
                        // ou un sélecteur ouvert ne doit pas disparaître sous
                        // une erreur arrivée de l'arrière-plan.
                        None => self.overlay = Some(Overlay::Message(e)),
                        Some(_) => {}
                    }
                }
            }
        }
    }

    fn clamp_cursors(&mut self) {
        let saved = self.screen;
        for screen in Screen::ALL {
            self.screen = screen;
            let max = self.row_count().saturating_sub(1);
            let i = screen.index();
            self.cursors[i] = self.cursors[i].min(max);
        }
        self.screen = saved;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `App` porte un `Core`, qui ouvre la base de l'utilisateur : on ne
    // l'instancie pas ici. La logique de navigation est testable seule, et
    // c'est elle qui casse en silence quand on ajoute un écran.

    /// `fleetforge_providers::describe` construit un `ProviderInfo` réel, sans
    /// identifiants ni appel réseau : le formulaire se teste donc sur les
    /// champs que les hébergeurs déclarent vraiment.
    fn form_for(kind: ProviderKind, saved: Option<Credentials>) -> CredentialsForm {
        // Compte nommé : le nom est verrouillé, les champs commencent à 0.
        CredentialsForm::new(&fleetforge_providers::describe(kind), "default", saved.as_ref())
    }

    /// Formulaire de CRÉATION : le nom du compte est le premier champ.
    fn new_account_form(kind: ProviderKind) -> CredentialsForm {
        CredentialsForm::new(&fleetforge_providers::describe(kind), "", None)
    }

    #[test]
    fn a_saved_secret_is_never_put_back_in_the_form() {
        // Le réafficher le renverrait tel quel dès qu'on ne touche qu'un autre
        // champ : une clé révoquée resterait en place sans qu'on le voie.
        let mut fields = std::collections::HashMap::new();
        fields.insert("OVH_APPLICATION_KEY".to_string(), "clé-publique".to_string());
        fields.insert("OVH_APPLICATION_SECRET".to_string(), "à-ne-pas-reprendre".to_string());
        let saved = Credentials {
            method: "api_keys".into(),
            fields,
        };

        let form = form_for(ProviderKind::Ovh, Some(saved));
        let method = form.current().expect("une méthode");

        let key = method.fields.iter().find(|f| f.key == "OVH_APPLICATION_KEY").unwrap();
        assert_eq!(key.value, "clé-publique", "un champ non secret se pré-remplit");

        let secret = method.fields.iter().find(|f| f.key == "OVH_APPLICATION_SECRET").unwrap();
        assert!(secret.secret);
        assert!(secret.value.is_empty(), "un secret enregistré ne revient pas dans le formulaire");
    }

    #[test]
    fn a_field_marked_optional_does_not_block_submission() {
        let mut form = form_for(ProviderKind::Ovh, None);
        // OVH_ENDPOINT est facultatif (défaut ovh-eu), les autres non.
        let missing = form.missing();
        assert!(!missing.is_empty());
        assert!(
            !missing.iter().any(|label| label.contains("Point d'entrée")),
            "le point d'entrée est facultatif : {missing:?}"
        );

        for index in 0..form.current().unwrap().fields.len() {
            form.field = index + 1;
            if !form.current_field().unwrap().optional {
                for c in "x".chars() {
                    form.push(c);
                }
            }
        }
        assert!(form.missing().is_empty(), "tous les champs requis sont remplis");
    }

    #[test]
    fn an_empty_optional_field_is_omitted_rather_than_sent_blank() {
        // Transmis vide, il serait enregistré comme une valeur choisie, et
        // masquerait ensuite le défaut de l'hébergeur.
        let mut form = form_for(ProviderKind::Ovh, None);
        for index in 0..form.current().unwrap().fields.len() {
            form.field = index + 1;
            if !form.current_field().unwrap().optional {
                form.push('x');
            }
        }
        let (_, credentials) = form.credentials().expect("des identifiants");
        assert!(!credentials.fields.contains_key("OVH_ENDPOINT"));
        assert!(credentials.fields.contains_key("OVH_APPLICATION_KEY"));
    }

    #[test]
    fn changing_method_restarts_from_the_first_field() {
        // Les méthodes n'ont pas le même nombre de champs : garder l'index
        // ferait pointer le focus hors de la nouvelle liste.
        let mut form = form_for(ProviderKind::Aws, None);
        assert!(form.methods.len() > 1, "AWS déclare deux méthodes");
        form.field = 1;
        form.move_method(1);
        assert_eq!(form.field, 0);
    }

    #[test]
    fn a_provider_with_a_single_method_ignores_the_method_keys() {
        let mut form = form_for(ProviderKind::Contabo, None);
        assert_eq!(form.methods.len(), 1);
        form.move_method(1);
        assert_eq!(form.method, 0);
    }

    #[test]
    fn typing_lands_in_the_focused_field() {
        let mut form = form_for(ProviderKind::Contabo, None);
        form.move_field(1);
        form.push('a');
        form.push('b');
        assert_eq!(form.current_field().unwrap().value, "ab");
        form.backspace();
        assert_eq!(form.current_field().unwrap().value, "a");
        // Le premier champ n'a pas bougé.
        assert!(form.current().unwrap().fields[0].value.is_empty());
    }

    #[test]
    fn a_new_account_asks_for_its_name_first() {
        // Sans ce champ, configurer un hébergeur ne pouvait que REMPLACER le
        // compte existant : il n'y avait aucun moyen d'en déclarer un second.
        let mut form = new_account_form(ProviderKind::Oracle);
        assert!(form.original.is_none());
        assert!(form.on_account_field(), "le focus démarre sur le nom");

        for c in "Acme Prod".chars() {
            form.push(c);
        }
        assert_eq!(form.account, "Acme Prod");
        // Le nom est normalisé au moment d'en faire une clé, pas à la frappe :
        // corriger une faute deviendrait sinon impossible.
        assert_eq!(form.account_id().name, "acme-prod");
    }

    #[test]
    fn an_existing_account_opens_on_its_credentials_and_can_be_renamed() {
        let mut form = form_for(ProviderKind::Oracle, None);
        assert!(!form.on_account_field(), "le focus démarre sur les identifiants");
        assert_eq!(form.account_id().name, "default");
        assert!(!form.is_rename());

        form.move_field(-1);
        assert!(form.on_account_field());
        for c in "-bis".chars() {
            form.push(c);
        }
        assert!(form.is_rename());
        assert_eq!(form.original_id().unwrap().name, "default");
    }

    #[test]
    fn typing_on_a_new_account_form_lands_in_the_right_row() {
        // Le nom décale les champs d'identifiants d'un rang : sans ce décalage
        // la frappe destinée au premier champ partait dans le nom.
        let mut form = new_account_form(ProviderKind::Contabo);
        form.move_field(1);
        assert!(!form.on_account_field());
        form.push('z');
        assert_eq!(form.current_field().unwrap().value, "z");
        assert_eq!(form.account, "", "le nom n'a pas bougé");
    }

    #[test]
    fn the_focus_walks_down_and_back_up_the_three_levels() {
        assert_eq!(ProviderFocus::Providers.account(), None);
        assert_eq!(ProviderFocus::Accounts(2).account(), Some(2));
        assert_eq!(ProviderFocus::Accounts(2).instance(), None);

        let deep = ProviderFocus::Instances {
            account: 2,
            instance: 5,
        };
        assert_eq!(deep.account(), Some(2));
        assert_eq!(deep.instance(), Some(5));
    }

    #[test]
    fn sections_cycle_both_ways() {
        assert_eq!(Section::Parc.previous(), Section::Providers);
        assert_eq!(Section::Providers.next(), Section::Parc);
        assert_eq!(Section::Parc.next(), Section::Ansible);
    }

    #[test]
    fn digits_select_sections_from_one() {
        assert_eq!(Section::from_digit('1'), Some(Section::Parc));
        assert_eq!(Section::from_digit('5'), Some(Section::Providers));
        assert_eq!(Section::from_digit('6'), None);
        assert_eq!(Section::from_digit('0'), None);
    }

    #[test]
    fn every_screen_belongs_to_a_section_reachable_by_digit() {
        for screen in Screen::ALL {
            assert!(Section::ALL.contains(&screen.section()));
        }
    }

    #[test]
    fn a_picker_filters_by_what_is_typed_and_keeps_its_cursor_inside() {
        let item = |l: &str| PickItem { label: l.into(), detail: String::new(), value: l.into() };
        let mut picker = Picker::new(
            "t",
            PickPurpose::Parc,
            vec![item("web3c"), item("papanglabs"), item("gcp")],
        );
        picker.cursor = 2;
        picker.query = "web".into();
        picker.retarget();
        assert_eq!(picker.cursor, 0);
        assert_eq!(picker.selected().map(|i| i.label.as_str()), Some("web3c"));
        picker.query = "zzz".into();
        picker.retarget();
        assert!(picker.selected().is_none());
    }

    #[test]
    fn every_screen_has_an_index_and_a_title() {
        for (i, screen) in Screen::ALL.iter().enumerate() {
            assert_eq!(screen.index(), i);
            assert!(!screen.title().is_empty());
        }
    }

    #[test]
    fn the_cursor_array_covers_every_screen() {
        // Ajouter un écran sans agrandir `cursors` indexerait hors bornes.
        // Le tableau et cette borne viennent maintenant de la MÊME constante ;
        // le test garde que `ALL` ne s'en écarte pas.
        assert_eq!(Screen::ALL.len(), Screen::COUNT);
    }
}
