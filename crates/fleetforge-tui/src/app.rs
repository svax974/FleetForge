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

use fleetforge_core::deploy::RunHandle;
use fleetforge_core::diagnostics::Finding;
use fleetforge_core::model::{Fleet, MachineKey, ProviderKind};
use fleetforge_core::{
    AnsibleInventoryInfo, AnsiblePlaybook, AnsibleRole, Core, ServerServiceState,
};
use fleetforge_providers::{
    AccountId, AccountStatus, Capabilities, Credentials, Instance, InstanceRef, MachineControl,
    PowerAction, PowerState, ProviderInfo, ProviderStatus, SessionAction,
};
use std::collections::HashSet;
use std::sync::Arc;

/// Écrans. Même colonne vertébrale que le GUI, un raccourci chiffré chacun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Premier écran : le parc courant conditionne tout ce que les suivants
    /// affichent. Le TUI héritait du choix fait dans le GUI sans pouvoir en
    /// changer, ce qui rendait les huit autres écrans muets sur un poste où
    /// le GUI n'avait jamais tourné.
    Inventories,
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
    pub const COUNT: usize = 9;

    pub const ALL: [Screen; Screen::COUNT] = [
        Screen::Inventories,
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
            Screen::Inventories => "Inventaires",
            Screen::Servers => "Serveurs",
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

    pub fn next(self) -> Screen {
        Screen::ALL[(self.index() + 1) % Screen::ALL.len()]
    }

    pub fn previous(self) -> Screen {
        Screen::ALL[(self.index() + Screen::ALL.len() - 1) % Screen::ALL.len()]
    }

    pub fn from_digit(d: char) -> Option<Screen> {
        d.to_digit(10)
            .and_then(|n| (n >= 1).then(|| n as usize - 1))
            .and_then(|i| Screen::ALL.get(i).copied())
    }
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
    /// Le compte existe déjà : son nom n'est plus modifiable. Le changer
    /// n'aurait pas renommé le compte, il en aurait créé un second en laissant
    /// le premier derrière, avec ses identifiants.
    pub account_locked: bool,
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
            account_locked: !account.is_empty(),
            methods,
            method,
            field: 0,
            error: None,
        }
    }

    /// Le nom du compte est-il le champ qui a le focus ?
    ///
    /// Il précède les champs d'identifiants et n'apparaît qu'à la création :
    /// `field == 0` y désigne le nom, et les champs sont décalés d'un rang.
    pub fn on_account_field(&self) -> bool {
        !self.account_locked && self.field == 0
    }

    /// Index du champ d'identifiants visé, le nom du compte déduit.
    fn credential_index(&self) -> Option<usize> {
        if self.account_locked {
            Some(self.field)
        } else {
            self.field.checked_sub(1)
        }
    }

    /// Nombre de lignes navigables : les champs, plus le nom à la création.
    fn row_count(&self) -> usize {
        let fields = self.current().map_or(0, |m| m.fields.len());
        fields + usize::from(!self.account_locked)
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
    InventoriesLoaded(Vec<AnsibleInventoryInfo>),
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
    /// Les parcs disponibles. Chargés au démarrage comme les catalogues : ce
    /// qui est proposé ici ne dépend pas de l'inventaire courant.
    pub inventories: Vec<AnsibleInventoryInfo>,

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
            inventories: Vec::new(),
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
        // Le filtre est propre à une liste ; le garder d'un écran à l'autre
        // ferait apparaître le suivant vide sans raison visible.
        self.filter.clear();
    }

    // === Données filtrées ===

    fn matches(&self, haystack: &str) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_lowercase();
        haystack.to_lowercase().contains(&needle)
    }

    pub fn visible_inventories(&self) -> Vec<&AnsibleInventoryInfo> {
        self.inventories
            .iter()
            .filter(|i| self.matches(&i.name) || self.matches(&i.organization))
            .collect()
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
        fleet
            .hosts
            .iter()
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
        self.services
            .iter()
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
            Screen::Inventories => self.visible_inventories().len(),
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
            Screen::Hosts => {
                let name = self.selected_host_name()?;
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
            Msg::InventoriesLoaded(list) => {
                self.inventories = list;
                self.clamp_cursors();
            }
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
            form.field = index;
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
            form.field = index;
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
        assert!(!form.account_locked);
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
    fn an_existing_account_cannot_be_renamed_by_the_form() {
        // Changer le nom n'aurait pas renommé le compte : il en aurait créé un
        // second, en laissant le premier derrière avec ses identifiants.
        let form = form_for(ProviderKind::Oracle, None);
        assert!(form.account_locked);
        assert!(!form.on_account_field());
        assert_eq!(form.account_id().name, "default");
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
    fn screens_cycle_both_ways() {
        assert_eq!(Screen::Inventories.next(), Screen::Servers);
        assert_eq!(Screen::Inventories.previous(), Screen::Providers);
        assert_eq!(Screen::Providers.next(), Screen::Inventories);
    }

    #[test]
    fn digits_select_screens_from_one() {
        // Le choix du parc est en tête : c'est lui qui conditionne ce que les
        // autres écrans montrent.
        assert_eq!(Screen::from_digit('1'), Some(Screen::Inventories));
        assert_eq!(Screen::from_digit('9'), Some(Screen::Providers));
        assert_eq!(Screen::from_digit('0'), None);
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
