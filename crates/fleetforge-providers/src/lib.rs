/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Accès aux hébergeurs, et rapprochement avec l'inventaire Ansible.
//!
//! Transport retenu, par hébergeur :
//!
//! | Hébergeur | Transport | Pourquoi |
//! |---|---|---|
//! | Contabo | REST | `password grant` OAuth2, REST ordinaire |
//! | OVH | REST | signature SHA-1, quelques dizaines de lignes |
//! | AWS | CLI `aws` | SigV4 |
//! | GCP | CLI `gcloud` | JWT de compte de service |
//! | Oracle | CLI `oci` | signature RSA-SHA256 |
//! | custom | — | machines physiques, aucune API |
//!
//! Réimplémenter les trois schémas de signature représenterait plusieurs
//! centaines de lignes de code cryptographique invérifiable sans identifiants
//! réels, là où le CLI officiel gère déjà SSO, jetons de session et
//! rafraîchissement. L'absence du binaire devient une CAPACITÉ manquante,
//! visible dans l'UI, et non une erreur au premier appel.

pub mod cli;
pub mod contabo;
pub mod credentials;
pub mod custom;
pub mod ovh;
pub mod provider;

pub use credentials::CredentialStore;
pub use provider::{
    AccountId, AuthField, AuthMethod, Capabilities, Credentials, Instance, InstanceRef,
    PowerAction, PowerState, Provider, ProviderError, Result, SessionAction, DEFAULT_ACCOUNT,
};

use fleetforge_core::model::{Fleet, MachineKey, ProviderKind, Server};
use serde::{Deserialize, Serialize};

/// Construit l'implémentation d'un hébergeur.
pub fn build(kind: ProviderKind) -> Box<dyn Provider> {
    match kind {
        ProviderKind::Contabo => Box::new(contabo::ContaboProvider::new()),
        ProviderKind::Ovh => Box::new(ovh::OvhProvider::new()),
        ProviderKind::Aws => Box::new(cli::AwsProvider::new()),
        ProviderKind::Gcp => Box::new(cli::GcpProvider::new()),
        ProviderKind::Oracle => Box::new(cli::OracleProvider::new()),
        ProviderKind::Custom => Box::new(custom::CustomProvider::new()),
    }
}

/// Ce que l'UI a besoin de savoir d'un hébergeur avant toute connexion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub kind: ProviderKind,
    pub label: String,
    pub capabilities: Capabilities,
    pub auth_methods: Vec<AuthMethod>,
    /// Outil requis et absent, le cas échéant. Affiché tel quel plutôt que de
    /// laisser l'opérateur découvrir le manque au premier clic.
    pub missing_tool: Option<String>,
}

pub fn describe(kind: ProviderKind) -> ProviderInfo {
    let p = build(kind);
    let caps = p.capabilities();
    // Aucune capacité sur un hébergeur qui EN A normalement signifie que son
    // outil manque — `custom` n'en a jamais, ce n'est pas une anomalie.
    let missing_tool = (kind.has_cloud_api() && !caps.list)
        .then(|| match kind {
            ProviderKind::Aws => "aws",
            ProviderKind::Gcp => "gcloud",
            ProviderKind::Oracle => "oci",
            _ => "",
        })
        .filter(|t| !t.is_empty())
        .map(String::from);

    ProviderInfo {
        kind,
        label: kind.label().to_string(),
        capabilities: caps,
        auth_methods: p.auth_methods(),
        missing_tool,
    }
}

pub fn describe_all() -> Vec<ProviderInfo> {
    ProviderKind::ALL.into_iter().map(describe).collect()
}

/// Ce qu'une interface affiche d'un hébergeur : ses capacités réelles, plus
/// l'état de la session et la présence d'identifiants enregistrés.
///
/// Vit ici et non dans une façade : les trois interfaces rendent la même
/// vignette, et deux définitions de la même chose finissent par diverger sur
/// un champ — c'est alors le TUI ou le navigateur qui affiche « déconnecté »
/// sur un hébergeur connecté.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderStatus {
    #[serde(flatten)]
    pub info: ProviderInfo,
    /// Au moins un compte connecté.
    pub connected: bool,
    /// Au moins un compte enregistré.
    pub has_saved_credentials: bool,
    /// Les comptes déclarés chez cet hébergeur, connectés ou non.
    pub accounts: Vec<AccountStatus>,
}

/// Un compte et l'état de sa session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccountStatus {
    pub name: String,
    pub connected: bool,
    pub has_saved_credentials: bool,
    /// Commandes de session disponibles sur CE compte. Vide s'il n'est pas
    /// connecté : elles dépendent de la façon dont il s'authentifie, qui n'est
    /// connue qu'une fois le provider construit.
    #[serde(default)]
    pub session_actions: Vec<SessionAction>,
}

/// Connexions actives aux hébergeurs, partagées par les deux interfaces.
///
/// Le prototype gardait son état dans l'application Textual : rien n'était
/// réutilisable ailleurs. Ici, GUI et TUI pilotent le même hub.
pub struct ProviderHub {
    /// Indexé par COMPTE et non par hébergeur : deux tenancies Oracle doivent
    /// pouvoir être ouvertes ensemble. Avec `ProviderKind` pour clé, connecter
    /// la seconde fermait la première sans rien dire.
    providers: tokio::sync::Mutex<std::collections::HashMap<AccountId, Box<dyn Provider>>>,
    store: CredentialStore,
}

impl Default for ProviderHub {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderHub {
    pub fn new() -> Self {
        Self {
            providers: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            store: CredentialStore::new(),
        }
    }

    /// Identifiants enregistrés pour ce compte, s'il y en a.
    ///
    /// LIT le secret : à n'appeler que pour s'en servir. Pour savoir s'il en
    /// existe un, c'est `has_credentials` — sur macOS, chaque lecture du
    /// trousseau demande une autorisation à l'utilisateur.
    pub fn saved_credentials(&self, account: &AccountId) -> Option<Credentials> {
        self.store.load(account)
    }

    /// Ce compte a-t-il des identifiants ? Sans toucher au trousseau.
    pub fn has_credentials(&self, account: &AccountId) -> bool {
        self.store.has(account)
    }

    /// Comptes déclarés chez un hébergeur. Toujours au moins `default`, pour
    /// qu'un hébergeur jamais configuré offre quand même une ligne à remplir.
    pub fn accounts(&self, kind: ProviderKind) -> Vec<AccountId> {
        let mut accounts = self.store.accounts(kind);
        if accounts.is_empty() {
            accounts.push(AccountId::default_for(kind));
        }
        accounts
    }

    /// Connecte, et n'enregistre les identifiants QUE si la connexion a abouti.
    /// Le prototype essayait toutes les méthodes en boucle avec le même jeu de
    /// champs et persistait celle qui passait, sans que l'opérateur sache
    /// laquelle avait servi.
    pub async fn connect(&self, account: &AccountId, credentials: &Credentials) -> Result<()> {
        let mut provider = build(account.provider);

        // La MÉTHODE et les NOMS de champs, jamais les valeurs : un journal ne
        // doit pas devenir l'endroit où les secrets finissent en clair.
        let mut keys: Vec<&str> = credentials.fields.keys().map(String::as_str).collect();
        keys.sort_unstable();
        fleetforge_core::logging::info(
            "providers",
            format!("connexion {account} · méthode « {} » · champs {keys:?}", credentials.method),
        );

        if let Err(e) = provider.connect(credentials).await {
            fleetforge_core::logging::error("providers", format!("connexion {account} refusée : {e}"));

            // Modifier un compte qui existe, c'est vouloir ses nouvelles valeurs
            // MÊME quand la connexion échoue : un profil Oracle neuf dont la
            // session reste à ouvrir, une région corrigée. Les jeter renvoyait
            // l'ancienne valeur au formulaire suivant, comme si rien n'avait
            // été enregistré. Un compte NEUF qui échoue, lui, n'est pas gardé :
            // il laisserait un compte fantôme.
            if self.store.load(account).is_some() {
                if let Err(save) = self.store.save(account, &persistent(credentials)) {
                    fleetforge_core::logging::warn(
                        "providers",
                        format!("identifiants {account} non enregistrés : {save}"),
                    );
                }
            }

            // Une session OCI expirée fait échouer la connexion, et c'est
            // précisément le moment où l'opérateur a besoin de la commande qui
            // en rouvre une. Jeter le provider ici l'en privait : plus aucune
            // commande de session n'était proposée, et le seul recours annoncé
            // était un terminal — pour une application qui sait le faire.
            //
            // Il est donc CONSERVÉ quand il offre une porte de sortie. Il se
            // déclare non connecté : listage, alimentation et rapprochement
            // continuent de l'ignorer.
            if !filter_session_actions(provider.session_actions()).is_empty() {
                self.providers.lock().await.insert(account.clone(), provider);
            }
            return Err(e);
        }

        if let Err(e) = self.store.save(account, &persistent(credentials)) {
            // Échouer ici serait absurde : la connexion, elle, a réussi.
            fleetforge_core::logging::warn(
                "providers",
                format!("identifiants {account} non enregistrés : {e}"),
            );
        }
        self.providers.lock().await.insert(account.clone(), provider);
        fleetforge_core::logging::info("providers", format!("{account} connecté"));
        Ok(())
    }

    /// Reconnecte depuis les identifiants enregistrés.
    pub async fn reconnect(&self, account: &AccountId) -> Result<()> {
        let credentials = self.store.load(account).map(|c| persistent(&c)).ok_or_else(|| {
            ProviderError::Auth(format!("aucun identifiant enregistré pour {account}"))
        })?;
        self.connect(account, &credentials).await
    }

    /// Reconnecte TOUS les comptes enregistrés d'un hébergeur, et rend les
    /// échecs sans s'arrêter au premier : une tenancy dont la session a expiré
    /// ne doit pas empêcher les autres de s'ouvrir.
    pub async fn reconnect_all(&self, kind: ProviderKind) -> Vec<(AccountId, Result<()>)> {
        let mut out = Vec::new();
        for account in self.store.accounts(kind) {
            let result = self.reconnect(&account).await;
            out.push((account, result));
        }
        out
    }

    /// Au lancement d'une façade : rouvre TOUS les comptes enregistrés qui ne le
    /// sont pas, tous hébergeurs confondus. L'état « connecté » ne survit pas au
    /// processus. Un échec laisse le compte non connecté et est rendu avec les
    /// autres : c'est à la façade de décider comment le montrer.
    pub async fn reconnect_saved(&self) -> Vec<(AccountId, Result<()>)> {
        let mut out = Vec::new();
        for info in describe_all() {
            for account in self.store.accounts(info.kind) {
                if self.is_connected(&account).await {
                    continue;
                }
                let result = self.reconnect(&account).await;
                out.push((account, result));
            }
        }
        out
    }

    /// Ferme la session SANS oublier les identifiants — la déconnexion du
    /// prototype effaçait la configuration, ce qui n'est pas la même chose.
    pub async fn disconnect(&self, account: &AccountId) {
        if let Some(mut p) = self.providers.lock().await.remove(account) {
            p.disconnect();
        }
    }

    /// Oublie les identifiants, explicitement.
    pub async fn forget(&self, account: &AccountId) -> anyhow::Result<()> {
        self.disconnect(account).await;
        self.store.forget(account)
    }

    /// Renomme un compte, sa connexion ouverte comprise.
    ///
    /// Le nom est l'identifiant du compte (clé du trousseau, table des
    /// connexions, rapprochement des instances) : le changer dans un formulaire
    /// en créait un second. Ici les identifiants sont déplacés, pas copiés, et
    /// la session déjà ouverte suit le compte sans se rouvrir.
    ///
    /// Les `InstanceRef` déjà listés portent l'ancien nom : à relister.
    pub async fn rename(&self, from: &AccountId, new_name: &str) -> anyhow::Result<AccountId> {
        let to = AccountId::new(from.provider, new_name);
        if to.name.is_empty() {
            anyhow::bail!("le nouveau nom est vide");
        }
        self.store.rename(from, &to)?;

        let mut live = self.providers.lock().await;
        if let Some(provider) = live.remove(from) {
            live.insert(to.clone(), provider);
        }
        fleetforge_core::logging::info("providers", format!("{from} renommé en {to}"));
        Ok(to)
    }

    pub async fn is_connected(&self, account: &AccountId) -> bool {
        self.providers
            .lock()
            .await
            .get(account)
            .is_some_and(|p| p.is_connected())
    }

    /// Comptes dont la session est ouverte.
    pub async fn connected_accounts(&self) -> Vec<AccountId> {
        let guard = self.providers.lock().await;
        let mut open: Vec<AccountId> = guard
            .iter()
            .filter(|(_, p)| p.is_connected())
            .map(|(a, _)| a.clone())
            .collect();
        open.sort();
        open
    }

    pub async fn connected_kinds(&self) -> Vec<ProviderKind> {
        let mut kinds: Vec<ProviderKind> = self
            .connected_accounts()
            .await
            .into_iter()
            .map(|a| a.provider)
            .collect();
        kinds.dedup();
        kinds
    }

    /// État complet des six hébergeurs, connectés ou non. Un seul verrou pris
    /// pour tous : interroger `is_connected` en boucle le reprendrait six fois.
    pub async fn statuses(&self) -> Vec<ProviderStatus> {
        // UN seul verrou pour tout : `connected_accounts` le reprendrait, et
        // le reprendre dans une fermeture synchrone n'est de toute façon pas
        // possible. L'état de session ET les commandes disponibles se lisent
        // donc sur la même prise.
        let guard = self.providers.lock().await;

        describe_all()
            .into_iter()
            .map(|info| {
                let accounts: Vec<AccountStatus> = self
                    .accounts(info.kind)
                    .into_iter()
                    .map(|account| {
                        let built = guard.get(&account);
                        let live = built.filter(|p| p.is_connected());
                        AccountStatus {
                            connected: live.is_some(),
                            // `has` et non `saved_credentials` : la vignette
                            // ne demande que la PRÉSENCE, et la lire par le
                            // secret coûtait une autorisation de trousseau par
                            // compte et par rafraîchissement.
                            has_saved_credentials: self.store.has(&account),
                            // Déduites du provider CONSTRUIT, connecté ou
                            // NON : un profil OCI par clé n'a pas de session à
                            // renouveler, un profil de session si — et c'est
                            // justement quand la session est refusée qu'il faut
                            // pouvoir en rouvrir une.
                            session_actions: built
                                .map(|p| filter_session_actions(p.session_actions()))
                                .unwrap_or_default(),
                            name: account.name,
                        }
                    })
                    .collect();

                ProviderStatus {
                    connected: accounts.iter().any(|a| a.connected),
                    has_saved_credentials: accounts.iter().any(|a| a.has_saved_credentials),
                    accounts,
                    info,
                }
            })
            .collect()
    }

    /// Instances d'UN compte. Chacune repart estampillée du compte d'où elle
    /// vient : sans quoi une action d'alimentation ne saurait pas vers quelle
    /// connexion partir quand deux tenancies sont ouvertes.
    pub async fn list_instances(&self, account: &AccountId) -> Result<Vec<Instance>> {
        let guard = self.providers.lock().await;
        let provider = guard
            .get(account)
            .ok_or(ProviderError::NotConnected(account.provider))?;

        let mut instances = provider.list_instances().await?;
        for instance in &mut instances {
            instance.reference.account = account.name.clone();
        }
        Ok(instances)
    }

    /// Instances de TOUS les comptes connectés d'un hébergeur, rassemblées.
    ///
    /// Les échecs sont rendus à côté des résultats plutôt que de tout annuler :
    /// une tenancy expirée ne doit pas effacer les instances des autres.
    pub async fn list_instances_everywhere(
        &self,
        kind: ProviderKind,
    ) -> (Vec<Instance>, Vec<(AccountId, ProviderError)>) {
        let mut all = Vec::new();
        let mut failures = Vec::new();

        for account in self.connected_accounts().await {
            if account.provider != kind {
                continue;
            }
            match self.list_instances(&account).await {
                Ok(list) => all.extend(list),
                Err(e) => failures.push((account, e)),
            }
        }
        (all, failures)
    }

    pub async fn power(&self, reference: &InstanceRef, action: PowerAction) -> Result<()> {
        let guard = self.providers.lock().await;
        let provider = guard
            .get(&reference.account_id())
            .ok_or(ProviderError::NotConnected(reference.provider))?;

        // Une action d'alimentation modifie l'état du parc : elle est tracée
        // qu'elle aboutisse ou non. « Qui a arrêté cette machine, et quand ? »
        // n'a pas de réponse ailleurs.
        let what = format!("{} sur {} ({})", action.label(), reference.id, reference.provider);
        fleetforge_core::logging::info("providers", format!("demande : {what}"));

        match provider.power(reference, action).await {
            Ok(()) => {
                fleetforge_core::logging::info("providers", format!("acceptée : {what}"));
                Ok(())
            }
            Err(e) => {
                fleetforge_core::logging::error("providers", format!("refusée : {what} — {e}"));
                Err(e)
            }
        }
    }

    /// Commandes de session proposées par un compte, connecté ou non.
    ///
    /// Elles dépendent de la façon dont le compte s'authentifie — un profil
    /// OCI par clé n'a pas de session à renouveler — donc du provider
    /// construit, pas du seul type d'hébergeur. Un compte dont la session vient
    /// d'être refusée les propose toujours : c'est là qu'elles servent.
    pub async fn session_actions(&self, account: &AccountId) -> Vec<SessionAction> {
        self.providers
            .lock()
            .await
            .get(account)
            .map(|p| p.session_actions())
            .unwrap_or_default()
    }

    /// Commandes de session d'un compte, en le CONSTRUISANT si besoin.
    ///
    /// Un compte enregistré mais jamais connecté DANS CETTE EXÉCUTION n'a pas
    /// de provider construit, donc rien à proposer : l'écran répondait « aucune
    /// commande de session » au démarrage, c'est-à-dire là où il fallait
    /// justement en ouvrir une. Ne rien faire avant que l'opérateur ait essayé
    /// de se connecter — et échoué — lui imposait un détour pour obtenir la
    /// commande qui répare ce qu'il n'a pas encore cassé.
    ///
    /// La connexion est donc TENTÉE ici, et son échec IGNORÉ : `connect` garde
    /// le provider quand il offre une porte de sortie, et c'est cette porte
    /// qu'on vient chercher.
    ///
    /// Le coût est un appel réseau, sur un geste explicite de l'opérateur, et
    /// une seule fois : le provider construit reste ensuite dans la table.
    pub async fn ensure_session_actions(&self, account: &AccountId) -> Vec<SessionAction> {
        let known = filter_session_actions(self.session_actions(account).await);
        if !known.is_empty() || !self.store.has(account) {
            return known;
        }
        let _ = self.reconnect(account).await;
        filter_session_actions(self.session_actions(account).await)
    }

    /// Exécute une commande de session, puis vérifie qu'elle a servi à quelque
    /// chose en relistant : `refresh` peut rendre un succès et laisser une
    /// session que l'hébergeur refuse toujours.
    pub async fn run_session_action(&self, account: &AccountId, name: &str) -> Result<String> {
        fleetforge_core::logging::info("providers", format!("{account} : {name}"));

        let message = {
            let guard = self.providers.lock().await;
            let provider = guard
                .get(account)
                .ok_or(ProviderError::NotConnected(account.provider))?;

            // Masquer le bouton ne suffit pas : l'appel reste atteignable par
            // l'API HTTP, et une commande qui ouvre un navigateur sur le
            // serveur y resterait en attente sans que personne ne le voie.
            //
            // Seule une commande qui EXIGE le navigateur est refusée ici. Une
            // commande absente de la liste (proposée selon l'état du moment,
            // comme « Libérer le port », ou inconnue) revient au fournisseur,
            // qui la traite ou la refuse avec son propre message : l'annoncer
            // comme « exige un navigateur » était faux.
            let needs_browser = provider
                .session_actions()
                .iter()
                .any(|a| a.name == name && a.needs_local_browser);
            if needs_browser
                && !filter_session_actions(provider.session_actions())
                    .iter()
                    .any(|a| a.name == name)
            {
                return Err(ProviderError::Api(format!(
                    "« {name} » n'est pas disponible ici : elle exige un navigateur \
                     sur la machine qui exécute l'application"
                )));
            }
            provider.run_session_action(name).await
        };

        match message {
            Ok(m) => {
                fleetforge_core::logging::info("providers", format!("{account} : {name} — {m}"));

                // Rouvrir une session ne rouvre pas la CONNEXION : le provider
                // gardé après un refus reste marqué hors ligne, et l'écran
                // continuerait d'afficher « non connecté » juste après une
                // authentification réussie. Le rattraper ici évite de demander
                // à l'opérateur un geste que l'application peut faire seule.
                if !self.is_connected(account).await {
                    if let Err(e) = self.reconnect(account).await {
                        fleetforge_core::logging::warn(
                            "providers",
                            format!("{account} : session ouverte mais reconnexion refusée : {e}"),
                        );
                        // Annoncer « session ouverte » seul laissait croire à un
                        // compte connecté : la session l'est, pas le compte.
                        return Err(ProviderError::Api(format!(
                            "session ouverte, mais la connexion du compte reste refusée : {e}"
                        )));
                    }
                }
                Ok(m)
            }
            Err(e) => {
                fleetforge_core::logging::error("providers", format!("{account} : {name} — {e}"));
                Err(e)
            }
        }
    }

    /// Empêche l'expiration des sessions. À appeler périodiquement — le
    /// prototype le faisait toutes les cinq minutes.
    pub async fn keepalive_all(&self) {
        let guard = self.providers.lock().await;
        for provider in guard.values() {
            let _ = provider.keepalive().await;
        }
    }

    /// Ce que chaque MACHINE d'inventaire permet de piloter chez son hébergeur.
    ///
    /// Les écrans Serveurs et Hôtes listaient un parc sans jamais permettre
    /// d'agir dessus : pour éteindre `proxy1` il fallait passer par l'écran
    /// Providers, y retrouver la bonne tenancy, puis l'instance — c'est-à-dire
    /// refaire à la main le rapprochement que l'application sait faire. Une
    /// liste qu'on ne peut que regarder ne sert qu'à regarder.
    ///
    /// Le rapprochement est le MÊME que celui de `reconcile_fleet` : par
    /// (hébergeur, adresse). Ce qui s'ajoute ici, ce sont les capacités de
    /// l'hébergeur et l'état de la machine — de quoi décider, dans chaque
    /// façade et de la même manière, ce qui peut être proposé.
    ///
    /// Une machine ambiguë — adresse revendiquée par deux comptes — en est
    /// EXCLUE : agir dessus depuis une liste où rien ne dit laquelle des deux
    /// tenancies répond serait piloter au hasard. L'écran Providers la signale
    /// et laisse choisir.
    pub async fn machine_controls(&self, fleet: &Fleet) -> Vec<MachineControl> {
        let mut out = Vec::new();

        for (kind, rec) in self.reconcile_fleet(fleet).await {
            let capabilities = describe(kind).capabilities;
            let disputed: Vec<&str> = rec
                .ambiguous
                .iter()
                .map(|a| a.server.key.address.as_str())
                .collect();

            for m in &rec.matched {
                if disputed.contains(&m.server.key.address.as_str()) {
                    continue;
                }
                out.push(MachineControl {
                    key: m.server.key.clone(),
                    hosts: m.server.hosts.clone(),
                    instance: m.instance.reference.clone(),
                    name: m.instance.name.clone(),
                    state: m.instance.state,
                    raw_state: m.instance.raw_state.clone(),
                    capabilities,
                });
            }
        }
        out
    }

    /// Rapproche un parc de TOUS les hébergeurs connectés.
    ///
    /// Le rapprochement se fait par hébergeur sur les instances de TOUS ses
    /// comptes réunies. C'est ce qui rend le résultat juste quand le parc
    /// s'étend sur plusieurs tenancies : n'interroger qu'un compte ferait
    /// passer les machines des autres pour « sans instance », c'est-à-dire
    /// pour un inventaire faux.
    pub async fn reconcile_fleet(&self, fleet: &Fleet) -> Vec<(ProviderKind, Reconciliation)> {
        let mut out = Vec::new();
        for kind in self.connected_kinds().await {
            let (instances, failures) = self.list_instances_everywhere(kind).await;

            // Un compte injoignable retire ses instances du rapprochement : ses
            // machines basculeraient en « sans instance » sans que rien ne dise
            // pourquoi. On le signale au journal plutôt que de le taire.
            for (account, error) in failures {
                fleetforge_core::logging::warn(
                    "providers",
                    format!("{account} hors du rapprochement : {error}"),
                );
            }
            let rec = reconcile(fleet, kind, &instances);
            for a in &rec.ambiguous {
                fleetforge_core::logging::warn(
                    "providers",
                    format!(
                        "{} revendiquée par {} comptes {:?} — retenu : {}",
                        a.server.key.address,
                        a.accounts.len(),
                        a.accounts,
                        a.accounts.first().map(String::as_str).unwrap_or("?")
                    ),
                );
            }
            out.push((kind, rec));
        }
        out
    }
}

/// Retire les commandes que CETTE exécution ne peut pas mener à bien.
///
/// Le filtrage est fait ici, dans le cœur, et non dans chaque interface :
/// proposer un bouton qui ouvrira un navigateur sur une machine distante est le
/// même défaut que de proposer un arrêt gracieux chez un hébergeur qui n'en a
/// pas — une promesse que rien ne tiendra, et dont l'échec ne dira pas pourquoi.
///
/// `FLEETFORGE_NO_LOCAL_BROWSER=1` force le retrait : le serveur web le pose, parce
/// qu'il peut très bien tourner sur le poste de l'opérateur sans que son
/// navigateur y soit — un tunnel SSH suffit à les séparer.
/// Ce qu'on garde d'une saisie. `OCI_REGION` est un ORDRE (« règle cette région
/// dans le profil »), pas un état : le fichier `~/.oci/config` fait foi. Le
/// conserver le rejouerait à chaque reconnexion et écraserait une région
/// corrigée à la main depuis.
fn persistent(credentials: &Credentials) -> Credentials {
    let mut kept = credentials.clone();
    kept.fields.remove("OCI_REGION");
    kept
}

fn filter_session_actions(actions: Vec<SessionAction>) -> Vec<SessionAction> {
    let forced_off = std::env::var("FLEETFORGE_NO_LOCAL_BROWSER")
        .map(|v| v.trim() != "0" && !v.trim().is_empty())
        .unwrap_or(false);
    let local = !forced_off && provider::has_local_browser();

    actions
        .into_iter()
        .filter(|a| local || !a.needs_local_browser)
        .collect()
}

/// Rapprochement d'une instance cloud et d'une machine d'inventaire.
///
/// C'est LE lien que la fusion existe pour établir : l'App connaissait les
/// hôtes sans jamais parler aux hébergeurs, le prototype listait les instances
/// sans rien savoir d'Ansible. Les deux moitiés avaient la donnée, personne ne
/// joignait.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reconciliation {
    /// Machine d'inventaire ET instance cloud : le cas nominal.
    pub matched: Vec<Match>,
    /// Instances chez l'hébergeur qu'aucune entrée d'inventaire ne décrit —
    /// machines payées et non gérées, ou oubliées après un essai.
    pub unmanaged: Vec<Instance>,
    /// Machines d'inventaire sans instance correspondante — adresse morte,
    /// instance détruite, ou hébergeur simplement non connecté.
    pub unmatched: Vec<Server>,
    /// Machines dont l'adresse est revendiquée par PLUSIEURS comptes.
    ///
    /// Le rapprochement retient la première instance trouvée, dans l'ordre
    /// alphabétique des comptes. Ce choix n'a aucune raison d'être le bon : il
    /// est signalé ici plutôt que passé sous silence, pour que personne ne
    /// pilote `acme` en croyant piloter `perso`.
    #[serde(default)]
    pub ambiguous: Vec<Ambiguity>,
}

/// Ce qu'une machine d'inventaire permet de piloter, du point de vue d'un
/// écran qui la liste.
///
/// Porte l'état ET les capacités : sans les deux, une façade ne peut pas
/// décider seule quoi proposer. `capabilities.stop` désigne l'arrêt BRUTAL et
/// `stop_graceful` l'arrêt propre — plusieurs hébergeurs n'ont que l'un des
/// deux, ne tester que le premier effacerait l'action chez GCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineControl {
    pub key: MachineKey,
    /// Entrées d'inventaire portées par cette machine. Huit sur
    /// 203.0.113.10 : l'action porte sur la MACHINE, pas sur l'une d'elles.
    pub hosts: Vec<String>,
    pub instance: InstanceRef,
    /// Nom de l'instance chez l'hébergeur, qui n'est pas celui de l'inventaire.
    /// C'est lui que la confirmation doit montrer : c'est ce qui s'éteindra.
    pub name: String,
    pub state: PowerState,
    pub raw_state: String,
    pub capabilities: Capabilities,
}

/// Une adresse revendiquée par plusieurs comptes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ambiguity {
    pub server: Server,
    /// Comptes candidats, celui retenu en tête.
    pub accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub server: Server,
    pub instance: Instance,
}

/// Joint un parc et un lot d'instances sur `(provider, adresse)`.
///
/// Seules les machines DU provider concerné sont examinées : une machine
/// Contabo absente d'un listing OVH n'est pas une anomalie, et la compter comme
/// telle noierait les vrais écarts.
pub fn reconcile(fleet: &Fleet, kind: ProviderKind, instances: &[Instance]) -> Reconciliation {
    let servers: Vec<&Server> = fleet
        .servers
        .iter()
        .filter(|s| s.provider == Some(kind))
        .collect();

    let mut matched = Vec::new();
    let mut unmatched = Vec::new();
    let mut claimed: Vec<bool> = vec![false; instances.len()];

    let mut ambiguous = Vec::new();

    for server in servers {
        // TOUTES les instances qui portent l'adresse, et non la première.
        //
        // Une IP publique n'appartient qu'à une instance au monde, mais les
        // instances déclarent aussi leurs adresses PRIVÉES : `10.0.0.5` peut
        // très bien exister dans deux tenancies. Depuis que plusieurs comptes
        // sont interrogés ensemble, cette collision est atteignable, et prendre
        // la première trouvée revient à trancher par ordre alphabétique de nom
        // de compte — ce qui n'a aucune raison d'être juste.
        let candidates: Vec<(usize, &Instance)> = instances
            .iter()
            .enumerate()
            .filter(|(_, i)| i.has_address(&server.key.address))
            .collect();

        match candidates.first() {
            Some((idx, instance)) => {
                if candidates.len() > 1 {
                    ambiguous.push(Ambiguity {
                        server: server.clone(),
                        accounts: candidates
                            .iter()
                            .map(|(_, i)| i.reference.account.clone())
                            .collect(),
                    });
                }
                // Seule l'instance retenue est marquée : les autres candidates
                // restent « non gérées », ce qui les rend visibles au lieu de
                // les faire disparaître dans un rapprochement douteux.
                claimed[*idx] = true;
                matched.push(Match {
                    server: server.clone(),
                    instance: (*instance).clone(),
                });
            }
            None => unmatched.push(server.clone()),
        }
    }

    let unmanaged = instances
        .iter()
        .enumerate()
        .filter(|(i, _)| !claimed[*i])
        .map(|(_, inst)| inst.clone())
        .collect();

    Reconciliation {
        matched,
        unmanaged,
        unmatched,
        ambiguous,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_region_order_is_not_remembered() {
        let mut c = Credentials::default();
        c.fields.insert("OCI_REGION".into(), "eu-paris-1".into());
        c.fields.insert("OCI_PROFILE".into(), "acme".into());
        let kept = persistent(&c);
        assert!(kept.get("OCI_REGION").is_none());
        assert_eq!(kept.get("OCI_PROFILE"), Some("acme"));
    }

    use super::*;
    use fleetforge_core::models::{AnsibleGroup, AnsibleHost};
    use std::collections::HashMap;

    fn host(name: &str, addr: &str, provider: &str) -> AnsibleHost {
        AnsibleHost {
            name: name.into(),
            ansible_host: addr.into(),
            ansible_port: None,
            ansible_user: None,
            hostname: None,
            server_type: None,
            provider: Some(provider.into()),
            ansible_roles: vec![],
            alert_exclude: vec![],
            svcprobe_port: None,
            monitor_port: None,
            groups: vec![],
            vars: HashMap::new(),
        }
    }

    fn fleet(hosts: Vec<AnsibleHost>) -> Fleet {
        Fleet::build(
            "t",
            "inv.yml",
            vec![AnsibleGroup { name: "g".into(), hosts, children: vec![] }],
        )
    }

    fn instance(kind: ProviderKind, id: &str, addr: &str) -> Instance {
        Instance {
            reference: InstanceRef {
                account: "default".into(),
                provider: kind,
                id: id.into(),
                zone: None,
                region: "EU".into(),
            },
            name: id.into(),
            state: PowerState::Running,
            raw_state: "running".into(),
            shape: "V5".into(),
            addresses: vec![addr.into()],
            tags: HashMap::new(),
        }
    }

    #[test]
    fn matches_a_machine_to_its_instance_by_address() {
        let f = fleet(vec![
            host("proxy1", "203.0.113.10", "contabo"),
            host("mail", "203.0.113.10", "contabo"),
        ]);
        let r = reconcile(
            &f,
            ProviderKind::Contabo,
            &[instance(ProviderKind::Contabo, "vps-1", "203.0.113.10")],
        );
        // Les deux entrées d'inventaire décrivent UNE machine, donc UN
        // rapprochement — pas deux.
        assert_eq!(r.matched.len(), 1);
        assert_eq!(r.matched[0].server.hosts.len(), 2);
        assert!(r.unmanaged.is_empty());
        assert!(r.unmatched.is_empty());
    }

    /// Les variables d'environnement sont partagées par tout le processus de
    /// test, où les tests tournent en parallèle : un `remove_var` d'un test
    /// tombait au milieu d'un autre et le faisait échouer une fois sur deux.
    /// Tout test qui en pose une prend ce verrou d'abord.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn browser_action() -> SessionAction {
        SessionAction::new("authenticate", "Ouvrir", "…").needing_browser()
    }

    #[test]
    fn a_browser_action_is_withdrawn_when_there_is_no_local_browser() {
        // `oci session authenticate` attend la redirection OAuth sur le
        // `localhost` de la machine QUI EXÉCUTE. Proposée depuis un serveur,
        // elle ouvrirait un navigateur que personne ne voit et attendrait
        // indéfiniment.
        let _env = env_lock();
        std::env::set_var("FLEETFORGE_NO_LOCAL_BROWSER", "1");
        let kept = filter_session_actions(vec![
            SessionAction::new("refresh", "Renouveler", "…"),
            browser_action(),
        ]);
        std::env::remove_var("FLEETFORGE_NO_LOCAL_BROWSER");

        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(kept[0].name, "refresh");
    }

    #[test]
    fn a_plain_action_survives_everywhere() {
        let _env = env_lock();
        std::env::set_var("FLEETFORGE_NO_LOCAL_BROWSER", "1");
        let kept = filter_session_actions(vec![SessionAction::new("refresh", "R", "…")]);
        std::env::remove_var("FLEETFORGE_NO_LOCAL_BROWSER");
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn an_ssh_session_counts_as_having_no_local_browser() {
        // Le TUI joint en SSH s'exécute sur le serveur : son navigateur s'y
        // ouvrirait aussi. C'est le même cas que la façade web.
        let _env = env_lock();
        std::env::set_var("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22");
        let local = provider::has_local_browser();
        std::env::remove_var("SSH_CONNECTION");
        assert!(!local);
    }

    #[test]
    fn an_address_claimed_by_two_accounts_is_flagged_not_silently_picked() {
        // Atteignable depuis que plusieurs comptes sont interrogés ensemble :
        // deux tenancies peuvent porter la même adresse PRIVÉE. Trancher par
        // ordre alphabétique de compte ferait piloter `acme` en croyant
        // piloter `perso`.
        let fleet = fleet(vec![host("db1", "10.0.0.5", "oracle")]);

        let mut from_acme = instance(ProviderKind::Oracle, "i-acme", "10.0.0.5");
        from_acme.reference.account = "acme".into();
        let mut from_perso = instance(ProviderKind::Oracle, "i-perso", "10.0.0.5");
        from_perso.reference.account = "perso".into();

        let rec = reconcile(&fleet, ProviderKind::Oracle, &[from_acme, from_perso]);

        assert_eq!(rec.ambiguous.len(), 1, "collision non signalée");
        assert_eq!(rec.ambiguous[0].accounts, vec!["acme", "perso"]);
        // La machine est tout de même rapprochée — sur le premier candidat —
        // et l'autre instance reste visible en « non gérée » plutôt que de
        // disparaître dans un rapprochement douteux.
        assert_eq!(rec.matched.len(), 1);
        assert_eq!(rec.unmanaged.len(), 1);
    }

    #[test]
    fn a_single_claim_is_not_reported_as_ambiguous() {
        let fleet = fleet(vec![host("vpn1", "198.51.100.51", "ovh")]);
        let only = instance(ProviderKind::Ovh, "i-1", "198.51.100.51");
        let rec = reconcile(&fleet, ProviderKind::Ovh, &[only]);

        assert!(rec.ambiguous.is_empty());
        assert_eq!(rec.matched.len(), 1);
    }

    #[test]
    fn an_instance_absent_from_the_inventory_is_unmanaged() {
        let f = fleet(vec![host("proxy1", "10.0.0.1", "contabo")]);
        let r = reconcile(
            &f,
            ProviderKind::Contabo,
            &[
                instance(ProviderKind::Contabo, "a", "10.0.0.1"),
                instance(ProviderKind::Contabo, "b", "10.0.0.2"),
            ],
        );
        assert_eq!(r.matched.len(), 1);
        assert_eq!(r.unmanaged.len(), 1);
        assert_eq!(r.unmanaged[0].reference.id, "b");
    }

    #[test]
    fn a_machine_without_an_instance_is_reported() {
        let f = fleet(vec![host("ghost", "10.0.0.9", "contabo")]);
        let r = reconcile(&f, ProviderKind::Contabo, &[]);
        assert_eq!(r.unmatched.len(), 1);
        assert_eq!(r.unmatched[0].key.address, "10.0.0.9");
    }

    #[test]
    fn machines_of_another_provider_are_left_alone() {
        // Une machine Contabo absente d'un listing OVH n'est pas un écart :
        // la compter comme tel noierait les vrais.
        let f = fleet(vec![
            host("proxy1", "10.0.0.1", "contabo"),
            host("small1", "10.0.0.2", "oracle"),
        ]);
        let r = reconcile(
            &f,
            ProviderKind::Contabo,
            &[instance(ProviderKind::Contabo, "a", "10.0.0.1")],
        );
        assert_eq!(r.matched.len(), 1);
        assert!(r.unmatched.is_empty(), "la machine Oracle a été comptée");
    }

    #[test]
    fn custom_declares_no_capability_and_no_missing_tool() {
        let info = describe(ProviderKind::Custom);
        assert!(!info.capabilities.list);
        // Absence d'API par nature, pas un outil manquant à installer.
        assert!(info.missing_tool.is_none());
    }

    #[test]
    fn every_provider_can_be_described_without_credentials() {
        let all = describe_all();
        assert_eq!(all.len(), 6);
        for info in all {
            assert!(!info.label.is_empty());
        }
    }

    /// Un champ sans indication oblige à sortir de l'application pour savoir
    /// quoi y mettre — et c'est le formulaire qui décide alors, en silence,
    /// que l'utilisateur ira chercher ailleurs.
    #[test]
    fn every_credential_field_says_where_to_find_its_value() {
        for info in describe_all() {
            for method in &info.auth_methods {
                for field in &method.fields {
                    assert!(
                        !field.hint.trim().is_empty(),
                        "{} / {} : le champ `{}` n'a aucune indication",
                        info.label,
                        method.label,
                        field.key
                    );
                }
            }
        }
    }

    /// Les trois façades affichent ces libellés tels quels : un champ dont le
    /// libellé porte « (facultatif) » alors que `optional` vaut faux dit deux
    /// choses contradictoires, et c'est le drapeau qui décide de l'envoi.
    #[test]
    fn optionality_is_carried_by_the_flag_not_by_the_label() {
        for info in describe_all() {
            for method in &info.auth_methods {
                for field in &method.fields {
                    assert!(
                        !field.label.to_lowercase().contains("facultatif"),
                        "{} : `{}` annonce sa facultativité dans son libellé",
                        info.label,
                        field.key
                    );
                }
            }
        }
    }

    #[test]
    fn contabo_and_ovh_need_no_external_tool() {
        for kind in [ProviderKind::Contabo, ProviderKind::Ovh] {
            let info = describe(kind);
            assert!(info.capabilities.list, "{kind} devrait pouvoir lister");
            assert!(info.missing_tool.is_none());
        }
    }
}
