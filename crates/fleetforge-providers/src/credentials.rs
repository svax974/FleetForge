/*
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

//! Conservation des identifiants d'hébergeur.
//!
//! Le prototype les écrivait en clair dans `~/.instance-manager/credentials.json`,
//! sans `chmod`, alors que sa propre `ARCHITECTURE.md` promettait un fichier
//! chiffré par trousseau. Ici : trousseau système quand il est disponible,
//! sinon un fichier en `0600` — jamais un fichier lisible par tous.

use crate::provider::{AccountId, Credentials, DEFAULT_ACCOUNT};
use anyhow::{Context, Result};
use fleetforge_core::model::ProviderKind;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

const SERVICE: &str = "fleetforge";
/// Service du trousseau sous l'ancien nom du projet : une entrée qui n'existe
/// que là est recopiée sous `SERVICE` à sa première lecture, puis effacée.
#[cfg(feature = "keyring")]
const LEGACY_SERVICE: &str = "vx-infra-manager";

pub struct CredentialStore {
    /// Repli lorsque le trousseau n'est pas accessible (session sans agent,
    /// exécution en CI, conteneur).
    fallback_path: PathBuf,
    /// Le trousseau du système est-il utilisé ?
    ///
    /// Faux dans les tests, et uniquement là. Sans ce garde-fou ils lisent le
    /// trousseau RÉEL de qui joue la suite : ils y voyaient ses comptes — d'où
    /// un `default` surgissant dans une liste censée n'en contenir aucun — et
    /// `forget` y aurait supprimé de vrais identifiants.
    use_keyring: bool,
    /// Index mémorisé pour la durée du processus, pour ne pas relire le
    /// fichier — ni, au premier appel, sonder le trousseau — à chaque question.
    cache: Mutex<Option<Vec<AccountId>>>,
    /// Liste des comptes connus, SANS secret.
    ///
    /// Le trousseau du système ne s'énumère pas : on peut lire une entrée dont
    /// on connaît la clé, pas demander « quelles entrées existent ». Sans cet
    /// index, un compte enregistré au lancement précédent serait invisible au
    /// suivant — il faudrait le ressaisir pour le retrouver.
    index_path: PathBuf,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    pub fn new() -> Self {
        let dir = fleetforge_core::paths::data_dir();
        Self {
            cache: Mutex::new(None),
            use_keyring: true,
            fallback_path: dir.join("credentials.json"),
            index_path: dir.join("accounts.json"),
        }
    }

    /// Comptes enregistrés pour un hébergeur, dans l'ordre d'affichage.
    pub fn accounts(&self, provider: ProviderKind) -> Vec<AccountId> {
        let mut names: Vec<String> = self
            .index()
            .into_iter()
            .filter(|a| a.provider == provider)
            .map(|a| a.name)
            .collect();
        names.sort_unstable();
        names.dedup();
        names
            .into_iter()
            .map(|name| AccountId { provider, name })
            .collect()
    }

    pub fn all_accounts(&self) -> Vec<AccountId> {
        let mut all = self.index();
        all.sort();
        all.dedup();
        all
    }

    /// Ce compte a-t-il des identifiants enregistrés ?
    ///
    /// Répond par l'INDEX, sans lire le secret. C'est une question
    /// d'existence : y répondre par `load(...).is_some()` faisait déchiffrer
    /// le secret — et, sur macOS, demander une autorisation de trousseau — pour
    /// n'en regarder que la présence. L'interface pose cette question pour
    /// chaque compte de chaque hébergeur, à chaque rafraîchissement.
    pub fn has(&self, account: &AccountId) -> bool {
        self.index().contains(account)
    }

    pub fn load(&self, account: &AccountId) -> Option<Credentials> {
        let key = account.storage_key();
        if let Some(raw) = self.keyring_get(&key) {
            if let Ok(c) = serde_json::from_str(&raw) {
                return Some(c);
            }
        }
        if let Some(c) = self.file_all().ok()?.remove(&key) {
            return Some(c);
        }

        // Reprise d'une version antérieure : les identifiants y étaient rangés
        // sous le seul nom de l'hébergeur. On ne les migre pas d'office — un
        // trousseau peut refuser l'écriture — on les relit simplement sous le
        // compte `default`, qui est celui que l'index leur attribue.
        if account.name == DEFAULT_ACCOUNT {
            return self.load_legacy(account.provider);
        }
        None
    }

    pub fn save(&self, account: &AccountId, credentials: &Credentials) -> Result<()> {
        let key = account.storage_key();
        let raw = serde_json::to_string(credentials)?;

        if self.keyring_set(&key, &raw).is_ok() {
            // Le trousseau a pris : retirer une éventuelle copie en clair
            // laissée par une version antérieure, sans quoi le secret resterait
            // lisible sur le disque.
            let _ = self.file_remove(&key);
        } else {
            self.file_save(&key, credentials)?;
        }

        self.index_add(account)
    }

    /// Oublie les identifiants. Distinct de la déconnexion : le prototype
    /// confondait les deux, si bien que se déconnecter effaçait la
    /// configuration et non la seule session.
    pub fn forget(&self, account: &AccountId) -> Result<()> {
        let key = account.storage_key();
        let _ = self.keyring_delete(&key);
        self.file_remove(&key)?;

        // L'entrée héritée porte le seul nom de l'hébergeur : sans cela,
        // oublier le compte `default` le verrait réapparaître au démarrage
        // suivant, relu depuis l'ancien emplacement.
        if account.name == DEFAULT_ACCOUNT {
            let _ = self.keyring_delete(account.provider.as_str());
            let _ = self.file_remove(account.provider.as_str());
        }

        self.index_remove(account)
    }

    /// Renomme un compte : ses identifiants passent sous le nouveau nom, puis
    /// l'ancien est oublié.
    ///
    /// L'ordre compte : écrire d'abord, effacer ensuite. Une coupure entre les
    /// deux laisse deux comptes identiques — un doublon qu'on supprime — et non
    /// un compte perdu avec ses secrets.
    pub fn rename(&self, from: &AccountId, to: &AccountId) -> Result<()> {
        if from == to {
            anyhow::bail!("le compte s'appelle déjà « {} »", to.name);
        }
        if self.has(to) {
            anyhow::bail!("un compte « {} » existe déjà chez {}", to.name, to.provider);
        }
        let credentials = self
            .load(from)
            .ok_or_else(|| anyhow::anyhow!("aucun identifiant enregistré pour {from} : rien à renommer"))?;
        self.save(to, &credentials)?;
        self.forget(from)
    }

    /// Identifiants rangés par une version antérieure, sous le seul hébergeur.
    fn load_legacy(&self, provider: ProviderKind) -> Option<Credentials> {
        let key = provider.as_str();
        if let Some(raw) = self.keyring_get(key) {
            if let Ok(c) = serde_json::from_str(&raw) {
                return Some(c);
            }
        }
        self.file_all().ok()?.remove(key)
    }

    // --- index des comptes ---

    /// Comptes connus, SANS toucher au trousseau.
    ///
    /// C'est tout l'intérêt de l'index : répondre à « ce compte a-t-il des
    /// identifiants ? » est une question d'EXISTENCE, et y répondre en lisant
    /// le secret lui-même fait payer le prix fort. Sur macOS, chaque lecture
    /// du trousseau est une demande d'autorisation — mesuré : un seul appel à
    /// `statuses()` en déclenchait une quarantaine, et prenait cinq secondes.
    ///
    /// Le résultat est mémorisé pour la durée du processus : `statuses()`
    /// interroge les six hébergeurs, et relire le fichier six fois de suite ne
    /// peut rien apprendre de neuf.
    fn index(&self) -> Vec<AccountId> {
        if let Some(cached) = self.cache.lock().ok().and_then(|c| c.clone()) {
            return cached;
        }

        let found = self.index_from_disk();
        if let Ok(mut c) = self.cache.lock() {
            *c = Some(found.clone());
        }
        found
    }

    fn index_from_disk(&self) -> Vec<AccountId> {
        let listed: Option<Vec<AccountId>> = std::fs::read_to_string(&self.index_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .map(|keys| keys.iter().filter_map(|k| AccountId::parse_storage_key(k)).collect());

        if let Some(listed) = listed {
            return listed;
        }

        // Pas d'index : on sonde le trousseau pour retrouver ce qu'une version
        // antérieure y a rangé sous le seul nom de l'hébergeur.
        let found: Vec<AccountId> = ProviderKind::ALL
            .into_iter()
            .filter(|p| self.load_legacy(*p).is_some())
            .map(AccountId::default_for)
            .collect();

        // Un résultat VIDE n'est PAS écrit.
        //
        // `keyring_get` rend `None` aussi bien pour « aucun identifiant » que
        // pour « l'utilisateur a refusé l'autorisation » ou « pas de session
        // graphique pour la demander ». Persister ce vide graverait un refus
        // ponctuel : les identifiants existeraient toujours dans le trousseau,
        // mais plus rien ne les chercherait — ils seraient perdus sans l'être.
        // C'est exactement ce qui est arrivé sur ce poste.
        //
        // Ne rien écrire fait rejouer la sonde au démarrage suivant. Elle est
        // sans coût quand le trousseau ne contient rien — c'est l'entrée
        // EXISTANTE qui déclenche une demande d'autorisation, pas son absence —
        // et le premier enregistrement crée l'index, après quoi elle cesse.
        if !found.is_empty() {
            let _ = self.index_write(&found);
        }
        found
    }

    /// Oublie l'index mémorisé. Appelé après toute écriture : sans cela, un
    /// compte ajouté n'apparaîtrait qu'au prochain démarrage.
    fn invalidate(&self) {
        if let Ok(mut c) = self.cache.lock() {
            *c = None;
        }
    }

    fn index_write(&self, accounts: &[AccountId]) -> Result<()> {
        self.invalidate();
        if let Some(parent) = self.index_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let keys: Vec<String> = accounts.iter().map(AccountId::storage_key).collect();
        std::fs::write(&self.index_path, serde_json::to_string_pretty(&keys)?)?;
        Ok(())
    }

    fn index_add(&self, account: &AccountId) -> Result<()> {
        let mut all = self.index();
        if !all.contains(account) {
            all.push(account.clone());
            all.sort();
        }
        self.index_write(&all)
    }

    fn index_remove(&self, account: &AccountId) -> Result<()> {
        let mut all = self.index();
        all.retain(|a| a != account);
        self.index_write(&all)
    }

    // --- trousseau ---

    #[cfg(feature = "keyring")]
    fn entry(&self, key: &str) -> Option<keyring::Entry> {
        keyring::Entry::new(SERVICE, key).ok()
    }

    #[cfg(feature = "keyring")]
    fn keyring_get(&self, key: &str) -> Option<String> {
        if !self.use_keyring {
            return None;
        }
        if let Some(raw) = self.entry(key)?.get_password().ok() {
            return Some(raw);
        }
        let legacy = keyring::Entry::new(LEGACY_SERVICE, key).ok()?;
        let raw = legacy.get_password().ok()?;
        if self.entry(key)?.set_password(&raw).is_ok() {
            let _ = legacy.delete_credential();
        }
        Some(raw)
    }

    #[cfg(feature = "keyring")]
    fn keyring_set(&self, key: &str, raw: &str) -> Result<()> {
        if !self.use_keyring {
            anyhow::bail!("trousseau désactivé");
        }
        self.entry(key)
            .context("trousseau indisponible")?
            .set_password(raw)
            .context("écriture dans le trousseau refusée")
    }

    #[cfg(feature = "keyring")]
    fn keyring_delete(&self, key: &str) -> Result<()> {
        if !self.use_keyring {
            return Ok(());
        }
        self.entry(key)
            .context("trousseau indisponible")?
            .delete_credential()
            .context("suppression dans le trousseau refusée")
    }

    #[cfg(not(feature = "keyring"))]
    fn keyring_get(&self, _key: &str) -> Option<String> {
        None
    }

    #[cfg(not(feature = "keyring"))]
    fn keyring_set(&self, _key: &str, _raw: &str) -> Result<()> {
        anyhow::bail!("trousseau non compilé")
    }

    #[cfg(not(feature = "keyring"))]
    fn keyring_delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    // --- repli fichier ---

    fn file_all(&self) -> Result<HashMap<String, Credentials>> {
        if !self.fallback_path.exists() {
            return Ok(HashMap::new());
        }
        let raw = std::fs::read_to_string(&self.fallback_path)?;
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    fn file_write(&self, all: &HashMap<String, Credentials>) -> Result<()> {
        if let Some(parent) = self.fallback_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.fallback_path, serde_json::to_string_pretty(all)?)?;
        restrict_permissions(&self.fallback_path)?;
        Ok(())
    }

    fn file_save(&self, key: &str, credentials: &Credentials) -> Result<()> {
        let mut all = self.file_all()?;
        all.insert(key.to_string(), credentials.clone());
        self.file_write(&all)
    }

    fn file_remove(&self, key: &str) -> Result<()> {
        let mut all = self.file_all()?;
        if all.remove(key).is_some() {
            self.file_write(&all)?;
        }
        Ok(())
    }
}

/// `0600`. Un fichier de secrets lisible par tous les comptes de la machine
/// n'est pas un stockage, c'est une fuite.
fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_at(dir: &std::path::Path) -> CredentialStore {
        CredentialStore {
            cache: Mutex::new(None),
            // JAMAIS le trousseau réel depuis un test.
            use_keyring: false,
            fallback_path: dir.join("credentials.json"),
            index_path: dir.join("accounts.json"),
        }
    }

    fn account(provider: ProviderKind, name: &str) -> AccountId {
        AccountId::new(provider, name)
    }

    fn creds(v: &str) -> Credentials {
        let mut fields = HashMap::new();
        fields.insert("CONTABO_CLIENT_ID".to_string(), v.to_string());
        Credentials {
            method: "oauth2".into(),
            fields,
        }
    }

    #[test]
    fn renaming_moves_the_credentials_and_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("im-rename-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);
        let old = account(ProviderKind::Contabo, "ancien");
        let new = account(ProviderKind::Contabo, "Nouveau Nom");
        store.save(&old, &creds("abc")).unwrap();

        store.rename(&old, &new).unwrap();

        assert_eq!(store.load(&new).unwrap().fields, creds("abc").fields);
        assert!(!store.has(&old), "l'ancien nom subsiste");
        assert!(store.load(&old).is_none(), "les secrets restent sous l'ancien nom");
        assert_eq!(store.accounts(ProviderKind::Contabo), vec![new]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn renaming_onto_an_existing_account_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("im-rename-clash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);
        let a = account(ProviderKind::Contabo, "a");
        let b = account(ProviderKind::Contabo, "b");
        store.save(&a, &creds("secret-a")).unwrap();
        store.save(&b, &creds("secret-b")).unwrap();

        assert!(store.rename(&a, &b).is_err());
        assert_eq!(store.load(&a).unwrap().fields, creds("secret-a").fields);
        assert_eq!(store.load(&b).unwrap().fields, creds("secret-b").fields, "écrasé");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn renaming_an_account_without_credentials_or_to_itself_is_refused() {
        let dir = std::env::temp_dir().join(format!("im-rename-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);
        let a = account(ProviderKind::Contabo, "a");
        assert!(store.rename(&a, &account(ProviderKind::Contabo, "b")).is_err());
        store.save(&a, &creds("x")).unwrap();
        assert!(store.rename(&a, &a).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_fallback_file_is_not_world_readable() {
        let dir = std::env::temp_dir().join(format!("im-creds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        store.file_save("contabo:default", &creds("abc")).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store.fallback_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "secrets lisibles par d'autres comptes");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_then_forgetting_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("im-creds2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        store.file_save("ovh:default", &creds("xyz")).unwrap();
        assert!(store.file_all().unwrap().contains_key("ovh:default"));

        store.file_remove("ovh:default").unwrap();
        assert!(!store.file_all().unwrap().contains_key("ovh:default"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn providers_do_not_overwrite_each_other() {
        let dir = std::env::temp_dir().join(format!("im-creds3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        store.file_save("contabo:default", &creds("c")).unwrap();
        store.file_save("ovh:default", &creds("o")).unwrap();

        let all = store.file_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all["contabo:default"].fields["CONTABO_CLIENT_ID"], "c");
        assert_eq!(all["ovh:default"].fields["CONTABO_CLIENT_ID"], "o");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_accounts_of_the_same_provider_do_not_overwrite_each_other() {
        // C'EST le défaut que les comptes nommés corrigent : avec le seul
        // `ProviderKind` pour clé, enregistrer la seconde tenancy écrasait la
        // première, sans erreur ni message.
        let dir = std::env::temp_dir().join(format!("im-creds4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        let acme = account(ProviderKind::Oracle, "acme");
        let perso = account(ProviderKind::Oracle, "perso");
        store.save(&acme, &creds("A")).unwrap();
        store.save(&perso, &creds("P")).unwrap();

        assert_eq!(store.load(&acme).unwrap().fields["CONTABO_CLIENT_ID"], "A");
        assert_eq!(store.load(&perso).unwrap().fields["CONTABO_CLIENT_ID"], "P");

        let listed: Vec<String> = store
            .accounts(ProviderKind::Oracle)
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(listed, vec!["acme", "perso"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forgetting_one_account_leaves_the_other_alone() {
        let dir = std::env::temp_dir().join(format!("im-creds5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        let acme = account(ProviderKind::Oracle, "acme");
        let perso = account(ProviderKind::Oracle, "perso");
        store.save(&acme, &creds("A")).unwrap();
        store.save(&perso, &creds("P")).unwrap();

        store.forget(&acme).unwrap();

        assert!(store.load(&acme).is_none());
        assert!(store.load(&perso).is_some(), "le compte voisin a disparu");
        assert_eq!(store.accounts(ProviderKind::Oracle).len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_saved_by_an_earlier_version_are_found_under_default() {
        // Elles étaient rangées sous le seul nom de l'hébergeur. Sans reprise,
        // une mise à jour ferait disparaître des identifiants qui marchent, et
        // l'application demanderait de tout ressaisir sans expliquer pourquoi.
        let dir = std::env::temp_dir().join(format!("im-creds6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        store.file_save("ovh", &creds("ancien")).unwrap();

        let default = account(ProviderKind::Ovh, "default");
        assert_eq!(
            store.load(&default).unwrap().fields["CONTABO_CLIENT_ID"],
            "ancien"
        );
        // Et le compte apparaît dans la liste, sans index écrit.
        assert_eq!(store.accounts(ProviderKind::Ovh).len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn presence_is_answered_without_reading_the_secret() {
        // Le magasin est construit SANS trousseau : si `has` en dépendait, il
        // ne pourrait rien trouver. C'est ce qui garantit que la vignette
        // n'ouvre pas le trousseau pour chaque compte, à chaque
        // rafraîchissement — sur macOS, chaque lecture demande une
        // autorisation à l'utilisateur.
        let dir = std::env::temp_dir().join(format!("im-creds7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        let acme = account(ProviderKind::Oracle, "acme");
        assert!(!store.has(&acme));
        store.save(&acme, &creds("A")).unwrap();
        assert!(store.has(&acme), "présence non vue depuis l'index");

        store.forget(&acme).unwrap();
        assert!(!store.has(&acme));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_probe_is_never_written_to_the_index() {
        // `keyring_get` rend `None` aussi bien pour « rien » que pour
        // « autorisation refusée ». Graver ce vide ferait disparaître des
        // identifiants qui existent toujours : plus rien n'irait les chercher.
        // C'est arrivé sur le poste, et l'index était à `[]`.
        let dir = std::env::temp_dir().join(format!("im-creds8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = store_at(&dir);

        assert!(store.accounts(ProviderKind::Oracle).is_empty());
        assert!(
            !dir.join("accounts.json").exists(),
            "un index vide a été écrit ; il masquerait un trousseau non autorisé"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_name_is_normalised_so_one_account_stays_one_account() {
        // « Acme Prod », « acme prod » et « ACME-PROD » désignent le même
        // compte pour qui les saisit.
        assert_eq!(AccountId::new(ProviderKind::Oracle, "Acme Prod").name, "acme-prod");
        assert_eq!(AccountId::new(ProviderKind::Oracle, "ACME-PROD").name, "acme-prod");
        assert_eq!(AccountId::new(ProviderKind::Oracle, "  ").name, "default");
        assert_eq!(AccountId::new(ProviderKind::Oracle, "a//b").name, "a-b");
    }

    #[test]
    fn a_storage_key_round_trips() {
        let a = AccountId::new(ProviderKind::Oracle, "acme");
        assert_eq!(AccountId::parse_storage_key(&a.storage_key()), Some(a));
    }
}
