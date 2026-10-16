# Paramétrer les hébergeurs

Les six hébergeurs se configurent **depuis l'application**, dans les trois
façades. Rien n'est à écrire dans un fichier à la main : le cœur
(`crates/fleetforge-providers`) déclare pour chacun ses méthodes d'authentification,
ses champs, lesquels sont des secrets et où l'on trouve leur valeur. Les trois
interfaces rendent cette même déclaration — une indication corrigée l'est
partout d'un coup.

## Plusieurs comptes par hébergeur

Un hébergeur porte autant de **comptes** qu'on veut : deux tenancies Oracle,
deux profils AWS, deux projets GCP. Ils sont ouverts **en même temps**, et leurs
instances sont listées et rapprochées de l'inventaire ensemble.

C'est ce qui rend le rapprochement juste quand le parc s'étend sur plusieurs
comptes : n'en interroger qu'un ferait passer les machines des autres pour
« sans instance », c'est-à-dire pour un inventaire faux.

Chaque compte a un **nom court** que vous choisissez — `acme`, `perso`,
`client-x` — qui l'identifie dans l'application et nulle part ailleurs. Il est
normalisé (« Acme Prod » → `acme-prod`) pour que deux graphies ne fassent pas
deux comptes. Un hébergeur jamais configuré propose un compte `default`.

| Geste | Bureau / Web | TUI |
|---|---|---|
| Ajouter un compte | bouton **Ajouter un compte** | **`a`** |
| Saisir / changer les identifiants | icône ⚙ de la ligne | **`C`** |
| Connecter un compte | icône 🔗 de la ligne | **`c`** sur le compte |
| Tout connecter | bouton **Tout connecter** | **`c`** sur l'hébergeur |
| Fermer la session | icône ⛓ de la ligne | **`x`** |
| Oublier les identifiants | icône 🗑 (confirmation) | **`X`** (confirmation) |
| Renouveler la session | icône ⟳ de la ligne | **`s`** |
| Ouvrir une session neuve | icône 🌐 de la ligne | **`s`** puis choix |

Dans le TUI, `↵` descend d'un niveau (hébergeur → comptes → instances) et `⎋`
remonte. Le nom du compte ne se modifie qu'à la création : le changer ensuite
n'aurait pas renommé le compte, il en aurait créé un second en laissant le
premier derrière avec ses identifiants.

**Un compte en échec n'empêche pas les autres.** Une tenancy dont la session a
expiré est signalée, les autres s'ouvrent quand même — c'est toute la raison
d'en avoir plusieurs.

**Reprise** : les identifiants enregistrés par une version antérieure sont
retrouvés sous le compte `default`, sans ressaisie.

## Où se règle quoi

| Façade | Chemin |
|---|---|
| Bureau (Tauri) et Web | écran **Hébergeurs** → ligne du compte → ⚙ |
| TUI | écran **9 Providers** → `↵` sur l'hébergeur → touche **`C`** |

Le bouton et la touche restent disponibles quand des identifiants sont déjà
enregistrés : une clé se révoque, un projet change. `Connecter` / `c` se
contentent de rejouer ce qui est en mémoire.

### Où les identifiants sont conservés

Trousseau du système quand il est accessible (Keychain sur macOS, Secret
Service sur Linux, Credential Manager sur Windows), sous le service
`fleetforge`, une entrée par compte (`oracle:acme`). Une entrée laissée sous
l'ancien service `vx-infra-manager` y est reprise à sa première lecture. Le trousseau ne
s'énumérant pas, la LISTE des comptes — sans aucun secret — vit à côté, dans
`accounts.json`. À défaut de trousseau — session sans agent, conteneur, CI — un
fichier en `0600` dans le répertoire de données local :
`~/Library/Application Support/fleetforge/credentials.json` sur macOS,
`~/.local/share/fleetforge/credentials.json` sur Linux.

Un secret déjà enregistré n'est **jamais réaffiché** dans le formulaire, même
masqué : le reprendre le renverrait tel quel dès qu'on ne modifie qu'un autre
champ, et une clé révoquée resterait en place sans que rien ne le montre. Pour
changer un secret, on le ressaisit.

---

## Deux familles d'hébergeurs

**Contabo et OVH parlent à une API REST** : il suffit de renseigner les champs,
aucun outil à installer.

**AWS, GCP et Oracle passent par leur CLI officiel** (`aws`, `gcloud`, `oci`),
lancé en sous-processus. Réimplémenter SigV4, le JWT de compte de service et la
signature RSA-SHA256 représenterait des centaines de lignes de cryptographie
invérifiable sans identifiants réels, là où le CLI gère déjà SSO, jetons de
session et rafraîchissement.

**Conséquence à connaître** : si le binaire n'est pas installé, l'hébergeur
apparaît sans aucune capacité, grisé, avec la mention « outil « aws » non
installé ». Ce n'est pas une panne de connexion — c'est l'outil qui manque.

**custom** ne se configure pas : machines physiques, SSH seul, aucune API.

---

## Contabo — REST

Panneau client → **API**.

| Champ | Où le prendre |
|---|---|
| `CONTABO_CLIENT_ID` | écran API, « Client ID » — pas l'identifiant du compte |
| `CONTABO_CLIENT_SECRET` | même écran, sous le Client ID |
| `CONTABO_USER` | l'adresse e-mail du compte |
| `CONTABO_PASSWORD` | le **mot de passe API**, à générer dans le panneau — distinct de celui du compte |

## OVH — REST

Les trois clés viennent d'un **seul passage** sur
`https://eu.api.ovh.com/createToken/`, en y demandant `GET` et `POST` sur
`/cloud/*`.

| Champ | Où le prendre |
|---|---|
| `OVH_ENDPOINT` | `ovh-eu`, `ovh-us`, `ovh-ca`, `kimsufi-eu`, `soyoustart-eu` — *facultatif*, défaut `ovh-eu` |
| `OVH_APPLICATION_KEY` | createToken |
| `OVH_APPLICATION_SECRET` | createToken |
| `OVH_CONSUMER_KEY` | createToken — c'est elle qui porte les droits demandés |
| `OVH_CLOUD_PROJECT_SERVICE` | ID du projet (32 caractères), visible dans l'URL du manager Public Cloud |

## AWS — CLI `aws`

Deux méthodes, au choix dans le formulaire.

**Configuration AWS CLI (profil, SSO)** — quand `~/.aws/` existe déjà :

| Champ | Où le prendre |
|---|---|
| `AWS_PROFILE` | une section de `~/.aws/credentials` — *facultatif*, défaut `default` |
| `AWS_REGION` | ex. `eu-west-3` |

**Clés d'accès IAM** :

| Champ | Où le prendre |
|---|---|
| `AWS_ACCESS_KEY_ID` | Console IAM → Utilisateurs → Security credentials → Create access key. Commence par `AKIA` |
| `AWS_SECRET_ACCESS_KEY` | montré **une seule fois**, à la création de la clé |
| `AWS_REGION` | ex. `eu-west-3` |

> EC2 liste **par région**. Sans région renseignée, les instances des autres
> régions sont simplement absentes — ce qui ressemble à un parc vide.

## GCP — CLI `gcloud`

**Session gcloud** (après `gcloud auth login`) :

| Champ | Où le prendre |
|---|---|
| `GCP_PROJECT` | l'**ID** du projet, pas son nom d'affichage — `gcloud projects list` donne les deux |

**Compte de service (fichier JSON)** :

| Champ | Où le prendre |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | chemin **absolu** sur cette machine. IAM → Comptes de service → Clés → Ajouter une clé (JSON) |
| `GCP_PROJECT` | l'ID du projet |

## Oracle — CLI `oci`

**Fichier `~/.oci/config`.** Deux modes d'authentification y coexistent, et
l'application détecte lequel votre profil utilise :

| Mode | Le profil porte | Se crée par |
|---|---|---|
| Clé d'API | `user`, `fingerprint`, `key_file` | `oci setup config` |
| **Session** | `security_token_file`, **pas** de `user` | `oci session authenticate` |

En mode session, l'application ajoute `--auth security_token` à chaque appel.
Sans ce drapeau, le CLI retombe sur le mode par clé et réclame `user` — un
champ qu'une session n'a pas, et qu'il est donc inutile d'essayer d'ajouter.

**Une session expire** (une heure par défaut). L'application sait la renouveler
elle-même : sur la ligne du compte, le bouton ⟳ (touche **`s`** dans le TUI)
lance `oci session refresh`. Il n'apparaît que sur un compte connecté en mode
session — un profil par clé d'API n'a rien à renouveler.

Passé cette fenêtre, il faut une session neuve — et l'application sait aussi la
lancer, **là où c'est possible** : `oci session authenticate` ouvre un navigateur
et attend la redirection OAuth sur `http://localhost:8181`. Le processus et le
navigateur doivent donc être sur la MÊME machine.

| Façade | Session neuve |
|---|---|
| Bureau (Tauri) | ✅ — l'application tourne sur votre poste |
| TUI en local | ✅ |
| TUI joint en SSH | ❌ — détecté par `SSH_CONNECTION` |
| Web | ❌ — le navigateur s'ouvrirait sur le serveur |

Là où c'est impossible, l'action n'est **pas affichée** et un appel direct à
l'API est refusé — masquer un bouton ne suffit pas. Il reste alors à taper
`oci session authenticate` dans un terminal sur votre poste.

| Champ | Où le prendre |
|---|---|
| `OCI_PROFILE` | une section de `~/.oci/config` — *facultatif*, défaut `DEFAULT` |
| `OCI_COMPARTMENT` | `ocid1.compartment.oc1..…` — Console → Identité → Compartiments, ou `oci iam compartment list --all` |

**Plusieurs tenancies** : déclarez un compte par tenancy (`acme`, `perso`) et
donnez à chacun son `OCI_PROFILE`, chaque profil étant une section de
`~/.oci/config`. Les deux sont alors ouvertes ensemble.

> Sans compartiment, seules les instances de la **racine de la tenancy**
> seraient listées : celles des sous-compartiments resteraient invisibles.

---

## Ce que chaque hébergeur sait faire

Les capacités sont **déclarées**, jamais supposées : l'interface grise ce qui
n'existe pas plutôt que de proposer une action qui échouerait — ou, pire, qui
en réaliserait une autre. La variante douce est retenue dès qu'elle existe.

| Hébergeur | Voie | démarrer | arrêter | arrêt gracieux | redémarrer | redémarrage gracieux |
|---|---|:-:|:-:|:-:|:-:|:-:|
| Contabo | REST | ✅ | ✅ | — | ✅ | — |
| OVH | REST | ✅ | ✅ | — | ✅ `hard` | ✅ `soft` |
| AWS | CLI `aws` | ✅ | ✅ `--force` | ✅ | — | ✅ |
| GCP | CLI `gcloud` | ✅ | — | ✅ | ✅ `reset` | — |
| Oracle | CLI `oci` | ✅ | ✅ `STOP` | ✅ `SOFTSTOP` | ✅ `RESET` | ✅ `SOFTRESET` |
| custom | — | — | — | — | — | — |

Un tiret n'est pas un manque d'implémentation : c'est l'hébergeur qui n'a pas
cette variante. GCP n'a **pas** de redémarrage propre (`reset` coupe
l'alimentation) ni d'arrêt brutal ; EC2 n'a **pas** de redémarrage brutal
(`reboot-instances` demande un arrêt propre à l'OS).

## Piloter une instance

**Bureau / Web** — écran Hébergeurs → `Connecter`, puis `Lister les instances`.
Les trois icônes de chaque ligne (démarrer, arrêter, redémarrer) n'apparaissent
que si l'hébergeur sait faire.

**TUI** — écran `9 Providers` :

| Touche | Effet |
|---|---|
| `c` | connecter depuis les identifiants enregistrés |
| `C` | saisir / changer les identifiants |
| `↵` | descendre dans la liste des instances |
| `j` `k` | choisir l'instance |
| `S` | démarrer |
| `A` | arrêter |
| `R` | redémarrer |
| `⎋` | remonter à la liste des hébergeurs |

Les trois actions sont en **majuscules** et passent par une confirmation :
`r` recharge le parc, `R` redémarre une machine — une frappe de trop ne doit
pas couper un serveur.
