# NodeInfo

certbot certonly --expand --non-interactive --agree-tos -m <email du parc (variable `email`)> --standalone -d papanglabs.com,store.papanglabs.com,cert.papanglabs.com,monitor.papanglabs.com,vpn.papanglabs.com,rpcbtc.papanglabs.com,back.papanglabs.com,front.papanglabs.com,db.papanglabs.com,analytics.papanglabs.com

Note (2026-09-14): `analytics.papanglabs.com` (Umami) needs its DNS record created manually first, then this cert command re-run with `--expand` to add it, before `deploy-umami.yml` + `update-proxy.yml` can serve it over TLS.

## Playbooks
Prerequisites : have all cert domains declared in a DNS provider and pointing to proxies with health check on proxies TCP port 443
1. Deploy initial proxies : deploy-proxy (in order to redirect/allow traffic to cert)
2. Deploy cert : deploy-cert which includes cert-update (to install certbot, create certificates and copy them over initial proxies)
    Note : Warning, the /etc/letsencrypt creation with "srvc" owner has not been tested (that might corrupt the rsync certs copy)
3. Update all proxies : deploy-update (to activate SSL website after proxies got the certificates)

VPN : after install/dump import, must go on each Pritunl machine web interface to :
- Initialize admin access and set new password
- Deactivate IPv6 if it causes problems (in global settings AND on each "VPN server" configured on Pritunl machines)

Run deploy-cert-update when adding a new proxy
Run deploy-proxy-update when adding a new proxy or modifying proxies config

## Roles
For each server type (proxy, rpc, db, back, front, ...), there can be a few roles to fully setup a server :
- "TYPE-install" role that takes care of installing all needed software
- "TYPE-setup" role that takes care of setting up / configuring the services/servers if needed
- "TYPE-security" role that takes care of setting-up security measures for the server
- "TYPE-update" role that takes care of installing/updating data/configurations that might change int time

`agenthub-flutter-build-linux` / `agenthub-flutter-build-macos` (playbook `deploy-agenthub-flutter-build.yml`, tags `linux` / `macos`) complete `agenthub-install` with what a runner needs to BUILD Flutter apps : JDK 17 + Android SDK (+ licences, `flutter precache`) on a Debian/Ubuntu AgentHub server (targets android, web, linux), and Homebrew + JDK + Android SDK + CocoaPods + Flutter with an Xcode check on a Mac (targets android, web, macos, ios ; Xcode and signing certificates stay manual). Flutter cannot cross-compile desktop targets, so Windows and macOS/iOS-from-Linux are not covered. The macOS play targets the `agenthub_flutter_macos` inventory group (to be declared, see the playbook header).

# Docker Repo
docker login {registry_url} -u {username}

## GCP SSH connection
- Create a service account and export a key in json for it
- Create a SSH key and add it to the GCP project containing the GCP instances to be used with ansible :
ssh-keygen -t rsa -b 2048 -f ./ansible_key -C "ansible", leave empty password, ansible doesn't handle well password protected keys :(
https://console.cloud.google.com/compute/metadata?resourceTab=sshkeys&project=PROJECT_NAME&scopeTab=projectMetadata
- Customize ./inventories/gcp.yml with those keys files/paths
- Customize ./ansible.cfg :
    - host_key_checking = False
    - remote_user = default user to run script with (must exist on GCP instance)
    - private_key_file = path to SSH key

- Add the ansible_key.pub to all used user accounts' ~/.ssh/authorized_keys on GCP instances
- Prevent keyboard-interactive SSH connections (will block pubkey)  :
    - Customize sshd configuration by removing "keyboard-interactive" method in AuthenticationMethods publickey,keyboard-interactive
    or better (depending if Google OS Login controls the section containingAuthenticationMethods)
    - Match User *
       AuthenticationMethods publickey

- Optional for checks : Activate Cloud Resource Manager API : https://console.developers.google.com/apis/api/cloudresourcemanager.googleapis.com/overview?project=PROJECT_ID

# VPN
- Clean the hosts table from the dump after Pritunl has started : mongosh mongodb://USER:PASSWORD@localhost:PORT/pritunl --eval 'db.hosts.deleteMany({"status": "offline"})'

## pgadmin4 - check if needed
- Create /opt/pgadmin
- Chown 5050 it

# Serveurs de synchronisation (web3c-sync)

Trois serveurs PUBLICS de synchronisation chiffrée de bout en bout, un conteneur Docker par instance, sur la
machine PARTAGÉE (ctdapi, dev, rotki, agenthub, xbot, docker-repo — aucun port existant n'est
réattribué). Entrées d'inventaire web3c du groupe `sync_servers` :

| Instance | Hôte d'inventaire | Nom public (CNAME → `proxy.web3c.cc`) | Port service | Port métriques |
|---|---|---|---|---|
| iptv | `sync-iptv` | sync-iptv.web3c.cc | 4710 | 9710 |
| banking | `sync-banking` | sync-banking.web3c.cc | 4711 | 9711 |
| aiteam | `sync-aiteam` | sync-aiteam.web3c.cc | 4712 | 9712 |

Aucun secret (inscription ouverte, pas de jeton administrateur) : rien dans le vault. Rôles : `sync-server-install`,
`-security`, `-monitoring`, `-remove`, `-purge`, plus `sync-backup-install`/`-remove`/`-purge`. L'image se construit SUR
L'HÔTE depuis `sync_server_src` (défaut `~/Dev/Apps/web3c-sync/server` sur le poste qui lance Ansible, rsync ; ce
sera un clone git quand le dépôt aura un remote), taguée par l'empreinte du contenu : rejeu sans changement = aucun
rebuild ni redémarrage.

## Certificat

Rien à émettre : le parc web3c utilise le certificat WILDCARD `*.web3c.cc` (rôles `cert-install`/`install-cert`,
`certbot certonly --dns-cloudflare -d "*.web3c.cc"`), qui couvre déjà `sync-iptv.web3c.cc`, `sync-banking.web3c.cc` et
`sync-aiteam.web3c.cc` (un seul niveau de sous-domaine). Le `certbot --expand` à liste de domaines du haut de ce
fichier ne concerne que papanglabs.com (certificat non wildcard). Si un jour le certificat web3c n'était plus wildcard,
la commande ponctuelle, à jouer à la main sur chaque proxy AVANT `update-proxy.yml` (comme pour
`analytics.papanglabs.com`), serait : `certbot certonly --expand --non-interactive --agree-tos -m <email>
--dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare_web3c.cc.ini -d <liste existante>,sync-iptv.web3c.cc,sync-banking.web3c.cc,sync-aiteam.web3c.cc`.

## Déploiement — ordre

**DNS : automatique.** `sync-server-install` publie lui-même le CNAME de l'instance (`proxy_hostname` →
front des proxies, tâche `cloudflare-dns-update`/`cnames` en portée réduite à l'hôte) au premier déploiement ;
aucune étape DNS séparée n'est nécessaire. `update-cloudflare-dns.yml` ne sert qu'à resynchroniser tout le parc.

1. `./play.sh web3c deploy-monitoring.yml` — ajoute le job Prometheus `sync-server` et le groupe d'alertes `sync`
   (`prom_alert_groups`). À jouer AVANT (ou APRÈS, `sync-server-monitoring` avertit si le job manque) le déploiement.
2. `./play.sh web3c deploy-sync-server.yml` — preflight, DOCKER-USER (`sync-server-security`, joué sur `ctdapi`), build +
   conteneurs + contrôles fonctionnels, supervision. Une instance : `--limit sync-iptv:ctdapi`. Supervision seule :
   `--tags monitoring`.
3. `./play.sh web3c update-proxy.yml` — pose les vhosts `sites-enabled/sync-<x>.conf` (publics, pas de whitelist ni
   X-Api-Key) ET le répertoire de journaux dédié `/var/log/nginx-sync/` avec sa rotation (`/etc/logrotate.d/nginx-sync`).
4. `./play.sh web3c deploy-backup.yml` — sauvegarde SQLite quotidienne (04:05/04:15/04:25) vers `backup-sync`.

Retrait : `./play.sh web3c remove-sync-server.yml [--limit sync-iptv]` (conserve données, sauvegardes, CNAME, vhost).
Purge, IRRÉVERSIBLE : `./play.sh web3c purge-sync-server.yml --limit sync-iptv -e sync_purge_confirm=yes` (exige une
sauvegarde de moins de 7 jours, sinon `-e sync_purge_no_backup=yes`; `-e sync_purge_backups=yes` supprime aussi les
archives ; retirer EN MÊME TEMPS l'entrée d'inventaire ou son `proxy_hostname`, sinon le CNAME est republié).

## Vérifications après déploiement

- Prometheus (sur `monitor`) : `count(sync_up{job="sync-server"})` doit valoir 3 (une règle sans série est décorative) ;
  `count(backup_last_success_timestamp_seconds)` doit valoir 5 une fois les sauvegardes jouées (6 avec la passerelle MCP) ;
  `service_up{service=~"sync-.*"}` à 1.
- Depuis une machine NON whitelistée (ni proxy, ni `monitor`) les ports 4710-4712 et 9710-9712 doivent être BLOQUÉS :
  `for p in 4710 4711 4712 9710 9711 9712; do nc -zv -w5 `ctdapi` $p; done` — tous en échec. Sur la machine,
  `iptables -S DOCKER-USER | grep -E '47(10|11|12)|97(10|11|12)'` doit montrer un DROP par port (`ufw status` ne prouve rien).
- `curl -fsS https://sync-iptv.web3c.cc/v1/health` répond `{"ok":true,"instance":"iptv",…}` (idem banking, aiteam) ;
  `curl -s -o /dev/null -w '%{http_code}' https://sync-iptv.web3c.cc/metrics` donne 404.
- Anti-usurpation : `curl -H 'X-Real-IP: 1.2.3.4' https://sync-iptv.web3c.cc/v1/health` — le proxy écrase l'en-tête
  (`proxy_set_header X-Real-IP $remote_addr`) ; le serveur ne fait confiance qu'aux /32 des proxies (SYNC_TRUSTED_PROXIES).

## Vie privée : journaux et sauvegardes

- Adresses IP : uniquement dans `/var/log/nginx-sync/{access,error}-<instance>.log` sur les proxies, `daily` + `rotate 6` +
  `maxage 7` (le fichier courant plus six générations = 7 jours au plus). Le format n'a ni corps, ni en-têtes d'auth, ni
  chaîne de requête, et masque les identifiants de groupe/document. Limite : les erreurs antérieures à la sélection du
  vhost (poignée de main TLS) vont au `/var/log/nginx/error.log` global, conservé 14 jours par la règle de la distribution.
- Sauvegardes : 14 générations quotidiennes. L'effacement d'un groupe est physique dans la base vivante, PAS dans les
  archives : un groupe supprimé reste (chiffré) dans les sauvegardes jusqu'à 14 jours.
- Restauration : procédure en tête du script `/usr/local/sbin/sync-backup-<instance>.sh` sur l'hôte. Repointer la
  destination : `deploy-backup.yml --tags retarget --limit sync_servers` (`retarget-backups-web3c.yml` ne couvre
  que les bases PostgreSQL : tradekong, ctdapi, passerelle MCP).

# Sauvegardes (famille `backup`)

`deploy-backup.yml` (retrait `remove-backup.yml`, purge `purge-backup.yml -e confirm=yes`, repointage
`retarget-backups(-web3c).yml`). Destinations = entrées du groupe `backups` ; les sources poussent en SSH, rien ne
transite par leur disque. Ce qui suit vaut pour PostgreSQL (`postgres-backup-install` : tradekong, ctdapi, passerelle MCP)
et SQLite (`sync-backup-install`) ; BRK et TimescaleDB (papanglabs) écrivent encore par `remote_username`.

## Compte dédié et passerelle sur la destination

- Compte `backup_account` (défaut `dbbackup`, rôle `backup-setup`, créé par la première source qui vise la
  destination) : compte dédié à toutes les sauvegardes de bases, sans lien avec FleetForge ; sans sudo ni groupe, mot
  de passe verrouillé. Jamais `backup` : compte SYSTÈME de toute Debian/Ubuntu
  (uid 34), qu'une mise à jour de la distribution peut remettre à `nologin` — le rôle refuse tout compte existant
  d'uid < 1000.
- Chaque clé de source : `restrict,from="<adresse IP littérale de la source>",command="/usr/local/sbin/backup-gate
  <racine> <nom> <générations> <plancher Go>"`. Quoi que demande le client, seule la passerelle s'exécute (aucun shell,
  aucun pty) : verbes fermés (`free-kb`, `last-success`, `put`, `commit`, `abort`, `list`, `get`), noms de fichiers à la
  grammaire des sauvegardes, répertoire `/home/<compte>/backups/<nom>` (0700) de LA source. Une source ne lit ni n'efface
  celles d'une autre. Chaque appel est journalisé (`journalctl -t backup-gate` : source, verbe, fichier, octets — jamais
  de contenu).
- **La destination tient la rétention et la fraîcheur, pas la source** : un nom de fichier porte un horodatage qui doit
  être une vraie date à moins de 26 h de l'horloge de la destination (sinon refusé) ; `commit` contrôle le fichier
  (flux gzip complet et NON VIDE, ou fichier age structurellement complet), le rend visible, élague au nombre de
  générations de la commande forcée selon l'heure de RÉCEPTION (mtime de la destination, qu'une source ne fixe pas), et
  n'écrit `last-success` (horloge de la destination) que si la nouvelle génération est encore là. Les scripts vérifient
  ensuite par `list` que leur fichier y est : sinon, échec (BackupFailed).
- Une écriture par source à la fois (verrou exclusif dans son répertoire) ; les `.tmp` d'un transfert interrompu sont
  effacés au transfert suivant, et tout appel d'une source efface ceux de SON répertoire restés plus de 6 h sans
  écriture (jamais ceux d'une autre source : une source abandonnée qui ne rappelle plus garde son `.tmp` — à
  supprimer à la main si le disque approche du plancher).
- Pare-feu (`backup-security`) : même logique qu'avant, sur le port SSH de LA destination (`ansible_port` de son entrée
  — une machine derrière un NAT a le sien). known_hosts de la source : clé d'hôte LUE sur la destination par la connexion
  d'Ansible (déjà authentifiée), plus de `ssh-keyscan` depuis le poste ; sur le port 22, l'entrée porte l'adresse seule.
  Règles ufw purement additives (une source retirée de l'inventaire garde son ouverture) : hors périmètre, comme pour
  les autres rôles de sauvegarde.
- Place libre exigée par la source avant d'écrire : `backup_min_free_gb` sur l'entrée de destination, **20 Go par
  défaut**. Sur une destination qui a moins de 20 Go libres, TOUTES les sauvegardes y échouent (BackupFailed, « Place
  insuffisante ») : régler la valeur sur l'entrée de destination (proxy1 : 132 Gio libres mesurés le 16/11/2026, la valeur
  par défaut convient ; mesurer `df -h /home` sur station avant d'y envoyer la passerelle). Plancher tenu par la
  passerelle PENDANT l'écriture, contrôlé à chaque Mio : `backup_floor_gb` (5 Go) — sous ce seuil, `put` s'arrête et
  efface son `.tmp`. Des sources différentes en parallèle peuvent chacune le dépasser d'au plus 1 Mio : le disque ne se
  remplit pas, il peut descendre de quelques Mio sous le plancher.
- authorized_keys du compte dédié dans sa maison (propriété du compte, comme le veut sshd) : aucun verbe n'y écrit, seul
  un contournement de la passerelle le pourrait. Un fichier possédé par root hors de la maison (`AuthorizedKeysFile`)
  imposerait de modifier sshd_config sur chaque destination : non fait, risque dit.

## Chiffrement (age)

- Posé par `backup_encrypt_recipient` (group_vars du parc) ou par entrée (`pgbak_encrypt_recipient`,
  `sync_backup_encrypt_recipient`) : `pg_dump | gzip | age -r <destinataire>` (`tar -cz | age` pour les serveurs de
  synchro), fichiers `.sql.gz.age` / `.tar.gz.age`. Compression AVANT chiffrement (un flux chiffré ne se compresse
  plus), en flux, mémoire constante. Pas de repli : `age` absent ou en échec, la sauvegarde échoue (BackupFailed) ; la
  passerelle `backup-gate` n'accepte un `.age` que structurellement complet (en-tête, destinataire, MAC, charge). Sans
  destinataire : en clair, comme avant — sauf la passerelle MCP, dont la garde l'EXIGE.
- Pourquoi age : paquet officiel (Ubuntu 22.04+, Debian 12+ ; installé par le rôle, jamais un binaire téléchargé),
  destinataire d'une ligne dans l'inventaire, pas de trousseau sur les sources (gpg en tiendrait un, et y écrirait la
  clé privée le temps d'une restauration), format authentifié par blocs de 64 Kio (un fichier tronqué ou modifié est
  refusé au déchiffrement). `openssl` ne chiffre pas en flux authentifié vers une clé publique (`cms -decrypt` charge
  tout en mémoire).
- Coût mesuré le 16/11/2026 sur le poste (300 Mio de dump synthétique, implémentation du format age v1 avec
  `cryptography`/OpenSSL, `age` n'étant pas installé sur le poste) : `gzip -6` 4,3 s CPU ; chiffrement du flux compressé
  (83 Mo) 0,16 s CPU (≈ 4 %, interpréteur compris) ; +20 Ko (0,025 %) ; mémoire constante (≈ 30 Mo pour 8 Mo comme pour
  83 Mo) ; aller-retour identique octet pour octet, mauvaise clé et fichier tronqué refusés. ChaCha20-Poly1305 seul
  (`openssl speed`) : ≈ 2 Go/s sur un cœur. Le coût est celui de gzip et de pg_dump, pas du chiffrement.

## Clé de l'opérateur (sur SON poste, jamais dans ce dépôt ni sur une machine du parc)

    brew install age            # ou : sudo apt install age
    mkdir -p ~/.config/fleetforge && cd ~/.config/fleetforge && umask 077
    age-keygen | age -p -a > backup-key.age   # clé privée chiffrée par une phrase de passe ; affiche « Public key: age1… »
    age -d backup-key.age | age-keygen -y     # redonne le destinataire public, à tout moment

Le destinataire public (`age1…`) va dans `backup_encrypt_recipient` (group_vars privé du parc, ce n'est pas un secret).
Deux copies hors ligne de `backup-key.age` (et de sa phrase de passe, séparément) : sans elles, les sauvegardes sont
illisibles. Rotation : nouveau destinataire → les sauvegardes suivantes l'utilisent ; garder l'ancienne clé tant que des
générations chiffrées pour elle existent (3 jours pour PostgreSQL, 14 pour les serveurs de synchro).

**Une clé DISTINCTE pour la passerelle MCP** (`pgbak_encrypt_recipient` sur son entrée, `backup-key-ffg.age` sur le
poste) : une restauration envoie la clé sur la machine de la base. Avec une seule clé de parc, restaurer ctdapi (machine
mutualisée) y enverrait aussi de quoi déchiffrer l'audit et les approbations de la passerelle.

## Restauration

- PostgreSQL, sur la machine de la base, UN mode par appel (deux modes = refus) : `<pgbak_dir>/postgres-restore.sh
  --check` (liste, sans clé), `--verify [--file <nom>]` (relit, déchiffre, décompresse, exige la ligne finale
  `-- PostgreSQL database dump complete`, n'écrit rien), `--yes [--file <nom>]` (application arrêtée) :
  1. relecture COMPLÈTE comme `--verify` ;
  2. place : sous 1,5 × `pg_database_size(<base>)` libres sur le volume PGDATA du conteneur (`df` dans le conteneur),
     arrêt AVANT toute écriture avec les chiffres — pas de disque plein en plein chargement ;
     chargement dans une base À CÔTÉ, `<base>_restore`, `ON_ERROR_STOP=1` — une erreur arrête tout, base vivante intacte ;
  3. les deux relectures doivent avoir la même empreinte sha256 ;
  4. échange en UNE transaction : la base vivante devient `<base>_before_<horodatage>` (GARDÉE, jamais supprimée par le
     script : `DROP DATABASE` à la main après validation — la machine doit avoir la place de deux copies), la copie
     devient `<base>`.
  Vérifié de bout en bout sur un PostgreSQL 17 jetable (vrai `pg_dump`, double de `docker` et d'`age`). Clé sur
  l'entrée standard, depuis le poste : `age -d ~/.config/fleetforge/backup-key.age | ssh -p <port> srvc@<machine>
  '<pgbak_dir>/postgres-restore.sh --verify'`. La clé reste en mémoire du script et passe à age par un tube : jamais un
  fichier, jamais un argument de processus.
- Serveurs de synchro : en-tête de `/usr/local/sbin/sync-backup-<instance>.sh` (`set -o pipefail`, extraction vérifiée
  avant de toucher aux données).

## Migration depuis l'ancien schéma (`remote_username` sur la destination)

Avant le compte dédié, une source posait sa clé SANS restriction sur `srvc` (sudo sans mot de passe) de la
destination, et ses sauvegardes, en clair, sous `<backup_root>/<nom>`. Au premier déploiement du nouveau schéma, par
source, et seulement APRÈS la pose de la clé restreinte sur le compte dédié :
- la clé de la source est RETIRÉE de `srvc` sur la destination (par son contenu, et par son commentaire
  `<source>-<nom>-backup`) — automatique ;
- les anciennes sauvegardes sont SIGNALÉES (« AVERTISSEMENT … fichier(s) de l'ancien schéma »), jamais supprimées
  d'office. Pour les garder dans le nouveau schéma : sur la destination, `sudo install -p -o dbbackup -g dbbackup
  -m 0600 <ancien fichier> /home/dbbackup/backups/<nom>/` (en le chiffrant d'abord si voulu : `age -r <destinataire>
  -o <fichier>.age <fichier>`, le nom gardant sa grammaire), vérifier par `postgres-restore.sh --check` puis
  `--verify` ; `-p` garde leur date : ils sortent de la rotation les premiers, au fil des nouvelles générations. Une fois
  les nouvelles sauvegardes validées, rejouer `deploy-backup.yml --limit <source>` avec
  `-e backup_legacy_purge=yes` pour supprimer `<backup_root>/<nom>`. Les purges (`purge-backup.yml`, `purge_old` de
  `retarget-backups-web3c.yml`) révoquent et suppriment aussi l'ancien schéma.
- **À vérifier après un changement de destination** : une clé restée sur `srvc` d'une destination ANTÉRIEURE (ex.
  `monitor`, une machine dont la destination a déjà changé une fois) n'est retirée que par `purge_old` vers CETTE
  machine — le retrait automatique ci-dessus ne vise que la destination courante. Contrôle : `authorized_keys` de
  `srvc` sur chaque ancienne destination (commentaire `<source>-<nom>-backup`).
- `purge_old` refuse l'adresse d'une destination encore en service, comparée après normalisation par le filtre
  `normalize_address` (`playbooks/filter_plugins/`, bibliothèque standard `ipaddress`, aucune dépendance) : espaces,
  casse, crochets, zéros omis, compression `::`, forme IPv4-mappée (`::ffff:192.0.2.1` = `192.0.2.1`) et zone IPv6
  (`%eth0`, ignorée) d'une même adresse sont reconnus égaux. Limite restante, volontaire : un NOM face à son adresse
  n'est pas reconnu égal (aucune résolution DNS dans un garde-fou) — donner l'adresse de l'ANCIENNE destination, et
  vérifier qu'elle n'est pas celle d'une destination en service avant de lancer.

## Supervision

`backup_last_*{backup="<nom>"}` (collecteur textfile). Par nom de `prom_alert_backup_max_age_hours` : `BackupStale`
(dernière réussite plus vieille que le seuil) et `BackupMissing` (`absent()` : aucune série depuis le seuil — jamais
installée, jamais passée, métrique perdue) ; `BackupFailed` pour tout échec. Ne déclarer un seuil que pour une sauvegarde
qui doit exister (une instance de synchro non déployée ferait sonner `BackupMissing`). `alert_exclude: [BackupMissing]`
sur une entrée n'a AUCUN effet : `absent()` ne porte pas de label `instance`, l'exemption par hôte ne s'y applique pas —
pour éteindre la règle, retirer le nom de `prom_alert_backup_max_age_hours`.

## Limites dites

- Rétention par nombre de générations : une base VIDÉE (ou une source compromise qui pousse des générations valides mais
  vides de sens) évince les bonnes copies en `<générations>` passages (3 jours pour PostgreSQL). La destination ne peut
  pas juger le contenu chiffré ; seuls la taille (`backup_last_size_bytes`, à surveiller dans la durée) et une
  vérification supervisée le révèlent.
- Une destination compromise peut effacer les sauvegardes, jamais les lire (sans la clé privée).

## Hors périmètre

BRK et TimescaleDB (papanglabs) : toujours `remote_username` sur la destination, sans chiffrement. Une seule destination par
sauvegarde, pas de copie hors ligne. Le compte dédié n'est jamais supprimé par `purge-backup.yml` (il peut porter d'autres
sources) : `userdel -r <compte>` à la main une fois la destination vide. Ouvertures ufw des destinations purement
additives (pas de retrait d'une source sortie de l'inventaire).

# Passerelle MCP de FleetForge (`fleetforge-gateway`)

App Nest privée (dépôt séparé) devant l'API d'automatisation de FleetForge, déployée par **le même
playbook** que FleetForge : `deploy-fleetforge.yml` (garde du groupe `fleetforge_gateways`, puis import de
`deploy-webapp.yml`, tag `gateway`). C'est une entrée de la famille GÉNÉRIQUE `webapp` avec le profil durci
`webapp_hardening` (`../docs/etude-passerelle-sur-webapp.md`). Mode d'emploi, prérequis et exposition : en-tête de
`deploy-fleetforge.yml`.

- **Entrée dédiée** (jamais `infras`, jamais la famille `fleetforge`), même quand elle partage la machine
  d'`infra1` (premier déploiement) : la déplacer = changer son `ansible_host`. Gardes sans connexion.
- **Comptes aval** `ffg_read` / `ffg_check` / `ffg_run` dans `ff_api_accounts` de l'entrée FleetForge, qui
  nomme la passerelle dans `access_linked` ; mots de passe au vault du parc, écrits dans le `.env` de l'app par
  `webapp_env_from_vault` (`no_log`) puis rechiffrés au coffre `.private/apps/fleetforge-gateway`.
- **Exposition E1** : vhost privé (gabarit générique) ; `/mcp` limité à la liste NOMMÉE de sa location
  (`webapp_vhost_locations[].access`, partiel `proxy-update/templates/_named_access.inc` : serveurs nommés,
  whitelist filtrée si accès de TEST, adresses VPN écartées) puis `deny all`. Ports publiés filtrés dans
  DOCKER-USER (proxies distants seulement).
- **Durcissement** (profil `webapp_hardening`) : compte Unix dédié `ffgateway`, compose durci exigé (contrôle
  statique avant déploiement, `docker inspect` après — conteneurs arrêtés en cas d'écart).
- **Contrôles statiques** : `scripts/webapp_hardening_check.py` et ses tests
  (`python3 -I scripts/test_webapp_hardening_check.py`, tenus par `cargo test -p fleetforge-core --test gateway_isolation`).
- Retrait : `remove-webapp.yml -e webapp=fleetforge-gateway`, `purge-webapp.yml -e webapp=fleetforge-gateway
  -e webapp_purge_confirm=fleetforge-gateway` (FleetForge intact).
- Étude d'isolation par VM légère : `../docs/etude-isolation-passerelle-vm.md`.

## Notes
