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
  `count(backup_last_success_timestamp_seconds)` doit valoir 5 une fois les sauvegardes jouées ; `service_up{service=~"sync-.*"}` à 1.
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
  que tradekong/ctdapi).

## Notes
