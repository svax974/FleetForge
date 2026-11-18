# Cloudflare DDNS IPv4

Famille `cloudflare-ddns` : conteneur Python Alpine sans dépendance Python
supplémentaire, contrôle au démarrage puis toutes les heures. Aucun port entrant.
Il mesure l'IPv4 publique de sortie de la machine (celle du NAT derrière un routeur),
force IPv4, ignore les proxies d'environnement et exige l'accord de deux services HTTPS.

## Déploiement

Ajouter `cloudflare-ddns` aux `ansible_roles` de l'entrée **canonique** de la
machine, et à `prom_alert_groups` dans les group_vars du parc (avec le groupe
`services` pour l'alerte d'arrêt). Une seule instance
par connexion publique ; pour plusieurs machines derrière le même NAT, en choisir une.

```sh
./play.sh <parc> deploy-cloudflare-ddns.yml --limit <machine>
```

L'unique entrée portant la famille `docker-repo` fournit le constructeur et
le registre. L'image est construite sur celui-ci, poussée sur son port local,
puis tirée par son `proxy_hostname` (repli : `hostname`). Les tags portent le
hash des sources et l'architecture cible (amd64/arm64). Une construction pour
une architecture différente nécessite le support habituel de Docker BuildKit.
Le registre doit avoir été installé via `deploy-docker-repo.yml`.

Les secrets viennent des group_vars existants : `cloudflare_token`,
`docker_repo_pass`, `docker_repo_pull_pass`. Comptes : `docker_repo_user`
(défaut `srvc`) et `docker_repo_pull_user` (défaut `srvc-pull`). Le token doit
permettre Zone Read et DNS Edit sur les zones visées. Il reste dans un fichier
0400 monté en lecture seule, hors image, arguments et environnement du conteneur.

## Paramètres

| Variable | Défaut | Sens |
| --- | --- | --- |
| `cloudflare_ddns_initial_ipv4` | **aucun — obligatoire** | IPv4 que les records portent AUJOURD'HUI, avant le premier passage. Sans défaut : la déduire d'`ansible_host` rendait le premier passage no-op (DNS faux, sonde verte) dès que l'inventaire était déjà à jour |
| `cloudflare_ddns_records` | **aucun — obligatoire** | Noms EXACTS que ce client a le droit de réécrire (`["proxy.web3c.cc", …]`). Aucun autre enregistrement n'est touché, même s'il porte la même adresse. Liste vide = refus au démarrage |
| `cloudflare_ddns_zones` | `["{{ domain_name }}"]` | Zones visées ; `[]` signifie toutes les zones accessibles au token |
| `cloudflare_ddns_dir` | `/opt/cloudflare-ddns` | Configuration et état persistant |
| `cloudflare_ddns_discovery_urls` | ipify IPv4 + icanhazip IPv4 | Au moins deux services HTTPS qui doivent répondre et s'accorder |

Si `ansible_host` est un nom DNS ou si l'IP a déjà changé, fournir l'ancienne
adresse présente dans les records : `-e cloudflare_ddns_initial_ipv4=1.2.3.4`.

## Réconciliation

Seuls les records **A** dont le NOM est dans `cloudflare_ddns_records` sont changés, dans les zones configurées — un voisin qui porte la même adresse n'est jamais touché. À chaque cycle, les records autorisés sont RELUS : une dérive (DNS remis à une ancienne valeur) est réparée même si l'IP n'a pas bougé, et le premier passage vérifie au lieu de supposer. Aucun changement des TXT/SPF, AAAA, MX, TTL,
proxy ou commentaire. Toutes les pages sont lues avant le premier PATCH
(`content` seul), y compris pour les records proxifiés.

Un journal dans `state/state.json` est synchronisé sur disque avant les écritures
Cloudflare. Un échec partiel ou un redémarrage reprend les mêmes records, même
si l'IP a encore changé. Un record modifié entre-temps vers une adresse étrangère
au journal bloque la reprise et le signale. Zéro correspondance avec l'ancienne
adresse est un échec et conserve la référence initiale. Nouvel essai à l'heure suivante.

Le client ne modifie pas l'inventaire. Un `update-cloudflare-dns.yml` joué avec
des IP périmées peut réintroduire l'ancienne adresse ; le client ne corrige pas
cette dérive tant que l'IPv4 réelle ne change pas de nouveau. Les adresses des
règles réseau et des cibles de supervision restent elles aussi gérées par l'inventaire.

## Supervision et retrait

`svcprobe` (9110) publie `service_up{service="cloudflare-ddns"}` et lit les métriques
de réconciliation dans `state/status.json` depuis l'hôte. Le rejeu avec
`--tags monitoring` installe ce collecteur sur un déploiement existant.
Sa cible et son ouverture de scrape sont partagées avec
les autres services de la machine.

**Le groupe d'alertes `cloudflare-ddns` n'est chargé que si Prometheus SCRAPE vraiment cette machine.**
Sur `station` (92.130.213.98, NAT domestique partagé avec hub, nuc, proxy2 et vpn1), le routeur ne redirige
que 9100 : svcprobe n'est pas joignable, donc `cloudflare_ddns_up` n'arrive jamais dans Prometheus et une règle
chargée y serait indiscernable d'une règle qui veille. Le groupe est donc absent de `prom_alert_groups` sur
web3c, et le déploiement le signale sans bloquer. Pour l'armer : ajouter la redirection du port svcprobe de la
machine côté routeur (hors Ansible), vérifier `count(cloudflare_ddns_up)` non nul dans Prometheus, PUIS
réajouter `cloudflare-ddns` à `prom_alert_groups`. Le déploiement échoue désormais si le PREMIER cycle du
client n'aboutit pas (jeton, zone ou liste de noms) : un déploiement vert prouve que Cloudflare a répondu.

```sh
./play.sh <parc> deploy-cloudflare-ddns.yml --limit <machine> --tags monitoring
./play.sh <parc> remove-cloudflare-ddns.yml --limit <machine>
./play.sh <parc> purge-cloudflare-ddns.yml --limit <machine> -e confirm=yes
```

Remove conserve configuration, token et état. Purge efface `/opt/cloudflare-ddns`
(un chemin personnalisé impose un nettoyage explicite). Les records DNS, les
images du registre et la cible svcprobe commune sont conservés.

Signaux d'usage : `IPv4 unchanged` confirme un contrôle sans écriture ;
`Updated A record` puis `IPv4 reconciled` confirment une rotation ;
`Reconciliation failed` et `cloudflare_ddns_up=0` exposent l'échec.
`cloudflare_ddns_last_success_timestamp_seconds` avance à chaque succès.
Alertes : `CloudflareDDNSFailing`, `CloudflareDDNSStale` (> 7500 s),
`CloudflareDDNSMetricsMissing` ; l'arrêt est couvert par `ServiceDown` (groupe `services`).

Validation locale : `python3 -B scripts/test_cloudflare_ddns.py -v`.
Le premier déploiement réel, la rotation d'IP et la reprise après erreur
Cloudflare restent à observer avec ces signaux. Aucun hôte réel n'est déployé
pour tester ce changement.

Références API : [liste paginée des records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
et [PATCH d'un record](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/).
