# Étude : isolation de la passerelle par VM légère

> Date : 15/11/2026 · Statut : **étude seulement** — rien n'est implémenté, aucune machine n'a été
> contactée. (Mise à jour du 16/11/2026 : la passerelle est affectée à une machine propre, `185.237.252.206`, hors du
> nœud de contrôle ; le risque « noyau partagé avec `infra1` » ci-dessous vaut alors pour les autres applications de
> cette machine, non pour le nœud de contrôle. Voir `etude-passerelle-sur-webapp.md`, « Machine distante ».) Contexte : la passerelle MCP de FleetForge (`fleetforge-gateway`, étape 6.6 du lot 6)
> démarre sur la MÊME machine que le nœud de contrôle `infra1` (décision du 15/11/2026). Cette étude
> regarde comment lui donner un **noyau séparé sur ce même serveur**, sans nouvelle adresse publique,
> avec une entrée d'inventaire dédiée dont `ansible_host` deviendrait l'adresse de la VM.

## 1. Ce qu'on cherche à protéger

Sur la machine d'`infra1` vivent la clé SSH de pilotage du parc (agent ssh), le mot de passe du vault,
l'arbre Ansible et les clés publiques du parc, plus d'autres services (proxy, supervision, relais mail…).
La passerelle, elle, détient trois comptes d'automatisation bornés (`ffg_read`, `ffg_check`, `ffg_run`)
et sera un jour exposée (E2/E3, OAuth). Aujourd'hui (conteneurs durcis, compte Unix dédié, DOCKER-USER) :

| Attaque | Conteneurs durcis (état du 15/11/2026) | VM légère (KVM) | gVisor `runsc` |
|---|---|---|---|
| RCE Node dans la passerelle | trois comptes bornés + ce que lit l'uid dédié dans le conteneur | idem, confinée à la VM | idem |
| Évasion de conteneur (runc, montage, capacité) | atteint l'hôte avec l'uid dédié (pas srvc, pas docker) | reste dans la VM | très réduite (pas d'appels système directs à l'hôte) |
| Faille du noyau (élévation de privilèges) | **root sur l'hôte → clés du parc, vault** | root dans la VM seulement ; il faut en plus une faille de l'hyperviseur | surface réduite à l'API du « Sentry » (~70 appels hôte), pas nulle |
| Lecture des clés du parc | possible après élévation noyau | impossible sans évasion de l'hyperviseur | possible après évasion du Sentry + élévation |
| Réseau vers les services locaux de l'hôte | filtré par DOCKER-USER / ufw | filtré par la chaîne FORWARD/INPUT de l'hôte (à écrire) | comme les conteneurs |
| Canaux auxiliaires (cache, CPU partagé) | non traités | non traités | non traités |

Seule une VM matérielle sépare le **noyau**. gVisor réduit fortement la surface du noyau sans la supprimer.

## 2. Options réalistes sur Linux

| Option | Principe | Pour | Contre |
|---|---|---|---|
| **KVM/QEMU + libvirt** (type `q35`, ou `microvm` pour démarrer vite) | VM complète, image cloud Ubuntu + cloud-init | outillage connu (virsh, virt-install), disque qcow2, sauvegardes simples, Ansible la voit comme une machine ordinaire | QEMU = grosse surface d'attaque côté hôte (atténuée par `microvm`, seccomp, AppArmor/sVirt) ; ~150–250 Mio de surcoût |
| **Firecracker** (+ `jailer`) | microVM minimale (virtio-net/blk seulement) | surface d'hyperviseur très petite, démarrage < 1 s, ~5 Mio de surcoût VMM | pas de libvirt : noyau invité, rootfs, réseau tap, cycle de vie à écrire soi-même ; mises à jour du noyau invité à la main |
| **Cloud Hypervisor** | microVM en Rust, virtio, hotplug | petite surface, plus outillé que Firecracker (API REST, images cloud) | moins répandu, documentation d'exploitation plus mince |
| **Kata Containers** (runtime OCI) | chaque pod/conteneur dans une microVM (QEMU/CH/Firecracker) | garde le compose de l'app ; `runtime: kata` par service | installation lourde (runtime + noyau + image), intégration Docker moins nette que containerd ; débogage plus difficile |
| **Repli sans virtualisation : gVisor `runsc`** | noyau en espace utilisateur (Sentry) qui intercepte les appels système ; **pas une VM** | aucune virtualisation requise (plateforme `systrap`), un `runtime: runsc` par service | surcoût E/S et appels système (Postgres en souffre) ; compatibilité à vérifier ; isolement du noyau partiel |

Toutes les options matérielles exigent `/dev/kvm` sur l'hôte.

## 3. Prérequis : virtualisation disponible chez l'hébergeur — INCONNU

La machine d'`infra1` est elle-même un VPS (`provider` de son entrée). La virtualisation **imbriquée**
n'y est disponible que si l'hébergeur l'expose. À vérifier par le propriétaire, **en lecture seule**
(aucune installation, aucun module chargé, aucun redémarrage) :

```sh
systemd-detect-virt                         # kvm/qemu/vmware… : on est déjà dans une VM
grep -cE '(vmx|svm)' /proc/cpuinfo          # 0 = instructions de virtualisation NON exposées
lscpu | grep -i virtuali                    # « VT-x » / « AMD-V » attendu
ls -l /dev/kvm                              # absent = pas de KVM utilisable
lsmod | grep -E '^kvm'                      # modules kvm / kvm_intel / kvm_amd chargés ?
```

`vmx`/`svm` présents ET `/dev/kvm` présent : KVM utilisable. Sinon, seul gVisor (ou une autre machine)
reste possible. Ne pas lancer `modprobe kvm_*` « pour voir » sur la machine de production : une
modification du noyau de l'hôte du nœud de contrôle se décide, elle ne s'essaie pas.

## 4. Réseau (sans nouvelle adresse publique)

- **NAT sur un pont privé de l'hôte** (ex. `virbr-ffg`, 10.73.0.0/24) : la VM n'a qu'une adresse privée.
  Le parc la décrit comme hub/nuc derrière le NAT domestique : **même `ansible_host` que l'hôte,
  `ansible_port`, `monitor_port`, `svcprobe_port` propres**, redirigés par l'hôte vers la VM (DNAT,
  ports à inscrire au registre). `host-preflight`, `setup-server.yml`, svcprobe et node_exporter la
  traitent alors comme une machine ordinaire (identifiée par adresse + port SSH, CLAUDE.md § 2).
- **Proxies → passerelle** : proxy1 (sur l'hôte) joint directement l'adresse privée de la VM ; les
  proxies distants passent par un DNAT de l'hôte vers la VM, filtré dans la chaîne FORWARD (même
  règle qu'aujourd'hui : proxies distants seulement). Le vhost (générique, `webapp.conf.j2`) vise déjà
  `ansible_host:app_port` : il faudrait alors une adresse de service distincte de l'adresse SSH
  (variable à ajouter à l'entrée).
- **Passerelle → FleetForge** : par l'URL d'automatisation (`https://infra.<domaine>`). Depuis la VM,
  le paquet vers l'adresse publique de l'hôte arrive en local avec l'adresse de la VM :
  `access_local_cidrs: [<sous-réseau du pont>]` sur l'entrée (mécanisme déjà livré).
- **Rien d'autre** : chaîne INPUT de l'hôte pour le pont = 443 (proxy local) et DNS, tout le reste
  rejeté (en particulier 9750 direct, 9090/9093, 22, le relais mail). C'est le point qui fait la
  valeur de la VM : sans lui, la VM voit les services de l'hôte comme n'importe quel conteneur.

## 5. Stockage, sauvegardes, mises à jour, supervision

- **Disque** : qcow2 (libvirt) ou fichier brut (Firecracker/CH) sous un répertoire root de l'hôte, hors
  `/home/srvc`. La base Postgres de la passerelle vit DANS la VM (volume Docker ou paquet).
- **Sauvegardes** : `postgres-backup-install` tel quel, la VM étant une machine du parc ;
  destination une AUTRE machine (les entrées `backup-*` de web3c sont sur la machine d'`infra1`).
  Optionnel : instantané du disque de la VM (cohérence Postgres non garantie sans `pg_dump`).
- **Noyau invité** : libvirt/Ubuntu cloud → `unattended-upgrades` + redémarrage planifié de la VM.
  Firecracker/CH : noyau fourni par l'hôte, à reconstruire/mettre à jour à la main — c'est leur
  principal coût d'exploitation.
- **Supervision** : node_exporter + svcprobe dans la VM (ports de scrape redirigés), sondes de la
  passerelle inchangées ; plus une sonde côté hôte que la VM tourne (`virsh domstate` / processus VMM).

## 6. Surcoût

| Option | Mémoire hôte | CPU | Disque |
|---|---|---|---|
| KVM/QEMU (libvirt) | invité ~1,5 Gio (Node + Postgres + front) + ~200 Mio QEMU | 1–2 vCPU partagés, surcoût < 5 % | image ~3–5 Gio + données |
| Firecracker / Cloud Hypervisor | invité ~1,5 Gio + ~5–20 Mio VMM | idem | rootfs ~1–2 Gio + données |
| Kata | ~130–200 Mio par pod + invité | idem | images Kata |
| gVisor | ~50 Mio par Sentry | +10 à +50 % sur les appels système et les E/S (Postgres) | — |

Chiffres d'ordre de grandeur (documentation publique des projets), **non mesurés** sur cette machine.

## 7. Intégration Ansible

- Nouvelle famille d'**hôte de VM** (création, pont, DNAT, filtrage, sonde « VM en marche ») sur
  l'entrée canonique de l'hôte — rôle à écrire (`<famille>-install/-remove/-purge/-security/-monitoring`).
- La VM : entrée du parc ordinaire, `setup-server.yml --limit <vm>` puis l'entrée dédiée de la passerelle
  y pointe (`ansible_host` + ports). Aucun rôle ne change (famille `webapp`, profil `webapp_hardening`) :
  ils ne contiennent ni adresse ni chemin de machine (vérifié par `scripts/webapp_hardening_check.py`).
- gVisor : rôle d'installation de `runsc` sur l'hôte (dépôt APT officiel), `runtime: runsc` dans le
  compose durci de l'app, contrôle `docker inspect … .HostConfig.Runtime` dans `tasks/runtime.yml`.

## 8. Recommandation et effort

1. **Vérifier `/dev/kvm`** (§ 3) — S, une commande, aucune modification.
2. **Si KVM est disponible : KVM/QEMU + libvirt + image cloud Ubuntu** (type `microvm` si le noyau
   invité le permet). C'est l'option qui sépare le noyau avec l'outillage le plus courant ; Firecracker
   ne vaut son coût d'exploitation que pour beaucoup de VM éphémères. Effort **M** (rôle d'hôte de VM,
   réseau/DNAT/filtrage, supervision, registre des ports, revue).
3. **Sans KVM : gVisor `runsc` pour les services de code** (back, back-worker) en attendant mieux —
   effort **S** — et le dire honnêtement : ce n'est pas une VM.
4. Dans les deux cas, **une petite machine séparée** reste l'isolation la plus simple et la plus forte
   (option D du plan 06 §2.1) : effort **S** côté Ansible (changer `ansible_host`), coût d'hébergement en plus.

### Séquence de migration depuis le déploiement sur l'hôte

1. Créer la VM (ou la machine), `setup-server.yml --limit <vm>` ; inscrire ses ports au registre.
2. `remove-webapp.yml -e webapp=fleetforge-gateway` sur l'emplacement ACTUEL (avant de changer l'adresse) —
   les volumes restent ; exporter la base (`pg_dump`) si elle porte déjà des credentials/audit.
3. Changer l'entrée dédiée : `ansible_host` (+ `ansible_port`, `monitor_port`, `svcprobe_port` derrière
   le NAT de l'hôte), `provider`, `access_local_cidrs` (pont de la VM, ou vide sur une autre machine),
   `webapp_hardening.docker_subnet` si besoin.
4. `deploy-fleetforge.yml -e ff_deploy_scope=gateway` (garde, pare-feu, vhost, app, durcissement,
   supervision) ; restaurer
   la base ; vérifier les sondes `upstream_<id>` et `service_up`.
5. `deploy-fleetforge.yml -e ff_deploy_scope=fleetforge --tags proxy-conf` (vhost de FleetForge :
   nouvelle adresse dans `access_linked`), puis `purge` des restes sur l'hôte.

### Condition de bascule vers E2/E3 (OAuth public)

Aucune exposition publique tant que la passerelle partage le **noyau** du nœud de contrôle. Préalables :
passerelle sur une autre machine ou dans une VM matérielle (pas gVisor seul) ; `whitelist: false` dans
l'`access` de `/mcp` ; revue du lot 4 (OAuth) et de l'E2 ; plages d'adresses du consommateur vérifiées ; revue Opus
indépendante du réseau de la VM (§ 4, « Rien d'autre »).
