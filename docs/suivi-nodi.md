# Suivi du boîtier NOD-I Revival (`nodi`)

> Ouvert le 24/11/2026. Boîtier NOD-I v1 (CM4, SSD 1 To, écran ST7789) derrière le NAT domestique, SSH 1222.
> Fork `svax974/nodi-revival` : TOUTE la personnalisation vit dans `scripts/init.sh` du fork ; la famille Ansible
> `nodi` n'est qu'un lanceur (commit épinglé `nodi_ref`). Signaux : séries `nodi_*` de svcprobe (job `svcprobe`,
> cible `:9113`), alertes du groupe `nodi`, `service_up{service="nodi"}`.

## État au 24/11/2026

- Boîtier installé À LA MAIN le 23/11 (Bitcoin Core 32.1, archive, txindex=1, datadir `/mnt/bitcoin`, clone `/opt/nodi-revival`).
  Cockpit encore sur le port 8080 ; la cible est 4740 (`--http-port 4740`).
- Famille Ansible écrite, NON déployée, NON vérifiée sur la machine (jamais jouée sur un hôte réel pour « tester »).
- Hors inventaires avant ce jour : `srvc`/node_exporter/svcprobe peuvent manquer (`setup-server.yml`, `host-preflight` le dira).

## Reste à observer

| Point | Signal qui le valide | Condition de départ |
|---|---|---|
| Boîtier joignable par Ansible | `host-preflight` passe sur `nodi` ; `up{instance="92.130.213.98:9103"}` = 1 | Redirections routeur 1222, 9103, 9113 en place |
| Cockpit sur 4740 | `curl http://127.0.0.1:4740/api/health` = 200 sur le boîtier ; `iptables -S DOCKER-USER` montre le DROP du port 4740 | Rejeu de `init.sh --http-port 4740` puis `deploy-nodi.yml` |
| Vhost + CNAME | `nodi.web3c.cc` → `proxy-private.web3c.cc`, 200 depuis un VPN, 403 hors whitelist | `--tags dns,proxy-conf`, redirection routeur 4740 |
| Règles chargées | `count(nodi_bitcoin_up)` = 1 ; groupe `nodi` dans `/api/v1/rules` de `monitor` | `--tags monitoring,alerts` |
| P2P entrant | `nodi_bitcoin_peers` > 8 durablement | Redirection routeur 8333 |
| Mineur / écran | `nodi_miner_enabled`, `nodi_miner_running` ; agent d'écran actif | Seulement si `nodi_miner` / `nodi_display` activés |
| Ménage de l'ancien NOD-I | Aucune unité `nodi-nvme|mining|feargreed|stats`, plus d'image `hub.nod-i.com/*` | Premier passage de `init.sh` (pas d'état `.nodi-init.state`) |

## Anomalies à signaler si vues

`NodiBitcoinStalled` (aucun bloc en 3 h), `NodiBitcoinNoPeers`, `NodiDataDiskLow` (< 50 Go libres sur un SSD archive),
`NodiMinerStopped` (limite thermique). Un `deploy-nodi.yml` qui échoue sur « Local modifications exist » = fichier du clone
édité à la main sur le boîtier : le reporter dans le fork, jamais l'écraser.

## À décider

- `nodi_miner: true` posé dans l'inventaire (décision du 24/11/2026) ; `nodi_miner_address` à renseigner. Le mineur est à
  vérifier et activer sur le boîtier lors de la lecture de la machine. `nodi_display: true` posé sans lecture du boîtier.
- Montée de version : changer `nodi_ref` (commit complet du fork) dans les defaults du rôle ou en variable d'inventaire.
