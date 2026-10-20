/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

use crate::models::AnsiblePlaybook;
use anyhow::Result;
use std::path::Path;

/// Scan {playbooks_path}/*.yml and return a sorted list of playbooks.
pub fn list_playbooks(playbooks_path: &str) -> Result<Vec<AnsiblePlaybook>> {
    let dir = Path::new(playbooks_path);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut playbooks = Vec::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let (description, hosts, roles) = parse_playbook(&content);

        let (label, meta_description) = get_playbook_metadata(&name);
        let final_description = if !meta_description.is_empty() {
            meta_description
        } else {
            description
        };

        let category = categorize(&name);

        playbooks.push(AnsiblePlaybook {
            name,
            label,
            category,
            description: final_description,
            path: path.to_string_lossy().to_string(),
            hosts,
            roles,
        });
    }

    playbooks.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(playbooks)
}

/// Extract (description, hosts, roles) from a playbook file content.
/// Uses simple line-by-line scanning — no YAML parser dependency.
fn parse_playbook(content: &str) -> (String, String, Vec<String>) {
    let mut description = String::new();
    let mut hosts = String::new();
    let mut roles: Vec<String> = Vec::new();

    let mut in_roles_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // First `name:` at play level → description
        if description.is_empty() && (line.starts_with("- name:") || line.starts_with("  name:")) {
            if let Some(val) = trimmed.strip_prefix("name:") {
                description = val.trim().to_string();
            }
        }

        // First `hosts:` value
        if hosts.is_empty() && (line.starts_with("  hosts:") || line.starts_with("- hosts:") || trimmed.starts_with("hosts:")) {
            if let Some(val) = trimmed.strip_prefix("hosts:") {
                hosts = val.trim().to_string();
            }
        }

        // Detect start of a `roles:` block
        if trimmed == "roles:" {
            in_roles_block = true;
            continue;
        }

        // Detect end of roles block: non-indented line that isn't a list item
        if in_roles_block {
            if trimmed.starts_with("- ") && (line.starts_with("    -") || line.starts_with("  -")) {
                let role = trimmed.trim_start_matches("- ").trim().to_string();
                if !role.is_empty() && !roles.contains(&role) {
                    roles.push(role);
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                in_roles_block = false;
            }
        }
    }

    (description, hosts, roles)
}

/// Returns (label, description) for a known playbook name.
fn get_playbook_metadata(name: &str) -> (String, String) {
    match name {
        "update-journald-all" => ("Plafond du journal systemd".into(), "Applique la limite de taille et de rétention du journal systemd sur tout l'inventaire, et élague l'existant. Rattrapage du parc déjà en place ; `setup-server.yml` s'en charge sur une machine neuve.".into()),
        "update-ufw-all" => ("Rejeu des règles de pare-feu".into(), "Réapplique toutes les règles UFW et DOCKER-USER de l'inventaire après un changement de whitelist ou de VPN. Refuse de tourner si l'IP publique du poste n'est pas whitelistée (-e ufw_force_apply=true pour outrepasser).".into()),
        "deploy-readonly-user" => ("Déploiement compte lecture seule".into(), "Crée le compte SSH openclaw-ro, limité à la passerelle ro-gate (lecture seule, sorties caviardées), pour les clés de keys/<parc>/readonly/ (agents de diagnostic) et révoque celles qui en ont été retirées. Cibler les machines physiques avec --limit.".into()),
        "remove-readonly-user" => ("Suppression compte lecture seule".into(), "Retire le compte openclaw-ro et ses règles sudo.".into()),
        "purge-readonly-user" => ("Purge compte lecture seule".into(), "Retire le compte openclaw-ro, ses règles sudo et son répertoire personnel.".into()),
        "deploy-exporter-sys" => ("Déploiement exporteur système".into(), "Installe node_exporter sur les hôtes ciblés et enregistre leur cible auprès de Prometheus. Cibler les machines physiques avec --limit pour éviter les doublons.".into()),
        "remove-exporter-sys" => ("Suppression exporteur système".into(), "Retire node_exporter et sa cible Prometheus.".into()),
        "deploy-prometheus" => ("Déploiement Prometheus".into(), "Installe Prometheus sur prometheus1, déploie les règles d'alerte partagées, puis restreint l'accès au port 9090 à la whitelist et aux VPN.".into()),
        "remove-prometheus" => ("Suppression Prometheus".into(), "Retire le conteneur Prometheus en conservant la TSDB et la configuration.".into()),
        "purge-prometheus" => ("Purge Prometheus".into(), "Supprime Prometheus et tout l'historique des métriques. Destructif.".into()),
        "deploy-alertmanager" => ("Déploiement Alertmanager".into(), "Installe Alertmanager sur alertmanager1 (notifications e-mail) et filtre le port 9093 via ufw ET DOCKER-USER — publié par Docker, il serait sinon joignable sans authentification depuis Internet. Vaut pour les deux parcs. Requiert alertmanager_email_to.".into()),
        "remove-alertmanager" => ("Suppression Alertmanager".into(), "Retire le conteneur Alertmanager en conservant sa configuration et son état.".into()),
        "purge-alertmanager" => ("Purge Alertmanager".into(), "Supprime Alertmanager, sa configuration (identifiants SMTP) et son état. Destructif.".into()),
        "deploy-fleetforge" => ("Déploiement FleetForge (web)".into(), "Déploie l'application de gestion du parc, servie dans un navigateur : compilation sur la machine, service systemd, filtrage du port et cible Prometheus native. La machine devient un nœud de contrôle Ansible ; sans `ff_deploy_secrets=true` l'application voit le parc sans pouvoir le piloter. Avec, elle reçoit une clé SSH dédiée, autorisée sur le parc par le play `authorize` et restreinte à l'adresse de cette machine (`from=`). Prérequis : `npm run build` dans apps/gui. Le vhost appartient à update-proxy.yml.".into()),
        "remove-fleetforge" => ("Suppression FleetForge".into(), "Retire le service, les binaires, la cible Prometheus et les ouvertures de pare-feu. Conserve le code livré et la base locale.".into()),
        "purge-fleetforge" => ("Purge FleetForge".into(), "Supprime FleetForge, le code livré, l'arbre Ansible synchronisé et la base locale. Destructif.".into()),
        "update-proxy" => ("MAJ vhosts et pare-feu des proxies".into(), "Resynchronise les vhosts du parc (Ansible/parcs/<parc_name>/nginx/, gitignoré) et les règles ufw des proxies. Remplace update-proxy-web3c / update-proxy-papang. Vérifier d'abord avec --check --diff.".into()),
        "deploy-pushgateway" => ("Déploiement Pushgateway".into(), "Contrôle préalable, installation de la Prometheus Pushgateway (binaire natif sous srvc, séries persistées), filtrage ufw aux vpns, Prometheus, whitelist et pousseurs, puis cible Prometheus native. Exige un job `pushgateway` avec honor_labels: true dans la stack de supervision du parc.".into()),
        "remove-pushgateway" => ("Suppression Pushgateway".into(), "Retire le service, le binaire, la cible Prometheus et les règles ufw. Conserve les séries persistées.".into()),
        "purge-pushgateway" => ("Purge Pushgateway".into(), "Supprime la Pushgateway et son magasin de persistance. Destructif.".into()),
        "deploy-llmauth" => ("Déploiement LLM Auth".into(), "Déploie sur les proxies (groupe llmauth) le service de validation des clés d'API appelé par nginx (auth_request), avec contrôle d'exposition et supervision. Le vhost s'active quand la famille llmauth est portée par le proxy (update-proxy.yml).".into()),
        "remove-llmauth" => ("Suppression LLM Auth".into(), "Retire le service de validation des clés d'API des proxies en conservant la base des clés.".into()),
        "purge-llmauth" => ("Purge LLM Auth".into(), "Supprime le service de validation des clés d'API et sa base de clés, de façon irréversible.".into()),
        "deploy-aiserver" => ("Déploiement serveur IA".into(), "Contrôle préalable puis installation, pare-feu DOCKER-USER et supervision du serveur IA conteneurisé (llama.cpp, ComfyUI, DCGM) sur le groupe aiservers.".into()),
        "remove-aiserver" => ("Suppression serveur IA".into(), "Retire les conteneurs, le pare-feu, la sonde et les cibles du serveur IA en conservant les modèles.".into()),
        "purge-aiserver" => ("Purge serveur IA".into(), "Supprime le serveur IA et toutes ses données, modèles compris.".into()),
        "deploy-scripting" => ("Déploiement orchestrateur scripting".into(), "Contrôle préalable puis installation, sécurité et supervision de l'orchestrateur scripting (tâches cron Python d'autodéploiement et de maintenance) sur le groupe scripting_servers. Fichiers du parc : Ansible/parcs/<parc>/scripting/.".into()),
        "remove-scripting" => ("Suppression orchestrateur scripting".into(), "Arrête l'orchestrateur et retire son code en conservant configuration, logs et outputs.".into()),
        "purge-scripting" => ("Purge orchestrateur scripting".into(), "Supprime l'orchestrateur et toutes ses données, secrets du parc compris. Destructif.".into()),
        "deploy-searxng" => ("Déploiement relai SearXNG".into(), "Installe SearXNG (Docker) sur l'hôte `station`, filtre son port et pose sa supervision. L'exposition se déduit de la co-localisation : port sur 127.0.0.1 si tous les proxies autorisés sont sur la même machine, sinon 0.0.0.0 restreint à leurs IP dans DOCKER-USER. Le vhost appartient à update-proxy.".into()),
        "remove-searxng" => ("Suppression relai SearXNG".into(), "Retire le conteneur SearXNG, sa sonde et ses règles DOCKER-USER. Conserve la configuration et la clé secrète.".into()),
        "purge-searxng" => ("Purge relai SearXNG".into(), "Supprime SearXNG, son image, sa configuration, sa clé secrète et le CNAME public. Destructif.".into()),
        "deploy-freellm" => ("Déploiement FreeLLMAPI".into(), "Installe FreeLLMAPI (Docker Compose) sur l'entrée d'inventaire `freellm`, filtre son port et pose sa supervision. L'exposition se déduit de la co-localisation avec les proxies : port sur 127.0.0.1 si tous les proxies autorisés sont sur la même machine, sinon 0.0.0.0 restreint à leurs IP dans DOCKER-USER. Publie aussi le CNAME DNS vers le proxy. Le vhost appartient à update-proxy.".into()),
        "remove-freellm" => ("Suppression FreeLLMAPI".into(), "Retire le conteneur FreeLLMAPI, sa sonde et ses règles DOCKER-USER. Conserve la configuration, l'ENCRYPTION_KEY et les clés fournisseur importées.".into()),
        "purge-freellm" => ("Purge FreeLLMAPI".into(), "Supprime FreeLLMAPI, son image, son volume de données, sa configuration, son ENCRYPTION_KEY et le CNAME public. Destructif.".into()),
        "deploy-starnet" => ("Déploiement StarNet".into(), "Installe StarNet nativement sous srvc sur l'entrée d'inventaire `starnet` (tag épinglé, Node embarqué, systemd --user), publie le sidecar loopback via un relai systemd filtré par ufw aux proxies/whitelist/Prometheus/VPN, pousse le vhost starnet.conf (whitelist + supervision + VPN) sur les proxies et pose la supervision. Publie aussi le CNAME DNS.".into()),
        "remove-starnet" => ("Suppression StarNet".into(), "Retire StarNet (unité, relai, code, Node embarqué), sa sonde, ses règles ufw et son vhost sur les proxies. Conserve les workspaces et la configuration.".into()),
        "purge-starnet" => ("Purge StarNet".into(), "Supprime StarNet, ses workspaces, sa configuration, la clé des connecteurs, son vhost et le CNAME public. Destructif.".into()),
        "deploy-rotki" => ("Déploiement Rotki".into(), "Installe Rotki (conteneur autonome) sur l'hôte dédié `rotki` (machine partagée avec ctdapi/dev/docker-repo/xbot), filtre son port dans DOCKER-USER via docker_ports_rules (host_vars/ctdapi.yml, l'hôte canonique de cette machine), publie le CNAME rotki.web3c.cc vers le front des proxies, et pose sa supervision. Sidecar de valorisation de portefeuille pour la fusion WalletOptimizer → TradeKong (Phase 4.2), toujours publié sur 0.0.0.0 — clients : TradeKong (`tradekong`, appel direct) et les proxies (vhost public token-gated + UI restreinte VPN, déployés séparément par update-proxy.yml).".into()),
        "remove-rotki" => ("Suppression Rotki".into(), "Retire le conteneur Rotki et sa sonde. Conserve les volumes de données/logs et l'entrée docker_ports_rules.".into()),
        "purge-rotki" => ("Purge Rotki".into(), "Supprime Rotki, son image, ses volumes nommés (portefeuille valorisé, historique) et le CNAME public. Destructif — exige -e confirm=yes.".into()),
        "deploy-openclaw" => ("Déploiement OpenClaw".into(), "Installe OpenClaw NATIVEMENT (CLI officiel, systemd --user) sur l'hôte `hub`, sous le compte srvc, onboardé en mode non interactif, filtre son port à la whitelist/aux proxies/au LAN via ufw, puis pose sa supervision. Idempotent : si déjà installé et onboardé, seules les étapes annexes (pare-feu, supervision) sont rejouées.".into()),
        "remove-openclaw" => ("Suppression OpenClaw".into(), "Arrête OpenClaw (unité systemd --user), retire la sonde et les règles ufw. Conserve la configuration, le workspace et le jeton de gateway.".into()),
        "purge-openclaw" => ("Purge OpenClaw".into(), "Supprime le binaire OpenClaw, le Node embarqué, sa configuration, son workspace, ses secrets, son jeton de gateway, le CNAME public, sa clé SSH du parc et son clone FleetForge. Destructif.".into()),
        "deploy-agenthub" => ("Déploiement AgentCenter".into(), "Déploie le hub AgentCenter sur l'hôte `agenthub` (machine partagée avec ctdapi/dev/rotki) : CNAME agenthub.web3c.cc, vhost proxies (WebSocket), filtrage DOCKER-USER des ports 4700/4701, build + déploiement de l'app via les scripts du dépôt, supervision, puis activation du runner (tag runner, jeton en vault).".into()),
        "remove-agenthub" => ("Suppression AgentCenter".into(), "Arrête le hub et le runner, retire la sonde. Conserve données, volumes et l'entrée docker_ports_rules.".into()),
        "purge-agenthub" => ("Purge AgentCenter".into(), "Supprime le hub (conteneurs, images, volumes nommés) et le CNAME, désactive le runner. Destructif — exige -e confirm=yes.".into()),
        "deploy-llm-proxy" => ("Déploiement LLM Proxy".into(), "Déploie la passerelle LLM Proxy (OpenAI/Anthropic-compatible) sur l'entrée `llm-proxy` (machine partagée avec ctdapi/agenthub/rotki) : CNAME llm-proxy.web3c.cc, vhost public sur les proxies (passerelles en flux), filtrage DOCKER-USER des ports 4800-4803, build + déploiement de l'app via les scripts du dépôt, supervision.".into()),
        "remove-llm-proxy" => ("Suppression LLM Proxy".into(), "Arrête l'app (tous ses conteneurs) et retire la sonde. Conserve données, volumes, vhost, CNAME et l'entrée docker_ports_rules.".into()),
        "purge-llm-proxy" => ("Purge LLM Proxy".into(), "Supprime l'app (conteneurs, images, volumes) et le CNAME. Destructif — exige -e confirm=yes.".into()),
        "deploy-sync-server" => ("Déploiement serveurs de synchro".into(), "Déploie les trois serveurs web3c-sync PUBLICS (iptv 4710, banking 4711, aiteam 4712 ; métriques 9710-9712) en conteneurs sur `ctdapi` (machine partagée) : filtrage DOCKER-USER, image construite sur l'hôte depuis les sources du poste, CNAME, supervision (/metrics natif, sonde, règles d'alerte). Les vhosts se posent par update-proxy.yml, les sauvegardes par deploy-backup.yml. Aucun secret.".into()),
        "remove-sync-server" => ("Suppression serveurs de synchro".into(), "Retire les conteneurs web3c-sync, leurs sondes et cibles Prometheus. Conserve données, image, sauvegardes, CNAME, vhosts et entrées docker_ports_rules.".into()),
        "purge-sync-server" => ("Purge serveurs de synchro".into(), "IRRÉVERSIBLE : supprime une instance web3c-sync et ses données (base, blobs), le CNAME et le cron de sauvegarde. Exige -e sync_purge_confirm=yes et une sauvegarde récente ; toujours avec --limit sync-<instance>. -e sync_purge_backups=yes supprime aussi les archives.".into()),
        "deploy-monitoring" => ("Déploiement supervision web3c".into(), "Installe Prometheus en conteneur sur `monitor` (parc web3c) et déploie les règles d'alerte partagées. Grafana n'y est pas installé. Côté papanglabs : deploy-prometheus.".into()),
        "remove-monitoring" => ("Suppression supervision web3c".into(), "Arrête Prometheus sur `monitor` (configuration et historique conservés). Plus aucune alerte du parc ne part tant qu'il est arrêté.".into()),
        "purge-monitoring" => ("Purge supervision web3c".into(), "Supprime Prometheus, sa configuration et tout l'historique des métriques sur `monitor`.".into()),
        "deploy-proxy" => ("Déploiement Proxy".into(), "Installe Nginx en reverse proxy avec certificats SSL, vhosts du parc (Ansible/parcs/<parc_name>/nginx/) et pare-feu, puis la supervision.".into()),
        "remove-proxy" => ("Suppression Proxy".into(), "Arrête nginx sur les proxies ciblés (vhosts et certificats conservés). --limit recommandé.".into()),
        "purge-proxy" => ("Purge Proxy".into(), "Supprime nginx, les vhosts et les certificats des proxies ciblés. --limit recommandé.".into()),
        "deploy-back" => ("Déploiement Backend".into(), "Déploie les services backend avec sécurisation des ports applicatifs.".into()),
        "deploy-front" => ("Déploiement Frontend".into(), "Déploie les services frontend et configure le reverse proxy associé.".into()),
        "deploy-dbs" => ("Déploiement DB (maître + réplica)".into(), "Déploie le cluster PostgreSQL complet avec réplication streaming.".into()),
        "deploy-timescaledb-standalone" => ("Déploiement TimescaleDB (VPS neuf)".into(), "Bootstrap de la machine (root, port 22) puis import de deploy-timescaledb.yml. Seule différence avec ce dernier : la phase de bootstrap.".into()),
        "deploy-timescaledb" => ("Déploiement TimescaleDB".into(), "Déploie TimescaleDB self-hosted (indicateurs PapangMetrics) sur l'hôte `timescale` + sécurité.".into()),
        "remove-timescaledb" => ("Suppression TimescaleDB".into(), "Arrête TimescaleDB et ses sauvegardes sur `timescale` (conserve les données).".into()),
        "purge-timescaledb" => ("Purge TimescaleDB".into(), "Supprime TimescaleDB, ses données ET ses sauvegardes. Destructif — exige -e confirm=yes.".into()),
        "deploy-brk" => ("Déploiement BRK".into(), "Configure le nœud (server=1, ZMQ, prune=0) puis installe et lance BRK sur rpcbtc1.".into()),
        "remove-brk" => ("Suppression BRK".into(), "Supprime BRK (conserve les données calculées).".into()),
        "purge-brk" => ("Purge BRK".into(), "Supprime BRK et ses données calculées. Destructif.".into()),
        "deploy-esplora" => ("Déploiement Esplora".into(), "Configure le nœud (server=1, ZMQ, prune=0, comme BRK) puis construit et installe Esplora (mempool/electrs) sur l'entrée d'inventaire `esplora1` (co-localisée avec rpcbtc1/brk1), filtre son API REST (whitelist + hôtes de l'inventaire), publie le CNAME esplora.papanglabs.com vers le front des proxies, et pose sa supervision (endpoint Prometheus natif d'electrs). Exige un nœud fully synced. Le vhost appartient à update-proxy.yml.".into()),
        "remove-esplora" => ("Suppression Esplora".into(), "Retire le service Esplora, le binaire et sa cible Prometheus. Conserve l'index construit.".into()),
        "purge-esplora" => ("Purge Esplora".into(), "Supprime Esplora, son binaire, ses sources, son index construit et le CNAME public. Destructif — exige -e confirm=yes.".into()),
        "deploy-papangmetrics" => ("Déploiement PapangMetrics".into(), "Déploie le code + API + ETL + firewall sur brk1 (Node.js, build, services systemd).".into()),
        "remove-papangmetrics" => ("Suppression PapangMetrics".into(), "Arrête et supprime les services API + ETL (conserve le code).".into()),
        "purge-papangmetrics" => ("Purge PapangMetrics".into(), "Supprime services + code PapangMetrics. Ne touche pas à TimescaleDB.".into()),
        "migrate-papangmetrics" => ("Migration PapangMetrics".into(), "Déplace API + ETL d'un hôte à un autre (-e src_host=.. dst_host=..). App stateless (watermark en DB).".into()),
        "update-cloudflare-dns" => ("Synchronisation DNS Cloudflare".into(), "Aligne la zone Cloudflare sur l'inventaire : un enregistrement A par hôte portant un `hostname` dans la zone du parc. Sens unique, rien n'est supprimé. `--check` simule sans publier. Aucune machine n'est jointe.".into()),
        "deploy-papanglabs-back" => ("Déploiement back PapangLabs".into(), "Livre le code, construit l'image, démarre les conteneurs (back, worker, répartiteur, redis), filtre le port publié et pose la supervision. Prod et préprod partagent le playbook et ne diffèrent que par `pgb_env_file` en host_vars : jouer avec --limit. Tags : code, config, monitoring.".into()),
        "update-papanglabs-back" => ("Mise à jour back PapangLabs".into(), "Version légère de deploy-papanglabs-back : code + build + redémarrage + contrôle de santé, sans rejouer le pare-feu ni la supervision. Jouer avec --limit.".into()),
        "remove-papanglabs-back" => ("Suppression back PapangLabs".into(), "Arrête les conteneurs et retire la sonde. Conserve le code, les .env et les volumes.".into()),
        "purge-papanglabs-back" => ("Purge back PapangLabs".into(), "Suppression, plus les volumes (dont les graphiques générés), l'image, le répertoire livré et le CNAME public. Destructif.".into()),
        "deploy-papanglabs-front" => ("Publication front PapangLabs".into(), "Construit et publie le front sur Cloudflare Pages depuis le poste de contrôle, branche `main` (production) par défaut. Aucune machine du parc n'intervient, donc pas de contrepartie remove/purge : le seul geste équivalent effacerait le projet Pages et son historique.".into()),
        "setup-server" => ("Bootstrap serveur".into(), "Point d'entrée d'une machine NEUVE (root sur le port 22, ou le compte de l'image via -e ansible_user=… quand root est interdit) : SSH, hostname, outillage, utilisateur de service, compte lecture seule (si le parc déclare des clés readonly), node_exporter. Dépose le témoin /var/lib/fleetforge/state/setup-server.json. À jouer avec --limit.".into()),
        "deploy-btc-pipeline" => ("Déploiement pipeline BTC complet".into(), "Redéploie le pipeline entier dans l'ordre : nœud Bitcoin → BRK → TimescaleDB → ETL/API → sauvegardes → supervision, avec contrôle de bout en bout.".into()),
        "deploy-backup" => ("Déploiement sauvegardes".into(), "Sauvegardes off-host des deux parcs : magasin BRK et base d'indicateurs (papanglabs), PostgreSQL de tradekong/ctdapi et SQLite des serveurs de synchro (web3c), pare-feu des destinations et alertes de fraîcheur.".into()),
        "remove-backup" => ("Suppression sauvegardes".into(), "Arrête toutes les sauvegardes des deux parcs. Conserve les données sauvegardées et les scripts de restauration.".into()),
        "purge-backup" => ("Purge sauvegardes".into(), "Supprime les dispositifs ET les données sauvegardées (BRK, indicateurs, PostgreSQL tradekong/ctdapi). Destructif — exige -e confirm=yes.".into()),
        "retarget-backups" => ("Repointage sauvegardes".into(), "Repointe les sauvegardes après un changement d'adresse de `backup-brk`/`backup-timescale` : clés, pare-feu, known_hosts, scripts, puis vérification.".into()),
        "retarget-backups-web3c" => ("Repointage sauvegardes Web3C".into(), "Repointe les sauvegardes tradekong/ctdapi après un changement d'adresse de destination : clés, pare-feu, known_hosts, scripts, puis vérification.".into()),
        "deploy-tradekong" => ("Supervision TradeKong".into(), "Déploie la sonde svcprobe de TradeKong (endpoint de santé, back, PostgreSQL, Redis). La stack applicative elle-même est déployée hors Ansible.".into()),
        "remove-tradekong" => ("Suppression supervision TradeKong".into(), "Retire la sonde svcprobe de TradeKong.".into()),
        "purge-tradekong" => ("Purge TradeKong (Ansible)".into(), "Retire la sonde svcprobe et supprime la sauvegarde PostgreSQL de TradeKong. Destructif — exige -e confirm=yes. Ne touche pas à la stack applicative, hors Ansible.".into()),
        "deploy-ctdapi" => ("Supervision ctdapi".into(), "Déploie la sonde svcprobe de ctdapi (endpoint de santé, front, back, PostgreSQL, Redis). La stack applicative elle-même est déployée hors Ansible.".into()),
        "remove-ctdapi" => ("Suppression supervision ctdapi".into(), "Retire la sonde svcprobe de ctdapi.".into()),
        "purge-ctdapi" => ("Purge ctdapi (Ansible)".into(), "Retire la sonde svcprobe et supprime la sauvegarde PostgreSQL de ctdapi. Destructif — exige -e confirm=yes. Ne touche pas à la stack applicative, hors Ansible.".into()),
        "deploy-xbot" => ("Supervision xbot".into(), "Déploie la sonde svcprobe de xbot (front, back). La stack applicative elle-même est déployée hors Ansible.".into()),
        "remove-xbot" => ("Suppression supervision xbot".into(), "Retire la sonde svcprobe de xbot.".into()),
        "purge-xbot" => ("Purge xbot (Ansible)".into(), "Identique à remove — pas de sauvegarde à purger, xbot n'a pas de base de données.".into()),
        "restore-brk" => ("Restauration BRK".into(), "Restaure le magasin BRK depuis la dernière sauvegarde (-e confirm=yes, -e generation=previous). Sans confirmation : état des sauvegardes seul.".into()),
        "restore-timescale" => ("Restauration TimescaleDB".into(), "Restaure la base d'indicateurs depuis le dernier dump, ETL et API arrêtés le temps de l'opération (-e confirm=yes).".into()),
        "deploy-db-single" => ("Déploiement DB simple".into(), "Déploie une instance PostgreSQL standalone.".into()),
        "deploy-dbfront" => ("Déploiement DB Frontend".into(), "Déploie la base de données dédiée au frontend.".into()),
        "deploy-pgpool" => ("Déploiement PgPool".into(), "Déploie PgPool-II pour le pooling de connexions PostgreSQL.".into()),
        "deploy-vpn" => ("Déploiement VPN".into(), "Installe et configure l'infrastructure VPN Pritunl.".into()),
        "install-vpn-routes" => ("Installation routes VPN".into(), "Configure les règles de routage réseau pour le trafic VPN.".into()),
        // Ex-`deploy-mail-relay.yml`, renommé le 11/10/2026 : famille `mailserver`.
        "deploy-mailserver" => ("Déploiement relai SMTP".into(), "Installe Postfix + OpenDKIM multi-domaines, TLS Let's Encrypt (SNI), SASL, filtre Reply-To/préfixe sujet, Fail2ban et exporter Prometheus. Publie les enregistrements DNS Cloudflare (A, SPF, DKIM, DMARC). Variables : mail_domains, relay_user, relay_user_password, mailserver_dmarc_org_domains.".into()),
        "remove-mailserver" => ("Suppression relai SMTP".into(), "Arrête Postfix, OpenDKIM et l'exporter (certs et clés DKIM préservés).".into()),
        "purge-mailserver" => ("Purge relai SMTP".into(), "Supprime complètement le relai SMTP : services, certificats Let's Encrypt, clés DKIM, SASL et config.".into()),
        "deploy-dmarc-exporter" => ("Déploiement exporteur DMARC".into(), "Installe l'exporteur des rapports agrégés DMARC sur le relais (port 7489) et l'enregistre auprès de Prometheus. Les rapports quotidiens deviennent des métriques : plus de mail sauf anomalie. Variables : dmarc_exporter_imap_user, dmarc_exporter_imap_password, dmarc_exporter_rua_addresses.".into()),
        "remove-dmarc-exporter" => ("Suppression exporteur DMARC".into(), "Arrête et retire l'exporteur DMARC (état agrégé et cible Prometheus conservés).".into()),
        "purge-dmarc-exporter" => ("Purge exporteur DMARC".into(), "Supprime l'exporteur DMARC, son état agrégé, ses identifiants IMAP et sa cible Prometheus. Destructif.".into()),
        "deploy-rpcbtc" => ("Déploiement noeud Bitcoin".into(), "Installe et configure un noeud Bitcoin Core avec accès RPC.".into()),
        "deploy-docker-repo" => ("Déploiement registre Docker".into(), "Installe un registre Docker privé avec authentification.".into()),
        "deploy-install-cert" => ("Installation certificats SSL".into(), "Génère et installe les certificats Let's Encrypt via certbot.".into()),
        "deploy-wordpress" => ("Déploiement WordPress".into(), "Installe WordPress (Apache2, MySQL), publie le CNAME, ouvre le pare-feu, pose le vhost des proxies et la sonde.".into()),
        "deploy-ollama" => ("Déploiement Ollama".into(), "Installe Ollama sur l'entrée dédiée `ollama` (machine hub), publie le CNAME ollama.web3c.cc, restreint l'API 11434 (sans authentification) aux proxies, vpns, Prometheus et whitelist, puis pose la sonde. Vhost en mode privé via update-proxy. Aucun modèle téléchargé — voir deploy-ollama-model.".into()),
        "remove-ollama" => ("Suppression Ollama".into(), "Arrête Ollama, supprime le binaire, l'override systemd et la sonde (modèles préservés).".into()),
        "purge-ollama" => ("Purge Ollama".into(), "Supprime Ollama, tous les modèles, l'utilisateur système, la sonde, les règles de pare-feu et le CNAME public. Destructif.".into()),
        "deploy-ollama-model" => ("Déploiement modèle Ollama".into(), "Télécharge un modèle sur l'entrée `ollama`. Variable : ollama_model_name (requis).".into()),
        "remove-ollama-model" => ("Suppression modèle Ollama".into(), "Supprime un modèle sans toucher au service. Variable : ollama_model_name (requis).".into()),
        "deploy-opencode" => ("Déploiement opencode".into(), "Installe l'agent de codage opencode : un binaire pour la machine, une configuration globale par compte pointant sur le modèle gratuit MiMo V2.5 de OpenCode Zen, sans clé d'API (les modèles gratuits sont limités par IP publique, pas authentifiés). Ni sonde ni pare-feu — opencode n'a ni démon ni port d'écoute. --limit obligatoire.".into()),
        "remove-opencode" => ("Suppression opencode".into(), "Supprime le binaire système. Configuration, historique des sessions et identifiants des fournisseurs conservés. --limit obligatoire.".into()),
        "purge-opencode" => ("Purge opencode".into(), "Supprime le binaire, la configuration, opencode.db (sessions et identifiants des fournisseurs) et le modèle sélectionné, pour chaque compte. Destructif et irréversible : exige -e confirm=yes. --limit obligatoire.".into()),
        "update-opencode-model" => ("Mise à jour modèle opencode".into(), "Change le modèle par défaut d'une installation existante sans rien retélécharger, après contrôle de l'identifiant contre le catalogue OpenCode Zen. Variable : opencode_model (requis). --limit obligatoire.".into()),
        "deploy-llamacpp" => ("Déploiement moteur llama.cpp".into(), "Compile et installe llama-server (llama.cpp) sur le serveur cible. Aucun modèle n'est chargé — utiliser ensuite deploy-llamacpp-model.".into()),
        "remove-llamacpp" => ("Suppression llama.cpp".into(), "Arrête toutes les instances llama-server et supprime le binaire (modèles préservés).".into()),
        "purge-llamacpp" => ("Purge llama.cpp".into(), "Supprime le binaire, toutes les instances, tous les modèles GGUF téléchargés et les targets Prometheus associées.".into()),
        "deploy-llamacpp-model" => ("Déploiement modèle llama.cpp".into(), "Télécharge un modèle GGUF et démarre une instance llama-server dédiée, puis enregistre sa target Prometheus native (/metrics). Variables : llamacpp_model_name, llamacpp_model_url (requis), llamacpp_instance_id (défaut : 1 — incrémenter pour plusieurs modèles en parallèle).".into()),
        "remove-llamacpp-model" => ("Suppression modèle llama.cpp".into(), "Arrête l'instance llama-server, supprime le fichier GGUF et retire la target Prometheus. Variables : llamacpp_model_name (requis), llamacpp_instance_id (défaut : 1).".into()),
        "deploy-astar" => ("Déploiement noeud Astar".into(), "Installe la dernière release du collator Astar, configure le service systemd et enregistre ses deux endpoints Prometheus natifs — parachaîne 9615 et relais 9616. Variable : astar_node_name. --limit obligatoire.".into()),
        "remove-astar" => ("Suppression noeud Astar".into(), "Arrête le collator, supprime le binaire, l'utilisateur système et la cible Prometheus (blockchain préservée). --limit obligatoire.".into()),
        "purge-astar" => ("Purge noeud Astar".into(), "Supprime le collator, la cible Prometheus et toute la blockchain (~500 GB en mode archive : plusieurs jours de resynchronisation). Exige -e confirm=yes. --limit obligatoire.".into()),
        "deploy-theta-edge" => ("Déploiement noeuds Theta Edge".into(), "Déploie theta_edge_instances noeuds Theta Edge (une identité par instance), vérifie leur exposition, installe l'exporter Prometheus et rapatrie les clés sur le poste. Hôtes portant theta-edge dans ansible_roles ; theta_passwd (vault) requis.".into()),
        "remove-theta-edge" => ("Suppression noeuds Theta Edge".into(), "Arrête toutes les instances et retire la supervision (clés et données préservées).".into()),
        "purge-theta-edge" => ("Purge noeuds Theta Edge".into(), "Rapatrie les clés sur le poste puis supprime instances, supervision, sweep, données et clés. Exige -e confirm=yes.".into()),
        "export-theta-edge-keys" => ("Export clés Theta Edge".into(), "Rapatrie sur le poste (~/.config/fleetforge/theta-edge/<hôte>/) le keystore du noeud, la mnémonique du wallet interne et le Summary de staking de chaque instance.".into()),
        "deploy-theta-edge-sweep" => ("Sweep TFuel Theta Edge".into(), "Déploie un cron Node.js qui transfère le TFuel de chaque noeud au-delà d'un seuil vers theta_wallet.".into()),
        "remove-theta-edge-sweep" => ("Suppression sweep TFuel".into(), "Supprime le cron et les scripts de sweep TFuel.".into()),
        "purge-theta-edge-sweep" => ("Purge sweep TFuel".into(), "Supprime le sweep TFuel et son journal.".into()),
        "deploy-mtbridge" => ("Déploiement MTBridge".into(), "Installe MTBridge sur les hôtes Windows (groupe mtbridges) et enregistre la target Prometheus sur le monitor. Variables : mtbridge_github_token (vault), mtbridge_api_key (vault, optionnel), app_port (inventaire, défaut 5005).".into()),
        "remove-mtbridge" => ("Suppression MTBridge".into(), "Arrête la tâche planifiée MTBridge et retire la target Prometheus (données préservées).".into()),
        "purge-mtbridge" => ("Purge MTBridge".into(), "Supprime complètement MTBridge : tâche planifiée, répertoire d'installation, données MT5, règles firewall et target Prometheus.".into()),
        "remove-wordpress" => ("Suppression WordPress".into(), "Retire Apache2/MySQL, la sonde, les règles ufw et le vhost (données conservées).".into()),
        "purge-wordpress" => ("Purge WordPress".into(), "Supprime WordPress, sa base, ses fichiers, la sonde, les règles ufw et le vhost.".into()),
        "backup-wordpress" => ("Sauvegarde WordPress".into(), "Sauvegarde les fichiers et la base de données WordPress.".into()),
        "restore-wordpress" => ("Restauration WordPress".into(), "Restaure WordPress depuis une sauvegarde précédente.".into()),
        "deploy-copyfail-patch" => ("Patch CVE-2026-31431 Copy Fail".into(), "Mitigation algif_aead + mise à jour kernel sur tous les hôtes Linux. Debian/Ubuntu : blacklist modprobe immédiate. RedHat/Suse : initcall_blacklist via grubby. Variables : copyfail_upgrade_kernel (défaut: true), copyfail_reboot (défaut: false — recommandé true sur RedHat/Suse).".into()),
        "remove-copyfail-patch" => ("Retrait mitigation Copy Fail".into(), "Retire la blacklist modprobe algif_aead (Debian/Ubuntu) et l'argument initcall_blacklist du cmdline kernel (RedHat/Suse). Le kernel n'est pas rétrogradé.".into()),
        "purge-copyfail-patch" => ("Purge mitigation Copy Fail".into(), "Identique à remove — aucune donnée persistante associée à cette mitigation.".into()),
        _ => {
            let label = name.replace('-', " ");
            let label = label
                .split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().to_string() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            (label, String::new())
        }
    }
}

fn categorize(name: &str) -> String {
    if name.contains("monitor")
        || name.contains("pushgateway")
        || name.contains("exporter")
        || name.contains("prometheus")
        || name.contains("alertmanager")
    {
        "Monitoring".to_string()
    } else if (name.contains("proxy") && !name.contains("llm-proxy")) || name.contains("cert") {
        // `llm-proxy` est une passerelle LLM, pas un reverse proxy du parc :
        // rangé plus bas avec l'IA.
        "Proxy / SSL".to_string()
    } else if name.contains("db") || name.contains("pgpool") {
        "Base de données".to_string()
    } else if name.contains("vpn") {
        "VPN".to_string()
    } else if name.contains("mail") {
        "Mail".to_string()
    } else if name.contains("rpcbtc") || name.contains("btc") || name.contains("astar") || name.contains("theta") {
        "Blockchain".to_string()
    } else if name.contains("mtbridge") {
        "Trading".to_string()
    } else if name.contains("scripting") {
        "Orchestration".to_string()
    } else if name.contains("docker") {
        "Docker".to_string()
    } else if name.contains("wordpress") || name.contains("backup") || name.contains("restore") {
        "WordPress".to_string()
    } else if name.contains("ollama")
        || name.contains("llamacpp")
        || name.contains("searxng")
        || name.contains("opencode")
        || name.contains("openclaw")
        || name.contains("agenthub")
        || name.contains("llm-proxy")
        || name.contains("freellm")
        || name.contains("starnet")
        || name.contains("aiserver")
        || name.contains("llmauth")
    {
        "IA / LLM".to_string()
    } else if name.contains("copyfail") {
        "Sécurité".to_string()
    } else if name.contains("front") {
        "Frontend".to_string()
    } else if name.contains("back") {
        "Backend".to_string()
    } else {
        "Autre".to_string()
    }
}
