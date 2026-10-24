/**
 * FleetForge
 *
 * Copyright © 2025 Stéphane VAXELAIRE
 * SPDX-License-Identifier: MIT — see LICENSE
 */

use crate::models::AnsibleRole;
use anyhow::Result;
use std::path::Path;

/// Scan {playbooks_path}/roles/ and return a sorted list of roles.
pub fn list_roles(playbooks_path: &str) -> Result<Vec<AnsibleRole>> {
    let roles_dir = Path::new(playbooks_path).join("roles");
    if !roles_dir.exists() {
        return Ok(vec![]);
    }

    let mut roles = Vec::new();

    for entry in std::fs::read_dir(&roles_dir)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let tasks_main = path.join("tasks").join("main.yml");
        let templates_dir = path.join("templates");
        let handlers_dir = path.join("handlers");

        let has_tasks = tasks_main.exists();
        let has_templates = templates_dir.exists();
        let has_handlers = handlers_dir.exists();

        let (label, meta_description) = get_role_metadata(&name);
        let description = if !meta_description.is_empty() {
            meta_description
        } else if has_tasks {
            extract_description(&tasks_main)
        } else {
            String::new()
        };

        let category = categorize(&name);

        roles.push(AnsibleRole {
            name,
            label,
            category,
            description,
            path: path.to_string_lossy().to_string(),
            has_tasks,
            has_templates,
            has_handlers,
        });
    }

    // Sort by category then name
    roles.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(roles)
}

/// Extract the first descriptive comment from tasks/main.yml.
/// Looks for a line starting with "# " that comes after the "---" front matter.
fn extract_description(tasks_main: &Path) -> String {
    let content = match std::fs::read_to_string(tasks_main) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let mut past_front_matter = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "---" {
            past_front_matter = true;
            continue;
        }
        if past_front_matter && trimmed.starts_with("# ") {
            return trimmed[2..].to_string();
        }
    }

    String::new()
}

/// Returns (label, description) for a known role name.
/// Falls back to (formatted name, "") for unknown roles.
fn get_role_metadata(name: &str) -> (String, String) {
    match name {
        // Sécurité
        "security-ssh" => ("Sécurisation SSH (bootstrap)".into(), "Bascule SSH sur le port du parc et pose les règles UFW restreintes lors du bootstrap. Neutralise au passage le jeu de règles iptables des images cloud qui rendrait UFW décoratif. Pose les clés de keys/<parc>/ sur root.".into()),
        "ssh-security-update" => ("MAJ sécurité SSH".into(), "Applique les mises à jour de configuration SSH et des règles firewall sur les serveurs existants.".into()),
        "create-user-remove" => ("Suppression utilisateur système".into(), "Supprime l'utilisateur de service et son répertoire personnel.".into()),
        "firewall-security" => ("Restrictions firewall".into(), "Applique des règles de restriction réseau avancées via UFW.".into()),
        "back-security" => ("Sécurité backend".into(), "Configure les règles firewall spécifiques aux serveurs backend (ports applicatifs).".into()),
        "front-security" => ("Sécurité frontend".into(), "Configure les règles firewall pour les serveurs frontend.".into()),
        "db-security" => ("Sécurité base de données".into(), "Configure les règles firewall pour protéger l'accès aux serveurs PostgreSQL.".into()),
        "dbpool-security" => ("Sécurité PgPool".into(), "Règles firewall pour les instances de connection pooling PgPool.".into()),
        "docker-repo-security" => ("Sécurité registre Docker".into(), "Sécurise l'accès au registre Docker privé via UFW.".into()),
        // Les rôles `mail-*` sont décrits plus bas, marqués dépréciés : ils
        // étaient dupliqués ici, et c'est cette copie-là qui gagnait, si bien
        // que l'UI présentait comme fonctionnels des rôles qui ne le sont plus.
        "proxy-security" => ("Sécurité proxy".into(), "Règles ufw des proxies de tous les parcs : 80/443 publics, ports VPN, et ports relayés (base, registre Docker, backs) ouverts à la whitelist, aux vpns, backs et fronts — chaque section ne s'applique que si son port est déclaré dans le group_vars du parc.".into()),
        "rpcbtc-security" => ("Sécurité noeud Bitcoin".into(), "Protège les ports RPC et P2P du noeud Bitcoin via UFW.".into()),
        "vpn-security" => ("Sécurité VPN".into(), "Configure le firewall et le routage pour l'infrastructure VPN Pritunl.".into()),
        "monitoring-security" => ("Sécurité monitoring".into(), "Configure les règles firewall pour l'accès à Prometheus et Grafana.".into()),
        "copyfail-security" => ("CVE-2026-31431 Copy Fail".into(), "Mitigation et patch kernel pour la faille locale d'élévation de privilèges Copy Fail (CVE-2026-31431). Debian/Ubuntu : blacklist modprobe algif_aead (immédiat). RedHat/Suse : initcall_blacklist via grubby (reboot requis). Variables : copyfail_upgrade_kernel (défaut: true), copyfail_reboot (défaut: false).".into()),
        "copyfail-remove" => ("Retrait mitigation Copy Fail".into(), "Retire la blacklist algif_aead et l'argument initcall_blacklist du cmdline kernel. Le kernel n'est pas rétrogradé. Reboot requis sur RedHat/Suse.".into()),

        // Base de données
        "db-purge" => ("Purge base de données".into(), "Supprime les conteneurs et données PostgreSQL existants avant une réinstallation.".into()),
        "db-remove" => ("Suppression base de données".into(), "Arrête et supprime le conteneur PostgreSQL (données préservées).".into()),
        "db-install-master" => ("Installation DB maître".into(), "Déploie le serveur PostgreSQL maître avec Docker, crée les bases, configure la réplication.".into()),
        "timescaledb-install" => ("Installation TimescaleDB".into(), "Déploie TimescaleDB (Docker, self-hosted) pour les indicateurs PapangMetrics + watchdog disque ; TLS par AC privée (certificat serveur généré hors dépôt, pg_hba hostssl, clair refusé en mode exigé). La sauvegarde appartient à timescaledb-backup-install.".into()),
        "timescaledb-remove" => ("Suppression TimescaleDB".into(), "Arrête et supprime le conteneur TimescaleDB. Préserve les données et la config sur disque.".into()),
        "timescaledb-purge" => ("Purge TimescaleDB".into(), "Supprime le conteneur TimescaleDB PLUS les données, backups et config. Destructif.".into()),
        "timescaledb-security" => ("Sécurité TimescaleDB".into(), "Refuse l'accès externe au port TimescaleDB (DB en localhost only).".into()),
        "brk-install" => ("Installation BRK".into(), "Installe Bitcoin Research Kit (toolchain Rust + cargo install brk_cli) et le lance en service systemd sous l'utilisateur du nœud.".into()),
        "brk-remove" => ("Suppression BRK".into(), "Arrête et supprime le service BRK et le binaire. Préserve les données calculées (brkdir).".into()),
        "brk-purge" => ("Purge BRK".into(), "Supprime BRK : service, binaire ET données calculées (brkdir). Destructif (re-sync de plusieurs heures nécessaire).".into()),
        "brk-security" => ("Sécurité BRK".into(), "Refuse l'accès externe au port de l'API BRK (localhost only).".into()),
        "esplora-install" => ("Installation Esplora".into(), "Construit et installe Esplora (mempool/electrs, depuis les sources, toolchain Rust) sur le nœud Bitcoin déjà déployé, sous l'utilisateur du nœud (accès direct aux blk*.dat, comme BRK). Publie l'API REST compatible Blockstream Esplora (app_port) et son CNAME public. Exige un nœud fully synced.".into()),
        "esplora-remove" => ("Suppression Esplora".into(), "Arrête et supprime le service Esplora et le binaire. Préserve l'index construit (base d'adresses/transactions).".into()),
        "esplora-purge" => ("Purge Esplora".into(), "Supprime Esplora : service, binaire, ET index construit et CNAME public. Destructif (ré-import de plusieurs heures nécessaire) — exige -e confirm=yes.".into()),
        "esplora-security" => ("Sécurité Esplora".into(), "Filtre l'API REST Esplora (ufw) : accessible depuis les hôtes de l'inventaire et la whitelist opérateur uniquement, jamais depuis Internet.".into()),
        "nodejs-install" => ("Installation Node.js".into(), "Installe Node.js LTS (NodeSource) — requis par l'API/ETL PapangMetrics.".into()),
        "papangmetrics-deploy" => ("Déploiement code PapangMetrics".into(), "Synchronise le code (rsync), npm ci + build, installe une clé publique JWT de service par environnement, génère le .env (secrets du vault exigés). Base partagée par l'API et l'ETL.".into()),
        "papangmetrics-api-install" => ("Service API PapangMetrics".into(), "Installe et démarre le service systemd de l'API read-only (suppose le code déjà déployé).".into()),
        "papangmetrics-etl-install" => ("Service ETL PapangMetrics".into(), "Installe et démarre le worker ETL systemd (BRK → TimescaleDB).".into()),
        "papangmetrics-api-security" => ("Sécurité API PapangMetrics".into(), "Firewall : ouvre le port du frontal TLS aux backs, à la whitelist, aux VPN et à Prometheus, et referme les ports en clair de l'API et de l'ETL (rouverts en transition ou en retour arrière).".into()),
        "papangmetrics-tls-install" => ("Frontal TLS PapangMetrics".into(), "Enregistrement A DNS seul du nom de la machine, nginx + certificat wildcard (DNS-01) devant 127.0.0.1 : chiffre les appels des backs et les scrapes Prometheus, accès restreint aux sources de l'inventaire.".into()),
        "papangmetrics-tls-remove" => ("Suppression frontal TLS PapangMetrics".into(), "Retire le vhost, le hook de renouvellement et la sonde ; arrête nginx s'il ne sert plus rien. Garde le certificat.".into()),
        "papangmetrics-tls-monitoring" => ("Supervision frontal TLS PapangMetrics".into(), "Sonde svcprobe (nginx, port TLS, certificat valable 14 jours) et vérification de bout en bout : /metrics refusé (401) sans bearer à travers nginx.".into()),
        "papangmetrics-api-remove" => ("Suppression API PapangMetrics".into(), "Arrête et supprime le service systemd de l'API. Conserve le code déployé.".into()),
        "papangmetrics-etl-remove" => ("Suppression ETL PapangMetrics".into(), "Arrête et supprime le worker ETL systemd. Conserve le code déployé.".into()),
        "papangmetrics-purge" => ("Purge PapangMetrics".into(), "Supprime les services API + ETL ET le code déployé. Ne touche pas à TimescaleDB.".into()),
        "host-preflight" => ("Contrôle préalable d'hôte".into(), "Échoue si le parc n'a pas d'hôte de supervision, puis vérifie et répare le socle (setup-server), node_exporter et sa cible Prometheus. Dépose des témoins dans /var/lib/fleetforge/state/.".into()),
        "svcprobe-install" => ("Sonde de services partagée".into(), "Installe svcprobe (port 9110) et ses collecteurs partagés. Expose `service_up` pour chaque sonde déposée par les rôles <service>-monitoring, sous une cible par machine nommée d'après son entrée canonique (celle qui porte host_vars).".into()),
        "rpcbtc-monitoring" => ("Supervision nœud Bitcoin".into(), "Exporter Prometheus maison (port 9898, job node-btc) : bitcoin_up, hauteur, en-têtes, pairs, mempool, âge du dernier bloc, élagage. Remplace exporter-btc, inexploitable.".into()),
        "brk-monitoring" => ("Supervision BRK".into(), "Sonde svcprobe sur l'API de synchronisation de BRK (/api/server/sync) et son unité systemd.".into()),
        "esplora-monitoring" => ("Supervision Esplora".into(), "Endpoint Prometheus natif d'electrs (monitoring_addr, job node-esplora) — pas d'exporter dédié. Enregistre la cible, ouvre le scrape, vérifie la métrique de référence (electrs_index_height).".into()),
        "timescaledb-monitoring" => ("Supervision TimescaleDB".into(), "Sonde conteneur + port + validité du certificat TLS servi (30 jours), et métriques PostgreSQL/TimescaleDB : taille, connexions, chunks compressés, transaction la plus longue.".into()),
        "db-monitoring" => ("Supervision base PostgreSQL".into(), "Sonde conteneur + port, métriques PostgreSQL dont retard de réplication et slots inactifs (rétention de WAL).".into()),
        "dbfront-monitoring" => ("Supervision base frontend".into(), "Sonde conteneur + port et métriques PostgreSQL de la base dédiée au frontend.".into()),
        "dbpool-monitoring" => ("Supervision pgpool".into(), "Sonde conteneur pgpool et port du pool — celui par lequel passent réellement les applications.".into()),
        "proxy-monitoring" => ("Supervision reverse proxy".into(), "Sonde nginx (unité, 80, 443), métriques stub_status et EXPIRATION DES CERTIFICATS TLS.".into()),
        "vpn-monitoring" => ("Supervision VPN".into(), "Sonde OpenVPN (unité + port) et métriques du fichier de statut : clients connectés, octets, fraîcheur du fichier.".into()),
        "wordpress-monitoring" => ("Supervision WordPress".into(), "Sonde HTTP de la page d'accueil (exclut les 5xx) plus les unités Apache et MySQL.".into()),
        "docker-repo-monitoring" => ("Supervision registre Docker".into(), "Sonde HTTP de l'API /v2/ du registre (200 ou 401) et état du conteneur.".into()),
        "mailserver-monitoring" => ("Supervision relai SMTP".into(), "Exporter Postfix (cible + scrape) et sonde svcprobe sur Postfix, Dovecot, OpenDKIM et les ports 25/587/993. Extrait de mailserver-setup pour être rejouable seul.".into()),
        "ollama-monitoring" => ("Supervision Ollama".into(), "Sonde HTTP sur /api/tags — le démon accepte les connexions bien avant de pouvoir servir un modèle — plus son unité systemd.".into()),
        "llamacpp-monitoring" => ("Supervision llama.cpp".into(), "Sonde HTTP sur /health — 503 tant que le modèle charge, alors que le port est déjà ouvert — plus l'unité de l'instance publiée, et cible /metrics native (job node-llamacpp : requêtes en attente de slot).".into()),
        "grafana-monitoring" => ("Supervision Grafana".into(), "Cible native /metrics plus sonde /api/health, qui distingue « Grafana répond » de « Grafana répond ET sa base interne est joignable ».".into()),
        "alertmanager-monitoring" => ("Supervision Alertmanager".into(), "Enregistre la cible native /metrics d'Alertmanager — le maillon qui ÉMET les alertes, et dont la chute ne serait signalée par rien d'autre.".into()),
        "backup-security" => ("Sécurité destination de sauvegarde".into(), "Ouvre SSH sur l'hôte de destination pour chaque source déclarée en `backup_sources`. Sans lui, la source ne peut rien pousser.".into()),
        "brk-backup-install" => ("Sauvegarde BRK".into(), "Copie rsync du magasin BRK vers l'hôte `backup-brk` : passe à chaud puis passe courte BRK arrêté, deux générations en liens durs, métrique Prometheus, script de restauration.".into()),
        "brk-backup-remove" => ("Suppression sauvegarde BRK".into(), "Arrête les sauvegardes du magasin BRK (cron + script). Conserve les données sur la destination et le script de restauration.".into()),
        "brk-backup-purge" => ("Purge sauvegarde BRK".into(), "Supprime le dispositif ET les sauvegardes du magasin BRK sur la destination, clé SSH comprise. Destructif — exige -e confirm=yes.".into()),
        "timescaledb-backup-install" => ("Sauvegarde TimescaleDB".into(), "Dump logique de la base d'indicateurs vers l'hôte `backup-timescale` (local ou SSH selon l'inventaire), rétention, métrique Prometheus, script de restauration.".into()),
        "timescaledb-backup-remove" => ("Suppression sauvegarde TimescaleDB".into(), "Arrête les sauvegardes de la base d'indicateurs (cron + script). Conserve les dumps et le script de restauration.".into()),
        "timescaledb-backup-purge" => ("Purge sauvegarde TimescaleDB".into(), "Supprime le dispositif ET les dumps de la base d'indicateurs sur la destination. Destructif — exige -e confirm=yes.".into()),
        "postgres-backup-install" => ("Sauvegarde PostgreSQL générique".into(), "Dump logique d'une base PostgreSQL en conteneur vers un hôte de destination (groupe `backups`), streamé en SSH, rétention, métrique Prometheus, script de restauration. Paramétré par host_vars (pgbak_*) — un seul rôle pour tradekong, ctdapi, etc.".into()),
        "postgres-backup-remove" => ("Suppression sauvegarde PostgreSQL".into(), "Arrête la sauvegarde d'une base (cron + script). Conserve les dumps sur la destination et le script de restauration.".into()),
        "postgres-backup-purge" => ("Purge sauvegarde PostgreSQL".into(), "Supprime le dispositif ET les dumps sur la destination, clé SSH comprise. Destructif — exige -e confirm=yes.".into()),
        "tradekong-monitoring" => ("Supervision TradeKong".into(), "Sonde svcprobe sur l'endpoint de santé applicatif, les réplicas back, PostgreSQL et Redis, plus métriques PostgreSQL partagées (postgres-metrics.sh).".into()),
        "tradekong-remove" => ("Suppression supervision TradeKong".into(), "Retire la sonde svcprobe déposée par Ansible. Ne touche pas à la stack docker-compose, hors Ansible.".into()),
        "tradekong-purge" => ("Purge supervision TradeKong".into(), "Retire la sonde svcprobe et supprime la sauvegarde PostgreSQL (dispositif et dumps). Destructif — exige -e confirm=yes.".into()),
        "ctdapi-monitoring" => ("Supervision ctdapi".into(), "Sonde svcprobe sur l'endpoint de santé applicatif, le front, les réplicas back, PostgreSQL et Redis, plus métriques PostgreSQL partagées.".into()),
        "ctdapi-remove" => ("Suppression supervision ctdapi".into(), "Retire la sonde svcprobe déposée par Ansible. Ne touche pas à la stack docker-compose, hors Ansible.".into()),
        "ctdapi-purge" => ("Purge supervision ctdapi".into(), "Retire la sonde svcprobe et supprime la sauvegarde PostgreSQL (dispositif et dumps). Destructif — exige -e confirm=yes.".into()),
        "xbot-monitoring" => ("Supervision xbot".into(), "Sonde svcprobe sur les conteneurs front et back — pas de base de données.".into()),
        "xbot-remove" => ("Suppression supervision xbot".into(), "Retire la sonde svcprobe déposée par Ansible. Ne touche pas à la stack docker-compose, hors Ansible.".into()),
        "xbot-purge" => ("Purge supervision xbot".into(), "Identique à xbot-remove — aucune donnée supplémentaire propre à Ansible sur cet hôte.".into()),
        "db-install-backup" => ("Installation DB réplica".into(), "Déploie le serveur PostgreSQL de réplication en streaming depuis le maître.".into()),
        "dbfront-install-master" => ("Installation DB frontend maître".into(), "Déploie la base PostgreSQL dédiée au frontend en mode maître.".into()),
        "dbfront-install-backup" => ("Installation DB frontend réplica".into(), "Configure la réplication streaming pour la base frontend.".into()),
        "dbfront-remove" => ("Suppression DB frontend".into(), "Arrête et supprime le conteneur PostgreSQL frontend (données préservées).".into()),
        "dbfront-purge" => ("Purge DB frontend".into(), "Supprime le conteneur et toutes les données de la base PostgreSQL frontend.".into()),
        "dbpool-install" => ("Installation PgPool".into(), "Déploie PgPool-II pour le pooling de connexions et la répartition entre réplicas PostgreSQL.".into()),
        "dbpool-remove" => ("Suppression PgPool".into(), "Arrête et supprime le conteneur PgPool.".into()),
        "dbpool-purge" => ("Purge PgPool".into(), "Supprime le conteneur PgPool et tous ses fichiers de configuration.".into()),

        // Proxy
        "proxy-install" => ("Installation Nginx proxy".into(), "Installe et configure Nginx comme reverse proxy avec support SSL.".into()),
        "proxy-remove" => ("Suppression proxy Nginx".into(), "Arrête et désinstalle Nginx (configs préservées).".into()),
        "proxy-purge" => ("Purge proxy Nginx".into(), "Supprime Nginx, tous ses fichiers de configuration et les certificats SSL.".into()),
        "proxy-update" => ("MAJ vhosts proxy".into(), "Resynchronise nginx.conf, vhosts, streams, certificats et htpasswd des proxies depuis Ansible/parcs/<parc_name>/nginx/ (gitignoré), valide avec nginx -t puis redémarre. Le répertoire du parc fait foi : un vhost qui en sort est retiré des proxies.".into()),
        "proxy-certs-bind9" => ("Certificats SSL (BIND9)".into(), "Gère les certificats Let's Encrypt via le challenge DNS avec BIND9 (RFC2136).".into()),

        // Nginx
        "nginx-install" => ("Installation Nginx".into(), "Installe le serveur web Nginx depuis les dépôts officiels.".into()),
        "nginx-remove" => ("Suppression Nginx".into(), "Arrête et désinstalle Nginx (configs préservées).".into()),
        "nginx-purge" => ("Purge Nginx".into(), "Désinstalle Nginx et supprime tous ses fichiers de configuration et logs.".into()),

        // Certbot / SSL
        "cert-install" => ("Installation certificats SSL".into(), "Configure certbot et installe les certificats Let's Encrypt.".into()),
        "cert-remove" => ("Suppression certbot".into(), "Désinstalle certbot (certificats préservés).".into()),
        "cert-purge" => ("Purge certificats SSL".into(), "Désinstalle certbot et supprime tous les certificats Let's Encrypt.".into()),

        // VPN
        "vpn-install" => ("Installation VPN Pritunl".into(), "Installe Pritunl et MongoDB pour l'infrastructure VPN OpenVPN.".into()),
        "vpn-remove" => ("Suppression VPN".into(), "Désinstalle Pritunl et MongoDB, supprime les fichiers de configuration.".into()),
        "vpn-purge" => ("Purge VPN".into(), "Supprime Pritunl, MongoDB et toutes les données VPN (utilisateurs, configs, logs).".into()),
        "vpn-setup" => ("Configuration VPN".into(), "Configure les organisations, utilisateurs et serveurs Pritunl.".into()),
        "vpn-routes-install" => ("Routes VPN".into(), "Configure les règles de routage réseau et l'IP forwarding pour le trafic VPN.".into()),
        "vpn-routes-remove" => ("Suppression routes VPN".into(), "Supprime les règles iptables et désactive l'IP forwarding.".into()),

        // Mail (anciens rôles non fonctionnels — conservés pour référence)
        "mail-install" => ("Installation serveur mail (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-install.".into()),
        "mail-remove" => ("Suppression serveur mail (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-remove.".into()),
        "mail-purge" => ("Purge serveur mail (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-purge.".into()),
        "mail-setup" => ("Configuration serveur mail (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-setup.".into()),
        "mail-setup-multi" => ("Configuration multi-domaines (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-setup.".into()),
        "mail-security" => ("Sécurité serveur mail (déprécié)".into(), "Rôle non fonctionnel — utiliser mailserver-security.".into()),

        // Mailserver (relai SMTP multi-domaines — rôles fonctionnels)
        "mailserver-stop" => ("Arrêt relai SMTP".into(), "Arrête proprement Postfix, OpenDKIM et l'exporter Prometheus. Force le kill des processus résiduels et supprime les lock files.".into()),
        "mailserver-install" => ("Installation relai SMTP".into(), "Installe Postfix, OpenDKIM, certbot (Cloudflare DNS), SASL et prometheus-postfix-exporter.".into()),
        "mailserver-setup" => ("Configuration relai SMTP".into(), "Configure Postfix multi-domaines avec TLS (Let's Encrypt SNI), DKIM par domaine, SASL, filtre de headers (Reply-To + préfixe sujet) et exporter Prometheus. Publie sur Cloudflare les enregistrements A, SPF, DKIM et DMARC de chaque domaine de relais, plus le DMARC des domaines racines (mailserver_dmarc_org_domains).".into()),
        "mailserver-security" => ("Sécurité relai SMTP".into(), "Configure UFW (ports 465/587, bloque 25 entrant) et Fail2ban pour Postfix.".into()),
        "mailserver-remove" => ("Suppression relai SMTP".into(), "Arrête et supprime Postfix, OpenDKIM et l'exporter. Préserve les certificats et clés DKIM.".into()),
        "mailserver-purge" => ("Purge relai SMTP".into(), "Supprime tous les services, certificats Let's Encrypt, clés DKIM, config SASL et scripts de filtre.".into()),
        "dmarc-exporter-install" => ("Installation exporteur DMARC".into(), "Relève une boîte IMAP, agrège les rapports DMARC et les expose sur le port 7489 (dmarc_up, messages alignés/non alignés, fraîcheur des rapports). Enregistre la cible auprès de Prometheus.".into()),
        "dmarc-exporter-remove" => ("Suppression exporteur DMARC".into(), "Arrête et supprime le service, le script et l'utilisateur système. Conserve l'état agrégé et la cible Prometheus.".into()),
        "dmarc-exporter-purge" => ("Purge exporteur DMARC".into(), "Supprime le service, l'état agrégé, la configuration (identifiants IMAP) et la cible Prometheus. Destructif.".into()),

        // Monitoring
        "prometheus-install" => ("Installation Prometheus".into(), "Déploie Prometheus (Docker) avec authentification basique et lien vers Alertmanager. Les règles d'alerte sont posées par prometheus-alerts-update. Variables : prometheus_port (défaut 9090), prometheus_retention, alertmanager_host.".into()),
        "prometheus-alerts-update" => ("MAJ règles d'alerte Prometheus".into(), "Déploie les règles d'alerte sur l'hôte Prometheus du parc courant. Partagé par les deux stacks (prometheus-install et monitoring-install) pour que les règles ne divergent pas. Groupes sélectionnables via prom_alert_groups : availability, resources, database, papangmetrics, bitcoin, astar, theta, searxng, openclaw, sync, services, dmarc, backups.".into()),
        "prometheus-remove" => ("Suppression Prometheus".into(), "Arrête et supprime le conteneur Prometheus. Préserve la TSDB, la configuration et les règles d'alerte.".into()),
        "prometheus-purge" => ("Purge Prometheus".into(), "Supprime Prometheus et toutes ses données : TSDB, configuration, règles et cibles. Destructif (historique des métriques perdu).".into()),
        "prometheus-security" => ("Sécurité Prometheus".into(), "Firewall : accès à l'UI/API Prometheus réservé à la whitelist et aux VPN. Additif, ne modifie pas la politique UFW par défaut.".into()),
        "docker-ports-security" => ("Sécurité des ports Docker".into(), "Filtre les ports publiés par des conteneurs dans la chaîne DOCKER-USER — les règles UFW n'ont aucun effet sur eux. Sources autorisées déclarées par hôte via docker_ports_rules.".into()),
        "alertmanager-install" => ("Installation Alertmanager".into(), "Déploie Alertmanager (Docker) et le configure pour notifier par e-mail via le smarthost SMTP. Variables : alertmanager_email_to (requis), alertmanager_smtp_host.".into()),
        "alertmanager-remove" => ("Suppression Alertmanager".into(), "Arrête et supprime le conteneur Alertmanager. Préserve la configuration et l'état (silences).".into()),
        "alertmanager-purge" => ("Purge Alertmanager".into(), "Supprime Alertmanager, sa configuration (identifiants SMTP inclus) et son état persistant.".into()),
        "alertmanager-update" => ("Silence Alertmanager".into(), "Pose un silence borné (60 min) sur des matchers précis le temps d'une intervention (tasks_from: silence), puis le raccourcit à 20 min à sa fin (tasks_from: unsilence) pour laisser retomber les alertes maintenues par keep_firing_for. Fait taire aussi la veille OpenClaw.".into()),
        "alertmanager-security" => ("Sécurité Alertmanager".into(), "Firewall : UI réservée à la whitelist et aux VPN, plus l'accès de Prometheus pour la remontée des alertes.".into()),
        "monitoring-install" => ("Installation monitoring".into(), "Déploie Prometheus et Grafana en conteneurs Docker avec authentification, y compris rule_files et le lien vers Alertmanager (absents jusqu'ici : le parc collectait sans pouvoir alerter).".into()),
        "monitoring-remove" => ("Suppression monitoring".into(), "Arrête et supprime les conteneurs Prometheus et Grafana (données préservées).".into()),
        "monitoring-purge" => ("Purge monitoring".into(), "Supprime les conteneurs et toutes les données métriques, configs et target files.".into()),
        "exporter-sys-install" => ("Exporteur système".into(), "Installe node_exporter et enregistre le host dans Prometheus pour les métriques CPU/RAM/disque.".into()),
        "exporter-sys-remove" => ("Suppression exporteur système".into(), "Arrête node_exporter et retire le host des targets Prometheus.".into()),
        "readonly-user-install" => ("Compte lecture seule".into(), "Crée le compte SSH openclaw-ro pour les clés de keys/<parc>/readonly/, liées en commande forcée à la passerelle ro-gate : verbes en lecture seule fermés (journaux sélectionnés et regroupés par motif, état d'unité, conteneurs, pare-feu, système, GET local) et sorties caviardées des secrets. Aucun shell, aucun groupe. Le dossier fait foi : vide, il révoque toutes les clés.".into()),
        "readonly-user-remove" => ("Suppression compte lecture seule".into(), "Retire le compte openclaw-ro, sa passerelle ro-gate et ses règles sudo (répertoire personnel conservé).".into()),
        "readonly-user-purge" => ("Purge compte lecture seule".into(), "Retire le compte openclaw-ro, sa passerelle ro-gate, ses règles sudo et son répertoire personnel.".into()),
        "exporter-sys-windows-install" => ("Exporteur système Windows".into(), "Installe windows_exporter (MSI) comme service Windows et enregistre la target Prometheus pour les métriques CPU/RAM/disque.".into()),
        "exporter-sys-windows-remove" => ("Suppression exporteur système Windows".into(), "Désinstalle windows_exporter et retire le host des targets Prometheus.".into()),
        "exporter-sys-windows-purge" => ("Purge exporteur système Windows".into(), "Désinstalle windows_exporter, supprime les fichiers résiduels et retire la target Prometheus.".into()),
        "journald-setup" => ("Plafond du journal systemd".into(), "Limite la taille et la rétention du journal systemd via un drop-in, puis élague l'existant. Sans lui, journald consomme jusqu'à 10 % du disque sans limite de durée.".into()),

        // Docker
        "docker-install" => ("Installation Docker".into(), "Installe Docker CE depuis les dépôts officiels avec configuration du démon.".into()),
        "docker-remove" => ("Suppression Docker".into(), "Arrête et désinstalle Docker CE (images et volumes préservés).".into()),
        "docker-purge" => ("Purge Docker".into(), "Désinstalle Docker CE et supprime toutes les images, volumes et données.".into()),
        "docker-repo-install" => ("Registre Docker privé".into(), "Déploie un registre Docker privé avec configuration et volumes persistants.".into()),
        "docker-repo-remove" => ("Suppression registre Docker".into(), "Arrête et supprime le conteneur du registre (images préservées).".into()),
        "docker-repo-purge" => ("Purge registre Docker".into(), "Supprime le conteneur du registre et toutes les images stockées.".into()),

        // WordPress
        "site-pages-install" => ("Pages statiques sur www".into(), "Publie des fichiers statiques (docs légaux d'une application) dans un sous-dossier du docroot WordPress de www, avec .htaccess et réécriture de liens.".into()),
        "site-pages-remove" => ("Suppression pages statiques".into(), "Supprime le sous-dossier publié par site-pages-install.".into()),
        "site-pages-purge" => ("Purge pages statiques".into(), "Identique à la suppression (aucune donnée hors du dossier).".into()),
        "wordpress-install" => ("Installation WordPress".into(), "Déploie Apache2, MySQL et WordPress avec configuration complète.".into()),
        "wordpress-security" => ("Sécurité WordPress".into(), "Filtre le port d'Apache (ufw) : proxies, vpns, Prometheus et whitelist.".into()),
        "wordpress-remove" => ("Suppression WordPress".into(), "Arrête et désinstalle Apache2/MySQL (fichiers et BDD préservés).".into()),
        "wordpress-purge" => ("Purge WordPress".into(), "Supprime Apache2, MySQL, tous les fichiers WordPress et la base de données.".into()),
        "wordpress-backup" => ("Sauvegarde WordPress".into(), "Sauvegarde les fichiers et la base de données WordPress.".into()),
        "wordpress-restore" => ("Restauration WordPress".into(), "Restaure WordPress depuis une sauvegarde précédente.".into()),

        // Blockchain
        "rpcbtc-install" => ("Installation noeud Bitcoin".into(), "Télécharge et installe Bitcoin Core v27.0 en service systemd utilisateur.".into()),
        "rpcbtc-remove" => ("Suppression noeud Bitcoin".into(), "Arrête le service bitcoind et supprime le binaire (blockchain préservée).".into()),
        "rpcbtc-purge" => ("Purge noeud Bitcoin".into(), "Supprime le binaire, le service et toute la blockchain (~700 GB).".into()),
        "rpcbtc-setup" => ("Configuration noeud Bitcoin".into(), "Configure le fichier bitcoin.conf avec les paramètres réseau et RPC.".into()),
        "rpcbtc-rpcauth" => ("Authentification RPC Bitcoin".into(), "Génère et configure les identifiants d'authentification RPC.".into()),
        "rpc-docker-TODO" => ("Noeud RPC Docker (WIP)".into(), "Noeud RPC Bitcoin en conteneur Docker — en cours de développement.".into()),

        // Système
        "python-install" => ("Installation Python".into(), "Installe Python 3 et pip pour les dépendances Ansible et applicatives.".into()),
        "python-remove" => ("Suppression Python".into(), "Désinstalle Python 3 et pip.".into()),
        "tools-install" => ("Outils système".into(), "Installe les utilitaires courants : curl, wget, git, htop, etc.".into()),
        "tools-remove" => ("Suppression outils système".into(), "Désinstalle les utilitaires génériques installés par tools-install.".into()),
        "scripts-install" => ("Scripts utilitaires".into(), "Déploie les alias et scripts utilitaires sur les serveurs.".into()),
        "scripts-remove" => ("Suppression scripts utilitaires".into(), "Supprime les scripts et alias déployés par scripts-install.".into()),
        "set-hostname" => ("Hostname serveur".into(), "Configure le nom d'hôte du serveur.".into()),
        "terraform" => ("Exécution Terraform".into(), "Exécute les plans Terraform pour le provisionnement cloud.".into()),

        // IA / Ollama
        "ollama-install" => ("Installation Ollama".into(), "Installe Ollama (écoute sur toutes les interfaces, port app_port) et publie le CNAME du nom public (proxy_hostname).".into()),
        "ollama-remove" => ("Suppression Ollama".into(), "Arrête et supprime Ollama, son override systemd et sa sonde (modèles et utilisateur préservés).".into()),
        "ollama-purge" => ("Purge Ollama".into(), "Supprime Ollama, tous les modèles téléchargés, l'utilisateur système, la sonde, les règles de pare-feu et le CNAME public.".into()),
        "ollama-security" => ("Sécurité Ollama".into(), "Restreint l'API 11434 (sans authentification) aux proxies, vpns, Prometheus et whitelist, refus par défaut ensuite ; signale un ufw inactif.".into()),
        "ollama-model-install" => ("Déploiement modèle Ollama".into(), "Télécharge et déploie un modèle IA via Ollama (nécessite la variable ollama_model_name).".into()),
        "ollama-model-remove" => ("Suppression modèle Ollama".into(), "Supprime un modèle spécifique d'Ollama (nécessite la variable ollama_model_name).".into()),

        // IA / llama.cpp
        "llamacpp-install" => ("Installation llama.cpp".into(), "Installe llama-server depuis la release précompilée ggml-org épinglée (llamacpp_version, binaire CPU à variantes par génération de processeur), sous srvc, et publie le CNAME du nom public (proxy_hostname). Aucune instance n'est démarrée.".into()),
        "llamacpp-remove" => ("Suppression llama.cpp".into(), "Arrête et supprime toutes les instances llama-server détectées, le moteur, la sonde et les cibles Prometheus (modèles préservés).".into()),
        "llamacpp-purge" => ("Purge llama.cpp".into(), "Fait tout ce que llamacpp-remove fait, plus : tous les modèles GGUF, les règles de pare-feu et le CNAME public.".into()),
        "llamacpp-security" => ("Sécurité llama.cpp".into(), "Restreint le port de l'instance publiée (app_port, API sans authentification) aux proxies, vpns, Prometheus et whitelist, refus par défaut ensuite ; refuse un port publié par Docker et signale un ufw inactif.".into()),
        "llamacpp-model-install" => ("Déploiement modèle llama.cpp".into(), "Télécharge un modèle GGUF (empreinte vérifiée si llamacpp_model_checksum) et démarre une instance llama-server dédiée (systemd + port propres, sous srvc), puis attend /health. Variables : llamacpp_model_name, llamacpp_model_url (requis), llamacpp_instance_id (défaut : 1).".into()),
        "llamacpp-model-remove" => ("Suppression modèle llama.cpp".into(), "Arrête l'instance llama-server et supprime son fichier GGUF. Variables : llamacpp_model_name (requis), llamacpp_instance_id (défaut : 1).".into()),
        "exporter-llamacpp-install" => ("Exporteur llama.cpp".into(), "Enregistre le endpoint Prometheus natif de l'instance llama-server (--metrics, /metrics, job node-llamacpp) sur le serveur de monitoring et ouvre le firewall. Variable : llamacpp_instance_id (défaut : 1).".into()),
        "exporter-llamacpp-remove" => ("Suppression exporteur llama.cpp".into(), "Retire l'instance llama.cpp des targets Prometheus et ferme le port firewall. Variable : llamacpp_instance_id (défaut : 1).".into()),

        // DNS / Cloudflare
        "cloudflare-dns-update" => ("Synchronisation DNS Cloudflare".into(), "Publie un enregistrement A par hôte d'inventaire portant un `hostname` dans la zone du parc, pointant sur son `ansible_host`. Créé s'il manque, mis à jour s'il diffère (`solo`, sinon un second A ferait répondre la zone en tourniquet), jamais supprimé : ce qui existe sans correspondre à un hôte n'est pas touché. Les hôtes écartés sont listés avec leur motif.".into()),

        // Application PapangLabs
        "papanglabs-back-install" => ("Installation back PapangLabs".into(), "Synchronise le contexte de build (rsync -L : back/src/modules_shared est un ensemble de liens vers .libs, exclu de la copie), dépose les deux .env — runtime et interpolation compose — et construit l'image. Ne démarre rien. Variables : pgb_src, pgb_env_file, pgb_compose_file.".into()),
        "papanglabs-back-setup" => ("Démarrage back PapangLabs".into(), "Lance back, back-worker, back-lb et redis, puis attend une réponse RÉELLE de /api/v1/health à travers le répartiteur. Contrôle l'état de chaque service : un back sain derrière un répartiteur resté en état `Created` répond 502 sans que `docker ps` ne le montre.".into()),
        "papanglabs-back-security" => ("Sécurité back PapangLabs".into(), "Applique les règles DOCKER-USER de la machine et refuse de passer si le port du répartiteur n'y figure pas — publié par Docker, il ignorerait toute règle ufw. Les règles vivent en host_vars, une par machine.".into()),
        "papanglabs-back-monitoring" => ("Supervision back PapangLabs".into(), "Sonde svcprobe (service_up via /api/v1/health + les trois conteneurs) et métriques applicatives poussées par vmagent vers TOUS les hôtes portant la famille `prometheus`, un scrape par conteneur via le socket Docker. Vérifie que chaque Prometheus accepte le remote_write et que /metrics n'est pas laissé sans jeton.".into()),
        "prometheus-remotewrite-security" => ("Ouverture remote_write Prometheus".into(), "Autorise un hôte pousseur à joindre le récepteur remote_write, par un fichier de drop-in lu à l'exécution par le pare-feu des ports Docker — il survit donc à tout rejeu de `docker-ports-security`. Posé par le déploiement du service pousseur, retiré par son `-remove` : la liste des clients de Prometheus suit le cycle de vie de ses clients, pas les host_vars de la machine de supervision.".into()),
        "papanglabs-back-remove" => ("Suppression back PapangLabs".into(), "Arrête et supprime les conteneurs (profil metrics compris), le répartiteur au nom fixe et la sonde d'état. Conserve le code livré, les .env et les volumes.".into()),
        "papanglabs-back-purge" => ("Purge back PapangLabs".into(), "Suppression, plus les volumes nommés (dont les graphiques générés), l'image applicative, le répertoire livré et le CNAME public. Docker, node_exporter et svcprobe restent : ils sont partagés.".into()),
        "papanglabs-front-publish" => ("Publication front PapangLabs".into(), "Construit le bundle Vite sur le poste de contrôle — mode déduit du suffixe du fichier d'environnement — et le publie sur Cloudflare Pages via wrangler. La branche décide de l'environnement Cloudflare : `main` publie en production, tout autre nom crée une prévisualisation.".into()),

        // IA / SearXNG
        "fleetforge-install" => ("Installation FleetForge (web)".into(), "Déploie l'application de gestion du parc servie en HTTP : livraison du workspace Rust et du frontal construit, compilation d'`fleetforge-web` sur la machine, service systemd et authentification basique. Installe Ansible (pipx) — la machine devient un nœud de contrôle. Mot de passe d'accès tiré au premier déploiement et déposé chiffré dans le group_vars du parc ; la machine n'en reçoit que l'empreinte argon2. Avec `ff_deploy_secrets=true`, crée en plus une clé SSH DÉDIÉE (passphrase au vault, jamais régénérée) chargée dans un ssh-agent systemd, et livre le mot de passe du vault.".into()),
        "fleetforge-security" => ("Sécurité FleetForge".into(), "Ouvre le port applicatif (9750 par défaut) à la whitelist et aux proxies. Le service étant un binaire natif et non un conteneur, les règles ufw s'appliquent réellement — contrairement à Prometheus ou Alertmanager, dont les ports publiés par Docker échappent à ufw.".into()),
        "fleetforge-monitoring" => ("Supervision FleetForge".into(), "Enregistre la cible Prometheus sur le port applicatif : l'application expose /metrics nativement, sans exporter ni sonde svcprobe. Vérifie qu'un scrape_config lit réellement le répertoire de cibles, et surveille l'état dégradé propre au service — répond en HTTP mais ne peut plus rien déployer (`fleetforge_ansible_available`).".into()),
        "fleetforge-remove" => ("Suppression FleetForge".into(), "Arrête le service, retire l'unité systemd, les binaires compilés, la cible Prometheus et les ouvertures de pare-feu. Conserve le code livré, l'arbre Ansible synchronisé et la base locale.".into()),
        "fleetforge-purge" => ("Purge FleetForge".into(), "Suppression, plus le répertoire livré, l'arbre Ansible synchronisé, la base locale (historique des runs, réglages) et le mot de passe d'accès. Ne retire ni Rust, ni Ansible, ni les clés SSH : outils et secrets partagés.".into()),
        "pushgateway-install" => ("Installation Pushgateway".into(), "Installe la Prometheus Pushgateway en binaire natif épinglé (amd64/arm64, somme sha256 vérifiée, retéléchargé seulement si la version change), sous srvc dans une unité systemd durcie, avec persistance des séries poussées (--persistence.file) pour qu'un redémarrage ne les efface pas en silence.".into()),
        "pushgateway-security" => ("Sécurité Pushgateway".into(), "Ouvre le port de la passerelle (9900 par défaut, sans authentification) aux seuls vpns, Prometheus, whitelist et pousseurs (groupe aiservers + pushgateway_allowed_hosts), adresses dérivées de l'inventaire ; bridge Docker autorisé si Prometheus est co-localisé.".into()),
        "pushgateway-monitoring" => ("Supervision Pushgateway".into(), "Enregistre la cible /metrics native sur prometheus_host, ouvre le scrape, vérifie qu'un job lit le répertoire de cibles avec honor_labels: true, et rapporte pushgateway_build_info et push_time_seconds — l'âge du dernier push révèle un pousseur arrêté que la passerelle continuerait de servir.".into()),
        "pushgateway-remove" => ("Suppression Pushgateway".into(), "Arrête et retire l'unité systemd, le binaire, la cible Prometheus et les règles ufw. Conserve le magasin de persistance.".into()),
        "pushgateway-purge" => ("Purge Pushgateway".into(), "Suppression, plus le répertoire de données : toutes les séries poussées sont perdues.".into()),
        "llmauth-install" => ("Installation LLM Auth".into(), "Construit et démarre le service Go de validation des clés d'API (auth_request nginx), publié sur 127.0.0.1 uniquement. Requiert llmauth_pepper et llmauth_admin_token (vault).".into()),
        "llmauth-security" => ("Sécurité LLM Auth".into(), "Vérifie que le port du service n'écoute que sur la boucle locale et retire toute règle ufw décorative.".into()),
        "llmauth-monitoring" => ("Supervision LLM Auth".into(), "Sonde svcprobe (/healthz, conteneur, /validate) et collecteur relayant les métriques natives et le nombre de clés actives — à 0, toutes les requêtes sont refusées.".into()),
        "llmauth-remove" => ("Suppression LLM Auth".into(), "Arrête le conteneur et retire le compose, le contexte de build et la sonde, en conservant la base des clés.".into()),
        "llmauth-purge" => ("Purge LLM Auth".into(), "Supprime le service, son image et tout son répertoire, base des clés d'API comprise (irréversible).".into()),
        "aiserver-install" => ("Installation serveur IA".into(), "Déploie en conteneurs llama.cpp, ComfyUI et l'exporter GPU DCGM, avec pilote NVIDIA, runtime Docker GPU et modèles Hugging Face.".into()),
        "aiserver-security" => ("Sécurité serveur IA".into(), "Filtre les ports publiés du serveur IA dans DOCKER-USER (proxies, vpns, Prometheus, whitelist) et vérifie la chaîne réelle.".into()),
        "aiserver-monitoring" => ("Supervision serveur IA".into(), "Enregistre les cibles Prometheus llama.cpp, ComfyUI et DCGM et la sonde svcprobe du serveur IA.".into()),
        "aiserver-remove" => ("Suppression serveur IA".into(), "Arrête les conteneurs du serveur IA et retire pare-feu, sonde et cibles Prometheus en conservant les modèles.".into()),
        "aiserver-purge" => ("Purge serveur IA".into(), "Supprime le serveur IA avec ses images, volumes de modèles et répertoires, sans toucher à Docker ni au pilote NVIDIA.".into()),
        "scripting-install" => ("Installation orchestrateur scripting".into(), "Déploie l'orchestrateur scripting : dépôts git mis à jour en place, venvs Python, fichiers du parc (vault, parcs/<parc>/scripting/), instances d'autodéploiement, identifiants GCP et planification /etc/cron.d.".into()),
        "scripting-security" => ("Sécurité orchestrateur scripting".into(), "Impose 0600 aux secrets de l'orchestrateur, refuse tout jeton dans les remotes git et tout port d'écoute ouvert depuis son répertoire d'installation.".into()),
        "scripting-monitoring" => ("Supervision orchestrateur scripting".into(), "Sonde svcprobe : présence du cron, exécutions cron récentes, âge des journaux par famille, âge des commits et synchronisation des instances.".into()),
        "scripting-remove" => ("Suppression orchestrateur scripting".into(), "Arrête l'orchestrateur (retrait du fichier cron) et supprime code, venvs, instances et sonde en conservant configuration, logs et outputs.".into()),
        "scripting-purge" => ("Purge orchestrateur scripting".into(), "Supprime l'orchestrateur et toutes ses données : répertoire d'installation, secrets du parc, logs, outputs et identifiants GCP.".into()),
        "searxng-install" => ("Installation relai SearXNG".into(), "Déploie SearXNG (Docker) en relai de recherche JSON. Publie le port sur 127.0.0.1 quand tous les proxies autorisés sont sur la même machine, sur 0.0.0.0 sinon. Variables : searxng_port (défaut 8888), searxng_allowed_proxies, searxng_hostname, searxng_engines_enabled/_disabled (moteurs qui refusent l'IP de sortie). Tire la dernière image à chaque déploiement (searxng_image_pull).".into()),
        "searxng-security" => ("Sécurité relai SearXNG".into(), "Restreint le port publié aux seules IP des proxies distants dans la chaîne DOCKER-USER — une règle ufw n'a aucun effet sur un port publié par Docker — et vérifie l'état réel de la chaîne. Ne pose rien quand le port est publié sur la boucle locale.".into()),
        "searxng-monitoring" => ("Supervision relai SearXNG".into(), "Sonde svcprobe (/healthz, conteneur, /config) et collecteur de requête réelle mis en cache : détecte l'instance qui répond mais ne rapporte plus rien, moteurs amont bloqués — état qu'aucune sonde binaire ne voit. Compte les moteurs qui rapportent réellement des résultats, avec le détail par moteur ; requêtes de contrôle en rotation (searxng_probe_queries).".into()),
        "searxng-remove" => ("Suppression relai SearXNG".into(), "Arrête le conteneur, retire la sonde et purge les règles DOCKER-USER du port. Conserve la configuration et la clé secrète.".into()),
        "searxng-purge" => ("Purge relai SearXNG".into(), "Supprime le conteneur, l'image, la configuration, la clé secrète du relai SearXNG et le CNAME public.".into()),

        // IA / FreeLLMAPI
        "freellm-install" => ("Installation FreeLLMAPI".into(), "Déploie FreeLLMAPI (proxy unifié multi-fournisseurs LLM, API OpenAI-compatible) via l'installeur officiel (curl | bash, Docker Compose). Publie le port sur 127.0.0.1 quand tous les proxies autorisés sont sur la même machine, sur 0.0.0.0 sinon. Monte un fichier de clés fournisseur optionnel (FREEAPI_CONFIG_PATH) et publie le CNAME DNS vers le proxy. Variables : freellm_port (défaut 3001), freellm_allowed_proxies, freellm_hostname.".into()),
        "freellm-security" => ("Sécurité FreeLLMAPI".into(), "Restreint le port publié aux seules IP des proxies distants dans la chaîne DOCKER-USER — une règle ufw n'a aucun effet sur un port publié par Docker — et vérifie l'état réel de la chaîne. Ne pose rien quand le port est publié sur la boucle locale.".into()),
        "freellm-monitoring" => ("Supervision FreeLLMAPI".into(), "Sonde svcprobe (/api/ping, conteneur) et collecteur du nombre de modèles exposés par /v1/models : détecte l'instance qui répond mais ne sert plus aucune requête réelle faute de clé fournisseur, état qu'aucune sonde binaire ne voit.".into()),
        "freellm-remove" => ("Suppression FreeLLMAPI".into(), "Arrête le conteneur, retire la sonde et purge les règles DOCKER-USER du port. Conserve la configuration, l'ENCRYPTION_KEY et les clés fournisseur importées.".into()),
        "freellm-purge" => ("Purge FreeLLMAPI".into(), "Supprime le conteneur, l'image, le volume de données (clés fournisseur chiffrées), la configuration, l'ENCRYPTION_KEY et le CNAME public.".into()),
        "starnet-install" => ("Installation StarNet".into(), "Déploie StarNet (harnais d'agents IA, UI + moteur dans un seul process Node) NATIVEMENT sous srvc : Node embarqué (archive officielle, somme vérifiée), clone superficiel et partiel du tag épinglé (starnet_version), dépendances de production, unité systemd --user. Le sidecar n'écoutant que sur 127.0.0.1 (en dur dans le code amont), un relai systemd (systemd-socket-proxyd) publie app_port. Tire une fois la clé de chiffrement des connecteurs et publie le CNAME DNS. Variables : starnet_port (app_port, défaut 4720), starnet_sidecar_port (8787), starnet_openrouter_key (vault, optionnelle).".into()),
        "starnet-security" => ("Sécurité StarNet".into(), "Restreint le port du relai aux proxies, à la whitelist, à Prometheus et aux VPN via ufw (process natif, règle réellement effective), vérifie que le sidecar reste confiné à la boucle locale et échoue si ufw est inactif — la page servie donnant le contrôle complet de la station.".into()),
        "starnet-monitoring" => ("Supervision StarNet".into(), "Sonde svcprobe (service_up via /api/health, check du relai de bout en bout) et collecteur du code et de la latence de /api/health : distingue un sidecar dégradé (503, boucle de crash) d'un sidecar arrêté, et révèle une boucle d'événements saturée.".into()),
        "starnet-remove" => ("Suppression StarNet".into(), "Arrête l'unité --user et le relai, retire le code, le Node embarqué, la sonde et les règles ufw. Conserve les workspaces et la configuration (dont la clé des connecteurs).".into()),
        "starnet-purge" => ("Purge StarNet".into(), "Supprime StarNet ET ses données : workspaces (agents, mémoire, transcripts, ledgers), configuration, clé des connecteurs et CNAME public. Destructif.".into()),

        // TradeKong / Rotki
        "rotki-install" => ("Installation Rotki".into(), "Déploie Rotki (conteneur autonome, image rotki/rotki:v1.43.2) en sidecar de valorisation de portefeuille pour TradeKong (fusion WalletOptimizer, Phase 4.2), sur une machine dédiée séparée de TradeKong. Toujours publié sur 0.0.0.0 : le seul client est TradeKong (`tradekong`), une vraie machine distante, filtré dans DOCKER-USER par IP réelle. Variables : rotki_port (défaut 4302), rotki_data_volume, rotki_logs_volume.".into()),
        "rotki-monitoring" => ("Supervision Rotki".into(), "Sonde svcprobe (/api/1/ping, conteneur), ouverture du port 4302 à l'hôte Prometheus dans DOCKER-USER (drop-in docker-ports-security) et contrôle d'accès depuis cet hôte. Pas de collecteur dédié : aucun état 'répond mais dégradé' identifié à ce jour.".into()),
        "rotki-remove" => ("Suppression Rotki".into(), "Arrête et retire le conteneur, retire la sonde. Conserve les volumes de données/logs et l'entrée docker_ports_rules (host_vars/ctdapi.yml, à retirer à la main — un flush iptables manuel est nécessaire si c'est la dernière règle du fichier).".into()),
        "rotki-purge" => ("Purge Rotki".into(), "Supprime le conteneur, l'image, les volumes nommés (portefeuille valorisé, historique) et le CNAME public. Destructif, non reconstructible sans re-synchronisation complète — exige -e confirm=yes.".into()),

        // IA / OpenClaw
        "openclaw-install" => ("Installation OpenClaw".into(), "Déploie OpenClaw (assistant IA auto-hébergé) NATIVEMENT via le CLI officiel (install-cli.sh, Node embarqué), sous le compte srvc, démon géré par une unité systemd --user (lingering activé). Onboardé en mode non interactif, secrets passés par l'environnement du process. Configure aussi gateway.trustedProxies, controlUi.allowedOrigins et, optionnellement, un provider de modèles personnalisé (openclaw_custom_provider_name, valeurs modifiables ensuite dans l'UI — config set ne teste jamais la connectivité à l'écriture). Idempotent : n'onboarde qu'une fois. Veille du parc (fleet-watch) : automation OpenClaw sans modèle qui lit Alertmanager, ignore les hôtes monitor: off et ne réveille le modèle (analyse + solutions PROPOSÉES, jamais appliquées) que si les alertes changent (un ensemble qui disparaît puis revient dans la fenêtre de renvoi n'en est pas un). Coupe la revue Skill Workshop et le réveil sur fin d'exec, qui consommaient le modèle sans rien produire. Les analyses tournent sous un agent dédié `watch` : exec limité par liste blanche à fleet-ssh (compte lecture seule openclaw-ro des machines, clé sans passphrase copiée dans keys/<parc>/readonly/, config SSH root dans /etc/openclaw), read confiné à son workspace où vivent le clone FleetForge et son index FleetForge-INDEX.md (playbooks et fichiers de chaque rôle, read ne listant pas les répertoires), ni écriture, ni web, ni mémoire. L'agent main n'est pas modifié. Modèle par défaut et utilitaire des agents posés depuis l'inventaire (openclaw_default_model, openclaw_utility_model ; vide = réglage de l'UI conservé). Variables : openclaw_port (app_port, défaut 18789), openclaw_openai_api_key (vault, requis), openclaw_default_model, openclaw_fleetwatch_* .".into()),
        "openclaw-security" => ("Sécurité OpenClaw".into(), "Restreint le port de la gateway (process natif sous systemd, pas de conteneur) à la whitelist du parc, aux proxies et au LAN domestique via ufw — réellement effectif ici, contrairement à un port publié par Docker.".into()),
        "openclaw-monitoring" => ("Supervision OpenClaw".into(), "Sonde svcprobe (service_up via /healthz, /readyz) — signal HTTP indépendant du mode de déploiement, partagée avec les autres alias de la machine NAT domestique. Pas de check systemd --user : le hardening de svcprobe (NoNewPrivileges, ProtectHome) l'empêche structurellement de sonder l'unité utilisateur de srvc. Sonde des modèles : timer systemd openclaw-model-probe (srvc, toutes les heures) qui envoie une complétion réelle de quelques tokens à chaque modèle qu'OpenClaw appelle (défaut et replis, utilityModel, heartbeat actif, agents, fleet-watch) et publie openclaw_model_up, la raison d'un échec (not_found, auth, no_credit…) et les modèles non sondables, relayés par la sonde svcprobe openclaw. Alertes : groupe openclaw de prometheus-alerts-update.".into()),
        "openclaw-remove" => ("Suppression OpenClaw".into(), "Arrête et désactive l'unité systemd --user, retire la sonde svcprobe, la sonde des modèles (timer, script, fichier .prom), les règles ufw du port, le wrapper CLI et fleet-ssh. Conserve la configuration, le workspace et le jeton de gateway.".into()),
        "openclaw-purge" => ("Purge OpenClaw".into(), "Supprime le binaire, le Node embarqué, la configuration, le workspace, les secrets, le jeton de gateway et le CNAME public, ainsi que la clé SSH du parc, /etc/openclaw (config fleet-ssh), l'état de la sonde des modèles et la clé publique de keys/<parc>/readonly/ ; l'agent watch et le clone FleetForge partent avec ~/.openclaw. Destructif.".into()),
        "agenthub-install" => ("Installation AgentCenter".into(), "Publie le CNAME agenthub.web3c.cc vers le front des proxies (Cloudflare) pour le hub AgentCenter (pilotage d'agents IA CLI dans des terminaux tmux). Le vhost est posé par proxy-update (support WebSocket, ACL parc + whitelist).".into()),
        "agenthub-security" => ("Sécurité AgentCenter".into(), "Filtre les ports publiés du hub (front app_port 4700, back-lb back_port 4701) dans DOCKER-USER via docker_ports_rules (host_vars/ctdapi.yml, hôte canonique de la machine `ctdapi`) : proxies, whitelist et VPN uniquement. Les règles ufw posées par deploy-full.sh sont décoratives sur un port Docker.".into()),
        "agenthub-deploy" => ("Déploiement AgentCenter".into(), "Orchestre le déploiement du hub via les scripts du dépôt app (scripts/run.sh prod → deploy-full.sh, build local + contexte Docker SSH) depuis le poste de contrôle, attend la santé du hub, puis (tag runner) réinstalle/active le runner AgentCenter sur l'hôte (utilisateur agents, Node 22 embarqué, systemd KillMode=process, HUB_URL en boucle locale). Variables : agenthub_src, agenthub_back_env_file, agenthub_front_env_file, agenthub_runner_token (vault, requis pour le runner).".into()),
        "agenthub-monitoring" => ("Supervision AgentCenter".into(), "Sonde svcprobe du hub (santé HTTP de l'API).".into()),
        "agenthub-remove" => ("Suppression AgentCenter".into(), "Arrête et retire les conteneurs du hub (clean-remote.sh, puis tout conteneur restant des projets compose du déploiement : réplicas back, back-lb, redis, vmagent), arrête et désactive le runner (conservé installé), retire la sonde. Conserve les volumes, l'entrée docker_ports_rules et le CNAME.".into()),
        "agenthub-purge" => ("Purge AgentCenter".into(), "Supprime conteneurs, images et volumes du hub, listés par étiquette compose (base SQLite ou Postgres, Redis, répertoire partagé : transcripts, archives ; y compris ceux de l'ancien nom AgentCenter) et le CNAME ; désactive le runner (binaire et état conservés). Vhost et règles de pare-feu à retirer séparément. Destructif — exige -e confirm=yes.".into()),

        // IA / LLM Proxy (passerelle OpenAI/Anthropic-compatible, AppTemplate)
        "llm-proxy-install" => ("Installation LLM Proxy".into(), "Publie le CNAME llm-proxy.web3c.cc vers le front des proxies (Cloudflare, portée réduite à l'entrée `llm-proxy`). Le vhost public (passerelles en flux, 50 Mo, 600 s) est posé par deploy-llm-proxy.yml via proxy-update.".into()),
        "llm-proxy-security" => ("Sécurité LLM Proxy".into(), "Filtre les ports publiés de l'app (front app_port 4800, back-lb back_port 4801 : proxies uniquement ; Postgres 4802 / Redis 4803 : profil non exposé) dans DOCKER-USER via docker_ports_rules (host_vars/ctdapi.yml, hôte canonique de la machine `ctdapi`), et vérifie le DROP par défaut en IPv4 et IPv6.".into()),
        "llm-proxy-deploy" => ("Déploiement LLM Proxy".into(), "Orchestre le déploiement de l'app via les scripts du dépôt (scripts/run.sh prod → deploy-full.sh, contexte Docker SSH) depuis le poste de contrôle, attend le front et la santé de l'API à travers lui, vérifie que Postgres/Redis restent sur la boucle locale. Variables : llm_proxy_src, llm_proxy_back_env_file, llm_proxy_front_env_file, llm_proxy_migrate, llm_proxy_update_common.".into()),
        "llm-proxy-monitoring" => ("Supervision LLM Proxy".into(), "Sonde svcprobe : santé de l'API à travers le front (service_up), plus front, back-lb, conteneurs Postgres et Redis en sondes secondaires.".into()),
        "llm-proxy-remove" => ("Suppression LLM Proxy".into(), "Arrête et retire les conteneurs de l'app (clean-remote.sh, puis passe sur l'hôte par étiquette des projets compose de deploy-full.sh), retire la sonde. Conserve les volumes, l'entrée docker_ports_rules, le vhost et le CNAME.".into()),
        "llm-proxy-purge" => ("Purge LLM Proxy".into(), "Supprime conteneurs, volumes (Postgres, Redis, répertoire partagé — préfixe du projet uniquement), images et le CNAME. Vhost et règles de pare-feu à retirer séparément. Destructif — exige -e confirm=yes.".into()),

        // Synchronisation web3c-sync (serveurs publics iptv / banking / aiteam)
        "sync-server-install" => ("Installation serveur de synchro".into(), "Déploie UNE instance web3c-sync (iptv, banking ou aiteam) : synchronise les sources du poste par rsync, construit l'image sur l'hôte (tag = empreinte du contenu, rejeu idempotent), lance le conteneur durci (lecture seule, cap_drop ALL, non-root 65532, SYNC_TRUST_PROXY avec les /32 des proxies, inscription ouverte), contrôle /v1/health et les routes de notes, garantit le CNAME sync-<instance>. Variables d'inventaire : sync_instance, app_port, sync_metrics_port ; sync_server_src.".into()),
        "sync-server-security" => ("Sécurité serveurs de synchro".into(), "Filtre dans DOCKER-USER (host_vars/ctdapi.yml, hôte canonique de la machine partagée) les ports de service 4710-4712 (proxies uniquement) et de métriques 9710-9712 (Prometheus uniquement, jamais publics), IPv4 et IPv6, et vérifie le DROP par défaut. Joué sur `ctdapi`.".into()),
        "sync-server-monitoring" => ("Supervision serveurs de synchro".into(), "/metrics natif de chaque instance : autorisation du scrape (drop-in DOCKER-USER), cible Prometheus du job sync-server, sonde svcprobe sur /v1/health, contrôle de sync_up ; alimente le groupe d'alertes `sync`.".into()),
        "sync-server-remove" => ("Suppression serveur de synchro".into(), "Arrête et retire le conteneur d'une instance, sa sonde, sa cible Prometheus et l'autorisation de scrape. Conserve les données, l'image, les sources, les sauvegardes, le CNAME, le vhost et les entrées docker_ports_rules.".into()),
        "sync-server-purge" => ("Purge serveur de synchro".into(), "IRRÉVERSIBLE : supprime une instance ET ses données (base SQLite, blobs), la sonde, la cible Prometheus, le cron de sauvegarde et le CNAME ; image et sources si plus aucune instance. Exige -e sync_purge_confirm=yes et une sauvegarde de moins de 7 jours (sinon -e sync_purge_no_backup=yes).".into()),
        "sync-backup-install" => ("Sauvegarde serveur de synchro".into(), "Sauvegarde quotidienne cohérente d'une instance web3c-sync (VACUUM INTO sous l'uid de l'image + blobs, jamais un cp d'une base WAL) vers `backup-sync` en SSH, rétention 14 générations, métrique backup_last_success_timestamp_seconds.".into()),
        "sync-backup-remove" => ("Suppression sauvegarde synchro".into(), "Arrête la sauvegarde d'une instance (cron, script, métrique). Conserve les archives de la destination.".into()),
        "sync-backup-purge" => ("Purge sauvegarde synchro".into(), "Supprime le dispositif ET les archives de l'instance sur la destination, clé SSH comprise. Destructif — exige -e sync_purge_confirm=yes.".into()),

        // IA / opencode
        "opencode-install" => ("Installation opencode".into(), "Pose le binaire opencode pour la machine (/usr/local/bin) depuis la release GitHub, variante -baseline détectée pour les x86 sans AVX2, puis la configuration globale de chaque compte pointant sur le modèle gratuit MiMo V2.5 de OpenCode Zen. Aucune clé d'API : les modèles gratuits de Zen répondent sans authentification. Termine par un appel réel au modèle — le seul contrôle qui distingue « binaire posé » de « agent fonctionnel ». Variables : opencode_version (défaut : latest), opencode_users, opencode_model, opencode_smoke_test.".into()),
        "opencode-remove" => ("Suppression opencode".into(), "Supprime le binaire système et le témoin d'installation. Conserve la configuration et opencode.db (sessions et identifiants des fournisseurs) ; signale les installations personnelles laissées par le script officiel dans ~/.opencode/bin, qui masqueraient le binaire système dans le PATH.".into()),
        "opencode-purge" => ("Purge opencode".into(), "Supprime le binaire, la configuration, opencode.db — historique des sessions ET identifiants des fournisseurs dans la même base — et le modèle sélectionné dans le TUI, pour chaque compte. Rien n'est récupérable : exige -e confirm=yes.".into()),
        "opencode-model-update" => ("Mise à jour modèle opencode".into(), "Réécrit la seule clé `model` de la configuration existante — les blocs ajoutés à la main sont préservés — après contrôle de l'identifiant contre le catalogue OpenCode Zen PUIS appel réel au modèle : figurer au catalogue ne prouve pas que le palier gratuit répond encore. Un modèle muet n'atteint jamais la configuration. Variables : opencode_model (requis), opencode_smoke_test, opencode_model_reset_selection (efface le modèle mémorisé par le TUI, qui prime sinon sur le défaut).".into()),

        // Astar
        "astar-security" => ("Sécurité noeud Astar".into(), "Ouvre à tous les ports publics du collator : P2P parachaîne 30333, P2P relais 30334 et RPC 9944 (méthodes Safe), par décision opérateur. Sans eux, activer ufw couperait le noeud de ses pairs.".into()),
        "astar-install" => ("Installation noeud Astar".into(), "Télécharge la dernière release GitHub d'Astar, crée l'utilisateur système et configure le service systemd (chaîne, nom du noeud via astar_node_name), plafonne sa mémoire (MemoryHigh, MALLOC_ARENA_MAX) et abaisse vm.swappiness.".into()),
        "astar-remove" => ("Suppression noeud Astar".into(), "Arrête le service, supprime le binaire, l'utilisateur système, la cible Prometheus et la sonde svcprobe (blockchain préservée).".into()),
        "astar-purge" => ("Purge noeud Astar".into(), "Supprime le service, le binaire, l'utilisateur, la cible Prometheus, la sonde svcprobe, le réglage swappiness et toute la blockchain Astar (~500 GB). Exige -e confirm=yes.".into()),
        "astar-monitoring" => ("Supervision noeud Astar".into(), "Enregistre les deux endpoints Prometheus natifs du collator — parachaîne 9615 et relais 9616 — ouvre le scrape vérifie que substrate_block_height est réellement exposé, et ajoute via svcprobe service_up et la consommation du processus (RSS, swap, CPU, cgroup). Remplace exporter-astar-install.".into()),

        // Theta Edge
        "theta-edge-install" => ("Installation noeuds Theta Edge".into(), "Déploie theta_edge_instances noeuds Theta Edge (Docker Compose, une identité par instance, RPC sur 127.0.0.1:17888+(N-1)×10) puis rapatrie sur le poste le keystore, la mnémonique du wallet interne et le Summary de staking de chaque instance. Nécessite theta_passwd (vault).".into()),
        "theta-edge-remove" => ("Suppression noeuds Theta Edge".into(), "Arrête toutes les instances, retire l'exporter, la cible Prometheus et l'ouverture du scrape (clés et données préservées).".into()),
        "theta-edge-purge" => ("Purge noeuds Theta Edge".into(), "Rapatrie d'abord les clés sur le poste, puis supprime instances, exporter, sweep, données et clés. Exige -e confirm=yes.".into()),
        "theta-edge-security" => ("Sécurité noeuds Theta Edge".into(), "Vérifie Docker ≥ 28 et qu'aucun port Theta Edge n'est publié hors 127.0.0.1 (le RPC edgecore rend la mnémonique sans authentification).".into()),
        "theta-edge-monitoring" => ("Supervision noeuds Theta Edge".into(), "Exporter Python par hôte (9601) : theta_edge_up par instance, hauteur, retard sur la chaîne, pairs, soldes TFuel du noeud et du wallet interne. Enregistre la cible node-theta-edge et ouvre le scrape.".into()),
        "theta-edge-sweep-install" => ("Sweep TFuel Theta Edge".into(), "Installe un script Node.js (cron) qui transfère le TFuel de l'adresse de chaque noeud vers theta_wallet au-delà d'un seuil. Instances : toutes celles de theta_edge_instances.".into()),
        "theta-edge-sweep-remove" => ("Suppression sweep TFuel".into(), "Supprime le cron et les scripts de sweep TFuel (Node.js et journal conservés).".into()),
        "theta-edge-sweep-purge" => ("Purge sweep TFuel".into(), "Supprime le sweep TFuel et son journal (Node.js conservé).".into()),

        // MTBridge (MetaTrader 5 bridge — Windows)
        "mtbridge-deploy" => ("Déploiement MTBridge".into(), "Clone et installe MTBridge sur un hôte Windows via Task Scheduler. Configure Python, l'environnement MT5 et l'auto-logon. Variables : mtbridge_github_token (vault), mtbridge_api_key (vault, optionnel), app_port (inventaire).".into()),
        "mtbridge-monitoring" => ("Monitoring MTBridge".into(), "Enregistre MTBridge comme target Prometheus sur le serveur monitor (scrape /metrics sur app_port). Ouvre le firewall Windows pour l'IP du monitor.".into()),
        "mtbridge-remove" => ("Suppression MTBridge".into(), "Arrête et supprime la tâche planifiée MTBridge et retire la target Prometheus. Préserve les répertoires d'installation et données MT5.".into()),
        "mtbridge-purge" => ("Purge MTBridge".into(), "Supprime complètement MTBridge : tâche planifiée, répertoire d'installation, données MT5, règles firewall et target Prometheus.".into()),

        // Fallback for unknown roles
        _ => {
            let label = name.replace('-', " ");
            let label = label.split_whitespace()
                .map(|w| {
                    let mut chars = w.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            (label, String::new())
        }
    }
}

/// Categorize a role by its name prefix or suffix.
fn categorize(name: &str) -> String {
    if name.ends_with("-security") || name == "firewall-security" {
        "Sécurité".to_string()
    } else if name.starts_with("ssh-") || name.starts_with("create-user-") {
        "Sécurité".to_string()
    } else if name.starts_with("fleetforge") {
        // L'application de gestion du parc, déployée comme un service du parc.
        // Catégorie à elle seule plutôt que « Système » : c'est le seul service
        // dont la machine devient un nœud de contrôle Ansible, et le confondre
        // avec l'outillage de base masquerait cette particularité.
        "FleetForge".to_string()
    } else if name.starts_with("db-")
        || name.starts_with("dbfront-")
        || name.starts_with("dbpool-")
    {
        "Base de données".to_string()
    } else if name.starts_with("proxy-") || name.starts_with("nginx-") || name.starts_with("cert-") {
        "Proxy".to_string()
    } else if name.starts_with("vpn-") {
        "VPN".to_string()
    } else if name.starts_with("mail-") {
        "Mail".to_string()
    } else if name.starts_with("monitoring-")
        || name.starts_with("prometheus-")
        || name.starts_with("pushgateway-")
        || name.starts_with("alertmanager-")
        || (name.starts_with("exporter-")
            && !name.starts_with("exporter-llamacpp"))
    {
        "Monitoring".to_string()
    } else if name.starts_with("rpcbtc-")
        || name.starts_with("rpc-")
        || name.starts_with("astar-")
        || name.starts_with("theta-edge-")
    {
        "Blockchain".to_string()
    } else if name.starts_with("docker-") {
        "Docker".to_string()
    } else if name.starts_with("wordpress-") {
        "WordPress".to_string()
    } else if name.starts_with("cloudflare-") {
        "DNS".to_string()
    } else if name.starts_with("papanglabs-") {
        // Avant les branches `front-`/`back-` génériques, qui ne matcheraient
        // de toute façon pas ce préfixe — mais l'ordre rend l'intention lisible
        // et survit à un renommage.
        "PapangLabs".to_string()
    } else if name.starts_with("front-") {
        "Frontend".to_string()
    } else if name.starts_with("back-") {
        "Backend".to_string()
    } else if name == "set-hostname" || name == "terraform" {
        "Configuration".to_string()
    } else if name.starts_with("ollama-")
        || name.starts_with("llamacpp-")
        || name.starts_with("exporter-llamacpp")
        // SearXNG est un relai de recherche : son unique client est applicatif
        // (requêtes JSON), et sur ce parc c'est la brique de recherche web des
        // services d'IA. Rangé avec eux plutôt que dans « Autre ».
        || name.starts_with("searxng-")
        || name.starts_with("opencode-")
        || name.starts_with("openclaw-")
        || name.starts_with("agenthub-")
        || name.starts_with("llm-proxy-")
        || name.starts_with("freellm-")
        || name.starts_with("starnet-")
        || name.starts_with("aiserver-")
        || name.starts_with("llmauth-")
    {
        "IA / LLM".to_string()
    } else if name.starts_with("python-") || name.starts_with("tools-") || name.starts_with("scripts-") {
        "Système".to_string()
    } else if name.starts_with("mtbridge-") {
        "Trading".to_string()
    } else if name.starts_with("scripting-") {
        // Orchestrateur EasyNode (déploiement des nœuds clients par cron).
        "Orchestration".to_string()
    } else if name.starts_with("copyfail-") {
        "Sécurité".to_string()
    } else {
        "Autre".to_string()
    }
}
