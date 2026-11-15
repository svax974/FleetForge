{# ── Filtre d'accès d'un vhost selon le MODE de l'entrée (CLAUDE.md § 1) ──────
   Fichier PARTIEL, jamais déployé seul (préfixe `_`). À inclure dans un bloc
   `location`, après avoir posé `access_entry` = nom de l'entrée d'inventaire
   du service :

       {% set access_entry = 'ollama' %}
       ...
       location / {
           {% include '_access.inc' %}
           proxy_pass ...;
       }

   `access_mode` de l'entrée, PRIVÉ par défaut — un oubli doit fermer, pas
   ouvrir :
     • private → vpns + Prometheus + whitelist + serveurs liés (`access_linked`
                 de l'entrée : NOMS d'entrées d'inventaire, clients applicatifs
                 réels ; plus, sur un proxy de la MÊME machine qu'un serveur
                 lié, les sous-réseaux Docker privés déclarés par son
                 `access_local_cidrs`), puis `deny all` ;
     • public  → aucun filtre d'adresse : l'authentification est celle du
                 service (signatures d'appareil, jeton…), et elle doit exister.
                 Entrée `cloudflare_front: true` : public MAIS seulement par
                 NOTRE Cloudflare — le certificat client vérifié par
                 `_cloudflare_front.inc` est exigé ici (403 sinon), ce qui
                 ferme l'accès direct aux proxies et celui d'un autre compte
                 Cloudflare pointé sur eux. Sans l'attribut : rien de plus.
   Une valeur inconnue rend `deny all` : un vhost fermé se remarque, un vhost
   ouvert par erreur non.

   Surcharge pour UN bloc : `{% set access_mode_local = 'private' %}` avant
   l'include. Sert aux services qui exposent deux vhosts de natures
   différentes — API publique gardée par jeton + UI privée (rotki.conf,
   searxng.conf). La remettre à `none` n'est pas nécessaire tant que chaque
   bloc qui en dépend la pose lui-même.

   `deny all` n'est PAS optionnel en mode privé : sans lui, les `allow`
   laissent tout le reste AUTORISÉ. #}
{% set _access_mode = access_mode_local | default(hostvars[access_entry].access_mode | default('private'), true) %}
{% if _access_mode == 'private' %}
        # Mode privé ({{ access_entry }}) : vpns + supervision + whitelist.
        {% for host in groups['vpns'] | default([]) %}
        allow {{ hostvars[host]['ansible_host'] }};  # vpn {{ host }}
        {% endfor %}
        {% if prometheus_host is defined and prometheus_host in hostvars %}
        allow {{ hostvars[prometheus_host]['ansible_host'] }};  # supervision {{ prometheus_host }}
        {% endif %}
        {% for ip in whitelist %}
        allow {{ ip }};
        {% endfor %}
        {% for host in hostvars[access_entry].access_linked | default([]) %}
        allow {{ hostvars[host]['ansible_host'] }};  # serveur lié {{ host }}
        {#- Serveur lié sur la MÊME machine que ce proxy : il joint le nom public
            par l'adresse publique de la machine, mais depuis un conteneur le
            paquet arrive en local, avec l'adresse du conteneur (pas de NAT
            pour une destination locale). Ses sous-réseaux Docker DÉDIÉS sont
            alors déclarés sur son entrée (`access_local_cidrs`) — et admis ici
            SEULEMENT sur un proxy co-localisé, SEULEMENT s'ils sont valides :
            IPv4 aux octets ≤ 255, préfixe /16 à /32, forme CANONIQUE (aucun
            bit d'hôte), plage privée (10/8, 172.16/12, 192.168/16), et ne
            contenant l'adresse d'AUCUN serveur VPN. Toute autre valeur est
            ignorée (fermé), jamais élargie ni corrigée. #}
        {% if hostvars[host]['ansible_host'] == ansible_host %}
        {% for cidr in hostvars[host].access_local_cidrs | default([]) %}
        {% set _lc = namespace(ok=false, vpn=false) %}
        {% if cidr is string and cidr is match('^[0-9]{1,3}([.][0-9]{1,3}){3}/[0-9]{1,2}$') %}
        {% set _o = cidr.split('/')[0].split('.') | map('int') | list %}
        {% set _len = cidr.split('/')[1] | int %}
        {% if (_o | max) <= 255 and _len >= 16 and _len <= 32 %}
        {% set _net = ((_o[0] * 256 + _o[1]) * 256 + _o[2]) * 256 + _o[3] %}
        {% set _size = 2 ** (32 - _len) %}
        {% for v in groups['vpns'] | default([]) %}
        {% set _va = hostvars[v]['ansible_host'] | default('') | string %}
        {% if _va is match('^[0-9]{1,3}([.][0-9]{1,3}){3}$') %}
        {% set _vo = _va.split('.') | map('int') | list %}
        {% set _vn = ((_vo[0] * 256 + _vo[1]) * 256 + _vo[2]) * 256 + _vo[3] %}
        {% if _vn >= _net and _vn < _net + _size %}{% set _lc.vpn = true %}{% endif %}
        {% endif %}
        {% endfor %}
        {% set _lc.ok = (_net % _size == 0)
             and (_o[0] == 10 or (_o[0] == 172 and _o[1] >= 16 and _o[1] <= 31) or (_o[0] == 192 and _o[1] == 168))
             and not _lc.vpn %}
        {% endif %}
        {% endif %}
        {% if _lc.ok %}
        allow {{ cidr }};  # serveur lié {{ host }}, réseau Docker local
        {% else %}
        # access_local_cidrs « {{ cidr }} » de {{ host }} ignoré : pas un sous-réseau IPv4 privé canonique /16 à /32 hors VPN.
        {% endif %}
        {% endfor %}
        {% endif %}
        {% endfor %}
        deny all;
{% elif _access_mode == 'public' and hostvars[access_entry].cloudflare_front | default(false) | bool %}
        # Mode public ({{ access_entry }}) derrière Cloudflare : certificat client de NOTRE zone exigé.
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
{% elif _access_mode == 'public' %}
        # Mode public ({{ access_entry }}) : aucun filtre d'adresse.
{% else %}
        # access_mode « {{ _access_mode }} » inconnu sur {{ access_entry }} : fermé.
        deny all;
{% endif %}
