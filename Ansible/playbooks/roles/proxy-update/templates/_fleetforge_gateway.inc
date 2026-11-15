{# ── Passerelle MCP de FleetForge (famille `fleetforge-gateway`) ──────────────
   Fichier PARTIEL (préfixe `_`), inclus par le gabarit du parc
   `parcs/<parc>/nginx/sites-enabled/fleetforge-gateway.conf` après
   `{% set ffg_entry = '<entrée>' %}`. Générique : tout vient de l'entrée
   dédiée de l'inventaire (adresse, ports, nom public, listes d'accès).

   Deux chemins, deux politiques d'accès, toutes deux fermées par `deny all` :

   • `/mcp` — serveur MCP de la passerelle (pilotage du parc par des agents).
     N'admet QUE :
       1. les serveurs liés NOMMÉS par `ffg_mcp_allowed_hosts` (noms d'entrées
          d'inventaire ; vide = personne) ;
       2. la `whitelist` du parc, SI `ffg_mcp_allow_whitelist` est vrai — accès
          de TEST, à repasser à `false` dès la fin des tests et avant toute
          exposition E2/E3 ;
       3. rien d'autre : ni vpns, ni supervision, ni `access_linked`, ni plage
          large. Une adresse qui n'est pas une IPv4 est ignorée (commentaire),
          jamais élargie.
     Une seule `location` regex insensible à la casse couvre `/mcp`, `/MCP`,
     `/mcp/…` : nginx normalise l'URI avant le choix de la `location`
     (`//mcp`, `/x/../mcp`, `%2e%2e` → `/mcp`), et Express route `/MCP` et
     `/mcp/` vers le même contrôleur — aucune variante ne retombe dans
     `location /`. Elle vise le back-lb (`back_port`) : le front de l'app ne
     relaie que `/api/`, `/mcp` n'est servi que par le back.
   • tout le reste (front « Mes connexions MCP », approbations, `/api/v1/…`) —
     des humains y viennent : mode de l'entrée via `_access.inc` (`private` :
     vpns + supervision + whitelist + `access_linked`, puis `deny all`).
   • `/.well-known/` — fermé en E1 (aucune découverte OAuth tant que la
     passerelle n'est pas exposée en E2/E3).

   `X-Forwarded-For` est RÉÉCRIT avec `$remote_addr` (jamais complété) : la
   passerelle (TRUST_PROXY = ces proxies) lit l'adresse vue par le proxy, pas
   une chaîne fournie par le client. C'est elle que la seconde barrière —
   l'allow-list d'adresses propre à chaque credential `exec` (≤ /16, imposée
   par `mcp-access`) — compare ; elle ne s'élargit pas avec la whitelist.

   Co-localisation (modèle freellm.conf) : passerelle sur la machine de CE
   proxy → 127.0.0.1, sinon son adresse ; le port distant n'est ouvert qu'aux
   proxies dans DOCKER-USER (`fleetforge-gateway-security`). #}
{% if ffg_entry is defined and ffg_entry in hostvars %}
{% set _gw = hostvars[ffg_entry] %}
{% set _gw_backend = '127.0.0.1' if _gw.ansible_host == ansible_host else _gw.ansible_host %}
{% set _gw_front = 'http://' ~ _gw_backend ~ ':' ~ _gw.app_port %}
{% set _gw_back = 'http://' ~ _gw_backend ~ ':' ~ _gw.back_port %}
{% set _gw_ipv4 = '^[0-9]{1,3}([.][0-9]{1,3}){3}$' %}
{% set access_entry = ffg_entry %}
# Passerelle {{ ffg_entry }} : front {{ _gw_front }}, back-lb {{ _gw_back }}
# ({{ 'co-localisée sur ce proxy' if _gw_backend == '127.0.0.1' else 'hôte distant' }})

server {
    listen      80;
    listen      [::]:80;
    server_name {{ _gw.proxy_hostname }};
    return 301 https://$host$request_uri;
}

server {
{% if nginx_version is version('1.25.1', '>=') %}
    listen      443 ssl;
    listen      [::]:443 ssl;
    http2       on;
{% else %}
    listen      443 ssl http2;
    listen      [::]:443 ssl http2;
{% endif %}
    server_name {{ _gw.proxy_hostname }};

    ssl_certificate     /etc/letsencrypt/live/{{ domain_name }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ domain_name }}/privkey.pem;

    add_header X-Robots-Tag "noindex, nofollow" always;

    # ── /mcp : serveurs liés nommés (+ whitelist de test), rien d'autre ──
    location ~* ^/mcp(/.*)?$ {
        # 1. Serveurs liés (ffg_mcp_allowed_hosts de {{ ffg_entry }})
{% for h in _gw.ffg_mcp_allowed_hosts | default([]) %}
{% if h in hostvars and (hostvars[h].ansible_host | default('')) is match(_gw_ipv4) %}
        allow {{ hostvars[h].ansible_host }};  # mcp: serveur lié {{ h }}
{% else %}
        # mcp: serveur lié {{ h }} ignoré (absent de l'inventaire ou adresse non IPv4)
{% endif %}
{% endfor %}
        # 2. Whitelist du parc : {{ 'ACTIVÉE (accès de test, ffg_mcp_allow_whitelist)' if (_gw.ffg_mcp_allow_whitelist | default(false) | bool) else 'non admise' }}
{% if _gw.ffg_mcp_allow_whitelist | default(false) | bool %}
{% for ip in whitelist | default([]) %}
        allow {{ ip }};  # mcp: whitelist (test)
{% endfor %}
{% endif %}
        # 3. Rien d'autre.
        deny all;

        proxy_pass              {{ _gw_back }};
        proxy_http_version      1.1;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_set_header        X-Forwarded-For $remote_addr;
        proxy_set_header        X-Forwarded-Proto $scheme;
        proxy_set_header        Connection "";
        client_max_body_size    128k;
        proxy_buffering         off;
        proxy_read_timeout      180s;
        proxy_send_timeout      180s;
    }

    # ── Découverte OAuth : fermée en E1 ──
    location ^~ /.well-known/ {
        deny all;
    }

    # ── Front, approbations, /api/v1 : mode de l'entrée (privé) ──
    location / {
        {% include '_access.inc' %}

        proxy_pass         {{ _gw_front }};
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_read_timeout 300s;
    }
}
{% endif %}
