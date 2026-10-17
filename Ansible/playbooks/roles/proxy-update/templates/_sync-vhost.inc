{# ── Serveur de synchronisation web3c-sync — corps commun des trois vhosts ─────
   Fichier PARTIEL, jamais déployé seul : le nom commence par `_`, et
   tasks/main.yml ignore ces fichiers lors de la copie de sites-enabled/. Il est
   inclus par sync-iptv.conf, sync-banking.conf et sync-aiteam.conf, qui
   n'écrivent que `sync_inst` — un seul endroit où se trouvent les exigences de
   sécurité ci-dessous, donc aucune des trois copies ne peut dériver.

   Le service (rôles `sync-server-*`, entrée d'inventaire `sync-<instance>`, groupe
   `sync_servers`) tourne dans un conteneur sur `ctdapi` (machine
   partagée) — JAMAIS co-localisé avec un proxy : `proxy_pass` vise l'adresse
   `ansible_host` de cette entrée, port `app_port`.

   PUBLIC : ni whitelist, ni X-Api-Key. L'accès aux données est contrôlé par les
   signatures d'appareil du protocole (spec/PROTOCOL.md) ; ce vhost n'est qu'un
   relais TLS avec quelques garde-fous de défense en profondeur.

   EXIGENCES IMPÉRATIVES (spec/SECURITY-REVIEW.md §3 C9, PROTOCOL.md §12) :
   • `X-Real-IP $remote_addr` ÉCRASE toute valeur cliente : le serveur fait
     confiance à cet en-tête venant des proxies de confiance
     (SYNC_TRUSTED_PROXIES) ; un client qui le poserait lui-même contournerait
     toutes les limites de débit par adresse. `proxy_set_header` remplace
     l'en-tête entrant, il ne s'y ajoute pas. X-Forwarded-For est écrasé de la
     même façon (jamais `$proxy_add_x_forwarded_for`, qui propagerait une chaîne
     forgée par le client).
   • AUCUN préfixe ajouté ni retiré : `proxy_pass` sans partie URI transmet l'URI
     telle que reçue — la signature couvre le chemin tel quel.
   • Les adresses IP ne vivent QUE dans des journaux dédiés, conservés 7 jours au
     plus (logrotate : tasks/sync-logs.yml). Le format de journal ne contient ni
     corps, ni en-têtes d'authentification, ni chaîne de requête, et masque les
     identifiants de groupe/document/blob.
   • /metrics n'est JAMAIS exposé ici (il est d'ailleurs sur un autre port, non
     relayé) : 404 explicite par précaution. #}
{% set sy_name   = 'sync-' ~ sync_inst %}
{% if sy_name in hostvars %}
{% set sy_host     = sy_name ~ '.' ~ domain_name %}
{% set sy_upstream = 'http://' ~ hostvars[sy_name].ansible_host ~ ':' ~ hostvars[sy_name].app_port %}
{% set sy_zone     = 'sync_' ~ sync_inst ~ '_rl' %}
{% set sy_fmt      = 'sync_' ~ sync_inst ~ '_anon' %}
{% set sy_path     = '$sync_' ~ sync_inst ~ '_logpath' %}
{% set sy_log      = '/var/log/nginx-sync/access-' ~ sync_inst ~ '.log' %}
{% set sy_errlog   = '/var/log/nginx-sync/error-' ~ sync_inst ~ '.log' %}
# Backend sync-{{ sync_inst }} : {{ sy_upstream }} (hôte distant, jamais co-localisé)

# Limite de débit par adresse, en défense en profondeur seulement : le serveur
# applique déjà 600 requêtes/min/adresse et 120 écritures/min/appareil. Celle-ci
# est volontairement plus large (20 r/s, rafale 100) pour ne casser ni les
# synchronisations initiales (nombreux documents d'un coup) ni les reconnexions
# SSE ; elle coupe seulement l'inondation brute avant qu'elle n'atteigne le
# conteneur.
limit_req_zone $binary_remote_addr zone={{ sy_zone }}:10m rate=20r/s;

# Chemin tel que journalisé : les identifiants de groupe/document/blob ne sont
# pas utiles à l'exploitation et rapprochés d'une adresse IP ils seraient de la
# métadonnée sensible. On garde le verbe (members, changes, stream, d, b…).
map $uri {{ sy_path }} {
    default                                  "$uri";
    ~^/v1/g/[^/]+/(?<sy_seg_{{ sync_inst }}>[^/]+)           "/v1/g/{gid}/$sy_seg_{{ sync_inst }}";
    ~^/v1/g/[^/]+$                           "/v1/g/{gid}";
    ~^/v1/public/ratings/                    "/v1/public/ratings/{key}";
}

# Pas de corps, pas d'en-têtes (Authorization, X-Device, X-Sig…), pas de chaîne
# de requête, pas de User-Agent ni de Referer.
log_format {{ sy_fmt }} '$remote_addr [$time_iso8601] "$request_method {{ sy_path }}" $status $body_bytes_sent $request_time';

server {
    listen      80;
    listen      [::]:80;
    server_name {{ sy_host }};
    server_tokens off;
    access_log  {{ sy_log }} {{ sy_fmt }};
    error_log   {{ sy_errlog }} warn;
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
    server_name {{ sy_host }};
    server_tokens off;

    ssl_certificate     /etc/letsencrypt/live/{{ domain_name }}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{ domain_name }}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    access_log {{ sy_log }} {{ sy_fmt }};
    error_log  {{ sy_errlog }} warn;

    # Documents 256 Kio, blobs 16 Mio (+ marge d'enveloppe) : 17m. Le serveur
    # applique ses propres plafonds exacts par route ; ceci n'est que le filet.
    client_max_body_size 17m;

    limit_req        zone={{ sy_zone }} burst=100 nodelay;
    limit_req_status 429;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Robots-Tag              "noindex, nofollow" always;
    add_header Referrer-Policy           "no-referrer" always;

    # Les métriques ne sont JAMAIS publiques.
    location = /metrics {
        return 404;
    }

    # Flux SSE (GET /v1/g/<gid>/stream) : connexion longue, jamais bufferisée.
    # Le serveur coupe lui-même ses flux à 1 h ; le client se reconnecte.
    location ~ ^/v1/g/[^/]+/stream$ {
        proxy_pass         {{ sy_upstream }};
        proxy_http_version 1.1;
        proxy_set_header   Connection "";
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;

        proxy_buffering         off;
        proxy_cache             off;
        gzip                    off;
        proxy_read_timeout      3600s;
        proxy_send_timeout      3600s;
        proxy_next_upstream     off;
    }

    location / {
        proxy_pass         {{ sy_upstream }};
        proxy_http_version 1.1;
        proxy_set_header   Connection "";
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Un POST/PUT signé n'est jamais rejoué vers un autre amont (il n'y en a
        # d'ailleurs qu'un) ; le corps est tamponné avant envoi pour protéger le
        # conteneur des clients lents.
        proxy_next_upstream off;
        proxy_read_timeout  120s;
        proxy_send_timeout  120s;
    }
}
{% else %}
# L'entrée d'inventaire {{ sy_name }} est absente : aucun vhost n'est servi ici.
{% endif %}
