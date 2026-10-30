{# ── Vhost derrière Cloudflare (`cloudflare_front: true` sur l'entrée) ───────
   Fichier PARTIEL, jamais déployé seul (préfixe `_`). À inclure dans le bloc
   `server {}` (les directives real_ip ne valent pas dans un `location`), après
   avoir posé `access_entry` = nom de l'entrée d'inventaire du service :

       {% set access_entry = 'agenthub' %}
       server {
           {% include '_cloudflare_front.inc' %}
           location / { {% include '_access.inc' %} ... }
       }

   Sans l'attribut sur l'entrée, ne rend RIEN : un vhost non déclaré reste ce
   qu'il était.

   Pourquoi : le nom public est servi par l'edge Cloudflare (enregistrement
   géré chez Cloudflare, hors Ansible — la synchronisation DNS n'y touche pas).
   Les proxies voient donc l'IP d'un edge, pas celle du client, et le filtre
   d'`_access.inc` (vpns + supervision + whitelist + serveurs liés) refuserait
   tout le monde. `set_real_ip_from` remplace $remote_addr par
   CF-Connecting-IP, mais SEULEMENT quand la socket vient d'une plage
   Cloudflare : un client direct ne peut pas forger l'en-tête, et son adresse
   réelle reste filtrée comme avant. `_access.inc` teste ensuite l'adresse
   APRÈS remplacement — il ne faut donc PAS y admettre les plages Cloudflare.

   Plages : `cloudflare_ips` (group_vars/all.yml), seule liste du parc.
   Modèle écrit à la main : openclaw.conf, ctdapi.conf (à migrer).

   Authenticated Origin Pulls : ce partiel pose AUSSI la vérification du
   certificat client que Cloudflare présente (autorité PROPRE au parc,
   deploy-cloudflare-origin-pull.yml), en `optional` : rien n'est exigé ici.
   C'est `_access.inc` qui l'exige, dans chaque location en mode `public` d'une
   entrée `cloudflare_front` — une location privée garde son filtre d'adresse et
   reste joignable par ses appelants directs (Alertmanager local…).
   Pourquoi pas un filtre sur `cloudflare_ips` : ces plages sont communes à TOUS
   les clients Cloudflare (n'importe quel compte peut pointer un nom vers nos
   proxies) ; le certificat client, lui, n'est présenté que pour NOTRE zone.
   L'autorité est déposée par proxy-update (main et deploy-one-site) AVANT tout
   gabarit : `nginx -t` refuse un `ssl_client_certificate` absent. #}
{% if hostvars[access_entry].cloudflare_front | default(false) | bool %}
    # Derrière Cloudflare ({{ access_entry }}) : IP cliente lue dans CF-Connecting-IP.
    {% for ip in cloudflare_ips %}
    set_real_ip_from {{ ip }};
    {% endfor %}
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
    # Certificat client de NOTRE zone Cloudflare : vérifié ici, exigé par
    # `_access.inc` dans les locations publiques.
    ssl_client_certificate {{ cfopull_ca_dest | default('/etc/nginx/cloudflare-origin-pull-ca.pem') }};
    ssl_verify_client optional;
{% endif %}
