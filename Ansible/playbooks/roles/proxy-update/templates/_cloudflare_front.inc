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
   Modèle écrit à la main : openclaw.conf, ctdapi.conf (à migrer). #}
{% if hostvars[access_entry].cloudflare_front | default(false) | bool %}
    # Derrière Cloudflare ({{ access_entry }}) : IP cliente lue dans CF-Connecting-IP.
    {% for ip in cloudflare_ips %}
    set_real_ip_from {{ ip }};
    {% endfor %}
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
{% endif %}
