{# ── IP client réelle derrière Cloudflare (nom « proxifié », nuage orange) ───
   Fichier PARTIEL, jamais déployé seul (préfixe `_`). Deux morceaux, un par
   contexte nginx, choisis par `cf_part` ; poser `cf_edge_var` (nom de variable
   nginx propre au vhost) avant chaque include :

       {% set cf_edge_var = 'backindicators_prod_edge' %}
       {% set cf_part = 'geo' %}{% include '_cloudflare_realip.inc' %}   ← hors server {}
       server {
           {% set cf_part = 'realip' %}{% include '_cloudflare_realip.inc' %}
           location / {
               {% set cf_part = 'guard' %}{% include '_cloudflare_realip.inc' %}
               proxy_set_header X-Forwarded-For $remote_addr;   ← écrasé, jamais complété
           }
       }

   Pourquoi : derrière Cloudflare, $remote_addr est l'IP d'un edge. Les
   limiteurs par IP de l'application (et `limit_req` ici) voyaient donc
   quelques dizaines d'edges au lieu des clients. `realip` remplace
   $remote_addr par CF-Connecting-IP, mais SEULEMENT quand la socket vient d'une
   plage Cloudflare (`set_real_ip_from`) : un client direct ne peut pas forger
   l'en-tête.

   Conséquence sur le filtrage : `allow`/`deny` testent l'adresse APRÈS
   remplacement — un `allow <plage Cloudflare>` ne matcherait plus personne.
   Le filtre « edges Cloudflare + VPN + whitelist » se fait donc sur l'adresse
   de la SOCKET ($realip_remote_addr) par un `geo`, et `guard` refuse le reste.

   Plages : `cloudflare_ips` (group_vars/all.yml), seule liste du parc. #}
{% if cf_part == 'geo' %}
{# Dédupliqué : une adresse en double dans un `geo` est un avertissement nginx. #}
{% set cf_edge_sources = (cloudflare_ips
     + (groups['vpns'] | default([]) | map('extract', hostvars, 'ansible_host') | list)
     + whitelist) | unique %}
geo $realip_remote_addr ${{ cf_edge_var }} {
    default 0;
{% for ip in cf_edge_sources %}
    {{ ip }} 1;
{% endfor %}
}
{% elif cf_part == 'realip' %}
{% for ip in cloudflare_ips %}
  set_real_ip_from {{ ip }};
{% endfor %}
  real_ip_header CF-Connecting-IP;
{% elif cf_part == 'guard' %}
    if (${{ cf_edge_var }} = 0) {
        return 403;
    }
{% endif %}
