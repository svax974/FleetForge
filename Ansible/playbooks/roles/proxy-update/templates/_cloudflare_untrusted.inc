{# ── Socket Cloudflare SANS certificat client : `geo` + `map` d'un vhost ──────────
   FleetForge

   Copyright © 2025 Stéphane VAXELAIRE
   SPDX-License-Identifier: MIT — see LICENSE

   Fichier PARTIEL, jamais déployé seul (préfixe `_`). À inclure AVANT le `server {}` (`geo` et `map`
   n'existent qu'au niveau `http`), après avoir posé `cf_slug` = nom du vhost réduit à `[a-z0-9_]` (les
   variables nginx sont PROPRES au vhost : deux noms servis par Cloudflare ne doivent pas déclarer deux
   fois la même) :

       {% set cf_slug = server_name | regex_replace('[^a-z0-9]', '_') %}
       {% set cf_untrusted_var = 'cf_untrusted_' ~ cf_slug %}
       {% include '_cloudflare_untrusted.inc' %}{{ '\n\n' -}}
       server {
           {% include '_cloudflare_front.inc' %}
           location / { {% include '_access.inc' %} ... }
       }

   Pourquoi : `_cloudflare_front.inc` fait confiance à CF-Connecting-IP de TOUTE socket d'une plage Cloudflare,
   et ces plages sont communes à tous les clients Cloudflare : sans certificat client (Authenticated Origin
   Pulls de NOTRE zone), un tiers qui y ouvre une socket forge une adresse de la whitelist ou du VPN et passe
   le filtre d'adresse d'`_access.inc`. `$cf_untrusted_<slug>` vaut 1 pour une telle socket ; `_access.inc`
   (branche privée) et `_named_access.inc` la refusent (403) AVANT tout `allow`, pour une entrée
   `cloudflare_named` ET `cloudflare_front` dès que `cf_untrusted_var` est posée par le vhost. Même mécanisme
   pour les deux attributs : `webapp.conf.j2` et les vhosts écrits à la main (agenthub.conf) incluent ce partiel.

   Fermé au rendu : `_cloudflare_front.inc` refuse de rendre un vhost qui l'inclut sans `cf_untrusted_var`.
   Variable nginx `cf_untrusted_<slug>` : nom court (limite probable ~46 caractères sous la taille de hash par défaut, non vérifiée).

   Le partiel perd sa fin de ligne finale au rendu : l'appelant la remet (`{{ '\n\n' -}}`). #}
# Socket d'une plage Cloudflare (`cloudflare_ips`, la même liste que `set_real_ip_from`) : elle SEULE peut remplacer l'adresse
# cliente par CF-Connecting-IP. Une telle socket sans certificat client valide (Authenticated Origin Pulls de NOTRE zone) n'est
# pas Cloudflare : `$cf_untrusted_{{ cf_slug }}` vaut 1 et les locations PRIVÉES refusent (403) avant tout filtre d'adresse. Fermé par
# défaut : seule une clé « hors Cloudflare » (0:…) ou « Cloudflare + certificat vérifié » (1:SUCCESS) donne 0.
geo $realip_remote_addr $cf_socket_{{ cf_slug }} {
    default 0;
{% for _ip in cloudflare_ips | unique %}
    {{ _ip }} 1;
{% endfor %}
}
map "$cf_socket_{{ cf_slug }}:$ssl_client_verify" $cf_untrusted_{{ cf_slug }} {
    default 1;
    "~^0:" 0;
    "1:SUCCESS" 0;
}
