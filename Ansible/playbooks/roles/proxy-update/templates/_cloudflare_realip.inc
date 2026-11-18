{# ── IP client réelle derrière Cloudflare (nom « proxifié », nuage orange) ───
   Fichier PARTIEL, jamais déployé seul (préfixe `_`). Quatre morceaux (plus deux pour un
   vhost qui garde son propre filtre d'adresse, voir plus bas), un par
   contexte nginx, choisis par `cf_part` ; poser `cf_edge_var` (nom de variable
   nginx propre au vhost) avant chaque include :

       {% set cf_edge_var = 'backindicators_prod_edge' %}
       {% set cf_slug = 'backindicators_prod' %}                 ← nom de variable nginx (voir plus bas)
       {% set cf_aop_name = back_public %}                       ← nom PUBLIC du vhost (= son server_name)
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

   Plages : `cloudflare_ips` (group_vars/all.yml), seule liste du parc.

   ── Authenticated Origin Pulls (opt-in par l'inventaire) ────────────────────
   Faiblesse restante du filtre ci-dessus : ses plages sont communes à TOUS les clients Cloudflare. N'importe quel compte peut
   ouvrir une socket depuis une plage Cloudflare et forger CF-Connecting-IP : les limiteurs par IP (celui de l'application,
   `limit_req`) voient alors une adresse choisie par l'appelant (évasion, ou adresse d'une victime). Seul le certificat client
   de NOTRE zone (autorité PROPRE au parc, deploy-cloudflare-origin-pull.yml, jamais le certificat partagé de Cloudflare) prouve
   que la requête vient d'elle. Même mécanisme que `_cloudflare_untrusted.inc` (`geo` + `map` fermé par défaut, ce partiel
   l'inclut) : `$cf_untrusted_<cf_slug>` vaut 1 pour une socket d'une plage Cloudflare SANS certificat client vérifié.

   L'entrée d'inventaire qui porte le nom public (`proxy_hostname` ou `cloudflare_origin_pull_aliases`) déclare
   `cloudflare_origin_pull: observe | enforce` (`proxy_update_aop`, defaults du rôle) :
     • absent       → ce partiel rend EXACTEMENT ce qu'il rendait avant (octet pour octet) ;
     • `observe`    → le `server {}` demande et vérifie le certificat (`ssl_verify_client optional_no_ca` : jamais de rejet, même
                      d'un certificat qui ne chaîne pas à notre autorité ; `optional` en enforce), un journal dédié
                      `cf-aop-<cf_slug>.log` (en plus de access.log) porte `$ssl_client_verify` et `$cf_untrusted_<cf_slug>` :
                      RIEN n'est refusé de plus. C'est le signal qui prouve, sur le trafic réel, que Cloudflare présente le
                      certificat AVANT d'exiger quoi que ce soit ;
     • `enforce`    → en plus, `guard` refuse (403) la socket d'une plage Cloudflare sans certificat vérifié. VPN, whitelist et
                      appelants directs (sockets hors plage Cloudflare) ne sont pas concernés. Le rendu n'est posé que si
                      l'activation chez Cloudflare est PROUVÉE (proof.yml du rôle cloudflare-origin-pull) : exiger le certificat
                      avant l'activation répondrait 403 à TOUT le trafic légitime.
   `cf_part = 'cert'` : seulement la garde du certificat (sans le filtre d'adresse), pour une location volontairement hors
   du filtre VPN/whitelist/Cloudflare (`inline-image/`) qui voudrait l'exiger des sockets Cloudflare — non posée aujourd'hui.

   ── Vhost qui garde SON PROPRE filtre d'adresse (ctdapi.conf, ctdapi-back.conf, tradekong-back.conf) ─────────────────────────────
   Deux morceaux de plus (`certhttp`, `certserver`), avec `cert`, pour un vhost qui ne veut AJOUTER que l'exigence du certificat client aux sockets d'une plage Cloudflare,
   sans toucher à ses `allow`/`deny`, ni à sa façon de lire l'adresse cliente (avec ou sans `real_ip`, avec ou sans `real_ip_recursive`) :
       {% set cf_slug = 'ctdapi_back' %}  {% set cf_aop_name = 'ctdapi-back.' ~ domain_name %}
       {% set cf_part = 'certhttp' %}{% include '_cloudflare_realip.inc' %}     ← hors server {} : `geo` + `map` + journal
       server {
           {% set cf_part = 'certserver' %}{% include '_cloudflare_realip.inc' %}  ← server {} : ssl_client_certificate, ssl_verify_client
           location / {
               {% set cf_part = 'cert' %}{% include '_cloudflare_realip.inc' %}     ← garde `if ($cf_untrusted_<slug>) { return 403; }`
               allow … ; deny all;                                                  ← filtre d'adresse du vhost, INCHANGÉ
           }
       }
   `certhttp` et `certserver` sont EXACTEMENT les morceaux d'authentification de `geo` et de `realip` (mêmes octets), sans le filtre
   d'adresse (`geo` d'edge) ni `set_real_ip_from` : un vhost sans `real_ip` garde sa socket comme adresse. `$realip_remote_addr` y vaut
   l'adresse de la socket (nginx la renseigne même sans `set_real_ip_from`). Poser les trois include À LA COLONNE 0 : sans déclaration
   pour ce nom ils ne rendent rien et leur ligne disparaît (`trim_blocks`), le vhost est alors rendu octet pour octet comme avant.

   FERMÉ : dès qu'UNE entrée du parc déclare `cloudflare_origin_pull`, un vhost qui inclut ce partiel DOIT avoir posé `cf_slug` ET
   `cf_aop_name` : le rendu échoue sinon (variable non définie, dont le nom dit quoi ajouter), au lieu de laisser un vhost sans
   la protection que l'inventaire déclare. Une valeur inconnue, ou deux entrées en désaccord sur un même nom, refusent aussi.
   `cf_slug` : `[a-z0-9_]`, court (variable nginx `cf_untrusted_<cf_slug>`, limite `variables_hash_bucket_size` ~46 caractères,
   non vérifiée) et PROPRE au vhost (deux vhosts ne déclarent pas deux fois la même variable). #}
{% set _aop = proxy_update_aop | default({}) %}
{% if _aop | length > 0 and (cf_slug is not defined or cf_aop_name is not defined) %}{{ ERREUR_rendu_refuse__un_vhost_qui_inclut__cloudflare_realip_inc__doit_poser__cf_slug__et__cf_aop_name__des_qu_une_entree_declare__cloudflare_origin_pull }}{% endif %}
{% set _mode = _aop.get(cf_aop_name, '') if _aop | length > 0 else '' %}
{% if _mode not in ['', 'observe', 'enforce'] %}{{ ERREUR_rendu_refuse__cloudflare_origin_pull_invalide_ou_en_desaccord_entre_entrees__attendu_observe_ou_enforce }}{% endif %}
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
{% endif %}
{% if cf_part in ['geo', 'certhttp'] and _mode != '' %}
{% include '_cloudflare_untrusted.inc' %}{{ '\n' -}}
# Journal dédié (en plus de access.log) : ce que nginx a lu du certificat client de CHAQUE requête de ce vhost{{ ', inline-image comprise' if cf_part == 'geo' else '' }}.
# `cf_socket=1` : socket d'une plage Cloudflare ; `verify` : $ssl_client_verify (SUCCESS, NONE, FAILED:…) ; `untrusted=1` : socket
# Cloudflare SANS certificat vérifié, ce que `enforce` refuse (mode={{ _mode }}). `claimed` : CF-Connecting-IP tel que reçu (forgeable),
# `client` : adresse retenue. Jamais la chaîne de requête ($uri), jamais d'en-tête d'authentification.
log_format cf_aop_{{ cf_slug }} '$time_iso8601 host=$host socket=$realip_remote_addr claimed="$http_cf_connecting_ip" client=$remote_addr '
    'cf_socket=$cf_socket_{{ cf_slug }} verify="$ssl_client_verify" untrusted=$cf_untrusted_{{ cf_slug }} mode={{ _mode }} '
    'status=$status method=$request_method uri="$uri" ray="$http_cf_ray" ua="$http_user_agent"';
{% endif %}
{% if cf_part == 'realip' %}
{% for ip in cloudflare_ips %}
  set_real_ip_from {{ ip }};
{% endfor %}
  real_ip_header CF-Connecting-IP;
{% endif %}
{% if cf_part in ['realip', 'certserver'] and _mode != '' %}
{% if _mode == 'enforce' %}
  # Certificat client de NOTRE zone Cloudflare (Authenticated Origin Pulls, mode enforce) : vérifié ici, exigé par la garde du repli `/`.
{% else %}
  # Certificat client de NOTRE zone Cloudflare (Authenticated Origin Pulls, mode observe) : vérifié et journalisé, rien n'est refusé de
  # plus ; `optional_no_ca` ne rejette jamais un certificat présenté dont la chaîne n'aboutit pas à notre autorité (journal : FAILED:…).
{% endif %}
  ssl_client_certificate {{ cfopull_ca_dest | default('/etc/nginx/cloudflare-origin-pull-ca.pem') }};
  ssl_verify_client {{ 'optional' if _mode == 'enforce' else 'optional_no_ca' }};
  access_log /var/log/nginx/access.log;
  access_log /var/log/nginx/cf-aop-{{ cf_slug }}.log cf_aop_{{ cf_slug }};
{% endif %}
{% if cf_part == 'guard' %}
    if (${{ cf_edge_var }} = 0) {
        return 403;
    }
{% if _mode == 'enforce' %}
    if ($cf_untrusted_{{ cf_slug }}) {
        return 403;
    }
{% endif %}
{% endif %}
{% if cf_part == 'cert' %}
{% if _mode == 'enforce' %}
    if ($cf_untrusted_{{ cf_slug }}) {
        return 403;
    }
{% endif %}
{% endif %}
