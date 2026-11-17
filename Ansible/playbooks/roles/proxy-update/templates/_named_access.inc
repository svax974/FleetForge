{# ── Liste d'accès NOMMÉE d'une location ─────────────────────────────────────
   Fichier PARTIEL (préfixe `_`), inclus dans le corps d'une `location` du vhost
   générique (`webapp.conf.j2`) après `{% set named_access = <dict> %}` quand
   l'entrée déclare `webapp_vhost_locations[].access` — à la place du mode de
   l'entrée (`_access.inc`). Générique : tout vient de l'inventaire.

   N'admet QUE, puis `deny all` :
     1. les serveurs NOMMÉS par `hosts` (entrées d'inventaire ; vide = personne),
        par leur adresse IPv4 (une autre forme est ignorée, jamais élargie) ;
     2. la `whitelist` du parc SI `whitelist` est vrai — FILTRÉE : IPv4 seule ou
        /32 ; IPv6 seulement avec un préfixe ≥ `v6_min_prefix` (128 par défaut =
        une adresse ; 64 au plus large). Le reste est ignoré (commentaire) ;
     3. rien d'autre : ni vpns, ni supervision, ni `access_linked`, ni plage large.
   Toute adresse d'un serveur VPN (serveur nommé OU whitelist) est écartée —
   proxy2 = vpn1 = NAT domestique : l'admettre ouvrirait le chemin à tout ce qui
   sort par le VPN —, sauf `vpn_addresses: true` (décision explicite).
   Une valeur n'est JAMAIS réaffichée brute (elle pourrait porter un saut de
   ligne et une directive) : en commentaire, seulement ses caractères d'adresse ;
   une valeur à plusieurs lignes ou à espaces est ignorée.
   Le marqueur `# named-access` est lu par scripts/webapp_hardening_check.py
   (`vhost`) : allow étroits, aucune adresse interdite, `deny all` en dernier. #}
{% set _na_vpn_addresses = groups['vpns'] | default([]) | map('extract', hostvars, 'ansible_host') | list %}
{% set _na_allow_vpn = named_access.vpn_addresses | default(false) | bool %}
{% set _na_v6_min = named_access.v6_min_prefix | default(128) | int %}
{% set _na_ipv4 = '^(0|[1-9][0-9]{0,2})([.](0|[1-9][0-9]{0,2})){3}(?!(?s:.))' %}
        # named-access
{% if (hostvars[access_entry].cloudflare_named | default(false) | bool) and not (hostvars[access_entry].cloudflare_front | default(false) | bool) %}
        # Nom servi par Cloudflare : socket Cloudflare sans certificat client valide refusée avant tout filtre d'adresse
        # (voir `_access.inc`), et jamais de mise en cache par l'edge.
        add_header Cloudflare-CDN-Cache-Control "no-store" always;
        if (${{ cf_untrusted_var }}) {
            return 403;
        }
{% endif %}
        # 1. Serveurs nommés
{% for h in named_access.hosts | default([]) %}
{% set _na_name = h | string | regex_replace('[^A-Za-z0-9_.-]', '?') %}
{% set _na_addr = (hostvars[h].ansible_host | default('') | string) if h in hostvars else '' %}
{% if _na_addr is match(_na_ipv4) and _na_addr == (_na_addr | trim) and (_na_addr.splitlines() | length) == 1 and (_na_allow_vpn or _na_addr not in _na_vpn_addresses) %}
        allow {{ _na_addr }};  # serveur nommé {{ _na_name }}
{% else %}
        # serveur nommé {{ _na_name }} ignoré (absent, adresse non IPv4, ou adresse d'un serveur VPN)
{% endif %}
{% endfor %}
        # 2. Whitelist du parc : {{ 'ADMISE (filtrée)' if (named_access.whitelist | default(false) | bool) else 'non admise' }}{{ ' — adresses VPN ADMISES (vpn_addresses)' if _na_allow_vpn else '' }}
{% if named_access.whitelist | default(false) | bool %}
{% for ip in whitelist | default([]) %}
{% set _ip = ip | string %}
{% set _shown = _ip | regex_replace('[^0-9A-Fa-f.:/]', '?') %}
{% set _clean = _ip == (_ip | trim) and (_ip.splitlines() | length) == 1 and ' ' not in _ip %}
{% set _v4 = _clean and _ip is match('^(0|[1-9][0-9]{0,2})([.](0|[1-9][0-9]{0,2})){3}(/32)?(?!(?s:.))') %}
{% set _v6 = _clean and _ip is match('^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(/[0-9]{1,3})?(?!(?s:.))')
             and ((_ip.split('/')[1] | int) if '/' in _ip else 128) >= _na_v6_min
             and ((_ip.split('/')[1] | int) if '/' in _ip else 128) <= 128 %}
{% set _is_vpn = _ip.split('/')[0] in _na_vpn_addresses %}
{% if (_v4 or _v6) and (_na_allow_vpn or not _is_vpn) %}
        allow {{ _ip }};  # whitelist
{% elif _is_vpn %}
        # whitelist {{ _shown }} ignorée (adresse d'un serveur VPN)
{% else %}
        # whitelist {{ _shown }} ignorée (forme invalide ou plage plus large qu'autorisé)
{% endif %}
{% endfor %}
{% endif %}
        # 3. Rien d'autre.
        deny all;
