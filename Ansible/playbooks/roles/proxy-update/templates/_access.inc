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
                 réels), puis `deny all` ;
     • public  → aucun filtre d'adresse : l'authentification est celle du
                 service (signatures d'appareil, jeton…), et elle doit exister.
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
        {% endfor %}
        deny all;
{% elif _access_mode == 'public' %}
        # Mode public ({{ access_entry }}) : aucun filtre d'adresse.
{% else %}
        # access_mode « {{ _access_mode }} » inconnu sur {{ access_entry }} : fermé.
        deny all;
{% endif %}
