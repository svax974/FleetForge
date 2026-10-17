# `Ansible/parcs/` — fichiers propres à chaque parc

Les rôles de ce dépôt sont **génériques**. Ce qui décrit un parc réel — vhosts
nginx, fichiers de configuration d'une application, certificats — vit ici, un
répertoire par parc, nommé d'après `parc_name` (déclaré dans
`playbooks/group_vars/<parc>.yml`, sans défaut).

Tout ce répertoire est **gitignoré** dans le dépôt public, sauf ce README : son
contenu se versionne dans le dépôt PRIVÉ du parc.

```
parcs/<parc_name>/
  nginx/                     # rôle proxy-update (deploy-proxy.yml, update-proxy.yml)
    nginx.conf               # optionnel — configuration globale
    sites-enabled/*.conf     # vhosts actifs   (gabarits Jinja)
    sites-available/*.conf   # vhosts inactifs (gabarits Jinja)
    streams-enabled/*.conf   # streams TCP/UDP
    streams-available/*.conf
    certs/*                  # 🔒 ansible-vault encrypt — copiés dans /etc/nginx/certs/
    auth/*                   # 🔒 ansible-vault encrypt — htpasswd, /etc/nginx/auth/
  scripting/                 # rôle scripting-install (fichiers chiffrés)
```

- Un fichier préfixé `_` est un **partiel**, inclus par un autre gabarit et
  jamais déployé seul. Les partiels génériques (`_access.inc`,
  `_sync-vhost.inc`) restent dans `playbooks/roles/proxy-update/templates/` et
  s'incluent tels quels : `{% include '_access.inc' %}`.
- Le répertoire **fait foi** : `proxy-update` vide puis reconstruit
  `/etc/nginx/{sites,streams}-{enabled,available}`. Un vhost retiré d'ici est
  retiré des proxies au passage suivant.
- Un fichier sensible est chiffré **en entier** :
  `ansible-vault encrypt parcs/<parc>/nginx/certs/<clé>.key` — `copy` et
  `template` le déchiffrent à la volée (mot de passe : `ansible.cfg`).
- Avant de pousser : `./play.sh <parc> update-proxy.yml --check --diff`.
