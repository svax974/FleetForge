# `Ansible/parcs/` — fichiers propres à chaque parc

Les rôles de ce dépôt sont **génériques**. Ce qui décrit un parc réel — vhosts
nginx, fichiers de configuration d'une application, certificats — vit ici, un
répertoire par parc, nommé d'après `parc_name` (déclaré dans
`playbooks/group_vars/<parc>.yml`, sans défaut).

Tout ce répertoire est **gitignoré** dans le dépôt public, sauf ce README : son
contenu se versionne dans le dépôt PRIVÉ du parc, `svax974/fleetforge-parcs`.

## Montage du dépôt privé

```
cd Ansible
git clone https://github.com/svax974/fleetforge-parcs.git .private   # .private/ est ignoré ici
./link-private.sh                                                    # liens symboliques, idempotent
```

`.private/` reproduit l'arborescence d'`Ansible/`. `link-private.sh` y relie `parcs/<parc>/` et `keys/<parc>/`
(répertoires entiers), `inventories/*.yml`, `playbooks/group_vars/*.yml`, `playbooks/host_vars/*.yml` (fichier par
fichier : ces répertoires gardent ici leurs `*.template` publics) et, depuis `repo-root/`, les fichiers non publiés de
la racine du dépôt (`CLAUDE.md`, `CLAUDE.local.md`, `crates/fleetforge-core/tests/real_inventories.rs`). Il relie aussi les fichiers
sensibles que des rôles publics attendent à leur propre chemin (`.private/playbooks/roles/…`, chiffrés en entier par
ansible-vault : clés FreeLLM, dump Pritunl). Les écritures traversent
les liens (`blockinfile` d'Ansible résout le chemin réel, FleetForge écrit par `std::fs::write`) : un fichier modifié
ici l'est dans `.private/`, à commiter dans le dépôt privé. Un fichier de parc créé ensuite côté public (nouvel
inventaire, nouveau parc) : `./link-private.sh --adopt`. Le script refuse d'écraser un fichier qui diffère de sa
copie privée.

Le dépôt privé porte aussi les `.env` de production des applications du parc, chiffrés en entier par ansible-vault
(`apps/<app>/{back,front}.env.vault`, liste dans `apps/apps.yml`) : `./app-env.sh status | save <app> | restore
<app>`. Les rôles `<app>-deploy` (llm-proxy, agenthub) les restaurent avant de lancer le déploiement de l'app.

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
