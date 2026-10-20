# Clés SSH autorisées, par parc

`keys/<parc_name>/*.pub` — une clé publique par fichier — est la liste
EXCLUSIVE des clés posées sur `root` et sur l'utilisateur de service
(`remote_username`) de chaque machine du parc, par
`security-ssh/tasks/authorized_keys.yml` (`exclusive: true`) au prochain
`setup-server.yml`.

- `parc_name` est déclaré dans `playbooks/group_vars/<parc>.yml`.
- Ajouter un accès : déposer le `.pub`. Révoquer : supprimer le fichier.
- La clé de CONTRÔLE du parc (celle qu'utilise Ansible, `ssh_key`) doit y
  rester, sinon Ansible se coupe lui-même l'accès.
- Un dossier vide est refusé (assert) plutôt que de vider les comptes.

Sous-dossier `keys/<parc_name>/readonly/*.pub` : clés du compte en LECTURE
SEULE `openclaw-ro` (`readonly-user-install`, joué par `setup-server.yml` et
`deploy-readonly-user.yml`), jamais posées sur root ni srvc — `security-ssh`
ne lit pas les sous-dossiers. Chaque clé n'y lance que la passerelle `ro-gate`
(commande forcée, sorties caviardées). Même règle : le dossier fait foi, vidé il
révoque. `id_openclaw.pub` y est déposée par `openclaw-install`.

Le contenu de ce dossier est gitignoré : il décrit qui accède au parc.
