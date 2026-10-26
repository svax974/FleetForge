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
révoque. `id_openclaw.pub` y est déposée par `openclaw-install`,
`id_fleetforge_ro.pub` par `fleetforge-install` (`ff_ro_diagnostics`, pour
`ssh_diagnose`) et retirée par `fleetforge-remove`.

Sous-dossier `keys/<parc_name>/control/*.pub` : clés d'une MACHINE qui pilote le
parc (FleetForge), posées sur l'utilisateur de service uniquement — jamais sur
root. Le fichier contient la ligne `authorized_keys` COMPLÈTE avec ses options
(`from="<adresse>",no-agent-forwarding,…`). `security-ssh` l'ajoute à la liste
exclusive : sans lui, `setup-server.yml` retirerait la clé. Déposé par
`fleetforge-install` (`ff_deploy_secrets`), retiré par `fleetforge-remove` ; la
révocation atteint les machines au passage suivant de `setup-server.yml`.

Origine restreinte : une clé nommée dans `readonly_key_from`
(`readonly-user-install/defaults`) reçoit `from="<adresses>"` — celle de
FleetForge, les adresses des machines `infras`. Sans adresse IP résolue, elle
n'est pas posée du tout.

Le contenu de ce dossier est gitignoré : il décrit qui accède au parc.
