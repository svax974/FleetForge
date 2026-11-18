#!/usr/bin/env bash
# Hôtes d'inventaire marqués `disabled: true` — à IGNORER au déploiement.
#
#   scripts/disabled-hosts.sh <inventaire.yml> [<inventaire.yml>…]
#
# Affiche sur la sortie standard les noms d'hôtes désactivés, séparés par une
# espace (rien si aucun), pour que `play.sh` et le lanceur de l'application les
# retirent du déploiement par un `--limit` (voir CLAUDE.md, « Parc et play.sh »).
# Le drapeau vit sur l'hôte, quel que soit le groupe ou la liste qui le cible :
# c'est le seul moyen de l'appliquer sans toucher chaque play.
#
# `ansible-inventory --list` est lu ici et n'est JAMAIS affiché : ses valeurs de
# coffre y figurent chiffrées, et une erreur d'analyse ne doit rien laisser fuir.
# Le répertoire courant devient `Ansible/` (ansible.cfg, donc le mot de passe du
# coffre, ne sont lus que depuis là).
set -euo pipefail

cd "$(dirname "$0")/.."

args=()
for f in "$@"; do
  [ -f "$f" ] || { echo "disabled-hosts.sh: inventaire introuvable : $f" >&2; exit 2; }
  args+=(-i "$f")
done
[ ${#args[@]} -gt 0 ] || { echo "disabled-hosts.sh: aucun inventaire" >&2; exit 2; }

ansible-inventory "${args[@]}" --list 2>/dev/null | python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

hostvars = data.get("_meta", {}).get("hostvars", {})
truthy = (True, "true", "yes", "on", "1")
disabled = sorted(
    host for host, variables in hostvars.items()
    if (variables.get("disabled") is True
        or (isinstance(variables.get("disabled"), str) and variables["disabled"].lower() in truthy[1:]))
)
print(" ".join(disabled))
'
