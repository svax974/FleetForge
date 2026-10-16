#!/usr/bin/env bash
# Lance un playbook sur un PARC — remplace playw3.sh et playpl.sh.
#
#   ./play.sh <parc> <playbook> [arguments ansible-playbook…]
#   ./play.sh --inventory <fichier> <playbook> [arguments…]
#   ./play.sh                                   # liste les parcs
#
#   ./play.sh web3c deploy-ollama.yml --tags monitoring
#   ./play.sh papanglabs deploy-brk.yml --check
#   ./play.sh --inventory inventories/web3c_inventory.yml deploy-proxy.yml
#
# Un parc est l'UNION des inventaires `inventories/<parc>_*.yml` (plus
# `inventories/<parc>.yml` s'il existe) : un `-i` par fichier, jamais une liste
# séparée par des virgules, qu'Ansible lirait comme une liste d'HÔTES.
# Chaque fichier d'un parc range ses hôtes sous `all.children.<parc>`, sans quoi
# `playbooks/group_vars/<parc>.yml` ne s'applique pas à eux.
#
# `--inventory` (répétable) contourne la résolution : un fichier précis, en cas
# de doute sur ce que le parc assemble.
#
# Le répertoire courant devient `Ansible/` : ansible.cfg (et donc le mot de
# passe du vault) n'est lu que depuis là.
set -euo pipefail

cd "$(dirname "$0")"

# Le projet s'appelait InfraManager : le mot de passe du vault (ansible.cfg),
# les clés Theta et la clé FreeLLM vivaient sous ~/.config/infra-manager.
# Repris une fois, et seulement si le nouveau répertoire n'existe pas encore.
# L'application fait de même au démarrage (fleetforge_core::paths).
if [ -d "$HOME/.config/infra-manager" ] && [ ! -e "$HOME/.config/fleetforge" ]; then
  mv "$HOME/.config/infra-manager" "$HOME/.config/fleetforge"
  echo "play.sh: ~/.config/infra-manager renommé en ~/.config/fleetforge" >&2
fi

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "Parcs disponibles :"
  for f in inventories/*.yml; do
    b=$(basename "$f" .yml)
    echo "  ${b%%_*}"
  done | sort -u
}

inventories=()
while [ $# -gt 0 ]; do
  case "$1" in
    --inventory|-i)
      [ $# -ge 2 ] || { echo "play.sh: $1 attend un fichier" >&2; exit 2; }
      [ -f "$2" ] || { echo "play.sh: inventaire introuvable : $2" >&2; exit 2; }
      inventories+=("$2"); shift 2 ;;
    --inventory=*)
      f="${1#--inventory=}"
      [ -f "$f" ] || { echo "play.sh: inventaire introuvable : $f" >&2; exit 2; }
      inventories+=("$f"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done

if [ ${#inventories[@]} -eq 0 ]; then
  [ $# -ge 1 ] || { usage; exit 2; }
  parc="$1"; shift
  for f in "inventories/${parc}.yml" inventories/"${parc}"_*.yml; do
    [ -f "$f" ] && inventories+=("$f")
  done
  if [ ${#inventories[@]} -eq 0 ]; then
    echo "play.sh: aucun inventaire pour le parc « $parc »" >&2
    usage >&2
    exit 2
  fi
fi

[ $# -ge 1 ] || { echo "play.sh: playbook manquant" >&2; usage >&2; exit 2; }
playbook="${1#playbooks/}"; shift
[ -f "playbooks/$playbook" ] || [ ! -f "playbooks/$playbook.yml" ] || playbook="$playbook.yml"
[ -f "playbooks/$playbook" ] || { echo "play.sh: playbook introuvable : playbooks/$playbook" >&2; exit 2; }

args=()
for f in "${inventories[@]}"; do args+=(-i "$f"); done
echo "play.sh: ${inventories[*]} → playbooks/$playbook" >&2

# macOS : sans cette variable, les forks d'Ansible meurent sur l'initialisation
# Objective-C (« objc[…]: +[__NSCFConstantString initialize] … »).
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
exec ansible-playbook "${args[@]}" "playbooks/$playbook" "$@"
