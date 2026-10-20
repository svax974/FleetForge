#!/usr/bin/env bash
# Mounts the PRIVATE parc repository (cloned into .private/, see parcs/README.md) into this public tree: every file
# that describes a real parc lives there and is reached here through a symbolic link.
#
#   ./link-private.sh            # create / check the links (idempotent)
#   ./link-private.sh --adopt    # also move into .private/ the parc files created here since (new inventory,
#                                # group_vars, host_vars, parc directory), then link them — commit .private/ after
#
# Linked: parcs/<parc>/ and keys/<parc>/ (whole directories), inventories/*.yml, playbooks/group_vars/*.yml,
# playbooks/host_vars/*.yml (file by file: these directories also hold the public *.template files), and every file of
# .private/repo-root/ at the same path from the repository root (CLAUDE.md, CLAUDE.local.md, tests against the real
# inventories).
# Writers follow the links (Ansible blockinfile resolves the real path, FleetForge writes with std::fs::write), so a
# file edited through a link is edited in .private/.
#
# A regular file in place of a link is replaced only when it is IDENTICAL to the private copy; otherwise the script
# stops and lists it, so nothing is ever overwritten silently.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PRIVATE=.private
ADOPT=0
[[ "${1:-}" == "--adopt" ]] && ADOPT=1
[[ -d "${PRIVATE}/.git" ]] || { echo "✖ ${PRIVATE}/ is not a clone of the private parc repository (parcs/README.md)." >&2; exit 1; }

conflicts=()
changed=0

# relative_target <link path> <target path>: target expressed relative to the link's directory.
relative_target() { python3 -c 'import os,sys; print(os.path.relpath(sys.argv[2], os.path.dirname(sys.argv[1])))' "$1" "$2"; }

same_content() { if [[ -d "$1" ]]; then diff -rq "$1" "$2" >/dev/null 2>&1; else cmp -s "$1" "$2"; fi; }

# link_one <path in this tree> <path in .private>
link_one() {
  local here="$1" private="$2" target
  target=$(relative_target "${here}" "${private}")
  if [[ -L "${here}" ]]; then
    [[ "$(readlink "${here}")" == "${target}" ]] && return 0
    rm "${here}"
  elif [[ -e "${here}" ]]; then
    if ! same_content "${here}" "${private}"; then conflicts+=("${here}"); return 0; fi
    rm -rf "${here}"
  fi
  mkdir -p "$(dirname "${here}")"
  ln -s "${target}" "${here}"
  echo "linked ${here} -> ${target}"
  changed=$((changed + 1))
}

# adopt_one <path in this tree> <path in .private>: a regular parc file/dir created here and absent from .private.
adopt_one() {
  local here="$1" private="$2"
  [[ -e "${here}" && ! -L "${here}" && ! -e "${private}" ]] || return 0
  mkdir -p "$(dirname "${private}")"
  mv "${here}" "${private}"
  echo "adopted ${here} into ${private}"
}

if [[ "${ADOPT}" -eq 1 ]]; then
  for f in inventories/*.yml playbooks/group_vars/*.yml playbooks/host_vars/*.yml; do
    [[ -e "${f}" ]] && adopt_one "${f}" "${PRIVATE}/${f}"
  done
  for d in parcs/*/ keys/*/; do
    d="${d%/}"
    [[ -d "${d}" ]] && adopt_one "${d}" "${PRIVATE}/${d}"
  done
fi

shopt -s nullglob
for d in "${PRIVATE}"/parcs/*/ "${PRIVATE}"/keys/*/; do
  d="${d%/}"; link_one "${d#"${PRIVATE}"/}" "${d}"
done
for f in "${PRIVATE}"/inventories/*.yml "${PRIVATE}"/playbooks/group_vars/*.yml "${PRIVATE}"/playbooks/host_vars/*.yml; do
  link_one "${f#"${PRIVATE}"/}" "${f}"
done
while IFS= read -r f; do
  link_one "../${f#"${PRIVATE}/repo-root/"}" "${f}"
done < <(find "${PRIVATE}/repo-root" -type f 2>/dev/null)

if [[ ${#conflicts[@]} -gt 0 ]]; then
  echo "✖ left untouched, they differ from their private copy (compare, then fix one side and rerun):" >&2
  printf '  %s\n' "${conflicts[@]}" >&2
  exit 1
fi
echo "==> private parc files linked (${changed} change(s))"
