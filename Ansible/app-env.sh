#!/usr/bin/env bash
# Production env files of the applications deployed on the parc, kept encrypted (ansible-vault) in the private parc
# repository mounted at .private/ (see parcs/README.md):  .private/apps/<app>/{back,front}.env.vault
#
#   ./app-env.sh status  [app]   # identical | differs | vault only | local only — never prints a value
#   ./app-env.sh save    <app>   # app checkout -> vault (re-encrypted only when the content changed)
#   ./app-env.sh restore <app>   # vault -> app checkout (mode 0600, a differing local file is kept as .env.bak-<date>)
#
# `--env=<name>` (any position, e.g. `--env=preprod`) selects the files of another environment: `<stack>/.env.<name>` in the checkout
# and `.private/apps/<app>/<stack>.env.<name>.vault`. Without it: production (`<stack>/.env`, `<stack>.env.vault`), unchanged.
#
# Apps and their checkout paths: .private/apps/apps.yml. Vault password: ansible.cfg (vault_password_file), which is
# why this script runs ansible-vault from its own directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

APPS_FILE=.private/apps/apps.yml
STACKS=(back front)

die() { echo "✖ $*" >&2; exit 1; }
[[ -f "${APPS_FILE}" ]] || die "${APPS_FILE} not found — clone the private parc repository into .private/ (parcs/README.md)."

app_path() {
  local path
  path=$(awk -v app="$1" -F': *' '$1 == app { print $2 }' "${APPS_FILE}")
  [[ -n "${path}" ]] || die "unknown app '$1' (${APPS_FILE})"
  printf '%s' "${path}"
}

list_apps() { awk -F': *' '/^[a-z0-9_-]+:/ { print $1 }' "${APPS_FILE}"; }

# Status of one stack: compares decrypted content in memory, never on disk.
stack_status() {
  local vault="$1" local_file="$2"
  if [[ -f "${vault}" && -f "${local_file}" ]]; then
    if cmp -s <(ansible-vault view "${vault}") "${local_file}"; then echo identical; else echo differs; fi
  elif [[ -f "${vault}" ]]; then echo "vault only"
  elif [[ -f "${local_file}" ]]; then echo "local only"
  else echo absent
  fi
}

cmd_status() {
  local app src apps=("$@")
  if [[ ${#apps[@]} -eq 0 ]]; then
    while IFS= read -r app; do apps+=("${app}"); done < <(list_apps)
  fi
  for app in "${apps[@]}"; do
    src=$(app_path "${app}")
    for stack in "${STACKS[@]}"; do
      printf '%-22s %-6s %s\n' "${app}" "${stack}" "$(stack_status ".private/apps/${app}/${stack}.env${ENV_SUFFIX}.vault" "${src}/${stack}/.env${ENV_SUFFIX}")"
    done
  done
}

cmd_save() {
  local app="${1:?usage: app-env.sh save <app>}" src vault local_file
  src=$(app_path "${app}")
  mkdir -p ".private/apps/${app}"
  for stack in "${STACKS[@]}"; do
    vault=".private/apps/${app}/${stack}.env${ENV_SUFFIX}.vault"; local_file="${src}/${stack}/.env${ENV_SUFFIX}"
    [[ -f "${local_file}" ]] || { echo "${app} ${stack}: no local .env, skipped"; continue; }
    if [[ "$(stack_status "${vault}" "${local_file}")" == identical ]]; then
      echo "${app} ${stack}: unchanged"
      continue
    fi
    ansible-vault encrypt --output "${vault}" "${local_file}" >/dev/null
    echo "${app} ${stack}: saved to ${vault}"
  done
}

cmd_restore() {
  local app="${1:?usage: app-env.sh restore <app>}" src vault local_file
  src=$(app_path "${app}")
  for stack in "${STACKS[@]}"; do
    vault=".private/apps/${app}/${stack}.env${ENV_SUFFIX}.vault"; local_file="${src}/${stack}/.env${ENV_SUFFIX}"
    [[ -f "${vault}" ]] || { echo "${app} ${stack}: no vault copy, skipped"; continue; }
    case "$(stack_status "${vault}" "${local_file}")" in
      identical) echo "${app} ${stack}: unchanged"; continue ;;
      differs) cp -p "${local_file}" "${local_file}.bak-$(date +%Y%m%d-%H%M%S)"; echo "${app} ${stack}: local copy kept as .env${ENV_SUFFIX}.bak-*" ;;
    esac
    ( umask 077; ansible-vault decrypt --output "${local_file}" "${vault}" >/dev/null )
    chmod 600 "${local_file}"
    echo "${app} ${stack}: restored from ${vault}"
  done
}

# `--env=<name>` is taken out of the arguments wherever it stands.
ENV_SUFFIX=""
ARGS=()
for arg in "$@"; do
  case "${arg}" in
    --env=*)
      env_name="${arg#--env=}"
      [[ "${env_name}" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || die "invalid environment name '${env_name}'"
      [[ "${env_name}" == prod ]] || ENV_SUFFIX=".${env_name}" ;;
    *) ARGS+=("${arg}") ;;
  esac
done
set -- ${ARGS[@]+"${ARGS[@]}"}

case "${1:-}" in
  status) shift; cmd_status "$@" ;;
  save) shift; cmd_save "$@" ;;
  restore) shift; cmd_restore "$@" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
