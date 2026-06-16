#!/usr/bin/env bash
set -euo pipefail

uninstall=false
for arg in "$@"; do
  case "$arg" in
    --uninstall|-Uninstall) uninstall=true ;;
  esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$script_dir/install-manifest.txt"

ask_yes_no() {
  local prompt=$1 answer
  while true; do
    printf '%s [yes/no] ' "$prompt"
    read -r answer || answer=no
    case "$answer" in
      yes|no) printf '%s\n' "$answer"; return 0 ;;
    esac
  done
}

if [ "$uninstall" = true ]; then
  selected=""
  if [ -f "$manifest" ]; then
    while IFS='|' read -r type path action; do
      [ -n "${type:-}" ] || continue
      if [ "$action" = "delete" ] && [ -e "$path" ]; then
        if [ "$(ask_yes_no "Delete $type: $path?")" = "yes" ]; then
          selected=${selected}${path}$'\n'
        fi
      fi
    done < "$manifest"
  fi

  if [ -n "$selected" ]; then
    printf 'Items selected for removal:\n%s' "$selected"
    if [ "$(ask_yes_no 'Proceed with selected removals?')" = "yes" ]; then
      while IFS= read -r path; do
        [ -n "$path" ] && rm -rf -- "$path"
      done <<EOF_SELECTED
$selected
EOF_SELECTED
    fi
  fi
  exit 0
fi

: > "$manifest"
printf 'emtask package is ready at: %s\n' "$script_dir"
printf 'No system service is installed by default. Configure emtask.conf.example and run ./emtask manually or integrate it with your service manager.\n'
printf 'Install manifest written: %s\n' "$manifest"
