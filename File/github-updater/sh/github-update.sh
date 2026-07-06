#!/usr/bin/env bash
set -euo pipefail

repo=""
channel="release"
mode="list"
version=""
name_pattern="*"
workflow=""
branch=""
output_dir="."
install_dir=""
package_name=""
package_path=""
token="${GITHUB_TOKEN:-}"
include_prerelease="false"
force="false"
repo_explicit="false"
channel_explicit="false"
name_pattern_explicit="false"
output_dir_explicit="false"
script_path=${BASH_SOURCE[0]:-$0}
script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd)

usage() {
  cat <<'EOF'
Usage: github-update.sh --repo owner/repo [options]
       github-update.sh --mode uninstall [--install-dir DIR] [--package-name NAME]
  github-update.sh --uninstall [--install-dir DIR] [--package-name NAME]

Options:
  --channel release|action       Update channel, default: release
  --mode list|download|install|uninstall
                                 Mode, default: list
  --uninstall                    Alias for --mode uninstall
  --version VALUE                Release tag/name or Actions run id/run number/SHA prefix/title
  --name-pattern PATTERN         Asset/artifact wildcard, default: *
  --workflow VALUE               Workflow file/name/id for Actions
  --branch VALUE                 Branch filter for Actions
  --output-dir DIR               Download directory, default: .
  --install-dir DIR              Install root, default for install/uninstall: current directory
  --package-name NAME            Installed xxx directory name, inferred during install
  --package-path FILE            Install an already downloaded release package or action artifact zip
  --token TOKEN                  GitHub token, default: GITHUB_TOKEN; Actions can also use gh auth
  --include-prerelease           Include prerelease releases
  --force                        Reserved for compatibility; install always supports overwrite
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo|-r) repo=${2:?}; repo_explicit="true"; shift 2 ;;
    --channel) channel=${2:?}; channel_explicit="true"; shift 2 ;;
    --mode) mode=${2:?}; shift 2 ;;
    --uninstall) mode="uninstall"; shift ;;
    --version) version=${2:?}; shift 2 ;;
    --name-pattern) name_pattern=${2:?}; name_pattern_explicit="true"; shift 2 ;;
    --workflow) workflow=${2:?}; shift 2 ;;
    --branch) branch=${2:?}; shift 2 ;;
    --output-dir) output_dir=${2:?}; output_dir_explicit="true"; shift 2 ;;
    --install-dir) install_dir=${2:?}; shift 2 ;;
    --package-name) package_name=${2:?}; shift 2 ;;
    --package-path) package_path=${2:?}; shift 2 ;;
    --token) token=${2:?}; shift 2 ;;
    --include-prerelease) include_prerelease="true"; shift ;;
    --force) force="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$channel" in release|action) ;; *) echo "Invalid --channel: $channel" >&2; exit 2 ;; esac
case "$mode" in list|download|install|uninstall) ;; *) echo "Invalid --mode: $mode" >&2; exit 2 ;; esac

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 2
  fi
}

need_archive_cmds() {
  need_cmd tar
}

resolve_repo() {
  local value=${1%.git}
  if [[ "$value" =~ ^https://github\.com/([^/]+)/([^/#?]+) ]]; then
    printf '%s/%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]%.git}"
  elif [[ "$value" =~ ^git@github\.com:([^/]+)/(.+) ]]; then
    printf '%s/%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]%.git}"
  elif [[ "$value" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]]; then
    printf '%s' "$value"
  else
    echo "Invalid GitHub repository address: $1" >&2
    exit 2
  fi
}

install_root() {
  local root=$install_dir
  if [ -z "$root" ]; then
    if [ "$(basename "$script_dir")" != "sh" ]; then
      root=$script_dir
    else
      root="."
    fi
  fi
  mkdir -p "$root"
  (cd "$root" && pwd)
}

gh_api() {
  if [ -n "$token" ]; then
    GH_TOKEN="$token" gh api "$@"
  else
    gh api "$@"
  fi
}

match_name() {
  local name=$1
  [[ "$name" == $name_pattern ]]
}

current_platform() {
  case "$(uname -s 2>/dev/null || echo unknown)" in
    CYGWIN*|MINGW*|MSYS*|Windows_NT) printf 'windows\n' ;;
    Darwin*) printf 'macos\n' ;;
    Linux*) printf 'linux\n' ;;
    *) printf 'linux\n' ;;
  esac
}

json_value() {
  local file=$1
  local key=$2
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg key "$key" '.[$key] // empty' "$file"
  else
    sed -nE 's/^[[:space:]]*"'"$key"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$file" | head -n 1
  fi
}

assert_info_compatible() {
  local info_file=$1
  local source_name=$2
  if [ ! -f "$info_file" ]; then
    return 0
  fi

  local package_type platform updater host_platform
  package_type=$(json_value "$info_file" package_type | tr '[:upper:]' '[:lower:]')
  platform=$(json_value "$info_file" platform | tr '[:upper:]' '[:lower:]')
  updater=$(json_value "$info_file" updater | tr '[:upper:]' '[:lower:]')
  host_platform=$(current_platform)

  if [ "$package_type" = "apk" ]; then
    echo "Package '$source_name' is an Android APK artifact; github-update.sh cannot install APK packages. Use an Android installer or choose a Linux/macOS package with --name-pattern." >&2
    exit 2
  fi
  if [ -n "$package_type" ] && [ "$package_type" != "archive" ]; then
    echo "Package '$source_name' has unsupported package_type '$package_type'." >&2
    exit 2
  fi
  if [ -n "$platform" ] && [ "$platform" != "any" ] && [ "$platform" != "$host_platform" ]; then
    echo "Package '$source_name' is for platform '$platform', but this host is '$host_platform'. Choose a matching package with --name-pattern." >&2
    exit 2
  fi
  if [ -n "$updater" ] && [ "$updater" != "sh" ]; then
    echo "Package '$source_name' expects updater '$updater', but this is github-update.sh. Choose a shell package with --name-pattern." >&2
    exit 2
  fi
}

is_install_candidate_name() {
  local name=$1
  local kind=$2
  local platform
  case "$name" in
    *.sha256|*android*|*Android*|*apk*|*APK*) return 1 ;;
  esac
  if [ "$kind" = "release" ]; then
    case "$name" in
      *.zip|*.tar.gz|*.tgz) ;;
      *) return 1 ;;
    esac
  fi
  platform=$(current_platform)
  case "$platform" in
    windows) [[ "$name" =~ [Ww]indows|[Ww]in ]] ;;
    linux) [[ "$name" =~ [Ll]inux ]] ;;
    macos) [[ "$name" =~ [Mm]acos|[Dd]arwin|[Oo][Ss][Xx] ]] ;;
    *) return 1 ;;
  esac
}

installed_identity_names() {
  local root
  root=$(install_root)
  if [ -n "$package_name" ]; then
    if [ -d "$root/$package_name" ]; then
      printf '%s\n' "$package_name"
      if [ -f "$root/$package_name/info.Dat" ]; then
        json_value "$root/$package_name/info.Dat" artifact
        json_value "$root/$package_name/info.Dat" package
        json_value "$root/$package_name/info.Dat" name
      fi
    fi
    return 0
  fi

  local count=0 selected=""
  while IFS= read -r dir; do
    if [ -f "$dir/install.sh" ] || [ -f "$dir/info.Dat" ]; then
      count=$((count + 1))
      selected=$dir
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d ! -name .git | sort)

  if [ "$count" -ne 1 ]; then
    return 0
  fi

  printf '%s\n' "$(basename "$selected")"
  if [ -f "$selected/info.Dat" ]; then
    json_value "$selected/info.Dat" artifact
    json_value "$selected/info.Dat" package
    json_value "$selected/info.Dat" name
  fi
}

installed_info_file() {
  local root
  root=$(install_root)
  if [ -n "$package_name" ]; then
    if [ -f "$root/$package_name/info.Dat" ]; then
      printf '%s\n' "$root/$package_name/info.Dat"
    fi
    return 0
  fi

  local count=0 selected=""
  while IFS= read -r dir; do
    if [ -f "$dir/info.Dat" ]; then
      count=$((count + 1))
      selected="$dir/info.Dat"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d ! -name .git | sort)
  if [ "$count" -eq 1 ]; then
    printf '%s\n' "$selected"
  fi
}

use_installed_updater_defaults() {
  local info_file repo_value channel_value pattern
  info_file=$(installed_info_file)
  if [ -z "$info_file" ]; then
    return 0
  fi

  if [ "$repo_explicit" != "true" ] && [ -z "$repo" ]; then
    repo_value=$(json_value "$info_file" repo)
    if [ -n "$repo_value" ]; then
      repo=$repo_value
    fi
  fi

  if [ "$channel_explicit" != "true" ]; then
    channel_value=$(json_value "$info_file" channel | tr '[:upper:]' '[:lower:]')
    if [ -z "$channel_value" ]; then
      channel_value=$(json_value "$info_file" default_channel | tr '[:upper:]' '[:lower:]')
    fi
    if [ "$channel_value" = "release" ] || [ "$channel_value" = "action" ]; then
      channel=$channel_value
    elif [ -n "$(json_value "$info_file" artifact)" ]; then
      channel="action"
    fi
  fi

  if [ "$name_pattern_explicit" != "true" ]; then
    pattern=$(json_value "$info_file" name_pattern)
    if [ -z "$pattern" ]; then
      pattern=$(json_value "$info_file" artifact)
    fi
    if [ -z "$pattern" ]; then
      pattern=$(json_value "$info_file" package)
    fi
    if [ -n "$pattern" ]; then
      name_pattern=$pattern
      name_pattern_explicit="true"
    fi
  fi
}

select_install_records() {
  local kind=$1
  local records=$2
  if [ "$mode" != "install" ] || [ "$name_pattern_explicit" = "true" ]; then
    printf '%s\n' "$records"
    return 0
  fi

  local identities identity_matches compatible_matches
  identities=$(installed_identity_names | awk 'NF && !seen[$0]++')
  identity_matches=""
  if [ -n "$identities" ]; then
    while IFS= read -r record; do
      [ -z "$record" ] && continue
      local name
      name=$(printf '%s\n' "$record" | cut -f2)
      while IFS= read -r identity; do
        [ -z "$identity" ] && continue
        if [ "$name" = "$identity" ] || [[ "$name" == "$identity"* ]] || [[ "$identity" == "$name"* ]]; then
          identity_matches="${identity_matches}${record}"$'\n'
          break
        fi
      done <<<"$identities"
    done <<<"$records"
    if [ "$(printf '%s' "$identity_matches" | sed '/^$/d' | wc -l)" -eq 1 ]; then
      printf '%s' "$identity_matches" | sed '/^$/d'
      return 0
    fi
  fi

  compatible_matches=""
  while IFS= read -r record; do
    [ -z "$record" ] && continue
    local name
    name=$(printf '%s\n' "$record" | cut -f2)
    if is_install_candidate_name "$name" "$kind"; then
      compatible_matches="${compatible_matches}${record}"$'\n'
    fi
  done <<<"$records"

  local count names
  count=$(printf '%s' "$compatible_matches" | sed '/^$/d' | wc -l)
  if [ "$count" -eq 1 ]; then
    printf '%s' "$compatible_matches" | sed '/^$/d'
    return 0
  fi
  if [ "$count" -eq 0 ]; then
    names=$(printf '%s\n' "$records" | sed '/^$/d' | cut -f2 | paste -sd ', ' -)
    echo "Default --name-pattern '*' did not find an installable $kind package for $(current_platform). Available: $names. Use --name-pattern to select the exact package." >&2
    exit 1
  fi
  names=$(printf '%s' "$compatible_matches" | sed '/^$/d' | cut -f2 | paste -sd ', ' -)
  echo "Default --name-pattern '*' matched multiple installable $kind packages: $names. Use --name-pattern to select one package." >&2
  exit 1
}

extract_to_dir() {
  local archive=$1
  local dest=$2
  case "$archive" in
    *.zip)
      need_cmd unzip
      unzip -q "$archive" -d "$dest"
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$archive" -C "$dest"
      ;;
    *)
      echo "Unsupported package archive: $archive" >&2
      exit 2
      ;;
  esac
}

find_package_dir() {
  local root=$1
  local selected=""
  if [ -n "$package_name" ] && [ -d "$root/$package_name" ]; then
    printf '%s\n' "$root/$package_name"
    return 0
  fi
  while IFS= read -r dir; do
    if [ -f "$dir/install.sh" ] || [ -f "$dir/install.ps1" ]; then
      if [ -n "$selected" ]; then
        echo "Multiple package directories with install script found. Use --package-name." >&2
        exit 2
      fi
      selected=$dir
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d | sort)
  if [ -z "$selected" ]; then
    selected=$(find "$root" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1 || true)
  fi
  if [ -z "$selected" ]; then
    echo "No top-level package directory found in archive" >&2
    exit 2
  fi
  printf '%s\n' "$selected"
}

run_install_script() {
  local package_dir=$1
  local script="$package_dir/install.sh"
  if [ -f "$script" ]; then
    chmod +x "$script"
    "$script"
  else
    echo "No install.sh found in $(basename "$package_dir"); skipping project-specific install." >&2
  fi
}

run_uninstall_script() {
  local package_dir=$1
  local script="$package_dir/install.sh"
  if [ -f "$script" ]; then
    chmod +x "$script"
    "$script" --uninstall
  else
    echo "No install.sh found in $(basename "$package_dir"); skipping project-specific uninstall." >&2
  fi
}

verify_sha256() {
  local sha_file=$1
  local archive=$2
  if [ ! -f "$sha_file" ]; then
    return 0
  fi
  local sha_tool=""
  if command -v sha256sum >/dev/null 2>&1; then
    sha_tool="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    sha_tool="shasum -a 256"
  else
    echo "No sha256sum/shasum found for checksum verification" >&2
    exit 2
  fi

  local expected actual first second
  read -r first second < "$sha_file" || true
  if [ -n "${second:-}" ]; then
    (cd "$(dirname "$archive")" && $sha_tool -c "$sha_file")
  else
    expected=$first
    actual=$($sha_tool "$archive" | awk '{print $1}')
    if [ "$expected" != "$actual" ]; then
      echo "Checksum mismatch for $archive" >&2
      exit 1
    fi
  fi
}

write_updater_info() {
  local package_dir=$1
  local source_channel=$2
  local source_name_pattern=$3
  local repo_value=$4
  local info_file="$package_dir/info.Dat"
  local tmp_info
  if [ ! -f "$info_file" ]; then
    return 0
  fi

  tmp_info=$(mktemp)
  if command -v jq >/dev/null 2>&1; then
    jq \
      --arg repo "$repo_value" \
      --arg channel "$source_channel" \
      --arg name_pattern "$source_name_pattern" \
      '. + {repo: $repo, channel: $channel, name_pattern: $name_pattern}' \
      "$info_file" > "$tmp_info"
  else
    cp "$info_file" "$tmp_info"
  fi
  mv "$tmp_info" "$info_file"
}

install_archive_package() {
  local archive=$1
  local updater_root=$2
  local root=$3
  local source_channel=${4:-}
  local source_name_pattern=${5:-}
  local repo_value=${6:-}
  local tmp package_dir name
  tmp=$(mktemp -d)
  extract_to_dir "$archive" "$tmp"
  package_dir=$(find_package_dir "$tmp")
  assert_info_compatible "$package_dir/info.Dat" "$(basename "$archive")"
  if [ -f "$tmp/github-update.sh" ]; then
    cp -f "$tmp/github-update.sh" "$root/github-update.sh"
    chmod +x "$root/github-update.sh"
  elif [ -f "$updater_root/github-update.sh" ]; then
    cp -f "$updater_root/github-update.sh" "$root/github-update.sh"
    chmod +x "$root/github-update.sh"
  fi
  name=$(basename "$package_dir")
  rm -rf "$root/$name"
  cp -a "$package_dir" "$root/"
  write_updater_info "$root/$name" "$source_channel" "$source_name_pattern" "$repo_value"
  rm -rf "$tmp"
  run_install_script "$root/$name"
  echo "Installed: $root/$name"
}

prepare_action_package() {
  local artifact_zip=$1
  local root=$2
  local source_channel=${3:-}
  local source_name_pattern=${4:-}
  local repo_value=${5:-}
  local outer inner sha_file
  outer=$(mktemp -d)
  extract_to_dir "$artifact_zip" "$outer"
  assert_info_compatible "$outer/info.Dat" "$(basename "$artifact_zip")"
  inner=$(find "$outer" -maxdepth 1 -type f \( -name '*.zip' -o -name '*.tar.gz' -o -name '*.tgz' \) ! -name '*.artifact.zip' | sort | head -n 1 || true)
  if [ -z "$inner" ]; then
    apk=$(find "$outer" -maxdepth 1 -type f -name '*.apk' | sort | head -n 1 || true)
    if [ -n "$apk" ]; then
      echo "Action artifact '$artifact_zip' contains Android APK '$(basename "$apk")'; github-update.sh cannot install APK packages. Use an Android installer or choose a Linux/macOS package with --name-pattern." >&2
      exit 2
    fi
    echo "No inner package archive found in action artifact: $artifact_zip" >&2
    exit 2
  fi
  sha_file="$outer/$(basename "$inner").sha256"
  if [ ! -f "$sha_file" ]; then
    sha_file=$(find "$outer" -maxdepth 1 -type f -name '*.sha256' | sort | head -n 1 || true)
  fi
  if [ -n "$sha_file" ]; then
    verify_sha256 "$sha_file" "$inner"
  fi
  install_archive_package "$inner" "$outer" "$root" "$source_channel" "$source_name_pattern" "$repo_value"
  rm -rf "$outer"
}

uninstall_package() {
  local root package_dir name selected count
  root=$(install_root)
  if [ -n "$package_name" ]; then
    package_dir="$root/$package_name"
  else
    selected=""
    count=0
    while IFS= read -r dir; do
      count=$((count + 1))
      selected=$dir
    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/install.sh' \; -print | sort)
    if [ "$count" -ne 1 ]; then
      echo "Unable to infer installed package directory. Use --package-name." >&2
      exit 2
    fi
    package_dir=$selected
  fi
  if [ ! -d "$package_dir" ]; then
    echo "Installed package directory not found: $package_dir" >&2
    exit 1
  fi
  name=$(basename "$package_dir")
  run_uninstall_script "$package_dir"
  rm -rf "$package_dir"
  echo "Uninstalled: $name"
}

jq_release_filter() {
  if [ "$include_prerelease" = "true" ]; then
    printf '.[] | select(.draft|not)'
  else
    printf '.[] | select(.draft|not) | select(.prerelease|not)'
  fi
}

select_release_info() {
  local filter
  filter=$(jq_release_filter)
  if [ -n "$version" ]; then
    gh_api "/repos/$repo_path/releases?per_page=100" --jq "$filter | select(.tag_name == \"$version\" or .name == \"$version\") | [.id, .tag_name] | @tsv" | head -n 1
  else
    gh_api "/repos/$repo_path/releases?per_page=100" --jq "$filter | [.id, .tag_name] | @tsv" | head -n 1
  fi
}

list_releases() {
  local filter
  filter=$(jq_release_filter)
  gh_api "/repos/$repo_path/releases?per_page=100" --jq "$filter | [.tag_name, (.name // \"\"), (\"assets=\" + ((.assets | length) | tostring))] | @tsv"
}

list_release_assets() {
  local release_id=$1
  gh_api "/repos/$repo_path/releases/$release_id" --jq '.assets[] | .name'
}

runs_endpoint=()
build_runs_endpoint() {
  if [ -n "$workflow" ]; then
    runs_endpoint=("/repos/$repo_path/actions/workflows/$workflow/runs")
  else
    runs_endpoint=("/repos/$repo_path/actions/runs")
  fi
  runs_endpoint+=(--method GET -f per_page=100 -f status=success)
  if [ -n "$branch" ]; then
    runs_endpoint+=(-f "branch=$branch")
  fi
}

list_action_runs() {
  build_runs_endpoint
  gh_api "${runs_endpoint[@]}" --jq '.workflow_runs[] | [.id, ("#" + (.run_number | tostring)), (.name // ""), (.display_title // ""), (.head_branch // ""), ((.head_sha // "")[0:12])] | @tsv'
}

select_action_run_id() {
  local id run_number name display_title head_branch head_sha
  while IFS=$'\t' read -r id run_number name display_title head_branch head_sha; do
    run_number=${run_number#\#}
    if [ -z "$version" ] || [ "$id" = "$version" ] || [ "$run_number" = "$version" ] || [ "$name" = "$version" ] || [ "$display_title" = "$version" ] || [[ "$head_sha" == "$version"* ]]; then
      printf '%s\n' "$id"
      return 0
    fi
  done < <(list_action_runs)
  return 1
}

list_action_artifacts() {
  local run_id=$1
  gh_api "/repos/$repo_path/actions/runs/$run_id/artifacts?per_page=100" --jq '.artifacts[] | select(.expired|not) | [.id, .name, (.size_in_bytes | tostring)] | @tsv'
}

if [ "$mode" = "uninstall" ]; then
  uninstall_package
  exit 0
fi

use_installed_updater_defaults

if [ "$mode" = "install" ] && [ -n "$package_path" ]; then
  need_archive_cmds
  if [ ! -f "$package_path" ]; then
    echo "Package path not found: $package_path" >&2
    exit 1
  fi
  package_full=$(cd "$(dirname "$package_path")" && pwd)/$(basename "$package_path")
  source_name_pattern=$name_pattern
  if [ "$name_pattern_explicit" != "true" ] || [ "$source_name_pattern" = "*" ]; then
    source_name_pattern=$(basename "$package_full")
    if [ "$channel" = "action" ]; then
      source_name_pattern=${source_name_pattern%.zip}
    fi
  fi
  repo_value=""
  if [ -n "$repo" ]; then
    repo_value=$(resolve_repo "$repo")
  fi
  if [ "$channel" = "action" ]; then
    prepare_action_package "$package_full" "$(install_root)" "action" "$source_name_pattern" "$repo_value"
  else
    install_archive_package "$package_full" "$(dirname "$package_full")" "$(install_root)" "release" "$source_name_pattern" "$repo_value"
  fi
  exit 0
fi

if [ -z "$repo" ]; then
  echo "--repo is required unless --mode uninstall is used" >&2
  usage >&2
  exit 2
fi

need_cmd gh
need_archive_cmds

if [ "$channel" = "action" ] && [ -z "$token" ]; then
  token=$(gh auth token 2>/dev/null || true)
fi

repo_path=$(resolve_repo "$repo")
download_tmp=""
if [ "$mode" = "install" ] && [ "$output_dir_explicit" != "true" ]; then
  download_tmp=$(mktemp -d)
  output_dir=$download_tmp
fi
mkdir -p "$output_dir"
cleanup_download_tmp() {
  if [ -n "$download_tmp" ] && [ -d "$download_tmp" ]; then
    rm -rf "$download_tmp"
  fi
}
trap cleanup_download_tmp EXIT

if [ "$channel" = "release" ]; then
  if [ "$mode" = "list" ]; then
    list_releases
    exit 0
  fi

  release_info=$(select_release_info)
  if [ -z "$release_info" ]; then
    echo "No release version found" >&2
    exit 1
  fi
  IFS=$'\t' read -r release_id release_tag <<<"$release_info"

  records=""
  while IFS= read -r asset_name; do
    if match_name "$asset_name"; then
      records="${records}${release_id}"$'\t'"${asset_name}"$'\t'"${release_tag}"$'\n'
    fi
  done < <(list_release_assets "$release_id")
  if [ -z "$(printf '%s' "$records" | sed '/^$/d')" ]; then
    echo "No release asset matched pattern: $name_pattern" >&2
    exit 1
  fi
  records=$(select_install_records release "$records")
  while IFS=$'\t' read -r _release_id asset_name _release_tag; do
    [ -z "$asset_name" ] && continue
    target="$output_dir/$asset_name"
      echo "Downloading release asset: $asset_name"
      rm -f "$target"
      if [ -n "$token" ]; then
        GH_TOKEN="$token" gh release download "$release_tag" --repo "$repo_path" --pattern "$asset_name" --dir "$output_dir"
      else
        gh release download "$release_tag" --repo "$repo_path" --pattern "$asset_name" --dir "$output_dir"
      fi
      echo "Saved: $target"
      [ "$mode" = "install" ] && install_archive_package "$target" "$output_dir" "$(install_root)" "release" "$asset_name" "$repo_path"
  done <<<"$records"
  exit 0
fi

if [ -z "$token" ] && [ "$mode" != "list" ]; then
  echo "Warning: GitHub Actions artifact downloads usually require authentication. Run 'gh auth login' or pass --token." >&2
fi

if [ "$mode" = "list" ]; then
  list_action_runs
  exit 0
fi

run_id=$(select_action_run_id || true)
if [ -z "$run_id" ]; then
  echo "No action run found" >&2
  exit 1
fi

records=""
while IFS=$'\t' read -r artifact_id artifact_name artifact_size; do
  if match_name "$artifact_name"; then
    records="${records}${artifact_id}"$'\t'"${artifact_name}"$'\t'"${artifact_size}"$'\n'
  fi
done < <(list_action_artifacts "$run_id")
if [ -z "$(printf '%s' "$records" | sed '/^$/d')" ]; then
  echo "No action artifact matched pattern: $name_pattern" >&2
  exit 1
fi
records=$(select_install_records "action artifact" "$records")
while IFS=$'\t' read -r artifact_id artifact_name artifact_size; do
  [ -z "$artifact_name" ] && continue
  target="$output_dir/$artifact_name.zip"
    echo "Downloading action artifact: $artifact_name ($artifact_size bytes)"
    gh_api "/repos/$repo_path/actions/artifacts/$artifact_id/zip" > "$target"
    echo "Saved: $target"
    [ "$mode" = "install" ] && prepare_action_package "$target" "$(install_root)" "action" "$artifact_name" "$repo_path"
done <<<"$records"
