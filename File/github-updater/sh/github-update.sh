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
token="${GITHUB_TOKEN:-}"
include_prerelease="false"
force="false"

usage() {
  cat <<'EOF'
Usage: github-update.sh --repo owner/repo [options]

Options:
  --channel release|action     Update channel, default: release
  --mode list|download|install Mode, default: list
  --version VALUE              Release tag/name or Actions run id/run number/SHA prefix/title
  --name-pattern PATTERN       Asset/artifact wildcard, default: *
  --workflow VALUE             Workflow file/name/id for Actions
  --branch VALUE               Branch filter for Actions
  --output-dir DIR             Download directory, default: .
  --install-dir DIR            Install/extract directory for install mode
  --token TOKEN                GitHub token, default: GITHUB_TOKEN; Actions can also use gh auth
  --include-prerelease         Include prerelease releases
  --force                      Allow install into non-empty directory
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo|-r) repo=${2:?}; shift 2 ;;
    --channel) channel=${2:?}; shift 2 ;;
    --mode) mode=${2:?}; shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --name-pattern) name_pattern=${2:?}; shift 2 ;;
    --workflow) workflow=${2:?}; shift 2 ;;
    --branch) branch=${2:?}; shift 2 ;;
    --output-dir) output_dir=${2:?}; shift 2 ;;
    --install-dir) install_dir=${2:?}; shift 2 ;;
    --token) token=${2:?}; shift 2 ;;
    --include-prerelease) include_prerelease="true"; shift ;;
    --force) force="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$repo" ]; then
  echo "--repo is required" >&2
  usage >&2
  exit 2
fi
case "$channel" in release|action) ;; *) echo "Invalid --channel: $channel" >&2; exit 2 ;; esac
case "$mode" in list|download|install) ;; *) echo "Invalid --mode: $mode" >&2; exit 2 ;; esac

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 2
  fi
}
need_cmd gh
need_cmd tar

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

if [ "$channel" = "action" ] && [ -z "$token" ]; then
  token=$(gh auth token 2>/dev/null || true)
fi

repo_path=$(resolve_repo "$repo")
mkdir -p "$output_dir"

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

extract_archive() {
  local archive=$1
  local dest=$2
  if [ -z "$dest" ]; then
    echo "--install-dir is required for install mode" >&2
    exit 2
  fi
  mkdir -p "$dest"
  if [ "$force" != "true" ] && [ -n "$(find "$dest" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1)" ]; then
    echo "Install dir is not empty: $dest. Use --force." >&2
    exit 2
  fi

  local tmp
  tmp=$(mktemp -d)
  case "$archive" in
    *.zip)
      need_cmd unzip
      unzip -q "$archive" -d "$tmp"
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$archive" -C "$tmp"
      ;;
    *)
      cp -f "$archive" "$dest/"
      rm -rf "$tmp"
      return
      ;;
  esac

  local src="$tmp"
  local first count
  first=$(find "$tmp" -mindepth 1 -maxdepth 1 | head -n 1 || true)
  count=$(find "$tmp" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
  if [ "$count" = "1" ] && [ -d "$first" ]; then
    src="$first"
  fi
  cp -a "$src"/. "$dest"/
  rm -rf "$tmp"
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
  local line id run_number name display_title head_branch head_sha
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

  matched="false"
  while IFS= read -r asset_name; do
    if match_name "$asset_name"; then
      matched="true"
      target="$output_dir/$asset_name"
      echo "Downloading release asset: $asset_name"
      rm -f "$target"
      if [ -n "$token" ]; then
        GH_TOKEN="$token" gh release download "$release_tag" --repo "$repo_path" --pattern "$asset_name" --dir "$output_dir"
      else
        gh release download "$release_tag" --repo "$repo_path" --pattern "$asset_name" --dir "$output_dir"
      fi
      echo "Saved: $target"
      [ "$mode" = "install" ] && extract_archive "$target" "$install_dir"
    fi
  done < <(list_release_assets "$release_id")
  if [ "$matched" != "true" ]; then
    echo "No release asset matched pattern: $name_pattern" >&2
    exit 1
  fi
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

matched="false"
while IFS=$'\t' read -r artifact_id artifact_name artifact_size; do
  if match_name "$artifact_name"; then
    matched="true"
    target="$output_dir/$artifact_name.artifact.zip"
    echo "Downloading action artifact: $artifact_name ($artifact_size bytes)"
    gh_api "/repos/$repo_path/actions/artifacts/$artifact_id/zip" > "$target"
    echo "Saved: $target"
    [ "$mode" = "install" ] && extract_archive "$target" "$install_dir"
  fi
done < <(list_action_artifacts "$run_id")
if [ "$matched" != "true" ]; then
  echo "No action artifact matched pattern: $name_pattern" >&2
  exit 1
fi
