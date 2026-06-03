#!/usr/bin/env bash

set -euo pipefail

OUTPUT=""
DIRECTORY="."
BUILD_DIR=""
CC_CMD=""
CXX_CMD=""
AS_CMD=""
CFLAGS_VALUE=""
CXXFLAGS_VALUE=""
ASFLAGS_VALUE=""
C_SOURCES=""
CPP_SOURCES=""
ASM_SOURCES=""
UNAME_S="$(uname -s 2>/dev/null || printf '')"

usage() {
    cat <<'EOF'
Usage:
  gen_compile_commands.sh --output FILE --build DIR --cc CC --cxx CXX --as AS [options]

Options:
  --output FILE
  --directory DIR
  --build DIR
  --cc CMD
  --cxx CMD
  --as CMD
  --cflags FLAGS
  --cxxflags FLAGS
  --asflags FLAGS
  --c-sources "a.c b.c"
  --cpp-sources "a.cpp b.cpp"
  --asm-sources "startup.S"
EOF
}

json_escape() {
    local value="${1-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

absolute_path() {
    local path="$1"
    if [[ "$path" = /* ]]; then
        printf '%s' "$path"
    else
        printf '%s/%s' "$ROOT_DIR" "$path"
    fi
}

normalize_host_path() {
    local path="$1"
    local drive_letter

    if [[ "$UNAME_S" == CYGWIN* && "$path" =~ ^/cygdrive/([a-zA-Z])/(.*)$ ]]; then
        drive_letter="${BASH_REMATCH[1]}"
        drive_letter="${drive_letter^^}"
        printf '%s:/%s' "$drive_letter" "${BASH_REMATCH[2]}"
    else
        printf '%s' "$path"
    fi
}

append_entry() {
    local compiler="$1"
    local flags="$2"
    local source="$3"
    local source_abs output_rel output_abs command

    [[ -n "$source" ]] || return 0

    source_abs="$(normalize_host_path "$(absolute_path "$source")")"
    output_rel="${BUILD_DIR}/${source}.o"
    output_abs="$(normalize_host_path "$(absolute_path "$output_rel")")"
    command="${compiler} -c ${flags} -o \"${output_rel}\" \"${source}\""

    if [[ "$ENTRY_COUNT" -gt 0 ]]; then
        printf ',\n' >> "$OUTPUT_PATH"
    fi

    printf '  {\n' >> "$OUTPUT_PATH"
    printf '    "directory": "%s",\n' "$(json_escape "$ROOT_DIR_NORMALIZED")" >> "$OUTPUT_PATH"
    printf '    "file": "%s",\n' "$(json_escape "$source_abs")" >> "$OUTPUT_PATH"
    printf '    "output": "%s",\n' "$(json_escape "$output_abs")" >> "$OUTPUT_PATH"
    printf '    "command": "%s"\n' "$(json_escape "$command")" >> "$OUTPUT_PATH"
    printf '  }' >> "$OUTPUT_PATH"

    ENTRY_COUNT=$((ENTRY_COUNT + 1))
}

append_group() {
    local compiler="$1"
    local flags="$2"
    local sources="$3"
    local source

    for source in $sources; do
        append_entry "$compiler" "$flags" "$source"
    done
}

while (($# > 0)); do
    case "$1" in
        --output)
            shift
            OUTPUT="${1-}"
            ;;
        --directory)
            shift
            DIRECTORY="${1-}"
            ;;
        --build)
            shift
            BUILD_DIR="${1-}"
            ;;
        --cc)
            shift
            CC_CMD="${1-}"
            ;;
        --cxx)
            shift
            CXX_CMD="${1-}"
            ;;
        --as)
            shift
            AS_CMD="${1-}"
            ;;
        --cflags)
            shift
            CFLAGS_VALUE="${1-}"
            ;;
        --cxxflags)
            shift
            CXXFLAGS_VALUE="${1-}"
            ;;
        --asflags)
            shift
            ASFLAGS_VALUE="${1-}"
            ;;
        --c-sources)
            shift
            C_SOURCES="${1-}"
            ;;
        --cpp-sources)
            shift
            CPP_SOURCES="${1-}"
            ;;
        --asm-sources)
            shift
            ASM_SOURCES="${1-}"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unsupported option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

[[ -n "$OUTPUT" ]] || { echo "error: --output is required" >&2; exit 1; }
[[ -n "$BUILD_DIR" ]] || { echo "error: --build is required" >&2; exit 1; }
[[ -n "$CC_CMD" ]] || { echo "error: --cc is required" >&2; exit 1; }
[[ -n "$CXX_CMD" ]] || { echo "error: --cxx is required" >&2; exit 1; }
[[ -n "$AS_CMD" ]] || { echo "error: --as is required" >&2; exit 1; }

ROOT_DIR="$(cd "$DIRECTORY" && pwd)"
ROOT_DIR_NORMALIZED="$(normalize_host_path "$ROOT_DIR")"
if [[ "$OUTPUT" = /* ]]; then
    OUTPUT_PATH="$OUTPUT"
else
    OUTPUT_PATH="${ROOT_DIR}/${OUTPUT}"
fi

ENTRY_COUNT=0

printf '[\n' > "$OUTPUT_PATH"
append_group "$CC_CMD" "$CFLAGS_VALUE" "$C_SOURCES"
append_group "$CXX_CMD" "$CXXFLAGS_VALUE" "$CPP_SOURCES"
append_group "$AS_CMD" "$ASFLAGS_VALUE" "$ASM_SOURCES"
if [[ "$ENTRY_COUNT" -gt 0 ]]; then
    printf '\n' >> "$OUTPUT_PATH"
fi
printf ']\n' >> "$OUTPUT_PATH"
