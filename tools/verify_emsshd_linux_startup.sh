#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <emsshd-binary>" >&2
    exit 2
fi

BIN="$1"
PORT="${EMSSHD_VERIFY_PORT:-2222}"
RUNNER="${EMSSHD_RUNNER:-}"
TMP_DIR="${TMPDIR:-/tmp}/emsshd-linux-startup-$$"
LOG_FILE="${TMP_DIR}/emsshd.log"

mkdir -p "${TMP_DIR}"

cmd=()
if [ -n "${RUNNER}" ]; then
    cmd+=("${RUNNER}")
fi
cmd+=("${BIN}" --port "${PORT}" --permit-root-login yes --password-authentication yes)

"${cmd[@]}" >"${LOG_FILE}" 2>&1 &
pid="$!"

cleanup() {
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

deadline=$((SECONDS + 10))
while [ "${SECONDS}" -lt "${deadline}" ]; do
    if grep -q 'server template init failed' "${LOG_FILE}"; then
        cat "${LOG_FILE}" >&2
        echo "emsshd startup failed before listen" >&2
        exit 1
    fi
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
        cat "${LOG_FILE}" >&2
        echo "emsshd exited before listen" >&2
        exit 1
    fi
    if grep -q 'linux posix+stdio server listening' "${LOG_FILE}"; then
        python3 - "${PORT}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
    data = sock.recv(128)
if not data.startswith(b"SSH-"):
    raise SystemExit("missing SSH banner")
print(data.decode("utf-8", errors="ignore").strip())
PY
        cat "${LOG_FILE}"
        exit 0
    fi
    sleep 0.1
done

cat "${LOG_FILE}" >&2
echo "timed out waiting for emsshd listen" >&2
exit 1
