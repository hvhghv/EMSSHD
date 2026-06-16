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

mkdir -p "${TMP_DIR}"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

probe_banner() {
    local port="$1"
    python3 - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
    data = sock.recv(128)
if not data.startswith(b"SSH-"):
    raise SystemExit("missing SSH banner")
print(data.decode("utf-8", errors="ignore").strip())
PY
}

run_startup_probe() {
    local name="$1"
    local port="$2"
    shift 2
    local log_file="${TMP_DIR}/${name}.log"
    local cmd=()
    local pid
    local deadline

    if [ -n "${RUNNER}" ]; then
        cmd+=("${RUNNER}")
    fi
    cmd+=("${BIN}" "$@")

    "${cmd[@]}" >"${log_file}" 2>&1 &
    pid="$!"

    deadline=$((SECONDS + 10))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        if grep -q 'server template init failed\|crypto hostkey prepare failed' "${log_file}"; then
            cat "${log_file}" >&2
            echo "emsshd startup failed before listen (${name})" >&2
            kill "${pid}" >/dev/null 2>&1 || true
            wait "${pid}" 2>/dev/null || true
            exit 1
        fi
        if ! kill -0 "${pid}" >/dev/null 2>&1; then
            cat "${log_file}" >&2
            echo "emsshd exited before listen (${name})" >&2
            exit 1
        fi
        if grep -q 'linux posix+stdio server listening' "${log_file}"; then
            if ! probe_banner "${port}"; then
                cat "${log_file}" >&2
                echo "emsshd banner probe failed (${name})" >&2
                kill "${pid}" >/dev/null 2>&1 || true
                wait "${pid}" 2>/dev/null || true
                exit 1
            fi
            cat "${log_file}"
            kill "${pid}" >/dev/null 2>&1 || true
            wait "${pid}" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done

    cat "${log_file}" >&2
    echo "timed out waiting for emsshd listen (${name})" >&2
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
    exit 1
}

run_startup_probe \
    cli \
    "${PORT}" \
    --port "${PORT}" \
    --permit-root-login yes \
    --password-authentication yes

if ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "ssh-keygen not found; cannot run OpenSSH hostkey smoke test" >&2
    exit 1
fi

OPENSSH_PORT=$((PORT + 1))
mkdir -p "${TMP_DIR}/etc/emsshd"
ssh-keygen -q -t rsa -b 2048 -N '' -C emsshd-startup-test -f "${TMP_DIR}/etc/emsshd/ssh_host_rsa_key"
cat >"${TMP_DIR}/sshd_config" <<EOF
Port ${OPENSSH_PORT}
ListenAddress 127.0.0.1

AuthorizedKeysFile .ssh/authorized_keys
HostKey ${TMP_DIR}/etc/emsshd/ssh_host_rsa_key
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin prohibit-password
Subsystem sftp sftp
EOF

run_startup_probe \
    openssh-hostkey \
    "${OPENSSH_PORT}" \
    --sshd-config "${TMP_DIR}/sshd_config"
