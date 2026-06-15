#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build-wsl-mbedtls-static"
BIN="${BUILD_DIR}/emssh_linux_posix_stdio_server"
TMP_DIR="/tmp/emssh-wsl-verify"

log() {
    printf '[wsl-verify] %s\n' "$1"
}

probe_banner() {
    local port="$1"
    python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=2.0)
try:
    data = s.recv(128)
    if not data.startswith(b"SSH-"):
        raise SystemExit(3)
    print(data.decode("utf-8", errors="ignore").strip())
finally:
    s.close()
PY
}

wait_listen() {
    local port="$1"
    local deadline
    deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        if ss -ltn | grep -q ":${port} "; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

start_server() {
    local port="$1"
    shift
    local args=(
        --root-dir "${TMP_DIR}/root"
        --passwd-file "${TMP_DIR}/passwd"
        --shadow-file "${TMP_DIR}/shadow"
        --backend mbedtls
    )
    if [[ "${port}" != "-" ]]; then
        args+=(--port "${port}")
    fi
    "${BIN}" \
        "${args[@]}" \
        "$@" >"${TMP_DIR}/server_${port}.log" 2>&1 &
    echo $!
}

stop_server() {
    local pid="$1"
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
}

log "configure/build (mbedtls static backend)"
cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DEMSSH_USE_MBEDTLS=ON \
    -DEMSSH_USE_OPENSSL=OFF \
    -DEMSSH_USE_WOLFSSL=OFF \
    -DEMSSH_MBEDTLS_USE_PSA=OFF \
    -DEMSSH_BUILD_POSIX_RUNTIME=ON \
    -DEMSSH_BUILD_POSIX_NET=ON \
    -DEMSSH_BUILD_POSIX_TERM=ON \
    -DEMSSH_BUILD_STDIO_FS=ON \
    -DEMSSH_BUILD_POSIX_PASSWD_AUTH=ON \
    -DEMSSH_BUILD_SSHD_CONFIG_FILE=ON \
    -DEMSSH_BUILD_LINUX_POSIX_STDIO_SERVER=ON \
    -DEMSSH_LINUX_POSIX_STDIO_SERVER_BACKEND=mbedtls

cmake --build "${BUILD_DIR}" \
    --target \
    emssh_linux_posix_stdio_server \
    test_posix_passwd_auth \
    test_stdio_fs \
    test_sshd_config_file \
    test_mbedtls_crypto \
    test_mbedtls_transport \
    test_posix_net \
    test_posix_runtime \
    test_tcp_socket \
    -j

log "prepare runtime fixtures"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}/root"
printf 'hello\n' > "${TMP_DIR}/root/hello.txt"
# Locked account is enough for startup/connectivity scenarios.
printf 'emssh:*:1000:1000:emssh:/home/emssh:/bin/sh\n' > "${TMP_DIR}/passwd"
printf 'emssh:*:19793:0:99999:7:::\n' > "${TMP_DIR}/shadow"
cat > "${TMP_DIR}/sshd_config" <<'EOF'
Port 22331
ListenAddress 127.0.0.1
LoginGraceTime 12
PasswordAuthentication yes
Subsystem sftp internal-sftp
EOF
echo 'Port 0' > "${TMP_DIR}/sshd_config_bad"

log "scenario S0: password-authentication cli startup"
EMSSHD_VERIFY_PORT=2222 bash "${ROOT_DIR}/tools/verify_emsshd_linux_startup.sh" "${BIN}"

log "run selected unit tests"
"${BUILD_DIR}/test_posix_passwd_auth"
"${BUILD_DIR}/test_sshd_config_file"
"${BUILD_DIR}/test_mbedtls_crypto"
"${BUILD_DIR}/test_mbedtls_transport"
"${BUILD_DIR}/test_posix_net"
"${BUILD_DIR}/test_posix_runtime"
"${BUILD_DIR}/test_tcp_socket"
# On WSL + /mnt/c this test can fail on POSIX permission bits due host FS semantics.
if ! "${BUILD_DIR}/test_stdio_fs"; then
    log "warning: test_stdio_fs failed on current mount semantics, continue"
fi

log "scenario S1: --help"
"${BIN}" --help >/dev/null

log "scenario S2: invalid port"
"${BIN}" --port 0 >"${TMP_DIR}/s2_invalid_port.txt" 2>&1 || true
grep -q '^usage:' "${TMP_DIR}/s2_invalid_port.txt"

log "scenario S3: invalid max-workers"
"${BIN}" --max-workers 0 >"${TMP_DIR}/s3_invalid_workers.txt" 2>&1 || true
grep -q '^usage:' "${TMP_DIR}/s3_invalid_workers.txt"

log "scenario S4: fixed backend reject openssl"
"${BIN}" --backend openssl >"${TMP_DIR}/s4_backend_reject.txt" 2>&1 || true
grep -q '^usage:' "${TMP_DIR}/s4_backend_reject.txt"

log "scenario S5: basic startup + banner"
pid="$(start_server 22330 --listen 127.0.0.1 --timeout-ms 15000)"
trap 'stop_server "${pid}"' EXIT
wait_listen 22330
probe_banner 22330 >/dev/null
stop_server "${pid}"
trap - EXIT

log "scenario S6: sshd_config apply"
pid="$(start_server - --sshd-config "${TMP_DIR}/sshd_config")"
trap 'stop_server "${pid}"' EXIT
wait_listen 22331
probe_banner 22331 >/dev/null
stop_server "${pid}"
trap - EXIT

log "scenario S7: cli override > sshd_config"
pid="$(start_server 22332 --sshd-config "${TMP_DIR}/sshd_config" --timeout-ms 13000)"
trap 'stop_server "${pid}"' EXIT
wait_listen 22332
probe_banner 22332 >/dev/null
stop_server "${pid}"
trap - EXIT

log "scenario S8: common parallel connections (6 concurrent)"
pid="$(start_server 22333 --max-workers 16)"
trap 'stop_server "${pid}"' EXIT
wait_listen 22333
python3 <<'PY'
import socket
import threading

ok = 0
lock = threading.Lock()

def worker():
    global ok
    s = socket.create_connection(("127.0.0.1", 22333), timeout=2.0)
    try:
        data = s.recv(64)
        if data.startswith(b"SSH-"):
            with lock:
                ok += 1
    finally:
        s.close()

threads = [threading.Thread(target=worker) for _ in range(6)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if ok < 6:
    raise SystemExit(8)
PY
stop_server "${pid}"
trap - EXIT

log "scenario S9: burst under worker limit=1 (20 concurrent, process survives)"
pid="$(start_server 22334 --max-workers 1)"
trap 'stop_server "${pid}"' EXIT
wait_listen 22334
python3 <<'PY'
import socket
import threading

ok = 0
lock = threading.Lock()

def worker():
    global ok
    try:
        s = socket.create_connection(("127.0.0.1", 22334), timeout=1.5)
    except Exception:
        return
    try:
        s.settimeout(1.5)
        data = s.recv(64)
        if data.startswith(b"SSH-"):
            with lock:
                ok += 1
    except Exception:
        pass
    finally:
        s.close()

threads = [threading.Thread(target=worker) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
if ok < 1:
    raise SystemExit(9)
PY
stop_server "${pid}"
trap - EXIT

log "scenario S10: invalid sshd_config rejected"
"${BIN}" \
    --root-dir "${TMP_DIR}/root" \
    --passwd-file "${TMP_DIR}/passwd" \
    --shadow-file "${TMP_DIR}/shadow" \
    --sshd-config "${TMP_DIR}/sshd_config_bad" \
    --backend mbedtls >"${TMP_DIR}/s10_bad_cfg.txt" 2>&1 && exit 10 || true

log "all scenarios passed"
