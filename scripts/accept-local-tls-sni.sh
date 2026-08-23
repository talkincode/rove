#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.local.yml"
CERT_DIR="$ROOT_DIR/docker/local/certs"
CA_CERT="$CERT_DIR/local-rove-ca.crt"
DEFAULT_CERT="$CERT_DIR/local-rove.crt"
DEFAULT_KEY="$CERT_DIR/local-rove.key"
ALT_CERT="$CERT_DIR/local-rove-alt.crt"
ALT_KEY="$CERT_DIR/local-rove-alt.key"
HOST_PORT="${Rove_SNI_ACCEPT_PORT:-18443}"
KEEP_STACK="${Rove_SNI_ACCEPT_KEEP_STACK:-0}"
CONTAINER_NAME="rove-local-main"
MARKER="rove-sni-acceptance-ok"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

for command in docker openssl curl python3; do
  require_command "$command"
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rove-sni-acceptance.XXXXXX")"
ORIGIN_PID=""
WAS_RUNNING="$(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$ORIGIN_PID" ] && kill -0 "$ORIGIN_PID" 2>/dev/null; then
    kill "$ORIGIN_PID" 2>/dev/null || true
    wait "$ORIGIN_PID" 2>/dev/null || true
  fi
  if [ "$WAS_RUNNING" != "true" ] && [ "$KEEP_STACK" != "1" ]; then
    docker compose -f "$COMPOSE_FILE" stop rove >/dev/null 2>&1 || true
    docker compose -f "$COMPOSE_FILE" rm -f rove >/dev/null 2>&1 || true
  fi
  /bin/rm -rf "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$ROOT_DIR/scripts/generate-local-certs.sh"

for file in "$CA_CERT" "$DEFAULT_CERT" "$DEFAULT_KEY" "$ALT_CERT" "$ALT_KEY"; do
  if [ ! -s "$file" ]; then
    echo "missing local TLS fixture: $file" >&2
    exit 1
  fi
done

ORIGIN_DIR="$TMP_DIR/origin"
mkdir -p "$ORIGIN_DIR"
printf '%s' "$MARKER" >"$ORIGIN_DIR/marker.txt"
ORIGIN_PORT="$(
  python3 -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 0)); print(s.getsockname()[1]); s.close()'
)"

python3 - "$ORIGIN_PORT" "$DEFAULT_CERT" "$DEFAULT_KEY" "$ORIGIN_DIR" \
  >"$TMP_DIR/origin.log" 2>&1 <<'PY' &
import http.server
import os
import ssl
import sys

port = int(sys.argv[1])
cert = sys.argv[2]
key = sys.argv[3]
root = sys.argv[4]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


os.chdir(root)
server = http.server.ThreadingHTTPServer(("0.0.0.0", port), QuietHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
ORIGIN_PID=$!

origin_ready=0
attempt=0
while [ "$attempt" -lt 50 ]; do
  attempt=$((attempt + 1))
  if curl --silent --show-error --fail --insecure \
    "https://127.0.0.1:$ORIGIN_PORT/marker.txt" >/dev/null 2>&1; then
    origin_ready=1
    break
  fi
  sleep 0.1
done
if [ "$origin_ready" != "1" ]; then
  echo "temporary HTTPS origin did not start" >&2
  cat "$TMP_DIR/origin.log" >&2
  exit 1
fi

docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate --no-deps rove

served_fingerprint() {
  openssl s_client \
    -connect "127.0.0.1:$HOST_PORT" \
    -servername "$1" \
    -showcerts </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256 2>/dev/null |
    sed 's/^[^=]*=//'
}

proxy_ready=0
attempt=0
while [ "$attempt" -lt 120 ]; do
  attempt=$((attempt + 1))
  fingerprint="$(served_fingerprint local-rove || true)"
  if [ -n "$fingerprint" ]; then
    proxy_ready=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)" = "false" ]; then
    break
  fi
  sleep 0.25
done
if [ "$proxy_ready" != "1" ]; then
  echo "Rove HTTPS listener did not become ready on 127.0.0.1:$HOST_PORT" >&2
  docker compose -f "$COMPOSE_FILE" logs --no-color rove >&2 || true
  exit 1
fi

expected_fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^[^=]*=//'
}

assert_certificate() {
  server_name="$1"
  cert_path="$2"
  expected="$(expected_fingerprint "$cert_path")"
  actual="$(served_fingerprint "$server_name")"
  if [ "$actual" != "$expected" ]; then
    echo "certificate mismatch for SNI $server_name" >&2
    echo "expected: $expected" >&2
    echo "actual:   $actual" >&2
    exit 1
  fi
  echo "PASS certificate: $server_name -> $actual"
}

assert_proxy_connect() {
  server_name="$1"
  response="$(
    NO_PROXY= no_proxy= HTTPS_PROXY= HTTP_PROXY= ALL_PROXY= \
      curl --silent --show-error --fail --max-time 15 \
      --proxy "https://$server_name:$HOST_PORT" \
      --proxy-cacert "$CA_CERT" \
      --proxy-user "bench-direct:bench" \
      --resolve "$server_name:$HOST_PORT:127.0.0.1" \
      --insecure \
      "https://host.docker.internal:$ORIGIN_PORT/marker.txt"
  )"
  if [ "$response" != "$MARKER" ]; then
    echo "unexpected proxy response for SNI $server_name: $response" >&2
    exit 1
  fi
  echo "PASS HTTP CONNECT: $server_name"
}

assert_certificate local-rove "$DEFAULT_CERT"
assert_certificate alt.local-rove "$ALT_CERT"
assert_proxy_connect local-rove
assert_proxy_connect alt.local-rove

echo "PASS local TLS SNI acceptance on 127.0.0.1:$HOST_PORT"
