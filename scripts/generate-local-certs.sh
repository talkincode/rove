#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CERT_DIR="$ROOT_DIR/docker/local/certs"
CONFIG="$ROOT_DIR/docker/local/openssl-san.cnf"
ALT_CONFIG="$ROOT_DIR/docker/local/openssl-sni-alt.cnf"
CA_CERT="$CERT_DIR/local-rove-ca.crt"
CA_KEY="$CERT_DIR/local-rove-ca.key"
CSR="$CERT_DIR/local-rove.csr"
ALT_CSR="$CERT_DIR/local-rove-alt.csr"
SERIAL="$CERT_DIR/local-rove-ca.srl"
CERT="$CERT_DIR/local-rove.crt"
KEY="$CERT_DIR/local-rove.key"
ALT_CERT="$CERT_DIR/local-rove-alt.crt"
ALT_KEY="$CERT_DIR/local-rove-alt.key"

mkdir -p "$CERT_DIR"

if [ "${1:-}" = "--force" ]; then
  /bin/rm -f \
    "$CA_CERT" "$CA_KEY" "$CSR" "$ALT_CSR" "$SERIAL" \
    "$CERT" "$KEY" "$ALT_CERT" "$ALT_KEY"
fi

if [ -s "$CA_CERT" ] &&
  [ -s "$CERT" ] && [ -s "$KEY" ] &&
  [ -s "$ALT_CERT" ] && [ -s "$ALT_KEY" ]; then
  echo "local certificates already exist: $CERT, $ALT_CERT"
  exit 0
fi

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 365 \
  -subj "/CN=local-rove-ca" \
  -keyout "$CA_KEY" \
  -out "$CA_CERT" \
  -sha256

openssl req \
  -new \
  -nodes \
  -newkey rsa:2048 \
  -subj "/CN=local-rove" \
  -keyout "$KEY" \
  -out "$CSR" \
  -sha256

openssl x509 \
  -req \
  -in "$CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -days 365 \
  -out "$CERT" \
  -extfile "$CONFIG" \
  -extensions v3_req \
  -sha256

openssl req \
  -new \
  -nodes \
  -newkey rsa:2048 \
  -subj "/CN=local-rove-alt" \
  -keyout "$ALT_KEY" \
  -out "$ALT_CSR" \
  -sha256

openssl x509 \
  -req \
  -in "$ALT_CSR" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -days 365 \
  -out "$ALT_CERT" \
  -extfile "$ALT_CONFIG" \
  -extensions v3_req \
  -sha256

chmod 0644 "$CA_CERT"
chmod 0600 "$CA_KEY"
chmod 0644 "$CERT" "$KEY" "$ALT_CERT" "$ALT_KEY"
/bin/rm -f "$CSR" "$ALT_CSR" "$SERIAL"
echo "created local certificates: $CERT, $ALT_CERT"
