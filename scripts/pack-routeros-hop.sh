#!/usr/bin/env bash
# Build a downloadable RouterOS deployment bundle for rove-hop.
#
# Produces:
#   dist/rove-hop-routeros-<version>-<arch>.tar.gz
# containing GUIDE, scripts, docker-save image, checksum sidecar.
#
# Usage:
#   ./scripts/pack-routeros-hop.sh \
#       --target aarch64-unknown-linux-musl \
#       --version v0.5.2 \
#       [--bin path/to/rove-hop] \
#       [--out-dir dist]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="aarch64-unknown-linux-musl"
VERSION="dev"
BIN=""
OUT_DIR="${ROOT}/dist"
BUILD=1

usage() {
  sed -n '1,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --bin) BIN="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

case "$TARGET" in
  aarch64-unknown-linux-musl|aarch64-unknown-linux-gnu) ARCH_LABEL="arm64" ;;
  x86_64-unknown-linux-musl|x86_64-unknown-linux-gnu) ARCH_LABEL="amd64" ;;
  *)
    echo "unsupported --target $TARGET (expected linux aarch64/x86_64)" >&2
    exit 1
    ;;
esac

if [[ -z "$BIN" ]]; then
  BIN="${ROOT}/target/${TARGET}/release/rove-hop"
fi

if [[ ! -f "$BIN" ]]; then
  if [[ "$BUILD" -eq 1 ]]; then
    echo "==> building rove-hop for ${TARGET}"
    if command -v cargo-zigbuild >/dev/null 2>&1; then
      rustup target add "${TARGET}" >/dev/null || true
      (cd "$ROOT" && cargo zigbuild --release --locked --bin rove-hop --target "${TARGET}")
    else
      echo "cargo-zigbuild not found; install it or pass --bin <rove-hop>" >&2
      exit 1
    fi
  else
    echo "binary not found: $BIN" >&2
    exit 1
  fi
fi

test -f "$BIN"
file "$BIN" || true

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rove-hop-ros.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

PKG="${STAGE}/pkg"
IMG_WORK="${STAGE}/img"
ROOTFS="${STAGE}/rootfs"
mkdir -p "${PKG}/scripts" "${PKG}/images" "${ROOTFS}/usr/local/bin" "${ROOTFS}/tmp" "${ROOTFS}/etc/ssl/certs"

cp -a "${ROOT}/deploy/routeros-hop/." "${PKG}/"
mkdir -p "${PKG}/scripts"
cp -f "${ROOT}/deploy/routeros-hop/scripts/"*.rsc "${PKG}/scripts/"

install -m 0755 "$BIN" "${ROOTFS}/usr/local/bin/rove-hop"
if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
  cp /etc/ssl/certs/ca-certificates.crt "${ROOTFS}/etc/ssl/certs/ca-certificates.crt"
elif [[ -f /etc/ssl/cert.pem ]]; then
  cp /etc/ssl/cert.pem "${ROOTFS}/etc/ssl/certs/ca-certificates.crt"
fi
printf 'nameserver 1.1.1.1\n' > "${ROOTFS}/etc/resolv.conf"

mkdir -p "$IMG_WORK"
LAYER_TAR="${IMG_WORK}/layer.tar"
tar -C "$ROOTFS" -cf "$LAYER_TAR" .
if command -v shasum >/dev/null 2>&1; then
  LAYER_ID="$(shasum -a 256 "$LAYER_TAR" | awk '{print $1}')"
else
  LAYER_ID="$(sha256sum "$LAYER_TAR" | awk '{print $1}')"
fi
mkdir -p "${IMG_WORK}/${LAYER_ID}"
mv "$LAYER_TAR" "${IMG_WORK}/${LAYER_ID}/layer.tar"
printf '1.0' > "${IMG_WORK}/${LAYER_ID}/VERSION"

export PACK_IMG_WORK="$IMG_WORK"
export PACK_LAYER_ID="$LAYER_ID"
export PACK_TARGET="$TARGET"
export PACK_VERSION="$VERSION"
python3 <<'PY'
import hashlib, json, os, time
from pathlib import Path

wd = Path(os.environ["PACK_IMG_WORK"])
lid = os.environ["PACK_LAYER_ID"]
target = os.environ["PACK_TARGET"]
version = os.environ["PACK_VERSION"]
created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
arch = "arm64" if "aarch64" in target else "amd64"

(wd / lid / "json").write_text(
    json.dumps(
        {
            "id": lid,
            "created": created,
            "os": "linux",
            "architecture": arch,
            "container_config": {
                "Hostname": "",
                "Domainname": "",
                "User": "",
                "Env": None,
                "Cmd": None,
                "Image": "",
                "Volumes": None,
                "WorkingDir": "",
                "Entrypoint": None,
                "OnBuild": None,
                "Labels": None,
            },
        }
    )
)

cfg = {
    "architecture": arch,
    "os": "linux",
    "config": {
        "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "Entrypoint": ["/usr/local/bin/rove-hop"],
        "Cmd": ["--help"],
        "WorkingDir": "/",
    },
    "rootfs": {"type": "layers", "diff_ids": [f"sha256:{lid}"]},
    "history": [
        {
            "created": created,
            "created_by": f"rove-hop routeros pack {version}",
        }
    ],
}
cfg_bytes = json.dumps(cfg, separators=(",", ":")).encode()
cfg_id = hashlib.sha256(cfg_bytes).hexdigest()
(wd / f"{cfg_id}.json").write_bytes(cfg_bytes)
manifest = [
    {
        "Config": f"{cfg_id}.json",
        "RepoTags": [f"rove-hop:{version}"],
        "Layers": [f"{lid}/layer.tar"],
    }
]
(wd / "manifest.json").write_text(json.dumps(manifest))
tag = version[1:] if version.startswith("v") else version
(wd / "repositories").write_text(json.dumps({"rove-hop": {tag or "latest": lid}}))
print("docker-save config", cfg_id, "arch", arch)
PY

IMAGE_NAME="rove-hop-${ARCH_LABEL}.tar"
EXTRA_JSON=()
while IFS= read -r -d '' f; do
  EXTRA_JSON+=("$(basename "$f")")
done < <(find "$IMG_WORK" -maxdepth 1 -name '*.json' ! -name 'manifest.json' -print0)

tar -C "$IMG_WORK" -cf "${PKG}/images/${IMAGE_NAME}" \
  manifest.json repositories "${LAYER_ID}" "${EXTRA_JSON[@]}"

# env.example expects rove-hop-arm64.tar on arm64; IMAGE_NAME already uses that label.
if [[ "$ARCH_LABEL" == "arm64" && "$IMAGE_NAME" != "rove-hop-arm64.tar" ]]; then
  cp -f "${PKG}/images/${IMAGE_NAME}" "${PKG}/images/rove-hop-arm64.tar"
fi

{
  echo "version=${VERSION}"
  echo "target=${TARGET}"
  echo "arch=${ARCH_LABEL}"
  echo "image=${IMAGE_NAME}"
  echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${PKG}/VERSION.txt"

if command -v shasum >/dev/null 2>&1; then
  (cd "$PKG" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS)
else
  (cd "$PKG" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
fi

mkdir -p "$OUT_DIR"
OUT_TGZ="${OUT_DIR}/rove-hop-routeros-${VERSION}-${ARCH_LABEL}.tar.gz"
tar -C "$PKG" -czf "$OUT_TGZ" .

if command -v shasum >/dev/null 2>&1; then
  (cd "$OUT_DIR" && shasum -a 256 "$(basename "$OUT_TGZ")" > "rove-hop-routeros-${VERSION}-${ARCH_LABEL}.sha256")
else
  (cd "$OUT_DIR" && sha256sum "$(basename "$OUT_TGZ")" > "rove-hop-routeros-${VERSION}-${ARCH_LABEL}.sha256")
fi

echo "==> packed ${OUT_TGZ}"
ls -lh "$OUT_TGZ"
tar -tzf "$OUT_TGZ" | head -50
