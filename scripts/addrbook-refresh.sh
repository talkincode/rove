#!/usr/bin/env bash
# 刷新 addrbook 全部上游数据源，然后可用 rove-abctl build 离线构建。
#
#   scripts/addrbook-refresh.sh
#   rove-abctl build --manifest addrbook/book.toml --out addrbook/book.rab --epoch <序号>
#
# 三类上游：
#   1. 直链源（AWS/GCP/Cloudflare/Telegram）→ 交给 rove-abctl fetch；
#   2. v2fly domain-list-community → 无单文件直链依赖（include: 需要整目录），
#      从 GitHub tarball 展开完整 data/ 目录；
#   3. Azure Service Tags → download.microsoft.com 链接每周轮换，
#      先从发布页解析当前 JSON 直链再下载。
set -euo pipefail

cd "$(dirname "$0")/.."
UPSTREAM=addrbook/data/upstream
ABCTL=${ABCTL:-target/release/rove-abctl}
mkdir -p "$UPSTREAM"

[ -x "$ABCTL" ] || { echo "error: $ABCTL 不存在，先 cargo build --release --locked --bin rove-abctl" >&2; exit 1; }

echo "==> v2fly domain-list-community（tarball 展开完整 data/）"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --max-time 300 -o "$tmp/dlc.tar.gz" \
  "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"
mkdir -p "$tmp/data"
tar -xzf "$tmp/dlc.tar.gz" -C "$tmp/data" --strip-components=2 domain-list-community-master/data
[ -e "$UPSTREAM/v2fly-community.new" ] && rm -rf "$UPSTREAM/v2fly-community.new"
mv "$tmp/data" "$UPSTREAM/v2fly-community.new"
[ -e "$UPSTREAM/v2fly-community" ] && rm -rf "$UPSTREAM/v2fly-community"
mv "$UPSTREAM/v2fly-community.new" "$UPSTREAM/v2fly-community"
echo "    $(ls "$UPSTREAM/v2fly-community" | wc -l | tr -d ' ') files"

echo "==> Azure Service Tags（解析发布页当前直链）"
az_url=""
for i in 1 2 3; do
  az_url=$(curl -fsSL --max-time 60 --retry 2 \
    -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36" \
    "https://www.microsoft.com/en-us/download/details.aspx?id=56519" 2>/dev/null |
    grep -oE 'https://download\.microsoft\.com/download/[^"]+ServiceTags_Public_[0-9]+\.json' |
    head -1) && [ -n "$az_url" ] && break
  sleep $((i * 3))
done
if [ -n "$az_url" ]; then
  echo "    $az_url"
  curl -fsSL --max-time 300 -o "$UPSTREAM/azure-service-tags.json.new" "$az_url"
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$UPSTREAM/azure-service-tags.json.new"
  mv "$UPSTREAM/azure-service-tags.json.new" "$UPSTREAM/azure-service-tags.json"
elif [ -s "$UPSTREAM/azure-service-tags.json" ]; then
  echo "    warn: 发布页不可达，沿用本地已有 azure-service-tags.json" >&2
else
  echo "error: 未能解析 Azure 直链且本地无缓存文件" >&2
  exit 1
fi

echo "==> 直链源（AWS / GCP / goog / Cloudflare / Telegram）"
"$ABCTL" fetch --manifest addrbook/book.toml

echo "==> done"
