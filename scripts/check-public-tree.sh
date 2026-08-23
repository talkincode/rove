#!/usr/bin/env bash
# Fail closed if the public tree looks like it grew real secrets.
# Embedded unit-test PEMs and placeholder examples are allowed.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

status=0
say() { printf '%s\n' "$*"; }
fail() { say "FAIL: $*"; status=1; }

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tracked="$(git ls-files)"
else
  tracked="$(find . -type f \
    -not -path './.git/*' \
    -not -path './target/*' \
    -not -path './book/*' \
    -not -path './dist/*' \
    -not -path './data/*' \
    -not -path './logs/*' \
    | sed 's|^\./||')"
fi

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    data/*|logs/*|dist/*|target/*|book/*|.smoke/*)
      fail "runtime/secret path is tracked: $path"
      ;;
    *.pem|*.p12|*.pfx)
      fail "private material is tracked: $path"
      ;;
    *.key)
      case "$path" in
        tests/fixtures/tls/*) ;;
        *) fail "private key is tracked: $path" ;;
      esac
      ;;
  esac
done <<< "$tracked"

token_files=()
pem_files=()
while IFS= read -r path; do
  [[ -z "$path" || ! -f "$path" ]] && continue
  case "$path" in
    mermaid.min.js|Cargo.lock|*.png|*.zip|*.crt|*.rab) continue ;;
  esac
  token_files+=("$path")
  case "$path" in
    tests/*|*.rs) ;;
    *) pem_files+=("$path") ;;
  esac
done <<< "$tracked"

if ((${#token_files[@]})); then
  if rg -n -I \
    -e 'ghp_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{20,}' \
    -e 'sk-[A-Za-z0-9]{20,}' \
    -e 'AKIA[0-9A-Z]{16}' \
    "${token_files[@]}"; then
    fail "cloud token shape found in tracked files"
  fi
fi

if ((${#pem_files[@]})); then
  if rg -n -I -e '-----BEGIN ([A-Z ]*)PRIVATE KEY-----' "${pem_files[@]}"; then
    fail "private key PEM found outside tests/ and Rust sources"
  fi
fi

if [[ "$status" -eq 0 ]]; then
  say "public-tree check passed"
fi
exit "$status"
