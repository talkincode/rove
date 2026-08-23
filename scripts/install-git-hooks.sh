#!/usr/bin/env sh
# One-time setup: point this clone's git hooks at the tracked .githooks/
# directory so pre-commit/pre-push actually run. Re-run safely any time.
set -eu

repo_root="$(git rev-parse --show-toplevel)"
chmod +x "$repo_root/.githooks/pre-commit" "$repo_root/.githooks/pre-push"
git -C "$repo_root" config core.hooksPath .githooks

echo "Git hooks installed (core.hooksPath = .githooks):"
echo "  pre-commit -> cargo fmt --check, cargo clippy -D warnings"
echo "  pre-push   -> full local CI mirror of .github/workflows/ci.yml"
echo ""
echo "Bypass in a genuine emergency with --no-verify; GitHub Actions CI remains the source of truth."
