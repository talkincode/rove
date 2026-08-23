---
name: project-audit
description: Run a comprehensive, evidence-backed audit of the Rove Rust proxy repository and write a scored Chinese Markdown report. Use when asked for 项目审计, 全面审计, 代码审查, repo review, project health, 给项目打分, 技术债审计, 安全边界审计, MQTT/控制面同步审计, or to check whether the Rust rewrite matches README/docs/roadmap. Read-only by default; only writes the audit report.
---

# Rove Project Audit

Audit the whole Rove repository as a Rust single-binary edge proxy: source,
docs, config, release/runtime assumptions, control-plane snapshot sync, MQTT
operations channel, and probe tracing. Produce one scored Markdown report.

Run read-only checks by default. Do not edit source, docs, config, or workflows
during an audit. The only allowed write is the report under `reports/`; if that
directory is not ignored, add `reports/` to `.gitignore` or write to `/tmp` and
say why.

## Ground Truth

Score against the project's own declared intent, not personal taste:

- `README.md` describes the current Rust rewrite architecture and public contract.
- `docs/roadmap.md` defines project image, current capabilities, non-goals, and
  direction.
- `docs/mqtt-integration.md` defines the MQTT async operations protocol.
- `config.example.toml` plus `src/config.rs` define the runtime config surface.
- `Cargo.toml` / `Cargo.lock` define the Rust dependency and build boundary.
- `src/` is the executable truth. If docs and code disagree, code wins for
  current behavior and docs get the finding.

Do not rely on old Go implementation files from history as current behavior.
Use them only when the user explicitly asks for legacy parity.

Never read large generated artifacts in full: `target/`, `.smoke/`, runtime
`data/`, large logs, or generated JSONL. Grep narrowly if needed.

## Dimensions

Score each dimension as `PASS`, `WARN`, `FAIL`, or `blocked`. Cite one concrete
piece of evidence for the score: path, line, command, or count.

1. **DF - Documentation to functionality.** README, roadmap, MQTT docs, config
   example, and source agree on protocols, MQTT topics, sync behavior, limits,
   TLS support, and non-goals.
2. **DX - Operator friendliness.** A new operator can build, configure, run, and
   diagnose the node without guessing secret injection, MQTT setup, control-plane
   snapshot requirements, or listener configuration.
3. **CQ - Code quality and robustness.** Rust code is idiomatic, errors are
   explicit, parsing is bounded, no reachable `panic!`/`unwrap()` on untrusted
   input paths, long-running tasks have clear failure behavior, and hot paths are
   not overloaded with management logic.
4. **RB - Roadmap and boundary compliance.** The implementation stays a
   self-contained edge proxy node. It does not become a control plane, web admin,
   billing/user-management system, GOST plugin wrapper, or general protocol zoo.
5. **CC - Config consistency.** `config.example.toml`, `src/config.rs`, README,
   and MQTT docs agree on fields, defaults, valid values, and secret placeholders.
6. **SEC - Security and secret hygiene.** No committed real secrets; credentials
   are not logged or returned over MQTT; reply topics are constrained; MQTT and
   control-plane tokens are handled as deployment secrets; policy failures stay
   conservative.
7. **MQTT - Async operations channel.** MQTT user query, sync command, node
   status, throttling, TLS broker behavior, reply-topic restrictions, and
   network-isolated deployment assumptions are implemented and documented.
8. **OBS - Probe observability.** Probe tracing is on-demand, short-lived, and
   identifies useful stages (`parse`, `auth`, `policy`, `outbound`, `splice`)
   without turning into all-user realtime tracing or OpenTelemetry scope creep.
9. **BT - Build and test health.** Formatting, tests, release build, and relevant
   static checks pass from the current checkout. If the worktree is dirty, also
   consider whether a clean committed-tree build is needed.
10. **API - Dependency and public-surface discipline.** The binary remains
    lightweight; dependencies are justified; public config/docs do not promise
    unsupported APIs; management features stay behind MQTT/config opt-in.

## Procedure

Run from the repo root. Prefer `rg` over `grep`. Record pre-existing dirty state
and do not clean it.

### 0. Orient

```sh
git rev-parse --short HEAD
git status --short
rg --files -g 'README*' -g 'docs/**' -g 'Cargo.toml' -g 'config.example.toml' -g 'src/**'
```

Read at least:

```sh
sed -n '1,260p' README.md
sed -n '1,260p' docs/roadmap.md
sed -n '1,260p' docs/mqtt-integration.md
sed -n '1,220p' Cargo.toml
sed -n '1,260p' config.example.toml
```

### 1. Build and Test

```sh
cargo fmt --check
cargo test
cargo build --release
git diff --check
```

Optional, if installed and reasonable for the task:

```sh
cargo clippy --all-targets -- -D warnings
cargo audit
```

If local untracked files may hide a committed-tree failure, run a clean archive
smoke in a temp directory and say exactly what was tested.

### 2. Documentation and Config Consistency

Cross-check advertised behavior against implementation:

```sh
rg -n 'mqtt|probe|sync|snapshot|healthz|Prometheus|OpenTelemetry|GOST|gRPC|CONNECT|SOCKS5' README.md docs config.example.toml src
rg -n 'struct Config|struct MqttConfig|struct ControlPlane|struct Listener' src/config.rs
rg -n 'rove/user/query|rove/sync/command|rove/node/status|rove/probe/trace' .
```

Flag any public capability in docs but absent in code, and any public code
surface absent from docs.

### 3. Security and Boundary Checks

```sh
git check-ignore .env config.toml data/snapshot.json target 2>/dev/null || true
rg -n 'password|token|secret|Bearer|NODE_TOKEN|mqtt-pass|sk-[A-Za-z0-9]' README.md docs config.example.toml src
rg -n 'unwrap\\(|expect\\(|panic!|todo!|unimplemented!' src
rg -n 'reply_topic|allowed_reply|password|auth|tls|insecure|skip' src/mqtt.rs src/model.rs src/config.rs
```

Do not paste secret values. Test fixtures or placeholders are acceptable only if
clearly fake. Any real credential, unconstrained reply topic, password leakage in
MQTT response, or open-proxy fallback is `FAIL`.

### 4. MQTT and Probe Tracing

Inspect:

```sh
sed -n '1,260p' src/mqtt.rs
sed -n '1,260p' src/trace.rs
sed -n '1,260p' src/inbound/http.rs
sed -n '1,280p' src/inbound/socks5.rs
sed -n '1,240p' src/sync/mod.rs
```

Confirm:

- MQTT is disabled by default and opt-in by config.
- Default topics match docs and old control-plane expectations.
- User query responses are read-only and do not reveal passwords.
- Sync command triggers one immediate snapshot pull and publishes status.
- Sync command has throttling or concurrency protection.
- Probe tracing only arms a bounded TTL matcher and reports one matching
  connection.
- Probe result contains enough stage data to distinguish auth, policy, outbound,
  and splice failures.
- No OpenTelemetry dependency or always-on per-user trace stream is introduced.

### 5. Code Structure and Dependency Discipline

```sh
rg --files src | sort
rg -n '^mod |pub struct|pub enum|pub fn|async fn' src
cargo tree -e normal
```

Check whether new dependencies are justified for MQTT/TLS/HTTP and whether
management features remain isolated from proxy hot paths.

## Report

Read `report-template.md` from this skill directory and write a timestamped
Chinese report:

- Preferred path: `reports/<YYYYMMDD-HHMMSS>-project-audit.md`.
- If `reports/` is not gitignored, add `reports/` to `.gitignore` first or write
  to `/tmp`.

The report must contain:

1. Header with timestamp, commit, worktree state, and scored/skipped dimensions.
2. Scorecard table for all ten dimensions.
3. Findings by dimension with concrete evidence.
4. Prioritized recommendations, highest leverage first.
5. Overall verdict: any `FAIL` caps overall at `FAIL`; otherwise any `WARN`
   caps at `WARN`; otherwise `PASS`.

## Final Summary

Reply with a concise summary:

- overall verdict and score line,
- build/test status,
- top 1-3 findings,
- smallest next change that improves health most,
- report path.

## Guardrails

- Read-only by default. Do not implement fixes during an audit.
- Do not clean or revert a dirty tree.
- Do not treat explicit non-goals as missing features.
- Mark blocked checks as `blocked` instead of guessing.
- Keep reports evidence-backed; avoid generic praise or vague "looks good".
