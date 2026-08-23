# Rove Project Audit Report

- **Timestamp:** <YYYY-MM-DD HH:MM:SS TZ>
- **Commit:** <short SHA>
- **Working tree:** <clean | dirty: summarize pre-existing changes>
- **Dimensions scored:** <all 10 | subset>
- **Dimensions skipped:** <none | list with reason>
- **Validation commands:** <commands run and pass/fail/blocked>

## Scorecard

| # | Dimension | Verdict | Rationale | Evidence |
|---|-----------|---------|-----------|----------|
| DF | Documentation ↔ Functionality | PASS/WARN/FAIL/blocked | | `path:line` / command |
| DX | Operator Friendliness | PASS/WARN/FAIL/blocked | | |
| CQ | Code Quality & Robustness | PASS/WARN/FAIL/blocked | | |
| RB | Roadmap Boundary Compliance | PASS/WARN/FAIL/blocked | | |
| CC | Config Consistency | PASS/WARN/FAIL/blocked | | |
| SEC | Security & Secret Hygiene | PASS/WARN/FAIL/blocked | | |
| MQTT | Async Operations Channel | PASS/WARN/FAIL/blocked | | |
| OBS | Probe Observability | PASS/WARN/FAIL/blocked | | |
| BT | Build & Test Health | PASS/WARN/FAIL/blocked | | |
| API | Dependency & Public Surface | PASS/WARN/FAIL/blocked | | |

**Overall verdict:** <PASS | WARN | FAIL> — <worst dimension caps the grade>

## Findings by Dimension

### DF — Documentation ↔ Functionality

<Evidence-backed findings, or "No material issues found.">

### DX — Operator Friendliness

<Build/run/config/MQTT/operator diagnosis experience.>

### CQ — Code Quality & Robustness

<Rust error handling, bounded parsing, concurrency, hot-path clarity.>

### RB — Roadmap Boundary Compliance

<Whether implementation respects `docs/roadmap.md` non-goals and project image.>

### CC — Config Consistency

<Config keys and defaults across code, example, README, docs.>

### SEC — Security & Secret Hygiene

<Secrets, reply-topic constraints, auth/policy conservative behavior, logging. Do not paste secret values.>

### MQTT — Async Operations Channel

<User query, sync command, node status, TLS broker behavior, throttling, compatibility.>

### OBS — Probe Observability

<On-demand probe trace behavior, stages, TTL, one-shot matching, no always-on per-user tracing.>

### BT — Build & Test Health

<Formatting, test, release build, optional clippy/audit, clean-tree caveats.>

### API — Dependency & Public Surface

<Dependency weight, config/public docs promises, management surface isolation.>

## Prioritized Recommendations

1. **[DIM|SEVERITY]** <one concrete change> — `<file>` — <why it matters>
2. **[DIM|SEVERITY]** <one concrete change> — `<file>`
3. **[DIM|SEVERITY]** <one concrete change> — `<file>`

## Notes

- <Blocked checks and how to unblock them.>
- <Intentional non-goals encountered; out-of-scope, not failures.>
- <Dirty-tree context, if relevant.>
