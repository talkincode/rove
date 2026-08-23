# Changelog

## [0.1.0] - 2026-08-23

### Added

- 以 Rove 之名首次公开发布：应用网络优化器，面向 Agent API、投资交易、SaaS 出口等路径敏感场景。
- 单二进制正向代理：HTTP CONNECT / absolute-form、SOCKS5（含 UDP）、TUIC v5，进程内认证、策略、限速。
- 伴生进程 `rove-hop`、`rove-relay`、`rove-abctl`。
- 控制面 HTTP 快照同步、本地缓存热启动、fail-closed 安全失败模式。
- Homebrew tap `talkincode/tap/rove`；crates.io 包名 `rove-proxy`（二进制仍为 `rove`）。
