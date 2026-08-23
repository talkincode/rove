# Changelog

## [Unreleased]

### Changed

- **破坏性**：快照协议收敛为单一 schema `1`（原 v4 的 `routing_policies` + named
  `egresses` 形状）。旧的 v1–v3 group 文档与 `userdata.json` 不再被解码——过期文档会
  撞上 `deny_unknown_fields` 被整份拒收，而不是静默降级成更弱的路由。
- **破坏性**：MQTT `user_policy_query` 响应去掉 `group`、`policies` 与对象形态的
  `policy`，改为字符串 `policy` 加一个带 `routes` / `default_egress` 的
  `routing_policy` 对象；`snapshot_schema_version` 现在返回 `1`。
- **破坏性**：`rove-hop` 配置了任一入口监听时，`--username` / `--password`（或
  `Rove_HOP_USERNAME` / `Rove_HOP_PASSWORD`）成为必填项，不再回退到内置凭据。回退值会
  被编进每一份发布二进制，忘记设置等同于运行一个公开口令的开放代理。反向 QUIC-only
  的 hop 不监听入口，不受影响。

## [0.1.0] - 2026-08-23

### Added

- 以 Rove 之名首次公开发布：应用网络优化器，面向 Agent API、投资交易、SaaS 出口等路径敏感场景。
- 单二进制正向代理：HTTP CONNECT / absolute-form、SOCKS5（含 UDP）、TUIC v5，进程内认证、策略、限速。
- 伴生进程 `rove-hop`、`rove-relay`、`rove-abctl`。
- 控制面 HTTP 快照同步、本地缓存热启动、fail-closed 安全失败模式。
- Homebrew tap `talkincode/tap/rove`；crates.io 包名 `rove-proxy`（二进制仍为 `rove`）。
