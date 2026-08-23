# Changelog

## [Unreleased]

### Added

- routing policy 新增 `default_action`：所有 route 都未命中时执行的 action，语法与
  `routes[].action` 完全一致（`egress` / `direct` / `block`）。把它设为
  `{"type":"block"}` 即可写出 deny-by-default（allowlist）策略——policy 只能到达它自己
  列出的目标。选择器没有 catch-all 写法，此前无法表达这种策略，未命中的目标只会退化为直连。
  MQTT `user_policy_query` 的 `routing_policy.default_action` **总是存在**（缺省显式呈现
  为 `{"action":"direct"}`），让运维直接看到未命中时的行为而不必从字段缺失去推断。

### Changed

- **破坏性**：routing policy 的 `default_egress`（egress ID 字符串）由 `default_action`
  （与 route 同形的 action 对象）取代。迁移：`"default_egress": "x"` 写成
  `"default_action": {"type": "egress", "egress": "x"}`。带 `default_egress` 的快照会撞上
  `deny_unknown_fields` 被整份拒收，节点继续使用上一份有效快照。
- **破坏性**：快照协议收敛为单一 schema `1`（原 v4 的 `routing_policies` + named
  `egresses` 形状）。旧的 v1–v3 group 文档与 `userdata.json` 不再被解码——过期文档会
  撞上 `deny_unknown_fields` 被整份拒收，而不是静默降级成更弱的路由。
- **破坏性**：MQTT `user_policy_query` 响应去掉 `group`、`policies` 与对象形态的
  `policy`，改为字符串 `policy` 加一个带 `routes` / `default_action` 的
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
