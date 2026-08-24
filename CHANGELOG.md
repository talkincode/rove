# Changelog

## [Unreleased]

### Added

- 访问日志与 probe trace 新增 `policy_id` 与 `matched_route`：记录**是哪条规则**做出的决策，
  而不只是决策结果。`matched_route` 是命中 route 在该 policy `routes` 数组中的下标；缺省表示
  没有 route 命中、由 `default_action` 决定。`policy_id` 缺省的语义是「压根没查到策略」——
  未知用户，或用户指向了快照未定义的 policy——与「策略主动拒绝」区分开：后者是正常执行，
  前者是快照下发与用户管理脱节的信号。此前一条 `"decision":"block"` 无法回溯到规则，而产生
  它的快照可能早已被替换。
- routing policy 新增 `default_action`：所有 route 都未命中时执行的 action，语法与
  `routes[].action` 完全一致（`egress` / `direct` / `block`）。把它设为
  `{"type":"block"}` 即可写出 deny-by-default（allowlist）策略——policy 只能到达它自己
  列出的目标。选择器没有 catch-all 写法，此前无法表达这种策略，未命中的目标只会退化为直连。
  MQTT `user_policy_query` 的 `routing_policy.default_action` **总是存在**（缺省显式呈现
  为 `{"action":"direct"}`），让运维直接看到未命中时的行为而不必从字段缺失去推断。

### Changed

- 文档新增 [应用出口网关](docs/egress-gateway.md)：写清 T1 SNI 透传 / T2 声明式 origin /
  T3 通用反代三层态度，并和已有的 reverse hop、reverse ingress 划清术语。这是方向文档，
  代码尚未落地。
- 文档站点首页（`docs/introduction.md`）补齐与 README 一致的产品叙事：主干写成
  `identity → policy → route → egress → transport → observability`，HTTP/SOCKS5/TUIC
  降为 listener adapter，并在站点内公开「使用边界」。FAQ 同步修正 hop 凭据说明——
  配置了入口监听时凭据必填，不再写「回退到默认 `rove`/`rove`」。

- **破坏性**：`addrbook/book.toml` 的收录范围收敛为基础设施与企业应用数据。移除
  `geosite/cn`（geolocation-cn）、`geosite/category-ai-!cn`、`geosite/category-netdisk-!cn`
  以及流媒体、社交、`telegram-ip` 等分类——这些数据集以「哪些站点需要特殊访问」为组织方式，
  服务的是消费级绕行场景，不是应用出口治理。新增 `exchange/binance`、`exchange/okx`、
  `exchange/bybit`、`exchange/kraken`：交易系统对出口 IP 稳定性最敏感，是固定出口的主用例。
  这是发布清单的取舍，不是格式限制——`.rab` 格式和 `book:` selector 对分类内容没有任何约束，
  需要其它数据的部署方可自行维护私有 manifest。引用了被移除分类的快照会 fail-closed 拒收
  （`unknown addrbook category`），不会静默放行。
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
