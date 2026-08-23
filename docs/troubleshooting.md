# 故障排查

按「现象」查。排查第一站永远是**访问日志**（默认在 `./logs/access.YYYY-MM-DD`）—— 每条连接的
`result`、`failure_stage`、`decision`、`message` 会直接告诉你卡在哪一步。

```bash
# 看某用户最近的失败
jq 'select(.kind=="connection" and .username=="alice" and .result!="success")' logs/access.*
```

---

## 客户端连不上 / 认证失败

| 现象 | 排查 |
|---|---|
| `407 Proxy Authentication Required` | 缺少代理凭据或用户名/密码错误。核对客户端配置与快照里的 `password`。 |
| `403 Forbidden` | 账号已过期，或目标命中分组 `block`。看日志 `failure_stage` / `decision`。 |
| SOCKS5 直接被拒 | 同上（SOCKS5 没有 407，认证失败即拒绝）。 |
| 连接超时 | 端口没放行；或客户端 scheme 与入口不匹配（明文入口用了 `https://`，或反之）。 |

**账号明明没过期却 403？** `expire` 是日期（如 `2026-12-31`）。确认控制面下发的日期格式正确、且节点时钟准确。

---

## TLS / 证书问题

| 现象 | 排查 |
|---|---|
| 客户端报证书不受信任 | 自签名证书未导入 CA。curl 用 `--proxy-cacert`；系统/浏览器需导入你的 CA。 |
| 节点启动即失败，提示证书/私钥 | `[listeners.tls].cert` / `.key` 路径错误或 PEM 格式不对。 |
| 节点连**上游 hop** 报证书错误 | hop 是自签名。给节点设 `Rove_EXTRA_CA_CERTS` 追加 CA，或该上游设 `skip_cert_verify=true`（仅受控网络）。 |

> `skip_cert_verify` 是**逐上游**开关，只影响出站方向，不影响入站监听的 TLS，也没有全局开关。

---

## 分流不生效

- **本该走上游却直连了**（当前快照 schema）：确认目标命中了 policy `routes[].selectors`，且 action 指向
  正确的 named egress。注意匹配规则 —— 默认是**后缀匹配**，`full:` 才是精确。IP 目标要用 CIDR
  （如 `10.0.0.0/8`）。
- **本该直连却走了上游**：检查 `default_action` 是不是 egress（它会兜底所有未命中 route 的目标）。
- **本该放行却被拒绝**：检查 `default_action` 是不是 `{"type":"block"}`（deny-by-default 策略只
  能到达 route 里列出的目标）。
- **顺序**：`routes` 数组 first-match-wins；未命中再执行 `default_action`，没有则直连。见
  [数据模型](./data-model.md)。
- 日志里 `decision` 会显示实际走向：`direct` / `block` / `upstream:<addr>` / `reverse:<hop_id>` /
  `chain:<id>`。

---

## 控制面同步问题

| 现象 | 排查 |
|---|---|
| 策略改了但节点没变 | 确认控制面 `version` **递增**了；`version <= since` 或 `304` 时节点不替换。 |
| 节点一直用旧缓存 | 控制面不可达。看日志是否有拉取失败/退避；连续失败会退避到最高 5 分钟。 |
| 新快照没生效 | 快照解码或编译失败会被丢弃、保留当前状态。看日志里的编译错误信息。 |
| 请求地址不对 | `snapshot_url` 必须是**完整地址**，节点只追加 `?since=`，不会拼 `/api/...` 之类路径。 |

**手动确认控制面响应**：

```bash
curl -H "Authorization: <token>" "https://control.example.com/snapshot?since=0" | jq .version
```

---

## rove-addrbook 问题

| 现象 | 排查 |
|---|---|
| 节点启动即失败 | 对 `[addrbook].path` 运行 `rove-abctl verify`；再检查权限、256 MiB 上限与容器目录挂载。 |
| 新快照报 `no [addrbook]` | 快照引用了 `book:` selector，但节点未配置 `[addrbook]`；配置并验证本地 `.rab`，或先移除该 selector。 |
| 新快照报 `unknown addrbook category` | 用 `rove-abctl inspect book.rab --categories` 核对分类；错误信息会带上未知分类名，未知分类会拒绝整份快照。 |
| 新书未热替换 | 查运行日志中的 `addrbook reload failed` / `new addrbook rejected`；新书缺少当前快照引用的分类时会保留旧书。 |
| 域名未命中云厂商 IP 段 | 域名请求不会先 DNS 解析再查 IP 分类；给地址簿补充相应域名数据源。 |
| Docker 中始终是旧书 | 不要 bind mount 单个文件；挂载目录并在目录内原子替换 `.rab`。 |
| 多节点决策不同 | 对比各节点启动/热替换日志里的 addrbook epoch 与 checksum，而不只看快照 `version`。 |

构建、六种数据源、CLI 退出码、发布门禁与回滚流程见
[rove-addrbook 指南](./addrbook-format.md)。

---

## 反向 hop 连不上

| 现象 | 排查 |
|---|---|
| hop 注册不上 edge | edge 的 `[reverse_hop].listen` 是 **UDP** 端口，确认放行的是 **UDP** 不是 TCP。 |
| 认证失败 | hop 的 `--reverse-token` / `Rove_HOP_REVERSE_TOKEN` 要在 edge 的 `[reverse_hop].tokens` 里。 |
| 用户请求报错、不回落直连 | 这是**预期**的 fail-closed：edge 没有该 `hop_id` 的已认证会话就报错。先让 hop 注册成功。 |
| 失败阶段 | 日志 `failure_stage` 分为 `reverse_lookup` / `reverse_open` / `hop_connect` / `stream_io`，据此定位。 |
| 账号/节点正常但站点仍打不开 | CONNECT 内源站 TLS 发生在 hop 出网之后，edge 看不到。本机跑 `rove-hop doctor egress <host:port> --json`，或给 hop 打开 `--mqtt-broker` 走 `rove/hop/<hop_id>/doctor`（见 [hop MQTT doctor](./mqtt-integration.md#hop-egress-doctor)）。 |

连接会因 NAT UDP 超时断开？内建 15s QUIC 保活已压在常见 NAT 超时下；仍断开则检查中间设备的 UDP 超时设置。
详见 [反向 hop 数据面](./reverse-hop.md)。

---

## SNMP 轮询不到数据

- 确认 `[snmp].enable = true`，且轮询源 IP 在 `allow_cidrs` 白名单内（白名单外的包**静默丢弃**，不产生日志）。
- v2c：`community` 要匹配。v3：用户、认证/加密协议与口令要对上；配了加密口令的用户**只接受 authPriv**。
- 只支持 GET/GETNEXT/GETBULK；SET/TRAP/INFORM、MD5/DES 不支持。
- SNMP 端口被占用只记一条 `error!` 日志，**代理照常服务**。见 [SNMP 监控](./snmp-cacti.md)。

---

## 性能 / 丢日志

- 日志里出现「access log 丢弃」警告：写入队列打满。调大 `[access_log].channel_capacity`（默认 8192）。
  注意这是**有意的**保护 —— 队满宁可丢日志也绝不阻塞代理转发。
- 吞吐达不到预期：确认没给不需要限速的用户设非零 `up_rate`/`down_rate`（0 才走零开销快路）。
- 本地压测：`docker compose -f docker-compose.local.yml up --build` +
  `cargo run --release --example proxy-benchmark-local -- all --json-out /tmp/rove-proxy-bench.json`
  （覆盖 4 个入口 × 5 条出口链路的延迟、吞吐、并发扫描与限速精度）。
- Subnetra 业务路径压测：`cargo run --release --example subnetra-benchmark-local -- --json-out /tmp/rove-subnetra-bench.json`。
  该示例不需要 Docker/TUN，会在同进程内拉起 Rove hub/spoke，分别测 `spoke-egress` 与 `hub-inbound`
  的 overlay 连接、代理 CONNECT 与下载/上传吞吐。

---

## 还是不行？

1. 把 `[log].level` 临时调到 `debug`，复现一次。
2. 收集对应时间段的访问日志（记得**脱敏**，别贴真实凭据）。
3. 用 `rove-hop doctor egress <目标> --trace` 单独诊断出口网络是否通。
4. 带上版本、配置（占位化）、日志片段提 [Issue](https://github.com/talkincode/rove/issues)。
