# 访问日志

结构化访问日志是老版本 GOST 详细流量日志的**直接替代品**：每条完成的连接 —— 无论成功，还是在认证 / 策略 /
上游连接 / 隧道转发哪个阶段失败 —— 都会落一行 JSON。它独立于运行日志 `log.level` 和 MQTT 诊断：哪怕把
`log.level` 调到 `error` 且从未开启 MQTT，访问日志依然完整记录。运维可以直接对着日志文件 `grep` 排查
「某用户 / 某目标连不上」这类故障。

默认**开启**、按天轮转、保留 7 天。

## 两种记录形状

同一个文件里混着两类记录，用 `kind` 区分：

```bash
jq 'select(.kind=="connection")' logs/access.2026-07-01   # 每条连接
jq 'select(.kind=="stats")'      logs/access.2026-07-01   # 每 60 秒心跳
```

### `kind:"connection"` —— 每条连接一行

| 字段 | 含义 |
|---|---|
| `timestamp` | 完成时间 |
| `node_id` | 节点标识 |
| `listener` | 入口名 |
| `protocol` | `http` / `socks5` 等 |
| `client_addr` | **客户端来源 `ip:port`**；reverse ingress 下由已认证 relay 可信传递 |
| `client_addr_source` | reverse ingress 流量为 `reverse_ingress`；普通本地 accept 时省略 |
| `relay_addr` / `relay_instance_id` | 实际隧道对端与 relay 实例 |
| `tunnel_session_id` | Rove↔relay QUIC 会话 ID |
| `ingress_id` / `flow_id` | TCP 连接或 UDP flow 的跨 relay/Rove 关联 ID |
| `username` | 认证用户名 |
| `target_host` / `target_port` | 兼容既有目标字段；成功/出站失败时是拨号目标，前置拒绝时是请求目标 |
| `requested_host` / `requested_port` | 客户端在代理协议中声明的目标 |
| `sniffed_host` / `sniff_protocol` | observe-only 从首包识别出的域名及 `tls` / `http` 来源；未匹配时省略 |
| `sniff_outcome` | `matched` / `unsupported` / `timeout` / `malformed` / `limit_exceeded` / `incomplete` |
| `effective_policy_host` | 当前策略候选 host；observe-only 阶段与 requested host 相同 |
| `policy_id` | 做出该决策的 routing policy id。**省略**表示压根没有查到策略——未知用户，或用户指向了快照未定义的 policy；这与「策略主动拒绝」是两类事件 |
| `matched_route` | 命中路由在该 policy `routes` 数组中的下标（从 0 开始）。**省略**表示没有任何 route 命中，由 `default_action` 决定 |
| `decision` | `direct` / `block` / `upstream:<addr>` / `reverse:<hop_id>` / `chain:<chain_id>`（携带具体上游地址或逻辑出口链，不只是类别；**不含**上游密码） |
| `egress` | 仅 chain 决策：胜出成员的物理出口标识（如 `reverse:h1` / `upstream:10.2.2.1:1080`） |
| `chain_member` | 仅 chain 决策：胜出成员的稳定 ID |
| `attempts` | 仅 chain 决策：隧道建立尝试次数（全部失败时同样记录） |
| `result` | 成功 / 失败 |
| `failure_stage` | 失败阶段（如 `auth` / `policy` / `dns` / `dial` / `tls` / `outbound` / `hop_connect` / `chain_exhausted` / `splice`） |
| `message` | 补充信息 |
| `snapshot_version` | 当时生效的快照版本 |
| `duration_ms` | 连接时长 |
| `bytes_up` / `bytes_down` | 上/下行字节数 |

**永不包含密码等凭据。**

### `kind:"stats"` —— 每 60 秒一行心跳

按 listener 聚合（不按用户，避免用户数增长带来无界基数）：

| 字段 | 含义 |
|---|---|
| `listener` | 入口名 |
| `active_connections` | 当前该入口仍在隧道转发阶段的连接数 |
| `bytes_up_total` / `bytes_down_total` | 自进程启动以来累计字节 |
| `bytes_up_delta` / `bytes_down_delta` | 相对上一次 60 秒 tick 的增量 |
| `sniff_*_total` | 按 listener 聚合的六类识别结果累计值；不以域名作 label，基数固定 |

这是老版本 Go `ObserverEvent` 周期性 stats 事件最接近的对应物。即使一段时间没有新连接完成（因此没有
`connection` 行），这行心跳也能证明该 listener 仍在正常工作，而不是进程假死或某入口静默失效。

Sniffing 默认关闭。开启后也只保存规范化域名、协议来源和结果枚举，不保存 URL、HTTP 路径、header
集合、body 或 TLS payload；ECH、QUIC/HTTP3 与 UDP 不在当前可见范围。

## 配置

```toml
[access_log]
enable = true            # 关闭后完全不产生访问日志（不建议在生产关闭）
dir = "./logs"           # 文件名形如 access.2026-07-01
file_prefix = "access"
retention_days = 7       # 按文件名日期清理，与 mtime 无关
channel_capacity = 8192  # 写入队列容量
```

- **非阻塞热路径**：一次记录只是把结构体投进有界 `mpsc` 队列，队列打满**直接丢弃并计数，绝不阻塞代理转发**。
  后台任务单独消费、写文件、（可选）转发 syslog。
- 当发生丢弃时，后台每 60 秒检查一次，若有新增丢弃就输出一条含增量与累计总数的警告，提醒你调大
  `channel_capacity`。
- 按天轮转由 `tracing-appender` 完成；每小时按**文件名日期**清理超过 `retention_days` 的旧文件。

## 转发到远程 syslog（可选）

```toml
[access_log.syslog]
enable = false
address = "syslog.example.com:514"
protocol = "udp"    # udp | tcp
facility = "local0"
tag = "rove"
```

- 打开后，**同一条 JSON** 会额外按手搓的最小 RFC 3164（`<pri>timestamp node_id tag: message`）转发给远程
  collector。`message` 就是那条 JSON，下游可继续按字段检索。
- 支持 `udp`（fire-and-forget）与 `tcp`（RFC 6587 octet-counting 分帧）。
- HOSTNAME 字段固定填 `node_id` 而非 OS 主机名，便于在多节点 fleet 里按节点归集。
- 转发失败只记一条警告，**不影响本地文件写入**，也不重试阻塞热路径。TCP 单条写入有 3 秒超时：远程 collector
  卡死时会主动断开重连，避免拖垮本地写入。

## 常见用法

```bash
# 某用户最近的失败连接
jq 'select(.kind=="connection" and .username=="alice" and .result!="success")' logs/access.*

# 按目标域名统计失败
jq -r 'select(.kind=="connection" and .result!="success") | .target_host' logs/access.* | sort | uniq -c | sort -rn

# 各 listener 最新吞吐（心跳）
jq 'select(.kind=="stats")' logs/access.$(date +%F) | tail -n 20

# 某条 route 到底拦了什么：按 policy + route 下标反查
jq 'select(.policy_id=="llm-egress" and .matched_route==0)' logs/access.*

# 哪些拒绝不是策略拒绝的：policy_id 缺失 = 压根没查到策略
# （未知用户，或用户指向了快照未定义的 policy）——这类应当为 0，否则说明
# 快照下发与用户管理脱节了
jq 'select(.kind=="connection" and .decision=="block" and (has("policy_id")|not))' logs/access.*

# 有多少流量是靠 default_action 兜底走的，而不是被显式 route 命中的：
# 这个比例偏高说明策略写得太粗，出口选择实际上没有被治理
jq -r 'select(.kind=="connection") | if has("matched_route") then "routed" else "default" end' \
  logs/access.* | sort | uniq -c
```
