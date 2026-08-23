# Rove MQTT 对接开发文档

本文档描述 Rust 版 Rove 的 MQTT 异步运维通道。该通道用于网络隔离场景：控制面不能直接访问节点时，通过 MQTT 下发查询、同步和拨测追踪指令。

MQTT 不替代代理数据面，也不要求对每个用户做实时链路追踪。链路追踪只在拨测前短时间武装，匹配到下一条连接后发布一次结果。

## 能力边界

- 用户策略查询：控制面发布查询请求，Rove 从当前快照读取用户策略并向一次性回复主题返回脱敏结果。
- 同步指令：控制面发布同步请求，Rove 立即拉取一次控制面 snapshot，并向节点状态主题发布结果。
- 节点状态通知：Rove 连接 MQTT 后、同步指令处理后发布状态。
- 拨测链路追踪：控制面先发布一次追踪武装指令，再发起真实代理拨测；节点匹配该连接后向回复主题发布故障阶段或成功结果。出站失败阶段会拆成 `dns` / `dial` / `tls`（Rove 终止的 hop TLS）以及既有的 `hop_connect` / `reverse_*`；CONNECT 隧道内的源站 TLS 仍由客户端完成，节点看不到握手，需用 `rove-hop doctor egress`。
- 诊断事件会话：控制面开启一个有限时长、按用户维度的会话；存活期间节点对每条匹配连接持续发布脱敏诊断事件，到期或取消时发布汇总。默认关闭、不落盘；连接完成路径使用有界同步临界区，发布不执行异步等待。

## 配置

默认不启用 MQTT。示例见 `config.example.toml`：

```toml
[mqtt]
enable = true
broker = "ssl://mqtt.example.com:8883"
client_id = "" # 留空时使用 rove-<node_id>
username = "mqtt-user"
password = "mqtt-pass"
qos = 1
reply_topic_prefix = "rove/replies/"

[mqtt.topics]
user_query = "rove/user/query"
sync_command = "rove/sync/command"
node_status = "rove/node/status"
probe_trace = "rove/probe/trace"
diagnostics_command = "rove/diagnostics/command"

[mqtt.diagnostics]
default_ttl_secs = 30
max_ttl_secs = 300
max_sessions = 16
max_sessions_per_user = 2
channel_capacity = 256

[mqtt.tls]
enable = true
```

说明：

- `broker` 支持 `tcp://`、`mqtt://`、`ssl://`、`tls://`、`tcps://`、`mqtts://`。
- `mqtt.tls.enable=true` 且 broker 使用 `tcp://` 或 `mqtt://` 时，客户端会按 TLS 连接改写为 `ssl://`，端口保持原值。
- `reply_topic` 必须以 `reply_topic_prefix` 开头，且不能包含 `#`、`+` 或空白字符。
- 发布消息不设置 retained。
- 用户密码、upstream 密码不会出现在查询响应中。
- broker URL 即使携带兼容的 userinfo，启动日志也只输出 scheme、host 与 port；部署仍建议使用独立的 `username` / `password` 字段。

## 默认主题

| 用途 | 默认主题 | 方向 |
| --- | --- | --- |
| 用户策略查询 | `rove/user/query` | 控制面 -> Rove |
| 同步指令 | `rove/sync/command` | 控制面 -> Rove |
| 节点状态 | `rove/node/status` | Rove -> 控制面 |
| 拨测追踪武装 | `rove/probe/trace` | 控制面 -> Rove |
| 诊断会话指令 | `rove/diagnostics/command` | 控制面 -> Rove |
| 一次性回复前缀 | `rove/replies/` | Rove -> 控制面 |
| hop egress doctor | `rove/hop/<hop_id>/doctor` | 控制面 -> `rove-hop`（可选，默认关） |

edge MQTT **不会**把 doctor 转到 hop，也不得用 edge 本机网络冒充 hop 出网。hop 出网 / 源站 TLS 只能由 hop 自己的 MQTT 或本机 `rove-hop doctor egress` 完成。

## hop egress doctor

`rove-hop` 可另开一条与 edge 隔离的 MQTT 客户端，远程触发与 `rove-hop doctor egress --json` 同构的分层探测。默认关闭；不配 `--mqtt-broker` 时 hop 进程行为不变。doctor 不进入 splice / CONNECT 热路径。

```bash
Rove_HOP_MQTT_PASSWORD=... rove-hop --socks5 0.0.0.0:1080 \
  --mqtt-broker tcp://mqtt.example.com:1883 \
  --mqtt-hop-id rove-hop-jp \
  --mqtt-username mqtt-user
```

请求：

```json
{
  "command": "hop_egress_doctor",
  "request_id": "doc-1",
  "reply_topic": "rove/replies/hop-doctor-doc-1",
  "data": {
    "target": "api.openai.com:443",
    "trace": false,
    "timeout_ms": 5000
  }
}
```

约束：

- `target` 必填（preset 名、`host:port` 或 URL）；远程触发不做随机 preset，避免生产 hop 被误打到公网。
- `reply_topic` 必须落在 `--mqtt-reply-prefix`（默认 `rove/replies/`）下，且不能含 `#` / `+` / 空白。
- `trace` 默认 `false`。`timeout_ms` 夹在 500–30000。同时只跑一个 doctor，第二个回 `throttled`。
- 回包 flatten `EgressDiagnosticReport`：`kind`、`result`、`dns` / `route` / `tcp` / `tls` / `http` / `trace`，并带 `event=hop_egress_doctor`、`hop_id`、`request_id`。
- 回包与访问日志不含 hop 代理密码、reverse token、MQTT 密码。

## 用户策略查询

请求：

```json
{
  "command": "user_policy_query",
  "request_id": "query-1",
  "reply_topic": "rove/replies/query-1",
  "data": {
    "username": "alice"
  }
}
```

兼容字段：

- 用户名优先级：`data.username` > `data.client` > `username` > `client`。
- `request_id` 会原样带回。

成功响应：

```json
{
  "request_id": "query-1",
  "node_id": "edge-node-01",
  "status": "ok",
  "user": {
    "username": "alice",
    "expire": "2099-12-31",
    "policy": "shared-policy",
    "up_rate": 1024,
    "down_rate": 2048,
    "max_connections": 2,
    "routing_policy": {
      "id": "shared-policy",
      "routes": [
        {"selectors": ["book:security/blocked"], "action": "block"},
        {
          "selectors": ["openai.com"],
          "action": "egress",
          "egress": {
            "id": "tokyo",
            "upstream": {
              "kind": "socks5",
              "addr": "proxy.example:1080",
              "tls": true,
              "auth": true
            }
          }
        },
        {"selectors": ["full:private.example"], "action": "direct"}
      ],
      "default_action": {
        "action": "egress",
        "egress": {
          "id": "backup",
          "upstream": {"kind": "reverse", "addr": "tokyo-hop", "tls": false, "auth": false}
        }
      }
    }
  },
  "timestamp": 1781690000
}
```

字段语义：

- `policy`：该身份绑定的 routing policy **ID**（字符串）。
- `routing_policy`：解析后的脱敏策略对象——policy ID、有序 `routes`，以及 `default_action`。
  route 顺序与快照一致，就是 first-match-wins 的求解顺序。
- `routes[].action` 为 `"egress"` / `"direct"` / `"block"` 之一；只有 `"egress"` 会附带
  `egress` 对象（命名 egress 的 ID 与脱敏 realization）。
- `default_action` 是所有 route 都未命中时的行为，**总是存在**：`{"action": "direct"}`、
  `{"action": "block"}`（deny-by-default 策略），或 `{"action": "egress", "egress": {...}}`。
  它不会因为快照里没写 `default_action` 而消失——缺省会显式呈现为 `{"action": "direct"}`，
  让运维直接看到未命中时的行为，而不必从字段缺失去推断。
- egress 引用[出口链](./data-model.md)时，`upstream` 呈现为
  `{"kind": "chain", "addr": "<egress-id>", "tls": false, "auth": false, "members": [...]}`；
  `members` 逐个列出成员的 `id`、`priority`、`kind`、`addr`、`tls` 与 `auth: true/false`，
  但**永不包含**成员密码、token 或认证头。
- 用户密码、TUIC 密码、backend 用户名/密码、token 和认证头永不返回；`auth` 只是一个布尔标记，
  表示该出口是否配置了认证。

用户不存在：

```json
{
  "request_id": "query-1",
  "node_id": "edge-node-01",
  "status": "not_found",
  "message": "user not found",
  "timestamp": 1781690000
}
```

## 同步指令

请求：

```json
{
  "command": "sync_users",
  "request_id": "sync-1",
  "data": {
    "syncflag": "public"
  }
}
```

Rust 版中，`syncflag` 字段仅用于兼容旧控制面消息和状态回显；实际同步行为是立即向当前 `[control_plane]` 拉取一次 snapshot。空 payload 或 `{}` 也会触发同步。

状态主题响应：

```json
{
  "request_id": "sync-1",
  "node_id": "edge-node-01",
  "event": "sync_command",
  "status": "ok",
  "message": "snapshot applied",
  "syncflag": "public",
  "success": true,
  "updated": true,
  "already_running": false,
  "elapsed_ms": 123,
  "version": "Rove/0.1.0",
  "snapshot_version": 12,
  "snapshot_schema_version": 1,
  "timestamp": 1781690000
}
```

`snapshot_schema_version` 是当前生效快照声明的线协议结构/语义版本，与 `snapshot_version`
（内容修订号）相互独立。当前只有一个 schema，该字段恒为 `1`；它存在的意义是让控制面在未来
bump schema 前，能先确认全网节点都已升级到支持新 schema 的二进制，再让 producer 输出新
schema。快照 wire contract 见[快照协议](./snapshot-protocol.md)。

同步指令有 5 秒节流窗口；窗口内重复请求状态为 `throttled`，不会并发拉取控制面。
节点建立 MQTT 连接时还会发布 `event: "startup"`：已有快照时状态为 `synced` 且
`success: true`；尚无快照时状态为 `starting`、`success: false`、`snapshot_version: 0`，
不会把“同步器已创建”误报成“快照已同步”。

## 拨测链路追踪

控制面先订阅一次性回复主题，然后发布追踪武装指令：

```json
{
  "request_id": "probe-1",
  "reply_topic": "rove/replies/probe-1",
  "data": {
    "username": "alice",
    "target_host": "example.com",
    "target_port": 443,
    "protocol": "http",
    "ttl_secs": 30
  }
}
```

匹配字段都是可选的，但生产拨测建议至少传 `username`、`target_host`、`target_port` 和 `protocol`，避免多节点或多连接串扰。支持字段：

- `data.username` 或 `data.client`
- `data.target_host` 或 `data.host`
- `data.target_port` 或 `data.port`
- `data.protocol`: `http` 或 `socks5`
- `data.listener`: 限定某个 listener 名称
- `data.ttl_secs`: 1 到 300 秒，默认 30 秒

武装成功后立即回复：

```json
{
  "request_id": "probe-1",
  "node_id": "edge-node-01",
  "event": "probe_trace_armed",
  "status": "ok",
  "message": "probe trace armed",
  "ttl_secs": 30,
  "timestamp": 1781690000
}
```

随后控制面发起真实代理拨测。节点匹配到连接后发布一次结果：

```json
{
  "request_id": "probe-1",
  "reply_topic": "rove/replies/probe-1",
  "event": "probe_trace_result",
  "status": "error",
  "listener": "http-in",
  "protocol": "http",
  "username": "alice",
  "target_host": "example.com",
  "target_port": 443,
  "decision": "upstream",
  "failure_stage": "outbound",
  "message": "upstream connect failed",
  "snapshot_version": 12,
  "duration_ms": 35,
  "timestamp": 1781690001
}
```

`failure_stage` 取值包括：

- `parse`: 协议解析或请求目标格式错误。
- `auth`: 认证缺失、认证失败或账号过期。
- `policy`: 命中 block 策略。
- `limit`: 超过用户 `max_connections` 活跃隧道限制。
- `outbound`: direct 或上游出口连接失败。
- `reverse_lookup`: 找不到已认证的 reverse hop 会话。
- `reverse_open`: edge 无法在 reverse hop 上打开目标流。
- `hop_connect`: reverse hop 无法连接最终目标。
- `chain_exhausted`: 出口链所有成员在隧道建立阶段全部失败（fail-closed，不回落直连）。
- `splice`: 隧道建立后双向转发失败。
- `stream_io`: reverse/TUIC 等流在建立后转发失败。

chain 决策的追踪结果还携带 `egress`（胜出成员的物理出口）、`chain_member`（成员 ID）与
`attempts`（建立尝试次数）字段；凭据永不出现。

成功结果中 `status` 为 `ok`，通常没有 `failure_stage`。

## 诊断事件会话

拨测追踪是「武装一次、匹配一条连接、回一条结果」。诊断事件会话是它的可选扩展：在一段有限的 TTL 内保持武装，对**每一条**匹配的代理连接持续发布结构化、脱敏的诊断事件，并在到期或取消时发布一条汇总。

安全边界（与拨测追踪一致，且更严格）：

- 默认关闭，只有收到显式命令后才会临时开启；任何状态都不落盘。
- 连接完成路径进入受会话上限约束的同步临界区；事件通过有界通道 `try_send`，通道满时直接丢弃并计数（`dropped_events`），发布过程不 await。
- 事件只携带拨测追踪已暴露的非敏感字段（用户名标识、目标 host/port、路由决策、失败阶段与静态描述）。用户密码、令牌、upstream 凭据永不进入诊断通道。
- 会话数量受全局与单用户上限约束，TTL 受 `max_ttl_secs` 约束。

### 开启会话

控制面先订阅一次性回复主题，然后向 `rove/diagnostics/command` 发布：

```json
{
  "command": "diagnostic_session_start",
  "request_id": "diag-1",
  "reply_topic": "rove/replies/diag-1",
  "data": {
    "username": "alice",
    "target_host": "example.com",
    "target_port": 443,
    "protocol": "http",
    "listener": "http-in",
    "event_types": ["auth", "policy", "outbound"],
    "ttl_secs": 60
  }
}
```

字段说明：

- `command`：诊断主题专用，缺省即视为 `diagnostic_session_start`；取消用 `diagnostic_session_cancel`。
- `data.username`（或 `data.client`）：**必填**，会话按用户名维度匹配。
- `data.target_host`（或 `data.host`）、`data.target_port`（或 `data.port`）、`data.protocol`（`http`/`socks5`）、`data.listener`：可选的额外过滤维度，未提供即不限制。
- `data.event_types`：可选，限定需要的**每连接**事件类型；省略或为空数组表示全部（`auth`/`policy`/`limit`/`outbound`/`splice`）。无法识别的取值会被忽略，回执中 `event_types` 会回显实际生效的集合。`summary` 为生命周期事件，始终发布，不受此过滤影响。
- `data.ttl_secs`：会话存活时间，钳制到 `[1, max_ttl_secs]`；省略时使用 `default_ttl_secs`。
- `request_id`：会话标识，用于续期与取消；省略时自动生成 `diag-<timestamp>`。对同一 `request_id` 重复开启表示续期，不会新增会话计数。

武装成功后立即回复：

```json
{
  "request_id": "diag-1",
  "node_id": "edge-node-01",
  "event": "diagnostic_session_started",
  "status": "ok",
  "message": "diagnostic session armed",
  "ttl_secs": 60,
  "event_types": ["auth", "outbound", "policy"],
  "timestamp": 1781690000
}
```

超过全局或单用户会话上限时，回复 `event` 为 `diagnostic_session_rejected`、`status` 为 `throttled`；`reply_topic` 非法（不以前缀开头或含通配符）时直接忽略，不回复；缺少 `username` 时回复 `status` 为 `bad_request`。

### 每连接事件

会话存活期间，节点对每条匹配连接发布一条事件到 `reply_topic`：

```json
{
  "request_id": "diag-1",
  "node_id": "edge-node-01",
  "event": "diagnostic_event",
  "event_type": "outbound",
  "status": "error",
  "listener": "http-in",
  "protocol": "http",
  "username": "alice",
  "target_host": "example.com",
  "target_port": 443,
  "decision": "upstream",
  "failure_stage": "outbound",
  "message": "upstream connect failed",
  "snapshot_version": 12,
  "duration_ms": 35,
  "timestamp": 1781690001
}
```

`event_type` 取值：

- `auth`：认证缺失、失败或账号过期。
- `policy`：命中 block 策略。
- `limit`：超过连接数上限。
- `outbound`：direct、上游出口、chain 或 reverse 出口建立失败；`failure_stage` 会进一步区分 `outbound`、`chain_exhausted`、`reverse_lookup`、`reverse_open` 与 `hop_connect`。
- `splice`：隧道建立后转发失败（`failure_stage` 为 `splice` 或 `stream_io`），或成功隧道（`status` 为 `ok`）。

协议解析阶段（`parse`）不产生诊断事件，仍由一次性拨测追踪覆盖。

### 汇总与取消

到期时节点自动发布汇总并清除会话；控制面也可主动取消：

```json
{
  "command": "diagnostic_session_cancel",
  "request_id": "diag-1"
}
```

无论到期还是取消，都会向会话记录的 `reply_topic` 发布一条汇总：

```json
{
  "request_id": "diag-1",
  "node_id": "edge-node-01",
  "event": "diagnostic_summary",
  "status": "ok",
  "matched_events": 12,
  "dropped_events": 0,
  "ttl_secs": 60,
  "timestamp": 1781690060
}
```

- `matched_events`：成功投递的事件数。
- `dropped_events`：因通道满而被丢弃的事件数；持续非零说明事件速率超过 `channel_capacity`，应缩小过滤范围或调大容量。
