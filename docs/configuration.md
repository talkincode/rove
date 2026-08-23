# 配置详解

Rove 用一个扁平的 TOML 文件配置。对比 GOST 一大堆 services / chains / hops / connectors，这里一个节点
只回答三件事：**我是谁、控制面在哪、监听哪些口**。访问日志默认开启；SNMP、MQTT、反向 hop 等能力默认关闭。

完整可复制的样例见仓库根目录的
[`config.example.toml`](https://github.com/talkincode/rove/blob/main/config.example.toml)。
本章逐段解释。

---

## 节点身份

```toml
node_id = "edge-tokyo-01"
```

节点的唯一标识。它会出现在访问日志、SNMP、MQTT 消息里，也用于从快照的 `node_overrides` 里挑出属于本节点的
分组覆盖（见 [控制面同步协议](./snapshot-protocol.md)）。同一 fleet 内务必唯一、稳定。

---

## `[control_plane]` 控制面

用户与策略的**唯一真相来源**。节点只拉取编译好的快照，不在本地管理用户。

```toml
[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "REPLACE_WITH_NODE_TOKEN"
poll_interval_secs = 30
cache_path = "./data/snapshot.json"
```

| 字段 | 说明 |
|---|---|
| `snapshot_url` | **完整地址**，节点原样请求，只会追加 `?since=` 或 `&since=`，**不会拼接任何固定路径**。填控制面实际暴露的那个地址。 |
| `token` | 请求头 `Authorization` 携带的节点令牌。所有节点可共用同一个 URL 和令牌。 |
| `poll_interval_secs` | 轮询周期。连续失败会指数退避，最高退到 5 分钟或该值（取较大者）。 |
| `cache_path` | 本地快照缓存。**启动先读它**，实现离线/控制面不可达时的热启动。Unix 上写入权限为 `0600`。 |

工作方式：启动 → 读缓存立即服务 → 后台立刻拉一次控制面 → 之后按周期轮询。拿到新版本先解码编译验证，
只有可服务的快照才会原子写回缓存并热替换。`304` 或 `version <= since` 时静默、不重编译。
详见 [控制面同步协议](./snapshot-protocol.md)。

---

## `[health]` 存活与就绪探针（默认关闭）

```toml
[health]
enable = false
listen = "127.0.0.1:9090"
control_plane_unreachable_secs = 90
```

| 字段 | 说明 |
|---|---|
| `enable` | 是否启动独立 HTTP 探针端口。 |
| `listen` | 探针监听地址；默认仅回环，若暴露到其它网络应由防火墙限制来源。 |
| `control_plane_unreachable_secs` | 已有可服务快照时，控制面连续失败多久后把 readiness 标为 degraded。短暂抖动不会立即摘除节点。 |

- `GET /healthz`：进程能响应即返回 `200`。
- `GET /readyz`：仅在已加载快照、至少一个显式配置的 TCP/TUIC listener 仍活跃、未进入停机排空、控制面未持续不可达时返回 `200`；否则返回 `503`。仅启用 Subnetra hub、未配置 TCP/TUIC listener 时不要求该计数。
- JSON 只包含程序版本、快照版本/schema、同步时间与失败计数，不包含 URL、令牌、用户、密码或策略内容。
- JSON 的 `data_plane.required` 与 `data_plane.active_listeners` 可直接说明 listener readiness 的判定依据。

## `[shutdown]` 优雅停机

```toml
[shutdown]
grace_period_secs = 30
```

收到 `SIGINT` / `SIGTERM` 后，节点立即停止 TCP、TUIC 与 Subnetra hub 的新接入，并等待在途代理连接完成。
超过 `grace_period_secs` 后仍未结束的连接会被强制终止，进程随后以正常退出码结束。排空开始、完成或超时都会写运行日志。

---

## `[[listeners]]` 监听入口

可配置任意多个。`protocol` 决定协议，是否存在 `[listeners.tls]` 决定是否升级为 TLS 变体。`socks5` 入口支持 UDP ASSOCIATE（UDP 出口经反向 hop，见 [客户端接入 · SOCKS5 UDP ASSOCIATE](./client-setup.md#socks5-udp-associate)）。

```toml
# 明文 HTTP 应用入口（HTTPS 用 CONNECT；http:// 用 absolute-form）
[[listeners]]
name = "http-in"
protocol = "http"
listen = "0.0.0.0:8080"

# 加 TLS 段 → HTTPS（HTTP CONNECT over TLS）
[[listeners]]
name = "https-in"
protocol = "http"
listen = "0.0.0.0:8443"
[listeners.tls]
cert = "./certs/server.crt"
key  = "./certs/server.key"

[[listeners.tls.certificates]]
server_names = ["proxy.example.net"]
cert = "./certs/proxy.example.net.crt"
key  = "./certs/proxy.example.net.key"

# 明文 SOCKS5
[[listeners]]
name = "socks5-in"
protocol = "socks5"
listen = "0.0.0.0:1080"

# 加 TLS 段 → SOCKS5-over-TLS
[[listeners]]
name = "socks5tls-in"
protocol = "socks5"
listen = "0.0.0.0:1081"
[listeners.tls]
cert = "./certs/server.crt"
key  = "./certs/server.key"
```

| 字段 | 说明 |
|---|---|
| `name` | 入口名，用于日志/统计聚合。 |
| `protocol` | `http`（CONNECT + 明文 HTTP absolute-form）或 `socks5`（RFC1928 + 用户名密码认证）。 |
| `listen` | 监听地址 `ip:port`。 |
| `[listeners.tls].cert` / `.key` | PEM 默认证书与私钥。存在此段即在监听层包裹 TLS；客户端未发送 SNI 或名称未命中时返回这张证书。 |
| `[[listeners.tls.certificates]]` | 可重复的 SNI 证书映射；`server_names` 是选择该 `cert` / `key` 的精确 DNS 名称列表。 |
| `[listeners.sniff]` | 可选 TCP 首包观察；默认关闭。`observe` 只记日志；`route` 按嗅探域名选 hop / 阻断（仅 CONNECT）。 |

**协议与 TLS 正交**：`http` + TLS = `https`，`socks5` + TLS = `socks5tls`。四种入口任意组合。
一个 TCP listener 可通过 `[[listeners.tls.certificates]]` 在同一 IP、端口和进程内按 ClientHello SNI
选择多张证书，无需为每个域名复制 listener 或 Rove 实例。域名匹配不区分大小写，但配置项必须唯一；
每张额外证书至少声明一个域名。空域名列表、重复域名、证书不覆盖声明域名、证书与私钥不匹配都会
让启动失败。SNI 只负责选证书，不参与用户认证、策略或租户隔离。

本地 Docker 验收可运行 `./scripts/accept-local-tls-sni.sh`。脚本会在主机 `18443` 端口启动同一
Rove listener，分别验证 `local-rove` 与 `alt.local-rove` 的证书指纹，并通过两个域名各完成一次
HTTP CONNECT；可用 `Rove_SNI_ACCEPT_PORT` 覆盖主机端口。

节点会在启动后台服务前绑定并校验全部 TCP/TUIC listener；任一显式配置的地址、协议、证书或私钥无效都会让启动非零失败，而不是留下缺失入口后继续报 ready。
HTTP absolute-form 转发与 CONNECT 共用认证、过期、策略、连接数、限速和访问日志语义；代理会移除
`Proxy-Authorization` 等逐跳头、把请求行改为 origin-form，并强制单请求连接关闭。它不做透明代理、
缓存、内容改写或浏览器网关。

需要为精细化运营补充隧道内域名，或按嗅探域名分流时，可在任一 HTTP/SOCKS5 listener 上打开 sniff：

```toml
[listeners.sniff]
enabled = true
mode = "route"     # observe = 只记日志；route = 先回 200/SOCKS5 成功再读首包，然后按域名选 hop / 阻断
max_bytes = 16384  # 1..65536；达到上限后记 limit_exceeded，已读字节仍回放
timeout_ms = 500   # 1..5000；route 会等待这个窗口，observe 不会延迟首包
```

识别器只看 client→target 的连接起始字节（TLS ClientHello SNI 或 HTTP/1 Host）。`observe` 不改变握手/拨号时序；
`route` 仅作用于 HTTP CONNECT 与 SOCKS5 CONNECT：先向客户端确认隧道，再读首包、用 requested + sniffed
双候选决策，然后才拨出。绝对形式 HTTP 转发与 UDP ASSOCIATE 不走 route。结果写入访问日志及 listener
固定枚举计数；不保存 URL、HTTP body、header 集合或 TLS payload。ECH 内层域名、QUIC/HTTP3 和 UDP 不可见。

`route` 与 TUIC 共用同一套安全规则（见下方 `[tuic_listeners.sniff]`）：任一候选命中 block 即拒绝；只有
requested 是 IP 时 sniffed 域名才能命中 egress route 选择出口；实际拨号目标永不改写。timeout / unsupported /
malformed 回退到只按 requested host 决策，已读字节照常回放。
客户端怎么连见 [客户端接入](./client-setup.md)。

---

## `[log]` 运行日志

```toml
[log]
level = "info"   # error | warn | info | debug | trace
```

这是 `tracing` 的运行日志等级，和结构化访问日志、MQTT 诊断相互独立 —— 把 `level` 调到 `error`
也不会影响访问日志的完整记录。

---

## `[access_log]` 访问日志（默认开启）

每条完成的连接落一行 JSON，是排查「某用户/某目标连不上」时 `grep` 的对象。

```toml
[access_log]
enable = true
dir = "./logs"
file_prefix = "access"
retention_days = 7
channel_capacity = 8192

[access_log.syslog]
enable = false
address = "syslog.example.com:514"
protocol = "udp"    # udp | tcp
facility = "local0"
tag = "rove"
```

字段含义、记录形状与 syslog 转发细节见 [访问日志](./access-log.md)。默认不建议在生产关闭。

---

## `[mqtt]` 异步运维通道（默认关闭）

网络隔离场景下，节点主动连 MQTT broker，响应用户策略查询、同步指令、拨测追踪。

```toml
[mqtt]
enable = false
broker = "tcp://mqtt.example.com:1883"   # 或 ssl://...:8883
client_id = ""                            # 留空用 rove-<node_id>
username = ""
password = ""
qos = 1
reply_topic_prefix = "rove/replies/"

[mqtt.topics]
user_query = "rove/user/query"
sync_command = "rove/sync/command"
node_status = "rove/node/status"
probe_trace = "rove/probe/trace"
diagnostics_command = "rove/diagnostics/command"

[mqtt.diagnostics]   # 诊断会话的安全上限（爆炸半径），不是开关
default_ttl_secs = 30
max_ttl_secs = 300
max_sessions = 16
max_sessions_per_user = 2
channel_capacity = 256

[mqtt.tls]
enable = false
```

消息契约见 [MQTT 运维通道](./mqtt-integration.md)。
建议把 broker 凭据放在独立的 `username` / `password` 字段；即使兼容 URL userinfo，启动日志也只记录 broker 的 scheme、host 与 port。

---

## `[snmp]` 只读 SNMP agent（默认关闭）

供 Cacti / LibreNMS 等标准 NMS 直接轮询每 listener、每出口的流量计数。

```toml
[snmp]
enable = false
listen = "0.0.0.0:161"
community = ""                              # v2c community；留空则 v2c 关闭
allow_cidrs = ["127.0.0.1/32", "::1/128"]  # 来源白名单，白名单外直接丢弃
state_path = "./data/snmp-state.json"      # v3 engineBoots 持久化

# SNMPv3 USM 用户（可多个）
# [[snmp.v3_users]]
# username = "cacti"
# auth_protocol = "sha256"      # sha1 | sha256
# auth_password = "change-me-auth"
# priv_protocol = "aes128"      # 留空表示不加密
# priv_password = "change-me-priv"
```

只实现 GET / GETNEXT / GETBULK，**SET / TRAP / INFORM、MD5 / DES 永不支持**。MIB 表与 Cacti 接入见
[SNMP 监控](./snmp-cacti.md)。

---

## `[reverse_hop]` 反向 hop 数据面（默认关闭）

当 hop 位于 NAT / 防火墙后、edge 无法主动拨号时，改由 hop 用 QUIC 主动拨到 edge 注册。

```toml
[reverse_hop]
enable = false
listen = "0.0.0.0:9443"           # QUIC 的 UDP 监听地址（放行 UDP！）
cert = "./certs/server.crt"       # QUIC 强制 TLS 1.3
key  = "./certs/server.key"
tokens = ["REPLACE_WITH_REVERSE_HOP_TOKEN"]
duplicate = "reject"              # 同 hop_id 重复注册：reject | replace
max_streams_per_hop = 256
open_timeout_secs = 10
# initial_mtu = 1332              # 可选：固定 edge 侧 QUIC 路径 MTU（UDP 载荷字节，1200-1500）
```

原理、多 edge、观测与 NAT 保活见 [反向 hop 数据面](./reverse-hop.md)。

> **压缩隧道适配**：当 edge/hop 之间的 QUIC 跑在已被压缩、路径固定的外层隧道里时，用
> `initial_mtu` 固定 QUIC 的最大 UDP 载荷（≈ 隧道路径 MTU 减去 IPv4 的 28 或 IPv6 的 48
> 字节），quinn 便从该值起步且不再向上探测，避免大包被载体静默丢弃。edge 侧写在
> `[reverse_hop].initial_mtu`；hop 客户端（`rove-hop`）侧用 `--reverse-initial-mtu`。留空则走
> quinn 默认 PMTUD（从 1200 起步向上发现），QUIC 本身可自愈，一般无需设置。

## `[[reverse_ingress]]` NAT 后反向公网入口（默认关闭）

Rove 接入点位于 NAT 后时，主动连接公网 `rove-relay`，在 relay 上申请预授权
TCP/UDP 端口。配置可重复，每段独立连接一个 relay：

```toml
[[reverse_ingress]]
enable = true
relay = "relay.example.com:9444"
server_name = "relay.example.com"
token_env = "Rove_INGRESS_RELAY_TOKEN"
initial_mtu = 1452
max_streams = 1024
max_udp_flows = 4096
reconnect_min_secs = 1
reconnect_max_secs = 30

[[reverse_ingress.listeners]]
id = "https-public"
transport = "tcp"
public_port = 443
local_listener = "https-in"

[[reverse_ingress.listeners]]
id = "tuic-public"
transport = "udp"
public_port = 8443
local_listener = "tuic-in"
max_inner_datagram = 1200
```

`local_listener` 只能引用本配置已声明的 listener；relay 不能要求 Rove 连接任意
内网地址。`public_port = 0` 表示动态分配。证书、relay 配置、真实 IP 溯源、
MTU 与故障语义见 [反向公网入口](./reverse-ingress.md)。

## `[[tuic_listeners]]` TUIC 前端入口（QUIC，可选）

QUIC 原生前门，面向移动端与实时应用；能隧道 UDP。与 `[[listeners]]`（TCP）相互独立。

```toml
[[tuic_listeners]]
name   = "tuic-in"
listen = "0.0.0.0:8443"        # QUIC 的 UDP ip:port（放行 UDP！）
cert   = "./certs/server.crt"  # QUIC 强制 TLS 1.3
key    = "./certs/server.key"
alpn   = ["h3"]                # 必须与客户端一致
# initial_mtu = 1332           # 可选：固定 QUIC 路径 MTU（UDP 载荷字节，1200-1500），压缩隧道用
[tuic_listeners.sniff]
enabled = true
mode = "route"                 # observe | route；UDP Packet 不处理
```

认证用快照里的 `frontends.tuic`（uuid + password，独立于登录密码）。TCP 请求复用现有出口并按用户限速；
UDP 请求走反向 hop 的 UDP 出口。`initial_mtu` 与 `[reverse_hop]` 同义（跑在压缩/固定 MTU 隧道里才需设）。
`[tuic_listeners.sniff]` 与 TCP listener 使用相同边界，但只包裹 TUIC TCP Connect。完整说明见
[TUIC 前端接入](./tuic.md)。

HTTP/SOCKS5 CONNECT 与 TUIC TCP Connect 的 `route` 模式共用同一套规则。TUIC 在 outbound connect 前读取首包；HTTP/SOCKS5 必须先向客户端确认隧道，客户端才会发送首包。窗口均为 `timeout_ms` / `max_bytes`：

- requested host 与 sniffed host 任一命中 block 都拒绝，block 永远优先；
- 只有 requested host 是 IP 时，sniffed 域名才能命中 proxy 规则选择出口；
- 实际 CONNECT/直连目标始终是 requested host/port，嗅探域名不会改写目的地址；
- timeout、unsupported、malformed、limit_exceeded 或 incomplete 均回退到 requested host 决策；
- 已读取字节通过前缀流逐字节回放，仍进入原有限速和流量统计。

## `[subnetra]` 内嵌组网底座（默认关闭）

原生实现 Subnetra v1 加密 Layer-3 隧道，在 overlay 上跑 HTTP/SOCKS——无需单独部署守护进程、
无需 TUN。`mode = "hub"` 接受 spoke 充当隧道内代理入口；`mode = "spoke"` 拨到 hub，把流量从
overlay 打进隔离网段。hub / spoke 共用同一份数据面。

```toml
[subnetra]
enable = true
mode = "hub"                  # "hub"（收 spoke、代理入口）| "spoke"（拨 hub、egress）
local_id = 1                  # 本节点 mesh id，0 < id <= 65535
listen = "0.0.0.0:18020"      # 数据面 UDP 绑定地址（放行 UDP！）
overlay_cidr = "10.0.0.1/24"  # 本节点 overlay 地址（主机位=inner IP，前缀=虚拟子网）
obfuscate = true              # 头部混淆，默认开；必须全网一致，否则 fail-closed
keepalive_secs = 25           # spoke NAT 保活间隔（秒），hub 忽略
# mtu = 1360                   # 可选：内层 overlay MTU，范围 [576, 1452]，默认 1452（压缩隧道用）
proxy_protocol = "http"       # 仅 hub：overlay 上服务的协议 "http" | "socks5"
proxy_port = 8080             # 仅 hub：overlay IP 上的代理端口

[[subnetra.peers]]
id = 2
psk = "REPLACE_LINK_1_2_64_HEX_CHARS"   # 每条链路唯一的 32 字节（64 hex）预共享密钥
allowed_src = "10.0.0.2/32"             # 内源过滤前缀，也是路由键
endpoint = "203.0.113.2:18020"          # hub 可留空（学习得到）；spoke 必填
name = "bj-spoke"
```

校验 fail-closed（psk 长度/字符、id 冲突、spoke 缺 endpoint、hub 缺 proxy 设置等启动即报错）。
**hub 节点即便没有任何 `[[listeners]]` 也能启动**（代理入口在 overlay）。作为出口时在快照里把
`upstream.kind` 写成 `subnetra`。`mtu` 用于让整张 mesh 适配已被压缩、路径固定的外层隧道（默认
1452；只调本节点发包大小与通告 MSS，不改协议线格常量，与旧节点互通不受影响）。原理、拓扑与
注意事项见 [内嵌 Subnetra 组网底座](./subnetra.md)。

## `[dns]` 专用出口 DNS（默认关闭）

默认 Rove 用操作系统解析器（`getaddrinfo`）解析出口目标，行为与旧版逐字节一致。当宿主机的
`/etc/resolv.conf` 指向分裂视图或不被信任的解析器，而网络里另有指定递归解析器时，配上
`[dns].servers`：Rove 便把**所有出口域名解析**——直连（`Direct`）、上游代理拨号（`dial`）、
reverse UDP 解析、edge 拨号——统一改走这些服务器，绕开宿主机配置。`servers` 为空或整段缺省即
无操作，继续用系统解析器（完全向后兼容，仅在显式配置时生效）。

```toml
[dns]
servers = ["10.0.0.53", "10.0.0.54:5353"]  # ip 或 ip:port；默认端口随传输
protocol = "udp"        # udp（默认）| tcp | tls/dot | https/doh
timeout_ms = 2000       # 单次查询超时（毫秒）
attempts = 2            # 每台服务器的重试次数
ipv4_first = true       # 优先 IPv4（先查 A 再查 AAAA）
cache_size = 64         # 内存 answer 缓存条数；0 关闭
```

配置解析 fail-closed：`servers` 里出现非法 `ip` / `ip:port`，或 `protocol` 不是
`udp`/`tcp`/`tls`(`dot`)/`https`(`doh`)，启动即报错（避免拼错时静默回落系统解析器）。UDP 应答被
截断时会自动改用 TCP 重试（部分解析器会返回较大的 EDNS 应答）。字面量 IP 目标不走 DNS，直接连接。

### 加密 DNS（DoT / DoH）

明文 UDP/TCP DNS 仍可能被链路上抢先注入伪造应答。跨不可信链路解析时，
建议用 **DoT（DNS-over-TLS，853）** 或 **DoH（DNS-over-HTTPS，443）**——它们对查询加密、校验服务器
证书。默认端口随传输自动选择（`tls`=853、`https`=443），bare IP 无需写端口。

```toml
[dns]
servers = ["1.1.1.1"]                 # DoT 到 Cloudflare；bare IP 自动用 853
protocol = "tls"                      # 或 "dot"
tls_server_name = "cloudflare-dns.com"  # 必填：SNI + 证书校验名
# doh_path = "/dns-query"             # 仅 DoH（protocol = "https"），默认 /dns-query
# tls_ca = "/etc/rove/dns-ca.pem"      # 自建服务器的私有 CA；留空=Mozilla 公共根 + Rove_EXTRA_CA_CERTS
# tls_insecure = false                # 跳过证书校验（自签名）——危险
```

信任根按优先级：`tls_insecure`（接受任意证书，仅自签名逃生用）> `tls_ca`（只信这份 CA，适合自建
内部 DNS）> 默认 Mozilla webpki 根（加上 `Rove_EXTRA_CA_CERTS`，适合公共 DoT/DoH）。`tls`/`https`
未填 `tls_server_name` 会 fail-closed 报错。若服务器证书用 IP-SAN，把 `tls_server_name` 填成该 IP。
加密传输走 `ring`，不引入 `aws-lc-rs`。

> **rove-hop 独立二进制**：`rove-hop` 不读该 TOML 段，但支持等价的命令行开关
> `--dns-server`（可重复）/ `--dns-protocol`（`udp|tcp|tls|https`）/ `--dns-server-name` /
> `--dns-doh-path` / `--dns-ca` / `--dns-insecure`，让位于目标网络里的 hop 也能把出口目标解析
> 走到指定解析器；不设则回落系统解析器。

## `[addrbook]` 版本化地址数据集（默认关闭）

```toml
[addrbook]
path = "/etc/rove/addrbook/book.rab"
poll_interval_secs = 300
```

| 字段 | 说明 |
|---|---|
| `path` | `rove-abctl build` 产出的本地 `.rab` 工件。配置后缺失、不可读、超过 256 MiB 或校验失败都会拒绝启动。 |
| `poll_interval_secs` | 缺省 `300`；轮询本地文件变化并尝试原子热替换。`0` 表示只在重启时加载。 |

控制面快照可在 route `selectors` 里用 `book:<category>` 引用层级分类；`book:` 规则不需要额外
schema 版本门槛。未配置地址簿、未知分类或 selector 内存超限会拒绝整份新快照并保留旧策略。
运行期新工件必须先通过完整格式校验，再用它重新编译最近一次成功快照；任一步失败都保留旧书与旧快照。

Rove 不读取 manifest、不自动下载工件。生产应在独立发布流程中执行 `fetch → build → verify/query → diff`，
通过受认证通道分发，并在同一目录内原子替换文件。Docker 热更新应挂载整个目录而不是单个文件。
完整流程、六种数据源、CLI、限制与回滚见 [rove-addrbook 指南](./addrbook-format.md)。

---

## 小结

- **必填**：`node_id`、`[control_plane]`，以及至少一个 `[[listeners]]` 或 `[[tuic_listeners]]`（**例外**：启用 `[subnetra]` 的 hub 走 overlay 入口时可不配置 TCP/TUIC listener）。
- **建议保留默认开启**：`[access_log]`。
- **按需开启**：`[mqtt]`、`[snmp]`、`[reverse_hop]`、`[subnetra]`、`[dns]`、`[addrbook]`。
- 证书、令牌、缓存等敏感/本地文件不要提交进仓库；示例里一律用占位符。
