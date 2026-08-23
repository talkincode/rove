# 反向 hop 数据面（Reverse-Hop QUIC）

当 hop 节点位于 NAT / 防火墙 / 运营商网络 / 私有办公网之后、**edge 无法主动拨号 hop 地址**时，传统的 `http` / `socks5` 上游模型（要求 edge 能连到 hop）就用不了。反向 hop 数据面把方向反过来：**hop 主动用 QUIC 连到 edge**，edge 在这条已认证的长连接上为每个用户连接开一条独立的双向流，作为一条隧道。

- 传输用 QUIC（ALPN `rove-reverse/1`）：自带 TLS 1.3 加密、多路复用双向流、流级流控、流生命周期独立。
- 一条 hop→edge 的出站连接即可满足 NAT/防火墙约束；edge 在已有连接上按需开新流。
- **fail-closed**：edge 若没有目标 `hop_id` 的已认证会话，或开流/握手失败，请求直接报错，**绝不回落直连**。

> 非目标：不拿 MQTT 当隧道传输、不引入 GOST 插件 / chain / hop 图、不把策略/鉴权/计费搬进 `rove-hop`、第一版不做 UDP relay。

## 拓扑与角色

```
        用户 ──HTTP/SOCKS5──▶  edge (rove)  ◀──QUIC(出站)──  hop (rove-hop --reverse-quic)  ──TCP──▶ 目标
                                   │  ReverseHopManager                 │  accept_bi + 拨号 + splice
                                   └── 每个用户连接 = 一条 QUIC 双向流 ──┘
```

- **hop = QUIC 客户端**：主动拨 edge，注册 `hop_id`，然后接受 edge 开过来的隧道流，拨号真实目标并对拼字节。
- **edge = QUIC 服务端**：监听 UDP，认证 hop 的注册帧，维护 `hop_id → connection`；策略命中反向出口时开一条流。
- 一个用户连接映射到一条独立的 QUIC 双向流；单条流上目标拨号失败只影响该流，不会污染整条 QUIC 连接。

### 多 edge 注册（hop 侧）

一个 hop 出口可以同时注册到多个 edge（用户绑定到某个 hop 出口，但可能从不同 edge 入口漫游进来）：

- `rove-hop` 可以用多个 `--reverse-quic` 显式配置多条反向 edge 会话。
- 每条会话有各自的 `edge_id`、地址、令牌、重连循环与观测上下文。
- edge 之间互相不发现、不互为代理、不共享状态；每个 edge 只路由它自己收到并认证过的反向会话。

## 线协议（`rove-reverse/1`）

帧是按行、带版本、有大小上限（4 KiB）的头部块，以空行结尾；读取时逐字节读到空行为止，**不会越读**紧跟在 `OK` 之后、同一条流上的原始隧道字节。

### 注册（hop → edge，每连接一次，走 hop 开的第一条双向流）

```text
REGISTER rove-reverse/1
hop-id: <hop_id>
token: <token>
edge-id: <edge_id>        # 可选，仅用于观测
caps: udp                 # 可选，声明支持的能力（如 udp）；缺省=仅 TCP 隧道

```

> `caps` 是 reverse/2 引入的能力协商位。旧 hop 不带该头 → edge 视为仅支持 TCP，把 UDP association fail-closed 拒绝（`udp_unsupported`），绝不假设支持。新旧 hop 可在同一 edge 混跑。

edge 回复：

```text
OK

```

或

```text
ERR <code>

```

控制流保持打开 = 会话存活信号；连接关闭即注销。

### 隧道（edge → hop，每个用户连接一条流）

```text
CONNECT <host> <port>
tunnel-id: <opaque>       # 可选，仅用于日志/指标

```

hop 回复 `OK` 后，该 QUIC 流上双向承载原始 TCP 字节；或回复 `ERR <code>` 后关闭该流（连接不受影响）。

### 稳定错误码（`ERR <code>`，不含任何密钥）

| code | 含义 |
| --- | --- |
| `unauthorized` | 注册令牌缺失或不被接受 |
| `duplicate_hop_id` | 该 `hop_id` 已有会话且策略为 reject |
| `bad_request` | 帧无法解析（动词/版本/host/port 非法）|
| `connect_failed` | hop 无法连接目标 |
| `at_capacity` | 触达 per-edge 或全局并发隧道上限 |
| `udp_unsupported` | 目标 hop 未声明 `caps: udp`，UDP association 被拒 |
| `udp_at_capacity` | hop 触达 UDP 会话数上限 |
| `internal` | 响应端意外内部错误 |

## reverse/2 UDP relay

reverse/2 在同一条 QUIC 连接上叠加了 **UDP 中继**，供前端的 UDP 出口使用（[TUIC](./tuic.md) 的 `Packet` 与 [SOCKS5 UDP ASSOCIATE](./client-setup.md#socks5-udp-associate) 都接到这里）。它是 Rove 里**唯一可行的非 Direct UDP 出口**（HTTP 上游的 CONNECT 载不了 UDP，SOCKS5 上游依赖外部支持，Direct 无分流意义）。

**传输**：UDP 包走 QUIC **datagram**（不可靠、无序、消息定界，匹配 UDP 语义，无队头阻塞、无重传）；每个 UDP 会话由一条**控制双向流**管理建立/拆除。

**控制帧**（edge → hop）：

```text
ASSOCIATE <session_id>     # edge 分配 session_id（每连接唯一），hop 分配一个出口 socket
assoc-id: <opaque>         # 可选，仅用于日志

```

```text
DISSOCIATE <session_id>    # 拆除会话；控制流关闭也等价于拆除

```

**datagram 载荷**（二进制头 + 原始 UDP 包）：`session_id(4) | atyp(1) | dst_addr | dst_port(2) | payload`。每个包自带目标，一个会话可打到多个目标（与 SOCKS5 UDP 语义一致）。

**hop 侧 NAT 模型**：**每会话一个固定出口 socket（Endpoint-Independent Mapping）** + **address-restricted 过滤**（只放行客户端已联系过目标的回包）。这既能让 client→server 实时流量（WebRTC 到 SFU、游戏到专用服务器）正常工作，又防止 hop 变成开放的 UDP 反射器。**不是** symmetric NAT（会毁掉 ICE 反射候选），**不是** full-cone（P2P 才需要，且受 hop 自身 NAT 限制）。

**策略与安全边界**：目标由 edge 侧逐包 `decide()` 判定，命中 `block` 直接丢弃；未知会话、容量满、无 UDP 能力一律 fail-closed。UDP 会话数、每会话已联系目标集合、DNS 解析缓存均有上限与 idle 驱逐（超时 > 实时保活周期）。UDP 中继不限速（与反向 hop 的 TCP splice 一致）。

**明确不做**：UDP 分片重组（超 datagram 上限的包丢弃并计数）、full-cone / 入站发起的 P2P。

## 边缘配置（edge）

见 [`config.example.toml`](https://github.com/talkincode/rove/blob/main/config.example.toml) 的 `[reverse_hop]` 段：

```toml
[reverse_hop]
enable = true
listen = "0.0.0.0:9443"      # QUIC 监听的 UDP 地址
cert = "./certs/server.crt"  # QUIC 强制 TLS 1.3
key  = "./certs/server.key"
tokens = ["REPLACE_WITH_REVERSE_HOP_TOKEN"]  # 至少一个非空令牌；勿提交真实密钥
duplicate = "reject"         # reject（默认）| replace
max_streams_per_hop = 256    # 单 hop 并发隧道上限
open_timeout_secs = 10       # 开隧道超时（超时按 reverse_open fail-closed）
```

启用时若缺 `listen` / `cert` / `key` / 令牌，或 `duplicate` 非法，启动会 fail-closed 报错。

### 快照里怎么写反向出口

控制面快照（schema v4）把 named egress 的 backend 写成 `kind = "reverse"`、`addr = "<hop_id>"`：

```json
{
  "schema_version": 4,
  "version": 1,
  "users": { "alice": { "password": "example", "policy": "reverse-egress" } },
  "routing_policies": {
    "reverse-egress": {
      "routes": [
        {
          "selectors": ["example.com"],
          "action": { "type": "egress", "egress": "jp" }
        }
      ]
    }
  },
  "egresses": {
    "jp": {
      "type": "upstream",
      "backend": { "kind": "reverse", "addr": "rove-hop-jp" }
    }
  }
}
```

`kind = "reverse"` 的 backend **不允许**再带 `username` / `password` / `tls` / `skip_cert_verify`（认证由 hop 会话令牌负责、加密由 QUIC 负责），否则快照编译期就会被保守拒绝。

## hop 侧运行（`rove-hop --reverse-quic`）

`hop_id` 请使用统一前缀 **`rove-hop-`**（如 `rove-hop-jp`、`rove-hop-cn-office-ax2`），
并与快照 `egresses.*.backend.addr`（`kind = "reverse"`）完全一致。详见 [命名规范](./hop-id-naming.md)。

RouterOS 容器部署（脚本 + 可下载包）：[RouterOS 容器部署 rove-hop](./hop-routeros.md)。

```bash
rove-hop \
  --reverse-quic edge.example.com:9443 \
  --reverse-hop-id rove-hop-jp \
  --reverse-token "$Rove_HOP_REVERSE_TOKEN"
```

多 edge：每个 `--reverse-quic` 开启一条新会话，其后的子标志绑定到最近的那条：

```bash
rove-hop \
  --reverse-hop-id rove-hop-jp \               # 出现在第一个 --reverse-quic 之前 = 各 edge 的共享默认值
  --reverse-quic edge-a.example.com:9443 --reverse-edge-id edge-a \
  --reverse-quic edge-b.example.com:9443 --reverse-edge-id edge-b --reverse-insecure
```

| 标志 | 说明 |
| --- | --- |
| `--reverse-quic ADDR` | edge 反向 QUIC 监听 `host:port`（可重复）|
| `--reverse-hop-id ID` | 前一条 edge 的 hop 身份；出现在首个 `--reverse-quic` 之前则作为共享默认 |
| `--reverse-token TOKEN` | 注册令牌（env：`Rove_HOP_REVERSE_TOKEN`，避免进 argv）|
| `--reverse-edge-id ID` | 前一条 edge 的可选标签（仅日志/指标）|
| `--reverse-server-name NAME` | 校验的证书/SNI 名（默认取 edge host）|
| `--reverse-insecure` | 接受前一条 edge 的自签名 / 纯 IP 证书（显式 opt-in）|
| `--reverse-max-streams N` | per-edge 并发隧道上限（默认 256）|
| `--reverse-initial-mtu N` | 前一条 edge 的固定 QUIC 路径 MTU（UDP 载荷字节，1200-1500）；跑在已压缩/固定 MTU 隧道里时设，不设走默认 PMTUD |
| `--reverse-global-max-streams N` | 跨所有 edge 的全局并发隧道上限（默认 0 = 不限）|

`rove-hop` 可以**只**跑反向会话（不配任何本地 listener）——纯粹作为拨向 edge 的出口。每条会话有独立的、带上限指数退避的自愈重连循环。

## 网络暴露与 NAT 保活

- edge 的 `[reverse_hop].listen` 是 **UDP**（QUIC 跑在 UDP 上），防火墙/安全组要放行**该 UDP 端口**，别只放行同号 TCP。
- 隧道内建 QUIC 保活（间隔 15s，空闲超时 45s），足够压在常见 NAT 的 UDP 映射超时之下，让 hop 的出站映射在没有用户流量时也不被回收；hop 侧无需额外 keepalive。
- hop 到 edge 只需要一条**出站** UDP 流，满足 NAT/防火墙“只出不进”的约束。

## 认证与鉴权边界

- v1 认证 = 注册帧里的**共享令牌**，跑在 QUIC 强制的 TLS 1.3 加密之上。
- hop 可对自签名 / 纯 IP 的 edge 证书用 `--reverse-insecure` 显式跳过证书校验（对齐既有 `skip_cert_verify` 上游开关），绝不是默认行为。
- 令牌只存在于 edge 配置与注册帧中，**从不出现在**访问日志、决策名或错误信息里。

## 可观测性

- **访问日志决策名**：反向路由记为 `reverse:<hop_id>`（如 `reverse:rove-hop-jp`），与直连的 `upstream:<addr>` 可区分，且不含任何密钥。
- **失败阶段**（`failure_stage`）稳定分类，便于 grep 定位反向路由在哪一步断掉：

  | stage | 含义 |
  | --- | --- |
  | `reverse_lookup` | 没有该 `hop_id` 的已认证会话（或反向数据面未启用）|
  | `reverse_open` | 开 QUIC 流 / 写 CONNECT / 读回复 失败或超时 |
  | `hop_connect` | hop 无法连接目标（或触达容量）|
  | `stream_io` | 隧道建立后对拼阶段 IO 失败 |

- **出口维度指标**：edge 侧按 `reverse:<hop_id>` egress 维度计数已建立的隧道；hop 侧反向隧道计在 `reverse` egress 维度，和 hop 自身的普通直连 listener（`direct`）区分开。
- hop 侧结构化日志带 `edge_id` / `hop_id` / `tunnel_id` / `target` / 结果 / 失败阶段等维度。

## 限制

- 每条 QUIC 连接一个 `hop_id`；同一 `hop_id` 的重复注册按 `duplicate` 策略处理（reject / replace）。
- 令牌是共享密钥；mTLS 客户端证书鉴权可作为后续增强。
- UDP 中继见上文 [reverse/2 UDP relay](#reverse2-udp-relay)：只做 native datagram、不分片、不支持 full-cone/P2P，适用于 client→server 实时场景。
