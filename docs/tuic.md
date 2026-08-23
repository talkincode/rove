# TUIC 前端接入（QUIC）

`rove` 除了 TCP 上的 HTTP CONNECT / SOCKS5，还可以开一个 **TUIC v5** 前端入口。它跑在 QUIC（UDP + TLS 1.3）上，面向移动端与实时应用：单 UDP 口、TLS 混淆、客户端生态成熟（Shadowrocket、v2rayN 等），并且能把 **UDP** 一起隧道——这是浏览器代理设置做不到的。

节点的核心角色不变：**本地完成认证、策略分流、限速、连接数限制，失败即拒绝**。TUIC 只是多了一扇 QUIC 前门，出口仍复用现有能力。

> 参考实现：[TUIC v5 协议规范](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)。

## 拓扑

```text
TUIC 客户端 ──QUIC──▶ rove（TUIC 监听）
                         │ authenticate（uuid + token）
                         │ decide() 分流 · 限速 · 连接数
                         ├─ Connect(TCP) ─▶ 现有出口（direct / http / socks5 / reverse）
                         └─ Packet(UDP)  ─▶ 反向 hop UDP 出口（reverse/2）─▶ 媒体/游戏服务器
```

- **TCP（`Connect`）** 直接复用 [`outbound`] 出口选择，**按用户限速**、计连接数、写访问日志，和 HTTP/SOCKS5 完全一致。
- **UDP（`Packet`，native datagram 模式）** 走 [reverse/2 UDP 数据面](./reverse-hop.md#reverse2-udp-relay)，**不限速**（与反向 hop 的 TCP splice 一致），逐包执行策略。

## 认证模型（UUID + Token，独立于登录密码）

TUIC 用 `uuid + token` 而非用户名/密码：

1. 客户端在一条单向流上发 `Authenticate{ uuid(16B), token(32B) }`。
2. `token` 由客户端用 **TLS Keying Material Exporter**（RFC 5705）在当前 TLS 会话上导出：`label = 原始 uuid`，`context = TUIC 密码`，长度 32 字节。
3. 节点用同一 TLS 会话、同样的 label/context 重新导出，**常量时间比对**。这把认证绑定到当前 TLS 握手，天然防重放。

节点侧只做查表归属：快照在编译期建立 `uuid → 用户名` 索引（见[数据模型](./data-model.md#tuic-前端身份)）。**TUIC 凭据独立于登录密码**，泄露前端凭据不会暴露账号登录口令；同一个 `uuid` 被两个用户占用会导致快照编译失败（认证必须无歧义）。

失败即拒绝：未知 uuid、token 不匹配、uuid/token 长度非法、账号过期 —— 一律认证失败并关闭连接；连接在超时时间内未完成认证也会被关闭。

## 配置

```toml
[[tuic_listeners]]
name   = "tuic-in"
listen = "0.0.0.0:8443"        # QUIC 的 UDP ip:port（记得放行 UDP！）
cert   = "./certs/server.crt"  # QUIC 强制 TLS 1.3
key    = "./certs/server.key"
alpn   = ["h3"]                # 必须与客户端配置的 ALPN 一致
[tuic_listeners.sniff]
enabled = true                 # 可选；默认 false
mode = "route"                 # observe | route
max_bytes = 16384
timeout_ms = 500
```

- `[[tuic_listeners]]` 与 `[[listeners]]`（TCP 的 HTTP/SOCKS5）相互独立，可以只开其一、都开、或都不开。
- `cert`/`key` 必填（QUIC 强制 TLS）。缺 `listen`/`cert`/`key` 会在启动时 fail-closed 报错，绝不半配置启动。
- `alpn` 默认 `["h3"]`；改了要让客户端一并改。
- `[tuic_listeners.sniff]` 只处理 TCP `Connect` 的首包并提取 TLS SNI / HTTP Host，不处理 UDP
  `Packet`。`observe` 只记录；`route` 在拨号前让识别域名参与策略，但绝不改写 requested 目标。
- `route` 中 requested/sniffed 任一命中 block 都拒绝；只有 requested 是 IP 时，sniffed 域名才能命中
  proxy 规则选择出口。识别失败或超时回退 requested 决策，已读取字节原样回放。

要让某个用户能用 TUIC，控制面需要在快照里给该用户配 `frontends.tuic`（uuid + password）：

```jsonc
{
  "schema_version": 4,
  "users": {
    "alice": {
      "password": "login-only-secret",         // 登录密码（HTTP/SOCKS5）
      "policy": "media",
      "frontends": {                            // 按协议命名空间的前端凭据
        "tuic": {
          "uuid": "550e8400-e29b-41d4-a716-446655440000",
          "password": "front-end-only-secret"   // 独立于 password
        }
      }
    }
  }
}
```

> `frontends` 是按协议命名的凭据表（`frontends.<协议>`）。将来新增前端协议（如 Trojan / VLESS）只需加一个协议条目，不动顶层 schema，且可按协议独立启停 / 轮换。

## UDP 出口：必须落在反向 hop

TUIC 的 UDP 只经 **reverse/2 UDP 出口**（唯一可行的非 Direct UDP 出口）。要让某用户的 UDP 打到目标服务器，其 routing policy 必须把目标路由到一个 `reverse` named egress（`backend.kind = "reverse"`，`addr = hop_id`）：

```jsonc
{
  "schema_version": 4,
  "routing_policies": {
    "media": {
      "routes": [],
      "default_egress": "tokyo"
    }
  },
  "egresses": {
    "tokyo": {
      "type": "upstream",
      "backend": { "kind": "reverse", "addr": "rove-hop-jp" }
    }
  }
}
```

- 命中 `block` action 的目标：**逐包丢弃**，绝不出 hop。
- 决策落到 Direct / HTTP 上游 / SOCKS5 上游的 UDP 包：**fail-closed 丢弃**（HTTP CONNECT 物理上载不了 UDP；Direct/SOCKS5-UDP 出口不在当前范围）。
- 目标 hop 未声明 UDP 能力（旧版 hop）：association 直接被拒（`udp_unsupported`）。
- 决策落到[出口链（chain）](./data-model.md#出口链chains与主备故障转移)时：只在 chain 的
  **reverse 成员**中按优先级尝试；chain 只有 HTTP/SOCKS5 成员时同样 fail-closed 丢弃。
  association 建立后粘住选中的 hop，不逐包切换。UDP 主备需要 chain 里至少两个 reverse 成员。

适用场景是 **client → server 的实时 UDP**：WebRTC 连 SFU / 媒体服务器、OpenAI Realtime（WebRTC 变体）、游戏连专用服务器。详见 [reverse/2 UDP relay](./reverse-hop.md#reverse2-udp-relay)。

## 限制（当前范围）

- **只做 native（QUIC datagram）UDP 模式**，不做 quic-stream 可靠模式（会引入 HOL 阻塞，毁掉实时语义）。
- **不做 UDP 分片重组**：单个 UDP 包超过 QUIC datagram 上限（约 1200B）会被丢弃并计数。目标实时应用（WebRTC/DTLS/SRove、游戏网络码）本就 MTU 感知，不受影响。
- **不支持 full-cone / 浏览器↔浏览器 P2P 打洞**：一是需要更宽松的 NAT（攻击面大），二是出口 hop 自身往往也在 NAT 后，物理上打不通。client→server 场景不受此限。
- UDP relay 不参与令牌桶限速；如需限额，先用连接/会话上限与目标端口约束兜底。

## 可观测性

- 每条 TCP `Connect` 隧道结束写一条访问日志记录（`protocol: "tuic"`，含用户、目标、决策、字节数、时长），复用现有 [访问日志](./access-log.md) 管线，永不含密码。启用 sniff 后还会写 requested/sniffed/effective identity 与固定结果枚举；route 模式的策略阻断和出站失败也会落记录。
- 连接建立/认证成功/失败通过结构化 `tracing` 日志输出。

## 客户端配置

见 [客户端接入 · TUIC](./client-setup.md#tuic-客户端)。要点：客户端的 `uuid`/`password`/`alpn` 必须与快照凭据和监听 `alpn` 对齐；自签名证书需在客户端开启「允许不安全 / skip-cert-verify」或导入 CA。

[`outbound`]: ./data-model.md#二级代理upstream
