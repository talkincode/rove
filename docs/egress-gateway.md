# 应用出口网关

> **状态：T1 SNI 透明网关已交付；T2 声明式 HTTPS 网关仍在规划；T3 明确不做。**
> T1 的实际配置见[配置详解](./configuration.md)，已有代理客户端仍应使用
> HTTP CONNECT、SOCKS5 或 TUIC，见[客户端接入](./client-setup.md)。

应用出口网关让不能设置 `HTTP_PROXY` 或 SOCKS 的应用，也能复用 Rove 的身份、策略、出口选择、限速和审计。
它是新的 **listener adapter**，不是 reverse proxy，更不是把客户端给出的 Host 或 URL 变成任意拨号目标。

---

## 先把三个容易混的词分开

| 名字 | 方向 | 现在有没有 | 实际做什么 |
|---|---|---|---|
| [反向 hop](./reverse-hop.md) | 出向（egress） | 有 | NAT 后的出口节点用 QUIC **主动回连** edge，成为一个 egress backend |
| [反向公网入口](./reverse-ingress.md) | 入向（admission） | 有 | NAT 后的节点通过公网 `rove-relay` **接受入站代理连接** |
| **应用出口网关**（本章） | 入向（gateway） | **T1 有** | 应用把受控 DNS 名称连到 Rove，Rove 只允许服务端配置的 origin，再走既有策略与出口 |

需要把内网服务发布到公网，用 reverse ingress、[Subnetra](./subnetra.md)，或在 Rove 前面放 nginx / Envoy。
那不是本能力要做的事。

---

## 三层，不是一个功能

| 层 | 形态 | 状态 |
|---|---|---|
| **T1 SNI 透明网关** | DNS 把允许的域名指到 Rove；读 ClientHello SNI，对照闭合 origin 白名单，TLS **不终止**，按字节转发 | **已交付** |
| **T2 L7 HTTPS 网关** | 客户端把 `base_url` 指到网关；按 endpoint 查服务端声明的 origin，终止 TLS 后再出站 | 规划中 |
| **T3 通用反代 / API 网关** | 虚拟主机、ACME、后端池、健康检查、重写、WAF | **明确不做** |

三者都只能接到同一条
`identity → policy → route → egress → transport → observability` 主干上；策略层和出口层不为网关另起炉灶。

| 入口 | identity 来源 | target 来源 |
|---|---|---|
| HTTP CONNECT | `Proxy-Authorization` | 客户端 CONNECT 行 |
| SOCKS5 | RFC 1929 | 客户端请求 |
| TUIC | `frontends.tuic` | 客户端请求 |
| **sni（T1）** | listener 绑定的快照用户 | ClientHello SNI ∩ **本地闭合白名单** |
| **gateway（T2，规划）** | `frontends.gateway` bearer token | **服务端声明的 endpoint → origin 表** |

---

## T1｜SNI 透明网关

DNS（split-horizon、CoreDNS rewrite 或受管 hosts）把目标 DNS 名称指到 Rove。应用仍以原始名称发起 TLS；
Rove 在有界窗口内解析 ClientHello 的 SNI，只有它同时满足有效 TLS、规范 DNS 名和本机 `origins` 白名单时，
才会套用 listener 绑定身份的策略、选择出口、回放已读字节并继续透传。

它**不终止 TLS**：节点看不到 HTTP 内容、不持有 origin 证书、不接触 API key。治理的是路径，不是数据。

### 配置

```toml
[[listeners]]
name     = "egress-sni"
protocol = "sni"
listen   = "0.0.0.0:443"
identity = "team-agent"
origins  = [
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
]

# 可选：限制读 ClientHello 的时间和字节数；T1 始终使用这两个上限。
[listeners.sniff]
max_bytes = 16384
timeout_ms = 500
```

- `identity` 必填，且连接建立时必须在**当前快照**中存在且未过期；未知或过期身份直接断开。
  它没有客户端凭据，因而不能省略身份或使用匿名回退。
- `origins` 至少一个。只接受精确 DNS 名；大小写和末尾点会规范化，URL、IP、通配符、无效或重复名称会使配置校验失败。
- `protocol = "sni"` **禁止** `[listeners.tls]`。它透传客户端原始 TLS，而不是接收 TLS 后再解密。
- SNI 中没有端口。Rove 将应用连接到的 listener 端口作为 origin 端口：通常把 DNS 改写到 `:443`，所以它也拨 `:443`；
  使用非 443 端口时必须确保 origin 在同一端口服务。
- `sniff.enabled` 与 `sniff.mode` 不改变 T1 的准入语义；T1 总会在 `max_bytes` / `timeout_ms` 上限内读取 ClientHello。

### 实际数据路径

```text
应用 ── TLS ClientHello(SNI=api.example.com) ──► Rove :443
                                                     │
          快照身份有效 + 精确 origins 命中          │
                                                     ▼
                     identity → policy → route → egress → TLS origin :443
```

实现复用 `sniff` 的受限 ClientHello 解析、`PrefixedIo` 的字节回放、`decide_with_sniff` 的策略决策、
`outbound::connect` 的 direct / HTTP / SOCKS5 出口，以及 `splice` 的双向传输和限速。访问日志和诊断仍会记录
策略、出口和失败阶段；T1 成功或策略处理的记录额外带 `ingress_mode: "sni"` 和服务端 origin 标识，
不记录路径、请求头、请求体或 TLS payload。

### 失败即断开

T1 没有 HTTP 错误页：以下情况均在**拨出前关闭 TCP**，没有默认 origin、没有直连回退、没有按任意 SNI 拨号：

| 情形 | 行为 |
|---|---|
| 配置缺少 identity / origins，白名单无效或误配 TLS | 启动前配置校验失败 |
| 当前快照没有绑定身份，或用户已过期 | 关闭连接 |
| 非 TLS、ClientHello 畸形、超时、超限、ECH 导致无可见 SNI | 关闭连接 |
| SNI 不在 `origins` | 关闭连接 |
| 策略结果为 `block`、连接数超限、出口拨号失败 | 关闭连接 |

T1 不支持 QUIC / HTTP/3，也不能读取 ECH 的内层名称。若应用只能改 `base_url`、不能保持原始 DNS 名和 TLS SNI，
请等待 T2，而不是把 Host 当作任意目标地址。

**这是 L4/SNI 边界，不是 HTTP 语义检查。** TLS 建立后 Rove 不可见加密请求中的 Host、CONNECT 或业务协议；
不要把允许的 CDN、共享 HTTPS 代理或可 domain-front 的名称当作“只允许某个应用 API”的证明。需要应用层 origin
约束时，应使用专用、不可共享的 origin，或等待会终止 TLS 的 T2。

### 部署注意事项

DNS 改写只应覆盖 `origins` 中的名称，并让客户端的 TLS 校验继续使用原始 origin 名称。Rove 自己的 egress DNS
必须把该名称解析到**真正的 origin**，不能再次解析到本 gateway；需要时配置独立的 `[dns]`、split-horizon 视图或
将网关监听地址从 egress DNS 回答中排除，否则会形成自我回环。

`identity` 是服务端对整条 listener 的归属，不是终端用户认证。若多租户之间需要不同策略或审计身份，应配置多个
SNI listener，并使用各自的端口 / 地址 / DNS 视图和快照用户；不要用一个 listener 承载不受控名称。

---

## T2｜L7 HTTPS 网关（规划中）

客户端把 SDK 的 `base_url` 指到网关，带 `Authorization: Bearer …`。网关将按 endpoint（Host，可选 path 前缀）
查**服务端声明的 origin**，再走既有策略与出口。

**生死线：origin 只能来自节点本地配置或控制面快照，绝不能来自客户端的 Host、URL 或路径。** 否则这不是网关，
而是带 TLS 的开放正向代理，也是 SSRF 入口。未命中的 Host 必须拒绝，不能按 Host 拨号。

T2 预计使用独立的 `frontends.gateway` 身份命名空间，并默认不把 path、query、请求头写入访问日志。它不做请求体
解析、API key 注入或轮换、模型路由、响应缓存、证书签发、后端池、重写或 WAF。

---

## T3｜通用反向代理 —— 不做

虚拟主机、ACME 自动签发、后端池与负载均衡、主动健康检查、灰度、重写规则和 WAF 是 nginx / Envoy / Traefik 的产品，
不是 Rove 的。发布内网服务用 [反向公网入口](./reverse-ingress.md) 或 [Subnetra](./subnetra.md)；更复杂的 HTTP
入口放在 Rove 前面。

---

## 怎么选

| 我想…… | 使用方式 |
|---|---|
| 应用能配 `HTTP_PROXY` / SOCKS / TUIC | [客户端接入](./client-setup.md) |
| 应用不能配代理，但可把允许的原始域名 DNS 改到 Rove | **T1 SNI 透明网关** |
| 应用只能改 `base_url`，且需要 TLS 终止和 endpoint 映射 | 等 T2 |
| 出口藏在 NAT 后 | [反向 hop](./reverse-hop.md) |
| 让公网连进 NAT 后的 listener | [反向公网入口](./reverse-ingress.md) |
| 打进隔离网段 | [Subnetra](./subnetra.md) |
| 虚拟主机 / 证书签发 / WAF | nginx / Envoy |

完整边界和质量门禁见[项目画像与方向](./roadmap.md)。
