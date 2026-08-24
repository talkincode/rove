# 应用出口网关

> **状态：方向已定，代码未落地。** 本章写的是产品边界和接入形状，不是一份可以照抄上线的配置手册。
> 现有可运行入口仍是 HTTP CONNECT / SOCKS5 / TUIC，见 [客户端接入](./client-setup.md)。

应用访问一个**你自己拥有的普通 HTTPS 端点**，由 Rove 在服务端完成身份、策略、出口选择和审计。
客户端不必设置 `HTTP_PROXY`、不必改 SDK transport。这是企业 egress 治理的标准形态，也是
把 Rove 从「让应用配代理」翻成「应用出口平面」的关键一步。

产品名是**应用出口网关**。配置和代码用 `sni` / `gateway` listener，日志用
`ingress_mode`。**不要叫它 reverse proxy。**

---

## 先把三个容易混的词分开

仓库里已经有两个「reverse」，和新能力不是一回事：

| 名字 | 方向 | 现在有没有 | 实际做什么 |
|---|---|---|---|
| [反向 hop](./reverse-hop.md) | 出向（egress） | 有 | NAT 后的出口节点用 QUIC **主动回连** edge，成为一个 egress backend |
| [反向公网入口](./reverse-ingress.md) | 入向（admission） | 有 | NAT 后的节点通过公网 `rove-relay` **接受入站代理连接** |
| **应用出口网关**（本章） | 入向（gateway） | **没有** | 客户端访问你拥有的端点，Rove 把入口映射到**服务端声明的 origin**，再走既有策略与出口 |

需要把内网服务发布到公网，用 reverse ingress 或 [Subnetra](./subnetra.md)，或在 Rove 前面放 nginx / Envoy。
那不是网关要做的事。

---

## 为什么要网关

当前三种入口都要求应用「知道自己在用代理」：设环境变量、配 SOCKS、改 SDK。这会卡住两类真实场景：

- Serverless / 托管 runtime / 第三方 Webhook / 某些官方 SDK **根本没有代理开关**。
- 企业内部推一次「全员改代理配置」的成本，远高于改一条 DNS 或一个 `base_url`。

网关把接入反过来：

```text
应用 ──► https://openai.egress.internal/v1
              │
              ▼
         Rove 出口网关
              │  identity → policy → route → egress
              ▼
         https://api.openai.com
```

演示也不再是「看出口 IP」，而是：把 `base_url` 指过来，API 正常返回，访问日志里能看到走了哪条规则、哪个出口。

---

## 三层，不是一个功能

「加反向代理」下面其实是三件成本、风险、边界完全不同的事。

| 层 | 形态 | 态度 |
|---|---|---|
| **T1 SNI 透明网关** | DNS 把 `api.openai.com` 指到 Rove；读 ClientHello SNI，对照闭合 origin 白名单，TLS **不终止**，按字节转发 | **做，作为 MVP** |
| **T2 L7 HTTPS 网关** | 客户端把 `base_url` 指到网关；按 endpoint 查服务端声明的 origin，终止 TLS 后再出站 | **做，但 origin 必须服务端声明** |
| **T3 通用反代 / API 网关** | 虚拟主机、ACME、后端池、健康检查、重写、WAF | **明确不做** |

它们都只是新的 **listener adapter**，接到同一条
`identity → policy → route → egress → transport → observability` 主干。
策略层和出口层不需要为网关另起炉灶。

| 入口 | identity 来源 | target 来源 |
|---|---|---|
| HTTP CONNECT | `Proxy-Authorization` | 客户端 CONNECT 行 |
| SOCKS5 | RFC 1929 | 客户端请求 |
| TUIC | `frontends.tuic` | 客户端请求 |
| **sni（规划）** | listener 绑定身份，或源 IP ACL | ClientHello SNI ∩ **服务端白名单** |
| **gateway（规划）** | `frontends.gateway` bearer token | **服务端声明的 endpoint → origin 表** |

---

## T1｜SNI 透明网关（规划中）

DNS（split-horizon / CoreDNS rewrite / hosts）把目标域名指到 Rove。Rove 读 TLS ClientHello 的 SNI，
对照**闭合 origin 白名单**，命中后套用该 listener 绑定身份的策略，选出口，把已读字节连同后续流量转发出去。

决定性属性：**不终止 TLS**。节点看不到明文，不持有 origin 证书，不接触 API key。
治理的是路径，不是数据。

现有实现已经覆盖大部分零件：`src/sniff.rs` 抽 SNI、`PrefixedIo` 回放已读字节、
`decide_with_sniff` 按嗅探主机选路、`outbound::connect` 与 `splice` 原样复用。
缺的是一个新的 listener 类型，以及「SNI 必须落在白名单里」这条 fail-close。

L4 没有 per-request 凭据，身份必须显式解决，否则就是开放中继：

- 首选：listener 绑定快照里的一个用户，`identity = "team-agent"`，缺了就拒绝启动。
- 备选：源 IP → 身份 ACL（由快照下发），未知源 IP 直接断开。
- **禁止**：无身份即放行。

SNI 缺失、畸形、超长、或不在 `origins` 白名单 → **立即断开**。不回落直连，不按 SNI 随意拨号。

配置草案（未实现，不要照抄上线）：

```toml
[[listeners]]
name     = "egress-sni"
protocol = "sni"
listen   = "127.0.0.1:8443"
identity = "team-agent"
origins  = [
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
]
```

---

## T2｜L7 HTTPS 网关（规划中）

客户端把 SDK 的 `base_url` 指到网关，带 `Authorization: Bearer …`。
网关按 endpoint（Host，可选 path 前缀）查**服务端声明的 origin**，再走既有策略与出口。

**生死线：origin 只能来自节点本地配置或控制面快照，绝不能来自客户端的 Host、URL 或路径。**
否则这不是网关，是一个带 TLS 的开放正向代理，也是 SSRF 入口。未命中的 Host 一律拒绝
（草案用 `421 Misdirected Request`），不得按 Host 拨号。

身份复用已有的 `frontends.<协议>` 命名空间，TUIC 已经在用。网关占用 `frontends.gateway`，
编译期检测同一 key 被两个用户占用。同一条 keep-alive 连接上换 token 必须重新鉴权，
不得复用第一个请求的身份。

`endpoint → origin` 表应放在快照里，让控制面成为映射关系的真相来源。快照结构带
`deny_unknown_fields`：老节点收到带新字段的文档会**整份拒收**，继续用上一份有效快照，
而不是忽略未知字段后按旧语义放行。

访问日志默认**不记录 path / query / 请求头**。终止 TLS 之后这些字段可见，而 API key
出现在 query 里是常见的；默认记下来，日志本身就变成凭据泄露面。

配置草案（未实现）：

```toml
[[listeners]]
name     = "egress-gateway"
protocol = "gateway"
listen   = "127.0.0.1:8443"

[listeners.tls]
cert = "/etc/rove/gw.crt"
key  = "/etc/rove/gw.key"

[listeners.gateway]
max_body_bytes  = 16777216
request_timeout = "60s"
log_path        = false
```

快照侧草案：

```jsonc
{
  "schema_version": 1,
  "endpoints": {
    "openai.egress.internal":    { "origin": "https://api.openai.com" },
    "anthropic.egress.internal": { "origin": "https://api.anthropic.com" }
  }
}
```

T2 不做这些事：不解析请求体和 SSE、不注入或轮换 API key、不做模型路由、不做响应缓存、
不在节点里理解 OpenAI / 券商的业务语义。优化的仍然是路径、出口、认证、限速和审计。

---

## T3｜通用反向代理 —— 不做

虚拟主机、ACME 自动签发、后端池与负载均衡、主动健康检查、灰度、重写规则、WAF，
是 nginx / Envoy / Traefik 的产品，不是 Rove 的。

- 会把节点推向管理面，违反「节点只消费快照」的边界。
- 方向是 ingress 产品，会稀释而不是强化 application egress plane。
- 正当需求已经有着落：发布内网服务用 [reverse ingress](./reverse-ingress.md) 或
  [Subnetra](./subnetra.md)；更复杂的 HTTP 入口放在 Rove **前面**。

---

## 失败就必须拒绝

网关落地时，下面每一行都要有测试。今天还没有实现，所以这是验收清单，不是当前行为。

| 情形 | 要求行为 | 禁止行为 |
|---|---|---|
| SNI 缺失 / 畸形 / 超长 | 断开 | 回落直连、回落默认 origin |
| SNI 不在 `origins` | 断开 | 按 SNI 直接拨号 |
| 网关请求无 `Authorization` | `401` | 匿名放行 |
| token 未知 / 用户过期 / block | `401` / `403` | — |
| `Host` 不在 endpoint 表 | `421` | 按 Host 拨号 |
| 同一连接更换 token | 重新鉴权 | 复用首个请求的身份 |
| origin 拨号失败 | `502` | 静默换出口（除非显式 chain） |
| 快照为空 | 全拒绝 | — |

规划中的审计字段：`ingress_mode`（`forward` / `sni` / `gateway`）、`endpoint`、`origin_id`。
现有 `policy_id` / `matched_route` / `decision` / `egress` 继续复用。

---

## 怎么选现有能力

| 我想…… | 现在用 | 不要用网关去…… |
|---|---|---|
| 应用能配 `HTTP_PROXY` / SOCKS / TUIC | [客户端接入](./client-setup.md) | 等一个还没落地的入口 |
| 出口藏在 NAT 后 | [反向 hop](./reverse-hop.md) | 把 hop 误叫成 reverse proxy |
| 让公网连进 NAT 后的 listener | [反向公网入口](./reverse-ingress.md) | 把它当成 HTTP 反代 |
| 打进隔离网段 | [Subnetra](./subnetra.md) | 在网关里做内网发布 |
| 应用改不了代理，只能改 DNS 或 `base_url` | 等 T1 / T2；本章是方向 | 把任意 Host 转发出去 |
| 虚拟主机 / 证书签发 / WAF | nginx / Envoy | 让 Rove 变成通用反代 |

完整非目标见 [项目画像与方向](./roadmap.md)。
