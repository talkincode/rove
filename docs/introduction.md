# Rove 文档

> 应用出口平面（application egress plane）。
> 为 Agent API、投资交易、SaaS 多云调用和其他对路径敏感的应用流量，
> 做身份、策略、选路、出口与审计。一个二进制，控制面挂了也能靠本地缓存继续服务。

Rove 优化的是**应用访问网络的那一跳**。客户端接进来后，认证、策略、限速全部在节点本地内存当场判完——不查数据库、不发 RPC。「谁能用、怎么走」来自你自己的控制面快照；节点只消费编译好的策略，离线也能服务。

它服务的不是「谁都能连的通用上网」，而是一条可认证、可分流、可限速、可审计的应用出口。

**先看这些场景：**

- **Agent / LLM API**：把模型推理、工具调用、Webhook 从多云、多区域、多供应商里选路出去，按模型或域名拆出口，给每个 Agent 身份单独限速。
- **投资交易 / 行情**：券商、交易所、行情和风控回调走固定出口与低抖动路径；失败就拒绝，绝不悄悄改道。
- **SaaS 与多云 API**：同一应用访问 AWS / Azure / GCP / 自建服务时，用地址簿和策略选最近或合规的出口。
- **Webhook 与回调出口**：支付、券商、IM 机器人的回源 IP 必须稳定、可审计。
- **远程与隔离网段**：把办公或 CI 里的应用流量送进只在内网可达的服务，不必给整台机器开 VPN。

节点自己**不保存业务真相**。用户、密码、分流策略这些数据的唯一来源是你的**控制面**；节点只是通过
HTTP 定期拉取一份「编译好的快照」，在内存里热替换，控制面挂了也能靠本地缓存继续服务。

---

## 主干：identity → policy → route → egress → transport → observability

| 层 | 做什么 |
|---|---|
| **identity** | 谁在连。每个 listener adapter 只负责把接入协议译成用户身份。 |
| **policy** | 这个身份绑定哪条 routing policy。 |
| **route** | 有序 first-match-wins。命中 `egress` / `direct` / `block`。 |
| **egress** | 从哪个命名出口出去；未命中执行 `default_action`（可写成 deny-by-default）。 |
| **transport** | 出口怎么实现：直连、HTTP / SOCKS5 上游、反向 hop、Subnetra overlay。 |
| **observability** | 每条连接留下「谁、去哪、哪条规则判的、从哪个出口出去」。 |

HTTP CONNECT、SOCKS5、TUIC 与 T1 SNI 网关都是 **listener adapter**，不是产品本身。新的接入方式必须能证明自己服务的是应用入口，并且有 fail-closed 的身份路径，才能加到这条主干上。

---

## 它能做什么

- **怎么接都行**：HTTP(S) CONNECT、明文 HTTP absolute-form、SOCKS5（含 UDP）；监听上叠一层 TLS 就是 `https` / `socks5tls`；还有 TUIC v5（QUIC）前端。
- **应用改不了代理也能受控出站**：T1 SNI 透明网关将服务端精确允许的 DNS 名转入同一条身份、策略、出口、限速和审计链路，不终止 TLS、不接受任意目标。
- **想从哪儿出去都行**：本地直连、HTTP / SOCKS5 上游；hop 藏在 NAT 后也没关系——它主动用 QUIC 反向连上来注册。
- **入口藏在 NAT 后也能接公网**：`rove-relay` 提供经过授权的动态 TCP/UDP 端口；用户 TLS 私钥仍留在 Rove。
- **能打进隔离网段**：内嵌 Subnetra 加密 Layer-3 组网，不用 TUN、不要 `NET_ADMIN`、不用另起进程。
- **策略当场判**：账号密码 + 有效期、可复用 routing policy、有序域名/IP route、每用户限速和连接数上限，全部在内存完成。
- **地址簿当软件发布**：`rove-abctl` 把 AWS / Azure / GCP 官方地址段和企业应用域名构建成带 SHA-256 校验的 `.rab` 地址集，规则里一句 `book:openai` 就能引用；坏数据集自动保留旧版本。
- **控制面松耦合**：定期 HTTP 拉快照、内存热替换；拉不到就用本地缓存，断网也能启动。
- **看得见、管得住**：JSONL 访问日志（可转 syslog）、内置 SNMP；隔离环境还能走 MQTT 下发指令。
- **坏了就拒绝**：认证失败、账号过期、快照损坏，一律拒绝服务，绝不悄悄退化成开放代理。

## 它不是什么

- 不是控制面，也不是管理后台。节点只**消费**快照，不管理用户、套餐、计费。
- 不是公共出口、不是跨境接入服务、不是机场。软件和网络运营是两回事，所有线路由部署者自行准备。
- 不是通用反向代理或 API 网关。origin 必须由服务端声明，不能由客户端的 Host / URL 指定。
  已交付的 T1 SNI 出口网关与规划中的 L7 T2 见 [应用出口网关](./egress-gateway.md)；发布内网服务请用
  [reverse ingress](./reverse-ingress.md) 或 [Subnetra](./subnetra.md)。
- 不会「失败即放行」。认证失败、账号过期、策略拒绝、快照无效时，一律保守拒绝。

---

## 架构一览

```text
   应用客户端 ──►  listener adapter          ──►  identity → policy → route → egress  ──►  transport  ──► 目标
   HTTP / SOCKS5 / TUIC / SNI     （可叠 TLS / QUIC；SNI 原样透传）              ▲
                                                            │  热替换快照 (ArcSwap)
                                                  控制面 HTTP 拉取 + 本地缓存
```

一个节点只需要回答三个问题：**我是谁**（`node_id`）、**控制面在哪**（`snapshot_url` + `token`）、
**监听哪些口**（`[[listeners]]`）。访问日志默认开启；SNMP、MQTT、反向 hop、reverse ingress、
Subnetra 等管理或扩展能力默认关闭，用到再开。

---

## 使用边界

Rove 是通用的应用网络基础设施，用于出口治理、路径优化与访问审计。

- **软件与网络运营是两回事。** 本项目只发布软件，不运营网络：不提供官方公共出口节点，
  不提供任何形式的公共跨境网络接入服务，没有订阅、节点分发或流量套餐。所有出口线路
  都由部署者自行准备并自行负责。
- **不存在开放代理形态。** HTTP/SOCKS5/TUIC 使用客户端凭据；T1 SNI listener 则必须绑定当前快照中
  有效的服务端身份和闭合 origin 白名单。身份无效、策略命中阻断、快照编译失败或上游不可达时一律拒绝连接，
  不会降级为直连或匿名放行。
- **部署者是合规责任主体。** 使用 Rove 组建的任何网络路径，都需遵守部署地与流量落地地的
  法律法规，以及你与网络运营商、云厂商、上游服务商之间的协议。
- **不面向消费级代理市场。** 项目不提供机场面板、订阅链接、流量计费、客户端一键配置这类
  功能，相关需求不在项目范围内。

---

## 从这里开始

| 我想…… | 去看 |
|---|---|
| 5 分钟先把它跑起来 | [快速开始](./quickstart.md) |
| 用二进制 / Docker / 源码部署到生产 | [安装与部署](./installation.md) |
| 弄清每个配置项什么意思 | [配置详解](./configuration.md) |
| 客户端接入参数 | [客户端接入](./client-setup.md) |
| 应用改不了代理，只能改 DNS 或 base_url | [应用出口网关（T1 SNI 已交付；T2 规划中）](./egress-gateway.md) |
| 理解用户、routing policy、named egress 怎么算 | [数据模型与策略决策](./data-model.md) |
| 构建、发布并接入大型域名/IP 地址簿 | [rove-addrbook 指南](./addrbook-format.md) |
| 对接我自己的控制面 | [控制面同步协议](./snapshot-protocol.md) |
| 看典型部署拓扑怎么搭 | [最佳实践场景](./best-practices.md) |
| 看性能数据与压测方法 | [基准测试报告](./benchmark.md) |
| 遇到问题快速排查 | [常见问题](./faq.md) · [故障排查](./troubleshooting.md) |

> 想了解项目边界、非目标与质量门禁，见 [项目画像与方向](./roadmap.md)。
