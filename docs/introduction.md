# Rove 文档

> 应用网络优化器。一个二进制搞定接入、鉴权、分流、限速；控制面只下发快照。
>
> 面向 Agent API、投资交易、SaaS 出口和其他对路径敏感的应用流量。

Rove 优化的是应用访问网络的那一跳。它把数据面和策略判定收进一个可审计的
Rust 二进制：客户端接进来，节点在本地完成认证、策略决策、限速和出口连接。
「谁能用、怎么走」来自控制面快照，节点不持有业务真相。

节点自己**不保存业务真相**。用户、密码、分流策略这些数据的唯一来源是你的**控制面**；节点只是通过
HTTP 定期拉取一份「编译好的快照」，在内存里热替换，控制面挂了也能靠本地缓存继续服务。

---

## 它能做什么

- **前端接入**：HTTP(S) CONNECT、SOCKS5；监听层叠加 TLS 就是 `https` / `socks5tls`。
- **二级代理（出口分流）**：直连 / HTTP 上游 / SOCKS5 上游，可选 TLS；NAT 后的 hop 可用反向 QUIC。
- **轻量组网底座**：内嵌 Subnetra v1 加密 Layer-3 隧道（无需 TUN / 独立守护进程），在 overlay 上跑 HTTP/SOCKS，可作 hub 或 spoke，并与现有 Zig 版 subnetra 线兼容。
- **进程内策略**：用户名密码 + 过期校验、域名后缀树 + IP CIDR 分流、每用户字节令牌桶限速、连接数限制。
- **版本化地址簿**：`rove-abctl` 把 Provider IP 段和社区域名表构建为 `.rab` 工件，节点通过
  `book:<category>` 使用层级分类并原子热替换。
- **控制面同步**：HTTP 拉取快照，本地缓存热替换，离线也能启动。
- **可观测**：结构化 JSONL 访问日志（可转发 syslog）、内置只读 SNMP agent（Cacti / LibreNMS）。
- **隔离网络运维**：可选 MQTT 通道，响应策略查询、同步指令、按需拨测追踪。

## 它不是什么

- 不是控制面，也不是管理后台。节点只**消费**快照，不管理用户、套餐、计费。
- 当前热路径是 HTTP CONNECT、SOCKS5 与 TUIC。Trojan / VLESS / Hysteria2 等主流代理协议在路线图里，落地时不得牺牲现有热路径。
- 不会「失败即放行」。认证失败、账号过期、策略拒绝、快照无效时，一律保守拒绝，绝不降级成开放代理。
- 不是科学上网发行版。默认场景是 Agent、交易、SaaS 和隔离网段的应用路径优化。

---

## 架构一览

```text
   client ──►  监听 (TCP + 可选 TLS)  ──►  引擎 authenticate + decide  ──►  出口 (direct / 上游代理)  ──► 目标
   http/socks5                                      ▲
                                                    │  热替换快照 (ArcSwap)
                                          控制面 HTTP 拉取 + 本地缓存
```

一个节点只需要回答三个问题：**我是谁**（`node_id`）、**控制面在哪**（`snapshot_url` + `token`）、
**监听哪些口**（`[[listeners]]`）。访问日志默认开启；SNMP、MQTT、反向 hop 等能力默认关闭，按需开启。

---

## 从这里开始

| 我想…… | 去看 |
|---|---|
| 5 分钟先把它跑起来 | [快速开始](./quickstart.md) |
| 用二进制 / Docker / 源码部署到生产 | [安装与部署](./installation.md) |
| 弄清每个配置项什么意思 | [配置详解](./configuration.md) |
| 让 Shadowrocket / 浏览器 / curl 连上 | [客户端接入](./client-setup.md) |
| 理解用户、routing policy、named egress 怎么算 | [数据模型与策略决策](./data-model.md) |
| 构建、发布并接入大型域名/IP 地址簿 | [rove-addrbook 指南](./addrbook-format.md) |
| 对接我自己的控制面 | [控制面同步协议](./snapshot-protocol.md) |
| 看典型部署拓扑怎么搭 | [最佳实践场景](./best-practices.md) |
| 看性能数据与压测方法 | [基准测试报告](./benchmark.md) |
| 遇到问题快速排查 | [常见问题](./faq.md) · [故障排查](./troubleshooting.md) |

> 想了解项目边界、非目标与质量门禁，见 [项目画像与方向](./roadmap.md)。
