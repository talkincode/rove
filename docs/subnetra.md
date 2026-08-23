# 内嵌 Subnetra 组网底座

Rove 原生实现了 [Subnetra](https://github.com/jamiesun/subnetra) v1 线格协议，把一层
轻量级 Layer-3 加密组网能力直接内置进代理进程。这样就不必单独部署 subnetra 守护进程、
不需要 TUN 设备、也不需要 `NET_ADMIN`：一套用户态 IP 栈在 overlay 上终结 TCP，直接把流量
交给 Rove 现有的 HTTP/SOCKS 处理，或作为出口把代理流量打进隔离网段。

> 与现有 Zig 版 subnetra **完全线兼容**：跨实现的 known-answer-test 向量
> （`tests/subnetra_conformance.rs`，取自参考实现 `tests/protocol-vectors.json`）逐字节
> 校验 Rove 的密钥派生、报文封装、混淆与收发决策，任何漂移都会让 CI 变红。现有的 subnetra
> 节点可以不做任何改动直接连上 Rove。

## 为什么内置

subnetra 单独部署当然可以，但会让 Rove 的部署叙事复杂化（两个进程、TUN、路由、权限）。
把协议做进底座后，「一层隧道 + 在隧道上跑 http/socks」变成一条配置即可开启，运维和对外解释
都简单得多。hub 与 spoke 共用同一份数据面，唯一区别是 `mode`。

## 架构

```text
                 ┌─────────────────────────── Rove 进程（单二进制） ───────────────────────────┐
  现有 Zig spoke │  ┌────────────┐   inner IPv4    ┌──────────────┐   TCP 流   ┌────────────┐ │
  ──────────────┼─▶│  UDP 反应器 │◀───────────────▶│ smoltcp 用户态│◀─────────▶│ HTTP/SOCKS │ │
   (hub 角色)    │  │ 加密/防重放 │                 │   IP 栈       │           │  代理引擎  │ │
                 │  └────────────┘                 └──────────────┘           └────────────┘ │
                 └────────────────────────────────────────────────────────────────────────────┘
```

- **UDP 反应器**（`src/subnetra/reactor.rs`）——单个 Tokio 任务独占 UDP socket 与 peer 表，
  实现 §5 的收包流程：`key_id` 选 peer（含混淆试解掩码）、认证前不改状态的 epoch 前向排序、
  64 位滑动防重放、内源过滤、认证后端点学习、按内层目的路由（hub 可 relay，禁反射）。
- **smoltcp 用户态 IP 栈**（`src/subnetra/netstack/`）——把 overlay 的内层 TCP 在用户态终结，
  产出普通异步流（`SubnetraStream` 实现 `AsyncRead`/`AsyncWrite`），无缝接入 Rove 的
  splice/代理机制。规范 §1 明确允许用户态 IP 栈作为内层包来源，因此无需 TUN。

## 两种角色

- **hub（入站）**：在 `overlay_ip:proxy_port` 上接受各 spoke 的连接，充当隧道内的代理入口。
  NAT 后的 spoke 拨到 hub，就能「在隧道上」用到 Rove 的 HTTP/SOCKS 代理。
- **spoke（出站）**：主动拨到 hub，并把某些目标的代理流量从 overlay 打出去——用来触达
  只能经由 mesh 到达的隔离网段服务（见下文「出口」）。

> 两种角色怎么摆、双方完整配置与客户端用法，见
> [最佳实践 · 场景七/八](./best-practices.md#场景七subnetra--打进隔离网段spoke-egress)（含拓扑图）。

## 配置

在 `config.toml` 增加 `[subnetra]` 段（默认关闭）：

```toml
[subnetra]
enable = true
mode = "hub"                 # "hub"（收 spoke、代理入口）| "spoke"（拨 hub、egress）
local_id = 1                 # 本节点 mesh id，0 < id <= 65535，充当线上 key_id 选择器
listen = "0.0.0.0:18020"     # 数据面 UDP 绑定地址（放行 UDP）
overlay_cidr = "10.0.0.1/24" # 本节点 overlay 地址：主机位是自身 inner IP，前缀是虚拟子网
obfuscate = true             # 头部混淆（协议 §3.4），默认开；必须全网一致
keepalive_secs = 25          # spoke NAT 保活间隔（秒），hub 忽略
proxy_protocol = "http"      # 仅 hub：overlay 上服务的协议 "http" | "socks5"
proxy_port = 8080            # 仅 hub：overlay IP 上的代理端口

[[subnetra.peers]]
id = 2
psk = "REPLACE_LINK_1_2_64_HEX_CHARS"  # 每条链路唯一的 32 字节（64 hex）预共享密钥
allowed_src = "10.0.0.2/32"            # §5.7 内源过滤前缀，也是 §5.9 路由键
endpoint = "203.0.113.2:18020"         # hub 可留空（从已认证流量学习）；spoke 必填
name = "bj-spoke"
```

**校验是 fail-closed 的**：mode 非法、`local_id` 为 0、psk 长度/字符错误、peer id 冲突/重复、
spoke 缺 endpoint、hub 缺 `proxy_protocol`/`proxy_port` 等都会在启动时报错，绝不带病运行。

> hub 节点即便没有任何 `[[listeners]]`（TCP 监听）也能启动，因为它的代理入口是 overlay。

### 作为出口（spoke egress）

要让 Rove 把某些目标从 overlay 打出去，在**控制面快照**里把出口写成 `kind = "subnetra"`：

```json
{ "kind": "subnetra" }
```

匹配到该出口的请求，其目标 `host` 必须是 overlay 内的 IPv4 地址；Rove 会用内置的用户态栈把它
在 mesh 上拨通。subnetra 出口不接受 `username`/`password`/`tls`（overlay 由每链路 PSK 的 AEAD
保护），并且 **fail-closed**——subnetra 未启用或目标不是 overlay 地址时直接报错，绝不回落直连。

## 拓扑与语义要点

- **spoke 的默认路由**：把 spoke 侧 hub peer 的 `allowed_src` 配成整个 overlay 子网
  （如 `10.0.0.0/24`），这样 spoke 的所有 overlay 目标都会路由到 hub，由 hub 再 relay 到
  目的 spoke；同时 hub relay 过来的、源为其他 spoke 的包也能通过内源过滤。
- **hub 的 peer**：每个 spoke 配其精确前缀（如 `10.0.0.2/32`），endpoint 留空由学习得到。
- **内层 MTU**（协议 §8：`1500 - 64` 字节开销 → 默认上限 1452）。smoltcp 按此通告 MSS。
  若整张 mesh 跑在**已被压缩、路径固定**的外层隧道里（例如载体只有 1360），在 `[subnetra]`
  下设 `mtu`（范围 `[576, 1452]`），smoltcp 会据此下调对端 TCP MSS，让密封后的外层 UDP
  数据报不分片地穿过隧道；不设则用协议上限 1452。注意这只调**本节点发出**的包大小与通告的
  MSS，不改协议线格常量（`max_plaintext` 仍为 1452），因此与旧节点互通不受影响。
- **混淆必须全网一致**：subnetra 无握手协商，`obfuscate` 一端开一端关会 fail-closed 互不通。
- **时钟与 epoch**：节点启动采样一次 boot epoch（纳秒墙钟）。早于 2024-01-01 会拒绝启动
  （协议 §2.3）；跨重启时钟回拨会让对端在追上旧值前拒收——用 NTP/RTC 运维缓解，协议内不修复。
- **仅 v1 `raw_direct`**：保留的 v2 模式（`kcp_arq` / `fec_xor`）不属于 v1 线契约，未实现。

## 与现有 subnetra 混合部署

因为 Rove 复现的是同一套 v1 线格，Rove 既可作为 hub 接受现有 Zig spoke，也可作为 spoke 连到
现有 Zig hub，还能作为纯 relay 在两个 Zig 节点间转发。兼容性的唯一权威是
`tests/vectors/subnetra-protocol-vectors.json` 里的 KAT 向量；参考实现做出会改变发出字节或
收发决策的变更（并 bump `wire_version`）时，重新拷贝该文件即可让 CI 守住漂移。
