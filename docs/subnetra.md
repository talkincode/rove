# 内嵌 Subnetra 组网底座

Rove 原生实现了 [Subnetra](https://github.com/jamiesun/subnetra) v1 线格协议，把一层
轻量级 Layer-3 加密组网能力直接内置进代理进程。支持两种设备后端：
- **`netstack`（默认，用户态 IP 栈）**：无需单独部署 subnetra 守护进程、不需要 TUN 设备、也不需要 `NET_ADMIN`。用户态 IP 栈在 overlay 上终结 TCP，直接把流量交给 Rove 现有的 HTTP/SOCKS 处理，或作为出口把代理流量打进隔离网段；
- **`tun`（可选，内核 TUN 网卡模式）**：在操作系统中创建或绑定 TUN 虚拟网卡，将 overlay 接入系统网络栈，实现节点主机之间的纯三层互联（直接 `ssh 10.0.0.x`、`ping`、访问系统端口），无需经过应用层代理。

> 与现有 Zig 版 subnetra **完全线兼容**：跨实现的 known-answer-test 向量
（`tests/subnetra_conformance.rs`，取自参考实现 `tests/protocol-vectors.json`）逐字节
校验 Rove 的密钥派生、报文封装、混淆与收发决策，任何漂移都会让 CI 变红。现有的 subnetra
节点可以不做任何改动直接连上 Rove。

## 为什么内置

subnetra 单独部署当然可以，但会让 Rove 的部署叙事复杂化（两个进程、TUN、路由、权限）。
把协议做进底座后，「一层隧道 + 在隧道上跑 http/socks」或「轻量主机三层组网」变成一条配置即可开启，运维和对外解释
都简单得多。hub 与 spoke 共用同一份数据面，通过 `mode` 和 `device` 灵活组合。

## 架构

```text
                 ┌─────────────────────────── Rove 进程（单二进制） ───────────────────────────┐
  现有 Zig spoke │  ┌────────────┐   inner IPv4    ┌──────────────┐   TCP 流   ┌────────────┐ │
  ──────────────┼─▶│  UDP 反应器 │◀───────────────▶│ smoltcp 用户态│◀─────────▶│ HTTP/SOCKS │ │ (device = "netstack")
   (hub 角色)    │  │ 加密/防重放 │                 │   IP 栈       │           │  代理引擎  │ │
                 │  │ 路由/中继  │                 └──────────────┘           └────────────┘ │
                 │  │            │   inner IPv4    ┌──────────────┐                          │
                 │  │            │◀───────────────▶│  内核 TUN    │ (device = "tun")         │
                 │  └────────────┘                 │ rove0 / utun │                          │
                 └─────────────────────────────────┴──────────────┴──────────────────────────┘
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

## 设备后端：netstack vs tun

Subnetra 支持两种设备后端，通过 `[subnetra].device` 配置：

| 特性 | `device = "netstack"`（默认） | `device = "tun"`（新增） |
|---|---|---|
| **定位** | 代理入口与 egress 出口 | 主机三层互通局域网（SSH、Ping、系统服务） |
| **系统特权** | **零特权**（普通用户即可运行） | 需要 `CAP_NET_ADMIN` 或 root（或挂载预建设备） |
| **内核网络** | 内核看不到网卡，完全在用户空间终结 TCP | 创建内核网卡（如 `rove0`），接入操作系统路由表 |
| **服务提供方式** | 仅由 Rove 内置代理引擎处理流量 | 本机任何守护进程（`sshd`、`nginx`、`mysqld`）均可监听 |
| **快照 egress** | 快照中 `upstream.kind = "subnetra"` | 直接由操作系统路由表转发，无需应用层快照 |
| **平台** | 全平台（含 Linux, macOS, RouterOS 容器） | Linux（一等支持）、macOS（`utun`，二级支持） |

### hub 模式的中继兼容性

值得注意的是：
- **hub 跑 `device = "netstack"` 时，依然可以为所有 `device = "tun"` 的 spoke 转发中继！**
  因为 spoke 之间的互访流量在 hub 处的反应器（Reactor）层即完成路由与中继（relay），数据包根本不进入 hub 主机的操作系统内核。因此，hub 节点本身不需要开 `ip_forward`，不需要配置 iptables，也不需要系统特权挂载 TUN 网卡。
- 只有当 **hub 主机本身**也需要对外暴露 SSH / 接受系统端口访问时，hub 才需要开启 `device = "tun"`。

## 权限与部署说明（TUN 模式）

### 1. 自动管理设备（`manage = true`，推荐）
当 `[subnetra.tun] manage = true` 时，Rove 会自动调用内核接口创建 TUN 网卡、配置 overlay IP 与子网掩码、设置 MTU 并启动网卡（macOS 上还会自动安装点对点子网路由）。这需要网络管理特权：

- **普通主机 / 虚拟机**：
  ```bash
  # 方式 A：sudo 运行
  sudo rove --config /etc/rove/rove.toml
  # 或 spoke 节点：
  sudo rove-hop --subnetra-config /etc/rove/mesh.toml

  # 方式 B：通过 setcap 赋予二进制能力（免 root）
  sudo setcap cap_net_admin+ep /usr/local/bin/rove
  sudo setcap cap_net_admin+ep /usr/local/bin/rove-hop
  ```
- **systemd 服务**：
  在 unit 文件中配置 AmbientCapabilities：
  ```ini
  [Service]
  User=rove
  AmbientCapabilities=CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_ADMIN
  ```
- **Docker 容器**：
  ```bash
  docker run -d --cap-add NET_ADMIN --device /dev/net/tun rove-image ...
  ```

### 2. 持久化设备（`manage = false`，严格免 root 运行）
若运维策略完全禁止赋予服务进程任何系统能力，可由运维预先创建好持久化 TUN 设备并授权给运行用户：

```bash
# 1. 运维以 root 创建持久化网卡并赋予普通用户 rove
sudo ip tuntap add dev rove0 mode tun user rove
sudo ip addr add 10.0.0.2/24 dev rove0
sudo ip link set rove0 mtu 1400 up

# 2. Rove 以普通用户 rove 启动，配置 manage = false，直接 attach
# [subnetra.tun]
# name = "rove0"
# manage = false
```

## 安全边界与防火墙建议

> [!WARNING]
> **overlay 是全扁平二层/三层网络。** 开启 TUN 模式后，mesh 内的任何节点都可以主动访问其他节点在 overlay IP 上监听的所有服务与端口。

如果某台主机作为 spoke 接入了 mesh，且主机上的 `sshd` 监听在 `0.0.0.0:22`，则所有掌握有效 PSK 连入 hub 的节点均能尝试连接该主机的 SSH 端口。

强烈建议在生产环境中通过主机防火墙（`nftables` / `iptables` / `ufw`）限制 `rove0` 网卡的入站流量，只放行必要端口：

```bash
# 仅允许从 overlay 网段访问 SSH (22 端口)，阻断其他入站请求
sudo iptables -A INPUT -i rove0 -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -i rove0 -p icmp -j ACCEPT # 允许 ping 排障
sudo iptables -A INPUT -i rove0 -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -i rove0 -j DROP
```

## 与现有 subnetra 混合部署

因为 Rove 复现的是同一套 v1 线格，Rove 既可作为 hub 接受现有 Zig spoke，也可作为 spoke 连到
现有 Zig hub，还能作为纯 relay 在两个 Zig 节点间转发。兼容性的唯一权威是
`tests/vectors/subnetra-protocol-vectors.json` 里的 KAT 向量；参考实现做出会改变发出字节或
收发决策的变更（并 bump `wire_version`）时，重新拷贝该文件即可让 CI 守住漂移。
