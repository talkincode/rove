# Rove

> 应用网络优化器：把 Agent API、投资交易和其他对路径敏感的应用流量，
> 接到一条可认证、可分流、可限速的边上。一个二进制，控制面挂了也能靠本地缓存继续扛。

Rove 优化的是**应用访问网络的那一跳**。
客户端接进来后，认证、分流、限速全部在节点本地内存当场判完——不查数据库、不发 RPC。
「谁能用、怎么走」由你自己的控制面统一下发快照；节点只消费编译好的策略，离线也能服务。

**先看这些场景：**

- **Agent / LLM API**：把模型推理、工具调用、Webhook 从多云、多区域、多供应商里选路出去，按模型或域名拆出口，给每个 Agent 身份单独限速。
- **投资交易 / 行情**：券商、交易所、行情和风控回调走固定出口与低抖动路径；失败就拒绝，绝不悄悄改道成开放代理。
- **SaaS 与多云 API**：同一应用访问 AWS / Azure / GCP / 自建服务时，用地址簿和策略选最近或合规的出口。
- **Webhook 与回调出口**：支付、券商、IM 机器人的回源 IP 必须稳定、可审计。
- **远程与隔离网段**：把办公或 CI 里的应用流量送进只在内网可达的服务，不必给整台机器开 VPN。

完整文档见 **[talkincode.github.io/rove](https://talkincode.github.io/rove/)**（中文）。

## ✨ 它能做什么

- **怎么接都行**：HTTP(S) CONNECT、明文 HTTP absolute-form、SOCKS5（含 UDP）；监听上叠一层 TLS 就是 `https` / `socks5tls`，同一端口还能按 SNI 选择多张证书；还有
  TUIC v5（QUIC）前端，弱网和移动端更稳，还能隧道 UDP。
- **想从哪儿出去都行**：本地直连、HTTP / SOCKS5 上游；hop 藏在 NAT 后也没关系——它主动用 QUIC 反向
  连上来注册，edge 顺着这条连接把流量送过去。
- **入口藏在 NAT 后也能接公网**：`rove-relay` 提供经过授权的动态 TCP/UDP 端口，Rove 主动拨出；
  用户 TLS 私钥仍留在 Rove，真实客户端 IP 用关联 ID 进入统一日志。
- **能打进隔离网段**：内嵌 Subnetra 加密 Layer-3 组网，不用 TUN、不要 `NET_ADMIN` 权限、不用另起
  进程，一段配置就把代理流量送进只有内网能到的网段。
- **策略当场判**：账号密码 + 有效期、可复用 routing policy、有序域名/IP route（命名出口 /
  直连 / 阻断）、每用户限速和连接数上限，全部在内存完成。
- **地址簿当软件发布**：`rove-abctl` 把 AWS/Azure/GCP 官方地址段、v2fly 社区域名表等公开数据
  构建成确定性、带 SHA-256 校验的 `.rab` 二进制地址集（[构建、发布与接入指南](docs/addrbook-format.md)），
  节点热加载后规则里一句 `book:google/ads` 就能引用层级分类；坏数据集自动保留旧版本。
  官方数据集由工作流每周构建、过 diff 异常门后发布在 Release
  [`addrbook-latest`](https://github.com/talkincode/rove/releases/tag/addrbook-latest)
  。
- **控制面松耦合**：定期 HTTP 拉快照、内存热替换；拉不到就用本地缓存，断网也能启动。
- **看得见、管得住**：JSONL 访问日志（可转 syslog）、内置 SNMP 监控；隔离环境还能走 MQTT 下发指令。
- **域名运营观测**：HTTP CONNECT、SOCKS5 CONNECT 与 TUIC TCP 可选识别 TLS SNI / HTTP Host；
  默认关闭。HTTP/SOCKS5 仅观测；TUIC 可显式启用 `route` 按域名阻断/选出口，但不改写 requested 目标。
- **坏了就拒绝**：认证失败、账号过期、快照损坏，一律拒绝服务，绝不悄悄退化成开放代理。

## 🏗 一个节点长什么样

```mermaid
flowchart LR
    C["客户端<br/>HTTP · SOCKS5 · TUIC"] --> L

    subgraph N["rove 节点 · 一个进程"]
        direction LR
        L["监听<br/>可叠 TLS / QUIC"] --> P["认证 · 分流 · 限速<br/>全在内存判定"]
        P --> O["出口选择"]
    end

    O -->|"直连"| T["目标站点"]
    O -->|"上游代理 · 反向 hop · overlay"| H["二级出口"]
    H --> T

    CP["你的控制面"] -. "定期下发用户与策略快照" .-> P
    P <-. "断网兜底" .-> F[("本地缓存<br/>snapshot.json")]
```

节点只需要回答三个问题：**我是谁**（`node_id`）、**控制面在哪**（`snapshot_url` + `token`）、
**监听哪些口**（`[[listeners]]`）。访问日志默认开启；SNMP、MQTT、反向 hop、reverse ingress、
Subnetra 等管理或扩展能力默认关闭，用到再开。

## 🗺 三个典型场景

### 场景一：一个入口，按规则分流到不同出口

客户端全部接到一个 edge，edge 按域名 / IP 规则决定每个请求从哪儿出去。出口 hop 公网可达就直接连；
藏在 NAT 后就让 hop 主动反向注册上来。

```mermaid
flowchart LR
    C["客户端"] --> E{"rove edge<br/>认证 + 分流"}

    E ==>|"命中规则 A"| HA["hop-A · 公网可达<br/>edge 主动连它"]
    E ==>|"命中规则 B"| HB["hop-B · NAT 后<br/>它先反向 QUIC 连到 edge"]
    E -->|"没命中 · 本地直连"| T0["目标"]

    HA --> T1["目标"]
    HB --> T2["目标"]
```

没命中规则就本地直连；命中 `block` 一律拒绝，绝不悄悄放行。

### 场景二：多入口漫游，出口不变

多个 edge 各自独立认证、互不通信。hop 启动时把自己同时注册到每一个 edge；用户绑定了某个 hop 出口之后，
接哪个 edge 都从同一个出口出去——人挪了，出口 IP 不变。

```mermaid
flowchart TB
    U["用户 · 绑定出口 hop-1"]

    U -->|"今天在公司，接 edge-A"| EA["edge-A"]
    U -.->|"明天出差，接 edge-B"| EB["edge-B"]

    EA ==> H["hop-1<br/>启动时已反向注册到 A 和 B"]
    EB ==> H

    H --> T["目标站点<br/>看到的永远是 hop-1 的 IP"]
```

edge 之间不共享任何状态，扩容就是多摆一台；hop 多写一个 `--reverse-quic` 参数就多注册一个入口。
细节见 [反向 hop 数据面](https://talkincode.github.io/rove/reverse-hop.html)。

### 场景三：Subnetra —— 不装 VPN，打进隔离网段

有些服务只有内网能访问。在隔离网段里放一个 hub 节点，edge 上开一段 `[subnetra]` 配置组成加密 overlay，
代理流量就能顺着隧道进去——不需要 TUN 设备、不需要 root、不需要额外守护进程。

```mermaid
flowchart LR
    C["客户端"] --> E["rove edge<br/>subnetra spoke"]

    E ==>|"加密 UDP overlay"| S["hub · 隔离网段内<br/>rove 或原版 Zig 节点均可"]
    E -->|"普通目标照常分流"| T0["公网目标"]

    S --> T1["内网服务<br/>公网到不了"]
```

反过来也行：让 rove 作 hub，NAT 后的 spoke 拨上来，spoke 一侧就能顺着 overlay 用 hub 的 HTTP/SOCKS 代理。与
[Zig 版 subnetra](https://github.com/jamiesun/subnetra) 完全线兼容（CI 里有逐字节 KAT 校验），
老节点不改任何东西直接连。详见 [内嵌 Subnetra 组网底座](https://talkincode.github.io/rove/subnetra.html)。

## 📊 性能大概什么水平

v0.2.0 单机回环基准（本地 Docker 栈 + 进程内 subnetra；纯 Rust 负载发生器，
2000 请求 / 并发 20 / 256 MiB 单流），60 个用例 0 失败：

| 模式 | 一句话定位 | 延迟 p50 | 单流下载 |
|---|---|---:|---:|
| `direct` | 本地直连 | 2.1 ms | ~1.6 GiB/s |
| `socks5` | 明文转发到上游 | 3.1 ms | ~730 MiB/s |
| `https` / `socks5tls` | TLS 加密到上游 | 6.0–6.3 ms | ~680–750 MiB/s |
| `reverse` | NAT 后 hop 的 QUIC 反向隧道 | 2.9 ms | ~430 MiB/s |
| `tuic` | QUIC 前端（移动端友好） | 1.8 ms | ~166 MiB/s |
| `subnetra` | 加密 L3 overlay 组网 | 0.7 ms | ~210 MiB/s |

- 表中为 HTTP 入口数据；HTTPS-TLS / SOCKS5 / SOCKS5-TLS 四个入口全部实测，
  入口 TLS 握手约再加 1 ms，其余同档。
- `reverse` 建隧道走复用的 QUIC 反向通道，不需要新建 edge→hop 连接，
  延迟接近 direct，是穿 NAT 场景的低延迟优选。
- 限速与配额实测：1 MiB/s 限速双向误差 **≤0.1%**，`max_connections` 精确拒绝超额连接。
- 资源占用很小：满载 CPU 约一个核，全栈 5 容器内存峰值合计 <40 MiB。
- 以上是无丢包、零 RTT 的回环上限；生产环境的实际数字取决于你的公网 RTT 和丢包率。

想自己复现：`docker compose -f docker-compose.local.yml up -d` 起本地栈，然后跑
`cargo run --release --example proxy-benchmark-local -- all`（延迟 + 吞吐 + 并发扫描 + 限速精度）与
`cargo run --release --example subnetra-benchmark-local`。完整矩阵、分相延迟与方法学见
[基准测试报告](https://talkincode.github.io/rove/benchmark.html)。
要测 reverse ingress 接入开销，加
`--paths local,reverse-ingress --modes direct` 即可对比同一 listener 的两条路径。
TUIC/UDP 使用
`cargo run --release --example tuic-benchmark-local -- --path reverse-ingress`。

## 🚀 快速开始

安装（任选其一）：

```bash
# Homebrew
brew install talkincode/tap/rove

# 从源码（Rust 1.88+）
git clone https://github.com/talkincode/rove.git && cd rove
cargo build --release --bins

# crates.io（包名 rove-proxy，二进制仍是 rove）
cargo install rove-proxy --locked
```

也可从 [Releases](https://github.com/talkincode/rove/releases) 下载对应平台的压缩包。

写一份最小配置 `config.toml`：

```toml
node_id = "dev-local-01"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "dev"
cache_path = "./data/snapshot.json"

[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:8080"
```

控制面发布快照前可用节点自身的真实解码/编译链预检，不会启动代理服务：

```bash
rove validate-snapshot --node-id dev-local-01 snapshot.json
```

本地试用不用真搭控制面——先手放一份缓存快照 `data/snapshot.json`，节点启动会先读它（schema v4）：

```json
{
  "schema_version": 4,
  "version": 1,
  "users": { "alice": { "password": "s3cret", "policy": "open" } },
  "routing_policies": { "open": { "routes": [] } },
  "egresses": {}
}
```

跑起来，验证一下：

```bash
./target/release/rove -c config.toml
curl -x http://alice:s3cret@127.0.0.1:8080 https://ifconfig.me
```

Docker 部署时把监听地址改成 `0.0.0.0:8080`，并把配置里的 `cache_path` 改为
`/var/lib/rove/snapshot.json`、`access_log.dir` 改为 `/var/log/rove`：

```bash
docker run -d --name rove -p 8080:8080 \
  -v "$PWD/config.toml:/etc/rove/config.toml:ro" \
  -v "$PWD/data:/var/lib/rove:rw" \
  -v "$PWD/logs:/var/log/rove:rw" \
  ghcr.io/talkincode/rove:latest
```

更完整的步骤（TLS 证书、SOCKS5、systemd、独立 hop 出口）见
[快速开始](https://talkincode.github.io/rove/quickstart.html) 与
[安装与部署](https://talkincode.github.io/rove/installation.html)。

## 🔗 相关链接

- **[文档站点](https://talkincode.github.io/rove/)** — 配置详解、数据模型、快照协议、FAQ、故障排查
  （源码在 [`docs/`](./docs/)，mdBook 构建）
- [最佳实践场景](https://talkincode.github.io/rove/best-practices.html) ·
  [rove-addrbook](https://talkincode.github.io/rove/addrbook-format.html) ·
  [反向 hop](https://talkincode.github.io/rove/reverse-hop.html) ·
  [反向公网入口](https://talkincode.github.io/rove/reverse-ingress.html) ·
  [TUIC 前端](https://talkincode.github.io/rove/tuic.html) ·
  [Subnetra 组网](https://talkincode.github.io/rove/subnetra.html) ·
  [独立 hop 节点](https://talkincode.github.io/rove/hop.html)
- [Subnetra 协议参考实现（Zig）](https://github.com/jamiesun/subnetra) — Rove 与其完全线兼容
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) · [quinn](https://github.com/quinn-rs/quinn) —
  内嵌用户态 IP 栈与 QUIC 实现
- [项目画像与方向](./docs/roadmap.md) · [验收矩阵](./docs/acceptance-matrix.md) ·
  [`AGENT.md`](./AGENT.md) — 贡献前必读；验收矩阵定义每个一级能力的测试锚点与硬性覆盖门禁
  （Happy Path / 失败路径 / 双角色 / 恢复回滚 / 新功能必配 E2E）

## 📄 许可

[MIT](./LICENSE)
