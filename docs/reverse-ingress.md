# 反向公网入口（Reverse Ingress）

当 Rove 接入点位于 NAT 后、无法直接接收公网连接时，可在公网服务器运行
`rove-relay`。Rove 主动建立一条经过认证的 QUIC 长连接，在 relay 上申请预授权
TCP/UDP 端口，再把公网流量送回本地 listener。

```text
浏览器 / TUIC 客户端
        │ 域名解析到 relay 公网 IP
        ▼
rove-relay（公网端口、节点认证、租约、观测）
        ⇅ rove-ingress/1 QUIC
NAT 内 Rove connector
        ▼
本地 HTTP / SOCKS5 / TUIC listener → 策略与后端
```

这和 [反向 hop](./reverse-hop.md) 方向相反：

- reverse ingress 把**公网用户流量送入 NAT 内 Rove**；
- reverse hop 把 **Rove 已认证流量送到 NAT 后出口**；
- 两者使用独立 ALPN、协议、凭据和配置，不能互换。

## TLS 与 DNS

用户域名解析到 relay 公网 IP，但用户 TLS 仍在 Rove listener 终止。relay 只转发
原始 TCP 字节或 UDP datagram，不解析 ClientHello、不持有用户证书私钥。relay
自身另有一套证书，仅用于 Rove↔relay 的 `rove-ingress/1` QUIC 隧道。

因此需要两套边界清晰的证书：

1. `relay.crt/key`：安装在公网 relay，Rove connector 校验它；
2. 用户域名证书：只安装在 NAT 内 Rove 的 `[listeners.tls]` 或
   `[[tuic_listeners]]`。

## 公网 relay

复制 [`relay.example.toml`](../relay.example.toml)，使用独立节点令牌：

```bash
export Rove_NODE_EDGE_NAT_01_TOKEN='deployment-secret'
rove-relay --config relay.toml
```

relay 的授权粒度是 `node_id + listener_id + transport + ports`。节点只能申请授权表
中的端口；`ports` 支持单端口与闭区间。每个 grant 展开后最多 4096 个端口，防止
错误配置产生无界扫描。同一 transport 的端口授权不得跨 node/listener 重叠，避免
relay 重启后把旧动态端口分配给另一节点。

```toml
[[nodes.listeners]]
id = "https-public"
transport = "tcp"
ports = ["443", "10443-10449"]
```

`rove-relay` 的运行日志是结构化 JSONL，适合由 systemd/journald、容器日志驱动或
日志代理集中采集。事件包含 relay/node/listener/session/lease/ingress/flow ID、
客户端地址、流量和稳定失败阶段，不包含 token、用户密码或载荷。

节点可配置多个 `token_envs` 做无中断轮换：先同时接受旧/新 token，切换 connector
后再移除旧 token。撤销某个节点时删除其 grant 并重启 relay。

## NAT 内 Rove

`[[reverse_ingress]]` 可重复；每段对应一个独立 relay 会话，分别认证、申请租约、
保活和重连。

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

- `public_port = 0`：从 relay 为该 listener 授权的端口池动态选择；
- `local_listener` 必须精确引用当前 Rove 配置中已经声明的 TCP 或 TUIC listener；
- 本地 listener 必须绑定 loopback 或 wildcard。connector 会改拨 loopback，relay
  无法指定任意内网地址，避免形成 SSRF/内网探测通道；
- `token` 与 `token_env` 互斥；生产使用 `token_env`；
- 自签 relay 可显式设置 `skip_cert_verify = true`，默认必须校验证书。

## TCP 与 UDP 数据面

TCP 每个公网连接对应一条独立 QUIC 双向流。relay 生成 128-bit `ingress_id`，
传递真实客户端地址后原样拼接字节。流开始后不会跨 relay/节点重放。

UDP 走 QUIC datagram，不经过可靠 stream。relay 按公网客户端五元组建立有上限、
带 idle 回收的 flow，并分配 128-bit `flow_id`。connector 为每个 flow 创建独立
loopback UDP socket，因此 TUIC 回包和 QUIC 地址迁移不会串流。未知、过期、反向
错误或容量超限的 flow 一律丢弃。

隧道中断时：

- 新 TCP 连接立即关闭；
- 新 UDP 包直接丢弃；
- 不缓存用户流量等待重连；
- connector 指数退避重连；
- 动态端口在 `lease_grace_secs` 内优先恢复原分配。

## 真实客户端 IP 与联合溯源

relay 是公网 socket 的直接接收者，因此它记录真实来源 IP。可信元数据通过已认证
QUIC 会话进入 Rove；Rove 不读取客户端提供的 `X-Forwarded-For`。

Rove 访问日志新增：

- `client_addr_source: "reverse_ingress"`
- `relay_addr`
- `relay_instance_id`
- `tunnel_session_id`
- TCP 的 `ingress_id` 或 UDP 的 `flow_id`

集中日志按 `node_id + ingress_id/flow_id` 关联，即可还原：

```text
真实 IP → relay 公网入口 → Rove 用户 → 目标/策略 → 实际后端
```

客户端 IP 与用户身份的关联属于敏感数据，应限制查询权限并设置保留周期。时间戳只
用于排序，不作为唯一关联键；relay 与 Rove 主机都应启用 NTP。

## MTU

配置中的 `initial_mtu` 是 **Quinn 最大 UDP payload**，不是网卡/L3 MTU：

| 路径 L3 MTU | IPv4 Quinn 上限 | IPv6 Quinn 上限 |
|---:|---:|---:|
| 1500 | 1472 | 1452 |
| 1360 | 1332 | 1312 |

公网 ingress 路径为 1500 时建议两端设置 `initial_mtu = 1452`，并将业务
`max_inner_datagram` 保守设为 1200。实现每包检查
`connection.max_datagram_size()`；编码后超限会记录
`oversized_datagram_drop` 并丢弃，不依赖 IP 分片、不降级为 stream。

Rove→后端的 1360 MTU 是另一个 MTU 域，不会反向压缩 relay→Rove 的 1500 路径。
若 1360 指 L3 MTU，后端 QUIC payload 应用 1332（IPv4）或 1312（IPv6）；若它
已经是 Quinn `initial_mtu`，则不要再次扣除 IP/UDP 头。

## 防火墙与权限

- relay 放行 `listen` 的 UDP 端口（QUIC）；
- 放行授权池中实际使用的公网 TCP/UDP 端口；
- NAT 内 Rove 只需要主动出站 UDP 到 relay；
- 绑定 443 等低端口时给 `rove-relay` 最小化授予
  `CAP_NET_BIND_SERVICE`，不要长期以 root 运行；
- relay 配置与节点 token 不进入策略快照。

## 本地基准测试

`docker-compose.local.yml` 已包含 `rove-local-relay-ingress`，并把同一组 Rove
HTTP/HTTPS/SOCKS5 listener 同时暴露为本地直连与 reverse-ingress 两条路径：

```bash
./scripts/generate-local-certs.sh
docker compose -f docker-compose.local.yml up -d --build

cargo run --release --example proxy-benchmark-local -- latency \
  --paths local,reverse-ingress --modes direct
```

本地 TCP 路径端口为 `18080/18443/11080/11081`，relay TCP 路径为
`38080/38443/31080/31081`。benchmark JSON 的 `path` 字段用于分组比较；默认仍只
测 `local`，避免历史 `all` 命令的用例数和耗时翻倍。

TUIC 使用专用基准，直连端口为 `10443/udp`，relay 路径为 `30443/udp`：

```bash
cargo run --release --example tuic-benchmark-local -- --path reverse-ingress
```
