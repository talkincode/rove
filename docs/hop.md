# 独立 hop 节点（`rove-hop`）

`rove-hop` 是一个**独立运行的二级出口（hop）代理**：不连控制面、不读快照、不执行策略、不限速。它的定位是
「受控网络里的一个干净出口」—— 主节点（edge）把命中分流规则的流量转发给它，由它直连真实目标。

> 它和主节点 `rove` 共用同一套访问日志与 SNMP 方案，但**没有**用户/策略/限速这些控制面能力。

## 认证

hop 用单一用户名密码认证，来自命令行或环境变量：

- `--username` / `--password`
- `Rove_HOP_USERNAME` / `Rove_HOP_PASSWORD`

未配置时使用兼容默认值 `rove` / `rove`，进程会打印警告。**公网或共享网络部署必须显式设置非默认凭据。**

## 三种入口

| 参数 | 含义 |
|---|---|
| `--socks5 ADDR` | 明文 SOCKS5 |
| `--https ADDR` | HTTP CONNECT over TLS |
| `--socks5tls ADDR` | SOCKS5 over TLS |
| `--tls-cert` / `--tls-key` | TLS 入口所需的证书与私钥 |

```bash
# 只启动明文 SOCKS5
./rove-hop --socks5 0.0.0.0:1080

# 同时启动 HTTPS、SOCKS5、SOCKS5-over-TLS
./rove-hop \
  --https 0.0.0.0:8443 \
  --socks5 0.0.0.0:1080 \
  --socks5tls 0.0.0.0:1081 \
  --tls-cert ./certs/server.crt \
  --tls-key ./certs/server.key \
  --username hop-user \
  --password hop-pass
```

主节点分组里把 `upstream` 指向这个 hop（`kind = "http"` 或 `"socks5"`，`addr` 填 hop 地址，带上凭据），
即可把命中 `proxy` 的流量分流过来。见 [数据模型 · 二级代理](./data-model.md#二级代理upstream)。

## 专用出口 DNS（可选）

hop 常位于目标网络里、亲自解析并连出用户目标域名，因此这里最需要防污染 DNS。用
`--dns-server`（可重复，`ip` 或 `ip:port`）把 hop 的**所有出口目标解析**（HTTP/SOCKS5
入口与反向隧道目标）改走指定 DNS，`--dns-protocol udp|tcp|tls|https` 选传输；不设则用系统解析器。
bare IP 的默认端口随传输：udp/tcp=53、tls=853、https=443。

```bash
./rove-hop --socks5 0.0.0.0:1080 \
  --dns-server 10.0.0.53 --dns-server 10.0.0.54:5353 --dns-protocol tcp
```

跨不可信链路时用加密 DNS（DoT/DoH）抗投毒，`--dns-server-name` 校验证书名，私有服务器用
`--dns-ca` 指向自签 CA：

```bash
./rove-hop --socks5 0.0.0.0:1080 \
  --dns-server 10.0.0.53 --dns-protocol tls \
  --dns-server-name dns.internal --dns-ca /etc/rove/dns-ca.pem
```

DoH 加 `--dns-doh-path`（默认 `/dns-query`）；自签名且无 CA 时可用 `--dns-insecure`（危险，跳过校验）。
拼错地址或协议、或 tls/https 少填 `--dns-server-name` 会 fail-closed（启动即报错），不会静默回落系统解析器。

## 反向模式（NAT / 防火墙后）

当 edge 无法主动拨号 hop（hop 在 NAT / 私有网络后）时，hop 可以**主动用 QUIC 拨到 edge 注册**，由 edge 反向
开隧道。可以只跑反向会话（不配任何本地 listener），也支持多个 `--reverse-quic` 注册到多个 edge：

```bash
# 令牌走环境变量，避免进 argv
Rove_HOP_REVERSE_TOKEN=REPLACE_WITH_TOKEN ./rove-hop \
  --reverse-quic edge.example.com:9443 \
  --reverse-hop-id rove-hop-jp
```

常用反向参数：`--reverse-quic`（可重复）、`--reverse-hop-id`、`--reverse-token`、`--reverse-server-name`、
`--reverse-insecure`、`--reverse-max-streams`、`--reverse-initial-mtu`（跑在压缩/固定 MTU 隧道里时固定
QUIC 路径 MTU，UDP 载荷字节 1200-1500）。edge 侧 `[reverse_hop]` 配置、多 edge、观测与 NAT 保活见
[反向 hop 数据面](./reverse-hop.md)。

## 外网出口诊断 `doctor egress`

内置一个手工诊断命令，**不启动代理监听、不连控制面**。默认从 Google、YouTube、OpenAI、Cloudflare、GitHub
里随机挑一个目标做深度诊断；也可指定 preset 名、域名、`host:port` 或 URL：

```bash
./rove-hop doctor egress                         # 随机目标，文本输出
./rove-hop doctor egress github.com              # 指定目标
./rove-hop doctor egress api.openai.com:443 --trace
./rove-hop doctor egress --target github --trace --json   # 给脚本用
```

输出按 **DNS、route、TCP、TLS、HTTP** 和可选 **trace** 分层。`--trace` 优先调用系统 `traceroute`，缺失时尝试
`tracepath`，逐跳输出 hop index、IP、反查主机名、RTT；系统没有 trace 工具则该层标记 `skipped`，不影响其他层。

## MQTT 远程 egress doctor（可选，默认关）

hop **不**挂 edge 的用户查询 / 同步 / 拨测通道。需要 TE3 远程回收与 `doctor egress --json`
同构的分层报告时，单独打开 hop MQTT：

```bash
rove-hop --socks5 0.0.0.0:1080 \
  --mqtt-broker tcp://mqtt.example.com:1883 \
  --mqtt-hop-id rove-hop-jp \
  --mqtt-username mqtt-user
# 密码走 Rove_HOP_MQTT_PASSWORD，不要进 argv
```

| 用途 | 主题 | 方向 |
| --- | --- | --- |
| 触发 doctor | `rove/hop/<hop_id>/doctor` | 控制面 → hop |
| 一次性回复 | `rove/replies/hop-doctor-<id>`（前缀默认 `rove/replies/`） | hop → 控制面 |

请求必须带 `target`（preset / `host:port` / URL）和合法 `reply_topic`。`trace` 默认关，超时夹在 500ms–30s。
回包字段与 `--json` 相同（`kind=egress_diagnostic`，`dns/route/tcp/tls/http/trace`），并附加
`event=hop_egress_doctor`、`hop_id`、`request_id`。token / 密码不会进回包。doctor **不**跑在 splice / CONNECT 热路径上；
未配 `--mqtt-broker` 时进程行为与现在完全一致。

详见 [MQTT 对接](./mqtt-integration.md#hop-egress-doctor)。

## 访问日志

hop 与主节点访问日志方案完全一致（默认开启、按天轮转、保留 7 天）。可用这些参数调整：

`--access-log-disable`、`--access-log-dir`、`--access-log-file-prefix`、`--access-log-retention-days`、
`--access-log-channel-capacity`；转发 syslog 用 `--access-log-syslog ADDR`（搭配 `--access-log-syslog-protocol`
/ `-facility` / `-tag`）。详见 [访问日志](./access-log.md)。

## SNMP 监控

hop 同样内置只读 SNMP agent：

- 快捷开启 v2c：`--snmp-listen 0.0.0.0:161 --snmp-community <secret> --snmp-allow <cidr>`（`--snmp-allow` 可重复）。
- 需要 SNMPv3 时：`--snmp-config snmp.toml` 引用一个只含 `[snmp]` 段的 TOML 文件，避免把 v3 口令暴露在命令行。

两种方式互斥。MIB 表与 Cacti 接入见 [SNMP 监控](./snmp-cacti.md)。

> 完整参数列表随时可查：`rove-hop --help`。

## RouterOS 容器部署

在 MikroTik RouterOS 上把 `rove-hop` 跑在 **container** 里、做 NAT 后反向出口时，请直接看运维专题：

- [RouterOS 容器部署 rove-hop](./hop-routeros.md)（步骤、脚本、验收、排障）
- [reverse-hop-id 命名规范](./hop-id-naming.md)（统一前缀 `rove-hop-`，如 `rove-hop-jp`）
- Release 可下载包：`rove-hop-routeros-<version>-arm64.tar.gz`
