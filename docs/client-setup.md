# 客户端接入

节点提供四种入口，全部需要**用户名 + 密码**认证（凭据来自控制面下发的快照）。本章给出各类客户端怎么连。

| 入口 | `protocol` + TLS | 典型 URL scheme | 说明 |
|---|---|---|---|
| HTTP | `http` | `http://` | HTTPS 走 CONNECT；明文 HTTP 走 absolute-form；Proxy-Authorization Basic |
| HTTPS | `http` + `[listeners.tls]` | `https://` | CONNECT / absolute-form over TLS |
| SOCKS5 | `socks5` | `socks5h://` | RFC1928 + 用户名密码认证 |
| SOCKS5-TLS | `socks5` + `[listeners.tls]` | —— | SOCKS5 over TLS，需客户端/隧道支持 |

> 假设用户名 `alice`、密码 `s3cret`，节点地址 `proxy.example.com`。

---

## curl

```bash
# HTTPS 目标：HTTP CONNECT（代理连接明文）
curl -x http://alice:s3cret@proxy.example.com:8080 https://ifconfig.me

# 明文 HTTP 目标：absolute-form 正向转发
curl --proxy http://proxy.example.com:8080 --proxy-user 'alice:s3cret' http://example.com/

# HTTPS 代理（代理连接本身走 TLS）
curl -x https://alice:s3cret@proxy.example.com:8443 https://ifconfig.me
#   自签名证书时任选其一：
#   --proxy-cacert ./ca.crt      指定 CA（推荐）
#   --proxy-insecure             跳过校验（仅测试）

# SOCKS5（socks5h 让 DNS 在代理侧解析，避免本地 DNS 泄露）
curl -x socks5h://alice:s3cret@proxy.example.com:1080 https://ifconfig.me
```

拿到你的出口 IP 即成功。密码错误应得到 `407`（HTTP/HTTPS）或被 SOCKS5 拒绝。

---

## 环境变量（大多数 CLI 通用）

```bash
export http_proxy="http://alice:s3cret@proxy.example.com:8080"
export https_proxy="http://alice:s3cret@proxy.example.com:8080"
# 之后 curl / wget / git / pip / npm 等大多会自动走代理
git clone https://github.com/some/repo.git
```

---

## 浏览器 / 操作系统代理

- **HTTP/HTTPS 代理**：在系统或浏览器代理设置里填 `proxy.example.com` + 端口。原生代理设置通常不带鉴权
  输入框，首次访问会弹窗要用户名密码；需要免弹窗可借助扩展（如 SwitchyOmega）在 URL 里带上凭据。
- **SOCKS5**：填 SOCKS5 主机与端口，勾选「远程 DNS」（等价于 `socks5h`）以避免 DNS 泄露。

---

## 移动客户端（Shadowrocket 等）

以 Shadowrocket 为例，新增节点：

- **HTTP / HTTPS**：类型选 HTTP / HTTPS，填地址、端口、用户名、密码；HTTPS 需要服务端证书被信任
  （自签名要导入 CA）。
- **SOCKS5 / SOCKS5-over-TLS**：类型选 SOCKS5，勾选 TLS 即对应 `socks5tls` 入口；同样需要证书可信。
- **TUIC**：类型选 TUIC，填 UUID、密码、ALPN——见下方 [TUIC 客户端](#tuic-客户端)。

---

## TUIC 客户端

当节点开了 [`[[tuic_listeners]]`](./tuic.md) 时，用支持 TUIC v5 的客户端（Shadowrocket、v2rayN、sing-box 等）接入。关键字段必须与服务端对齐：

| 客户端字段 | 取值 |
| --- | --- |
| 地址 / 端口 | 监听的 `listen`（UDP 口） |
| UUID | 该用户快照 `frontends.tuic.uuid` |
| 密码 | 该用户快照 `frontends.tuic.password`（**不是**登录密码） |
| ALPN | 监听配置的 `alpn`（默认 `h3`），须逐字一致 |
| UDP relay mode | `native`（QUIC datagram）；本节点不支持 `quic`（stream）模式 |
| 证书 | 自签名证书需开启「允许不安全 / skip-cert-verify」或导入 CA |

sing-box `outbounds` 片段示例：

```jsonc
{
  "type": "tuic",
  "server": "edge.example.com",
  "server_port": 8443,
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "password": "front-end-only-secret",
  "udp_relay_mode": "native",
  "tls": { "enabled": true, "alpn": ["h3"], "insecure": false }
}
```

要走 UDP（如 WebRTC / 游戏），该用户的分组还需把目标路由到一个 `reverse` 上游（见 [TUIC · UDP 出口](./tuic.md#udp-出口必须落在反向-hop)）。

---

## 关于 SOCKS5-over-TLS（`socks5tls`）

这是「先建立 TLS，再在里面跑 SOCKS5」。`curl` 没有内建的 SOCKS5-over-TLS 开关，接入方式：

1. 使用**原生支持**的客户端（如 Shadowrocket 勾选 TLS 的 SOCKS5）。
2. 或本地用 `stunnel` 起一个 TLS 客户端隧道，把本地明文 SOCKS5 端口包成 TLS 连到节点的 `socks5tls` 口，
   再让应用连本地端口。

如果只是想给 SOCKS 流量加密，通常直接用 HTTPS 入口（`http` + TLS）更省事、生态支持更好。

---

## SOCKS5 UDP ASSOCIATE

`socks5` 入口支持 **UDP ASSOCIATE**（RFC 1928），可代理 UDP（如 DNS、QUIC、游戏、WebRTC 到媒体服务器）。用法对客户端透明：支持 UDP 的 SOCKS5 客户端（`curl --socks5-hostname` 不涉及 UDP；但 sing-box、v2rayN、Shadowrocket 的 SOCKS5 出站、`tun2socks` 等都支持）在 ASSOCIATE 后把 UDP datagram 发到节点回复的 BND 地址即可。

要点与边界：

- **UDP 出口只经反向 hop**：该用户的分组必须把目标路由到一个 `reverse` 上游（见 [数据模型](./data-model.md#二级代理upstream)）。命中 Direct / HTTP 上游 / SOCKS5 上游或 `block` 的 UDP 包一律 **fail-closed 丢弃**（HTTP CONNECT 载不了 UDP）。
- **不分片**（`FRAG` 必须为 0）、**不限速**、**只放行 association 客户端源地址**的回包，适用 client→server 实时场景；不支持 full-cone / P2P 打洞（见 [reverse/2 UDP relay](./reverse-hop.md#reverse2-udp-relay)）。
- UDP 关联的生命周期 = 那条 TCP 控制连接：控制连接关闭即拆除。

---

## 排错速查

| 现象 | 可能原因 |
|---|---|
| `407 Proxy Authentication Required` | 用户名/密码错，或账号已过期 |
| `403 Forbidden` | 账号过期，或目标命中策略 `block` |
| 连接超时 | 端口未放行；TLS 入口用了明文 scheme（或反之） |
| TLS 证书报错 | 自签名未导入 CA；用 `--proxy-cacert` 或导入系统信任 |
| SOCKS5 能连但 DNS 解析异常 | 用 `socks5h://` 而非 `socks5://`，让代理侧解析 |

更多见 [故障排查](./troubleshooting.md)。
