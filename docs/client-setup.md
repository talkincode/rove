# 客户端接入

节点当前提供四种入口，全部需要认证。客户端按入口填参数即可。

应用改不了代理、只能改 DNS 或 `base_url` 时，看规划中的 [应用出口网关](./egress-gateway.md)
（SNI 透传 / 声明式 origin）。那一页还没落地，不要把现有 HTTP/SOCKS/TUIC 入口配成「反代」。
也不要把 [反向 hop](./reverse-hop.md) 或 [反向公网入口](./reverse-ingress.md) 理解成反向代理——
那两个词在本仓库里已经各有含义。

下面示例统一使用：用户 `alice` / 密码 `s3cret`，节点 `proxy.example.com`。

## HTTP / HTTPS

认证：用户名 + 密码（快照登录口令）。HTTPS 目标走 CONNECT；明文 HTTP 走 absolute-form。

| 参数 | HTTP | HTTPS |
|---|---|---|
| 类型 | HTTP 代理 | HTTP 代理 + TLS |
| 地址 | `proxy.example.com` | `proxy.example.com` |
| 端口 | `8080`（`[[listeners]]` 的 `listen`） | `8443` |
| 用户名 | 快照用户名 | 同左 |
| 密码 | 快照 `password` | 同左 |
| 鉴权 | `Proxy-Authorization: Basic` | 同左 |
| TLS | 无 | 服务端证书须被客户端信任；自签名需导入 CA 或关闭校验 |
| 远程 DNS | 由代理解析目标主机 | 同左 |

## SOCKS5 / SOCKS5-TLS

认证：RFC 1928 用户名密码，凭据同上。

| 参数 | SOCKS5 | SOCKS5-TLS |
|---|---|---|
| 类型 | SOCKS5 | 先 TLS，再 SOCKS5 |
| 地址 | `proxy.example.com` | `proxy.example.com` |
| 端口 | `1080` | `[[listeners]]` 带 `[listeners.tls]` 的口 |
| 用户名 / 密码 | 快照用户名 / `password` | 同左 |
| 远程 DNS | 开启（等价 `socks5h`） | 同左 |
| TLS | 无 | 证书须被信任 |
| UDP ASSOCIATE | 支持，见下 | 同左 |

`socks5tls` 需要客户端原生支持「SOCKS5 over TLS」。只想加密代理连接时，优先用 HTTPS 入口。

## TUIC v5

节点开了 [`[[tuic_listeners]]`](./tuic.md) 时使用。凭据是 `frontends.tuic`，**不是**登录密码。

| 参数 | 取值 |
|---|---|
| 类型 | TUIC v5 |
| 地址 | 监听主机 |
| 端口 | `listen`（UDP） |
| UUID | 快照 `frontends.tuic.uuid` |
| 密码 | 快照 `frontends.tuic.password` |
| ALPN | 监听配置的 `alpn`（默认 `h3`），须逐字一致 |
| UDP relay mode | `native`（QUIC datagram）；不支持 `quic` stream 模式 |
| 证书 | 须信任服务端证书；自签名则导入 CA 或关闭校验 |

UDP 还要求该用户策略把目标路由到 `reverse` 上游，见 [TUIC · UDP 出口](./tuic.md#udp-出口必须落在反向-hop)。

## SOCKS5 UDP ASSOCIATE

`socks5` 入口支持 RFC 1928 UDP ASSOCIATE。客户端在 ASSOCIATE 成功后，把 UDP datagram 发到节点返回的 BND 地址。

- UDP 出口只经反向 hop：用户策略须把目标路由到 `reverse` 上游。Direct / HTTP 上游 / SOCKS5 上游 / `block` 一律丢弃。
- 不分片（`FRAG` 必须为 0）、不限速、只放行 association 客户端源地址的回包。
- 关联生命周期等于那条 TCP 控制连接。

详见 [reverse/2 UDP relay](./reverse-hop.md#reverse2-udp-relay)。

## 排错

| 现象 | 可能原因 |
|---|---|
| `407 Proxy Authentication Required` | 用户名/密码错，或账号已过期 |
| `403 Forbidden` | 账号过期，或目标命中策略 `block` |
| 连接超时 | 端口未放行；TLS 入口用了明文，或反之 |
| TLS 证书报错 | 自签名未导入 CA |
| SOCKS5 能连但解析异常 | 未开远程 DNS |

更多见 [故障排查](./troubleshooting.md)。
