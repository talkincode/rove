# 客户端接入

代理客户端当前使用 HTTP、HTTPS、SOCKS5、SOCKS5-TLS 或 TUIC，全部需要各自的客户端凭据。另有不需要
客户端代理设置的 [应用出口网关](./egress-gateway.md)：T1 SNI 透明入口已可用，T2 `base_url` HTTPS 网关仍在规划。
不要把 HTTP/SOCKS/TUIC 入口配成「反代」。
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

## T1 SNI 透明应用出口网关

适用于应用**不能设置代理**、但能保留原始目标名称并让 DNS 指向 Rove 的场景。客户端无需填写代理地址、
用户名或密码；它仍照常连接 `https://api.example.com`，而部署者只将这个已允许的域名在客户端 DNS 视图中
改写到 Rove 的 `protocol = "sni"` listener。

- 客户端必须发送普通 TLS ClientHello SNI；无 SNI、ECH 内层名称、QUIC/HTTP3 不适用。
- listener 的服务端 `identity` 是当前快照中的用户，不是客户端凭据；`origins` 是闭合精确白名单。
- listener 与 origin 使用同一端口，通常均为 `443`；Rove 会原样转发 TLS，不需要也不应安装 origin 证书。
- 只为 `origins` 中的名称改写 DNS，并保证 Rove 的 egress DNS 解析真实 origin，而非网关自身，避免回环。

完整配置、拒绝语义和多租户边界见[应用出口网关](./egress-gateway.md)。若应用只能修改 `base_url`，请等待
规划中的 T2，而不是把客户端 Host 当作转发目标。

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
