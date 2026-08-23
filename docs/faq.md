# 常见问题 FAQ

按主题整理。找不到答案时，看 [故障排查](./troubleshooting.md) 或提 [Issue](https://github.com/talkincode/rove/issues)。

## 基础与概念

**Rove 和 GOST 是什么关系？**
旧版 Rove 是 GOST 的一组控制面插件（auth/bypass/limiter/hop/observer，走 gRPC），受限于 GOST 的插件边界。
本项目是 **Rust 重写**，把代理数据面和策略控制收进一个二进制，**不再依赖 GOST、gRPC、数据库或转发中继**。

**它是控制面吗？能管理用户吗？**
不是。节点只**消费**控制面下发的快照，自己不管理用户、套餐、计费。用户和策略的真相在你的控制面。

**必须有控制面才能用吗？**
不是必须。节点启动时先读本地缓存 `cache_path`，只要缓存里有用户就能工作。快速试用可以直接手写一份
`snapshot.json`（见 [快速开始](./quickstart.md)）。但生产环境推荐用控制面统一下发。

**支持哪些接入方式和出口？**
应用接入（listener adapter）：HTTP CONNECT 隧道、明文 HTTP absolute-form 转发、SOCKS5（含 UDP），
各自可叠加 TLS（`https` / `socks5tls`）；另有独立的 TUIC v5（QUIC）前端。
出口（egress）：直连、HTTP 上游、SOCKS5 上游、反向 hop（QUIC）、Subnetra 加密 L3 组网，
以及按优先级故障转移的 egress chain。

---

## 部署与运行

**怎么指定配置文件？**
`rove -c config.toml` 或 `--config config.toml`。省略时默认读当前目录 `config.toml`。

**需要 root 吗？**
不需要。只有绑定 <1024 的端口（443/161 等）需要权限，用 systemd 的
`AmbientCapabilities=CAP_NET_BIND_SERVICE` 授予即可，无需整个进程用 root。

**有系统依赖吗？**
没有。TLS 走 rustls（ring），二进制自带 CA 根证书，不依赖 OpenSSL。运行环境要求见 [安装与部署](./installation.md)。

**支持优雅停机 / 零停机升级吗？**
当前收到退出信号后会先停止新接入，并在配置的有界窗口内排空在途连接；超时后强制结束剩余会话。升级仍建议先通过 readiness 摘流。节点
**先读缓存再联网**，重启后能立即恢复服务。

**能在 RouterOS 容器里跑 rove-hop 吗？**
可以。推荐 **reverse QUIC only**（NAT 后主动注册到 edge）。运维专题见
[RouterOS 容器部署 rove-hop](./hop-routeros.md)；Release 提供
`rove-hop-routeros-<version>-arm64.tar.gz`（手册 + `.rsc` + Docker-save 镜像）。
`hop_id` 使用前缀 `rove-hop-`（如 `rove-hop-jp`），见 [命名规范](./hop-id-naming.md)。

**Docker 里缓存/证书怎么处理？**
把 `cache_path` 指向挂进容器的可写目录，证书按 `[listeners.tls]` 路径挂载。自定义 CA 用
`Rove_EXTRA_CA_CERTS` 追加。见 [安装与部署 · Docker](./installation.md#方式二docker)。

---

## 控制面与快照

**快照接口长什么样？**
`GET {snapshot_url}?since={本地版本}`，带 `Authorization` 头。返回 `200` + `RawSnapshot`（版本前进时）或
`304 Not Modified`（无变更）。接口**不带 `node_id`**，所有节点命中同一 URL、收到相同响应。完整协议见
[控制面同步协议](./snapshot-protocol.md)。

**控制面可以是静态文件吗？**
可以。因为接口不按节点路由，控制面完全可以用静态文件 / 对象存储提供，无需后端逻辑。

**不同节点要不同策略怎么办？**
用快照里的 `node_overrides`（按 `node_id` 索引）。控制面对所有节点发同一份快照，节点用本地 `node_id` 自行挑出
覆盖并在本地合并。见 [数据模型 · 节点级覆盖](./data-model.md#节点级覆盖-node_overrides)。

**控制面挂了会怎样？**
节点继续用当前内存快照服务；坏快照 / 超大响应 / HTTP 错误 / 编译失败都不会污染当前状态。连续失败会指数退避到
最高 5 分钟再重试。

**`since` 怎么工作？**
节点带上本地版本号；`version <= since` 或 `304` 时不重编译、不刷日志。`version` 必须**单调递增**。

---

## 认证、策略与限速

**一个用户最少要配哪些字段？**
当前快照 schema：`password` 和 `policy`（指向 `routing_policies` 中的一项）。`expire` 缺省为永不过期，
`up_rate`/`down_rate`/`max_connections` 缺省为 0（不限）。

**决策顺序是什么？**
按 policy 的 `routes` 数组 first-match-wins；命中 `block` 拒绝，命中 `egress`/`direct`
按 action 执行；都未命中则用 `default_egress`，没有 default 则直连。sniff 安全语义见
[数据模型 · 决策流程](./data-model.md#决策流程-decide)。

**域名规则 `discord.dev` 会匹配子域名吗？**
会。默认是**后缀匹配**，同时匹配 `discord.dev` 和 `*.discord.dev`。要精确匹配用 `full:`，关键字用 `keyword:`。
写在 route 的 `selectors` 里，语义相同。

**怎么让某个用户全量走某个上游？**
policy 配 `default_egress` 指向 named egress，不必写 catch-all route。未命中其它 route 的目标都会走该出口。

**限速精度如何？**
每用户字节令牌桶（`up_rate`/`down_rate`）。两者为 0 时走 `copy_bidirectional` 零开销快路，不影响吞吐。

**账号过期后返回什么？**
HTTP 入口返回 `403`，SOCKS5 入口拒绝。策略 `block` 命中同样如此。密码错误则是 `407`（HTTP）。

---

## TLS 与证书

**怎么开 HTTPS 入口？**
给 `http` 协议的 listener 加 `[listeners.tls]`（cert + key）即升级为 HTTPS。`socks5` 加 TLS 段则是 `socks5tls`。

**上游 hop 是自签名证书，节点连不上？**
两个选择：给节点设 `Rove_EXTRA_CA_CERTS` 追加信任那张 CA（推荐），或在该上游单独设
`skip_cert_verify=true`（仅限受控网络）。`skip_cert_verify` 是**逐上游**开关，不存在全局关校验。

**curl 走 HTTPS 代理报证书错误？**
自签名时用 `--proxy-cacert ./ca.crt` 指定 CA，或 `--proxy-insecure` 跳过（仅测试）。

---

## 二级代理与 hop

**`rove` 和 `rove-hop` 有什么区别？**
`rove` 是主节点（连控制面、执行策略/限速）。`rove-hop` 是独立出口，**不连控制面、不执行策略、不限速**，
只做认证 + 直连。见 [独立 hop 节点](./hop.md)。

**hop 忘了设密码会怎样？**
会用默认 `rove`/`rove` 并打印警告。**公网部署务必显式设置非默认凭据。**

**反向 hop 连不上，edge 端口放行了 TCP 还是不行？**
反向 hop 走 **QUIC = UDP**。请放行 `[reverse_hop].listen` 对应的 **UDP** 端口，不是 TCP。

**edge 找不到 hop 会回落直连吗？**
不会。`kind = "reverse"` 是 fail-closed：没有该 `hop_id` 的已认证会话就直接报错。

---

## 可观测与监控

**怎么排查「某用户连不上某站点」？**
`grep` / `jq` 访问日志：每条连接都有 `username`、`target_host`、`decision`、`result`、`failure_stage`。见
[访问日志](./access-log.md)。

**访问日志会记密码吗？**
永不。`decision` 携带上游地址但不含上游密码，用户密码也从不出现在日志里。

**能接 Cacti / LibreNMS 吗？**
能。内置只读 SNMP agent（v2c + v3 USM），暴露每 listener、每出口的活跃连接与累计字节。只支持
GET/GETNEXT/GETBULK。见 [SNMP 监控](./snmp-cacti.md)。

**有 `/healthz` 或 Prometheus 端点吗？**
有可选的 `/healthz`（存活）和 `/readyz`（快照/控制面/listener 活性/排空状态）HTTP 端点，默认关闭且只监听
`127.0.0.1:9090`；配置见 [配置详解](./configuration.md#health-存活与就绪探针默认关闭)。Prometheus
端点仍未提供。访问日志 `kind:"stats"` 心跳和 SNMP 轮询继续用于流量与历史观测。

---

## 安全

**会不会在失败时变成开放代理？**
不会。认证失败、账号过期、`block` 命中、快照编译失败、上游连接失败等，默认行为一律保守拒绝。

**示例配置里能放真实令牌吗？**
不能。仓库和示例只允许占位符。真实令牌、密码、证书、客户策略必须由部署环境管理，不进版本库。
