# Rove 项目画像与方向

## 项目概述

Rove 是开源的应用网络优化器：一个轻量、单体、模块化的应用出口节点。
它服务的是 Agent API、投资交易、SaaS 多云出口、Webhook 固定出口、隔离网段访问等对路径、时延和策略敏感的应用流量。
节点本地完成前端接入、用户鉴权、策略决策、限速和出口连接。仓库可以包含 `rove-hop`、`rove-relay` 等第一方伴生进程，但这些进程必须保持独立部署和窄边界；应用层（模型请求体、成交回报、账单）语义不进入节点热路径。

节点不持有业务真相。控制面通过 HTTP 下发编译好的用户与策略快照，节点将快照编译为进程内结构并热替换；本地缓存用于离线或控制面不可达时的热启动。当前事实主要由 `README.md`、`Cargo.toml`、`config.example.toml` 和 `src/` 下的实现支撑。

架构图：

```text
client
  |
  v
optional public rove-relay -- rove-ingress/1 QUIC --> NAT-side connector
  |
  v
listeners: HTTP CONNECT / absolute-form / SOCKS5 / TUIC, optional TLS
  |
  v
engine: authenticate + decide over ArcSwap snapshot
  |                    ^
  |                    |
  v                    |
outbound: direct / HTTP upstream / SOCKS5 upstream
  |                    |
  v                    |
origin or upstream     |
                       |
control plane HTTP snapshot sync
  |
  v
local cache: data/snapshot.json
```

## 项目画像（目标状态）

Rove 应该成为一个可以部署在边缘节点上的自包含**应用出口平面（application egress plane）**：为应用侧的出站流量提供身份、策略、路由、出口选择、限速与审计。配置面简单、热路径短、失败模式可预期，运维人员不需要理解一张 service / chain / hop / listener / connector 的组合图，也不需要在节点侧维护反范式的用户数据。

项目优先级是：链路正确性和策略一致性高于功能数量；离线可启动和快照热替换高于控制面实时性；节点二进制的可审计性和低依赖高于插件式扩展的灵活性。新增能力必须服务于「应用出口平面」这个核心角色，不能把节点扩张成控制面、管理后台或通用流量编排平台。

工程质量上，Rove 不能接受“先堆功能、后补测试”的开发方式。任何影响出口链路、认证、策略、限速、快照同步、MQTT 运维通道、配置解析或安全失败模式的变化，都必须先定义可失败的自动化验收，再通过最小实现让测试通过。覆盖率是项目准入门槛，不是发布后的补救项。

用户体验上，节点应该保持少量明确配置：节点身份、控制面地址与令牌、监听列表、日志等级。运行时行为应该可观察、可回退、可解释；当控制面失败、快照无效、出口不可达或认证失败时，节点应给出明确结果，而不是静默降级成绕过策略的开放代理。

## 当前能力清单

- 单体 Rust 代理二进制

  `Cargo.toml` 定义 `rove` 二进制入口为 `src/main.rs`，Rust 最低版本为 1.88。当前实现使用 Tokio、rustls、reqwest、ArcSwap 等库，不依赖 GOST、gRPC、数据库或 OpenSSL 系统库。

- HTTP CONNECT、absolute-form 与 SOCKS5 前端接入

  `src/inbound/listener.rs` 根据监听配置分发 `http` 与 `socks5` 协议，并可在监听层包裹 TLS。`src/inbound/http.rs` 支持 CONNECT 和明文 HTTP absolute-form；`src/inbound/socks5.rs` 支持用户名密码认证后的 CONNECT 与 UDP ASSOCIATE。

- NAT 后反向公网入口（reverse ingress）

  `rove-relay` 在公网提供独立的 `rove-ingress/1` QUIC 数据面；NAT 内 Rove 通过可重复的
  `[[reverse_ingress]]` connector 主动注册，只能把 relay 预授权的 TCP/UDP 端口映射到本机已经声明的
  listener 名称。TCP 每连接一条独立 QUIC stream，UDP 保持 datagram 语义并按有界 flow 转发，可承载真实
  TUIC 握手；relay 不终止用户 TLS、不持有用户证书私钥、不执行用户策略。节点 token、端口池、并发/flow
  上限、动态租约 grace、MTU 与原始客户端地址关联均 fail-closed，详见
  [反向公网入口](./reverse-ingress.md)。

- 用户认证、过期校验、策略决策和热替换

  `src/engine.rs` 使用 `ArcSwap<Snapshot>` 提供热替换快照，认证路径按用户名查找用户并检查密码与过期日期。`src/model.rs` 将控制面下发的唯一一种快照 schema（`schema_version: 1`：`users` + `routing_policies` + `egresses` 三张独立表）按节点 `node_id` 编译为运行期 `Snapshot`（`Snapshot::compile(doc, node_id)`）。决策按有序 route first-match-wins 选择 named egress / direct / block，未命中执行 policy 的 `default_action`（同一套 `egress` / `direct` / `block` 词汇，其中 `block` 表达 deny-by-default 策略），没有 default 则直连。全部 wire 结构 `deny_unknown_fields`，异形或含未知字段的文档整份拒收而非半懂半猜地执行。`node_overrides` 让控制面向所有节点发同一份快照，同时仍能给个别节点整项替换已存在的 egress realization（不能新增 node-only egress，也不能改 policy），详见 `docs/snapshot-protocol.md`。

- 域名与 IP 规则匹配

  `src/policy/domain.rs` 支持默认后缀匹配、`full:` 精确匹配和 `keyword:` 关键字匹配；`src/policy/ip.rs` 支持单 IP 和 CIDR。当前 `cargo test` 覆盖这些匹配语义，测试结果为 4 项通过。

- rove-addrbook 版本化地址数据集（`.rab` + `book:` 规则 scheme）

  `src/addrbook/` 实现稳定的 `.rab` 二进制格式（小端、偏移寻址、SHA-256 尾部校验、确定性构建、加载期全量不变量校验，规范见 `docs/addrbook-format.md`）与层级分类查询（IP 区间二分、域名 exact/后缀/关键字、`google` 自动展开 `google/ads` 等子孙）。控制面快照在 route `selectors` 里用 `book:<category>` 引用分类；同一条 route 内显式规则与 addrbook 分类按“或”组合，跨 route 的优先级由 routes 数组顺序决定。快照编译期钉住书版本，书热替换 = 重编译最近快照，成功才双双替换。fail-closed：无书或未知分类拒绝整个快照，坏工件启动即拒绝、运行期保留旧书。`rove-abctl` 提供 fetch/build/verify/diff/query/bench 采集构建工具链，支持 cidrs、Rove 域名规则、v2fly domain-list、AWS/Azure/GCP 官方地址段六种数据源，`diff --max-shrink` 作为发布异常门。控制面快照里的显式地址仅作补充，addrbook 是主要地址源。数据发布走独立于二进制版本的定期通道：`.github/workflows/addrbook-release.yml` 用仓库清单 `addrbook/book.toml` 定时构建，经 verify/diff 门/探针后发布到滚动 Release 标签 `addrbook-latest`；数据门禁失败只阻断数据更新，不影响代码发布。

- direct、HTTP upstream、SOCKS5 upstream 出站连接

  `src/outbound/mod.rs` 支持直连、HTTP CONNECT 上游出口、SOCKS5 上游出口，并允许 upstream 连接使用 TLS。HTTP upstream 可带 Basic 认证，SOCKS5 upstream 可带用户名密码认证。每个 upstream 可通过 `skip_cert_verify`（默认 `false`）单独关闭 TLS 证书链/主机名/有效期校验，用于自签名证书或纯 IP 的 hop 节点；这是逐个 upstream 的显式开关，不影响入站监听端的 TLS 校验，也不存在全局开关。

- 每用户字节速率限制

  `src/io.rs` 在双向 splice 中按用户 `up_rate` 和 `down_rate` 应用字节令牌桶；速率为 0 时使用 `copy_bidirectional` 快路。

- 控制面轮询、快照缓存与热启动

  `src/sync/mod.rs` 从配置的 `snapshot_url`——完整地址，不拼接任何固定路径，只追加 `?since=`/`&since=`——拉取快照。接口不带 `node_id`，所有节点命中同一个 URL 并收到完全相同的响应体。使用 Bearer token，支持 304 不变更语义，先读本地缓存再立即尝试一次控制面同步；远端新版本先编译验证，只有可服务的快照才会原子写回缓存并热替换引擎快照，连续同步失败会退避重试。需要按节点区分的出口（如不同边缘位置的本地 hop）由节点拿到同一份响应体后，用本地配置的 `node_id` 去响应体自带的 `node_overrides` 里自选、在本地合并，控制面不需要知道请求者是哪个节点。

- MQTT 异步运维通道

  `src/mqtt.rs` 在配置启用后连接 MQTT broker，沿用旧版默认主题响应用户策略查询和同步指令；`src/trace.rs` 支持拨测前短 TTL 武装追踪，匹配到下一条 HTTP CONNECT 或 SOCKS5 连接后回传阶段结果；`src/diagnostics.rs` 在此之上提供可选的诊断事件会话：按用户维度武装有限时长会话，对每条匹配连接持续发布脱敏事件并在到期或取消时汇总，默认关闭、不落盘；连接完成路径只进入有界同步临界区，发布使用 `try_send`、不执行异步等待。消息契约见 `docs/mqtt-integration.md`。

- 结构化访问日志

  `src/access_log.rs` 是老版本 GOST 详细流量日志的直接替代品：每条完成的连接（成功或在任一阶段失败）落一行 `kind:"connection"` 的 JSONL，字段含客户端来源 `client_addr`、用户名、目标、决策（`decision` 携带具体上游地址如 `upstream:10.0.0.5:1080` 而非仅类别）、结果、失败阶段、字节数等；reverse ingress 流量还带 `relay_instance_id`、`tunnel_session_id` 与 `ingress_id`/`flow_id`，可和 relay JSONL 联合溯源真实 IP。日志永不包含密码或 token，独立于 `log.level` 和 MQTT。默认开启，用 `tracing-appender` 按天轮转，按文件名日期保留 7 天；热路径经有界 `mpsc` 队列非阻塞投递，队满丢弃并计数；可选转发到远程 syslog（手搓最小 RFC 3164，支持 UDP/TCP，TCP 写入带 3 秒超时以避免卡死的远程 collector 拖垃后台写入任务）。同一条流水线每 60 秒还额外写一行 `kind:"stats"` 记录，按 listener（不按用户，避免无界基数）聚合当前活跃连接数与累计/增量字节数，是老版本 Go `ObserverEvent` 周期性 stats 事件最接近的对应物，也是连接量低谷期证明进程和 listener 仍存活的心跳信号。

- 内置只读 SNMP agent（v2c + v3 USM）

  `src/snmp/` 内嵌一个默认关闭的只读 SNMP agent（`rove` 与 `rove-hop` 都支持），供 Cacti / LibreNMS 等标准 NMS 直接轮询：手写 BER 编解码子集，暴露标准 `system` 组与企业子树下的 `listenerTable` / `egressTable`（每监听入口、每出口的活跃连接 Gauge32 与累计上/下行字节 Counter64，由 `src/stats.rs` 在热路径原子维护）。SNMPv2c 走 community（常量时间比较）+ 来源 CIDR 白名单；SNMPv3 USM 支持 SHA-1/SHA-256 认证、AES-128-CFB 加密、密钥本地化、engineBoots 落盘和完整的 discovery/Report 流程，安全策略 fail-closed（用户必须有认证；配了加密就强制 authPriv）。只实现 GET/GETNEXT/GETBULK，SET/TRAP/INFORM、MD5/DES 永不支持；SNMP 故障（端口占用、畸形包）不影响代理转发。MIB 与 Cacti 接入见 `docs/snmp-cacti.md`。

- 扁平 TOML 配置

  `src/config.rs` 和 `config.example.toml` 表明节点配置集中在节点 ID、控制面、监听和日志等级。TLS 由监听项内的默认证书和私钥路径开启；TCP listener 还可声明额外的 SNI → 证书映射，在同一 IP:port 和单个 Rove 进程内服务多个独立证书，未知或缺失 SNI 回退默认证书。

- 内嵌 Subnetra 组网底座（hub / spoke）

  `src/subnetra/` 原生实现 Subnetra v1 线格协议，作为可插拔的轻量 Layer-3 加密隧道底座——无需单独部署守护进程、无需 TUN（规范 §1 允许用户态 IP 栈）。数据面（`crypto`/`wire`/`replay`/`session`/`peer`/`reactor`）实现 BLAKE2b-256 keyed KDF + ChaCha20-Poly1305、20 字节小端头、头部混淆、64 位滑动防重放、认证前不改状态的 epoch 前向排序、内源过滤、认证后端点学习与最长前缀路由（hub 可 relay、禁反射）；`netstack/`（smoltcp，Medium::Ip）在 overlay 上终结内层 TCP，产出 `AsyncRead`/`AsyncWrite` 流接入现有代理机制。`mode = "hub"` 在 overlay 上跑 HTTP/SOCKS 代理入口（可无 TCP 监听）；`mode = "spoke"` 作为 `upstream.kind = "subnetra"` 出口把流量打进隔离网段，fail-closed 不回落直连。与现有 Zig 版 subnetra **线兼容**，由 `tests/subnetra_conformance.rs` 对参考 KAT 向量逐字节校验。配置见 `docs/subnetra.md`。

## 非目标（铁律）

- 不回到 GOST 插件运行时。

  Rove 的核心价值是把数据面和策略控制收进一个可审计二进制；重新依赖 GOST、gRPC 插件或外部代理编排图会破坏项目边界。

- 不在节点内实现控制面或管理后台。

  节点只消费编译快照，不成为用户、套餐、计费、审计、租户或 Web 管理的真相来源。

- 不引入控制面长连接推送通道（SSE / WebSocket）。

  推送通道会让节点的策略生效路径依赖与控制面之间的长连接状态，耦合性太强，破坏"HTTP 拉取 + 本地缓存 + 离线可服务"这一松耦合契约。低延迟同步需求已由 MQTT 同步指令覆盖：控制面发一条 `sync_command`，节点立即拉取一次快照——传输通道（MQTT broker）与真相来源（快照 URL）保持分离。轮询间隔可配短至秒级，无需第二条推送协议。

- 不把节点做成「先堆协议、再补正确性」的厨房水槽。

  当前可靠热路径是 HTTP CONNECT、SOCKS5 与 TUIC，它们是 listener adapter，不是产品本身。
  新的接入方式必须先证明自己服务的是应用入口，并且有独立的认证命名空间、fail-closed
  失败路径和 E2E，才能加到 `identity → policy → route → egress` 主干上。
  不得为了协议清单去引入消费级代理生态的协议或客户端一键配置。

- 不把出口平面做成通用反向代理或 API 网关。

  Rove 可以在入站侧增加以服务端声明的 origin 为准的网关型 listener（例如按 SNI 路由的 TLS
  透传入口），把它们当作又一种 listener adapter 复用同一条 `identity -> policy -> route ->
  egress` 主干。但 origin 必须由节点本地配置或快照声明，**绝不能由客户端的 Host、URL 或路径
  表达**——那等于把出口平面退化成开放正向代理和 SSRF 入口。请求改写、鉴权卸载、限流计费、
  证书签发、L7 负载均衡策略、虚拟主机管理这类 API 网关职责不属于 Rove。

- 不把 AI Provider 或交易柜台的 L7 业务语义嵌入节点热路径。

  Agent API 与投资交易是一等场景，但优化的是路径、出口、认证、限速和可观测性。
  OpenAI / Anthropic 的请求体、SSE、API key 账本，以及券商成交、持仓、资金划转语义，
  不属于 Rove 节点。若未来需要此类能力，必须由独立进程承载，不能假设与节点同机。

- 不允许策略失败时开放放行。

  认证失败、账号过期、block 命中、快照编译失败或上游连接失败时，默认行为必须保持保守，不能为了可用性绕过访问控制。

- 不在仓库里固化生产密钥、真实节点令牌或客户策略数据。

  这是公开仓库的铁律。示例只能使用占位值；`data/`、`logs/`、真实证书、token、内部控制面
  地址不得入库。每次推送、打 tag、发 Release / crate 前必须跑 `scripts/check-public-tree.sh`。
  详见 `AGENT.md` 与 `SECURITY.md`。

- 不把方向文档当作日常任务看板。

  本文档维护目标画像和边界，不记录每个提交、每个 PR 或每次发布状态。

- 不接受无测试驱动的功能开发。

  新增或变更功能必须先落下能表达预期行为和失败边界的自动化测试，再实现代码；修复缺陷必须先复现缺陷并让测试失败。没有对应测试的代码改动只能进入探索分支，不能合入主线。

- 不允许覆盖率低于 80%。

  仓库主线的 Rust 代码行覆盖率必须保持不低于 80%，CI 使用 `cargo llvm-cov --fail-under-lines 80` 执行门禁。低于该门槛时，不得发布新功能；安全失败模式、认证、策略决策、快照编译、协议握手、上游连接和限速路径不得用整体覆盖率达标掩盖局部无测试。

## 方向与意图

- 建立测试基线和 TDD 门禁

  当前测试覆盖仍然不足，项目需要把测试从“局部验证”提升为“开发驱动”。目标状态是每个功能入口都有先失败、后实现、再回归的测试证据；覆盖率报告能在本地和 CI 中稳定产出；低于 80% 或关键路径缺测会阻断合入和发布。

- 补齐运行健康与可观测性：已交付主动健康探针

  已交付独立、默认回环监听的 `/healthz` 与 `/readyz`：编排系统可区分进程存活、未加载快照、无活跃数据面 listener、已加载的快照/schema 版本、控制面持续不可达和停机排空；响应不包含 URL、令牌、用户密码或策略内容。显式配置的 TCP/TUIC listener 会在后台服务启动前完成绑定和 TLS 校验，失败时节点非零退出；运行期无活跃 listener 时 readiness 返回 503。网络隔离场景仍可通过 MQTT 节点状态和拨测追踪确认故障点；结构化访问日志与 `kind:"stats"`、SNMP 继续承担历史连接和流量观测。Prometheus 指标端点仍按真实需求评估。

- TCP 首包运营识别：已交付 observe-only 与 HTTP/SOCKS5/TUIC route

  HTTP CONNECT、SOCKS5 CONNECT 与 TUIC TCP Connect 可按 listener 显式启用有界首包观察，从 TLS
  ClientHello 或 HTTP/1 请求提取规范化域名。`observe` 不改变握手/拨号时序；`route` 在拨号前执行
  requested + sniffed 双候选策略：任一 block 即拒绝，仅当 requested 为 IP 时允许 sniffed 域名选择
  proxy 出口，实际目标永远不改写。HTTP/SOCKS5 的 route 必须先向客户端确认隧道（200 / SOCKS5 成功）
  客户端才会发送首包，再决定出口。访问日志区分 requested/sniffed/effective/target identity，周期
  stats 只按 listener 记录固定结果枚举，域名不进入指标 label。默认关闭，不保存 URL、header 集合或
  payload；ECH、QUIC/HTTP3 与 UDP sniff 仍是后续独立方向。

- 加强认证与策略安全硬度

  密码比较、快照编译失败处理、日志脱敏、TLS 证书加载错误和认证失败反馈都应保持可审计、保守和低泄露。README 中已列出密码常量时间比较，这是值得优先收敛的安全方向。

- 让停机和升级更适合生产节点：已交付有界排空

  节点同时接收 `SIGINT` 与 `SIGTERM`，收到信号后立即停止 TCP、TUIC 与 Subnetra hub 的新接入，并在 `[shutdown].grace_period_secs` 的有界窗口内排空在途连接；完成或超时均有明确日志，超时后强制终止剩余会话并以退出码 0 结束。`tests/shutdown_integration.rs` 同时守护窗口内传输完成与超时必退语义。

- HTTP 应用入口：已交付 absolute-form 明文转发

  普通 HTTP 绝对形式 GET/POST 已与 CONNECT 共用认证、过期、策略、连接数限制、限速、出口选择和访问日志语义；转发前移除代理凭据与逐跳头，改写为 origin-form，并以单请求关闭控制边界。CONNECT 仍是 HTTPS 主路径；透明代理、缓存、内容改写和浏览器网关不在范围内。

- 移动端 TLS 入口：已交付 TUIC v5 前端接入

  TUIC v5 前端已落地为 **[TUIC v5 前端接入](./tuic.md)**（QUIC/TLS 1.3）。节点仍本地执行用户过期、策略分流、限速和连接数限制；身份归属只做查表（快照按协议命名空间 `frontends.<协议>` 建 `uuid -> username` 索引，前端凭据独立于登录密码），不从报文还原用户名、不复用登录口令。`frontends` 结构让后续 listener adapter 按协议命名空间纯加法接入。

  TCP `Connect` 复用现有出口并按用户限速；UDP `Packet` 走反向 hop 的 UDP 出口。Web fallback 伪装、TUIC over 其它传输等仍需分别证明真实应用入口需求，不搭车。

- NAT 后公网接入：已交付 reverse ingress

  公网 `rove-relay` 与 NAT 内 connector 已提供统一节点认证、预授权固定/动态端口、原生 TCP/UDP、
  多 relay 独立会话、结构化集中观测和真实客户端 IP 关联。该能力严格属于接入基础设施，不进入用户策略
  快照；relay 不成为用户认证/策略控制面，也不允许指定任意内网目标。UDP 保证 1200B 内层 datagram，
  编码后超出 Quinn 路径能力时明确丢弃并计数，不通过可靠 stream 模拟 UDP，不实现通用分片重组。

- UDP relay：已交付 reverse/2（client→server）与 SOCKS5 UDP ASSOCIATE

  UDP 出口已落地为 **[reverse/2 UDP relay](./reverse-hop.md#reverse2-udp-relay)**：经反向 hop 出口、维持认证/策略/可观测一致语义，适用于 WebRTC→SFU、实时 API、游戏连专用服务器等 client→server 场景（EIM + address-restricted、不分片、不做 full-cone/P2P）。前端侧 **TUIC** 与 **SOCKS5 UDP ASSOCIATE** 均已接到此出口。UDP 分片、full-cone 打洞等仍只在明确的真实业务场景下才进入范围。

- 收敛限速精度和突发行为

  当前令牌桶已经提供每用户字节速率限制；后续方向是让突发容量、双向统计和误差表现更可解释。任何调整都必须以不破坏代理吞吐和连接稳定性为前提。

- 应用场景优先：Agent API 与投资交易

  文档、示例和基准应覆盖「按模型/供应商选出口」「交易与行情固定出口」「Webhook 回源 IP 稳定」这类路径问题。
  不在节点内解析业务 payload。

- 新 listener adapter 必须先证明应用入口需求

  `frontends.<协议>` 只是加法挂钩，不是「协议动物园」的开工许可。候选接入方式必须先回答：
  它服务哪一类应用入口、认证如何 fail-closed、对现有 HTTP/SOCKS5/TUIC 热路径是否零回归。
  消费级代理生态的协议、订阅和一键客户端配置不在范围内。

- 应用出口网关：T1 SNI 透传为 MVP，T2 声明式 origin，T3 不做

  产品边界与术语见 **[应用出口网关](./egress-gateway.md)**。T1 复用现有 sniff / PrefixedIo /
  splice，不终止 TLS；T2 可以做，但 origin 必须由服务端声明，绝不能来自客户端 Host / URL。
  通用反代、证书签发、后端池、WAF 不是 Rove 的事——发布内网服务走 reverse ingress / Subnetra。
  新入口不要再叫 reverse：仓库里 reverse hop 与 reverse ingress 已经各占一次。

## 验收流程与标准

任何整体功能、方向能力或可发布变更，必须经过同一套可复现验收流程。验收材料应能说明“需求是什么、先写了哪些失败测试、实现后哪些测试通过、覆盖率是多少、哪些风险仍未关闭”。

各一级能力与测试锚点的对应关系由 **[验收矩阵](./acceptance-matrix.md)**（业务能力覆盖矩阵）维护，五条硬性不变量为：每个一级功能至少一条 Happy Path；每个高风险功能至少一条失败路径；每个涉及凭据/身份的功能至少验证两种角色结局；每个修改系统状态的操作至少验证一次失败后的恢复或回滚；每次新增一级业务功能必须同步新增对应 E2E 并在矩阵中登记。矩阵中的 ⚠️ 缺口在对应方向标记完成前必须先关闭。

1. 需求验收定义

   开发前必须把目标行为、失败边界、兼容性要求和不可接受行为写清楚。涉及安全失败模式时，要明确认证失败、账号过期、策略拒绝、快照无效、控制面不可达、上游失败等场景的期望结果。

2. TDD 证据

   功能实现前必须提交或保留能失败的测试用例，证明测试确实覆盖新增行为或缺陷复现。测试通过后，不能删除或弱化这些用例来迁就实现。

3. 自动化测试门禁

   合入前至少要通过格式化、静态检查、单元测试、集成测试和关键链路回归测试；具体命令以仓库 CI 为准。CI 未覆盖的验收项不得只写在 PR 描述里，必须补成可执行脚本、测试或明确的人工验收记录。

4. 覆盖率门禁

   覆盖率必须不低于 80%，统计范围以仓库内 Rust 业务代码为准，排除生成物、示例配置和部署产物。覆盖率报告必须能在本地和 CI 复现；如果不同工具口径不一致，以 CI 中固定工具的结果为准。

5. 关键路径专项验收

   HTTP CONNECT、SOCKS5、TLS 监听、认证失败、账号过期、block、direct、HTTP upstream、SOCKS5 upstream、限速、快照编译、热替换、缓存热启动、控制面 304、MQTT 查询和同步指令、MQTT 拨测追踪与诊断事件会话、reverse ingress 的认证/租约/TCP/UDP/TUIC/MTU/恢复、访问日志记录与轮转保留清理，都必须有自动化验收覆盖。缺少其中任一项时，相关方向不得标记完成。

   如果新增 listener adapter，完成前还必须覆盖：有效凭据归属到正确用户、未知凭据保守拒绝、目标解析失败拒绝、block 命中拒绝、direct 转发成功、HTTP/SOCKS5 upstream 转发成功、过期用户拒绝、限速生效、连接数限制生效、TLS listener 配置错误拒绝启动，以及至少一次真实客户端兼容拨测。

6. 发布前验收

   发布前必须确认测试全绿、覆盖率达标、配置示例不含真实凭据、日志不泄露密码或令牌、失败模式默认保守、README 与路线图没有把未完成能力写成已完成事实。

## 完成的样子

Rove 达到目标状态时，应表现为一个小而稳的应用出口节点：启动配置清楚，快照同步和缓存语义可靠，核心协议链路有自动化验证守护，安全失败模式明确，运维可以通过健康和指标判断节点状态。

- 核心出口路径被自动化回归守住。

  HTTP CONNECT、SOCKS5、认证失败、账号过期、block、direct、HTTP upstream、SOCKS5 upstream、限速和快照热替换等路径不应只依赖手工冒烟；回归必须能在本地或 CI 中被拦下，且整体覆盖率持续不低于 80%。

- 生产部署能判断节点状态。

  节点应暴露足够的健康、版本、快照和错误状态，让编排系统可以区分未加载快照、控制面暂时不可达、配置错误、上游错误和正常服务中。

- 安全边界清楚且默认保守。

  密码、令牌、证书路径、快照内容和用户策略不会被无意写入日志或文档；任何策略或认证不确定状态都不会变成开放代理。

- 方向扩展不破坏项目形状。

  新增协议、指标、推送或限速能力后，项目仍然保持单体节点、控制面快照消费方、少量配置和可审计热路径这几个基本特征。

- 文档与代码保持一致。

  当 README、配置示例或实现行为发生变化时，本文档的当前能力和非目标要同步校正；不确定的能力应标为待核验，而不是写成已完成事实。
