# Rove Agent 说明

Rove 是公开的应用网络优化器：一个轻量单体正向代理，内置认证、
策略、限速、连接数限制、hop 代理、控制面快照同步，以及可选的 MQTT 运维通道。
它服务 Agent API、投资交易、SaaS 出口等对路径敏感的应用流量。

## 公开树审查（硬性，先于一切）

本仓库是公开源码。合入、打 tag、发 Release、发 crate 之前必须先做敏感数据审查。没有审查记录的发布视为未完成。

禁止进入 git 历史或 GitHub Release 的内容：

- 生产或预发的 `snapshot.json`、用户密码、节点 token、控制面 URL 里的真实主机
- TLS 私钥、ACME 账号、SSH 密钥、`.pem` / `.key` / `.p12`（测试夹具除外，且必须是专门生成的假证书）
- 访问日志、SNMP 状态、真实客户策略、地址簿里的非公开数据
- CI / crates.io / Homebrew tap 的 token；个人 `.env`、kubeconfig、云厂商密钥
- 内部部署清单、未脱敏的节点 ID、真实 hop token

示例配置只能使用 `example.com`、`REPLACE_WITH_*`、`dev` 这类占位值。
`data/`、`logs/`、`dist/`、本地证书目录默认不入库。新增示例前先问：这会不会让外人连上真实系统？

发布前最少跑一次：

```bash
./scripts/check-public-tree.sh
```

命中真实密钥形态、内网主机名或非占位 token 时必须失败。不确定就不要推。

## 开始前先读

- 先读 `docs/roadmap.md`。它是本仓库的一等公民，定义项目画像、非目标、质量门禁和方向边界。
- 先读 `docs/acceptance-matrix.md`。它是验收矩阵（业务能力覆盖矩阵），定义每个一级能力的测试锚点和硬性覆盖不变量。
- 先读 `README.md`，了解架构、数据模型、运行配置、Docker 本地测试和已验证行为。
- 修改控制面同步或用户数据格式前，先读 `docs/snapshot-protocol.md`。
- 修改 MQTT 命令、拨测追踪或远程诊断行为前，先读 `docs/mqtt-integration.md`。
- 编辑前先执行 `git status --short`。工作树可能已有用户或前序 agent 的改动，不要回滚无关变更。

## 路线图是一等公民

- `docs/roadmap.md` 不是普通背景材料，而是判断需求是否应该做、怎么做、做到什么程度的第一约束。
- 开始实现前，先把当前需求映射到路线图里的目标状态、非目标、方向意图和验收标准。
- 如果用户需求与路线图冲突，先指出冲突和风险，再给出符合项目边界的替代实现。
- 如果实现改变了项目能力、非目标、验收口径或发布边界，必须同步更新 `docs/roadmap.md`。
- 不要把临时任务、PR 状态或流水账写进路线图；路线图维护长期方向和边界。
- README 描述当前事实，路线图描述目标状态和边界。两者冲突时，先核验代码，再修正文档。

## 验收矩阵是硬性规定

`docs/acceptance-matrix.md` 维护业务能力覆盖矩阵。以下五条不变量是合入门禁，不是建议：

1. 每个一级功能至少有一条 Happy Path 自动化验收。
2. 每个高风险功能（认证、策略、加密、快照/状态写入、出站选择）至少覆盖一条失败路径，
   且失败行为必须保守（fail-closed）。
3. 每个涉及凭据/身份的功能至少验证两种角色结局（如 合法 vs 过期用户、正确 vs 错误凭据/token）。
4. 每个会修改系统状态的操作至少验证一次失败后的恢复或回滚
   （如 无效快照不覆盖缓存、连接配额释放、日志轮转清理）。
5. 每次新增一级业务功能，必须同步新增 `tests/` 下的 E2E 集成测试，并在矩阵中登记一行；
   只有单元测试不算完成。

执行要求：

- 新增或修改一级能力的 PR，必须在同一 PR 内更新矩阵对应行；测试重命名或删除时同步修订锚点。
- 矩阵中 ⚠️ 标记是显式技术债；对应路线图方向标记完成前必须先转为 ✅。
- 不确定是否覆盖的维度写 ⚠️ 待核验，不许写成 ✅；`—`（不适用）必须附理由。

## 关键文件

- `src/main.rs`：主节点运行时组装。
- `src/bin/rove-hop.rs`：独立 hop 二进制入口。
- `src/config.rs`：TOML 配置结构。
- `src/model.rs`：线缆/缓存模型、旧 userdata 兼容转换、编译后的 `Snapshot`、认证/策略/限速字段。
- `src/engine.rs`：`ArcSwap<Snapshot>` 访问和热替换。
- `src/sync/mod.rs`：HTTP 快照拉取、本地缓存预热、轮询和快照应用。
- `src/addrbook/`、`src/bin/rove-abctl.rs`：`.rab` 构建/校验/查询、数据源解析和节点热替换。
- `src/inbound/`：HTTP CONNECT 和 SOCKS5 入口实现。
- `src/outbound/`：直连、HTTP CONNECT upstream、SOCKS5 upstream，以及可选 TLS。
- `src/io.rs`：隧道转发、字节限速和活跃连接计数。
- `src/proxy/mod.rs`：独立 hop 代理实现。
- `tests/proxy_integration.rs`：本地端到端代理测试。
- `tests/addrbook_integration.rs`：地址簿规则、失败恢复与格式 golden 向量 E2E。
- `docker-compose.local.yml`、`docker/local/`、`examples/proxy-benchmark-local.rs`：
  本地 Docker 部署和压力测试（延迟/吞吐/并发扫描/限速精度）。

## 数据模型规则

- 控制面输出必须使用 `docs/snapshot-protocol.md` 中定义的 `RawSnapshot`。
- **只有一种 schema**（`schema_version: 1`）：`users` + `routing_policies` + `egresses` 三张独立表。
  没有兼容层，也不接受任何其他形态的文档。
- 全部 wire 结构都是 `deny_unknown_fields`：含未知字段或异形的文档整份拒收，绝不半懂半猜地编译。
  新增语义字段必须配合 schema/capability 门控发布，因为不支持该字段的旧节点会明确拒收。
- 用户通过 `policy` 绑定一条 routing policy；route 按数组顺序 first-match-wins；
  未命中执行 policy 的 `default_action`（`egress` / `direct` / `block`），没有则直连。
  `default_action: {"type":"block"}` 是表达 deny-by-default 策略的唯一方式——选择器没有
  catch-all 写法。
- `node_overrides` 只能整项替换 base `egresses` 里已存在的同名 egress，不能新增 node-only
  egress，也不能改 policy —— route 表在全网必须是同一份。
- `version` 必须单调递增。`304` 或 `version <= since` 表示不替换当前快照。

## 构建与测试

使用 Rust 1.88 或更新版本。

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release --bins
```

发布前还必须跑覆盖率门禁。当前项目画像要求 Rust 业务代码覆盖率不低于 80%，
本地优先使用：

```bash
cargo llvm-cov --locked --all-targets --fail-under-lines 80
```

常用聚焦检查：

```bash
cargo test model::tests
cargo test sync::tests
cargo test --test proxy_integration
```

本地 Docker 模拟：

```bash
./scripts/generate-local-certs.sh
docker compose -f docker-compose.local.yml up --build
cargo run --release --example proxy-benchmark-local -- latency
cargo run --release --example proxy-benchmark-local -- bandwidth
```

## 本地运行注意事项

- `data/`、`.smoke/`、`reports/`、生成证书、私钥和 env 文件都只属于本地环境，不应提交。
- 为兼容测试复制的远程 userdata 可能包含真实用户名、密码、hop 节点或拓扑信息。
  这些文件必须放在已忽略路径下，不要把敏感内容写入日志、提交、报告或 memory。
- Docker 和 hop 模拟中使用自签名本地 TLS 是正常情况。测试里优先显式配置 CA，
  不要全局关闭 TLS 校验。
- 如果手动启动了后台代理进程，结束前检查测试监听端口是否已释放。

## 修改准则

- 改动范围应贴合当前需求。除非为了正确性必须处理，否则不要做大范围重构。
- 实现前检查需求是否符合 `docs/roadmap.md` 的项目画像、非目标和验收标准。
- 优先保持现有模块边界。新入口协议放在 `src/inbound/`；出口行为放在 `src/outbound/`；
  同步和缓存格式处理放在 `src/model.rs` 与 `src/sync/mod.rs`。
- 认证、策略、同步解析、TLS 或 upstream 选择不能引入宽松的 fail-open 行为。
- 修改认证、策略匹配、限速、连接数限制、同步、TLS 或 hop 行为时，要新增或更新测试。
- 对用户可见的协议变更，要同步更新 `docs/snapshot-protocol.md`、README 和必要的路线图章节。

## 提交习惯

- 不要提交被忽略的本地运行数据，也不要提交下载下来的生产 userdata。
- 提交前至少运行：

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
git status --short
```

- 如果只修改文档，也要做轻量的状态和 diff 检查，并说明不需要运行代码测试。

## 发布习惯

- 发布 tag 前必须同步 `Cargo.toml` 的 `[package].version`，例如发布 `v2.0.1`
  时版本字段必须是 `2.0.1`；随后运行一次非 `--locked` 的 cargo 命令刷新
  `Cargo.lock` 中的本包版本，再回到 `--locked` 门禁。
- 新版本发布必须从干净的 `origin/main` 执行，先确认本地/远端 tag 和 GitHub Release
  不存在，再创建 annotated tag。
- 发布前至少通过 `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、
  `cargo test --locked`、`cargo build --release --locked --bins`、
  `cargo llvm-cov --locked --all-targets --fail-under-lines 80` 和 `git diff --check`。
- 如果任何发布门禁失败，不要推 tag；先修复、走 PR 合入并重新验证。
