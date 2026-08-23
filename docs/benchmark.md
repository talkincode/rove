# 基准测试报告

Rove 自带一套纯 Rust 的端到端基准套件，直接压真实的本地 Docker 栈，覆盖
**2 条接入路径 × 4 个入口 × 7 条出口模式**：接入路径是本机直连 listener 或
`rove-relay` reverse ingress；出口是 direct / 三种上游 hop / reverse，以及两条出口链
主备故障转移模式。套件测延迟、吞吐、并发扩展性、限速精度和连接数配额。
本页给出最近一轮完整实测结果与复现方法。

> 数字均为**单机回环上限**（无丢包、零 RTT）。生产环境的实际表现取决于公网 RTT
> 与丢包率，横向比较各链路的相对开销比绝对值更有参考意义。

## 测试环境

| 项 | 值 |
| --- | --- |
| 日期 | 2026-07-04 |
| 硬件 / OS | Apple M4，macOS 26.5 |
| Docker | 29.4.0（Docker Desktop） |
| Rust | 1.96.0 |
| 部署 | `docker-compose.local.yml` 本地栈：1 × edge + 1 × ingress relay + 4 × hop |
| 负载发生器 | `examples/proxy-benchmark-local.rs`（与 Rove 同一 tokio/rustls 栈） |
| 参数 | 每用例 2000 请求 + 100 warmup / 并发 20 / 带宽单流 256 MiB |

**下表是 `path=local` 的历史实测：60 个用例全部成功，0 失败。**

## 方法学

- **接入路径**：
  - `local`：`http:18080`、`https-tls:18443`、`socks5:11080`、`socks5-tls:11081`
  - `reverse-ingress`：`http:38080`、`https-tls:38443`、`socks5:31080`、`socks5-tls:31081`
  两条路径最终进入同一组 Rove listener；TLS 都在 Rove 终止并正常校验本地 CA。
- **出口链路**：`direct`（直连）、`https` / `socks5` / `socks5-tls`（三种上游 hop）、
  `reverse`（QUIC 反向注册 hop）；另有两条[出口链](./data-model.md#出口链chain与主备故障转移)模式：
  `chain`（主 reverse 成员健康，首选即胜出，测 chain 的簿记开销）与 `chain-failover`
  （主 reverse 成员未注册，每条隧道都在建立期故障转移到 socks5 备份成员，测转移成本）。
- **分相计时**：每个请求拆成 `connect`（TCP 建连）→ `tls`（入口 TLS 握手）→
  `tunnel`（CONNECT / SOCKS5 建隧道，含 edge→hop 全部握手）→ `request`（HTTP 往返），
  可直接定位延迟花在哪一层。
- **warmup**：每用例先跑 100 个不计入统计的请求，排除冷启动噪声。
- **开环模式**：支持 `--rate` 按固定 schedule 发起请求，消除 coordinated omission
  （慢响应不会拖住后续请求的发起时刻）；矩阵默认闭环。
- **策略快照**：`docker/local/snapshot.json` 使用当前 schema 的 `routing_policies` + named
  `egresses`，基准矩阵会经过与生产控制面相同的解码、编译和有序 route 决策链。
- **目标服务器**内建于负载发生器（宿主机 `:19090`），容器内经 `host.docker.internal` 回连。

## 延迟矩阵

闭环，2000 请求 / 并发 20，单位 ms。`rps` 为墙钟吞吐，对个别环境级 stall 敏感
（见[尾部说明](#macos-docker-下的-1003ms-极值)），横向比较以 `p50` / `p99` 为准。

| 入口 | 出口链路 | RPS | p50 | p90 | p99 |
| --- | --- | ---: | ---: | ---: | ---: |
| `http` | `direct` | 1759 | 2.09 | 3.74 | 7.84 |
| `http` | `https` | 3038 | 6.26 | 8.58 | 14.03 |
| `http` | `socks5` | 1503 | 3.08 | 4.30 | 12.45 |
| `http` | `socks5-tls` | 1196 | 5.96 | 8.33 | 12.54 |
| `http` | `reverse` | 1432 | 2.85 | 4.17 | 11.22 |
| `https-tls` | `direct` | 1390 | 3.24 | 4.99 | 7.54 |
| `https-tls` | `https` | 1452 | 9.10 | 15.50 | 29.00 |
| `https-tls` | `socks5` | 1232 | 5.68 | 8.21 | 15.70 |
| `https-tls` | `socks5-tls` | 2123 | 7.91 | 11.49 | 15.34 |
| `https-tls` | `reverse` | 1405 | 4.05 | 5.77 | 22.70 |
| `socks5` | `direct` | 4562 | 3.25 | 6.27 | 10.97 |
| `socks5` | `https` | 1126 | 6.55 | 9.80 | 25.48 |
| `socks5` | `socks5` | 1513 | 4.21 | 6.58 | 20.01 |
| `socks5` | `socks5-tls` | 2531 | 7.27 | 9.95 | 16.46 |
| `socks5` | `reverse` | 1740 | 3.51 | 5.06 | 20.97 |
| `socks5-tls` | `direct` | 3049 | 3.81 | 5.55 | 14.54 |
| `socks5-tls` | `https` | 1232 | 8.09 | 11.07 | 27.17 |
| `socks5-tls` | `socks5` | 1322 | 4.94 | 8.61 | 14.83 |
| `socks5-tls` | `socks5-tls` | 1116 | 9.01 | 12.15 | 22.06 |
| `socks5-tls` | `reverse` | 1691 | 4.31 | 7.12 | 20.87 |

- 最快端到端链路 `http → direct` p50 **2.09 ms**；最重链路
  `socks5-tls → socks5-tls`（双层 TLS + 两次 SOCKS5 握手）p50 **9.01 ms**。
  每加一层加密或握手，p50 大约 +1.5~3 ms，单调可预期。
- 全矩阵 p99 都在 30 ms 以内。

### 分相 p50（ms）

| 入口 | 出口链路 | connect | tls | tunnel | request |
| --- | --- | ---: | ---: | ---: | ---: |
| `http` | `direct` | 0.06 | — | 1.26 | 0.72 |
| `http` | `https` | 0.12 | — | 4.68 | 1.36 |
| `http` | `socks5` | 0.07 | — | 2.11 | 0.84 |
| `http` | `socks5-tls` | 0.12 | — | 4.66 | 1.07 |
| `http` | `reverse` | 0.06 | — | 1.64 | 1.06 |
| `https-tls` | `direct` | 0.06 | 1.05 | 1.09 | 0.88 |
| `https-tls` | `https` | 0.09 | 1.49 | 5.39 | 1.82 |
| `https-tls` | `socks5` | 0.07 | 1.32 | 2.65 | 1.32 |
| `https-tls` | `socks5-tls` | 0.07 | 1.22 | 5.07 | 1.25 |
| `https-tls` | `reverse` | 0.07 | 0.97 | 1.51 | 1.25 |
| `socks5` | `direct` | 0.07 | — | 2.30 | 0.88 |
| `socks5` | `https` | 0.06 | — | 5.21 | 1.20 |
| `socks5` | `socks5` | 0.07 | — | 3.14 | 0.93 |
| `socks5` | `socks5-tls` | 0.23 | — | 5.94 | 1.02 |
| `socks5` | `reverse` | 0.07 | — | 2.29 | 1.10 |
| `socks5-tls` | `direct` | 0.06 | 0.94 | 1.90 | 0.81 |
| `socks5-tls` | `https` | 0.06 | 1.05 | 5.33 | 1.31 |
| `socks5-tls` | `socks5` | 0.06 | 0.96 | 2.82 | 0.93 |
| `socks5-tls` | `socks5-tls` | 0.08 | 1.24 | 6.06 | 1.18 |
| `socks5-tls` | `reverse` | 0.07 | 0.89 | 2.06 | 1.07 |

三个值得记住的结论：

- **入口 TLS 握手稳定在 ~1.0–1.5 ms**，四个入口除此之外同档——选 TLS 入口的代价就这么多。
- **上游 TLS hop 把 `tunnel` 从 ~1.3–2.3 ms 抬到 ~4.7–6.1 ms**，是全链路里最贵的一层。
- **`reverse` 建隧道只要 ~1.5–2.3 ms，接近 direct**——QUIC 反向通道是复用的，
  不需要为每个请求新建 edge→hop 连接。穿 NAT 场景里它同时是低延迟优选。

## 带宽矩阵

单流 256 MiB，单位 MiB/s。单次测量，±20% 内属运行间波动。

| 入口 | 出口链路 | 下载 | 上传 |
| --- | --- | ---: | ---: |
| `http` | `direct` | 1607 | 2076 |
| `http` | `https` | 753 | 621 |
| `http` | `socks5` | 732 | 723 |
| `http` | `socks5-tls` | 683 | 724 |
| `http` | `reverse` | 433 | 467 |
| `https-tls` | `direct` | 746 | 749 |
| `https-tls` | `https` | 771 | 466 |
| `https-tls` | `socks5` | 1262 | 471 |
| `https-tls` | `socks5-tls` | 780 | 621 |
| `https-tls` | `reverse` | 384 | 311 |
| `socks5` | `direct` | 2341 | 2250 |
| `socks5` | `https` | 851 | 454 |
| `socks5` | `socks5` | 830 | 922 |
| `socks5` | `socks5-tls` | 755 | 736 |
| `socks5` | `reverse` | 462 | 489 |
| `socks5-tls` | `direct` | 803 | 694 |
| `socks5-tls` | `https` | 792 | 402 |
| `socks5-tls` | `socks5` | 1153 | 366 |
| `socks5-tls` | `socks5-tls` | 818 | 578 |
| `socks5-tls` | `reverse` | 384 | 415 |

档位一目了然：

| 链路档位 | 单流吞吐 |
| --- | --- |
| 明文入口 + 直连 | **1.6–2.3 GiB/s** |
| 任一环节带 TLS（入口或上游） | **~0.6–0.9 GiB/s** |
| reverse（QUIC 反向通道） | **~0.3–0.5 GiB/s** |

带宽测试期间 edge 容器 CPU 峰值 94%（打满约一个核）——测到的是代理数据面的
真实上限，而不是客户端上限。QUIC 链路吞吐低于 TCP+TLS 属预期
（用户态 QUIC 栈 + 单容器 CPU 上限）。

## 并发扩展性

`http → direct`，逐级抬并发：

| 并发 | 请求 | 失败 | RPS | p50 (ms) | p99 (ms) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 200 | 0 | 1638 | 0.58 | 0.74 |
| 8 | 200 | 0 | 5685 | 1.34 | 2.11 |
| 32 | 800 | 0 | 759* | 2.32 | 1002.52* |
| 128 | 2000 | 0 | 1534* | 3.83 | 1009.71* |

1→8 并发接近线性扩展（1638→5685 RPS），p99 仍在 2 ms 档。
带 `*` 的行受宿主环境影响，见[下节](#macos-docker-下的-1003ms-极值)：
冷启动单独跑并发 32 的结果是 **6377 RPS / p99 14.7 ms**，无塌陷。

## 出口链（chain）故障转移验收

2026-07-11 对[出口链](./data-model.md#出口链chain与主备故障转移)模式的单独验收
（同栈同参数：2000 请求 / 并发 20 / warmup 100；本地快照
`docker/local/snapshot.json` 定义 `bench-pop`——健康 reverse 主 + socks5 备，与
`bench-pop-failover`——未注册 reverse 主 + socks5 备）。**64000 请求（16 用例 ×
2000 + 带宽）全部成功，0 失败。**

| 入口 | `chain` p50 / p99 | `chain-failover` p50 / p99 | 参照 `reverse` p50 | 参照 `socks5` p50 |
| --- | ---: | ---: | ---: | ---: |
| `http` | 2.33 / 3.73 | 3.17 / 5.81 | 2.72 | 3.00 |
| `https-tls` | 3.03 / 18.88 | 3.54 / 9.63 | 4.10 | 4.29 |
| `socks5` | 3.11 / 5.12 | 3.39 / 7.18 | 3.16 | 2.88 |
| `socks5-tls` | 4.01 / 7.63 | 4.41 / 13.19 | 4.25 | 4.21 |

- **`chain`（主成员健康）**：p50 与纯 `reverse` 基线持平（±0.5 ms 内），chain 的
  簿记与决策开销在测量噪声之下。
- **`chain-failover`（主成员不可用，每条隧道都经历一次建立期故障转移）**：p50 比
  直接走 socks5 备份成员多约 0.2~0.6 ms——即一次 `reverse_lookup` 失败的成本；带宽
  与基线一致（单流 ≥ 440 MiB/s，转移只发生在建立期，数据面零开销）。
- **fail-closed 实测**：停掉 socks5 备份 hop 后，`chain-failover` 用户的 CONNECT 返回
  `502 Bad Gateway`（决不回落直连）；恢复 hop 后新连接立即自愈；期间 `chain` 用户
  不受影响（reverse 主成员照常服务）。

复现：`--modes chain,chain-failover`（已包含在默认矩阵中）。

## 限速精度与连接数配额

用 `bench-limited` 用户（`up_rate` = `down_rate` = 1 MiB/s，`max_connections` = 2）实测：

| 方向 | payload | 用时 | 实测速率 | 期望速率* | 误差 |
| --- | ---: | ---: | ---: | ---: | ---: |
| download | 8 MiB | 7.008 s | 1,197,035 B/s | 1,198,373 B/s | **-0.1%** |
| upload | 8 MiB | 7.007 s | 1,197,192 B/s | 1,198,373 B/s | **-0.1%** |

\* 令牌桶初始带 1 秒突发额度，期望速率按 `payload / ((payload - rate) / rate)` 修正。

连接数配额：并发发起 4 个隧道，**放行 2、拒绝 2**，与 `max_connections=2` 完全一致
（HTTP 入口拒绝时返回 `429`，SOCKS5 返回 `rep=0x02`）。

## 资源占用

带宽阶段 `docker stats` 采样：

| 容器 | CPU 均值 | CPU 峰值 | 内存峰值 |
| --- | ---: | ---: | ---: |
| edge（`rove-local-main`） | 74.6% | 94.1% | 10.4 MiB |
| hop-socks5tls | 24.3% | 51.0% | 6.9 MiB |
| hop-https | 12.9% | 39.0% | 6.5 MiB |
| hop-reverse | 8.9% | 24.2% | 8.8 MiB |
| hop-socks5 | 1.8% | 6.1% | 6.4 MiB |

全栈 5 个容器内存峰值合计 **< 40 MiB**。

## macOS Docker 下的 1003ms 极值

在 macOS + Docker Desktop 上连续大量新建连接（完整矩阵连跑、并发扫描多 step 连跑）时，
部分用例的 `max` 会出现孤立的 ~1003 ms 极值（p99 通常不受影响，占比 < 0.1%）。
1003 ms 是 TCP SYN 重传定时器的特征值，定性为 **Docker Desktop 端口转发链路
（docker-proxy / VM NAT）在连接风暴下丢首个 SYN**，属宿主环境行为，
不是 Rove 数据面缺陷——同样的用例冷启动单独跑即恢复正常。

在 Linux 原生环境（无 docker-proxy 中转）复测不受此影响。压测时如需规避：
单独跑目标用例，或降低用例间的连接新建密度。

## 复现

```bash
# 1. 生成本地证书并起栈（1 edge + 1 ingress relay + 4 hop）
./scripts/generate-local-certs.sh
docker compose -f docker-compose.local.yml up -d

# 2. 完整矩阵：延迟 + 带宽 + 并发扫描 + 限速/配额，附容器资源采样
cargo run --release --example proxy-benchmark-local -- all --stats \
  --json-out reports/rove-proxy-bench.json

# 3. 对比本地直连 listener 与 reverse ingress 的完整矩阵
cargo run --release --example proxy-benchmark-local -- latency \
  --paths local,reverse-ingress

# 只测 relay 接入开销，出口固定 direct
cargo run --release --example proxy-benchmark-local -- latency \
  --paths reverse-ingress --modes direct
```

按需单独跑某一类：

```bash
cargo run --release --example proxy-benchmark-local -- latency    # 延迟矩阵（分相计时）
cargo run --release --example proxy-benchmark-local -- bandwidth  # 吞吐矩阵
cargo run --release --example proxy-benchmark-local -- sweep      # 并发梯度
cargo run --release --example proxy-benchmark-local -- limits     # 限速精度 + 连接数配额
```

常用选项（完整列表见 `-- --help`）：

| 选项 | 作用 |
| --- | --- |
| `--inbounds http,socks5` | 只测部分入口 |
| `--paths local,reverse-ingress` | 选择本地 listener / reverse ingress 接入路径；默认仅 `local` |
| `--modes direct,reverse,chain,chain-failover` | 只测部分出口链路 |
| `--requests N` / `--concurrency N` | 延迟用例规模 |
| `--rate RPS` | 开环模式（固定到达率，消除 coordinated omission） |
| `--mib N` / `--streams N` | 带宽 payload 与并发流数 |
| `--stats` | 采样 `docker stats` 输出容器资源报告 |
| `--json-out PATH` | 机器可读结果（延迟分位数、吞吐、限速误差全量） |

JSON 中每条 latency/bandwidth/sweep/limit 记录都有 `path` 字段，可按相同
`inbound + mode` 对比 relay 封装、额外 QUIC hop 与 loopback connector 的成本。

QUIC 前端与 overlay 组网有各自的专属基准：

```bash
cargo run --release --example tuic-benchmark-local        # TUIC 本地 UDP:10443
cargo run --release --example tuic-benchmark-local -- \
  --path reverse-ingress                                  # TUIC 经 relay UDP:30443
cargo run --release --example subnetra-benchmark-local    # Subnetra overlay 业务路径
```
