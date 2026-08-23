# RouterOS 容器部署 rove-hop

> 运维专题：在 MikroTik RouterOS 上用 **container** 部署 `rove-hop` 反向出口。  
> 推荐 **reverse QUIC only**。`hop_id` 统一前缀 **`rove-hop-`**（如 `rove-hop-jp`）。

## 可下载材料（离线包）

除本页外，Release / 文档站提供**可下载部署包**（手册 + 命名规范 + `.rsc` 脚本 + Docker-save 镜像）：

| 获取方式 | 说明 |
|---|---|
| [GitHub Releases](https://github.com/talkincode/rove/releases)（**完整部署包**） | `rove-hop-routeros-<version>-arm64.tar.gz` / `…-amd64.tar.gz`：**手册 + 脚本 + Docker-save 镜像** |
| 文档站下载（**离线文档包**） | [rove-hop-routeros-bundle.zip](./downloads/rove-hop-routeros-bundle.zip)：手册 + 命名规范 + `.rsc`（**不含镜像**；镜像请用 Release） |

包内必读：

- `GUIDE.md` — 完整运维手册（与下文章节同源）
- `HOP-ID-NAMING.md` — `reverse-hop-id` 命名规范
- `scripts/rove-hop-routeros.rsc` / `rove-hop-routeros-remove.rsc`
- `env.example`
- `images/rove-hop-arm64.tar`（Release 完整包）

仓库路径：`deploy/routeros-hop/`，打包脚本：`scripts/pack-routeros-hop.sh`。

---


> 面向运维：在 MikroTik RouterOS（container 包）上部署 **NAT 后反向出口** `rove-hop`。  
> 推荐形态：**reverse QUIC only**（不在路由上开 SOCKS/HTTPS 入口）。  
> 配套：本目录脚本、Release 部署包、文档站页面。

| 项 | 值 |
|---|---|
| 组件 | `rove-hop`（独立 hop，不连控制面） |
| 推荐模式 | `--reverse-quic` 主动注册到 edge |
| 目标平台 | RouterOS 7.x + `container` 包，**arm64 / x86_64** |
| 命名 | 见 [HOP-ID-NAMING.md](./hop-id-naming.md)，前缀 **`rove-hop-`** |
| 脚本 | 部署包 `scripts/*.rsc`；源码 `deploy/routeros-hop/scripts/` |

---

## 1. 先建立心智模型

```text
用户 ──▶ edge (rove)  ◀── QUIC/UDP 出站注册 ──  hop (RouterOS 容器里的 rove-hop)
              │                                    │
              └── 每条用户连接 = 一条 QUIC 流 ──────┴── TCP ──▶ 目标网站
```

| 角色 | 职责 | 是否常改 |
|---|---|---|
| **edge `rove`** | 用户接入、策略、限速；`[reverse_hop]` 收 hop 注册 | 底座一次；策略靠快照热更 |
| **hop `rove-hop`** | 只做出口：注册 + 拨目标 + 字节对拼 | 设备级，少动 |
| **快照** | `kind=reverse` + `addr=<hop_id>` 决定谁走这个出口 | 经常 |

要点：

1. hop **不读快照、不做策略**；策略全在 edge。  
2. hop 在 NAT 后：**只需要出站 UDP** 打到 edge 的 reverse 端口。  
3. hop **支持自动重连**（1s–30s 退避）。可以先起 hop 再启 edge。  
4. 未注册成功时，命中该出口的请求 **fail-closed**（不会偷跑直连）。

更完整的协议说明见仓库文档：[反向 hop 数据面](https://talkincode.github.io/rove/reverse-hop.html)。

---

## 2. 命名：`reverse-hop-id`

**必须**使用统一前缀：

```text
rove-hop-<region>[-<site>][-<seq>]
```

示例：`rove-hop-jp`、`rove-hop-cn-office-ax2`。

规则摘要：

- 全小写，`a-z` `0-9` `-` only  
- 与快照 `upstream.addr` **逐字相同**  
- 一台出口设备一个 id；不要多机共用（除非明确主备 replace）

完整规范：**[hop-id 命名规范](./hop-id-naming.md)**（部署前先定名并写入变更单）。

---

## 3. 部署前检查清单

### 3.1 edge（`rove`）— 建议先完成

```toml
[reverse_hop]
enable = true
listen = "0.0.0.0:9443"     # UDP
cert = "/path/server.crt"
key  = "/path/server.key"
tokens = ["<长随机令牌>"]
duplicate = "reject"
max_streams_per_hop = 256
```

- [ ] 防火墙/安全组放行 **UDP** reverse 端口（不是 TCP）  
- [ ] 证书与 hop 侧 SNI/`--reverse-server-name` 一致；自签/纯 IP 时 hop 需 `--reverse-insecure`  
- [ ] 快照中相关 group：

```json
"upstream": { "kind": "reverse", "addr": "rove-hop-jp" }
```

> edge 底座配置 ≈ 一次性；日常改用户/域名走快照即可。

### 3.2 RouterOS 设备

| 检查项 | 要求 |
|---|---|
| 架构 | **arm64** 或 **x86_64**（与镜像一致） |
| 软件包 | 已安装并启用 **container** |
| 内存 | 建议整机 ≥ 512 MiB 可用余量；hop 自身空闲约 1–3 MiB |
| 存储 | 镜像+root 约 **15–25 MiB**；内置 flash 紧时用 USB |
| 出网 | 容器网段能 masq 出网；能访问 edge 的 UDP 端口 |
| 机型示例 | hAP ax² / ax³、RB5009、CCR 等支持 container 的型号 |

查看：

```text
/system resource print
/system package print where name=container
```

### 3.3 你需要准备的参数

| 变量 | 示例 | 说明 |
|---|---|---|
| `HOP_ID` | `rove-hop-jp` | 见命名规范 |
| `EDGE` | `edge.example.com:9443` | host:port，UDP |
| `TOKEN` | （密钥） | 与 edge `tokens` 之一相同 |
| `SERVER_NAME` | `edge.example.com` | 校验证书名；默认可用 host |
| `INSECURE` | `no` / `yes` | 自签才 yes |
| `IMAGE_FILE` | `rove-hop-arm64.tar` | 部署包内 Docker-save 镜像 |
| `VETH_NET` | `172.30.68.0/30` | 勿与现网冲突 |

---

## 4. 获取部署包

### 4.1 GitHub Release（推荐）

发布资产名（版本号随 tag 变化）：

```text
rove-hop-routeros-<version>-arm64.tar.gz
rove-hop-routeros-<version>-amd64.tar.gz   # 若该版本提供
```

内容通常包括：

```text
GUIDE.md                 # 本文
HOP-ID-NAMING.md
README.md                # 一页纸速查
env.example
scripts/rove-hop-routeros.rsc
scripts/rove-hop-routeros-remove.rsc
images/rove-hop-arm64.tar # Docker-save 镜像（可直接 /container add file=）
SHA256SUMS
```

校验：

```bash
tar -tzf rove-hop-routeros-vX.Y.Z-arm64.tar.gz | head
sha256sum -c SHA256SUMS
```

### 4.2 文档站下载

GitHub Pages 提供同名 zip（随文档构建更新），入口见文档页
[RouterOS 容器部署 rove-hop](https://talkincode.github.io/rove/hop-routeros.html)。

### 4.3 自行打包（开发机）

```bash
# 需要：cargo-zigbuild + zig，目标 aarch64-unknown-linux-musl
./scripts/pack-routeros-hop.sh --target aarch64-unknown-linux-musl --version dev
```

---

## 5. 标准部署流程（reverse-only）

### 步骤 A — 上传镜像到 RouterOS

任选其一：

**A1. Winbox / WebFig / `ftp` 上传**  
把 `rove-hop-arm64.tar` 放到路由器文件列表根目录（与脚本里 `IMAGE_FILE` 一致）。

**A2. 设备拉文件**（设备能访问你的 HTTP）：

```text
/tool fetch url="http://<你的主机>/rove-hop-arm64.tar" dst-path=rove-hop-arm64.tar
```

确认：

```text
/file print where name~"rove-hop"
```

> RouterOS 需要 **Docker-save** 格式（含 `manifest.json`）。  
> 裸 rootfs tar/tar.gz 会报 `no manifest.json in archive`。

### 步骤 B — 设置全局变量并导入脚本

在 Terminal（或 SSH）执行（**先改成你的值**）：

```text
:global RoveHopId "rove-hop-jp"
:global RoveHopEdge "edge.example.com:9443"
:global RoveHopToken "REPLACE_WITH_TOKEN"
:global RoveHopServerName "edge.example.com"
:global RoveHopInsecure "no"
:global RoveHopImage "rove-hop-arm64.tar"
:global RoveHopVeth "rove-hop-veth"
:global RoveHopAddr "172.30.68.2/30"
:global RoveHopGateway "172.30.68.1"
:global RoveHopHostAddr "172.30.68.1/30"
:global RoveHopRoot "/rove-hop-root"
:global RoveHopName "rove-hop"
:global RoveHopMemHigh "67108864"
:global RoveHopDns "1.1.1.1"
:global RoveHopMaxStreams "256"
```

导入并运行：

```text
/import file-name=rove-hop-routeros.rsc
```

或先把 `.rsc` 存为 system script 再 `/system script run ...`。

脚本会：

1. 创建 veth + 主机侧地址  
2. `/container add`（entrypoint=`rove-hop`，reverse-only cmd）  
3. `start-on-boot=yes`，`memory-high` 默认 64 MiB  
4. 启动容器  
5. **不**添加 LAN dst-nat（reverse 不需要对外暴露端口）

> 若设备上已有全局 `masquerade`，容器出网一般即可。  
> 若无，请为容器网段补一条 srcnat masquerade（见脚本内注释）。

### 步骤 C — 验收

```text
/container print where name="rove-hop"
/log print where topics~"container" 
```

期望：

- `running=true`，`arch` 有值（arm64/amd64）  
- 日志类似：`reverse edge session` / hop 已监听 reverse（无本地 socks 也可）  
- edge 侧能看到该 `hop_id` 会话（或对应用户访问日志出现 `reverse:rove-hop-jp`）

业务验收：用绑定了该 reverse 出口的测试账号访问目标站，确认源 IP 为 hop 出口公网 IP。

### 步骤 D — 卸载 / 重装

```text
/import file-name=rove-hop-routeros-remove.rsc
```

会停删容器、veth、相关 address；**默认不删镜像 tar**（可手动 `/file remove`）。

---

## 6. 容器命令行（脚本生成的本质）

等价进程参数：

```bash
rove-hop \
  --reverse-quic edge.example.com:9443 \
  --reverse-hop-id rove-hop-jp \
  --reverse-token "$TOKEN" \
  --reverse-server-name edge.example.com \
  --reverse-max-streams 256 \
  --access-log-disable \
  --dns-server 1.1.1.1
# 自签时加：--reverse-insecure
# 不要加 --socks5 / --https（生产 reverse-only）
```

令牌优先来自 RouterOS 脚本变量；**不要**把生产 token 写进 Git。

---

## 7. 并发与重连（运维必知）

| 项 | 默认 | 说明 |
|---|---:|---|
| 每 hop 并发隧道 | 256 | edge `max_streams_per_hop` 与 hop `--reverse-max-streams` |
| 满载错误 | `at_capacity` | 只拒新隧道，fail-closed |
| 自动重连 | 是 | 1s 起指数退避，上限 30s |
| 先 hop 后 edge | 可以 | edge 就绪后 hop 自动连上 |
| QUIC 保活 | 15s / idle 45s | 适配常见 NAT UDP 映射 |

ax² 实机量级参考（SOCKS 压测，reverse 资源同量级更轻）：空闲 ~1 MiB，八流下载峰值 ~11 MiB，CPU 个位数百分比。

---

## 8. 存储与日志建议

- 内置 flash 小时：镜像与 `root-dir` 放到 **USB**（`/usb1/...`），`layer-dir` 按型号调整。  
- 生产 hop：**`--access-log-disable`**，避免打爆 flash。  
- 需要审计时：syslog 打到远端，或 USB 目录 + 短保留。  
- `memory-high`：办公室 64 MiB 足够；可按并发调到 32–128 MiB。

---

## 9. 故障排查速查

| 现象 | 排查 |
|---|---|
| `no manifest.json` | 镜像不是 docker save；换官方部署包内 `.tar` |
| `download/extract failed` | 存储满 / 架构不符 / 文件损坏 |
| 一直 reconnecting | edge 未启、UDP 未放行、token 错、证书名不匹配 |
| `unauthorized` | token 与 edge `tokens` 不一致 |
| `duplicate_hop_id` | 同 id 已在线且 `duplicate=reject` |
| 有会话但业务不通 | 快照 `addr` 与 hop_id 不一致；或用户未进对应 group |
| 容器起不来 | `/log print where topics~"container"`；检查 entrypoint 路径 |
| 出网失败 | veth 地址/网关、masquerade、DNS |

edge 失败阶段（访问日志 `failure_stage`）：

- `reverse_lookup` — 无该 hop 会话  
- `reverse_open` — 开流/握手失败  
- `hop_connect` — hop 连目标失败  
- `stream_io` — 对拼中断  

---

## 10. 安全基线

1. 令牌足够长，仅 edge 与 hop 持有；不进仓库、不进截图。  
2. 生产 **reverse-only**，不要把 SOCKS  dst-nat 到公网。  
3. `--reverse-insecure` 仅实验网；生产用正规证书。  
4. 限制谁能 Winbox/API 改 container。  
5. 升级：先起新容器验证注册，再切快照/下旧容器。

---

## 11. 升级步骤

1. 下载新版本 `rove-hop-routeros-*.tar.gz`，校验 SHA256  
2. 上传新 `rove-hop-arm64.tar`（可换文件名避免覆盖）  
3. 跑 remove 脚本停旧容器（或手动 stop/remove，保留 veth）  
4. 更新 `RoveHopImage` 后重跑部署脚本  
5. 确认 `running` + edge 会话 + 抽样业务  
6. 删除旧 tar 释放 flash  

hop 无状态（不吃快照），升级窗口通常只影响该出口上的在途连接。

---

## 12. 与 SOCKS 模式的关系

| | reverse（推荐生产） | SOCKS（仅调试） |
|---|---|---|
| 端口暴露 | 无 | 需 dst-nat |
| NAT 友好 | 只出站 UDP | 要能被拨入 |
| 策略位置 | edge | 调用方自己指上游 |
| 多 edge | 多 `--reverse-quic` | 每边分别配上游 |

基准/排障可临时加 `--socks5`，**不要**当作办公室长期入口。

---

## 13. 一页纸检查表（上线签字）

- [ ] hop_id 符合 `rove-hop-…` 并已写入变更单  
- [ ] edge `[reverse_hop]` 已启，UDP 放行，token/证书就绪  
- [ ] 快照 `kind=reverse` `addr=<同一 hop_id>`  
- [ ] 镜像 arch 匹配，docker-save 格式  
- [ ] veth 网段无冲突，出网 masq 正常  
- [ ] 容器 `running=true`，日志无 fatal  
- [ ] 测试账号走 `reverse:<hop_id>`，出口 IP 正确  
- [ ] 访问日志关闭或外置；memory-high 已设  
- [ ] remove 脚本与回滚步骤已备份  

---

## 14. 相关链接

- 文档站：独立 hop、反向 hop、配置详解、故障排查  
- Release：https://github.com/talkincode/rove/releases  
- 镜像（通用容器）：`ghcr.io/talkincode/rove`（RouterOS 更推荐本部署包内的 flat docker-save tar）

---

*本文随 `deploy/routeros-hop/` 发布；与 mdBook 页面 `hop-routeros.md` 同源维护。*
