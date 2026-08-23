# SNMP 监控：MIB 参考与 Cacti 接入

Rove 内置一个只读 SNMP agent（`rove` 与 `rove-hop` 都有，默认关闭），
供 Cacti、LibreNMS、Zabbix 等标准 NMS 直接轮询每个 listener 与每个出口（egress）
的流量计数器，无需部署任何 exporter 或旁路 agent。

能力边界（铁律）：

- 只响应 **GET / GETNEXT / GETBULK**；收到 SET 一律返回 `notWritable`。
- **TRAP / INFORM 永不支持**——告警靠 NMS 侧阈值，不靠节点推送。
- 支持 **SNMPv2c** 与 **SNMPv3 USM**；不支持 SNMPv1。
- v3 认证只支持 **SHA-1 / SHA-256**，加密只支持 **AES-128-CFB**；**MD5 / DES 永不支持**。

## 开启

### `rove`（主节点）：`[snmp]` 配置段

```toml
[snmp]
enable = true
listen = "0.0.0.0:161"        # UDP；<1024 端口需要相应权限
community = "your-secret"     # v2c community；留空则 v2c 关闭
allow_cidrs = ["10.0.0.0/8"]  # 来源白名单（默认仅 loopback）
state_path = "./data/snmp-state.json"

# 可选：SNMPv3 用户（可多个）
[[snmp.v3_users]]
username = "cacti"
auth_protocol = "sha256"      # sha1 | sha256
auth_password = "change-me-auth"
priv_protocol = "aes128"      # 留空 = 该用户不加密（authNoPriv）
priv_password = "change-me-priv"
```

规则（fail-closed，配置错误在启动时报错）：

- `enable = true` 时，`community` 与 `v3_users` 至少要配一个。
- v3 用户必须有认证口令；**配置了 `priv_password` 的用户只接受 authPriv 级别请求**，
  用 authNoPriv 来问会收到 `usmStatsUnsupportedSecLevels` Report。
- 白名单外的来源、错误的 community、未知用户名一律静默丢弃（只递增协议计数器），
  不写日志——扫描器刷不出日志风暴。

### `rove-hop`（独立 hop 节点）：命令行

快捷开启 v2c：

```sh
rove-hop --socks5 0.0.0.0:1080 \
  --snmp-listen 0.0.0.0:161 \
  --snmp-community your-secret \
  --snmp-allow 10.0.0.0/8 --snmp-allow 192.168.1.0/24
```

需要 SNMPv3 时，把上面的 `[snmp]` 段单独放进一个 TOML 文件（v3 口令不进命令行）：

```sh
rove-hop --socks5 0.0.0.0:1080 --snmp-config /etc/rove/snmp.toml
```

`--snmp-config` 与 `--snmp-listen`/`--snmp-community`/`--snmp-allow` 互斥。

## OID 参考

### 企业子树基点

```
.1.3.6.1.4.1.32473.61
```

> **注意**：`32473` 是 RFC 5612 保留给**文档示例**的企业号（PEN），当前作为占位使用。
> 如果你的网络里有其他设备也用了这个示例 PEN，OID 会冲突；生产环境建议向 IANA
> 申请正式 PEN 后替换（修改 `src/snmp/mod.rs` 的 `ENTERPRISE_BASE` 常量）。

下文用 `BASE` 代指 `.1.3.6.1.4.1.32473.61`。

### 标准 system 组（`.1.3.6.1.2.1.1`）

| OID | 名称 | 类型 | 值 |
|---|---|---|---|
| `.1.3.6.1.2.1.1.1.0` | sysDescr | OctetString | `Rove edge node, version x.y.z`（hop 节点为 `hop`） |
| `.1.3.6.1.2.1.1.2.0` | sysObjectID | OID | `BASE` |
| `.1.3.6.1.2.1.1.3.0` | sysUpTime | TimeTicks | 进程启动以来的时间（百分之一秒） |
| `.1.3.6.1.2.1.1.4.0` | sysContact | OctetString | 空 |
| `.1.3.6.1.2.1.1.5.0` | sysName | OctetString | `node_id` |
| `.1.3.6.1.2.1.1.6.0` | sysLocation | OctetString | 空 |
| `.1.3.6.1.2.1.1.7.0` | sysServices | Integer | 72（transport + application） |

### 标准 snmp 组（`.1.3.6.1.2.1.11`，agent 自身计数）

| OID | 名称 | 说明 |
|---|---|---|
| `.1.3.6.1.2.1.11.1.0` | snmpInPkts | 收到的 UDP 包总数（含被丢弃的） |
| `.1.3.6.1.2.1.11.3.0` | snmpInBadVersions | 版本不支持的包数 |
| `.1.3.6.1.2.1.11.4.0` | snmpInBadCommunityNames | community 错误的包数 |
| `.1.3.6.1.2.1.11.6.0` | snmpInASNParseErrs | BER 解析失败的包数 |

### 节点身份标量（`BASE.1`）

| OID | 名称 | 类型 | 值 |
|---|---|---|---|
| `BASE.1.1.0` | geNodeId | OctetString | 配置的 `node_id` |
| `BASE.1.2.0` | geNodeRole | Integer | 1 = edge（`rove`），2 = hop（`rove-hop`） |
| `BASE.1.3.0` | geVersion | OctetString | 软件版本号 |

### listenerTable（`BASE.2.1`，每监听入口一行）

行索引是**长度前缀的 listener 名字**：名字 `web`（3 字节）的索引为 `3.119.101.98`。
GETNEXT/GETBULK 遍历时 OID 序稳定，Cacti 用 snmp query 自动发现即可，无需手算索引。

| 列 OID | 名称 | 类型 | 说明 |
|---|---|---|---|
| `BASE.2.1.1.<idx>` | geListenerName | OctetString | listener 名（配置中的 `name`） |
| `BASE.2.1.2.<idx>` | geListenerActive | Gauge32 | 当前处于隧道转发阶段的连接数 |
| `BASE.2.1.3.<idx>` | geListenerBytesUp | Counter64 | 进程启动以来客户端→上游累计字节 |
| `BASE.2.1.4.<idx>` | geListenerBytesDown | Counter64 | 进程启动以来上游→客户端累计字节 |

listener 在绑定端口时即注册（计数为 0），Cacti 不必等第一条连接就能发现所有行。

### egressTable（`BASE.3.1`，每出口一行）

行索引同上（长度前缀的出口名）。出口名为策略决策结果：`direct` 或
`upstream:<host:port>`（与访问日志 `decision` 字段一致）。行在第一条走该出口的
连接出现时创建。

| 列 OID | 名称 | 类型 | 说明 |
|---|---|---|---|
| `BASE.3.1.1.<idx>` | geEgressName | OctetString | `direct` 或 `upstream:<addr>` |
| `BASE.3.1.2.<idx>` | geEgressActive | Gauge32 | 当前经该出口转发中的连接数 |
| `BASE.3.1.3.<idx>` | geEgressBytesUp | Counter64 | 该出口累计上行字节 |
| `BASE.3.1.4.<idx>` | geEgressBytesDown | Counter64 | 该出口累计下行字节 |

被策略 block 的连接不产生 egress 行；所有 listener 的字节总和与所有 egress 的
字节总和一致（同一份计数从两个维度聚合）。

### SNMPv3 引擎与 USM 统计（仅配置了 v3 用户时可见）

| OID | 名称 | 说明 |
|---|---|---|
| `.1.3.6.1.6.3.10.2.1.1.0` | snmpEngineID | `80 00 7E D9 04` + `node_id`（截断至 32 字节） |
| `.1.3.6.1.6.3.10.2.1.2.0` | snmpEngineBoots | 重启计数（落盘于 `state_path`） |
| `.1.3.6.1.6.3.10.2.1.3.0` | snmpEngineTime | 本次启动以来秒数 |
| `.1.3.6.1.6.3.10.2.1.4.0` | snmpEngineMaxMessageSize | 最大消息尺寸 |
| `.1.3.6.1.6.3.15.1.1.1.0`〜`.6.0` | usmStats* | 6 个安全失败计数器（unsupportedSecLevels / notInTimeWindows / unknownUserNames / unknownEngineIDs / wrongDigests / decryptionErrors） |

## 用 net-snmp 验证

```sh
# v2c 全量遍历
snmpwalk -v2c -c your-secret 10.0.0.5:161 .1.3.6.1

# GETBULK 遍历（结果应与上面完全一致）
snmpbulkwalk -v2c -c your-secret 10.0.0.5:161 .1.3.6.1.4.1.32473.61

# v3 authPriv（net-snmp 老版本不支持 -a SHA-256，用 SHA 即 SHA-1）
snmpwalk -v3 -l authPriv -u cacti \
  -a SHA-256 -A change-me-auth -x AES -X change-me-priv \
  10.0.0.5:161 .1.3.6.1.4.1.32473.61

# 单点取值：某 listener 的累计上行字节（listener 名 "web" → 索引 3.119.101.98）
snmpget -v2c -c your-secret 10.0.0.5:161 .1.3.6.1.4.1.32473.61.2.1.3.3.119.101.98
```

## Cacti 接入步骤

1. **建设备**：Console → Create → New Device。Hostname 填节点地址；
   SNMP Version 选 `Version 2`（填 community）或 `Version 3`
   （Auth Protocol `SHA`/`SHA-256`、Priv Protocol `AES`，与 `[[snmp.v3_users]]` 一致）。
   SNMP Port 与 `[snmp].listen` 端口一致。保存后设备页应显示 sysDescr /
   sysUptime，说明连通。
2. **建 Data Query**（自动发现表行，一次即可，之后所有节点复用）：
   Console → Data Collection → Data Queries → 新建一个 SNMP Query，
   XML 里 `<oid_index>` 指向 `BASE.2.1.1`（listener 名列），四个字段分别映射
   `BASE.2.1.1`〜`BASE.2.1.4`；egress 表同理指向 `BASE.3.1.*`。
   字节列的 Data Source 类型选 **COUNTER**（Counter64 需要设备 SNMP v2c/v3，
   Cacti 的 spine/cmd.php 原生支持），active 列选 **GAUGE**。
3. **挂到设备**：设备页 Associated Data Queries 添加上面两个 Query，
   Re-index Method 选 `Uptime Goes Backwards`（节点重启后自动重发现）。
4. **建图**：New Graphs → 选中该设备 → 勾选要画的 listener / egress 行。
   字节计数器按 COUNTER 采样后 Cacti 自动算出 bytes/s 速率曲线；
   乘 8 可换算 bits/s（在 CDEF 里配 `8,*`）。

LibreNMS / Zabbix 用法类似：LibreNMS 加设备后用 Custom OID 或 discovery 模块
指向上述表；Zabbix 用 SNMP agent item + discovery rule（`walk[BASE.2.1.1]`）。

## 安全建议

- **默认白名单只有 loopback**（`127.0.0.1/32`、`::1/128`）。把 NMS 的采集网段
  显式加进 `allow_cidrs`，不要图省事配 `0.0.0.0/0`。
- 跨不可信网络轮询时用 **SNMPv3 authPriv**；v2c community 是明文的，只适合
  管理网/内网。
- community 比较是常量时间的；v3 安全失败只递增 `usmStats*` 计数器并按 RFC 3414
  返回 Report（或静默丢弃），都不写日志——可以放心暴露给有扫描噪音的管理网。
- SNMP 端口被占用或 agent 异常退出只影响监控本身：代理转发**不受任何影响**，
  只在启动日志里留一条 `error!`。
- `state_path`（engineBoots 持久化）写失败也只降级为告警；但会导致重启后 boots
  不递增，NMS 侧可能要重新同步时间窗。

## 故障排查

| 现象 | 排查 |
|---|---|
| snmpwalk 超时 | 来源 IP 在 `allow_cidrs` 里吗？中间防火墙放行 UDP 了吗？`enable = true` 了吗？ |
| v2c 超时但 v3 正常 | `community` 是否为空（空 = v2c 关闭）或不匹配？看 `snmpInBadCommunityNames` |
| v3 报 Authentication failure | 口令/协议与配置不一致；节点侧 `usmStatsWrongDigests` 会递增 |
| v3 报 Unsupported security level | 用户配了 `priv_password` 却用 authNoPriv 来问（fail-closed 特性） |
| 重启后 v3 需要重新同步 | 正常：engineBoots +1，net-snmp/spine 会自动重新 discovery |
| egressTable 是空的 | 还没有连接走过任何出口；发起一条经代理的连接后即出现 |
