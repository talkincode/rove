# 数据模型与策略决策

理解 Rove，只要理解它每次连接怎么做两件事：**认证**（你是谁、有没有过期）和**决策**（这个目标该直连、
走二级代理、还是拒绝）。这两件事的依据全在一份**快照**里。

## 为什么是「编译好的扁平快照」

旧版 `userdata.json`（216KB / 890 用户）是反范式的：扁平 `user_list` + `address_list` + `routings`，
鉴权要在 `users[]` 与 `codes[]` 里线性扫描（O(n)）。新版把「真相」留在控制面，节点只接收**编译好的扁平快照**，
鉴权按用户名索引，O(1)。

## Schema v4：可复用 Routing Policy

schema v4 把三个概念分开：

- **user**：认证、限速、前端凭据，并且只引用一个 `policy`；
- **routing policy**：有序 first-match-wins routes；每条 route 的 action 严格为 named
  egress、direct 或 block；
- **named egress**：可复用的单 backend 或主备 chain，凭据只保存一次。节点差异在
  `node_overrides.<node_id>.egresses` realization 层整项替换，policy 不依赖节点。

```json
{
  "schema_version": 4,
  "version": 42,
  "users": {
    "alice": {"password": "secret", "policy": "work"}
  },
  "routing_policies": {
    "work": {
      "routes": [
        {
          "selectors": ["openai.com"],
          "action": {"type": "egress", "egress": "tokyo"}
        },
        {
          "selectors": ["full:private.example"],
          "action": {"type": "direct"}
        },
        {
          "selectors": ["book:security/blocked"],
          "action": {"type": "block"}
        }
      ],
      "default_egress": "backup"
    }
  },
  "egresses": {
    "tokyo": {
      "type": "upstream",
      "backend": {"kind": "reverse", "addr": "tokyo-hop"}
    },
    "backup": {
      "type": "chain",
      "members": [
        {
          "id": "primary",
          "priority": 10,
          "backend": {"kind": "socks5", "addr": "10.0.0.9:1080"}
        }
      ]
    }
  }
}
```

route 之间允许 selector 重叠，数组顺序决定结果。未命中时有 `default_egress` 就使用它，
否则直连。`block` 是显式 route action；requested/sniffed 任一候选的 first-match action
为 block 都会拒绝。只有 requested target 是 IP 时，sniffed host 的非 block action 才能选择
路由，且永不改写实际 dial target。完整 wire contract、严格混用校验和 validator 见
[快照协议](./snapshot-protocol.md#schema-v4routing-policy-与-named-egress)。

## Schema v1-v3 快照结构（兼容）

```jsonc
{
  "version": 12,                     // 单调递增；<= 本地版本或 304 则不替换
  "users": {                         // 按用户名索引
    "alice": {
      "password": "s3cret",          // 必填
      "expire": "2026-12-31",        // 可选；缺省=永不过期
      "up_rate": 0,                  // 上行字节/秒，0=不限速
      "down_rate": 0,                // 下行字节/秒，0=不限速
      "max_connections": 0,          // 并发连接上限，0=不限
      "group": "open",               // 必填，指向下面某个分组
      "frontends": {                 // 可选；前端协议凭据，按协议命名空间
        "tuic": { "uuid": "550e8400-...", "password": "front-secret" }
      }
    }
  },
  "groups": {                        // 按 group code 索引
    "open": {},                                        // 空分组 = 纯直连
    "walled": {
      "upstream": {                                    // 命中 proxy 时走的二级代理
        "kind": "socks5",                              // http | socks5 | reverse
        "addr": "10.0.0.9:1080",
        "username": "u", "password": "p",
        "tls": false,
        "skip_cert_verify": false                      // tls=true 时可跳过证书校验（自签名 hop）
      },
      "default_upstream": {                            // 可选：未命中 proxy 时的默认出口
        "kind": "socks5", "addr": "10.0.0.10:1080", "tls": false
      },
      "proxy": ["discord.dev", "203.0.113.0/24"],      // 命中 → 走 upstream
      "block": ["full:ads.example.com", "10.0.0.0/8"]  // 命中 → 拒绝
    }
  }
}
```

> `users` 和 `groups` 缺省都为空对象。一个用户最少只需要 `password` 和 `group` 两个字段。

## v1-v3 决策流程 `decide()`（兼容）

对每条连接的目标（域名或 IP），按顺序判断：

```text
1. 命中 block          → 拒绝（403 / SOCKS5 拒绝）
2. 分组有 upstream 且命中 proxy → 走该二级代理
3. 否则若有 default_upstream    → 走默认二级代理
4. 其余                → 直连
```

即：**黑名单优先；proxy 命中走指定上游；未命中可兜底默认上游；都没有就直连。**

- 纯直连节点：给用户一个空分组（`"open": {}`）即可。
- 全量走某个上游：分组只配 `default_upstream`，不配 `proxy`。
- 选择性分流：`proxy` 列出需要走上游的域名/网段，其余直连。

## 域名与 IP 匹配

schema v4 的 route `selectors[]`，以及兼容 schema v1–v3 的 `proxy` / `block` 列表，每一项都按前缀
区分匹配方式：

| 写法 | 匹配方式 | 示例 |
|---|---|---|
| `discord.dev` | **后缀匹配**（默认）：匹配自身及所有子域 | 命中 `discord.dev`、`app.discord.dev` |
| `full:ads.example.com` | **精确匹配**：只匹配完全相同的域名 | 只命中 `ads.example.com`，不含子域 |
| `keyword:analytics` | **关键字**：域名包含该子串即命中 | 命中 `x-analytics.io`、`analytics.cdn.net` |
| `10.0.0.0/8` | **IP CIDR**：网段匹配 | 命中该网段内所有 IP |
| `203.0.113.7` | 单 IP（等价 `/32` 或 `/128`） | 只命中该地址 |
| `book:google/ads` | **地址簿分类**：匹配该分类及其子孙中的域名/IP | 需要节点 `[addrbook]` 与快照 schema v3 |

后缀匹配语义与旧 Go 版 `MatcherDomain` 一致（`discord.dev` 同时匹配 `discord.dev` 与 `*.discord.dev`）。

`book:` 适合把 Provider 地址段、社区域名表等大型数据集从快照中分离出来。多个分类与显式规则按“或”
组合；v4 里顺序由 `routes` 数组决定，v1–v3 仍是组级 `block` 优先于 `proxy`。任何 `book:` 规则都要求
`schema_version >= 3`（推荐直接发 v4）；节点没有地址簿、分类不存在或 selector 超限时，整份新快照拒收。

地址簿只匹配客户端请求中的目标：域名请求查域名表，IP 字面量请求查 IP 表；不会把域名先解析成 IP
再查 Provider 网段。构建、发布、层级分类、热替换与失败恢复见
[rove-addrbook 指南](./addrbook-format.md)。

## 二级代理（upstream）

schema v4 的 named egress `backend`，以及兼容 schema v1–v3 的 `upstream` / `default_upstream`，
描述同一个出口对象：

| 字段 | 说明 |
|---|---|
| `kind` | `http`（HTTP CONNECT 上游）、`socks5`（SOCKS5 上游）、`reverse`（反向 hop，`addr` 填 `hop_id`）、`subnetra`（经内嵌 overlay 出口，目标须为 overlay IPv4）、`chain`（引用命名出口链，`addr` 填 chain ID，见下节） |
| `addr` | 上游地址 `host:port`；`reverse` 时填注册的 `hop_id`；`chain` 时填 chain ID；`subnetra` 时不使用（目标取自请求本身） |
| `username` / `password` | 上游认证（可选；`reverse` / `subnetra` / `chain` 不接受） |
| `tls` | 与上游的连接是否走 TLS（`reverse` / `subnetra` / `chain` 不接受，chain 的连接参数由成员各自携带） |
| `skip_cert_verify` | **逐上游**开关，`tls=true` 时可跳过证书链/主机名/有效期校验，用于自签名或纯 IP 的 hop。默认 `false` |

> `skip_cert_verify` 只影响这一个上游、只影响出站方向，不存在全局关校验的开关，也不影响入站监听的 TLS。
> `kind = "reverse"` 的语义、部署见 [反向 hop 数据面](./reverse-hop.md)；`kind = "subnetra"` 见 [内嵌 Subnetra 组网底座](./subnetra.md)。

## 出口链（chains）与主备故障转移

一个业务出口（例如 `JP POP`）往往有多台功能等价的主备后端。**出口链（chain）**把它们组织成
一个按优先级排序的候选集合，策略绑定逻辑出口而不是单个物理后端；主后端建立失败时自动按
优先级尝试下一个。chain **不是** A → B → 目标的串联多跳代理，也不做权重/轮询/并行竞速/健康
探测——首版是按新连接执行的被动故障转移。

schema v4 把 chain 写成 named egress（`type: "chain"`），route 只引用 egress ID：

```jsonc
{
  "schema_version": 4,
  "version": 13,
  "egresses": {
    "jp-pop": {
      "type": "chain",
      "members": [
        { "id": "jp-reverse-1", "priority": 1, "backend": { "kind": "reverse", "addr": "h1" } },
        { "id": "jp-socks-2",   "priority": 2, "backend": { "kind": "socks5", "addr": "10.2.2.1:1080" } }
      ]
    }
  },
  "routing_policies": {
    "rule-a": {
      "routes": [
        {
          "selectors": ["example.com"],
          "action": { "type": "egress", "egress": "jp-pop" }
        }
      ]
    }
  }
}
```

兼容 schema v2–v3 仍可用顶层 `chains` + `upstream.kind = "chain"`（见
[快照协议 · 出口链](./snapshot-protocol.md#出口链chainsschema-v2)）。

- 成员 `id` 与 `priority` 在 chain 内唯一，数字越小越先尝试；`backend` 复用上表的 upstream
  字段与全部校验规则，可混合 `reverse` hop 与地址型 HTTP/SOCKS5 后端，但不得嵌套 `chain`。
- 同一 chain/egress 可被多个 policy/route 复用。
- 未知 chain 引用、空 chain、重复 ID/priority、字段冲突、chains 超上限（1000 条 / 每条 16 成员）
  都会让**整份快照编译失败**，节点继续用上一份有效快照。
- 旧节点不认识 chain 语义时会拒收新快照并保留旧快照（fail-closed 哨兵），不会静默
  直连；发布顺序与 `schema_version` 语义见 [快照协议](./snapshot-protocol.md)。

### TCP 故障转移语义

1. `block` 判断仍优先于所有出口选择（决策顺序不变）。
2. 按 `priority` 从小到大顺序尝试成员——不做随机、轮询或并行竞速。
3. **只有隧道建立阶段的失败会触发下一成员**：拨号失败/超时、TLS 或上游代理握手失败、
   HTTP CONNECT / SOCKS5 CONNECT 建立失败、reverse hop 未注册/开流失败/超时/hop 无法连目标。
4. 每次成员尝试有界超时（默认 10s），一次请求的总故障转移时间有上限（默认 30s，常量
   `CHAIN_ATTEMPT_TIMEOUT` / `CHAIN_TOTAL_TIMEOUT`）；预算耗尽即停止尝试。
5. 任一成员返回已建立的数据流后立即**固定**该成员；开始转发客户端数据后的 IO 错误不会在其他
   成员上重放，避免重复请求或协议状态错乱。
6. 所有成员失败时 fail-closed（HTTP 502 / SOCKS5 拒绝），**不会隐式回落直连**；失败阶段记为
   `chain_exhausted`。

### UDP 语义

1. 当前只有 `reverse` 成员具备 UDP relay 能力；HTTP、SOCKS5、Subnetra 成员对 UDP 请求一律不合格。
2. 建立 UDP association 时只在 reverse 成员中按优先级尝试；混合 chain 里的非 UDP 成员不会被误用。
3. chain 没有可用 reverse 成员时保持 fail-closed（丢弃，不直连）。
4. association 建立后**粘住**选中的 hop，不逐包切换、不静默迁移（出口 IP/端口与 NAT 映射保持稳定）。
5. 若需要 UDP 主备，chain 必须至少配置两个 reverse 成员；“reverse 主、SOCKS5 备”只能为 TCP 提供备份。

### 可观测性

访问日志与统计同时保留逻辑与物理两个维度：决策记为 `chain:jp-pop`（`decision` 字段），实际
出口记为胜出成员的安全标识（`egress` 字段，如 `reverse:h1` / `upstream:10.2.2.1:1080`），并带
`chain_member`（成员 ID）与 `attempts`（建立尝试次数，全部失败时也会记录）。流量与活跃隧道
统计按物理出口维度计数。每次成员失败在 debug 日志中带 chain/member/阶段分类。日志不含成员
密码、reverse token 或 Proxy-Authorization 内容。

### 节点级覆盖

schema v4 用 `node_overrides.{node_id}.egresses` **整项替换**同名 egress（不能新增 node-only
egress，也不能改 policy）。兼容 schema v2–v3 仍支持 `node_overrides.{node_id}.chains` /
`.groups`。MQTT 节点状态带 `snapshot_schema_version`，便于控制面确认全网升级完成后再启用
chain 或 v4 producer 输出。

## 认证与限速

- **认证**：按用户名查用户 → 常量时间比较密码 → 校验 `expire`（已过期直接拒绝）。
- **限速**：`up_rate` / `down_rate` 是每用户的字节令牌桶；两者都为 0 时走 `copy_bidirectional` 零开销快路。
- **连接数**：`max_connections` 限制该用户并发连接，0 表示不限。

## TUIC 前端身份

在 `frontends.tuic` 里给用户配 `uuid` + `password` 即启用该用户的 [TUIC 前端接入](./tuic.md)。`frontends` 是按协议命名空间的凭据表（`frontends.<协议>`），将来加前端协议（如 Trojan / VLESS）只需加一个协议条目，不动顶层 schema，也能按协议独立启停 / 轮换：

- 快照编译期为每个协议建立 `uuid → 用户名` 索引；同一协议下一个 `uuid` 被两个用户占用会**导致编译失败**（认证必须无歧义）。
- `frontends.tuic.password` **独立于登录 `password`**：TUIC 用 TLS keying-material 导出的 token 认证，节点只做「uuid 查表 → 归属用户名」，不复用登录口令、也不从报文还原用户名。
- 认证通过后，`expire` / 限速 / 连接数 / routing policy（或兼容 `group`）全部沿用该用户既有语义。TCP 请求按 `up_rate`/`down_rate` 限速；UDP 请求不限速（走反向 hop UDP 出口）。

## 节点级覆盖 `node_overrides`

控制面向所有节点发**完全相同**的快照。个别节点（例如不同边缘位置有各自的本地 hop）需要不同的分组时，
快照可带一个按 `node_id` 索引的 `node_overrides`，节点拿到后用**本地配置的 `node_id`** 自行挑出属于自己的
覆盖并在本地合并。控制面自始至终不需要知道是哪个节点在请求。字段语义见
[控制面同步协议 · 节点级 override](./snapshot-protocol.md)。

schema v4 不再覆盖 group/chain，只允许整项替换同名 egress；不能新增 node-only egress，
不能改变 routing policy。

## 兼容旧 `userdata.json`

节点仍能读入旧结构（`timestamp` / `user_list` / `address_list` / `routings`）用于迁移：每条旧 routing 映射为一个
内部 `legacy-route-*` 分组，用户按 routing 顺序用用户名或 code 做 first-match 归组。新模型是「每用户一个分组」，
若旧数据依赖同一用户按不同规则走不同上游，将无法无损表达 —— 迁移到新快照格式即可解决。
