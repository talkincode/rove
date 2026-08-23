# 数据模型与策略决策

理解 Rove，只要理解它每次连接怎么做两件事：**认证**（你是谁、有没有过期）和**决策**（这个目标该直连、
走命名出口、还是拒绝）。这两件事的依据全在一份**快照**里。

## 为什么是「编译好的扁平快照」

「真相」留在控制面，节点只接收**编译好的扁平快照**：用户按用户名索引，鉴权 O(1)；选择器在快照编译期
就编成 matcher，热路径上不做字符串解析，也不做任何回控制面的同步查询。控制面不可达时节点继续用
上一份有效快照服务，而不是降级放行。

## 三张表：identity / policy / egress

Rove 只有一种快照 schema（`schema_version: 1`），它把三个概念分开：

- **user**：认证、限速、前端凭据，并且只引用一个 `policy`；
- **routing policy**：有序 first-match-wins routes；每条 route 的 action 严格为命名 egress、
  direct 或 block；
- **named egress**：可复用的单 backend 或主备 chain，凭据只保存一次。节点差异在
  `node_overrides.<node_id>.egresses` realization 层整项替换，policy 不依赖节点。

```json
{
  "schema_version": 1,
  "version": 42,
  "users": {
    "alice": {"password": "secret", "policy": "work"}
  },
  "routing_policies": {
    "work": {
      "routes": [
        {
          "selectors": ["book:security/blocked"],
          "action": {"type": "block"}
        },
        {
          "selectors": ["openai.com"],
          "action": {"type": "egress", "egress": "tokyo"}
        },
        {
          "selectors": ["full:private.example"],
          "action": {"type": "direct"}
        }
      ],
      "default_action": { "type": "egress", "egress": "backup" }
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

> `users` / `routing_policies` / `egresses` 缺省都是空对象。一个用户最少只需要 `password` 和
> `policy` 两个字段。

这样分表的收益是直接的：一条 policy 可以被任意多个用户复用而不复制规则；一个 egress 可以被任意多条
route 复用而不复制凭据；换出口只改 egress realization，不动任何 route。

## 决策流程 `decide()`

对每条连接的目标（域名或 IP）：

```text
1. 认证：用户名存在 → 常量时间比对密码 → 校验 expire。任一失败即拒绝。
2. 取该用户的 policy。
3. 按 routes 数组顺序求第一个命中的 route，采用它的 action。
4. 任一候选（requested host / 已验证的 sniffed host）first-match 为 block → 拒绝。
5. 都未命中 → 执行 policy 的 default_action；没有 default 则直连。
```

即：**顺序即语义，第一个命中的 route 说了算；未命中执行 policy 的默认 action；没有默认就直连。**

`default_action` 与 route 的 `action` 是同一套词汇（`egress` / `direct` / `block`），所以未命中
时的行为写得和命中时一样明确：

- 纯直连策略：给用户一条空 policy（`"open": {}`）即可。
- 全量走某个出口：policy 只配 `default_action` 为 `{"type":"egress","egress":"..."}`，不配 route。
- 选择性分流：把需要走出口的域名/网段写成 route，其余落到 `default_action` 或直连。
- **deny-by-default（allowlist）**：`default_action` 设为 `{"type":"block"}`，policy 就只能到达
  它自己列出的目标。选择器没有 catch-all 写法，这是表达「只放行清单内目标」的唯一方式。

> route 之间允许 selector 重叠，**数组顺序决定结果**。因此 block route 应该放在最前面——一条更靠前的
> `egress` route 会让后面的 `block` route 永远不生效。

sniff 只影响策略身份，不改写实际 dial target：只有 requested target 是 IP 时，sniffed host 的
非 block action 才能改变路由选择。完整 wire contract、严格校验与 validator 见
[快照协议](./snapshot-protocol.md)。

## 域名与 IP 匹配

route `selectors[]` 的每一项都按前缀区分匹配方式：

| 写法 | 匹配方式 | 示例 |
|---|---|---|
| `api.openai.com` | **后缀匹配**（默认）：匹配自身及所有子域 | 命中 `api.openai.com`、`app.api.openai.com` |
| `full:ads.example.com` | **精确匹配**：只匹配完全相同的域名 | 只命中 `ads.example.com`，不含子域 |
| `keyword:analytics` | **关键字**：域名包含该子串即命中 | 命中 `x-analytics.io`、`analytics.cdn.net` |
| `10.0.0.0/8` | **IP CIDR**：网段匹配 | 命中该网段内所有 IP |
| `203.0.113.7` | 单 IP（等价 `/32` 或 `/128`） | 只命中该地址 |
| `book:google/ads` | **地址簿分类**：匹配该分类及其子孙中的域名/IP | 需要节点配置 `[addrbook]` |

`book:` 适合把 Provider 地址段、云厂商网段表等大型数据集从快照中分离出来。多个分类与显式规则在同一条
route 内按「或」组合；跨 route 的优先级由 `routes` 数组顺序决定。节点没有地址簿、分类不存在或 selector
超限时，**整份新快照拒收**——绝不会把 `book:aws` 当成一个普通域名放行。

地址簿只匹配客户端请求中的目标：域名请求查域名表，IP 字面量请求查 IP 表；不会把域名先解析成 IP
再查 Provider 网段。构建、发布、层级分类、热替换与失败恢复见
[rove-addrbook 指南](./addrbook-format.md)。

## 出口 backend

命名 egress 的 `backend` 描述一个具体的出口对象：

| 字段 | 说明 |
|---|---|
| `kind` | `http`（HTTP CONNECT 上游）、`https`（HTTP CONNECT over TLS）、`socks5`（SOCKS5 上游）、`reverse`（反向 hop，`addr` 填 `hop_id`）、`subnetra`（经内嵌 overlay 出口，目标须为 overlay IPv4） |
| `addr` | 出口地址 `host:port`；`reverse` 时填注册的 `hop_id`；`subnetra` 时不使用（目标取自请求本身） |
| `username` / `password` | 出口认证（可选；`reverse` / `subnetra` 不接受） |
| `tls` | 与出口的连接是否走 TLS（`reverse` / `subnetra` 不接受，二者传输自带加密） |
| `skip_cert_verify` | **逐 backend** 开关，`tls=true` 时可跳过证书链/主机名/有效期校验，用于自签名或纯 IP 的 hop。默认 `false` |

> `skip_cert_verify` 只影响这一个 backend、只影响出站方向，不存在全局关校验的开关，也不影响入站监听的 TLS。
> `kind = "reverse"` 的语义、部署见 [反向 hop 数据面](./reverse-hop.md)；`kind = "subnetra"` 见 [内嵌 Subnetra 组网底座](./subnetra.md)。

chain 不是一种 backend kind，而是 egress 的另一种形态（`"type": "chain"`），见下节。

## 出口链（chain）与主备故障转移

一个业务出口（例如 `JP POP`）往往有多台功能等价的主备后端。**出口链（chain）**把它们组织成
一个按优先级排序的候选集合，策略绑定逻辑出口而不是单个物理后端；主后端建立失败时自动按
优先级尝试下一个。chain **不是** A → B → 目标的串联多跳，也不做权重/轮询/并行竞速/健康
探测——它是按新连接执行的被动故障转移。

chain 就是一个命名 egress，route 照常只引用 egress ID：

```jsonc
{
  "schema_version": 1,
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

- 成员 `id` 与 `priority` 在 chain 内唯一，数字越小越先尝试；`backend` 复用上表的字段与全部校验
  规则，可混合 `reverse` hop 与地址型 HTTP/SOCKS5 后端，但不得嵌套 chain。
- 同一 egress 可被多个 policy/route 复用。
- 未知 egress 引用、空 chain、重复 ID/priority、字段冲突、超出上限（10000 个 egress / 每条 chain
  16 成员）都会让**整份快照编译失败**，节点继续用上一份有效快照。

### TCP 故障转移语义

1. `block` 判断仍优先于所有出口选择（决策顺序不变）。
2. 按 `priority` 从小到大顺序尝试成员——不做随机、轮询或并行竞速。
3. **只有隧道建立阶段的失败会触发下一成员**：拨号失败/超时、TLS 或上游握手失败、
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
5. 若需要 UDP 主备，chain 必须至少配置两个 reverse 成员；「reverse 主、SOCKS5 备」只能为 TCP 提供备份。

### 可观测性

访问日志与统计同时保留逻辑与物理两个维度：决策记为 `chain:jp-pop`（`decision` 字段），实际
出口记为胜出成员的安全标识（`egress` 字段，如 `reverse:h1` / `upstream:10.2.2.1:1080`），并带
`chain_member`（成员 ID）与 `attempts`（建立尝试次数，全部失败时也会记录）。流量与活跃隧道
统计按物理出口维度计数。每次成员失败在 debug 日志中带 chain/member/阶段分类。日志不含成员
密码、reverse token 或 Proxy-Authorization 内容。

## 认证与限速

- **认证**：按用户名查用户 → 常量时间比较密码 → 校验 `expire`（已过期直接拒绝）。
- **限速**：`up_rate` / `down_rate` 是每用户的字节令牌桶；两者都为 0 时走 `copy_bidirectional` 零开销快路。
- **连接数**：`max_connections` 限制该用户并发连接，0 表示不限。

## TUIC 前端身份

在 `frontends.tuic` 里给用户配 `uuid` + `password` 即启用该用户的 [TUIC 前端接入](./tuic.md)。`frontends` 是按协议命名空间的凭据表（`frontends.<协议>`），将来加前端协议只需加一个协议条目，不动顶层 schema，也能按协议独立启停 / 轮换：

- 快照编译期为每个协议建立 `uuid → 用户名` 索引；同一协议下一个 `uuid` 被两个用户占用会**导致编译失败**（认证必须无歧义）。
- `frontends.tuic.password` **独立于登录 `password`**：TUIC 用 TLS keying-material 导出的 token 认证，节点只做「uuid 查表 → 归属用户名」，不复用登录口令、也不从报文还原用户名。
- 认证通过后，`expire` / 限速 / 连接数 / routing policy 全部沿用该用户既有语义。TCP 请求按 `up_rate`/`down_rate` 限速；UDP 请求不限速（走反向 hop UDP 出口）。

## 节点级覆盖 `node_overrides`

控制面向所有节点发**完全相同**的快照。个别节点（例如不同边缘位置有各自的本地 hop）需要不同出口时，
快照可带一个按 `node_id` 索引的 `node_overrides`，节点拿到后用**本地配置的 `node_id`** 自行挑出属于自己的
覆盖并在本地合并。控制面自始至终不需要知道是哪个节点在请求。

override 只允许**整项替换 base `egresses` 里已经存在的同名 egress**：不能新增 node-only egress，
不能改 routing policy，也不能改 `users`。这条约束保证 route 表在全网是同一份，只有出口 realization
因节点而异。引入一个不存在的 egress ID 会让该节点拒收整份快照。字段语义见
[控制面同步协议 · 节点级 Override](./snapshot-protocol.md)。

MQTT 节点状态带 `snapshot_schema_version`，便于控制面在未来 bump schema 前确认全网能力。
