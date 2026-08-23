# Rove Snapshot Protocol

本文档定义控制面向 Rove 节点下发的身份与策略快照协议。

Rove 只有**一种**快照 schema（`schema_version: 1`）：身份、策略、出口是三张独立的表。
用户显式引用一条可复用的 routing policy，policy 用有序 route 选择命名 egress、直连或阻断，
egress 表单独承载出口 realization 与凭据。

**同步接口是完全扯平、与节点无关的静态接口**：没有 `{node_id}` 路径参数，控制面不需要
知道、也不关心是哪个节点在请求，对所有请求返回**完全相同的字节**。需要按节点区分的
行为（如不同边缘节点用不同本地 hop）完全由节点自己在本地用 `node_overrides` 字段解决，
详见下方「节点级 Override」一节。

## HTTP 同步接口

```http
GET {snapshot_url}?since={version}
Authorization: Bearer {node_token}
Accept: application/json
```

`{snapshot_url}` 是节点本地配置里的完整地址（例如 `https://control.example.com/snapshot`，
或控制面实际暴露的任何其他地址）。节点原样请求它，**不会拼接任何固定路径**（比如
不会假设存在 `/api/v1/...` 这类结构），只会根据 `snapshot_url` 是否已包含 `?` 追加 `?since=`
或 `&since=`。

响应：

```text
200 application/json  返回完整快照（所有节点收到的 body 完全一样）
304 Not Modified      节点当前 version 已是最新
4xx/5xx               同步失败，节点继续使用当前内存快照或本地缓存
```

规则：

- 接口不包含 `node_id`：`since` 是节点本地当前已加载的 version，控制面只需要比较它与全局当前
  version，不需要任何按节点区分的服务端逻辑。可以用一个静态文件服务（比如 nginx/S3/对象
  存储直接把一份 JSON 抛出来）实现，无需动态后端。
- `Authorization` 仍可以是每个节点不同的 token，但这只是凭据/鉴权的事，不影响接口本身与响应体的
  扯平性。
- `version` 必须单调递增。
- 如果没有更新，优先返回 `304`。如果返回 `200` 但 `version <= since`，节点也会忽略。
- 响应必须是完整快照，不是增量 patch。
- 控制面应避免返回明文调试字段、审计字段或与节点无关的业务数据。
- 节点会先解码并编译验证新快照；只有编译成功的快照才会进入本地缓存和内存热替换。
- 同步失败、响应过大、JSON 无法解析、快照 shape 无效、引用未知 policy/egress，或 egress 配置
  非法时，节点继续使用当前内存快照，且不会覆盖已有本地缓存。

## 快照 JSON

```json
{
  "schema_version": 1,
  "version": 42,
  "users": {
    "alice": {
      "password": "user-secret",
      "expire": "2026-12-31",
      "up_rate": 1048576,
      "down_rate": 1048576,
      "max_connections": 2,
      "policy": "shared-policy",
      "frontends": {
        "tuic": {
          "uuid": "550e8400-e29b-41d4-a716-446655440000",
          "password": "tuic-front-end-secret"
        }
      }
    }
  },
  "routing_policies": {
    "shared-policy": {
      "routes": [
        {
          "selectors": ["book:security/blocked"],
          "action": {"type": "block"}
        },
        {
          "selectors": ["domain:egress-a.example", "198.51.100.0/24"],
          "action": {"type": "egress", "egress": "egress-a"}
        },
        {
          "selectors": ["full:intranet.example"],
          "action": {"type": "direct"}
        }
      ],
      "default_egress": "egress-b"
    }
  },
  "egresses": {
    "egress-a": {
      "type": "upstream",
      "backend": {
        "kind": "socks5",
        "addr": "proxy-a.example:1080",
        "username": "upstream-user",
        "password": "upstream-secret"
      }
    },
    "egress-b": {
      "type": "chain",
      "members": [
        {
          "id": "primary",
          "priority": 10,
          "backend": {"kind": "reverse", "addr": "hop-primary"}
        },
        {
          "id": "standby",
          "priority": 20,
          "backend": {"kind": "socks5", "addr": "proxy-b.example:1080"}
        }
      ]
    }
  },
  "node_overrides": {
    "edge-tokyo-01": {
      "egresses": {
        "egress-a": {
          "type": "upstream",
          "backend": {"kind": "reverse", "addr": "tokyo-hop"}
        }
      }
    }
  }
}
```

## 字段定义

### 顶层

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `schema_version` | integer | 是 | 线协议结构/语义版本，**必须是 `1`**。没有默认值：缺失该字段的文档在解码阶段就被拒收。与 `version` 相互独立。 |
| `version` | integer | 是 | 快照内容修订号，必须单调递增；用于 `?since=` 与 `304`。 |
| `users` | object | 否 | 身份表，key 是用户名。缺省为空对象。 |
| `routing_policies` | object | 否 | 可复用 routing policy 表，key 是 policy ID。缺省为空对象。 |
| `egresses` | object | 否 | 命名出口表，key 是 egress ID。缺省为空对象。 |
| `node_overrides` | object | 否 | 节点级 egress 覆盖表，key 是 `node_id`。缺省为空对象。详见下方「节点级 Override」。 |

### `users.{username}`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `password` | string | 是 | HTTP/SOCKS5 登录密码。 |
| `expire` | string/null | 否 | `YYYY-MM-DD`；空或缺省表示不过期。超过该日期后认证失败。 |
| `up_rate` | integer | 否 | 上传限速，单位 bytes/sec；`0` 或缺省表示不限速。 |
| `down_rate` | integer | 否 | 下载限速，单位 bytes/sec；`0` 或缺省表示不限速。 |
| `max_connections` | integer | 否 | 单节点内该身份最大活跃隧道数；`0` 或缺省表示不限制。 |
| `policy` | string | 是 | 该身份绑定的 routing policy ID，非空且必须存在于 `routing_policies`。 |
| `frontends` | object | 否 | 前端协议凭据表，key 是协议名。缺省为空对象；当前支持 `frontends.tuic`。 |

### `users.{username}.frontends.tuic`

给用户配置该对象即可启用 [TUIC v5 前端接入](./tuic.md)。TUIC 凭据独立于用户顶层
`password`：顶层 `password` 用于 HTTP/SOCKS5 登录，`frontends.tuic.password` 只用于
TUIC TLS keying-material token 认证。

```json
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "password": "tuic-front-end-secret"
}
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `uuid` | string | 是 | TUIC 用户 UUID，使用标准带连字符格式 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`。同一份快照中不得被两个用户的 `frontends.tuic` 重复占用（比较时不区分大小写）；重复会导致整份快照编译失败。 |
| `password` | string | 是 | TUIC 前端密码，用作 TLS keying-material exporter 的 context；独立于用户顶层登录 `password`。 |

约束：

- `frontends` 缺省或没有 `tuic` 条目时，该用户不能通过 TUIC 认证，但仍可使用已配置的其他前端。
- TUIC 条目必须同时提供 `uuid` 和 `password`；控制面应在发布快照前拒绝不完整条目。
- `listen`、`cert`、`key`、`alpn`、`initial_mtu` 是节点本地
  `[[tuic_listeners]]` 配置，不属于用户快照，也不得放进 `frontends.tuic`。
- TUIC 认证成功后，`expire`、`up_rate`、`down_rate`、`max_connections` 与 `policy` 继续沿用
  该身份的通用字段。

### `routing_policies.{policy_id}`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `routes` | array | 否 | 有序 route 数组，缺省为空。数组顺序就是协议语义：first-match-wins，不同 route 的 selector 可以重叠。 |
| `default_egress` | string/null | 否 | 所有 route 都未命中时使用的 egress ID，必须存在于 `egresses`。缺省表示未命中即直连。 |

`routes` 为空的 policy 是合法的——它退化为「只有 `default_egress`」，或在没有 `default_egress`
时退化为「认证后直连」。

### `routes[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `selectors` | string[] | 是 | 至少一项，任意一项命中即视为该 route 命中。语法见下方「选择器语义」。 |
| `action` | object | 是 | 严格 tagged union，见下。 |

`action` 只能是以下三种之一：

```json
{"type": "egress", "egress": "<egress_id>"}
{"type": "direct"}
{"type": "block"}
```

未知 `type`、缺失 `egress`、给 `direct`/`block` 带上 `egress`，或任何额外字段，都会拒收整份
快照。route 只保存 egress ID，凭据只存在于 egress realization，多个 policy/route 复用同一
egress 时不会复制密码。

### `egresses.{egress_id}`

同样是严格 tagged union：

```json
{"type": "upstream", "backend": { "...": "..." }}
{"type": "chain",    "members": [ { "...": "..." } ]}
```

`type = "upstream"` 携带一个具体 backend；`type = "chain"` 携带一组按 `priority` 排序的主备
成员。upstream backend 不能使用 `kind = "chain"`（chain 是独立的 egress 变体，不是一种
backend kind）；chain member 也不能嵌套 chain。

### `backend`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `kind` | string | 是 | `http` / `https` / `socks5` / `socks` / `reverse` / `subnetra`。`https` 按 HTTP CONNECT over TLS 处理；`reverse` 走反向 hop（`addr` 填 `hop_id`）；`subnetra` 经内嵌 overlay 出口（目标须为 overlay IPv4，见 [内嵌 Subnetra 组网底座](./subnetra.md)）。 |
| `addr` | string | 是* | 出口地址，格式 `host:port`；`reverse` 时填 `hop_id`；`subnetra` 时不使用。 |
| `username` | string/null | 否 | 出口认证用户名（`reverse` / `subnetra` 不接受）。 |
| `password` | string/null | 否 | 出口认证密码（`reverse` / `subnetra` 不接受）。 |
| `tls` | boolean | 否 | 是否用 TLS 连接出口（`reverse` / `subnetra` 不接受，二者传输自带加密）。 |
| `skip_cert_verify` | boolean | 否 | 缺省 `false`。仅在 `tls` 为 `true` 时生效：`true` 表示跳过证书链、主机名和有效期校验（自签名证书、纯 IP hop 节点常见场景）。这是**逐个 backend 的显式开关**，不是全局配置，也不会影响入站监听端的 TLS 校验。 |

### `egresses.{egress_id}.members[]`（chain）

一条 chain 表示**同一逻辑出口的按优先级主备候选集合**（例如同一 POP 的主 reverse hop + 备
SOCKS5 后端），**不是** A → B → 目标的串联多跳。运行时故障转移语义（仅隧道建立阶段重试、
超时预算、UDP 仅 reverse 成员、exhausted 后 fail-closed）见
[数据模型 · 出口链与主备故障转移](./data-model.md)。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | 成员的稳定 ID，同一 chain 内唯一；出现在访问日志与指标里。 |
| `priority` | integer | 是 | 同一 chain 内唯一；数字越小优先级越高（越先尝试）。 |
| `backend` | object | 是 | 复用上面的 `backend` 结构与全部校验规则；`backend.kind` 不得为 `chain`（禁止递归）。 |

## 决策语义

节点对每个请求按以下顺序求解，全过程 fail-closed：

1. 认证：用户名必须存在、密码匹配、未过期。任何一项不成立即拒绝，不会降级为直连。
2. 用户 → `policy` → `routing_policies` 中的那一条 policy。
3. requested host 与经过验证的 sniffed host 分别按 `routes` 顺序求各自的第一个匹配 action。
4. 任一候选的 first-match action 为 `block` 都会阻断。
5. requested target 是域名时，sniffed host 的非 block action 不改变路由。
6. requested target 是 IP 时，sniffed host 的非 block action 优先于 requested-IP action。
7. 仍未选中 action 时使用 `default_egress`；没有 default 则直连。

sniff 只影响策略身份，不改写实际 dial target；访问日志的 `effective_policy_host` 记录最终
用于选择 action 的 host。

## 选择器语义

`selectors` 里的每一项可以是：

- `example.com` 或 `domain:example.com`：域名后缀匹配，匹配 `example.com` 和任意子域。
- `full:example.com`：精确域名匹配。
- `keyword:openai`：域名关键字匹配。
- `203.0.113.10`：单 IP。
- `100.117.0.0/16`：CIDR。
- `book:<category>`：引用节点已加载的 addrbook 层级分类。

域名匹配大小写不敏感，并忽略首尾点。

`book:` 规则要求节点已配置 `[addrbook]` 并成功加载工件：**未配置地址簿或分类不存在时，节点
拒收整份快照**，不会把 `book:aws` 当作普通域名放行。快照编译期钉住当前书版本，书热替换等价于
重编译最近一份快照，两者都成功才双双替换。地址簿构建、发布、层级分类、节点接入与热替换语义见
[rove-addrbook 指南](./addrbook-format.md)。

## 严格校验与 fail-closed

### 未知字段整份拒收（设计承诺）

全部 wire 结构（`RawSnapshot`、`RawUser`、`RawRoutingPolicy`、`RawRoute`、`action`、
`egress`、`NodeOverride`）都声明了 `deny_unknown_fields`：**收到任何不认识的字段，节点拒收
整份快照，而不是忽略该字段后按旧语义继续放行。**

这是刻意的安全属性，不是实现细节。它意味着：

- 未来给 policy / route / egress 增加语义字段（例如显式的兜底 action）时，不支持该字段的
  旧节点会明确拒收，而不会因为「忽略未知字段」把一份收紧过的策略执行成宽松版本。
- 任何来自其他形态的文档——包括本协议出现之前的 group 表形态——都会撞上这条规则被整份拒收，
  而不会被半懂半猜地执行成一份宽松策略。
- 代价是拒收后节点保留上一份有效快照，因此**收紧类变更必须配合 schema 或 capability 门控
  发布**：先确认目标节点已支持，再让控制面输出带新字段的快照，否则节点会停留在旧策略上。
- 控制面发布前用 `rove validate-snapshot` 预检，可以在下发之前就发现字段不被接受。

### schema 版本守卫

`schema_version` 必须落在节点支持的 `1..=MAX_SUPPORTED_SCHEMA_VERSION` 区间内（当前二者都是
`1`）。超出范围的快照被整份拒收，节点保留此前有效的内存快照和 cache。未来若要 bump schema，
发布顺序必须是：先部署支持新 schema 的节点二进制并通过 MQTT 节点状态的
`snapshot_schema_version` 字段确认全网能力，再让控制面输出新 schema。

### 编译期校验

以下任一违反都会让**整份快照**编译失败，节点继续使用上一份有效快照：

- 用户的 `policy` 为空，或引用了不存在的 policy。
- route 的 `selectors` 为空。
- `action` 或 `default_egress` 引用了不存在的 egress。
- egress ID / chain member ID 为空。
- chain 没有成员，或同一 chain 内 member `id` / `priority` 重复。
- chain member 的 backend 是另一条 chain。
- `reverse` / `subnetra` backend 携带了 `username` / `password` / `tls` / `skip_cert_verify`。
- `book:` 选择器所需的 addrbook 缺失，或分类不存在。
- 节点 override 引入了 base `egresses` 里不存在的 egress ID。
- 触碰任一规模上限。

### 规模上限

| 上限 | 值 |
| --- | --- |
| `users` 条目数 | 100000 |
| `routing_policies` 条目数 | 10000 |
| `egresses` 条目数 | 10000 |
| 全快照 route selector 总数 | 200000 |
| `node_overrides` 条目数 | 10000 |
| 单条 chain 的成员数 | 16 |
| 单个 `book:` 选择器展开后的字节数 | 64 MiB |

## 节点级 Override（`node_overrides`）

### 背景

控制面通常只维护一份统一的身份/策略数据。但多节点部署里，同一条 policy 在不同边缘节点上落地
的出口往往不同——例如「经东京落地」策略，在东京节点上应该走本地 hop（`127.0.0.1:11080`），
在大阪节点上应该走大阪本地 hop（`127.0.0.1:12080`），而路由规则完全一样，只有出口 realization
不同。

`node_overrides` 就是为了解决这个问题：同步接口本身不区分节点（没有 `{node_id}` 路径参数），
控制面仍然只生成、只分发**完全同一份**快照给所有节点。节点拿到这份完全一样的 body 之后，在
编译快照时用自己**本地配置**的 `node_id`（节点 TOML 里的 `node_id` 字段，从未发往控制面）去
响应体自带的 `node_overrides` 里找属于自己的那一份，完全在本地做合并。

### 结构

```json
{
  "node_overrides": {
    "{node_id}": {
      "egresses": {
        "{egress_id}": {"type": "upstream", "backend": {"...": "..."}}
      }
    }
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `node_overrides.{node_id}` | object | 否 | 该 `node_id` 对应的 override 集合。key 必须和节点**本地配置文件**里的 `node_id` 完全一致；同步接口本身不携带 `node_id`，它纯粹是节点本地用来自选的 key。 |
| `node_overrides.{node_id}.egresses` | object | 否 | 该节点要替换的 egress，key 是 `egress_id`，value 是完整的 egress 定义（结构和顶层 `egresses.{egress_id}` 完全一样）。 |

### 合并语义

- override **只能整项替换顶层已经存在的 egress**。引入一个 base 表里没有的 egress ID 会让节点
  拒收整份快照——这条规则保证 routing policy 始终是 node-independent 的：所有节点看到同一张
  route 表，只有出口 realization 因节点而异。
- 替换是整项替换，不是逐字段合并。override 里要把该 egress 的完整定义写全。
- override 不能修改 `users`、`routing_policies` 或 `version`。
- 合并发生在 route → egress 引用校验和 backend 编译**之前**，所以 override 出来的 egress 同样
  要满足所有校验规则。一个 override 把 chain 的 `members` 换成空数组会导致该节点**拒收整份
  快照**（「override 后消失」按非法快照处理），而不是静默保留旧成员。
- 其他节点的 `node_overrides` 条目会被忽略；一个节点只应用 key 精确等于自己 `node_id` 的那一条。
- 不填 `node_overrides`，或者当前节点的 `node_id` 不在里面，行为和没有这个字段完全一样——即所有
  节点用同一份 `egresses`。

## 公共 validator

使用节点二进制做发布前预检，不启动 listener、同步器或守护进程：

```bash
rove validate-snapshot --node-id edge-tokyo-01 snapshot.json
cat snapshot.json | rove validate-snapshot --node-id edge-tokyo-01 -
rove validate-snapshot --node-id edge-tokyo-01 --addrbook book.rab snapshot.json
```

成功时 exit 0，并在 stdout 输出单行 JSON：

```json
{"ok":true,"schema_version":1,"version":42,"users":1,"routing_policies":1,"egresses":2}
```

失败时 exit 非零，输出 `{"ok":false,"stage":"...","error":"..."}`。`stage` 为
`arguments`、`read`、`addrbook`、`decode` 或 `compile`。输出不包含 snapshot 原文或凭据；
输入默认从 stdin 读取，最大 8 MiB。

`--node-id` 会真正参与编译：带 `node_overrides` 的快照必须对**每一个**在线 node_id 分别
validate，才能确认它在全网都能编译通过。

## 控制面实现建议

- 生成前校验 user → policy、route/default → egress 的所有引用，并保持 route 数组顺序稳定：
  数组顺序就是策略语义，重排等于改策略。
- 把 block route 放在最前面。first-match-wins 意味着一条更靠前的 `egress` route 会让后面的
  `block` route 永远不生效。
- 为用户启用 TUIC 时，输出完整的 `frontends.tuic.uuid` 和 `frontends.tuic.password`；校验
  UUID 格式，并保证同一协议内 UUID 全局唯一。
- 不要把 TUIC 监听地址、证书路径、私钥路径、ALPN 或 MTU 写入快照；这些字段属于各节点本地
  `[[tuic_listeners]]` 配置。
- 对 `version` 使用数据库变更序列、Unix 秒加递增序号，或其他严格单调来源。
- 不要把空字符串作为 policy ID、egress ID、`kind`、`addr`、用户名或密码。
- 需要按节点区分出口时，优先用 `node_overrides`，而不是让控制面为每个节点渲染一份不同的
  响应体：`users` / `routing_policies` 继续保持全节点统一，只在 `node_overrides.{node_id}.egresses`
  里给需要特殊处理的 egress 补一份该节点专属 realization。
- 密码字段是敏感信息，传输必须使用 HTTPS 或受控内网链路；本地 cache 文件应按部署环境限制权限。
- 控制面发布前使用 `rove validate-snapshot` 做真实编译预校验；节点拒收坏快照是最后一道
  fail-closed 保护，不应作为常规校验流程。
