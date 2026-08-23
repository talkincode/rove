# Rove Snapshot Protocol

本文档定义控制面向 Rove 节点下发的用户与策略快照协议。节点兼容 schema v1-v3 和旧版
`userdata.json`，但新控制面应输出 schema v4：用户显式引用可复用的 routing policy，
policy 用有序 route 选择命名 egress、直连或阻断。

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
200 application/json  返回完整 RawSnapshot（所有节点收到的 body 完全一样）
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
- 同步失败、响应过大、JSON 无法解析、快照 shape 无效、用户引用未知 group 或 upstream 配置非法时，节点继续使用当前内存快照，且不会覆盖已有本地缓存。

## Schema v1-v3 JSON（兼容）

```json
{
  "version": 12,
  "users": {
    "alice": {
      "password": "secret",
      "expire": "2026-12-31",
      "up_rate": 1048576,
      "down_rate": 1048576,
      "max_connections": 2,
      "group": "openai-via-tokyo",
      "frontends": {
        "tuic": {
          "uuid": "550e8400-e29b-41d4-a716-446655440000",
          "password": "tuic-front-end-secret"
        }
      }
    }
  },
  "groups": {
    "openai-via-tokyo": {
      "upstream": {
        "kind": "socks5",
        "addr": "10.0.0.9:1080",
        "username": "upstream-user",
        "password": "upstream-password",
        "tls": false
      },
      "default_upstream": {
        "kind": "socks5",
        "addr": "10.0.0.10:1080",
        "tls": false
      },
      "proxy": [
        "openai.com",
        "chatgpt.com",
        "github.com",
        "100.117.0.0/16"
      ],
      "block": [
        "full:blocked.example.com"
      ]
    },
    "direct": {
      "proxy": [],
      "block": []
    }
  },
  "node_overrides": {
    "edge-tokyo-01": {
      "groups": {
        "openai-via-tokyo": {
          "upstream": {
            "kind": "socks5",
            "addr": "127.0.0.1:11080",
            "tls": false
          },
          "default_upstream": {
            "kind": "socks5",
            "addr": "127.0.0.1:11081",
            "tls": false
          },
          "proxy": [
            "openai.com",
            "chatgpt.com",
            "github.com",
            "100.117.0.0/16"
          ],
          "block": [
            "full:blocked.example.com"
          ]
        }
      }
    },
    "edge-osaka-01": {
      "groups": {
        "openai-via-tokyo": {
          "upstream": {
            "kind": "socks5",
            "addr": "127.0.0.1:12080",
            "tls": false
          },
          "default_upstream": {
            "kind": "socks5",
            "addr": "127.0.0.1:12081",
            "tls": false
          },
          "proxy": [
            "openai.com",
            "chatgpt.com",
            "github.com",
            "100.117.0.0/16"
          ],
          "block": [
            "full:blocked.example.com"
          ]
        }
      }
    }
  }
}
```

上面的例子里 `users`/`groups` 对所有节点完全一样（控制面只需要生成和分发一份 body），
但 `edge-tokyo-01` 和 `edge-osaka-01` 各自把 `openai-via-tokyo` 组的 `upstream`
和 `default_upstream` 换成了自己本地的 hop 地址；其余字段（`proxy`/`block`）照抄一遍是因为 override
是整组替换，见下方「节点级 Override」一节。

## 字段定义

### 顶层

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `schema_version` | integer | 否 | 线协议结构/语义版本，缺省为 `1`。当前节点支持 `1..=4`；高于支持范围的快照会被整份拒收。`2` 增加顶层 `chains` 与 `kind: "chain"`；`3` 增加 `book:<category>`；`4` 改为显式 routing policy + named egress。与 `version` 相互独立。**新控制面应输出 `4`。** |
| `version` | integer | 是 | 快照内容修订号，必须单调递增；继续用于 `?since=` 与 `304`。 |
| `users` | object | 否 | 用户表，key 是用户名。缺省为空对象。v4 用户用 `policy`；v1–v3 用 `group`。 |
| `routing_policies` | object | v4 | schema v4 的可复用 routing policy 表，key 是 policy ID。详见下方「Schema v4」。 |
| `egresses` | object | v4 | schema v4 的 named egress 表，key 是 egress ID。详见下方「Schema v4」。 |
| `groups` | object | v1–v3 | 兼容策略组表，key 是组 ID。缺省为空对象；**v4 禁止出现**。 |
| `chains` | object | v2–v3 | 兼容命名出口链表，key 是 chain ID。缺省为空对象；**v4 改用 `egresses` 的 `type: "chain"`**。详见下方「出口链（chains）」。 |
| `node_overrides` | object | 否 | 节点级覆盖表，key 是 `node_id`。v4 只允许 `egresses` 整项替换；v1–v3 允许 `groups`/`chains`。详见下方「节点级 Override」。 |

## Schema v4：Routing Policy 与 Named Egress

v4 不再把策略承载在组织含义模糊的 `groups` 中。一个用户只属于一个 routing policy；多个
TeamsEdge Workplane 可以把用户编译到同一个 policy。客户端接入点和 PAC 不属于 Rove snapshot
routing，v4 不定义这些字段。

```json
{
  "schema_version": 4,
  "version": 42,
  "users": {
    "alice": {"password": "user-secret", "policy": "shared-policy"}
  },
  "routing_policies": {
    "shared-policy": {
      "routes": [
        {
          "selectors": ["domain:egress-a.example", "198.51.100.0/24"],
          "action": {"type": "egress", "egress": "egress-a"}
        },
        {
          "selectors": ["full:direct.example"],
          "action": {"type": "direct"}
        },
        {
          "selectors": ["book:security/blocked"],
          "action": {"type": "block"}
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

### v4 字段与严格校验

- `users.{username}.policy` 必填且非空，必须引用 `routing_policies` 中的一项。v4 用户不能携带
  `group`。
- `routing_policies.{id}.routes` 是有序数组。每条 route 的 `selectors` 至少一项；一项命中即
  视为 route 命中。route 按数组顺序 first-match-wins；不同 route 的 selector 可以重叠，顺序
  是协议语义。
- `action` 是严格 tagged union，且只能是
  `{"type":"egress","egress":"<id>"}`、`{"type":"direct"}` 或
  `{"type":"block"}`。未知 type、缺失字段、跨 variant 字段或额外字段均拒绝整份快照。
- `default_egress` 可选；存在时必须引用 `egresses`。缺省表示未命中 route 时直连。
- named egress 也是严格 tagged union：`type=upstream` 携带一个具体 `backend`；
  `type=chain` 携带按 `priority` 排序的既有 chain members。upstream backend 不能再使用
  `kind=chain`，chain member 也不能嵌套 chain。
- route 只保存 egress ID，认证信息只存在于 named egress realization，多个 policy/route 复用
  时不会复制密码。
- `node_overrides.{node_id}.egresses` 只能整项替换顶层已经存在的 egress，不能新增 node-only
  egress，也不能覆盖 policy/user。这样 policy 保持 node-independent。
- 缺失 policy/egress 引用、空 ID、非法 backend、空 chain、重复 member ID/priority、
  selector 超限、缺失 addrbook 或未知 `book:` 分类，都会拒绝整份快照。

### v4 决策与 sniff 安全语义

1. requested host 与经过验证的 sniffed host 分别按 route 顺序求各自的第一个匹配 action。
2. 任一候选的 first-match action 为 `block` 都会阻断。
3. requested target 是域名时，sniffed host 的非 block action 不改变路由。
4. requested target 是 IP 时，sniffed host 的非 block action 优先于 requested-IP action。
5. 仍未选中 action 时使用 `default_egress`；没有 default 则直连。

sniff 只影响策略身份，不改写实际 dial target；`effective_policy_host` 记录选择 action 的 host。
chain 的建立期故障转移、总超时、TCP 固定成员、UDP 仅 reverse member、exhausted 后
fail-closed 等语义保持不变。

### Schema 隔离与旧节点行为

- schema v4 不能出现顶层 `groups`/`chains`、`user.group` 或
  `node_overrides.*.groups/chains`，即使值为空也拒绝。
- schema v1-v3 不能出现 `routing_policies`、`egresses`、`user.policy` 或
  `node_overrides.*.egresses`。节点不会在两种模型之间静默转换。
- v4 节点继续解码、编译并执行有效 v1-v3 与旧 `userdata.json`。
- 最大 schema 为 3 的节点拒绝 `schema_version: 4` 并保留此前有效的内存快照和 cache。
  发布顺序必须是先部署 capability 且生产者继续输出 <=3；确认节点能力后再允许生产者输出 4。

#### v4 结构对未知字段 fail closed（设计承诺）

schema v4 的全部 wire 结构（`RawSnapshotV4`、`RawUserV4`、`RawRoutingPolicy`、`RawRoute`、
`NodeOverrideV4` 及其嵌套 action / egress 结构）都声明了 `deny_unknown_fields`：
**收到任何不认识的字段，节点拒收整份快照，而不是忽略该字段后按旧语义继续放行。**

这是刻意的安全属性，不是实现细节。它意味着：

- 未来给 policy / route / egress 增加语义字段（例如显式的兜底 action）时，不支持该字段的
  旧节点会明确拒收，而不会因为「忽略未知字段」把一份收紧过的策略执行成宽松版本。
- 代价是拒收后节点保留上一份有效快照，因此**收紧类变更必须配合 schema 或 capability 门控
  发布**：先确认目标节点已支持，再让控制面输出带新字段的快照，否则节点会停留在旧策略上。
- 控制面发布前用 `rove validate-snapshot` 预检，可以在下发之前就发现字段不被接受。

注意这条只适用于 v4 结构族。v1-v3 的旧结构不带 `deny_unknown_fields`，旧二进制会忽略未知
字段——那条升级路径的 fail-closed 哨兵是不认识的取值（如 `kind: "chain"`），见下文。

### 公共 validator

使用节点二进制做发布前预检，不启动 listener、同步器或守护进程：

```bash
rove validate-snapshot --node-id edge-tokyo-01 snapshot.json
cat snapshot.json | rove validate-snapshot --node-id edge-tokyo-01 -
rove validate-snapshot --node-id edge-tokyo-01 --addrbook book.rab snapshot.json
```

成功时 exit 0，并在 stdout 输出单行 JSON：

```json
{"ok":true,"schema_version":4,"version":42,"users":1,"routing_policies":1,"egresses":2}
```

失败时 exit 非零，输出 `{"ok":false,"stage":"...","error":"..."}`。`stage` 为
`arguments`、`read`、`addrbook`、`decode` 或 `compile`。输出不包含 snapshot 原文或凭据；
输入默认从 stdin 读取，最大 8 MiB。

### `users.{username}`（schema v1-v3）

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `password` | string | 是 | 代理认证密码。 |
| `expire` | string/null | 否 | `YYYY-MM-DD`；空或缺省表示不过期。超过该日期后认证失败。 |
| `up_rate` | integer | 否 | 上传限速，单位 bytes/sec；`0` 或缺省表示不限速。 |
| `down_rate` | integer | 否 | 下载限速，单位 bytes/sec；`0` 或缺省表示不限速。 |
| `max_connections` | integer | 否 | 单节点内该用户最大活跃隧道数；`0` 或缺省表示不限制。 |
| `group` | string | 是 | 用户所属策略组，必须存在于 `groups`。 |
| `frontends` | object | 否 | 该用户的前端协议凭据表，key 是协议名。缺省为空对象；当前支持 `frontends.tuic`。 |

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
- TUIC 认证成功后，`expire`、`up_rate`、`down_rate`、`max_connections` 以及 v4 的
  `policy`（或兼容 v1–v3 的 `group`）继续沿用该用户的通用字段。

### `groups.{group_id}`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `upstream` | object/null | 否 | 特定规则二级代理。`proxy` 命中时优先走它；缺省或 null 表示命中特定规则后没有单独出口。 |
| `default_upstream` | object/null | 否 | 默认二级代理。目标未命中 `block`/`proxy`，或命中 `proxy` 但没有 `upstream` 时走它；缺省或 null 表示默认直连。 |
| `proxy` | string[] | 否 | 命中后走 `upstream` 的目标规则；如果 `upstream` 为空但 `default_upstream` 存在，则仍走默认二级代理。缺省为空。 |
| `block` | string[] | 否 | 命中后拒绝的目标规则。缺省为空。 |

决策顺序：

1. `block` 命中则拒绝。
2. `proxy` 命中且有 `upstream` 则走特定二级代理。
3. 有 `default_upstream` 则走默认二级代理。
4. 其他目标直连。

规则字符串支持：IP / CIDR、默认域名后缀、`domain:` 后缀、`full:` 精确域名、
`keyword:` 子串，以及 `book:<category>` 地址簿分类。含任何
`book:` 规则的快照**必须**声明 `schema_version >= 3`（推荐直接发 v4，把 `book:` 写在
route `selectors`）；节点会拒绝 v1/v2 的 `book:` 快照，确保滚动升级中的旧节点因不支持
新 scheme 而保留旧快照，而不是把它误读成普通域名。节点未配置 `[addrbook]` 或分类不存在时
同样整份拒收。
地址簿构建、发布、层级分类、节点接入与热替换语义见
[rove-addrbook 指南](./addrbook-format.md)。

### `upstream`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `kind` | string | 是 | `http` / `https` / `socks5` / `socks` / `reverse` / `subnetra` / `chain`。`https` 会按 HTTP CONNECT over TLS 处理；`reverse` 走反向 hop（`addr` 填 `hop_id`）；`subnetra` 经内嵌 overlay 出口（目标须为 overlay IPv4，见 [内嵌 Subnetra 组网底座](./subnetra.md)）；`chain` 引用顶层 `chains` 里的一条出口链（`addr` 填 chain ID，schema v2）。 |
| `addr` | string | 是* | 二级代理地址，格式 `host:port`；`reverse` 时填 `hop_id`；`chain` 时填 chain ID；`subnetra` 时不使用。 |
| `username` | string/null | 否 | 二级代理认证用户名（`reverse` / `subnetra` / `chain` 不接受）。 |
| `password` | string/null | 否 | 二级代理认证密码（`reverse` / `subnetra` / `chain` 不接受）。 |
| `tls` | boolean | 否 | 是否用 TLS 连接二级代理（`reverse` / `subnetra` / `chain` 不接受，前两者传输自带加密，chain 的连接参数由成员各自携带）。 |
| `skip_cert_verify` | boolean | 否 | 缺省 `false`。仅在 `tls` 为 `true` 时生效：`true` 表示跳过证书链、主机名和有效期校验（自签名证书、纯 IP hop 节点常见场景）。这是**逐个 upstream 的显式开关**，不是全局配置，也不会影响入站监听端的 TLS 校验。 |

## 出口链（`chains`，schema v2）

一条 chain 表示**同一逻辑出口的按优先级主备候选集合**（例如同一 POP 的主 reverse hop + 备
SOCKS5 后端），**不是** A → B → 目标的串联多跳代理。策略组通过既有的 `upstream` /
`default_upstream` 槽位以 `{ "kind": "chain", "addr": "<chain-id>" }` 引用它；运行时故障
转移语义（仅隧道建立阶段重试、超时预算、UDP 仅 reverse 成员、fail-closed）见
[数据模型 · 出口链与主备故障转移](./data-model.md#出口链chains与主备故障转移)。

```json
{
  "schema_version": 2,
  "version": 13,
  "chains": {
    "jp-pop": {
      "members": [
        { "id": "jp-reverse-1", "priority": 1, "backend": { "kind": "reverse", "addr": "h1" } },
        {
          "id": "jp-socks-2",
          "priority": 2,
          "backend": { "kind": "socks5", "addr": "10.2.2.1:1080", "tls": false }
        }
      ]
    }
  },
  "groups": {
    "rule-a": {
      "upstream": { "kind": "chain", "addr": "jp-pop" },
      "proxy": ["example.com"],
      "block": []
    }
  }
}
```

### `chains.{chain_id}.members[]`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | 成员的稳定 ID，同一 chain 内唯一；出现在访问日志与指标里。 |
| `priority` | integer | 是 | 同一 chain 内唯一；数字越小优先级越高（越先尝试）。 |
| `backend` | object | 是 | 复用上面的 `upstream` 结构与全部校验规则（`reverse.addr` 是 `hop_id`；http/socks5 的 `addr` 是 `host:port`）；`backend.kind` 不得再为 `chain`（禁止递归引用）。 |

校验规则（任一违反都会让**整份快照**编译失败，节点继续使用上一份有效快照）：

- 使用 `chains` 或 `kind: "chain"` 引用必须声明 `schema_version >= 2`；
- chain ID、member ID 非空；同一 chain 内 member `id` 与 `priority` 唯一；
- chain 必须至少包含一个成员；每条 chain 成员数上限 16，chains 总数上限 1000；
- group 引用的 chain 必须存在（顶层或本节点 override 合并后可见）；
- `kind: "chain"` 的引用不得设置 `username`/`password`/`tls`/`skip_cert_verify`。

### 兼容性与两阶段发布

`schema_version` 本身无法保护旧节点（旧二进制忽略未知字段）；本次升级的 fail-closed
哨兵是 `kind: "chain"`——旧节点在 `compile_upstream` 遇到不支持的 kind 时会**拒收整份
快照并继续使用上一份有效快照**，而不会静默把该组退化为直连。因此发布顺序必须是：

1. 先把所有节点升级到支持 schema v2 / chain 的版本（同时保持兼容 v1）；控制面仍下发现有单
   upstream 快照。
2. 通过 MQTT 节点状态的 `snapshot_schema_version` 字段确认目标节点均已应用 v2 能力后，控制面
   再下发 `schema_version: 2` + `chains` + `kind: "chain"` 引用，同时递增 `version`。
3. 若仍有遗漏的旧节点，它们会因不认识 `kind: "chain"` 而拒收新快照并保留旧快照（同步失败会出现
   在日志与 MQTT 节点状态里），不会 fail-open。

## 节点级 Override（`node_overrides`）

> 本节以下 `groups`/`chains` override 仅适用于 schema v1-v3。schema v4 只允许前文定义的
> `node_overrides.{node_id}.egresses` 整项替换。

### 背景

控制面通常只维护一份统一的用户/策略数据（`users` + `groups`）。但多节点部署里，同一个
`group` 在不同边缘节点上落地的二级代理往往不同——例如“经东京落地”策略组，在东京节点上应该走
本地 hop（`127.0.0.1:11080`），在大阪节点上应该走大阪本地 hop（`127.0.0.1:12080`），业务规则
（`proxy`/`block`）完全一样，只有 `upstream` 不同。

`node_overrides` 就是为了解决这个问题：同步接口本身不区分节点（没有 `{node_id}` 路径参数），控制面
仍然只生成、只分发**完全同一份** `RawSnapshot` 给所有节点（不需要知道请求者是谁，也不需要按
节点计算不同的响应体）。节点拿到这份完全一样的 body 之后，在编译快照时用自己**本地配置**的
`node_id`（节点 TOML 里的 `node_id` 字段，从未发往控制面）去响应体自带的 `node_overrides` 里找属于
自己的那一份，完全在本地做合并。控制面自始至终不需要知道哪个节点在请求、也不需要按 `node_id`
路由请求。

### 结构

```json
{
  "node_overrides": {
    "{node_id}": {
      "groups": {
        "{group_id}": { "upstream": { "...": "..." }, "default_upstream": { "...": "..." }, "proxy": [], "block": [] }
      },
      "chains": {
        "{chain_id}": { "members": [ { "id": "...", "priority": 1, "backend": { "...": "..." } } ] }
      }
    }
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `node_overrides.{node_id}` | object | 否 | 该 `node_id` 对应的 override 集合。key 必须和节点**本地配置文件**里的 `node_id` 完全一致；同步接口本身不携带 `node_id`，它纯粹是节点本地用来自选的 key。 |
| `node_overrides.{node_id}.groups` | object | 否 | 该节点要覆盖或新增的 group，key 是 `group_id`，value 是完整的 `RawGroup`（结构和顶层 `groups.{group_id}` 完全一样）。 |
| `node_overrides.{node_id}.chains` | object | 否 | 该节点要覆盖或新增的 chain，key 是 `chain_id`，value 是完整的 `RawChain`（结构和顶层 `chains.{chain_id}` 完全一样），schema v2。 |

### 合并语义

- 节点编译快照时，先取出 `node_overrides[node_id]`（如果存在），按 **chains → groups** 的顺序合入
  顶层：先把 override 的 `chains` 逐条合入顶层 `chains`（**同 `chain_id` 整条替换**，members 不做
  逐成员合并），再把 `groups` 逐个合入顶层 `groups`：**同 `group_id` 整组替换**，不是逐字段合并。
  也就是说 override 里只写了 `upstream`，
  没写 `default_upstream`/`proxy`/`block`，编译后该节点上这个组的这些字段会变成空（不会保留 base 组的值）。
  如果只想换 `upstream` 或 `default_upstream`，override 里要把该 group 的其他字段也完整抄一遍（见上面的 JSON 示例）。
- 如果 `group_id` 在顶层 `groups` 里不存在，override 会新增一个**只对该节点生效**的 group（可以用来
  给个别节点单独开一条只在它自己那里存在的策略组）。`chain_id` 同理：override 可以新增只在该节点
  存在的 chain，group 可以引用顶层 chain 或本节点 override 后得到的 chain。
- 合并发生在 `users` → `group` 引用校验、chain 引用校验和 upstream 编译**之前**，所以 override 的
  group/chain 同样要满足所有校验规则（`group_id`/`chain_id` 不能是空字符串；chain 成员非空且 ID/priority
  唯一等）。一个 override 把 chain 的 `members` 换成空数组会导致该节点**拒收整份快照**（“override 后
  消失”按非法快照处理），而不是静默保留旧成员。
- 其他节点的 `node_overrides` 条目会被忽略；一个节点只应用 key 精确等于自己 `node_id` 的那一条。
- `node_overrides` 里的条目数量有上限（当前实现为 10000），超过会被节点直接拒收整份快照（fail
  closed，不会应用部分更新）。
- 不填 `node_overrides`，或者当前节点的 `node_id` 不在里面，行为和没有这个字段完全一样——即所有
  节点用同一份 `groups`。所以给已有部署接入这个字段是完全向后兼容的。

## 规则语义

`proxy` 和 `block` 支持以下字符串：

- `example.com` 或 `domain:example.com`：域名后缀匹配，匹配 `example.com` 和任意子域。
- `full:example.com`：精确域名匹配。
- `keyword:openai`：域名关键字匹配。
- `203.0.113.10`：单 IP。
- `100.117.0.0/16`：CIDR。

域名匹配大小写不敏感，并忽略首尾点。

## 旧 userdata 兼容

节点兼容旧版 `userdata.json` 顶层结构：

```json
{
  "timestamp": 1782830958,
  "user_list": [],
  "address_list": [],
  "routings": []
}
```

兼容转换规则（与 `src/model.rs` 的 `legacy_userdata_to_snapshot` 及其辅助函数一致）：

### 顶层

| 旧 `userdata.json` | 新 `RawSnapshot` | 说明 |
| --- | --- | --- |
| `timestamp`（u64） | `version` | `version = timestamp.max(1)`——0 或缺失时用 `1`，保证非零。 |
| `user_list[]`（数组） | `users{}`（以 username 为 key 的 map） | 数组转 map，`username` 字段被提出来做 key。 |
| `address_list[]` | **不出现在新模型里** | 只是转换过程中的宏展开表（`tag -> [address,...]`），转完就丢弃。 |
| `routings[]` | `groups{}` | 每条 routing 按数组下标（`idx`，从 0 开始）转成一个 group。 |

### 用户字段（`user_list[i]` → `users.{username}`）

| 旧字段 | 新字段 | 说明 |
| --- | --- | --- |
| `username` | 作为 map 的 key | — |
| `password` | `password` | 原样 |
| `expire` | `expire` | 原样，`YYYY-MM-DD` 或 null |
| `up_rate` / `down_rate` | `up_rate` / `down_rate` | 宽松解析：数字或数字字符串都行，解析失败按 `0` |
| `code` | **不进入新 `RawUser`** | 只在下面“归组”逻辑里用一次，之后丢弃 |
| （旧协议没有） | `max_connections` | 转换后固定填 `0`（不限制），因为旧协议压根没这个概念 |
| （旧协议没有） | `frontends` | 转换后为空对象；旧 `userdata.json` 无法表达 `frontends.tuic`，因此不能仅靠旧格式为用户启用 TUIC。 |
| （旧协议没有，反向推导） | `group`（必填） | 见下 |

### 用户怎么归组（最反直觉的一步）

旧协议里没有 `user.group` 这种字段，而是反过来——每条 `routings[i]` 自带 `users: []` 和 `codes: []` 两个列表。转换逻辑按 `routings` 数组顺序（`idx` 从 0 开始）依次判断：

1. 这个用户的 `username` 在不在这条 routing 的 `users[]` 里；
2. 不在的话，再看这个用户的 `code` 在不在这条 routing 的 `codes[]` 里；
3. **第一条命中就是这个用户的 group**（first-match，不会继续往后找）；
4. 全部没命中 → 扔进内置的 `__legacy_direct` group（无 upstream，`proxy`/`block` 都空，等于直连无策略）。

这一步是有损的：如果旧数据依赖过“同一用户被多条 routing 交叉引用”之类的复杂语义，新模型只能拿 first-match 保证确定性，行为不保证和旧版完全一致。

### Group ID 怎么生成

```
sanitized_tag = server_tag 里只保留 [a-zA-Z0-9_-]，其余字符（含中文、空格）替换成 '-'，转小写，去掉首尾多余的 '-'
group_id = sanitized_tag 非空 ? "legacy-route-{idx}-{sanitized_tag}" : "legacy-route-{idx}"
```

`idx` 是这条 routing 在原数组里的下标，所以同一份旧数据每次转换出来的 group id 是稳定可复现的。

### Upstream 字段（routing 的一堆散字段 → `groups.{id}.upstream` / `default_upstream`）

| 旧字段 | 新字段 | 兆底/派生规则 |
| --- | --- | --- |
| `server_addr` | `upstream.addr` | 存在时作为 `proxy` 规则命中后的特定出口；缺失则 `upstream=null` |
| `connector_type` / `connector.type` | `upstream.kind` | `server_addr` 存在时使用；都没有则默认 `"http"` |
| `connector_type=="https"` 或 `dialer_type=="tls"` / `dialer.type=="tls"` | `upstream.tls` | 任一命中即 `true` |
| `use_auth=="enabled"/"true"`；缺失则看 `auth_user` 或 `connector.auth.username` 是否非空 | 是否搬认证 | 只有判定“启用认证”才会把认证字段搬进 `upstream.username`/`password` |
| `default_hop_node.addr` | `default_upstream.addr` | 存在时作为未命中特定规则时的默认出口；缺失则默认直连 |
| `default_hop_node.connector.type` | `default_upstream.kind` | 缺失则默认 `"http"` |
| `default_hop_node.dialer.type=="tls"` | `default_upstream.tls` | 命中即 `true` |
| `default_hop_node.connector.auth.username/password` | `default_upstream.username/password` | trim 后非空才搬入 |
| （旧协议没有这个概念） | `upstream.skip_cert_verify` / `default_upstream.skip_cert_verify` | 转换后固定填 `false` |

### 规则字段（`routings[i].rules[]` → `groups.{id}.proxy` / `.block`）

- `action=="proxy"` → 追加进 `proxy[]`；`action=="block"/"deny"` → 追加进 `block[]`；其他 action 值直接忽略。
- `tag` 展开：去 `address_list[]` 里找同名 `tag`，命中则展开成该 tag 下所有 `address`（一个 tag 允许对应多条地址）；找不到就把 `tag` 原样当一条规则字符串塞进去。展开完对 `proxy`/`block` 各自去重。
- `address_list[].type` 字段完全被忽略，从未使用。

限制：

- 旧格式只作为迁移兼容层。控制面应尽快输出新版 `RawSnapshot`。
- 如果旧数据依赖“同一用户跨多条 routing 叠加多组规则/多组默认出口”的复杂语义，当前新版模型无法无损表达；兼容转换采用旧 routing 顺序 first-match，避免不确定行为。

## 控制面实现建议

- 新控制面直接生成 schema v4，不要让节点长期依赖旧格式转换；仍输出 v1-v3 时，生成前校验
  所有用户的 `group` 都存在。
- v4 生成前校验 user → policy、route/default → egress 的所有引用，并保持 route 数组顺序稳定。
- 为用户启用 TUIC 时，输出完整的 `frontends.tuic.uuid` 和
  `frontends.tuic.password`；校验 UUID 格式，并保证同一协议内 UUID 全局唯一。
- 不要把 TUIC 监听地址、证书路径、私钥路径、ALPN 或 MTU 写入快照；这些字段属于各节点本地
  `[[tuic_listeners]]` 配置。
- 对 `version` 使用数据库变更序列、Unix 秒加递增序号，或其他严格单调来源。
- 不要把空字符串作为 `group`、`kind`、`addr`、用户名或密码。
- 密码字段仍是敏感信息，传输必须使用 HTTPS 或受控内网链路；本地 cache 文件应按部署环境限制权限。
- schema v1-v3 需要按节点区分 upstream/policy 时，优先用 `node_overrides`，
  而不是让控制面为每个节点渲染一份不同的响应体：`users`/`groups` 继续保持全节点统一，只在
  `node_overrides.{node_id}.groups` 里给需要特殊处理的 group 补一份该节点专属版本。
- `node_overrides` 的 group 是整组替换，生成 override 条目时要把该 group 的 `default_upstream`、`proxy`/`block` 也一起
  写全，不要只写变化的 `upstream` 字段，否则该节点上这个组的默认出口或规则会被清空。
- schema v4 的 override 只替换同名 egress realization，不复制 policy，不新增 node-only egress。
- 控制面发布前使用 `rove validate-snapshot` 做真实编译预校验；节点拒收坏快照是最后一道
  fail-closed 保护，不应作为常规校验流程。
