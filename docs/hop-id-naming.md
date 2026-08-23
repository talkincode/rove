# reverse-hop-id 命名规范

`hop_id` 是 edge 识别出口的**稳定主键**。它出现在：

- hop 启动参数 `--reverse-hop-id`
- 控制面快照 named egress：`egresses.*.backend.addr`（`kind = "reverse"`）
- 访问日志决策名 `reverse:<hop_id>`
- 指标 / 排障维度

命名一旦上线并写入快照，**不要随意改**；改名等于换了一个新出口。

---

## 强制格式

```text
rove-hop-<region>[-<site>][-<seq>]
```

| 段 | 规则 | 示例 |
|---|---|---|
| 前缀 | **必须** `rove-hop-` | `rove-hop-` |
| region | 小写字母/数字，建议 ISO 国家或城市短码 | `jp` `sg` `us` `cn` `hk` |
| site | 可选，机房/网点/设备角色 | `osaka` `office` `ax2` |
| seq | 可选，同站多实例序号，从 `1` 起 | `1` `2` |

字符集（整串）：

- 仅 **`a-z` `0-9` `-`**
- 全小写
- 不以 `-` 开头/结尾，无连续 `--`
- 建议长度 **≤ 32**（日志友好；技术上限以实现为准，勿炫技）

---

## 推荐示例

| hop_id | 含义 |
|---|---|
| `rove-hop-jp` | 日本统一出口（单点） |
| `rove-hop-jp-osaka-1` | 大阪 1 号 hop |
| `rove-hop-sg-equinix-2` | 新加坡 Equinix 2 号 |
| `rove-hop-cn-office-ax2` | 国内办公室 ax² 容器 hop |
| `rove-hop-us-west-1` | 美西 1 号 |

---

## 反例（不要用）

| 错误 | 原因 |
|---|---|
| `hop-s604` | 缺统一前缀，难检索 |
| `Rove-HOP-JP` | 大写；与日志/配置易不一致 |
| `rove_hop_jp` | 下划线禁止 |
| `rove-hop-日本` | 非 ASCII |
| `jp` | 无前缀，易与其它系统 ID 撞车 |
| `rove-hop-jp.office` | 点号禁止 |
| 每次重启换随机串 | 快照无法稳定指向 |

---

## 与快照的对应关系

edge 快照（当前 schema 概念示例）：

```json
{
  "schema_version": 1,
  "version": 42,
  "users": { "alice": { "password": "example", "policy": "jp-policy" } },
  "routing_policies": {
    "jp-policy": {
      "routes": [
        {
          "selectors": ["example.jp"],
          "action": { "type": "egress", "egress": "jp" }
        }
      ]
    }
  },
  "egresses": {
    "jp": {
      "type": "upstream",
      "backend": { "kind": "reverse", "addr": "rove-hop-jp" }
    }
  }
}
```

必须满足：

```text
快照 backend.addr  ===  hop --reverse-hop-id
```

大小写、连字符必须**完全一致**。

---

## 多 edge / 多 hop 建议

- **一个物理出口一个 hop_id**（不要多台机器共用同一 id，除非明确用 `duplicate=replace` 做主备漂移）。
- 同一 hop 注册多个 edge：`hop_id` 保持同一个，只加多个 `--reverse-quic`。
- 同城双活：用 `…-1` / `…-2`，策略层做 chain/主备，而不是复用 id。

---

## 运维清单（命名）

1. 按上表选好 `rove-hop-…` 并写入变更单  
2. edge 快照先（或同步）写入该 id  
3. 容器/进程用**同一字符串**启动  
4. 用访问日志 `reverse:rove-hop-…` 验收流量是否命中  
