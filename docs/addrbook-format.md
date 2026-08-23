# rove-addrbook 使用、发布与 `.rab` v1 格式

rove-addrbook 用来管理不适合反复塞进控制面快照的大型域名与 IP 数据集。完整链路由四部分组成：

1. `rove-abctl` 从本地清单和公开上游构建地址簿；
2. `.rab` 保存确定性、带 SHA-256 完整性校验的发布工件；
3. Rove 节点通过本地 `[addrbook]` 加载并热替换工件；
4. 控制面快照用 route selector 里的 `book:<category>` 决定哪些分类参与分流或阻断。

地址簿只回答“目标属于哪些分类”，**不决定用户、出口或允许/拒绝结果**。快照仍是策略唯一真相；
同一个分类可以在不同 policy 的 route 里用于 `egress`，也可以用于 `block`。

> **目标语义很重要**：地址簿匹配的是客户端请求中的目标域名或 IP 字面量，不会先解析域名再用解析结果
> 查询 IP 分类。因此 AWS/Azure/GCP IP 段只会命中以 IP 字面量发起的请求；要按域名分流，必须同时提供
> 域名数据源。TLS SNI 嗅探也不会替换 HTTP CONNECT / SOCKS5 请求中的目标。

设计约束（规范性）：

- **格式即协议**。消费方之间不通过网络协议协商，只通过文件格式契约耦合。
  任何布局变更都必须提升 `format_version`；v1 读取器遇到未知版本、未知
  section kind、重复 section 一律拒绝加载，不做猜测性兼容。
- **确定性构建**。同一输入源在任何机器上构建出的工件逐字节相同
  （`build_epoch` 由 manifest 或 `--epoch` 显式传入，绝不取墙钟）。
  发布产物可以被第三方复现校验。
- **fail-closed**。校验和不符、越界、排序违规、引用悬空——任何一项违规都
  导致整个文件拒绝加载；绝不部分加载。
- **mmap-ready**。所有 section 经由 section 表偏移寻址、记录定宽、小端。
  当前实现解码进类型化向量；未来零拷贝 mmap 读取器无需任何格式变更。

## 5 分钟构建并接入

### 1. 准备清单与源文件

下面的目录只依赖本地文件，适合先验证完整链路：

```text
addrbook/
├── book.toml
└── data/
    ├── corp.cidrs
    └── domains.txt
```

`addrbook/book.toml`：

```toml
# 由发布系统维护的单调递增 u64；不要取构建机当前时间作为隐式默认值。
epoch = 2026072301

[[source]]
category = "corp"
kind = "cidrs"
path = "data/corp.cidrs"

[[source]]
category = "ads"
kind = "domains"
path = "data/domains.txt"
```

`addrbook/data/corp.cidrs`：

```text
10.20.0.0/16
2001:db8:20::/48
```

`addrbook/data/domains.txt`：

```text
# 默认是 apex + 子域后缀匹配
ads.example
full:telemetry.example
keyword:tracker
```

### 2. 构建、验证和抽查

源码构建会生成独立工具 `target/release/rove-abctl`：

```bash
cargo build --release --locked --bin rove-abctl

./target/release/rove-abctl build \
  --manifest addrbook/book.toml \
  --out addrbook/book.rab

./target/release/rove-abctl verify addrbook/book.rab
./target/release/rove-abctl inspect addrbook/book.rab --categories
./target/release/rove-abctl query addrbook/book.rab sub.ads.example ads
./target/release/rove-abctl query addrbook/book.rab 10.20.1.8 corp
```

`query` 在目标后的一个或多个分类参数组成 selector：匹配时退出 `0`，不匹配时退出 `1`，
可直接用于发布脚本。

### 3. 让节点加载工件

```toml
[addrbook]
path = "/etc/rove/addrbook/book.rab"
poll_interval_secs = 300
```

节点配置了 `[addrbook]` 后，文件缺失、超过大小限制、校验和错误或格式不合法都会使启动失败。

### 4. 在快照里引用分类

在当前快照 schema 里，把 `book:<category>` 写进 route `selectors`：

```json
{
  "schema_version": 1,
  "version": 42,
  "users": {
    "alice": { "password": "replace-me", "policy": "filtered" }
  },
  "routing_policies": {
    "filtered": {
      "routes": [
        {
          "selectors": ["book:ads"],
          "action": { "type": "block" }
        },
        {
          "selectors": ["book:corp"],
          "action": { "type": "egress", "egress": "corp-hop" }
        }
      ]
    }
  },
  "egresses": {
    "corp-hop": {
      "type": "upstream",
      "backend": { "kind": "socks5", "addr": "10.0.0.9:1080" }
    }
  }
}
```

节点未配置地址簿、分类不存在或规则为空时，整份新快照拒收并保留上一份有效策略。

## `.rab` v1 二进制格式

### 顶层布局

所有整数一律**小端**（little-endian）。

```text
偏移      长度   字段
0         4      magic            = "RAB1"
4         2      format_version   = 1 (u16)
6         2      reserved         = 0 (u16；非零必须拒绝)
8         8      build_epoch      (u64) 构建纪元，由发布方定义（unix 秒或序列号）
16        4      n_sections       = 7 (u32；v1 的 7 个 section 全部必需)
20        20×n   section 表        n_sections 个 {kind u32, offset u64, len u64}
…         …      section payloads  由 section 表偏移寻址（offset 相对文件起点）
EOF-32    32     sha256           前面所有字节的 SHA-256 摘要
```

校验顺序（规范性）：读取器**必须**先验证尾部 SHA-256（覆盖除自身外的全部
字节），再解析 magic 与版本，然后才解析 section。任何 section 越界、重叠、
留有未引用字节、kind 重复或 kind 未知都必须拒绝整个文件。

### Section 目录

| kind | 名称          | 内容 |
|------|---------------|------|
| 1    | CATEGORIES    | 层级分类表（名称池 + parent 索引） |
| 2    | CATSETS       | 去重后的分类位图池 |
| 3    | IP4           | IPv4 区间表（排序、两两不相交） |
| 4    | IP6           | IPv6 区间表（排序、两两不相交） |
| 5    | DOMAIN_EXACT  | 精确域名表（规范化、排序、唯一） |
| 6    | DOMAIN_SUFFIX | 后缀域名表（标签反转、排序、唯一） |
| 7    | KEYWORD       | 关键字片段表 |

#### CATEGORIES (kind=1)

```text
n (u32) | n × { name_off u32, name_len u16, parent u32 } | pool_len (u32) | pool
```

- `name` 是完整层级路径（如 `google/ads`），字符集 `[a-z0-9-_.@!]` 加 `/`
  分隔符；表按 `name` 字节序排序。
- name pool 引用必须按记录顺序首尾相接，不得重叠、复用或留空洞；因此解码
  后字符串总量受工件字节数线性约束，不允许小文件放大成巨额堆分配。
- `parent` 是分类表内索引；根分类为 `u32::MAX`。父分类必须存在且路径
  必须是子路径去掉最后一段（引用完整性在加载时校验）。
- 层级语义：选择 `google` 时其全部子孙（`google/ads`、`google/play`…）
  一并选中。排序表上子孙即前缀区间 `[name+"/", name+"0")`，二分可得。

#### CATSETS (kind=2)

```text
words (u32) | n (u32) | n × words × u64
```

- 每个 catset 是 `words` 个 u64 的位图，bit i 对应分类表索引 i；
  `words = ceil(categories / 64)`。
- 所有地址条目通过 `catset` id（表内索引）引用位图，重复位图在构建期
  去重（intern）。位图中置位的分类索引必须小于分类总数。

#### IP4 (kind=3) / IP6 (kind=4)

```text
n (u32) | n × { start, end, catset u32 }     start/end: IP4=u32, IP6=u128
```

- 闭区间 `[start, end]`，按 `start` 排序且**两两不相交**（构建器用边界
  扫描线把重叠 CIDR 合并成带合并位图的不相交区间）。
- 查询：`partition_point(start ≤ key) - 1` 后验 `key ≤ end`，O(log n)。
- IPv4 映射的 IPv6 地址（`::ffff:a.b.c.d`）在查询层折回 IPv4 表。
  构建器会把 IPv6 CIDR 与该映射区重叠的部分切入 IP4 section；规范工件的
  IP6 section 不得覆盖映射区，读取器会拒绝这种非规范记录。

#### DOMAIN_EXACT (5) / DOMAIN_SUFFIX (6) / KEYWORD (7)

```text
n (u32) | n × { pool_off u32, len u16, catset u32 } | pool_len (u32) | pool
```

- 域名规范化：小写、去尾点、去首尾空白；后缀规则输入的 `*.example.com`
  是 `example.com` 的兼容别名（两者都匹配 apex 与任意子域）。
- DOMAIN_EXACT 按规范化名称排序唯一；查询为整名二分。
- DOMAIN_SUFFIX 存**标签反转**形式（`google.com` → `com.google`），排序
  唯一；查询对宿主名每个标签边界做前缀精确二分（≤ 标签数 × log n），
  `google.com` 与 `*.google.com` 均命中，`notgoogle.com` 不命中。
- KEYWORD 为子串匹配，线性扫描；仅用于 `keyword:` 语义（v2fly 数据里
  大量存在），构建时应控制数量。
- 三个字符串 section 的 pool 引用同样必须按记录顺序连续、不重叠且完整覆盖 pool。
- 三表的 `catset` 均指向 CATSETS 位图。命中结果 = 命中条目位图与查询
  selector 位图求交，非空即匹配。

### 语义不变量（加载时强制）

1. 分类表按名称排序、名称唯一、路径字符合法、parent 引用完整；
2. 位图池长度 = `n × words`，置位索引 < 分类数；
3. IP 表排序且不相交，`start ≤ end`；
4. 字符串表排序唯一、pool 引用在界内、UTF-8 合法；
5. 所有 `catset` id < 位图数。

违反任意一条 → 拒绝加载（`AddrBook::from_bytes` 返回错误）。

Rove v1 读取器另有 fail-closed 资源上限：最多 100,000 个分类、单 section
最多 8,000,000 条记录、解码目标堆预算 256 MiB；节点从文件加载时工件本身
也不得超过 256 MiB。预算在任何 `Vec::reserve` / 字符串复制前预检，恶意计数
字段不能先触发巨额分配再等待语义校验拒绝。

## 快照规则：`book:<category>`

控制面快照在 route selector 中引用 addrbook 分类：

```json
{
  "schema_version": 1,
  "version": 42,
  "users": {
    "alice": { "password": "replace-me", "policy": "ads-policy" }
  },
  "routing_policies": {
    "ads-policy": {
      "routes": [
        {
          "selectors": ["book:google/ads", "ads.custom.example"],
          "action": { "type": "block" }
        }
      ]
    }
  },
  "egresses": {}
}
```

- `book:` 规则始终在当前快照 schema 的 `selectors` 中可用，不再有额外 schema 版本门槛。
- 显式域名/IP 规则与 `book:` 分类按“或”组合（快照仍是“谁走哪”的唯一真相，
  addrbook 只提供地址数据）。
- 快照编译期把 `book:` 模式解析成位图 selector 并**钉住当时的书**——
  一个快照永远是内部一致的（规则与书版本成对固定）。
- 相同分类组合共享同一不可变 selector 位图；单快照唯一 selector 的总内存
  上限为 64 MiB，超过即拒绝新快照、继续服务旧快照。
- fail-closed：配置了 `book:` 规则但节点无 `[addrbook]`、或分类不存在，
  **整个快照被拒绝**，节点继续用旧快照服务。
- 书热替换 = 用新书重编译最近一次成功的原始快照，成功才书+快照同时
  替换；失败则两者都不动（见 `tests/addrbook_integration.rs`）。

### 分类与组合语义

- 分类名构建时会去首尾 `/`、转小写；每段只允许 `a-z 0-9 - _ . @ !`。
- 添加 `google/ads` 时会自动创建祖先 `google`；`book:google` 选择自身和全部子孙，
  `book:google/ads` 只选择该子树。没有通配符、排除或正则 selector。
- 同一数组中的多个 `book:` 条目是“或”；显式域名/IP 与地址簿 selector 也是“或”。
- 路由仍按 `routes` 数组 first-match-wins；把更具体的 `block` / `direct` / `egress` route 放在前面。
- scheme 前缀必须写成小写 `book:`；分类名本身匹配不区分大小写。
- `book:` 只允许出现在 route `selectors` 中；节点级覆盖只替换已存在的 named egress，不改变 selector。

## Manifest 清单

清单是 TOML 文件；相对 `path` 以清单所在目录为基准：

```toml
epoch = 2026072301

[[source]]
category = "geosite/google"
kind = "v2fly-domains"
path = "data/domain-list-community/data/google"
url = "https://download.example/google" # 可选，仅供 fetch 使用
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `epoch` | 否 | 写入工件的 `u64` 发布序号，缺省为 `0`；生产必须显式维护并递增。`--epoch` 可覆盖。 |
| `[[source]]` | 是 | 至少一项；按声明顺序读取，但最终工件仍确定性排序。 |
| `source.category` | 是 | 目标层级分类；自动转小写并创建祖先分类。 |
| `source.kind` | 是 | 下表六种数据源之一；未知值直接失败。 |
| `source.path` | 是 | 本地源文件路径；相对值以 manifest 目录为基准。 |
| `source.url` | 否 | `fetch` 下载地址；`build` 不访问网络，只读取 `path`。 |

每个 source 必须至少产出一条受支持记录；空文件、只有注释、或 v2fly 文件只有被跳过的
`regexp:` 都会使整个构建失败。

## 六种数据源

| `kind` | 输入 | 自动生成的分类 |
|---|---|---|
| `cidrs` | 每行一个 IP 或 CIDR，支持 IPv4/IPv6 | 只写入 `category` |
| `domains` | Rove 规则：域名模式，也接受 IP/CIDR | 只写入 `category` |
| `v2fly-domains` | v2fly domain-list-community 文件 | 基础分类、`@attr` 分类及 `&affiliation` 分类 |
| `aws-ip-ranges` | AWS `ip-ranges.json` | `category` 与 `category/<service>` |
| `azure-service-tags` | Azure Service Tags JSON | `category` 与 `category/<systemService>` |
| `gcp-cloud-json` | GCP `cloud.json` / `goog.json` | `category` 与可选的 `category/<service>` |

文本源会去掉 `#` 之后的注释和空白行。

### `cidrs`

接受单 IP（等价 `/32` 或 `/128`）和 CIDR。重叠网段会在构建时拆成不相交区间并合并分类位图，
所以同一地址可以同时属于多个分类。

```text
203.0.113.7
203.0.113.0/24
2001:db8::/32
```

### `domains`

| 写法 | 语义 |
|---|---|
| `example.com` / `domain:example.com` | 后缀匹配，包含 apex 与所有子域 |
| `*.example.com` | 后缀匹配兼容写法，同样包含 apex |
| `full:api.example.com` | 只匹配完整域名 |
| `keyword:tracker` | 规范化域名包含该子串 |
| `203.0.113.0/24` / `203.0.113.7` | CIDR 或单 IP，与 `cidrs` 语义相同 |

域名会转小写、去首尾空白和点。`keyword:` 在查询时线性扫描，数量过大时应改用精确或后缀规则。
如果文件应当只允许 IP/CIDR，使用更严格的 `cidrs` source；它会拒绝任何域名行。

### `v2fly-domains`

支持 domain-list-community 的 `include:`、`@attr`、选择性 `@-attr` 和 `&affiliation`：

```text
google.com
full:g.co @cn
keyword:gvid @ads
include:google-base @ads @-cn
```

如果 manifest 分类是 `geosite/google`，`@cn` 条目同时进入 `geosite/google@cn`。
`&category-special` 会进入同一命名空间下的 `geosite/category-special`；affiliation 会先在源文件
同目录、同扩展名的文件中建立全局索引，再执行 include/filter。

安全与兼容边界：

- `regexp:` 明确跳过，rove-addrbook 不提供正则匹配；
- include 最大深度 16，循环引用失败；
- include 只能使用源根目录内的相对路径，绝对路径、`..` 和 symlink 逃逸失败；
- 单条规则或 include 最多 64 个 metadata/filter 项；
- 解析、展开、过滤和输出总工作量上限为 1,000,000 次；
- 同一解析过程按文件缓存并去重，但不会跨构建保存缓存。

### AWS / Azure / GCP Provider JSON

Provider 源只接受**规范 CIDR**：必须带前缀长度，网络地址的 host bits 必须为零。裸 IP、缺失必要字段、
无地址字段、非法前缀，或 GCP 一条记录同时声明 IPv4/IPv6 都会使构建失败。

服务名会转小写，空格、斜杠等非法字符转为 `-`。例如 AWS `EC2` 进入 `aws/ec2`，
GCP `Google Cloud` 进入 `gcp/google-cloud`。Azure 优先用 `systemService`；为空时取 tag 名第一个
点分段。每条 Provider 地址也始终加入父分类，所以 `book:aws` 会覆盖所有服务。

## `rove-abctl` 命令参考

```bash
rove-abctl fetch   --manifest book.toml [--only <path-substr>]
rove-abctl build   --manifest book.toml --out book.rab [--epoch <u64>]
rove-abctl inspect book.rab [--categories]
rove-abctl verify  book.rab
rove-abctl query   book.rab <host-or-ip> [category ...]
rove-abctl diff    old.rab new.rab [--max-shrink <0..100>]
rove-abctl bench   book.rab [--iterations <n>]
rove-abctl export  book.rab --out rove-addrbook.json
```

| 命令 | 行为与退出语义 |
|---|---|
| `fetch` | 仅下载声明了 `url` 的 source；`--only` 按 `path` 子串过滤。每项 60 秒超时、128 MiB 上限，成功后原子替换源文件。 |
| `build` | 解析全部 source、构建并自验证，再原子发布到 `--out`；不会联网。 |
| `inspect` | 输出 epoch、SHA-256、大小、分类数与各 section 记录数；`--categories` 列出完整分类名。 |
| `verify` | 完整解码、校验和及语义校验；有效退出 `0`，无效退出 `1`。 |
| `query` | 先列出目标命中的所有分类；带 selector 时匹配退出 `0`、不匹配退出 `1`。不带 selector 时即使无命中也退出 `0`。 |
| `diff` | 比较两个有效工件并执行发布异常门；异常退出 `1`。 |
| `bench` | 用固定的域名/IP 命中与未命中探针做内存查询微基准；默认 1,000,000 次，不能替代真实代理压测。 |
| `export` | 将 `.rab` 全量投影为控制面 sidecar JSON（TeamsEdge `rove-addrbook.json`）：`schema_version=1`、与分类 1:1 的 `expansions`（exact/suffix/keyword/cidrs）。节点不读此文件。 |

所有命令拒绝未知、重复或缺值选项；命令/用法错误退出 `2` 或报错退出 `1`，不会悄悄使用默认值。

### `fetch` 的边界

`fetch` 只是受限下载器，不验证上游内容签名，也不把 URL 或下载内容写入 `.rab`。它依赖 HTTPS 与发布环境
自身的信任配置；高价值数据应在外部固定可信 URL/版本并保留源文件审计记录。未声明 `url` 的 source
会跳过，不是错误。`--only` 是对 source `path` 的区分大小写子串过滤。

Manifest 是受信任的构建配置：它能指定读取路径、下载 URL 和 `fetch` 写入目标，不应直接运行来源不明的
manifest。v2fly `include:` 的目录约束只保护该数据源的递归展开，不等于为整个 manifest 提供沙箱。

### `diff` 发布异常门

默认 `--max-shrink 30`。只要新旧工件不同，以下任一条件都会返回非零：

- 新工件 `build_epoch` 没有严格增加；
- 旧分类在新工件中被删除；
- CATSETS、IPv4、IPv6、精确域名、后缀域名或关键字任一 section 的记录数缩减超过阈值。

逐字节相同的工件直接成功，即使 epoch 相同。`diff` 是**异常门而非语义证明**：它不会判断新增地址是否正确，
也不会发现阈值以内但业务上错误的变化，所以仍需 `query` 抽查和 canary。

## 官方数据发布通道

仓库工作流 `.github/workflows/addrbook-release.yml` 每周一自动（也可手动 dispatch、或在
`addrbook/**` 变更合入 main 时）刷新上游、构建并把工件发布到滚动 Release 标签
`addrbook-latest`，下载 URL 长期稳定。仓库当前为 internal 可见性，下载需要 GitHub 认证；
仓库公开后匿名 `curl` 直链同样可用：

```bash
# 认证下载（internal/private 仓库）
gh release download addrbook-latest -R talkincode/rove --pattern 'book.rab*'
gh release download addrbook-latest -R talkincode/rove --pattern 'rove-addrbook.json*'

# 仓库公开后的匿名直链
curl -fsSLO https://github.com/talkincode/rove/releases/download/addrbook-latest/book.rab
curl -fsSLO https://github.com/talkincode/rove/releases/download/addrbook-latest/book.rab.sha256
curl -fsSLO https://github.com/talkincode/rove/releases/download/addrbook-latest/rove-addrbook.json
curl -fsSLO https://github.com/talkincode/rove/releases/download/addrbook-latest/rove-addrbook.json.sha256

sha256sum -c book.rab.sha256
sha256sum -c rove-addrbook.json.sha256
rove-abctl verify book.rab   # 建议部署前独立复核
```

- **Rove 节点**加载 `book.rab`
- **TeamsEdge / 控制面**加载 `rove-addrbook.json`（由 `rove-abctl export` 从同一 `.rab` 生成，同 epoch）

发布前工作流强制执行：`verify`、与上一版资产的 `diff --max-shrink 30` 异常门、固定正负
`query` 探针、分类与记录数下限断言，以及控制面 JSON 导出；任一失败都不更新已发布资产。
`SOURCES.txt` 记录构建时间、源提交、epoch 与全部上游文件校验和；`azure-service-tags.json`
一并发布，既是审计凭据也是下次构建在微软发布页不可达时的降级种子。预期外的缩水需人工审查后用
`skip_diff_gate=true` 手动 dispatch 放行。

epoch 取构建时刻 `YYYYMMDDHHMMSS`（UTC）。滚动标签指向首次发布时的提交，数据版本以
Release notes 与 `SOURCES.txt` 中的 epoch/checksum 为准；需要长期固定版本的部署应自建
发布通道归档具体工件，而不是依赖滚动标签的历史状态。

## 推荐构建与发布流程

本仓库自带一份可直接使用的清单 `addrbook/book.toml`（本地 corp/ads 源 + AWS/Azure/GCP/
Cloudflare/Telegram 官方 IP 段 + v2fly 域名大表）；`scripts/addrbook-refresh.sh` 负责刷新
全部上游，包括两个没有稳定直链的特殊源（Azure 发布页轮换链接、v2fly 整目录 tarball）。

```bash
# 1. 刷新声明了 url= 的原始源
rove-abctl fetch --manifest book.toml

# 2. 用明确、递增的发布序号构建候选
rove-abctl build \
  --manifest book.toml \
  --out book-20260723.rab \
  --epoch 2026072301

# 3. 独立验证、查看分类并抽查关键目标
rove-abctl verify book-20260723.rab
rove-abctl inspect book-20260723.rab --categories
rove-abctl query book-20260723.rab www.example.com geosite/example

# 4. 与线上版本执行异常门
rove-abctl diff book-current.rab book-20260723.rab --max-shrink 30

# 5. 通过受认证的发布通道分发，并在同一文件系统内原子 rename
```

`.rab` 尾部 SHA-256 只证明文件内部完整，**不证明发布者身份**。对象存储、配置分发、制品仓库或 SSH
等外部通道必须负责认证与授权；如需供应链签名，应在 `.rab` 外使用组织现有的签名/证明机制。

### 首次启用顺序

1. 先升级所有节点到支持当前快照 schema 和 `.rab` v1 的版本；
2. 给每个节点配置并部署一份已验证地址簿，确认启动日志中的 epoch/checksum；
3. 再让控制面发布带 `book:` route selector 的快照；
4. 最后按节点/机房 canary 扩大地址簿更新范围。

如果先发布 `book:` 快照，未配置地址簿的节点会按设计拒收它。不同节点使用不同 checksum 时，同一快照可能
产生不同决策；fleet 发布系统应把 checksum 当作版本一致性依据。

## 节点配置与部署

```toml
[addrbook]
path = "/etc/rove/addrbook/book.rab"
poll_interval_secs = 300
```

| 字段 | 说明 |
|---|---|
| `path` | 必填，本地 `.rab` 文件；空路径、缺失或不可读会拒绝启动。 |
| `poll_interval_secs` | 缺省 `300`；按文件身份轮询更新。`0` 表示只在启动时加载。 |

Rove 节点**不会**读取 manifest、调用 `rove-abctl fetch` 或从网络下载工件。构建与分发必须在节点之外完成。
运行用户只需要对 `.rab` 和父目录有读取/遍历权限，不需要源文件或 manifest。

### Docker

主 Rove 运行镜像不包含离线构建工具 `rove-abctl`。在 CI/发布机使用 Release 包或源码构建工具，再把
**目录**只读挂进容器：

```toml
[addrbook]
path = "/etc/rove/addrbook/book.rab"
poll_interval_secs = 300
```

```bash
docker run ... \
  -v "$PWD/addrbook:/etc/rove/addrbook:ro" \
  ghcr.io/talkincode/rove:latest
```

不要把单个 `book.rab` 文件直接 bind mount 后再依赖 host 侧 rename 热更新；文件级 bind mount
可能继续指向旧 inode。挂载目录后，在该目录内原子替换 `book.rab` 才能让容器看到新文件。

### systemd / 裸机

建议把地址簿放在独立只读目录，如 `/var/lib/rove/addrbook/book.rab`。发布程序先写同目录临时文件，
`fsync` 后 rename；不要原地截断覆写。`rove-abctl build --out` 自身已使用临时文件 + 原子 rename。

## 热重载、失败与回滚

节点每次轮询按 mtime、长度以及 Unix 下的设备/inode 判断候选变化，并在读取前后复核文件身份；连续变化
三次的文件拒绝读取。候选通过 `.rab` 全量校验后：

1. checksum 未变化：只确认文件身份，不替换策略；
2. 尚无成功快照：直接安装新书，后续快照会引用它；
3. 已有成功快照：用新书重新编译最近一次成功的原始快照；
4. 重编译成功：书与运行期快照一起替换；
5. 重编译失败：两者都不变，记录告警，并在后续轮询继续尝试该候选。

典型失败是新书删除了当前快照仍引用的分类。可以先发布移除引用的更高 `version` 快照，再等候选书自动重试；
也可以恢复一份包含该分类的新工件。

节点加载器只校验格式和 checksum，**不强制 epoch 单调**；单调门禁属于发布流程。生产回滚不要直接复制旧
`.rab`，而应使用旧数据重新构建一个更高 epoch 的新工件，通过 `diff/query` 后正常发布。

## 限制与安全边界

| 项目 | 上限/语义 |
|---|---|
| 单个节点工件 | 256 MiB |
| 解码目标堆预算 | 256 MiB |
| 分类数 | 100,000 |
| 单 section 记录数 | 8,000,000 |
| 单个 fetch 响应 | 128 MiB |
| v2fly include 深度 | 16 |
| v2fly metadata/filter | 每条 64 项 |
| v2fly 总展开工作量 | 1,000,000 |
| 单快照唯一 selector 位图 | 合计 64 MiB，超过则拒收快照 |
| selector 弱缓存 | 最多 20,000 个组合；不延长旧快照生命周期 |

其他边界：

- `.rab` 有完整性校验，没有内置签名、加密或来源证明；
- 地址簿不是 DNS、GeoIP 服务或动态 API，不做域名解析和反向解析；
- `keyword:` 是线性扫描；v1 不支持正则；
- 节点不自动拉取远端工件，也没有从控制面内嵌/传输 `.rab` 的协议；
- 工件包含的域名/IP 可能具有业务敏感性，文件权限和分发日志应按策略资产保护；
- 所有解析和替换失败都 fail-closed：启动失败或保留旧书，不会退化成“分类不匹配”。

## 排障速查

| 现象 | 检查 |
|---|---|
| `rove-abctl build` 报 source 无有效记录 | 检查路径是否相对 manifest、文本是否只有注释、v2fly 是否只有 `regexp:`。 |
| `query` 列出分类但退出 `1` | 目标命中了别的分类，未命中命令末尾指定的 selector；先不带分类运行查看全部命中。 |
| 节点启动报 addrbook 错误 | 先运行 `rove-abctl verify`，再检查路径、权限、256 MiB 上限和容器挂载。 |
| 快照报 `no [addrbook]` | 节点未配置 `[addrbook]`，但快照引用了 `book:` selector；先配置并验证 `.rab`，或移除该 selector。 |
| 快照报 `unknown addrbook category` | 用 `inspect --categories` 核对完整分类名；错误信息会带上未知分类名，先修快照引用或发布包含该分类的书。 |
| 新书一直被拒绝 | 查看运行日志中的 `new addrbook rejected`；通常是最近快照引用了新书已删除的分类。 |
| 域名没有命中 Provider IP 分类 | 这是预期：域名目标不会先 DNS 解析再查 IP 表；补充域名 source。 |
| Docker 内看不到新书 | 确认挂载的是目录而非单文件，并在挂载目录内原子 rename。 |
| 多节点结果不一致 | 对比各节点加载日志的 epoch 和 checksum；快照版本相同不代表本地书相同。 |

## 协议稳定性锚点

`tests/vectors/addrbook_v1.rab` 是提交入库的 golden 工件，
`tests/addrbook_integration.rs::golden_vector_matches_deterministic_rebuild`
从 `tests/fixtures/addrbook/` 的源数据重建并逐字节比对。编码器的任何输出
变化都会使该测试失败——这被定义为**格式破坏**，必须有意识地：
提升 `format_version` 或确认向后兼容、重新生成 golden 向量、在本文档记录
变更理由。
