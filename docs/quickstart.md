# 快速开始

本章用最短路径把一个能用的代理跑起来，并用 `curl` 验证。全程不需要控制面 —— 我们先用一份**本地快照缓存**
喂给节点，让它离线也能鉴权和转发。

> 需要 Rust 1.88+（源码构建）或 Docker。想要预编译二进制见 [安装与部署](./installation.md)。

## 1. 拿到二进制

```bash
git clone https://github.com/talkincode/rove.git
cd rove
cargo build --release --bins
# 产物：target/release/rove 与 target/release/rove-hop
```

## 2. 写一份最小配置 `config.toml`

```toml
node_id = "dev-local-01"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"  # 本地试用先随便填，反正连不上会用缓存
token = "dev"
poll_interval_secs = 30
cache_path = "./data/snapshot.json"

[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:8080"

[[listeners]]
name = "socks5-in"
protocol = "socks5"
listen = "127.0.0.1:1080"

[log]
level = "info"
```

## 3. 放一份本地快照缓存 `data/snapshot.json`

节点启动时**先读缓存再联网**，所以哪怕控制面不可达，只要缓存里有用户就能鉴权。下面这份是
**当前快照 schema（schema_version: 1）**：用户 `alice`（密码 `s3cret`）绑定 `open` routing policy
（无 route、无 default egress = 纯直连）：

```json
{
  "schema_version": 1,
  "version": 1,
  "users": {
    "alice": { "password": "s3cret", "policy": "open" }
  },
  "routing_policies": {
    "open": { "routes": [] }
  },
  "egresses": {}
}
```

```bash
mkdir -p data
# 把上面的 JSON 存成 data/snapshot.json
# 可选：rove validate-snapshot --node-id dev-local-01 data/snapshot.json
```

> 完整字段（过期、限速、连接数、有序 route、named egress）见
> [数据模型与策略决策](./data-model.md)。Rove 只接受这一套 `routing_policies` + `egresses` 快照形状。

## 4. 启动

```bash
./target/release/rove -c config.toml
```

看到监听日志即成功。省略 `-c` 时默认读当前目录的 `config.toml`。

## 5. 用 curl 验证

```bash
# HTTPS 目标走 HTTP CONNECT
curl -x http://alice:s3cret@127.0.0.1:8080 https://www.example.com -I

# 明文 HTTP 目标走 absolute-form 转发
curl --proxy http://127.0.0.1:8080 --proxy-user 'alice:s3cret' http://www.example.com -I

# SOCKS5 入口
curl -x socks5h://alice:s3cret@127.0.0.1:1080 https://www.example.com -I
```

拿到 `HTTP/2 200` 就通了。故意把密码打错，应该得到 `407`（HTTP）或被 SOCKS5 拒绝 —— 这说明鉴权在工作。

---

## 下一步

- 接上你自己的控制面，让用户和策略自动下发 → [控制面同步协议](./snapshot-protocol.md)
- 加 HTTPS / SOCKS5-over-TLS 入口、限速、分流到二级代理 → [配置详解](./configuration.md) · [数据模型](./data-model.md)
- 用 AWS/Azure/GCP、v2fly 或自有列表维护大型分流规则 → [rove-addrbook 指南](./addrbook-format.md)
- 部署到生产（systemd / Docker / 反代） → [安装与部署](./installation.md)
- 看典型拓扑怎么搭 → [最佳实践场景](./best-practices.md)
