# 安装与部署

Rove 是一个静态的 Rust 二进制，TLS 走 rustls（ring），**不依赖 OpenSSL 等系统库**，部署非常简单。
下面按由易到难给出四种方式。

## 系统要求

- 运行：任意 64 位 Linux / macOS。二进制自带 CA 根证书，无额外系统依赖。
- 源码构建：**Rust 1.88+**。
- 端口：监听端口按需放行。反向 hop 用的是 **UDP**（QUIC），别只放行 TCP。

---

## 方式一：预编译二进制（推荐）

从 [GitHub Releases](https://github.com/talkincode/rove/releases) 下载对应平台的压缩包，里面包含
`rove`、`rove-hop`、`rove-relay`、`rove-abctl`、`README.md`、`LICENSE`、
`config.example.toml` 和 `relay.example.toml`。

```bash
tar -xzf rove-<版本>-linux-x86_64.tar.gz
./rove --config config.toml
```

---

## 方式二：Docker

官方镜像发布在 `ghcr.io/talkincode/rove`，基于 alpine；`ENTRYPOINT` 已是 `rove`，
默认读 `/etc/rove/config.toml`。

```bash
docker run -d --name rove \
  -p 8443:8443 -p 1080:1080 \
  -v "$PWD/config.toml:/etc/rove/config.toml:ro" \
  -v "$PWD/certs:/etc/rove/certs:ro" \
  -v "$PWD/data:/var/lib/rove:rw" \
  -v "$PWD/logs:/var/log/rove:rw" \
  ghcr.io/talkincode/rove:latest
```

要点：

- 配置里的 `cache_path` 应指向挂进容器的可写目录（如 `/var/lib/rove/snapshot.json`），
  这样容器重启也能靠缓存热启动。
- 默认开启的访问日志应把 `access_log.dir` 指向持久化目录（如 `/var/log/rove`）。
- 证书文件按 `[listeners.tls]` 里的路径挂进去。
- 使用 rove-addrbook 时挂载地址簿**目录**并把 `[addrbook].path` 指向容器内 `.rab`；目录挂载才能让
  host 侧原子 rename 的热更新对容器可见。运行镜像不包含离线构建工具 `rove-abctl`。
- 需要自定义 CA（例如上游 hop 是自签名证书）时，用环境变量
  `Rove_EXTRA_CA_CERTS=/etc/rove/certs/your-ca.crt` 追加信任，而不是全局关校验。

### 从源码构建镜像

```bash
docker build -t rove:local .
```

---

## 方式三：源码构建

```bash
git clone https://github.com/talkincode/rove.git
cd rove
cargo build --release --bins
```

产物在 `target/release/` 下：`rove`（主节点）、`rove-hop`（独立出口）、
`rove-relay`（公网 reverse-ingress relay）与
`rove-abctl`（离线地址簿构建/验证/发布工具）。
`--locked` 可保证使用 `Cargo.lock` 锁定的依赖版本。

---

## 方式四：systemd 常驻

`/etc/systemd/system/rove.service`：

```ini
[Unit]
Description=Rove forward proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rove
Group=rove
WorkingDirectory=/opt/rove
ExecStart=/opt/rove/rove --config /opt/rove/config.toml
Restart=on-failure
RestartSec=3
# 加固建议
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rove/data /opt/rove/logs
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin rove
sudo systemctl daemon-reload
sudo systemctl enable --now rove
journalctl -u rove -f
```

> 监听 <1024 的端口（如 443、161）需要相应权限。可以用 `AmbientCapabilities=CAP_NET_BIND_SERVICE`
> 授予绑定低端口的能力，而不必用 root 运行整个进程。

---

## 升级

1. 停止服务（`systemctl stop rove` 或停容器）。
2. 替换二进制 / 拉取新镜像。
3. 启动。节点会**先读本地缓存快照**再联控制面，所以升级期间即便控制面短暂不可达也能立即恢复服务。

> 当前版本收到 `SIGINT` / `SIGTERM` 后会先停止新接入，并在配置的有界窗口内排空在途连接；超时后强制结束剩余会话。编排环境仍建议先通过 `/readyz` 摘流再停止实例。

---

## 方式五：RouterOS 容器（rove-hop 反向出口）

在 MikroTik 设备上部署 **NAT 后 hop** 时，不要手搓 rootfs：使用 Release 中的

`rove-hop-routeros-<version>-arm64.tar.gz`

（内含 Docker-save 镜像、`.rsc` 部署/卸载脚本、完整运维手册与 `hop_id` 命名规范）。

专题文档：[RouterOS 容器部署 rove-hop](./hop-routeros.md)。

---

## 下一步

- [配置详解](./configuration.md)：逐段解释 `config.example.toml`。
- [最佳实践场景](./best-practices.md)：单节点、分流、NAT 后反向 hop、隔离网络等拓扑。
- [RouterOS 容器部署 rove-hop](./hop-routeros.md)：ax² / RB 等设备上的 reverse hop。
