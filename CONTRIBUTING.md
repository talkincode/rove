# Contributing

先读 `AGENT.md` 和 `docs/roadmap.md`。Rove 优化的是应用网络路径（Agent API、交易、SaaS 出口），不是把节点做成控制面或协议堆料场。

## 公开树审查

任何 PR、tag、Release 之前：

1. 跑 `./scripts/check-public-tree.sh`，必须退出 0。
2. 目检 diff：有没有真实主机名、token、私钥、快照、日志。
3. 新示例只用占位符。不确定就不提交。

`data/`、`logs/`、`dist/`、本地证书默认不入库。

## 开发门禁

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
./scripts/check-public-tree.sh
```

影响认证、策略、加密、快照或出站选择时，先补能失败的测试，再改代码。新的一级能力必须有 `tests/` 下的 E2E，并登记到 `docs/acceptance-matrix.md`。

## 协议

现有热路径是 HTTP CONNECT、SOCKS5、TUIC。新的主流代理协议欢迎规划，但必须独立认证命名空间、fail-closed，且不破坏现有热路径。
