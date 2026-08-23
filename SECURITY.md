# Security

## 公开仓库红线

Rove 是公开项目。安全问题按「会不会把真实系统或真实人暴露出去」处理，而不是按「看起来像密钥」的关键字处理。

永远不要提交：

- 节点 token、控制面 bearer、MQTT 密码、SNMP 凭证
- 用户密码、快照缓存、真实 `node_id` / hop id
- TLS 私钥与生产证书（`tests/fixtures/tls/` 里的假证书除外）
- 访问日志、诊断导出、客户策略、非公开地址簿
- CI、crates.io、Homebrew tap 的发布凭据

示例配置必须使用 `example.com` 与 `REPLACE_WITH_*`。发布前运行：

```bash
./scripts/check-public-tree.sh
```

## 报告漏洞

请不要开公开 Issue 贴复现里的真实凭据。发邮件或 GitHub Security Advisory 到 [talkincode/rove](https://github.com/talkincode/rove/security)。

我们会优先处理：认证绕过、策略 fail-open、快照未校验即热替换、凭据进入日志。
