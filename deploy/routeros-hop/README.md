# rove-hop RouterOS 部署包

在 MikroTik RouterOS **container** 上部署 `rove-hop` 反向出口（reverse QUIC）。

## 包内文件

| 文件 | 用途 |
|---|---|
| `GUIDE.md` | **完整运维手册**（部署/验收/排障） |
| `HOP-ID-NAMING.md` | `reverse-hop-id` 命名规范（前缀 `rove-hop-`） |
| `env.example` | 参数模板 |
| `scripts/rove-hop-routeros.rsc` | 部署脚本 |
| `scripts/rove-hop-routeros-remove.rsc` | 卸载脚本 |
| `images/rove-hop-*.tar` | Docker-save 容器镜像（若本包含镜像） |
| `SHA256SUMS` | 校验（Release 包） |

## 3 分钟上手

1. **定名**：如 `rove-hop-jp`（见 `HOP-ID-NAMING.md`）  
2. **edge**：开启 `[reverse_hop]`，快照 `upstream.addr` 与 hop_id 一致  
3. **上传** `images/rove-hop-arm64.tar` 到路由器  
4. **设变量**（见 `env.example`）后：

```text
/import file-name=rove-hop-routeros.rsc
```

5. **检查**：`/container print` → `running=true`；edge 侧出现会话  

详细步骤、安全基线、故障表：**先读 `GUIDE.md`**。

## 推荐形态

- **生产：reverse-only**（脚本默认）  
- SOCKS 仅调试，不在本脚本开启  

## 支持架构

- arm64（hAP ax²/ax³、RB5009 等）  
- amd64（CHR / x86 设备，若 Release 提供对应包）  
