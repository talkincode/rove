# 验收矩阵（业务能力覆盖矩阵）

本文档是 `docs/roadmap.md`「验收流程与标准」的执行载体：把路线图里的每个一级业务能力映射到
可执行的自动化测试锚点，回答"这条能力靠什么证据算验收通过"。矩阵与代码同仓演进，
引用的测试必须真实存在；测试重命名或删除时必须同步修订本表。

## 硬性不变量（合入门禁）

以下五条对本仓库是**硬性规定**（同时固化在 `AGENT.md`），不满足时相关变更不得合入主线：

1. **每个一级功能至少有一条 Happy Path 自动化验收。**
2. **每个高风险功能至少覆盖一条失败路径。** 凡涉及认证、策略决策、加密、快照/状态写入、
   出站选择的能力一律视为高风险；失败路径必须验证保守行为（fail-closed），不能只测成功。
3. **每个涉及凭据/身份的功能至少验证两种角色。** Rove 没有传统 RBAC，"角色"指身份结局：
   例如 合法用户 vs 过期用户、正确密码 vs 错误密码、正确 token/community vs 错误值。
4. **每个会修改系统状态的操作至少验证一次失败后的恢复或回滚。** 例如无效快照不得覆盖缓存、
   连接数拒绝后配额释放、日志轮转清理、engineBoots 跨重启持久化。
5. **每次新增一级业务功能，必须同步新增对应的 E2E（`tests/` 下集成测试），并新增本表一行。**
   只有单元测试不算完成；缺 E2E 的功能只能停留在探索分支。

## 矩阵总览

图例：✅ 已有自动化验收（锚点见下文明细）· ⚠️ 已识别缺口或待核验 · — 该维度不适用（须给出理由）。

| 一级能力 | Happy Path | 失败路径 | 角色/凭据 | 恢复/回滚 | E2E（`tests/`） |
|---|---|---|---|---|---|
| HTTP CONNECT 前端 | ✅ | ✅ | ✅ | ✅ | ✅ `proxy_integration` |
| HTTP absolute-form 前端 | ✅ | ✅ | ✅ | — 单请求无持久状态 | ✅ `proxy_integration` |
| SOCKS5 前端（含 UDP ASSOCIATE） | ✅ | ✅ | ✅ | ✅ | ✅ `proxy_integration` / `socks5_udp_integration` |
| TLS 监听（含 SNI 多证书） | ✅ | ✅ | — 无用户角色 | — 无状态写入 | ✅ `tls_sni_integration` |
| 认证与过期校验 | ✅ | ✅ | ✅ | — 只读决策 | ✅ 经 `proxy_integration` 链路 |
| 策略决策与规则匹配 | ✅ | ✅ | ✅ | — 只读决策 | ✅ `proxy_integration`（block/direct） |
| 出站（direct / HTTP / SOCKS5 upstream） | ✅ | ✅ dns/dial/tls 分阶段 | ✅ | ✅ | ✅ 经 `proxy_integration` / `reverse_hop_integration` |
| 每用户限速 | ✅ | — 令牌桶无失败分支 | ✅ | — 无独立状态写入 | ✅ `proxy_integration` |
| 连接数限制 | ✅ | ✅ | ✅ | ✅ | ✅ `proxy_integration` |
| 控制面快照同步 / 缓存 / 热替换 | ✅ | ✅ | ✅ | ✅ | ✅ `snapshot_sync_integration` |
| 健康探针与 listener readiness | ✅ | ✅ | — 无凭据 | ✅ | ✅ `health_integration` |
| MQTT 运维通道（查询/同步/拨测/诊断） | ✅ | ✅ | ✅ | ✅ | ✅ `mqtt_integration` |
| 结构化访问日志 | ✅ | ✅ | — 无角色 | ✅ | ✅ `proxy_integration` |
| TCP 首包 observe-only 识别 | ✅ | ✅ | — 不涉及新凭据 | — 只读观察 | ✅ `proxy_integration` / `tuic_integration` |
| TUIC sniff route 双候选策略 | ✅ | ✅ | ✅ requested/sniffed 身份结局 | — 只读决策 | ✅ `tuic_integration` |
| HTTP/SOCKS5 sniff route 双候选策略 | ✅ | ✅ | ✅ requested/sniffed 身份结局 | — 只读决策 | ✅ `proxy_integration` |
| SNMP agent（v2c + v3 USM） | ✅ | ✅ | ✅ | ✅ | ✅ `snmp_integration` |
| 反向 hop（QUIC）+ reverse/2 UDP | ✅ | ✅ | ✅ | ✅ | ✅ `reverse_hop_integration` |
| 反向公网入口（TCP/UDP） | ✅ | ✅ | ✅ | ✅ | ✅ `reverse_ingress_integration` |
| TUIC v5 前端 | ✅ | ✅ | ✅ | — 无状态写入 | ✅ `tuic_integration` |
| Subnetra hub / spoke | ✅ | ✅ | ✅ 密钥即身份 | — fail-closed 即恢复语义 | ✅ `subnetra_*` 四个套件 |
| 独立 hop 二进制（rove-hop） | ✅ | ✅ | ✅ | ✅ | ✅ `rove_hop_integration` |
| hop MQTT egress doctor | ✅ | ✅ | ✅ | — 只读一次探测，无状态写入 | ✅ `hop_mqtt_integration` |
| 优雅停机（SIGINT/SIGTERM） | ✅ | ✅ | — 无身份语义 | ✅ | ✅ `shutdown_integration` |
| 配置解析（TOML） | ✅ | ✅ | — 无身份语义 | — 解析不修改外部状态 | — 单元层验收即可 |
| rove-addrbook（`.rab` 数据集 + `book:` 规则） | ✅ | ✅ 未知分类/缺书拒快照 | — 无独立用户角色，沿用组策略 | ✅ 坏工件保旧书、坏书换失败不动快照 | ✅ `addrbook_integration`（含 golden 向量） |
| Snapshot schema v4（routing policy + named egress） | ✅ | ✅ 严格混用/缺失引用/坏 override 拒绝 | ✅ v4 policy 与未知用户 fail-closed | ✅ 坏 v4 不替换内存快照/cache | ✅ `snapshot_v4_integration` / `snapshot_validator_integration` |

## 测试锚点明细

锚点格式为 `文件::测试名`。以下按能力列出各维度的证据。

### HTTP CONNECT 前端

- Happy Path：`tests/proxy_integration.rs::http_connect_direct_tunnels_bytes`
- 失败路径：`src/inbound/http.rs::rejects_method_missing_auth_bad_auth_and_bad_target`、
  `tests/proxy_integration.rs::http_connect_blocked_by_policy_returns_403_without_dialing_out`
- 角色：合法用户成功（Happy Path）vs 过期用户拒绝
  `src/inbound/http.rs::rejects_expired_users_before_policy`、错误凭据拒绝（同上失败用例）
- 恢复/回滚：`tests/proxy_integration.rs::http_connect_max_connections_rejects_second_tunnel_then_releases`

### HTTP absolute-form 前端

- Happy Path：`tests/proxy_integration.rs::http_absolute_get_forwards_origin_form_and_strips_proxy_headers`、
  `http_absolute_post_forwards_body_sent_with_request_head`
- 失败路径 / 角色：`tests/proxy_integration.rs::http_absolute_request_requires_auth_before_dialing_origin`
  对照有效凭据的 Happy Path，验证缺失或错误认证不会先拨号。
- 恢复/回滚：单请求转发不持久化状态，不适用。

### SOCKS5 前端（含 UDP ASSOCIATE）

- Happy Path：`tests/proxy_integration.rs::socks5_connect_direct_tunnels_bytes`、
  `tests/socks5_udp_integration.rs::socks5_udp_associate_relays_through_hop_to_echo`
- 失败路径：`src/inbound/socks5.rs::rejects_auth_failure` / `rejects_unsupported_command` /
  `rejects_target_blocked_by_policy` / `rejects_when_upstream_connect_fails`
- 角色：正确用户名密码 vs 错误凭据（`rejects_auth_failure`）
- 恢复/回滚：`tests/proxy_integration.rs::socks5_max_connections_rejects_second_tunnel_then_releases`

### TLS 监听

- Happy Path：`src/inbound/listener.rs::run_accepts_and_dispatches_http_over_real_tls`；
  `tests/tls_sni_integration.rs::single_tls_listener_selects_certificates_by_sni_and_tunnels_http_connect`
  通过真实 `rove` 进程验证同一 IP:port 按两个 SNI 返回不同叶证书，两条连接随后都能完成
  HTTP CONNECT 并双向传输字节；未命中的 SNI 回退默认证书。
- 失败路径：`src/inbound/listener.rs::run_reports_bind_errors_for_invalid_address`、
  `src/tls.rs::cert_and_key_loaders_report_missing_or_empty_files`；
  `tests/tls_sni_integration.rs::duplicate_sni_mapping_fails_startup` 与
  `certificate_that_does_not_cover_sni_fails_startup`、`certificate_without_server_names_fails_startup`
  验证重复域名、证书 SAN 不匹配和空名称列表均使真实进程 fail-closed 非零退出。
- 本地 Docker 验收：`./scripts/accept-local-tls-sni.sh` 在主机 `18443` 端口验证两个 SNI
  返回各自证书，并通过两条 HTTPS 代理连接分别完成 HTTP CONNECT。

### 认证与过期校验

- Happy Path：`src/inbound/http.rs::authenticates_username_and_password_containing_special_characters`
- 失败路径 / 角色：`src/inbound/http.rs::rejects_expired_users_before_policy`（过期用户）、
  错误密码拒绝（HTTP/SOCKS5 失败用例）；常量时间比较
  `src/engine.rs::constant_time_eq_matches_string_equality`

### 策略决策与规则匹配

- Happy Path：`src/policy/domain.rs::suffix_matches_subdomains` / `full_and_keyword`、
  `src/policy/ip.rs::single_and_cidr` / `many_exact_hosts_keep_or_semantics`、
  `src/model.rs::v4_first_match_keeps_declaration_order_on_overlap` /
  `v4_indexed_first_match_agrees_with_linear_scan`（索引与线性扫描对同一 host 集同结果）、
  `tests/snapshot_v4_integration.rs::overlapping_routes_resolve_in_declaration_order`
- 失败路径（fail-closed）：`src/model.rs::decide_blocks_when_user_or_group_is_missing`、
  `tests/proxy_integration.rs::http_connect_blocked_by_policy_returns_403_without_dialing_out`
- 角色：block 组用户被拒 vs direct 组用户放行（`proxy_integration` 中不同 group 的引擎构造）
- 复杂度回归：`src/model.rs::v4_many_full_routes_miss_stays_sublinear`
  （2000 条 `full:` 路由 × 20000 次未命中必须低于 80 ms，锁住 O(n) 回潮）

### 出站（direct / HTTP upstream / SOCKS5 upstream）

- Happy Path：`src/outbound/mod.rs::direct_connect_tunnels_bytes` /
  `http_upstream_connects_with_basic_auth_and_tunnels` / `socks5_upstream_connects_with_auth_and_tunnels`
- 失败路径：`http_upstream_refusal_is_reported`、`socks5_upstream_failures_are_reported`、
  `tls_upstream_with_self_signed_cert_is_rejected_by_default`（默认拒绝自签名）；
  访问日志分阶段 `tests/proxy_integration.rs::http_connect_unresolvable_host_records_dns_stage` /
  `http_connect_refused_port_records_dial_stage` /
  `http_connect_upstream_tls_handshake_failure_records_tls_stage`
- 角色：upstream Basic 认证 / SOCKS5 用户名密码（Happy Path 用例内验证）
- 恢复/回滚：`tls_upstream_with_skip_cert_verify_accepts_self_signed_cert`
  （逐 upstream 显式开关，验证默认关、显式开两种状态）

### 每用户限速

- Happy Path（不限速快路）：`src/io.rs::splice_reports_byte_counts_on_unthrottled_fast_path`
- 限速生效：`tests/proxy_integration.rs::http_connect_down_rate_throttles_target_to_client_bytes` /
  `http_connect_up_rate_throttles_client_to_target_bytes`
- 角色：限速用户 vs 零速率用户走 64 KiB 无限速快路（两组用例对照）

### 连接数限制

- 全维度：`tests/proxy_integration.rs::http_connect_max_connections_rejects_second_tunnel_then_releases` /
  `socks5_max_connections_rejects_second_tunnel_then_releases`（拒绝即失败路径，释放即恢复）

### 控制面快照同步 / 缓存 / 热替换

- Happy Path：`src/sync/mod.rs::sync_once_applies_remote_snapshot_and_saves_cache`、
  `load_cache_accepts_valid_snapshot`、`load_cache_accepts_legacy_userdata`
- 失败路径：`sync_once_rejects_invalid_remote_snapshot_without_overwriting_cache`、
  `load_cache_reports_invalid_snapshot_compile_error`、`load_cache_rejects_oversized_file`
- 恢复/回滚：无效快照不覆盖缓存（同上）、temp-then-rename 原子写
  `save_cache_round_trips_valid_snapshot` 与私有权限 `save_cache_writes_private_file_permissions`、
  304/旧版本不替换 `sync_once_treats_304_and_stale_versions_as_no_update`
- 编译门禁：`src/model.rs::compile_rejects_unknown_user_group` 等 `compile_*` 系列、
  node_overrides 覆盖 `compile_applies_node_specific_override_for_matching_node_id`
- 双角色：合法 token 同步成功（Happy Path 系列）vs 控制面 401/403 拒绝 token 时
  fail-closed —— 同步失败、继续热服务已加载快照、缓存文件逐字节不变
  `sync_once_rejected_token_fails_closed_without_touching_cache`
- 进程级 E2E：`tests/snapshot_sync_integration.rs` 拉起真实 `rove` 进程：远程快照热替换后
  block 生效、坏快照不覆盖缓存、401 保持旧快照继续服务。

### Snapshot schema v4

- Happy Path：`tests/snapshot_v4_integration.rs` 覆盖 egress A/B、单 backend/chain、direct、
  block、default egress/direct、overlap/order、IP/CIDR、book 与 sniff safety。
- 失败路径：同文件 `strict_rejections_fail_closed`、`node_override_introducing_new_egress_fails_closed`；
  `src/sync/mod.rs::sync_once_rejects_v4_missing_refs_without_replacing_snapshot_or_cache`。
- inspection：`src/mqtt.rs::user_policy_query_exposes_v4_routes_and_named_egresses_without_credentials`。
- public validator：`tests/snapshot_validator_integration.rs` 覆盖 file/stdin、node override、
  addrbook、decode/compile/read/arguments 失败阶段与凭据安全 JSON。

### 健康探针与 listener readiness

- Happy Path：`tests/health_integration.rs::health_endpoints_report_snapshot_and_sustained_control_plane_failure`
  验证已加载快照时 `/healthz` 与 `/readyz` 的响应。
- 失败路径：同一 E2E 验证控制面持续不可达后 `/readyz=503`；
  `tests/health_integration.rs::configured_listener_bind_failure_exits_nonzero` 验证显式 listener
  端口冲突时节点启动失败。
- 恢复/生命周期：`src/health.rs::readiness_tracks_required_data_plane_liveness`、
  `readiness_distinguishes_starting_ready_unreachable_and_draining`。

### MQTT 运维通道

- Happy Path：`src/mqtt.rs::user_policy_query_replies_without_passwords`、
  `sync_command_accepts_empty_payload_and_syncflag_aliases`
- 失败路径：`rejects_bad_reply_topics`、`user_policy_query_reports_missing_user`、
  `sync_command_throttle_allows_first_and_rejects_second`
- 拨测/诊断：`probe_trace_command_arms_valid_requests_and_rejects_bad_ones`、
  `src/trace.rs::armed_probe_reports_once_on_match`、
  `src/diagnostics.rs::record_publishes_events_only_for_matching_active_sessions` /
  `events_never_leak_credentials` /
  `event_type_from_candidate_maps_stages_and_skips_parse`
- 恢复/回滚：`src/diagnostics.rs::sweep_expired_emits_summaries_and_clears_sessions`、
  `cancel_unknown_session_returns_none`、`start_enforces_global_and_per_user_caps`
- 进程级 E2E：`tests/mqtt_integration.rs` 经真实 TCP MQTT broker 拉起 `rove`，用户策略查询
  回包不含密码。

### 结构化访问日志

- Happy Path：`tests/proxy_integration.rs::access_log_file_records_bytes_for_successful_http_tunnel`、
  stats 记录 `src/access_log.rs::access_log_stats_record_json_uses_kind_stats_and_gauge_fields`
- 失败路径：队列饱和丢弃计数 `record_drops_and_counts_when_channel_saturated`、
  syslog 卡死超时 `syslog_tcp_send_times_out_on_stalled_peer_instead_of_hanging_forever`
- 脱敏：`record_from_candidate_carries_bytes_and_never_leaks_secrets`
- 恢复/回滚：轮转清理 `sweep_removes_files_older_than_retention_and_keeps_recent`、
  `sweep_on_missing_directory_is_a_no_op`

### TCP 首包 observe-only 识别

- Happy Path：`tests/proxy_integration.rs::http_connect_observe_sniff_records_host_without_changing_tunnel_bytes`、
  `socks5_connect_observe_sniff_records_host_without_changing_tunnel_bytes`、
  `tests/tuic_integration.rs::tuic_connect_observe_sniff_records_host_without_changing_stream_bytes`
- 失败路径：`tests/proxy_integration.rs::socks5_connect_observe_sniff_forwards_unsupported_payload_and_counts_outcome`
  验证不可识别 payload 原样转发并记录 `unsupported`；`src/sniff.rs` 的 `passive_observer_*` 单测覆盖
  timeout、limit、incomplete、畸形与精确回放。
- 配置边界：`src/config.rs::listener_sniff_defaults_off_and_parses_observe_bounds` /
  `listener_sniff_rejects_invalid_limits_and_modes`
- 隐私/基数：`src/access_log.rs::record_from_candidate_carries_bytes_and_never_leaks_secrets` /
  `src/stats.rs::sniff_outcomes_are_counted_per_listener_without_domain_labels`

### TUIC sniff route 双候选策略

- Happy Path：`tests/tuic_integration.rs::tuic_route_unmatched_sniff_replays_captured_prefix_to_requested_ip`、
  `tuic_route_sniffed_proxy_selects_egress_but_dials_requested_ip`
- 失败路径（fail-closed）：`tests/tuic_integration.rs::tuic_route_sniffed_block_prevents_requested_ip_dial`
  验证 sniffed block 在任何目标拨号前拒绝；`src/model.rs::decide_prefers_special_upstream_then_default_upstream`
  覆盖 requested block / sniffed block 任一命中即 block、IP 目标按 sniffed 域名选出口、显式域名不被
  sniffed proxy 规则改路。
- 捕获边界：`src/sniff.rs::prefix_capture_returns_match_and_every_consumed_byte` /
  `prefix_capture_times_out_without_waiting_for_stream_eof` /
  `prefix_capture_enforces_limit_and_preserves_captured_byte`
- 配置边界：`src/config.rs::tuic_listener_accepts_sniff_route_mode`

### HTTP/SOCKS5 sniff route 双候选策略

- Happy Path：`tests/proxy_integration.rs::http_connect_route_unmatched_sniff_replays_captured_prefix_to_requested_ip`、
`http_connect_route_sniffed_proxy_selects_egress_but_dials_requested_ip`、
`socks5_connect_route_sniffed_proxy_selects_egress_but_dials_requested_ip`
- 失败路径（fail-closed）：`http_connect_route_sniffed_block_prevents_requested_ip_dial`、
`socks5_connect_route_sniffed_block_prevents_requested_ip_dial`
验证 sniffed block 在任何目标拨号前拒绝；与 TUIC 共用 `decide_with_sniff` 双候选规则。
- 配置边界：`src/config.rs::listener_sniff_accepts_route_mode`

### SNMP agent（v2c + v3 USM）

- Happy Path：`tests/snmp_integration.rs::getnext_walk_and_getbulk_walk_return_the_same_tree`、
  `byte_counters_are_monotonic_as_traffic_accumulates`
- 失败路径：`wrong_community_gets_no_answer_over_udp`、
  `source_addresses_outside_the_allowlist_get_no_answer`、
  `port_conflict_surfaces_as_bind_error_not_panic`（SNMP 故障不影响转发）
- 角色：正确 vs 错误 community；v3 discovery `v3_discovery_over_udp_returns_unknown_engine_ids_report`；
  fail-closed 校验 `src/config.rs::snmp_validate_enforces_fail_closed_rules`
- 恢复/回滚：`src/snmp/usm.rs::engine_boots_increment_across_restarts_and_reset_on_engine_change`

### 反向 hop（QUIC）+ reverse/2 UDP relay

- Happy Path：`tests/reverse_hop_integration.rs::reverse_tunnel_transfers_bytes_both_directions`、
  `udp_association_relays_through_hop_to_echo`
- 失败路径：`open_without_registered_hop_fails_closed`、`registration_with_wrong_token_is_rejected`、
  `hop_target_connect_failure_is_isolated_to_one_stream`、
  `udp_open_fails_closed_for_hop_without_udp_cap`、`udp_open_fails_closed_without_reverse_plane`
- 角色：正确注册 token vs 错误 token
- 恢复/回滚：`duplicate_hop_id_is_rejected_under_reject_policy`、
  `replace_policy_swaps_in_the_new_session`
- 日志脱敏：`hop_access_log_records_reverse_decision_without_secrets`

### 反向公网入口（TCP/UDP）

- Happy Path：`tests/reverse_ingress_integration.rs::relay_forwards_tcp_and_1200_byte_udp_with_client_metadata`
  同时覆盖真实 QUIC 会话、TCP 双向流、UDP datagram、1200B MTU 保证值与真实客户端地址；
  `relay_preserves_end_to_end_tls_termination_at_rove` 证明 relay 不终止用户 TLS；
  `relay_carries_a_real_tuic_quic_handshake_over_udp` 验证真实 TUIC/QUIC 握手穿过 UDP relay。
- 失败路径：`src/ingress/frame.rs::duplicate_and_unknown_headers_fail_closed`、
  `reader_stops_before_raw_payload_and_enforces_limit`、
  `tests/reverse_ingress_integration.rs::relay_rejects_bad_token_unknown_listener_and_unauthorized_port`。
- 角色/凭据：上述 E2E 覆盖正确 token 与错误 token；relay 配置要求每 node 独立凭据。
- 恢复/回滚：`tests/reverse_ingress_integration.rs::dynamic_tcp_lease_restores_the_same_port_within_grace`
  验证 session 断开释放 socket，并在 grace 窗口内恢复同一动态端口；connector 使用有界指数退避且不缓存公网流量。
- 关联与脱敏：`src/access_log.rs::reverse_ingress_metadata_is_correlation_safe_and_secret_free`。

### TUIC v5 前端

- Happy Path：`tests/tuic_integration.rs::tuic_connect_tcp_relays_to_echo`、
  `tuic_packet_relays_udp_through_reverse_hop`
- 失败路径 / 角色：`tuic_bad_token_closes_connection`、
  `src/engine.rs::authenticate_tuic_fails_closed_on_bad_inputs` vs
  `authenticate_tuic_accepts_correct_uuid_and_token`

### Subnetra hub / spoke

- Happy Path：`tests/subnetra_netstack.rs::tcp_stream_flows_both_ways_over_the_overlay`、
  `tests/subnetra_http_over_overlay.rs::http_connect_is_proxied_over_the_subnetra_overlay`、
  `tests/subnetra_egress.rs::outbound_subnetra_upstream_dials_over_the_overlay`
- 失败路径（fail-closed 不回落直连）：
  `tests/subnetra_egress.rs::outbound_subnetra_rejects_non_overlay_host_when_enabled`
- 线兼容 KAT：`tests/subnetra_conformance.rs` 全套（逐字节向量校验）
- 压力/恢复：`tests/subnetra_netstack.rs::concurrent_connect_burst_beyond_listen_backlog_succeeds`、
  `bulk_transfer_survives_flow_control`

### 独立 hop 二进制（rove-hop）

- Happy Path：`tests/rove_hop_integration.rs::https_forward_proxy_tunnels_after_trusted_tls_and_cleans_up`、
  `socks5_forward_proxy_tunnels_after_authentication`
- 失败路径：`tests/rove_hop_integration.rs::https_forward_proxy_rejects_untrusted_tls_bad_credentials_and_failed_upstream`
  覆盖未受信任 TLS、错误凭据的 407 和出站连接失败的 502。
- 角色：同一失败路径覆盖有效 `gate-service` 凭据与错误凭据。
- 恢复/回滚：`https_forward_proxy_tunnels_after_trusted_tls_and_cleans_up` 和
  `socks5_forward_proxy_tunnels_after_authentication` 均验证客户端关闭后目标连接被关闭，不遗留出站隧道。

### hop MQTT egress doctor

- Happy Path：`tests/hop_mqtt_integration.rs::hop_mqtt_doctor_reports_tls_failure_after_tcp_ok_without_leaking_secrets`
  经真实 `rove-hop` 进程 + 假 MQTT broker + 明文 TCP 目标，断言回包与 `doctor egress --json`
  同构（`dns/route/tcp/tls/http`），且 `tcp.status=ok`、`tls.status=failed`。
- 失败路径：`hop_mqtt_doctor_rejects_missing_target_without_running_probe` 缺 `target` 回
  `bad_request` 且不跑探测；`src/hop_mqtt.rs` 丢弃前缀外 / 含通配符的 `reply_topic`。
- 角色/凭据：同一 Happy Path 断言回包不含 hop 代理密码与 MQTT 密码。
- 恢复/回滚：doctor 是只读一次探测，不写快照或热路径状态；并发第二请求回 `throttled`，不排队打爆 hop。
- 默认关闭：`src/bin/rove-hop.rs::mqtt_doctor_defaults_off_and_parses_broker`。

### 优雅停机

- Happy Path：`tests/shutdown_integration.rs::node_exits_cleanly_on_sigterm` / `node_exits_cleanly_on_sigint`
- 停止接收与恢复语义：`tests/shutdown_integration.rs::sigterm_stops_accepting_and_allows_inflight_tunnel_to_finish`
  验证停止新接入后在途隧道仍可完成。
- 有界失败路径：`tests/shutdown_integration.rs::graceful_shutdown_forces_exit_after_drain_timeout`
  验证超过窗口后强制结束且进程按时退出。

### 配置解析（TOML）

- Happy Path / 默认值：`src/config.rs::load_applies_defaults_and_effective_mqtt_values`、
  `load_custom_listener_mqtt_and_log_settings`
- 失败路径：`src/config.rs::load_reports_read_and_parse_errors`、
  `load_rejects_zero_health_and_shutdown_timeouts`、
  `load_accepts_full_snmp_config_and_rejects_invalid_ones`、
  `snmp_validate_enforces_fail_closed_rules`

### rove-addrbook（`.rab` 地址数据集 + `book:` 规则 scheme）

- Happy Path：`tests/addrbook_integration.rs::http_connect_to_book_blocked_category_is_rejected`
  经真实 HTTP CONNECT 链路验证 `book:blocked-nets` 分类阻断（403）；
  `http_connect_passes_when_book_category_not_selected` 验证未选中分类不泄漏进判定、
  隧道端到端可通字节；`book_domain_block_applies_to_requested_host` 验证域名类分类命中。
- 失败路径（fail-closed）：`snapshot_with_unknown_book_category_is_rejected` 验证未知分类
  拒绝整个快照；`snapshot_with_book_rules_but_no_book_is_rejected` 验证配置了 `book:` 规则
  但节点无 `[addrbook]` 时快照编译失败；`book_rules_require_snapshot_schema_v3` 验证旧
  schema 明确拒绝新规则语义；`startup_with_unloadable_artifact_is_a_hard_error` 验证
  缺失/损坏工件启动即拒绝。
- 角色/凭据：无独立用户角色——addrbook 只提供地址数据，判定归属沿用组策略
  （`proxy_integration` 已覆盖组/用户角色结局）。
- 恢复/回滚：`corrupt_artifact_on_reload_keeps_previous_book` 验证单字节损坏被校验和
  拦下且旧书继续服务；`addrbook_swap_recompiles_snapshot_atomically_and_rejects_bad_books`
  验证换书 = 重编译最近快照原子替换（旧规则语义消失、新语义生效），且新书缺分类时
  换书失败、书与快照都保持不动。
- 协议稳定性：`golden_vector_matches_deterministic_rebuild` 从 `tests/fixtures/addrbook/`
  重建并与提交入库的 `tests/vectors/addrbook_v1.rab` 逐字节比对 + 钉住 SHA-256——
  编码器输出漂移即测试失败（格式破坏门禁，见 `docs/addrbook-format.md`）。
- 单元层：`src/addrbook/format.rs` 覆盖编解码 roundtrip、确定性、坏 magic/版本/校验和、
  section 重叠/缺失、字符串池放大、伪造大计数/堆预算、语义违规拒绝与单字节变异不 panic；`src/addrbook/book.rs`
  覆盖层级子孙展开（含同前缀
  兄弟隔离）、三种域名匹配、双栈 IP 区间；`src/addrbook/builder.rs` 覆盖重叠 CIDR 扫描线
  合并、位图并集与 mapped IPv6 规范化；`src/addrbook/sources.rs` 覆盖六种数据源解析
  （v2fly 全局 affiliation 先于选择性 include、目录逃逸/展开预算拒绝、空源拒绝、
  Provider 缺字段/坏 CIDR 拒绝）；
  `src/policy/mod.rs` 覆盖显式规则与 `book:` 规则组合、selector 共享语义。

## 维护规则

- **新增一级能力**：先在本表加一行（允许先全 ⚠️ 表达 TDD 红灯状态），实现完成时五个维度
  必须落到真实锚点，且 E2E 列必须指向 `tests/` 下的集成测试。
- **修改既有能力**：若行为、失败边界或角色语义变化，同一 PR 内更新对应行。
- **测试重命名/删除**：同一 PR 内修订本表引用，禁止留下悬空锚点。
- **消除缺口**：表中 ⚠️ 项是显式技术债；对应方向在 `docs/roadmap.md` 标记完成前，
  必须先把 ⚠️ 转为 ✅。
- **诚实原则**：不确定是否覆盖的维度写 ⚠️ 待核验，不许写成 ✅；`—` 必须附不适用理由。
