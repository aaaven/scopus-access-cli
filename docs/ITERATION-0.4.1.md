# 0.4.1：诊断可操作性与请求边界

本次修复与测试全部离线；不读取真实 Keychain，不访问 Scopus，不修改使用者工程的
配置、账本或历史证据。不以离线测试代替实网多页或授权验证。

| 事项 | 实现 | 离线证据 |
|---|---|---|
| 本地余额不一致漏报 | diagnostics 白名单补 `RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING`；ledger/integration/runner 传递本次尝试后的本地余额；events 限定非负整数 | test_iteration_041：服务器 99、本地 98，保存成功页、保留两个计费尝试，resume 不继续发送 |
| 请求头清理 | client 的 finally 覆盖 reveal 后校验/能力签发；UrllibTransport 覆盖快照校验、Request 构造、HTTP 错误、open/read 异常 | test_iteration_041：校验/能力签发/claim/构造/open/read 失败及成功、401；检查已创建副本为空，输出不含秘密 |
| 最终 urllib 请求契约 | 沿用固定 HTTPS 主机、无代理、无重定向及白名单头部；没有切换认证模式 | test_iteration_041：模拟最终 opener，校验 numeric-ID + META_ABS、项目 alias、API key 仅在头部、调用前已有持久 ATTEMPT；原有 proxy/redirect 测试保留 |
| 独立诊断准备 | diagnose 默认离线，冻结原查询及原始/传输文本哈希；固定 STANDARD/1 请求/1 条/0 重试；新 grant 才执行 | test_iteration_041：预览零 secret/transport，账本逐条不变，已用需 correction，源哈希改变/401 前序拒绝，多行原文不变 |
| 防重复后继 | release 固定 predecessor；底层 BEGIN IMMEDIATE 再核对最新前序、HTTP outcome、实际请求/剩余预算；不读回或重置旧任务 | test_preflight_ledger 的并发事务；test_installed_cli 两个真实子进程各持新预览，只有一个额外发送；重复执行原有测试保持 |

## 暂停后使用顺序

1. `inspect --run-info <原文件>` 查看 telemetry、current_bucket_reason、保存页数、原预算和 next_actions。current_bucket_reason 是**当前桶**的原因，可能晚于该 run；历史 telemetry 仍按原事件保存，不会回写。
2. 如果原预检在读 key 时失败且未发出请求，用原 `resume --run-info ... --execute-live`。该路径核验原授权仍有效，沿用原预约。
3. 配额未知但独立诊断尚未使用时，`diagnose --run-info ...` 只生成预览。它不扩大原任务，执行需对新预览单独批准。
4. 独立诊断已经使用时，默认拒绝。操作者核对实际请求修正、网络环境变化或供应商指引后，可明确指定 `--correction request_fix|environment_change|provider_guidance`。必须引用**最新已完成诊断**的 run-info，成功核验后生成新预览；前序仅能被后继使用一次。
5. 核对预览并明确批准后，用 `execute --run-info <新预览> --execute-live`。可在宿主允许时明确加 `--terminal`，不是权限拒绝后的自动替代途径。额度仍未知时继续暂停；只有被接受的真实遥测才能恢复普通准入。
6. 原任务有剩余预算和未取页时，再 `resume` 原文件；完成页不会重发。预算耗尽不能在 resume 中追加。零活动证据不完整时不猜测重发。

后继预览保留控制文件 `diagnostic-lineage.json` 的来源哈希、前序引用及固定 correction
枚举；批准的 release 自身哈希固定 predecessor，事务准入再验证账本中的前序。
并发生成多个草稿不会增加已预约的额度。任意后继都须重新明确批准并单独计费；
没有实际变化时不应连续调用，以免不断消耗独立诊断。

## 认证与实网未决项

当前实现仅使用项目 Keychain 引用对应的 `X-ELS-APIKey`，未增加 insttoken、authtoken
或 OAuth。最终 urllib 边界的离线通过仅证明请求构造契约，不证明机构授权、API
出口 IP 或 META_ABS/COMPLETE/REF 权限，也不能确定历史 401 根因。

若需要定位 401，下一步应单独批准一个两请求、零自动重试的对照验收：同一网络、
同一 key、同一已冻结 ID/view，CLI 一次与独立最小参考构造一次。两次均必须预先
计费、限额、留证，参考请求不允许成为未记账的旁路。此版本未提供独立参考实网
执行器，也没有执行该验收。只有供应商或该对照证明确需额外认证时，再设计具有
独立 Keychain 引用、固定头部及冻结授权的认证 profile；不自动猜测或尝试 token。

可对照 [Elsevier 认证文档](https://dev.elsevier.com/tecdoc_api_authentication.html)
及 [Abstract Retrieval API](https://dev.elsevier.com/documentation/AbstractRetrievalAPI.wadl)。
文档说明不构成当前凭据的权限证明。
