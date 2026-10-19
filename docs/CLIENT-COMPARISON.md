# 一次性双客户端诊断（0.4.4）

`compare` 用于隔离真实详情请求的客户端差异。自动测试完全离线；通过模拟
响应不等于拥有真实 API/view 权限。

准备：从本工程一个已计费、已完成的一次 META/META_ABS/FULL/REF 详情 401
运行创建冻结预览。仅支持其原始单一数字 Scopus ID，不改 ID、view 或 key 引用。

```sh
scopus-access compare --source-run-info <failed-detail-execution/run-info.json>
```

预览不读 Keychain、不联网、不准入。审核输出及冻结任务后，明确批准两次诊断请求：

```sh
scopus-access compare --run-info <comparison-preview/run-info.json> --execute-live
```

预算严格为 **2 次**：CLI 一次，然后独立 `http.client` 一次，零重试。
两次在同一进程顺序执行，只读一次项目 Keychain，在内存共用同一值；不输出或保存
密钥指纹。参考客户端自行构造固定 GET URL 和认证头，不调用 CLI 请求构造函数、
URL 编码器、urllib 或 transport。双方使用同一 JSON Accept、User-Agent、API-key-only
认证、直接 HTTPS、系统信任库、30 秒超时、不采用环境代理、不跟随重定向。

同机顺序执行控制了程序路径，但不能独立证明 NAT/VPN 出口在两次请求之间没有变化，
也不能证明出口被 Elsevier 识别为某机构；结果明确保留这个限制。

账本用 BEGIN IMMEDIATE 一次预约两次请求，分别在请求前写 ATTEMPT/扣款，再记
OUTCOME 和真实配额头。不会把 401 改成 NORMAL 来准入。要求原详情桶最新的已知
状态为 HTTP_401_FAIL_CLOSED 且保守余额足以覆盖两次；每个 key/API/窗口最多一对。
这是一项独立的有界诊断授权，普通检索及初次 preflight 的门禁不变。
CLI 即使收到 401，仍可执行明确批准的参考对照；429、重定向、传输异常、未知状态
或确定额度不足会停止。异常发送照常计费，禁止自动重放。

每个冻结预览有进程锁与执行标记，重复启动不再预约或发送。`execute`/`run`/普通
`resume` 不会把比较任务当作两条不同文献来取数。执行 run-info 始终保留。
0.4.4 支持“已准入但未开始发送”的显式继续：

```sh
scopus-access compare --run-info <original-comparison-preview/run-info.json> --resume-unused --execute-live
```

它复用 marker 指向的原 execution、未过期授权和同一个两请求预约，不重新准入。
要求原项目、冻结包、配置/授权哈希与预算完全相同，累计请求为零、无 ATTEMPT，
也无响应页、checkpoint、receipt、事件或比较输出；未登记 raw 文件同样拒绝。
任何发送尝试（即使传输失败）、授权过期、哈希改变或证据不明均拒绝。两个并发
继续进程通过同一锁协调，最多一个发送原先那对请求。

0.4.4 修复比较入口漏传 `policy.keychain_service` 的问题；工程绑定 service/alias
始终来自校验过的原策略，旧配置继续使用既有应用 service，不搜索或借用其他 key。
不会因本地凭据查找失败要求重新初始化、替换 key 或清除账本。

成功原始响应和每个客户端的转换 JSONL 只在 `restricted_metadata/scopus/` 内保存。
错误只保留白名单服务错误及响应摘要，不保存可能回显凭据的错误原文。安全报告逐项
给出原始/转换字段非空数和百分比、返回 ID 是否匹配、作者数组长度、声明作者数、
作者 ID 缺失/重复及数值是否一致。数量一致仍不等于独立证明完整作者/参考文献列表。
API 转换结果不代表网页原生导出。

| 结果 | 允许的判断 |
| --- | --- |
| 参考 200，CLI 失败 | 核对固定 URL/头、真实 transport、凭据绑定、运行时/出口差异；尚不能只凭结果认定某一行代码有错 |
| 两者 401/403 | 故障未局限于 CLI；向服务商/机构核验实际机构识别和应用/API/view 权限；不反复探测 |
| 两者 200 | 对这一个 ID/view 实际比较字段；不能推断其他文献、view、完整参考文献或权限范围 |

一次 200 如果没有字段，报告零覆盖率；不能推断文献本身无摘要或关键词。
任何一方访问拒绝，都不会由另一方最后的 200 静默解锁常规取数。
