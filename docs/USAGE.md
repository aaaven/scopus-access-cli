# 使用说明

当前版本 0.3.2。安装步骤见[首页](../README.md#安装一次)。命令面向终端、脚本和
本机编码代理；不存在聊天身份、跨机器服务或外部通知步骤。

## 1. 一个本机工具，多个工程

在每个实际工程根目录运行一次 `scopus-access init`。它为该目录生成稳定 UUID、
凭据 alias、Keychain label 和共享数据库。工程名称只用于显示。同一工程内的不同
终端/对话/进程使用同一配置、账本和结果；独立工程分别初始化各自 key。

查找从当前物理目录向上进行，最近的 `.scopus-access` 标记优先。较近标记缺少
policy、JSON 损坏或绑定不匹配时停止，不跳过它借用上层凭据。没有配置会提示 init。
没有环境变量、用户目录或源码目录默认配置回退。

```sh
cd /path/to/project
scopus-access init
mkdir -p notes/drafts
cd notes/drafts
scopus-access usage
```

上面的 `usage` 仍然读取 project 的同一个 control.sqlite。

## 2. 初始化和 Keychain

在交互终端运行 `init` 时，直接提示输入。在 GPT/自动化的无交互终端环境中，仍运行
同一个 `scopus-access init`；工具自动打开 macOS Terminal 并等待结果。使用者只在
新窗口粘贴 API key 后按回车，不必复制 shell 命令；Ctrl-C 可取消。首次 macOS 可能
要求允许调用方控制 Terminal。没有可用的桌面会话或权限被拒绝时，明确失败并停止。

输入不回显，通过 Apple Security.framework 直接写入 Keychain，不通过带 key 的
子进程、argv、环境变量或临时文件中转。GPT 收到的仍是原有初始化 JSON 字段，不包含
key。终端子进程只执行初始化，不能执行查询；进程间只交换有界的非秘密完成状态。
受保护的完成文件位于本工程忽略的控制目录，正常结束后删除；不存输入正文。
macOS 可能要求允许系统凭据访问；这与远端 Scopus 权限是两件事。

初始化不读取远端额度，不消耗 API 请求。初始配额显示 `UNVERIFIED`。
重复初始化复用既有 ready 绑定，不创建新账户、不覆盖 key、不清空历史。
取消或中断后可以重跑；若 key 已成功写入，重试只查条目元数据，避免再次覆盖。

当前没有换 key 命令。不要通过删除配置、数据库或重新 init 绕过已有记录。

自动弹窗最多等待 5 分钟；取消、终端关闭或等待超时均不增加额度，原绑定保留。
若窗口仍开着，可先完成或关闭，再由 GPT 重跑 init；已完成的配置会直接复用。
同一工程同时初始化只允许一个等待中的 Terminal 窗口，其他调用返回
`TERMINAL_INIT_IN_PROGRESS`。已有 ready 绑定，或中断后已存在对应 key 的情况不弹窗，
不重写 key。成功 JSON 仍区分 initialized/reused，UNVERIFIED 仍表示尚未向 API 验证。

若配置/数据库缺失或复制了工程目录，应停止操作并恢复原状态；工具不会重建一份假余额。
目录改名保留项目 ID，但旧运行中固定的绝对路径不会自动迁移。

## 3. 准备精确查询

使用编辑器在调用工程的 `restricted_metadata/query.txt` 保存 UTF-8 查询，可多行排版。
文件内容就是你要发送的完整 Scopus 表达式；不把 key 放在文件中。本文不预选研究
主题，也没有自动科学替代、去重、改写或按年份拆分。

支持 LF、Windows CRLF 和 Tab，首尾排版也完整保留。冻结查询包同时保存 `query`
（实际发送文本）及 `provenance`：`source_text`、`source_sha256`、`transport_sha256`、
`schema_version=1.0` 和 `transformation=identity-utf8-v1`。两份文本当前相同；没有
单行转换或空白合并，因而引号和花括号中的空白、甚至换行也不会被工具改写。
URL 百分号编码只是传输封装，服务端解码后的查询与原文相同；具体语法能否被
Scopus 接受仍由 API 决定。工具不在失败后自动转换并重发。

NUL 等禁止控制字符（小于 32，但 LF/CR/Tab 除外）以及 DEL 会给出
`QUERY_INVALID_CONTROL`、`codepoint`、`character_position`、`line`、`column`。
位置均从 1 开始，按 Unicode 字符计算；CRLF 算一个换行，Tab 算一个字符，
列号不按终端视觉宽度展开。错误中没有查询片段。空查询、超限和非法 UTF-8
也有单独的 QUERY_* 错误码。非法查询在凭据读取和网络之前停止。

例如你可以自行确定 `DOI(...)`、`TITLE(...)` 或 `TITLE-ABS-KEY(...)` 条件。
工具只检查已实现的请求边界，不保证你选择的检索式适合研究问题。
不要使用 `examples/synthetic-*` 作为真实查询；这些是离线测试合成材料。

## 4. 首次检查访问与配额

```sh
scopus-access check --query-file /path/to/project/restricted_metadata/query.txt
```

这是预览，零网络、零 key 读取。JSONL 输出给出 `run_info_path`、文件 hash 和边界。
明确同意该查询后有两种入口，**选择其一，不要为了同一次检查都执行**：

```sh
# A：执行刚才的冻结预览
scopus-access execute --run-info /path/to/check-preview/run-info.json --execute-live

# B：另行冻结当前输入文件，并立即执行一次
scopus-access check --query-file /path/to/project/restricted_metadata/query.txt --execute-live
```

每次 `check` 上限 1 请求、1 条结果、STANDARD、零重试。尚无观测或额度状态需要
核验时，走有界诊断路径；已观测的正常额度走普通原子预留，不豁免计数。
重复诊断仍受限制，不能通过重复执行指令无限探测。

返回 HTTP 200 并不保证命中记录；零命中可能只是查询没有匹配。若查询有多条匹配，
`check` 达到一条上限可能以暂停退出码结束，仍需结合实际 HTTP 状态与结果判断。
HTTP 成功但缺少有效配额头时会记录 `QUOTA_TELEMETRY_UNKNOWN`，不会编造余额。

## 5. 有界检索

```sh
scopus-access search --query-file /path/to/project/restricted_metadata/query.txt --max-requests 2 --page-size 25
scopus-access execute --run-info /path/to/search-preview/run-info.json --execute-live
```

`--pages` 是 `--max-requests` 的兼容别名。简化 Search 使用 offset，从 start=0 开始。
默认 STANDARD、offset、1 请求、每页 200 条；请求预算允许显式 1–1000。STANDARD 每页最多 200，COMPLETE 最多 25。超过 offset 范围须显式选择 cursor，权限和实际服务限制仍需验证。
实际发送可能少于上限，例如结果已经耗尽或额度/存储检查要求停止。
零自动重试、零重定向，不换 key、不切 endpoint、不改查询。

普通 search 要求已有可用的真实配额观测。无法准入时不会先读取 key 试探。
所有必要桶一次事务预留；每个请求发送前写尝试，之后追加结果证据。
多个本机进程通过 SQLite `BEGIN IMMEDIATE` 和进程锁共用账本，避免争抢相同余额。
相同 release 不允许重复消费；新一次 search 则是新任务，会重新计费，不能当作恢复。

## 6. 理解输出与文件

终端输出是逐行 JSON；每行可以独立解析。常见字段包括 `command`、`status`、
`network_calls`、`secret_reads`、`run_info_path`、`parent_run_id`、`requests_attempted`、
`records_ref` 和 `stop_reason`。不是每类事件都包含全部字段。

当 stdin 和 stderr 均为交互终端时，stderr 另显示操作结果、失败步骤及下一步；
stdout 的原有 JSON 和退出码保持兼容。初始化完成会提示 key 已存入钥匙串，
并明确 UNVERIFIED 表示尚未联网验证，不是本地初始化失败。重复初始化提示复用。
非交互调用不增加这些人工说明，也不会为说明额外读 key 或联网。

预览生成的 run-info 标记 mode=preview；执行开始前生成一份新的 mode=run 文件。
`prepared` 只表示计划已保存，不表示请求已发送。后续 status/export/resume 必须使用
执行 run-info；尚未准入时可能得到 `RUN_NOT_FOUND`。

```text
.scopus-access/runs/       运行控制文件；包含 hash、边界和引用
restricted_metadata/scopus/
  operations/             冻结查询包
  raw/                    原始响应页
  manifests/              页文件与 hash 的链接
  records/                records.jsonl 及导出元数据
  checkpoints/            分页及恢复证据
  receipts/               完成或暂停回执
```

使用 `records_ref` 相对于该运行的 `project_output_dir` 定位导出文件。
不要把 stdout 当作 bibliographic 数据源；它只包含控制信息。
不将查询、标题、摘要、参考文献或 raw payload 写入控制 SQLite/JSONL/异常。
受限数据目录写入前会检查 allowlist、路径穿越和 symlink 逃逸。

导出是逐记录 JSONL，保留 DOI、EID、标题、期刊等实际字段、来源页/hash 和缺失列表。
STANDARD 不保证摘要、完整作者、关键词、参考文献。字段缺失保留为 null/缺失记录，
不推断补齐，不做科学去重。raw 响应仍是未映射字段的来源。

## 7. 离线状态、导出和用量

```sh
scopus-access status --run-info /path/to/execution/run-info.json
scopus-access export --run-info /path/to/execution/run-info.json
scopus-access usage
```

这些命令不读取 key、不联网、不消耗额度。export 从已经保存并核验的 raw 页生成
本地 JSONL，不重新请求 Scopus。usage 是 SQLite 的可重建派生视图；不生成独立
USAGE.md，也没有可以手工修改的文档余额。

用量中的实际尝试与服务端观测分别保留。一个请求有 ATTEMPT 和 OUTCOME 两类证据，
不能把两行事件计为两次请求。剩余额度为最近一次有效服务端响应的观测，其他客户端
可能已经继续消耗；它不代表账户此刻的全局实时余额。

## 8. 暂停与恢复

```sh
# 先离线看状态
scopus-access resume --run-info /path/to/execution/run-info.json
# 明确继续同一个任务，可能联网
scopus-access resume --run-info /path/to/execution/run-info.json --execute-live
```

恢复沿用原 query、reservation、分页位置和预算。预算耗尽不允许追加；达到查询
上限后的“部分完成”不是要求工具自动多发一页。授权有效期为 1 小时，resume 不续期；
过期、跨配额窗口、已发送但证据缺失/冲突等情况均停止，不自动重发。
不要以重新执行 search 的方式假装延续原预算。

### 首次 check 在读取 Keychain 时失败

若 execution 记录是 `secret_unavailable`，且 `requests_attempted=0`、`pages_completed=0`，
可在解决 macOS 钥匙串授权后按上面的 `resume --run-info ... --execute-live` 继续。
请使用失败执行输出的 run-info，保留原 policy、冻结查询、数据库和受限输出目录。
支持多行查询；恢复只读取原冻结包的来源文本、发送文本及双 hash，不重新读入新的查询。

专用预检恢复核验原授权、预约、失败回执、checkpoint 和所有关联 hash；用量日志须无
任何发送尝试，raw 目录须无响应文件，包括没有登记的文件。只允许 STANDARD Search、
一条记录、总共一次请求、零自动重试。重新执行首次 check 不能绕开已占用标记；不要
删库、改任务类型或清除历史。同一预检的两个本机恢复进程经锁串行校验和执行，第二个
不能重发或把完成状态覆盖为旧失败状态。普通 survey_run 恢复路径保持原有预算逻辑。

`RELEASE_EXPIRED` 明确表示原授权已过期，需要另行显式重新授权；当前没有自动续期或
renew 命令，工具会保留未用预约并停止，不将重新批准视为新增一次额度。

## 9. 退出码和处理

| 退出码 | 含义 |
|---|---|
| 0 | 完成、预览或本地操作成功 |
| 1 | 本地操作错误 |
| 2 | 输入或配置无效 |
| 3 | 实网能力被锁定 |
| 4 | 配额未准入 |
| 5 | 达到请求边界或额度条件而暂停 |
| 6 | 执行失败 |

处理常见情况：

| 现象 | 下一步 |
|---|---|
| command not found | `source ~/.zprofile`；核对 `command -v scopus-access` |
| PROJECT_NOT_INITIALIZED | 在实际工程根执行 init；不要指向其他工程的 key |
| 较近 policy 损坏或数据库缺失 | 恢复原文件；不要删除标记以借用父工程 |
| UNVERIFIED / 遥测不明 | 查看状态，明确批准有界 check；普通 search 不自行探测 |
| HTTP 401/403 | 检查自己的 key 与 API/机构访问权限；工具不会自动换 key 或 endpoint |
| HTTP 200、零记录 | 检查所选查询及总命中数；不是自动等同于鉴权失败 |
| 退出码 5 | 读取 stop_reason、实际 HTTP 状态、已保存页数与剩余预算 |
| 数据已被 Git 跟踪 | 先在工具之外审查并移除跟踪；工具不会替你改 Git 索引 |
| 原工程复制或改名后旧运行不可用 | 路径和物理目录绑定不自动迁移；恢复原位置再操作旧 handoff |

不要把错误码当作追加请求许可。检查/导出失败时应先保留已有证据，避免重复发送。

## 10. 升级、兼容和卸载

`scopus-access install --wheel /absolute/path/to/new.whl` 不读取任何工程配置，
不更改配置、账本、结果或历史。新环境验证失败不会替换旧活动入口。
不要删除基础 Python 安装，否则依赖该解释器的 venv 可能失效。

旧配置通过显式 `--policy /path/to/legacy-policy.json` 使用。此入口不允许覆盖当前
已绑定工程；无工程时也不会自动寻找旧配置。`scopus-fetch` 和底层命令保留兼容。
底层命令的 `--db` 默认取 policy 绑定，不在子目录另建数据库。

发行包名称和旧 Keychain service/application 标识保留兼容；新工程使用通用的
`Scopus Access Tool` service。旧 schema 中的通知/组织字段只用于历史兼容，
没有新的审批或外部通知操作。

卸载工具时只移除 `~/.local/bin/` 下这两个受管理的符号链接、
`~/.local/share/scopus-access/` 和 profile 中的 Scopus PATH 行。
工程数据和 Keychain 条目是独立的，不随 CLI 卸载删除；需要删除时由使用者另行处理。

## 11. 凭据错误诊断

初始化与运行时读取均使用原生 Security.framework，不再用 `security -w` 的进程
stdout 接收密钥。service/alias 与旧配置保持一致；升级不创建或替换条目。

外层保留 `SECRET_UNAVAILABLE`（CLI 设置阶段）或 `secret_unavailable`（运行事件），
附带下列受限字段；系统原始错误文本、成功返回数据和密钥都不会进入日志：

| provider_reason | 解释及处理 |
|---|---|
| credential_not_found | OSStatus -25300；未找到对应条目，检查当前工程绑定 |
| interaction_not_allowed | OSStatus -25308；系统不允许本次交互，改在可授权的本机环境操作 |
| access_denied | OSStatus -128 或 -25293；取消或认证/授权未通过，不推断具体点击或账户状态 |
| keychain_timeout | 本地等待截止，尚无系统返回码；检查授权窗口后再明确操作 |
| keychain_error | 其他情况；有 OSStatus 就原样保留，不猜测“锁定”等原因 |
| credential_already_exists | 写入发现 -25299；未覆盖，保留 pending 后重试检查 |
| credential_input_invalid | 隐藏输入为空或格式无效；在交互提示重新输入 |

`failure_stage` 标识隐藏输入、条目检查、保存、读取、解码或后端加载等阶段；
`provider_backend` 是 `macos_security_framework`、`terminal_input` 或 `unknown`。
`system_error_code` 为原始有符号 OSStatus 整数，没有系统结果时为 null。
不得把退出码或进程 stderr 猜测转换成 OSStatus。

`network_request_sent=false` 表示失败前没有请求发送；true 表示原运行已有完成页；
null 表示已有未能可靠判定发送状态的尝试。原分页的请求计数仍看 `requests_attempted`。
凭据首次读取失败发生于 ATTEMPT 落账之前，因此不消耗一次 API 尝试。

读取默认等待 10 秒（保留原 Python 接口的 timeout_seconds）。系统调用无法被强制
中断：超时后不会发送请求或自动重试，后台晚到的密钥会立即清零丢弃。
这个限制不会被伪装成“用户拒绝”或系统返回的超时状态码。


## 12. 由 GPT 打开 Terminal 执行或恢复

需要 macOS 桌面中的钥匙串授权交互时，GPT 可以直接运行下面的 CLI 入口，
不必让使用者复制 shell 命令。先按前面的步骤预览并取得对具体查询和请求边界的批准。

```sh
# 执行已批准的冻结预览；输出新的 execution run-info
scopus-access execute --run-info /path/to/preview/run-info.json --execute-live --terminal

# 原任务曾因读取 key 失败且未发送请求：继续使用原 execution run-info
scopus-access resume --run-info /path/to/execution/run-info.json --execute-live --terminal
```

这些命令由调用方执行，使用者只需处理可能出现的 macOS 钥匙串授权窗口。
已有 key 不需要再次粘贴。CLI 打开 Terminal、等待完成，并将经过验证的控制事件
（状态、计数、错误码）返回原调用方；查询、文献内容和 key 不进入交接文件或输出。
结果仍在原工程，`status` 和 `export` 仍可本地使用。

`--terminal` 是显式的交互方式选择，不会在权限错误后自动启用。调用方仍须有权限
打开 Terminal，并可能需要 macOS 自动化授权。它不能修复 GPT 宿主的自动审批服务
不可用、403 或执行拒绝；此时保留原任务，先恢复调用方的执行权限。

`execute` 先保存并返回新的执行引用，再打开窗口；`resume` 完整沿用原查询、授权、
预约和预算，不重新准入、不延长授权、不增加请求。专用 preflight 恢复仍要求
secret_unavailable、零尝试、零页和无原始响应，保持一次请求、一条记录、零重试。
普通检索仍使用现有恢复内核。没有 `--execute-live` 就拒绝打开执行窗口。

最长等待五分钟。若窗口仍运行、交接丢失或调用中断，返回明确终端错误，
`network_calls`/`secret_reads` 为 null、`execution_counts_status=unknown`；
这不表示请求未发送。GPT 应读取原运行状态和已有结果，不能自动重发或重新建任务。
同一运行的并发 Terminal 交接有进程锁，实际请求仍受原数据库事务和恢复锁保护。


## 13. 遥测、错误、已准备任务恢复与字段覆盖率

```sh
# 全部为本地操作，不读取 key、不发送 API 请求
scopus-access status --run-info /path/to/execution/run-info.json
scopus-access inspect --run-info /path/to/execution/run-info.json
scopus-access audit --run-info /path/to/execution/run-info.json
scopus-access capabilities --records 5039
```

`quota_telemetry` 对 limit/remaining/reset 分别记录 valid/missing/invalid/stale/inconsistent，
只保留允许字段的有效数字与校验结果，不保存完整 HTTP 头。`telemetry_reason` 还区分
重置时间回退、同窗口额度变化或增加、提前换窗及无法确认的本地对账；客户端
`observed_epoch` 可用于核对时钟。HTTP 200 数据先保存，遥测不可信时暂停，不认定耗尽。
旧版本未记录字段状态的响应显示 telemetry=null，无法事后还原，不推断缺失原因。

`inspect` 返回原 run-info、phase、request_budget、reserved_remaining、diagnostic_allowed、
diagnostic_used、next_actions。诊断资格指一次有界诊断预约能否申请，已预约也算已用；
这不是联网许可，执行仍需批准具体查询及边界。诊断未用时可另行批准一次 STANDARD、
count=1 的 `check`；若诊断已用且仍未知，保留数据，检查遥测/时钟/权限或联系服务方。
不要重新初始化、删除账本或不断创建任务。恢复条件满足后，`resume` 沿用原 checkpoint
及剩余预约，不重发已保存页；预算耗尽不能用 resume 扩大。

0.4.2 对有效同窗口数值自动取较小余额并继续原任务。非阻断原因
`RATE_LIMIT_BALANCE_MIN_APPLIED` 同时记录服务器 `quota_remaining`、
`local_remaining_after_attempt` 和选定的 `reconciled_remaining`。不存在自动 +1 容差，
也不退回已计费尝试；尚未花出的预约仅用于计算新准入容量，不再从余额重复扣除。

```sh
# 修正历史仅因数值差异暂停的状态：离线，无 key 读取，无 API 请求
scopus-access reconcile --run-info /path/to/original/run-info.json
# 沿用未过期的原授权和剩余预约；会先自动核验并追加历史数值对账
scopus-access resume --run-info /path/to/original/run-info.json --execute-live
```

reconcile 只接受最新桶的数字差异旧暂停及完整保留证据。它校验原运行、查询/配置哈希、
ATTEMPT/OUTCOME、HTTP 200 保存页、有效遥测和窗口，并追加前序链接的对账行；重复执行
不重复追加，也不会联网。它不改旧 receipt/checkpoint。`can_resume` 同时考虑窗口、
原预算、保存页及授权期限；余额修正不能让已用尽的诊断再发一次请求，也不会续期授权。

缺失或非法遥测仍可能需要单独有界诊断，保留原 `diagnose` 离线预览及明确批准机制。
不要为已能取最小值的数值差异另外消耗 diagnostic。权限失败或后来出现其他失败时，
不能拿更早的数值证据解锁。详见 [余额口径、并发和恢复](QUOTA-RECONCILIATION.md)。

```sh
# 原任务已准备但未准入：明确批准后由调用方继续同一任务
scopus-access start --run-info /path/to/execution/run-info.json --execute-live
```

`start` 使用原冻结查询、参数、grant 和 run-info，不续期。它持有原执行的进程锁，
核对数据库、请求日志、事件、checkpoint、receipt 和 raw 文件后才允许首次准入。
已有准入或不明活动就拒绝，并要求 inspect/resume。Terminal 启动失败本身仍为未知；
离线检查得到的 prepared_not_admitted 是本地时点证据，start 会在锁内重新检查。
迟到的 Terminal 子进程也走同一 start，不会和公开调用重复预约或发送。
这不绕过宿主执行拒绝。授权过期须重新明确授权，工具不会自动续期。

HTTP 非成功响应的 `service_error` 支持 JSON/XML 错误 envelope，只输出白名单代码、
固定类别、已识别参数及响应 SHA-256。自由文本（可能含查询/key/token）从不复制；
安全摘要位于 restricted_metadata 下 diagnostics 目录。只有服务端完整匹配已识别的
数字限制格式才报告 service_max_count，其他情况不猜允许值。失败请求照常计入用量。

```sh
# 另建离线参数版本，原任务和失败证据保持不变
scopus-access revise --run-info /path/to/execution/run-info.json --page-size 25
# 批准新预览后才 execute，新执行有独立明确预算
```

新 Search 包冻结排序（默认 -coverDate）和参数版本；多词排序参数使用
`--sort=-coverDate,+creator` 形式，最多三个官方允许字段。更大检索可显式选择
`--pagination cursor --max-requests 100 --view COMPLETE --page-size 25`。offset 的
5,000 文档范围与 CLI 的 1,000 请求预算是两个限制，不能把它们解释为同一上限。
不自动切换 cursor、拆年份或改写研究检索式。相同总量也不证明稳定快照或无遗漏。
`audit` 逐页校验 raw 哈希，报告页序、offset、总量变化、缺失标识符及重复 occurrence；
保留所有原始 occurrence，不做科学去重。observed_pages_consistent 仅指保存页的技术
一致性；snapshot_stability_verified 始终为 false。真实多页能力仍须单独验收。

```sh
# 受限 JSON 文件示意为唯一 Scopus ID 列表；不要将研究数据放进工具源码
scopus-access details --identifiers-file /path/to/project/restricted_metadata/ids.json --view META_ABS
# 单记录权限检查的预览（执行仍需另行明确批准）
scopus-access details --identifiers-file /path/to/project/restricted_metadata/one-id.json --view FULL --check
```

details 每个 ID 一次请求，最多 1,000 个，零自动重试；Abstract Retrieval 使用独立配额桶。
初始权限/配额可用一个 ID 的 --check 明确测试，不能用 Search 额度替代详情额度。
META_ABS、FULL、REF 所需权限不能由 STANDARD 成功推断。当前单记录预检的专用
零发送恢复仅支持旧有 STANDARD Search；详情预检若在凭据读取前失败，应保留原证据，
不能删除预约反复检查。字段覆盖率只计实际非空值；完整作者和参考文献完整性显示
not_verified，不承诺 REF/FULL 默认页包含完整参考文献。完整参考分页尚未实现。
