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

`init` 必须在可交互终端执行。提示输入时不回显，通过 Apple Security.framework
直接写入 Keychain，不通过带 key 的子进程、argv、环境变量或临时文件中转。
macOS 可能要求允许系统凭据访问；这与远端 Scopus 权限是两件事。

初始化不读取远端额度，不消耗 API 请求。初始配额显示 `UNVERIFIED`。
重复初始化复用既有 ready 绑定，不创建新账户、不覆盖 key、不清空历史。
取消或中断后可以重跑；若 key 已成功写入，重试只查条目元数据，避免再次覆盖。

当前没有换 key 命令。不要通过删除配置、数据库或重新 init 绕过已有记录。
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
默认 1 请求、每页 200 条；请求上限 1–25，每页 1–200，最多 5,000 条。
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
