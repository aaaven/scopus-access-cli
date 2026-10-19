# Scopus Access CLI

一个通用的 macOS 本地命令行工具：使用者提供自己的 Scopus API key，工具负责精确
查询、有界分页、配额记录、恢复与本地 JSON/JSONL 导出。当前版本 **0.5.0**。

**一台 Mac 安装一次；每个研究工程分别初始化自己的 key 绑定、账本和结果。**
工具不负责选题、corpus 建立、筛选、科学去重或文献计量分析。

## 功能与平台

- macOS，Python **3.9+**，可使用 `venv` 和 `ensurepip`；运行时仅用 Python 标准库。
- key 在交互终端隐藏输入，直接写入 Apple Keychain；不使用 key 参数或环境变量。
- 从当前目录向上寻找最近的工程配置，多个本机调用方共享同一工程状态。
- 默认离线预览；只有明确添加 `--execute-live` 才允许本次有界请求联网。
- 检索入口支持显式 **STANDARD/COMPLETE**、offset/cursor 分页和固定排序，零自动重试。
- 本地状态、用量及导出不读取 key、不联网。

这是本地 CLI，不需要 Codex skill、服务器、组织身份流程或外部通知服务。
Scopus API 权限由使用者自己的 key、订阅及机构访问条件决定。

## DOI 补全（可选）

0.5.0 新增 `scopus-access enrich prepare|execute|resume|status|export`：从当前工程已保存
的 Scopus JSONL 中选定记录，单独通过 Crossref/OpenAlex 补空值。明确预算、零重试、
原字段保留、缓存及来源可追溯；不再次查询 Scopus，也不读取 Scopus key。
作者/索引关键词与模型关键词分开，参考文献条目与引用链接分开，不能保证补齐或完整。
完整命令、存储、恢复及字段限制见 [DOI 补全使用说明](docs/DOI-ENRICHMENT.md)。

另有 [出版社 HTML 独立试验脚本](docs/PUBLISHER-HTML-PROBE.md)，用于同批 DOI 的
网页增量验证。它尚未进入 CLI 或 wheel；有独立预算，保留原始 HTML，不自动跳转或
绕过站点规则。作者关键词与一般网页关键词、Scopus 索引词分别处理。

## 安装一次

在源码仓库构建 wheel，再安装到固定工具环境。下面准备构建依赖的命令可能联网；
CLI 安装器本身只使用本地 wheel，离线安装且不接触任何研究工程。

```sh
cd /path/to/scopus-access-cli
python3 -m venv .venv-build
.venv-build/bin/python -m pip install setuptools wheel
.venv-build/bin/python -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir dist
.venv-build/bin/python scripts/install_cli.py --wheel "$PWD/dist/uaeu_scopus_access_layer-0.5.0-py3-none-any.whl"
source ~/.zprofile
command -v scopus-access
scopus-access --help
```

如果已取得维护者提供的 wheel，可直接使用 `python3 scripts/install_cli.py --wheel
/absolute/path/to/file.whl`，跳过构建。不要给每个研究工程重复安装。

| 安装内容 | 位置 |
|---|---|
| 固定入口 | `~/.local/bin/scopus-access`、`scopus-fetch` |
| 当前工具环境 | `~/.local/share/scopus-access/current` |
| 已安装版本与回滚副本 | `~/.local/share/scopus-access/versions/` |
| PATH 设置 | 在 `~/.zprofile` 末尾追加一次，保留既有内容 |

新登录终端自动生效；当前终端使用 `source ~/.zprofile`。如果使用非 zsh shell，
在该 shell 的启动配置中加入 `~/.local/bin`。安装完成后可移动或删除源码副本；
运行时不依赖源码目录。基础 Python 安装仍需保留。

## 五分钟开始

先准备一个自己的 Scopus API key。**不要把 key 粘贴到命令、脚本、聊天或配置文件。**

```sh
mkdir -p /path/to/my-survey
cd /path/to/my-survey
scopus-access init
```

按不回显的提示输入 key。由 GPT/脚本在没有交互终端的环境调用时，`init` 会自动打开
macOS Terminal；你只需在新窗口粘贴 key 并回车，无须复制 shell 命令。完成状态会返回
原调用方，key 不会返回 GPT。首次可能需要允许 macOS 控制 Terminal。

初始化不联网，额度为 `UNVERIFIED`，尚不表示 key 已验证。重复执行 `init` 会复用
已有绑定，不覆盖 key、不清空账本，也不再次打开输入窗口。

用编辑器在工程的 `restricted_metadata/query.txt` 中保存 UTF-8 Scopus 查询，可正常多行排版。
可使用自己确认过的 `DOI(...)` 或 `TITLE-ABS-KEY(...)` 表达式；工具原样发送，不替换查询。

```sh
# 1. 预览单请求检查，零网络
scopus-access check --query-file "$PWD/restricted_metadata/query.txt"

# 2. 明确执行：最多 1 次请求、1 条记录，零重试
scopus-access check --query-file "$PWD/restricted_metadata/query.txt" --execute-live

# 3. 预览最多 2 页，每页 25 条
scopus-access search --query-file "$PWD/restricted_metadata/query.txt" --max-requests 2 --page-size 25

# 4. 确认查询及边界后执行
scopus-access search --query-file "$PWD/restricted_metadata/query.txt" --max-requests 2 --page-size 25 --execute-live

# 5. 离线查看实际用量和服务端配额观测
scopus-access usage
```

`check` 的查询仍由你选择；命中零条不必然意味着 key 无效。首次成功响应中的有效
配额头用于建立观测；未取得有效观测时普通 `search` 会停止，不偷偷增加探测请求。
查看 `http_status`、`stop_reason` 和配额状态，不能只看退出码判断 key。

## 预览、执行与取回结果

CLI stdout 是有界 JSONL 控制流，包含状态、请求计数、hash 和文件路径，
不打印查询或文献正文。每次预览/执行会输出 `run_info_path`。
交互终端同时在 stderr 显示简明中文说明；非交互调用保持 JSON 行为，不增加网络或密钥读取。
`init` 会明确区分“本地配置完成”和“Scopus API 尚未验证（UNVERIFIED）”。

若要执行已检查的冻结预览，使用预览的路径；不要为了执行同一次预览重新提交查询：

```sh
scopus-access execute --run-info /path/to/preview/run-info.json --execute-live
```

由 GPT 调用而需要本机钥匙串授权窗口时，可在上述 `execute` 命令末尾加 `--terminal`。
GPT 直接打开 Terminal 并接收结果，使用者无需复制命令。原任务恢复也支持
`resume --run-info ... --execute-live --terminal`，沿用原预约和预算。
这仍要求调用方获准打开 Terminal，不能绕过宿主的执行拒绝或修复审批服务不可用。
详见 [Terminal 执行与恢复](docs/USAGE.md#12-由-gpt-打开-terminal-执行或恢复)。

执行输出的是一份**新的 execution run-info**。后续操作使用新文件：

```sh
scopus-access status --run-info /path/to/execution/run-info.json
scopus-access export --run-info /path/to/execution/run-info.json
scopus-access resume --run-info /path/to/execution/run-info.json
scopus-access resume --run-info /path/to/execution/run-info.json --execute-live
```

`status` 和 `export` 全离线。`resume` 默认只检查状态，显式执行也只沿用原任务、
分页位置和剩余预算；不增加额度、不续期授权、不重发证据不明的请求。
已完成或已准入的同一个预览不能当作新请求重复消费。

若首次 `check` 已准入，但读取钥匙串失败并报告 `secret_unavailable`、请求尝试为 0，
修复系统授权后使用其 **execution run-info** 执行 `resume --execute-live`。
工具沿用原预约的一次请求、一条记录、零重试；不会再申请首次预检名额。
任何发送尝试、结果页、原文/配置 hash 改变或证据不完整都拒绝此恢复。
原授权过期会返回 `RELEASE_EXPIRED`，须显式重新授权；resume 本身不会续期。

## 工程数据与凭据

```text
my-survey/
  .scopus-access/
    policy.json          # 非秘密配置、项目 ID、Keychain 引用
    control.sqlite       # 本工程共享的用量与运行账本
    runs/                # 无查询正文的运行控制文件
  restricted_metadata/
    query.txt            # 使用者自己的输入文件
    scopus/              # 冻结查询、raw、records、checkpoint、receipt
```

key 本身只保存在 Keychain。工具会添加 Git 忽略规则，并拒绝操作已被 Git 跟踪的
控制/受限目录。不要强制加入这些文件，也不要手改账本余额。

查询允许 LF、CRLF、Tab；原始 UTF-8 文本（含首尾排版）与实际发送文本分别记录在
受限查询包中，各有 SHA-256，转换规则固定为 `identity-utf8-v1`。此版本不做单行化、
空白合并或引号内改写，URL 编码还原后与原文一致。NUL、DEL 等禁止字符会报告码位和
1 起始的字符位置/行/列，不输出查询片段。旧 query-only 冻结包继续兼容。

Keychain 读写统一使用 Security.framework。`SECRET_UNAVAILABLE` / `secret_unavailable`
继续保留，并附脱敏原因、失败阶段、后端、OSStatus 和请求活动状态；参见
[凭据错误诊断](docs/USAGE.md#11-凭据错误诊断)。

根目录或任意子目录都绑定同一工程；最近配置损坏时立即停止，不借用父工程、
用户级配置、环境变量或源码仓库的 key。项目 ID 不随目录名改变；复制到另一个
物理目录不会创建可独立消费同一 key 的新账户。历史运行的绝对路径不会随改名自动迁移。

## 命令与限制

| 命令 | 用途 | 默认联网 |
|---|---|---|
| `init` | 创建/复用工程绑定并安全存 key | 否 |
| `check --query-file ...` | 一次、最多一条的访问/配额检查预览 | 否 |
| `search --query-file ...` | 有界检索预览 | 否 |
| `execute --run-info ...` | 检查或明确执行冻结预览 | 否 |
| `status --run-info ...` | 查看本地运行状态 | 否 |
| `export --run-info ...` | 从已保存 raw 页导出 JSONL | 否 |
| `resume --run-info ...` | 检查或继续原运行 | 否 |
| `usage` | 查看本工程派生用量视图 | 否 |
| `install --wheel ...` | 离线安装/升级固定工具环境 | 否 |

Search 默认 STANDARD、offset、1 请求、每页 200 条；允许显式 1–1000 请求。COMPLETE 每页最多 25 条，offset 的文档上限与 cursor 权限要求分别检查。
达到明确边界会保存结果并报告部分完成，不自动按年份拆分或扩展预算。
STANDARD 不保证摘要、完整作者、关键词或参考文献；导出保留实际字段与缺失值。

当前没有专用换 key 命令、自动 USAGE.md、CSV/RIS/BibTeX 导出、Windows/Linux
凭据适配、多 Mac 协作或远程取回。`init` 永不静默更换 key。Abstract Retrieval 等
底层兼容接口不属于简化 Search 工作流。

## 升级

取得新的本地 wheel 后：

```sh
scopus-access install --wheel /absolute/path/to/new.whl
```

安装器先验证独立环境再切换 `current`；失败时保留旧活动版本。不发现、不重置或
改写任何工程配置、账本和历史。旧版本目录仅为程序回滚副本，不是新的配额账户。

## 文档、测试与发布

- [完整使用说明与常见问题](docs/USAGE.md)
- [开发、离线测试、打包与上传](docs/DEVELOPMENT.md)
- [架构与兼容性](docs/ARCHITECTURE.md)
- [验证范围与实际结果](docs/VALIDATION.md)
- [版本记录](CHANGELOG.md) · [贡献约定](CONTRIBUTING.md)

所有自动化测试均模拟凭据和传输，并对 socket 连接设置硬门禁。开发测试不会
访问真实 Keychain/API；真实请求必须由操作者另行明确授权。

发行包名保留 `uaeu-scopus-access-layer`，Python import 为 `scopus_access`，
公开命令为 `scopus-access`，以兼容既有安装。旧应用名和 Keychain service 只是兼容标识，
不要求使用者隶属原机构。本仓库不包含 API key 或实网结果。

许可元数据沿用原工程的 **Proprietary** 标记，尚未选择开源许可证。

English: A local macOS CLI for exact Scopus queries, bounded retrieval, shared
per-project quota state and local exports. Bring your own API key. Install once,
initialize each project, preview first, and use `--execute-live` for explicit
bounded execution. Runtime dependencies: Python standard library only.


## 0.4.2：有效同窗口余额取小值并自动继续

有效且同一凭据引用/API/窗口的响应现在自动使用
`min(server_remaining, local_remaining_after_attempt)`。差异输出为非阻断的
`RATE_LIMIT_BALANCE_MIN_APPLIED`，保留服务器原值、本地值与 `reconciled_remaining`。
任务在原预算与实际可用额度内自动取下一未保存页，无需额外诊断、批准或手动 resume。
不退款、不增加请求预算、不把 ATTEMPT 和 OUTCOME 当成两次请求；重复高余额响应不能补回额度。
缺失/非法遥测、窗口未验证、权限错误、真实额度不足和预算耗尽仍分别处理。

历史上仅因该数值差异暂停的任务，可在工程中离线追加对账，不读取 key 或发出 API 请求：

```sh
scopus-access reconcile --run-info /absolute/path/to/original/run-info.json
# 若原授权仍有效、预算有剩余，resume 也会先自动进行上述本地对账，再继续未保存页
scopus-access resume --run-info /absolute/path/to/original/run-info.json --execute-live
```

历史修复核验保留的有效遥测、原始页面哈希、计费链、项目绑定和最新窗口，仅追加账本
证据，不改旧记录、checkpoint、receipt 或任务预算。授权过期不续期，已耗尽任务不重发。
旧证据不足或后来出现权限/窗口等失败时拒绝使用旧数值解锁。单请求诊断已用尽预算时，
可以修正配额状态，但不会得到第二次请求。详见 [配额规则与恢复](docs/QUOTA-RECONCILIATION.md)。

## 历史 0.4.1：余额原因显示与独立诊断

以下描述 0.4.1 的旧行为；仅因有效数值差异暂停的控制流程已被 0.4.2 替换。

服务器余额高于本地扣费后余额时，输出准确的
`RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING`、服务器值和本地值；保守暂停，
保留已取得的数据与计费历史。它不等于额度耗尽，也不能证明服务端采用何种扣费时序。

```sh
scopus-access inspect --run-info /absolute/path/to/run-info.json
# 首次独立诊断：只生成预览，沿用原查询
scopus-access diagnose --run-info /absolute/path/to/run-info.json
# 仅在核对并修正具体问题后，才为已使用的诊断准备后继预览
scopus-access diagnose --run-info /absolute/path/to/diagnostic-run-info.json --correction request_fix
# 核对新预览后，明确批准其单独的一次请求；没有隐式执行
scopus-access execute --run-info /absolute/path/to/new-preview/run-info.json --execute-live
```

诊断固定 STANDARD、至多一条记录、一次请求、零重试，单独记账，不扩大或重播原任务。
`--correction` 还可明确选择 `environment_change` 或 `provider_guidance`；该选择是操作者
对实际变化的说明，不会验证网络归属或权限。没有新证据时先检查记录或联系服务商，
不要连续新建诊断。未发送的原预检应使用 `resume`，而不是新诊断。

修复了校验、授权能力校验及 urllib 构造/发送/读取失败时的请求头清理边界。
新增离线测试检查最终 urllib 请求的 numeric-ID/META_ABS 路径、固定头部、先记账后发送、
401 不重试及所有已创建头部副本清理。当前认证仍是 API key；Search 成功不能证明
详情 view 权限。历史 401 的根因和新版本实网行为尚待单独授权验收。
详见 [0.4.1 迭代说明](docs/ITERATION-0.4.1.md)。

## 0.4.0：诊断、恢复及元数据能力

- `inspect --run-info ...`：查看保存页数、实际请求、剩余预算、配额暂停原因、诊断是否已用及允许的下一步。
- `start --run-info ... --execute-live`：继续原“已准备但未准入”的执行；复用冻结任务与授权，禁止重复准入。可显式加 `--terminal`。
- `revise --run-info ... --page-size 25`：准备新的参数版本，保留原失败证据；默认离线，必须另外批准执行。
- `search ... --pagination cursor --max-requests 100 --view COMPLETE --page-size 25 --sort=-coverDate`：显式选择有界分页与元数据 profile，权限不够时失败，不自动降级。
- `details --identifiers-file ... --view META_ABS`：冻结受限 JSON 文件中的 Scopus ID，按每个 ID 一次请求准备详情任务。`--check` 限定一个 ID，零重试；FULL/REF 权限需单独验证。
- `audit --run-info ...`：核查实际字段非空覆盖率、重复标识符、页边界和总量变化。预算耗尽标为未完成，不能当作结果集穷尽。
- `capabilities --records 5039`：离线查看 profile、权限未知状态及请求成本估计。

摘要、完整作者、作者关键词、索引关键词及参考文献分别计数。API 转换保留原始响应、
转换版本及 `scopus_api_json` 来源标记，不冒充原生网页导出。参考文献分页与完整性仍未
实现；切换 COMPLETE 或收到 FULL/REF 的部分内容均不代表参考文献网络完整。
详见 [反馈落实与证据](docs/FEEDBACK-F01-F05.md)。

## 0.4.3：有界双客户端详情诊断

新增 `scopus-access compare`：先从原详情 401 运行准备离线预览；再显式批准
CLI 与独立最小客户端各一次、共两次、零重试。两次都计入原工程账本，报告
原始响应与转换字段覆盖率及作者计数一致性。[使用与限制](docs/CLIENT-COMPARISON.md)。


0.5.0 修复双客户端诊断的工程 Keychain service 传递，并新增 `compare --resume-unused`，
只允许零发送证据下沿用原授权与两请求预约继续，任何已开始请求均拒绝重放。
