# Scopus Access Tool：通用本地 CLI 架构

更新：2026-10-21。当前源码为 0.8.0。工程绑定、有界检索、离线导出及 DOI 优先级交付已接通；实际离线验收与安装状态见 [VALIDATION.md](VALIDATION.md)。

## 产品范围

交付一个通过 Python wheel 安装的本地 CLI。每个本机账户只维护一个活动工具环境
~/.local/share/scopus-access/current，~/.local/bin 中的固定命令已加入 PATH。
安装器从本地 wheel 离线创建并验证版本环境，再切换 current；升级不发现或修改
任何工程文件。源码位置与运行时数据无关。任何使用者都可配置自己的 Scopus API
key；终端、脚本和 Codex 调用相同命令。维护者不提供公共 key、不代管使用者
凭据、不维护中央服务。API、view 和字段的实际可用性由使用者的访问权限决定。

只负责调用方给定的查询或标识符、有界检索、额度计数、恢复和本地导出。
DOI 输出整理使用版本化政策；研究主题、corpus 建立、筛选和文献计量分析由调用工程处理。

明确不做：Codex skill、plugin、SRC/PI 通知及反馈、人员身份和组织审批流程、
多 Mac 调用、远程结果取回、SSH/SFTP、HTTP/MCP 服务及中央任务队列。
新工程使用本地显式执行授权，旧配置与历史证据保留兼容。

## 配置绑定实际工程文件夹

一个实际工程对应一个固定凭据引用和一份本机状态。Codex 对话、侧栏项目和每次
运行不是新的配额账户。同一工程的所有本机调用方共享配置、数据库和结果。

工程配置为 `.scopus-access/policy.json`。从当前目录逐级向上查找最近的配置；
遇到不完整或不安全的较近工程就停止，不跳过它借用上一级的凭据。
统一 search 找不到工程配置就报错，除非明确选择一个已有的 legacy policy。
显式 policy 也不能覆盖当前工程的已初始化绑定。

所有入口删除环境变量、用户级和源码目录的隐式回退；没有工程就提示初始化。
旧配置通过显式 --policy 使用，不能绕过当前工程绑定；底层 live 命令同样检查。

工程文件夹名称只用于展示。UUID 生成的项目 ID、alias、Keychain label 独立于
名称；同名工程得到不同 ID，原文件夹改名保留 ID。配置还绑定目录设备/inode，
复制到另一个实际文件夹不会被当成可以独立花费同一额度的新工程。

```text
survey-project/
  .scopus-access/
    policy.json           非秘密配置，含生成的 project_binding
    control.sqlite        本工程的用量与恢复状态
    runs/                 每次运行的控制文件
  restricted_metadata/
    scopus/               查询、原始响应、记录导出、checkpoint
```

初始化自动补充 Git 忽略规则。key 本身不写工程文件、命令行、环境变量、临时
文件、日志、异常或报表。工程配置包含凭据引用，不包含凭据值。

## 初始化流程

在 survey 工程的交互终端执行 `scopus-access init`，不需要初始化 sh 脚本。

1. 查找最近工程，以本机文件锁串行协调初始化。
2. 新工程生成一次稳定 ID、alias、label，先保存非秘密 pending 配置。
3. 建立工程的 SQLite 状态和受限数据目录，不插入任何假定额度。
4. 在不回显提示中输入 key；通过 Apple Security.framework 的 SecItemAdd
   直接写入 Keychain，不启动携带 key 的子进程。
5. 追加项目与 alias 关联，原子发布 ready 配置。额度保持 UNVERIFIED。

重复 init 复用 ready 配置，不重新提示、不读取或覆盖 key，也不重置数据库。
中断后沿用 pending 配置的编号；若 Keychain 写入已经完成，仅查询项目条目
元数据，避免二次覆盖。既有数据库丢失会报错，不自动新建一份余额。
明确更新 key 的命令尚未实现；重复初始化不会执行更新。

新工程使用通用 service `Scopus Access Tool`。旧工程的 service
`UAEU Survey Research Access Layer` 及 alias（包括 `uaeu-scopus-preflight`）
保持原样，不自动转换。旧名称是兼容标识，不是使用者必须隶属 UAEU 的要求。

初始化写入与运行读取统一经由 Security.framework，使用结构化 OSStatus 分类。
未知状态保留原始数值；不解析可能包含敏感内容的系统文本，也不启动 security
命令读取 key。读取等待超时后不自动重试，迟到的密钥只会在内存中销毁。

Apple 系统接口参考：[SecItemAdd](https://developer.apple.com/documentation/security/secitemadd(_:_:))。
当前平台依赖 macOS Keychain 和 POSIX 文件锁；Windows 凭据与锁适配未实现。

## 请求与共享状态

保留现有 SQLite 原子预留、尝试计数、分页、受限输出及恢复内核。
多个本机调用方通过同一数据库与请求锁协调，不各自复制余额。
`BEGIN IMMEDIATE` 原子预留所有所需 API；请求发送前记尝试，发送后追加结果。
证据记录只追加。输出限定在允许的 restricted_metadata 内并拒绝路径逃逸。
stdout 为有界控制 JSONL，不输出查询或文献正文。交互终端的简明说明只写 stderr；
脚本调用不增加这些说明，不改变原 JSON 字段含义或退出码。

查询允许 LF、CRLF 和 Tab；禁止的控制字符仅报告码位与字符位置，不输出原文片段。
restricted_metadata 内的查询包分别保存 source_text 与实际 query，两者独立记录
SHA-256，并固定转换规则 identity-utf8-v1。当前不改写任何空白，包括引号内空白；
通过 URL 百分号编码传输原文，不做静默单行转换。旧 query-only 包仍可读取。
这验证了本地数据完整性，Scopus 对具体多行语法的接受情况须另做明确批准的实网检查。

状态记录用于避免重复花费、覆盖结果和误判已发送请求；使用者无需手工维护。
未来自动生成的 USAGE.md 是可读派生报表，可离线重建，不作为可手改的余额来源。
该自动报表尚未实现，不在初始化生成目录中冒充已有文件。

额度初始 UNVERIFIED；只有真实响应才建立观测。Search 与 Abstract Retrieval
分别计数。默认预览不读 key、不联网，真正发送需对明确查询/标识符及请求上限
给出执行指令。初始化成功或配置存在本身不创造执行权限。

新工程的 policy 允许明确的本地操作；每次执行仍需 --execute-live，并固定查询、
页数、输出、数据库和有效期。该配置不是组织许可证明，也不单独构成执行指令。
canonical 工程 policy 的 hash 被封入内存执行许可，发送前再次读取核验；凭据引用、
工程目录身份或 policy 改变时停止。原内核的 topology_* 许可字段名保留兼容，新工程
在这些字段中固定实际工程 policy，不生成虚构的 license/topology 文件。

check 是显式单请求路径：STANDARD、count=1、零重试。UNVERIFIED、重置待核验或
遥测不明时使用受限的 preflight 准入；已有观测额度时走正常预留。普通 search 不
自动发探测请求。失败或无有效配额头时保留实际状态，不假定成功或重置余额。

预览固定查询包、参数和控制 hash。execute 追加明确批准的后继控制文件，保留原预览；
任务 ID、查询 hash 和请求预算不变，已准入 release 不能重跑消费。resume 必须复用
原 reservation 和已核验分页位置，不扩展预算；默认只读状态，显式执行才可能联网。
专用 build_preflight_resume_authorization 仅接受原预检的 secret_unavailable、零请求、
零完成页和无 raw 文件状态，验证 checkpoint、receipt、来源/传输与授权 hash。
从原 seed 预约直接签发运行许可，不调用首次 admission；cap 仍为一次请求、一条记录、
零重试。每个执行的恢复锁覆盖校验到最终回执发布，请求锁仍负责原子计费与发送协调。
任何发送尝试或授权过期均拒绝该路径；过期单独报 RELEASE_EXPIRED，不自动续期。
status/export/usage 全离线。其他已绑定工程不能使用本工程的 run-info。

原始响应与 checkpoint 仍由受限 artifact store 校验保存。新额度事件是本机记录，
不创建通知待办。SQLite 旧 SRC/PI 列名和旧处置方法为历史读取及兼容保留，没有
新的 CLI 审批或外部通知入口。旧部署继续使用原配置检查，不改变既有执行证据。

## 接口与范围

```sh
scopus-access init
scopus-access check --query-file /absolute/path/to/query.txt
scopus-access search --query-file /absolute/path/to/query.txt --max-requests 2 --page-size 25
scopus-access execute --run-info /absolute/path/to/preview/run-info.json --execute-live
scopus-access status --run-info /absolute/path/to/execution/run-info.json
scopus-access export --run-info /absolute/path/to/execution/run-info.json
scopus-access resume --run-info /absolute/path/to/execution/run-info.json --execute-live
scopus-access usage
```

| 功能 | 当前情况 |
|---|---|
| 初始化、工程识别、共享状态 | 已实现，含两个进程并发验证 |
| 通用本地准入、单请求检查 | 已实现；真实 API 验收另行记录 |
| STANDARD Search、分页、JSON/JSONL | 已接通；明确请求上限、零重试 |
| 统一状态、导出、恢复、用量 | 已实现；恢复不扩展原预算 |
| 明确更新 key、自动 USAGE.md | 尚未实现 |
| SRC/PI、人员审批、通知 | 不在新工程工作流中；旧 schema/方法保留兼容 |
| Abstract Retrieval、COMPLETE/cursor | 显式 CLI 入口；离线验证，实际权限和多页仍待实网 |
| CSV/RIS/BibTeX | 尚未实现 |

文件夹改名保持工程 ID，但旧运行中固定的绝对路径不会自动迁移。

开发与测试全离线，注入模拟凭据存储和 transport，任何 socket 尝试均失败。
初始化测试覆盖同名工程、重复与中断初始化、文件夹改名、并发和秘密不泄露；
不读取或写入真实 Keychain，不发送实网请求。迁移保留既有证据与结果，不重写
历史或搬动数据库后声称原执行许可仍有效。

## Noninteractive initialization

When hidden input is required and the caller has no TTY on macOS, init releases
its normal initialization lock and opens Terminal with the same package's fixed
initialization child. A separate per-project lock permits one pending window.
The child takes the existing initialization lock, validates the original folder
and project identity, prompts without echo, and writes directly to Keychain.
Only a bounded non-secret status packet crosses back; the parent verifies the
ready binding and returns the usual init JSON. No network or new live authority
is involved. Cancelled, timed-out, or interrupted setup retains its binding for
safe retry; ready projects bypass the handoff.


## Explicit Terminal execution

execute/resume accept --terminal together with --execute-live and the original
run-info. This is an explicit local UI handoff, not an automatic fallback after
permission denial. The parent validates pinned context; execute publishes its
execution reference before launch, while resume reuses its original reference.
The same package's child validates the run-info digest and physical working
folder, then invokes the existing task-specific admission or recovery kernel.
A separate per-source lock prevents competing windows. Only schema-validated,
identity-matched control events and sanitized failure diagnostics return through
a bounded local packet. Missing completion reports unknown activity and never
causes a retry. Host execution approval and macOS automation permissions remain
necessary; no policy or sandbox bypass is implemented.


## 0.4.0 feedback implementation

New control-only telemetry/service-error schemas keep whitelisted validation
states, normalized quota numbers and response digests. No response header dump
or free remote error string enters evidence. inspect reports original state and
bounded diagnostic eligibility. start serializes evidence validation with first
admission of an existing prepared execution, including delayed Terminal children.
Search plans expose cursor, fixed sort and up to 1000 explicit requests, while
retaining the separate offset ceiling. details exposes the existing frozen-ID
retrieval kernel. audit verifies saved pages and reports field presence and
technical coverage; it never certifies a stable scientific population, complete
author lists or reference networks. Reference pagination is not implemented.

## 0.4.1 accounting and diagnostic preparation

The accounting result carries the conservative post-attempt local balance to
the fixed telemetry schema. A larger server remaining value pauses with the
original ledger reason, without refund or history rewrite. Client and urllib
header cleanup now encloses validation, capability checks and transport errors.
Offline contract tests inspect the final urllib Request through a mock opener.
diagnose freezes a separate unapproved one-request STANDARD check from the
verified source query. A used diagnostic requires an explicit correction and
the latest completed predecessor. The approved release pins that predecessor;
the existing transactional admission arbitrates concurrent drafts. Original
reservations and saved pages remain unchanged. Authentication stays API-key
only; additional credentials and a live reference comparator remain future work.

## 0.4.2 minimum balance reconciliation

Valid same-window responses atomically retain the smaller of the server
observation and the latest already-charged local balance. Raw server values
stay separate from effective balances; outstanding unspent reservations are
subtracted once for new admissions. Outcomes do not charge again, and larger
or out-of-order observations cannot refill a window. The difference emits a
non-blocking fixed-shape event while original pagination continues within its
budget. A supported offline reconcile entry validates retained telemetry,
saved-page hashes and attempt/outcome linkage before appending one successor
for an old numeric-only pause. Repeated recovery is idempotent; resume also
uses this correction before executing its original unexpired authorization.
Normal missing/invalid-window, actual capacity, budget and access gates remain.
See [QUOTA-RECONCILIATION.md](QUOTA-RECONCILIATION.md) for the balance contract.

## Implemented optional DOI enrichment (0.5.0)

The enrich command family is independent from Scopus retrieval. It consumes project-restricted saved normalized records, freezes the selected occurrences and public DOI singleton tasks, and requires separate bounded execution consent. A dedicated enrichment.sqlite append-only ledger avoids changing the strict Scopus control schema; third-party requests do not affect Scopus quota observations. Per-run and cache locks serialize local callers.

Raw provider bodies, immutable snapshots and versioned mixed-source exports remain under the project's allowlisted restricted root. Missing fields alone may be filled after DOI/title/version checks; presence, cross-source agreement and publisher-verified completeness remain distinct. Native Scopus fields and external model keywords/citation links cannot be conflated. See [DOI enrichment](DOI-ENRICHMENT.md) for the exact supported semantics and recovery limits.

## Publisher HTML integration (0.6.0 onward)

The enrich router accepts an explicit publisher_html source. Saved browser bundles import entirely offline;
static and browser acquisition are separately frozen choices and never fall back automatically. Existing
nonempty API values and field provenance remain intact; article Keywords fill author_keywords only.
Affiliations and Scopus index keyword inference remain outside this change.

The package owns the parser, saved-evidence importer and a shared public RequestBudget kernel. Legacy
scripts remain compatibility entry points. Independent project-bound web ledgers count requests without
changing Scopus quota observations. Browser HTTP GETs use a fixed-header stateless dispatcher and durable
attempt/outcome evidence; isolated offline Chromium renders fulfilled responses, with service workers,
WebSocket, additional pages, redirects and unapproved hosts blocked. Each dispatched resource counts;
completion caches prevent navigation replay and unknown activity stops resume. Context routes and launch
settings do not certify whole-process egress coverage. Real browser acceptance is still pending.

See [publisher HTML usage](PUBLISHER-HTML.md), [offline validation](VALIDATION.md) and the
[bounded live proposal](PUBLISHER-HTML-LIVE-PLAN.md). The development wheel is tested in disposable
environments. Publisher live acceptance remains separate; current local installation and release validation are recorded in [VALIDATION.md](VALIDATION.md).


## DOI 代表交付层（0.7.0）

原始 occurrence 导出仍使用旧路径、计数及 receipt 契约。运行 receipt 持久化后，
离线生成 `deliveries/<generation>/`；仅计数、固定引用和哈希进入 run_completed。
派生写入失败报告 delivery_status=failed，原运行证据、配额及恢复边界不改变；
可用 export 从已保存页重建。显式 deliver 聚合多个选定运行或 CSV/JSONL 输入，
不扫描其他批次，不读取 key，也不打开或更改控制账本。

输入字节、政策快照、实现代码及 CLI 版本固定 generation。派生文件不可覆盖，
manifest 最后发布；相同输入可幂等恢复，不同政策/元数据另产版本。
书目内容、冲突细节和逐 occurrence 来源只进入 allowlisted restricted 输出。
见 [DOI 优先级交付](DOI-PRIORITY.md)。

## Optional Zotero synchronization (0.8.0)

`dataset create` freezes a project-bound local bibliography; existing 0.7 delivery
JSONL/CSV and DOI/publisher enrichment exports retain their EIDs and provenance.
`zotero prepare` is offline; `check` and `plan` read only. `push` requires a
reviewed one-use plan, positive item bound and explicit live execution. It fills
empty fields, preserves manual values and holds identity/type conflicts.

Zotero credentials use a separate project/target-bound Keychain reference.
Restricted immutable bundles store content, mappings and predecessor-linked
attempt/result/reconciliation evidence; project-wide locks and persisted cooldowns
coordinate callers. No automatic retries or attachments are implemented.
Scopus quota, history and completed retrievals are independent of sync results.
Real account access and writes remain unverified. See [Zotero](ZOTERO.md) and
[release validation](RELEASE-0.8.0.md).
