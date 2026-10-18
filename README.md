# Scopus Access CLI

一个通用的 macOS 本地命令行工具：使用者提供自己的 Scopus API key，工具负责精确
查询、有界分页、配额记录、恢复与本地 JSON/JSONL 导出。当前版本 **0.3.1**。

**一台 Mac 安装一次；每个研究工程分别初始化自己的 key 绑定、账本和结果。**
工具不负责选题、corpus 建立、筛选、科学去重或文献计量分析。

## 功能与平台

- macOS，Python **3.9+**，可使用 `venv` 和 `ensurepip`；运行时仅用 Python 标准库。
- key 在交互终端隐藏输入，直接写入 Apple Keychain；不使用 key 参数或环境变量。
- 从当前目录向上寻找最近的工程配置，多个本机调用方共享同一工程状态。
- 默认离线预览；只有明确添加 `--execute-live` 才允许本次有界请求联网。
- 简化检索接口使用 Scopus Search **STANDARD**、offset 分页、零自动重试。
- 本地状态、用量及导出不读取 key、不联网。

这是本地 CLI，不需要 Codex skill、服务器、组织身份流程或外部通知服务。
Scopus API 权限由使用者自己的 key、订阅及机构访问条件决定。

## 安装一次

在源码仓库构建 wheel，再安装到固定工具环境。下面准备构建依赖的命令可能联网；
CLI 安装器本身只使用本地 wheel，离线安装且不接触任何研究工程。

```sh
cd /path/to/scopus-access-cli
python3 -m venv .venv-build
.venv-build/bin/python -m pip install setuptools wheel
.venv-build/bin/python -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir dist
.venv-build/bin/python scripts/install_cli.py --wheel "$PWD/dist/uaeu_scopus_access_layer-0.3.1-py3-none-any.whl"
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

按不回显的提示输入 key。初始化不联网，额度为 `UNVERIFIED`，尚不表示 key 已验证。
重复执行 `init` 会复用已有绑定，不覆盖 key、不清空账本。

用编辑器在工程的 `restricted_metadata/query.txt` 中保存一条单行 UTF-8 Scopus 查询。
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

若要执行已检查的冻结预览，使用预览的路径；不要为了执行同一次预览重新提交查询：

```sh
scopus-access execute --run-info /path/to/preview/run-info.json --execute-live
```

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

Search 默认 1 页、每页 200 条；允许 1–25 页、每页 1–200 条，上限 5,000 条。
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
