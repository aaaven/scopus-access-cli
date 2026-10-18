# 开发、验证和发布

## 目录

```text
src/scopus_access/       Python 包与统一 CLI
tests/                  离线单元、集成、并发和安装后回归
scripts/                一次性安装入口、测试器与发布检查
examples/               明确标为 synthetic/offline 的兼容示例
docs/                   使用说明、架构及验证范围
```

运行时只使用标准库。Python 3.9 是最低版本；Keychain 与文件锁实现面向 macOS。
入口为 `scopus-access`，Python 包为 `scopus_access`，发行包名保留
`uaeu-scopus-access-layer`。不要因通用命名改动旧凭据 service 或应用标识。

## 构建 wheel

```sh
python3 -m venv .venv-build
.venv-build/bin/python -m pip install setuptools wheel
.venv-build/bin/python -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir dist
```

第一条 pip 安装准备构建依赖，可以联网；构建与 CLI 安装可在依赖已有时全离线。
离线机器可以从自己的依赖 wheel 目录安装相同构建依赖。不要在研究工程里构建运行数据。
`dist/`、build 环境及 egg-info 均被忽略，不提交打包产物；wheel 可另行作为 release 附件。

## 完整离线验收

单独运行 `python3 scripts/run_offline_tests.py` 可测试源码，但安装后子进程测试需要
一个**安装在源码之外的临时环境**。下面使用构建出的本地 wheel，不碰真实 Keychain：

```sh
validation_root="$(mktemp -d)"
python3 -m venv "$validation_root/tool"
"$validation_root/tool/bin/python" -m pip install --no-index --no-deps --no-cache-dir \
  "$PWD/dist/uaeu_scopus_access_layer-0.3.3-py3-none-any.whl"
export SCOPUS_TEST_INSTALLED_PYTHON="$validation_root/tool/bin/python"
export SCOPUS_TEST_INSTALLED_BIN="$validation_root/tool/bin"

# 源码包，全套（包括已安装 console 的子进程）
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_offline_tests.py

# 再以已安装 package 运行全套；路径从该环境求得，不硬编码 Python 小版本
installed_package_root="$("$validation_root/tool/bin/python" -I -c 'import pathlib,scopus_access; print(pathlib.Path(scopus_access.__file__).parent.parent)')"
SCOPUS_TEST_PACKAGE_ROOT="$installed_package_root" \
  "$validation_root/tool/bin/python" -B scripts/run_offline_tests.py

PYTHONPYCACHEPREFIX="$validation_root/pycache" python3 -m compileall -q src tests scripts
python3 scripts/verify_repository.py
git diff --check
```

这些变量只用于测试目标，不携带 API key，也不是运行时凭据配置。
不要将 `SCOPUS_TEST_PACKAGE_ROOT` 用于生产调用。

测试器在导入测试前封锁 socket/DNS，并检查零连接尝试。安装后子进程也先启用门禁，
再导入包，且注入模拟 Keychain 和 transport。安装后的 console 通过 PATH 查找，
使用隔离解释器 `-I`，验证 import 位于环境内，从源码目录外执行。
不得将真实 Keychain 或实网 smoke check 混入自动测试。

若只有源码测试通过但报告跳过安装后测试，不算完整发布验收。
测试覆盖初始化、中断恢复、并发共享状态、冻结授权、防重复发送、secret/content
不泄露、路径边界、导出、分页恢复及旧配置兼容。实际数字见 [VALIDATION.md](VALIDATION.md)。

## 仓库发布检查

```sh
python3 scripts/verify_repository.py
git status --short
git ls-files
```

检查器只读工作树/索引，不读 Keychain、不联网。它拒绝发布索引中的运行目录、
数据库、jsonl、key 文件、符号链接、开发者个人目录绝对路径及本机 Markdown 链接，
并检查相对文档链接。测试里的标识符和凭据都是明确的合成 sentinel。

禁止提交 `.scopus-access/`、`restricted_metadata/`、`runtime/`、raw 响应、
checkpoint、receipt、运行日志、真实查询、实际 API key 或本机验收控制包。
只纳入 allowlisted 程序、测试、合成示例和公开文档。不要复制原工程 `.git` 历史。

## 上传到自己的远端

此交付目录是独立 Git 仓库。先检查已有远端；如果还没有 origin，在自己的 Git
托管平台建立空仓库，再将下列占位地址换成实际地址：

```sh
cd /path/to/scopus-access-cli
git status --short
git remote -v
# 仅在尚未配置 origin 时添加
git remote add origin "YOUR_REPOSITORY_URL"
git push -u origin HEAD:main
```

这里只介绍上传，工具不会自动创建远端、推送或公开数据。若选择其他远端分支名，
相应修改 `HEAD:main`。不要 force-push 到已有历史；先确认远端是你准备好的仓库。

## 变更要求

修改 Python 代码后运行完整离线测试与 Python 3.9 编译；发布时构建并测试实际 wheel。
保持 append-only 账本、原子多桶预留、受限目录校验和明确本次执行授权。
新功能必须区分已实现与计划，不能凭模拟成功声称实网成功。
升级不操作工程；非秘密配置可维护，但不能生成假配额或隐式凭据回退。

当前许可元数据是 Proprietary。未在本次整理中替所有者选择开源许可证。
