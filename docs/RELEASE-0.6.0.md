# 0.6.0 — Publisher HTML enrichment / 出版社 HTML 补全

2026-10-20 · Python 3.9+ · macOS

## 中文说明

此版本将已验证的出版社 HTML 解析与保存证据导入接入正式 `enrich` CLI，
复用调用工程的绑定、受限目录、预算和恢复机制。已有 DOI 补全入口保持兼容。

- 新增 `enrich import --source publisher_html --bundle ...`，完全离线导入已有浏览器证据，
  校验并缓存原始 document、渲染 DOM、捕获源码和报告，支持重复导入及版本化分析。
- 新增 `enrich prepare --source publisher_html --backend static|browser`，明确选择获取
  后端，冻结已保存记录、精确页面/域名、代码哈希及请求边界，再使用
  `enrich execute|resume|status|export --run-info ...`。
- 文章 Keywords 栏补入作者关键词空值；无栏目正常留空。已有 API 非空字段与来源保留，
  HTML 候选另存；主题分类、SEO 词与 Scopus 索引词分开。作者单位未扩展。
- 浏览器为可选 Playwright 依赖；基础安装不下载依赖或 Chromium。每个实际放行的资源
  请求及 robots 请求都计费；发送前持久化 ATTEMPT，沿用原预算恢复。完成页不重发，
  状态不明时拒绝重放；重定向、未冻结主机、Cookie/登录态及额外导航均不获准。

安装已有本地 wheel：

```sh
scopus-access install --wheel /absolute/path/to/uaeu_scopus_access_layer-0.6.0-py3-none-any.whl
scopus-access enrich --help
```

首次安装及从源码构建见 [README](../README.md#安装一次)；完整参数、输入格式和
恢复规则见 [出版社 HTML 使用说明](PUBLISHER-HTML.md)。安装只更新工具环境，保留旧版，
不发现或更改研究工程。数据和原始页面仍仅写入调用工程允许的 `restricted_metadata`。

验证包括 Python 3.9/3.12 的完整离线套件、实际 wheel 安装后执行、语法编译及仓库检查；
具体结果与制品哈希见 [验证记录](VALIDATION.md)。自动测试使用合成内容、模拟凭据和
transport，并封锁 socket/DNS；本次未新增真实 Scopus、DOI 或出版社请求。

**浏览器真实网络拦截与后台流量边界尚待另行验收。** 历史两页保存证据的离线复核不能
证明本版本已通过真实 Chromium 获取、多篇访问或全文完整性认证。每次真实执行仍需
具体页面、精确域名和预算的明确批准；已有方案见 [实网验收计划](PUBLISHER-HTML-LIVE-PLAN.md)。

## English release notes

This release integrates publisher HTML parsing and saved browser evidence into the
project-bound `enrich` CLI. Existing DOI enrichment commands remain compatible.

- Import saved browser bundles entirely offline with
  `enrich import --source publisher_html --bundle ...`. Validate and retain the
  original document, rendered DOM, capture code and reports in immutable caches;
  repeat imports and versioned analyses preserve earlier evidence.
- Explicitly prepare `publisher_html` acquisition with `--backend static` or
  `--backend browser`. Freeze saved records, exact pages/hosts, code hashes and
  request bounds, then use `enrich execute|resume|status|export --run-info ...`.
- Fill missing author keywords from article Keywords sections. Retain populated
  API fields and their provenance; keep HTML candidates, subject classifications,
  SEO terms and Scopus index keywords distinct. Affiliations are outside this release.
- Playwright and Chromium are optional and are never downloaded by the installer.
  Charge each dispatched resource and robots request before sending; resume with
  the original budget, reuse completed pages and reject uncertain replay. Block
  redirects, unfrozen hosts, login state, cookies and extra navigation.

Upgrade from the local wheel using the command above. Installation switches the
verified per-user tool environment and retains the previous version without
changing research projects. See the [usage guide](PUBLISHER-HTML.md) for formats,
commands, request accounting and recovery.

Validation covers full offline suites on Python 3.9 and 3.12, an installed wheel,
syntax compilation and publication checks. Tests use synthetic content, mock
secrets and transports, with socket/DNS access blocked. Exact results and the wheel
checksum are recorded in [VALIDATION](VALIDATION.md).

**Live browser interception and background egress acceptance remain pending.**
No live Scopus, DOI or publisher request was added for this release. Historical
saved-page checks do not establish live Chromium acquisition, broad availability
or full-text completeness. Live execution requires separate explicit approval for
the frozen pages, exact hosts and request budget; see the [live plan](PUBLISHER-HTML-LIVE-PLAN.md).
