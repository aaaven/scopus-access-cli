# 出版社 HTML 补全

`enrich` 将已保存的 Scopus 记录和出版社 HTML 绑定到实际调用工程。已保存浏览器
bundle 的导入完全离线；静态 HTTP 与可选浏览器获取必须明确选择，并在执行前取得
本次页面、精确域名和请求上限的批准。不会重新查询 Scopus 或自动更换获取后端。

这份文档对应源码中的正式集成接口。本机固定安装是否已经升级，以已安装包版本和
[验证记录](VALIDATION.md) 为准。安装、构建或离线测试不构成实网授权。

## 字段规则

- 文章 `Keywords`、`Author Keywords` 等栏目直接补入 `author_keywords`。没有栏目
  时正常留空。SEO metadata、`dc.subject` 及出版社主题分类不混入作者关键词，也不填
  Scopus 索引词。
- 只填原记录的空值。API 已有的摘要、关键词、作者和参考文献及其来源逐字段保留，
  HTML 候选、栏目标签、路径、方法、HTML 哈希和转换版本另存受限导出。
- DOI 必须匹配，标题相似度至少 0.90；版本风险进入复核。作者截断、参考文献加载标记、
  数量和内容检查分别记录。取得非空字段或连续编号不等于完成全文完整性认证。
- 页面能否获取和字段是否存在分别报告；作者单位不在本轮范围内。

## 离线导入已有证据

在已初始化的调用工程根或其子目录运行：

```sh
scopus-access enrich import --source publisher_html \
  --bundle /path/to/project/restricted_metadata/scopus/saved-browser-bundle
```

当前导入器兼容既有试验的 bundle 格式：`plan.json`、`report.json`、
`offline-review.json`、`inputs.jsonl`、`network-control.jsonl`、取数及复核源码、handoff，
以及每个样本的 `document-response.html`、`rendered.html`、`extraction.json`。
它读取数据，不执行 bundle 中的源码。新生产浏览器获取的保存格式由其自身的
prepare/execute/status/export 管理。

导入校验捕获范围、原始报告及追加修正、已有 DOM 哈希，并分别重解析原始 document
和 rendered DOM。首次导入将所有文件按哈希复制到不可变缓存；相同输入可重复导入，
中断可本地继续，缓存或原始来源变化拒绝复用。解析器或复核器改变时生成新的分析，
历史结果保留。原始 document 的首次导入哈希不能追溯证明捕获时已校验。

命令输出 `run_info_path`、数量、状态和哈希。随后使用该固定路径：

```sh
scopus-access enrich status --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json
scopus-access enrich export --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json
```

这些操作不启动 Playwright、不联网、不读凭据；导出内容只写入该工程受限目录。
从其他工程调用同一个 run-info 会失败，不借用原工程的配置。缺少可选浏览器依赖
不会阻止离线导入、现有 DOI 补全或 Scopus 功能。

## 准备静态获取

输入位于工程 policy 允许的 `restricted_metadata` 下。`--records` 接受现有规范化
Scopus JSONL，或已有 DOI 补全导出的 `merged` / `field_provenance` 封装。规范化记录
按输入顺序分配 `D0001` 等样本号；已有封装保留其样本号与字段来源。

`--targets` 是受限目录中的 JSON 数组，显式指定样本与 URL；可只选择部分记录：

```json
[
  {"sample_id": "D0001", "url": "https://link.springer.com/article/10.1234/synthetic"}
]
```

示例标识符完全合成。正式输入应来自调用者已核对的出版社页面，不以 DOI 自动猜测
入口，也不从失败响应自动跟随规范地址或身份转址。

```sh
scopus-access enrich prepare --source publisher_html --backend static \
  --records /path/to/project/restricted_metadata/scopus/records.jsonl \
  --targets /path/to/project/restricted_metadata/scopus/publisher-targets.json \
  --limit 10 --max-requests 15
```

静态后端最多 10 个页面、5 个 robots 主机，冻结总上限最多 15 次请求；每个页面只尝试
一次。robots 请求也计费。它只做匿名 HTTPS GET，不加载子资源、不执行 JavaScript、
不发送 Cookie、不跟随 HTTP/HTML 转址，零自动重试。站点规则未知或禁止时跳过；
401/403/429、服务器或传输失败会停止相应主机后续页面。

已有 DOI 补全 run-info 也可作为静态输入：

```sh
scopus-access enrich prepare --source publisher_html --backend static \
  --baseline-run-info /path/to/project/.scopus-access/runs/DOI_RUN/run-info.json \
  --limit 10 --max-requests 15
```

此入口只读取已保存的 Crossref 主页面证据，不新增 API 请求。

## 准备可选浏览器获取

浏览器后端只在明确选择 `--backend browser` 时启用。它需要操作者另行准备
Playwright >=1.48（可选 `browser` extra）与匹配的 Chromium；CLI 不安装依赖或下载浏览器。离线导入和
静态后端不需要它。

浏览器目标文件在静态目标格式上增加逐页精确 `domains` 名单：

```json
[
  {
    "sample_id": "D0001",
    "url": "https://link.springer.com/article/10.1234/synthetic",
    "domains": ["link.springer.com"]
  }
]
```

```sh
scopus-access enrich prepare --source publisher_html --backend browser \
  --records /path/to/project/restricted_metadata/scopus/records.jsonl \
  --targets /path/to/project/restricted_metadata/scopus/browser-targets.json \
  --max-requests 13 --max-requests-per-page 12 --max-robots-requests 1
```

每页上限包含 document、script、stylesheet、fetch/XHR 及其他放行的 HTTP 资源，
同 URL 每次实际发送都计费。robots 每个冻结主机一次，其上限须等于主机并集数量，
计入总预算、单列计数，不计入逐页上限。最多 10 页、20 个精确主机，逐页上限最多
100、总上限最多 1000；应按具体批准选择更小上限。已有完全相同页面范围复用原任务，
不能通过新建同范围任务补充预算。

Chromium 使用新的隔离 context、离线模式及拒绝连接的代理。路由在创建页面前注册，
由固定头部、无 Cookie 的 Python HTTPS transport 逐次获取并 fulfill 响应；它不转发
浏览器 Cookie 或认证头。service worker、WebSocket、额外页面、iframe 导航和重定向
均阻断。完成页同时保存原始 document 与 rendered DOM，分别提取候选和哈希。

这些机制的离线模拟覆盖不能证明真实浏览器进程所有后台流量均已计费。实际平台的
拦截与后台流量边界须在另行批准的实测中核对；本轮没有进行这项实网验证。

## 有界执行和恢复

prepare 零联网，固定输入、页面、后端、代码哈希和预算；输出不能替代具体批准。
获得本次批准后执行原 run-info：

```sh
scopus-access enrich execute --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json \
  --execute-live
scopus-access enrich resume --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json \
  --execute-live
```

不带 `--execute-live` 只做本地预览。恢复沿用原授权有效期和预算，不新建任务增加额度。
每个实际 HTTP 请求发送前持久化 ATTEMPT，结束时追加响应或失败记录。完成页面从
校验过的缓存导出，不重发；未知发送或未知完成状态拒绝重新加载。不同本地调用者
共享该工程的进程锁和事务预算。

网页预算独立于 Scopus 配额，不将其计划上限变成服务端配额观测，不改变已有
`UNVERIFIED` 状态。控制 stdout 仅含有界 JSONL；正文、页面来源、候选和原始文件
只保存在工程的 policy 允许目录。不会读取 Scopus key 或导入用户浏览器登录态。

浏览器后端的依赖、拦截和预算边界以及下一次实测要求见
[有界实网验收方案](PUBLISHER-HTML-LIVE-PLAN.md)。旧脚本仍保留兼容入口；历史试验
和证据格式详见 [PUBLISHER-HTML-PROBE.md](PUBLISHER-HTML-PROBE.md)。

浏览器接口依据 Playwright 官方文档：[网络拦截](https://playwright.dev/python/docs/network)、
[BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext)、
[响应 fulfill](https://playwright.dev/python/docs/api/class-route)、
[service worker](https://playwright.dev/python/docs/service-workers) 与
[启动参数](https://playwright.dev/python/docs/api/class-browsertype)。这些接口文档不替代本机实测。
