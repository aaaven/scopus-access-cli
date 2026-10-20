# 出版社 HTML 独立试验（历史记录）

2026-10-20：开发源码 0.6.0.dev0 已接入包内及 `enrich`，旧脚本保留为兼容入口。
当前正式接口见 [出版社 HTML 补全](PUBLISHER-HTML.md)，验收见
[VALIDATION.md](VALIDATION.md)。固定安装仍为 0.5.0，未发布、升级或新增实网执行。
以下“未加入 CLI”“仅回调模型”等描述记录 2026-10-19 的历史试验状态；它们不描述
后来的开发源码。真实浏览器拦截及后台流量边界仍待另行批准的实测。

继续开发请先读 [最新集成建议与交接](PUBLISHER-HTML-INTEGRATION.md)，其中明确记录
文章 Keywords 直接作为作者关键词的最终口径及正式 CLI 尚待实现的工作。

这是源码目录中的实验脚本 `scripts/publisher_html_probe.py`，**不是已安装 CLI 的新功能**，
也未加入 wheel。Scopus Access CLI 保持 0.5.0，现有 API 补全阶段、凭据和配额行为不变。
实验只判断特定样本的公开文章页面能否带来字段增量；没有真实文章验证成功时不进入 CLI。

## 作者关键词与索引关键词

出版社文章 HTML 可能提供摘要、作者关键词、完整作者名及书目条目，但各站点、文献
类型和页面权限不同，不能承诺每篇都有。字段的来源含义必须确认：

- 文章正文的 Keywords / Author Keywords / Author Provided Keywords 栏均作为
  `author_keywords`，保留原栏目标签、HTML 路径和提取方法。按已确认的字段口径，
  不再要求 Keywords 标题额外写出 Author；没有关键词栏目时正常留空。
- 一般 `keywords`、`citation_keywords`、Schema.org `keywords` 保留为
  `publisher_keywords_unclassified`；文章正文的 Keywords 区域同时保存为
  `publisher_article_keywords`，与 `author_keywords` 的映射规则透明记录。
  `dc.subject` 另存 `publisher_subject_classifications`，不与文章 Keywords 栏混为一组。
- 出版社主题分类、SEO 关键词及模型词不能填成作者关键词。出版社作者关键词也不能
  填成 Scopus 索引关键词。缺少 Scopus 索引词是来源边界，不代表初始化或本地转换失败。

[NISO JATS4R](https://jats4r.niso.org/subjects-and-keywords/) 明确区分作者/出版社提供的
关键词以及主题；[Schema.org ScholarlyArticle](https://schema.org/ScholarlyArticle) 的
通用 keywords 属性本身不证明作者来源。

## 准备和有界执行

使用已经初始化的工程，以及原 DOI API 补全阶段的 run-info。试验取其固定的十条记录，
使用已保存 Crossref 的出版社主页面地址，不重新查询任何 API。仅支持脚本中列明的
Elsevier / Springer Nature 主机；不注册新 key，不读取 Keychain。

在调用工程内，用现有工具环境的 Python 运行源码脚本：

```sh
~/.local/share/scopus-access/current/bin/python \
  /path/to/scopus-access-cli/scripts/publisher_html_probe.py prepare \
  --baseline-run-info /path/to/project/.scopus-access/runs/<doi-run>/run-info.json
```

预览不联网，输出 run-info、冻结操作哈希、记录数和预算。文献内容在工程受限目录的
`records.jsonl`；新版操作清单只存输入引用/哈希、目标和边界，不嵌入标题、摘要或书目。
旧试验的受限数据封装只可离线读取，原始证据不改写。

```sh
# 仅在明确批准本阶段目标和请求边界后执行。
~/.local/share/scopus-access/current/bin/python \
  /path/to/scopus-access-cli/scripts/publisher_html_probe.py execute \
  --run-info <publisher-run-info.json> --execute-live

# 完全本地重建分析，不联网、不读 key。
~/.local/share/scopus-access/current/bin/python \
  /path/to/scopus-access-cli/scripts/publisher_html_probe.py analyze \
  --run-info <publisher-run-info.json>
```

每个试验只有两个可冻结阶段，各最多 **15 次 HTTP 请求**，合计最多 **30 次**。
每阶段最多 10 个页面和 5 个 robots.txt；同一 DOI 每阶段最多一次页面请求。
这些是实验请求预算，不是上游配额观测。预算没有用满也不会自动追加访问。

客户端不跟随 HTTP/HTML 跳转，不执行 JavaScript，不载入子资源，不发送或保存 Cookie，
不登录，不导入浏览器会话，不伪装浏览器或绕过抓取规则，零自动重试。robots 禁止或
无法确认访问规则时跳过页面；401/403/429、服务器或传输失败会停止该主机的后续页面。
HTTP 200 的转址壳页不会当成真实文章。身份流程不等于已证明需要付费或 API key 无权限。

仅当操作员明确核对了第一阶段保留的同出版社公开规范页面地址，才可单独准备第二阶段：

```sh
~/.local/share/scopus-access/current/bin/python \
  /path/to/scopus-access-cli/scripts/publisher_html_probe.py prepare-reviewed \
  --parent <phase1-run-info.json> \
  --targets /path/to/project/restricted_metadata/scopus/<reviewed-targets.json>
```

目标文件是 sample_id / url 列表，保留在受限目录。脚本验证其与保存的规范地址证据
一致、仍属于同一出版社且符合 URL 白名单；不会自动从响应生成并执行第二阶段。
不接受登录目标、鉴权查询参数或任意外部 URL。不允许第三阶段或重新准入原阶段。

中断后若代码未变、授权未过期且请求状态已知，可在原 execute 命令加 `--resume`。
沿用原授权和预算，完成/失败/跳过请求不重发；不明发送状态拒绝重放。
取数脚本哈希改变时拒绝继续发送；可用新解析器离线分析旧响应，每版另存新生成目录。

## 提取、来源和完整性

先读文章的结构化 metadata / DOI 匹配的 JSON-LD，再回退到明确的摘要、作者关键词、
参考文献正文区域。通用 SEO description 不当作完整摘要；脚本只解析数据，不执行页面
中的指令或脚本。DOI 必须精确匹配、标题相似度至少 0.90，版本风险进入人工核对。

合并仅填补 API 基线空值，已存在字段保留；即使发现更长列表也先记录候选和差异。
每个候选保留 HTML 路径/行号、方法、原始响应引用/哈希与解析脚本版本。

- 作者记录 HTML 数量、与 API 的人数/规范化姓名顺序比较、et al. 截断标记；发现已知
  截断不填作者列表。比较时可按有记录的规则将单逗号“姓, 名”转换为“名 姓”，保留
  原姓名和转换前结果；后缀或多逗号不猜测转换。列表非空或数量相等不等同于原文完整。
- 书目候选必须有实际条目文本，DOI/URL 链接与 JSON-LD citation 链接单独保存。
  读取显式 `data-counter` / 可见编号，核查连续性、重复文本、逐位置 DOI 链接与年份，
  对照返回数、明确的页面计数、API 条目数和 load/show more 标记。没有匹配 DOI 链接
  不等于缺少参考文献；没有截断标记也不等于已证明完整。
- `publisher_fulltext_verified_complete_* = 0` 表示没有完成全文完整性核验，不表示原文
  没有作者或参考文献。访问不到文章时不能据此判断该字段缺失。

查询/文献内容、HTML、站点规则、响应来源和合并 JSONL 只存入工程的
`restricted_metadata/scopus/publisher-html-probe/<trial>/`。独立的
`.scopus-access/publisher-html-probe.sqlite` 追加记录预算与请求证据，不修改 Scopus
或 DOI API 的账本。控制输出只含数量、状态、引用和哈希。

响应头只保留 content-type、content-language、location 这三个字段；不记录完整请求头
或 Cookie。原始响应和取数脚本快照不改写；新解析结果按事件与脚本哈希生成独立目录。
HTML 数据的可读取性不构成再分发许可，页面的许可/权利标记需要单独保留和核对。

## 验证边界

离线测试仅用合成 HTML 和模拟 transport/凭据，封锁 socket。它们验证提取和恢复逻辑，
不能证明真实出版社可访问或真实文献可补齐。实网响应、逐条字段覆盖率、来源与失败原因
必须保留在调用工程，并与模拟结果分开。没有可用文章页面或没有实际增量时，应保留
实验状态而不升级生产 CLI；不以不断换入口或新建任务解决访问限制。

## 保存的浏览器证据：纯离线导入与复核

`scripts/review_publisher_browser.py` 只处理已有受限证据；不启动浏览器，不联网，
不读凭据，不更新 Scopus 或 DOI 账本。当前适配的是侧试验的固定 bundle 格式：
plan/report/追加的 offline-review、inputs、网络准入日志、取数/复核脚本、handoff，
以及各样本的 document-response.html、rendered.html 和 extraction.json。

在对应工程根或子目录运行：

```sh
~/.local/share/scopus-access/current/bin/python \
  /path/to/scopus-access-cli/scripts/review_publisher_browser.py \
  --bundle /path/to/project/restricted_metadata/scopus/<saved-browser-bundle>
```

输出只含数量、引用和哈希。原文、两种 HTML、新候选、原始 API 基线及合并结果仅在
当前工程 `restricted_metadata/scopus/publisher-browser-review/` 保存：

- `cache/<bundle-sha>/`：逐文件校验和副本；部分复制中断后可重跑，损坏缓存拒绝复用。
- `sources/<source-run>/receipt.json`：首次导入绑定；之后源文件变化拒绝重放。
- `analyses/<generation>/`：由 bundle、解析器和复核器代码哈希决定的新生成目录。
  旧证据及旧分析不改写，重复调用得到相同结果，不触发网页重取。

原始 document 响应在历史取数时未独立保存哈希，首次离线导入的哈希只证明此后未变，
不能追溯声称捕获时已校验。原始 report 的作者比较 false 与追加 correction 一起保留。
合并只填原 API 空值；文章 Keywords 补入作者关键词，主题分类单列，不能填 Scopus
索引关键词。解析器 v4 记录这一映射，新生成目录不改写 v3 或更早的提取结果。

两篇保存证据的复核结果：Springer 的六项 Keywords 位于 bibliographic-information
区域 h3 后的 ul/li，四项 dc.subject 为分类；Nature 没有检出的文章关键词栏目，
三项 dc.subject 为分类。两篇摘要、作者（1/4）及71条文本书目在 document 响应中
已经存在，与渲染 DOM 提取一致。此事实不证明必须执行 JavaScript，也不证明所有
页面可访问或书目全文完整。该二条 API 基线的摘要/作者/参考文献已非空，非空覆盖
增量为零。按 v4 规则，作者关键词覆盖由0/2增至1/2：Springer六项；Nature留空。
另保留全文条目文本的候选证据，不覆盖已有 Crossref 书目。

## Playwright 可选路径的评估（尚未接入 CLI）

保留静态传输与 robots 门禁；浏览器可作为今后明确选择的可选依赖，不默认下载浏览器，
不导入用户登录态，不把一次导航算作一次请求。侧试验已有20次页面上下文准入记录，
其中 document 2、script 12、stylesheet 5、fetch 1；这不是20次成功响应或浏览器全部
系统流量。原日志结束时才落盘、缺逐请求终结证据，不可直接支持可靠的崩溃恢复。

`scripts/publisher_browser_budget.py` 是**仅离线验证的回调准入模型**，没有启动或接线
Playwright：精确主机名单、全局/逐页预算、发送前持久化 ATTEMPT、追加终结结果，
原预算恢复，未明完成状态拒绝自动重载；同 URL 的每次真实回调都占请求预算。
模拟 route 测试验证 document/脚本/CSS/fetch 等计费，不能证明真实浏览器拦截覆盖。
模型的 robots allow 标志及 execute_live 布尔值只是测试接口，尚未构成可用的授权
验证器；生产适配仍须绑定冻结页面、域名、许可/robots 证据、有效期及预算哈希。

后续适配必须完成：

1. 在创建任何页面前设置 context 路由；阻断 service worker 和 WebSocket，拒绝额外
   页面/弹窗及未冻结主机。Playwright 的 page.route 本地文档说明重定向只处理首个
   URL，必须另测重定向链，不宣称普通 route 已覆盖每跳。无法计费则禁止自动跟随。
2. 逐回调发送前以事务/进程锁记账；分别记录准入、拦截、响应、失败、不明状态。
   页面 document 加全部子请求共用冻结预算，robots 获取也须单独纳入总预算。
   浏览器自身后台流量不属于 page/context route，需限定或明确未覆盖边界。
3. 同一页保存原始 document 字节与渲染 DOM、来源及各自哈希；完成页仅离线复用。
   崩溃后的未知活动不得隐式重新导航；实时缓存/恢复与双进程竞争须另行验收。
4. 页面中的 Cookie、临时会话及个人数据不得进入控制输出/账本或导出持久化浏览器态。
   两篇访问成功不等于 robots 已允许批量使用，也不构成其他页面的访问授权。

建议先保留并使用已实现的离线证据导入/提取，再单独准备页面、精确域名、请求上限与
零重试边界明确的浏览器验证。当前没有新增实网请求，没有正式浏览器命令、包升级或发布。
