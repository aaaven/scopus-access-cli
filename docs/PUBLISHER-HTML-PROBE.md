# 出版社 HTML 独立试验（未加入 CLI）

这是源码目录中的实验脚本 `scripts/publisher_html_probe.py`，**不是已安装 CLI 的新功能**，
也未加入 wheel。Scopus Access CLI 保持 0.5.0，现有 API 补全阶段、凭据和配额行为不变。
实验只判断特定样本的公开文章页面能否带来字段增量；没有真实文章验证成功时不进入 CLI。

## 作者关键词与索引关键词

出版社文章 HTML 可能提供摘要、作者关键词、完整作者名及书目条目，但各站点、文献
类型和页面权限不同，不能承诺每篇都有。字段的来源含义必须确认：

- 明确的 Author Keywords / Author Provided Keywords、作者专用 metadata 或带 author
  标记的关键词组可作为作者关键词候选，并保留 HTML 路径与提取方法。
- 一般 `keywords`、`citation_keywords`、`dc.subject`、Schema.org `keywords` 或仅标为
  Keywords 的区域保留为 `publisher_keywords_unclassified`，当前试验不推定其由作者提供。
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
  截断不填作者列表。列表非空或数量相等不自动等同于原文完整。
- 书目候选必须有实际条目文本，DOI/URL 链接与 JSON-LD citation 链接单独保存。
  对照返回数、明确的页面计数、API 条目数和 load/show more 标记；完整性仍须核验。
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
