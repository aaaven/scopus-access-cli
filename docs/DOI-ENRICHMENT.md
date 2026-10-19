# DOI 补全阶段（0.5.0）

这是独立的、可选的公开元数据补全阶段。输入是**当前工程已经保存的 Scopus API
规范化 JSONL**，不重新查询 Scopus，不读取 Keychain，不改变 Scopus 配额状态。
Crossref、OpenAlex 仅接收选定的 DOI；查询式、Scopus key、原始 Scopus 记录不会发送。
这项功能只能部分补缺，不能保证每篇文献的全部字段可用。

## 预览 → 执行 → 本地导出

在已初始化工程的根目录或子目录运行。路径必须属于该工程 policy 允许的
`restricted_metadata/scopus` 存储，不接受其他工程或符号链接路径。

```sh
scopus-access enrich prepare \
  --records restricted_metadata/scopus/records/<original-run>/records.jsonl \
  --limit 10 --max-requests 20
```

这一步不联网。按输入保存顺序取前 10 个**记录出现位置**；重复 DOI 保留原记录，但
每个 DOI/来源只安排一次请求。缺失或无效 DOI 原样保留且不请求。JSON 输出给出
`run_info_path`、冻结操作 SHA-256、总预算及各来源上限。具体 DOI 和缺失项保存在
受限目录的 input/operation 文件；操作员应先检查这些文件再批准执行。

支持 `--sources crossref` 或 `--sources openalex`。默认两个来源，固定单条 DOI HTTPS
接口、匿名访问、零重试、不跟随重定向。不会自动换 endpoint、注册 key 或访问出版社。
一次请求通常支持多个字段，不能把每个字段的来源请求数相加当作总消耗。

```sh
# 不加 --execute-live，只显示原任务状态，不请求。
scopus-access enrich execute --run-info <run-info.json>

# 明确批准该冻结 DOI 批次与预算后执行。
scopus-access enrich execute --run-info <run-info.json> --execute-live

# 以下两项完全本地，不读取 key、不联网。
scopus-access enrich status --run-info <run-info.json>
scopus-access enrich export --run-info <run-info.json>
```

执行返回覆盖率、来源、累计请求、预算、缓存命中数及导出引用。控制输出不包含 DOI、
标题、摘要、作者或参考文献内容。交互终端的 stderr 有简短说明，stdout 保持 JSONL。
`requests_attempted` 是整个任务累计的持久计费尝试；执行输出还给出
`requests_attempted_this_invocation` 和 `http_responses_this_invocation`。
`network_calls` 的范围由 `network_calls_scope` 明示；本地 export 的 0 不代表原任务
从未联网。传输失败时实际发送状态可能未知，不猜测为 0。

## 合并和字段语义

- 原始记录始终保存在 `scopus_original`。`merged` 保留原有非空字段，只补空值；字段
  非空不等于完整。不会用外部数据覆盖已有 Scopus 字段或更新原始记录。
- Crossref 优先，OpenAlex 次之。精确规范化 DOI 必须匹配，规范化标题相似度至少 0.90；
  无标题、DOI 不匹配、预印本或提交版本迹象均保留候选并进入人工核对，不自动合并。
  DOI 相同、标题相似、`publishedVersion` 均不构成独立的出版社版本证明。
- Crossref 的 JATS/HTML 摘要转为纯文本；OpenAlex 的倒排索引按位置重建，位置冲突、
  负值或缺口时不生成摘要。原始响应和转换版本保留。
- Crossref `author` 与 OpenAlex 单记录 `authorships` 可补作者列表。记录各来源人数、
  规范化姓名顺序、重复姓名及已知截断；发现截断不填列表。跨来源一致仍不保证完整：
  OpenAlex 可能使用 Crossref 数据，独立的出版社完整性核验状态始终单独报告。
- Crossref `reference` 作为**出版社存入的参考文献条目**，条目可能只有 DOI 或部分
  书目信息。仅 key 的占位条目不填。返回数量与 `reference-count` 相等，只证明这次
  存入数据内部一致，不能宣称出版社原文的参考文献完整。
- OpenAlex `referenced_works` 只存入 `external_semantics.openalex_citation_links`，不填
  `references`，也不把引用网络当作完整书目。
- Crossref `subject` 和 OpenAlex 模型 `keywords` 分别标记为独立的外部分类。
  **不会补成作者关键词或 Scopus 索引关键词。** 当前适配器不提供这两个原生字段；
  如果只缺这些不支持字段，不安排无用请求。

JSONL 包含字段来源、原始响应路径/哈希/时间、候选及身份/版本检查；CSV 包含合并字段、
各字段来源列、单独的模型关键词和引用链接。它们标记为 `scopus_plus_doi_enrichment`，
不是 Scopus 网页原生导出。报告分别给出原始字段存在、转换候选、通过身份门禁的候选、
最终合并覆盖率及仍缺信息；作者/参考文献“非空”与“出版社核实完整”分开。

## 缓存、恢复和预算

```sh
scopus-access enrich resume --run-info <same-run-info.json> --execute-live
```

- `.scopus-access/enrichment.sqlite` 是独立的追加式请求证据库，固定在当前工程。
  不往 Scopus 控制库增加表，不把第三方请求扣成 Scopus 请求或伪造配额观测。
- 请求前用 `BEGIN IMMEDIATE` 检查总量与来源上限并持久记录尝试；同一任务有进程锁，
  不同任务对相同缓存键也有进程锁。多进程不会重复发送同一已完成请求。
- 恢复核验项目/配置/输入/操作/原授权及数据库身份，沿用原预算和 24 小时期限，不续期。
  过期明确报告 `RELEASE_EXPIRED`。预算耗尽不代表字段齐全，也不自动增加预算。
- 已完成、失败、跳过或缓存命中的任务均不重发。发送后状态不明则拒绝重发，需人工检查。
  401/403/429、服务器或传输错误会停止该来源剩余请求；保留证据，不自动重试。
- 同工程成功缓存按来源、规范化 DOI 和映射版本索引，使用前校验路径和正文哈希。
  缓存无自动刷新；如希望再次检查，必须另行设计明确的新请求，而非删除账本绕过门禁。
- 新的预览可以复用成功缓存；`--max-requests 0` 是严格的缓存专用预算，未命中不会联网。
  原批次不因新批次获得额度。每个新的联网批次都需独立明确授权。
- 原始响应在 `restricted_metadata/scopus/enrichment/cache/`；冻结输入/操作、失败响应和
  导出在 `enrichment/batches/<run>/`。导出版本和事件决定不可变的生成目录，升级不会
  覆盖旧证据。运行配置、数据库、缓存和导出不进入 Git。

每个批次最多选择 1,000 个记录出现位置，最多 2,000 次请求。这些是工具边界，并非
上游服务的权限或配额承诺。公开接口仍有速率/访问规则；零重试和失败停止可以减少
无效消耗，但不能保证任意批次均成功。请求成本按实际来源尝试数记录，接口若提供
白名单数值成本头则保留；不推测账单或付费授权。

## 出版社接口评估与尚未验证事项

Crossref/OpenAlex 只提供它们实际持有的元数据。Springer Nature Metadata/Open Access
接口可能提供更多摘要或关键词，但需要独立的服务 key/许可；Elsevier ScienceDirect
文章接口同样有自己的内容权限。当前没有调用、实现或假定这些权限，也不会把 Scopus
key 发送给其他服务。后续出版社适配器必须单独明确接口、凭据、预算和原生字段语义。

实网试验应保存在调用工程，记录样本规则、日期、原始响应和脚本版本。工具仓库的测试
只用合成数据、模拟 transport 和凭据存储；完整离线套件禁止 socket。离线成功不代表
任何文献字段可用，更不证明筛选可靠性或研究结论。

官方接口与字段定义：
[Crossref REST](https://www.crossref.org/documentation/retrieve-metadata/rest-api/)、
[Crossref 访问方式](https://www.crossref.org/documentation/retrieve-metadata/rest-api/access-and-authentication/)、
[OpenAlex 单实体查询](https://help.openalex.org/api/get-single-entities/)、
[OpenAlex Works 字段](https://help.openalex.org/data/works/attributes/)、
[OpenAlex 身份认证](https://help.openalex.org/api/authentication/)、
[Springer Nature Metadata](https://dev.springernature.com/docs/api-endpoints/metadata-api/)、
[Elsevier 文章访问](https://dev.elsevier.com/tecdoc_article_access.html)。
