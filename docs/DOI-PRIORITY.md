# DOI 优先级交付（0.7.0）

这是本地输出整理政策。它选择同 DOI 组的输出代表，不能证明 DOI、文献类型或
出版身份正确，也不代替筛选、研究纳排或出版商核验。

## 默认交付与显式集合

Search/check/details 执行保存 receipt 后默认生成一份 DOI 派生交付。
`scopus-access export --run-info ...` 从已保存的原始页离线重建 occurrence 和代表交付。
stdout 的 `delivery_ref` 指向受限目录内的摘要 manifest。
原 `records_count` 继续表示原始 occurrence，不改成代表数。

多个互补批次必须由使用者显式指定；一次 deliver 对所有指定输入整体处理：

```sh
cd /path/to/consuming-project
scopus-access deliver --run-info /path/to/batch-a/run-info.json --run-info /path/to/batch-b/run-info.json
scopus-access deliver --input /path/to/union.csv --input /path/to/records.jsonl
scopus-access deliver --input /path/to/enriched/merged.jsonl --doi-policy /path/to/doi-priority-v2.json
```

输入可混用重复的 `--input` 和 `--run-info`，最多 128 个显式文件/运行。
不自动发现邻近任务。run-info 必须属于当前消费工程；从工程根目录或后代目录调用。
已初始化工程不回退到其他工程的配置。兼容旧配置时可显式指定 `--policy`。

CSV 使用 Scopus 导出列名（EID、DOI、Document Type 等）；JSONL/JSON 支持
Scopus 规范化记录及包含 `merged` / `scopus_original` 的补全 wrapper。
显式本地文件可位于受限目录外，按只读方式导入；符号链接、路径逃逸及非法结构拒绝。
输出仅写到当前政策 allowlisted `restricted_metadata` 下。每文件最多 256 MiB，
总输入最多 512 MiB、100 万 occurrence。导入不会创建凭据或请求预算。

## 默认政策 doi-priority-v1.0

先合并同 EID 的 occurrence，再以有效规范化 DOI 分组。每个原 occurrence 均保留
来源文件、输入字节哈希、行位置、原记录哈希及原有 run/page/raw provenance。
同 EID 元数据不同时也整体选择一个来源记录并保留差异，不拼接字段。

DOI 去掉 `doi:` 或 DOI resolver URL 前缀、URL 转义，大小写归一；有效格式为
`10.`、4–9 位数字、斜线及非空且无空白的后缀；ASCII 控制字符和 DEL 无效。缺失或无效 DOI 按 EID 保留；
没有 EID 的记录按 occurrence 独立保留。不同 DOI 不因题名相同合并。

同 DOI 内排序为 Article > Book Chapter > Conference Paper > Preprint，
未列类型排在其后；单例不会因类型被排除。支持 ar/ch/cp、journal article、
chapter、proceedings paper、posted content 等默认别名。

同级比较十个非空书目字段：Title、Authors、Creator、Source title、Year、Abstract、
Author Keywords、Index Keywords、References、Cover Date，再按 EID 升序稳定选择。
这也是原生 lower-case Scopus 字段的对应映射；优先级先于完整度。

题名、来源、类型、年份/日期等冲突为非阻断标记。代表字段来自一条完整来源记录，
不从次记录补空值。状态为 `policy_selected_not_publisher_verified`；稳定 EID 兜底
只是可复现的技术选择。选择理由、全部 EID 和检索成员关系保留在受限映射/日志。

## 版本化文件与计数

`restricted_metadata/scopus/deliveries/<generation>/` 包含：

- `raw_occurrences.jsonl`：原记录及每个输入 occurrence 的来源描述。
- `publications.jsonl`、`publications.csv`：代表主表及归并元数据。
- `record_to_publication.jsonl`：每个原 occurrence 到代表的完整映射。
- `doi_decisions.jsonl`：多 EID 同 DOI 组及同 EID occurrence 归并的取舍、冲突及来源。
- 政策快照、`deduplication.json`：输入、规则、代码和各输出哈希及摘要。

控制输出分别报告 `raw_occurrences_count`、`unique_eid_count`、
`representatives_count`、`secondary_records_count`。缺/无效 DOI、重复 EID
occurrence、重复 DOI 组及取舍理由的细分计数见受限摘要。
Scopus 原始命中量、完整分页核对使用原检索层级，不能拿代表数比较原命中总量。

记录对象哈希采用 UTF-8、键排序的紧凑 JSON（ensure_ascii=false，无尾换行）；
文件哈希覆盖完整原始字节。generation 绑定完整输入字节、政策来源及内容、实现哈希及 CLI 版本。相同输入可幂等重建；
补充元数据、调整政策或升级实现会生成新目录，旧结果不覆盖。自定义政策用
`--doi-policy` 提供版本化 JSON，沿用默认政策结构；不支持替换分组、字段混合等边界。
manifest 最后发布，半途失败不会把不完整版本报告为成功。

派生写入失败时，检索 `run_completed` 报告 `delivery_status=failed`，原 receipt、
消耗和 checkpoint 保留。修复本地问题后离线 export 即可重建，无需重发 API。
本地归并没有凭据读取、配额变更或网络请求；实网检索授权与预算保持原规则。

默认政策内置于包中，仓库提供[机器可读政策样例](../examples/doi-priority-v1.0.json)。
补全批次继续生成原有 merged 导出；随后用 deliver --input 指定这些文件可另产代表版本。
真实验收数据不在仓库或 wheel 内。
