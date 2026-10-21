# 0.7.0：默认 DOI 优先级交付

2026-10-21。本版加入离线 DOI 输出整理，并保留 0.6.1 的出版社旧任务兼容行为。

检索及 export 默认生成代表主表、每个 occurrence 的完整映射、取舍日志和摘要。
显式 `deliver` 可跨页、跨批整体整理已保存 CSV/JSONL/JSON 或当前工程的多个
run-info。同 EID 先归并；同 DOI 按 Article > Book Chapter > Conference Paper >
Preprint、完整度和稳定 EID 选择。冲突为非阻断记录，不声称出版商验证，不拼接
不同记录字段，不按题名合并不同 DOI。

派生文件使用不可覆盖的版本目录，保留输入、来源、原始哈希、政策及代码哈希。
原始 occurrence、命中数、分页完整性、receipt、原任务预算和累计消耗均保持。
详见 [使用说明](DOI-PRIORITY.md) 和 [验收记录](VALIDATION.md)。

安装本地 wheel：

```sh
scopus-access install --wheel /absolute/path/to/uaeu_scopus_access_layer-0.7.0-py3-none-any.whl
```

本次功能验收只使用模拟传输及保留数据，不新增 Scopus、出版社或补全请求。
本版不改变实网授权、订阅权限或浏览器实网验收状态。

English: Versioned offline DOI-priority deliveries now preserve representative records,
every-occurrence mappings, nonblocking conflicts and complete provenance across explicit
collections. Original retrieval evidence, page totals, quota and request budgets remain
unchanged. Policy selection is not publisher verification.
