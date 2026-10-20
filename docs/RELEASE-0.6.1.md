# 0.6.1 — 升级后沿用出版社任务

2026-10-20 · Python 3.9+ · macOS

浏览器和静态 HTML 执行/恢复取消当前源码哈希必须等于准备哈希的条件。浏览器
`prepare` 的任务复用比较移除代码哈希，继续校验原输入、页面、域名与全部请求上限。
旧 run-info、scope binding 和历史哈希保持原样，原授权有效期和累计计费继续生效。

执行、恢复和离线解析追加 `runtime.jsonl` 到原任务控制目录，记录实际 CLI/解析器
版本与当前代码哈希。已完成页复用保存证据；已消耗请求不清零；未知发送或完成状态
继续拒绝重发。`enrich export --run-info ...` 可直接离线重解析保存的 HTML，保留历史分析。

```sh
scopus-access install --wheel /absolute/path/to/uaeu_scopus_access_layer-0.6.1-py3-none-any.whl
scopus-access enrich export --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json
scopus-access enrich resume --run-info /path/to/project/.scopus-access/runs/RUN/run-info.json --execute-live
```

恢复仍须本次明确批准、原授权未过期且活动可核实。升级与导出本身不构成联网授权。
验证范围见 [验证记录](VALIDATION.md)，具体边界见 [使用说明](PUBLISHER-HTML.md)。

Browser and static publisher tasks now survive code upgrades without changing
their frozen files. Preparation reuses the original browser task and budget when
inputs and request bounds match. Actual CLI/parser versions and code hashes are
appended to the run log. Completed pages remain cached, spent requests remain
charged, and saved HTML can be reparsed offline. Existing consent, expiry,
integrity and uncertain-replay checks still apply.
