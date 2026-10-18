# F01–F05 落实与边界（0.4.0）

这份记录只说明工具实现与离线验证。研究项目的历史 HTTP 200、主对话导入测试、
实际 Scopus 多页能力、筛选可靠性及实质综合是不同层级，不互相替代。

| 项目 | 状态 | 代码依据 | 离线测试依据 |
|---|---|---|---|
| F01 配额遥测诊断与恢复指引 | 已实现 | diagnostics.py、runner.py 的 quota_telemetry；operations.py 的 inspect；保留现有诊断门禁 | test_feedback.py：正常/大小写、缺字段、坏值、过期、不一致、诊断已用、原页恢复 |
| F02 一般 HTTP 错误诊断与参数版本 | 已实现 | 白名单 service_diagnostic、service_error 与受限安全摘要；revise 另建离线预览 | test_feedback.py：400 INVALID_INPUT、数值限制、不同代码、JSON/XML、秘密/查询不泄露、原失败证据不变 |
| F03 大结果集正式分页与技术覆盖检查 | 已实现（离线能力） | 显式 cursor、1–1000 请求、冻结排序；audit 页序/offset/标识符/总量核查 | test_feedback.py：5039 条/26 页、预算耗尽、无重复续取、总量变化/重复/缺口 |
| F04 元数据 profile 与字段能力 | 部分实现 | COMPLETE、details META/META_ABS/FULL/REF、capabilities 成本、conversion 2.0 实际覆盖率 | test_feedback.py：实际字段/缺失字段、403 不降级、独立详情桶与原始来源标记 |
| F05 已准备任务的公开继续入口 | 已实现 | start 沿用原 grant，复用持久执行锁核验全部零活动证据；Terminal 子进程同路分派 | test_feedback.py 与 test_installed_cli.py：启动失败、失联迟到子进程、已准入拒绝、两个进程只发一次 |

实现位于 [src/scopus_access](../src/scopus_access)，测试位于 [tests](../tests)。
完整运行结果与交付 wheel 身份见 [VALIDATION.md](VALIDATION.md)。

F04 尚未实现完整参考文献分页，也没有证明完整作者列表或参考文献网络的覆盖。
FULL/REF 返回一部分数据不会被当作完整性证明；audit 明确输出 not_verified。
Scopus 详情预检的“零发送专用恢复”目前仍只支持原 STANDARD Search 路径，
详情预检凭据失败后不能删除预约或重新初始化绕过。

F03 选择更大初始预算是一种正式有界接口，不会给已有耗尽任务加预算。
同一任务的 resume 只使用原 checkpoint 与剩余预约。跨任务分区检索/覆盖合并与
稳定快照证明不在本次实现中；工具不会自动加年份过滤或宣称总量相同就无遗漏。
所有原始 occurrence 均保留；audit 的 ID 重复计数属于技术核查，不是科学去重。

旧响应若没有保存头部校验信息，inspect 只能报告 telemetry=null；不会补造原因或
认定耗尽。新响应也仅保存允许的配额数值及校验结果，不保存完整头部。参数调整
必须新建版本并另外明确批准，不通过新建任务避开未知配额门禁。

## 官方资料与实网边界

- [Scopus Search 参数](https://dev.elsevier.com/documentation/ScopusSearchAPI.wadl)：显式 view、分页与排序参数。
- [API 设置与限制](https://dev.elsevier.com/api_key_settings.html)：STANDARD 与 COMPLETE 的页数量、offset/cursor 区别。
- [Abstract Retrieval views](https://dev.elsevier.com/sc_abstract_retrieval_views.html)：不同字段和受限 entitlement。

文档核对不是当前 key 的权限证明。真实多页、COMPLETE、详情字段、完整作者及
参考文献能力都需要在另外明确批准的有界实网验收中验证。本次开发不读取真实
Keychain，不向 Scopus API 发送请求，不修改任何研究工程的已有运行证据。
