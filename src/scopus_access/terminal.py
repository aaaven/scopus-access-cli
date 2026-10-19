"""Optional human summaries on interactive stderr, separate from JSONL."""

import sys
import unicodedata


_STEPS = {
    "project_discovery": "工程识别", "project_configuration": "工程配置检查",
    "local_storage": "本地目录或数据库准备", "local_publish": "本地配置发布",
    "credential_prompt": "隐藏输入", "credential_metadata": "钥匙串条目检查",
    "credential_write": "钥匙串保存", "credential_read": "钥匙串读取",
    "credential_decode": "钥匙串数据检查", "keychain_backend": "钥匙串后端加载",
    "terminal_launch": "打开交互终端", "terminal_initialization": "终端初始化", "terminal_execution": "终端执行",
}
_REMEDIES = {
    "credential_not_found": "检查钥匙串是否有当前工程对应的条目；不要借用其他工程配置。",
    "interaction_not_allowed": "在可交互的本机终端重试，并检查 macOS 的授权提示。",
    "access_denied": "授权未通过或已取消；确认允许本工具访问该条目后再明确重试。",
    "keychain_timeout": "读取等待超时，未自动重试；检查系统授权窗口后再明确操作。",
    "credential_already_exists": "已有条目未被覆盖；重跑 init 可检查并复用已有绑定。",
    "keychain_error": "保留系统错误码，检查 macOS 钥匙串状态；工具无法可靠推断具体原因。",
    "credential_input_invalid": "输入为空或格式无效；请在隐藏输入提示中重新输入，勿把 key 放进命令。",
}


def _count(value):
    return str(value) if type(value) is int and value >= 0 else "未知"


def _project(value):
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value if not unicodedata.category(c).startswith("C"))[:60]


def human_message(record):
    command, status, event = record.get("command"), record.get("status"), record.get("event")
    if command == "init":
        name = _project(record.get("display_name"))
        prefix = ("项目“" + name + "”：") if name else ""
        if status in {"initialized", "reused", "legacy_reused"}:
            outcome = ("初始化完成，API key 已保存到 macOS 钥匙串。" if status == "initialized"
                       else "已复用当前项目配置；凭据和账本未被覆盖。")
            state = record.get("quota_state")
            verification = ("本地配置已完成；Scopus API 尚未验证（UNVERIFIED）。" if state == "UNVERIFIED"
                            else "本地配置已就绪；这次 init 没有验证 Scopus API。")
            return prefix + outcome + "\n" + verification + "下一步：scopus-access check --query-file <查询文件>（先预览）。"
    if record.get("code") == "SECRET_UNAVAILABLE" or record.get("code") == "secret_unavailable":
        step = _STEPS.get(record.get("failure_stage"), "凭据访问")
        reason = record.get("provider_reason", "keychain_error")
        explanation = _REMEDIES.get(reason, _REMEDIES["keychain_error"])
        number = record.get("system_error_code")
        suffix = "（OSStatus %d）" % number if type(number) is int else ""
        sent = record.get("network_request_sent")
        activity = "未发出网络请求。" if sent is False else "请求活动请查看原运行记录。"
        return "%s失败：%s%s。%s%s" % (step, reason if reason in _REMEDIES else "keychain_error", suffix, explanation, activity)
    if command == "inspect" and status == "ok":
        return "已核对原任务：状态见 phase；诊断资格、剩余预算和允许的下一步见 next_actions。不需要重新初始化。"
    if command == 'diagnose' and status == 'previewed':
        return "已准备独立诊断预览：沿用原查询，STANDARD、1 次请求、1 条记录、零重试；未联网。需要单独批准后 execute，不改变原任务预算。"
    if command == 'reconcile' and status in {'reconciled','unchanged'}:
        return "已核对历史配额并保留较小余额；仅追加对账证据，未联网或读取密钥。原任务预算与授权期限不变，是否可继续见 can_resume。"
    if command == "audit" and status == "ok":
        return "本地字段覆盖率与分页核查已完成；字段非空不代表权限或参考文献完整，详见 JSON 中的覆盖率和校验状态。"
    if record.get("event") == "quota_telemetry" and record.get("telemetry_reason") not in {"RATE_LIMIT_HEADERS_VALID", "RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC"}:
        if record.get('telemetry_reason') == 'RATE_LIMIT_BALANCE_MIN_APPLIED':
            return "配额差异已自动对账：服务器 %s，本地已计费后 %s，采用较小余额 %s；按原任务预算继续，未退还请求或增加预约。" % (_count(record.get('quota_remaining')), _count(record.get('local_remaining_after_attempt')), _count(record.get('reconciled_remaining')))
        if record.get('telemetry_reason') == 'RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING':
            return "服务器报告余额 %s，本地扣除本次尝试后为 %s；两者不一致，已保守暂停。不是额度耗尽的证据。数据和计费记录保留；用 inspect 核对，不要重新 init。" % (_count(record.get('quota_remaining')), _count(record.get('local_remaining_after_attempt')))
        return "配额遥测未通过：%s。已取得的数据保留；使用 inspect 检查原任务、诊断资格和剩余预算，不要重新 init。" % record.get("telemetry_reason")
    if record.get("event") == "service_error":
        return "服务端返回 HTTP %s：%s。未自动改写查询、切换 view 或重试；具体参数信息见控制记录。" % (_count(record.get("http_status")),record.get("remote_error_code","unclassified"))
    if status in {"error", "locked"}:
        if record.get('code') == 'DIAGNOSTIC_CORRECTION_REQUIRED':
            return "本窗口诊断已用；先检查原任务证据或联系服务商。仅在实际修正请求、网络环境变化或得到服务商指引后，以 --correction 准备一项需另行批准的诊断。"
        if record.get('code') == 'DIAGNOSTIC_NOT_ALLOWED':
            return "当前证据不允许准备该诊断；请 inspect 原 run-info。已有请求、配额和结果均未重置。"
        if str(record.get("code", "")).startswith("TERMINAL_"):
            if command != "init":
                return "终端任务尚未完成：请检查原任务状态和已打开的窗口；请求活动可能未知，不会自动重发或增加预算。"
            return "终端初始化尚未完成：请检查已打开的 Terminal 窗口及 macOS 自动化授权；完成或关闭后可重试 init。凭据和账本未被重置，未联网。"
        if record.get("code") == "EXECUTION_ALREADY_STARTED":
            return "原任务已有准入或请求证据，start 不会重复预约；请 inspect 后按原预算使用 resume。"
        if record.get("code") == "RELEASE_EXPIRED":
            return "原任务授权已过期；需要显式重新授权。resume 不会续期或增加额度，本次未发送请求。"
        if record.get("code") == "PREFLIGHT_RESUME_DENIED":
            return "预检不能恢复：需原预约、零请求尝试、零结果页且失败原因为 secret_unavailable。已发送或证据不完整时不会重发。"
        if record.get("code") == "QUERY_INVALID_CONTROL":
            return "查询含禁止的控制字符 %s，位于第 %s 行、第 %s 列；请修改原文件。未联网。" % (
                record.get("codepoint", "未知"), _count(record.get("line")), _count(record.get("column")))
        if str(record.get("code", "")).startswith("QUERY_"):
            return "查询文件验证失败；请检查 UTF-8 编码、非空内容和 32768 字节上限。未联网。"
        if command == "init":
            step = _STEPS.get(record.get("failure_stage"), "工程配置或本地状态检查")
            return step + "失败。检查当前工程配置及目录权限，保留原文件和账本后重跑 init。"
        if record.get("code") == "PROJECT_NOT_INITIALIZED":
            return "没有找到当前工程配置；请在工程根目录运行 scopus-access init。未联网。"
        return "操作未完成；请按 JSON 中的错误码检查输入、本地配置和运行证据。"
    if status == "previewed":
        return "预览已保存：最多 %s 次请求，每页 %s 条；未联网、未读取密钥。确认后使用 JSON 的 run_info_path 执行。" % (
            _count(record.get("planned_requests")), _count(record.get("page_size")))
    if status == "prepared":
        return "执行计划已保存；正在检查本次批准范围与配额，尚不代表请求已成功。"
    if status == "not_admitted":
        return "本次任务未获配额准入，未发送请求；请检查本地用量和停止原因。"
    if command == "run-status":
        return "本地运行状态已读取：累计尝试 %s 次；未联网、未读取密钥。" % _count(record.get("requests_attempted"))
    if command == "export-records" and status == "completed":
        return "本地导出完成：%s 条记录；未联网、未读取密钥。结果位置见 JSON 的 records_ref。" % _count(record.get("records_count"))
    if command == "usage":
        return "当前工程用量已读取：累计尝试 %s 次。配额状态以本地记录为准，本次未联网。" % _count(record.get("requests_attempted"))
    if command == "quota-status":
        return "已读取本地配额观测；本次没有向 Scopus 查询实时余额。"
    if command == "doctor" and status == "ok":
        return "本地配置和数据库检查完成；这不是 Scopus API 的联网验证。"
    if command == "install" and status in {"installed", "upgraded", "reused"}:
        return "本机 CLI 安装已就绪；工程配置、凭据和历史未被修改。"
    if event == "page_completed":
        return "第 %s 页已保存：HTTP %s，%s 条记录。" % (
            _count(record.get("page_number")), _count(record.get("http_status")), _count(record.get("result_count")))
    if event == "run_completed":
        result = "完成" if status == "completed" else "暂停" if status == "paused" else "失败"
        return "运行%s：%s 次请求尝试，%s 页；结果和后续操作以 JSON 控制记录为准。" % (
            result, _count(record.get("requests_attempted")), _count(record.get("pages_completed")))
    return None


def emit_human(record):
    try:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            return
        message = human_message(record)
        if message:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
    except (OSError, ValueError, AttributeError):
        # A diagnostic must not alter execution or JSON/exit-code semantics.
        pass
