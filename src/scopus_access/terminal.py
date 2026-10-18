"""Optional human summaries on interactive stderr, separate from JSONL."""

import sys
import unicodedata


_STEPS = {
    "project_discovery": "工程识别", "project_configuration": "工程配置检查",
    "local_storage": "本地目录或数据库准备", "local_publish": "本地配置发布",
    "credential_prompt": "隐藏输入", "credential_metadata": "钥匙串条目检查",
    "credential_write": "钥匙串保存", "credential_read": "钥匙串读取",
    "credential_decode": "钥匙串数据检查", "keychain_backend": "钥匙串后端加载",
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
    if status in {"error", "locked"}:
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
