"""Explicit visible-terminal execution of one existing pinned operation.

This is a local UI handoff, not a permission fallback. The caller must still
supply bounded live consent and have permission to open Terminal. No denied
execution is retried through this module automatically.
"""
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import shlex
import stat
import sys
import time
import uuid
from pathlib import Path

if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scopus_access.errors import ScopusAccessError, ValidationError, SecretProviderError, secret_error_details
from scopus_access.events import validate_event
from scopus_access.project import _atomic_write, _json_bytes
from scopus_access.security import read_file_no_follow, reject_symlink_components
from scopus_access.terminal_init import _launch

_LIMIT = 1024 * 1024
_NAME = re.compile(r"^terminal-run-[0-9a-f]{32}\.json$")
_CODES = {"RELEASE_EXPIRED", "PREFLIGHT_RESUME_DENIED", "LIVE_CAPABILITY_LOCKED", "SECRET_UNAVAILABLE",
          "FETCH_SETUP_FAILED", "PROJECT_NOT_INITIALIZED", "PROJECT_BINDING_MISMATCH", "LOCAL_CONTROL_ERROR",
          "RUN_NOT_FOUND", "RUN_MISMATCH", "TERMINAL_RUN_FAILED", "INVALID_ARGUMENTS"}


class TerminalRunError(ScopusAccessError):
    def __init__(self, code):
        messages = {
            "TERMINAL_RUN_FAILED": "Terminal execution did not return valid completion evidence. Inspect the original run; do not start a new request automatically.",
            "TERMINAL_RUN_TIMEOUT": "Terminal execution has not returned. Inspect the original run and Terminal window; request activity is unknown and no automatic retry was made.",
            "TERMINAL_RUN_IN_PROGRESS": "Another caller is already using Terminal for this run. Use its existing window and original run info.",
        }
        super().__init__(messages[code], code=code)
        self.exit_code = 2 if code == "TERMINAL_RUN_IN_PROGRESS" else 6
        self.failure_stage = "terminal_execution"


def _context(source):
    from scopus_access.fetch import _read_run_info
    from scopus_access.manifest import load_task_manifest
    from scopus_access.policy import load_policy
    info = _read_run_info(str(source))
    manifest = load_task_manifest(info["manifest_path"], load_policy(info["policy_path"]))
    return info, manifest


def _result_path(source, value):
    path = Path(value)
    if path.parent != source.parent or not _NAME.fullmatch(path.name):
        raise TerminalRunError("TERMINAL_RUN_FAILED")
    reject_symlink_components(path)
    return path


def _records(rows, info):
    """Relay only existing validated events and sanitized local failure codes."""
    from scopus_access.cli import _result
    if not isinstance(rows, list) or len(rows) > 256:
        raise TerminalRunError("TERMINAL_RUN_FAILED")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise TerminalRunError("TERMINAL_RUN_FAILED")
        if "event" in row:
            clean = validate_event(row)
            if any(clean.get(key) != info[key] for key in ("project_id", "task_id", "release_id", "parent_run_id", "api_name")):
                raise TerminalRunError("TERMINAL_RUN_FAILED")
            result.append(clean)
        elif row.get("status") in {"error", "locked", "not_admitted"}:
            code = row.get("code")
            code = code if type(code) is str and code in _CODES else "TERMINAL_RUN_FAILED"
            counts = {"network_calls": None, "secret_reads": None, "execution_counts_status": "unknown"}
            if row.get("network_calls") == 0 and row.get("secret_reads") == 0:
                counts = {"network_calls": 0, "secret_reads": 0, "execution_counts_status": "not_started"}
            details = {}
            if code == "SECRET_UNAVAILABLE":
                details = secret_error_details(SecretProviderError(
                    reason=row.get("provider_reason"), stage=row.get("failure_stage"),
                    backend=row.get("provider_backend"), system_error_code=row.get("system_error_code")))
            result.append(_result("terminal-run", row["status"], code=code,
                                  message="Terminal operation did not complete; inspect the error code and original local run.",
                                  **counts, **details))
        # Other run summaries duplicate validated events. Their arbitrary text
        # is never copied into the completion file or agent output.
    return result


def _read_result(path, info, digest, action):
    try:
        reject_symlink_components(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            item = os.fstat(fd)
            if not stat.S_ISREG(item.st_mode) or item.st_size > _LIMIT:
                raise ValueError()
            chunks, remaining = [], _LIMIT + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk: break
                chunks.append(chunk); remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > _LIMIT: raise ValueError()
        finally:
            os.close(fd)
        value = json.loads(data)
        if (not isinstance(value, dict) or set(value) != {"schema_version", "source_sha256", "action", "exit_code", "records"}
                or value["schema_version"] != "1.0" or value["source_sha256"] != digest or value["action"] != action
                or type(value["exit_code"]) is not int or not 0 <= value["exit_code"] <= 6):
            raise ValueError()
        value["records"] = _records(value["records"], info)
        if value["exit_code"] == 0 and not any(
                row.get("event") == "run_completed" and row.get("status") == "completed"
                for row in value["records"]):
            raise ValueError()
        return value
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError, ScopusAccessError):
        raise TerminalRunError("TERMINAL_RUN_FAILED") from None


def run_in_terminal(args, *, timeout=300):
    from scopus_access import cli
    from scopus_access.fetch import _approve_preview, _read_run_info, _write_run_info
    if not args.execute_live or args.command not in {"execute", "resume"} or not args.run_info:
        raise ValidationError("Terminal execution requires original run info and explicit --execute-live consent.")
    if sys.platform != "darwin":
        raise ValidationError("Visible Terminal execution requires macOS.")
    source = Path(args.run_info).absolute()
    reject_symlink_components(source)
    if args.command == "execute":
        _read_run_info(str(source), preview=True)
    else:
        _context(source)
    lock = source.parent / ("terminal-" + hashlib.sha256(str(source).encode()).hexdigest()[:32] + ".lock")
    reject_symlink_components(lock)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    result = None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TerminalRunError("TERMINAL_RUN_FAILED")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TerminalRunError("TERMINAL_RUN_IN_PROGRESS") from None
        action = "start" if args.command == "execute" else "resume"
        if action == "start":
            manifest, policy, database = _approve_preview(str(source))
            source, info = _write_run_info(manifest, policy, database, execute_live=True)
            # Persist and report the exact execution reference BEFORE opening a
            # window, so a missing completion never hides a potentially sent run.
            cli._write_control(sys.stdout, cli._result(
                "scopus-fetch", "prepared", run_info_path=str(source),
                parent_run_id=info["parent_run_id"], manifest_path=str(manifest), policy_path=str(policy),
                database_path=str(database), query_package_sha256=info["query_package_sha256"],
                planned_requests=info["planned_requests"], page_size=info["page_size"], network_calls=0, secret_reads=0))
        info, _ = _context(source)
        digest = hashlib.sha256(read_file_no_follow(source, max_bytes=16384)).hexdigest()
        cwd = Path.cwd().resolve(strict=True)
        identity = str(cwd.stat().st_dev) + ":" + str(cwd.stat().st_ino)
        result = _result_path(source, source.parent / ("terminal-run-" + uuid.uuid4().hex + ".json"))
        words = [sys.executable, "-I", str(Path(__file__).resolve()), str(cwd), str(source), digest, action, str(result), identity]
        command = "cd " + shlex.quote(str(cwd)) + " && exec " + " ".join(shlex.quote(v) for v in words)
        args.runner_entered = True  # after launch, failed IPC cannot establish zero activity
        _launch(command)
        sys.stderr.write("Scopus：已打开 Terminal 执行原任务；请处理可能出现的 macOS 钥匙串授权窗口，无须复制命令。\n")
        sys.stderr.flush()
        deadline = time.monotonic() + timeout
        while True:
            value = _read_result(result, info, digest, action)
            if value is not None:
                _context(source)
                for record in value["records"]: cli._write_control(sys.stdout, record)
                return value["exit_code"]
            if time.monotonic() >= deadline:
                raise TerminalRunError("TERMINAL_RUN_TIMEOUT")
            time.sleep(0.1)
    except KeyboardInterrupt:
        raise TerminalRunError("TERMINAL_RUN_TIMEOUT") from None
    finally:
        if result is not None:
            try:
                reject_symlink_components(result)
                result.unlink()
            except (FileNotFoundError, ValidationError):
                pass
        os.close(fd)


def child_main(arguments=None):
    from scopus_access import cli
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 6: return 2
    try:
        cwd, source, digest, action, result, identity = arguments
        cwd, source = Path(cwd), Path(source)
        reject_symlink_components(cwd); reject_symlink_components(source)
        if action not in {"start", "resume"} or not sys.stdin.isatty():
            raise TerminalRunError("TERMINAL_RUN_FAILED")
        if str(cwd.stat().st_dev) + ":" + str(cwd.stat().st_ino) != identity:
            raise TerminalRunError("TERMINAL_RUN_FAILED")
        os.chdir(cwd)
        if hashlib.sha256(read_file_no_follow(source, max_bytes=16384)).hexdigest() != digest:
            raise TerminalRunError("TERMINAL_RUN_FAILED")
        info, manifest = _context(source)
        result = _result_path(source, result)
        if os.path.lexists(result): raise TerminalRunError("TERMINAL_RUN_FAILED")
        sys.stderr.write("Scopus：执行已明确批准的原查询与预算；key 仅从钥匙串读取，不需要再次粘贴。\n")
        if action == "resume":
            command = ["resume", "--run-info", str(source), "--execute-live"]
        else:
            command = ["preflight" if manifest.task_type == "preflight" else "run", info["manifest_path"],
                       "--policy", info["policy_path"], "--db", info["database_path"],
                       "--run-id", info["parent_run_id"], "--execute-live"]
        output = io.StringIO()
        with contextlib.redirect_stdout(output): code = cli.main(command)
        if len(output.getvalue().encode()) > _LIMIT: raise TerminalRunError("TERMINAL_RUN_FAILED")
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        packet = {"schema_version": "1.0", "source_sha256": digest, "action": action,
                  "exit_code": code, "records": _records(rows, info)}
        _atomic_write(result, _json_bytes(packet))
        sys.stderr.write("操作结束，可以返回 GPT；结果已保存在原工程。\n")
        return code
    except (OSError, ValueError, ScopusAccessError):
        sys.stderr.write("Scopus：无法完成终端交接。请查看原任务状态，不要自动重新发起请求。\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(child_main())
