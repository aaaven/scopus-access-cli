"""Local Terminal handoff for hidden credential input; no API access.

Only non-secret project references and a bounded completion packet cross the
process boundary. The credential stays in the interactive child's memory and
is passed directly to Security.framework by the existing initializer.
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
import subprocess
import sys
import time
import uuid
from pathlib import Path

# The absolute script entry also works when developing from source. -I keeps
# environment/PYTHONPATH out; this is the package containing this exact script.
if __name__ == "__main__" and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scopus_access.errors import ScopusAccessError, SecretProviderError, ValidationError, secret_error_details
from scopus_access.project import (
    ProjectBinding, _atomic_write, _json_bytes, discover_project_policy,
    initialize_project,
)
from scopus_access.security import parse_json_object, read_file_no_follow, reject_symlink_components


WAIT_SECONDS = 300
_PACKET_LIMIT = 4096
_RESULT_NAME = re.compile(r"^terminal-init-[0-9a-f]{32}\.json$")
_APPLESCRIPT = '''on run arguments
    tell application "Terminal"
        activate
        do script (item 1 of arguments)
    end tell
end run'''


class TerminalInitError(ScopusAccessError):
    def __init__(self, code, *, exit_code=2):
        messages = {
            "TERMINAL_OPEN_FAILED": "Could not open Terminal. Check macOS permission to control Terminal and inspect the original operation before retrying.",
            "TERMINAL_INIT_TIMEOUT": "Terminal initialization is still incomplete. Finish or close its window, then retry init; existing state and credentials are preserved.",
            "TERMINAL_INIT_IN_PROGRESS": "Another caller is waiting for this project's Terminal initialization. Use its existing window.",
            "TERMINAL_INIT_FAILED": "Initialization in Terminal did not complete. Inspect that window and retry init; existing state and credentials are preserved.",
        }
        super().__init__(messages[code], code=code)
        self.exit_code = exit_code
        self.failure_stage = "terminal_launch" if code == "TERMINAL_OPEN_FAILED" else "terminal_initialization"


def needs_terminal(error):
    return (sys.platform == "darwin" and not sys.stdin.isatty()
            and isinstance(error, SecretProviderError)
            and error.reason == "interaction_not_allowed"
            and error.failure_stage == "credential_prompt"
            and error.backend == "terminal_input")


def _binding(root, project_id=None):
    root = Path(root).absolute()
    reject_symlink_components(root)
    policy = root / ".scopus-access" / "policy.json"
    reject_symlink_components(policy)
    value = parse_json_object(read_file_no_follow(policy, max_bytes=65536), description="project policy")
    binding = ProjectBinding.from_mapping(value.get("project_binding"), base_dir=policy.parent, allow_pending=True)
    if binding.root != root or (project_id is not None and binding.project_id != project_id):
        raise ValidationError("Terminal initialization must use the original project.", code="PROJECT_BINDING_MISMATCH")
    return binding


def _binding_digest(binding):
    # State may progress pending -> ready; credential references must not change
    # while a different process is asking the human to provide the key.
    value = [str(binding.root), binding.project_id, binding.alias,
             binding.keychain_service, binding.keychain_label]
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _result_path(root, result):
    result = Path(result)
    if (not result.is_absolute() or result.parent != root / ".scopus-access" / "runs"
            or not _RESULT_NAME.fullmatch(result.name)):
        raise ValidationError("Invalid Terminal completion reference.")
    reject_symlink_components(result)
    return result


def _command(binding, result):
    # Every path is shell-quoted; none of these arguments contains a credential.
    arguments = [sys.executable, "-I", str(Path(__file__).resolve()),
                 str(binding.root), str(result), binding.project_id, _binding_digest(binding)]
    return "cd " + shlex.quote(str(binding.root)) + " && exec " + " ".join(shlex.quote(v) for v in arguments)


def _launch(command):
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", _APPLESCRIPT, command],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
        if result.returncode:
            raise TerminalInitError("TERMINAL_OPEN_FAILED")
    except (OSError, subprocess.TimeoutExpired):
        raise TerminalInitError("TERMINAL_OPEN_FAILED") from None


def _packet(project_id, code, row):
    """Keep only fixed-shape, non-secret outcome metadata from the init CLI."""
    success = code == 0 and row.get("status") in {"initialized", "reused"} and row.get("project_id") == project_id
    error = None
    if not success and row.get("code") == "SECRET_UNAVAILABLE":
        error = secret_error_details(SecretProviderError(
            reason=row.get("provider_reason"), stage=row.get("failure_stage"),
            backend=row.get("provider_backend"), system_error_code=row.get("system_error_code"),
        ))
    return {"schema_version": "1.0", "project_id": project_id,
            "exit_code": code if type(code) is int and 0 <= code <= 6 and (code != 0 or success) else 1,
            "status": row["status"] if success else "error",
            "credential_written": row.get("credential_written") is True if success else False,
            "secret_error": error}


def _read_packet(result, project_id):
    try:
        reject_symlink_components(result)
        descriptor = os.open(result, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > _PACKET_LIMIT:
                raise ValueError()
            encoded = os.read(descriptor, _PACKET_LIMIT + 1)
            if len(encoded) > _PACKET_LIMIT:
                raise ValueError()
        finally:
            os.close(descriptor)
        value = json.loads(encoded)
        if (not isinstance(value, dict) or set(value) != {"schema_version", "project_id", "exit_code", "status", "credential_written", "secret_error"}
                or value["schema_version"] != "1.0" or value["project_id"] != project_id
                or type(value["exit_code"]) is not int or not 0 <= value["exit_code"] <= 6
                or type(value["credential_written"]) is not bool
                or value["status"] not in {"initialized", "reused", "error"}
                or (value["exit_code"] == 0) != (value["status"] != "error")):
            raise ValueError()
        if value["secret_error"] is not None:
            details = value["secret_error"]
            if not isinstance(details, dict) or set(details) != {"provider_reason", "failure_stage", "provider_backend", "system_error_code"}:
                raise ValueError()
            error = SecretProviderError(reason=details["provider_reason"], stage=details["failure_stage"],
                                        backend=details["provider_backend"], system_error_code=details["system_error_code"])
            if secret_error_details(error) != details or value["exit_code"] == 0:
                raise ValueError()
        return value
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError, KeyError, ValidationError):
        raise TerminalInitError("TERMINAL_INIT_FAILED") from None


def initialize_in_terminal(start=None, *, launcher=None, timeout=WAIT_SECONDS):
    """Launch only after init released its lock and a hidden prompt was needed."""
    policy = discover_project_policy(start, allow_incomplete=True)
    if policy is None:
        raise TerminalInitError("TERMINAL_INIT_FAILED")
    binding = _binding(policy.parent.parent)
    lock = policy.parent / "terminal-init.lock"
    reject_symlink_components(lock)
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    result = None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise TerminalInitError("TERMINAL_INIT_FAILED")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TerminalInitError("TERMINAL_INIT_IN_PROGRESS") from None
        binding = _binding(binding.root, binding.project_id)
        if binding.state == "ready":
            return initialize_project(binding.root)
        result = _result_path(binding.root, policy.parent / "runs" / ("terminal-init-" + uuid.uuid4().hex + ".json"))
        (launcher or _launch)(_command(binding, result))
        sys.stderr.write("Scopus：已打开 Terminal。请在新窗口粘贴 API key 并回车（不回显）；正在等待初始化结果。\n")
        sys.stderr.flush()
        deadline = time.monotonic() + timeout
        while True:
            if _binding_digest(_binding(binding.root, binding.project_id)) != _binding_digest(binding):
                raise TerminalInitError("TERMINAL_INIT_FAILED")
            packet = _read_packet(result, binding.project_id)
            if packet is not None:
                if packet["secret_error"] is not None:
                    details = packet["secret_error"]
                    raise SecretProviderError(reason=details["provider_reason"], stage=details["failure_stage"],
                                              backend=details["provider_backend"], system_error_code=details["system_error_code"])
                if packet["exit_code"]:
                    raise TerminalInitError("TERMINAL_INIT_FAILED", exit_code=packet["exit_code"])
                if _binding(binding.root, binding.project_id).state != "ready":
                    raise TerminalInitError("TERMINAL_INIT_FAILED")
                summary = initialize_project(binding.root)  # ready path: no credential read or prompt
                summary.update(status=packet["status"], credential_written=packet["credential_written"])
                return summary
            if time.monotonic() >= deadline:
                raise TerminalInitError("TERMINAL_INIT_TIMEOUT", exit_code=4)
            time.sleep(0.1)
    except KeyboardInterrupt:
        raise SecretProviderError(reason="access_denied", stage="terminal_initialization", backend="terminal_input") from None
    finally:
        # Metadata only. A later child completion after timeout is safe and
        # idempotent; a following init will reuse the ready project.
        if result is not None:
            try:
                result.unlink()
            except FileNotFoundError:
                pass
        os.close(descriptor)


def child_main(arguments=None):
    """Private fixed-purpose child: init only, never search or live execution."""
    from scopus_access.cli import main
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 4:
        return 2
    try:
        root, result, project_id, digest = arguments
        binding = _binding(Path(root), project_id)
        if _binding_digest(binding) != digest:
            raise TerminalInitError("TERMINAL_INIT_FAILED")
        result = _result_path(binding.root, result)
        if os.path.lexists(result):
            raise TerminalInitError("TERMINAL_INIT_FAILED")
        os.chdir(binding.root)
        sys.stderr.write("Scopus 初始化：请在下面粘贴 API key 后按回车；输入不会显示。Ctrl-C 可取消。\n")
        if not sys.stdin.isatty():
            error = SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input")
            code, row = error.exit_code, {"code": error.code, **secret_error_details(error)}
        else:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["init"])
            lines = output.getvalue().splitlines()
            row = json.loads(lines[0]) if len(lines) == 1 and len(lines[0]) <= 16384 else {}
        packet = _packet(binding.project_id, code, row if isinstance(row, dict) else {})
        if _binding_digest(_binding(binding.root, binding.project_id)) != digest:
            raise TerminalInitError("TERMINAL_INIT_FAILED")
        _atomic_write(result, _json_bytes(packet))
        sys.stderr.write("已完成，可以返回 GPT；此窗口可以关闭。\n" if packet["exit_code"] == 0
                         else "初始化未完成；请查看上方提示，返回 GPT 后可重试。\n")
        return packet["exit_code"]
    except (OSError, ValueError, ScopusAccessError):
        sys.stderr.write("Scopus：终端初始化未完成；请返回 GPT 重试。\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(child_main())
