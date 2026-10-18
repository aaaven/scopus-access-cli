"""Offline project-folder binding and idempotent local initialization."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .ledger import Ledger
from .security import parse_json_object, read_file_no_follow, reject_symlink_components, safe_identifier


@dataclass(frozen=True)
class ProjectBinding:
    root: Path
    project_id: str
    alias: str
    keychain_service: str
    keychain_label: str
    state: str

    @property
    def output(self):
        return self.root / "restricted_metadata" / "scopus"

    @property
    def database(self):
        return self.root / ".scopus-access" / "control.sqlite"

    @classmethod
    def from_mapping(cls, value: Any, *, base_dir: Path, allow_pending=False):
        fields = {"root", "directory_device", "directory_inode", "project_id", "alias",
                  "keychain_service", "keychain_label", "state"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValidationError("Invalid project binding.", code="INVALID_PROJECT_BINDING")
        if not isinstance(value["root"], str) or not value["root"]:
            raise ValidationError("Invalid project root.")
        # '..' is the one generated relation from .scopus-access to its root.
        raw = Path(value["root"])
        if not raw.is_absolute() and raw != Path(".."):
            raise ValidationError("Invalid project root relation.")
        root = (base_dir / raw).resolve(strict=True) if not raw.is_absolute() else raw
        reject_symlink_components(root)
        info = root.stat()
        if (not stat.S_ISDIR(info.st_mode)
                or type(value["directory_device"]) is not int
                or type(value["directory_inode"]) is not int
                or (info.st_dev, info.st_ino) != (value["directory_device"], value["directory_inode"])):
            raise ValidationError("Project configuration belongs to a different folder.",
                                  code="PROJECT_FOLDER_MISMATCH")
        project_id = safe_identifier(value["project_id"], field="project_id")
        alias = safe_identifier(value["alias"], field="api_key_alias")
        for field in ("keychain_service", "keychain_label"):
            item = value[field]
            if (not isinstance(item, str) or not item or len(item) > 128
                    or any(ord(character) < 32 for character in item)):
                raise ValidationError("Invalid Keychain metadata.")
        if value["state"] not in ("pending", "ready"):
            raise ValidationError("Invalid initialization state.")
        if value["state"] != "ready" and not allow_pending:
            raise ValidationError("Finish scopus-access init before using this project.",
                                  code="PROJECT_INIT_INCOMPLETE")
        return cls(root, project_id, alias, value["keychain_service"], value["keychain_label"], value["state"])


def discover_project_policy(start=None, *, allow_incomplete=False):
    """Find the nearest marker, rejecting an incomplete or unsafe nearer binding."""

    directory = Path(start or Path.cwd()).resolve(strict=True)
    for root in (directory,) + tuple(directory.parents):
        control = root / ".scopus-access"
        if not os.path.lexists(control):
            continue
        reject_symlink_components(control)
        if not control.is_dir():
            raise ValidationError("Project control path must be a directory.")
        policy = control / "policy.json"
        if os.path.lexists(policy):
            reject_symlink_components(policy)
            read_file_no_follow(policy, max_bytes=65536)
            return policy
        if allow_incomplete:
            return policy
        raise ValidationError("Nearest project has no complete configuration; run scopus-access init.",
                              code="PROJECT_INIT_INCOMPLETE")
    return None


def require_project_context(policy):
    """Explicit legacy files are compatible; bound policies require their folder."""
    from .policy import load_policy
    enclosing = discover_project_policy()
    if enclosing is None:
        if policy.project_binding is not None:
            raise ValidationError("Run scopus-access init in this project first.",
                                  code="PROJECT_NOT_INITIALIZED")
        return
    current = load_policy(str(enclosing))
    if policy.project_binding is not None or current.project_binding is not None:
        if (policy.project_binding != current.project_binding
                or policy.project_api_key_aliases != current.project_api_key_aliases
                or policy.control_database_path != current.control_database_path):
            raise ValidationError("Configuration must use this project's binding.",
                                  code="PROJECT_BINDING_MISMATCH")
        _check_runtime_not_tracked(current.project_binding.root)


@contextmanager
def _initialization_lock(control):
    reject_symlink_components(control)
    control.mkdir(mode=0o700, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(control / "init.lock"), flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValidationError("Invalid initialization lock.")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _atomic_write(path, data):
    """Publish only non-secret configuration; never use this for credential data."""

    reject_symlink_components(path)
    temporary = path.parent / (".init-" + uuid.uuid4().hex)
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        reject_symlink_components(path)
        os.replace(str(temporary), str(path))
        parent = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _check_runtime_not_tracked(root):
    git = shutil.which("git")
    if git is not None:
        # Ignore rules cannot protect files already in the index. Refuse to
        # create/update runtime data in that case; never alter the user's index.
        result = subprocess.run(
            [git, "-C", str(root), "-c", "core.fsmonitor=false", "ls-files", "-z", "--",
             ".scopus-access", "restricted_metadata"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            raise ValidationError("Project control or restricted data is already tracked by Git; remove it from the index first.",
                                  code="PROJECT_RUNTIME_TRACKED")


def _ignore_runtime(root):
    _check_runtime_not_tracked(root)
    path = root / ".gitignore"
    reject_symlink_components(path)
    original = read_file_no_follow(path) if path.exists() else b""
    patterns = [b"/.scopus-access/", b"/restricted_metadata/"]
    # Append after any negations. Repeated initialization is byte-identical
    # once the final protective rules exist.
    if original.splitlines()[-2:] != patterns:
        value = original + (b"\n" if original and not original.endswith(b"\n") else b"")
        _atomic_write(path, value + b"\n".join(patterns) + b"\n")


def initialize_project(start=None, *, writer=None, prompt=None):
    """Initialize once, or resume a pending setup without replacing its key."""

    progress = {"stage": "project_discovery"}
    try:
        return _initialize_project(start, writer=writer, prompt=prompt, progress=progress)
    except BaseException as exc:
        # Attach only a fixed step name; preserve the original exception type
        # and CLI exit code. Keychain errors already carry a precise stage.
        from .errors import SecretProviderError
        if not isinstance(exc, SecretProviderError):
            try:
                exc.failure_stage = progress["stage"]
            except (AttributeError, TypeError):
                pass
        raise


def _initialize_project(start=None, *, writer=None, prompt=None, progress):

    from .policy import load_policy
    from .errors import SecretProviderError
    from .secrets import LOCAL_KEYCHAIN_SERVICE, MacOSKeychainWriter, prompt_api_key

    directory = Path(start or Path.cwd()).resolve(strict=True)
    existing = discover_project_policy(directory, allow_incomplete=True)
    path = existing or directory / ".scopus-access" / "policy.json"
    root = path.parent.parent
    with _initialization_lock(path.parent):
        progress["stage"] = "project_configuration"
        _ignore_runtime(root)
        new = not path.exists()
        if not new:
            value = parse_json_object(read_file_no_follow(path, max_bytes=65536), description="project policy")
            if "project_binding" not in value:
                # A legacy policy is never silently converted or renamed.
                policy = load_policy(str(path))
                if len(policy.project_api_key_aliases) != 1:
                    raise ValidationError("Legacy initialization needs one configured project.")
                project_id = next(iter(policy.project_api_key_aliases))
                return {"status": "legacy_reused", "project_id": project_id,
                        "policy_path": str(path), "credential_written": False,
                        "quota_state": None, "quota_unchanged": True}
            binding = ProjectBinding.from_mapping(value["project_binding"], base_dir=path.parent,
                                                  allow_pending=True)
            if binding.root != root:
                raise ValidationError("Initialization must use the bound project folder.")
            if binding.state == "ready":
                policy = load_policy(str(path))
                reject_symlink_components(binding.database)
                ledger = Ledger(policy.control_database_path, require_existing_identity=True)
                return _summary(binding, path, "reused", False, ledger)
        else:
            identity = root.stat()
            identifier = uuid.uuid4().hex
            project_id, alias = "project_" + identifier, "scopus_" + identifier
            value = {
                "schema_version": "1.0",
                "project_binding": {
                    "root": "..", "directory_device": identity.st_dev,
                    "directory_inode": identity.st_ino, "project_id": project_id,
                    "alias": alias, "keychain_service": LOCAL_KEYCHAIN_SERVICE,
                    "keychain_label": "Scopus Access Tool / " + project_id, "state": "pending",
                },
                "project_output_roots": {project_id: ["../restricted_metadata"]},
                "project_api_key_aliases": {project_id: {
                    "scopus_search": alias, "abstract_retrieval": alias,
                }},
                "control_database_path": "control.sqlite", "live_capability_enabled": True,
            }
            _atomic_write(path, _json_bytes(value))
            binding = ProjectBinding.from_mapping(value["project_binding"], base_dir=path.parent,
                                                  allow_pending=True)
        # Validate the whole candidate before any prompt or credential write.
        candidate = json.loads(json.dumps(value))
        candidate["project_binding"]["state"] = "ready"
        from .policy import PolicyConfig
        PolicyConfig.from_mapping(candidate, base_dir=path.parent)
        progress["stage"] = "local_storage"
        for directory in (path.parent / "runs", binding.root / "restricted_metadata", binding.output):
            reject_symlink_components(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        reject_symlink_components(binding.database)
        ledger = Ledger(binding.database)
        for suffix in ("", "-wal", "-shm"):
            database_file = Path(str(binding.database) + suffix)
            if os.path.lexists(database_file):
                reject_symlink_components(database_file)
                os.chmod(str(database_file), 0o600)
        writer = writer if writer is not None else MacOSKeychainWriter(binding.keychain_service)
        written = False
        # On a resumed setup, query attributes only. A crash after SecItemAdd
        # must not overwrite the item or force a second credential entry.
        progress["stage"] = "credential_metadata"
        if new or not writer.contains_api_key(binding.alias):
            progress["stage"] = "credential_prompt"
            with (prompt or prompt_api_key)() as secret:
                try:
                    progress["stage"] = "credential_write"
                    writer.add_api_key(binding.alias, binding.keychain_label, secret)
                except SecretProviderError:
                    raise
                except Exception:
                    raise SecretProviderError(stage="credential_write", backend="macos_security_framework") from None
            written = True
        progress["stage"] = "local_publish"
        reference = hashlib.sha256(_json_bytes(candidate)).hexdigest()
        ledger.register_project_key_alias(binding.project_id, binding.alias, reference)
        _atomic_write(path, _json_bytes(candidate))
        ready = ProjectBinding.from_mapping(candidate["project_binding"], base_dir=path.parent)
        return _summary(ready, path, "initialized", written, ledger)


def _summary(binding, path, status, written, ledger):
    states = {}
    for api in ("scopus_search", "abstract_retrieval"):
        snapshot = ledger.quota_status(binding.alias, api)
        states[api] = snapshot.state.value if snapshot is not None else "UNVERIFIED"
    return {"status": status, "project_id": binding.project_id,
            "display_name": binding.root.name, "key_alias": binding.alias,
            "keychain_label": binding.keychain_label, "policy_path": str(path),
            "database_path": str(binding.database), "output_dir": str(binding.output),
            "credential_written": written, "quota_state": states["scopus_search"],
            "quota_states": states, "quota_unchanged": True}
