"""Offline, per-user CLI installation; never reads or writes project state."""

from __future__ import annotations

import email
import fcntl
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import uuid
import venv
import zipfile
from pathlib import Path

from .errors import ValidationError
from .project import _atomic_write, _json_bytes
from .security import read_file_no_follow, reject_symlink_components


COMMANDS = ("scopus-access", "scopus-fetch")
PATH_LINE = 'export PATH="$HOME/.local/bin:$PATH"'


def _wheel_info(path):
    data = read_file_no_follow(path, max_bytes=16 * 1024 * 1024)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                raise ValueError()
            value = email.message_from_bytes(archive.read(names[0]))
        version = value.get("Version", "")
        if (value.get("Name", "").replace("_", "-") != "uaeu-scopus-access-layer"
                or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version)):
            raise ValueError()
    except (ValueError, KeyError, zipfile.BadZipFile):
        raise ValidationError("Select a supported Scopus Access wheel.", code="INVALID_INSTALL_WHEEL") from None
    return version, hashlib.sha256(data).hexdigest(), data


def _run(arguments):
    result = subprocess.run(
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": os.defpath, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
             "PYTHONDONTWRITEBYTECODE": "1"}, check=False,
    )
    if result.returncode:
        raise ValidationError("Offline CLI installation failed; the previous installation remains active.",
                              code="INSTALL_FAILED")


def _install_environment(wheel, environment, version):
    venv.EnvBuilder(with_pip=True).create(str(environment))
    executable = str(environment / "bin/python")
    _run([executable, "-I", "-m", "pip", "install", "--no-index", "--no-deps",
          "--no-cache-dir", str(wheel)])
    # Isolated imports prove this is installed code, independent of PYTHONPATH,
    # the working directory, user site packages, and the source checkout.
    _run([executable, "-I", "-c",
          "import scopus_access,sys; from pathlib import Path; "
          "assert scopus_access.__version__ == sys.argv[1]; "
          "assert Path(scopus_access.__file__).is_relative_to(Path(sys.prefix))", version])
    for command in COMMANDS:
        _run([str(environment / "bin" / command), "--help"])


def _replace_link(path, target):
    temporary = path.parent / (".scopus-link-" + uuid.uuid4().hex)
    try:
        temporary.symlink_to(target)
        os.replace(str(temporary), str(path))
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def install_local(wheel_path, *, home=None, backend=None):
    """Install/upgrade one active user CLI without discovering any project.

    Version directories let activation switch atomically after verification.
    Previous versions are retained; an upgrade failure cannot reset a project
    or remove the last working CLI. The backend injection is for offline tests.
    """
    home = Path(home or Path.home()).resolve(strict=True)
    wheel = Path(wheel_path).expanduser().absolute()
    version, digest, wheel_bytes = _wheel_info(wheel)
    base = home / ".local/share/scopus-access"
    bin_dir = home / ".local/bin"
    profile = home / ".zprofile"
    for directory in (base / "versions", bin_dir):
        reject_symlink_components(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    reject_symlink_components(profile)
    current = base / "current"
    for command in COMMANDS:
        launcher = bin_dir / command
        expected = current / "bin" / command
        if os.path.lexists(launcher) and (not launcher.is_symlink() or os.readlink(launcher) != str(expected)):
            raise ValidationError("An unrelated CLI launcher already exists; it will not be overwritten.",
                                  code="INSTALL_TARGET_CONFLICT")
    lock_path = base / "install.lock"
    reject_symlink_components(lock_path)
    descriptor = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        existing = None
        if os.path.lexists(current):
            if not current.is_symlink():
                raise ValidationError("The installation selector must be a managed link.")
            target = Path(os.readlink(current))
            if not target.is_absolute() or target.parent != base / "versions":
                raise ValidationError("The installation selector points outside the tool environment.")
            reject_symlink_components(target)
            existing = json.loads(read_file_no_follow(target / "installation.json", max_bytes=16384))
        reused = existing == {"schema_version": "1.0", "version": version, "wheel_sha256": digest}
        if not reused:
            environment = base / "versions" / (version + "-" + digest[:12] + "-" + uuid.uuid4().hex[:8])
            environment.mkdir(mode=0o700)
            # Freeze the exact inspected artifact before pip reads it. A
            # concurrently replaced caller wheel cannot change the install.
            artifact_dir = environment / "wheel"
            artifact_dir.mkdir(mode=0o700)
            frozen_wheel = artifact_dir / wheel.name
            _atomic_write(frozen_wheel, wheel_bytes)
            (backend or _install_environment)(frozen_wheel, environment, version)
            if any(not (environment / "bin" / command).is_file() for command in COMMANDS):
                raise ValidationError("The wheel did not install the required CLI commands.")
            _atomic_write(environment / "installation.json", _json_bytes({
                "schema_version": "1.0", "version": version, "wheel_sha256": digest,
            }))
        else:
            environment = target
        # Only fixed, non-secret shell setup is written. Existing profile
        # content is preserved; repeated installation adds no duplicate line.
        line = PATH_LINE.encode()
        old_profile = read_file_no_follow(profile, max_bytes=1024 * 1024) if profile.exists() else b""
        if line not in old_profile.splitlines():
            mode = profile.stat().st_mode & 0o777 if profile.exists() else 0o600
            _atomic_write(profile, old_profile + (b"\n" if old_profile and not old_profile.endswith(b"\n") else b"")
                          + b"\n# Scopus Access Tool (per-user CLI)\n" + line + b"\n")
            profile.chmod(mode)
        for command in COMMANDS:
            _replace_link(bin_dir / command, current / "bin" / command)
        if not reused:
            _replace_link(current, environment)
        return {"status": "reused" if reused else "upgraded" if existing else "installed",
                "version": version, "tool_environment": str(current), "bin_directory": str(bin_dir),
                "shell_profile": str(profile), "wheel_sha256": digest,
                "project_state_changed": False, "network_calls": 0, "secret_reads": 0}
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def main(argv=None):
    from . import cli
    parser = cli._SafeArgumentParser(prog="scopus-access-install", description="Install one per-user CLI from a local wheel, fully offline")
    parser.add_argument("--wheel", required=True)
    try:
        args = parser.parse_args(argv)
        summary = install_local(args.wheel)
        status = summary.pop("status")
        cli._write_control(sys.stdout, cli._result("install", status, **summary))
        return 0
    except (OSError, ValueError, RuntimeError, ValidationError):
        cli._write_control(sys.stdout, cli._result(
            "install", "error", code="INSTALL_FAILED", message="Check the local wheel and user installation paths.",
            network_calls=0, secret_reads=0,
        ))
        return 2
