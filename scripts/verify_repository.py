#!/usr/bin/env python3
"""Read-only publication checks; never reads credentials or accesses a network."""

import json
import re
import subprocess
import sys
from pathlib import Path


BLOCKED_PARTS = {".scopus-access", "restricted_metadata", "runtime", "raw", "checkpoints"}
BLOCKED_SUFFIXES = (".sqlite", ".sqlite3", ".db", ".jsonl", ".key", ".pem", ".pyc", ".log")
PERSONAL_PATH = re.compile(r"/Users/[A-Za-z0-9_.-]+/")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def repository_paths(root):
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "-c", "core.fsmonitor=false", "ls-files",
             "--cached", "--others", "--exclude-standard", "-z"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True,
        )
        return sorted(set(Path(name.decode("utf-8")) for name in result.stdout.split(b"\0") if name))
    ignored = {".git", "build", "dist", "__pycache__"}
    return sorted(p.relative_to(root) for p in root.rglob("*")
                  if (p.is_file() or p.is_symlink()) and not any(
                      part in ignored or part.startswith(".venv") or part.endswith(".egg-info")
                      for part in p.relative_to(root).parts))


def scan_repository(root, paths=None):
    root = Path(root).resolve(strict=True)
    entries = repository_paths(root) if paths is None else [Path(p) for p in paths]
    problems = []

    def reject(path, code):
        problems.append({"file": path.as_posix(), "code": code})

    for relative in entries:
        if relative.is_absolute() or ".." in relative.parts:
            reject(relative, "OUTSIDE_REPOSITORY")
            continue
        if (any(part in BLOCKED_PARTS or part.startswith(".venv") or part.endswith(".egg-info")
                or part in {"build", "dist", "__pycache__"} for part in relative.parts)
                or relative.name == ".env" or relative.name == "local-policy.json"
                or relative.name.endswith(BLOCKED_SUFFIXES)
                or any(marker in relative.name for marker in (".sqlite-", ".sqlite3-", ".db-"))
                or relative.name.endswith((".receipt.json", ".checkpoint.json"))):
            reject(relative, "RUNTIME_OR_SECRET_FILE")
            continue
        path = root / relative
        if any((root.joinpath(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            reject(relative, "SYMLINK")
            continue
        if not path.is_file():
            reject(relative, "MISSING_SOURCE_FILE")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            reject(relative, "NON_TEXT_SOURCE_FILE")
            continue
        if PERSONAL_PATH.search(content):
            reject(relative, "PERSONAL_ABSOLUTE_PATH")
        if re.search(r"(?m)^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", content):
            reject(relative, "PRIVATE_KEY_MATERIAL")
        if path.suffix != ".md":
            continue
        for match in MARKDOWN_LINK.finditer(content):
            link = match.group(1).strip("<>").split("#", 1)[0]
            if not link or link.startswith(("https://", "http://", "mailto:")):
                continue
            if link.startswith(("/", "file:", "codex:")):
                reject(relative, "LOCAL_MACHINE_LINK")
                continue
            destination = (path.parent / link).resolve()
            try:
                destination.relative_to(root)
            except ValueError:
                reject(relative, "DOCUMENT_LINK_OUTSIDE_REPOSITORY")
                continue
            if not destination.exists():
                reject(relative, "BROKEN_DOCUMENT_LINK")
    return {"status": "passed" if not problems else "failed", "files_checked": len(entries),
            "violations_count": len(problems), "violations": problems[:20],
            "network_calls": 0, "secret_reads": 0}


def main():
    try:
        result = scan_repository(Path(__file__).resolve().parent.parent)
    except (OSError, ValueError, subprocess.SubprocessError):
        result = {"status": "failed", "code": "REPOSITORY_CHECK_FAILED",
                  "network_calls": 0, "secret_reads": 0}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
