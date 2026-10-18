"""Small security primitives shared by policy, manifests, and the client."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .errors import ValidationError


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SENSITIVE_NAME_RE = re.compile(
    r"(?:api[_-]?key|authorization|cookie|token|secret|password)", re.IGNORECASE
)


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON suitable for a small receipt hash."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("Value cannot be represented as canonical JSON.") from exc
    return rendered.encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_sha256(value: Any, *, field: str = "sha256") -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError("Expected a lowercase SHA-256 digest.", code="INVALID_HASH")
    return value


def safe_identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise ValidationError(
            "Invalid control-plane identifier for {}.".format(field),
            code="INVALID_IDENTIFIER",
        )
    return value


def execution_run_id(
    project_id: str,
    task_id: str,
    release_id: str,
    parent_run_id: str,
    api_name: str,
) -> str:
    """Derive one stable child namespace from its complete control linkage."""

    values = (
        safe_identifier(project_id, field="project_id"),
        safe_identifier(task_id, field="task_id"),
        safe_identifier(release_id, field="release_id"),
        safe_identifier(parent_run_id, field="parent_run_id"),
        safe_identifier(api_name, field="api_name"),
    )
    material = "\x1f".join(values).encode("utf-8")
    return "exec_%s_%s" % (hashlib.sha256(material).hexdigest()[:32], api_name)


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("JSON contains a duplicate object key.", code="DUPLICATE_KEY")
        result[key] = value
    return result


def parse_json_object(data: bytes, *, description: str = "JSON document") -> Dict[str, Any]:
    """Parse a UTF-8 JSON object, rejecting duplicates and non-finite numbers."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("{} is not UTF-8.".format(description)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValidationError("JSON contains a non-finite number.")
            ),
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ValidationError("{} is not valid JSON.".format(description)) from exc
    if not isinstance(value, dict):
        raise ValidationError("{} must be a JSON object.".format(description))
    return value


def _lexical_path(path: Path) -> Path:
    if any(part == ".." for part in path.parts):
        raise ValidationError("Parent traversal is not allowed.", code="PATH_TRAVERSAL")
    if "\x00" in str(path):
        raise ValidationError("Path contains an invalid character.", code="INVALID_PATH")
    return path


def _existing_components(path: Path) -> Iterable[Path]:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        current = current / part
        if os.path.lexists(str(current)):
            yield current
        else:
            break


def reject_symlink_components(path: Path) -> None:
    """Reject an existing symlink in a path chain, including the leaf."""

    absolute = path if path.is_absolute() else (Path.cwd() / path)
    for component in _existing_components(absolute):
        try:
            mode = os.lstat(str(component)).st_mode
        except OSError as exc:
            raise ValidationError("Path could not be inspected.", code="INVALID_PATH") from exc
        if stat.S_ISLNK(mode):
            raise ValidationError("Symlink paths are not allowed.", code="SYMLINK_REJECTED")


def resolve_input_file(path_value: Any, *, base_dir: Optional[Path] = None) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValidationError("Evidence path must be a non-empty string.", code="INVALID_PATH")
    raw = _lexical_path(Path(path_value))
    if not raw.is_absolute():
        if base_dir is None:
            raise ValidationError("Relative path requires a base directory.", code="INVALID_PATH")
        raw = _lexical_path(base_dir / raw)
    # Hash pinning protects evidence reached through stable platform aliases such
    # as macOS /var -> /private/var.  The leaf itself must still be a real file.
    if os.path.islink(str(raw)):
        raise ValidationError("Symlink evidence files are not allowed.", code="SYMLINK_REJECTED")
    resolved = raw.resolve(strict=True)
    if not resolved.is_file():
        raise ValidationError("Evidence path is not a regular file.", code="INVALID_PATH")
    return resolved


def read_file_no_follow(path: Path, *, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    """Read one bounded regular file without following a leaf symlink."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise ValidationError("Evidence file could not be opened.", code="INVALID_PATH") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("Evidence path is not a regular file.", code="INVALID_PATH")
        if info.st_size > max_bytes:
            raise ValidationError("Evidence file exceeds the size limit.", code="FILE_TOO_LARGE")
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValidationError("Evidence file exceeds the size limit.", code="FILE_TOO_LARGE")
        return data
    finally:
        os.close(descriptor)


def read_verified_json(
    path_value: Any,
    expected_sha256: Any,
    *,
    base_dir: Optional[Path] = None,
    description: str = "evidence document",
    max_bytes: int = 2 * 1024 * 1024,
) -> Tuple[Path, Dict[str, Any]]:
    expected = validate_sha256(expected_sha256)
    path = resolve_input_file(path_value, base_dir=base_dir)
    data = read_file_no_follow(path, max_bytes=max_bytes)
    observed = sha256_bytes(data)
    if not hmac.compare_digest(observed, expected):
        raise ValidationError("Pinned evidence hash does not match.", code="HASH_MISMATCH")
    return path, parse_json_object(data, description=description)


def sha256_file(path_value: Any, *, max_bytes: int = 64 * 1024 * 1024) -> str:
    path = resolve_input_file(path_value)
    return sha256_bytes(read_file_no_follow(path, max_bytes=max_bytes))


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_restricted_output_dir(
    path_value: Any, allowed_roots: Sequence[Path]
) -> Path:
    """Validate a project ``restricted_metadata`` directory or a descendant.

    The path is not created here.  Existing symlinks in either the candidate or
    allow-list roots are rejected so a later writer cannot be redirected outside
    the approved project tree.
    """

    if not isinstance(path_value, str) or not path_value:
        raise ValidationError("Project output directory is required.", code="INVALID_PATH")
    raw = _lexical_path(Path(path_value))
    if not raw.is_absolute():
        raise ValidationError("Project output directory must be absolute.", code="INVALID_PATH")
    if "restricted_metadata" not in raw.parts:
        raise ValidationError(
            "Project output must be within restricted_metadata.",
            code="OUTPUT_NOT_RESTRICTED_METADATA",
        )
    candidate = raw.resolve(strict=False)
    if not allowed_roots:
        raise ValidationError("No project output roots are allow-listed.", code="OUTPUT_NOT_ALLOWED")
    for root_value in allowed_roots:
        root_raw = _lexical_path(Path(root_value))
        if not root_raw.is_absolute():
            raise ValidationError("Allow-list roots must be absolute.", code="INVALID_POLICY")
        root = root_raw.resolve(strict=False)
        try:
            lexical_relative = raw.relative_to(root_raw)
        except ValueError:
            lexical_relative = None
        if lexical_relative is not None:
            current = root_raw
            if os.path.islink(str(current)):
                raise ValidationError("Symlink paths are not allowed.", code="SYMLINK_REJECTED")
            for part in lexical_relative.parts:
                current = current / part
                if os.path.lexists(str(current)) and os.path.islink(str(current)):
                    raise ValidationError("Symlink paths are not allowed.", code="SYMLINK_REJECTED")
        if candidate == root or _is_within(candidate, root):
            # Reject symlinks controlled inside the allow-listed project tree,
            # while tolerating stable OS aliases that precede that tree.
            try:
                relative = raw.relative_to(root_raw)
                inspection_root = root_raw
            except ValueError:
                relative = candidate.relative_to(root)
                inspection_root = root
            if lexical_relative is not None:
                return candidate
            if os.path.islink(str(inspection_root)):
                raise ValidationError("Symlink paths are not allowed.", code="SYMLINK_REJECTED")
            current = inspection_root
            for part in relative.parts:
                current = current / part
                if os.path.lexists(str(current)) and os.path.islink(str(current)):
                    raise ValidationError("Symlink paths are not allowed.", code="SYMLINK_REJECTED")
            return candidate
    raise ValidationError("Project output is outside the allow-list.", code="OUTPUT_NOT_ALLOWED")


def redacted_mapping(mapping: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a shallow control-plane representation safe for diagnostics."""

    return {
        key: "<redacted>" if SENSITIVE_NAME_RE.search(key) else value
        for key, value in mapping.items()
    }
