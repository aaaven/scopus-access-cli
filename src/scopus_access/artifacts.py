"""Restricted data-plane artifact storage.

Raw response bytes never pass through the control event layer.  They are
written atomically beneath a pre-validated, policy-allowlisted project root;
the control plane receives only bounded relative references and SHA-256
digests.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .security import execution_run_id


ARTIFACT_SCHEMA_VERSION = "1.0"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_RECEIPT_LIMIT = 8_192


class ArtifactError(RuntimeError):
    """Base error for restricted artifact operations."""


class UnsafeArtifactPath(ArtifactError):
    """Raised when a requested path is outside an allowlisted root."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ArtifactError("%s must be a bounded identifier" % label)
    return value


def _validated_utc(value: str, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ArtifactError("%s must be a canonical UTC timestamp" % label)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ArtifactError("%s must be a valid UTC timestamp" % label) from None
    return value


def _open_absolute_directory_no_symlinks(path: Path) -> int:
    """Open every component relative to its parent with symlinks forbidden."""

    absolute = Path(path)
    if not absolute.is_absolute():
        raise UnsafeArtifactPath("artifact root must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        identity = os.fstat(descriptor)
        if not stat.S_ISDIR(identity.st_mode):
            raise UnsafeArtifactPath("artifact root must be a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_restricted_root(
    requested_root: Path,
    allowed_roots: Iterable[Path],
) -> Path:
    """Resolve and validate an existing restricted output directory.

    Both the requested directory and configured allowlist roots must be
    absolute and already exist.  Requiring provisioning before a run avoids
    guessing which project owns a newly created directory.
    """

    requested = Path(requested_root)
    if not requested.is_absolute():
        raise UnsafeArtifactPath("restricted output root must be absolute")
    try:
        resolved = requested.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as exc:
        raise UnsafeArtifactPath("restricted output root must already exist") from exc
    if not resolved.is_dir():
        raise UnsafeArtifactPath("restricted output root must be a directory")

    canonical_allowlist = []
    for configured in allowed_roots:
        root = Path(configured)
        if not root.is_absolute():
            raise UnsafeArtifactPath("allowlisted roots must be absolute")
        try:
            canonical = root.resolve(strict=True)
        except (FileNotFoundError, RuntimeError) as exc:
            raise UnsafeArtifactPath("allowlisted root must already exist") from exc
        if not canonical.is_dir():
            raise UnsafeArtifactPath("allowlisted root must be a directory")
        canonical_allowlist.append(canonical)
    if not canonical_allowlist:
        raise UnsafeArtifactPath("at least one restricted root must be allowlisted")
    if not any(_is_within(resolved, root) for root in canonical_allowlist):
        raise UnsafeArtifactPath("restricted output root is outside the allowlist")
    return resolved


@dataclass(frozen=True)
class ArtifactRecord:
    schema_version: str
    run_id: str
    attempt_id: str
    page_number: int
    artifact_ref: str
    sha256: str
    size_bytes: int
    recorded_at_utc: str


@dataclass(frozen=True)
class RecordsExport:
    ref: str
    sha256: str
    record_count: int
    page_count: int


@dataclass(frozen=True)
class Checkpoint:
    run_id: str
    next_page: int
    next_cursor: Optional[str]
    completed_pages: int
    requests_attempted: int
    retries_used: int
    complete: bool
    last_artifact_sha256: Optional[str]
    saved_at_utc: str = ""

    def validated(self, *, timestamp: Optional[str] = None) -> "Checkpoint":
        _safe_id(self.run_id, "run_id")
        for value in (
            self.next_page,
            self.completed_pages,
            self.requests_attempted,
            self.retries_used,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ArtifactError("checkpoint counts must be non-negative integers")
        if self.next_page < 1:
            raise ArtifactError("checkpoint next_page must be at least one")
        if self.next_cursor is not None:
            if not isinstance(self.next_cursor, str) or len(self.next_cursor) > 4_096:
                raise ArtifactError("checkpoint cursor is invalid")
            if any(ord(char) < 32 for char in self.next_cursor):
                raise ArtifactError("checkpoint cursor contains a control character")
        if self.last_artifact_sha256 is not None and not _SHA256_RE.fullmatch(
            self.last_artifact_sha256
        ):
            raise ArtifactError("checkpoint digest is invalid")
        if not isinstance(self.complete, bool):
            raise ArtifactError("checkpoint complete must be boolean")
        saved = self.saved_at_utc or timestamp or utc_now()
        _validated_utc(saved, "saved_at_utc")
        return Checkpoint(
            run_id=self.run_id,
            next_page=self.next_page,
            next_cursor=self.next_cursor,
            completed_pages=self.completed_pages,
            requests_attempted=self.requests_attempted,
            retries_used=self.retries_used,
            complete=self.complete,
            last_artifact_sha256=self.last_artifact_sha256,
            saved_at_utc=saved,
        )

    def as_json(self) -> Dict[str, Any]:
        validated = self.validated()
        data = asdict(validated)
        data["schema_version"] = ARTIFACT_SCHEMA_VERSION
        return data


@dataclass(frozen=True)
class RunReceipt:
    run_id: str
    parent_run_id: str
    project_id: str
    task_id: str
    release_id: str
    reservation_id: str
    api_name: str
    status: str
    completeness: str
    pages_completed: int
    requests_attempted: int
    retries_used: int
    stop_reason: str
    checkpoint_ref: str
    receipt_ref: str
    artifact_manifest_ref: Optional[str]
    artifact_manifest_sha256: Optional[str]
    started_at_utc: str
    completed_at_utc: str
    records_ref: Optional[str] = None
    records_sha256: Optional[str] = None
    records_count: int = 0
    records_pages: int = 0

    def as_json(self) -> Dict[str, Any]:
        for label, value in (
            ("run_id", self.run_id),
            ("parent_run_id", self.parent_run_id),
            ("project_id", self.project_id),
            ("task_id", self.task_id),
            ("release_id", self.release_id),
            ("reservation_id", self.reservation_id),
            ("api_name", self.api_name),
            ("status", self.status),
            ("completeness", self.completeness),
            ("stop_reason", self.stop_reason),
        ):
            _safe_id(value, label)
        if self.run_id != execution_run_id(
            self.project_id,
            self.task_id,
            self.release_id,
            self.parent_run_id,
            self.api_name,
        ):
            raise ArtifactError(
                "receipt execution namespace does not match its linkage"
            )
        if self.status not in {"completed", "paused", "failed"}:
            raise ArtifactError("receipt status is invalid")
        if self.completeness not in {"not_started", "partial", "complete"}:
            raise ArtifactError("receipt completeness is invalid")
        if self.stop_reason not in {
            "none",
            "already_complete",
            "request_boundary_reached",
            "secret_unavailable",
            "attempt_record_failed",
            "transport_error",
            "authorization_failed",
            "quota_exhausted",
            "quota_telemetry_unknown",
            "throttle_retry_exhausted",
            "http_error",
            "running_task_quota_risk",
            "reservation_close_failed",
        }:
            raise ArtifactError("receipt stop reason is invalid")
        for value in (
            self.pages_completed,
            self.requests_attempted,
            self.retries_used,
            self.records_count,
            self.records_pages,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ArtifactError("receipt counts must be non-negative integers")
        for digest in (
            self.artifact_manifest_sha256,
            self.records_sha256,
        ):
            if digest is not None and not _SHA256_RE.fullmatch(digest):
                raise ArtifactError("receipt digest is invalid")
        _validated_utc(self.started_at_utc, "started_at_utc")
        _validated_utc(self.completed_at_utc, "completed_at_utc")
        expected_checkpoint = (Path("checkpoints") / (self.run_id + ".checkpoint.json")).as_posix()
        expected_receipt = (Path("receipts") / (self.run_id + ".receipt.json")).as_posix()
        expected_manifest = (Path("manifests") / (self.run_id + ".responses.jsonl")).as_posix()
        if self.checkpoint_ref != expected_checkpoint or self.receipt_ref != expected_receipt:
            raise ArtifactError("receipt references do not match the run identifier")
        if self.artifact_manifest_ref not in {None, expected_manifest}:
            raise ArtifactError("artifact manifest reference does not match the run identifier")
        if (self.artifact_manifest_ref is None) != (
            self.artifact_manifest_sha256 is None
        ):
            raise ArtifactError("artifact manifest reference and digest must be paired")
        expected_records = (Path("records") / self.run_id / "records.jsonl").as_posix()
        if self.records_ref not in {None, expected_records}:
            raise ArtifactError("records reference does not match the run identifier")
        if (self.records_ref is None) != (self.records_sha256 is None):
            raise ArtifactError("records reference and digest must be paired")
        if self.records_ref is None and (self.records_count or self.records_pages):
            raise ArtifactError("records counts require an export reference")
        data = asdict(self)
        data["schema_version"] = ARTIFACT_SCHEMA_VERSION
        # The receipt must stay scalar and bounded; it must never become a
        # convenient container for result arrays.
        if any(isinstance(value, (dict, list, tuple, set)) for value in data.values()):
            raise ArtifactError("receipt fields must be scalar")
        return data


class RestrictedArtifactStore:
    """Write bytes and compact control receipts beneath one validated root."""

    def __init__(
        self,
        output_root: Path,
        *,
        allowed_roots: Iterable[Path],
    ) -> None:
        self.root = validate_restricted_root(output_root, allowed_roots)
        try:
            root_fd = _open_absolute_directory_no_symlinks(self.root)
        except OSError as exc:
            raise UnsafeArtifactPath("restricted output root is not symlink-safe") from exc
        try:
            root_stat = os.fstat(root_fd)
            self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        finally:
            os.close(root_fd)

    @staticmethod
    def _relative_parts(relative: Path) -> Tuple[str, ...]:
        value = Path(relative)
        if value.is_absolute() or not value.parts or ".." in value.parts:
            raise UnsafeArtifactPath("artifact path must be relative")
        if any(part in {"", "."} for part in value.parts):
            raise UnsafeArtifactPath("artifact path contains an invalid component")
        return tuple(value.parts)

    def _open_root_fd(self) -> int:
        try:
            descriptor = _open_absolute_directory_no_symlinks(self.root)
        except OSError as exc:
            raise UnsafeArtifactPath("restricted output root cannot be reopened safely") from exc
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(identity.st_mode)
            or (identity.st_dev, identity.st_ino) != self._root_identity
        ):
            os.close(descriptor)
            raise UnsafeArtifactPath("restricted output root identity changed")
        return descriptor

    @contextmanager
    def _parent_fd(self, relative: Path, *, create: bool) -> Any:
        parts = self._relative_parts(relative)
        descriptors = [self._open_root_fd()]
        try:
            current = descriptors[0]
            for component in parts[:-1]:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                child = os.open(component, flags, dir_fd=current)
                child_stat = os.fstat(child)
                if not stat.S_ISDIR(child_stat.st_mode):
                    os.close(child)
                    raise UnsafeArtifactPath("artifact parent is not a directory")
                descriptors.append(child)
                current = child
            yield current, parts[-1]
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise UnsafeArtifactPath("artifact path traversal was rejected") from exc
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @staticmethod
    def _require_regular(descriptor: int) -> None:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise UnsafeArtifactPath("artifact target must be a regular file")

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise ArtifactError("artifact write made no forward progress")
            offset += written

    def _atomic_write(self, relative: Path, data: bytes, *, immutable: bool = False) -> Path:
        if not isinstance(data, bytes):
            raise ArtifactError("artifact data must be bytes")
        return self._atomic_write_chunks(relative, (data,), original=data if immutable else None)

    def _atomic_write_chunks(
        self, relative: Path, chunks: Iterable[bytes], *, original: Optional[bytes] = None
    ) -> Path:
        temporary_name = ".pending-" + uuid.uuid4().hex
        with self._parent_fd(relative, create=True) as (parent_fd, target_name):
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
                try:
                    os.fchmod(descriptor, 0o600)
                    for chunk in chunks:
                        self._write_all(descriptor, chunk)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                try:
                    existing = os.stat(
                        target_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    existing = None
                if existing is not None and not stat.S_ISREG(existing.st_mode):
                    raise UnsafeArtifactPath(
                        "artifact target must not replace a symlink or directory"
                    )
                if original is not None:
                    # Publish without replacing an existing raw response.
                    try:
                        os.link(temporary_name, target_name,
                                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                                follow_symlinks=False)
                    except FileExistsError:
                        if self._read_relative(relative, max_bytes=len(original)) != original:
                            raise ArtifactError("immutable raw response conflict") from None
                    os.unlink(temporary_name, dir_fd=parent_fd)
                    temporary_name = ""
                else:
                    os.replace(
                        temporary_name,
                        target_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    temporary_name = ""
                os.fsync(parent_fd)
            finally:
                if temporary_name:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
        return self.root / relative

    def _locked(self) -> Tuple[int, Any]:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        root_fd = self._open_root_fd()
        try:
            fd = os.open(".artifact.lock", flags, 0o600, dir_fd=root_fd)
        finally:
            os.close(root_fd)
        self._require_regular(fd)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd, fcntl

    def _append_jsonl(self, relative: Path, record: Mapping[str, Any], *, locked: bool = False) -> Path:
        line = (
            json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        if len(line) > 8_192:
            raise ArtifactError("artifact manifest record is too large")
        lock_fd, lock_module = (None, None) if locked else self._locked()
        try:
            with self._parent_fd(relative, create=True) as (parent_fd, target_name):
                flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(target_name, flags, 0o600, dir_fd=parent_fd)
                try:
                    self._require_regular(fd)
                    os.fchmod(fd, 0o600)
                    self._write_all(fd, line)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            if lock_fd is not None:
                lock_module.flock(lock_fd, lock_module.LOCK_UN)
                os.close(lock_fd)
        return self.root / relative

    def _verify_relative_file(self, relative: Path) -> None:
        with self._parent_fd(relative, create=False) as (parent_fd, target_name):
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target_name, flags, dir_fd=parent_fd)
            try:
                self._require_regular(descriptor)
            finally:
                os.close(descriptor)

    def _read_relative(self, relative: Path, *, max_bytes: int) -> bytes:
        with self._parent_fd(relative, create=False) as (parent_fd, target_name):
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target_name, flags, dir_fd=parent_fd)
            try:
                self._require_regular(descriptor)
                chunks = []
                total = 0
                while True:
                    chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        raise ArtifactError("artifact control file exceeds its size limit")
                return b"".join(chunks)
            finally:
                os.close(descriptor)

    def relative_ref(self, path: Path) -> str:
        candidate = Path(path)
        try:
            relative = candidate.relative_to(self.root)
        except ValueError:
            raise UnsafeArtifactPath("artifact is outside the restricted root")
        self._verify_relative_file(relative)
        return relative.as_posix()

    def manifest_ref(self, run_id: str) -> str:
        run = _safe_id(run_id, "run_id")
        return (Path("manifests") / (run + ".responses.jsonl")).as_posix()

    def checkpoint_ref(self, run_id: str) -> str:
        run = _safe_id(run_id, "run_id")
        return (Path("checkpoints") / (run + ".checkpoint.json")).as_posix()

    def receipt_ref(self, run_id: str) -> str:
        run = _safe_id(run_id, "run_id")
        return (Path("receipts") / (run + ".receipt.json")).as_posix()

    def write_response(
        self,
        *,
        run_id: str,
        attempt_id: str,
        page_number: int,
        body: bytes,
        timestamp: Optional[str] = None,
    ) -> ArtifactRecord:
        run = _safe_id(run_id, "run_id")
        attempt = _safe_id(attempt_id, "attempt_id")
        if isinstance(page_number, bool) or not isinstance(page_number, int) or page_number < 1:
            raise ArtifactError("page_number must be a positive integer")
        if not isinstance(body, bytes):
            raise ArtifactError("raw response must be bytes")
        recorded_at = _validated_utc(timestamp or utc_now(), "recorded_at_utc")
        digest = hashlib.sha256(body).hexdigest()
        relative = (
            Path("raw")
            / run
            / ("page-%06d-attempt-%s.json" % (page_number, attempt))
        )
        lock_fd, lock_module = self._locked()
        try:
            for prior in self.load_response_records(run):
                if prior.page_number == page_number:
                    if (prior.attempt_id == attempt and prior.sha256 == digest
                            and prior.size_bytes == len(body)):
                        return prior
                    raise ArtifactError("raw response page already recorded")
                if prior.attempt_id == attempt:
                    raise ArtifactError("raw response attempt already recorded")
            target = self._atomic_write(relative, body, immutable=True)
            record = ArtifactRecord(
                schema_version=ARTIFACT_SCHEMA_VERSION,
                run_id=run,
                attempt_id=attempt,
                page_number=page_number,
                artifact_ref=self.relative_ref(target),
                sha256=digest,
                size_bytes=len(body),
                recorded_at_utc=recorded_at,
            )
            self._append_jsonl(Path(self.manifest_ref(run)), asdict(record), locked=True)
            return record
        finally:
            lock_module.flock(lock_fd, lock_module.LOCK_UN)
            os.close(lock_fd)

    def records_ref(self, run_id: str) -> str:
        return (Path("records") / _safe_id(run_id, "run_id") / "records.jsonl").as_posix()

    def write_search_package(
        self, *, project_id: str, task_id: str, release_id: str, query: str,
        task_type: str = "survey_run",
    ) -> Tuple[Path, str]:
        """Freeze a user-supplied Search operation inside restricted storage."""

        project = _safe_id(project_id, "project_id")
        task = _safe_id(task_id, "task_id")
        release = _safe_id(release_id, "release_id")
        if task_type not in {"survey_run", "preflight"}:
            raise ArtifactError("search task type is invalid")
        if (
            not isinstance(query, str) or not query.strip()
            or len(query.encode("utf-8")) > 32768
            or any(ord(character) < 32 for character in query)
        ):
            raise ArtifactError("search operation is invalid")
        raw = (json.dumps({
            "schema_version": "1.0", "project_id": project, "task_id": task,
            "task_type": task_type, "release_id": release,
            "queries": {"scopus_search": {"query": query}},
        }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        relative = Path("operations") / (task + ".json")
        path = self._atomic_write(relative, raw, immutable=True)
        return path, hashlib.sha256(raw).hexdigest()

    def _check_raw_inventory(self, run_id: str, records: Iterable[ArtifactRecord]) -> None:
        expected = {Path(record.artifact_ref).name for record in records}
        try:
            with self._parent_fd(Path("raw") / run_id / "inventory", create=False) as (fd, _):
                actual = {name for name in os.listdir(fd) if not name.startswith(".pending-")}
        except FileNotFoundError:
            actual = set()
        if expected != actual:
            raise ArtifactError("raw page inventory does not match its manifest")

    def require_unstarted_execution(self, run_id: str) -> None:
        """Reject stored execution evidence before continuing an unused bucket."""

        run = _safe_id(run_id, "run_id")
        lock_fd, lock_module = self._locked()
        try:
            if self.load_checkpoint(run) is not None or self.load_response_records(run):
                raise ArtifactError("unused reservation has stored execution evidence")
            self._check_raw_inventory(run, ())
        finally:
            lock_module.flock(lock_fd, lock_module.LOCK_UN)
            os.close(lock_fd)

    def export_records(self, run_id: str, api_name: str) -> RecordsExport:
        """Rebuild every occurrence from immutable pages, never append blindly.

        Safe to repeat offline after a partial export or checkpoint failure.
        Page gaps and conflicting page evidence fail before replacing output.
        This operation neither sends requests nor changes the control ledger.
        """
        from .records import normalize_page

        if api_name not in {"scopus_search", "abstract_retrieval"}:
            raise ArtifactError("record API is invalid")
        run = _safe_id(run_id, "run_id")
        if run.startswith("exec_") and not run.endswith("_" + api_name):
            raise ArtifactError("record API does not match execution namespace")
        lock_fd, lock_module = self._locked()
        try:
            pages: Dict[int, ArtifactRecord] = {}
            for record in self.load_response_records(run):
                previous = pages.get(record.page_number)
                if previous is not None and previous != record:
                    raise ArtifactError("record export has conflicting page evidence")
                pages[record.page_number] = record
            if sorted(pages) != list(range(1, len(pages) + 1)):
                raise ArtifactError("record export has a page gap")
            self._check_raw_inventory(run, pages.values())
            digest = hashlib.sha256()
            count = 0

            def chunks() -> Iterable[bytes]:
                nonlocal count
                for page in sorted(pages):
                    record = pages[page]
                    for value in normalize_page(self.read_response_record(record), record, api_name):
                        line = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=True) + "\n").encode("utf-8")
                        digest.update(line)
                        count += 1
                        yield line

            relative = Path(self.records_ref(run))
            self._atomic_write_chunks(relative, chunks())
            return RecordsExport(relative.as_posix(), digest.hexdigest(), count, len(pages))
        finally:
            lock_module.flock(lock_fd, lock_module.LOCK_UN)
            os.close(lock_fd)

    def write_checkpoint(
        self,
        checkpoint: Checkpoint,
        *,
        timestamp: Optional[str] = None,
    ) -> str:
        checked = checkpoint.validated(timestamp=timestamp)
        data = checked.as_json()
        encoded = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        relative = Path(self.checkpoint_ref(checked.run_id))
        target = self._atomic_write(relative, encoded + b"\n")
        return self.relative_ref(target)

    def load_checkpoint(self, run_id: str) -> Optional[Checkpoint]:
        relative = Path(self.checkpoint_ref(run_id))
        try:
            encoded = self._read_relative(relative, max_bytes=64 * 1024)
        except FileNotFoundError:
            return None
        try:
            data = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ArtifactError("checkpoint is unreadable") from exc
        expected = {
            "schema_version",
            "run_id",
            "next_page",
            "next_cursor",
            "completed_pages",
            "requests_attempted",
            "retries_used",
            "complete",
            "last_artifact_sha256",
            "saved_at_utc",
        }
        if set(data) != expected or data.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
            raise ArtifactError("checkpoint schema is invalid")
        checkpoint = Checkpoint(
            run_id=data["run_id"],
            next_page=data["next_page"],
            next_cursor=data["next_cursor"],
            completed_pages=data["completed_pages"],
            requests_attempted=data["requests_attempted"],
            retries_used=data["retries_used"],
            complete=data["complete"],
            last_artifact_sha256=data["last_artifact_sha256"],
            saved_at_utc=data["saved_at_utc"],
        ).validated()
        if checkpoint.run_id != run_id:
            raise ArtifactError("checkpoint run identifier does not match")
        return checkpoint

    def load_response_records(self, run_id: str) -> Tuple[ArtifactRecord, ...]:
        """Read and validate the bounded response-manifest chain for a run."""

        run = _safe_id(run_id, "run_id")
        relative = Path(self.manifest_ref(run))
        manifest_opened = False
        try:
            with self._parent_fd(relative, create=False) as (parent_fd, target_name):
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target_name, flags, dir_fd=parent_fd)
                manifest_opened = True
                try:
                    self._require_regular(descriptor)
                    stream = os.fdopen(descriptor, "rb", closefd=True)
                    descriptor = -1
                    try:
                        records = []
                        while True:
                            line = stream.readline(8_193)
                            if not line:
                                break
                            if len(line) > 8_192 or not line.endswith(b"\n"):
                                raise ArtifactError("artifact manifest record is invalid")
                            try:
                                value = json.loads(line.decode("utf-8"))
                            except (UnicodeDecodeError, ValueError):
                                raise ArtifactError("artifact manifest record is invalid") from None
                            expected = {
                                "schema_version",
                                "run_id",
                                "attempt_id",
                                "page_number",
                                "artifact_ref",
                                "sha256",
                                "size_bytes",
                                "recorded_at_utc",
                            }
                            if not isinstance(value, dict) or set(value) != expected:
                                raise ArtifactError("artifact manifest record schema is invalid")
                            if value.get("schema_version") != ARTIFACT_SCHEMA_VERSION:
                                raise ArtifactError("artifact manifest version is invalid")
                            record_run = _safe_id(value.get("run_id"), "run_id")
                            attempt = _safe_id(value.get("attempt_id"), "attempt_id")
                            page = value.get("page_number")
                            size = value.get("size_bytes")
                            digest = value.get("sha256")
                            artifact_ref = value.get("artifact_ref")
                            recorded_at = _validated_utc(
                                value.get("recorded_at_utc"), "recorded_at_utc"
                            )
                            if record_run != run:
                                raise ArtifactError("artifact manifest run identifier mismatches")
                            if isinstance(page, bool) or not isinstance(page, int) or page < 1:
                                raise ArtifactError("artifact manifest page is invalid")
                            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                                raise ArtifactError("artifact manifest size is invalid")
                            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                                raise ArtifactError("artifact manifest digest is invalid")
                            expected_ref = (
                                Path("raw")
                                / run
                                / ("page-%06d-attempt-%s.json" % (page, attempt))
                            ).as_posix()
                            if artifact_ref != expected_ref:
                                raise ArtifactError("artifact manifest reference is invalid")
                            record = ArtifactRecord(
                                schema_version=ARTIFACT_SCHEMA_VERSION,
                                run_id=record_run,
                                attempt_id=attempt,
                                page_number=page,
                                artifact_ref=artifact_ref,
                                sha256=digest,
                                size_bytes=size,
                                recorded_at_utc=recorded_at,
                            )
                            self.verify_response_record(record)
                            records.append(record)
                        return tuple(records)
                    finally:
                        stream.close()
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
        except FileNotFoundError:
            if manifest_opened:
                raise ArtifactError("manifest references a missing raw response") from None
            return ()

    def verify_response_record(self, record: ArtifactRecord) -> None:
        """Verify that a manifest record still names the exact raw bytes."""

        relative = Path(record.artifact_ref)
        with self._parent_fd(relative, create=False) as (parent_fd, target_name):
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target_name, flags, dir_fd=parent_fd)
            try:
                self._require_regular(descriptor)
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(descriptor, 65_536)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                if size != record.size_bytes or digest.hexdigest() != record.sha256:
                    raise ArtifactError("raw response does not match its manifest record")
            finally:
                os.close(descriptor)

    def read_response_record(self, record: ArtifactRecord) -> bytes:
        """Return one verified response for in-process resume-state validation."""

        encoded = self._read_relative(
            Path(record.artifact_ref), max_bytes=record.size_bytes
        )
        if (
            len(encoded) != record.size_bytes
            or hashlib.sha256(encoded).hexdigest() != record.sha256
        ):
            raise ArtifactError("raw response does not match its manifest record")
        return encoded

    def manifest_digest(self, run_id: str) -> Tuple[Optional[str], Optional[str]]:
        relative = Path(self.manifest_ref(run_id))
        try:
            with self._parent_fd(relative, create=False) as (parent_fd, target_name):
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target_name, flags, dir_fd=parent_fd)
                try:
                    self._require_regular(descriptor)
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(descriptor, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    os.close(descriptor)
        except FileNotFoundError:
            return None, None
        return relative.as_posix(), digest.hexdigest()

    def write_receipt(self, receipt: RunReceipt) -> str:
        data = receipt.as_json()
        encoded = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if len(encoded) > _RECEIPT_LIMIT:
            raise ArtifactError("run receipt exceeds the size limit")
        relative = Path(self.receipt_ref(receipt.run_id))
        if relative.as_posix() != receipt.receipt_ref:
            raise ArtifactError("receipt reference does not match run identifier")
        target = self._atomic_write(relative, encoded + b"\n")
        return self.relative_ref(target)


__all__ = [
    "ARTIFACT_SCHEMA_VERSION",
    "ArtifactError",
    "ArtifactRecord",
    "Checkpoint",
    "RestrictedArtifactStore",
    "RunReceipt",
    "UnsafeArtifactPath",
    "validate_restricted_root",
]
