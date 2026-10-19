"""Append-only SQLite control ledger and atomic quota reservation operations.

The database contains control metadata only.  It must never receive an API key,
query text, title, abstract, reference, response payload, cookie, or token.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import fcntl

from .quota import (
    BucketKey,
    BucketSnapshot,
    CandidateEvaluation,
    HeaderEvaluation,
    HttpDisposition,
    QuotaState,
    ReservationRequest,
    SCOPUS_SEARCH,
    build_event_packet,
    classify_http_response,
    evaluate_candidate,
    evaluate_headers,
    parse_utc,
    state_at,
    utc_now,
    utilization_pct,
    warning_threshold_reached,
)


SCHEMA_VERSION = 1
_CONTROL_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,199}$")
_CONTROL_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:\-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_SRC_DISPOSITION_CODES = {
    "WAIT_FOR_SERVER_CONFIRMED_RESET",
    "REPRIORITIZE_ALREADY_AUTHORIZED_TASKS",
    "REQUEST_NAMED_API_QUOTA_INCREASE",
    "APPROVE_CROSS_WINDOW_CONTINUATION",
    "USE_FROZEN_PREFLIGHTED_WITHIN_SOURCE_ALTERNATIVE",
    "RETURN_MATERIAL_CHANGE_TO_PI",
    "DEFER_PENDING_NAMED_EVIDENCE",
}
_PI_DISPOSITION_CODES = {
    "WAIT_FOR_SERVER_CONFIRMED_RESET",
    "APPROVE_REPRIORITIZATION",
    "APPROVE_NAMED_QUOTA_SUPPORT_REQUEST",
    "APPROVE_CROSS_WINDOW_CONTINUATION",
    "REJECT_CHANGE",
    "DEFER_PENDING_NAMED_EVIDENCE",
}
_QUOTA_EVENT_COLUMNS = (
    "quota_event_id",
    "event_group_id",
    "record_kind",
    "event_type",
    "severity",
    "detected_at_utc",
    "window_id",
    "api_key_alias",
    "api_name",
    "limit_value",
    "used",
    "committed",
    "remaining",
    "free",
    "projected_pct",
    "project_id",
    "task_id",
    "run_id",
    "original_forecast",
    "revised_forecast",
    "forecast_reason",
    "safe_checkpoint",
    "completeness_state",
    "schedule_coverage_deliverable_effect",
    "options_and_consequences_json",
    "exact_src_pi_question",
    "notification_evidence",
    "src_notified_at_utc",
    "pi_notified_at_utc",
    "src_coordination_response",
    "pi_disposition",
    "owner",
    "completion_condition",
    "closure_evidence",
    "predecessor_event_id",
    "recorded_at_utc",
)


class LedgerError(RuntimeError):
    """Base class for bounded control-ledger failures."""


class AliasBindingError(LedgerError):
    pass


class DuplicateResponseError(LedgerError):
    pass


class UnknownAttemptError(LedgerError):
    pass


@dataclass(frozen=True)
class AdmissionBucketResult:
    api_name: str
    reservation_id: Optional[str]
    state: QuotaState
    reason_code: str
    estimate: int
    capacity_gap: int


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    decision: str
    reason_code: str
    api_key_alias: Optional[str]
    buckets: Tuple[AdmissionBucketResult, ...]


@dataclass(frozen=True)
class AttemptResult:
    allowed: bool
    attempt_id: Optional[str]
    state: QuotaState
    reason_code: str
    reserved_remaining: int


@dataclass(frozen=True)
class ResponseResult:
    attempt_id: str
    disposition: HttpDisposition
    quota_state: QuotaState
    header_reason_code: str
    local_remaining_after_attempt: Optional[int] = None
    reconciled_remaining: Optional[int] = None


_SCHEMA = r"""
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL,
    installed_at_utc TEXT NOT NULL,
    database_instance_id TEXT NOT NULL,
    database_device INTEGER NOT NULL,
    database_inode INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS project_key_alias_ledger (
    binding_event_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    api_key_alias TEXT NOT NULL,
    event_type TEXT NOT NULL,
    effective_at_utc TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    change_authorization_ref TEXT,
    predecessor_event_id TEXT,
    recorded_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quota_window_ledger (
    record_id TEXT PRIMARY KEY,
    record_kind TEXT NOT NULL,
    window_id TEXT NOT NULL,
    api_key_alias TEXT NOT NULL,
    api_name TEXT NOT NULL,
    limit_value INTEGER,
    server_remaining INTEGER,
    local_attempts_since_header INTEGER NOT NULL,
    effective_remaining INTEGER,
    used INTEGER,
    committed_in_progress INTEGER NOT NULL,
    free_to_admit INTEGER,
    actual_used_pct REAL,
    projected_used_pct REAL,
    reset_at_utc TEXT,
    observed_at_utc TEXT NOT NULL,
    header_evidence_ref TEXT,
    state TEXT NOT NULL,
    reconciliation_predecessor TEXT,
    reason_code TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_reservation_ledger (
    reservation_event_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    event_seq INTEGER NOT NULL,
    event_kind TEXT NOT NULL,
    predecessor_event_id TEXT,
    window_id TEXT,
    api_key_alias TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    query_package_hash_or_ref TEXT NOT NULL,
    api_name TEXT NOT NULL,
    view_name TEXT NOT NULL,
    page_size INTEGER NOT NULL,
    forecast_pagination INTEGER NOT NULL,
    forecast_detail_retrieval INTEGER NOT NULL,
    forecast_validation INTEGER NOT NULL,
    retry_allowance INTEGER NOT NULL,
    estimated_requests_with_margin INTEGER NOT NULL,
    reserved_remaining INTEGER NOT NULL,
    actual_requests INTEGER NOT NULL,
    admission_decision TEXT NOT NULL,
    admission_reason TEXT NOT NULL,
    admitted_at_utc TEXT,
    completed_or_released_at_utc TEXT,
    recorded_at_utc TEXT NOT NULL,
    UNIQUE(reservation_id, event_seq)
);

CREATE TABLE IF NOT EXISTS request_usage_log (
    request_event_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    record_kind TEXT NOT NULL,
    predecessor_event_id TEXT,
    reservation_id TEXT,
    project_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    api_key_alias TEXT NOT NULL,
    api_name TEXT NOT NULL,
    endpoint_class TEXT NOT NULL,
    view_name TEXT NOT NULL,
    page_size INTEGER NOT NULL,
    cursor_or_page_ref TEXT,
    requested_at_utc TEXT NOT NULL,
    http_status INTEGER,
    result_count INTEGER,
    retry_number INTEGER NOT NULL,
    rate_limit_limit INTEGER,
    rate_limit_remaining INTEGER,
    rate_limit_reset_utc TEXT,
    reservation_delta INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    stop_reason TEXT,
    response_receipt_hash_or_ref TEXT,
    recorded_at_utc TEXT NOT NULL,
    UNIQUE(attempt_id, record_kind)
);

CREATE TABLE IF NOT EXISTS quota_event_disposition_log (
    quota_event_id TEXT PRIMARY KEY,
    event_group_id TEXT NOT NULL,
    record_kind TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detected_at_utc TEXT NOT NULL,
    window_id TEXT,
    api_key_alias TEXT NOT NULL,
    api_name TEXT NOT NULL,
    limit_value INTEGER,
    used INTEGER,
    committed INTEGER NOT NULL,
    remaining INTEGER,
    free INTEGER,
    projected_pct REAL,
    project_id TEXT,
    task_id TEXT,
    run_id TEXT,
    original_forecast INTEGER,
    revised_forecast INTEGER,
    forecast_reason TEXT,
    safe_checkpoint TEXT,
    completeness_state TEXT NOT NULL,
    schedule_coverage_deliverable_effect TEXT NOT NULL,
    options_and_consequences_json TEXT NOT NULL,
    exact_src_pi_question TEXT NOT NULL,
    notification_evidence TEXT,
    src_notified_at_utc TEXT,
    pi_notified_at_utc TEXT,
    src_coordination_response TEXT,
    pi_disposition TEXT,
    owner TEXT NOT NULL,
    completion_condition TEXT NOT NULL,
    closure_evidence TEXT,
    predecessor_event_id TEXT,
    recorded_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quota_bucket_latest
ON quota_window_ledger(api_key_alias, api_name, observed_at_utc);
CREATE INDEX IF NOT EXISTS idx_reservation_latest
ON task_reservation_ledger(reservation_id, event_seq);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reservation_release_consumed
ON task_reservation_ledger(project_id, task_id, release_id, api_name)
WHERE event_seq = 1 AND admission_decision = 'ADMITTED';
CREATE UNIQUE INDEX IF NOT EXISTS idx_reservation_run_consumed
ON task_reservation_ledger(run_id, api_name)
WHERE event_seq = 1 AND admission_decision = 'ADMITTED';
CREATE INDEX IF NOT EXISTS idx_request_attempt
ON request_usage_log(attempt_id, record_kind);
CREATE INDEX IF NOT EXISTS idx_binding_project
ON project_key_alias_ledger(project_id, effective_at_utc);

CREATE TRIGGER IF NOT EXISTS schema_meta_singleton
BEFORE INSERT ON schema_meta
WHEN EXISTS (SELECT 1 FROM schema_meta) BEGIN
    SELECT RAISE(ABORT, 'immutable schema metadata');
END;
CREATE TRIGGER IF NOT EXISTS no_update_schema_meta
BEFORE UPDATE ON schema_meta BEGIN
    SELECT RAISE(ABORT, 'immutable schema metadata');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_schema_meta
BEFORE DELETE ON schema_meta BEGIN
    SELECT RAISE(ABORT, 'immutable schema metadata');
END;
CREATE TRIGGER IF NOT EXISTS no_update_project_key_alias
BEFORE UPDATE ON project_key_alias_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_project_key_alias
BEFORE DELETE ON project_key_alias_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_update_quota_window
BEFORE UPDATE ON quota_window_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_quota_window
BEFORE DELETE ON quota_window_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_update_task_reservation
BEFORE UPDATE ON task_reservation_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_task_reservation
BEFORE DELETE ON task_reservation_ledger BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_update_request_usage
BEFORE UPDATE ON request_usage_log BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_request_usage
BEFORE DELETE ON request_usage_log BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_update_quota_event
BEFORE UPDATE ON quota_event_disposition_log BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
CREATE TRIGGER IF NOT EXISTS no_delete_quota_event
BEFORE DELETE ON quota_event_disposition_log BEGIN
    SELECT RAISE(ABORT, 'append-only ledger');
END;
"""

_REQUIRED_LEDGER_TABLES = {
    "schema_meta",
    "project_key_alias_ledger",
    "quota_window_ledger",
    "task_reservation_ledger",
    "request_usage_log",
    "quota_event_disposition_log",
}
_REQUIRED_LEDGER_TRIGGERS = {
    "schema_meta_singleton",
    "no_update_schema_meta",
    "no_delete_schema_meta",
    "no_update_project_key_alias",
    "no_delete_project_key_alias",
    "no_update_quota_window",
    "no_delete_quota_window",
    "no_update_task_reservation",
    "no_delete_task_reservation",
    "no_update_request_usage",
    "no_delete_request_usage",
    "no_update_quota_event",
    "no_delete_quota_event",
}
_REQUIRED_LEDGER_INDEXES = {
    "idx_quota_bucket_latest",
    "idx_reservation_latest",
    "idx_reservation_release_consumed",
    "idx_reservation_run_consumed",
    "idx_request_attempt",
    "idx_binding_project",
}


def _normalized_schema_sql(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError("control database schema definition is missing")
    # Preserve string-literal case.  In particular, 'ADMITTED' and 'admitted'
    # are different SQLite partial-index predicates even though SQL keywords
    # themselves are case-insensitive.
    return " ".join(value.split())


@lru_cache(maxsize=1)
def _expected_ledger_object_sql() -> Mapping[Tuple[str, str], str]:
    expected_names = (
        _REQUIRED_LEDGER_TABLES
        | _REQUIRED_LEDGER_TRIGGERS
        | _REQUIRED_LEDGER_INDEXES
    )
    with sqlite3.connect(":memory:") as connection:
        connection.executescript(_SCHEMA)
        rows = connection.execute(
            """
            SELECT type, name, sql FROM sqlite_master
            WHERE type IN ('table', 'trigger', 'index')
            """
        ).fetchall()
    return MappingProxyType(
        {
            (str(object_type), str(name)): _normalized_schema_sql(sql)
            for object_type, name, sql in rows
            if str(name) in expected_names
        }
    )


def _validate_control_schema(connection: sqlite3.Connection) -> None:
    expected = _expected_ledger_object_sql()
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE type IN ('table', 'trigger', 'index', 'view')
        """
    ).fetchall()
    actual: Dict[Tuple[str, str], str] = {}
    unexpected = False
    for row in rows:
        key = (str(row["type"]), str(row["name"]))
        if key in expected:
            actual[key] = _normalized_schema_sql(row["sql"])
        elif not (
            row["type"] == "index"
            and str(row["name"]).startswith("sqlite_autoindex_")
            and row["sql"] is None
        ):
            unexpected = True
    if unexpected or actual != expected:
        raise LedgerError("control database schema definition mismatch")


def _id(prefix: str) -> str:
    return "%s_%s" % (prefix, uuid.uuid4().hex)


def _window_id(api_key_alias: str, api_name: str, reset_at_utc: str) -> str:
    material = "%s\x1f%s\x1f%s" % (api_key_alias, api_name, reset_at_utc)
    return "window_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _validate_token(name: str, value: str) -> None:
    if not isinstance(value, str) or _CONTROL_TOKEN_RE.fullmatch(value) is None:
        raise ValueError("%s must be a bounded control identifier" % name)


def _validate_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError("%s must be a SHA-256 digest" % name)


def _validate_control_ref(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or _CONTROL_REF_RE.fullmatch(value) is None
        or value.startswith("/")
        or ".." in value.split("/")
    ):
        raise ValueError("%s must be a bounded relative control reference" % name)


class Ledger:
    """A connection-per-operation append-only ledger safe for many processes."""

    def __init__(
        self,
        database_path: Union[os.PathLike, str],
        busy_timeout_ms: int = 10000,
        *,
        require_existing_identity: bool = False,
    ):
        self.database_path = (
            ":memory:"
            if str(database_path) == ":memory:"
            else str(Path(database_path).resolve(strict=False))
        )
        self.busy_timeout_ms = busy_timeout_ms
        self._require_existing_identity = require_existing_identity
        self._memory_execution_lock = threading.RLock()
        if require_existing_identity and (
            self.database_path == ":memory:" or not Path(self.database_path).is_file()
        ):
            raise LedgerError("pre-existing control database identity is required")
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self.initialize()
        except sqlite3.Error:
            raise LedgerError("control database could not be initialized safely") from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=max(1.0, self.busy_timeout_ms / 1000.0),
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = %d" % self.busy_timeout_ms)
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            existing_objects = {
                (str(row[0]), str(row[1]))
                for row in connection.execute(
                    """
                    SELECT type, name FROM sqlite_master
                    WHERE type IN ('table', 'index', 'trigger', 'view')
                      AND name NOT LIKE 'sqlite_%'
                    """
                )
            }
            existing_tables = {
                name for object_type, name in existing_objects if object_type == "table"
            }
            meta_existed = "schema_meta" in existing_tables
            if self._require_existing_identity and not meta_existed:
                raise LedgerError("pre-existing control database identity is required")
            if existing_objects and not meta_existed:
                raise LedgerError("control database identity metadata is missing")
            if meta_existed:
                columns = {
                    str(row[1])
                    for row in connection.execute("PRAGMA table_info(schema_meta)")
                }
                required = {
                    "singleton",
                    "schema_version",
                    "installed_at_utc",
                    "database_instance_id",
                    "database_device",
                    "database_inode",
                }
                if columns != required:
                    raise LedgerError("control database identity metadata is missing")
                rows = connection.execute(
                    """
                    SELECT singleton, schema_version, installed_at_utc,
                           database_instance_id, database_device, database_inode
                    FROM schema_meta
                    """
                ).fetchall()
                if len(rows) != 1:
                    raise LedgerError("control database identity metadata is not unique")
                existing = rows[0]
                current = (
                    None
                    if self.database_path == ":memory:"
                    else os.stat(self.database_path, follow_symlinks=False)
                )
                if (
                    type(existing["singleton"]) is not int
                    or existing["singleton"] != 1
                    or type(existing["schema_version"]) is not int
                    or existing["schema_version"] != SCHEMA_VERSION
                    or not isinstance(existing["installed_at_utc"], str)
                    or not isinstance(existing["database_instance_id"], str)
                    or _UUID_RE.fullmatch(existing["database_instance_id"]) is None
                    or type(existing["database_device"]) is not int
                    or type(existing["database_inode"]) is not int
                    or (
                        current is not None
                        and (
                            existing["database_device"] != int(current.st_dev)
                            or existing["database_inode"] != int(current.st_ino)
                        )
                    )
                ):
                    raise LedgerError("control database identity metadata is invalid")
                try:
                    parse_utc(existing["installed_at_utc"])
                except (TypeError, ValueError):
                    raise LedgerError("control database identity metadata is invalid") from None
                # Existing ledgers are validation-only.  Never auto-heal a
                # missing guard or otherwise rewrite a nonempty database.
                _validate_control_schema(connection)
                return
            if self.database_path != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(_SCHEMA)
            if not meta_existed:
                if self.database_path == ":memory:":
                    database_device, database_inode = 0, 0
                else:
                    created = os.stat(self.database_path, follow_symlinks=False)
                    database_device = int(created.st_dev)
                    database_inode = int(created.st_ino)
                connection.execute(
                    """
                    INSERT INTO schema_meta(
                        singleton, schema_version, installed_at_utc, database_instance_id,
                        database_device, database_inode
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        1,
                        SCHEMA_VERSION,
                        utc_now(),
                        str(uuid.uuid4()),
                        database_device,
                        database_inode,
                    ),
                )
            _validate_control_schema(connection)

    def database_identity(self) -> Tuple[str, int, int]:
        """Return the immutable UUID and creation-time database file identity."""

        if self.database_path == ":memory:":
            raise LedgerError("in-memory ledgers have no durable identity")
        before = os.stat(self.database_path, follow_symlinks=False)
        with self._connect() as connection:
            try:
                row = connection.execute(
                    """
                    SELECT singleton, schema_version, installed_at_utc,
                           database_instance_id, database_device, database_inode
                    FROM schema_meta
                    """
                ).fetchall()
                _validate_control_schema(connection)
            except sqlite3.Error:
                raise LedgerError("control database identity is unavailable") from None
        after = os.stat(self.database_path, follow_symlinks=False)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or len(row) != 1
            or type(row[0]["singleton"]) is not int
            or row[0]["singleton"] != 1
            or type(row[0]["schema_version"]) is not int
            or row[0]["schema_version"] != SCHEMA_VERSION
            or not isinstance(row[0]["installed_at_utc"], str)
            or not isinstance(row[0]["database_instance_id"], str)
            or _UUID_RE.fullmatch(row[0]["database_instance_id"]) is None
            or type(row[0]["database_device"]) is not int
            or type(row[0]["database_inode"]) is not int
            or row[0]["database_device"] != int(after.st_dev)
            or row[0]["database_inode"] != int(after.st_ino)
        ):
            raise LedgerError("control database identity is unstable")
        try:
            parse_utc(row[0]["installed_at_utc"])
        except (TypeError, ValueError):
            raise LedgerError("control database identity is unstable") from None
        return (
            str(row[0]["database_instance_id"]),
            int(row[0]["database_device"]),
            int(row[0]["database_inode"]),
        )

    @staticmethod
    def _begin_immediate(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @contextmanager
    def execution_lock(self):
        """Serialize the attempt → transport → reconciliation critical section.

        The runner adapter acquires this cross-process file lock before it
        records an attempt and releases it only after the response disposition
        is durably appended.  SQLite transactions remain short; the network
        wait never holds a database write transaction.
        """

        if self.database_path == ":memory:":
            with self._memory_execution_lock:
                yield
            return
        lock_path = self.database_path + ".request.lock"
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def register_project_key_alias(
        self,
        project_id: str,
        api_key_alias: str,
        evidence_ref: str,
        effective_at_utc: Optional[str] = None,
        change_authorization_ref: Optional[str] = None,
    ) -> str:
        """Append a mapping; changing aliases requires named authorization.

        A live project cannot silently rotate onto a second key.  The schema
        retains history so a genuinely changed authorized use case can later be
        represented without overwriting the old mapping.
        """

        for name, value in (
            ("project_id", project_id),
            ("api_key_alias", api_key_alias),
        ):
            _validate_token(name, value)
        _validate_digest("evidence_ref", evidence_ref)
        effective = effective_at_utc or utc_now()
        parse_utc(effective)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            previous = connection.execute(
                """
                SELECT * FROM project_key_alias_ledger
                WHERE project_id = ?
                ORDER BY effective_at_utc DESC, rowid DESC LIMIT 1
                """,
                (project_id,),
            ).fetchone()
            if previous is not None and previous["api_key_alias"] != api_key_alias:
                if not change_authorization_ref:
                    raise AliasBindingError("API_KEY_ALIAS_CHANGE_REQUIRES_AUTHORIZATION")
                _validate_digest("change_authorization_ref", change_authorization_ref)
                if self._project_has_active_reservations(connection, project_id):
                    raise AliasBindingError("API_KEY_ALIAS_CHANGE_BLOCKED_BY_ACTIVE_RESERVATION")
                event_type = "AUTHORIZED_CHANGE"
            elif previous is not None:
                connection.commit()
                return str(previous["binding_event_id"])
            else:
                event_type = "BOUND"
            event_id = _id("binding")
            connection.execute(
                """
                INSERT INTO project_key_alias_ledger(
                    binding_event_id, project_id, api_key_alias, event_type,
                    effective_at_utc, evidence_ref, change_authorization_ref,
                    predecessor_event_id, recorded_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    project_id,
                    api_key_alias,
                    event_type,
                    effective,
                    evidence_ref,
                    change_authorization_ref,
                    previous["binding_event_id"] if previous is not None else None,
                    utc_now(),
                ),
            )
            connection.commit()
            return event_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _project_has_active_reservations(
        self, connection: sqlite3.Connection, project_id: str
    ) -> bool:
        row = connection.execute(
            """
            SELECT 1
            FROM task_reservation_ledger current
            WHERE current.project_id = ?
              AND current.event_seq = (
                SELECT MAX(newer.event_seq)
                FROM task_reservation_ledger newer
                WHERE newer.reservation_id = current.reservation_id
              )
              AND current.reserved_remaining > 0
              AND current.completed_or_released_at_utc IS NULL
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        return row is not None

    def current_project_key_alias(
        self, project_id: str, at_utc: Optional[str] = None
    ) -> Optional[str]:
        at_value = at_utc or utc_now()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT api_key_alias FROM project_key_alias_ledger
                WHERE project_id = ? AND effective_at_utc <= ?
                ORDER BY effective_at_utc DESC, rowid DESC LIMIT 1
                """,
                (project_id, at_value),
            ).fetchone()
        return None if row is None else str(row["api_key_alias"])

    def _latest_snapshot(
        self, connection: sqlite3.Connection, api_key_alias: str, api_name: str
    ) -> Optional[BucketSnapshot]:
        row = connection.execute(
            """
            SELECT * FROM quota_window_ledger
            WHERE api_key_alias = ? AND api_name = ?
            ORDER BY rowid DESC LIMIT 1
            """,
            (api_key_alias, api_name),
        ).fetchone()
        return self._row_to_snapshot(row) if row is not None else None

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> BucketSnapshot:
        return BucketSnapshot(
            record_id=str(row["record_id"]),
            window_id=str(row["window_id"]),
            key=BucketKey(str(row["api_key_alias"]), str(row["api_name"])),
            limit=row["limit_value"],
            server_remaining=row["server_remaining"],
            local_attempts_since_header=int(row["local_attempts_since_header"]),
            effective_remaining=row["effective_remaining"],
            used=row["used"],
            committed_in_progress=int(row["committed_in_progress"]),
            free_to_admit=row["free_to_admit"],
            actual_used_pct=row["actual_used_pct"],
            projected_used_pct=row["projected_used_pct"],
            reset_at_utc=row["reset_at_utc"],
            observed_at_utc=str(row["observed_at_utc"]),
            header_evidence_ref=row["header_evidence_ref"],
            state=QuotaState(str(row["state"])),
            reconciliation_predecessor=row["reconciliation_predecessor"],
            reason_code=str(row["reason_code"]),
        )

    def quota_status(
        self, api_key_alias: str, api_name: str, now_utc: Optional[str] = None
    ) -> Optional[BucketSnapshot]:
        with self._connect() as connection:
            snapshot = self._latest_snapshot(connection, api_key_alias, api_name)
        if snapshot is None:
            return None
        effective = state_at(snapshot, now_utc or utc_now())
        if effective is snapshot.state:
            return snapshot
        return BucketSnapshot(
            **{**snapshot.__dict__, "state": effective, "reason_code": "RESET_REQUIRES_HEADER_CONFIRMATION"}
        )

    def _insert_snapshot(
        self,
        connection: sqlite3.Connection,
        snapshot: BucketSnapshot,
        record_kind: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO quota_window_ledger(
                record_id, record_kind, window_id, api_key_alias, api_name,
                limit_value, server_remaining, local_attempts_since_header,
                effective_remaining, used, committed_in_progress, free_to_admit,
                actual_used_pct, projected_used_pct, reset_at_utc, observed_at_utc,
                header_evidence_ref, state, reconciliation_predecessor, reason_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.record_id,
                record_kind,
                snapshot.window_id,
                snapshot.key.api_key_alias,
                snapshot.key.api_name,
                snapshot.limit,
                snapshot.server_remaining,
                snapshot.local_attempts_since_header,
                snapshot.effective_remaining,
                snapshot.used,
                snapshot.committed_in_progress,
                snapshot.free_to_admit,
                snapshot.actual_used_pct,
                snapshot.projected_used_pct,
                snapshot.reset_at_utc,
                snapshot.observed_at_utc,
                snapshot.header_evidence_ref,
                snapshot.state.value,
                snapshot.reconciliation_predecessor,
                snapshot.reason_code,
            ),
        )

    def _reconciled_snapshot(
        self,
        api_key_alias: str,
        api_name: str,
        headers: Mapping[str, Any],
        evidence_ref: str,
        observed: str,
        previous: Optional[BucketSnapshot],
        committed: int,
        header_evaluation: Optional[HeaderEvaluation] = None,
    ) -> BucketSnapshot:
        evaluation = header_evaluation or evaluate_headers(headers, observed, previous)
        if not evaluation.valid:
            return BucketSnapshot(
                record_id=_id("quota"),
                window_id=previous.window_id if previous else _id("window_unknown"),
                key=BucketKey(api_key_alias, api_name),
                limit=previous.limit if previous else None,
                server_remaining=previous.server_remaining if previous else None,
                local_attempts_since_header=(
                    previous.local_attempts_since_header if previous else 0
                ),
                effective_remaining=previous.effective_remaining if previous else None,
                used=previous.used if previous else None,
                committed_in_progress=committed,
                free_to_admit=None,
                actual_used_pct=previous.actual_used_pct if previous else None,
                projected_used_pct=None,
                reset_at_utc=previous.reset_at_utc if previous else None,
                observed_at_utc=observed,
                header_evidence_ref=evidence_ref,
                state=QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                reconciliation_predecessor=previous.record_id if previous else None,
                reason_code=evaluation.reason_code,
            )
        assert evaluation.limit is not None
        assert evaluation.remaining is not None
        assert evaluation.reset_at_utc is not None
        remaining = evaluation.remaining
        if (previous is not None and previous.reset_at_utc == evaluation.reset_at_utc
                and previous.effective_remaining is not None):
            remaining = min(remaining, previous.effective_remaining)
        # effective_remaining is after ALL charged ATTEMPTs, before unspent
        # reservations. Outcomes never charge again; subtract commitments only
        # here for admission capacity, never from the retained balance itself.
        used = evaluation.limit - remaining
        free = remaining - committed
        projected = used + committed
        if remaining == 0:
            state = QuotaState.QUOTA_EXHAUSTED
        elif (
            previous is not None
            and previous.state is QuotaState.QUOTA_WARNING_80
            and not evaluation.window_id_changed
        ):
            # A warning freezes new unreserved work for the rest of the live
            # window.  A later header in that same window must not silently
            # erase the coordination hold merely because a rejected candidate
            # was never committed.
            state = QuotaState.QUOTA_WARNING_80
        elif warning_threshold_reached(projected, evaluation.limit):
            state = QuotaState.QUOTA_WARNING_80
        else:
            state = QuotaState.NORMAL
        return BucketSnapshot(
            record_id=_id("quota"),
            window_id=_window_id(api_key_alias, api_name, evaluation.reset_at_utc),
            key=BucketKey(api_key_alias, api_name),
            limit=evaluation.limit,
            server_remaining=evaluation.remaining,
            local_attempts_since_header=0,
            effective_remaining=remaining,
            used=used,
            committed_in_progress=committed,
            free_to_admit=free,
            actual_used_pct=utilization_pct(used, evaluation.limit),
            projected_used_pct=utilization_pct(projected, evaluation.limit),
            reset_at_utc=evaluation.reset_at_utc,
            observed_at_utc=observed,
            header_evidence_ref=evidence_ref,
            state=state,
            reconciliation_predecessor=previous.record_id if previous else None,
            reason_code=evaluation.reason_code,
        )

    @staticmethod
    def _release_or_run_already_consumed(
        connection: sqlite3.Connection,
        project_id: str,
        task_id: str,
        release_id: str,
        run_id: str,
    ) -> bool:
        """Return true once an admitted release or run has a seed row."""

        row = connection.execute(
            """
            SELECT 1
            FROM task_reservation_ledger
            WHERE event_seq = 1 AND admission_decision = 'ADMITTED'
              AND (
                    (project_id = ? AND task_id = ? AND release_id = ?)
                    OR run_id = ?
                  )
            LIMIT 1
            """,
            (project_id, task_id, release_id, run_id),
        ).fetchone()
        return row is not None

    def _admit_task(
        self,
        project_id: str,
        task_id: str,
        run_id: str,
        release_id: str,
        query_package_hash_or_ref: str,
        requirements: Sequence[ReservationRequest],
        now_utc: Optional[str] = None,
        *,
        expected_api_key_alias: str,
    ) -> AdmissionResult:
        """Atomically reserve every required API bucket or reserve none."""

        for name, value in (
            ("project_id", project_id),
            ("task_id", task_id),
            ("run_id", run_id),
            ("release_id", release_id),
        ):
            _validate_token(name, value)
        _validate_digest("query_package_hash_or_ref", query_package_hash_or_ref)
        _validate_token("expected_api_key_alias", expected_api_key_alias)
        if not requirements:
            raise ValueError("at least one API requirement is required")
        names = [item.api_name for item in requirements]
        if len(names) != len(set(names)):
            raise ValueError("each API bucket may appear only once")
        now = now_utc or utc_now()
        parse_utc(now)

        connection = self._connect()
        try:
            self._begin_immediate(connection)
            binding = connection.execute(
                """
                SELECT api_key_alias FROM project_key_alias_ledger
                WHERE project_id = ? AND effective_at_utc <= ?
                ORDER BY effective_at_utc DESC, rowid DESC LIMIT 1
                """,
                (project_id, now),
            ).fetchone()
            if binding is None:
                connection.commit()
                return AdmissionResult(False, "REJECTED", "PROJECT_KEY_ALIAS_UNBOUND", None, ())
            alias = str(binding["api_key_alias"])
            if alias != expected_api_key_alias:
                connection.commit()
                return AdmissionResult(
                    False,
                    "REJECTED",
                    "PROJECT_KEY_ALIAS_MISMATCH",
                    alias,
                    (),
                )
            if self._release_or_run_already_consumed(
                connection, project_id, task_id, release_id, run_id
            ):
                connection.commit()
                return AdmissionResult(
                    False, "REJECTED", "TASK_RELEASE_ALREADY_CONSUMED", alias, ()
                )

            snapshots: Dict[str, BucketSnapshot] = {}
            missing: List[AdmissionBucketResult] = []
            for requirement in requirements:
                snapshot = self._latest_snapshot(connection, alias, requirement.api_name)
                if snapshot is None:
                    missing.append(
                        AdmissionBucketResult(
                            requirement.api_name,
                            None,
                            QuotaState.UNVERIFIED,
                            "NO_VALID_QUOTA_HEADERS",
                            requirement.estimated_requests_with_margin,
                            requirement.estimated_requests_with_margin,
                        )
                    )
                else:
                    snapshots[requirement.api_name] = snapshot
            if missing:
                # UNVERIFIED is a derived default.  Do not fabricate a live
                # quota window, reservation, or event before a released probe.
                connection.commit()
                return AdmissionResult(False, "REJECTED", "UNVERIFIED", alias, tuple(missing))

            evaluations: Dict[str, CandidateEvaluation] = {}
            bucket_results: List[AdmissionBucketResult] = []
            for requirement in requirements:
                snapshot = snapshots[requirement.api_name]
                effective_state = state_at(snapshot, now)
                if effective_state is QuotaState.RESET_VERIFY and snapshot.state is not effective_state:
                    transitioned = BucketSnapshot(
                        **{
                            **snapshot.__dict__,
                            "record_id": _id("quota"),
                            "observed_at_utc": now,
                            "state": QuotaState.RESET_VERIFY,
                            "reconciliation_predecessor": snapshot.record_id,
                            "reason_code": "RESET_REQUIRES_HEADER_CONFIRMATION",
                        }
                    )
                    self._insert_snapshot(connection, transitioned, "STATE_TRANSITION")
                    self._insert_quota_event(
                        connection, transitioned, "RESET_VERIFY", "WARNING", project_id,
                        task_id, run_id, requirement.estimated_requests_with_margin,
                        requirement.estimated_requests_with_margin, None,
                        "RESET_REQUIRES_HEADER_CONFIRMATION"
                    )
                    snapshots[requirement.api_name] = transitioned
                    snapshot = transitioned
                evaluation = evaluate_candidate(
                    snapshot, requirement.estimated_requests_with_margin, now
                )
                evaluations[requirement.api_name] = evaluation
                bucket_results.append(
                    AdmissionBucketResult(
                        requirement.api_name,
                        None,
                        evaluation.state,
                        evaluation.reason_code,
                        evaluation.candidate_estimate,
                        evaluation.capacity_gap,
                    )
                )

            if not all(item.can_admit for item in evaluations.values()):
                for requirement in requirements:
                    evaluation = evaluations[requirement.api_name]
                    snapshot = snapshots[requirement.api_name]
                    if evaluation.warning_triggered:
                        warning_snapshot = BucketSnapshot(
                            **{
                                **snapshot.__dict__,
                                "record_id": _id("quota"),
                                "observed_at_utc": now,
                                "projected_used_pct": evaluation.projected_used_pct,
                                "state": QuotaState.QUOTA_WARNING_80,
                                "reconciliation_predecessor": snapshot.record_id,
                                "reason_code": evaluation.reason_code,
                            }
                        )
                        self._insert_snapshot(connection, warning_snapshot, "CANDIDATE_WARNING")
                        snapshot = warning_snapshot
                        self._insert_quota_event(
                            connection,
                            snapshot,
                            "QUOTA_WARNING_80",
                            "WARNING",
                            project_id,
                            task_id,
                            run_id,
                            requirement.estimated_requests_with_margin,
                            requirement.estimated_requests_with_margin,
                            evaluation.capacity_gap,
                            "CANDIDATE_REACHES_80_PERCENT",
                        )
                    reservation_evaluation = evaluation
                    if evaluation.can_admit:
                        reservation_evaluation = CandidateEvaluation(
                            False,
                            QuotaState.NEW_TASK_DEFERRED_QUOTA,
                            "ATOMIC_PEER_BUCKET_FAILED",
                            evaluation.candidate_estimate,
                            0,
                            evaluation.projected_used_pct,
                            evaluation.warning_triggered,
                        )
                    self._insert_deferred_reservation(
                            connection,
                            alias,
                            snapshot,
                            project_id,
                            task_id,
                            run_id,
                            release_id,
                            query_package_hash_or_ref,
                            requirement,
                            reservation_evaluation,
                            now,
                        )
                    if not evaluation.can_admit:
                        if evaluation.state is not QuotaState.QUOTA_WARNING_80:
                            self._insert_quota_event(
                                connection,
                                snapshot,
                                "NEW_TASK_DEFERRED_QUOTA",
                                "WARNING",
                                project_id,
                                task_id,
                                run_id,
                                requirement.estimated_requests_with_margin,
                                requirement.estimated_requests_with_margin,
                                evaluation.capacity_gap,
                                evaluation.reason_code,
                            )
                decision = (
                    "QUOTA_WARNING_80"
                    if any(
                        item.state is QuotaState.QUOTA_WARNING_80
                        for item in evaluations.values()
                    )
                    else "NEW_TASK_DEFERRED_QUOTA"
                )
                connection.commit()
                return AdmissionResult(False, decision, "ATOMIC_ADMISSION_FAILED", alias, tuple(bucket_results))

            admitted_results: List[AdmissionBucketResult] = []
            for requirement in requirements:
                snapshot = snapshots[requirement.api_name]
                estimate = requirement.estimated_requests_with_margin
                reservation_id = _id("reservation")
                event_id = _id("reservation_event")
                connection.execute(
                    """
                    INSERT INTO task_reservation_ledger(
                        reservation_event_id, reservation_id, event_seq, event_kind,
                        predecessor_event_id, window_id, api_key_alias, project_id,
                        task_id, run_id, release_id, query_package_hash_or_ref, api_name,
                        view_name, page_size, forecast_pagination,
                        forecast_detail_retrieval, forecast_validation, retry_allowance,
                        estimated_requests_with_margin, reserved_remaining,
                        actual_requests, admission_decision, admission_reason,
                        admitted_at_utc, completed_or_released_at_utc, recorded_at_utc
                    ) VALUES (?, ?, 1, 'ADMITTED', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'ADMITTED',
                              'FULL_RESERVATION_AVAILABLE', ?, NULL, ?)
                    """,
                    (
                        event_id,
                        reservation_id,
                        snapshot.window_id,
                        alias,
                        project_id,
                        task_id,
                        run_id,
                        release_id,
                        query_package_hash_or_ref,
                        requirement.api_name,
                        requirement.view,
                        requirement.page_size,
                        requirement.forecast_pagination,
                        requirement.forecast_detail_retrieval,
                        requirement.forecast_validation,
                        requirement.retry_allowance,
                        estimate,
                        estimate,
                        now,
                        now,
                    ),
                )
                committed = snapshot.committed_in_progress + estimate
                projected = (snapshot.used or 0) + committed
                reservation_snapshot = BucketSnapshot(
                    **{
                        **snapshot.__dict__,
                        "record_id": _id("quota"),
                        "committed_in_progress": committed,
                        "free_to_admit": (
                            snapshot.effective_remaining - committed
                            if snapshot.effective_remaining is not None
                            else None
                        ),
                        "projected_used_pct": utilization_pct(projected, snapshot.limit),
                        "observed_at_utc": now,
                        "reconciliation_predecessor": snapshot.record_id,
                        "reason_code": "TASK_RESERVATION_ADMITTED",
                    }
                )
                self._insert_snapshot(connection, reservation_snapshot, "RESERVATION_ADMITTED")
                admitted_results.append(
                    AdmissionBucketResult(
                        requirement.api_name,
                        reservation_id,
                        QuotaState.NORMAL,
                        "FULL_RESERVATION_AVAILABLE",
                        estimate,
                        0,
                    )
                )
            connection.commit()
            return AdmissionResult(True, "ADMITTED", "ALL_BUCKETS_RESERVED", alias, tuple(admitted_results))
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _admit_client_comparison(self, *, project_id, task_id, run_id, release_id,
                                 query_package_hash_or_ref, view, expected_api_key_alias,
                                 predecessor_reservation_id, now_utc=None):
        """One atomic two-request diagnostic, linked to a completed detail 401.

        This never changes the initial-preflight/ordinary admission gates and
        never creates a live observation. Only the matched executor uses it.
        One pair per key/API/window; uncertain sends cannot be replayed.
        """
        for name, value in (("project_id",project_id),("task_id",task_id),("run_id",run_id),
                            ("release_id",release_id),("alias",expected_api_key_alias),
                            ("predecessor",predecessor_reservation_id)):
            _validate_token(name,value)
        _validate_digest("query_package_hash_or_ref",query_package_hash_or_ref)
        if view not in {"META", "META_ABS", "FULL", "REF"}:
            raise LedgerError("COMPARISON_VIEW_INVALID")
        now=now_utc or utc_now(); parse_utc(now)
        connection=self._connect()
        try:
            self._begin_immediate(connection)
            prior=self._latest_reservation(connection,predecessor_reservation_id)
            binding=connection.execute("SELECT api_key_alias FROM project_key_alias_ledger WHERE project_id=? AND effective_at_utc<=? ORDER BY effective_at_utc DESC,rowid DESC LIMIT 1",(project_id,now)).fetchone()
            snapshot=self._latest_snapshot(connection,expected_api_key_alias,"abstract_retrieval")
            history=connection.execute("SELECT * FROM request_usage_log WHERE reservation_id=? ORDER BY rowid",(predecessor_reservation_id,)).fetchall()
            latest_outcome=connection.execute("SELECT * FROM request_usage_log WHERE api_key_alias=? AND api_name='abstract_retrieval' AND record_kind='OUTCOME' ORDER BY rowid DESC LIMIT 1",(expected_api_key_alias,)).fetchone()
            used=connection.execute("SELECT 1 FROM task_reservation_ledger WHERE event_seq=1 AND api_key_alias=? AND api_name='abstract_retrieval' AND admission_reason='AUTHORIZED_CLIENT_COMPARISON' AND window_id=?",(expected_api_key_alias,snapshot.window_id if snapshot else None)).fetchone()
            if (prior is None or binding is None or binding[0]!=expected_api_key_alias
                    or any(prior[k]!=v for k,v in (("project_id",project_id),("api_key_alias",expected_api_key_alias),("api_name","abstract_retrieval"),("view_name",view)))
                    or prior['actual_requests']!=1 or prior['reserved_remaining']!=0
                    or len(history)!=2 or history[0]['record_kind']!='ATTEMPT'
                    or history[1]['record_kind']!='OUTCOME' or history[1]['http_status']!=401
                    or history[1]['predecessor_event_id']!=history[0]['request_event_id']
                    or latest_outcome is None or latest_outcome['attempt_id']!=history[1]['attempt_id']
                    or snapshot is None or state_at(snapshot,now)!=QuotaState.QUOTA_TELEMETRY_UNKNOWN
                    or snapshot.reason_code!='HTTP_401_FAIL_CLOSED'
                    or snapshot.effective_remaining is None or snapshot.effective_remaining<2
                    or snapshot.committed_in_progress+2>snapshot.effective_remaining
                    or used or self._release_or_run_already_consumed(connection,project_id,task_id,release_id,run_id)):
                raise LedgerError("COMPARISON_NOT_ADMISSIBLE")
            reservation=_id("reservation")
            # Copy only control bounds, never the original raw content.
            fields=dict(prior)
            fields.update(reservation_event_id=_id("reservation_event"),reservation_id=reservation,
                event_seq=1,event_kind="COMPARISON_ADMITTED",predecessor_event_id=prior['reservation_event_id'],
                task_id=task_id,run_id=run_id,release_id=release_id,window_id=snapshot.window_id,query_package_hash_or_ref=query_package_hash_or_ref,
                forecast_pagination=0,forecast_detail_retrieval=2,forecast_validation=0,retry_allowance=0,
                estimated_requests_with_margin=2,reserved_remaining=2,actual_requests=0,
                admission_decision="ADMITTED",admission_reason="AUTHORIZED_CLIENT_COMPARISON",
                admitted_at_utc=now,completed_or_released_at_utc=None,recorded_at_utc=now)
            columns=list(fields)
            connection.execute("INSERT INTO task_reservation_ledger ("+",".join(columns)+") VALUES ("+",".join("?" for _ in columns)+")",tuple(fields[k] for k in columns))
            committed=snapshot.committed_in_progress+2
            successor=BucketSnapshot(**{**snapshot.__dict__,"record_id":_id("quota"),
                "committed_in_progress":committed,"free_to_admit":None,
                "projected_used_pct":utilization_pct((snapshot.used or 0)+committed,snapshot.limit),
                "observed_at_utc":now,"reconciliation_predecessor":snapshot.record_id})
            self._insert_snapshot(connection,successor,"COMPARISON_RESERVED")
            connection.commit()
            return reservation
        except BaseException:
            connection.rollback();raise
        finally:
            connection.close()

    def _admit_preflight(
        self,
        project_id: str,
        task_id: str,
        run_id: str,
        release_id: str,
        query_package_hash_or_ref: str,
        requirement: ReservationRequest,
        now_utc: Optional[str] = None,
        *,
        expected_api_key_alias: str,
        diagnostic_predecessor_reservation_id: Optional[str] = None,
    ) -> AdmissionResult:
        """Admit one separately authorized preflight or bounded diagnostic.

        This is deliberately distinct from :meth:`_admit_task`.  It creates no
        fabricated quota-window observation.  The caller must already have
        validated a preflight-specific live execution permit.  UNVERIFIED gets
        one minimal attempt; RESET_VERIFY/QUOTA_TELEMETRY_UNKNOWN get at most
        one diagnostic per unresolved window. A separately approved minimal
        correction may succeed the latest completed 200/403 diagnostic exactly
        once, linked to its predecessor. All paths are zero-retry.
        """

        for name, value in (
            ("project_id", project_id),
            ("task_id", task_id),
            ("run_id", run_id),
            ("release_id", release_id),
        ):
            _validate_token(name, value)
        _validate_digest("query_package_hash_or_ref", query_package_hash_or_ref)
        _validate_token("expected_api_key_alias", expected_api_key_alias)
        if diagnostic_predecessor_reservation_id is not None:
            _validate_token(
                "diagnostic_predecessor_reservation_id",
                diagnostic_predecessor_reservation_id,
            )
        if (
            requirement.estimated_requests_with_margin != 1
            or requirement.retry_allowance != 0
        ):
            raise ValueError("preflight must reserve exactly one request and no retries")
        now = now_utc or utc_now()
        parse_utc(now)

        connection = self._connect()
        try:
            self._begin_immediate(connection)
            binding = connection.execute(
                """
                SELECT api_key_alias FROM project_key_alias_ledger
                WHERE project_id = ? AND effective_at_utc <= ?
                ORDER BY effective_at_utc DESC, rowid DESC LIMIT 1
                """,
                (project_id, now),
            ).fetchone()
            if binding is None:
                connection.commit()
                return AdmissionResult(
                    False, "REJECTED", "PROJECT_KEY_ALIAS_UNBOUND", None, ()
                )
            alias = str(binding["api_key_alias"])
            if alias != expected_api_key_alias:
                connection.commit()
                return AdmissionResult(
                    False,
                    "REJECTED",
                    "PROJECT_KEY_ALIAS_MISMATCH",
                    alias,
                    (),
                )
            if self._release_or_run_already_consumed(
                connection, project_id, task_id, release_id, run_id
            ):
                connection.commit()
                return AdmissionResult(
                    False, "REJECTED", "TASK_RELEASE_ALREADY_CONSUMED", alias, ()
                )
            snapshot = self._latest_snapshot(connection, alias, requirement.api_name)
            predecessor_event_id = None
            if snapshot is None:
                if diagnostic_predecessor_reservation_id is not None:
                    raise LedgerError("DIAGNOSTIC_SUCCESSOR_REQUIRES_EXISTING_DIAGNOSTIC")
                prior_initial = connection.execute(
                    """
                    SELECT 1
                    FROM task_reservation_ledger
                    WHERE event_seq = 1 AND admission_decision = 'ADMITTED'
                      AND api_key_alias = ? AND api_name = ?
                      AND admission_reason = 'AUTHORIZED_MINIMAL_PREFLIGHT'
                    LIMIT 1
                    """,
                    (alias, requirement.api_name),
                ).fetchone()
                if prior_initial is not None:
                    connection.commit()
                    return AdmissionResult(
                        False,
                        "REJECTED",
                        "UNVERIFIED_PREFLIGHT_ALREADY_USED",
                        alias,
                        (),
                    )
                admission_reason = "AUTHORIZED_MINIMAL_PREFLIGHT"
                admission_state = QuotaState.UNVERIFIED
                window_id = None
            else:
                effective_state = state_at(snapshot, now)
                if effective_state not in {
                    QuotaState.RESET_VERIFY,
                    QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                }:
                    connection.commit()
                    return AdmissionResult(
                        False,
                        "REJECTED",
                        "PREFLIGHT_REQUIRES_UNVERIFIED_OR_DIAGNOSTIC_BUCKET",
                        alias,
                        (
                            AdmissionBucketResult(
                                requirement.api_name,
                                None,
                                effective_state,
                                "PREFLIGHT_REQUIRES_UNVERIFIED_OR_DIAGNOSTIC_BUCKET",
                                1,
                                0,
                            ),
                        ),
                    )
                admission_reason = "AUTHORIZED_BOUNDED_DIAGNOSTIC"
                admission_state = effective_state
                window_id = snapshot.window_id
                prior_diagnostic = connection.execute(
                    """
                    SELECT *
                    FROM task_reservation_ledger
                    WHERE event_seq = 1 AND admission_decision = 'ADMITTED'
                      AND api_key_alias = ? AND api_name = ?
                      AND window_id = ?
                      AND admission_reason = 'AUTHORIZED_BOUNDED_DIAGNOSTIC'
                    ORDER BY rowid DESC LIMIT 1
                    """,
                    (alias, requirement.api_name, window_id),
                ).fetchone()
                if prior_diagnostic is not None:
                    if diagnostic_predecessor_reservation_id is None:
                        connection.commit()
                        return AdmissionResult(
                            False, "REJECTED", "DIAGNOSTIC_ALREADY_USED_FOR_WINDOW", alias, (),
                        )
                    if (
                        prior_diagnostic["reservation_id"] != diagnostic_predecessor_reservation_id
                        or prior_diagnostic["project_id"] != project_id
                        or requirement.api_name != SCOPUS_SEARCH
                        or requirement.view != "STANDARD" or requirement.page_size != 1
                    ):
                        raise LedgerError("DIAGNOSTIC_SUCCESSOR_PREDECESSOR_MISMATCH")
                    previous = self._latest_reservation(connection, diagnostic_predecessor_reservation_id)
                    history = connection.execute(
                        "SELECT * FROM request_usage_log WHERE reservation_id = ? ORDER BY rowid",
                        (diagnostic_predecessor_reservation_id,),
                    ).fetchall()
                    if (
                        previous is None or int(previous["actual_requests"]) != 1
                        or int(previous["reserved_remaining"]) != 0 or len(history) != 2
                        or history[0]["record_kind"] != "ATTEMPT"
                        or history[1]["record_kind"] != "OUTCOME"
                        or history[1]["http_status"] not in {200, 403}
                        or history[1]["attempt_id"] != history[0]["attempt_id"]
                        or history[1]["predecessor_event_id"] != history[0]["request_event_id"]
                    ):
                        raise LedgerError("DIAGNOSTIC_SUCCESSOR_REQUIRES_COMPLETED_RESPONSE")
                    predecessor_event_id = previous["reservation_event_id"]
                elif diagnostic_predecessor_reservation_id is not None:
                    raise LedgerError("DIAGNOSTIC_SUCCESSOR_REQUIRES_EXISTING_DIAGNOSTIC")
            active = connection.execute(
                """
                SELECT 1
                FROM task_reservation_ledger AS seed
                JOIN task_reservation_ledger AS current
                  ON current.reservation_id = seed.reservation_id
                 AND current.event_seq = (
                      SELECT MAX(latest.event_seq)
                      FROM task_reservation_ledger AS latest
                      WHERE latest.reservation_id = seed.reservation_id
                 )
                WHERE seed.event_seq = 1
                  AND seed.api_key_alias = ? AND seed.api_name = ?
                  AND seed.admission_reason IN (
                      'AUTHORIZED_MINIMAL_PREFLIGHT',
                      'AUTHORIZED_BOUNDED_DIAGNOSTIC',
                      'AUTHORIZED_CLIENT_COMPARISON'
                  )
                  AND current.reserved_remaining > 0
                LIMIT 1
                """,
                (alias, requirement.api_name),
            ).fetchone()
            if active is not None:
                connection.commit()
                return AdmissionResult(
                    False, "REJECTED", "PREFLIGHT_ALREADY_RESERVED", alias, ()
                )

            reservation_id = _id("reservation")
            connection.execute(
                """
                INSERT INTO task_reservation_ledger(
                    reservation_event_id, reservation_id, event_seq, event_kind,
                    predecessor_event_id, window_id, api_key_alias, project_id,
                    task_id, run_id, release_id, query_package_hash_or_ref, api_name,
                    view_name, page_size, forecast_pagination,
                    forecast_detail_retrieval, forecast_validation, retry_allowance,
                    estimated_requests_with_margin, reserved_remaining,
                    actual_requests, admission_decision, admission_reason,
                    admitted_at_utc, completed_or_released_at_utc, recorded_at_utc
                ) VALUES (?, ?, 1, 'PREFLIGHT_ADMITTED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 0,
                          'ADMITTED', ?, ?, NULL, ?)
                """,
                (
                    _id("reservation_event"),
                    reservation_id,
                    predecessor_event_id,
                    window_id,
                    alias,
                    project_id,
                    task_id,
                    run_id,
                    release_id,
                    query_package_hash_or_ref,
                    requirement.api_name,
                    requirement.view,
                    requirement.page_size,
                    requirement.forecast_pagination,
                    requirement.forecast_detail_retrieval,
                    requirement.forecast_validation,
                    requirement.retry_allowance,
                    admission_reason,
                    now,
                    now,
                ),
            )
            connection.commit()
            return AdmissionResult(
                True,
                "ADMITTED",
                admission_reason,
                alias,
                (
                    AdmissionBucketResult(
                        requirement.api_name,
                        reservation_id,
                        admission_state,
                        admission_reason,
                        1,
                        0,
                    ),
                ),
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _insert_deferred_reservation(
        self,
        connection: sqlite3.Connection,
        alias: str,
        snapshot: BucketSnapshot,
        project_id: str,
        task_id: str,
        run_id: str,
        release_id: str,
        query_ref: str,
        requirement: ReservationRequest,
        evaluation: CandidateEvaluation,
        now: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO task_reservation_ledger(
                reservation_event_id, reservation_id, event_seq, event_kind,
                predecessor_event_id, window_id, api_key_alias, project_id,
                task_id, run_id, release_id, query_package_hash_or_ref, api_name,
                view_name, page_size, forecast_pagination,
                forecast_detail_retrieval, forecast_validation, retry_allowance,
                estimated_requests_with_margin, reserved_remaining, actual_requests,
                admission_decision, admission_reason, admitted_at_utc,
                completed_or_released_at_utc, recorded_at_utc
            ) VALUES (?, ?, 1, 'DEFERRED', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, NULL, ?, ?)
            """,
            (
                _id("reservation_event"),
                _id("reservation"),
                snapshot.window_id,
                alias,
                project_id,
                task_id,
                run_id,
                release_id,
                query_ref,
                requirement.api_name,
                requirement.view,
                requirement.page_size,
                requirement.forecast_pagination,
                requirement.forecast_detail_retrieval,
                requirement.forecast_validation,
                requirement.retry_allowance,
                requirement.estimated_requests_with_margin,
                evaluation.state.value,
                evaluation.reason_code,
                now,
                now,
            ),
        )

    def _latest_reservation(
        self, connection: sqlite3.Connection, reservation_id: str
    ) -> Optional[sqlite3.Row]:
        return connection.execute(
            """
            SELECT * FROM task_reservation_ledger
            WHERE reservation_id = ? ORDER BY event_seq DESC LIMIT 1
            """,
            (reservation_id,),
        ).fetchone()

    def record_request_attempt(
        self,
        reservation_id: str,
        endpoint_class: str,
        cursor_or_page_ref: Optional[str],
        retry_number: int = 0,
        requested_at_utc: Optional[str] = None,
    ) -> AttemptResult:
        """Charge an attempt and decrement its reservation in one transaction."""

        _validate_token("reservation_id", reservation_id)
        _validate_token("endpoint_class", endpoint_class)
        if cursor_or_page_ref is not None:
            _validate_control_ref("cursor_or_page_ref", cursor_or_page_ref)
        if retry_number < 0:
            raise ValueError("retry_number cannot be negative")
        now = requested_at_utc or utc_now()
        parse_utc(now)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            reservation = self._latest_reservation(connection, reservation_id)
            if reservation is None:
                raise LedgerError("UNKNOWN_RESERVATION")
            if (
                reservation["admission_decision"] != "ADMITTED"
                or reservation["completed_or_released_at_utc"] is not None
            ):
                connection.commit()
                return AttemptResult(
                    False,
                    None,
                    QuotaState.RUNNING_TASK_QUOTA_RISK,
                    "RESERVATION_NOT_ACTIVE",
                    int(reservation["reserved_remaining"]),
                )
            snapshot = self._latest_snapshot(
                connection, reservation["api_key_alias"], reservation["api_name"]
            )
            seed = connection.execute("SELECT admission_reason FROM task_reservation_ledger WHERE reservation_id=? AND event_seq=1",(reservation_id,)).fetchone()
            is_comparison = (
                snapshot is not None
                and seed is not None and seed[0] == "AUTHORIZED_CLIENT_COMPARISON"
                and reservation["estimated_requests_with_margin"] == 2
                and reservation["api_name"] == "abstract_retrieval"
                and int(reservation["actual_requests"]) in {0, 1}
                and retry_number == 0
                and connection.execute("SELECT 1 FROM request_usage_log a WHERE a.reservation_id=? AND a.record_kind='ATTEMPT' AND NOT EXISTS (SELECT 1 FROM request_usage_log o WHERE o.attempt_id=a.attempt_id AND o.record_kind='OUTCOME')",(reservation_id,)).fetchone() is None
                and state_at(snapshot, now) in {QuotaState.NORMAL, QuotaState.QUOTA_WARNING_80, QuotaState.QUOTA_TELEMETRY_UNKNOWN}
                and snapshot.effective_remaining is not None and snapshot.effective_remaining > 0
            )
            is_initial_preflight = (
                snapshot is None
                and reservation["window_id"] is None
                and reservation["admission_reason"] == "AUTHORIZED_MINIMAL_PREFLIGHT"
                and int(reservation["actual_requests"]) == 0
                and retry_number == 0
            )
            is_bounded_diagnostic = (
                snapshot is not None
                and reservation["admission_reason"] == "AUTHORIZED_BOUNDED_DIAGNOSTIC"
                and int(reservation["actual_requests"]) == 0
                and retry_number == 0
                and state_at(snapshot, now)
                in {QuotaState.RESET_VERIFY, QuotaState.QUOTA_TELEMETRY_UNKNOWN}
            )
            if snapshot is None and not is_initial_preflight:
                connection.commit()
                return AttemptResult(False, None, QuotaState.UNVERIFIED, "NO_QUOTA_WINDOW", 0)
            if (
                snapshot is not None
                and reservation["window_id"] is not None
                and reservation["window_id"] != snapshot.window_id
            ):
                reason = "CROSS_WINDOW_CONTINUATION_NOT_AUTHORIZED"
                self._append_reservation_state(
                    connection,
                    reservation,
                    "PAUSED",
                    "RUNNING_TASK_QUOTA_RISK",
                    reason,
                    now,
                )
                self._insert_quota_event(
                    connection,
                    snapshot,
                    "RUNNING_TASK_QUOTA_RISK",
                    "ERROR",
                    reservation["project_id"],
                    reservation["task_id"],
                    reservation["run_id"],
                    int(reservation["estimated_requests_with_margin"]),
                    int(reservation["reserved_remaining"]),
                    0,
                    reason,
                    completeness_state="PARTIAL_CHECKPOINTED",
                )
                connection.commit()
                return AttemptResult(
                    False,
                    None,
                    QuotaState.RUNNING_TASK_QUOTA_RISK,
                    reason,
                    int(reservation["reserved_remaining"]),
                )
            if (
                snapshot is not None
                and snapshot.effective_remaining is not None
                and snapshot.committed_in_progress > snapshot.effective_remaining
            ):
                reason = "ACTIVE_COMMITMENTS_EXCEED_LIVE_REMAINING"
                self._append_reservation_state(
                    connection,
                    reservation,
                    "PAUSED",
                    "RUNNING_TASK_QUOTA_RISK",
                    reason,
                    now,
                )
                self._insert_quota_event(
                    connection,
                    snapshot,
                    "RUNNING_TASK_QUOTA_RISK",
                    "ERROR",
                    reservation["project_id"],
                    reservation["task_id"],
                    reservation["run_id"],
                    int(reservation["estimated_requests_with_margin"]),
                    int(reservation["reserved_remaining"]),
                    snapshot.committed_in_progress - snapshot.effective_remaining,
                    reason,
                    completeness_state="PARTIAL_CHECKPOINTED",
                )
                connection.commit()
                return AttemptResult(
                    False,
                    None,
                    QuotaState.RUNNING_TASK_QUOTA_RISK,
                    reason,
                    int(reservation["reserved_remaining"]),
                )
            effective_state = (
                QuotaState.UNVERIFIED if snapshot is None else state_at(snapshot, now)
            )
            remaining = int(reservation["reserved_remaining"])
            allowed_states = {
                QuotaState.NORMAL,
                QuotaState.QUOTA_WARNING_80,
                QuotaState.THROTTLED,
            }
            if remaining <= 0 or (
                effective_state not in allowed_states
                and not is_initial_preflight
                and not is_bounded_diagnostic
                and not is_comparison
            ) or (
                snapshot is not None
                and snapshot.effective_remaining is not None
                and snapshot.effective_remaining <= 0
                and not is_initial_preflight
                and not is_bounded_diagnostic
                and not is_comparison
            ):
                reason = (
                    "RESERVATION_EXHAUSTED"
                    if remaining <= 0
                    else "BUCKET_BLOCKED_%s" % effective_state.value
                )
                self._append_reservation_state(
                    connection, reservation, "PAUSED", "RUNNING_TASK_QUOTA_RISK", reason, now
                )
                if snapshot is not None:
                    self._insert_quota_event(
                        connection,
                        snapshot,
                        "RUNNING_TASK_QUOTA_RISK",
                        "ERROR",
                        reservation["project_id"],
                        reservation["task_id"],
                        reservation["run_id"],
                        int(reservation["estimated_requests_with_margin"]),
                        remaining + 1,
                        max(1, 1 - remaining),
                        reason,
                    )
                connection.commit()
                return AttemptResult(False, None, QuotaState.RUNNING_TASK_QUOTA_RISK, reason, remaining)

            attempt_id = _id("attempt")
            request_event_id = _id("request_event")
            connection.execute(
                """
                INSERT INTO request_usage_log(
                    request_event_id, attempt_id, record_kind, predecessor_event_id,
                    reservation_id, project_id, task_id, run_id, api_key_alias,
                    api_name, endpoint_class, view_name, page_size, cursor_or_page_ref,
                    requested_at_utc, http_status, result_count, retry_number,
                    rate_limit_limit, rate_limit_remaining, rate_limit_reset_utc,
                    reservation_delta, outcome, stop_reason,
                    response_receipt_hash_or_ref, recorded_at_utc
                ) VALUES (?, ?, 'ATTEMPT', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, NULL, NULL, -1,
                          'ATTEMPT_RECORDED', NULL, NULL, ?)
                """,
                (
                    request_event_id,
                    attempt_id,
                    reservation_id,
                    reservation["project_id"],
                    reservation["task_id"],
                    reservation["run_id"],
                    reservation["api_key_alias"],
                    reservation["api_name"],
                    endpoint_class,
                    reservation["view_name"],
                    reservation["page_size"],
                    cursor_or_page_ref,
                    now,
                    retry_number,
                    now,
                ),
            )
            next_remaining = remaining - 1
            self._append_reservation_state(
                connection,
                reservation,
                "ATTEMPT_CONSUMED",
                "ADMITTED",
                "REQUEST_ATTEMPT_CHARGED",
                now,
                reserved_remaining=next_remaining,
                actual_requests=int(reservation["actual_requests"]) + 1,
            )

            if snapshot is None:
                connection.commit()
                return AttemptResult(
                    True,
                    attempt_id,
                    QuotaState.UNVERIFIED,
                    "PREFLIGHT_ATTEMPT_RECORDED",
                    next_remaining,
                )

            if is_bounded_diagnostic or is_comparison:
                effective_remaining = (
                    snapshot.effective_remaining - 1
                    if snapshot.effective_remaining is not None
                    else None
                )
                used = (
                    snapshot.limit - effective_remaining
                    if snapshot.limit is not None and effective_remaining is not None
                    else snapshot.used
                )
                diagnostic_snapshot = BucketSnapshot(
                    **{
                        **snapshot.__dict__,
                        "record_id": _id("quota"),
                        "local_attempts_since_header": snapshot.local_attempts_since_header + 1,
                        "effective_remaining": effective_remaining,
                        "used": used,
                        "committed_in_progress": max(0,snapshot.committed_in_progress-1) if is_comparison else snapshot.committed_in_progress,
                        "free_to_admit": None,
                        "actual_used_pct": (
                            utilization_pct(used, snapshot.limit)
                            if used is not None and snapshot.limit is not None
                            else snapshot.actual_used_pct
                        ),
                        "projected_used_pct": None,
                        "observed_at_utc": now,
                        "state": effective_state,
                        "reconciliation_predecessor": snapshot.record_id,
                        "reason_code": "AUTHORIZED_DIAGNOSTIC_ATTEMPT_CHARGED",
                    }
                )
                self._insert_snapshot(
                    connection, diagnostic_snapshot, "DIAGNOSTIC_REQUEST_ATTEMPT"
                )
                connection.commit()
                return AttemptResult(
                    True,
                    attempt_id,
                    effective_state,
                    "DIAGNOSTIC_ATTEMPT_RECORDED",
                    next_remaining,
                )

            effective_remaining = (
                snapshot.effective_remaining - 1
                if snapshot.effective_remaining is not None
                else None
            )
            used = (
                snapshot.limit - effective_remaining
                if snapshot.limit is not None and effective_remaining is not None
                else None
            )
            committed = max(0, snapshot.committed_in_progress - 1)
            free = (
                effective_remaining - committed if effective_remaining is not None else None
            )
            if effective_remaining is not None and effective_remaining <= 0:
                next_state = QuotaState.QUOTA_EXHAUSTED
            elif snapshot.state is QuotaState.QUOTA_WARNING_80:
                next_state = QuotaState.QUOTA_WARNING_80
            elif snapshot.limit is not None and used is not None and warning_threshold_reached(
                used + committed, snapshot.limit
            ):
                next_state = QuotaState.QUOTA_WARNING_80
            else:
                next_state = QuotaState.NORMAL
            charged_snapshot = BucketSnapshot(
                record_id=_id("quota"),
                window_id=snapshot.window_id,
                key=snapshot.key,
                limit=snapshot.limit,
                server_remaining=snapshot.server_remaining,
                local_attempts_since_header=snapshot.local_attempts_since_header + 1,
                effective_remaining=effective_remaining,
                used=used,
                committed_in_progress=committed,
                free_to_admit=free,
                actual_used_pct=(
                    utilization_pct(used, snapshot.limit)
                    if used is not None and snapshot.limit is not None
                    else None
                ),
                projected_used_pct=(
                    utilization_pct(used + committed, snapshot.limit)
                    if used is not None and snapshot.limit is not None
                    else None
                ),
                reset_at_utc=snapshot.reset_at_utc,
                observed_at_utc=now,
                header_evidence_ref=snapshot.header_evidence_ref,
                state=next_state,
                reconciliation_predecessor=snapshot.record_id,
                reason_code="REQUEST_ATTEMPT_CHARGED",
            )
            self._insert_snapshot(connection, charged_snapshot, "REQUEST_ATTEMPT")
            if next_state is QuotaState.QUOTA_WARNING_80 and snapshot.state is not next_state:
                self._insert_quota_event(
                    connection,
                    charged_snapshot,
                    "QUOTA_WARNING_80",
                    "WARNING",
                    reservation["project_id"],
                    reservation["task_id"],
                    reservation["run_id"],
                    int(reservation["estimated_requests_with_margin"]),
                    next_remaining,
                    0,
                    "ACTUAL_OR_COMMITTED_REACHED_80_PERCENT",
                )
            connection.commit()
            return AttemptResult(True, attempt_id, next_state, "ATTEMPT_RECORDED", next_remaining)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _append_reservation_state(
        self,
        connection: sqlite3.Connection,
        previous: sqlite3.Row,
        event_kind: str,
        decision: str,
        reason: str,
        now: str,
        reserved_remaining: Optional[int] = None,
        actual_requests: Optional[int] = None,
        completed_at: Optional[str] = None,
        replacement_window_id: Optional[str] = None,
    ) -> None:
        columns = (
            "reservation_id", "window_id", "api_key_alias", "project_id", "task_id",
            "run_id", "release_id", "query_package_hash_or_ref", "api_name", "view_name",
            "page_size", "forecast_pagination", "forecast_detail_retrieval",
            "forecast_validation", "retry_allowance", "estimated_requests_with_margin",
            "admitted_at_utc",
        )
        values = [previous[column] for column in columns]
        connection.execute(
            """
            INSERT INTO task_reservation_ledger(
                reservation_event_id, reservation_id, event_seq, event_kind,
                predecessor_event_id, window_id, api_key_alias, project_id, task_id,
                run_id, release_id, query_package_hash_or_ref, api_name, view_name,
                page_size, forecast_pagination, forecast_detail_retrieval,
                forecast_validation, retry_allowance, estimated_requests_with_margin,
                reserved_remaining, actual_requests, admission_decision,
                admission_reason, admitted_at_utc, completed_or_released_at_utc,
                recorded_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _id("reservation_event"),
                values[0],
                int(previous["event_seq"]) + 1,
                event_kind,
                previous["reservation_event_id"],
                replacement_window_id
                if replacement_window_id is not None
                else values[1],
                *values[2:-1],
                reserved_remaining if reserved_remaining is not None else previous["reserved_remaining"],
                actual_requests if actual_requests is not None else previous["actual_requests"],
                decision,
                reason,
                values[-1],
                completed_at,
                now,
            ),
        )

    def assess_running_forecast(
        self,
        reservation_id: str,
        revised_requests_remaining: int,
        safe_checkpoint: str,
        now_utc: Optional[str] = None,
    ) -> bool:
        """Pause at a safe boundary when a revised forecast exceeds reservation."""

        if revised_requests_remaining < 0:
            raise ValueError("revised_requests_remaining cannot be negative")
        _validate_control_ref("safe_checkpoint", safe_checkpoint)
        now = now_utc or utc_now()
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            reservation = self._latest_reservation(connection, reservation_id)
            if reservation is None:
                raise LedgerError("UNKNOWN_RESERVATION")
            available = int(reservation["reserved_remaining"])
            if revised_requests_remaining <= available:
                connection.commit()
                return True
            snapshot = self._latest_snapshot(
                connection, reservation["api_key_alias"], reservation["api_name"]
            )
            assert snapshot is not None
            self._append_reservation_state(
                connection, reservation, "PAUSED", "RUNNING_TASK_QUOTA_RISK",
                "REVISED_FORECAST_EXCEEDS_RESERVATION", now
            )
            self._insert_quota_event(
                connection,
                snapshot,
                "RUNNING_TASK_QUOTA_RISK",
                "ERROR",
                reservation["project_id"],
                reservation["task_id"],
                reservation["run_id"],
                available,
                revised_requests_remaining,
                revised_requests_remaining - available,
                "REVISED_FORECAST_EXCEEDS_RESERVATION",
                safe_checkpoint=safe_checkpoint,
                completeness_state="PARTIAL_CHECKPOINTED",
            )
            connection.commit()
            return False
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_reservation(
        self,
        reservation_id: str,
        completed_at_utc: Optional[str] = None,
    ) -> None:
        """Append task completion and release only its unused commitment.

        Paused and failed runs deliberately do not call this method: their
        remaining reservation stays protected pending coordination.  A normal
        completion may have used fewer requests than its upper bound, so the
        unused remainder is removed from ``committed_in_progress`` without
        rewriting any earlier evidence row.
        """

        _validate_token("reservation_id", reservation_id)
        completed = completed_at_utc or utc_now()
        parse_utc(completed)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            reservation = self._latest_reservation(connection, reservation_id)
            if reservation is None:
                raise LedgerError("UNKNOWN_RESERVATION")
            if reservation["completed_or_released_at_utc"] is not None:
                connection.commit()
                return
            unused = int(reservation["reserved_remaining"])
            self._append_reservation_state(
                connection,
                reservation,
                "COMPLETED",
                "COMPLETED",
                "TASK_COMPLETED_UNUSED_RESERVATION_RELEASED",
                completed,
                reserved_remaining=0,
                actual_requests=int(reservation["actual_requests"]),
                completed_at=completed,
            )
            snapshot = self._latest_snapshot(
                connection, reservation["api_key_alias"], reservation["api_name"]
            )
            if snapshot is not None and unused:
                committed = max(0, snapshot.committed_in_progress - unused)
                free = (
                    snapshot.effective_remaining - committed
                    if snapshot.effective_remaining is not None
                    else None
                )
                projected = (
                    snapshot.used + committed
                    if snapshot.used is not None
                    else None
                )
                released = BucketSnapshot(
                    **{
                        **snapshot.__dict__,
                        "record_id": _id("quota"),
                        "committed_in_progress": committed,
                        "free_to_admit": free,
                        "projected_used_pct": (
                            utilization_pct(projected, snapshot.limit)
                            if projected is not None and snapshot.limit is not None
                            else None
                        ),
                        "observed_at_utc": completed,
                        "reconciliation_predecessor": snapshot.record_id,
                        "reason_code": "UNUSED_RESERVATION_RELEASED_ON_COMPLETION",
                    }
                )
                self._insert_snapshot(connection, released, "RESERVATION_COMPLETED")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _evaluate_response_headers(
        self,
        connection: sqlite3.Connection,
        attempt: sqlite3.Row,
        http_status: int,
        headers: Mapping[str, Any],
        observed: str,
        previous: Optional[BucketSnapshot],
    ) -> HeaderEvaluation:
        evaluation = evaluate_headers(headers, observed, previous)
        if (
            http_status != 200 or previous is None
            or previous.state is not QuotaState.QUOTA_TELEMETRY_UNKNOWN
            or evaluation.reason_code != "RATE_LIMIT_WINDOW_CHANGED_EARLY"
        ):
            return evaluation
        seed = connection.execute(
            "SELECT * FROM task_reservation_ledger WHERE reservation_id = ? AND event_seq = 1",
            (attempt["reservation_id"],),
        ).fetchone()
        if (
            seed is None or seed["admission_reason"] != "AUTHORIZED_BOUNDED_DIAGNOSTIC"
            or int(seed["estimated_requests_with_margin"]) != 1
            or int(seed["page_size"]) != 1 or int(seed["retry_allowance"]) != 0
        ):
            return evaluation
        # A rejected request can report an unstarted/provisional quota window.
        # It must not prevent the first independently authorized successful
        # diagnostic from establishing the real window, including after the
        # operator replaced a credential while retaining its alias. Once any
        # successful response has established quota, ordinary window and local
        # accounting checks remain strict.
        accepted_success = connection.execute(
            """SELECT 1 FROM request_usage_log
               WHERE api_key_alias = ? AND api_name = ? AND record_kind = 'OUTCOME'
                 AND http_status BETWEEN 200 AND 299 AND rate_limit_limit IS NOT NULL
               LIMIT 1""",
            (attempt["api_key_alias"], attempt["api_name"]),
        ).fetchone()
        rejected_baseline = connection.execute(
            """SELECT 1 FROM request_usage_log
               WHERE api_key_alias = ? AND api_name = ? AND record_kind = 'OUTCOME'
                 AND http_status = 403 AND rate_limit_limit IS NOT NULL
                 AND rate_limit_reset_utc = ? LIMIT 1""",
            (attempt["api_key_alias"], attempt["api_name"], previous.reset_at_utc),
        ).fetchone()
        if accepted_success is not None or rejected_baseline is None:
            return evaluation
        fresh = evaluate_headers(headers, observed)
        if not fresh.valid:
            return evaluation
        return HeaderEvaluation(
            True, "RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC", fresh.limit,
            fresh.remaining, fresh.reset_at_utc, True,
        )

    def record_response(
        self,
        attempt_id: str,
        http_status: int,
        headers: Mapping[str, Any],
        response_receipt_hash_or_ref: Optional[str],
        result_count: Optional[int] = None,
        observed_at_utc: Optional[str] = None,
    ) -> ResponseResult:
        """Append an outcome and a sanitized reconciliation/status transition."""

        _validate_token("attempt_id", attempt_id)
        if response_receipt_hash_or_ref is not None:
            _validate_digest(
                "response_receipt_hash_or_ref", response_receipt_hash_or_ref
            )
        if result_count is not None and result_count < 0:
            raise ValueError("result_count cannot be negative")
        observed = observed_at_utc or utc_now()
        parse_utc(observed)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            attempt = connection.execute(
                "SELECT * FROM request_usage_log WHERE attempt_id = ? AND record_kind = 'ATTEMPT'",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                raise UnknownAttemptError("UNKNOWN_ATTEMPT")
            duplicate = connection.execute(
                "SELECT 1 FROM request_usage_log WHERE attempt_id = ? AND record_kind = 'OUTCOME'",
                (attempt_id,),
            ).fetchone()
            if duplicate is not None:
                raise DuplicateResponseError("OUTCOME_ALREADY_RECORDED")
            reservation = self._latest_reservation(connection, attempt["reservation_id"])
            if reservation is None:
                raise LedgerError("RESERVATION_MISSING_FOR_ATTEMPT")
            retry_allowance = int(reservation["retry_allowance"])
            retry_number = int(attempt["retry_number"])
            lowered = {str(key).lower(): value for key, value in headers.items()}
            disposition = classify_http_response(
                int(http_status),
                str(lowered.get("x-els-status")) if lowered.get("x-els-status") is not None else None,
                lowered.get("retry-after"),
                retry_number,
                retry_allowance,
            )
            previous = self._latest_snapshot(
                connection, attempt["api_key_alias"], attempt["api_name"]
            )
            header_evaluation = self._evaluate_response_headers(
                connection, attempt, int(http_status), headers, observed, previous
            )
            if (
                disposition.state is QuotaState.THROTTLED
                and not header_evaluation.valid
            ):
                disposition = HttpDisposition(
                    "PAUSED",
                    QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                    "QUOTA_TELEMETRY_UNKNOWN",
                    header_evaluation.reason_code,
                    False,
                    None,
                )
            elif header_evaluation.valid and header_evaluation.remaining == 0:
                # An authoritative zero balance is terminal for this bucket,
                # regardless of whether a 429 labels itself RATE_EXCEEDED or
                # QUOTA_EXCEEDED.  It must never become a retryable throttle.
                disposition = HttpDisposition(
                    "STOPPED" if int(http_status) == 429 else disposition.outcome,
                    QuotaState.QUOTA_EXHAUSTED,
                    "QUOTA_EXHAUSTED",
                    "RATE_LIMIT_REMAINING_ZERO",
                    False,
                    None,
                )
            connection.execute(
                """
                INSERT INTO request_usage_log(
                    request_event_id, attempt_id, record_kind, predecessor_event_id,
                    reservation_id, project_id, task_id, run_id, api_key_alias,
                    api_name, endpoint_class, view_name, page_size, cursor_or_page_ref,
                    requested_at_utc, http_status, result_count, retry_number,
                    rate_limit_limit, rate_limit_remaining, rate_limit_reset_utc,
                    reservation_delta, outcome, stop_reason,
                    response_receipt_hash_or_ref, recorded_at_utc
                ) VALUES (?, ?, 'OUTCOME', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (
                    _id("request_event"),
                    attempt_id,
                    attempt["request_event_id"],
                    attempt["reservation_id"],
                    attempt["project_id"],
                    attempt["task_id"],
                    attempt["run_id"],
                    attempt["api_key_alias"],
                    attempt["api_name"],
                    attempt["endpoint_class"],
                    attempt["view_name"],
                    attempt["page_size"],
                    attempt["cursor_or_page_ref"],
                    attempt["requested_at_utc"],
                    int(http_status),
                    result_count,
                    retry_number,
                    header_evaluation.limit if header_evaluation.valid else None,
                    header_evaluation.remaining if header_evaluation.valid else None,
                    header_evaluation.reset_at_utc if header_evaluation.valid else None,
                    disposition.outcome,
                    disposition.stop_reason,
                    response_receipt_hash_or_ref,
                    observed,
                ),
            )

            next_snapshot = self._reconciled_snapshot(
                attempt["api_key_alias"],
                attempt["api_name"],
                headers,
                attempt_id,
                observed,
                previous,
                previous.committed_in_progress if previous else 0,
                header_evaluation=header_evaluation,
            )

            if disposition.state is not None:
                forced_state = disposition.state
                if forced_state is QuotaState.QUOTA_EXHAUSTED:
                    next_snapshot = BucketSnapshot(
                        **{
                            **next_snapshot.__dict__,
                            "state": forced_state,
                            "free_to_admit": 0,
                            "reason_code": disposition.stop_reason or "QUOTA_EXHAUSTED",
                        }
                    )
                elif forced_state is QuotaState.THROTTLED:
                    next_snapshot = BucketSnapshot(
                        **{
                            **next_snapshot.__dict__,
                            "state": forced_state,
                            "reason_code": "THROTTLED_BOUNDED_RETRY",
                        }
                    )
                else:
                    next_snapshot = BucketSnapshot(
                        **{
                            **next_snapshot.__dict__,
                            "state": forced_state,
                            "free_to_admit": None,
                            "reason_code": disposition.stop_reason or "FAIL_CLOSED",
                        }
                    )
            comparison = connection.execute("SELECT 1 FROM task_reservation_ledger WHERE reservation_id=? AND event_seq=1 AND admission_reason='AUTHORIZED_CLIENT_COMPARISON'",(attempt['reservation_id'],)).fetchone()
            denied = connection.execute("SELECT 1 FROM request_usage_log WHERE reservation_id=? AND record_kind='OUTCOME' AND http_status IN (401,403)",(attempt['reservation_id'],)).fetchone()
            if comparison and denied and int(http_status)==200:
                next_snapshot=BucketSnapshot(**{**next_snapshot.__dict__,"state":QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                    "free_to_admit":None,"reason_code":"COMPARISON_ACCESS_MISMATCH"})
            self._insert_snapshot(connection, next_snapshot, "RESPONSE_RECONCILIATION")

            event_type = disposition.event_type
            if (
                event_type is None
                and next_snapshot.state is QuotaState.QUOTA_WARNING_80
                and (previous is None or previous.state is not QuotaState.QUOTA_WARNING_80)
            ):
                event_type = "QUOTA_WARNING_80"
            if event_type is None and next_snapshot.state is QuotaState.QUOTA_TELEMETRY_UNKNOWN:
                event_type = "QUOTA_TELEMETRY_UNKNOWN"
            if event_type is None and next_snapshot.state is QuotaState.QUOTA_EXHAUSTED:
                event_type = "QUOTA_EXHAUSTED"
            if event_type is not None:
                severity = "WARNING" if event_type in ("THROTTLED", "QUOTA_WARNING_80") else "ERROR"
                self._insert_quota_event(
                    connection,
                    next_snapshot,
                    event_type,
                    severity,
                    attempt["project_id"],
                    attempt["task_id"],
                    attempt["run_id"],
                    int(reservation["estimated_requests_with_margin"]),
                    int(reservation["reserved_remaining"]),
                    0,
                    next_snapshot.reason_code,
                )
            connection.commit()
            return ResponseResult(
                attempt_id,
                disposition,
                next_snapshot.state,
                header_evaluation.reason_code,
                previous.effective_remaining if previous else None,
                next_snapshot.effective_remaining,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def reconcile_retained_min(
        self, *, attempt_id: str, api_key_alias: str, api_name: str,
        project_id: str, headers: Mapping[str, Any], response_sha256: str,
        evidence_sha256: str, observed_at_utc: Optional[str] = None,
    ) -> Tuple[BucketSnapshot, bool]:
        """Append a local correction of an old numeric-only pause; no new charge.

        The caller validates retained control events and the saved raw-page
        hash. Recheck the immutable attempt/outcome and latest bucket under the
        transaction. A missing observation, later failure or new window is
        never repaired by replaying an older balance.
        """
        _validate_token('attempt_id', attempt_id)
        _validate_digest('response_sha256', response_sha256)
        _validate_digest('evidence_sha256', evidence_sha256)
        observed = observed_at_utc or utc_now()
        parse_utc(observed)
        reference = 'retained-' + evidence_sha256
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            attempt = connection.execute("SELECT * FROM request_usage_log WHERE attempt_id=? AND record_kind='ATTEMPT'",(attempt_id,)).fetchone()
            outcome = connection.execute("SELECT * FROM request_usage_log WHERE attempt_id=? AND record_kind='OUTCOME'",(attempt_id,)).fetchone()
            binding = connection.execute('SELECT api_key_alias FROM project_key_alias_ledger WHERE project_id=? ORDER BY rowid DESC LIMIT 1',(project_id,)).fetchone()
            if (attempt is None or outcome is None or binding is None or binding[0] != api_key_alias
                    or any(attempt[name] != expected for name,expected in
                           (('api_key_alias',api_key_alias),('api_name',api_name),('project_id',project_id)))
                    or attempt['reservation_delta'] != -1 or outcome['reservation_delta'] != 0
                    or outcome['predecessor_event_id'] != attempt['request_event_id']
                    or outcome['http_status'] != 200 or outcome['response_receipt_hash_or_ref'] != response_sha256):
                raise LedgerError('RETAINED_RECONCILIATION_EVIDENCE_MISMATCH')
            current = self._latest_snapshot(connection, api_key_alias, api_name)
            existing = connection.execute("SELECT 1 FROM quota_window_ledger WHERE api_key_alias=? AND api_name=? AND record_kind='RETAINED_MIN_RECONCILIATION' AND header_evidence_ref=?",(api_key_alias,api_name,reference)).fetchone()
            if existing and current is not None:
                connection.commit()
                return current, False
            if (current is None or current.state is not QuotaState.QUOTA_TELEMETRY_UNKNOWN
                    or current.reason_code != 'RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING'
                    or current.header_evidence_ref != attempt_id):
                raise LedgerError('RETAINED_RECONCILIATION_NOT_LATEST_NUMERIC_PAUSE')
            if state_at(current, observed) is QuotaState.RESET_VERIFY:
                raise LedgerError('RETAINED_RECONCILIATION_WINDOW_EXPIRED')
            evaluation = evaluate_headers(headers, outcome['recorded_at_utc'], current)
            if (not evaluation.valid or evaluation.window_id_changed
                    or evaluation.reset_at_utc != current.reset_at_utc
                    or current.window_id != _window_id(api_key_alias,api_name,evaluation.reset_at_utc)):
                raise LedgerError('RETAINED_RECONCILIATION_HEADERS_INVALID')
            successor = self._reconciled_snapshot(api_key_alias,api_name,headers,reference,observed,
                current,current.committed_in_progress,header_evaluation=evaluation)
            self._insert_snapshot(connection, successor, 'RETAINED_MIN_RECONCILIATION')
            connection.commit()
            return successor, True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_transport_failure(
        self,
        attempt_id: str,
        observed_at_utc: Optional[str] = None,
    ) -> ResponseResult:
        """Append a content-free failed outcome when no HTTP response exists.

        The attempt was already conservatively charged before transport.  With
        no authoritative headers, new admissions freeze as telemetry unknown;
        no fabricated HTTP status or response receipt is written.
        """

        _validate_token("attempt_id", attempt_id)
        observed = observed_at_utc or utc_now()
        parse_utc(observed)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            attempt = connection.execute(
                "SELECT * FROM request_usage_log WHERE attempt_id = ? AND record_kind = 'ATTEMPT'",
                (attempt_id,),
            ).fetchone()
            if attempt is None:
                raise UnknownAttemptError("UNKNOWN_ATTEMPT")
            duplicate = connection.execute(
                "SELECT 1 FROM request_usage_log WHERE attempt_id = ? AND record_kind = 'OUTCOME'",
                (attempt_id,),
            ).fetchone()
            if duplicate is not None:
                raise DuplicateResponseError("OUTCOME_ALREADY_RECORDED")
            reservation = self._latest_reservation(connection, attempt["reservation_id"])
            if reservation is None:
                raise LedgerError("RESERVATION_MISSING_FOR_ATTEMPT")
            connection.execute(
                """
                INSERT INTO request_usage_log(
                    request_event_id, attempt_id, record_kind, predecessor_event_id,
                    reservation_id, project_id, task_id, run_id, api_key_alias,
                    api_name, endpoint_class, view_name, page_size, cursor_or_page_ref,
                    requested_at_utc, http_status, result_count, retry_number,
                    rate_limit_limit, rate_limit_remaining, rate_limit_reset_utc,
                    reservation_delta, outcome, stop_reason,
                    response_receipt_hash_or_ref, recorded_at_utc
                ) VALUES (?, ?, 'OUTCOME', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?,
                          NULL, NULL, NULL, 0, 'TRANSPORT_ERROR', 'TRANSPORT_FAILED', NULL, ?)
                """,
                (
                    _id("request_event"),
                    attempt_id,
                    attempt["request_event_id"],
                    attempt["reservation_id"],
                    attempt["project_id"],
                    attempt["task_id"],
                    attempt["run_id"],
                    attempt["api_key_alias"],
                    attempt["api_name"],
                    attempt["endpoint_class"],
                    attempt["view_name"],
                    attempt["page_size"],
                    attempt["cursor_or_page_ref"],
                    attempt["requested_at_utc"],
                    attempt["retry_number"],
                    observed,
                ),
            )
            previous = self._latest_snapshot(
                connection, attempt["api_key_alias"], attempt["api_name"]
            )
            snapshot = self._reconciled_snapshot(
                attempt["api_key_alias"],
                attempt["api_name"],
                {},
                attempt_id,
                observed,
                previous,
                previous.committed_in_progress if previous else 0,
            )
            snapshot = BucketSnapshot(
                **{
                    **snapshot.__dict__,
                    "state": QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                    "free_to_admit": None,
                    "reason_code": "TRANSPORT_FAILED_NO_HEADERS",
                }
            )
            self._insert_snapshot(connection, snapshot, "TRANSPORT_FAILURE")
            self._insert_quota_event(
                connection,
                snapshot,
                "QUOTA_TELEMETRY_UNKNOWN",
                "ERROR",
                attempt["project_id"],
                attempt["task_id"],
                attempt["run_id"],
                int(reservation["estimated_requests_with_margin"]),
                int(reservation["reserved_remaining"]),
                0,
                "TRANSPORT_FAILED_NO_HEADERS",
            )
            disposition = HttpDisposition(
                "FAILED",
                QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                "QUOTA_TELEMETRY_UNKNOWN",
                "TRANSPORT_FAILED",
                False,
                None,
            )
            connection.commit()
            return ResponseResult(
                attempt_id,
                disposition,
                QuotaState.QUOTA_TELEMETRY_UNKNOWN,
                "RATE_LIMIT_HEADERS_MISSING",
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _insert_quota_event(
        self,
        connection: sqlite3.Connection,
        snapshot: BucketSnapshot,
        event_type: str,
        severity: str,
        project_id: Optional[str],
        task_id: Optional[str],
        run_id: Optional[str],
        original_forecast: Optional[int],
        revised_forecast: Optional[int],
        capacity_gap: Optional[int],
        forecast_reason: str,
        safe_checkpoint: Optional[str] = None,
        completeness_state: str = "NOT_STARTED",
    ) -> None:
        packet = build_event_packet(
            event_type,
            snapshot,
            project_id,
            task_id,
            run_id,
            original_forecast,
            revised_forecast,
            capacity_gap,
            safe_checkpoint,
            completeness_state,
        )
        event_id = _id("quota_event")
        connection.execute(
            """
            INSERT INTO quota_event_disposition_log(
                quota_event_id, event_group_id, record_kind, event_type, severity,
                detected_at_utc, window_id, api_key_alias, api_name, limit_value,
                used, committed, remaining, free, projected_pct, project_id, task_id,
                run_id, original_forecast, revised_forecast, forecast_reason,
                safe_checkpoint, completeness_state,
                schedule_coverage_deliverable_effect, options_and_consequences_json,
                exact_src_pi_question, notification_evidence, src_notified_at_utc,
                pi_notified_at_utc, src_coordination_response, pi_disposition, owner,
                completion_condition, closure_evidence, predecessor_event_id,
                recorded_at_utc
            ) VALUES (?, ?, 'EVENT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'LOCAL_RECORD_ONLY', NULL, NULL, NULL, NULL, 'LOCAL_OPERATOR',
                      'VERIFIED_CAPACITY_AND_EXPLICIT_EXECUTION', NULL, NULL, ?)
            """,
            (
                event_id,
                event_id,
                event_type,
                severity,
                snapshot.observed_at_utc,
                snapshot.window_id,
                snapshot.key.api_key_alias,
                snapshot.key.api_name,
                snapshot.limit,
                snapshot.used,
                snapshot.committed_in_progress,
                snapshot.effective_remaining,
                snapshot.free_to_admit,
                snapshot.projected_used_pct,
                project_id,
                task_id,
                run_id,
                original_forecast,
                revised_forecast,
                forecast_reason,
                safe_checkpoint,
                completeness_state,
                "LOCAL_RETRIEVAL_PAUSED_OR_DEFERRED",
                json.dumps(
                    {
                        "bounded_options": packet["bounded_options"],
                        "consequences": packet["consequences"],
                        "capacity_gap": packet["capacity_gap"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                packet["exact_question"],
                snapshot.observed_at_utc,
            ),
        )

    @staticmethod
    def _insert_event_successor(
        connection: sqlite3.Connection,
        previous: sqlite3.Row,
        **changes: Any,
    ) -> str:
        values = {column: previous[column] for column in _QUOTA_EVENT_COLUMNS}
        values.update(changes)
        event_id = _id("quota_event")
        values["quota_event_id"] = event_id
        values["predecessor_event_id"] = previous["quota_event_id"]
        placeholders = ",".join("?" for _ in _QUOTA_EVENT_COLUMNS)
        connection.execute(
            "INSERT INTO quota_event_disposition_log(%s) VALUES (%s)"
            % (",".join(_QUOTA_EVENT_COLUMNS), placeholders),
            tuple(values[column] for column in _QUOTA_EVENT_COLUMNS),
        )
        return event_id

    def append_quota_disposition(
        self,
        event_group_id: str,
        src_coordination_response: str,
        pi_disposition: str,
        notification_evidence_ref: str,
        src_notified_at_utc: str,
        pi_notified_at_utc: str,
        recorded_at_utc: Optional[str] = None,
    ) -> str:
        """Append a bounded SRC/PI disposition without rewriting the event."""

        _validate_token("event_group_id", event_group_id)
        _validate_digest("notification_evidence_ref", notification_evidence_ref)
        if src_coordination_response not in _SRC_DISPOSITION_CODES:
            raise ValueError("unsupported SRC coordination response")
        if pi_disposition not in _PI_DISPOSITION_CODES:
            raise ValueError("unsupported PI disposition")
        parse_utc(src_notified_at_utc)
        parse_utc(pi_notified_at_utc)
        recorded = recorded_at_utc or utc_now()
        parse_utc(recorded)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            previous = connection.execute(
                """
                SELECT * FROM quota_event_disposition_log
                WHERE event_group_id = ? ORDER BY rowid DESC LIMIT 1
                """,
                (event_group_id,),
            ).fetchone()
            if previous is None:
                raise LedgerError("UNKNOWN_QUOTA_EVENT_GROUP")
            if previous["record_kind"] == "CLOSURE":
                raise LedgerError("QUOTA_EVENT_GROUP_ALREADY_CLOSED")
            event_id = self._insert_event_successor(
                connection,
                previous,
                record_kind="DISPOSITION",
                notification_evidence=notification_evidence_ref,
                src_notified_at_utc=src_notified_at_utc,
                pi_notified_at_utc=pi_notified_at_utc,
                src_coordination_response=src_coordination_response,
                pi_disposition=pi_disposition,
                recorded_at_utc=recorded,
            )
            connection.commit()
            return event_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def close_quota_event(
        self,
        event_group_id: str,
        closure_evidence_ref: str,
        recorded_at_utc: Optional[str] = None,
    ) -> str:
        """Append closure only after a recorded two-party disposition."""

        _validate_token("event_group_id", event_group_id)
        _validate_digest("closure_evidence_ref", closure_evidence_ref)
        recorded = recorded_at_utc or utc_now()
        parse_utc(recorded)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            previous = connection.execute(
                """
                SELECT * FROM quota_event_disposition_log
                WHERE event_group_id = ? ORDER BY rowid DESC LIMIT 1
                """,
                (event_group_id,),
            ).fetchone()
            if previous is None:
                raise LedgerError("UNKNOWN_QUOTA_EVENT_GROUP")
            if previous["record_kind"] != "DISPOSITION":
                raise LedgerError("QUOTA_EVENT_DISPOSITION_REQUIRED_BEFORE_CLOSURE")
            event_id = self._insert_event_successor(
                connection,
                previous,
                record_kind="CLOSURE",
                closure_evidence=closure_evidence_ref,
                recorded_at_utc=recorded,
            )
            connection.commit()
            return event_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def authorize_cross_window_continuation(
        self,
        reservation_id: str,
        event_group_id: str,
        recorded_at_utc: Optional[str] = None,
    ) -> None:
        """Rebind a paused reservation only after matching SRC and PI approval."""

        _validate_token("reservation_id", reservation_id)
        _validate_token("event_group_id", event_group_id)
        recorded = recorded_at_utc or utc_now()
        parse_utc(recorded)
        connection = self._connect()
        try:
            self._begin_immediate(connection)
            reservation = self._latest_reservation(connection, reservation_id)
            if reservation is None:
                raise LedgerError("UNKNOWN_RESERVATION")
            if (
                reservation["admission_decision"] != "RUNNING_TASK_QUOTA_RISK"
                or reservation["admission_reason"]
                != "CROSS_WINDOW_CONTINUATION_NOT_AUTHORIZED"
            ):
                raise LedgerError("RESERVATION_NOT_PAUSED_FOR_CROSS_WINDOW_REVIEW")
            snapshot = self._latest_snapshot(
                connection, reservation["api_key_alias"], reservation["api_name"]
            )
            if snapshot is None or snapshot.window_id == reservation["window_id"]:
                raise LedgerError("NO_NEW_VERIFIED_WINDOW")
            disposition = connection.execute(
                """
                SELECT * FROM quota_event_disposition_log
                WHERE event_group_id = ? ORDER BY rowid DESC LIMIT 1
                """,
                (event_group_id,),
            ).fetchone()
            if disposition is None or disposition["record_kind"] not in {
                "DISPOSITION",
                "CLOSURE",
            }:
                raise LedgerError("RECORDED_SRC_PI_DISPOSITION_REQUIRED")
            if not (
                disposition["event_type"] == "RUNNING_TASK_QUOTA_RISK"
                and disposition["project_id"] == reservation["project_id"]
                and disposition["task_id"] == reservation["task_id"]
                and disposition["run_id"] == reservation["run_id"]
                and disposition["api_name"] == reservation["api_name"]
                and disposition["window_id"] == snapshot.window_id
                and disposition["src_coordination_response"]
                == "APPROVE_CROSS_WINDOW_CONTINUATION"
                and disposition["pi_disposition"]
                == "APPROVE_CROSS_WINDOW_CONTINUATION"
            ):
                raise LedgerError("CROSS_WINDOW_DISPOSITION_DOES_NOT_MATCH")
            self._append_reservation_state(
                connection,
                reservation,
                "CROSS_WINDOW_AUTHORIZED",
                "ADMITTED",
                "RECORDED_SRC_PI_CROSS_WINDOW_DISPOSITION",
                recorded,
                replacement_window_id=snapshot.window_id,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def ledger_count(self, ledger_name: str) -> int:
        tables = {
            "quota_window": "quota_window_ledger",
            "task_reservation": "task_reservation_ledger",
            "request_usage": "request_usage_log",
            "quota_event": "quota_event_disposition_log",
            "project_alias": "project_key_alias_ledger",
        }
        if ledger_name not in tables:
            raise ValueError("unknown ledger name")
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM " + tables[ledger_name]).fetchone()
        return int(row["n"])

    def request_attempt_count(self, project_id: str) -> int:
        """Count local attempts without loading an unbounded history into memory."""
        _validate_token("project_id", project_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM request_usage_log WHERE project_id = ? AND record_kind = 'ATTEMPT'",
                (project_id,),
            ).fetchone()
        return int(row["n"])

    def rows(self, ledger_name: str) -> Tuple[Dict[str, Any], ...]:
        """Return control-only rows for tests and bounded status reporting."""

        tables = {
            "quota_window": "quota_window_ledger",
            "task_reservation": "task_reservation_ledger",
            "request_usage": "request_usage_log",
            "quota_event": "quota_event_disposition_log",
            "project_alias": "project_key_alias_ledger",
        }
        if ledger_name not in tables:
            raise ValueError("unknown ledger name")
        with self._connect() as connection:
            result = connection.execute(
                "SELECT * FROM " + tables[ledger_name] + " ORDER BY rowid"
            ).fetchall()
        return tuple(dict(row) for row in result)


__all__ = [
    "AdmissionBucketResult",
    "AdmissionResult",
    "AliasBindingError",
    "AttemptResult",
    "DuplicateResponseError",
    "Ledger",
    "LedgerError",
    "ResponseResult",
    "SCHEMA_VERSION",
    "UnknownAttemptError",
]
