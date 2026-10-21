"""Offline, immutable delivery bundles for an explicit collection of saved records.

Inputs may be explicit local CSV, JSONL or JSON files outside restricted storage,
which permits importing a consuming project's existing exports. Inputs are read
without following symlinks and are never modified. Every derived file is written
through the configured restricted artifact store. This module never opens a
ledger, resolves credentials, or creates a network transport.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import __version__
from .artifacts import ArtifactError, _open_absolute_directory_no_symlinks
from .errors import ValidationError
from .security import reject_symlink_components


VERSION = "doi-priority-delivery-v1"
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 512 * 1024 * 1024
MAX_INPUTS = 128
MAX_OCCURRENCES = 1_000_000
_POLICY_BYTES = 1024 * 1024
_CSV_LOCK = threading.RLock()


def _encoded(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValidationError("Delivery metadata is not valid JSON.") from None


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_record_sha(value: Mapping[str, Any]) -> str:
    """Hash UTF-8 sorted compact JSON, with no ASCII escaping or trailing LF.

    JSONL transport newlines are excluded so the digest matches the selector's
    canonical parsed-object hash rather than the serialized line hash.
    """
    return _sha(_encoded(value)[:-1])


def _source_path(value: Any) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise ValidationError("Delivery input requires an explicit local file.")
    path = Path(value)
    if ".." in path.parts or "\x00" in str(path):
        raise ValidationError("Delivery input traversal is not allowed.")
    if not path.is_absolute():
        path = Path.cwd() / path
    reject_symlink_components(path)
    return path


def _read_regular_at(parent: int, name: str, maximum: int) -> bytes:
    descriptor = None
    try:
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0),
                             dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("Delivery input must be a regular file.")
        if info.st_size > maximum:
            raise ValidationError("Delivery input exceeds the size limit.")
        result = []
        remaining = maximum + 1
        while remaining:
            block = os.read(descriptor, min(65536, remaining))
            if not block:
                break
            result.append(block)
            remaining -= len(block)
        data = b"".join(result)
        if len(data) > maximum:
            raise ValidationError("Delivery input exceeds the size limit.")
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_external(path: Path, maximum: int) -> bytes:
    """Use descriptor traversal for external inputs, as for restricted files."""
    parent = _open_absolute_directory_no_symlinks(path.parent)
    try:
        return _read_regular_at(parent, path.name, maximum)
    finally:
        os.close(parent)


def _read_input(store: Any, value: Any, maximum: int) -> Tuple[Path, str, bytes]:
    try:
        path = _source_path(value)
        try:
            relative = path.relative_to(store.root)
        except ValueError:
            ref = str(path)
            body = _read_external(path, maximum)
        else:
            ref = relative.as_posix()
            with store._parent_fd(relative, create=False) as (parent, name):
                body = _read_regular_at(parent, name, maximum)
        return path, ref, body
    except ValidationError:
        raise
    except (OSError, ArtifactError, ValueError, RuntimeError):
        raise ValidationError("Delivery input could not be read safely.") from None


def _json_value(body: bytes) -> Any:
    def object_pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value

    def invalid_constant(value: str) -> Any:
        raise ValueError()

    try:
        return json.loads(body.decode("utf-8-sig"), object_pairs_hook=object_pairs,
                          parse_constant=invalid_constant)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ValidationError("Delivery input contains invalid JSON.") from None


def _parse_rows(path: Path, body: bytes) -> Tuple[List[Dict[str, Any]], str]:
    suffix = path.suffix.casefold()
    try:
        if suffix == ".csv":
            with _CSV_LOCK:
                previous_limit = csv.field_size_limit()
                try:
                    csv.field_size_limit(MAX_INPUT_BYTES)
                    reader = csv.DictReader(io.StringIO(body.decode("utf-8-sig"), newline=""))
                    columns = reader.fieldnames
                    if (not columns or any(not column for column in columns)
                            or len(columns) != len(set(columns))):
                        raise ValidationError("Delivery CSV columns are invalid.")
                    rows = list(reader)
                finally:
                    csv.field_size_limit(previous_limit)
            if any(None in row or any(value is None for value in row.values()) for row in rows):
                raise ValidationError("Delivery CSV rows do not match their columns.")
            source_format = "csv"
        elif suffix in {".jsonl", ".ndjson"}:
            rows = [_json_value(line) for line in body.splitlines() if line.strip()]
            source_format = "jsonl"
        elif suffix == ".json":
            value = _json_value(body)
            if isinstance(value, list):
                rows = value
            elif isinstance(value, dict) and isinstance(value.get("records"), list):
                rows = value["records"]
            elif isinstance(value, dict) and any(key in value for key in ("eid", "EID", "merged")):
                rows = [value]
            else:
                raise ValidationError("Delivery JSON requires saved record objects.")
            source_format = "json"
        else:
            raise ValidationError("Delivery inputs must be CSV, JSONL or JSON files.")
    except (UnicodeError, csv.Error, ValueError, TypeError, RecursionError):
        raise ValidationError("Delivery input records are invalid.") from None
    if len(rows) > MAX_OCCURRENCES or any(not isinstance(row, dict) for row in rows):
        raise ValidationError("Delivery requires a bounded collection of record objects.")
    if any("_delivery" in row for row in rows):
        raise ValidationError("Delivery input contains reserved provenance metadata.")
    return rows, source_format


def _json_lines(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join(_encoded(row) for row in rows)


def _csv_bytes(rows: List[Mapping[str, Any]]) -> bytes:
    flattened = []
    source_fields = set()
    for row in rows:
        original = row.get("record")
        if not isinstance(original, dict):
            raise ValidationError("Delivery representative records are invalid.")
        content = original.get("merged")
        if not isinstance(content, dict):
            content = original
        flattened.append(dict(content))
        source_fields.update(content)
    metadata_names = {}
    for name in ("_deduplication", "_delivery_provenance", "_source_record"):
        candidate = name
        while candidate in source_fields:
            candidate = "_" + candidate
        metadata_names[name] = candidate
        source_fields.add(candidate)
    for source, row in zip(rows, flattened):
        row[metadata_names["_deduplication"]] = source.get("deduplication")
        row[metadata_names["_delivery_provenance"]] = source.get("provenance")
        if isinstance(source["record"].get("merged"), dict):
            row[metadata_names["_source_record"]] = source["record"]
    columns = sorted({key for row in flattened for key in row})
    if not columns:
        columns = ["EID"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in flattened:
        writer.writerow({key: json.dumps(value, ensure_ascii=False, sort_keys=True,
                                         allow_nan=False, separators=(",", ":"))
                         if isinstance(value, (dict, list)) else value
                         for key, value in row.items()})
    return stream.getvalue().encode("utf-8")


def export_delivery(store: Any, inputs: Iterable[Any], *, policy_path: Optional[Any] = None) -> Dict[str, Any]:
    """Publish one version for exactly the supplied local file collection.

    The caller supplies a policy-allowlisted ``RestrictedArtifactStore``. Local
    imports outside that store are permitted only through explicit file paths;
    there is no recursive discovery. The return value is safe control metadata.
    The restricted manifest and raw occurrence wrappers retain source paths,
    file hashes, row positions and every original parsed source object.
    """
    from . import deduplication

    if isinstance(inputs, (str, bytes, Path)):
        raise ValidationError("Delivery inputs must be an explicit file list.")
    paths = list(inputs)
    if not 1 <= len(paths) <= MAX_INPUTS:
        raise ValidationError("Select 1-128 explicit delivery input files.")
    paths = sorted((_source_path(path) for path in paths), key=str)
    if policy_path is None:
        policy = copy.deepcopy(deduplication.DEFAULT_POLICY)
        policy_body = _encoded(policy)
        policy_input_ref = None
    else:
        _, policy_input_ref, policy_body = _read_input(store, policy_path, _POLICY_BYTES)
        policy = _json_value(policy_body)
    validated = deduplication.validate_policy(policy)
    if isinstance(validated, dict):
        policy = validated
    descriptors = []
    wrapped = []
    selected = []
    seen_paths = set()
    total_input_bytes = 0
    for input_number, value in enumerate(paths, 1):
        path, source_ref, body = _read_input(store, value, MAX_INPUT_BYTES)
        total_input_bytes += len(body)
        if total_input_bytes > MAX_TOTAL_INPUT_BYTES:
            raise ValidationError("Delivery input collection exceeds the size limit.")
        if path in seen_paths:
            raise ValidationError("A delivery input file may be selected only once.")
        seen_paths.add(path)
        rows, source_format = _parse_rows(path, body)
        source_sha = _sha(body)
        descriptors.append({"input_number": input_number, "input_ref": source_ref,
                            "input_sha256": source_sha, "source_format": source_format,
                            "occurrences": len(rows)})
        if len(selected) + len(rows) > MAX_OCCURRENCES:
            raise ValidationError("Delivery occurrence count exceeds the size limit.")
        for row_number, row in enumerate(rows, 1):
            provenance = {"input_number": input_number, "input_ref": source_ref,
                          "input_sha256": source_sha, "row_number": row_number,
                          "source_format": source_format,
                          "source_record_sha256": _source_record_sha(row)}
            wrapped.append({"record": row, "delivery_provenance": provenance})
            candidate = copy.deepcopy(row)
            candidate["_delivery"] = copy.deepcopy(provenance)
            selected.append(candidate)
    result = deduplication.select_occurrences(selected, policy=policy)
    implementations = {
        "delivery": _sha(_read_external(Path(__file__).resolve(), MAX_INPUT_BYTES)),
        "deduplication": _sha(_read_external(Path(deduplication.__file__).resolve(), MAX_INPUT_BYTES)),
    }
    generation_material = {"export_version": VERSION, "selection_version": deduplication.VERSION,
                           "cli_version": __version__,
                           "inputs": descriptors, "policy_input_sha256": _sha(policy_body),
                           "policy_input_ref": policy_input_ref,
                           "policy_sha256": _sha(_encoded(policy)),
                           "implementation_sha256": implementations}
    generation = _sha(_encoded(generation_material))
    root = Path("deliveries") / generation
    artifacts = {
        "raw_occurrences.jsonl": _json_lines(wrapped),
        "publications.jsonl": _json_lines(result["publications"]),
        "publications.csv": _csv_bytes(result["publications"]),
        "record_to_publication.jsonl": _json_lines(result["mapping"]),
        "doi_decisions.jsonl": _json_lines(result["decisions"]),
        "policy.json": _encoded(policy),
        "policy_input.json": policy_body,
    }
    manifest = {"schema_version": "1.0", **generation_material, "generation": generation,
                "policy_version": policy["version"], "scope": "explicit_saved_input_snapshot",
                "summary": result["summary"], "network_calls": 0, "secret_reads": 0,
                "control_ledger_changed": False,
                "output_hashes": {name: _sha(body) for name, body in artifacts.items()}}
    manifest_body = _encoded(manifest)
    # Publish the manifest last: its existence is the complete-bundle marker.
    for name, body in artifacts.items():
        store._atomic_write(root / name, body, immutable=True)
    store._atomic_write(root / "deduplication.json", manifest_body, immutable=True)
    return _control_report(root, manifest_body, result["summary"], policy, generation_material)


def _control_report(root: Path, manifest_body: bytes, summary: Mapping[str, Any],
                    policy: Mapping[str, Any], material: Mapping[str, Any]) -> Dict[str, Any]:
    """Revalidate the fixed summary fields before any control-plane publication."""
    report = {"delivery_ref": (root / "deduplication.json").as_posix(),
              "delivery_sha256": _sha(manifest_body), "delivery_version": VERSION,
              "delivery_selection_version": material["selection_version"],
              "delivery_policy_version": policy["version"],
              "delivery_policy_sha256": material["policy_sha256"],
              "publications_ref": (root / "publications.jsonl").as_posix(),
              "publications_csv_ref": (root / "publications.csv").as_posix(),
              "raw_occurrences_ref": (root / "raw_occurrences.jsonl").as_posix(),
              "record_to_publication_ref": (root / "record_to_publication.jsonl").as_posix(),
              "doi_decisions_ref": (root / "doi_decisions.jsonl").as_posix(),
              "control_ledger_changed": False}
    # Summary is fixed by the selector, never a source-row or user-policy blob.
    count_fields = {"raw_occurrences_count", "unique_eid_count", "representatives_count",
                    "secondary_records_count", "duplicate_doi_groups_count",
                    "records_in_duplicate_groups_count", "missing_doi_count",
                    "invalid_doi_count", "missing_eid_occurrences_count",
                    "duplicate_eid_occurrences_count"}
    for name, value in summary.items():
        if name not in count_fields | {"selection_reasons"}:
            continue
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_OCCURRENCES:
            report[name] = value
        elif name == "selection_reasons" and isinstance(value, dict):
            allowed = {"document_type_priority", "metadata_completeness", "stable_EID_tie_break", "singleton"}
            if set(value) <= allowed and all(type(count) is int and 0 <= count <= MAX_OCCURRENCES for count in value.values()):
                report[name] = dict(value)
    return report


def export_run_delivery(store: Any, run_id: str, api_name: str) -> Dict[str, Any]:
    """Rebuild original occurrence records, then deliver this explicit run offline."""
    records = store.export_records(run_id, api_name)
    return export_delivery(store, [store.root / records.ref])
