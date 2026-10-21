"""Project-bound, offline literature snapshots and optional Zotero configuration.

Bibliographic content lives exclusively in the restricted data plane. Bundle
manifests contain hashes, fixed implementation identifiers and counts only.
"""

from __future__ import annotations

import csv
import fcntl
import getpass
import io
import json
import os
import re
import sys
import uuid
import warnings
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .artifacts import RestrictedArtifactStore
from .errors import SecretProviderError, ValidationError
from .policy import load_policy
from .project import discover_project_policy, _atomic_write
from .records import nonempty
from .secrets import MacOSKeychainWriter, SecretValue
from .security import (canonical_json_bytes, parse_json_object, read_file_no_follow,
                       reject_symlink_components, resolve_restricted_output_dir,
                       safe_identifier, sha256_bytes, SENSITIVE_NAME_RE)


SCHEMA = "zotero-local-1"
CONVERSION = "zotero-field-mapping-1"
CREDENTIAL_SERVICE = "Scopus Access Tool / Zotero"
MARKER = "Scopus Access Record: "
DOI_POLICY = {
    "version": "doi-priority-v1.0",
    "priority": ["article", "bookchapter", "conferencepaper", "preprint"],
    "aliases": {"ar": "article", "journalarticle": "article", "ch": "bookchapter", "chapter": "bookchapter",
                "cp": "conferencepaper", "proceedingspaper": "conferencepaper", "proceedingpaper": "conferencepaper",
                "postedcontent": "preprint", "submittedversion": "preprint"},
    "completeness_fields": ["Title", "Authors", "Creator (may be first author)", "Source title", "Year",
                            "Abstract", "Author Keywords", "Index Keywords", "References", "Cover Date"],
    "tie_break": ["nonempty_bibliographic_fields_descending", "EID_ascending", "content_hash_ascending"],
    "field_merge": "retain_representative_fields_without_cross_record_filling",
    "scope": "representative_selection_within_DOI_only",
}
MAX_DATA_BYTES = 256 * 1024 * 1024


def _fail(message="Local Zotero input or state is invalid."):
    raise ValidationError(message, code="ZOTERO_LOCAL_INVALID")


def encode(value):
    return canonical_json_bytes(value) + b"\n"


def strict_loads(data):
    """Reject ambiguous/nonfinite JSON without echoing parser excerpts."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("Zotero JSON contains a duplicate object key.")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda value: _fail("Zotero JSON contains a nonfinite number."))
    except (ValueError, UnicodeError):
        _fail("Zotero JSON could not be parsed.")


def normalize_doi(value):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if value.lower().startswith(("https://", "http://")):
        url = urlsplit(value)
        if (url.hostname or "").lower() not in {"doi.org", "dx.doi.org"}:
            return ""
        value = unquote(url.path.lstrip("/"))
    elif value.lower().startswith("doi:"):
        value = value[4:].strip()
    return value.casefold() if re.fullmatch(r"10\.\d{4,9}/[^\s]+", value) else ""


def _kind(value):
    value = re.sub(r"[^a-z0-9]", "", str(value or "").casefold())
    return DOI_POLICY["aliases"].get(value, value)


def _field(row, *names):
    return next((row[name] for name in names if name in row and nonempty(row[name])), None)


def _text(row, *names):
    value = _field(row, *names)
    return value.strip() if isinstance(value, str) else ""


class Context:
    """One actual consuming project; never consult user-wide or chat state."""

    def __init__(self, policy_path):
        self.policy_path = Path(policy_path)
        self.policy = load_policy(str(policy_path))
        self._policy_sha256 = sha256_bytes(read_file_no_follow(self.policy_path, max_bytes=65536))
        binding = self.policy.project_binding
        if binding is None:
            _fail("Zotero requires an initialized, folder-bound project.")
        self.root, self.project_id = binding.root, binding.project_id
        self.control = self.root / ".scopus-access" / "zotero"
        self.storage = self.root / "restricted_metadata" / "zotero"
        allowed = self.policy.project_output_roots[self.project_id]
        resolve_restricted_output_dir(str(self.storage), allowed)
        for directory in (self.control, self.storage):
            reject_symlink_components(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.store = RestrictedArtifactStore(self.storage, allowed_roots=allowed)

    def revalidate(self, expected_target=None):
        """Fail closed if the bound folder, policy or selected target changed."""
        reject_symlink_components(self.policy_path)
        current = load_policy(str(self.policy_path))
        if (current.project_binding != self.policy.project_binding
                or sha256_bytes(read_file_no_follow(self.policy_path, max_bytes=65536)) != self._policy_sha256):
            _fail("Project binding or policy changed during the Zotero operation.")
        reject_symlink_components(self.control)
        reject_symlink_components(self.storage)
        if expected_target is not None and self.target != expected_target:
            _fail("Selected Zotero target changed during the operation.")

    @classmethod
    def from_project(cls, start=None):
        path = discover_project_policy(start)
        if path is None:
            _fail("Run scopus-access init in this consuming project first.")
        return cls(path)

    @property
    def target(self):
        path = self.control / "target.json"
        reject_symlink_components(path)
        value = parse_json_object(read_file_no_follow(path, max_bytes=65536))
        _validate_target(value, self.project_id)
        return value

    def relative(self, path):
        raw = Path(path)
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        if ".." in raw.parts:
            _fail("Parent traversal is not allowed for Zotero data.")
        reject_symlink_components(raw)
        try:
            return raw.relative_to(self.storage)
        except ValueError:
            _fail("Zotero content must remain in this project's restricted directory.")

    def restricted_file(self, path):
        raw = Path(path)
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        if ".." in raw.parts:
            _fail("Parent traversal is not allowed for dataset input.")
        reject_symlink_components(raw)
        resolve_restricted_output_dir(str(raw.parent), self.policy.project_output_roots[self.project_id])
        return raw

    def read_json(self, path):
        relative = self.relative(path)
        data = self.store._read_relative(relative, max_bytes=MAX_DATA_BYTES)
        try:
            return strict_loads(data)
        except (ValueError, UnicodeError):
            _fail()

    def write_json(self, relative, value, immutable=True):
        relative = Path(relative)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            _fail("Zotero output path must be relative without traversal.")
        return self.store._atomic_write(relative, encode(value), immutable=immutable)

    def bundle(self, kind, content, metadata=None):
        safe_identifier(kind, field="bundle_kind")
        identifier = uuid.uuid4().hex
        folder = Path(kind) / identifier
        content_bytes = encode(content)
        self.store._atomic_write(folder / "content.json", content_bytes, immutable=True)
        info = dict(metadata or {})
        info.update(schema_version=SCHEMA, kind=kind, bundle_id=identifier,
                    project_id=self.project_id, content_sha256=sha256_bytes(content_bytes))
        path = self.write_json(folder / "bundle.json", info)
        count = len(content.get("records", [])) if isinstance(content, dict) else len(content)
        return {"status": "prepared", "path": str(path), "sha256": sha256_bytes(encode(info)),
                "records": count, "network_calls": 0}

    def read_bundle(self, path, kind):
        raw = Path(path)
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        if raw.is_dir():
            raw = raw / "bundle.json"
        info = self.read_json(raw)
        if (not isinstance(info, dict) or info.get("kind") != kind or info.get("schema_version") != SCHEMA
                or info.get("project_id") != self.project_id
                or not re.fullmatch(r"[0-9a-f]{32}", str(info.get("bundle_id", "")))):
            _fail("Bundle belongs to another project or implementation.")
        expected = self.storage / kind / info["bundle_id"] / "bundle.json"
        if raw != expected:
            _fail("Bundle path does not match its frozen identity.")
        content_path = raw.parent / "content.json"
        data = self.store._read_relative(self.relative(content_path), max_bytes=MAX_DATA_BYTES)
        if sha256_bytes(data) != info.get("content_sha256"):
            _fail("Frozen Zotero input has changed; prepare a new version.")
        try:
            return info, strict_loads(data)
        except (ValueError, UnicodeError):
            _fail()


def _validate_target(value, project_id):
    expected = {"library_type", "library_id", "credential_alias", "credential_service", "project_id"}
    if not isinstance(value, dict) or set(value) != expected or value["project_id"] != project_id:
        _fail("Zotero target is not bound to this project.")
    if value["library_type"] not in {"group", "user"}:
        _fail()
    identifier = value["library_id"]
    if not isinstance(identifier, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", identifier):
        _fail("Zotero target ID must be a positive numeric identifier.")
    safe_identifier(value["credential_alias"], field="credential_alias")
    if value["credential_service"] != CREDENTIAL_SERVICE:
        _fail("Zotero credential service is invalid.")


def prompt_zotero_key():
    if not sys.stdin.isatty():
        raise SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input")
    value = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Zotero API key (hidden): ", stream=sys.stderr)
        return SecretValue(value.encode("utf-8"))
    except (EOFError, KeyboardInterrupt, OSError, ValueError, getpass.GetPassWarning):
        raise SecretProviderError(reason="credential_input_invalid", stage="credential_prompt", backend="terminal_input") from None
    finally:
        value = None


@contextmanager
def operation_lock(ctx):
    """Share the same lock as sync operations, including target selection."""
    reject_symlink_components(ctx.control)
    path = ctx.control / "sync.lock"
    reject_symlink_components(path)
    descriptor = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("Another Zotero operation is active for this project.")
        yield
    finally:
        os.close(descriptor)


def configure(ctx, library_type, library_id, *, writer=None, prompt=None):
    """Create/select a separate target credential reference; no network/readback."""
    library_id = str(library_id)
    value = {"library_type": library_type, "library_id": library_id,
             "credential_alias": "zotero_" + sha256_bytes((ctx.project_id + library_type + library_id).encode())[:32],
             "credential_service": CREDENTIAL_SERVICE, "project_id": ctx.project_id}
    _validate_target(value, ctx.project_id)
    writer = writer if writer is not None else MacOSKeychainWriter(CREDENTIAL_SERVICE)
    target_path = ctx.control / (library_type + "-" + library_id + ".json")
    with operation_lock(ctx):
        ctx.revalidate()
        reject_symlink_components(target_path)
        existing = target_path.exists()
        if existing:
            stored = parse_json_object(read_file_no_follow(target_path, max_bytes=65536))
            if stored != value:
                _fail("Existing target configuration differs; no credential was changed.")
        else:
            _atomic_write(target_path, encode(value))
        written = False
        if not writer.contains_api_key(value["credential_alias"]):
            with (prompt or prompt_zotero_key)() as secret:
                try:
                    writer.add_api_key(value["credential_alias"], "Scopus Access Tool / Zotero / " + ctx.project_id, secret)
                except SecretProviderError:
                    raise
                except Exception:
                    raise SecretProviderError(stage="credential_write", backend="macos_security_framework") from None
            written = True
        _atomic_write(ctx.control / "target.json", encode(value))
    return {"status": "configured", "library_type": library_type, "library_id": library_id,
            "credential_written": written, "network_calls": 0, "secret_reads": 0}


def _reject_credential_fields(value):
    if isinstance(value, dict):
        if any(SENSITIVE_NAME_RE.search(str(key)) for key in value):
            _fail("Dataset input contains a credential-like field.")
        for child in value.values():
            _reject_credential_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_credential_fields(child)


def _load_rows(data, suffix):
    try:
        text = data.decode("utf-8-sig")
        if suffix.casefold() == ".csv":
            rows = list(csv.DictReader(io.StringIO(text)))
        elif suffix.casefold() == ".jsonl":
            rows = [strict_loads(line) for line in text.splitlines() if line.strip()]
        else:
            rows = strict_loads(text)
            if isinstance(rows, dict):
                rows = rows.get("records")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            _fail("Dataset requires a local record array, JSONL, or CSV export.")
        _reject_credential_fields(rows)
        return rows
    except (ValueError, UnicodeError, csv.Error):
        _fail("Dataset input could not be parsed.")


def _canonical_record(row):
    original = row
    # 0.7 delivery JSONL wraps the selected source record; its CSV flattens
    # fields and retains structured delivery metadata as JSON columns.
    delivery = row.get("deduplication", row.get("_deduplication", {}))
    if isinstance(delivery, str):
        delivery = strict_loads(delivery)
    if not isinstance(delivery, dict):
        delivery = {}
    if isinstance(row.get("record"), dict) and "deduplication" in row:
        row = row["record"]
    provenance_record = row
    if isinstance(row.get("_source_record"), str):
        saved = strict_loads(row["_source_record"])
        if isinstance(saved, dict):
            provenance_record = saved
    if isinstance(row.get("merged"), dict):
        row = row["merged"]
    eid = _text(row, "eid", "EID")
    eids = _field(row, "all_eids", "All_EIDs") or delivery.get("all_eids", [])
    if isinstance(eids, str):
        eids = [item.strip() for item in eids.split(";") if item.strip()]
    if not isinstance(eids, list) or any(not isinstance(item, str) for item in eids):
        eids = []
    eids = sorted(set(eids + ([eid] if eid else [])))
    doi = normalize_doi(_text(row, "doi", "DOI_Normalized", "DOI"))
    kind = _kind(_field(row, "document_type", "Document Type", "subtype_description", "subtype", "aggregation_type"))
    fields = {
        "title": _text(row, "title", "Title"), "abstract": _field(row, "abstract", "Abstract"),
        "authors": _field(row, "full_authors", "Authors", "authors"),
        "creator": _field(row, "creator", "Creator (may be first author)"),
        "publication_name": _text(row, "publication_name", "Source title"),
        "cover_date": _text(row, "cover_date", "Cover Date", "Year", "year"),
        "author_keywords": _field(row, "author_keywords", "Author Keywords"),
        "index_keywords": _field(row, "index_keywords", "Index Keywords"),
        "references": _field(row, "references", "References"),
        "affiliations": _field(row, "affiliations", "Affiliations"),
    }
    paths = {"title": ("title", "Title"), "abstract": ("abstract", "Abstract"),
             "authors": ("full_authors", "Authors", "authors"),
             "creator": ("creator", "Creator (may be first author)"),
             "publication_name": ("publication_name", "Source title"),
             "cover_date": ("cover_date", "Cover Date", "Year", "year"),
             "author_keywords": ("author_keywords", "Author Keywords"),
             "index_keywords": ("index_keywords", "Index Keywords"),
             "references": ("references", "References"), "affiliations": ("affiliations", "Affiliations")}
    original_provenance = provenance_record.get("field_provenance", {})
    field_provenance = {}
    for name, aliases in paths.items():
        source_path = next((key for key in aliases if key in row and nonempty(row[key])), None)
        recorded = original_provenance.get(name) if isinstance(original_provenance, dict) else None
        field_provenance[name] = recorded if isinstance(recorded, dict) else {
            "provider": row.get("source", "caller_local_export"), "field_path": source_path,
            "run_id": row.get("run_id"), "raw_page_ref": row.get("raw_page_ref"),
            "raw_page_sha256": row.get("raw_page_sha256"), "source_row_sha256": sha256_bytes(encode(original))}
    completeness = sum(nonempty(value) for value in (
        fields["title"], fields["authors"], fields["creator"], fields["publication_name"],
        _field(row, "Year", "year"), fields["abstract"], fields["author_keywords"], fields["index_keywords"],
        fields["references"], _field(row, "cover_date", "Cover Date")))
    # Search STANDARD's creator and partial author arrays are never labelled a
    # complete author list. A caller must explicitly attest completeness.
    provenance = original_provenance.get("authors", {}) if isinstance(original_provenance, dict) else {}
    attested = row.get("authors_complete") is True
    eligible = (attested or bool(_field(row, "full_authors", "Authors"))
                or (provenance.get("action") == "filled_missing" and provenance.get("provider") in {"crossref", "openalex"}))
    return {"eid": eid, "original_eids": eids, "doi": doi, "document_type": kind, "fields": fields,
            "field_provenance": field_provenance, "policy_completeness": completeness,
            "author_mapping_eligible": eligible,
            "authors_completeness": "caller_attested" if attested else "not_independently_verified" if eligible else "partial_or_unknown",
            "source_record": original,
            "source_sha256": sha256_bytes(encode(original))}


def create_dataset(ctx, source, selection=None):
    """Freeze local candidates and a versioned, deterministic DOI representative policy."""
    if selection is not None:
        _fail("Choose a subset during Zotero prepare, after dataset IDs are fixed.")
    path = ctx.restricted_file(source)
    before = read_file_no_follow(path, max_bytes=MAX_DATA_BYTES)
    rows = [_canonical_record(row) for row in _load_rows(before, path.suffix)]
    input_sha256 = sha256_bytes(before)
    grouped = defaultdict(list)
    for position, row in enumerate(rows):
        row["source_occurrence_id"] = sha256_bytes((input_sha256 + ":" + str(position)).encode())
        source_row = row["source_record"]
        identity = "doi:" + row["doi"] if row["doi"] else (
            "eid:" + row["eid"] if row["eid"] else
            "source:" + _text(source_row, "stable_id", "record_id", "Publication_ID")
            if _text(source_row, "stable_id", "record_id", "Publication_ID") else "occurrence:" + row["source_occurrence_id"])
        grouped[identity].append(row)
    records, secondaries = [], []
    for identity, group in sorted(grouped.items()):
        def order(row):
            kind = row["document_type"]
            rank = DOI_POLICY["priority"].index(kind) if kind in DOI_POLICY["priority"] else len(DOI_POLICY["priority"])
            return rank, -row["policy_completeness"], row["eid"], row["source_sha256"]
        chosen = sorted(group, key=order)[0]
        record_id = "record_" + sha256_bytes((ctx.project_id + "\n" + identity).encode())[:32]
        all_eids = sorted({eid for row in group for eid in row["original_eids"]})
        records.append(dict(chosen, record_id=record_id, all_eids=all_eids,
                            occurrence_count=len(group), policy_version=DOI_POLICY["version"]))
        for row in sorted(group, key=lambda value: value["source_sha256"]):
            secondaries.append({"record_id": record_id, "eid": row["eid"],
                                "representative": row is chosen, "record": row})
    if read_file_no_follow(path, max_bytes=MAX_DATA_BYTES) != before:
        _fail("Dataset source changed while it was being frozen.")
    eid_records = defaultdict(set)
    for row in records:
        for eid in row["all_eids"]:
            eid_records[eid].add(row["record_id"])
    for row in records:
        row["identity_issues"] = ["eid_multiple_doi_groups"] if any(len(eid_records[eid]) > 1 for eid in row["all_eids"]) else []
    result = ctx.bundle("dataset", {"records": records, "secondary_records": secondaries}, {
        "source_sha256": sha256_bytes(before), "source_path": str(path), "policy": DOI_POLICY,
        "policy_sha256": sha256_bytes(encode(DOI_POLICY)), "input_records": len(rows),
        "conversion_version": CONVERSION, "conversion_sha256": sha256_bytes(Path(__file__).read_bytes())})
    result.update(input_records=len(rows), secondary_records=len(rows) - len(records))
    return result


def _creators(row):
    if not row["author_mapping_eligible"]:
        return [], None
    value = row["fields"]["authors"]
    if isinstance(value, str):
        try:
            value = strict_loads(value)
        except (ValueError, ValidationError):
            return [], "unstructured_full_authors"
    if not isinstance(value, list):
        return [], "unstructured_full_authors"
    result = []
    for author in value:
        if not isinstance(author, dict):
            return [], "unstructured_full_authors"
        family = _text(author, "family", "lastName", "surname")
        if family:
            result.append({"creatorType": "author", "lastName": family,
                           "firstName": _text(author, "given", "firstName", "given-name")})
        elif _text(author, "name", "indexed-name"):
            result.append({"creatorType": "author", "name": _text(author, "name", "indexed-name")})
        else:
            return [], "unstructured_full_authors"
    return result, None


def prepare(ctx, dataset, selection=None):
    """Freeze a full candidate set or an explicitly selected subset, without I/O to Zotero."""
    info, content = ctx.read_bundle(dataset, "dataset")
    dataset_path = ctx.storage / "dataset" / info["bundle_id"] / "bundle.json"
    records = content.get("records") if isinstance(content, dict) else None
    if not isinstance(records, list):
        _fail()
    chosen_ids = None
    if selection is not None:
        if isinstance(selection, (str, Path)):
            selection_path = ctx.restricted_file(selection)
            try:
                selection = strict_loads(read_file_no_follow(selection_path, max_bytes=MAX_DATA_BYTES))
            except (ValueError, UnicodeError):
                _fail("Subset must be a JSON array of stable record IDs.")
        if (not isinstance(selection, (list, tuple)) or any(not isinstance(item, str) for item in selection)
                or len(selection) != len(set(selection))):
            _fail("Subset must contain unique stable record IDs.")
        chosen_ids = set(selection)
        if not chosen_ids.issubset({row["record_id"] for row in records}):
            _fail("Subset references an unknown record ID.")
    rows = []
    types = {"article": "journalArticle", "bookchapter": "bookSection",
             "conferencepaper": "conferencePaper", "preprint": "preprint", "book": "book"}
    for row in records:
        if chosen_ids is not None and row["record_id"] not in chosen_ids:
            continue
        fields = row["fields"]
        kind = types.get(row["document_type"])
        creators, author_reason = _creators(row)
        item = {"itemType": kind or "document", "title": fields["title"],
                "creators": creators, "tags": [{"tag": "workflow:retrieved"}],
                "extra": MARKER + ctx.project_id + ":" + row["record_id"]}
        values = {"DOI": row["doi"], "date": fields["cover_date"],
                  "abstractNote": fields["abstract"]}
        container = {"bookSection": "bookTitle", "conferencePaper": "proceedingsTitle",
                     "journalArticle": "publicationTitle", "preprint": "repository"}.get(kind)
        if container:
            values[container] = fields["publication_name"]
        item.update({key: value for key, value in values.items() if isinstance(value, str) and value.strip()})
        reason = ("missing_title" if not fields["title"] else "local_identity_conflict" if row.get("identity_issues")
                  else "unsupported_document_type" if kind is None else None)
        rows.append({"record_id": row["record_id"], "eid": row["eid"], "all_eids": row["all_eids"],
                     "doi": row["doi"], "item": item, "hold_reason": reason,
                     "sidecar": {"record": row, "author_mapping_note": author_reason,
                                 "keywords_semantics": "author_index_model_human_workflow_distinct",
                                 "affiliations_semantics": "no_author_affiliation_link_inferred"}})
    result = ctx.bundle("prepared", rows, {"dataset_sha256": sha256_bytes(encode(info)),
                        "dataset_content_sha256": info["content_sha256"],
                        "dataset_path": str(dataset_path), "mapping_version": CONVERSION,
                        "conversion_sha256": sha256_bytes(Path(__file__).read_bytes()),
                        "selection_sha256": sha256_bytes(encode(sorted(chosen_ids))) if chosen_ids is not None else None,
                        "records": len(rows), "held_records": sum(bool(row["hold_reason"]) for row in rows)})
    result.update(held_records=sum(bool(row["hold_reason"]) for row in rows),
                  with_author_list=sum(bool(row["item"]["creators"]) for row in rows),
                  with_abstract=sum(bool(row["item"].get("abstractNote")) for row in rows))
    return result


def verify_prepared(ctx, path):
    """Recheck all nested frozen local sources before a remote operation."""
    info, rows = ctx.read_bundle(path, "prepared")
    code_hash = sha256_bytes(Path(__file__).read_bytes())
    if info.get("mapping_version") != CONVERSION or info.get("conversion_sha256") != code_hash:
        _fail("Prepared mapping implementation changed; prepare a new version.")
    dataset, content = ctx.read_bundle(info.get("dataset_path", ""), "dataset")
    if (sha256_bytes(encode(dataset)) != info.get("dataset_sha256")
            or dataset.get("content_sha256") != info.get("dataset_content_sha256")
            or dataset.get("conversion_sha256") != code_hash
            or dataset.get("policy") != DOI_POLICY
            or dataset.get("policy_sha256") != sha256_bytes(encode(DOI_POLICY))):
        _fail("Prepared dataset linkage changed; prepare a new version.")
    source = ctx.restricted_file(dataset.get("source_path", ""))
    if sha256_bytes(read_file_no_follow(source, max_bytes=MAX_DATA_BYTES)) != dataset.get("source_sha256"):
        _fail("Dataset source changed; create a new version before synchronizing.")
    if not isinstance(rows, list) or not isinstance(content, dict):
        _fail()
    return info, rows
