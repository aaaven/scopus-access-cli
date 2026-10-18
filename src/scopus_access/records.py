"""Fixed, loss-aware mappings used only inside the restricted data plane.

No filtering, scientific deduplication, inferred abstracts, or network access.
The original response remains authoritative for fields not mapped here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping

from .artifacts import ArtifactError, ArtifactRecord
from .search_response import search_entries


def _at(value: Any, *path: str) -> Any:
    for name in path:
        if not isinstance(value, dict) or name not in value:
            return None
        value = value[name]
    return value


def normalize_page(body: bytes, artifact: ArtifactRecord, api_name: str) -> List[Dict[str, Any]]:
    """Keep source records, including missing fields, but exclude status markers."""

    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ArtifactError("record response is not valid JSON") from None
    if api_name == "scopus_search":
        container = _at(payload, "search-results")
        if not isinstance(container, dict):
            raise ArtifactError("search record envelope is invalid")
        try:
            entries = search_entries(container)
        except ValueError:
            raise ArtifactError("search record entries are invalid") from None
    elif api_name == "abstract_retrieval":
        container = _at(payload, "abstracts-retrieval-response")
        if not isinstance(container, dict):
            raise ArtifactError("abstract record envelope is invalid")
        entries = [container]
    else:
        raise ArtifactError("record API is invalid")

    result = []
    for position, entry in enumerate(entries):
        # An empty/non-object entry is still an occurrence, not an exclusion.
        core = entry if api_name == "scopus_search" else _at(entry, "coredata")
        fields = {
            "eid": _at(core, "eid"),
            "identifier": _at(core, "dc:identifier"),
            "doi": _at(core, "prism:doi"),
            "title": _at(core, "dc:title"),
            "abstract": _at(core, "dc:description"),
            "creator": _at(core, "dc:creator"),
            "authors": _at(entry, "author") if api_name == "scopus_search" else _at(entry, "authors", "author"),
            "publication_name": _at(core, "prism:publicationName"),
            "cover_date": _at(core, "prism:coverDate"),
            "aggregation_type": _at(core, "prism:aggregationType"),
            "subtype": _at(core, "subtype"),
            "subtype_description": _at(core, "subtypeDescription"),
        }
        abstract_source = None
        if fields["abstract"] is not None:
            abstract_source = "dc:description" if api_name == "scopus_search" else "coredata.dc:description"
        elif api_name == "abstract_retrieval":
            # Preserve structured abstracts verbatim as JSON; never synthesize text.
            fields["abstract"] = _at(entry, "item", "bibrecord", "head", "abstracts")
            if fields["abstract"] is not None:
                abstract_source = "item.bibrecord.head.abstracts"
        occurrence = hashlib.sha256(
            ("%s\n%s\n%d\n%d" % (
                artifact.run_id, artifact.sha256, artifact.page_number, position
            )).encode("utf-8")
        ).hexdigest()
        stable_id = "occurrence:" + occurrence
        id_source = "occurrence"
        for name in ("eid", "identifier", "doi"):
            candidate = fields[name]
            if isinstance(candidate, str) and candidate:
                stable_id = "scopus:%s:%s" % (name, candidate)
                id_source = name
                break
        result.append({
            "schema_version": "1.0",
            "source": "Elsevier/Scopus",
            "api_name": api_name,
            "run_id": artifact.run_id,
            "stable_id": stable_id,
            "stable_id_source": id_source,
            "occurrence_id": occurrence,
            "raw_page_ref": artifact.artifact_ref,
            "raw_page_sha256": artifact.sha256,
            "page_number": artifact.page_number,
            "page_position": position,
            "abstract_source_path": abstract_source,
            "missing_fields": [name for name, value in fields.items() if value is None],
            "source_entry_type": "object" if isinstance(entry, dict) else "non_object",
            **fields,
        })
    return result
