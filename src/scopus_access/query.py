"""Versioned, lossless Search text validation inside the restricted data plane."""

import hashlib

from .errors import QueryValidationError


TRANSFORMATION = "identity-utf8-v1"


def _location(text, index):
    line, column, offset = 1, 1, 0
    while offset < index:
        character = text[offset]
        if character == "\r":
            line, column = line + 1, 1
            if offset + 1 < index and text[offset + 1] == "\n":
                offset += 1
        elif character == "\n":
            line, column = line + 1, 1
        else:
            column += 1
        offset += 1
    return {"position": index + 1, "line": line, "column": column}


def validate_query(text):
    if not isinstance(text, str) or not text.strip():
        raise QueryValidationError("Query must contain non-whitespace UTF-8 text.", code="QUERY_EMPTY")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        raise QueryValidationError("Query must contain valid UTF-8 text.", code="QUERY_INVALID_UTF8") from None
    if size > 32768:
        raise QueryValidationError("Query exceeds the 32768-byte limit.", code="QUERY_TOO_LARGE")
    for index, character in enumerate(text):
        value = ord(character)
        if (value < 32 and character not in "\n\r\t") or value == 127:
            location = _location(text, index)
            point = "U+%04X" % value
            raise QueryValidationError(
                "Illegal query control character %s at character %d (line %d, column %d)." %
                (point, location["position"], location["line"], location["column"]),
                code="QUERY_INVALID_CONTROL", codepoint=point, **location,
            )
    # No whitespace rewriting, inside OR outside quoted/exact phrases. URL
    # encoding handles layout characters without changing the query text.
    return text


def search_operation(source_text):
    transport = validate_query(source_text)
    digest = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    return {"query": transport, "provenance": {
        "schema_version": "1.0", "source_text": source_text,
        "source_sha256": digest, "transport_sha256": digest,
        "transformation": TRANSFORMATION,
    }}


def validate_search_operation(operation):
    """Accept legacy query-only packages and verify every new provenance field."""
    if not isinstance(operation, dict) or set(operation) not in ({"query"}, {"query", "provenance"}):
        raise QueryValidationError("Frozen Search operation is invalid.", code="QUERY_PROVENANCE_INVALID")
    validate_query(operation.get("query"))
    if "provenance" not in operation:
        return
    metadata = operation["provenance"]
    if not isinstance(metadata, dict) or not isinstance(metadata.get("source_text"), str):
        raise QueryValidationError("Frozen query provenance is invalid.", code="QUERY_PROVENANCE_INVALID")
    expected = search_operation(metadata["source_text"])
    if operation != expected:
        raise QueryValidationError("Frozen query provenance or hash does not match.", code="QUERY_PROVENANCE_INVALID")
