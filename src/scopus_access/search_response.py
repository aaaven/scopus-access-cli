"""Interpret Search entry envelopes without treating status markers as papers."""

from typing import Any, List, Mapping


def search_entries(search: Mapping[str, Any]) -> List[Any]:
    entries = search.get("entry", [])
    if not isinstance(entries, list):
        raise ValueError("SEARCH_ENTRIES_INVALID")
    errors = [entry for entry in entries if isinstance(entry, dict) and "error" in entry]
    if not errors:
        return entries
    # Elsevier can return HTTP 200 with a single empty-result marker. Match
    # the entire known shape; never silently discard unknown application errors
    # or entries that also carry bibliographic fields.
    if (
        len(entries) == 1
        and str(search.get("opensearch:totalResults")) == "0"
        and set(errors[0]) <= {"error", "@_fa"}
        and errors[0]["error"] == "Result set was empty"
    ):
        return []
    raise ValueError("SEARCH_APPLICATION_ERROR")
