"""Pure offline, provenance-preserving selection under an explicit DOI policy."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from urllib.parse import unquote, urlsplit

from .errors import ValidationError

VERSION = "doi-priority-implementation-v1"
DEFAULT_POLICY = {
    "version": "doi-priority-v1.0", "adopted_date": "2026-10-20", "timezone": "Asia/Dubai",
    "basis": "User preference: Article > Book Chapter > Conference Paper > Preprint",
    "priority": ["article", "bookchapter", "conferencepaper", "preprint"],
    "aliases": {"ar": "article", "journalarticle": "article", "ch": "bookchapter", "chapter": "bookchapter", "cp": "conferencepaper", "proceedingspaper": "conferencepaper", "proceedingpaper": "conferencepaper", "postedcontent": "preprint", "submittedversion": "preprint"},
    "unranked_type": "after_ranked_types; singleton records retained",
    "tie_break": ["nonempty_bibliographic_fields_descending", "EID_ascending"],
    "completeness_fields": ["Title", "Authors", "Creator (may be first author)", "Source title", "Year", "Abstract", "Author Keywords", "Index Keywords", "References", "Cover Date"],
    "grouping": "valid_normalized_DOI; otherwise individual_EID",
    "field_merge": "retain_representative_fields_without_cross_record_filling",
    "identity_status": "policy_selected; not_publisher_verified",
    "eligibility": "unchanged; type priority applies only within the same DOI group",
}
_FIELDS = {"EID": ("EID", "eid"), "DOI": ("DOI", "doi"), "Title": ("Title", "title"), "Authors": ("Authors", "authors"), "Creator (may be first author)": ("Creator (may be first author)", "creator"), "Source title": ("Source title", "publication_name", "source_title"), "Year": ("Year", "year"), "Abstract": ("Abstract", "abstract"), "Author Keywords": ("Author Keywords", "author_keywords"), "Index Keywords": ("Index Keywords", "index_keywords"), "References": ("References", "references"), "Cover Date": ("Cover Date", "cover_date"), "Document Type": ("Document Type", "document_type", "subtype_description", "subtype")}
_CONFLICT_FIELDS = ("DOI", "Title", "Creator (may be first author)", "Source title", "Year", "Document Type", "Cover Date")


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValidationError("Delivery records must contain valid JSON values.") from None


def _hash(value):
    try:
        return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()
    except UnicodeError:
        raise ValidationError("Delivery records must contain valid JSON values.") from None


def _key(value):
    return "".join(c for c in str(value or "").casefold() if c.isalnum())


def validate_policy(policy):
    """Validate supported policy operations, retaining exact supplied metadata."""
    if not isinstance(policy, dict):
        raise ValidationError("Delivery policy must be a JSON object.")
    if set(policy) != set(DEFAULT_POLICY):
        raise ValidationError("Delivery policy has unsupported or missing fields.")
    if not isinstance(policy["version"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", policy["version"]):
        raise ValidationError("Delivery policy version is invalid.")
    priority = policy["priority"]
    aliases = policy["aliases"]
    fields = policy["completeness_fields"]
    if not isinstance(priority, list) or not priority or len(priority) > 64 or any(not isinstance(v, str) or not v or _key(v) != v for v in priority) or len(set(priority)) != len(priority):
        raise ValidationError("Delivery type priority is invalid.")
    if not isinstance(aliases, dict) or len(aliases) > 256 or any(not isinstance(k, str) or not k or _key(k) != k or not isinstance(v, str) or v not in priority for k, v in aliases.items()):
        raise ValidationError("Delivery type aliases are invalid.")
    if not isinstance(fields, list) or not fields or any(not isinstance(v, str) or v not in DEFAULT_POLICY["completeness_fields"] for v in fields) or len(fields) != len(set(fields)):
        raise ValidationError("Delivery completeness fields are invalid.")
    for name in ("unranked_type", "tie_break", "grouping", "field_merge", "identity_status", "eligibility"):
        if policy[name] != DEFAULT_POLICY[name]:
            raise ValidationError("Delivery policy requests unsupported selection operations.")
    if any(not isinstance(policy[name], str) or len(policy[name]) > 512 for name in ("adopted_date", "timezone", "basis")):
        raise ValidationError("Delivery policy metadata is invalid.")
    _json(policy)
    return copy.deepcopy(policy)


def normalize_doi(value):
    """Normalize only DOI literals and the two DOI resolver hostnames."""
    if not isinstance(value, str):
        return ""
    doi = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in doi):
        return ""
    try:
        if doi.casefold().startswith(("https://", "http://")):
            url = urlsplit(doi)
            if (url.hostname or "").casefold() not in {"doi.org", "dx.doi.org"}:
                return ""
            doi = unquote(url.path.lstrip("/"))
        elif doi.casefold().startswith("doi:"):
            doi = doi[4:].strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in doi):
            return ""
        return doi.casefold() if re.fullmatch(r"10\.\d{4,9}/[^\s]+", doi) else ""
    except (ValueError, UnicodeError):
        return ""


def _record(row):
    # The complete wrapper remains the source object; only its selected view is inspected.
    if isinstance(row.get("merged"), dict):
        return row["merged"]
    if isinstance(row.get("scopus_original"), dict):
        return row["scopus_original"]
    return row


def _field(row, name):
    value = _record(row)
    for key in _FIELDS[name]:
        if key in value and _nonempty(value[key]):
            return value[key]
    return ""


def _nonempty(value):
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(_nonempty(v) for v in value)
    if isinstance(value, dict):
        return any(_nonempty(v) for k, v in value.items() if not str(k).startswith("@"))
    return isinstance(value, (int, float, bool))


def _eid(row):
    value = _field(row, "EID")
    return value.strip() if isinstance(value, str) else ""


def _rank(row, policy):
    key = _key(_field(row, "Document Type"))
    key = policy["aliases"].get(key, key)
    return policy["priority"].index(key) if key in policy["priority"] else len(policy["priority"])


def _completeness(row, policy):
    return sum(_nonempty(_field(row, name)) for name in policy["completeness_fields"])


def _conflicts(rows):
    result = []
    for field in _CONFLICT_FIELDS:
        values = set()
        for row in rows:
            value = _field(row, field)
            if not _nonempty(value):
                continue
            if field == "DOI":
                value = normalize_doi(value) or str(value).strip().casefold()
            else:
                value = _key(value) if isinstance(value, str) else _json(value)
            values.add(value)
        if len(values) > 1:
            result.append(field)
    return result


def _memberships(rows):
    result = set()
    for row in rows:
        source = _record(row)
        for field in ("Pilot_Membership", "pilot_membership", "membership", "memberships", "run_id", "Source Run ID"):
            value = source.get(field)
            if isinstance(value, str):
                result.update(part.strip() for part in value.split(";") if part.strip())
            elif isinstance(value, list):
                result.update(str(part) for part in value if isinstance(part, (str, int)))
    return sorted(result)


def select_occurrences(rows, policy=None):
    """Return whole-source representatives and a mapping for every occurrence.

    Input ``_delivery`` descriptors are kept outside the source record. Every
    other field, including enrichment wrappers and raw provenance, is retained.
    This function does not touch files, credentials, ledgers or the network.
    """
    policy = validate_policy(DEFAULT_POLICY if policy is None else policy)
    if not isinstance(rows, (list, tuple)) or any(not isinstance(row, dict) for row in rows):
        raise ValidationError("Delivery requires record objects.")
    occurrences = []
    by_identity = defaultdict(list)
    missing_identities = Counter()
    for original in rows:
        source = copy.deepcopy(original)
        provenance = source.pop("_delivery", {})
        if not isinstance(provenance, dict):
            raise ValidationError("Delivery provenance must be a JSON object.")
        source_hash = _hash(source)
        eid = _eid(source)
        # Missing-EID rows always retain separate identities, even if byte-identical.
        if eid:
            identity = "eid:" + eid
        else:
            missing_hash = _hash({"record": source, "provenance": provenance})
            missing_identities[missing_hash] += 1
            identity = "occurrence:%s:%d" % (missing_hash, missing_identities[missing_hash])
        occurrence = {"record": source, "provenance": provenance, "source_hash": source_hash, "eid": eid, "identity": identity}
        occurrences.append(occurrence)
        by_identity[identity].append(occurrence)
    candidates = []
    for identity, items in sorted(by_identity.items()):
        chosen = min(items, key=lambda item: (_rank(item["record"], policy), -_completeness(item["record"], policy), item["source_hash"], _json(item["provenance"])))
        top = [item for item in items if _rank(item["record"], policy) == _rank(chosen["record"], policy)]
        same_score = [item for item in top if _completeness(item["record"], policy) == _completeness(chosen["record"], policy)]
        eid_reason = ("single_occurrence" if len(items) == 1 else
                      "document_type_priority" if len(top) == 1 else
                      "metadata_completeness" if len(same_score) == 1 else
                      "stable_source_hash_tie_break")
        doi = normalize_doi(_field(chosen["record"], "DOI"))
        candidates.append({
            "identity": identity, "chosen": chosen, "items": items, "doi": doi,
            "eid_selection_reason": eid_reason,
            "group": "doi:" + doi if doi and chosen["eid"] else identity,
        })
    groups = defaultdict(list)
    for candidate in candidates:
        groups[candidate["group"]].append(candidate)
    publications, mapping, decisions = [], [], []
    reasons = Counter()
    doi_group_count = duplicate_group_records = 0
    for group_key, group in sorted(groups.items()):
        ordered = sorted(group, key=lambda candidate: (_rank(candidate["chosen"]["record"], policy), -_completeness(candidate["chosen"]["record"], policy), candidate["chosen"]["eid"], candidate["chosen"]["source_hash"]))
        representative = ordered[0]["chosen"]
        top = [candidate for candidate in ordered if _rank(candidate["chosen"]["record"], policy) == _rank(representative["record"], policy)]
        equal_score = [candidate for candidate in top if _completeness(candidate["chosen"]["record"], policy) == _completeness(representative["record"], policy)]
        reason = "singleton" if len(group) == 1 else "document_type_priority" if len(top) == 1 else "metadata_completeness" if len(equal_score) == 1 else "stable_EID_tie_break"
        if len(group) > 1:
            reasons[reason] += 1
            doi_group_count += 1
            duplicate_group_records += len(group)
        all_items = sorted([item for candidate in group for item in candidate["items"]], key=lambda item: (item["eid"], item["source_hash"], _json(item["provenance"])))
        all_rows = [item["record"] for item in all_items]
        conflicts = _conflicts(all_rows)
        common = {
            "publication_id": group_key,
            "representative_eid": representative["eid"],
            "representative_source_record_sha256": representative["source_hash"],
            "group_record_count": len(group),
            "group_occurrences_count": len(all_items),
            "doi_normalized": ordered[0]["doi"],
            "policy_version": policy["version"],
            "implementation_version": VERSION,
            "selection_reason": reason,
            "metadata_conflict_fields": conflicts,
            "conflicts_nonblocking": True,
            "identity_status": "policy_selected_not_publisher_verified",
            "factual_identity_verification": "not_performed",
        }
        # Group-sized arrays occur once, in the publication row. Mapping and
        # decision rows link back through publication_id and retain their own
        # complete source record/provenance, so output grows linearly.
        publication_metadata = dict(
            copy.deepcopy(common),
            all_eids=sorted({item["eid"] for item in all_items if item["eid"]}),
            memberships=_memberships(all_rows),
            all_occurrence_sources=[dict(item["provenance"], source_record_sha256=item["source_hash"])
                                    for item in all_items],
        )
        publications.append({
            "record": copy.deepcopy(representative["record"]),
            "provenance": copy.deepcopy(representative["provenance"]),
            "deduplication": publication_metadata,
        })
        for candidate in sorted(group, key=lambda value: value["identity"]):
            same_eid_conflicts = _conflicts([item["record"] for item in candidate["items"]])
            for item in sorted(candidate["items"], key=lambda item: (item["source_hash"], _json(item["provenance"]))):
                metadata = dict(copy.deepcopy(common), eid=item["eid"], source_record_sha256=item["source_hash"], is_representative_eid=item["identity"] == ordered[0]["identity"], is_selected_occurrence=item is representative, eid_occurrences_count=len(candidate["items"]), same_eid_conflict_fields=same_eid_conflicts, eid_occurrence_selection_reason=candidate["eid_selection_reason"], type_priority=_rank(item["record"], policy), metadata_completeness=_completeness(item["record"], policy))
                mapping.append({"record": copy.deepcopy(item["record"]), "provenance": copy.deepcopy(item["provenance"]), "deduplication": metadata})
            if len(group) > 1 or len(candidate["items"]) > 1:
                chosen = candidate["chosen"]
                metadata = dict(copy.deepcopy(common), eid=chosen["eid"], source_record_sha256=chosen["source_hash"], is_representative_eid=candidate is ordered[0], decision_scope="doi_group" if len(group) > 1 else "eid_occurrence_consolidation", eid_occurrences_count=len(candidate["items"]), same_eid_conflict_fields=same_eid_conflicts, eid_occurrence_selection_reason=candidate["eid_selection_reason"], type_priority=_rank(chosen["record"], policy), metadata_completeness=_completeness(chosen["record"], policy))
                decisions.append({"record": copy.deepcopy(chosen["record"]), "provenance": copy.deepcopy(chosen["provenance"]), "deduplication": metadata})
    unique_eids = len({item["eid"] for item in occurrences if item["eid"]})
    missing_eid = sum(not item["eid"] for item in occurrences)
    summary = {
        "raw_occurrences_count": len(occurrences),
        "unique_eid_count": unique_eids,
        "representatives_count": len(publications),
        "secondary_records_count": len(candidates) - len(publications),
        "duplicate_eid_occurrences_count": len(occurrences) - unique_eids - missing_eid,
        "duplicate_doi_groups_count": doi_group_count,
        "records_in_duplicate_groups_count": duplicate_group_records,
        "missing_eid_occurrences_count": missing_eid,
        "missing_doi_count": sum(not _nonempty(_field(candidate["chosen"]["record"], "DOI"))
                                 for candidate in candidates),
        "invalid_doi_count": sum(_nonempty(_field(candidate["chosen"]["record"], "DOI"))
                                 and not candidate["doi"] for candidate in candidates),
        "selection_reasons": dict(sorted(reasons.items())),
    }
    return {"publications": publications, "mapping": mapping, "decisions": decisions, "summary": summary}
