"""Synthetic restricted-record export regressions; no credentials or transport."""

import hashlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from scopus_access.artifacts import ArtifactError, RestrictedArtifactStore
from scopus_access.records import normalize_page
from scopus_access.security import execution_run_id


NOW = "2030-01-01T00:00:00Z"
CONTENT = "SYNTHETIC-RESTRICTED-TITLE"


class RecordsArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "project" / "restricted_metadata"
        self.root.mkdir(parents=True)
        self.store = RestrictedArtifactStore(self.root, allowed_roots=[self.root])
        self.run_id = execution_run_id(
            "project", "task", "release", "parent", "scopus_search"
        )

    def write_page(self, page, entries, *, run_id=None, body=None):
        run_id = run_id or self.run_id
        if body is None:
            body = json.dumps(
                {"search-results": {"entry": entries}},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        return self.store.write_response(
            run_id=run_id,
            attempt_id="%s.p%d.a1" % (run_id, page),
            page_number=page,
            body=body,
            timestamp=NOW,
        )

    def export(self):
        return self.store.export_records(self.run_id, "scopus_search")

    def read_rows(self, exported):
        return [
            json.loads(line)
            for line in (self.root / exported.ref).read_bytes().splitlines()
        ]

    def test_raw_replay_keeps_original_bytes_identity_and_single_manifest_entry(self):
        original = self.write_page(1, [{"dc:title": CONTENT}])
        raw = self.root / original.artifact_ref
        raw_before = raw.read_bytes()
        inode_before = raw.stat().st_ino
        manifest = self.root / self.store.manifest_ref(self.run_id)
        manifest_before = manifest.read_bytes()
        replay = self.store.write_response(
            run_id=self.run_id,
            attempt_id=original.attempt_id,
            page_number=1,
            body=raw_before,
            timestamp="2030-01-02T00:00:00Z",
        )
        self.assertEqual(original, replay)
        self.assertEqual(raw.read_bytes(), raw_before)
        self.assertEqual(raw.stat().st_ino, inode_before)
        self.assertEqual(manifest.read_bytes(), manifest_before)
        self.assertEqual(len(self.store.load_response_records(self.run_id)), 1)

    def test_raw_conflicting_page_or_attempt_does_not_overwrite_history(self):
        original = self.write_page(1, [{"dc:title": CONTENT}])
        raw = self.root / original.artifact_ref
        raw_before = raw.read_bytes()
        manifest = self.root / self.store.manifest_ref(self.run_id)
        manifest_before = manifest.read_bytes()
        for attempt_id, page, body in (
            (original.attempt_id, 1, b'{"changed":true}'),
            (self.run_id + ".p1.a2", 1, raw_before),
            (original.attempt_id, 2, raw_before),
        ):
            with self.subTest(attempt_id=attempt_id, page=page):
                with self.assertRaises(ArtifactError):
                    self.store.write_response(
                        run_id=self.run_id,
                        attempt_id=attempt_id,
                        page_number=page,
                        body=body,
                        timestamp=NOW,
                    )
                self.assertEqual(raw.read_bytes(), raw_before)
                self.assertEqual(manifest.read_bytes(), manifest_before)

    def test_raw_publish_before_manifest_failure_can_be_replayed_without_replacement(self):
        entries = [{"dc:title": CONTENT}]
        with mock.patch.object(self.store, "_append_jsonl", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.write_page(1, entries)
        raw = next((self.root / "raw").rglob("*.json"))
        before = raw.read_bytes()
        inode = raw.stat().st_ino
        with self.assertRaises(ArtifactError):
            self.write_page(1, [{"dc:title": "SYNTHETIC-CHANGED"}])
        self.assertEqual(raw.read_bytes(), before)
        self.write_page(1, entries)
        self.assertEqual(raw.stat().st_ino, inode)
        self.assertEqual(len(self.store.load_response_records(self.run_id)), 1)

    def test_rebuild_recovers_partial_export_and_preserves_repeated_source_occurrences(self):
        entry = {"eid": "SYNTHETIC-SAME-ID", "dc:title": CONTENT}
        first_page = self.write_page(1, [entry, entry])
        first_export = self.export()
        first_rows = self.read_rows(first_export)
        second_page = self.write_page(2, [entry])
        complete = self.export()
        expected = (self.root / complete.ref).read_bytes()
        rows = self.read_rows(complete)
        self.assertEqual(rows[:2], first_rows)
        self.assertEqual((complete.record_count, complete.page_count), (3, 2))
        self.assertEqual(len({row["stable_id"] for row in rows}), 1)
        self.assertEqual(len({row["occurrence_id"] for row in rows}), 3)
        self.assertEqual([row["page_position"] for row in rows], [0, 1, 0])
        self.assertEqual(
            [row["raw_page_sha256"] for row in rows],
            [first_page.sha256, first_page.sha256, second_page.sha256],
        )
        path = self.root / complete.ref
        path.write_bytes(expected[:len(expected) // 2])
        for _ in range(2):
            rebuilt = self.export()
            self.assertEqual(rebuilt, complete)
            self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(complete.sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_page_gap_preserves_prior_export_until_all_pages_are_available(self):
        self.write_page(1, [{"dc:identifier": "SYNTHETIC-1"}])
        initial = self.export()
        before = (self.root / initial.ref).read_bytes()
        self.write_page(3, [{"dc:identifier": "SYNTHETIC-3"}])
        with self.assertRaisesRegex(ArtifactError, "gap"):
            self.export()
        self.assertEqual((self.root / initial.ref).read_bytes(), before)
        self.write_page(2, [{"dc:identifier": "SYNTHETIC-2"}])
        self.assertEqual([row["page_number"] for row in self.read_rows(self.export())], [1, 2, 3])

    def test_duplicate_manifest_evidence_is_idempotent_but_conflict_preserves_export(self):
        record = self.write_page(1, [{"dc:title": CONTENT}])
        initial = self.export()
        before = (self.root / initial.ref).read_bytes()
        manifest = self.root / self.store.manifest_ref(self.run_id)
        original = manifest.read_bytes()
        manifest.write_bytes(original + original)
        self.assertEqual(self.export(), initial)
        conflict = asdict(record)
        conflict["recorded_at_utc"] = "2030-01-02T00:00:00Z"
        manifest.write_bytes(original + json.dumps(conflict).encode("utf-8") + b"\n")
        with self.assertRaisesRegex(ArtifactError, "conflicting"):
            self.export()
        self.assertEqual((self.root / initial.ref).read_bytes(), before)

    def test_missing_referenced_raw_page_fails_and_preserves_prior_export(self):
        self.write_page(1, [{"dc:identifier": "SYNTHETIC-1"}])
        missing = self.write_page(2, [{"dc:identifier": "SYNTHETIC-2"}])
        initial = self.export()
        before = (self.root / initial.ref).read_bytes()
        (self.root / missing.artifact_ref).unlink()
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertEqual((self.root / initial.ref).read_bytes(), before)

    def test_changed_raw_page_fails_and_preserves_prior_export(self):
        record = self.write_page(1, [{"dc:title": CONTENT}])
        initial = self.export()
        before = (self.root / initial.ref).read_bytes()
        (self.root / record.artifact_ref).write_bytes(b"SYNTHETIC-TAMPER")
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertEqual((self.root / initial.ref).read_bytes(), before)

    def test_empty_pages_count_even_when_the_jsonl_is_empty(self):
        absent = self.export()
        self.assertEqual((absent.record_count, absent.page_count), (0, 0))
        self.write_page(1, [])
        self.write_page(2, [])
        empty = self.export()
        self.assertEqual((empty.record_count, empty.page_count), (0, 2))
        self.assertEqual((self.root / empty.ref).read_bytes(), b"")
        self.assertEqual(empty.sha256, hashlib.sha256(b"").hexdigest())

    def test_empty_result_marker_is_not_a_bibliographic_record(self):
        body = json.dumps({"search-results": {
            "opensearch:totalResults": "0", "opensearch:startIndex": "0",
            "entry": [{"@_fa": "true", "error": "Result set was empty"}],
        }}).encode()
        self.write_page(1, None, body=body)
        exported = self.export()
        self.assertEqual((exported.record_count, exported.page_count), (0, 1))
        self.assertEqual(self.read_rows(exported), [])

    def test_unknown_or_conflicting_error_markers_are_not_silently_dropped(self):
        for total, entries in (
            ("0", [{"error": CONTENT}]),
            ("1", [{"error": "Result set was empty"}]),
            ("0", [{"error": "Result set was empty", "dc:title": CONTENT}]),
            ("0", [{"error": "Result set was empty"}, {}]),
        ):
            body = json.dumps({"search-results": {
                "opensearch:totalResults": total, "entry": entries,
            }}).encode()
            record = self.write_page(1, None, body=b'{}')
            with self.assertRaises(ArtifactError) as caught:
                normalize_page(body, record, "scopus_search")
            self.assertNotIn(CONTENT, str(caught.exception))

    def test_missing_fields_and_non_object_entries_remain_records_without_inference(self):
        record = self.write_page(1, [{}, None, {"dc:title": CONTENT}])
        rows = normalize_page(self.store.read_response_record(record), record, "scopus_search")
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["page_position"] for row in rows], [0, 1, 2])
        self.assertEqual(rows[1]["source_entry_type"], "non_object")
        self.assertEqual(rows[2]["title"], CONTENT)
        for row in rows:
            self.assertIsNone(row["abstract"])
            self.assertIn("abstract", row["missing_fields"])
            self.assertEqual(row["stable_id_source"], "occurrence")
        self.assertIn("title", rows[0]["missing_fields"])
        self.assertNotIn("title", rows[2]["missing_fields"])

    def test_abstract_fixed_mapping_preserves_structured_abstract_and_missing_coredata(self):
        run = execution_run_id("project", "task", "release", "parent", "abstract_retrieval")
        structured = {"abstract": {"ce:para": "SYNTHETIC-ABSTRACT"}}
        body = json.dumps({"abstracts-retrieval-response": {
            "authors": {"author": [{"@auid": "SYNTHETIC-AUTHOR"}]},
            "item": {"bibrecord": {"head": {"abstracts": structured}}},
        }}).encode("utf-8")
        self.write_page(1, None, run_id=run, body=body)
        exported = self.store.export_records(run, "abstract_retrieval")
        rows = self.read_rows(exported)
        self.assertEqual((exported.record_count, exported.page_count), (1, 1))
        self.assertEqual(rows[0]["abstract"], structured)
        self.assertEqual(rows[0]["abstract_source_path"], "item.bibrecord.head.abstracts")
        self.assertIsNone(rows[0]["title"])
        self.assertIn("title", rows[0]["missing_fields"])
        self.assertNotIn("abstract", rows[0]["missing_fields"])

    def test_records_directory_symlink_cannot_redirect_output(self):
        self.write_page(1, [{"dc:title": CONTENT}])
        outside = self.base / "outside"
        outside.mkdir()
        (self.root / "records").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertEqual(list(outside.iterdir()), [])

    def test_execution_directory_symlink_cannot_redirect_output(self):
        self.write_page(1, [{"dc:title": CONTENT}])
        outside = self.base / "outside"
        outside.mkdir()
        (self.root / "records").mkdir()
        (self.root / "records" / self.run_id).symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertEqual(list(outside.iterdir()), [])

    def test_records_file_symlink_or_directory_cannot_be_replaced(self):
        self.write_page(1, [{"dc:title": CONTENT}])
        target = self.root / self.store.records_ref(self.run_id)
        target.parent.mkdir(parents=True)
        outside = self.base / "outside.jsonl"
        outside.write_bytes(b"SYNTHETIC-UNRELATED")
        target.symlink_to(outside)
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertEqual(outside.read_bytes(), b"SYNTHETIC-UNRELATED")
        self.assertTrue(target.is_symlink())
        target.unlink()
        target.mkdir()
        with self.assertRaises(ArtifactError):
            self.export()
        self.assertTrue(target.is_dir())

    def test_invalid_run_or_api_cannot_cross_execution_namespace(self):
        self.write_page(1, [{"dc:title": CONTENT}])
        for run_id, api in (
            ("../escape", "scopus_search"),
            ("/absolute", "scopus_search"),
            (self.run_id, "abstract_retrieval"),
            (self.run_id, "unsupported_api"),
        ):
            with self.subTest(run_id=run_id, api=api):
                with self.assertRaises(ArtifactError):
                    self.store.export_records(run_id, api)
        self.assertFalse((self.root / "records").exists())


if __name__ == "__main__":
    unittest.main()
