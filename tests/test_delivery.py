"""Synthetic, offline delivery bundles; no project state or credentials."""

import copy
import csv
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scopus_access.artifacts import ArtifactError, RestrictedArtifactStore
from scopus_access.delivery import export_delivery, export_run_delivery
from scopus_access.errors import ValidationError


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "project" / "restricted_metadata"
        self.root.mkdir(parents=True)
        self.store = RestrictedArtifactStore(self.root, allowed_roots=[self.root])

    def write_rows(self, name, rows, *, external=False):
        path = (self.base if external else self.root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows))
        return path

    def read_rows(self, ref):
        return [json.loads(line) for line in (self.root / ref).read_bytes().splitlines()]

    def read_manifest(self, result):
        return json.loads((self.root / result["delivery_ref"]).read_bytes())

    def test_collection_uses_all_batches_and_retains_original_objects(self):
        first = {"eid": "2-s2.0-2", "doi": "https://doi.org/10.1234/synthetic",
                 "subtype_description": "Conference Paper", "title": "SYNTHETIC-ONE",
                 "raw_page_sha256": "a" * 64, "run_id": "first-batch"}
        second = {"eid": "2-s2.0-1", "doi": "10.1234/SYNTHETIC",
                  "subtype_description": "Article", "title": "SYNTHETIC-TWO",
                  "raw_page_sha256": "b" * 64, "run_id": "second-batch"}
        paths = [self.write_rows("first.jsonl", [first]), self.write_rows("second.jsonl", [second])]
        before = [path.read_bytes() for path in paths]
        result = export_delivery(self.store, paths)
        self.assertEqual(result["raw_occurrences_count"], 2)
        self.assertEqual(result["unique_eid_count"], 2)
        self.assertEqual(result["representatives_count"], 1)
        self.assertEqual(result["secondary_records_count"], 1)
        self.assertEqual(export_delivery(self.store, list(reversed(paths))), result)
        raw = self.read_rows(result["raw_occurrences_ref"])
        self.assertEqual([item["record"] for item in raw], [first, second])
        for index, item in enumerate(raw):
            source = item["delivery_provenance"]
            self.assertEqual(source["input_sha256"], hashlib.sha256(before[index]).hexdigest())
            self.assertEqual(source["row_number"], 1)
        mapping = self.read_rows(result["record_to_publication_ref"])
        self.assertEqual(len(mapping), 2)
        for item in mapping:
            canonical = json.dumps(item["record"], sort_keys=True, ensure_ascii=False,
                                   allow_nan=False, separators=(",", ":")).encode("utf-8")
            expected = hashlib.sha256(canonical).hexdigest()
            self.assertEqual(item["provenance"]["source_record_sha256"], expected)
            self.assertEqual(item["deduplication"]["source_record_sha256"], expected)
        for item in raw:
            canonical = json.dumps(item["record"], sort_keys=True, ensure_ascii=False,
                                   allow_nan=False, separators=(",", ":")).encode("utf-8")
            self.assertEqual(item["delivery_provenance"]["source_record_sha256"],
                             hashlib.sha256(canonical).hexdigest())
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertFalse(result["control_ledger_changed"])
        self.assertNotIn("SYNTHETIC", json.dumps(result))
        manifest = self.read_manifest(result)
        self.assertEqual((manifest["network_calls"], manifest["secret_reads"]), (0, 0))
        for name, expected in manifest["output_hashes"].items():
            output = (self.root / result["delivery_ref"]).parent / name
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), expected)

    def test_identical_rebuild_is_immutable_and_input_or_policy_change_versions_output(self):
        from scopus_access.deduplication import DEFAULT_POLICY
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1", "doi": "10.1234/synthetic"}])
        policy = self.base / "policy.json"
        policy.write_text(json.dumps(DEFAULT_POLICY))
        result = export_delivery(self.store, [source], policy_path=policy)
        manifest = self.root / result["delivery_ref"]
        previous_bytes = manifest.read_bytes()
        previous_inode = manifest.stat().st_ino
        self.assertEqual(export_delivery(self.store, [source], policy_path=policy), result)
        self.assertEqual(manifest.stat().st_ino, previous_inode)
        changed_policy = copy.deepcopy(DEFAULT_POLICY)
        changed_policy["version"] = "doi-priority-v1.1"
        policy.write_text(json.dumps(changed_policy))
        revised = export_delivery(self.store, [source], policy_path=policy)
        self.assertNotEqual(result["delivery_ref"], revised["delivery_ref"])
        source.write_text(json.dumps({"eid": "2-s2.0-1", "doi": "10.1234/synthetic", "title": "SYNTHETIC-ADDED"}) + "\n")
        changed = export_delivery(self.store, [source], policy_path=policy)
        self.assertNotEqual(changed["delivery_ref"], revised["delivery_ref"])
        self.assertEqual(manifest.read_bytes(), previous_bytes)

    def test_policy_source_provenance_is_bound_to_immutable_generation(self):
        from scopus_access.deduplication import DEFAULT_POLICY
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1"}])
        body = (json.dumps(DEFAULT_POLICY, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":")) + "\n").encode()
        first_policy = self.base / "first-policy.json"
        second_policy = self.base / "second-policy.json"
        first_policy.write_bytes(body)
        second_policy.write_bytes(body)
        default = export_delivery(self.store, [source])
        first = export_delivery(self.store, [source], policy_path=first_policy)
        second = export_delivery(self.store, [source], policy_path=second_policy)
        self.assertEqual(len({item["delivery_ref"] for item in (default, first, second)}), 3)
        self.assertEqual(export_delivery(self.store, [source], policy_path=second_policy), second)
        self.assertEqual(self.read_manifest(default)["scope"], "explicit_saved_input_snapshot")

    def test_explicit_external_csv_import_and_safe_control_metadata(self):
        source = self.base / "external.csv"
        source.write_text('EID,DOI,Document Type,Title,Source Raw SHA256\n'
                          '2-s2.0-1,10.1234/synthetic,Article,SYNTHETIC-RESTRICTED,' + 'c' * 64 + '\n')
        result = export_delivery(self.store, [source])
        self.assertEqual(result["raw_occurrences_count"], 1)
        self.assertEqual(result["representatives_count"], 1)
        self.assertNotIn(str(source), json.dumps(result))
        self.assertIn(str(source), json.dumps(self.read_manifest(result)))
        self.assertTrue((self.root / result["publications_csv_ref"]).is_file())
        with (self.root / result["publications_csv_ref"]).open(newline="") as handle:
            exported = list(csv.DictReader(handle))
        self.assertEqual(exported[0]["Title"], "SYNTHETIC-RESTRICTED")
        self.assertEqual(exported[0]["EID"], "2-s2.0-1")

    def test_empty_jsonl_run_produces_zero_count_bundle(self):
        result = export_run_delivery(self.store, "empty-run", "scopus_search")
        for name in ("raw_occurrences_count", "unique_eid_count", "representatives_count", "secondary_records_count"):
            self.assertEqual(result[name], 0)
        self.assertEqual(self.read_rows(result["raw_occurrences_ref"]), [])

    def test_enrichment_wrapper_retains_source_and_csv_uses_chosen_merged_fields(self):
        merged = {"eid": "2-s2.0-1", "doi": "10.1234/synthetic", "title": "SYNTHETIC-ENRICHED",
                  "subtype_description": "Article", "_deduplication": "SYNTHETIC-SOURCE-COLUMN"}
        original = {"sample_id": "D0001", "merged": merged,
                    "field_provenance": {"title": {"provider": "scopus", "action": "retained"}},
                    "scopus_original": {"eid": "2-s2.0-1", "title": "SYNTHETIC-ORIGINAL"}}
        source = self.base / "enriched.json"
        source.write_text(json.dumps([original]))
        result = export_delivery(self.store, [source])
        self.assertEqual(self.read_rows(result["raw_occurrences_ref"])[0]["record"], original)
        self.assertEqual(self.read_rows(result["publications_ref"])[0]["record"], original)
        with (self.root / result["publications_csv_ref"]).open(newline="") as handle:
            exported = list(csv.DictReader(handle))[0]
        self.assertEqual(exported["title"], "SYNTHETIC-ENRICHED")
        self.assertEqual(exported["_deduplication"], "SYNTHETIC-SOURCE-COLUMN")
        self.assertIn("__deduplication", exported)
        self.assertEqual(json.loads(exported["_source_record"]), original)

    def test_large_csv_fields_use_a_bounded_limit_and_restore_parser_setting(self):
        source = self.base / "large.csv"
        source.write_text("EID,DOI,Document Type,Abstract\n2-s2.0-1,10.1234/synthetic,Article," + "X" * 150000 + "\n")
        previous = csv.field_size_limit()
        result = export_delivery(self.store, [source])
        self.assertEqual(result["representatives_count"], 1)
        self.assertEqual(csv.field_size_limit(), previous)

    def test_symlink_inputs_parents_outputs_and_traversal_are_rejected(self):
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1"}])
        alias = self.base / "alias.jsonl"
        alias.symlink_to(source)
        parent = self.base / "alias-dir"
        parent.symlink_to(self.root, target_is_directory=True)
        for path in (alias, parent / source.name, self.root / ".." / "restricted_metadata" / source.name):
            with self.subTest(path=str(path)):
                with self.assertRaises(ValidationError):
                    export_delivery(self.store, [path])
        outside = self.base / "outside"
        outside.mkdir()
        (self.root / "deliveries").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValidationError, ArtifactError)):
            export_delivery(self.store, [source])
        self.assertEqual(list(outside.iterdir()), [])

    def test_source_parse_errors_never_include_source_content(self):
        for name, body in (("broken.jsonl", b'{"title":"SYNTHETIC-SENSITIVE"'),
                           ("broken.csv", b'EID,EID\nSYNTHETIC-SENSITIVE,x\n'),
                           ("broken.json", b'{"records":["SYNTHETIC-SENSITIVE"]}'),
                           ("broken-json.jsonl", b'{"eid":"first","eid":"SYNTHETIC-SENSITIVE"}\n')):
            path = self.base / name
            path.write_bytes(body)
            with self.subTest(name=name):
                with self.assertRaises(ValidationError) as captured:
                    export_delivery(self.store, [path])
                self.assertNotIn("SYNTHETIC-SENSITIVE", str(captured.exception))

    def test_reserved_metadata_duplicate_input_and_unsupported_file_are_rejected(self):
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1"}])
        with self.assertRaises(ValidationError):
            export_delivery(self.store, [source, source])
        reserved = self.write_rows("reserved.jsonl", [{"eid": "2-s2.0-1", "_delivery": {}}])
        with self.assertRaises(ValidationError):
            export_delivery(self.store, [reserved])
        unsupported = self.base / "input.txt"
        unsupported.write_text("SYNTHETIC-SENSITIVE")
        with self.assertRaises(ValidationError):
            export_delivery(self.store, [unsupported])
        for directory in (self.base, self.root):
            pipe = directory / "pipe.jsonl"
            os.mkfifo(str(pipe))
            with self.assertRaises(ValidationError):
                export_delivery(self.store, [pipe])

    def test_rebuild_does_not_replace_a_tampered_immutable_result(self):
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1"}])
        result = export_delivery(self.store, [source])
        target = self.root / result["publications_ref"]
        target.write_bytes(b"SYNTHETIC-TAMPER")
        with self.assertRaises(ArtifactError):
            export_delivery(self.store, [source])
        self.assertEqual(target.read_bytes(), b"SYNTHETIC-TAMPER")

    def test_no_secret_ledger_or_transport_is_constructed(self):
        source = self.write_rows("input.jsonl", [{"eid": "2-s2.0-1"}])
        with mock.patch("scopus_access.ledger.Ledger", side_effect=AssertionError("ledger access")), \
                mock.patch("scopus_access.secrets.MacOSKeychainSecretProvider", side_effect=AssertionError("credential access")), \
                mock.patch("scopus_access.client.UrllibTransport", side_effect=AssertionError("transport access")):
            result = export_delivery(self.store, [source])
        self.assertEqual(self.read_manifest(result)["network_calls"], 0)
        self.assertFalse(any(path.suffix in {".sqlite", ".db"} for path in self.root.rglob("*")))


if __name__ == "__main__":
    unittest.main()
