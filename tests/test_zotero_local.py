"""Synthetic, offline checks for immutable datasets and optional configuration."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scopus_access.errors import ValidationError, ScopusAccessError
from scopus_access.project import initialize_project
from scopus_access.secrets import SecretValue
from scopus_access import zotero_local as z


SECRET = b"SYNTHETIC_ZOTERO_TEST_CREDENTIAL"


class Writer:
    def __init__(self):
        self.aliases = set()
        self.handles = []

    def contains_api_key(self, alias):
        return alias in self.aliases

    def add_api_key(self, alias, label, secret):
        assert secret.reveal() == SECRET.decode()
        assert alias not in self.aliases
        self.aliases.add(alias)
        self.handles.append(secret)


def source(eid="synthetic-a", doi="10.1234/synthetic", title="SYNTHETIC TITLE", kind="Article", **fields):
    return dict(eid=eid, doi=doi, title=title, subtype_description=kind,
                run_id="synthetic_run", raw_page_ref="raw/synthetic.json",
                raw_page_sha256="a" * 64, creator="SYNTHETIC FIRST CREATOR", **fields)


class ZoteroLocalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "project"
        self.root.mkdir()
        self.writer = Writer()
        initialize_project(self.root, writer=self.writer, prompt=lambda: SecretValue(SECRET))
        self.ctx = z.Context.from_project(self.root)

    def dataset(self, rows):
        path = self.root / "restricted_metadata" / "synthetic.jsonl"
        path.write_bytes(b"".join(z.encode(row) for row in rows))
        before = path.read_bytes()
        result = z.create_dataset(self.ctx, path)
        self.assertEqual(path.read_bytes(), before)
        return result

    def test_configure_uses_separate_keychain_without_network_or_plaintext(self):
        prompt = mock.Mock(side_effect=lambda: SecretValue(SECRET))
        with mock.patch("http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")):
            first = z.configure(self.ctx, "group", "123", writer=self.writer, prompt=prompt)
            again = z.configure(self.ctx, "group", "123", writer=self.writer, prompt=prompt)
        self.assertTrue(first["credential_written"])
        self.assertFalse(again["credential_written"])
        self.assertEqual(prompt.call_count, 1)
        self.assertEqual(first["secret_reads"], 0)
        self.assertEqual(self.ctx.target["credential_service"], z.CREDENTIAL_SERVICE)
        self.assertTrue(all(secret._closed for secret in self.writer.handles))
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET, path.read_bytes())

    def test_targets_and_projects_isolate_credential_references(self):
        z.configure(self.ctx, "group", "123", writer=self.writer, prompt=lambda: SecretValue(SECRET))
        first = self.ctx.target
        z.configure(self.ctx, "user", "123", writer=self.writer, prompt=lambda: SecretValue(SECRET))
        second = self.ctx.target
        self.assertNotEqual(first["credential_alias"], second["credential_alias"])
        for kind, identifier in [("other", "1"), ("group", "0"), ("group", "1/../2")]:
            with self.assertRaises(ValidationError):
                z.configure(self.ctx, kind, identifier, writer=self.writer)

    def test_discovery_from_descendant_and_nearest_incomplete_stops(self):
        child = self.root / "child"
        child.mkdir()
        self.assertEqual(z.Context.from_project(child).project_id, self.ctx.project_id)
        (child / ".scopus-access").mkdir()
        with self.assertRaises(ValidationError):
            z.Context.from_project(child)

    def test_doi_representative_keeps_secondary_provenance_and_stable_ids(self):
        rows = [source("b", kind="Conference Paper", abstract="SYNTHETIC ABSTRACT"),
                source("a", kind="Article"), source("c", doi="", title="SYNTHETIC NO DOI")]
        first = self.dataset(rows)
        info, content = self.ctx.read_bundle(first["path"], "dataset")
        chosen = next(row for row in content["records"] if row["doi"])
        self.assertEqual(chosen["eid"], "a")
        self.assertEqual(chosen["all_eids"], ["a", "b"])
        self.assertIsNone(chosen["fields"]["abstract"])
        self.assertEqual(len(content["secondary_records"]), 3)
        self.assertEqual(chosen["source_record"]["raw_page_ref"], "raw/synthetic.json")
        self.assertIn("conversion_sha256", info)
        second = self.dataset(list(reversed(rows)))
        _, reordered = self.ctx.read_bundle(second["path"], "dataset")
        self.assertEqual({row["record_id"] for row in content["records"]},
                         {row["record_id"] for row in reordered["records"]})
        self.assertNotEqual(first["path"], second["path"])
        manifest = Path(first["path"]).read_text()
        self.assertNotIn("SYNTHETIC TITLE", manifest)
        self.assertNotIn("SYNTHETIC ABSTRACT", manifest)

    def test_equal_type_prefers_completeness_then_fixed_eid(self):
        result = self.dataset([source("c"), source("b", abstract="SYNTHETIC ABSTRACT"),
                               source("a", abstract="SYNTHETIC ABSTRACT")])
        _, data = self.ctx.read_bundle(result["path"], "dataset")
        self.assertEqual(data["records"][0]["eid"], "a")

    def test_missing_identifiers_keep_distinct_source_occurrences(self):
        result = self.dataset([source(eid="", doi=""), source(eid="", doi="")])
        _, data = self.ctx.read_bundle(result["path"], "dataset")
        self.assertEqual(len(data["records"]), 2)
        self.assertNotEqual(data["records"][0]["record_id"], data["records"][1]["record_id"])

    def test_existing_all_eids_and_conflicting_eid_groups_are_retained_and_held(self):
        result = self.dataset([dict(source(), All_EIDs="synthetic-a;synthetic-secondary"),
                               source(doi="10.1234/other")])
        _, data = self.ctx.read_bundle(result["path"], "dataset")
        self.assertTrue(any("synthetic-secondary" in row["all_eids"] for row in data["records"]))
        prepared = z.prepare(self.ctx, result["path"])
        _, rows = self.ctx.read_bundle(prepared["path"], "prepared")
        self.assertTrue(all(row["hold_reason"] == "local_identity_conflict" for row in rows))

    def test_prepare_is_offline_and_keeps_missing_doi_and_title(self):
        result = self.dataset([source("a", doi="", title=""), source("b", doi="")])
        with mock.patch("http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")), \
                mock.patch.object(z, "MacOSKeychainWriter", side_effect=AssertionError("credentials forbidden")):
            prepared = z.prepare(self.ctx, result["path"])
        info, rows = self.ctx.read_bundle(prepared["path"], "prepared")
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(row["hold_reason"] == "missing_title" for row in rows), 1)
        self.assertEqual(prepared["network_calls"], 0)
        self.assertEqual(prepared["with_author_list"], 0)
        self.assertTrue(all(not row["item"]["creators"] for row in rows))
        self.assertTrue(all(row["item"]["extra"].startswith(z.MARKER + self.ctx.project_id) for row in rows))
        self.assertEqual(info["mapping_version"], z.CONVERSION)

    def test_prepare_subset_and_unknown_type_hold_without_scientific_filter(self):
        result = self.dataset([source("a"), source("b", doi="", kind="Unranked Synthetic Type")])
        _, data = self.ctx.read_bundle(result["path"], "dataset")
        prepared = z.prepare(self.ctx, result["path"])
        _, rows = self.ctx.read_bundle(prepared["path"], "prepared")
        self.assertEqual(len(rows), 2)
        held = next(row for row in rows if row["hold_reason"])
        self.assertEqual(held["hold_reason"], "unsupported_document_type")
        subset = z.prepare(self.ctx, result["path"], [held["record_id"]])
        self.assertEqual(subset["records"], 1)
        with self.assertRaises(ValidationError):
            z.prepare(self.ctx, result["path"], ["unknown_record"])

    def test_enriched_wrapper_preserves_field_sources_and_separates_keywords(self):
        row = {"source_format": "scopus_plus_doi_enrichment", "merged": source(
            authors=[{"family": "SYNTHETIC", "given": "AUTHOR"}], author_keywords=["SYNTHETIC AUTHOR KW"],
            index_keywords=["SYNTHETIC INDEX KW"], affiliations=["SYNTHETIC AFFILIATION"]),
               "field_provenance": {"authors": {"provider": "crossref", "action": "filled_missing"}},
               "external_semantics": {"openalex_model_keywords": ["SYNTHETIC MODEL KW"]}}
        result = self.dataset([row])
        prepared = z.prepare(self.ctx, result["path"])
        _, rows = self.ctx.read_bundle(prepared["path"], "prepared")
        item = rows[0]["item"]
        self.assertEqual(item["creators"][0]["lastName"], "SYNTHETIC")
        self.assertEqual(rows[0]["sidecar"]["record"]["authors_completeness"], "not_independently_verified")
        self.assertEqual(item["tags"], [{"tag": "workflow:retrieved"}])
        self.assertEqual(rows[0]["sidecar"]["record"]["source_record"]["external_semantics"], row["external_semantics"])
        self.assertNotIn("affiliations", item)

    def test_frozen_content_tamper_and_cross_project_bundle_rejected(self):
        result = self.dataset([source()])
        content_path = Path(result["path"]).parent / "content.json"
        content_path.write_text("{}")
        with self.assertRaises(ValidationError):
            z.prepare(self.ctx, result["path"])
        second = self.root.parent / "other"
        second.mkdir()
        initialize_project(second, writer=Writer(), prompt=lambda: SecretValue(SECRET))
        ctx = z.Context.from_project(second)
        with self.assertRaises(ValidationError):
            ctx.read_bundle(result["path"], "dataset")

    def test_paths_credentials_and_symlink_escape_rejected(self):
        outside = self.root.parent / "outside.json"
        outside.write_text("[]")
        with self.assertRaises(ValidationError):
            z.create_dataset(self.ctx, outside)
        link = self.root / "restricted_metadata" / "link.json"
        link.symlink_to(outside)
        with self.assertRaises(ValidationError):
            z.create_dataset(self.ctx, link)
        with self.assertRaises(ScopusAccessError):
            self.ctx.write_json(Path("..") / "escape.json", {})
        with self.assertRaises(ValidationError):
            self.dataset([dict(source(), api_key="SYNTHETIC_FORBIDDEN")])

    def test_verify_prepared_checks_original_source_and_manifest_linkage(self):
        dataset = self.dataset([source()])
        prepared = z.prepare(self.ctx, dataset["path"])
        info, rows = z.verify_prepared(self.ctx, prepared["path"])
        self.assertEqual(len(rows), 1)
        source_path = self.root / "restricted_metadata/synthetic.jsonl"
        original = source_path.read_bytes()
        source_path.write_bytes(original + b"\n")
        with self.assertRaises(ValidationError):
            z.verify_prepared(self.ctx, prepared["path"])
        source_path.write_bytes(original)
        manifest_path = Path(dataset["path"])
        manifest = json.loads(manifest_path.read_text())
        manifest["input_records"] += 1
        manifest_path.write_bytes(z.encode(manifest))
        with self.assertRaises(ValidationError):
            z.verify_prepared(self.ctx, prepared["path"])

    def test_revalidate_rejects_edited_policy_and_replaced_folder_binding(self):
        self.ctx.revalidate()
        path = self.root / ".scopus-access/policy.json"
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with self.assertRaises(ValidationError):
            self.ctx.revalidate()
        path.write_bytes(original)
        moved = self.root.with_name("original-project")
        self.root.rename(moved)
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        with self.assertRaises(ValidationError):
            self.ctx.revalidate()

    def test_configure_shares_sync_lock_and_never_prompts_while_busy(self):
        prompt = mock.Mock(side_effect=lambda: SecretValue(SECRET))
        with z.operation_lock(self.ctx):
            with self.assertRaises(ValidationError):
                z.configure(self.ctx, "group", "123", writer=self.writer, prompt=prompt)
        prompt.assert_not_called()
        self.assertFalse((self.ctx.control / "target.json").exists())

    def test_target_switch_while_credential_lookup_returns_stops_before_transport(self):
        from scopus_access import zotero
        z.configure(self.ctx, "group", "123", writer=self.writer, prompt=lambda: SecretValue(SECRET))
        target = zotero._target(self.ctx)
        journal = zotero._Journal(self.ctx, target)
        transport = mock.Mock()
        owner = self

        class SwitchingProvider:
            def get_api_key(self, alias):
                config = dict(owner.ctx.target, library_id="456")
                (owner.ctx.control / "target.json").write_bytes(z.encode(config))
                return SecretValue(SECRET)

        api = zotero._API(self.ctx, journal, secret_provider=SwitchingProvider(), transport=transport)
        with self.assertRaises(zotero.ZoteroError):
            api.request("GET", "/keys/current")
        transport.request.assert_not_called()
        self.assertEqual(api.calls, 0)

    def test_json_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        source_path = self.root / "restricted_metadata/synthetic-bad.json"
        for data in (b'[{"eid":"a","eid":"b"}]', b'[{"eid":"a","score":NaN}]'):
            source_path.write_bytes(data)
            with self.assertRaises(ValidationError):
                z.create_dataset(self.ctx, source_path)
        journal = self.ctx.write_json("synthetic-bad.json", {})
        journal.write_bytes(b'{"sequence":1,"sequence":2}')
        with self.assertRaises(ValidationError):
            self.ctx.read_json(journal)


if __name__ == "__main__":
    unittest.main()
