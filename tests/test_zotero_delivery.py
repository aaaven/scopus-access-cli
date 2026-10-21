"""Synthetic compatibility checks for existing delivery and enrichment exports."""
import json
import tempfile
import unittest
from pathlib import Path

from scopus_access import project, zotero_local as local
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.delivery import export_delivery
from scopus_access.secrets import SecretValue


class Writer:
    def contains_api_key(self, alias):
        return True

    def add_api_key(self, alias, label, secret):
        assert secret.reveal() == "SYNTHETIC_UNUSED_CREDENTIAL"


class ZoteroDeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        project.initialize_project(self.root, writer=Writer(),
                                   prompt=lambda: SecretValue(b'SYNTHETIC_UNUSED_CREDENTIAL'))
        self.ctx = local.Context.from_project(self.root)
        self.store = RestrictedArtifactStore(self.root / 'restricted_metadata/scopus',
                                            allowed_roots=[self.root / 'restricted_metadata'])

    def test_delivery_jsonl_and_csv_preserve_representative_and_all_eids(self):
        original = {'eid': 'synthetic-a', 'doi': '10.1234/synthetic',
                    'subtype_description': 'Article', 'title': 'SYNTHETIC TITLE',
                    'publication_name': 'SYNTHETIC JOURNAL', 'cover_date': '2026'}
        source = self.store.root / 'synthetic.jsonl'
        source.write_text('\n'.join(json.dumps(row) for row in (
            dict(original, eid='synthetic-b', subtype_description='Conference Paper'), original)) + '\n')
        delivered = export_delivery(self.store, [source])
        for field in ('publications_ref', 'publications_csv_ref'):
            with self.subTest(format=field):
                path = self.store.root / delivered[field]
                before = path.read_bytes()
                dataset = local.create_dataset(self.ctx, path)
                prepared = local.prepare(self.ctx, dataset['path'])
                _, rows = self.ctx.read_bundle(prepared['path'], 'prepared')
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['all_eids'], ['synthetic-a', 'synthetic-b'])
                self.assertEqual(rows[0]['eid'], 'synthetic-a')
                self.assertIsNone(rows[0]['hold_reason'])
                self.assertEqual(rows[0]['item']['title'], original['title'])
                self.assertEqual(rows[0]['item']['publicationTitle'], original['publication_name'])
                self.assertEqual(path.read_bytes(), before)

    def test_delivery_of_enriched_records_retains_author_provenance(self):
        record = {'source_format': 'scopus_plus_doi_enrichment',
                  'merged': {'eid': 'synthetic-a', 'doi': '10.1234/synthetic',
                             'title': 'SYNTHETIC TITLE', 'subtype': 'ar',
                             'authors': [{'family': 'SYNTHETIC', 'given': 'AUTHOR'}]},
                  'field_provenance': {'authors': {'provider': 'crossref', 'action': 'filled_missing'}}}
        source = self.store.root / 'synthetic-enriched.jsonl'
        source.write_text(json.dumps(record) + '\n')
        delivered = export_delivery(self.store, [source])
        for field in ('publications_ref', 'publications_csv_ref'):
            with self.subTest(format=field):
                dataset = local.create_dataset(self.ctx, self.store.root / delivered[field])
                prepared = local.prepare(self.ctx, dataset['path'])
                _, rows = self.ctx.read_bundle(prepared['path'], 'prepared')
                self.assertEqual(rows[0]['item']['creators'], [
                    {'creatorType': 'author', 'lastName': 'SYNTHETIC', 'firstName': 'AUTHOR'}])
                self.assertEqual(rows[0]['sidecar']['record']['field_provenance']['authors'],
                                 record['field_provenance']['authors'])

    def test_saved_publisher_wrapper_maps_fields_and_retains_original(self):
        record = {'api_baseline': {'sample_id': 'synthetic'},
                  'merged': {'source_format': 'scopus_api_plus_publisher_html', 'eid': 'synthetic-a',
                             'subtype': 'ar', 'title': 'SYNTHETIC TITLE',
                             'abstract': 'SYNTHETIC ABSTRACT'},
                  'field_provenance': {'abstract': {'provider': 'publisher_html', 'action': 'filled_missing'}}}
        source = self.store.root / 'synthetic-publisher.jsonl'
        source.write_text(json.dumps(record) + '\n')
        dataset = local.create_dataset(self.ctx, source)
        prepared = local.prepare(self.ctx, dataset['path'])
        _, rows = self.ctx.read_bundle(prepared['path'], 'prepared')
        self.assertIsNone(rows[0]['hold_reason'])
        self.assertEqual(rows[0]['item']['abstractNote'], record['merged']['abstract'])
        self.assertEqual(rows[0]['sidecar']['record']['source_record'], record)
