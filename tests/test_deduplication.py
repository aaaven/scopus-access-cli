"""Synthetic checks of local selection; no credentials or network required."""
import copy
import json
import unittest
from unittest import mock

from scopus_access.deduplication import DEFAULT_POLICY, normalize_doi, select_occurrences, validate_policy
from scopus_access.errors import ValidationError


class DeduplicationTests(unittest.TestCase):
    def setUp(self):
        self.socket = mock.patch('socket.socket', side_effect=AssertionError('offline socket guard'))
        self.socket.start()
        self.addCleanup(self.socket.stop)

    def row(self, eid, doi='10.1234/synthetic', kind='Article', **extra):
        return dict({'EID': eid, 'DOI': doi, 'Document Type': kind}, **extra)

    def test_four_ranks_precede_completeness_without_stitching(self):
        rows = [self.row('z', kind='Article'), self.row('b', kind='Book Chapter', Title='SYNTHETIC', Abstract='SYNTHETIC'), self.row('c', kind='Conference Paper'), self.row('d', kind='Preprint')]
        before = copy.deepcopy(rows)
        result = select_occurrences(rows)
        chosen = result['publications'][0]
        self.assertEqual(chosen['record'], rows[0])
        self.assertEqual(chosen['deduplication']['selection_reason'], 'document_type_priority')
        self.assertEqual(chosen['deduplication']['all_eids'], ['b', 'c', 'd', 'z'])
        self.assertEqual(result['summary']['secondary_records_count'], 3)
        self.assertEqual(len(result['mapping']), 4)
        self.assertEqual(len(result['decisions']), 4)
        self.assertEqual(rows, before)
        for kind, other in [('Book Chapter', 'Conference Paper'), ('Conference Paper', 'Preprint'), ('Preprint', 'Unranked')]:
            result = select_occurrences([self.row('z', kind=kind), self.row('a', kind=other, Abstract='SYNTHETIC')])
            self.assertEqual(result['publications'][0]['record']['EID'], 'z')

    def test_complete_field_list_and_eid_stable_tie_break(self):
        fields = DEFAULT_POLICY['completeness_fields']
        for field in fields:
            rows = [self.row('z', **{field: 'SYNTHETIC'}), self.row('a')]
            selected = select_occurrences(rows)
            self.assertEqual(selected['publications'][0]['record']['EID'], 'z', field)
            self.assertEqual(selected['summary']['selection_reasons'], {'metadata_completeness': 1})
        rows = [self.row('b', Title='SYNTHETIC'), self.row('a', Title='SYNTHETIC'), self.row('c')]
        first = select_occurrences(rows)
        self.assertEqual(first, select_occurrences(list(reversed(rows))))
        self.assertEqual(first['publications'][0]['record']['EID'], 'a')
        self.assertEqual(first['summary']['selection_reasons'], {'stable_EID_tie_break': 1})

    def test_doi_normalization_and_invalid_hosts(self):
        for value in [' 10.1234/SYNTHETIC ', 'DOI: 10.1234/Synthetic', 'HTTPS://doi.org/10.1234/Synthetic', 'http://dx.doi.org/10.1234/%53YNTHETIC']:
            self.assertEqual(normalize_doi(value), '10.1234/synthetic')
        for value in [None, {}, 'bad', '10.123/a', '10.1234/a b', 'https://other.example/10.1234/a', 'http://[invalid/10.1234/a', '10.1234/a\x00', '10.1234/a\x7f', 'https://doi.org/10.1234/a%00', 'https://doi.org/10.1234/a%7F']:
            self.assertEqual(normalize_doi(value), '')

    def test_missing_invalid_and_different_doi_never_title_merge(self):
        rows = [self.row(str(i), doi=doi, Title='SYNTHETIC-SAME') for i, doi in enumerate(['', '', 'bad', 'bad', '10.1234/one', '10.1234/two'])]
        result = select_occurrences(rows)
        self.assertEqual(result['summary']['representatives_count'], 6)
        self.assertEqual(result['summary']['missing_doi_count'], 2)
        self.assertEqual(result['summary']['invalid_doi_count'], 2)
        self.assertEqual(result['decisions'], [])
        malformed = ['10.1234/a\x00', '10.1234/a\x7f', 'https://doi.org/10.1234/a%00']
        for doi in malformed:
            pair = select_occurrences([self.row('a', doi=doi), self.row('b', doi=doi)])
            self.assertEqual(pair['summary']['representatives_count'], 2)
            self.assertEqual(pair['summary']['invalid_doi_count'], 2)

    def test_eid_consolidation_across_pages_and_batches_preserves_every_occurrence(self):
        rows = [self.row('a', kind='Conference Paper', Title='SYNTHETIC-A', _delivery={'input_number': 1, 'row_number': 1}), self.row('a', kind='Article', Title='SYNTHETIC-B', _delivery={'input_number': 2, 'row_number': 4}), self.row('b', kind='Book Chapter', _delivery={'input_number': 2, 'row_number': 5})]
        result = select_occurrences(rows)
        self.assertEqual(result, select_occurrences(list(reversed(rows))))
        self.assertEqual(result['summary']['raw_occurrences_count'], 3)
        self.assertEqual(result['summary']['unique_eid_count'], 2)
        self.assertEqual(result['summary']['duplicate_eid_occurrences_count'], 1)
        self.assertEqual(result['summary']['secondary_records_count'], 1)
        self.assertEqual(result['summary']['representatives_count'], 1)
        self.assertEqual(result['publications'][0]['record']['Document Type'], 'Article')
        self.assertEqual(len(result['mapping']), 3)
        self.assertEqual(len(result['decisions']), 2)
        self.assertEqual(len(result['publications'][0]['deduplication']['all_occurrence_sources']), 3)
        self.assertEqual(sum(row['deduplication']['is_selected_occurrence'] for row in result['mapping']), 1)
        same = [row for row in result['mapping'] if row['record']['EID'] == 'a']
        self.assertIn('Title', same[0]['deduplication']['same_eid_conflict_fields'])

    def test_same_eid_doi_clash_is_deterministic_and_nonblocking(self):
        rows = [self.row('a', doi='10.1234/one', Title='SYNTHETIC-ONE'), self.row('a', doi='10.1234/two', Title='SYNTHETIC-TWO')]
        result = select_occurrences(rows)
        self.assertEqual(result, select_occurrences(rows[::-1]))
        self.assertEqual(result['summary']['unique_eid_count'], 1)
        self.assertEqual(len(result['publications']), 1)
        self.assertIn('DOI', result['mapping'][0]['deduplication']['same_eid_conflict_fields'])
        self.assertEqual(result['summary']['secondary_records_count'], 0)
        self.assertEqual(len(result['decisions']), 1)
        self.assertEqual(result['decisions'][0]['deduplication']['decision_scope'], 'eid_occurrence_consolidation')
        self.assertEqual(result['decisions'][0]['deduplication']['eid_occurrence_selection_reason'], 'stable_source_hash_tie_break')

    def test_unidentified_occurrences_remain_even_same_doi_and_identical_objects(self):
        rows = [{'doi': '10.1234/synthetic'}, {'doi': '10.1234/synthetic'}, {'title': 'SYNTHETIC'}]
        result = select_occurrences(rows)
        self.assertEqual(result, select_occurrences(rows[::-1]))
        self.assertEqual(result['summary']['representatives_count'], 3)
        self.assertEqual(result['summary']['missing_eid_occurrences_count'], 3)
        self.assertEqual(result['summary']['unique_eid_count'], 0)
        self.assertEqual(len({r['deduplication']['publication_id'] for r in result['publications']}), 3)

    def test_native_aliases_and_enrichment_wrappers_remain_whole(self):
        original = {'eid': 'b', 'doi': '10.1234/synthetic', 'subtype': 'cp', 'title': 'SYNTHETIC-ORIGINAL'}
        wrapper = {'scopus_original': original, 'merged': dict(original, subtype='ar', abstract='SYNTHETIC-ENRICHED'), 'field_provenance': {'abstract': {'provider': 'synthetic'}}}
        row = {'eid': 'a', 'doi': '10.1234/synthetic', 'subtype_description': 'Book Chapter'}
        result = select_occurrences([row, wrapper])
        self.assertEqual(result['publications'][0]['record'], wrapper)
        self.assertEqual(result['summary']['selection_reasons'], {'document_type_priority': 1})
        self.assertNotIn('abstract', wrapper['scopus_original'])

    def test_conflicts_memberships_source_refs_and_status(self):
        rows = [self.row('a', Title='SYNTHETIC-ONE', Year='2020', Pilot_Membership='P1;P2', **{'Source title': 'SYNTHETIC-JOURNAL', 'Cover Date': '2020-01-01', 'Source Raw SHA256': 'a' * 64}), self.row('b', kind='Book Chapter', Title='SYNTHETIC-TWO', Year='2021', Pilot_Membership='P3', **{'Source title': 'SYNTHETIC-BOOK', 'Cover Date': '2021-01-01', 'Source Raw SHA256': 'b' * 64})]
        result = select_occurrences(rows)
        metadata = result['publications'][0]['deduplication']
        self.assertEqual(metadata['memberships'], ['P1', 'P2', 'P3'])
        self.assertTrue(set(['Title', 'Document Type', 'Source title', 'Year', 'Cover Date']) <= set(metadata['metadata_conflict_fields']))
        self.assertEqual(metadata['identity_status'], 'policy_selected_not_publisher_verified')
        self.assertEqual(metadata['factual_identity_verification'], 'not_performed')
        self.assertTrue(metadata['conflicts_nonblocking'])
        self.assertEqual({r['record']['Source Raw SHA256'] for r in result['mapping']}, {'a' * 64, 'b' * 64})

    def test_valid_custom_priority_and_malformed_policies(self):
        policy = copy.deepcopy(DEFAULT_POLICY)
        policy['version'] = 'doi-priority-v2'
        policy['priority'] = ['preprint', 'conferencepaper', 'bookchapter', 'article']
        result = select_occurrences([self.row('a'), self.row('b', kind='Preprint')], policy)
        self.assertEqual(result['publications'][0]['record']['EID'], 'b')
        self.assertEqual(validate_policy(DEFAULT_POLICY), DEFAULT_POLICY)
        for change in [{'priority': []}, {'completeness_fields': [{}]}, {'field_merge': 'SYNTHETIC-UNSUPPORTED'}, {'version': 'SYNTHETIC SENSITIVE'}, {'unknown': 'SYNTHETIC'}]:
            policy = dict(copy.deepcopy(DEFAULT_POLICY), **change)
            with self.assertRaises(ValidationError) as captured:
                validate_policy(policy)
            self.assertNotIn('SYNTHETIC', str(captured.exception))

    def test_mapping_and_decision_storage_is_linear_for_repeated_occurrences(self):
        sizes = []
        for count in [100, 200]:
            rows = [self.row('a', _delivery={'row_number': i}) for i in range(count)]
            result = select_occurrences(rows)
            self.assertEqual(len(result['mapping']), count)
            self.assertEqual(len(result['decisions']), 1)
            self.assertEqual(len(result['publications'][0]['deduplication']['all_occurrence_sources']), count)
            for item in result['mapping'] + result['decisions']:
                self.assertNotIn('all_occurrence_sources', item['deduplication'])
                self.assertNotIn('all_eids', item['deduplication'])
            sizes.append(len(json.dumps(result)))
        self.assertLess(sizes[1], sizes[0] * 2.1)

    def test_empty_collection_and_json_validation_are_safe(self):
        result = select_occurrences([])
        self.assertEqual(result['publications'], [])
        self.assertEqual(result['summary']['raw_occurrences_count'], 0)
        for rows in [[None], [{'title': float('nan')}], [{'title': '\ud800'}]]:
            with self.assertRaises(ValidationError):
                select_occurrences(rows)


if __name__ == '__main__':
    unittest.main()
