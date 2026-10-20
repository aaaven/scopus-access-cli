"""Formal publisher CLI acceptance using synthetic saved evidence only."""
import builtins
import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from scopus_access import cli
import test_local_cli as local
import test_browser_evidence_review as saved
import test_installed_cli as installed


class PublisherCliTests(unittest.TestCase):
    invoke = local.LocalCliTests.invoke

    def setUp(self):
        saved.SavedReviewTests.setUp(self)

    def import_bundle(self):
        code, rows = self.invoke('enrich', 'import', '--source', 'publisher_html',
                                 '--bundle', str(self.bundle), local=True)
        self.assertEqual(code, 0, rows)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['network_calls'], 0)
        self.assertEqual(rows[0]['secret_reads'], 0)
        return rows[0]

    def test_offline_import_and_nested_status_export_need_no_optional_browser(self):
        original_import = builtins.__import__
        def no_browser(name, *args, **kwargs):
            if name == 'playwright' or name.startswith('playwright.'):
                raise AssertionError('offline import must not load Playwright')
            return original_import(name, *args, **kwargs)
        original = {p: p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()}
        policy_before = self.policy_path.read_bytes()
        with mock.patch.object(builtins, '__import__', side_effect=no_browser):
            imported = self.import_bundle()
            child = self.root / 'nested/a'; child.mkdir(parents=True)
            for action in ('status', 'export'):
                code, rows = self.invoke('enrich', action, '--run-info', imported['run_info_path'],
                                         root=child, local=True)
                self.assertEqual(code, 0, rows)
                self.assertEqual(rows[0]['network_calls'], 0)
                self.assertEqual(rows[0]['merged_sha256'], imported['merged_sha256'])
        self.assertEqual(policy_before, self.policy_path.read_bytes())
        self.assertEqual(original, {p: p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()})
        self.assertFalse(self.ledger.rows('request_usage'))
        for value in ('SYNTHETIC TITLE', 'SYNTHETIC FULL ABSTRACT', 'SYNTHETIC KEYWORD', 'SYNTHETIC REFERENCE'):
            self.assertNotIn(value, json.dumps(imported))

    def test_repeat_import_pins_same_evidence_without_overwriting_api_values_or_sources(self):
        baseline = self.records[0]['api_baseline']
        baseline['merged']['author_keywords'] = ['SYNTHETIC ORIGINAL KEYWORD']
        baseline['field_provenance']['author_keywords'] = {'provider': 'api', 'action': 'retained', 'synthetic_source': 'original'}
        (self.bundle / 'inputs.jsonl').write_bytes(b''.join(saved.html.encode(x) for x in self.records))
        first = self.import_bundle(); second = self.import_bundle()
        self.assertEqual(first['merged_sha256'], second['merged_sha256'])
        output = self.root / 'restricted_metadata/scopus' / first['merged_ref']
        row = json.loads(output.read_bytes().splitlines()[0])
        self.assertEqual(row['merged']['author_keywords'], baseline['merged']['author_keywords'])
        self.assertEqual(row['field_provenance']['author_keywords'], baseline['field_provenance']['author_keywords'])
        self.assertEqual(len(row['publisher_candidates']['rendered']['fields']['author_keywords']), 6)
        self.assertEqual(row['merged']['abstract'], baseline['merged']['abstract'])
        self.assertIsNone(json.loads(output.read_bytes().splitlines()[1])['merged']['author_keywords'])

    def test_import_rejects_source_tampering_and_export_rejects_result_tampering(self):
        imported = self.import_bundle()
        cache = self.root / 'restricted_metadata/scopus' / imported['merged_ref']
        cache.write_bytes(cache.read_bytes() + b' ')
        for action in ('status', 'export'):
            code, rows = self.invoke('enrich', action, '--run-info', imported['run_info_path'], local=True)
            self.assertEqual(code, 2, rows)
            self.assertNotIn('SYNTHETIC FULL ABSTRACT', json.dumps(rows))
        document = self.bundle / 'D0007/document-response.html'
        document.write_bytes(document.read_bytes() + b' ')
        code, rows = self.invoke('enrich', 'import', '--source', 'publisher_html', '--bundle', str(self.bundle), local=True)
        self.assertEqual(code, 2, rows)

    def test_rehashed_import_control_cannot_inject_nested_coverage_content_into_stdout(self):
        imported = self.import_bundle()
        original_info = Path(imported['run_info_path'])
        changed = json.loads(original_info.read_bytes())
        sentinel = 'SYNTHETIC_PRIVATE_ABSTRACT_CONTROL_SENTINEL'
        changed['result']['field_coverage']['abstract']['api_nonempty'] = sentinel
        changed['result_sha256'] = saved.html.api.digest(saved.html.api.encode(changed['result']))
        changed['run_id'] = 'html_import_' + changed['result_sha256'][:24]
        forged_info = original_info.parent.parent / changed['run_id'] / 'run-info.json'
        forged_info.parent.mkdir()
        forged_info.write_bytes(saved.html.api.encode(changed))
        # The plan hash, derived run identity and physical path agree; schema
        # validation must reject nested content before building control output.
        self.assertEqual(saved.html.api.digest(saved.html.api.encode(changed['result'])), changed['result_sha256'])
        for action in ('status', 'export'):
            code, rows = self.invoke('enrich', action, '--run-info', str(forged_info), local=True)
            self.assertEqual(code, 2, rows)
            self.assertEqual(len(rows), 1)
            self.assertNotIn(sentinel, json.dumps(rows))
            self.assertEqual((rows[0]['network_calls'], rows[0]['secret_reads']), (0, 0))

    def test_saved_run_cannot_borrow_another_project_binding(self):
        imported = self.import_bundle()
        other = self.root.parent / 'different-project'; other.mkdir()
        from scopus_access import project
        from scopus_access.secrets import SecretValue
        project.initialize_project(other, writer=local.Writer(), prompt=lambda: SecretValue(local.SECRET))
        code, rows = self.invoke('enrich', 'status', '--run-info', imported['run_info_path'], root=other, local=True)
        self.assertEqual(code, 2, rows)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_legacy_doi_prepare_remains_available_without_browser_dependency(self):
        records = self.root / 'restricted_metadata/scopus/synthetic-records.jsonl'
        row = copy.deepcopy(self.records[0]['api_baseline']['merged'])
        row['source_format'] = 'scopus_api_json'
        records.write_bytes(saved.html.encode(row))
        code, rows = self.invoke('enrich', 'prepare', '--records', str(records), '--sources', 'crossref', local=True)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]['network_calls'], 0)
        self.assertEqual(rows[0]['provider_limits'], {'crossref': 0})

    def static_plan(self, cap=4):
        records = self.root / 'restricted_metadata/scopus/static-records.jsonl'
        baselines = [copy.deepcopy(row['api_baseline']) for row in self.records]
        for baseline in baselines:
            baseline['doi_normalized'] = saved.html.api.normalize_doi(baseline['merged']['doi'])
        records.write_bytes(b''.join(saved.html.encode(row) for row in baselines))
        targets = self.root / 'restricted_metadata/scopus/static-targets.json'
        targets.write_bytes(saved.html.encode([{'sample_id': row['sample_id'], 'url': row['url']} for row in self.records]))
        code, rows = self.invoke('enrich', 'prepare', '--source', 'publisher_html', '--backend', 'static',
                                 '--records', str(records), '--targets', str(targets), '--max-requests', str(cap), local=True)
        self.assertEqual(code, 0, rows)
        return rows[0]

    def test_static_prepare_and_execute_without_consent_are_offline(self):
        plan = self.static_plan()
        self.assertEqual(plan['max_requests'], 4)
        self.assertEqual(plan['records'], 2)
        self.assertEqual(plan['planned_requests'], 4)
        self.assertEqual(plan['exact_hosts'], ['link.springer.com', 'www.nature.com'])
        self.assertEqual(plan['network_calls'], 0)
        code, rows = self.invoke('enrich', 'execute', '--run-info', plan['run_info_path'], local=True)
        self.assertEqual(code, 0, rows)
        self.assertTrue(rows[0]['consent_required'])
        self.assertEqual(rows[0]['requests_attempted'], 0)
        self.assertEqual(rows[0]['network_calls'], 0)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_zero_static_budget_stays_zero_on_resume_and_cap_tampering_is_rejected(self):
        plan = self.static_plan(cap=0)
        info = Path(plan['run_info_path'])
        original = info.read_bytes()
        for action in ('execute', 'resume'):
            code, rows = self.invoke('enrich', action, '--run-info', str(info), '--execute-live', local=True)
            self.assertEqual(code, 5, rows)
            self.assertEqual(rows[0]['stage_status'], 'budget_exhausted')
            self.assertEqual(rows[0]['requests_attempted'], 0)
            self.assertEqual(rows[0]['network_calls'], 0)
            self.assertEqual(info.read_bytes(), original)
        changed = json.loads(original); changed['max_requests'] = 15
        info.write_bytes(saved.html.encode(changed))
        code, rows = self.invoke('enrich', 'status', '--run-info', str(info), local=True)
        self.assertEqual(code, 2, rows)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_unsafe_cli_arguments_do_not_echo_contents(self):
        code, rows = self.invoke('enrich', 'prepare', '--source', 'publisher_html', '--backend',
                                 'SYNTHETIC PRIVATE VALUE', '--records', 'unused', local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[0]['code'], 'INVALID_ARGUMENTS')
        self.assertNotIn('SYNTHETIC PRIVATE VALUE', json.dumps(rows))


class InstalledPublisherCliTests(unittest.TestCase):
    """Real installed console import/export from a consuming project folder."""
    invoke = installed.InstalledCliTests.invoke

    @classmethod
    def setUpClass(cls):
        installed.InstalledCliTests.setUpClass.__func__(cls)

    def setUp(self):
        saved.SavedReviewTests.setUp(self)
        self.base = self.root.parent

    def test_installed_static_and_browser_prepare_and_consent_preview_are_offline(self):
        records = self.root / 'restricted_metadata/scopus/installed-records.jsonl'
        baseline = copy.deepcopy(self.records[0]['api_baseline']['merged'])
        baseline['source_format'] = 'scopus_api_json'
        records.write_bytes(saved.html.encode(baseline))
        targets = self.root / 'restricted_metadata/scopus/installed-targets.json'
        browser_targets = self.root / 'restricted_metadata/scopus/installed-browser-targets.json'
        url = self.records[0]['url']
        targets.write_bytes(saved.html.encode([{'sample_id': 'D0001', 'url': url}]))
        browser_targets.write_bytes(saved.html.encode([{'sample_id': 'D0001', 'url': url, 'domains': ['link.springer.com']}]))
        for backend, path, bounds in (
                ('static', targets, ['--max-requests', '2']),
                ('browser', browser_targets, ['--max-requests', '2', '--max-requests-per-page', '1', '--max-robots-requests', '1'])):
            code, rows = self.invoke(self.root, 'enrich', 'prepare', '--source', 'publisher_html', '--backend', backend,
                                     '--records', str(records), '--targets', str(path), *bounds)
            self.assertEqual(code, 0, rows)
            self.assertEqual(rows[0]['backend'], backend)
            self.assertEqual(rows[0]['network_calls'], 0)
            code, rows = self.invoke(self.root, 'enrich', 'execute', '--run-info', rows[0]['run_info_path'])
            self.assertEqual(code, 0, rows)
            self.assertTrue(rows[0]['consent_required'])
            self.assertEqual((rows[0]['requests_attempted'], rows[0]['network_calls']), (0, 0))

    def test_installed_offline_import_status_export_from_descendant(self):
        child = self.root / 'work/child'; child.mkdir(parents=True)
        code, rows = self.invoke(child, 'enrich', 'import', '--source', 'publisher_html', '--bundle', str(self.bundle))
        self.assertEqual(code, 0, rows)
        imported = rows[0]
        self.assertEqual((imported['network_calls'], imported['secret_reads']), (0, 0))
        for action in ('status', 'export'):
            code, rows = self.invoke(child, 'enrich', action, '--run-info', imported['run_info_path'])
            self.assertEqual(code, 0, rows)
            self.assertEqual(rows[0]['merged_sha256'], imported['merged_sha256'])
            self.assertEqual((rows[0]['network_calls'], rows[0]['secret_reads']), (0, 0))
        for row in rows:
            self.assertNotIn('SYNTHETIC FULL ABSTRACT', json.dumps(row))
