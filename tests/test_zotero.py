"""Synthetic HTTP-service tests; real sockets and credentials are never used."""
import copy
import io
import json
import multiprocessing
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from email.utils import formatdate
from pathlib import Path
from unittest import mock

from scopus_access import project, zotero as z, zotero_local as local
from scopus_access.secrets import SecretValue
from scopus_access.errors import ValidationError

SECRET = b'SYNTHETIC_ZOTERO_CREDENTIAL'


class Writer:
    def contains_api_key(self, alias): return True
    def add_api_key(self, alias, label, secret):
        assert secret.reveal().encode() == SECRET


class Provider:
    def __init__(self): self.reads = 0
    def get_api_key(self, alias):
        self.reads += 1
        return SecretValue(SECRET)


def template():
    return dict(itemType='journalArticle', title='', creators=[], tags=[], collections=[], relations={}, extra='',
                DOI='', date='', publicationTitle='', abstractNote='', language='')


class Service:
    """An in-memory HTTP service with server-side version/precondition semantics."""
    def __init__(self, items=None):
        self.items = copy.deepcopy(items or [])
        self.version = 4
        self.calls = []
        self.writes = []
        self.access = {'groups': {'123': {'library': True, 'write': True}}, 'user': {'library': True, 'write': True}}
        self.user_id = 456
        self.failure_index = None
        self.lose_response = False
        self.headers = {}
        self.changed_page = False
        self.duplicate_page = False
        self.inventory_omission = False
        self.page_size = 100
        self.write_status = 200
        self.malformed_partition = False
    def response(self, value, headers=None, status=200):
        merged = {'Last-Modified-Version': str(self.version), 'Total-Results': str(len(self.items))}
        merged.update(self.headers)
        merged.update(headers or {})
        return status, merged, json.dumps(value).encode()
    def request(self, method, path, headers, body):
        from urllib.parse import urlsplit, parse_qs
        self.calls.append((method, path))
        assert headers['Zotero-API-Key'] == SECRET.decode()
        assert SECRET.decode() not in path
        assert headers['Zotero-API-Version'] == '3'
        query = parse_qs(urlsplit(path).query)
        if path == '/keys/current': return self.response({'userID': self.user_id, 'access': self.access})
        if path == '/groups/123': return self.response({'id': 123, 'data': {'name': 'SYNTHETIC_GROUP'}})
        if path.startswith('/items/new?'): return self.response(template())
        if method == 'POST':
            payload = json.loads(body)
            self.writes.append(payload)
            if self.write_status != 200: return self.response({}, status=self.write_status)
            if headers['If-Unmodified-Since-Version'] != str(self.version): return self.response({}, status=412)
            result = {'successful': {}, 'unchanged': {}, 'failed': {}}
            self.version += 1
            for index, item in enumerate(payload):
                if index == self.failure_index:
                    result['failed'][str(index)] = {'code': 400, 'message': SECRET.decode() + ' CONTENT_SHOULD_NOT_LEAK'}
                    continue
                existing = next((x for x in self.items if x['key'] == item['key']), None)
                if existing:
                    existing['data'].update(item)
                    existing['data']['version'] = self.version
                    existing['version'] = self.version
                else:
                    data = dict(item, version=self.version)
                    existing = dict(key=item['key'], version=self.version, data=data)
                    self.items.append(existing)
                result['successful'][str(index)] = copy.deepcopy(existing)
            if self.lose_response: raise OSError(SECRET.decode())
            if self.malformed_partition: result['unchanged']['0'] = payload[0]['key']
            return self.response(result)
        if query.get('format') == ['versions']:
            rows = {item['key']: item['version'] for item in self.items}
            if self.inventory_omission and rows: rows.pop(next(iter(rows)))
            return self.response(rows)
        start = int(query.get('start', ['0'])[0])
        values = copy.deepcopy(self.items[start:start + self.page_size])
        if start and self.changed_page: self.version += 1
        if start and self.duplicate_page: values = copy.deepcopy(self.items[:self.page_size])
        return self.response(values)


def _worker_locked(policy, queue):
    ctx = local.Context(policy)
    try:
        z.check(ctx, secret_provider=Provider(), transport=Service())
    except z.ZoteroError as error:
        queue.put(error.code)
    else:
        queue.put('unexpected_success')


class ZoteroTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        project.initialize_project(self.root, writer=Writer(), prompt=lambda: SecretValue(SECRET))
        self.ctx = local.Context.from_project(self.root)
        local.configure(self.ctx, 'group', '123', writer=Writer())
        self.provider = Provider()
    def rows(self, count=1):
        return [dict(record_id='record_%02d' % i, doi='10.1234/synthetic%d' % i, eid='SYNTHETIC_EID_%d' % i,
                     hold_reason=None, item=dict(template(), title='SYNTHETIC_TITLE_%d' % i,
                     DOI='10.1234/synthetic%d' % i,
                     extra=z.MARKER + self.ctx.project_id + ':record_%02d' % i)) for i in range(count)]
    def prepared(self, rows=None):
        rows = rows if rows is not None else self.rows()
        # Synthetic upstream fixture: freeze the actual source and conversion
        # lineage, then inject its prepared service boundary as a mock input.
        source = self.ctx.storage / ('synthetic-source-' + z.uuid.uuid4().hex + '.json')
        source.write_bytes(local.encode(rows))
        dataset = local.create_dataset(self.ctx, source)
        prepared = local.prepare(self.ctx, dataset['path'])
        metadata, _ = self.ctx.read_bundle(prepared['path'], 'prepared')
        return self.ctx.bundle('prepared', rows, metadata)['path']
    def plan(self, api=None, rows=None):
        return z.plan(self.ctx, self.prepared(rows), secret_provider=self.provider, transport=api or Service())
    def push(self, plan, api, maximum=100):
        return z.push(self.ctx, plan['path'], maximum, True, secret_provider=self.provider, transport=api)
    def remote(self, row, key='ABCDEFGH'):
        return dict(key=key, version=4, data=dict(copy.deepcopy(row['item']), key=key, version=4))
    def actions(self, result): return self.ctx.read_bundle(result['path'], 'plan')[1]['actions']

    def test_missing_execute_and_bound_have_zero_reads_and_requests(self):
        api = Service()
        for bound, execute in ((1, False), (None, True), (0, True), (True, True)):
            with self.assertRaises(z.ZoteroError):
                z.push(self.ctx, '/untrusted', bound, execute, secret_provider=self.provider, transport=api)
        self.assertEqual(api.calls, [])
        self.assertEqual(self.provider.reads, 0)

    def test_check_and_plan_are_only_reads_and_group_names_are_generic(self):
        api = Service()
        result = z.check(self.ctx, secret_provider=self.provider, transport=api)
        self.assertTrue(result['key_reports_write'])
        self.assertFalse(result['write_test_performed'])
        self.plan(api)
        self.assertTrue(all(method == 'GET' for method, _ in api.calls))
        self.assertEqual(api.writes, [])

    def test_exact_permission_overrides_all_and_personal_user_id_is_bound(self):
        api = Service()
        api.access['groups'] = {'all': {'library': True, 'write': True}, '123': {'library': False}}
        with self.assertRaises(z.ZoteroError): z.check(self.ctx, secret_provider=self.provider, transport=api)
        local.configure(self.ctx, 'user', '456', writer=Writer())
        z.check(self.ctx, secret_provider=self.provider, transport=api)
        api.user_id = 789
        with self.assertRaises(z.ZoteroError): z.check(self.ctx, secret_provider=self.provider, transport=api)

    def test_first_push_and_repeat_import_and_manual_entry(self):
        api = Service()
        first = self.plan(api)
        result = self.push(first, api)
        self.assertEqual(result['successful'], 1)
        self.assertEqual(len(api.items), 1)
        with self.assertRaises(z.ZoteroError) as error: self.push(first, api)
        self.assertEqual(error.exception.code, 'ZOTERO_PLAN_SPENT')
        repeat = self.plan(api)
        self.assertEqual(repeat['counts'], {'skip': 1})
        self.assertEqual(self.push(repeat, api)['network_calls'], 0)
        manual = self.remote(self.rows()[0], api.items[0]['key']); manual['data']['extra'] = 'SYNTHETIC_MANUAL_NOTE'
        api = Service([manual])
        planned = self.plan(api)
        self.assertEqual(planned['counts'], {'skip': 1})
        self.assertEqual(api.items[0]['data']['extra'], 'SYNTHETIC_MANUAL_NOTE')

    def test_local_id_doi_conflicts_missing_identity_and_missing_title(self):
        rows = self.rows(3)
        rows[1]['doi'] = ''; rows[1]['item']['DOI'] = ''
        rows[2]['item']['title'] = ''; rows[2]['hold_reason'] = 'missing_title'
        api = Service([self.remote(rows[0]), self.remote(rows[0], 'BCDEFGHJ')])
        actions = self.actions(self.plan(api, rows))
        self.assertEqual([a['action'] for a in actions], ['hold', 'create', 'hold'])
        self.assertEqual(actions[0]['reason'], 'multiple_remote_matches')
        remote = self.remote(rows[0]); remote['data']['DOI'] = '10.1234/other'
        self.assertEqual(self.actions(self.plan(Service([remote])))[0]['reason'], 'remote_identity_conflict')

    def test_manual_fields_preserved_empty_fields_patched_conflicts_saved(self):
        row = self.rows()[0]
        row['item']['date'] = '2026'; row['item']['abstractNote'] = 'SYNTHETIC_LOCAL_ABSTRACT'
        remote = self.remote(row)
        remote['data']['date'] = ''; remote['data']['abstractNote'] = 'SYNTHETIC_MANUAL_ABSTRACT'
        remote['data']['extra'] = 'SYNTHETIC_MANUAL_NOTE'
        action = self.actions(self.plan(Service([remote]), [row]))[0]
        self.assertEqual(action['action'], 'update')
        self.assertEqual(action['payload'], {'date': '2026', 'key': 'ABCDEFGH', 'version': 4})
        self.assertIn('abstractNote', action['conflicts'])
        self.assertNotIn('extra', action['payload'])

    def test_type_and_trashed_and_foreign_project_identity_hold(self):
        row = self.rows()[0]
        for change in ({'itemType': 'book'}, {'deleted': 1}, {'extra': z.MARKER + 'other-project:record_00'}):
            old = self.remote(row); old['data'].update(change)
            self.assertEqual(self.actions(self.plan(Service([old])))[0]['action'], 'hold')

    def test_snapshot_version_duplicate_and_inventory_omission_fail(self):
        for mode in ('changed_page', 'duplicate_page', 'inventory_omission'):
            api = Service([self.remote(self.rows()[0]), self.remote(self.rows()[0], 'BCDEFGHJ')])
            api.page_size = 1; setattr(api, mode, True)
            with self.assertRaises(z.ZoteroError): self.plan(api)
            self.assertEqual(api.writes, [])

    def test_library_change_and_target_change_reject_frozen_plan(self):
        api = Service(); planned = self.plan(api); api.version += 1
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        self.assertEqual(api.writes, [])
        local.configure(self.ctx, 'group', '999', writer=Writer())
        with self.assertRaises(z.ZoteroError): self.push(planned, api)

    def test_partial_results_persist_safe_mapping_and_stop_batch_replay(self):
        api = Service(); planned = self.plan(api, self.rows(2)); api.failure_index = 1
        result = self.push(planned, api)
        self.assertEqual(result['successful'], 1); self.assertEqual(result['failed'], 1)
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        text = ''.join(path.read_text() for path in self.ctx.storage.rglob('*.json'))
        self.assertNotIn(SECRET.decode(), text)
        self.assertNotIn('CONTENT_SHOULD_NOT_LEAK', text)
        mapped = [path for path in (self.ctx.storage / 'mapping').rglob('content.json')]
        self.assertTrue(mapped)

    def test_committed_but_lost_response_requires_read_reconciliation_new_plan(self):
        api = Service(); planned = self.plan(api); api.lose_response = True
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        self.assertEqual(len(api.items), 1)
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        api.lose_response = False
        successor = self.plan(api)
        self.assertEqual(successor['counts'], {'skip': 1})
        self.assertEqual(successor['recovery_pending'], 0)
        self.assertEqual(len(api.writes), 1)

    def test_crash_before_send_is_reconciled_and_reuses_assigned_key(self):
        api = Service(); planned = self.plan(api)
        original = self.actions(planned)[0]['item_key']
        real_request = z._API.request
        def crashing(instance, method, *args, **kwargs):
            if method == 'POST': raise KeyboardInterrupt()
            return real_request(instance, method, *args, **kwargs)
        with mock.patch.object(z._API, 'request', crashing), self.assertRaises(KeyboardInterrupt):
            self.push(planned, api)
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        fresh = self.plan(api)
        self.assertEqual(self.actions(fresh)[0]['item_key'], original)
        self.assertEqual(self.push(fresh, api)['successful'], 1)

    def test_rate_limit_persists_http_date_and_does_not_retry(self):
        api = Service(); planned = self.plan(api)
        api.write_status = 503
        real_request = api.request
        def limited(method, *args):
            if method == 'POST': api.headers = {'Retry-After': formatdate(z.time.time() + 3600, usegmt=True)}
            return real_request(method, *args)
        api.request = limited
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        self.assertEqual(len(api.writes), 1)
        calls = len(api.calls)
        with self.assertRaises(z.ZoteroError): self.plan(api)
        self.assertEqual(len(api.calls), calls)

    def test_success_backoff_is_saved_before_any_next_batch(self):
        api = Service(); planned = self.plan(api, self.rows(51))
        real_request = api.request
        def response(method, *args):
            if method == 'POST': api.headers = {'Backoff': '3600'}
            return real_request(method, *args)
        api.request = response
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        self.assertEqual(len(api.writes), 1); self.assertEqual(len(api.writes[0]), 50)
        journal = z._Journal(self.ctx, z._target(self.ctx))
        self.assertEqual(sum(e['event'] == 'result' for e in journal.events), 1)

    def test_batch_partition_collision_is_uncertain_and_requires_reconciliation(self):
        api = Service(); planned = self.plan(api); api.malformed_partition = True
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        api.malformed_partition = False
        successor = self.plan(api)
        self.assertEqual(successor['counts'], {'skip': 1})

    def test_cross_process_lock_and_journal_successor_chain(self):
        if 'fork' not in multiprocessing.get_all_start_methods(): self.skipTest('requires POSIX fork')
        context = multiprocessing.get_context('fork'); queue = context.Queue()
        with z._lock(self.ctx):
            worker = context.Process(target=_worker_locked, args=(self.ctx.policy_path, queue))
            worker.start(); worker.join(10)
        self.assertEqual(worker.exitcode, 0); self.assertEqual(queue.get(timeout=2), 'ZOTERO_BUSY')
        self.plan(Service())
        journal = z._Journal(self.ctx, z._target(self.ctx))
        self.assertTrue(journal.events)
        self.assertEqual(journal.events[0]['previous_sha256'], None)
        for old, new in zip(journal.events, journal.events[1:]): self.assertEqual(new['previous_sha256'], z._digest(old))

    def test_secret_and_content_do_not_reach_safe_errors_or_control_summary(self):
        api = Service(); planned = self.plan(api)
        self.assertNotIn('SYNTHETIC_TITLE', json.dumps(planned))
        class Broken:
            def request(self, *args): raise OSError(SECRET.decode() + ' SYNTHETIC_TITLE')
        with self.assertRaises(z.ZoteroError) as error:
            z.check(self.ctx, secret_provider=self.provider, transport=Broken())
        self.assertNotIn(SECRET.decode(), str(error.exception)); self.assertNotIn('SYNTHETIC_TITLE', str(error.exception))

    def test_expired_and_edited_plan_cannot_send(self):
        api = Service(); planned = self.plan(api)
        with mock.patch.object(z.time, 'time', return_value=z.time.time() + 3601), self.assertRaises(z.ZoteroError):
            self.push(planned, api)
        self.assertEqual(api.writes, [])
        path = Path(planned['path']); content_path = path.parent / 'content.json'
        content = json.loads(content_path.read_text()); content['actions'][0]['payload']['title'] = 'SYNTHETIC_TAMPER'
        content_path.write_bytes(local.encode(content))
        manifest = json.loads(path.read_text()); manifest['content_sha256'] = local.sha256_bytes(content_path.read_bytes()); path.write_bytes(local.encode(manifest))
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        self.assertEqual(api.writes, [])

    def test_bounded_subset_spends_plan_and_replans_remaining(self):
        api = Service(); rows = self.rows(3); planned = self.plan(api, rows)
        result = self.push(planned, api, maximum=1)
        self.assertEqual(result['successful'], 1); self.assertEqual(result['remaining'], 2)
        with self.assertRaises(z.ZoteroError): self.push(planned, api, maximum=3)
        fresh = self.plan(api, rows)
        self.assertEqual(fresh['counts'], {'skip': 1, 'create': 2})
        self.assertEqual(self.push(fresh, api)['successful'], 2)

    def test_multiple_batches_respect_fifty_item_limit(self):
        api = Service(); planned = self.plan(api, self.rows(51))
        result = self.push(planned, api)
        self.assertEqual(result['successful'], 51)
        self.assertEqual([len(batch) for batch in api.writes], [50, 1])

    def test_uncertain_create_with_divergent_fields_stays_held(self):
        api = Service(); planned = self.plan(api); api.lose_response = True
        with self.assertRaises(z.ZoteroError): self.push(planned, api)
        api.lose_response = False
        api.items[0]['data']['title'] = 'SYNTHETIC_DIVERGENT_TITLE'
        fresh = self.plan(api)
        self.assertEqual(fresh['recovery_pending'], 1)
        self.assertEqual(fresh['counts'], {'hold': 1})
        with self.assertRaises(z.ZoteroError): self.push(fresh, api)
        self.assertEqual(len(api.writes), 1)

    def test_missing_or_modified_outcome_evidence_is_not_terminal(self):
        api = Service(); planned = self.plan(api); self.push(planned, api)
        journal = z._Journal(self.ctx, z._target(self.ctx))
        result_event = next(e for e in journal.events if e['event'] == 'result')
        path = Path(result_event['path']).parent / 'content.json'
        path.write_text('[]\n')
        with self.assertRaises(ValidationError): self.plan(api)
        self.assertEqual(len(api.writes), 1)

    def test_mapped_hard_deleted_item_is_held(self):
        api = Service(); planned = self.plan(api); self.push(planned, api)
        api.items = []; api.version += 1
        fresh = self.plan(api)
        self.assertEqual(self.actions(fresh)[0]['reason'], 'mapped_remote_missing')
        self.assertEqual(fresh['counts'], {'hold': 1})

    def test_doi_extra_matches_and_multiple_dois_hold(self):
        row = self.rows()[0]
        remote = self.remote(row); remote['data']['DOI'] = ''
        remote['data']['extra'] = 'DOI: ' + row['doi']
        self.assertEqual(self.actions(self.plan(Service([remote])))[0]['action'], 'update')
        remote['data']['extra'] += '\nDOI: 10.1234/conflicting'
        self.assertEqual(self.actions(self.plan(Service([remote])))[0]['reason'], 'remote_doi_conflict')

    def test_unchanged_partition_and_returned_key_validation(self):
        action = dict(record_id='record_synthetic', item_key='ABCDEFGH')
        result = z._parse_result({'successful': {}, 'unchanged': {'0': 'ABCDEFGH'}, 'failed': {}}, [action])
        self.assertEqual(result[0]['status'], 'unchanged')
        for value in ({'successful': {'0': {'key': 'BCDEFGHJ'}}, 'unchanged': {}, 'failed': {}},
                      {'successful': {}, 'unchanged': {}, 'failed': {'0': {'code': 400, 'key': 'BCDEFGHJ'}}}):
            with self.assertRaises(z.ZoteroError): z._parse_result(value, [action])

    def test_source_modification_stops_before_any_request(self):
        api = Service(); planned = self.plan(api)
        frozen = self.ctx.read_bundle(planned['path'], 'plan')[1]
        prepared = self.ctx.read_bundle(frozen['prepared_path'], 'prepared')[0]
        dataset = self.ctx.read_bundle(prepared['dataset_path'], 'dataset')[0]
        Path(dataset['source_path']).write_text('[]\n')
        before = len(api.calls)
        with self.assertRaises(ValidationError): self.push(planned, api)
        self.assertEqual(len(api.calls), before)

    def test_duplicate_json_keys_and_nonfinite_response_are_rejected(self):
        class Broken:
            def __init__(self, raw): self.raw = raw
            def request(self, *args): return 200, {}, self.raw
        for raw in (b'{"access":{},"access":{}}', b'{"access":NaN}'):
            with self.assertRaises(z.ZoteroError):
                z.check(self.ctx, secret_provider=self.provider, transport=Broken(raw))

    def test_target_switch_cannot_bypass_server_backoff(self):
        api = Service(); api.headers = {'Backoff': '3600'}
        with self.assertRaises(z.ZoteroError): z.check(self.ctx, secret_provider=self.provider, transport=api)
        local.configure(self.ctx, 'user', '456', writer=Writer())
        fresh = Service()
        with self.assertRaises(z.ZoteroError): z.check(self.ctx, secret_provider=self.provider, transport=fresh)
        self.assertEqual(fresh.calls, [])


if __name__ == '__main__': unittest.main()
