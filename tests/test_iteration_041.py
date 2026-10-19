"""Offline regressions for accounting diagnostics and final urllib requests."""
import dataclasses
import io
import json
import urllib.error
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scopus_access import client
from scopus_access.errors import UnsafeRequestError
import test_local_cli as fixtures


class IterationTests(unittest.TestCase):
    setUp = fixtures.LocalCliTests.setUp
    invoke = fixtures.LocalCliTests.invoke
    check = fixtures.LocalCliTests.check

    def test_same_window_stale_balance_reports_exact_reason_without_refund(self):
        self.check()
        original = self.wire.send
        def cached(request, **kwargs):
            return dataclasses.replace(original(request, **kwargs), headers={
                'X-RateLimit-Limit':'100', 'X-RateLimit-Remaining':'99',
                'X-RateLimit-Reset':'2000000000'})
        self.wire.send = cached
        code, rows = self.invoke('search','--query-file',str(self.query),'--max-requests','2','--page-size','1','--execute-live')
        self.assertEqual(code,5,rows)
        telemetry = [r for r in rows if r.get('event') == 'quota_telemetry'][-1]
        self.assertEqual(telemetry['telemetry_reason'],'RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING')
        self.assertEqual(telemetry['quota_remaining'],99)
        self.assertEqual(telemetry['local_remaining_after_attempt'],98)
        source = rows[0]['run_info_path']
        code, inspected = self.invoke('inspect','--run-info',source,local=True)
        self.assertEqual(code,0,inspected)
        self.assertEqual(inspected[0]['telemetry'],telemetry)
        self.assertEqual(inspected[0]['current_bucket_reason'],telemetry['telemetry_reason'])
        self.assertEqual(inspected[0]['pages_saved'],1)
        self.assertEqual(self.ledger.quota_status(self.policy.key_alias_for(self.policy.project_binding.project_id,'scopus_search'),'scopus_search').effective_remaining,98)
        code, _ = self.invoke('resume','--run-info',source,'--execute-live')
        self.assertNotEqual(code,0)
        self.assertEqual(len(self.wire.urls),2)
        attempts = [r for r in self.ledger.rows('request_usage') if r['record_kind']=='ATTEMPT']
        self.assertEqual(len(attempts),2)

    def failed_diagnostics(self, status=200):
        self.wire.headers = False
        self.wire.status = status
        for _ in range(2):
            code, rows = self.invoke('check','--query-file',str(self.query),'--execute-live')
            self.assertNotEqual(code,0,rows)
        return rows[0]['run_info_path']

    def test_diagnostic_preview_never_reads_secret_or_changes_ledger(self):
        self.wire.headers = False
        _, rows = self.invoke('check','--query-file',str(self.query),'--execute-live')
        source = rows[0]['run_info_path']
        before = self.ledger.rows('task_reservation'), self.ledger.rows('request_usage'), self.ledger.rows('quota_window')
        code, draft = self.invoke('diagnose','--run-info',source,local=True)
        self.assertEqual(code,0,draft)
        self.assertTrue(draft[0]['separate_approval_required'])
        self.assertIsNone(draft[0]['diagnostic_predecessor_reservation_id'])
        self.assertEqual((draft[0]['planned_requests'],draft[0]['page_size'],draft[0]['retry_allowance']),(1,1,0))
        self.assertEqual(before,(self.ledger.rows('task_reservation'),self.ledger.rows('request_usage'),self.ledger.rows('quota_window')))
        self.assertEqual(len(self.wire.urls),1)

    def test_successor_requires_review_and_new_approval_and_cannot_reuse_predecessor(self):
        source = self.failed_diagnostics()
        original = Path(source).read_bytes()
        history = self.ledger.rows('task_reservation')
        code, error = self.invoke('diagnose','--run-info',source,local=True)
        self.assertEqual((code,error[-1]['code']),(2,'DIAGNOSTIC_CORRECTION_REQUIRED'))
        drafts=[]
        for _ in range(2):
            code, rows = self.invoke('diagnose','--run-info',source,'--correction','request_fix',local=True)
            self.assertEqual(code,0,rows)
            drafts.append(rows[0]['run_info_path'])
            self.assertEqual(rows[0]['diagnostic_predecessor_reservation_id'],history[-1]['reservation_id'])
        self.assertEqual(self.ledger.rows('task_reservation'),history)
        self.wire.headers=True
        code, rows = self.invoke('execute','--run-info',drafts[0],'--execute-live')
        self.assertEqual(code,0,rows)
        after = self.ledger.rows('task_reservation')
        self.assertEqual(after[:len(history)],history)
        successor = next(r for r in after[len(history):] if r['event_seq']==1)
        self.assertEqual(successor['predecessor_event_id'],history[-1]['reservation_event_id'])
        code, rows = self.invoke('execute','--run-info',drafts[1],'--execute-live')
        self.assertNotEqual(code,0,rows)
        self.assertEqual(len(self.wire.urls),3)
        self.assertEqual(Path(source).read_bytes(),original)

    def test_successor_refuses_401_and_changed_source_hash(self):
        source = self.failed_diagnostics(status=401)
        code, rows = self.invoke('diagnose','--run-info',source,'--correction','provider_guidance',local=True)
        self.assertEqual((code,rows[-1]['code']),(2,'DIAGNOSTIC_NOT_ALLOWED'))
        info = json.loads(Path(source).read_text())
        path = Path(info['policy_path'])
        path.write_bytes(path.read_bytes()+b'\n')
        code, _ = self.invoke('diagnose','--run-info',source,'--correction','request_fix',local=True)
        self.assertNotEqual(code,0)
        self.assertEqual(len(self.wire.urls),2)

    def test_diagnostic_preserves_multiline_query_and_both_text_hashes(self):
        query = '(\nTITLE("two  spaces")\r\n\tAND TITLE(test)\n)'
        self.query.write_bytes(query.encode())
        source = self.failed_diagnostics()
        code, rows = self.invoke('diagnose','--run-info',source,'--correction','environment_change',local=True)
        self.assertEqual(code,0,rows)
        info = json.loads(Path(rows[0]['run_info_path']).read_text())
        task = json.loads(Path(info['manifest_path']).read_text())
        operation = json.loads(Path(task['query_manifest_path']).read_text())['queries']['scopus_search']
        self.assertEqual(operation['query'],query)
        self.assertEqual(operation['provenance']['source_text'],query)
        self.assertEqual(operation['provenance']['source_sha256'],operation['provenance']['transport_sha256'])

    def test_pending_preflight_uses_original_resume_instead_of_new_diagnostic(self):
        from scopus_access.errors import SecretProviderError
        def unavailable():
            raise SecretProviderError(reason='interaction_not_allowed',stage='credential_read',backend='macos_security_framework')
        self.secret.callback = unavailable
        _, rows = self.invoke('check','--query-file',str(self.query),'--execute-live')
        source=rows[0]['run_info_path']
        code, rows=self.invoke('diagnose','--run-info',source,local=True)
        self.assertEqual((code,rows[-1]['code']),(2,'DIAGNOSTIC_NOT_ALLOWED'))
        self.assertFalse(self.wire.urls)
        self.assertFalse(self.ledger.rows('request_usage'))

    def install_mock_opener(self, *, status=200, failure=None):
        transport = client.UrllibTransport()
        self.outgoing=[]
        self.snapshots=[]
        validate = client._validate_request
        def validated(request):
            self.snapshots.append(request)
            return validate(request)
        patch = mock.patch.object(client,'_validate_request',side_effect=validated)
        patch.start(); self.addCleanup(patch.stop)
        test = self
        class Response:
            status = 200
            headers = {'X-RateLimit-Limit':'100','X-RateLimit-Remaining':'99','X-RateLimit-Reset':'2000000000'}
            def __enter__(self): return self
            def __exit__(self,*args): return None
            def read(self,limit):
                if failure == 'read': raise RuntimeError(fixtures.SECRET.decode()+fixtures.QUERY)
                return b'{"abstracts-retrieval-response":{"coredata":{"dc:identifier":"SCOPUS_ID:777777777777"}}}'
        class Opener:
            def open(self, request, timeout):
                test.outgoing.append(request)
                test.assertEqual(request.get_method(),'GET')
                parsed = urlsplit(request.full_url)
                test.assertEqual((parsed.scheme,parsed.netloc,parsed.path),('https','api.elsevier.com','/content/abstract/scopus_id/777777777777'))
                test.assertEqual(parse_qs(parsed.query),{'view':['META_ABS']})
                headers = {k.lower():v for k,v in request.header_items()}
                test.assertEqual(set(headers),{'accept','user-agent','x-els-apikey'})
                test.assertEqual(headers['x-els-apikey'],fixtures.SECRET.decode())
                test.assertEqual(headers['accept'],'application/json')
                test.assertEqual(headers['user-agent'],client.USER_AGENT)
                attempts = [r for r in test.ledger.rows('request_usage') if r['record_kind']=='ATTEMPT']
                test.assertEqual(len(attempts),1)  # durable charge precedes actual urllib boundary
                test.assertEqual(attempts[0]['api_key_alias'],test.secret.aliases[0])
                if failure == 'open': raise RuntimeError(fixtures.SECRET.decode()+fixtures.QUERY)
                if status != 200:
                    raise urllib.error.HTTPError(request.full_url,status,'synthetic',{},io.BytesIO(b'{"error-response":{"error-code":"AUTHORIZATION_ERROR"}}'))
                return Response()
        transport._opener=Opener()
        self.wire=transport

    def detail(self):
        path=self.root/'restricted_metadata/ids.json'
        path.write_text('["777777777777"]')
        return self.invoke('details','--identifiers-file',str(path),'--view','META_ABS','--check','--execute-live')

    def assert_cleared(self):
        self.assertTrue(self.snapshots)
        for snapshot in self.snapshots: self.assertEqual(snapshot.headers,{})
        for outgoing in self.outgoing:
            self.assertEqual(outgoing.headers,{})
            self.assertEqual(outgoing.unredirected_hdrs,{})

    def test_numeric_meta_abs_contract_at_final_urllib_boundary(self):
        self.install_mock_opener()
        code, rows=self.detail()
        self.assertEqual(code,0,rows)
        self.assertEqual(len(self.outgoing),1)
        self.assert_cleared()

    def test_final_urllib_401_is_preserved_without_view_fallback_or_retry(self):
        self.install_mock_opener(status=401)
        code, rows=self.detail()
        self.assertNotEqual(code,0)
        self.assertEqual(len(self.outgoing),1)
        error=next(r for r in rows if r.get('event')=='service_error')
        self.assertEqual((error['http_status'],error['remote_error_code']),(401,'authorization_error'))
        self.assert_cleared()

    def test_opener_and_read_errors_are_redacted_and_all_header_copies_clear(self):
        for failure in ('open','read'):
            with self.subTest(failure=failure):
                # Each fixture is an independent, unverified project.
                self.setUp()
                self.install_mock_opener(failure=failure)
                code, rows=self.detail()
                self.assertNotEqual(code,0)
                self.assertEqual(len(self.outgoing),1)
                self.assert_cleared()

    def test_client_validation_failure_clears_header_before_transport(self):
        self.install_mock_opener()
        requests=[]
        def fail(request):
            requests.append(request)
            raise UnsafeRequestError()
        with mock.patch.object(client,'_validate_request',side_effect=fail):
            code, _=self.detail()
        self.assertNotEqual(code,0)
        self.assertEqual(len(requests),1)
        self.assertEqual(requests[0].headers,{})
        self.assertEqual(self.outgoing,[])

    def test_capability_failure_clears_header_before_transport(self):
        self.install_mock_opener()
        with mock.patch.object(client,'_issue_wire_execution_capability',side_effect=UnsafeRequestError()):
            code, _=self.detail()
        self.assertNotEqual(code,0)
        self.assertEqual(self.outgoing,[])
        self.assert_cleared()

    def test_transport_claim_failure_clears_snapshot_and_client_headers(self):
        self.install_mock_opener()
        def reject(capability, request):
            self.snapshots.append(request)
            raise UnsafeRequestError()
        with mock.patch.object(client._WireExecutionCapability,'claim',autospec=True,side_effect=reject):
            code, _=self.detail()
        self.assertNotEqual(code,0)
        self.assertEqual(self.outgoing,[])
        self.assert_cleared()

    def test_request_constructor_error_is_redacted_and_copies_clear(self):
        self.install_mock_opener()
        with mock.patch.object(client.urllib.request,'Request',side_effect=RuntimeError(fixtures.SECRET.decode()+fixtures.QUERY)):
            code, _=self.detail()
        self.assertNotEqual(code,0)
        self.assertEqual(self.outgoing,[])
        self.assert_cleared()
