"""Matched diagnostic: all credentials/responses synthetic, sockets forbidden."""
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock
from scopus_access import comparison
from scopus_access.client import TransportResponse
from scopus_access.errors import ValidationError, TransportError
from scopus_access.ledger import LedgerError
import test_local_cli as fixtures
SECRET=fixtures.SECRET


class ComparisonTests(unittest.TestCase):
    invoke=fixtures.LocalCliTests.invoke
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        self.sent=[]
        self.statuses=[401,200,200]
        test=self
        class Wire:
            def send(self,request,**kwargs):
                test.assertEqual(request.headers['X-ELS-APIKey'],SECRET.decode())
                test.assertEqual(request.url,'https://api.elsevier.com/content/abstract/scopus_id/777?view=META_ABS')
                test.assertEqual(len([r for r in test.ledger.rows('request_usage') if r['record_kind']=='ATTEMPT']),len(test.sent)+1)
                test.sent.append(request.url)
                return test.response(test.statuses[len(test.sent)-1])
        self.wire=Wire()

    def response(self,status):
        headers={'X-RateLimit-Limit':'100','X-RateLimit-Remaining':str(100-len(self.sent)),'X-RateLimit-Reset':'2000000000'}
        body=({'error-response':{'error-code':'AUTHORIZATION_ERROR','error-message':SECRET.decode()}}
            if status!=200 else {'abstracts-retrieval-response':{'coredata':{'dc:identifier':'SCOPUS_ID:777','dc:description':'SYNTHETIC_ABSTRACT'},
             'author-count':{'@total':'2'},'authors':{'author':[{'@auid':'11'},{'@auid':'22'}]},
             'authkeywords':{'author-keyword':[{'$':'SYNTHETIC_KEYWORD'}]}}})
        return TransportResponse(status,headers,json.dumps(body).encode())

    def failed(self):
        path=self.root/'restricted_metadata/ids.json';path.write_text('["777"]')
        code,rows=self.invoke('details','--identifiers-file',str(path),'--view','META_ABS','--check','--execute-live')
        self.assertEqual(code,6,rows)
        return rows[0]['run_info_path']

    def prepare(self):
        failed=self.failed()
        with mock.patch.object(Path,'cwd',return_value=self.root):
            prepared=comparison.prepare(failed)
        self.assertEqual(prepared['planned_requests'],2)
        self.assertEqual(len(self.sent),1)
        return prepared['run_info_path']

    def run_pair(self,source,**options):
        def reference(identifier,view,key):
            self.assertEqual((identifier,view,key),('777','META_ABS',SECRET.decode()))
            attempts=[r for r in self.ledger.rows('request_usage') if r['record_kind']=='ATTEMPT']
            self.assertEqual(len(attempts),3)
            self.sent.append('independent_reference')
            return self.response(self.statuses[2])
        with mock.patch.object(Path,'cwd',return_value=self.root):
            parameters=dict(secret_provider=self.secret,cli_transport=self.wire,reference=reference)
            parameters.update(options)
            return comparison.execute(source,**parameters)

    def test_pair_preserves_id_view_charges_twice_and_reports_raw_and_conversion(self):
        source=self.prepare();before=len(self.secret.aliases)
        report=self.run_pair(source)
        self.assertEqual(report['requests_attempted'],2)
        self.assertEqual(len(self.secret.aliases)-before,1)
        self.assertEqual([r['http_status'] for r in report['results']],[200,200])
        for result in report['results']:
            c=result['coverage']
            self.assertEqual(c['raw_nonempty_records']['abstract'],1)
            self.assertEqual(c['converted_nonempty_records']['author_keywords'],1)
            self.assertEqual(c['author_list_entries'],2)
            self.assertTrue(c['author_count_matches'])
        with mock.patch.object(Path,'cwd',return_value=self.root):
            with self.assertRaises(ValidationError): self.run_pair(source)
        self.assertEqual(len(self.sent),3)
        for row in self.ledger.rows('request_usage'):
            self.assertNotIn(SECRET.decode(),json.dumps(row))
        self.assertNotIn(SECRET.decode(),json.dumps(report))

    def test_two_401_responses_are_two_charged_requests_without_retry(self):
        self.statuses=[401,401,401]
        report=self.run_pair(self.prepare())
        self.assertEqual([r['http_status'] for r in report['results']],[401,401])
        self.assertTrue(all('coverage' not in r for r in report['results']))
        self.assertEqual(len(self.sent),3)

    def test_reference_success_cli_failure_keeps_access_gate_closed(self):
        self.statuses=[401,401,200]
        report=self.run_pair(self.prepare())
        snapshot=self.ledger.quota_status(self.policy.key_alias_for(self.policy.project_binding.project_id,'abstract_retrieval'),'abstract_retrieval')
        self.assertEqual(snapshot.reason_code,'COMPARISON_ACCESS_MISMATCH')
        self.assertEqual([r['http_status'] for r in report['results']],[401,200])

    def test_changed_source_is_rejected_before_key_or_network(self):
        source=self.prepare();data=json.loads(Path(source).read_text())
        release=json.loads(Path(json.loads(Path(data['manifest_path']).read_text())['release_evidence_path']).read_text())
        original=Path(release['comparison_source']['path'])
        original.write_bytes(original.read_bytes()+b' ')
        before=len(self.secret.aliases)
        with mock.patch.object(Path,'cwd',return_value=self.root):
            with self.assertRaises(ValidationError): self.run_pair(source)
        self.assertEqual(len(self.secret.aliases),before)
        self.assertEqual(len(self.sent),1)

    def test_http_client_builds_its_own_fixed_request_and_clears_headers(self):
        captured={}
        class Response:
            status=401
            def getheaders(self): return [('Set-Cookie',SECRET.decode()),('X-RateLimit-Limit','100')]
            def read(self,limit): return b'{}'
        class Connection:
            def __init__(self,host,port,**kwargs): captured.update(host=host,port=port,options=kwargs)
            def request(self,method,path,headers):
                captured.update(method=method,path=path,headers=headers,header_snapshot=dict(headers))
            def getresponse(self):return Response()
            def close(self): captured['closed']=True
        with mock.patch.object(comparison.http.client,'HTTPSConnection',Connection):
            r=comparison.reference_request('777','META_ABS',SECRET.decode())
        self.assertEqual((captured['host'],captured['port'],captured['method'],captured['path']),('api.elsevier.com',443,'GET','/content/abstract/scopus_id/777?view=META_ABS'))
        self.assertEqual(captured['header_snapshot']['X-ELS-APIKey'],SECRET.decode())
        self.assertEqual(captured['headers'],{})
        self.assertNotIn('set-cookie',r.headers)
        self.assertTrue(captured['closed'])

    def test_second_pair_in_window_is_denied_before_secret_lookup(self):
        failed=self.failed()
        with mock.patch.object(Path,'cwd',return_value=self.root):
            a=comparison.prepare(failed)['run_info_path']
            b=comparison.prepare(failed)['run_info_path']
        self.run_pair(a)
        before=len(self.secret.aliases)
        with self.assertRaises((LedgerError,ValidationError)):
            self.run_pair(b)
        self.assertEqual(before,len(self.secret.aliases))
        self.assertEqual(len(self.sent),3)

    def test_two_concurrent_callers_of_one_preview_send_one_pair(self):
        import threading
        source=self.prepare();reports=[];failures=[]
        def run():
            try:reports.append(self.run_pair(source))
            except ValidationError:failures.append(1)
        with mock.patch.object(Path,'cwd',return_value=self.root):
            threads=[threading.Thread(target=run) for _ in range(2)]
            for t in threads:t.start()
            for t in threads:t.join(timeout=10)
        self.assertEqual(len(reports),1)
        self.assertEqual(len(failures),1)
        self.assertEqual(len(self.sent),3)

    def test_transport_failure_stops_pair_and_uncertain_send_is_not_replayed(self):
        source=self.prepare()
        class Broken:
            def send(self,*args,**kwargs):raise RuntimeError(SECRET.decode())
        with mock.patch.object(Path,'cwd',return_value=self.root):
            report=comparison.execute(source,secret_provider=self.secret,cli_transport=Broken(),reference=lambda *a:self.fail('no second request'))
        self.assertEqual(report['status'],'incomplete')
        self.assertEqual(report['requests_attempted'],1)
        self.assertNotIn(SECRET.decode(),json.dumps(report))
        with self.assertRaises(ValidationError):self.run_pair(source)

    def test_ordinary_execute_cannot_run_comparison_as_two_detail_pages(self):
        source=self.prepare()
        code,rows=self.invoke('execute','--run-info',source,'--execute-live')
        self.assertNotEqual(code,0)
        self.assertEqual(len(self.sent),1)

    def test_raw_and_converted_author_mismatch_is_reported(self):
        from scopus_access.artifacts import ArtifactRecord
        body=json.dumps({'abstracts-retrieval-response':{'author-count':{'@total':'4'},'authors':{'author':[{'@auid':'11'},{'@auid':'11'}]}}}).encode()
        a=ArtifactRecord('1.0','run','attempt',1,'raw/a.json',hashlib.sha256(body).hexdigest(),len(body),'2030-01-01T00:00:00Z')
        report=comparison.coverage(body,a)
        self.assertFalse(report['author_count_matches'])
        self.assertEqual(report['duplicate_author_identifiers'],1)
        self.assertEqual(report['raw_nonempty_records']['abstract'],0)


    def failed_before_send(self):
        from scopus_access.errors import SecretProviderError
        source=self.prepare()
        class Unavailable:
            def get_api_key(self,alias):
                raise SecretProviderError(reason='credential_not_found',stage='credential_read',backend='macos_security_framework',system_error_code=-25300)
        with self.assertRaises(SecretProviderError):self.run_pair(source,secret_provider=Unavailable())
        return source

    def test_default_provider_uses_project_keychain_service(self):
        source=self.prepare()
        factory=mock.Mock(return_value=self.secret)
        report=self.run_pair(source,secret_provider=None,secret_provider_factory=factory)
        factory.assert_called_once_with(service_name=self.policy.keychain_service)
        self.assertEqual(report['requests_attempted'],2)

    def test_key_failure_zero_send_resumes_same_grant_and_reservation(self):
        source=self.failed_before_send()
        seeds=[r for r in self.ledger.rows('task_reservation') if r['event_seq']==1 and r['admission_reason']=='AUTHORIZED_CLIENT_COMPARISON']
        self.assertEqual(len(seeds),1)
        self.assertEqual(seeds[0]['actual_requests'],0)
        self.assertEqual(seeds[0]['reserved_remaining'],2)
        self.assertEqual(len(self.sent),1)
        report=self.run_pair(source,resume_unused=True)
        self.assertEqual(report['reservation_id'],seeds[0]['reservation_id'])
        self.assertEqual(report['requests_attempted'],2)
        self.assertEqual(len(self.sent),3)
        self.assertEqual(len([r for r in self.ledger.rows('task_reservation') if r['event_seq']==1 and r['admission_reason']=='AUTHORIZED_CLIENT_COMPARISON']),1)

    def test_unused_resume_rejects_any_started_attempt(self):
        source=self.prepare()
        class Broken:
            def send(self,*args,**kwargs):raise RuntimeError('synthetic failure')
        with mock.patch.object(Path,'cwd',return_value=self.root):
            report=comparison.execute(source,secret_provider=self.secret,cli_transport=Broken())
        self.assertEqual(report['requests_attempted'],1)
        before=len(self.secret.aliases)
        with self.assertRaises(ValidationError):self.run_pair(source,resume_unused=True)
        self.assertEqual(len(self.secret.aliases),before)

    def test_unused_resume_rejects_unlisted_raw_response(self):
        source=self.failed_before_send()
        from scopus_access.operations import context
        marker=Path(source).parent/'comparison-execution.json'
        path=json.loads(marker.read_text())['run_info_path']
        with mock.patch.object(Path,'cwd',return_value=self.root):
            _,_,_,_,store,run=context(path)
        raw=store.root/'raw'/run;raw.mkdir(parents=True,exist_ok=True)
        (raw/'unlisted.json').write_text('{}')
        before=len(self.secret.aliases)
        with self.assertRaises((ValidationError,RuntimeError)):self.run_pair(source,resume_unused=True)
        self.assertEqual(len(self.secret.aliases),before)

    def test_expired_original_grant_cannot_resume_unused_pair(self):
        source=self.failed_before_send()
        from scopus_access.manifest import ReleaseEvidence
        from scopus_access.errors import LiveCapabilityLocked
        before=len(self.secret.aliases)
        with mock.patch.object(ReleaseEvidence,'is_current',return_value=False):
            with self.assertRaises(LiveCapabilityLocked):self.run_pair(source,resume_unused=True)
        self.assertEqual(len(self.secret.aliases),before)

    def test_concurrent_unused_resume_sends_one_original_pair(self):
        import threading
        source=self.failed_before_send();reports=[];failures=[]
        def run():
            try:reports.append(self.run_pair(source,resume_unused=True))
            except ValidationError:failures.append(1)
        with mock.patch.object(Path,'cwd',return_value=self.root):
            threads=[threading.Thread(target=run) for _ in range(2)]
            for t in threads:t.start()
            for t in threads:t.join(timeout=10)
        self.assertEqual(len(reports),1)
        self.assertEqual(len(failures),1)
        self.assertEqual(len(self.sent),3)

    def test_cli_constructs_provider_with_policy_service_and_resumes_unused(self):
        import io
        from contextlib import redirect_stdout,redirect_stderr
        from scopus_access import cli
        source=self.failed_before_send()
        def reference(identifier,view,key):
            self.assertEqual((identifier,view,key),('777','META_ABS',SECRET.decode()))
            self.sent.append('independent_reference')
            return self.response(200)
        out=io.StringIO();err=io.StringIO()
        with redirect_stdout(out),redirect_stderr(err),mock.patch.object(Path,'cwd',return_value=self.root),mock.patch.object(cli,'MacOSKeychainSecretProvider',return_value=self.secret) as factory,mock.patch.object(cli,'UrllibTransport',return_value=self.wire),mock.patch.object(comparison,'reference_request',side_effect=reference):
            code=cli.main(['compare','--run-info',source,'--resume-unused','--execute-live'])
        self.assertEqual(code,0,out.getvalue())
        factory.assert_called_once_with(service_name=self.policy.keychain_service)
        rows=[json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(rows[-1]['requests_attempted'],2)
        self.assertNotIn(SECRET.decode(),out.getvalue()+err.getvalue())
