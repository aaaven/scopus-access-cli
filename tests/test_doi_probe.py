"""DOI enrichment acceptance with synthetic records, providers and sockets blocked."""
import importlib.util
import io
import json
import sqlite3
import threading
import unittest
from pathlib import Path
from unittest import mock

from scopus_access import secrets
from scopus_access.errors import ValidationError, LiveCapabilityLocked
from scopus_access.artifacts import ArtifactError
import test_local_cli as fixtures

from scopus_access import enrichment as probe

class ProbeTests(unittest.TestCase):
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        self.cwd=mock.patch.object(Path,'cwd',return_value=self.root);self.cwd.start();self.addCleanup(self.cwd.stop)
        self.no_secret=mock.patch.object(secrets.MacOSKeychainSecretProvider,'get_api_key',side_effect=AssertionError('no credential access'))
        self.no_secret.start();self.addCleanup(self.no_secret.stop)
        self.input=self.root/'restricted_metadata/scopus/saved.jsonl'
        self.row={'source_format':'scopus_api_json','source':'Elsevier/Scopus','doi':'10.1234/synthetic','title':'SYNTHETIC TEST TITLE',
            'abstract':None,'authors':None,'author_keywords':None,'index_keywords':None,'references':None,'eid':'SYNTHETIC-EID'}
        self.write_rows([self.row]);self.calls=[]
        test=self
        class Wire:
            def send(self,provider,doi,*,permit):
                test.calls.append((provider,doi))
                with sqlite3.connect(str(test.root/'.scopus-access/enrichment.sqlite')) as c:
                    count=c.execute("select count(*) from enrichment_event where kind='ATTEMPT'").fetchone()[0]
                test.assertEqual(count,len(test.calls))
                return 200,{},json.dumps(test.payload(provider,doi)).encode()
        self.wire=Wire()

    def write_rows(self,rows):self.input.write_bytes(b''.join(probe.encode(r) for r in rows))
    def payload(self,provider,doi):
        if provider=='crossref':return {'message':{'DOI':doi,'title':['SYNTHETIC TEST TITLE'],'type':'journal-article',
            'abstract':'<jats:p>SYNTHETIC ABSTRACT</jats:p>','author':[{'given':'A','family':'Example'},{'given':'B','family':'Example'}],
            'reference':[{'DOI':'10.1234/reference'}],'reference-count':1,'subject':['SYNTHETIC SUBJECT']}}
        return {'doi':'https://doi.org/'+doi,'title':'SYNTHETIC TEST TITLE','type':'article',
            'primary_location':{'version':'publishedVersion'},'abstract_inverted_index':{'SYNTHETIC':[0],'ABSTRACT':[1]},
            'authorships':[{'raw_author_name':'A Example'},{'raw_author_name':'B Example'}],
            'keywords':[{'display_name':'SYNTHETIC MODEL KEYWORD'}],'referenced_works':['https://openalex.org/W1']}
    def prepare(self,**kwargs):return probe.prepare(str(self.input),**kwargs)['run_info_path']
    def export_rows(self,report):
        return [json.loads(x) for x in (self.root/'restricted_metadata/scopus'/report['merged_ref']).read_bytes().splitlines()]
    def execute(self,source,**kwargs):return probe.execute(source,execute_live=True,transport=self.wire,**kwargs)

    def test_preview_is_offline_and_exposes_only_bounds_hashes_and_counts(self):
        preview=probe.prepare(str(self.input));self.assertEqual(preview['max_requests'],2)
        self.assertEqual(preview['scopus_requests'],0);self.assertFalse(self.calls)
        self.assertNotIn(self.row['title'],json.dumps(preview));self.assertNotIn(self.row['doi'],json.dumps(preview))
        with self.assertRaises(LiveCapabilityLocked):probe.execute(preview['run_info_path'])

    def test_fields_sources_and_original_record_are_preserved(self):
        report=self.execute(self.prepare());rows=self.export_rows(report);row=rows[0]
        self.assertEqual(row['scopus_original'],self.row)
        for f in ('abstract','authors','references'):self.assertEqual(report['field_coverage'][f]['after_nonempty'],1)
        for f in ('author_keywords','index_keywords'):self.assertEqual(report['field_coverage'][f]['after_nonempty'],0)
        self.assertEqual(row['field_provenance']['abstract']['provider'],'crossref')
        self.assertEqual(row['merged']['source_format'],'scopus_plus_doi_enrichment')
        self.assertEqual(row['merged']['abstract'],'SYNTHETIC ABSTRACT')
        self.assertEqual(report['additional_fields_nonempty']['openalex_model_keywords'],1)
        self.assertEqual(report['additional_fields_nonempty']['openalex_citation_links'],1)
        self.assertEqual(report['publisher_verified_complete_reference_lists'],0)
        self.assertEqual(report['author_counts_agree_records'],1)
        self.assertEqual(report['publisher_verified_complete_author_lists'],0)

    def test_existing_fields_are_never_overwritten_and_complete_record_costs_zero(self):
        original=dict(self.row,**{f:['SYNTHETIC EXISTING'] for f in probe.FIELDS})
        self.write_rows([original]);source=self.prepare();report=self.execute(source)
        self.assertEqual(report['requests_attempted'],0);self.assertFalse(self.calls)
        for f in probe.FIELDS:self.assertEqual(self.export_rows(report)[0]['merged'][f],original[f])

    def test_only_unsupported_keyword_gaps_do_not_trigger_useless_requests(self):
        self.write_rows([dict(self.row,abstract='SYNTHETIC EXISTING',authors=[{'name':'SYNTHETIC EXISTING'}],references=[{'DOI':'10.1234/kept'}])])
        report=self.execute(self.prepare());self.assertFalse(self.calls)
        self.assertEqual(report['field_coverage']['index_keywords']['still_missing'],1)

    def test_reference_only_gap_uses_crossref_not_openalex_links(self):
        self.write_rows([dict(self.row,abstract='SYNTHETIC EXISTING',authors=[{'name':'SYNTHETIC EXISTING'}])])
        report=self.execute(self.prepare());self.assertEqual([x[0] for x in self.calls],['crossref'])
        self.assertEqual(report['field_coverage']['references']['after_nonempty'],1)

    def test_duplicate_dois_share_calls_but_preserve_record_occurrences(self):
        self.write_rows([self.row,dict(self.row,eid='SYNTHETIC-2')])
        report=self.execute(self.prepare());self.assertEqual(len(self.calls),2)
        self.assertEqual(len(self.export_rows(report)),2)

    def test_invalid_or_missing_doi_is_retained_without_lookup(self):
        self.write_rows([dict(self.row,doi=None),dict(self.row,doi='../../bad')])
        report=self.execute(self.prepare());self.assertEqual(len(self.export_rows(report)),2);self.assertFalse(self.calls)

    def test_budget_is_bounded_and_resume_does_not_create_more_capacity(self):
        source=self.prepare(max_requests=1);report=self.execute(source)
        self.assertEqual(report['stage_status'],'budget_exhausted');self.assertEqual(len(self.calls),1)
        report=self.execute(source,resume=True);self.assertEqual(len(self.calls),1)
        self.assertEqual(report['budget_remaining'],0)

    def test_resume_after_interruption_skips_completed_task(self):
        source=self.prepare()
        def stop(number):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_task=stop)
        report=self.execute(source,resume=True)
        self.assertEqual(len(self.calls),2);self.assertEqual(report['requests_attempted'],2)
        self.assertEqual(report['stage_status'],'completed')

    def test_uncertain_attempt_is_not_resent(self):
        source=self.prepare();plan,sha,store,budget,rows,op=probe._context(source)
        budget.grant(plan,sha,False);budget.append(plan,op['tasks'][0],'ATTEMPT',code='charged')
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        self.assertFalse(self.calls)

    def test_new_batch_reuses_verified_cache_and_local_export_never_networks(self):
        first=self.execute(self.prepare());before=len(self.calls)
        source=self.prepare();second=self.execute(source)
        self.assertEqual(len(self.calls),before);self.assertEqual(second['cache_hits'],2)
        self.assertEqual(second['requests_attempted'],0)
        probe.status(source);again=probe.export(source)
        self.assertEqual(second['merged_sha256'],again['merged_sha256']);self.assertEqual(len(self.calls),before)

    def test_saved_response_corruption_blocks_cache_and_new_requests(self):
        first=self.execute(self.prepare());row=self.export_rows(first)[0]
        raw=self.root/'restricted_metadata/scopus'/row['field_provenance']['abstract']['body_ref']
        raw.write_text('{}')
        source=self.prepare();before=len(self.calls)
        with self.assertRaises(ValidationError):self.execute(source)
        self.assertEqual(len(self.calls),before)

    def test_mismatched_doi_title_or_preprint_is_kept_for_review_not_merged(self):
        for change in ({'DOI':'10.1234/other'},{'title':['SYNTHETIC COMPLETELY DIFFERENT']},{'type':'posted-content'}):
            payload=self.payload('crossref','10.1234/synthetic');payload['message'].update(change)
            n=probe.normalize('crossref',payload,self.row,'10.1234/synthetic')
            self.assertFalse(n['identity']['eligible'])

    def test_inverted_index_reconstruction_rejects_gaps_collisions_and_negative_positions(self):
        self.assertEqual(probe.abstract_from_index({'a':[0,2],'b':[1]}),'a b a')
        for value in ({'a':[0],'b':[0]},{'a':[1]},{'a':[-1]},{'a':[True]}):self.assertIsNone(probe.abstract_from_index(value))

    def test_crossref_subject_and_openalex_keywords_are_not_author_or_index_keywords(self):
        for p in probe.PROVIDERS:
            n=probe.normalize(p,self.payload(p,'10.1234/synthetic'),self.row,'10.1234/synthetic')
            self.assertIsNone(n['fields']['author_keywords']);self.assertIsNone(n['fields']['index_keywords'])
            if p=='openalex':self.assertIsNone(n['fields']['references'])

    def test_unusable_reference_stubs_and_truncated_author_lists_are_not_filled(self):
        payload=self.payload('crossref','10.1234/synthetic');payload['message']['reference']=[{'key':'SYNTHETIC-ONLY-ID'}]
        n=probe.normalize('crossref',payload,self.row,'10.1234/synthetic');self.assertIsNone(n['fields']['references'])
        payload=self.payload('openalex','10.1234/synthetic');payload['is_authors_truncated']=True
        n=probe.normalize('openalex',payload,self.row,'10.1234/synthetic');self.assertIsNone(n['fields']['authors'])

    def test_changed_input_snapshot_and_policy_block_before_send(self):
        source=self.prepare();p=json.loads(Path(source).read_text());sample=self.root/'restricted_metadata/scopus'/p['input_ref'];sample.write_text('{}')
        with self.assertRaises(ValidationError):self.execute(source)
        self.assertFalse(self.calls)

    def test_transport_failure_is_charged_once_and_does_not_retry(self):
        class Broken:
            def send(self,*args,**kwargs):raise RuntimeError('SYNTHETIC PRIVATE SERVER CONTENT')
        source=self.prepare();report=probe.execute(source,execute_live=True,transport=Broken())
        self.assertEqual(report['requests_attempted'],2)
        self.assertEqual(report['stage_status'],'completed_with_gaps')
        self.assertNotIn('SYNTHETIC PRIVATE SERVER CONTENT',json.dumps(report))
        self.assertEqual(probe.status(source)['requests_attempted'],2)

    def test_state_uses_append_only_separate_ledger_and_leaves_scopus_state_alone(self):
        before=[self.ledger.rows(name) for name in ('quota_window','request_usage','task_reservation')]
        self.execute(self.prepare())
        self.assertEqual(before,[self.ledger.rows(name) for name in ('quota_window','request_usage','task_reservation')])
        with sqlite3.connect(str(self.root/'.scopus-access/enrichment.sqlite')) as c:
            with self.assertRaises(sqlite3.IntegrityError):c.execute('DELETE FROM enrichment_event')

    def test_two_concurrent_callers_one_batch_cannot_double_send(self):
        source=self.prepare();reports=[];errors=[]
        def run():
            try:reports.append(self.execute(source))
            except ValidationError:errors.append(1)
        threads=[threading.Thread(target=run) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=10)
        self.assertEqual(len(reports),1);self.assertEqual(len(errors),1);self.assertEqual(len(self.calls),2)

    def test_http_transport_uses_only_fixed_public_hosts_and_no_credential_headers(self):
        captured=[]
        class Response:
            status=200
            def read(self,n):return b'{}'
            def getheaders(self):return [('Set-Cookie','SYNTHETIC-PRIVATE'),('X-RateLimit-Credits-Used','0')]
        class Connection:
            def __init__(self,host,port,**kwargs):captured.append({'host':host,'port':port})
            def set_debuglevel(self,n):self.n=n
            def request(self,method,path,headers):captured[-1].update(method=method,path=path,headers=headers)
            def getresponse(self):return Response()
            def close(self):pass
        with mock.patch.object(probe.http.client,'HTTPSConnection',Connection):
            t=probe._PublicTransport()
            permit=probe._SendPermit(probe._MARKER,'crossref','10.1234/synthetic','2099-01-01T00:00:00Z')
            status,headers,body=t.send('crossref','10.1234/synthetic',permit=permit)
            with self.assertRaises(LiveCapabilityLocked):t.send('crossref','10.1234/synthetic',permit=permit)
        self.assertEqual(captured[0]['host'],'api.crossref.org')
        self.assertEqual(set(captured[0]['headers']),{'Accept','User-Agent'})
        self.assertNotIn('set-cookie',headers)

    def test_execute_counts_are_not_confused_with_zero_network_local_export(self):
        report=self.execute(self.prepare())
        self.assertEqual(report['requests_attempted_this_invocation'],2)
        self.assertEqual(report['network_calls'],2)
        self.assertEqual(report['http_responses_this_invocation'],2)
        local=probe.export(report['run_info_path'])
        self.assertEqual(local['requests_attempted'],2)
        self.assertEqual(local['network_calls'],0)
        self.assertEqual(local['network_calls_scope'],'this_local_command')
        self.assertEqual(local['raw_response_field_coverage']['crossref']['abstract'],1)

    def test_cli_preview_execute_resume_status_export_are_separate_and_content_safe(self):
        from scopus_access import cli
        def call(arguments):
            out=io.StringIO()
            with mock.patch('sys.stdout',out):code=cli.main(['enrich']+arguments)
            lines=out.getvalue().splitlines();self.assertEqual(len(lines),1)
            for forbidden in (self.row['title'],self.row['doi'],'SYNTHETIC ABSTRACT','A Example','10.1234/reference'):
                self.assertNotIn(forbidden,out.getvalue())
            return code,json.loads(lines[0])
        code,preview=call(['prepare','--records',str(self.input),'--limit','10','--max-requests','2'])
        self.assertEqual(code,0);source=preview['run_info_path']
        with mock.patch.object(probe,'_PublicTransport',return_value=self.wire):
            code,dry=call(['execute','--run-info',source]);self.assertEqual(code,0)
            self.assertTrue(dry['consent_required']);self.assertFalse(self.calls)
            code,actual=call(['execute','--run-info',source,'--execute-live'])
            self.assertEqual(code,0);self.assertEqual(actual['requests_attempted'],2)
            code,resumed=call(['resume','--run-info',source,'--execute-live'])
            self.assertEqual(code,0);self.assertEqual(resumed['requests_attempted_this_invocation'],0)
        with mock.patch.object(probe,'_PublicTransport',side_effect=AssertionError('offline commands')):
            for action in ('status','export'):
                code,local=call([action,'--run-info',source]);self.assertEqual(code,0)
                self.assertEqual(local['network_calls'],0)
        self.assertEqual(len(self.calls),2)

    def test_corrupt_control_json_does_not_echo_data_or_claim_zero_after_execution(self):
        from scopus_access import cli
        source=self.prepare();Path(source).write_text('SYNTHETIC PRIVATE INVALID CONTROL')
        for action in ('execute','status'):
            out=io.StringIO()
            with mock.patch('sys.stdout',out):
                code=cli.main(['enrich',action,'--run-info',source]+(['--execute-live'] if action=='execute' else []))
            self.assertNotEqual(code,0);self.assertNotIn('SYNTHETIC PRIVATE',out.getvalue())
            self.assertIsNone(json.loads(out.getvalue())['network_calls']) if action=='execute' else self.assertEqual(json.loads(out.getvalue())['network_calls'],0)

    def test_expired_grant_is_not_renewed_or_replayed(self):
        from scopus_access.errors import ReleaseExpired
        source=self.prepare()
        def stop(number):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_task=stop)
        with mock.patch.object(probe,'utc_now',return_value='2099-01-01T00:00:00Z'):
            with self.assertRaises(ReleaseExpired):self.execute(source,resume=True)
        self.assertEqual(len(self.calls),1)

    def test_zero_budget_cache_only_batch_cannot_make_requests_on_miss(self):
        source=self.prepare(max_requests=0);report=self.execute(source)
        self.assertEqual(report['stage_status'],'budget_exhausted');self.assertFalse(self.calls)
        self.execute(self.prepare());n=len(self.calls)
        source=self.prepare(max_requests=0);report=self.execute(source)
        self.assertEqual(report['stage_status'],'completed');self.assertEqual(report['cache_hits'],2)
        self.assertEqual(report['network_calls'],0);self.assertEqual(len(self.calls),n)

    def test_evidence_schema_and_identity_changes_block_before_send(self):
        source=self.prepare()
        with sqlite3.connect(str(self.root/'.scopus-access/enrichment.sqlite')) as c:
            c.execute('DROP TRIGGER no_delete_enrichment_event')
        with self.assertRaises(ValidationError):self.execute(source)
        self.assertFalse(self.calls)

    def test_failed_provider_stops_remaining_calls_but_other_provider_is_independent(self):
        self.write_rows([self.row,dict(self.row,doi='10.1234/second')]);source=self.prepare()
        class Denied:
            def send(inner,provider,doi,*,permit):
                self.calls.append((provider,doi))
                return (429,{},b'{}') if provider=='crossref' else (200,{},json.dumps(self.payload(provider,doi)).encode())
        report=probe.execute(source,execute_live=True,transport=Denied())
        self.assertEqual([p for p,d in self.calls],['crossref','openalex','openalex'])
        self.assertEqual(report['requests_attempted'],3);self.assertEqual(report['failed_or_skipped_tasks'],2)
        self.assertEqual(report['stage_status'],'completed_with_gaps')
        again=probe.execute(source,execute_live=True,resume=True,transport=Denied())
        self.assertEqual(len(self.calls),3);self.assertEqual(again['requests_attempted_this_invocation'],0)

    def test_changed_policy_or_wrong_project_and_symlink_paths_do_not_fall_back(self):
        source=self.prepare();policy=self.root/'.scopus-access/policy.json'
        policy.write_bytes(policy.read_bytes()+b'\n')
        with self.assertRaises(ValidationError):self.execute(source)
        self.assertFalse(self.calls)

    def test_cache_and_control_files_have_no_secret_or_bibliographic_payload(self):
        source=self.prepare();self.execute(source)
        control=self.root/'.scopus-access'
        for path in control.rglob('*'):
            if not path.is_file():continue
            raw=path.read_bytes()
            for value in (b'SYNTHETIC TEST TITLE',b'SYNTHETIC ABSTRACT',b'10.1234/synthetic',b'SYNTHETIC MODEL KEYWORD',b'SYNTHETIC_LOCAL_KEY'):
                self.assertNotIn(value,raw)

    def test_missing_configuration_does_not_borrow_tool_or_other_project(self):
        with mock.patch.object(probe,'discover_project_policy',return_value=None):
            with self.assertRaises(ValidationError) as error:probe.prepare(str(self.input))
        self.assertEqual(error.exception.code,'PROJECT_NOT_INITIALIZED');self.assertFalse(self.calls)

    def test_two_processes_share_one_grant_and_send_each_task_at_most_once(self):
        import multiprocessing
        source=self.prepare()
        def run():
            try:self.execute(source)
            except ValidationError:raise SystemExit(2)
        processes=[multiprocessing.get_context('fork').Process(target=run) for _ in range(2)]
        for child in processes:child.start()
        for child in processes:
            child.join(15)
            if child.is_alive():child.terminate();child.join();self.fail('enrichment process did not exit')
        self.assertEqual(sorted(x.exitcode for x in processes),[0,2])
        self.assertEqual(probe.status(source)['requests_attempted'],2)

    def test_two_processes_in_different_batches_share_response_cache(self):
        import multiprocessing
        sources=[self.prepare(),self.prepare()]
        def run(source):self.execute(source)
        processes=[multiprocessing.get_context('fork').Process(target=run,args=(s,)) for s in sources]
        for child in processes:child.start()
        for child in processes:
            child.join(15)
            if child.is_alive():child.terminate();child.join();self.fail('enrichment cache process did not exit')
        self.assertEqual([x.exitcode for x in processes],[0,0])
        self.assertEqual(sum(probe.status(s)['requests_attempted'] for s in sources),2)
        self.assertEqual(sum(probe.status(s)['cache_hits'] for s in sources),2)

    def test_symlink_input_and_run_info_escape_are_rejected(self):
        source=self.prepare();link=self.input.parent/'linked.jsonl';link.symlink_to(self.input)
        with self.assertRaises((ValidationError,ArtifactError)):probe.prepare(str(link))
        linked=Path(source).parent/'linked-run.json';linked.symlink_to(source)
        with self.assertRaises((ValidationError,ArtifactError)):self.execute(str(linked))
        self.assertFalse(self.calls)
