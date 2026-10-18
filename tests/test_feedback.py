"""F01-F05 acceptance with mock credentials and transport; all data synthetic."""
import dataclasses
import hashlib
import io
import json
import os
import shlex
import sys
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scopus_access import cli, terminal_run
from scopus_access.client import TransportResponse
from scopus_access.diagnostics import quota_diagnostic, service_diagnostic
from scopus_access.terminal_init import TerminalInitError
from scopus_access.artifacts import RestrictedArtifactStore
import test_local_cli as fixtures


class FeedbackTests(unittest.TestCase):
    setUp=fixtures.LocalCliTests.setUp
    invoke=fixtures.LocalCliTests.invoke
    check=fixtures.LocalCliTests.check

    def headers(self, sent=1):
        if not hasattr(self,'reset_epoch'): self.reset_epoch=int(time.time())+3600
        return {'X-RateLimit-Limit':'100000','X-RateLimit-Remaining':str(100000-sent),
                'X-RateLimit-Reset':str(self.reset_epoch)}

    def wrap_headers(self, headers):
        original=self.wire.send
        def send(request,**kwargs):
            response=original(request,**kwargs)
            return dataclasses.replace(response,headers=headers)
        self.wire.send=send

    def telemetry(self,headers,reason):
        self.wrap_headers(headers)
        code,rows=self.invoke('check','--query-file',str(self.query),'--execute-live')
        record=next(r for r in rows if r.get('event')=='quota_telemetry')
        self.assertEqual(record['telemetry_reason'],reason)
        source=rows[0]['run_info_path']
        code,state=self.invoke('inspect','--run-info',source,local=True)
        self.assertEqual(code,0,state)
        self.assertEqual(state[0]['telemetry']['telemetry_reason'],reason)
        self.assertEqual(state[0]['pages_saved'],1)
        self.assertFalse(state[0]['initialization_required'])
        if reason!='RATE_LIMIT_HEADERS_VALID': self.assertEqual(rows[-1]['stop_reason'],'quota_telemetry_unknown')
        return state[0],record

    def test_quota_normal_and_mixed_case_are_valid(self):
        self.telemetry({k.swapcase():v for k,v in self.headers().items()},'RATE_LIMIT_HEADERS_VALID')

    def test_quota_missing_headers_save_data_and_report_presence(self):
        state,record=self.telemetry({'X-RateLimit-Limit':'100000','Set-Cookie':fixtures.SECRET.decode()},'RATE_LIMIT_HEADERS_MISSING')
        self.assertEqual(record['limit_status'],'valid')
        self.assertEqual(record['remaining_status'],'missing')
        self.assertTrue(state['result_set_exhausted'])
        self.assertEqual(state['quota_state'],'QUOTA_TELEMETRY_UNKNOWN')
        self.assertTrue(state['diagnostic_allowed'])
        self.assertFalse(state['diagnostic_used'])

    def test_quota_bad_value_is_not_missing_or_exhausted(self):
        headers=self.headers();headers['X-RateLimit-Remaining']='n/a '+fixtures.SECRET.decode()
        _,record=self.telemetry(headers,'RATE_LIMIT_HEADERS_INVALID')
        self.assertEqual(record['remaining_status'],'invalid')

    def test_quota_stale_reset_reports_clock_evidence(self):
        headers=self.headers();headers['X-RateLimit-Reset']='1'
        _,record=self.telemetry(headers,'RATE_LIMIT_RESET_STALE')
        self.assertEqual(record['reset_status'],'stale')
        self.assertGreater(record['observed_epoch'],1)

    def test_quota_inconsistent_remaining_is_explicit(self):
        headers=self.headers();headers['X-RateLimit-Remaining']='100001'
        self.telemetry(headers,'RATE_LIMIT_HEADERS_CONTRADICTORY')

    def test_quota_parser_bounded_values_and_unknown_fields_never_copy_content(self):
        for value in ('-1','inf','99999999999999999999999999999999999999',fixtures.SECRET.decode()):
            headers=self.headers();headers['X-RateLimit-Reset']=value
            record,values=quota_diagnostic(headers,time.time())
            self.assertIsNone(values)
            self.assertEqual(record['reset_status'],'invalid')
            self.assertNotIn(value,json.dumps(record))

    def test_two_unknown_responses_report_diagnostic_used_and_no_third_request(self):
        self.wrap_headers({})
        for _ in range(2):
            code,rows=self.invoke('check','--query-file',str(self.query),'--execute-live')
            self.assertEqual(code,5,rows)
        source=rows[0]['run_info_path']
        code,state=self.invoke('inspect','--run-info',source,local=True)
        self.assertTrue(state[0]['diagnostic_used'])
        self.assertFalse(state[0]['diagnostic_allowed'])
        self.assertIn('review_telemetry_or_contact_provider',state[0]['next_actions'])
        code,rows=self.invoke('check','--query-file',str(self.query),'--execute-live',local=True)
        self.assertEqual(code,4,rows)
        self.assertEqual(len(self.wire.urls),2)

    def test_http_400_codes_safe_limits_and_parameter_revision_preserve_evidence(self):
        self.check()
        original=self.wire.send
        payload={'service-error':{'status':{'statusCode':'INVALID_INPUT','statusText':'Requested count 200 exceeds maximum 25'}}}
        def bad(request,**kwargs):
            response=original(request,**kwargs)
            return dataclasses.replace(response,status=400,body=json.dumps(payload).encode())
        self.wire.send=bad
        code,rows=self.invoke('search','--query-file',str(self.query),'--execute-live')
        self.assertEqual(code,6,rows)
        source=rows[0]['run_info_path']; before=Path(source).read_bytes()
        info=json.loads(before); old_task=Path(info['manifest_path']).read_bytes()
        error=next(r for r in rows if r.get('event')=='service_error')
        self.assertEqual(error['remote_error_code'],'invalid_input')
        self.assertEqual(error['error_parameter'],'count')
        self.assertEqual(error['service_max_count'],25)
        self.assertEqual(len(self.wire.urls),2)
        code,revised=self.invoke('revise','--run-info',source,'--page-size','25',local=True)
        self.assertEqual(code,0,revised)
        self.assertEqual(revised[0]['new_page_size'],25)
        self.assertEqual(Path(source).read_bytes(),before)
        self.assertEqual(Path(info['manifest_path']).read_bytes(),old_task)
        new=json.loads(Path(revised[0]['run_info_path']).read_text())
        self.assertNotEqual(new['task_id'],info['task_id'])
        self.assertEqual(new['mode'],'preview')
        task=json.loads(Path(new['manifest_path']).read_text())
        package=json.loads(Path(task['query_manifest_path']).read_text())
        self.assertEqual(package['queries']['scopus_search']['query'],fixtures.QUERY)
        self.assertTrue((Path(new['manifest_path']).parent/'parameter-version.json').exists())
        self.assertEqual(len(self.wire.urls),2)

    def test_remote_errors_never_copy_arbitrary_details_or_guess_maximum(self):
        for code,expected in [('INVALID_QUERY','query_syntax'),('INVALID_COUNT','invalid_parameter'),('AUTHORIZATION_ERROR','access')]:
            body=json.dumps({'service-error':{'status':{'statusCode':code,'statusText':fixtures.SECRET.decode()+' '+fixtures.QUERY+' bearer unsafe'}}}).encode()
            result=service_diagnostic(body)
            self.assertEqual(result['error_category'],expected)
            self.assertNotIn('service_max_count',result)
            self.assertNotIn(fixtures.SECRET.decode(),json.dumps(result))
            self.assertNotIn(fixtures.QUERY,json.dumps(result))
        self.assertEqual(service_diagnostic(b'<invalid>')['remote_error_code'],'unclassified')
        xml=b'<service-error><status><statusCode>INVALID_QUERY</statusCode><statusText>private text</statusText></status></service-error>'
        self.assertEqual(service_diagnostic(xml)['error_category'],'query_syntax')
        self.assertEqual(service_diagnostic(b'<!DOCTYPE x [<!ENTITY x "unsafe">]><error-response/>')['remote_error_code'],'unclassified')

    def prepared_after_terminal_failure(self):
        _,rows=self.invoke('check','--query-file',str(self.query),local=True)
        preview=rows[0]['run_info_path']
        with mock.patch.object(terminal_run,'_launch',side_effect=TerminalInitError('TERMINAL_OPEN_FAILED')):
            code,rows=self.invoke('execute','--run-info',preview,'--execute-live','--terminal',local=True)
        self.assertNotEqual(code,0,rows)
        self.assertIsNone(rows[-1]['network_calls'])
        return rows[0]['run_info_path']

    def test_public_start_uses_prepared_grant_once_without_readmission(self):
        source=self.prepared_after_terminal_failure()
        before=Path(source).read_bytes()
        code,rows=self.invoke('inspect','--run-info',source,local=True)
        self.assertEqual(rows[0]['phase'],'prepared_not_admitted')
        self.assertTrue(rows[0]['can_start'])
        with mock.patch('scopus_access.fetch._approve_preview',side_effect=AssertionError('no new grant')):
            code,rows=self.invoke('start','--run-info',source,'--execute-live')
        self.assertEqual(code,0,rows)
        self.assertEqual(Path(source).read_bytes(),before)
        code,rows=self.invoke('start','--run-info',source,'--execute-live',local=True)
        self.assertEqual(code,2,rows)
        self.assertEqual(rows[-1]['code'],'EXECUTION_ALREADY_STARTED')
        self.assertEqual(len(self.wire.urls),1)

    def test_start_requires_consent_and_refuses_unresolved_local_evidence(self):
        source=self.prepared_after_terminal_failure()
        code,rows=self.invoke('start','--run-info',source,local=True)
        self.assertEqual(code,2,rows)
        info=json.loads(Path(source).read_text())
        from scopus_access.security import execution_run_id
        run=execution_run_id(info['project_id'],info['task_id'],info['release_id'],info['parent_run_id'],info['api_name'])
        path=self.policy.control_database_path.parent/'events'/(run+'.jsonl')
        path.parent.mkdir(exist_ok=True)
        path.write_text('{}\n')
        code,rows=self.invoke('start','--run-info',source,'--execute-live',local=True)
        self.assertNotEqual(code,0,rows)
        self.assertFalse(self.wire.urls)

    def cursor_wire(self,total):
        self.total=total; self.starts=[]
        def send(request,**kwargs):
            assert request.headers['X-ELS-APIKey']==fixtures.SECRET.decode()
            params=parse_qs(urlsplit(request.url).query)
            token=params.get('cursor',['*'])[0]
            start=0 if token=='*' else int(token.removeprefix('p'))
            count=int(params['count'][0]); end=min(start+count,self.total)
            self.starts.append(start); self.wire.urls.append(request.url)
            body={'search-results':{'entry':[{'eid':'SYNTHETIC-%d'%i,'dc:title':fixtures.TITLE} for i in range(start,end)],
                  'opensearch:totalResults':str(self.total),'opensearch:startIndex':str(start),
                  'cursor':{'@next':('p%d'%end) if end<self.total else token}}}
            return TransportResponse(200,self.headers(len(self.wire.urls)),json.dumps(body).encode())
        self.wire.send=send

    def test_cursor_formal_budget_exports_more_than_5000_with_explicit_sort(self):
        self.wrap_headers(self.headers()); self.check()
        self.cursor_wire(5039)
        code,rows=self.invoke('search','--query-file',str(self.query),'--pagination','cursor','--max-requests','26','--page-size','200','--sort=-coverDate','--execute-live')
        self.assertEqual(code,0,rows)
        self.assertEqual(self.starts,list(range(0,5039,200)))
        source=rows[0]['run_info_path']
        code,report=self.invoke('audit','--run-info',source,local=True)
        self.assertEqual(code,0,report)
        self.assertEqual(report[0]['records'],5039)
        self.assertEqual(report[0]['duplicate_occurrences'],0)
        self.assertTrue(report[0]['observed_pages_consistent'])
        self.assertEqual(report[0]['result_set_status'],'exhausted')
        self.assertFalse(report[0]['snapshot_stability_verified'])
        before=len(self.wire.urls)
        code,rows=self.invoke('resume','--run-info',source,'--execute-live',local=True)
        self.assertNotEqual(code,0,rows)
        self.assertEqual(len(self.wire.urls),before)

    def test_request_budget_exhaustion_is_partial_and_cannot_be_expanded_by_resume(self):
        self.wrap_headers(self.headers()); self.check()
        self.cursor_wire(5039)
        code,rows=self.invoke('search','--query-file',str(self.query),'--pagination','cursor','--max-requests','2','--page-size','200','--execute-live')
        self.assertEqual(code,5,rows)
        source=rows[0]['run_info_path']
        self.assertEqual(next(r for r in rows if r.get('event')=='run_completed')['completeness'],'partial')
        code,report=self.invoke('audit','--run-info',source,local=True)
        self.assertEqual(report[0]['result_set_status'],'budget_exhausted')
        self.assertFalse(report[0]['observed_pages_consistent'])
        before=len(self.wire.urls)
        code,rows=self.invoke('resume','--run-info',source,'--execute-live',local=True)
        self.assertNotEqual(code,0,rows)
        self.assertEqual(len(self.wire.urls),before)

    def test_complete_view_is_explicit_bounded_and_never_silently_downgraded(self):
        self.check()
        code,rows=self.invoke('search','--query-file',str(self.query),'--view','COMPLETE','--page-size','200',local=True)
        self.assertEqual(code,2,rows)
        before=len(self.wire.urls)
        code,rows=self.invoke('search','--query-file',str(self.query),'--view','COMPLETE',local=True)
        self.assertEqual(code,0,rows)
        self.assertEqual(rows[0]['page_size'],25)
        self.wire.status=403
        code,rows=self.invoke('execute','--run-info',rows[0]['run_info_path'],'--execute-live')
        self.assertEqual(code,6,rows)
        self.assertEqual(len(self.wire.urls),before+1)
        self.assertEqual(parse_qs(urlsplit(self.wire.urls[-1]).query)['view'],['COMPLETE'])

    def test_local_metadata_coverage_and_detail_profile_are_actual_values(self):
        identifiers=self.root/'restricted_metadata/ids.json'
        identifiers.write_text(json.dumps(['SYNTHETIC-DETAIL']))
        def detail(request,**kwargs):
            self.wire.urls.append(request.url)
            body={'abstracts-retrieval-response':{'coredata':{'dc:identifier':'SYNTHETIC-DETAIL','dc:title':fixtures.TITLE,'dc:description':'SYNTHETIC_ABSTRACT'},
                  'authors':{'author':[{'ce:indexed-name':'SYNTHETIC_AUTHOR'}]},'authkeywords':{'author-keyword':[{'$':'SYNTHETIC_KEYWORD'}]},
                  'idxterms':{'mainterm':[{'$':'SYNTHETIC_INDEX'}]},'item':{'bibrecord':{'tail':{'bibliography':{'reference':[{'ref-info':{'ref-title':'SYNTHETIC_REFERENCE'}}]}}}}}}
            return TransportResponse(200,self.headers(len(self.wire.urls)),json.dumps(body).encode())
        self.wire.send=detail
        code,rows=self.invoke('details','--identifiers-file',str(identifiers),'--view','FULL','--check',local=True)
        self.assertEqual(code,0,rows)
        self.assertEqual(rows[0]['entitlement_status'],'unverified')
        self.assertFalse(self.wire.urls)
        code,rows=self.invoke('execute','--run-info',rows[0]['run_info_path'],'--execute-live')
        self.assertEqual(code,0,rows)
        source=rows[0]['run_info_path']
        code,report=self.invoke('audit','--run-info',source,local=True)
        self.assertEqual(code,0,report)
        for name in ('abstract','authors','author_keywords','index_keywords','references'):
            self.assertEqual(report[0]['field_coverage'][name]['nonempty_records'],1)
        self.assertEqual(report[0]['source_format'],'scopus_api_json')
        self.assertEqual(report[0]['references_completeness'],'not_verified')
        self.assertEqual(len(self.wire.urls),1)

    def test_telemetry_recovery_never_resends_saved_page_or_expands_original_budget(self):
        self.wrap_headers(self.headers()); self.check()
        self.cursor_wire(3)
        original=self.wire.send
        def pause_once(request,**kwargs):
            response=original(request,**kwargs)
            return dataclasses.replace(response,headers={}) if len(self.starts)==1 else response
        self.wire.send=pause_once
        code,rows=self.invoke('search','--query-file',str(self.query),'--pagination','cursor','--max-requests','3','--page-size','1','--execute-live')
        self.assertEqual(code,5,rows)
        source=rows[0]['run_info_path']; info=json.loads(Path(source).read_text())
        self.assertEqual(self.starts,[0])
        # This is a newly, explicitly approved minimal diagnostic, not a retry.
        # It remains an offset check, so temporarily restore the fixture wire.
        self.wire.send=fixtures.Wire(self.ledger).send
        diagwire=self.wire.send.__self__
        diagwire.urls=self.wire.urls
        old_send=self.wire.send
        def diagnostic(request,**kwargs):
            response=old_send(request,**kwargs)
            return dataclasses.replace(response,headers=self.headers(len(self.wire.urls)))
        self.wire.send=diagnostic
        code,rows=self.invoke('check','--query-file',str(self.query),'--execute-live')
        self.assertEqual(code,0,rows)
        self.wire.send=original
        code,rows=self.invoke('resume','--run-info',source,'--execute-live')
        self.assertEqual(code,0,rows)
        self.assertEqual(self.starts,[0,1,2])
        seeds=[r for r in self.ledger.rows('task_reservation') if r['event_seq']==1 and r['run_id']==info['parent_run_id']]
        self.assertEqual(len(seeds),1)
        self.assertEqual(seeds[0]['estimated_requests_with_margin'],3)

    def test_audit_reports_repeated_identifiers_total_drift_and_offset_gap(self):
        self.wrap_headers(self.headers());self.check()
        self.cursor_wire(40)
        original=self.wire.send
        def drift(request,**kwargs):
            response=original(request,**kwargs)
            if self.starts[-1]:
                payload=json.loads(response.body)
                payload['search-results']['entry'][0]['eid']='SYNTHETIC-0'
                payload['search-results']['opensearch:totalResults']='41'
                payload['search-results']['opensearch:startIndex']='30'
                return dataclasses.replace(response,body=json.dumps(payload).encode())
            return response
        self.wire.send=drift
        code,rows=self.invoke('search','--query-file',str(self.query),'--pagination','cursor','--max-requests','2','--page-size','25','--execute-live')
        self.assertEqual(code,0,rows)
        code,report=self.invoke('audit','--run-info',rows[0]['run_info_path'],local=True)
        self.assertEqual(code,0,report)
        self.assertEqual(report[0]['duplicate_occurrences'],1)
        self.assertFalse(report[0]['offsets_contiguous'])
        self.assertFalse(report[0]['totals_consistent'])
        self.assertFalse(report[0]['observed_pages_consistent'])

    def test_late_terminal_child_cannot_send_after_public_start_has_completed(self):
        source=self.prepared_after_terminal_failure()
        # Use a fresh explicit terminal handoff for the already prepared reference,
        # but lose its IPC result. The child may still start later.
        original=terminal_run.run_in_terminal
        commands=[]
        def handoff(args): return original(args,timeout=0)
        with mock.patch.object(terminal_run,'run_in_terminal',side_effect=handoff), mock.patch.object(terminal_run,'_launch',side_effect=commands.append):
            code,rows=self.invoke('start','--run-info',source,'--execute-live','--terminal',local=True)
        self.assertEqual(code,6,rows)
        self.assertIsNone(rows[-1]['network_calls'])
        code,rows=self.invoke('start','--run-info',source,'--execute-live')
        self.assertEqual(code,0,rows)
        with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()),mock.patch.object(Path,'cwd',return_value=self.root),mock.patch.object(os,'chdir'),mock.patch.object(sys.stdin,'isatty',return_value=True),mock.patch.object(cli,'MacOSKeychainSecretProvider',side_effect=AssertionError('no second key read')):
            child=terminal_run.child_main(shlex.split(commands[0])[-6:])
        self.assertEqual(child,2)
        self.assertEqual(len(self.wire.urls),1)

    def test_missing_metadata_is_zero_coverage_not_a_filled_csv_column(self):
        source=self.check()
        code,rows=self.invoke('audit','--run-info',source,local=True)
        self.assertEqual(code,0,rows)
        for field in ('abstract','authors','author_keywords','index_keywords','references'):
            self.assertEqual(rows[0]['field_coverage'][field]['nonempty_records'],0)
            self.assertEqual(rows[0]['field_coverage'][field]['availability'],'unavailable_in_saved_records')
        self.assertEqual(rows[0]['entitlement_status'],'not_inferred_from_missing_fields')
        code,caps=self.invoke('capabilities','--records','5039',local=True)
        self.assertEqual(code,0,caps)
        self.assertEqual(caps[0]['estimated_complete_requests'],202)
        self.assertTrue(caps[0]['references_may_require_additional_requests'])
