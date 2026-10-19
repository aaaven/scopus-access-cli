"""Min-and-continue, atomic accounting and zero-request historical repair."""
import dataclasses
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from scopus_access import ledger as ledger_module
from scopus_access.ledger import LedgerError
from scopus_access.quota import QuotaState, evaluate_headers
import test_ledger_quota as ledger_fixtures
import test_local_cli as cli_fixtures


def legacy_headers(headers, observed, previous=None):
    result=evaluate_headers(headers,observed,previous)
    if (result.valid and previous is not None and previous.reset_at_utc==result.reset_at_utc
            and previous.effective_remaining is not None and result.remaining>previous.effective_remaining):
        return dataclasses.replace(result,valid=False,reason_code='RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING',
                                   limit=None,remaining=None,reset_at_utc=None,window_id_changed=False)
    return result


class MinLedgerTests(unittest.TestCase):
    setUp=ledger_fixtures.LedgerQuotaTests.setUp
    tearDown=ledger_fixtures.LedgerQuotaTests.tearDown
    seed=ledger_fixtures.LedgerQuotaTests.seed
    next_flow=ledger_fixtures.LedgerQuotaTests.next_flow
    admit_one=ledger_fixtures.LedgerQuotaTests.admit_one

    def test_numeric_comparisons_keep_server_observation_and_selected_floor(self):
        for server,local in ((19995,19994),(99,98),(90,98),(98,98),(0,98)):
            with self.subTest(server=server,local=local):
                self.tearDown()
                self.setUp()
                limit=20000 if local>100 else 100
                self.seed('scopus_search',limit=limit,remaining=local+1)
                admission=self.ledger._admit_task('project-alpha','task','run','release','a'*64,
                    [ledger_fixtures.requirement('scopus_search',2)],ledger_fixtures.OBSERVED,
                    expected_api_key_alias='institutional-primary')
                self.assertTrue(admission.admitted)
                attempt=self.ledger.record_request_attempt(admission.buckets[0].reservation_id,'search','page-1',0,ledger_fixtures.OBSERVED)
                before=self.ledger.quota_status('institutional-primary','scopus_search')
                self.assertEqual(before.effective_remaining,local)
                result=self.ledger.record_response(attempt.attempt_id,200,ledger_fixtures.headers(limit,server),'b'*64,1,ledger_fixtures.OBSERVED)
                after=self.ledger.quota_status('institutional-primary','scopus_search')
                self.assertEqual(after.server_remaining,server)
                self.assertEqual(after.effective_remaining,min(server,local))
                self.assertEqual(after.committed_in_progress,1)
                self.assertEqual(after.free_to_admit,0 if server==0 else min(server,local)-1)
                self.assertNotEqual(result.quota_state,QuotaState.QUOTA_TELEMETRY_UNKNOWN)
                if not server: self.assertEqual(result.quota_state,QuotaState.QUOTA_EXHAUSTED)
                self.assertEqual(after.reconciliation_predecessor,before.record_id)

    def test_out_of_order_responses_and_repeated_high_values_do_not_refill(self):
        reservation=self.admit_one(3,0)
        first=self.ledger.record_request_attempt(reservation,'search','p1',0,ledger_fixtures.OBSERVED)
        second=self.ledger.record_request_attempt(reservation,'search','p2',0,ledger_fixtures.OBSERVED)
        for attempt,server in ((second,98),(first,100)):
            self.ledger.record_response(attempt.attempt_id,200,ledger_fixtures.headers(100,server),'b'*64,1,ledger_fixtures.OBSERVED)
            self.assertEqual(self.ledger.quota_status('institutional-primary','scopus_search').effective_remaining,98)
        third=self.ledger.record_request_attempt(reservation,'search','p3',0,ledger_fixtures.OBSERVED)
        self.ledger.record_response(third.attempt_id,200,ledger_fixtures.headers(100,100),'b'*64,1,ledger_fixtures.OBSERVED)
        snapshot=self.ledger.quota_status('institutional-primary','scopus_search')
        self.assertEqual((snapshot.effective_remaining,snapshot.committed_in_progress,snapshot.free_to_admit),(97,0,97))
        history=[r for r in self.ledger.rows('request_usage') if r['reservation_id']==reservation]
        self.assertEqual(sum(r['record_kind']=='ATTEMPT' for r in history),3)
        self.assertEqual(sum(r['record_kind']=='OUTCOME' for r in history),3)

    def test_concurrent_outcomes_keep_all_charges_and_unspent_reservations_once(self):
        reservation=self.admit_one(10,0)
        attempts=[self.ledger.record_request_attempt(reservation,'search','p%d'%i,0,ledger_fixtures.OBSERVED) for i in range(8)]
        def finish(attempt):
            return self.ledger.record_response(attempt.attempt_id,200,ledger_fixtures.headers(100,100),'b'*64,1,ledger_fixtures.OBSERVED)
        with ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(finish,attempts))
        self.assertTrue(all(r.reconciled_remaining==92 for r in results))
        snapshot=self.ledger.quota_status('institutional-primary','scopus_search')
        self.assertEqual((snapshot.effective_remaining,snapshot.committed_in_progress,snapshot.free_to_admit),(92,2,90))
        self.assertEqual(snapshot.server_remaining,100)

    def test_missing_local_floor_and_changed_window_are_not_numeric_merges(self):
        baseline=self.seed('scopus_search')
        unavailable=dataclasses.replace(baseline,effective_remaining=None)
        self.assertEqual(evaluate_headers(ledger_fixtures.headers(),ledger_fixtures.OBSERVED,unavailable).reason_code,'RATE_LIMIT_LOCAL_ACCOUNTING_UNAVAILABLE')
        changed=evaluate_headers(ledger_fixtures.headers(reset=ledger_fixtures.RESET_2100+3600),ledger_fixtures.OBSERVED,baseline)
        self.assertFalse(changed.valid)
        self.assertEqual(changed.reason_code,'RATE_LIMIT_WINDOW_CHANGED_EARLY')


class MinCliTests(unittest.TestCase):
    setUp=cli_fixtures.LocalCliTests.setUp
    invoke=cli_fixtures.LocalCliTests.invoke
    check=cli_fixtures.LocalCliTests.check

    def cached_wire(self):
        original=self.wire.send
        def send(request,**kwargs):
            return dataclasses.replace(original(request,**kwargs),headers={
                'X-RateLimit-Limit':'100','X-RateLimit-Remaining':'99','X-RateLimit-Reset':'2000000000'})
        self.wire.send=send

    def pause_legacy(self,budget=3):
        self.check()
        self.wire.total=3
        self.cached_wire()
        with mock.patch.object(ledger_module,'evaluate_headers',side_effect=legacy_headers):
            code,rows=self.invoke('search','--query-file',str(self.query),'--max-requests',str(budget),'--page-size','1','--execute-live')
        self.assertEqual(code,5,rows)
        self.assertEqual(next(r for r in rows if r.get('event')=='run_completed')['stop_reason'],'quota_telemetry_unknown')
        return rows[0]['run_info_path']

    def test_three_pages_continue_automatically_on_same_window_numeric_difference(self):
        self.check()
        self.wire.total=3
        self.cached_wire()
        code,rows=self.invoke('search','--query-file',str(self.query),'--max-requests','3','--page-size','1','--execute-live')
        self.assertEqual(code,0,rows)
        completion=next(r for r in rows if r.get('event')=='run_completed')
        self.assertEqual(completion['pages_completed'],3)
        self.assertEqual(completion['requests_attempted'],3)
        self.assertFalse(any(r.get('event')=='paused' for r in rows))
        merged=[r for r in rows if r.get('event')=='quota_telemetry' and r['telemetry_reason']=='RATE_LIMIT_BALANCE_MIN_APPLIED']
        self.assertEqual([r['reconciled_remaining'] for r in merged],[98,97,96])
        self.assertTrue(all(r['quota_remaining']==99 for r in merged))
        self.assertEqual(len(self.wire.urls),4)  # one baseline + original three-page budget
        seeds=[r for r in self.ledger.rows('task_reservation') if r['event_seq']==1]
        self.assertEqual(len(seeds),2)
        self.assertFalse(any(r['admission_reason']=='AUTHORIZED_BOUNDED_DIAGNOSTIC' for r in seeds))

    def test_historical_reconciliation_is_offline_append_only_and_idempotent(self):
        source=self.pause_legacy()
        history={name:self.ledger.rows(name) for name in ('task_reservation','request_usage','quota_window','quota_event')}
        raw_files={p:p.read_bytes() for p in (self.root/'restricted_metadata').rglob('*') if p.is_file()}
        code,rows=self.invoke('reconcile','--run-info',source,local=True)
        self.assertEqual(code,0,rows)
        self.assertTrue(rows[0]['changed'])
        self.assertTrue(rows[0]['can_resume'])
        self.assertEqual(rows[0]['reconciled_remaining'],98)
        for name,old in history.items():
            after=self.ledger.rows(name)
            self.assertEqual(after[:len(old)],old)
            self.assertEqual(len(after)-len(old),1 if name=='quota_window' else 0)
        code,rows=self.invoke('reconcile','--run-info',source,local=True)
        self.assertEqual(code,0,rows)
        self.assertFalse(rows[0]['changed'])
        self.assertEqual(len(self.ledger.rows('quota_window')),len(history['quota_window'])+1)
        self.assertEqual(len(self.wire.urls),2)
        for p,raw in raw_files.items(): self.assertEqual(p.read_bytes(),raw)

    def test_resume_repairs_legacy_pause_and_only_fetches_remaining_pages(self):
        source=self.pause_legacy()
        saved={p:p.read_bytes() for p in (self.root/'restricted_metadata').rglob('*.json') if '/raw/' in str(p)}
        code,rows=self.invoke('resume','--run-info',source,'--execute-live')
        self.assertEqual(code,0,rows)
        self.assertEqual(rows[0]['command'],'reconcile')
        self.assertEqual(next(r for r in rows if r.get('event')=='run_completed')['pages_completed'],3)
        self.assertEqual(len(self.wire.urls),4)
        for p,raw in saved.items(): self.assertEqual(p.read_bytes(),raw)
        self.assertFalse(any(r.get('event')=='paused' for r in rows))

    def test_budget_exhausted_diagnostic_is_reconciled_without_new_allowance(self):
        source=self.pause_legacy(budget=1)
        code,rows=self.invoke('reconcile','--run-info',source,local=True)
        self.assertEqual(code,0,rows)
        self.assertEqual(rows[0]['reserved_remaining'],0)
        self.assertFalse(rows[0]['can_resume'])
        code,_=self.invoke('resume','--run-info',source,'--execute-live')
        self.assertNotEqual(code,0)
        self.assertEqual(len(self.wire.urls),2)

    def test_retained_raw_tamper_refuses_repair(self):
        source=self.pause_legacy()
        from scopus_access.operations import context
        with mock.patch.object(Path,'cwd',return_value=self.root):
            info,policy,manifest,ledger,store,run=context(source)
        record=store.load_response_records(run)[0]
        path=store.root/record.artifact_ref
        path.write_bytes(path.read_bytes()+b' ')
        before=self.ledger.rows('quota_window')
        code,_=self.invoke('reconcile','--run-info',source,local=True)
        self.assertNotEqual(code,0)
        self.assertEqual(self.ledger.rows('quota_window'),before)

    def test_expired_window_is_not_repaired_from_old_headers(self):
        source=self.pause_legacy()
        with mock.patch.object(ledger_module,'utc_now',return_value='2100-01-01T00:00:00Z'):
            code,rows=self.invoke('reconcile','--run-info',source,local=True)
        self.assertNotEqual(code,0)
        self.assertEqual(rows[-1]['code'],'RETAINED_RECONCILIATION_WINDOW_EXPIRED')
        self.assertEqual(len(self.wire.urls),2)

    def test_later_access_failure_is_not_unblocked_by_older_numeric_evidence(self):
        source=self.pause_legacy()
        self.wire.status=401
        self.invoke('check','--query-file',str(self.query),'--execute-live')
        code,rows=self.invoke('reconcile','--run-info',source,local=True)
        self.assertNotEqual(code,0)
        self.assertEqual(rows[-1]['code'],'RETAINED_RECONCILIATION_NOT_LATEST_NUMERIC_PAUSE')
        self.assertEqual(len(self.wire.urls),3)

    def test_expired_grant_can_reconcile_offline_but_cannot_resume_network(self):
        source=self.pause_legacy()
        from scopus_access.manifest import ReleaseEvidence
        with mock.patch.object(ReleaseEvidence,'has_expired',return_value=True):
            code,rows=self.invoke('reconcile','--run-info',source,local=True)
            self.assertEqual(code,0,rows)
            self.assertTrue(rows[0]['authorization_expired'])
            self.assertFalse(rows[0]['can_resume'])
            code,rows=self.invoke('resume','--run-info',source,'--execute-live',local=True)
        self.assertNotEqual(code,0)
        self.assertEqual(rows[-1]['code'],'RELEASE_EXPIRED')
        self.assertEqual(len(self.wire.urls),2)
