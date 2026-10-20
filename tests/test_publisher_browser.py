"""Optional browser wiring with a synthetic renderer and stateless mock wire."""
import copy
import json
import multiprocessing
import os
import sqlite3
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scopus_access import publisher_browser as browser, secrets
from scopus_access.errors import ValidationError, LiveCapabilityLocked
import test_local_cli as fixtures
from test_publisher_html_probe import page as synthetic_page


class Renderer:
    def __init__(self,requests=None,hook=None):
        self.contexts=[]; self.requests=requests or [('document',None),('script','https://link.springer.com/synthetic.js')]
        self.hook=hook
    @contextmanager
    def factory(self): yield self
    def new_context(self,**kwargs):
        c=Context(self,kwargs); self.contexts.append(c); return c


class Context:
    def __init__(self,owner,kwargs):self.owner=owner;self.options=kwargs;self.order=[];self.handlers={};self.routes=[];self.closed=False
    def route(self,pattern,callback):self.callback=callback;self.order.append('route')
    def route_web_socket(self,pattern,callback):self.websocket=callback;self.order.append('websocket')
    def add_init_script(self,**kwargs):self.script=kwargs['script'];self.order.append('init')
    def on(self,name,callback):self.handlers[name]=callback
    def new_page(self):self.order.append('page');self.page=Page(self);return self.page
    def close(self):self.closed=True


class Page:
    def __init__(self,context):self.context=context;self.main_frame=SimpleNamespace(page=self);self.handlers={};self.closed=False
    def on(self,name,callback):self.handlers[name]=callback
    def close(self):self.closed=True
    def goto(self,url,**kwargs):
        for kind,value in self.context.owner.requests:
            req=SimpleNamespace(url=value or url,resource_type=kind,frame=self.main_frame,method='GET')
            route=Route(req);self.context.routes.append(route);self.context.callback(route)
        if self.context.owner.hook:self.context.owner.hook(self.context,self)
    def content(self):return synthetic_page().decode()+'<!-- SYNTHETIC RENDERED DOM -->'


class Route:
    def __init__(self,request):self.request=request;self.aborted=False;self.fulfilled=None
    def abort(self):self.aborted=True
    def fulfill(self,**kwargs):self.fulfilled=kwargs


class BrowserTests(unittest.TestCase):
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        patch=mock.patch.object(Path,'cwd',return_value=self.root);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(secrets.MacOSKeychainSecretProvider,'get_api_key',side_effect=AssertionError('no real credentials'))
        patch.start();self.addCleanup(patch.stop)
        self.records=self.root/'restricted_metadata/scopus/browser-input.jsonl'
        self.base={'source_format':'scopus_api_json','doi':'10.1234/synthetic0','title':'SYNTHETIC TITLE','abstract':'SYNTHETIC API ABSTRACT',
            'authors':None,'author_keywords':None,'index_keywords':None,'references':None}
        self.records.write_bytes(browser.api.encode(self.base))
        self.targets=self.root/'restricted_metadata/scopus/browser-targets.json'
        self.page={'sample_id':'D0001','url':'https://link.springer.com/article/10.1234/synthetic0','domains':['link.springer.com']}
        self.targets.write_bytes(browser.api.encode([self.page]));self.calls=[];self.renderer=Renderer();test=self
        class Wire:
            def send(self,task,*,permit):
                permit.claim(task);test.calls.append(copy.deepcopy(task))
                with sqlite3.connect(str(test.root/'.scopus-access/publisher-browser.sqlite')) as c:
                    count=c.execute("SELECT COUNT(*) FROM enrichment_event WHERE kind='ATTEMPT'").fetchone()[0]
                test.assertEqual(count,len(test.calls))
                if task['resource_type']=='robots':return 200,{'content-type':'text/plain'},b'User-agent: *\nAllow: /\n'
                if task['resource_type']=='document':return 200,{'content-type':'text/html','set-cookie':'SYNTHETIC SECRET'},synthetic_page()
                return 200,{'content-type':'text/javascript'},b'/* SYNTHETIC SCRIPT */'
        self.wire=Wire()
    def prepare(self,**kwargs):
        return browser.prepare(self.records,self.targets,max_requests=kwargs.pop('max_requests',10),max_requests_per_page=kwargs.pop('max_requests_per_page',8),**kwargs)['run_info_path']
    def execute(self,source,**kwargs):
        return browser.execute(source,execute_live=True,browser_factory=self.renderer.factory,transport=self.wire,**kwargs)
    def output(self,result):return json.loads((self.root/'restricted_metadata/scopus'/result['merged_ref']).read_bytes().splitlines()[0])
    def events(self,source):return browser._context(source)[3].events(browser._context(source)[0]['run_id'])

    def test_preview_bounds_and_identity_reuse_are_offline(self):
        source=self.prepare();again=self.prepare();self.assertEqual(source,again);self.assertFalse(self.calls)
        with self.assertRaises(ValidationError):self.prepare(max_requests=11)
        with self.assertRaises(LiveCapabilityLocked):browser.execute(source)
        report=browser.status(source)
        self.assertNotIn(self.base['title'],json.dumps(report));self.assertNotIn(self.page['url'],json.dumps(report))
        self.assertEqual(report['max_robots_requests'],1)

    def test_success_caches_both_html_and_preserves_api_source(self):
        source=self.prepare();result=self.execute(source);row=self.output(result)
        self.assertEqual(result['requests_attempted'],3);self.assertEqual(result['stage_status'],'completed')
        self.assertEqual(result['robots_requests'],1);self.assertEqual(result['requests_by_page']['D0001'],2)
        self.assertEqual(row['merged']['abstract'],self.base['abstract'])
        self.assertEqual(row['field_provenance']['abstract']['provider'],'scopus')
        self.assertEqual(row['merged']['author_keywords'],['SYNTHETIC TERM']);self.assertIsNone(row['merged']['index_keywords'])
        self.assertEqual(set(row['publisher_candidates']),{'document','rendered'})
        self.assertEqual(row['field_provenance']['author_keywords']['provider'],'publisher_html')
        c=self.renderer.contexts[0];self.assertEqual(c.order[:4],['route','websocket','init','page'])
        self.assertEqual(c.options['service_workers'],'block');self.assertTrue(c.options['offline'])
        self.assertTrue(c.closed)
        for e in self.events(source):self.assertNotIn('SYNTHETIC',json.dumps(e))
        for p in (self.root/'restricted_metadata/scopus/enrichment/publisher-browser').rglob('metadata.json'):
            self.assertNotIn('set-cookie',p.read_text());self.assertNotIn('SYNTHETIC SECRET',p.read_text())

    def test_completed_resume_and_export_never_reload_or_increase_grant(self):
        source=self.prepare();first=self.execute(source);before=len(self.calls)
        again=self.execute(source,resume=True);self.assertEqual(len(self.calls),before)
        self.assertEqual(first['merged_sha256'],again['merged_sha256']);self.assertEqual(again['network_calls'],0)
        self.assertEqual(browser.export(source)['merged_sha256'],first['merged_sha256'])
        with self.assertRaises(ValidationError):self.execute(source)

    def test_every_resource_and_repeated_url_is_charged(self):
        self.renderer.requests=[('document',None)]+[(kind,'https://link.springer.com/same') for kind in sorted(browser.TYPES-{'document'})]
        source=self.prepare(max_requests=30,max_requests_per_page=20);result=self.execute(source)
        self.assertEqual(result['requests_attempted'],1+len(browser.TYPES));self.assertEqual(len(self.calls),result['requests_attempted'])
        self.assertEqual(len([e for e in self.events(source) if e['kind']=='RESULT']),len(self.calls))

    def _exhaust_budget(self,total,perpage):
        source=self.prepare(max_requests=total,max_requests_per_page=perpage);result=self.execute(source)
        self.assertEqual(len(self.calls),2);self.assertTrue(self.renderer.contexts[0].routes[-1].aborted)
        self.assertEqual(result['requests_by_page']['D0001'],1)
        self.assertEqual(len([e for e in self.events(source) if e['kind']=='SKIP']),1)

    def test_total_budget_exhaustion_blocks_send(self):self._exhaust_budget(2,8)

    def test_per_page_budget_exhaustion_blocks_send(self):self._exhaust_budget(10,1)

    def test_exact_host_navigation_post_popup_and_websocket_are_blocked(self):
        self.renderer.requests=[('document',None),('fetch','https://evil.invalid/synthetic'),('document','https://link.springer.com/redirect')]
        ws=SimpleNamespace(close=mock.Mock());popup=SimpleNamespace(close=mock.Mock())
        def hook(context,page):
            context.websocket(ws);context.handlers['page'](popup)
            req=SimpleNamespace(url=self.page['url'],resource_type='fetch',frame=page.main_frame,method='POST')
            context.callback(Route(req))
        self.renderer.hook=hook
        source=self.prepare();result=self.execute(source)
        self.assertEqual(len(self.calls),2);self.assertEqual(result['blocked_browser_callbacks'],5)
        self.assertTrue(ws.close.called);self.assertTrue(popup.close.called)
        self.assertEqual(len([e for e in self.events(source) if e['kind']=='SKIP']),5)

    def test_redirect_is_saved_but_never_fulfilled_or_followed(self):
        self.renderer.requests=[('document',None)];original=self.wire.send
        def wire(task,*,permit):
            result=original(task,permit=permit)
            return (302,{'location':'https://evil.invalid/'},b'') if task['resource_type']=='document' else result
        self.wire.send=wire;source=self.prepare();result=self.execute(source)
        route=self.renderer.contexts[0].routes[0];self.assertTrue(route.aborted);self.assertIsNone(route.fulfilled)
        self.assertEqual(result['saved_pages'],0);self.assertEqual(len(self.calls),2)

    def test_robots_unavailable_or_disallowed_never_launches(self):
        original=self.wire.send
        def wire(task,*,permit):
            original(task,permit=permit);return 200,{'content-type':'text/plain'},b'User-agent: *\nDisallow: /\n'
        self.wire.send=wire;source=self.prepare();result=self.execute(source)
        self.assertEqual(result['stage_status'],'completed_with_gaps');self.assertEqual(len(self.calls),1)
        self.assertFalse(self.renderer.contexts)

    def test_crash_after_attempt_response_save_or_result_refuses_replay(self):
        source=self.prepare()
        def stop(stage):
            if stage=='after_response':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        count=len(self.calls)
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        self.assertEqual(count,len(self.calls));self.assertEqual(browser.status(source)['stage_status'],'activity_unresolved')

    def test_before_admission_crash_can_resume_proven_zero_send(self):
        source=self.prepare()
        def stop(stage):
            if stage=='before_admit':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        self.assertFalse(self.calls);result=self.execute(source,resume=True)
        self.assertEqual(result['requests_attempted'],3)

    def test_saved_page_receipt_interruption_is_fail_closed(self):
        source=self.prepare()
        def stop(stage):
            if stage=='after_page_save':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        count=len(self.calls)
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        self.assertEqual(count,len(self.calls))

    def _crash_then_replay_denied(self,checkpoint,resource='robots'):
        source=self.prepare()
        def stop(stage):
            if stage==checkpoint and ((checkpoint=='after_attempt' and not self.calls) or (self.calls and self.calls[-1]['resource_type']==resource)):raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        before=len(self.calls)
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        self.assertEqual(before,len(self.calls))

    def test_crash_after_attempt_does_not_send_on_resume(self):self._crash_then_replay_denied('after_attempt')

    def test_crash_after_response_save_before_terminal_refuses_replay(self):self._crash_then_replay_denied('after_save')

    def test_crash_after_document_result_before_dom_save_refuses_reload(self):self._crash_then_replay_denied('after_result','document')

    def test_completed_page_survives_interrupted_return(self):
        source=self.prepare()
        def stop(stage):
            if stage=='after_page_receipt':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        count=len(self.calls);result=self.execute(source,resume=True)
        self.assertEqual(result['stage_status'],'completed');self.assertEqual(count,len(self.calls))

    def test_robots_completed_before_interruption_are_never_resent(self):
        source=self.prepare()
        def stop(stage):
            if stage=='after_result':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_stage=stop)
        result=self.execute(source,resume=True)
        self.assertEqual(result['requests_attempted'],3);self.assertEqual(sum(c['resource_type']=='robots' for c in self.calls),1)

    def test_reordered_identical_scope_reuses_run_and_budget(self):
        second=dict(self.page,sample_id='D0002',url='https://link.springer.com/article/10.1234/synthetic1')
        self.records.write_bytes(b''.join(browser.api.encode(r) for r in (self.base,dict(self.base,doi='10.1234/synthetic1'))))
        self.targets.write_bytes(browser.api.encode([self.page,second]));source=self.prepare()
        self.targets.write_bytes(browser.api.encode([second,self.page]));self.assertEqual(self.prepare(),source)

    def test_merged_without_provenance_is_rejected_before_dispatch(self):
        self.records.write_bytes(browser.api.encode({'sample_id':'D0001','merged':self.base,'field_provenance':None}))
        with self.assertRaises(ValidationError):self.prepare()
        self.assertFalse(self.calls)

    def test_completed_response_host_or_robots_binding_change_is_rejected(self):
        source=self.prepare();self.execute(source);plan,sha,store,budget,rows,operation=browser._context(source)
        event=next(e for e in self.events(source) if e['kind']=='RESULT')
        ref=store.root/event['receipt_ref'];data=json.loads(ref.read_bytes());data['host']='evil.invalid';ref.write_bytes(browser.api.encode(data))
        with self.assertRaises(ValidationError):browser.status(source)
        with self.assertRaises(ValidationError):self.execute(source,resume=True)

    def test_two_real_processes_compete_for_one_original_run(self):
        source=self.prepare();plan,sha,store,budget,rows,operation=browser._context(source);budget.grant(plan,sha,False)
        trace=self.root/'restricted_metadata/scopus/process-wire.txt';original=self.wire.send
        def wire(task,*,permit):
            result=original(task,permit=permit)
            descriptor=os.open(str(trace),os.O_APPEND|os.O_CREAT|os.O_WRONLY,0o600)
            try:os.write(descriptor,b'SYNTHETIC_REQUEST\n')
            finally:os.close(descriptor)
            return result
        self.wire.send=wire
        def run(number):
            result=self.execute(source,resume=True)
            (self.root/('process-result-%d.json'%number)).write_bytes(browser.api.encode({'status':result['stage_status']}))
        ctx=multiprocessing.get_context('fork');children=[ctx.Process(target=run,args=(n,)) for n in range(2)]
        for child in children:child.start()
        for child in children:child.join(20);self.assertEqual(child.exitcode,0)
        self.assertEqual(len(trace.read_bytes().splitlines()),3)
        self.assertEqual(browser.status(source)['requests_attempted'],3)

    def test_tampered_cache_response_and_budget_are_rejected(self):
        source=self.prepare();self.execute(source);plan,sha,store,budget,rows,operation=browser._context(source)
        dom=store.root/browser._root(plan)/'pages/D0001/rendered.html';dom.write_bytes(b'SYNTHETIC CORRUPT')
        with self.assertRaises(ValidationError):browser.export(source)
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        plan['max_requests']=100;plan['provider_limits']['D0001']=100;plan['max_requests_per_page']=100
        Path(source).write_bytes(browser.api.encode(plan))
        with self.assertRaises(ValidationError):browser.status(source)

    def test_auth_queries_invalid_domains_and_outside_paths_are_rejected(self):
        for query in ('?token=SYNTHETIC','?%74oken=SYNTHETIC','?x=1&api_key=SYNTHETIC',
                      '?auth_token=SYNTHETIC','?session_id=SYNTHETIC','?jwt=SYNTHETIC',
                      '?bearer=SYNTHETIC','?client_secret=SYNTHETIC'):
            with self.assertRaises(ValidationError):browser._url(self.page['url']+query,self.page['domains'])
        for url in ('http://link.springer.com/','https://u:p@link.springer.com/','https://link.springer.com:444/','https://evil.invalid/'):
            with self.assertRaises(ValidationError):browser._url(url,self.page['domains'])
        self.page['domains']=['*.springer.com'];self.targets.write_bytes(browser.api.encode([self.page]))
        with self.assertRaises(ValidationError):self.prepare()

    def test_missing_optional_dependency_fails_before_http_and_grant(self):
        source=self.prepare()
        with mock.patch.object(browser,'_playwright_api',side_effect=ValidationError('SYNTHETIC UNAVAILABLE')):
            with self.assertRaises(ValidationError):browser.execute(source,execute_live=True,transport=self.wire)
        self.assertFalse(self.calls);self.assertFalse(self.events(source))
        browser.status(source);browser.export(source)

    def test_transport_fixed_headers_and_no_redirect_or_cookie(self):
        response=SimpleNamespace(status=302,read=lambda n:b'SYNTHETIC',getheaders=lambda:[('Set-Cookie','SYNTHETIC SECRET'),('Location','https://evil.invalid'),('Content-Type','text/html')])
        conn=mock.Mock();conn.getresponse.return_value=response
        task={'url':self.page['url'],'request_sha256':'a'*64}
        permit=browser.DispatchPermit(browser._MARKER,task,'2099-01-01T00:00:00Z')
        with mock.patch.object(browser.http.client,'HTTPSConnection',return_value=conn):
            status,headers,body=browser.Transport().send(task,permit=permit)
        self.assertEqual(status,302);self.assertEqual(headers,{'content-type':'text/html'})
        self.assertEqual(conn.request.call_args.kwargs['headers'],browser._HEADERS)
        self.assertEqual(conn.request.call_count,1);self.assertTrue(conn.close.called)

    def test_competing_callers_serialize_and_completed_page_is_not_resent(self):
        source=self.prepare();errors=[];results=[]
        def run():
            try:results.append(self.execute(source,resume=True))
            except BaseException as e:errors.append(e)
        # Create the original grant, then race two resumes under the same project lock.
        plan,sha,store,budget,rows,operation=browser._context(source);budget.grant(plan,sha,False)
        threads=[threading.Thread(target=run) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(20)
        self.assertFalse(errors);self.assertEqual(len(results),2);self.assertEqual(len(self.calls),3)
        self.assertEqual(len(self.renderer.contexts),1)
