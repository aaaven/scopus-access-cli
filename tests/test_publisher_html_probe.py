"""Synthetic-only offline acceptance for the experimental script, not the CLI."""
import copy
import importlib.util
import io
import json
import sqlite3
import threading
import unittest
from pathlib import Path
from unittest import mock
from scopus_access.errors import ValidationError,LiveCapabilityLocked
from scopus_access import secrets
import test_local_cli as fixtures

spec=importlib.util.spec_from_file_location('html_probe',Path(__file__).resolve().parent.parent/'scripts/publisher_html_probe.py')
html=importlib.util.module_from_spec(spec);spec.loader.exec_module(html)


def page(doi='10.1234/synthetic0',title='SYNTHETIC TITLE',extra=''):
    return ('<html><head><meta name="citation_doi" content="'+doi+'"><meta name="citation_title" content="'+title+'">'
        '<meta name="citation_author" content="A Example"><meta name="citation_author" content="B Example"></head><body>'
        '<section id="Abs1"><h2>Abstract</h2><p>SYNTHETIC FULL ABSTRACT</p></section>'
        '<section id="keywords"><h2>Author Keywords</h2><ul><li>SYNTHETIC TERM</li></ul></section>'
        '<section id="Bib1"><h2>References (2)</h2><ol><li><p>1. A Example (2020). SYNTHETIC FULL REFERENCE. Journal 1, 2.</p></li>'
        '<li><p>2. B Example (2021). SYNTHETIC OTHER REFERENCE. Journal 2, 3.</p></li></ol></section>'+extra+'</body></html>').encode()


class HTMLProbeTests(unittest.TestCase):
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        self.cwd=mock.patch.object(Path,'cwd',return_value=self.root);self.cwd.start();self.addCleanup(self.cwd.stop)
        self.secret=mock.patch.object(secrets.MacOSKeychainSecretProvider,'get_api_key',side_effect=AssertionError('no credentials'))
        self.secret.start();self.addCleanup(self.secret.stop)
        self.rows=[{'sample_id':'D%04d'%(i+1),'doi_normalized':'10.1234/synthetic%d'%i,
            'merged':{'source_format':'scopus_plus_doi_enrichment','doi':'10.1234/synthetic%d'%i,'title':'SYNTHETIC TITLE',
                'abstract':None,'authors':None,'author_keywords':None,'index_keywords':None,'references':None},
            'field_provenance':{f:{'provider':None} for f in html.FIELDS}} for i in range(10)]
        self.calls=[];test=self
        class Wire:
            def send(inner,task,*,permit):
                permit.claim(task);test.calls.append(task)
                return (200,{'content-type':'text/plain'},b'User-agent: *\nAllow: /\n') if task['kind']=='robots' else (
                    200,{'content-type':'text/html'},page(test.rows[int(task['sample_id'][1:])-1]['doi_normalized']))
        self.wire=Wire()
    def prepare(self,rows=None):
        pages=[{'kind':'page','sample_id':r['sample_id'],'url':'https://link.springer.com/chapter/'+r['doi_normalized'],'source':'synthetic'} for r in self.rows]
        return html._plan(html.with_robots(pages),rows or self.rows,'html_'+html.uuid.uuid4().hex,1,baseline={'synthetic':True})['run_info_path']
    def execute(self,source,**kwargs):return html.execute(source,execute_live=True,transport=self.wire,**kwargs)
    def exported(self,report):return [json.loads(x) for x in (self.root/'restricted_metadata/scopus'/report['merged_ref']).read_bytes().splitlines()]
    def parsed(self,body=None):return html.parse_html(body or page(),self.rows[0]['merged'],'https://link.springer.com/chapter/10.1234/synthetic0')

    def test_explicit_author_keywords_abstract_authors_and_textual_references_have_paths(self):
        c=self.parsed();self.assertTrue(c['identity']['eligible'])
        self.assertEqual(c['fields']['author_keywords'],['SYNTHETIC TERM']);self.assertIsNone(c['fields']['index_keywords'])
        self.assertEqual(c['checks']['authors_returned'],2);self.assertEqual(len(c['fields']['references']),2)
        self.assertTrue(c['checks']['reference_count_matches_declared'])
        self.assertEqual(c['methods']['authors'],'structured_highwire')

    def test_structured_fields_have_priority_and_seo_description_is_not_a_full_abstract(self):
        body=page().replace(b'</head>',b'<meta name="citation_abstract" content="SYNTHETIC STRUCTURED ABSTRACT"></head>')
        self.assertEqual(self.parsed(body)['fields']['abstract'],'SYNTHETIC STRUCTURED ABSTRACT')
        body=b'<html><head><meta name="description" content="SYNTHETIC SEO EXCERPT"></head></html>'
        self.assertIsNone(self.parsed(body)['fields']['abstract'])

    def test_generic_keywords_subjects_and_jsonld_keywords_are_not_author_or_scopus_keywords(self):
        body=page().replace(b'Author Keywords',b'Keywords').replace(b'</head>',b'<meta name="keywords" content="SYNTHETIC SEO"><meta name="dc.subject" content="SYNTHETIC SUBJECT"></head>')
        c=self.parsed(body);self.assertIsNone(c['fields']['author_keywords']);self.assertIsNone(c['fields']['index_keywords'])
        self.assertEqual(len(c['publisher_keywords_unclassified']),3)

    def test_matching_jsonld_graph_only_and_url_citations_are_not_bibliography(self):
        graph={'@graph':[{'@type':['ScholarlyArticle'],'identifier':'10.1234/wrong','abstract':'SYNTHETIC WRONG'},
            {'@type':['ScholarlyArticle'],'identifier':{'value':'10.1234/synthetic0'},'headline':'SYNTHETIC TITLE',
             'abstract':'SYNTHETIC RIGHT','keywords':['SYNTHETIC MODEL'],'citation':['https://doi.org/10.1234/ref']}]}
        body=('<html><head><script type="application/ld+json">'+json.dumps(graph)+'</script></head></html>').encode()
        c=self.parsed(body);self.assertEqual(c['fields']['abstract'],'SYNTHETIC RIGHT');self.assertIsNone(c['fields']['references'])
        self.assertTrue(c['identity']['eligible']);self.assertIsNone(c['fields']['author_keywords'])

    def test_bad_doi_title_or_submitted_version_requires_review(self):
        for b in (page('10.1234/wrong'),page(title='SYNTHETIC DIFFERENT RECORD'),page().replace(b'</head>',b'<meta name="citation_version" content="submittedVersion"></head>')):
            self.assertFalse(self.parsed(b)['identity']['eligible'])

    def test_truncated_authors_and_reference_load_more_are_reported(self):
        c=self.parsed(page().replace(b'A Example',b'A Example et al.').replace(b'</section></body>',b'<button>Load more references</button></section></body>'))
        self.assertIsNone(c['fields']['authors']);self.assertTrue(c['checks']['known_author_truncation'])
        self.assertTrue(c['checks']['reference_load_more_detected'])

    def test_doi_only_reference_links_are_not_counted_as_textual_bibliography(self):
        body=page().replace(b'1. A Example (2020). SYNTHETIC FULL REFERENCE. Journal 1, 2.',b'https://doi.org/10.1234/only')
        self.assertEqual(len(self.parsed(body)['fields']['references']),1)

    def test_preview_has_separate_thirty_request_envelope_and_requires_execution_consent(self):
        source=self.prepare();plan,ps,store,budget,op=html.context(source)
        self.assertEqual(plan['trial_max_requests'],30);self.assertEqual(plan['max_requests'],15)
        self.assertEqual(len(op['tasks']),11);self.assertFalse(self.calls)
        with self.assertRaises(LiveCapabilityLocked):html.execute(source)

    def test_execute_saves_html_provenance_increment_and_never_overwrites_api_fields(self):
        rows=copy.deepcopy(self.rows);rows[0]['merged']['abstract']='SYNTHETIC API ABSTRACT'
        source=self.prepare(rows);report=self.execute(source);export=self.exported(report)
        self.assertEqual(len(self.calls),11);self.assertEqual(report['requests_attempted'],11)
        self.assertEqual(report['field_coverage']['abstract']['newly_filled'],9)
        self.assertEqual(export[0]['merged']['abstract'],'SYNTHETIC API ABSTRACT')
        self.assertEqual(report['field_coverage']['author_keywords']['newly_filled'],10)
        self.assertEqual(report['field_coverage']['index_keywords']['newly_filled'],0)
        self.assertEqual(report['publisher_fulltext_verified_complete_reference_lists'],0)
        self.assertEqual(export[0]['api_baseline'],rows[0])
        self.assertEqual(export[0]['merged']['missing_fields'],['index_keywords'])
        self.assertEqual(export[0]['merged']['conversion_version'],html.VERSION)

    def test_robots_disallow_or_unavailable_stops_without_page_requests(self):
        class Disallow:
            def send(inner,task,*,permit):self.calls.append(task);return 200,{},b'User-agent: *\nDisallow: /\n'
        report=html.execute(self.prepare(),execute_live=True,transport=Disallow())
        self.assertEqual(len(self.calls),1);self.assertEqual(report['page_requests'],0)
        self.assertEqual(report['page_outcomes']['robots_disallowed'],10)

    def test_redirects_are_saved_and_never_automatically_followed(self):
        class Redirect:
            def send(inner,task,*,permit):
                self.calls.append(task)
                return (404,{},b'') if task['kind']=='robots' else (301,{'location':task['url'].replace('link.springer.com','link.springernature.com')},b'SYNTHETIC REDIRECT')
        source=self.prepare();report=html.execute(source,execute_live=True,transport=Redirect())
        self.assertEqual(len(self.calls),11);self.assertEqual(report['html_200_records'],0)
        self.assertTrue(all(html.urlsplit(t['url']).hostname=='link.springer.com' for t in self.calls))
        targets=[{'sample_id':r['sample_id'],'url':'https://link.springernature.com/chapter/'+r['doi_normalized']} for r in self.rows]
        path=self.root/'restricted_metadata/scopus/reviewed.json';path.write_text(json.dumps(targets))
        follow=html.prepare_reviewed(source,str(path))['run_info_path']
        report=self.execute(follow)
        self.assertEqual(report['requests_attempted'],22);self.assertLessEqual(report['requests_attempted'],30)
        self.assertEqual(report['page_requests'],20);self.assertEqual(report['html_200_records'],10)
        with self.assertRaises(ValidationError):html.prepare_reviewed(follow,str(path))

    def test_resume_does_not_resend_completed_pages_or_expand_budget(self):
        source=self.prepare()
        def stop(i):
            if i==3:raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(source,after_task=stop)
        report=self.execute(source,resume=True);self.assertEqual(len(self.calls),11)
        self.assertEqual(report['requests_attempted'],11)
        self.execute(source,resume=True);self.assertEqual(len(self.calls),11)

    def test_uncertain_attempt_does_not_replay(self):
        source=self.prepare();p,ps,store,budget,op=html.context(source);budget.grant(p,ps,False)
        budget.append(p,op['tasks'][0],'ATTEMPT',code='charged')
        with self.assertRaises(ValidationError):self.execute(source,resume=True)
        self.assertFalse(self.calls)

    def test_changed_frozen_plan_or_response_is_rejected(self):
        source=self.prepare();report=self.execute(source);row=self.exported(report)[0]
        ref=row['publisher_candidates'][0]['source']['response']['body_ref']
        (self.root/'restricted_metadata/scopus'/ref).write_bytes(b'changed')
        with self.assertRaises(ValidationError):html.analyze(source)

    def test_two_concurrent_callers_one_phase_cannot_double_send(self):
        source=self.prepare();success=[];errors=[]
        def run():
            try:success.append(self.execute(source))
            except ValidationError:errors.append(1)
        threads=[threading.Thread(target=run) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(15)
        self.assertEqual(len(success),1);self.assertEqual(len(errors),1);self.assertEqual(len(self.calls),11)

    def test_transport_has_no_redirect_cookie_auth_or_arbitrary_host_capability(self):
        source=self.prepare();p,ps,s,b,op=html.context(source);task=op['tasks'][0];captured=[]
        class Response:
            status=302
            def read(self,n):return b'SYNTHETIC REDIRECT'
            def getheaders(self):return [('Location','https://www.nature.com/other'),('Set-Cookie','SYNTHETIC PRIVATE COOKIE')]
        class Connection:
            def __init__(self,host,port,**kw):captured.append((host,port))
            def set_debuglevel(self,n):pass
            def request(self,method,path,headers):self_headers.append(headers)
            def getresponse(self):return Response()
            def close(self):pass
        self_headers=[]
        with mock.patch.object(html.http.client,'HTTPSConnection',Connection):
            permit=html.Permit(html._PERMIT_MARKER,task,'2099-01-01T00:00:00Z')
            status,headers,body=html.Transport().send(task,permit=permit)
            with self.assertRaises(LiveCapabilityLocked):html.Transport().send(task,permit=permit)
        self.assertEqual(len(captured),1);self.assertEqual(set(self_headers[0]),{'Accept','User-Agent'})
        self.assertNotIn('set-cookie',headers)
        for url in ('https://evil.invalid/a','http://link.springer.com/a','https://link.springer.com/a?apiKey=SYNTHETIC','https://u:p@link.springer.com/a'):
            with self.assertRaises(ValidationError):html.safe_url(url)

    def test_control_output_and_ledger_contain_no_bibliographic_or_secret_content(self):
        source=self.prepare();self.execute(source);out=io.StringIO()
        with mock.patch('sys.stdout',out):code=html.main(['analyze','--run-info',source])
        self.assertEqual(code,0)
        for p in list((self.root/'.scopus-access').rglob('*'))+[None]:
            data=p.read_bytes() if p is not None and p.is_file() else out.getvalue().encode() if p is None else b''
            for forbidden in (b'SYNTHETIC TITLE',b'SYNTHETIC FULL ABSTRACT',b'SYNTHETIC TERM',b'SYNTHETIC FULL REFERENCE',b'SYNTHETIC_LOCAL_KEY'):
                self.assertNotIn(forbidden,data)

    def test_http200_forwarding_shell_is_not_an_article_and_only_explicit_review_can_prepare_target(self):
        b=b'<html><head><meta http-equiv="refresh" content="0;URL=https://www.sciencedirect.com/science/article/pii/SYNTHETIC"><meta name="tdm-reservation" content="1"></head></html>'
        c=self.parsed(b);self.assertFalse(c['identity']['eligible']);self.assertEqual(c['checks']['document_kind'],'publisher_forwarding_shell')
        self.assertEqual(c['checks']['tdm_reservation_metadata'],['1'])
        class Shell:
            def send(inner,t,*,permit):
                self.calls.append(t)
                return (404,{},b'') if t['kind']=='robots' else (200,{'content-type':'text/html'},b)
        source=self.prepare();html.execute(source,execute_live=True,transport=Shell())
        self.assertEqual(len(self.calls),11)
        targets=self.root/'restricted_metadata/scopus/targets.json'
        targets.write_text(json.dumps([{'sample_id':'D0001','url':'https://www.sciencedirect.com/science/article/pii/SYNTHETIC'}]))
        # Different publisher families cannot be substituted for the original Springer page.
        with self.assertRaises(ValidationError):html.prepare_reviewed(source,str(targets))

        # A same-publisher, explicitly selected target is preparable without any request.
        pages=[{'kind':'page','sample_id':r['sample_id'],'url':'https://linkinghub.elsevier.com/retrieve/pii/SYNTHETIC'+r['sample_id'],'source':'synthetic'} for r in self.rows]
        parent=html._plan(html.with_robots(pages),self.rows,'html_'+html.uuid.uuid4().hex,1,baseline={'synthetic':True})['run_info_path']
        html.execute(parent,execute_live=True,transport=Shell())
        count=len(self.calls);preview=html.prepare_reviewed(parent,str(targets))
        self.assertEqual(preview['phase'],2);self.assertEqual(preview['planned_requests'],2)
        self.assertEqual(len(self.calls),count)

    def test_operation_manifest_contains_only_references_not_bibliographic_payload(self):
        source=self.prepare();p,ps,store,budget,operation=html.context(source)
        manifest=store._read_relative(Path(p['operation_ref']),max_bytes=65536)
        for value in (b'SYNTHETIC TITLE',b'SYNTHETIC API ABSTRACT',b'"merged"',b'"field_provenance"'):
            self.assertNotIn(value,manifest)
        declared=json.loads(manifest);self.assertNotIn('records',declared)
        data=store._read_relative(Path(declared['input_ref']),max_bytes=1024*1024)
        self.assertEqual(html.sha(data),declared['input_sha256']);self.assertIn(b'SYNTHETIC TITLE',data)
