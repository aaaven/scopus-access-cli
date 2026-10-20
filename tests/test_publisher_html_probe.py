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
from scopus_access import publisher_runtime, publisher_html
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

    def test_article_keywords_supply_author_keywords_but_seo_and_subjects_do_not(self):
        body=page().replace(b'Author Keywords',b'Keywords').replace(b'</head>',b'<meta name="keywords" content="SYNTHETIC SEO"><meta name="dc.subject" content="SYNTHETIC SUBJECT"></head>')
        c=self.parsed(body);self.assertEqual(c['fields']['author_keywords'],['SYNTHETIC TERM']);self.assertIsNone(c['fields']['index_keywords'])
        self.assertEqual(len(c['publisher_keywords_unclassified']),2)
        self.assertEqual(c['methods']['author_keywords'],'article_dom_keywords_as_author_keywords')

    def test_navigation_keyword_sections_never_supply_article_author_keywords(self):
        section=b'<section id="keywords"><h2>Author Keywords</h2><ul><li>SYNTHETIC TERM</li></ul></section>'
        for container in ('nav','aside','form','footer'):
            with self.subTest(container=container):
                body=page().replace(section,('<'+container+'>').encode()+section+('</'+container+'>').encode())
                candidate=self.parsed(body)
                self.assertIsNone(candidate['fields']['author_keywords'])
                self.assertEqual(candidate['publisher_article_keywords'],[])
                self.assertTrue(candidate['identity']['eligible'])

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
        self.assertEqual(export[0]['merged']['conversion_version'],html.PARSER_VERSION)

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

    def test_upgrade_resumes_static_run_and_reparses_saved_evidence_without_reset(self):
        def stop(task):
            if task==2:raise KeyboardInterrupt()
        # Freeze an earlier fetch implementation, then leave one page complete.
        with mock.patch.object(publisher_html,'fetch_code_hash',return_value='a'*64), mock.patch.object(publisher_runtime,'__version__','0.6.0'):
            source=self.prepare()
            with self.assertRaises(KeyboardInterrupt):self.execute(source,after_task=stop)
        original=Path(source).read_bytes();p,ps,store,budget,op=html.context(source)
        events=budget.events(p['run_id']);self.assertEqual(len(self.calls),2)
        with budget.connect() as c:grant=dict(c.execute('SELECT * FROM enrichment_grant').fetchone())
        result=self.execute(source,resume=True)
        self.assertEqual((result['requests_attempted'],result['network_calls'],len(self.calls)),(11,9,11))
        self.assertEqual(events,budget.events(p['run_id'])[:len(events)])
        self.assertEqual(sum(t['task']==2 for t in self.calls),1)
        with budget.connect() as c:self.assertEqual(grant,dict(c.execute('SELECT * FROM enrichment_grant').fetchone()))
        self.assertEqual(original,Path(source).read_bytes())
        old=(store.root/result['merged_ref']).read_bytes();old_report=(store.root/result['report_ref']).read_bytes()
        with mock.patch('scopus_access.publisher_html.parse_html',wraps=html.parse_html) as parser:
            reparsed=html.analyze(source)
            self.assertEqual(parser.call_count,10)
        self.assertEqual(reparsed['merged_sha256'],result['merged_sha256']);self.assertEqual(len(self.calls),11)
        self.assertEqual(old,(store.root/result['merged_ref']).read_bytes())
        self.assertEqual(old_report,(store.root/result['report_ref']).read_bytes())
        log=Path(source).with_name('runtime.jsonl');records=[json.loads(x) for x in log.read_bytes().splitlines()]
        self.assertEqual(records[0]['cli_version'],'0.6.0');self.assertEqual(records[0]['fetch_code_sha256'],'a'*64)
        self.assertEqual(records[-1]['cli_version'],publisher_runtime.__version__)
        self.assertEqual(records[-1]['parser_version'],html.PARSER_VERSION)
        self.assertNotEqual(records[-1]['fetch_code_sha256'],'a'*64)
        resumed=self.execute(source,resume=True)
        self.assertEqual((resumed['network_calls'],resumed['requests_attempted'],len(self.calls)),(0,11,11))

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

    def test_bibliographic_h3_sibling_keywords_fill_author_keywords_without_subjects(self):
        extra='<article><div class="c-bibliographic-information__column"><h3>Keywords</h3>\n<ul>'+''.join('<li>SYNTHETIC TERM %d</li>'%i for i in range(6))+'</ul><h3>Subjects</h3><ul><li>SYNTHETIC NON KEYWORD</li></ul></div></article>'
        body=page().replace(b'<section id="keywords"><h2>Author Keywords</h2><ul><li>SYNTHETIC TERM</li></ul></section>',b'')
        body=body.replace(b'</head>',b'<meta name="dc.subject" content="SYNTHETIC SUBJECT A"><meta name="dc.subject" content="SYNTHETIC SUBJECT B"></head>')
        c=self.parsed(body+extra.encode())
        self.assertEqual(c['publisher_article_keywords'],['SYNTHETIC TERM %d'%i for i in range(6)])
        self.assertEqual(len(c['publisher_subject_classifications']),2)
        self.assertEqual(c['fields']['author_keywords'],c['publisher_article_keywords']);self.assertIsNone(c['fields']['index_keywords'])
        self.assertEqual(c['publisher_article_keyword_author_origin'],'publisher_article_keywords_used_as_author_keywords')
        self.assertEqual(c['keyword_sections'][0]['method'],'heading_sibling_list')

    def test_keyword_sibling_scanner_does_not_capture_navigation_or_later_lists(self):
        body=page().replace(b'<section id="keywords"><h2>Author Keywords</h2><ul><li>SYNTHETIC TERM</li></ul></section>',b'')
        body+=b'<nav><h3>Keywords</h3><ul><li>SYNTHETIC NAVIGATION</li></ul></nav><article><h3>Keywords</h3><h3>Subjects</h3><ul><li>SYNTHETIC SUBJECT</li></ul></article>'
        self.assertFalse(self.parsed(body)['publisher_article_keywords'])

    def test_author_comparison_reverses_single_comma_without_rewriting_byline(self):
        base=dict(self.rows[0]['merged'],authors=[{'name':'A Example'},{'name':'B Example'}])
        body=page().replace(b'content="A Example"',b'content="Example, A"').replace(b'content="B Example"',b'content="Example, B"')
        c=html.parse_html(body,base,'https://link.springer.com/chapter/10.1234/synthetic0')
        self.assertTrue(c['checks']['author_name_order_matches_api'])
        self.assertFalse(c['checks']['author_name_order_matches_api_literal'])
        self.assertEqual(c['fields']['authors'][0]['name'],'Example, A')
        self.assertEqual(html.comparison_name('A Example, Jr.'),(html.api._title('A Example, Jr.'),False))
        self.assertEqual(html.comparison_name('Example, A, Jr.')[1],False)

    def test_reference_content_checks_do_not_equate_matching_counts_with_matching_content(self):
        refs=[{'text':'1. SYNTHETIC FIRST (2020) TITLE','doi_links':['https://doi.org/10.1234/one'],'source_reference_number':1},
              {'text':'2. SYNTHETIC SECOND (2021) TITLE','doi_links':['https://doi.org/10.1234/two'],'source_reference_number':2}]
        base=[{'DOI':'10.1234/one','year':2020},{'DOI':'10.1234/two','year':2021}]
        c=html.reference_comparison(refs,base);self.assertEqual(c['doi_matches_at_same_position'],2)
        swapped=html.reference_comparison(list(reversed(refs)),base)
        self.assertEqual(swapped['doi_matches_at_same_position'],0);self.assertEqual(swapped['doi_matches_anywhere'],2)
        self.assertFalse(swapped['html_source_numbers_contiguous'])

    def test_reference_action_links_removed_and_paths_distinguish_minified_nodes(self):
        b=page().replace(b'</li>',b'<div class="c-article-references__links"><a href="https://doi.org/10.1234/reference">Google Scholar PubMed</a></div></li>')
        c=self.parsed(b);refs=c['fields']['references'];self.assertEqual(len(refs),2)
        self.assertNotIn('Google Scholar',refs[0]['text']);self.assertNotEqual(refs[0]['source_path'],refs[1]['source_path'])
        self.assertEqual([r['source_reference_number'] for r in refs],[1,2])
        self.assertTrue(c['checks']['reference_content_checks']['html_source_numbers_contiguous'])

    def test_reference_numbers_use_explicit_html_counter_without_fabricating_text(self):
        body=page().replace(b'<li><p>1. ',b'<li data-counter="1."><p>').replace(b'<li><p>2. ',b'<li data-counter="2."><p>')
        refs=self.parsed(body)['fields']['references']
        self.assertEqual([r['source_reference_number'] for r in refs],[1,2])
        self.assertEqual([r['source_reference_number_origin'] for r in refs],['data-counter','data-counter'])
        self.assertFalse(refs[0]['text'].startswith('1.'))
        refs[1]['source_reference_number']=3
        self.assertFalse(html.reference_comparison(refs,[])['html_source_numbers_contiguous'])

    def test_author_byline_control_does_not_imply_missing_names_and_order_is_checked(self):
        byline=b'<ul class="c-article-author-list"><li class="c-article-author-list__item"><a>A Example</a></li><li class="c-article-author-list__show-more">\xe2\x80\xa6</li><li class="c-article-author-list__item c-article-author-list__item--hide-small-screen"><a>B Example</a></li></ul>'
        checks=self.parsed(page()+byline)['checks']
        self.assertEqual(checks['byline_names_observed'],2);self.assertTrue(checks['byline_name_order_matches_metadata'])
        self.assertTrue(checks['byline_show_more_control_observed']);self.assertFalse(checks['known_author_truncation'])
        checks=self.parsed(page()+byline.replace(b'<a>B Example</a>',b'<a>C Example</a>'))['checks']
        self.assertFalse(checks['byline_name_order_matches_metadata'])
