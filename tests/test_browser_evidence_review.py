"""Synthetic saved browser bundles; no Playwright or real publisher content."""
import copy
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock
from scopus_access import secrets
from scopus_access.errors import ValidationError,LiveCapabilityLocked
import test_local_cli as fixtures


def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parent.parent/'scripts'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
review=module('review_publisher_browser');html=review.html;budget_model=module('publisher_browser_budget')


class SavedReviewTests(unittest.TestCase):
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        self.cwd=mock.patch.object(Path,'cwd',return_value=self.root);self.cwd.start();self.addCleanup(self.cwd.stop)
        self.secret=mock.patch.object(secrets.MacOSKeychainSecretProvider,'get_api_key',side_effect=AssertionError('no credential access'))
        self.secret.start();self.addCleanup(self.secret.stop)
        self.bundle=self.root/'restricted_metadata/scopus/browser-side/pw_synthetic';self.bundle.mkdir(parents=True)
        self.records=[];outcomes=[];corrections=[];events=[]
        capture_code=b'# SYNTHETIC CAPTURE CODE\n'
        for sid,count,terms,subjects,host in [('D0007',1,6,4,'link.springer.com'),('D0009',4,0,3,'www.nature.com')]:
            doi='10.1234/synthetic'+sid;names=['%s Example'%chr(65+i) for i in range(count)]
            base={'doi':doi,'title':'SYNTHETIC TITLE','abstract':'SYNTHETIC API ABSTRACT','authors':[{'name':n} for n in names],
                'references':[{'DOI':'10.1234/ref%d'%i,'year':2020} for i in (1,2)],'author_keywords':None,'index_keywords':None}
            meta='<meta name="citation_doi" content="'+doi+'"><meta name="citation_title" content="SYNTHETIC TITLE">'+''.join('<meta name="citation_author" content="Example, %s">'%chr(65+i) for i in range(count))
            meta+=''.join('<meta name="dc.subject" content="SYNTHETIC SUBJECT %d">'%i for i in range(subjects))
            kw='<div class="c-bibliographic-information__column"><h3>Keywords</h3><ul>'+''.join('<li>SYNTHETIC KEYWORD %d</li>'%i for i in range(terms))+'</ul></div>' if terms else ''
            texts=['%d. SYNTHETIC AUTHOR (2020). SYNTHETIC REFERENCE %d. Journal 1.'%(i,i) for i in (1,2)]
            refs=''.join('<li class="c-article-references__item"><p>'+t+'</p><div class="c-article-references__links"><a href="https://doi.org/10.1234/ref%d">Article</a></div></li>'%(i+1) for i,t in enumerate(texts))
            document=('<html><head>'+meta+'</head><body><article><section id="Abs1"><p>SYNTHETIC FULL ABSTRACT</p></section>'+kw+'<section id="Bib1"><h2>References (2)</h2><ol>'+refs+'</ol></section></article></body></html>').encode()
            rendered=document+b'<script>/* SYNTHETIC NONEXECUTED */</script>'
            folder=self.bundle/sid;folder.mkdir();(folder/'document-response.html').write_bytes(document);(folder/'rendered.html').write_bytes(rendered)
            extracted={'sample_id':sid,'html_sha256':html.sha(rendered),'raw_structured_data':{},'extracted':{
                'abstract':{'value':'SYNTHETIC FULL ABSTRACT'},'references':[{'text':t} for t in texts]}}
            (folder/'extraction.json').write_bytes(html.encode(extracted))
            baseline={'sample_id':sid,'doi_normalized':doi,'merged':base,'field_provenance':{f:{'provider':'api','action':'retained'} for f in html.FIELDS}}
            self.records.append({'sample_id':sid,'url':'https://'+host+'/article/'+doi,'doi':doi,'title':'SYNTHETIC TITLE','api_baseline':baseline})
            outcomes.append({'sample_id':sid,'status':200,'network':{'admitted':10,'failed':7,'blocked_resource':7},
                'author_name_order_matches_api':False,'html_sha256':html.sha(rendered),'html_ref':str((folder/'rendered.html').relative_to(self.root/'restricted_metadata/scopus'))})
            corrections.append({'sample_id':sid,'author_count':count,'textual_reference_count':2,'publisher_article_keywords_count':terms,
                'author_order_matches_after_documented_comma_name_reversal':True})
            for i in range(1,11):events.append({'sample_id':sid,'ordinal':i,'event':'admitted_before_dispatch','host':host,
                'url_sha256':html.sha(('SYNTHETIC-%s-%s'%(sid,i)).encode()),'resource_type':'document' if i==1 else 'script'})
        plan={'run_id':'pw_synthetic','sample_ids':['D0007','D0009'],'pages':2,'max_requests':80,'max_requests_per_page':40,'retry_allowance':0,'source_sha256':html.sha(capture_code)}
        capture={'run_id':'pw_synthetic','admitted_page_requests':20,'outcomes':outcomes}
        capture_bytes=html.encode(capture)
        self.data={'plan.json':html.encode(plan),'report.json':capture_bytes,
            'offline-review.json':html.encode({'original_report_sha256':html.sha(capture_bytes),'records':corrections}),
            'handoff.md':b'SYNTHETIC HANDOFF','inputs.jsonl':b''.join(html.encode(x) for x in self.records),
            'network-control.jsonl':b''.join(html.encode(x) for x in events),'browser_probe.py':capture_code,'offline_review.py':b'# SYNTHETIC OFFLINE CODE'}
        for name,raw in self.data.items():(self.bundle/name).write_bytes(raw)
    def run_review(self,**kwargs):return review.review_saved(str(self.bundle),**kwargs)
    def output(self,r):return [json.loads(x) for x in (self.root/'restricted_metadata/scopus'/r['merged_ref']).read_bytes().splitlines()]

    def test_saved_document_dom_replay_preserves_api_fields_and_separates_six_keywords(self):
        before={p:html.sha(p.read_bytes()) for p in self.bundle.rglob('*') if p.is_file()}
        r=self.run_review();out=self.output(r)
        self.assertTrue(r['all_document_vs_dom_fields_equal']);self.assertEqual(r['source_capture_admitted_requests'],20)
        self.assertEqual(r['publisher_article_keyword_values'],6);self.assertEqual(r['publisher_article_keyword_records'],1)
        for f in html.FIELDS:self.assertEqual(r['field_coverage'][f]['newly_filled'],1 if f=='author_keywords' else 0)
        for original,row in zip(self.records,out):
            for f in html.FIELDS:
                if f!='author_keywords':self.assertEqual(row['merged'][f],original['api_baseline']['merged'][f])
            self.assertTrue(row['review']['checks']['author_name_order_matches_api'])
            self.assertFalse(row['review']['checks']['author_name_order_matches_api_literal'])
        self.assertEqual(len(out[0]['external_semantics']['publisher_article_keywords']),6)
        self.assertEqual(out[0]['merged']['author_keywords'],out[0]['external_semantics']['publisher_article_keywords'])
        self.assertIsNone(out[1]['merged']['author_keywords'])
        self.assertEqual(out[0]['field_provenance']['author_keywords']['provider'],'publisher_html')
        self.assertEqual(len(out[0]['external_semantics']['publisher_subject_classifications']),4)
        self.assertFalse(out[1]['external_semantics']['publisher_article_keywords'])
        self.assertTrue(out[0]['review']['side_reference_text_order_agrees'])
        self.assertEqual(out[0]['review']['checks']['reference_content_checks']['doi_matches_at_same_position'],2)
        self.assertEqual(before,{p:html.sha(p.read_bytes()) for p in self.bundle.rglob('*') if p.is_file()})

    def test_cache_repeat_and_interrupted_copy_resume_are_offline_and_deterministic(self):
        n=[]
        def stop(name):n.append(name);raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.run_review(after_cache_file=stop)
        first=self.run_review();again=self.run_review()
        self.assertEqual(first['bundle_sha256'],again['bundle_sha256']);self.assertEqual(first['merged_sha256'],again['merged_sha256'])
        self.assertEqual(first['new_network_calls'],0)

    def test_abstract_label_comparison_preserves_api_original_without_claiming_literal_equality(self):
        for row in self.records:row['api_baseline']['merged']['abstract']='Abstract SYNTHETIC FULL ABSTRACT'
        (self.bundle/'inputs.jsonl').write_bytes(b''.join(html.encode(x) for x in self.records))
        rows=self.output(self.run_review())
        for row in rows:
            self.assertFalse(row['review']['api_abstract_normalized_equal'])
            self.assertTrue(row['review']['api_abstract_equal_after_optional_leading_label'])
            self.assertEqual(row['merged']['abstract'],'Abstract SYNTHETIC FULL ABSTRACT')

    def test_existing_api_author_keywords_are_retained_and_absence_is_not_an_error(self):
        self.records[0]['api_baseline']['merged']['author_keywords']=['SYNTHETIC API KEYWORD']
        self.records[0]['api_baseline']['field_provenance']['author_keywords']={'provider':'api','action':'retained'}
        (self.bundle/'inputs.jsonl').write_bytes(b''.join(html.encode(x) for x in self.records))
        result=self.run_review();rows=self.output(result)
        self.assertEqual(rows[0]['merged']['author_keywords'],['SYNTHETIC API KEYWORD'])
        self.assertEqual(rows[0]['field_provenance']['author_keywords']['provider'],'api')
        self.assertEqual(len(rows[0]['publisher_candidates']['rendered']['fields']['author_keywords']),6)
        self.assertIsNone(rows[1]['merged']['author_keywords'])
        self.assertEqual(result['field_coverage']['author_keywords']['newly_filled'],0)

    def test_cache_corruption_is_rejected_without_refetch(self):
        r=self.run_review();manifest=self.root/'restricted_metadata/scopus'/r['cache_manifest_ref']
        (manifest.parent/'D0007/document-response.html').write_bytes(b'CORRUPTED')
        with self.assertRaises(ValidationError):self.run_review()

    def test_source_raw_document_change_after_first_import_is_rejected(self):
        self.run_review();p=self.bundle/'D0007/document-response.html';p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValidationError):self.run_review()

    def test_capture_rendered_hash_or_capture_code_change_is_rejected(self):
        for path in ('D0007/rendered.html','browser_probe.py'):
            p=self.bundle/path;old=p.read_bytes();p.write_bytes(old+b'CHANGED')
            with self.assertRaises(ValidationError):self.run_review()
            p.write_bytes(old)

    def test_wrong_correction_and_budget_counts_are_rejected(self):
        for name in ('offline-review.json','report.json'):
            p=self.bundle/name;old=p.read_bytes();value=json.loads(old)
            if name=='offline-review.json':value['records'][0]['publisher_article_keywords_count']=4
            else:value['admitted_page_requests']=2
            p.write_bytes(html.encode(value))
            with self.assertRaises(ValidationError):self.run_review()
            p.write_bytes(old)

    def test_control_output_is_bounded_and_excludes_keywords_abstract_references_and_names(self):
        out=io.StringIO()
        with mock.patch('sys.stdout',out):code=review.main(['--bundle',str(self.bundle)])
        self.assertEqual(code,0);self.assertEqual(len(out.getvalue().splitlines()),1)
        for value in ('SYNTHETIC TITLE','SYNTHETIC FULL ABSTRACT','SYNTHETIC KEYWORD','SYNTHETIC REFERENCE','Example, A'):
            self.assertNotIn(value,out.getvalue())
        self.assertLess(len(out.getvalue().encode()),16384)

    def test_symlink_and_outside_project_inputs_are_rejected(self):
        p=self.bundle/'D0007/document-response.html';old=p.read_bytes();other=self.bundle/'original.html';other.write_bytes(old);p.unlink();p.symlink_to(other)
        with self.assertRaises(Exception):self.run_review()
        with self.assertRaises(ValidationError):review.review_saved(str(self.root.parent))


class BrowserAdmissionModelTests(unittest.TestCase):
    def setUp(self):
        fixtures.LocalCliTests.setUp(self)
        self.store=html.RestrictedArtifactStore(self.root/'restricted_metadata/scopus',allowed_roots=[self.root/'restricted_metadata/scopus'])
        self.budget=html.api._Budget(self.root/'.scopus-access/browser-model.sqlite','SYNTHETIC_PROJECT')
        self.plan={'run_id':'SYNTHETIC_BROWSER_RUN','project_id':'SYNTHETIC_PROJECT','operation_sha256':'a'*64,
            'max_requests':4,'provider_limits':{'D0007':3,'D0009':3},'domains':{'D0007':['link.springer.com'],'D0009':['www.nature.com']},'robots_decision':'allow'}
    def gate(self,**kwargs):return budget_model.RequestGate(self.plan,self.budget,self.store,execute_live=True,**kwargs)

    def test_document_scripts_css_and_fetch_all_count_before_dispatch(self):
        gate=self.gate();types=['document','script','stylesheet','fetch']
        for i,kind in enumerate(types):
            sid='D0007' if i<3 else 'D0009';host='link.springer.com' if i<3 else 'www.nature.com'
            task=gate.admit(sid,'https://'+host+'/SYNTHETIC',kind)
            self.assertEqual(sum(x['kind']=='ATTEMPT' for x in self.budget.events(self.plan['run_id'])),i+1)
            gate.complete(task,http_status=200)
        with self.assertRaises(ValidationError):gate.admit('D0009','https://www.nature.com/SYNTHETIC','xhr')
        again=self.gate(resume=True)
        with self.assertRaises(ValidationError):again.admit('D0009','https://www.nature.com/SYNTHETIC','fetch')

    def test_per_page_budget_and_repeated_urls_are_counted(self):
        gate=self.gate()
        for _ in range(3):gate.complete(gate.admit('D0007','https://link.springer.com/SYNTHETIC','fetch'),http_status=200)
        with self.assertRaises(ValidationError):gate.admit('D0007','https://link.springer.com/SYNTHETIC','fetch')
        self.assertEqual(sum(x['kind']=='ATTEMPT' for x in self.budget.events(self.plan['run_id'])),3)

    def test_robots_unknown_explicit_consent_and_wildcard_hosts_fail_closed(self):
        with self.assertRaises(LiveCapabilityLocked):budget_model.RequestGate(self.plan,self.budget,self.store)
        p=copy.deepcopy(self.plan);p['robots_decision']='unknown'
        with self.assertRaises(LiveCapabilityLocked):budget_model.RequestGate(p,self.budget,self.store,execute_live=True)
        p=copy.deepcopy(self.plan);p['domains']['D0007']=['*.springer.com']
        with self.assertRaises(ValidationError):budget_model.RequestGate(p,self.budget,self.store,execute_live=True)

    def test_route_abort_is_not_charged_and_dispatch_error_remains_uncertain(self):
        gate=self.gate()
        class Request:url='https://evil.invalid/a';resource_type='image'
        class Route:
            request=Request()
            def abort(self):self.aborted=True
            def continue_(self):raise RuntimeError('SYNTHETIC SECRET DO NOT ECHO')
        route=Route();self.assertIsNone(gate.route_callback(route,'D0007'))
        self.assertFalse(self.budget.events(self.plan['run_id']))
        route.request.url='https://link.springer.com/SYNTHETIC';route.request.resource_type='script'
        with self.assertRaises(ValidationError) as error:gate.route_callback(route,'D0007')
        self.assertNotIn('SYNTHETIC SECRET',str(error.exception))
        with self.assertRaises(LiveCapabilityLocked):self.gate(resume=True)

    def test_frozen_domains_are_copied_and_malformed_urls_do_not_consume_budget(self):
        gate=self.gate();self.plan['domains']['D0007'].append('evil.invalid');self.plan['max_requests']=100
        for url in ('https://evil.invalid/a','https://link.springer.com:invalid/a','https://[invalid/a',
                    'https://link.springer.com/a\nsecret','https://user@link.springer.com/a','https://link.springer.com/a#fragment'):
            with self.assertRaises(ValidationError):gate.admit('D0007',url,'script')
        self.assertFalse(self.budget.events('SYNTHETIC_BROWSER_RUN'))

    def test_frozen_hosts_reject_ports_userinfo_and_ambiguous_spelling(self):
        for host in ('user@link.springer.com','link.springer.com:443','link.springer.com.','-link.springer.com','link.springer.com/path'):
            plan=copy.deepcopy(self.plan);plan['domains']['D0007']=[host]
            with self.assertRaises(ValidationError):budget_model.RequestGate(plan,self.budget,self.store,execute_live=True)
