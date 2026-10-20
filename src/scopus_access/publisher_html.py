#!/usr/bin/env python3
"""Publisher HTML parser and bounded static retrieval for the local CLI.

One trial has two explicitly frozen phases, each <=15 requests (<=30 total).
No redirect following, login, cookies, JavaScript execution or automatic retry.
All content and exact URLs remain in project-restricted storage.
"""
import argparse
import copy
import hashlib
import http.client
import json
import re
import ssl
import sys
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, urljoin
from urllib.robotparser import RobotFileParser

from scopus_access import enrichment as api
from scopus_access.request_budget import RequestBudget
from scopus_access.publisher_runtime import record_runtime
from scopus_access import request_budget
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.errors import ValidationError, LiveCapabilityLocked
from scopus_access.policy import load_policy
from scopus_access.project import discover_project_policy, require_project_context
from scopus_access.security import read_file_no_follow, reject_symlink_components, parse_json_object, safe_identifier
from scopus_access.quota import utc_now, parse_utc

VERSION='publisher-html-probe-v2'
PARSER_VERSION='publisher-html-parser-v4'
LEGACY_VERSION='publisher-html-probe-v1'
UA='ScopusAccessToolPublisherHTMLProbe/1.0'
HOSTS=frozenset({'linkinghub.elsevier.com','www.sciencedirect.com','www.nature.com',
    'link.springer.com','link.springernature.com','bmcpsychology.biomedcentral.com',
    'bmcpublichealth.biomedcentral.com','bmcpsychiatry.biomedcentral.com'})
FIELDS=api.FIELDS
MAX_BODY=16*1024*1024
VOID={'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
sha=api.digest
encode=api.encode
nonempty=api.nonempty


def safe_url(value):
    if not isinstance(value,str) or len(value)>4096 or any(ord(c)<33 or ord(c)==127 for c in value):
        raise ValidationError('Publisher page URL is invalid.')
    try:p=urlsplit(value);port=p.port
    except ValueError:raise ValidationError('Publisher page URL is invalid.') from None
    if p.scheme!='https' or p.hostname not in HOSTS or port not in {None,443} or p.username or p.password or p.fragment:
        raise ValidationError('Publisher URL is outside the frozen HTTPS host policy.')
    if p.query and not re.fullmatch(r'via=ihub',p.query):
        raise ValidationError('Publisher URL query is outside the experiment scope.')
    if any(x in {'.','..'} for x in p.path.split('/')):raise ValidationError('Publisher path is invalid.')
    return value


def fetch_code_hash():
    return sha(encode({'publisher_html':sha(read_file_no_follow(Path(__file__))),
        'request_budget':sha(read_file_no_follow(Path(request_budget.__file__)))}))


def family(url):return 'elsevier' if urlsplit(url).hostname in {'linkinghub.elsevier.com','www.sciencedirect.com'} else 'springer_nature'


class Node:
    def __init__(self,tag,attrs=None,parent=None,pos=None):
        self.tag=tag;self.attrs=dict(attrs or []);self.parent=parent;self.children=[];self.pos=pos
    def walk(self):
        yield self
        for c in self.children:
            if isinstance(c,Node):yield from c.walk()
    def text(self):
        if self.tag in {'script','style','noscript','button'}:return ''
        return ' '.join(' '.join(c.text() if isinstance(c,Node) else c for c in self.children).split())
    def path(self):
        parts=[];node=self
        while node.parent is not None:
            peers=[n for n in node.parent.children if isinstance(n,Node) and n.tag==node.tag]
            parts.append('%s[%s]'%(node.tag,peers.index(node)+1));node=node.parent
        return '/'.join(reversed(parts))+'@%s:%s'%(self.pos or (0,0))
    def classes(self):return set(self.attrs.get('class','').split())


class HTML(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.root=Node('root');self.stack=[self.root];self.count=0
    def handle_starttag(self,tag,attrs):
        self.count+=1
        if self.count>120000 or len(self.stack)>256:raise ValidationError('Publisher HTML structure exceeds parsing bounds.')
        node=Node(tag,attrs,self.stack[-1],self.getpos());self.stack[-1].children.append(node)
        if tag not in VOID:self.stack.append(node)
    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        if tag not in VOID:self.handle_endtag(tag)
    def handle_endtag(self,tag):
        for i in range(len(self.stack)-1,0,-1):
            if self.stack[i].tag==tag:self.stack=self.stack[:i];break
    def handle_data(self,data):self.stack[-1].children.append(data)


def split_terms(values):
    return list(dict.fromkeys(term.strip() for value in values if isinstance(value,str) for term in value.split(';') if term.strip()))


def _json_nodes(value,path='$'):
    if isinstance(value,list):
        for i,x in enumerate(value):yield from _json_nodes(x,path+'[%d]'%i)
    elif isinstance(value,dict):
        kinds=value.get('@type',[]);kinds=kinds if isinstance(kinds,list) else [kinds]
        if any(isinstance(k,str) and k in {'ScholarlyArticle','Article','Chapter'} for k in kinds):yield path,value
        if '@graph' in value:yield from _json_nodes(value['@graph'],path+'.@graph')


def comparison_name(value):
    """Documented comparison only; never rewrite the stored publisher byline."""
    value=value if isinstance(value,str) else ''
    pieces=[x.strip() for x in value.split(',')]
    suffixes={'jr','jr.','sr','sr.','ii','iii','iv'}
    reversed_name=(len(pieces)==2 and all(pieces) and pieces[1].casefold() not in suffixes)
    return api._title(' '.join(reversed(pieces)) if reversed_name else value),reversed_name


def _reference_text(node):
    if node.tag in {'script','style','button'} or 'c-article-references__links' in node.classes():return ''
    return ' '.join(' '.join(_reference_text(x) if isinstance(x,Node) else x for x in node.children).split())


def _article_keyword_sections(nodes):
    """Follow heading siblings, including Springer bibliographic columns."""
    labels={'keywords','key words','author keywords','author provided keywords','author-generated keywords'}
    results=[];seen=set()
    for h in nodes:
        if h.tag not in {'h2','h3','h4','h5','label','title'} or h.text().casefold() not in labels or h.parent is None:continue
        ancestors=list(_parents(h))
        article_region=any(n.tag=='article' or n.attrs.get('id','').casefold() in {'bibliographic-information','keywords','keyword','key-words'}
            or n.classes() & {'c-bibliographic-information__column','keywords-section'} for n in ancestors)
        explicit='author' in h.text().casefold()
        # Section-labelled Keywords is an existing supported layout. Ignore search/nav widgets.
        section_region=any(n.tag in {'section','kwd-group'} for n in ancestors)
        if not (article_region or explicit or section_region):continue
        if any(n.tag in {'nav','aside','form','footer'} for n in ancestors):continue
        siblings=h.parent.children;at=siblings.index(h)
        for node in siblings[at+1:]:
            if not isinstance(node,Node):continue
            if node.tag in {'h1','h2','h3','h4','h5','h6'}:break
            if node.tag in {'ul','ol'}:
                terms=[x.text() for x in node.walk() if x.tag=='li' and x.text()]
                if terms and node.path() not in seen:
                    seen.add(node.path());results.append((node,h.text().casefold(),terms,explicit))
                break
    return results


def reference_comparison(refs,baseline):
    def doi(value):
        try:return api.normalize_doi(value)
        except (ValueError,TypeError):return None
    html_dois=[{d for d in (doi(x) for x in r.get('doi_links',[])) if d} for r in refs]
    api_dois=[doi(r.get('DOI')) if isinstance(r,dict) else None for r in baseline]
    all_html=set().union(*html_dois) if html_dois else set()
    doi_expected=sum(d is not None for d in api_dois)
    same_position=sum(d is not None and i<len(html_dois) and d in html_dois[i] for i,d in enumerate(api_dois))
    doi_anywhere=sum(d is not None and d in all_html for d in api_dois)
    years=year_matches=0
    for i,r in enumerate(baseline):
        year=r.get('year') if isinstance(r,dict) else None
        if year and re.fullmatch(r'\d{4}',str(year)):
            years+=1;year_matches+=i<len(refs) and bool(re.search(r'(?<!\d)'+str(year)+r'(?!\d)',refs[i]['text']))
    numbered=[r.get('source_reference_number') for r in refs]
    source_numbers=[n for n in numbered if n is not None]
    text_hashes=[sha(api._title(r['text']).encode()) for r in refs]
    return {'api_reference_dois':doi_expected,'doi_matches_at_same_position':same_position,
        'doi_matches_anywhere':doi_anywhere,'api_dois_absent_from_extracted_doi_links':doi_expected-doi_anywhere,
        'api_years_present':years,'year_matches_at_same_position':year_matches,
        'html_reference_numbers_observed':len(source_numbers),
        'html_source_numbers_contiguous':source_numbers==list(range(1,len(refs)+1)) if len(source_numbers)==len(refs) and refs else None,
        'duplicate_text_entries':len(text_hashes)-len(set(text_hashes)),
        'content_check_scope':'DOI_links_year_and_normalized_text_not_independent_fulltext_verification'}


def parse_html(body,base,url,content_type='text/html; charset=utf-8'):
    """Structured metadata first, then explicit article sections; never execute JS."""
    if not isinstance(body,bytes) or len(body)>MAX_BODY:raise ValidationError('Publisher HTML exceeds the parsing bound.')
    charset=re.search(r'charset\s*=\s*[\"\']?([\w-]+)',content_type,re.I)
    charset=charset.group(1).lower() if charset else 'utf-8'
    if charset not in {'utf-8','utf8','iso-8859-1','windows-1252','us-ascii'}:charset='utf-8'
    text=body.decode(charset,errors='replace');tree=HTML();tree.feed(text);tree.close()
    nodes=list(tree.root.walk());meta={};meta_paths={}
    for n in nodes:
        if n.tag=='meta' and any(p.tag=='head' for p in _parents(n)):
            name=n.attrs.get('name',n.attrs.get('property','')).lower();value=n.attrs.get('content')
            if name and value:meta.setdefault(name,[]).append(value);meta_paths.setdefault(name,n.path()+'@content')
    expected=api.normalize_doi(base.get('doi'))
    dois=[api.normalize_doi(x) for k in ('citation_doi','dc.identifier','dc.identifier.doi','prism.doi') for x in meta.get(k,[])]
    titles=meta.get('citation_title') or meta.get('dc.title') or meta.get('og:title') or []
    fields={f:None for f in FIELDS};paths={};methods={};generic_keywords=[];json_citations=[]
    versions=meta.get('citation_version',[])
    def put(field,value,path,method):
        if not nonempty(fields.get(field)) and nonempty(value):fields[field]=value;paths[field]=path;methods[field]=method
    # Author-specific metadata is distinct from generic publisher/SEO keywords.
    author_meta=meta.get('citation_author',[])
    put('authors',[{'name':x} for x in author_meta],meta_paths.get('citation_author'),'structured_highwire')
    for key in ('citation_abstract','dc.description.abstract'):
        if meta.get(key):put('abstract',api.plain(meta[key][0]),meta_paths[key],'structured_metadata')
    explicit_keywords=meta.get('citation_author_keywords') or meta.get('author_keywords')
    if explicit_keywords:put('author_keywords',split_terms(explicit_keywords),'meta:author_keywords','structured_author_label')
    for key in ('citation_keywords','keywords','dc.subject','article:tag'):
        if meta.get(key):generic_keywords.append({'field':key,'values':meta[key],'authorship':'unclassified'})
    for script in nodes:
        if script.tag!='script' or script.attrs.get('type','').lower()!='application/ld+json':continue
        raw=''.join(c for c in script.children if isinstance(c,str))
        try:data=json.loads(raw)
        except (ValueError,RecursionError):continue
        for path,item in _json_nodes(data):
            identifiers=item.get('identifier',[]);identifiers=identifiers if isinstance(identifiers,list) else [identifiers]
            item_dois=[api.normalize_doi(x.get('value') if isinstance(x,dict) else x) for x in identifiers]
            # Only the matching article node may supply fields; unrelated graph entities cannot leak in.
            if expected not in item_dois:continue
            dois.extend(item_dois)
            if isinstance(item.get('headline') or item.get('name'),str):titles.append(item.get('headline') or item.get('name'))
            put('abstract',api.plain(item.get('abstract')),script.path()+path+'.abstract','structured_jsonld')
            authors=item.get('author') or [];authors=authors if isinstance(authors,list) else [authors]
            names=[x.get('name') if isinstance(x,dict) else x for x in authors]
            put('authors',[{'name':x} for x in names if isinstance(x,str) and x.strip()],script.path()+path+'.author','structured_jsonld')
            if item.get('keywords'):generic_keywords.append({'field':path+'.keywords','values':item['keywords'],'authorship':'unclassified'})
            citations=item.get('citation') or [];citations=citations if isinstance(citations,list) else [citations]
            json_citations.extend(citations)
    abstract_sections=[];keyword_sections=[];reference_sections=[]
    for n in nodes:
        identifier=n.attrs.get('id','').lower();classes=n.classes();label=n.attrs.get('data-title','').lower()
        headings=[c.text() for c in n.children if isinstance(c,Node) and c.tag in {'h2','h3','h4','h5','title','label'}]
        heading=' '.join(headings).strip().lower()
        if n.tag in {'section','div'} and (identifier in {'abs1','abstract','abstracts','abs0010'} or label=='abstract' or n.attrs.get('itemprop')=='abstract'):
            abstract_sections.append(n)
        if n.tag in {'section','div','kwd-group'} and (identifier in {'keywords','kwd-group','keyword','key-words'} or label in {'keywords','author keywords'} or heading in {'keywords','key words','author keywords','author provided keywords'} or 'keywords-section' in classes):
            if not any(p.tag in {'nav','aside','form','footer'} for p in _parents(n)):
                keyword_sections.append((n,heading or label))
        if n.tag in {'ol','section','div'} and (identifier in {'bib1','references','reference-list'} or 'c-article-references' in classes or heading.startswith('references')):
            reference_sections.append(n)
    for n in abstract_sections:
        paragraphs=[x.text() for x in n.walk() if x.tag=='p' and x.text()]
        value=' '.join(paragraphs) or re.sub(r'^Abstract\s*','',n.text(),flags=re.I)
        put('abstract',value,n.path(),'article_dom_section')
    keyword_checks=[];article_keywords=[];article_seen=set()
    for n,label in keyword_sections:
        terms=[x.text() for x in n.walk() if (x.tag in {'li','kwd'} or 'keyword' in x.classes()) and x.text()]
        terms=list(dict.fromkeys(terms));specific=n.attrs.get('kwd-group-type','').lower()
        explicit='author' in label or specific in {'author','author-generated','author-supplied'}
        # Explicit user decision: article Keywords sections supply author_keywords.
        if terms:
            keyword_checks.append({'path':n.path(),'label':label,'values':terms,'explicit_author_label':explicit})
            article_keywords.extend(terms);article_seen.update(terms)
        put('author_keywords',terms,n.path(),'article_dom_author_keywords' if explicit else 'article_dom_keywords_as_author_keywords')
    for n,label,terms,explicit in _article_keyword_sections(nodes):
        # The broad section scanner may already have captured this same list.
        if not set(terms).issubset(article_seen):
            keyword_checks.append({'path':n.path(),'label':label,'values':terms,'explicit_author_label':explicit,
                'method':'heading_sibling_list','heading_label_evidence':'author_keywords_heading' if explicit else 'keywords_heading'})
            article_keywords.extend(terms);article_seen.update(terms)
        put('author_keywords',terms,n.path(),'article_dom_author_keywords' if explicit else 'article_dom_keywords_as_author_keywords')
    article_keywords=list(dict.fromkeys(article_keywords))
    refs=[];reference_path=None;declared_count=None;more=False
    for section in reference_sections:
        items=[n for n in section.walk() if n.tag=='li' and not any(p.tag=='li' for p in _parents(n,stop=section))]
        candidate=[]
        for n in items:
            value=_reference_text(n)
            # A DOI/URL alone is a citation link, not a textual bibliography entry.
            if len(value)>=20 and not re.fullmatch(r'(?:https?://\S+|10\.\d{4,9}/\S+)',value):
                counter=re.fullmatch(r'\s*(\d+)\.?\s*',n.attrs.get('data-counter',''))
                label=counter or re.match(r'^\s*(\d+)[.\s]',value)
                candidate.append({'text':value,'source_path':n.path(),'position':len(candidate)+1,
                    'source_reference_number':int(label.group(1)) if label else None,
                    'source_reference_number_origin':'data-counter' if counter else 'visible_text' if label else None,
                    'doi_links':[a.attrs['href'] for a in n.walk() if a.tag=='a' and 'doi.org/' in a.attrs.get('href','')]})
        if len(candidate)>len(refs):refs=candidate;reference_path=section.path()
        section_text=section.text()+' '+' '.join(c for n in section.walk() if n.tag=='button' for c in n.children if isinstance(c,str))
        count=re.search(r'References\s*\((\d+)\)',section_text,re.I)
        if count:declared_count=int(count.group(1))
        more=more or bool(re.search(r'(?:load|show)\s+(?:more|all)\s+references',section_text,re.I))
    put('references',refs,reference_path,'article_dom_bibliography')
    target=api._title(base.get('title'));scores=[api.SequenceMatcher(None,target,api._title(t),autojunk=False).ratio() for t in titles if api._title(t) and target]
    score=max(scores) if scores else None
    version_risk=any(re.search(r'preprint|submitted|accepted.?manuscript',x,re.I) for x in versions)
    matches={x for x in dois if x}
    refresh=any(n.tag=='meta' and n.attrs.get('http-equiv','').lower()=='refresh' for n in nodes)
    tdm=[n.attrs.get('content') for n in nodes if n.tag=='meta' and n.attrs.get('name','').lower()=='tdm-reservation']
    identity={'doi_match':expected in matches,'conflicting_primary_dois':bool(matches-{expected}),
        'title_similarity':round(score,5) if score is not None else None,'version_metadata':versions,
        'version_review_required':version_risk,'version_status':'publisher_landing_page_doi_matched_not_fulltext_version_verified',
        'eligible':expected is not None and matches=={expected} and score is not None and score>=0.90 and not version_risk}
    authors=fields['authors'] or []
    truncated=any(re.search(r'\bet\s+al\.?|\bothers\b',a['name'],re.I) for a in authors)
    if truncated:fields['authors']=None
    before_authors=base.get('authors') or []
    def raw_names(xs):return [api._title(a.get('name') if isinstance(a,dict) else a) for a in xs]
    def names(xs):return [comparison_name(a.get('name') if isinstance(a,dict) else a)[0] for a in xs]
    bylines=[];byline_controls=False
    for node in nodes:
        if 'c-article-author-list' not in node.classes():continue
        group=[]
        for item in node.walk():
            if item.tag!='li':continue
            if 'c-article-author-list__show-more' in item.classes():byline_controls=True;continue
            if 'c-article-author-list__item' not in item.classes():continue
            anchors=[x for x in item.walk() if x.tag=='a' and x.text()]
            if anchors:group.append({'name':anchors[0].text()})
        if group:bylines.append(group)
    byline=max(bylines,key=len) if bylines else None
    refs_check=reference_comparison(refs,base.get('references') or [])
    return {'fields':fields,'paths':paths,'methods':methods,'identity':identity,
        'publisher_keywords_unclassified':generic_keywords,'keyword_sections':keyword_checks,
        'publisher_article_keywords':article_keywords,
        'publisher_subject_classifications':meta.get('dc.subject',[]),
        'publisher_article_keyword_author_origin':'publisher_article_keywords_used_as_author_keywords' if article_keywords else 'not_observed',
        'keyword_interpretation_rule':'article_Keywords_section_is_author_keywords; explicit_user_decision; subject_classifications_excluded',
        'structured_citation_links_not_bibliography':json_citations,
        'checks':{'document_kind':'publisher_forwarding_shell' if refresh and not matches else 'article_candidate' if matches else 'non_article_html',
            'meta_refresh_present':refresh,'tdm_reservation_metadata':tdm,
            'authors_returned':len(authors),'api_authors_count':len(before_authors),'known_author_truncation':truncated,
            'author_count_matches_api':len(authors)==len(before_authors) if before_authors else None,
            'author_name_order_matches_api':names(authors)==names(before_authors) if before_authors and authors else None,
            'author_name_order_matches_api_literal':raw_names(authors)==raw_names(before_authors) if before_authors and authors else None,
            'author_comparison_transform':'single_comma_family_given_to_given_family_then_alnum_casefold_suffix_excluded',
            'publisher_comma_names_transformed':sum(comparison_name(a['name'])[1] for a in authors),
            'duplicate_normalized_author_names':len(names(authors))-len(set(names(authors))),
            'byline_names_observed':len(byline) if byline is not None else None,
            'byline_name_order_matches_metadata':names(byline)==names(authors) if byline is not None and authors else None,
            'byline_show_more_control_observed':byline_controls,
            'author_completeness':'saved_html_metadata_list_not_fulltext_verified',
            'textual_references_returned':len(refs),'api_reference_entries':len(base.get('references') or []),
            'reference_count_matches_api':len(refs)==len(base.get('references') or []) if base.get('references') else None,
            'reference_count_declared_in_html':declared_count,'reference_count_matches_declared':len(refs)==declared_count if declared_count is not None else None,
            'reference_load_more_detected':more,'reference_content_checks':refs_check,'reference_completeness':'saved_html_textual_entries_not_fulltext_verified',
            'decoding_replacements':text.count('\ufffd'),'generic_seo_description_not_used_as_full_abstract':True}}


def _parents(node,stop=None):
    current=node.parent
    while current is not None and current is not stop:yield current;current=current.parent


_PERMIT_MARKER=object()

class Permit:
    def __init__(self,marker,task,expires):
        if marker is not _PERMIT_MARKER:raise LiveCapabilityLocked('A durably charged publisher request is required.')
        self.sha=task['request_sha256'];self.expires=expires;self.used=False
    def claim(self,task):
        if self.used or self.sha!=task['request_sha256'] or parse_utc(utc_now())>=parse_utc(self.expires):raise LiveCapabilityLocked('Publisher request permit is invalid or expired.')
        if task['request_sha256']!=sha(encode({'version':VERSION,'kind':task['kind'],'sample_id':task.get('sample_id'),'url':task['url']})):
            raise LiveCapabilityLocked('Publisher request changed after approval.')
        self.used=True


class Transport:
    def send(self,task,*,permit):
        if not isinstance(permit,Permit):raise LiveCapabilityLocked('A durably charged publisher request is required.')
        permit.claim(task);url=safe_url(task['url']);parsed=urlsplit(url);connection=None
        try:
            connection=http.client.HTTPSConnection(parsed.hostname,443,timeout=25,context=ssl.create_default_context())
            connection.set_debuglevel(0)
            connection.request('GET',parsed.path+('?' + parsed.query if parsed.query else ''),
                headers={'Accept':'text/html,application/xhtml+xml,text/plain;q=0.8','User-Agent':UA})
            response=connection.getresponse();body=response.read(MAX_BODY+1)
            if len(body)>MAX_BODY:raise ValidationError('Publisher response exceeds the local bound.')
            headers={}
            for k,v in response.getheaders():
                if k.lower() in {'content-type','location','content-language'} and len(v)<=4096:headers[k.lower()]=v
            return response.status,headers,body
        except Exception:raise ValidationError('Publisher request failed; no automatic retry.',code='HTML_TRANSPORT_FAILED') from None
        finally:
            if connection is not None:connection.close()


def project():
    path=discover_project_policy()
    if path is None:raise ValidationError('Run scopus-access init in this project first.',code='PROJECT_NOT_INITIALIZED')
    policy=load_policy(str(path));require_project_context(policy)
    if policy.project_binding is None:raise ValidationError('Publisher probe requires the existing folder-bound project.')
    store=RestrictedArtifactStore(policy.project_binding.output,allowed_roots=policy.output_roots_for(policy.project_binding.project_id))
    budget=RequestBudget(policy.control_database_path.parent/'publisher-html-probe.sqlite',policy.project_binding.project_id)
    return Path(path),policy,store,budget


def _plan(tasks,rows,trial,phase,*,parent=None,baseline=None,max_requests=15):
    policy_path,policy,store,budget=project()
    if (not isinstance(rows,list) or not 1<=len(rows)<=10 or len(tasks)>15
            or type(max_requests) is not int or not 0<=max_requests<=15):
        raise ValidationError('Select 1-10 saved records and a bound of 0-15 publisher requests.')
    rows=validate_rows(rows)
    tasks=copy.deepcopy(tasks)
    run=trial+'_p'+str(phase);root=Path('publisher-html-probe')/trial/('phase'+str(phase))
    for number,t in enumerate(tasks,1):
        safe_url(t['url']);t.update(task=number,provider='publisher_policy' if t['kind']=='robots' else 'publisher_html')
        t['request_sha256']=sha(encode({'version':VERSION,'kind':t['kind'],'sample_id':t.get('sample_id'),'url':t['url']}))
    input_ref=root/'records.jsonl';input_bytes=b''.join(encode(r) for r in rows)
    store._atomic_write(input_ref,input_bytes,immutable=True)
    operation={'version':VERSION,'trial':trial,'phase':phase,'tasks':tasks,
        'input_ref':input_ref.as_posix(),'input_sha256':sha(input_bytes),'records_count':len(rows),'baseline':baseline,
        'max_requests':max_requests}
    raw=encode(operation);op_ref=root/'operation.json';store._atomic_write(op_ref,raw,immutable=True)
    plan={'schema_version':'1.0','stage':VERSION,'run_id':run,'trial':trial,'phase':phase,
        'project_id':policy.project_binding.project_id,'policy_path':str(policy_path),'policy_sha256':sha(read_file_no_follow(policy_path)),
        'database_path':str(budget.path),'database_identity':list(budget.identity),'operation_ref':op_ref.as_posix(),'operation_sha256':sha(raw),
        'parent':parent,'max_requests':max_requests,'provider_limits':{'publisher_html':10,'publisher_policy':5},
        'trial_max_requests':30,'trial_max_pages_per_doi':2,'max_phases':2,'retry_allowance':0,
        'backend':'static','source':'publisher_html','request_cap_configurable':True,
        'fetch_code_sha256':fetch_code_hash(),'created_at_utc':utc_now()}
    control=policy.control_database_path.parent/'runs'/run;reject_symlink_components(control);control.mkdir(parents=True,mode=0o700,exist_ok=True)
    from scopus_access.fetch import _save
    info=control/'run-info.json';_save(info,plan)
    return {'run_info_path':str(info),'phase':phase,'records':len(rows),'planned_requests':len(tasks),'max_requests':max_requests,
        'backend':'static','source':'publisher_html','exact_hosts':sorted({urlsplit(t['url']).hostname for t in tasks}),
        'trial_max_requests':30,'operation_sha256':plan['operation_sha256'],'retry_allowance':0,'network_calls':0,'secret_reads':0,'scopus_requests':0}


def with_robots(pages):
    hosts=list(dict.fromkeys(urlsplit(p['url']).hostname for p in pages))
    if len(hosts)>5:raise ValidationError('Publisher phase has too many hosts.')
    return [{'kind':'robots','url':'https://'+h+'/robots.txt'} for h in hosts]+pages


def validate_rows(rows):
    """Validate the restricted input envelope without changing any saved value."""
    if not isinstance(rows,list) or not 1<=len(rows)<=10:
        raise ValidationError('Select 1-10 saved records.')
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('merged'),dict) or not isinstance(row.get('field_provenance'),dict):
            raise ValidationError('Publisher input must retain its API baseline and field provenance.')
        sid=safe_identifier(row.get('sample_id'),field='sample_id')
        if sid in seen:raise ValidationError('Publisher input sample identifiers must be unique.')
        seen.add(sid)
        doi=api.normalize_doi(row['merged'].get('doi'))
        if doi is None or api.normalize_doi(row.get('doi_normalized'))!=doi:
            raise ValidationError('Publisher input requires a normalized DOI matching its API baseline.')
    return rows


def _restricted_input(store,source,*,max_bytes):
    path=Path(source)
    if not path.is_absolute():path=Path.cwd()/path
    reject_symlink_components(path)
    try:ref=path.relative_to(store.root)
    except ValueError:raise ValidationError('Use saved input inside this project restricted storage.') from None
    return path,store._read_relative(ref,max_bytes=max_bytes)


def prepare(baseline_info,*,limit=10,max_requests=15):
    if type(limit) is not int or not 1<=limit<=10:raise ValidationError('Select 1-10 saved records.')
    baseline=api.export(baseline_info);_,_,store,_=project()
    rows=[json.loads(x) for x in store._read_relative(Path(baseline['merged_ref']),max_bytes=32*1024*1024).splitlines()][:limit]
    validate_rows(rows);pages=[]
    for row in rows:
        cr=row.get('source_candidates',{}).get('crossref')
        if not cr:raise ValidationError('Saved Crossref publisher-page evidence or explicit page targets are required.')
        payload=json.loads(store._read_relative(Path(cr['response']['body_ref']),max_bytes=MAX_BODY))['message']
        url=payload.get('resource',{}).get('primary',{}).get('URL')
        pages.append({'kind':'page','sample_id':row['sample_id'],'url':safe_url(url),'source':'saved_crossref_resource_primary'})
    return _plan(with_robots(pages),rows,'html_'+uuid.uuid4().hex,1,max_requests=max_requests,
        baseline={'run_info_path':str(Path(baseline_info).absolute()),'merged_ref':baseline['merged_ref'],'merged_sha256':baseline['merged_sha256']})


def prepare_records(records,targets,*,limit=10,max_requests=15):
    """Freeze saved records and explicit publisher pages, with no API lookup."""
    if type(limit) is not int or not 1<=limit<=10:raise ValidationError('Select 1-10 saved records.')
    _,_,store,_=project()
    records_path,raw=_restricted_input(store,records,max_bytes=64*1024*1024)
    try:source_rows=[json.loads(x) for x in raw.splitlines() if x.strip()]
    except (ValueError,UnicodeError):raise ValidationError('Saved publisher input must be JSONL.') from None
    rows=[]
    for number,row in enumerate(source_rows[:limit],1):
        if not isinstance(row,dict):raise ValidationError('Saved publisher records must be objects.')
        if 'merged' in row:
            value=copy.deepcopy(row)
        elif row.get('source_format')=='scopus_api_json':
            value={'sample_id':'D%04d'%number,'doi_normalized':api.normalize_doi(row.get('doi')),
                'merged':copy.deepcopy(row),'field_provenance':{f:{'provider':'scopus' if nonempty(row.get(f)) else None,
                    'action':'retained' if nonempty(row.get(f)) else 'missing'} for f in FIELDS}}
        else:raise ValidationError('Use saved Scopus records or merged records retaining API field provenance.')
        rows.append(value)
    validate_rows(rows)
    targets_path,target_bytes=_restricted_input(store,targets,max_bytes=65536)
    try:items=json.loads(target_bytes)
    except (ValueError,UnicodeError):raise ValidationError('Publisher targets must be a JSON list.') from None
    ids={r['sample_id'] for r in rows};seen=set();pages=[]
    if not isinstance(items,list) or not 1<=len(items)<=len(rows):raise ValidationError('Select at most one publisher page per saved record.')
    for item in items:
        if not isinstance(item,dict) or set(item)!={'sample_id','url'}:raise ValidationError('Publisher targets require sample_id and url only.')
        sid=item['sample_id']
        if sid not in ids or sid in seen:raise ValidationError('Publisher targets must match unique frozen input samples.')
        seen.add(sid);pages.append({'kind':'page','sample_id':sid,'url':safe_url(item['url']),'source':'explicit_operator_target'})
    return _plan(with_robots(pages),rows,'html_'+uuid.uuid4().hex,1,max_requests=max_requests,
        baseline={'input_ref':records_path.relative_to(store.root).as_posix(),'input_sha256':sha(raw),
            'targets_ref':targets_path.relative_to(store.root).as_posix(),'targets_sha256':sha(target_bytes)})


def context(source):
    path=Path(source).absolute();reject_symlink_components(path)
    raw=read_file_no_follow(path,max_bytes=32768);plan=parse_json_object(raw,description='publisher probe plan')
    policy_path,policy,store,budget=project()
    trial=safe_identifier(plan.get('trial'),field='trial');phase=plan.get('phase');run=trial+'_p'+str(phase)
    expected={'stage':plan.get('stage'),'project_id':policy.project_binding.project_id,'policy_path':str(policy_path),
        'policy_sha256':sha(read_file_no_follow(policy_path)),'database_path':str(budget.path),'database_identity':list(budget.identity),
        'run_id':run,'max_requests':plan.get('max_requests') if plan.get('request_cap_configurable') is True else 15,'provider_limits':{'publisher_html':10,'publisher_policy':5},
        'trial_max_requests':30,'max_phases':2,'trial_max_pages_per_doi':2,'retry_allowance':0}
    if (type(plan.get('max_requests')) is not int or not 0<=plan['max_requests']<=15):
        raise ValidationError('Publisher request cap is invalid.')
    if plan.get('stage') not in {VERSION,LEGACY_VERSION}:raise ValidationError('Unsupported publisher probe plan version.')
    if type(phase) is not int or phase not in {1,2} or any(plan.get(k)!=v for k,v in expected.items()):raise ValidationError('Publisher phase binding or budget changed.')
    if path!=policy.control_database_path.parent/'runs'/run/'run-info.json':raise ValidationError('Publisher control path changed.')
    ref=Path('publisher-html-probe')/trial/('phase'+str(phase))/'operation.json'
    if plan.get('operation_ref')!=ref.as_posix():raise ValidationError('Publisher operation path changed.')
    operation_bytes=store._read_relative(ref,max_bytes=32*1024*1024)
    if sha(operation_bytes)!=plan['operation_sha256']:raise ValidationError('Frozen publisher operation changed.')
    operation=json.loads(operation_bytes);tasks=operation['tasks']
    if operation.get('max_requests',15)!=plan['max_requests']:raise ValidationError('Frozen publisher request cap changed.')
    if operation.get('version')!=plan['stage']:raise ValidationError('Publisher operation version changed.')
    if plan['stage']==VERSION:
        input_ref=ref.parent/'records.jsonl'
        if operation.get('input_ref')!=input_ref.as_posix():raise ValidationError('Publisher input snapshot path changed.')
        input_bytes=store._read_relative(input_ref,max_bytes=32*1024*1024)
        if sha(input_bytes)!=operation['input_sha256']:raise ValidationError('Publisher input snapshot hash changed.')
        operation['records']=[json.loads(x) for x in input_bytes.splitlines()]
        if len(operation['records'])!=operation['records_count']:raise ValidationError('Publisher input count changed.')
    # v1 is a historical restricted data envelope. Preserve its exact bytes and
    # allow local analysis; new previews keep bibliography outside operations.

    if len(tasks)>15:raise ValidationError('Publisher task bounds changed.')
    validate_rows(operation['records'])
    if sum(t['kind']=='page' for t in tasks)>10 or sum(t['kind']=='robots' for t in tasks)>5:raise ValidationError('Publisher task kinds exceed the frozen phase.')
    page_ids=[]
    for i,t in enumerate(tasks,1):
        safe_url(t['url'])
        if t.get('kind') not in {'robots','page'}:raise ValidationError('Publisher task kind changed.')
        if t['task']!=i or t['provider']!=('publisher_policy' if t['kind']=='robots' else 'publisher_html') or t['request_sha256']!=sha(encode({'version':operation['version'],'kind':t['kind'],'sample_id':t.get('sample_id'),'url':t['url']})):
            raise ValidationError('Frozen publisher request changed.')
        if t['kind']=='page':page_ids.append(t['sample_id'])
    if len(set(page_ids))!=len(page_ids) or any(x not in {r['sample_id'] for r in operation['records']} for x in page_ids):raise ValidationError('Publisher page identity scope changed.')
    if phase==2:
        parent=plan['parent'];p,ps,_,_,po=context(parent['run_info_path'])
        if p['phase']!=1 or p['trial']!=trial or ps!=parent['plan_sha256'] or po['records']!=operation['records']:
            raise ValidationError('Reviewed publisher phase no longer matches its original trial.')
    return plan,sha(raw),store,budget,operation


def prepare_reviewed(parent_info,targets_file):
    """Freeze operator-selected canonical pages; this is never invoked automatically."""
    p,ps,store,budget,op=context(parent_info)
    if p['phase']!=1:raise ValidationError('Only one reviewed supplemental phase is allowed.')
    source=Path(targets_file).absolute();reject_symlink_components(source)
    try:source.relative_to(store.root)
    except ValueError:raise ValidationError('Reviewed URL input must remain in this project restricted storage.') from None
    targets=json.loads(read_file_no_follow(source,max_bytes=65536))
    if not isinstance(targets,list) or len(targets)>10:raise ValidationError('Select at most ten reviewed page targets.')
    events=budget.events(p['run_id']);terminal,unknown=api._terminal(events)
    if unknown:raise ValidationError('Original publisher request activity is unresolved.')
    originals={t['sample_id']:t for t in op['tasks'] if t['kind']=='page'};pages=[];seen=set()
    for t in targets:
        sid=t['sample_id']
        if sid not in originals or sid in seen:raise ValidationError('Reviewed publisher sample scope changed.')
        seen.add(sid);original=originals[sid];event=terminal.get(original['task'])
        if not event or event['http_status'] not in {200,301,302,303,307,308}:raise ValidationError('A failed or completed page cannot be retried as a reviewed page.')
        receipt=json.loads(store._read_relative(Path(event['receipt_ref']),max_bytes=16384))
        metadata=json.loads(store._read_relative(Path(receipt['metadata_ref']),max_bytes=16384))
        url=safe_url(t['url']);allowed_targets=[]
        if event['http_status'] in {301,302,303,307,308}:
            allowed_targets=[urljoin(original['url'],metadata.get('location',''))]
        else:
            r,h,body=saved_response(store,event);tree=HTML();tree.feed(body.decode('utf-8',errors='replace'));tree.close()
            # Explicit operator input is checked against the saved publisher forwarding page.
            # There is no automatic refresh, link traversal, or request from this parser.
            for n in tree.root.walk():
                if n.tag=='meta' and n.attrs.get('http-equiv','').lower()=='refresh':
                    match=re.search(r'(?:^|;)\s*url\s*=\s*(.+)$',n.attrs.get('content',''),re.I)
                    if match:allowed_targets.append(urljoin(original['url'],match.group(1).strip().strip('\"\'')))
        if url not in allowed_targets or url==original['url'] or family(url)!=family(original['url']):raise ValidationError('Reviewed canonical target lacks matching same-publisher evidence.')
        pages.append({'kind':'page','sample_id':sid,'url':url,'source':'operator_reviewed_saved_canonical_location'})
    return _plan(with_robots(pages),op['records'],p['trial'],2,
        parent={'run_info_path':str(Path(parent_info).absolute()),'plan_sha256':ps},baseline=op['baseline'],max_requests=p['max_requests'])


def saved_response(store,event):
    receipt=json.loads(store._read_relative(Path(event['receipt_ref']),max_bytes=16384))
    body=store._read_relative(Path(receipt['body_ref']),max_bytes=MAX_BODY)
    metadata_raw=store._read_relative(Path(receipt['metadata_ref']),max_bytes=16384)
    if (sha(body)!=receipt['body_sha256'] or sha(metadata_raw)!=receipt['metadata_sha256']
            or receipt['body_sha256']!=event['body_sha'] or receipt['request_sha256']!=event['request_sha']
            or receipt['http_status']!=event['http_status']):
        raise ValidationError('Saved publisher response evidence changed.')
    return receipt,json.loads(metadata_raw),body


def execute(source,*,execute_live=False,resume=False,transport=None,after_task=None):
    if not execute_live:raise LiveCapabilityLocked('Explicit consent for this publisher HTML phase and separate request budget is required.')
    p,ps,store,budget,op=context(source)
    if p['stage']!=VERSION:raise ValidationError('Historical publisher phase supports local analysis only; no replay is allowed.')
    with store.resume_lock(p['run_id']):
        grant=budget.grant(p,ps,resume);events=budget.events(p['run_id']);terminal,unknown=api._terminal(events)
        prior_attempts=sum(e['kind']=='ATTEMPT' for e in events)
        if unknown:raise ValidationError('Prior publisher request has uncertain completion; replay denied.')
        record_runtime(source,p,ps,backend='static',action='resume' if resume else 'execute',
            parser_version=PARSER_VERSION,fetch_code_sha256=fetch_code_hash(),
            parser_code_sha256=sha(read_file_no_follow(Path(__file__))))
        policies={};blocked=set();wire=transport
        for t in op['tasks']:
            host=urlsplit(t['url']).hostname;prior=terminal.get(t['task'])
            if prior:
                if t['kind']=='robots' and prior['code']=='response_saved':
                    r,h,b=saved_response(store,prior);policies[host]=(r['http_status'],b)
                elif t['kind']=='page' and (prior['code']!='response_saved' or prior['http_status'] in {401,403,429}
                        or prior['http_status'] is None or prior['http_status']>=500):
                    blocked.add(host)
                continue
            if t['kind']=='page':
                status,robots=policies.get(host,(None,b''));allowed=status==404
                if status==200:
                    parser=RobotFileParser();parser.parse(robots.decode('utf-8',errors='replace').splitlines());allowed=parser.can_fetch(UA,t['url'])
                if not allowed or host in blocked:
                    budget.append(p,t,'SKIP',code='robots_disallowed' if status==200 else 'publisher_policy_unavailable');continue
            try:budget.append(p,t,'ATTEMPT',code='charged')
            except ValidationError as exc:
                if exc.code=='ENRICH_BUDGET_EXHAUSTED':break
                raise
            status=None;body=None;ref=None
            try:
                if wire is None:wire=Transport()
                status,headers,body=wire.send(t,permit=Permit(_PERMIT_MARKER,t,grant['expires_at']))
                if type(status) is not int or not 100<=status<=599 or not isinstance(body,bytes) or len(body)>MAX_BODY:raise ValidationError('Publisher transport result is invalid.')
                root=Path('publisher-html-probe')/p['trial']/('phase'+str(p['phase']))/'responses'/str(t['task'])
                body_ref=root/('body-'+sha(body)+('.txt' if t['kind']=='robots' else '.html'))
                store._atomic_write(body_ref,body,immutable=True)
                # Only three non-credential response fields are retained; never cookies or full headers.
                metadata={k:headers[k] for k in ('content-type','location','content-language') if isinstance(headers.get(k),str) and len(headers[k])<=4096}
                metadata_ref=root/'response-metadata.json';metadata_bytes=encode(metadata);store._atomic_write(metadata_ref,metadata_bytes,immutable=True)
                receipt={'request_sha256':t['request_sha256'],'http_status':status,'body_ref':body_ref.as_posix(),'body_sha256':sha(body),
                    'metadata_ref':metadata_ref.as_posix(),'metadata_sha256':sha(metadata_bytes),'retrieved_at_utc':utc_now()}
                ref=root/'receipt.json';store._atomic_write(ref,encode(receipt),immutable=True)
                code='response_saved'
            except Exception:code='transport_error'
            budget.append(p,t,'RESULT',status=status,body_sha=sha(body) if body is not None else None,receipt=ref.as_posix() if ref else None,code=code)
            if t['kind']=='robots':policies[host]=(status,body or b'')
            elif status in {401,403,429} or status is None or status>=500:blocked.add(host)
            if after_task is not None:after_task(t['task'])
        result=analyze(source)
        result['network_calls']=sum(e['kind']=='ATTEMPT' for e in budget.events(p['run_id']))-prior_attempts
        result['network_calls_scope']='this_command'
        return result


def analyze(source):
    p,ps,store,budget,op=context(source)
    record_runtime(source,p,ps,backend='static',action='export',parser_version=PARSER_VERSION,
        fetch_code_sha256=fetch_code_hash(),parser_code_sha256=sha(read_file_no_follow(Path(__file__))))
    phases=[(p,op)]
    if p['phase']==2:
        parent,_,_,_,parent_op=context(p['parent']['run_info_path']);phases.insert(0,(parent,parent_op))
    candidates={};history={};events=[];http_counts={};requests=0;policy_requests=0;page_requests=0;unresolved=0;planned=0;terminal_count=0
    for plan,operation in phases:
        rows=budget.events(plan['run_id']);events.extend(rows);terminal,unknown=api._terminal(rows)
        unresolved+=len(unknown);planned+=len(operation['tasks']);terminal_count+=len(terminal)
        for t in operation['tasks']:
            ev=terminal.get(t['task'])
            if t['kind']=='page':
                history.setdefault(t['sample_id'],[]).append({'phase':plan['phase'],'url':t['url'],
                    'code':ev['code'] if ev else 'activity_unresolved' if t['task'] in unknown else 'pending',
                    'http_status':ev['http_status'] if ev else None,'receipt_ref':ev['receipt_ref'] if ev else None})
            requests+=sum(e['kind']=='ATTEMPT' and e['task']==t['task'] for e in rows)
            if any(e['kind']=='ATTEMPT' and e['task']==t['task'] for e in rows):
                if t['kind']=='robots':policy_requests+=1
                else:page_requests+=1
            if not ev or ev['kind']!='RESULT' or ev['code']!='response_saved':continue
            r,h,b=saved_response(store,ev);key=str(r['http_status']);http_counts[key]=http_counts.get(key,0)+1
            if t['kind']!='page' or r['http_status']!=200:continue
            base=next(x for x in op['records'] if x['sample_id']==t['sample_id'])
            if 'html' not in h.get('content-type','').lower():continue
            candidate=parse_html(b,base['merged'],t['url'],h.get('content-type',''))
            candidate['source']={'url':t['url'],'phase':plan['phase'],'response':r,'parser_version':PARSER_VERSION,
                'parser_code_sha256':sha(read_file_no_follow(Path(__file__).resolve()))}
            candidates.setdefault(t['sample_id'],[]).append(candidate)
    current_attempts=sum(e['kind']=='ATTEMPT' for e in budget.events(p['run_id']))
    output=[];before={f:0 for f in FIELDS};after={f:0 for f in FIELDS};filled={f:0 for f in FIELDS};available={f:0 for f in FIELDS}
    for row in op['records']:
        base=row['merged'];merged=copy.deepcopy(base);provenance=copy.deepcopy(row['field_provenance']);cs=candidates.get(row['sample_id'],[])
        for f in FIELDS:
            before[f]+=nonempty(base.get(f));available[f]+=any(nonempty(c['fields'].get(f)) for c in cs)
            if not nonempty(base.get(f)) and f!='index_keywords':
                for c in cs:
                    if c['identity']['eligible'] and nonempty(c['fields'].get(f)):
                        merged[f]=c['fields'][f];provenance[f]={'provider':'publisher_html','action':'filled_missing','source_url':c['source']['url'],
                            'field_path':c['paths'][f],'method':c['methods'][f],'raw_html_ref':c['source']['response']['body_ref'],
                            'raw_html_sha256':c['source']['response']['body_sha256'],'parser_version':PARSER_VERSION};filled[f]+=1;break
            after[f]+=nonempty(merged.get(f))
        merged['missing_fields']=[f for f in FIELDS if not nonempty(merged.get(f))]
        merged['conversion_version']=PARSER_VERSION
        if provenance.get('abstract',{}).get('provider')=='publisher_html':
            merged['abstract_source_path']='publisher_html:'+str(provenance['abstract']['field_path'])
        merged['source_format']='scopus_api_plus_publisher_html'
        chosen=next((c for c in reversed(cs) if c['identity']['eligible']),None)
        extras={k:chosen[k] if chosen else ([] if k!='publisher_article_keyword_author_origin' else 'not_observed')
            for k in ('publisher_article_keywords','publisher_subject_classifications','publisher_article_keyword_author_origin')}
        output.append({'sample_id':row['sample_id'],'doi':row['doi_normalized'],'api_baseline':row,'merged':merged,
            'field_provenance':provenance,'external_semantics':extras,'publisher_candidates':cs,'fetch_history':history.get(row['sample_id'],[])})
    generation=sha(encode({'events':events,'parser_code_sha256':sha(read_file_no_follow(Path(__file__).resolve()))}))[:24]
    root=Path('publisher-html-probe')/p['trial']/'analysis'/generation
    out=root/'merged.jsonl';store._atomic_write(out,b''.join(encode(x) for x in output),immutable=True)
    report={'version':VERSION,'parser_version':PARSER_VERSION,'run_info_path':str(Path(source).absolute()),'trial':p['trial'],'phase':p['phase'],'records':len(output),
        'requests_attempted':requests,'page_requests':page_requests,'policy_requests':policy_requests,'trial_max_requests':30,
        'max_requests_per_phase':p['max_requests'],'retry_allowance':0,'http_status_counts':http_counts,
        'trial_budget_remaining_upper_bound':30-requests,'uncertain_requests':unresolved,
        'phase_completion':'activity_unresolved' if unresolved else 'tasks_terminal' if terminal_count==planned else 'pending',
        'stage_status':'activity_unresolved' if unresolved else 'completed_with_gaps' if terminal_count==planned and any(not cs or not any(c['identity']['eligible'] for c in cs) for cs in (candidates.get(r['sample_id'],[]) for r in op['records'])) else 'completed' if terminal_count==planned else 'budget_exhausted' if current_attempts>=p['max_requests'] else 'pending',
        'page_outcomes':{code:sum(x['code']==code for xs in history.values() for x in xs) for code in {x['code'] for xs in history.values() for x in xs}},
        'scopus_requests':0,'crossref_openalex_requests':0,'secret_reads':0,'analysis_network_calls':0,
        'network_calls':0,'network_calls_scope':'this_local_command',
        'html_200_records':len(candidates),'identity_eligible_records':sum(any(c['identity']['eligible'] for c in cs) for cs in candidates.values()),
        'field_coverage':{f:{'api_nonempty':before[f],'api_plus_html_nonempty':after[f],'newly_filled':filled[f],
            'raw_html_candidate_nonempty':available[f],'still_missing':len(output)-after[f]} for f in FIELDS},
        'records_with_unclassified_publisher_keywords':sum(any(c['publisher_keywords_unclassified'] for c in cs) for cs in candidates.values()),
        'publisher_article_keyword_records':sum(bool(x['external_semantics']['publisher_article_keywords']) for x in output),
        'publisher_article_keyword_values':sum(len(x['external_semantics']['publisher_article_keywords']) for x in output),
        'publisher_fulltext_verified_complete_author_lists':0,'publisher_fulltext_verified_complete_reference_lists':0,
        'merged_ref':out.as_posix(),'merged_sha256':sha(store._read_relative(out,max_bytes=128*1024*1024)),
        'baseline':op['baseline'],'cli_integration':'publisher_html','backend':'static'}
    store._atomic_write(root/'report.json',encode(report),immutable=True)
    return dict(report,report_ref=(root/'report.json').as_posix())


CONTROL_REPORT_FIELDS=(
    'version','parser_version','run_info_path','trial','phase','records','requests_attempted',
    'page_requests','policy_requests','trial_max_requests','max_requests_per_phase','retry_allowance',
    'http_status_counts','trial_budget_remaining_upper_bound','uncertain_requests','phase_completion',
    'page_outcomes','scopus_requests','crossref_openalex_requests','secret_reads','analysis_network_calls',
    'html_200_records','identity_eligible_records','field_coverage','records_with_unclassified_publisher_keywords',
    'publisher_article_keyword_records','publisher_article_keyword_values',
    'publisher_fulltext_verified_complete_author_lists','publisher_fulltext_verified_complete_reference_lists',
    'merged_ref','merged_sha256','report_ref','cli_integration','backend',
    'source','stage_status','planned_requests','max_requests','provider_limits','budget_remaining','tasks_terminal','network_calls','network_calls_scope','consent_required')


def control_result(report):
    """Only bounded control metadata may enter the CLI JSONL stream."""
    return {key:report[key] for key in CONTROL_REPORT_FIELDS if key in report}


def status(source):
    """Inspect original request evidence offline without producing a new export."""
    p,_,store,budget,op=context(source)
    events=budget.events(p['run_id']);terminal,unknown=api._terminal(events)
    for event in terminal.values():
        if event['kind']=='RESULT' and event['code']=='response_saved':saved_response(store,event)
    attempted=sum(e['kind']=='ATTEMPT' for e in events)
    return {'source':'publisher_html','backend':'static','run_info_path':str(Path(source).absolute()),
        'records':len(op['records']),'planned_requests':len(op['tasks']),
        'max_requests':p['max_requests'],'provider_limits':p['provider_limits'],'retry_allowance':0,
        'requests_attempted':attempted,'budget_remaining':p['max_requests']-attempted,
        'uncertain_requests':len(unknown),'tasks_terminal':len(terminal),
        'stage_status':'activity_unresolved' if unknown else 'completed' if len(terminal)==len(op['tasks']) else 'budget_exhausted' if attempted>=p['max_requests'] else 'pending',
        'network_calls':0,'network_calls_scope':'this_local_command','secret_reads':0,'scopus_requests':0}


def export(source):
    return analyze(source)


def main(argv=None):
    from scopus_access.cli import _SafeArgumentParser,_SafeArgumentError,_write_control,_result
    p=_SafeArgumentParser(prog='publisher-html-probe');sub=p.add_subparsers(dest='action',required=True)
    q=sub.add_parser('prepare');q.add_argument('--baseline-run-info',required=True)
    q=sub.add_parser('prepare-reviewed');q.add_argument('--parent',required=True);q.add_argument('--targets',required=True)
    for action in ('execute','analyze'):
        q=sub.add_parser(action);q.add_argument('--run-info',required=True)
        if action=='execute':q.add_argument('--execute-live',action='store_true');q.add_argument('--resume',action='store_true')
    local=True
    try:
        a=p.parse_args(argv);local=a.action!='execute' or not a.execute_live
        if a.action=='prepare':r=prepare(a.baseline_run_info)
        elif a.action=='prepare-reviewed':r=prepare_reviewed(a.parent,a.targets)
        elif a.action=='execute':r=execute(a.run_info,execute_live=a.execute_live,resume=a.resume)
        else:r=analyze(a.run_info)
        _write_control(sys.stdout,_result('publisher-html-probe','ok',**r));return 0
    except _SafeArgumentError:
        code='INVALID_ARGUMENTS'
    except (ValidationError,LiveCapabilityLocked) as exc:
        _write_control(sys.stdout,_result('publisher-html-probe','error',code=exc.code,message=str(exc),network_calls=0 if local else None));return 2
    except Exception:code='HTML_PROBE_LOCAL_ERROR'
    _write_control(sys.stdout,_result('publisher-html-probe','error',code=code,message='Publisher probe setup or integrity check failed.',network_calls=0 if local else None));return 2

if __name__=='__main__':raise SystemExit(main())
