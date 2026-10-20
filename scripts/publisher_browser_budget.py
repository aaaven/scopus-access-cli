"""Offline admission model for an optional browser adapter; no browser or network.

A callback model cannot prove interception coverage. Live redirect/WebSocket,
crash recovery and per-page DOM cache wiring still require separate acceptance.
"""
import copy
import re
from urllib.parse import urlsplit
from scopus_access import enrichment as api
from scopus_access.errors import ValidationError,LiveCapabilityLocked
from scopus_access.security import safe_identifier

TYPES=frozenset({'document','script','stylesheet','xhr','fetch','manifest','other'})


class RequestGate:
    def __init__(self,plan,budget,store,*,execute_live=False,resume=False):
        plan=copy.deepcopy(plan)
        if not execute_live:raise LiveCapabilityLocked('Explicit separate browser request consent is required.')
        if plan.get('robots_decision')!='allow':raise LiveCapabilityLocked('Browser execution requires a valid retained robots decision; browser success is not authority.')
        safe_identifier(plan.get('run_id'),field='run_id')
        pages=plan.get('provider_limits');domains=plan.get('domains')
        if (not isinstance(pages,dict) or not pages or set(pages)!=set(domains or {})
                or any(type(v) is not int or not 1<=v<=1000 for v in pages.values())
                or type(plan.get('max_requests')) is not int or not 1<=plan['max_requests']<=10000):
            raise ValidationError('Browser request bounds are invalid.')
        for sid,hosts in domains.items():
            safe_identifier(sid,field='sample_id')
            if not isinstance(hosts,list) or not hosts or any(not isinstance(h,str) or len(h)>253 or re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',h) is None for h in hosts):
                raise ValidationError('Freeze exact browser hosts, without wildcard domains.')
        self.plan=plan;self.budget=budget;self.store=store
        # Grant and original budget are reused; this does not launch a transport.
        self.grant=budget.grant(plan,api.digest(api.encode(plan)),resume)
        _,unknown=api._terminal(budget.events(plan['run_id']))
        if resume and unknown:raise LiveCapabilityLocked('Browser request completion is uncertain; no implicit page reload or replay.')

    def admit(self,sample_id,url,resource_type):
        if sample_id not in self.plan['provider_limits']:raise ValidationError('Browser page is outside the frozen scope.')
        if not isinstance(url,str) or len(url)>8192 or any(ord(c)<33 or ord(c)==127 for c in url):raise ValidationError('Browser request URL is invalid.')
        try:parts=urlsplit(url);port=parts.port
        except ValueError:raise ValidationError('Browser request URL is invalid.') from None
        if parts.scheme!='https' or parts.hostname not in self.plan['domains'][sample_id] or port not in {None,443} or parts.username or parts.password or parts.fragment:
            raise ValidationError('Browser request host is outside the frozen scope.')
        if resource_type not in TYPES:raise ValidationError('Browser resource type is not admitted.')
        # All page callbacks (document, scripts, CSS, fetch, XHR) are charged.
        with self.store.resume_lock('browser_admit_'+self.plan['run_id']):
            rows=self.budget.events(self.plan['run_id'])
            ordinal=max((e['task'] for e in rows),default=0)+1
            task={'task':ordinal,'provider':sample_id,'request_sha256':api.digest(api.encode({
                'url_sha256':api.digest(url.encode()),'resource_type':resource_type,'ordinal':ordinal}))}
            self.budget.append(self.plan,task,'ATTEMPT',code='dispatch_'+resource_type)
        return task

    def complete(self,task,*,http_status=None,failed=False):
        if failed and http_status is not None:raise ValidationError('Browser terminal outcome is ambiguous.')
        if not failed and (type(http_status) is not int or not 100<=http_status<=599):raise ValidationError('Browser HTTP outcome is invalid.')
        self.budget.append(self.plan,task,'RESULT',status=http_status,
            code='network_failed' if failed else 'response_received')

    def route_callback(self,route,sample_id):
        try:task=self.admit(sample_id,route.request.url,route.request.resource_type)
        except (ValidationError,LiveCapabilityLocked):route.abort();return None
        try:route.continue_()
        except Exception:
            # Attempt remains charged. Do not interpret route errors as zero send.
            raise ValidationError('Browser dispatch completion is uncertain; no automatic retry.') from None
        return task
