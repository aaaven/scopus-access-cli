"""Optional, project-bound Zotero Web API v3 sync. No automatic write retries.

Detailed plans, source fields, mappings and outcomes are restricted artifacts.
The small append-only journal contains only hashes, opaque IDs and safe counts.
"""
from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import ssl
import time
import uuid
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode

from .errors import ValidationError
from .secrets import MacOSKeychainSecretProvider
from .security import read_file_no_follow, reject_symlink_components
from .zotero_local import Context, normalize_doi
from . import zotero_local

HOST = 'api.zotero.org'
MAX_RESPONSE = 64 * 1024 * 1024
MAX_ITEMS = 100000
PLAN_LIFETIME = 3600
KEY_RE = re.compile(r'^[23456789ABCDEFGHIJKLMNPQRSTUVWXYZ]{8}$')
MARKER = 'Scopus Access Record: '
VERSION = 'zotero-sync-v1'


class ZoteroError(ValidationError):
    """Fixed, content-safe errors, never derived from remote messages."""
    def __init__(self, code='ZOTERO_STOPPED'):
        super().__init__('Zotero operation stopped; review restricted results and make a fresh plan.', code=code)


def _encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _json_constant(value):
    raise ValueError('nonfinite JSON number')


def _integer(value, code='ZOTERO_INVALID_RESPONSE'):
    if type(value) is int and value >= 0:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    raise ZoteroError(code)


def _target(ctx):
    config = ctx.target
    if config['library_type'] not in ('group', 'user') or not re.fullmatch(r'[1-9][0-9]*', config['library_id']):
        raise ZoteroError('ZOTERO_INVALID_TARGET')
    return {k: config[k] for k in ('library_type', 'library_id')}


def _slug(target):
    return target['library_type'] + '-' + target['library_id']


def _prefix(target):
    return ('/groups/' if target['library_type'] == 'group' else '/users/') + target['library_id']


def _policy_hash(ctx):
    return hashlib.sha256(read_file_no_follow(ctx.root / '.scopus-access' / 'policy.json', max_bytes=65536)).hexdigest()


def _implementation_hash():
    return _digest({'local': hashlib.sha256(Path(zotero_local.__file__).read_bytes()).hexdigest(),
                    'remote': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})


@contextmanager
def _lock(ctx):
    reject_symlink_components(ctx.control)
    ctx.control.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = ctx.control / 'sync.lock'
    reject_symlink_components(path)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ZoteroError('ZOTERO_BUSY') from None
        yield
    finally:
        os.close(fd)


class _Journal:
    def __init__(self, ctx, target):
        self.ctx, self.target = ctx, target
        self.relative = Path('journal') / _slug(target)
        self.path = ctx.storage / self.relative
        reject_symlink_components(self.path)
        self.path.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.events = []
        previous = None
        for path in sorted(self.path.glob('*.json')):
            value = ctx.read_json(path)
            if value.get('sequence') != len(self.events) + 1 or value.get('previous_sha256') != previous or value.get('target') != target:
                raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
            previous = _digest(value)
            self.events.append(value)
        self.last = previous

    def append(self, event, **fields):
        value = dict(schema_version=1, sequence=len(self.events) + 1, previous_sha256=self.last,
                     target=self.target, event=event, at_epoch=time.time(), **fields)
        relative = self.relative / ('%09d-%s.json' % (value['sequence'], uuid.uuid4().hex))
        self.ctx.write_json(relative, value)
        self.events.append(value)
        self.last = _digest(value)
        return value

    def cooldown(self):
        return max((e.get('not_before_epoch', 0) for e in self.events if e['event'] == 'cooldown'), default=0)


def _project_cooldown(ctx):
    """A target change cannot bypass a server Backoff in this project."""
    root = ctx.storage / 'journal'
    reject_symlink_components(root)
    if not root.exists(): return 0
    until = 0
    for directory in root.iterdir():
        reject_symlink_components(directory)
        match = re.fullmatch(r'(group|user)-([1-9][0-9]*)', directory.name)
        if not match or not directory.is_dir(): raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        journal = _Journal(ctx, {'library_type': match[1], 'library_id': match[2]})
        until = max(until, journal.cooldown())
    return until


class HTTPSTransport:
    """Fixed official HTTPS host; http.client does not follow redirects."""
    def request(self, method, path, headers, body):
        connection = http.client.HTTPSConnection(HOST, timeout=40, context=ssl.create_default_context())
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            return response.status, dict(response.getheaders()), raw
        finally:
            connection.close()


class _API:
    def __init__(self, ctx, journal, secret_provider=None, transport=None):
        self.ctx, self.journal = ctx, journal
        self.config = dict(ctx.target)
        self.secret_provider = secret_provider
        self.transport = transport
        self.calls = self.reads = self.writes = 0
        self.policy_hash = _policy_hash(ctx)
        self.config_hash = _digest(self.config)

    def request(self, method, path, payload=None, version=None):
        # Reparse the actual folder binding rather than trusting a stale
        # Context object after a configuration or directory replacement.
        self.ctx.revalidate(self.config)
        if _policy_hash(self.ctx) != self.policy_hash or _digest(self.ctx.target) != self.config_hash:
            raise ZoteroError('ZOTERO_PLAN_BINDING_CHANGED')
        if method not in ('GET', 'POST') or not path.startswith('/') or path.startswith('//') or any(x in path for x in ('\r', '\n', '#', '://')):
            raise ZoteroError('ZOTERO_REQUEST_INVALID')
        if time.time() < _project_cooldown(self.ctx):
            raise ZoteroError('ZOTERO_COOLDOWN')
        provider = self.secret_provider or MacOSKeychainSecretProvider(service_name=self.config['credential_service'])
        transport = self.transport or HTTPSTransport()
        headers = {'Zotero-API-Version': '3', 'User-Agent': 'scopus-access/zotero-v1', 'Accept': 'application/json'}
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        if version is not None:
            headers['If-Unmodified-Since-Version'] = str(version)
        try:
            with provider.get_api_key(self.config['credential_alias']) as key:
                self.ctx.revalidate(self.config)
                headers['Zotero-API-Key'] = key.reveal()
                self.calls += 1
                if method == 'GET': self.reads += 1
                else: self.writes += 1
                self.journal.append('request', method=method)
                status, response_headers, raw = transport.request(method, path, headers, None if payload is None else _encode(payload))
        except ZoteroError:
            raise
        except Exception:
            raise ZoteroError('ZOTERO_TRANSPORT_UNCERTAIN' if method == 'POST' else 'ZOTERO_READ_FAILED') from None
        finally:
            headers.pop('Zotero-API-Key', None)
        if type(status) is not int or not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
            raise ZoteroError('ZOTERO_INVALID_RESPONSE')
        if not 100 <= status <= 599:
            raise ZoteroError('ZOTERO_INVALID_RESPONSE')
        self.journal.append('response', method=method, status_code=status)
        response_headers = {str(k).lower(): str(v) for k, v in response_headers.items()}
        delays = []
        for name in ('backoff', 'retry-after'):
            value = response_headers.get(name)
            if value is None: continue
            try:
                if value.isascii() and value.isdigit():
                    delays.append(int(value))
                elif name == 'retry-after':
                    parsed = parsedate_to_datetime(value)
                    if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
                    delays.append(max(0, math.ceil(parsed.timestamp() - time.time())))
                else:
                    delays.append(60)
            except (ValueError, TypeError, OverflowError):
                delays.append(60)
        if status in (429, 503) and not delays:
            # No retries are made. Increasing persisted cooldown also protects
            # repeated user invocations when a server omits Retry-After.
            failures = sum(e['event'] == 'cooldown' for e in self.journal.events)
            delays.append(min(3600, 60 * 2 ** min(failures, 6)))
        if status in (429, 503):
            delays.append(1)
        if delays:
            self.journal.append('cooldown', not_before_epoch=time.time() + max(delays), status_code=status)
        if status != 200:
            raise ZoteroError('ZOTERO_HTTP_%d' % status if 100 <= status <= 599 else 'ZOTERO_INVALID_RESPONSE')
        try:
            value = json.loads(raw, object_pairs_hook=_json_pairs, parse_constant=_json_constant)
        except (ValueError, UnicodeError):
            raise ZoteroError('ZOTERO_INVALID_RESPONSE') from None
        return value, response_headers


def _check(api, target):
    value, _ = api.request('GET', '/keys/current')
    if not isinstance(value, dict) or not isinstance(value.get('access'), dict):
        raise ZoteroError('ZOTERO_PERMISSION_MISMATCH')
    if target['library_type'] == 'group':
        grants = value['access'].get('groups', {})
        if not isinstance(grants, dict): raise ZoteroError('ZOTERO_PERMISSION_MISMATCH')
        grant = grants.get(target['library_id'], grants.get('all', {}))
        group, _ = api.request('GET', _prefix(target))
        if not isinstance(group, dict) or str(group.get('id')) != target['library_id']:
            raise ZoteroError('ZOTERO_TARGET_MISMATCH')
    else:
        if str(value.get('userID')) != target['library_id']:
            raise ZoteroError('ZOTERO_TARGET_MISMATCH')
        grant = value['access'].get('user', {})
    if not isinstance(grant, dict) or grant.get('library') is not True:
        raise ZoteroError('ZOTERO_PERMISSION_MISMATCH')
    return {'key_reports_read': True, 'key_reports_write': grant.get('write') is True,
            'write_test_performed': False}


def check(ctx=None, *, secret_provider=None, transport=None):
    ctx = ctx or Context.from_project()
    with _lock(ctx):
        target = _target(ctx)
        journal = _Journal(ctx, target)
        api = _API(ctx, journal, secret_provider, transport)
        result = _check(api, target)
        journal.append('check', read_calls=api.reads, write_calls=0)
        return dict(status='checked', **target, **result, network_calls=api.calls, write_calls=0)


def snapshot(api, target):
    rows, offset, pinned, total = [], 0, None, None
    seen = set()
    while True:
        page, headers = api.request('GET', _prefix(target) + '/items?' + urlencode(dict(
            format='json', includeTrashed=1, limit=100, start=offset, sort='dateAdded', direction='asc')))
        version = _integer(headers.get('last-modified-version'))
        count = _integer(headers.get('total-results'))
        if pinned is None: pinned, total = version, count
        if version != pinned or count != total or count > MAX_ITEMS or not isinstance(page, list) or len(page) > 100:
            raise ZoteroError('ZOTERO_SNAPSHOT_CHANGED')
        for entry in page:
            if not isinstance(entry, dict) or not KEY_RE.fullmatch(entry.get('key', '')) or entry['key'] in seen:
                raise ZoteroError('ZOTERO_SNAPSHOT_KEYS')
            data = entry.get('data')
            if (not isinstance(data, dict) or data.get('key', entry['key']) != entry['key'] or
                    _integer(data.get('version', entry.get('version'))) != _integer(entry.get('version'))):
                raise ZoteroError('ZOTERO_SNAPSHOT_KEYS')
            library = entry.get('library')
            if library is not None and (not isinstance(library, dict) or str(library.get('id')) != target['library_id'] or library.get('type') != target['library_type']):
                raise ZoteroError('ZOTERO_TARGET_MISMATCH')
            seen.add(entry['key'])
        rows.extend(page)
        offset += len(page)
        if offset == total: break
        if not page or offset > total:
            raise ZoteroError('ZOTERO_SNAPSHOT_INCOMPLETE')
    versions, headers = api.request('GET', _prefix(target) + '/items?format=versions&includeTrashed=1')
    if (not isinstance(versions, dict) or _integer(headers.get('last-modified-version')) != pinned or
            set(versions) != seen or any(_integer(versions[r['key']]) != _integer(r['version']) for r in rows)):
        raise ZoteroError('ZOTERO_SNAPSHOT_INCOMPLETE')
    return rows, pinned


def _remote_ids(data, project_id):
    marker = MARKER + project_id + ':'
    extra = data.get('extra', '')
    if not isinstance(extra, str): raise ZoteroError('ZOTERO_INVALID_RESPONSE')
    ids = [line[len(marker):] for line in extra.splitlines() if line.startswith(marker)]
    dois = _doi_values(data)
    return set(ids), next(iter(dois)) if len(dois) == 1 else ''


def _doi_values(data):
    values = {normalize_doi(data.get('DOI', ''))}
    for line in data.get('extra', '').splitlines():
        if line.lower().startswith('doi:'):
            values.add(normalize_doi(line[4:]))
    return values - {''}


def _mappings(ctx, journal):
    result = {}
    for event in journal.events:
        if event['event'] != 'mapping': continue
        meta, rows = ctx.read_bundle(event['path'], 'mapping')
        if meta['content_sha256'] != event['content_sha256']:
            raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        for row in rows:
            if row['target'] != journal.target: raise ZoteroError('ZOTERO_TARGET_MISMATCH')
            result[row['record_id']] = row['item_key']
    return result


def _terminals(ctx, journal):
    """An outcome is evidence only while its pinned restricted artifact exists."""
    attempts = {e['attempt_id']: e for e in journal.events if e['event'] == 'attempt'}
    terminal = set()
    for event in journal.events:
        if event['event'] not in ('result', 'reconciled'): continue
        identifier = event['attempt_id']
        attempt = attempts.get(identifier)
        if attempt is None or identifier in terminal:
            raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        kind = 'result' if event['event'] == 'result' else 'reconciliation'
        metadata, rows = ctx.read_bundle(event['path'], kind)
        attempt_meta, actions = ctx.read_bundle(attempt['path'], 'attempt')
        if (metadata.get('target') != journal.target or metadata.get('attempt_id') != identifier or
                metadata['content_sha256'] != event.get('content_sha256') or
                attempt_meta['content_sha256'] != attempt['content_sha256'] or not isinstance(rows, list) or
                len(rows) != len(actions) or
                {(r.get('record_id'), r.get('item_key')) for r in rows} !=
                {(a['record_id'], a['item_key']) for a in actions}):
            raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        valid = {'successful', 'unchanged', 'failed'} if kind == 'result' else {'applied', 'not_applied', 'absent'}
        if any(r.get('status') not in valid for r in rows):
            raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        terminal.add(identifier)
    return terminal


def build_actions(rows, remote, templates, project_id, mappings=None, recovery_keys=None, recovery_holds=None):
    mappings, recovery_keys, recovery_holds = mappings or {}, recovery_keys or {}, recovery_holds or set()
    by_id, by_doi, by_key = defaultdict(list), defaultdict(list), {}
    for entry in remote:
        data = dict(entry['data'], key=entry['key'], version=entry['version'])
        by_key[data['key']] = data
        if data.get('itemType') in ('attachment', 'note'): continue
        ids, doi = _remote_ids(data, project_id)
        for rid in ids: by_id[rid].append(data)
        for doi in _doi_values(data): by_doi[doi].append(data)
    actions = []
    reserved = set(by_key)
    doi_counts = Counter(row.get('doi') for row in rows if row.get('doi'))
    for row in rows:
        rid, doi, wanted = row['record_id'], row.get('doi', ''), dict(row['item'])
        base = dict(record_id=rid, doi=doi)
        reason = row.get('hold_reason')
        if rid in recovery_holds: reason = 'uncertain_previous_write'
        if doi and doi_counts[doi] > 1: reason = 'duplicate_prepared_doi'
        item_type = wanted.get('itemType')
        template = templates.get(item_type)
        if not template: reason = reason or 'unsupported_item_type'
        if reason:
            actions.append(dict(base, action='hold', reason=reason)); continue
        # Strict equality after whitespace/case normalization is an identity
        # check only; no similarity-based title merging is performed.
        matches = {x['key']: x for x in by_id[rid] + (by_doi[doi] if doi else [])}
        mapped = mappings.get(rid)
        if mapped and mapped not in by_key:
            actions.append(dict(base, action='hold', reason='mapped_remote_missing', item_key=mapped)); continue
        if mapped and mapped in by_key: matches[mapped] = by_key[mapped]
        if len(matches) > 1:
            actions.append(dict(base, action='hold', reason='multiple_remote_matches')); continue
        if doi and 'DOI' not in template:
            wanted['extra'] = wanted.get('extra', '') + '\nDOI: ' + doi
        wanted = {k: v for k, v in wanted.items() if k in template}
        if not {'itemType', 'title', 'extra'}.issubset(template):
            actions.append(dict(base, action='hold', reason='unsupported_template')); continue
        if matches:
            old = next(iter(matches.values()))
            ids, old_doi = _remote_ids(old, project_id)
            if len(_doi_values(old)) > 1:
                actions.append(dict(base, action='hold', reason='remote_doi_conflict', item_key=old['key'])); continue
            if old.get('deleted'):
                actions.append(dict(base, action='hold', reason='remote_trashed', item_key=old['key'])); continue
            foreign = any(line.startswith(MARKER) and not line.startswith(MARKER + project_id + ':')
                          for line in old.get('extra', '').splitlines())
            if (foreign or (ids and ids != {rid}) or (old_doi and doi and old_doi != doi) or
                    (old.get('title') and ' '.join(str(old['title']).casefold().split()) != ' '.join(str(wanted['title']).casefold().split()))):
                actions.append(dict(base, action='hold', reason='remote_identity_conflict', item_key=old['key'])); continue
            if old.get('itemType') != item_type:
                actions.append(dict(base, action='hold', reason='remote_type_conflict', item_key=old['key'])); continue
            conflicts = {k: {'local': v, 'remote': old[k]} for k, v in wanted.items()
                         if k not in ('itemType', 'extra', 'tags', 'collections', 'relations') and v and old.get(k) and old[k] != v}
            patch = {k: v for k, v in wanted.items() if v and not old.get(k) and k not in ('itemType', 'tags', 'collections', 'relations')}
            # Existing nonempty extra is never amended, including manual imports.
            if patch:
                payload = dict(patch, key=old['key'], version=old['version'])
                actions.append(dict(base, action='update', reason='fill_empty_fields', item_key=old['key'], payload=payload, conflicts=conflicts))
            else:
                actions.append(dict(base, action='skip', reason='already_present', item_key=old['key'], conflicts=conflicts))
        else:
            key = recovery_keys.get(rid)
            if key is None:
                while True:
                    key = ''.join(secrets.choice('23456789ABCDEFGHIJKLMNPQRSTUVWXYZ') for _ in range(8))
                    if key not in reserved: break
            if key in reserved:
                actions.append(dict(base, action='hold', reason='item_key_collision')); continue
            reserved.add(key)
            payload = dict(template)
            payload.update(wanted)
            payload.update(key=key, version=0)
            actions.append(dict(base, action='create', reason='no_identity_match', item_key=key, payload=payload, conflicts={}))
    return actions


def _recover(ctx, journal, remote):
    terminal = _terminals(ctx, journal)
    by_key = {x['key']: x for x in remote}
    keys, holds = {}, set()
    for event in list(journal.events):
        if event['event'] != 'attempt' or event['attempt_id'] in terminal: continue
        metadata, actions = ctx.read_bundle(event['path'], 'attempt')
        if metadata['content_sha256'] != event['content_sha256']:
            raise ZoteroError('ZOTERO_EVIDENCE_INVALID')
        outcomes = []
        for action in actions:
            rid, key = action['record_id'], action['item_key']
            old = by_key.get(key)
            status = 'unresolved'
            if old is None and action['action'] == 'create':
                # Reuse exactly this assigned key on any successor plan.
                keys[rid], status = key, 'absent'
            elif old is not None:
                data = old['data']
                if action['action'] == 'create':
                    ids, doi = _remote_ids(data, ctx.project_id)
                    if (ids == {rid} and (not action['doi'] or doi == action['doi']) and not data.get('deleted') and
                            all(data.get(k) == v for k, v in action['payload'].items() if k not in ('key', 'version') and v)):
                        status = 'applied'
                elif all(data.get(k) == v for k, v in action['payload'].items() if k not in ('key', 'version')):
                    status = 'applied'
                elif old['version'] == action['payload']['version']:
                    status = 'not_applied'
            if status == 'unresolved': holds.add(rid)
            outcomes.append(dict(record_id=rid, item_key=key, status=status))
        bundle = ctx.bundle('reconciliation', outcomes, {'target': journal.target, 'attempt_id': event['attempt_id']})
        outcome_meta, _ = ctx.read_bundle(bundle['path'], 'reconciliation')
        if any(x['status'] == 'unresolved' for x in outcomes):
            journal.append('reconciliation_pending', attempt_id=event['attempt_id'], path=bundle['path'],
                           content_sha256=outcome_meta['content_sha256'])
        else:
            journal.append('reconciled', attempt_id=event['attempt_id'], path=bundle['path'],
                           content_sha256=outcome_meta['content_sha256'])
    return keys, holds


def _save_mappings(ctx, journal, rows):
    if not rows: return
    bundle = ctx.bundle('mapping', rows, {'target': journal.target})
    metadata, _ = ctx.read_bundle(bundle['path'], 'mapping')
    journal.append('mapping', path=bundle['path'], content_sha256=metadata['content_sha256'], count=len(rows))


def plan(ctx=None, prepared=None, *, secret_provider=None, transport=None):
    ctx = ctx or Context.from_project()
    with _lock(ctx):
        target = _target(ctx)
        metadata, rows = zotero_local.verify_prepared(ctx, prepared)
        if not isinstance(rows, list): raise ZoteroError('ZOTERO_INVALID_PREPARED')
        ids = [r.get('record_id') for r in rows]
        if len(set(ids)) != len(ids) or any(not isinstance(rid, str) or not rid for rid in ids):
            raise ZoteroError('ZOTERO_INVALID_PREPARED')
        journal = _Journal(ctx, target)
        api = _API(ctx, journal, secret_provider, transport)
        permissions = _check(api, target)
        remote, version = snapshot(api, target)
        keys, holds = _recover(ctx, journal, remote)
        templates = {}
        for kind in sorted({r['item']['itemType'] for r in rows if not r.get('hold_reason')}):
            if not isinstance(kind, str) or not re.fullmatch(r'[A-Za-z]+', kind):
                raise ZoteroError('ZOTERO_INVALID_PREPARED')
            template, _ = api.request('GET', '/items/new?' + urlencode({'itemType': kind}))
            if not isinstance(template, dict) or template.get('itemType') != kind:
                raise ZoteroError('ZOTERO_INVALID_TEMPLATE')
            templates[kind] = template
        actions = build_actions(rows, remote, templates, ctx.project_id, _mappings(ctx, journal), keys, holds)
        counts = dict(Counter(a['action'] for a in actions))
        frozen = dict(target=target, prepared_path=str(ctx.storage / 'prepared' / metadata['bundle_id'] / 'bundle.json'), prepared_sha256=metadata['content_sha256'],
                      prepared_manifest_sha256=_digest(metadata),
                      policy_sha256=_policy_hash(ctx), config_sha256=_digest(ctx.target), library_version=version,
                      created_epoch=time.time(), expires_epoch=time.time() + PLAN_LIFETIME, permissions=permissions,
                      actions=actions, recovery_pending=len(holds), implementation=VERSION,
                      implementation_sha256=_implementation_hash(), templates=templates, remote_snapshot=remote)
        bundle = ctx.bundle('plan', frozen, {'target': target, 'prepared_sha256': metadata['content_sha256']})
        planmeta, _ = ctx.read_bundle(bundle['path'], 'plan')
        journal.append('plan', path=bundle['path'], content_sha256=planmeta['content_sha256'], counts=counts)
        _save_mappings(ctx, journal, [dict(target=target, record_id=a['record_id'], item_key=a['item_key'])
                                      for a in actions if a['action'] == 'skip'])
        return dict(status='planned', path=bundle['path'], counts=counts, recovery_pending=len(holds),
                    network_calls=api.calls, read_calls=api.reads, write_calls=0, expires_epoch=frozen['expires_epoch'])


def _parse_result(value, actions):
    if not isinstance(value, dict): raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
    sections = ('successful', 'unchanged', 'failed')
    if any(not isinstance(value.get(section), dict) for section in sections):
        raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
    keys = [key for section in sections for key in value[section]]
    expected = {str(i) for i in range(len(actions))}
    if len(keys) != len(set(keys)) or set(keys) != expected:
        raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
    outcomes = []
    for index, action in enumerate(actions):
        key = str(index)
        status = next(s for s in sections if key in value[s])
        entry = value[status][key]
        result = dict(record_id=action['record_id'], item_key=action['item_key'], status=status)
        if status != 'failed':
            item_key = entry.get('key') if isinstance(entry, dict) else entry
            if item_key != action['item_key']: raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
        else:
            if (not isinstance(entry, dict) or type(entry.get('code')) is not int or
                    not 400 <= entry['code'] <= 599 or entry.get('key', action['item_key']) != action['item_key']):
                raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
            result['status_code'] = entry['code']
        outcomes.append(result)
    return outcomes


def push(ctx=None, plan_path=None, max_items=None, execute_live=False, *, secret_provider=None, transport=None):
    # These gates precede locks, credential reads and transport construction.
    if execute_live is not True: raise ZoteroError('ZOTERO_EXECUTION_REQUIRED')
    if type(max_items) is not int or not 1 <= max_items <= MAX_ITEMS:
        raise ZoteroError('ZOTERO_BOUND_REQUIRED')
    ctx = ctx or Context.from_project()
    with _lock(ctx):
        target = _target(ctx)
        metadata, frozen = ctx.read_bundle(plan_path, 'plan')
        if (frozen.get('target') != target or frozen.get('policy_sha256') != _policy_hash(ctx) or
                frozen.get('config_sha256') != _digest(ctx.target) or frozen.get('implementation') != VERSION or
                frozen.get('implementation_sha256') != _implementation_hash()):
            raise ZoteroError('ZOTERO_PLAN_BINDING_CHANGED')
        if not frozen['created_epoch'] <= time.time() <= frozen['expires_epoch']:
            raise ZoteroError('ZOTERO_PLAN_EXPIRED')
        preparedmeta, _ = zotero_local.verify_prepared(ctx, frozen['prepared_path'])
        if (preparedmeta['content_sha256'] != frozen['prepared_sha256'] or
                _digest(preparedmeta) != frozen['prepared_manifest_sha256']):
            raise ZoteroError('ZOTERO_PREPARED_CHANGED')
        if frozen.get('recovery_pending'): raise ZoteroError('ZOTERO_RECOVERY_REQUIRED')
        journal = _Journal(ctx, target)
        digest = metadata['content_sha256']
        if not any(e['event'] == 'plan' and e.get('content_sha256') == digest and
                   Path(e.get('path', '')) == Path(plan_path) for e in journal.events):
            raise ZoteroError('ZOTERO_PLAN_UNRECOGNIZED')
        if any(e['event'] == 'attempt' and e.get('plan_sha256') == digest for e in journal.events):
            raise ZoteroError('ZOTERO_PLAN_SPENT')
        terminal = _terminals(ctx, journal)
        if any(e['event'] == 'attempt' and e['attempt_id'] not in terminal for e in journal.events):
            raise ZoteroError('ZOTERO_RECOVERY_REQUIRED')
        all_changes = [a for a in frozen['actions'] if a['action'] in ('create', 'update')]
        changes = all_changes[:max_items]
        if not changes:
            return dict(status='unchanged', network_calls=0, write_calls=0, successful=0, failed=0, unchanged=0, path=str(plan_path))
        api = _API(ctx, journal, secret_provider, transport)
        permissions = _check(api, target)
        if not permissions['key_reports_write']: raise ZoteroError('ZOTERO_WRITE_PERMISSION_REQUIRED')
        _, headers = api.request('GET', _prefix(target) + '/items?format=versions&includeTrashed=1')
        version = _integer(headers.get('last-modified-version'))
        if version != frozen['library_version']: raise ZoteroError('ZOTERO_PLAN_STALE')
        outcomes = []
        for offset in range(0, len(changes), 50):
            # Recheck immutable local authorization before every batch.
            if _policy_hash(ctx) != frozen['policy_sha256'] or _digest(ctx.target) != frozen['config_sha256'] or time.time() > frozen['expires_epoch']:
                raise ZoteroError('ZOTERO_PLAN_BINDING_CHANGED')
            preparedmeta, _ = zotero_local.verify_prepared(ctx, frozen['prepared_path'])
            if (preparedmeta['content_sha256'] != frozen['prepared_sha256'] or
                    _digest(preparedmeta) != frozen['prepared_manifest_sha256']):
                raise ZoteroError('ZOTERO_PREPARED_CHANGED')
            batch = changes[offset:offset + 50]
            attempt_id = uuid.uuid4().hex
            attempt = ctx.bundle('attempt', batch, {'target': target, 'plan_sha256': digest})
            attemptmeta, _ = ctx.read_bundle(attempt['path'], 'attempt')
            journal.append('attempt', attempt_id=attempt_id, path=attempt['path'],
                           content_sha256=attemptmeta['content_sha256'], plan_sha256=digest, count=len(batch))
            # No automatic resend after this durable point, even on 429/503.
            value, headers = api.request('POST', _prefix(target) + '/items', [a['payload'] for a in batch], version)
            result = _parse_result(value, batch)
            next_version = _integer(headers.get('last-modified-version'))
            if next_version < version or (any(r['status'] == 'successful' for r in result) and next_version <= version):
                raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
            for entry in value['successful'].values():
                if isinstance(entry, dict):
                    if ('version' in entry and _integer(entry['version']) != next_version) or (
                            isinstance(entry.get('data'), dict) and 'version' in entry['data'] and
                            _integer(entry['data']['version']) != next_version):
                        raise ZoteroError('ZOTERO_BATCH_UNCERTAIN')
            result_bundle = ctx.bundle('result', result, {'target': target, 'attempt_id': attempt_id})
            result_meta, _ = ctx.read_bundle(result_bundle['path'], 'result')
            journal.append('result', attempt_id=attempt_id, path=result_bundle['path'], count=len(result),
                           content_sha256=result_meta['content_sha256'])
            _save_mappings(ctx, journal, [dict(target=target, record_id=r['record_id'], item_key=r['item_key'])
                                          for r in result if r['status'] != 'failed'])
            outcomes.extend(result)
            version = next_version
            if any(r['status'] == 'failed' for r in result): break
        summary_bundle = ctx.bundle('push_result', outcomes, {'target': target, 'plan_sha256': digest})
        counts = Counter(r['status'] for r in outcomes)
        return dict(status='completed_with_failures' if counts['failed'] else 'completed', path=summary_bundle['path'],
                    network_calls=api.calls, read_calls=api.reads, write_calls=api.writes,
                    successful=counts['successful'], unchanged=counts['unchanged'], failed=counts['failed'],
                    remaining=len(all_changes) - len(outcomes))
