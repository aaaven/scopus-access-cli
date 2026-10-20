"""Append-only project-bound request accounting shared by public sources.

Budgets count real dispatched attempts, independently of Scopus quota evidence.
The on-disk schema remains compatible with prior enrichment ledgers.
"""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from .errors import ValidationError, LiveCapabilityLocked, ReleaseExpired
from .security import reject_symlink_components
from .quota import utc_now, parse_utc

_SCHEMA='''
CREATE TABLE IF NOT EXISTS enrichment_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),instance_id TEXT NOT NULL,project_id TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enrichment_grant(run_id TEXT PRIMARY KEY,project_id TEXT NOT NULL,plan_sha TEXT NOT NULL,operation_sha TEXT NOT NULL,max_requests INTEGER NOT NULL,provider_limits TEXT NOT NULL,approved_at TEXT NOT NULL,expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrichment_event(event_id INTEGER PRIMARY KEY,run_id TEXT NOT NULL,task INTEGER NOT NULL,provider TEXT NOT NULL,request_sha TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('ATTEMPT','RESULT','CACHE','SKIP')),http_status INTEGER,body_sha TEXT,receipt_ref TEXT,code TEXT NOT NULL,cost_units REAL,recorded_at TEXT NOT NULL,UNIQUE(run_id,task,kind));
'''
for _table in ('enrichment_identity','enrichment_grant','enrichment_event'):
    for _verb in ('UPDATE','DELETE'):
        _SCHEMA+='CREATE TRIGGER IF NOT EXISTS no_'+_verb.lower()+'_'+_table+' BEFORE '+_verb+' ON '+_table+" BEGIN SELECT RAISE(ABORT,'append_only'); END;\n"


@lru_cache(maxsize=1)
def _expected_schema():
    c=sqlite3.connect(':memory:')
    try:
        c.executescript(_SCHEMA)
        return {(r[0],r[1]):' '.join(r[2].lower().split()) for r in c.execute("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL")}
    finally:c.close()


def _check_schema(connection):
    actual={(r[0],r[1]):' '.join(r[2].lower().split()) for r in connection.execute("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL")}
    if actual!=_expected_schema():raise ValidationError('Enrichment evidence schema definition changed.')


class RequestBudget:
    def __init__(self,path,project):
        self.path=Path(path);self.project=project
        reject_symlink_components(self.path)
        with self.connect() as c:
            objects=c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            if objects and {x[0] for x in objects}!={'enrichment_identity','enrichment_grant','enrichment_event'}:
                raise ValidationError('Enrichment ledger has an unexpected schema.')
            if objects:_check_schema(c)
            else:
                c.executescript(_SCHEMA)
                _check_schema(c)
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT * FROM enrichment_identity').fetchone();st=self.path.stat()
                if row is None:
                    if c.execute('SELECT COUNT(*) FROM enrichment_grant').fetchone()[0] or c.execute('SELECT COUNT(*) FROM enrichment_event').fetchone()[0]:
                        raise ValidationError('Enrichment ledger identity is missing from an existing run.')
                    c.execute('INSERT INTO enrichment_identity VALUES(1,?,?,?,?)',(str(uuid.uuid4()),project,st.st_dev,st.st_ino))
                    row=c.execute('SELECT * FROM enrichment_identity').fetchone()
                if row['project_id']!=project or (row['device'],row['inode'])!=(st.st_dev,st.st_ino):
                    raise ValidationError('Enrichment ledger identity changed.')
                self.identity=(row['instance_id'],row['device'],row['inode'])
                c.commit()
            except BaseException: c.rollback();raise
        self.path.chmod(0o600)
    @contextmanager
    def connect(self):
        reject_symlink_components(self.path)
        c=sqlite3.connect(str(self.path),timeout=10,isolation_level=None);c.row_factory=sqlite3.Row
        try:
            c.execute('PRAGMA busy_timeout=10000')
            if hasattr(self,'identity'):
                _check_schema(c)
                row=c.execute('SELECT * FROM enrichment_identity').fetchone();st=self.path.stat()
                if (row is None or row['project_id']!=self.project
                        or (row['instance_id'],row['device'],row['inode'])!=self.identity
                        or (st.st_dev,st.st_ino)!=self.identity[1:]):
                    raise ValidationError('Enrichment evidence database identity changed.')
            yield c
        finally:c.close()
    def events(self,run):
        with self.connect() as c:return [dict(r) for r in c.execute('SELECT * FROM enrichment_event WHERE run_id=? ORDER BY event_id',(run,))]
    def grant(self,plan,plan_sha,resume):
        now=utc_now()
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT * FROM enrichment_grant WHERE run_id=?',(plan['run_id'],)).fetchone()
                if row is None:
                    if resume: raise ValidationError('There is no admitted enrichment run to resume.')
                    expires=(parse_utc(now)+timedelta(hours=24)).isoformat().replace('+00:00','Z')
                    c.execute('INSERT INTO enrichment_grant VALUES(?,?,?,?,?,?,?,?)',
                        (plan['run_id'],plan['project_id'],plan_sha,plan['operation_sha256'],plan['max_requests'],json.dumps(plan['provider_limits'],sort_keys=True),now,expires))
                    row=c.execute('SELECT * FROM enrichment_grant WHERE run_id=?',(plan['run_id'],)).fetchone()
                elif not resume:
                    raise ValidationError('This enrichment run already has a grant; use resume or local status.',code='ENRICH_ALREADY_ADMITTED')
                if row['project_id']!=plan['project_id'] or row['plan_sha']!=plan_sha or row['operation_sha']!=plan['operation_sha256']:
                    raise ValidationError('Enrichment grant no longer matches the frozen plan.')
                if parse_utc(now)>=parse_utc(row['expires_at']):
                    raise ReleaseExpired()
                c.commit();return dict(row)
            except BaseException:c.rollback();raise
    def append(self,plan,task,kind,*,status=None,body_sha=None,receipt=None,code='none',cost=None):
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                grant=c.execute('SELECT * FROM enrichment_grant WHERE run_id=?',(plan['run_id'],)).fetchone()
                if grant is None or parse_utc(utc_now())>=parse_utc(grant['expires_at']):raise LiveCapabilityLocked('Enrichment grant is unavailable or expired.')
                rows=c.execute('SELECT * FROM enrichment_event WHERE run_id=? AND task=?',(plan['run_id'],task['task'])).fetchall()
                if kind=='ATTEMPT':
                    if rows: raise ValidationError('This DOI/provider task already has activity; request replay denied.')
                    count=c.execute("SELECT COUNT(*) FROM enrichment_event WHERE run_id=? AND kind='ATTEMPT'",(plan['run_id'],)).fetchone()[0]
                    provider_count=c.execute("SELECT COUNT(*) FROM enrichment_event WHERE run_id=? AND provider=? AND kind='ATTEMPT'",(plan['run_id'],task['provider'])).fetchone()[0]
                    if count>=grant['max_requests'] or provider_count>=json.loads(grant['provider_limits'])[task['provider']]:
                        raise ValidationError('Original enrichment request budget is exhausted.',code='ENRICH_BUDGET_EXHAUSTED')
                elif kind=='RESULT':
                    if len(rows)!=1 or rows[0]['kind']!='ATTEMPT':raise ValidationError('Enrichment result has no unique charged attempt.')
                elif rows:raise ValidationError('Enrichment task already has a terminal event.')
                c.execute('INSERT INTO enrichment_event(run_id,task,provider,request_sha,kind,http_status,body_sha,receipt_ref,code,cost_units,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (plan['run_id'],task['task'],task['provider'],task['request_sha256'],kind,status,body_sha,receipt,code,cost,utc_now()))
                c.commit()
            except BaseException:c.rollback();raise
