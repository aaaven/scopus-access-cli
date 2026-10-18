"""Recover an unused, credential-failed check without a second admission."""
import dataclasses
import hashlib
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scopus_access import cli
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.errors import SecretProviderError, LiveCapabilityLocked
from scopus_access.integration import build_preflight_resume_authorization, build_resume_authorization, IntegrationError
from scopus_access.ledger import Ledger
from scopus_access.manifest import load_task_manifest
from scopus_access.policy import load_policy, authorize_live_execution
import test_local_cli as fixtures


class PreflightResumeTests(unittest.TestCase):
    setUp = fixtures.LocalCliTests.setUp
    invoke = fixtures.LocalCliTests.invoke

    def fail_before_send(self):
        self.text = '\r\n(\n\t' + fixtures.QUERY + '\r\n)\n'
        self.query.write_bytes(self.text.encode())
        self.secret.get_api_key = mock.Mock(side_effect=SecretProviderError(
            reason='interaction_not_allowed', stage='credential_read',
            backend='macos_security_framework', system_error_code=-25308))
        code, rows = self.invoke('check', '--query-file', str(self.query), '--execute-live')
        self.assertEqual(code, 6, rows)
        self.assertEqual(rows[-1]['stop_reason'], 'secret_unavailable')
        self.info_path = rows[0]['run_info_path']
        self.info = json.loads(Path(self.info_path).read_text())
        self.task = json.loads(Path(self.info['manifest_path']).read_text())
        self.seed = next(r for r in self.ledger.rows('task_reservation') if r['event_seq'] == 1)
        self.assertEqual(self.seed['actual_requests'], 0)
        self.assertEqual(self.seed['reserved_remaining'], 1)
        self.assertFalse(self.ledger.rows('request_usage'))
        self.execution_id = rows[-1]['run_id']
        self.store = RestrictedArtifactStore(self.policy.project_binding.output,
                                           allowed_roots=self.policy.output_roots_for(self.info['project_id']))
        self.secret = fixtures.Secrets()

    def build(self, *, survey=False):
        policy = load_policy(self.info['policy_path'])
        manifest = load_task_manifest(self.info['manifest_path'], policy)
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        builder = build_resume_authorization if survey else build_preflight_resume_authorization
        return builder(ledger=self.ledger, manifest=manifest, authorization=permit,
                       artifacts=self.store, run_id=self.info['parent_run_id'], api_name='scopus_search')

    def resume(self, local=False):
        return self.invoke('resume', '--run-info', self.info_path, '--execute-live', local=local)

    def test_credential_failure_resumes_same_multiline_query_and_reservation_once(self):
        self.fail_before_send()
        original_package = Path(self.task['query_manifest_path']).read_bytes()
        capability = self.build()
        self.assertEqual(capability.reservation_id, self.seed['reservation_id'])
        self.assertEqual((capability.max_requests, capability.page_size, capability.retry_allowance), (1, 1, 0))
        with mock.patch.object(Ledger, '_admit_preflight', side_effect=AssertionError('must reuse original reservation')):
            code, rows = self.resume()
        self.assertEqual(code, 0, rows)
        self.assertEqual(len(self.wire.urls), 1)
        self.assertEqual(parse_qs(urlsplit(self.wire.urls[0]).query)['query'], [self.text])
        seeds = [r for r in self.ledger.rows('task_reservation') if r['event_seq'] == 1 and r['admission_decision'] == 'ADMITTED']
        self.assertEqual([r['reservation_id'] for r in seeds], [self.seed['reservation_id']])
        self.assertEqual(Path(self.task['query_manifest_path']).read_bytes(), original_package)
        operation = json.loads(original_package)['queries']['scopus_search']
        self.assertEqual(operation['query'], self.text)
        self.assertEqual(operation['provenance']['source_text'], self.text)
        self.assertEqual(operation['provenance']['transport_sha256'], hashlib.sha256(self.text.encode()).hexdigest())
        checkpoint = self.store.load_checkpoint(self.execution_id)
        self.assertTrue(checkpoint.complete)
        receipt = self.store.load_receipt(self.execution_id)
        self.assertEqual((receipt.status, receipt.requests_attempted), ('completed', 1))
        before = Path(self.store.root / receipt.checkpoint_ref).read_bytes()
        code, rows = self.resume(local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        self.assertEqual(Path(self.store.root / receipt.checkpoint_ref).read_bytes(), before)
        self.assertEqual(len(self.wire.urls), 1)

    def test_zero_send_repeated_key_failures_keep_original_budget(self):
        self.fail_before_send()
        self.secret.get_api_key = mock.Mock(side_effect=SecretProviderError(reason='keychain_timeout'))
        code, rows = self.resume()
        self.assertEqual(code, 6, rows)
        self.assertEqual(rows[-1]['requests_attempted'], 0)
        self.assertFalse(self.ledger.rows('request_usage'))
        self.secret = fixtures.Secrets()
        code, rows = self.resume()
        self.assertEqual(code, 0, rows)
        self.assertEqual(len(self.wire.urls), 1)

    def test_resume_preview_is_local_and_does_not_admit_or_resolve_key(self):
        self.fail_before_send()
        before = self.ledger.rows('task_reservation')
        code, rows = self.invoke('resume', '--run-info', self.info_path, local=True)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]['requests_attempted'], 0)
        self.assertEqual(self.ledger.rows('task_reservation'), before)
        self.assertFalse(self.wire.urls)

    def test_recorded_attempt_denies_resume_and_another_initial_preflight(self):
        self.fail_before_send()
        attempt = self.ledger.record_request_attempt(self.seed['reservation_id'], 'search', 'synthetic-page', 0)
        self.assertTrue(attempt.allowed)
        code, rows = self.resume(local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        code, rows = self.invoke('check', '--query-file', str(self.query), '--execute-live', local=True)
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED, rows)
        self.assertEqual(rows[-1]['reason_code'], 'UNVERIFIED_PREFLIGHT_ALREADY_USED')
        self.assertFalse(self.wire.urls)

    def test_query_hash_change_is_rejected_before_secret_access(self):
        self.fail_before_send()
        Path(self.task['query_manifest_path']).write_text('{}')
        code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_frozen_policy_hash_change_is_rejected_before_secret_access(self):
        self.fail_before_send()
        path = Path(self.info['policy_path'])
        path.write_bytes(path.read_bytes() + b'\n')
        code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_canonical_policy_disabled_blocks_resume(self):
        self.fail_before_send()
        value = json.loads(self.policy_path.read_text())
        value['live_capability_enabled'] = False
        self.policy_path.write_text(json.dumps(value))
        code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_release_hash_change_is_rejected(self):
        self.fail_before_send()
        path = Path(self.task['release_evidence_path'])
        path.write_bytes(path.read_bytes() + b'\n')
        code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)

    def test_expired_original_grant_reports_explicit_reauthorization_required(self):
        self.fail_before_send()
        class Future(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(timezone.utc) + timedelta(hours=2)
        with mock.patch('scopus_access.manifest.datetime', Future):
            code, rows = self.resume(local=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED, rows)
        self.assertEqual(rows[-1]['code'], 'RELEASE_EXPIRED')
        self.assertIn('explicit reauthorization', rows[-1]['message'])
        self.assertFalse(self.ledger.rows('request_usage'))
        self.assertEqual(self.ledger.rows('task_reservation')[-1]['reserved_remaining'], 1)

    def test_unlisted_raw_file_blocks_recovery_even_without_response_manifest(self):
        self.fail_before_send()
        raw = self.store.root / 'raw' / self.execution_id / 'stray.json'
        raw.parent.mkdir(parents=True)
        raw.write_bytes(b'{"synthetic":true}')
        code, rows = self.resume(local=True)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        self.assertNotEqual(code, 0)

    def test_non_secret_failure_receipt_is_not_recoverable_as_preflight(self):
        self.fail_before_send()
        receipt = self.store.load_receipt(self.execution_id)
        self.store.write_receipt(dataclasses.replace(receipt, stop_reason='attempt_record_failed'))
        code, rows = self.resume(local=True)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        self.assertNotEqual(code, 0)

    def test_missing_receipt_or_checkpoint_and_checkpoint_tamper_fail_closed(self):
        self.fail_before_send()
        receipt_path = self.store.root / self.store.receipt_ref(self.execution_id)
        checkpoint_path = self.store.root / self.store.checkpoint_ref(self.execution_id)
        receipt_bytes, checkpoint_bytes = receipt_path.read_bytes(), checkpoint_path.read_bytes()
        for target, original in ((receipt_path, receipt_bytes), (checkpoint_path, checkpoint_bytes)):
            target.unlink()
            code, rows = self.resume(local=True)
            self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
            self.assertNotEqual(code, 0)
            target.write_bytes(original)
        checkpoint = self.store.load_checkpoint(self.execution_id)
        self.store.write_checkpoint(dataclasses.replace(checkpoint, requests_attempted=1))
        code, rows = self.resume(local=True)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        self.assertNotEqual(code, 0)

    def test_sealed_permit_tamper_is_rejected_and_survey_builder_stays_separate(self):
        self.fail_before_send()
        with self.assertRaises(IntegrationError):
            self.build(survey=True)
        policy = load_policy(self.info['policy_path'])
        manifest = load_task_manifest(self.info['manifest_path'], policy)
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        with self.assertRaises(LiveCapabilityLocked):
            build_preflight_resume_authorization(ledger=self.ledger, manifest=manifest,
                authorization=dataclasses.replace(permit, query_manifest_sha256='0'*64), artifacts=self.store,
                run_id=self.info['parent_run_id'], api_name='scopus_search')


    def test_resume_lock_exclusively_creates_then_reuses_same_inode(self):
        self.fail_before_send()
        real_open = os.open
        calls = []
        def opened(path, flags, *args, **kwargs):
            if str(path).endswith('.resume.lock'): calls.append(flags)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch('scopus_access.artifacts.os.open', side_effect=opened):
            with self.store.resume_lock(self.execution_id): pass
            lock = self.store.root / 'locks' / (self.execution_id + '.resume.lock')
            inode = lock.stat().st_ino
            with self.store.resume_lock(self.execution_id): pass
        self.assertEqual(lock.stat().st_ino, inode)
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[0] & os.O_EXCL)
        self.assertTrue(calls[1] & os.O_EXCL)
        self.assertFalse(calls[2] & os.O_CREAT)
        self.assertFalse(self.wire.urls)

    def test_resume_lock_symlink_and_missing_existing_lock_fail_before_send(self):
        self.fail_before_send()
        locks = self.store.root / 'locks'
        locks.mkdir(exist_ok=True)
        outside = self.root / 'outside-lock'
        outside.write_bytes(b'synthetic retained file')
        lock = locks / (self.execution_id + '.resume.lock')
        lock.symlink_to(outside)
        code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)
        self.assertEqual(outside.read_bytes(), b'synthetic retained file')
        lock.unlink()
        real_open = os.open
        def missing(path, flags, *args, **kwargs):
            if str(path).endswith('.resume.lock'):
                if flags & os.O_EXCL: raise FileExistsError()
                raise FileNotFoundError()
            return real_open(path, flags, *args, **kwargs)
        with mock.patch('scopus_access.artifacts.os.open', side_effect=missing):
            code, rows = self.resume(local=True)
        self.assertNotEqual(code, 0, rows)
        self.assertFalse(self.wire.urls)
        self.assertFalse(self.ledger.rows('request_usage'))
