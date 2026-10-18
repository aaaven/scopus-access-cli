"""Explicit UI handoff with mocked Terminal, credential provider and transport."""
import fcntl
import hashlib
import json
import os
import shlex
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from scopus_access import cli, terminal_run as bridge
from scopus_access.errors import SecretProviderError
from scopus_access.ledger import Ledger
import test_local_cli as fixtures
import test_preflight_resume as recovery


class TerminalRunTests(unittest.TestCase):
    setUp = fixtures.LocalCliTests.setUp
    invoke = fixtures.LocalCliTests.invoke
    fail_before_send = recovery.PreflightResumeTests.fail_before_send

    def launch(self, command):
        words = shlex.split(command)
        self.assertEqual(words[:4], ['cd', str(self.root), '&&', 'exec'])
        self.assertEqual(words[4:6], [sys.executable, '-I'])
        self.assertEqual(Path(words[6]), Path(bridge.__file__).resolve())
        self.assertNotIn(fixtures.SECRET.decode(), command)
        self.assertNotIn(fixtures.QUERY, command)
        with mock.patch.object(sys.stdin, 'isatty', return_value=True), mock.patch.object(os, 'chdir'):
            self.child_code = bridge.child_main(words[-6:])
        self.result = Path(words[-2])
        if self.result.exists():
            self.packet = json.loads(self.result.read_text())
            self.assertNotIn(fixtures.SECRET.decode(), json.dumps(self.packet))
            self.assertNotIn(fixtures.TITLE, json.dumps(self.packet))

    def terminal(self, command, source, *, launcher=None, live=True, local=False, timeout=0):
        original = bridge.run_in_terminal
        def run(args): return original(args, timeout=timeout)
        arguments = [command, '--run-info', str(source), '--terminal']
        if live: arguments.append('--execute-live')
        with mock.patch.object(sys, 'platform', 'darwin'), \
                mock.patch.object(bridge, '_launch', side_effect=launcher or self.launch) as opened, \
                mock.patch.object(bridge, 'run_in_terminal', side_effect=run):
            result = self.invoke(*arguments, local=local)
            self.windows = opened.call_count
        return result

    def preview(self, command='check'):
        code, rows = self.invoke(command, '--query-file', str(self.query), local=True)
        self.assertEqual(code, 0, rows)
        return rows[0]['run_info_path']

    def test_execute_frozen_preview_in_terminal_reports_original_control_events(self):
        source = self.preview()
        before = json.loads(Path(source).read_text())
        self.query.write_text('SYNTHETIC_CHANGED_INPUT')
        self.secret.callback = lambda: self.assertTrue(sys.stdin.isatty())
        code, rows = self.terminal('execute', source)
        self.assertEqual(code, 0, rows)
        self.assertEqual(self.windows, 1)
        self.assertEqual(rows[0]['query_package_sha256'], before['query_package_sha256'])
        self.assertEqual(rows[-1]['event'], 'run_completed')
        self.assertEqual(rows[-1]['requests_attempted'], 1)
        self.assertEqual(len(self.wire.urls), 1)
        self.assertFalse(self.result.exists())
        self.assertEqual(json.loads(Path(source).read_text()), before)
        code, status = self.invoke('status', '--run-info', rows[0]['run_info_path'], local=True)
        self.assertEqual((code, status[0]['requests_attempted']), (0, 1))

    def test_zero_send_key_failure_terminal_resume_reuses_exact_one_request_budget(self):
        self.fail_before_send()
        original = Path(self.info_path).read_bytes()
        with mock.patch.object(Ledger, '_admit_preflight', side_effect=AssertionError('no second admission')):
            code, rows = self.terminal('resume', self.info_path)
        self.assertEqual(code, 0, rows)
        self.assertEqual(len(self.wire.urls), 1)
        self.assertEqual(rows[-1]['requests_attempted'], 1)
        self.assertEqual(Path(self.info_path).read_bytes(), original)
        seeds = [row for row in self.ledger.rows('task_reservation') if row['event_seq'] == 1]
        self.assertEqual([row['reservation_id'] for row in seeds], [self.seed['reservation_id']])
        code, rows = self.terminal('resume', self.info_path, local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[-1]['code'], 'PREFLIGHT_RESUME_DENIED')
        self.assertEqual(len(self.wire.urls), 1)

    def test_terminal_is_explicit_and_requires_original_info_and_live_consent(self):
        source = self.preview()
        code, rows = self.terminal('execute', source, live=False, local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(self.windows, 0)
        with mock.patch.object(bridge, '_launch') as opened:
            code, rows = self.invoke('execute', '--run-info', source, local=True)
        self.assertEqual(code, 2, rows)
        opened.assert_not_called()
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_timeout_retains_prepared_execution_and_reports_unknown_activity(self):
        source = self.preview()
        code, rows = self.terminal('execute', source, launcher=lambda command: None, local=True)
        self.assertEqual(code, 6, rows)
        self.assertEqual(rows[-1]['code'], 'TERMINAL_RUN_TIMEOUT')
        self.assertIsNone(rows[-1]['network_calls'])
        self.assertEqual(rows[-1]['execution_counts_status'], 'unknown')
        saved = json.loads(Path(rows[0]['run_info_path']).read_text())
        self.assertEqual(saved['parent_run_id'], rows[0]['parent_run_id'])
        self.assertEqual(saved['mode'], 'run')
        self.assertFalse(self.ledger.rows('request_usage'))

    def test_missing_completion_after_send_never_reports_zero_or_retries(self):
        self.fail_before_send()
        def drop(command):
            self.launch(command)
            self.result.unlink()
        code, rows = self.terminal('resume', self.info_path, launcher=drop)
        self.assertEqual(code, 6, rows)
        self.assertIsNone(rows[-1]['network_calls'])
        self.assertEqual(len(self.wire.urls), 1)
        code, rows = self.terminal('resume', self.info_path, local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(len(self.wire.urls), 1)

    def test_unchanged_original_expiry_is_reported_without_fresh_grant(self):
        self.fail_before_send()
        before = Path(self.info_path).read_bytes()
        class Future(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(timezone.utc) + timedelta(hours=2)
        with mock.patch('scopus_access.manifest.datetime', Future):
            code, rows = self.terminal('resume', self.info_path, local=True)
        self.assertEqual(code, 3, rows)
        self.assertEqual(rows[-1]['code'], 'RELEASE_EXPIRED')
        self.assertFalse(self.ledger.rows('request_usage'))
        self.assertEqual(Path(self.info_path).read_bytes(), before)

    def test_tampered_policy_query_or_run_info_reject_before_opening_terminal(self):
        self.fail_before_send()
        for path in (Path(self.info['policy_path']), Path(self.task['query_manifest_path']), Path(self.info_path)):
            data = path.read_bytes()
            path.write_bytes(b'{}')
            code, rows = self.terminal('resume', self.info_path, local=True)
            self.assertNotEqual(code, 0, rows)
            self.assertEqual(self.windows, 0)
            path.write_bytes(data)
        self.assertFalse(self.wire.urls)

    def test_changed_run_info_before_child_rejects_without_reading_key(self):
        self.fail_before_send()
        def change(command):
            path = Path(shlex.split(command)[-5])
            path.write_bytes(path.read_bytes() + b'\n')
            self.launch(command)
        code, rows = self.terminal('resume', self.info_path, launcher=change, local=True)
        self.assertEqual(self.child_code, 2)
        self.assertEqual(code, 6, rows)
        self.assertFalse(self.wire.urls)

    def test_same_run_lock_prevents_a_second_terminal(self):
        self.fail_before_send()
        source = Path(self.info_path)
        lock = source.parent / ('terminal-' + hashlib.sha256(str(source).encode()).hexdigest()[:32] + '.lock')
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, rows = self.terminal('resume', source, local=True)
        self.assertEqual(code, 2, rows)
        self.assertEqual(rows[-1]['code'], 'TERMINAL_RUN_IN_PROGRESS')
        self.assertEqual(self.windows, 0)

    def test_child_non_tty_never_recursively_launches_or_reads_key(self):
        self.fail_before_send()
        def no_tty(command):
            with mock.patch.object(sys.stdin, 'isatty', return_value=False):
                self.child_code = bridge.child_main(shlex.split(command)[-6:])
        code, rows = self.terminal('resume', self.info_path, launcher=no_tty, local=True)
        self.assertEqual(self.child_code, 2)
        self.assertEqual(code, 6, rows)
        self.assertFalse(self.wire.urls)

    def test_native_secret_failure_diagnostics_survive_safe_completion(self):
        self.fail_before_send()
        self.secret.get_api_key = mock.Mock(side_effect=SecretProviderError(
            reason='access_denied', stage='credential_read', backend='macos_security_framework', system_error_code=-128))
        code, rows = self.terminal('resume', self.info_path)
        self.assertEqual(code, 6, rows)
        failure = next(row for row in rows if row.get('code') == 'secret_unavailable')
        self.assertEqual(failure['provider_reason'], 'access_denied')
        self.assertFalse(failure['network_request_sent'])
        self.assertFalse(self.wire.urls)

    def test_packet_symlinks_fifos_foreign_events_and_arbitrary_content_are_rejected(self):
        self.fail_before_send()
        def bad(command):
            words = shlex.split(command)
            result = Path(words[-2])
            packet = dict(schema_version='1.0', source_sha256=words[-4], action=words[-3], exit_code=0,
                          records=[{'event': 'run_completed', 'query': fixtures.QUERY}])
            result.write_text(json.dumps(packet))
        code, rows = self.terminal('resume', self.info_path, launcher=bad, local=True)
        self.assertEqual(code, 6, rows)
        self.assertEqual(rows[-1]['code'], 'TERMINAL_RUN_FAILED')
        def fifo(command): os.mkfifo(shlex.split(command)[-2])
        code, rows = self.terminal('resume', self.info_path, launcher=fifo, local=True)
        self.assertEqual(code, 6, rows)
        outside = self.root / 'outside'
        outside.write_text(fixtures.SECRET.decode())
        def symlink(command): Path(shlex.split(command)[-2]).symlink_to(outside)
        code, rows = self.terminal('resume', self.info_path, launcher=symlink, local=True)
        self.assertEqual(code, 6, rows)
        self.assertFalse(self.wire.urls)

    def test_regular_survey_execute_uses_existing_runner_and_budget(self):
        code, rows = self.invoke('check', '--query-file', str(self.query), '--execute-live')
        self.assertEqual(code, 0, rows)
        source = self.preview('search')
        code, rows = self.terminal('execute', source)
        self.assertEqual(code, 0, rows)
        self.assertEqual(len(self.wire.urls), 2)
        self.assertEqual(rows[-1]['event'], 'run_completed')
