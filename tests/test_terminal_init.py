"""Offline Terminal handoff tests; never open an app or touch real Keychain."""
import fcntl
import io
import json
import multiprocessing
import time
import os
import shlex
import subprocess
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from scopus_access import cli, project, secrets, terminal_init as bridge
from scopus_access.errors import SecretProviderError
from scopus_access.ledger import Ledger
from scopus_access.policy import load_policy
import test_project_init as fixtures


def _agent_worker(root, name, start):
    root = Path(root)
    os.chdir(root)
    def prompt():
        if sys.stdin.isatty():
            return secrets.SecretValue(fixtures.SECRET)
        raise SecretProviderError(reason='interaction_not_allowed', stage='credential_prompt', backend='terminal_input')
    class Writer:
        def contains_api_key(self, alias):
            return (root/'mock-writes').exists()
        def add_api_key(self, alias, label, secret):
            assert secret.reveal().encode() == fixtures.SECRET
            with (root/'mock-writes').open('ab') as stream: stream.write(b'write\n')
    def launch(command):
        with (root/'mock-windows').open('ab') as stream: stream.write(b'opened\n')
        time.sleep(0.3)
        with mock.patch.object(sys.stdin,'isatty',return_value=True):
            bridge.child_main(shlex.split(command)[-4:])
    output = io.StringIO()
    with redirect_stdout(output), redirect_stderr(io.StringIO()), \
            mock.patch.object(sys,'platform','darwin'), \
            mock.patch.object(sys.stdin,'isatty',return_value=False), \
            mock.patch.object(secrets,'MacOSKeychainWriter',return_value=Writer()), \
            mock.patch.object(secrets,'prompt_api_key',side_effect=prompt), \
            mock.patch.object(secrets,'_AppleKeychain',side_effect=AssertionError('native Keychain forbidden')), \
            mock.patch.object(bridge,'_launch',side_effect=launch):
        start.wait(10)
        code=cli.main(['init'])
    (root/name).write_text(json.dumps({'code':code,'rows':[json.loads(v) for v in output.getvalue().splitlines()]}))


class TerminalInitTests(unittest.TestCase):
    setUp = fixtures.ProjectInitTests.setUp
    assert_no_secret_files = fixtures.ProjectInitTests.assert_no_secret_files

    def input_prompt(self):
        if sys.stdin.isatty():
            return secrets.SecretValue(fixtures.SECRET)
        raise SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input")

    def launch_child(self, command):
        words = shlex.split(command)
        self.commands.append(words)
        self.assertEqual(words[:4], ['cd', str(self.root), '&&', 'exec'])
        self.assertEqual(words[4:6], [sys.executable, '-I'])
        self.assertEqual(Path(words[6]), Path(bridge.__file__).resolve())
        # Simulate the real Terminal's TTY. The installed-process test separately
        # exercises this private entry against installed package code.
        with mock.patch.object(sys.stdin, 'isatty', return_value=True), \
                mock.patch.object(Path, 'cwd', return_value=self.root), \
                mock.patch.object(os, 'chdir'):
            self.child_code = bridge.child_main(words[-4:])
        self.packet = json.loads(Path(words[-3]).read_text())
        self.assertNotIn(fixtures.SECRET.decode(), json.dumps(self.packet))

    def invoke(self, launcher=None, *, directory=None, timeout=None):
        self.commands = []
        output, errors = io.StringIO(), io.StringIO()
        real = bridge.initialize_in_terminal
        def handoff(*args, **kwargs):
            if timeout is not None:
                kwargs['timeout'] = timeout
            return real(*args, **kwargs)
        with redirect_stdout(output), redirect_stderr(errors), \
                mock.patch.object(Path, 'cwd', return_value=directory or self.root), \
                mock.patch.object(sys, 'platform', 'darwin'), \
                mock.patch.object(sys.stdin, 'isatty', return_value=False), \
                mock.patch.object(secrets, 'MacOSKeychainWriter', return_value=self.writer), \
                mock.patch.object(secrets, 'prompt_api_key', side_effect=lambda: self.input_prompt()), \
                mock.patch.object(secrets, '_AppleKeychain', side_effect=AssertionError('real Keychain forbidden')), \
                mock.patch.object(cli, 'MacOSKeychainSecretProvider', side_effect=AssertionError('key read forbidden')), \
                mock.patch.object(cli, 'UrllibTransport', side_effect=AssertionError('network transport forbidden')), \
                mock.patch.object(bridge, '_launch', side_effect=launcher or self.launch_child), \
                mock.patch.object(bridge, 'initialize_in_terminal', side_effect=handoff):
            code = cli.main(['init'])
        self.assertNotIn(fixtures.SECRET.decode(), output.getvalue()+errors.getvalue())
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(rows), 1)
        return code, rows[0], errors.getvalue()

    def test_two_agent_processes_open_at_most_one_window_and_store_once(self):
        context=multiprocessing.get_context('fork')
        start=context.Event()
        processes=[context.Process(target=_agent_worker,args=(self.root,'worker-'+str(n)+'.json',start)) for n in range(2)]
        for process in processes: process.start()
        start.set()
        try:
            for process in processes:
                process.join(15)
                self.assertEqual(process.exitcode,0)
        finally:
            for process in processes:
                if process.is_alive(): process.terminate(); process.join()
        values=[json.loads((self.root/('worker-'+str(n)+'.json')).read_text()) for n in range(2)]
        self.assertTrue(any(v['code']==0 for v in values))
        self.assertTrue(all(v['code'] in {0,2} for v in values))
        self.assertEqual((self.root/'mock-writes').read_bytes(),b'write\n')
        self.assertEqual((self.root/'mock-windows').read_bytes(),b'opened\n')
        project_ids={r['project_id'] for v in values for r in v['rows'] if 'project_id' in r}
        self.assertEqual(len(project_ids),1)
        self.assert_no_secret_files()

    def test_noninteractive_init_opens_terminal_and_returns_original_success_json(self):
        code, row, error = self.invoke()
        self.assertEqual((code, row['status']), (0, 'initialized'))
        self.assertTrue(row['credential_written'])
        self.assertEqual((row['network_calls'], row['secret_reads'], row['quota_state']), (0, 0, 'UNVERIFIED'))
        self.assertEqual(len(self.commands), 1)
        self.assertIn('Terminal', error)
        ledger=Ledger(row['database_path'], require_existing_identity=True)
        self.assertEqual(ledger.request_attempt_count(row['project_id']), 0)
        self.assertEqual(len(self.writer.added), 1)
        self.assertFalse(list((self.root/'.scopus-access/runs').glob('terminal-init-*.json')))
        self.assert_no_secret_files()

    def test_repeat_ready_project_from_child_does_not_open_or_prompt(self):
        code, first, _ = self.invoke()
        self.assertEqual(code, 0)
        child = self.root/'a/b'; child.mkdir(parents=True)
        count = self.writer.checks
        code, row, _ = self.invoke(lambda cmd: self.fail('ready project must not open Terminal'), directory=child)
        self.assertEqual((code,row['status']), (0,'reused'))
        self.assertEqual(row['project_id'],first['project_id'])
        self.assertEqual(self.writer.checks,count)
        self.assertEqual(len(self.writer.added),1)

    def test_timeout_preserves_pending_identity_then_retry_succeeds(self):
        code, row, _ = self.invoke(lambda cmd: None, timeout=0)
        self.assertEqual((code,row['code']), (4,'TERMINAL_INIT_TIMEOUT'))
        path=self.root/'.scopus-access/policy.json'
        pending=json.loads(path.read_text())['project_binding']
        self.assertEqual(pending['state'],'pending')
        code, row, _ = self.invoke()
        self.assertEqual(code,0)
        self.assertEqual(row['project_id'],pending['project_id'])
        self.assertEqual(len(self.writer.added),1)
        self.assert_no_secret_files()

    def test_user_cancel_in_child_returns_safe_specific_reason_and_keeps_pending(self):
        # A side-effect lambda resolves the current method when the child runs.
        original = self.input_prompt
        def prompt():
            if sys.stdin.isatty():
                raise SecretProviderError(reason='access_denied',stage='credential_prompt',backend='terminal_input')
            return original()
        with mock.patch.object(self,'input_prompt',side_effect=prompt):
            code,row,_=self.invoke()
        self.assertEqual((code,row['code'],row['provider_reason']),(4,'SECRET_UNAVAILABLE','access_denied'))
        self.assertEqual(row['network_request_sent'],False)
        self.assertFalse(self.writer.added)
        self.assert_no_secret_files()

    def test_open_failure_does_not_prompt_or_overwrite_and_can_retry(self):
        code,row,_=self.invoke(lambda command: (_ for _ in ()).throw(bridge.TerminalInitError('TERMINAL_OPEN_FAILED')))
        self.assertEqual((code,row['code']),(2,'TERMINAL_OPEN_FAILED'))
        self.assertFalse(self.writer.added)
        code,row,_=self.invoke()
        self.assertEqual(code,0)

    def test_command_paths_are_shell_quoted_and_never_include_secret(self):
        self.root=self.base/"survey 'quote' $(touch SHOULD_NOT_EXIST); with spaces"
        self.root.mkdir()
        code,row,_=self.invoke()
        self.assertEqual(code,0)
        self.assertFalse((self.root/'SHOULD_NOT_EXIST').exists())
        self.assertNotIn(fixtures.SECRET.decode(),str(self.commands))

    def test_another_parent_lock_prevents_second_window(self):
        self.invoke(lambda command:None,timeout=0)
        with (self.root/'.scopus-access/terminal-init.lock').open('rb') as lock:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
            code,row,_=self.invoke(lambda cmd:self.fail('duplicate window'))
        self.assertEqual((code,row['code']),(2,'TERMINAL_INIT_IN_PROGRESS'))
        self.assertFalse(self.writer.added)

    def test_success_packet_cannot_fabricate_ready_configuration(self):
        def fabricated(command):
            args=shlex.split(command)[-4:]
            packet=bridge._packet(args[2],0,{'status':'initialized','project_id':args[2],'credential_written':True})
            Path(args[1]).write_text(json.dumps(packet))
        code,row,_=self.invoke(fabricated)
        self.assertEqual((code,row['code']),(2,'TERMINAL_INIT_FAILED'))
        self.assertFalse(self.writer.added)

    def test_malformed_packet_never_echoes_arbitrary_text_or_extra_fields(self):
        def malformed(command):
            result=Path(shlex.split(command)[-3])
            result.write_text(json.dumps({'message':fixtures.SECRET.decode()}))
        code,row,_=self.invoke(malformed)
        self.assertEqual((code,row['code']),(2,'TERMINAL_INIT_FAILED'))
        self.assert_no_secret_files()

    def test_symlink_and_fifo_completion_files_fail_without_blocking_or_reading_outside(self):
        for kind in ('symlink', 'fifo'):
            def unsafe(command):
                target=Path(shlex.split(command)[-3])
                if kind=='symlink':
                    outside=self.base/'outside-packet.json'
                    outside.write_text(fixtures.SECRET.decode())
                    target.symlink_to(outside)
                else:
                    os.mkfifo(target,0o600)
            code,row,_=self.invoke(unsafe)
            self.assertEqual((code,row['code']),(2,'TERMINAL_INIT_FAILED'))
        self.assertFalse(self.writer.added)

    def test_changed_credential_reference_during_handoff_fails_before_child_prompt(self):
        def changed(command):
            args=shlex.split(command)[-4:]
            path=self.root/'.scopus-access/policy.json'
            value=json.loads(path.read_text())
            value['project_binding']['alias']='scopus_'+'e'*32
            path.write_text(json.dumps(value))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(bridge.child_main(args),2)
        code,row,_=self.invoke(changed)
        self.assertEqual((code,row['code']),(2,'TERMINAL_INIT_FAILED'))
        self.assertFalse(self.writer.added)

    def test_existing_pending_key_is_reused_without_a_window_or_second_write(self):
        self.invoke(lambda cmd:None,timeout=0)
        value=json.loads((self.root/'.scopus-access/policy.json').read_text())
        self.writer.items.add(value['project_binding']['alias'])
        code,row,_=self.invoke(lambda cmd:self.fail('existing pending credential must be reused'))
        self.assertEqual((code,row['status'],row['credential_written']),(0,'initialized',False))
        self.assertFalse(self.writer.added)

    def test_only_missing_hidden_prompt_triggers_terminal_handoff(self):
        with mock.patch.object(sys,'platform','darwin'),mock.patch.object(sys.stdin,'isatty',return_value=False):
            self.assertTrue(bridge.needs_terminal(SecretProviderError(reason='interaction_not_allowed',stage='credential_prompt',backend='terminal_input')))
            for reason,stage in [('access_denied','credential_prompt'),('interaction_not_allowed','credential_metadata'),('keychain_timeout','credential_read')]:
                self.assertFalse(bridge.needs_terminal(SecretProviderError(reason=reason,stage=stage,backend='terminal_input')))
        with mock.patch.object(sys,'platform','linux'):
            self.assertFalse(bridge.needs_terminal(SecretProviderError(reason='interaction_not_allowed',stage='credential_prompt',backend='terminal_input')))

    def test_parent_cancel_releases_lock_preserves_binding_and_allows_retry(self):
        code,row,_=self.invoke(lambda command:(_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertEqual((code,row['provider_reason'],row['failure_stage']),(4,'access_denied','terminal_initialization'))
        self.assertFalse(self.writer.added)
        code,row,_=self.invoke()
        self.assertEqual(code,0)
        self.assertEqual(len(self.writer.added),1)

    def test_child_without_real_tty_returns_error_packet_instead_of_recursing(self):
        self.invoke(lambda command:None,timeout=0)
        binding=bridge._binding(self.root)
        result=self.root/'.scopus-access/runs'/('terminal-init-'+'b'*32+'.json')
        with mock.patch.object(sys.stdin,'isatty',return_value=False), \
                mock.patch.object(bridge,'_launch',side_effect=AssertionError('must not recurse')), \
                mock.patch.object(os,'chdir'), redirect_stderr(io.StringIO()):
            code=bridge.child_main([str(self.root),str(result),binding.project_id,bridge._binding_digest(binding)])
        packet=bridge._read_packet(result,binding.project_id)
        self.assertEqual((code,packet['secret_error']['provider_reason']),(4,'interaction_not_allowed'))
        self.assertFalse(self.writer.added)

    def test_native_launch_is_fixed_app_no_secret_and_diagnostics_are_suppressed(self):
        with mock.patch.object(bridge.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run:
            bridge._launch('SYNTHETIC_NON_SECRET_COMMAND')
        args,kwargs=run.call_args
        self.assertEqual(args[0][:2],['/usr/bin/osascript','-e'])
        self.assertIn('application "Terminal"',args[0][2])
        self.assertEqual(args[0][-1],'SYNTHETIC_NON_SECRET_COMMAND')
        self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
        with mock.patch.object(bridge.subprocess,'run',side_effect=OSError(fixtures.SECRET.decode())):
            with self.assertRaises(bridge.TerminalInitError) as caught: bridge._launch('SYNTHETIC_COMMAND')
        self.assertNotIn(fixtures.SECRET.decode(),str(caught.exception))

    def test_private_child_rejects_other_project_and_untrusted_result_path(self):
        self.invoke(lambda command:None,timeout=0)
        project_id=json.loads((self.root/'.scopus-access/policy.json').read_text())['project_binding']['project_id']
        for identity,result in [('project_'+'f'*32,self.root/'.scopus-access/runs'/('terminal-init-'+'a'*32+'.json')),
                                (project_id,self.base/'outside.json')]:
            with redirect_stderr(io.StringIO()):
                code=bridge.child_main([str(self.root),str(result),identity,bridge._binding_digest(bridge._binding(self.root))])
            self.assertEqual(code,2)
            self.assertFalse(result.exists())
        self.assertFalse(self.writer.added)
