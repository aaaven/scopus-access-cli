"""Interactive human feedback does not change stdout, exits or access activity."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from scopus_access import cli, project, terminal
from scopus_access.errors import SecretProviderError
from scopus_access.secrets import SecretValue
import test_project_init as init_fixtures


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class TerminalFeedbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'human-project'
        self.root.mkdir()
        self.writer = init_fixtures.FakeWriter()

    def invoke_init(self, interactive=True):
        out, err = io.StringIO(), TtyBuffer() if interactive else io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(Path, 'cwd', return_value=self.root), \
                mock.patch('sys.stdin.isatty', return_value=interactive), \
                mock.patch('scopus_access.secrets.MacOSKeychainWriter', return_value=self.writer), \
                mock.patch('scopus_access.secrets.prompt_api_key', side_effect=lambda: SecretValue(init_fixtures.SECRET)), \
                mock.patch.object(cli, 'MacOSKeychainSecretProvider', side_effect=AssertionError('no credential read')), \
                mock.patch.object(cli, 'UrllibTransport', side_effect=AssertionError('no HTTP')):
            code = cli.main(['init'])
        self.assertNotIn(init_fixtures.SECRET.decode(), out.getvalue() + err.getvalue())
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_interactive_initialized_reused_and_unverified_have_clear_human_meaning(self):
        code, row, text = self.invoke_init()
        self.assertEqual(code, 0)
        self.assertEqual(row['status'], 'initialized')
        self.assertEqual(row['quota_state'], 'UNVERIFIED')
        self.assertIn('初始化完成', text)
        self.assertIn('macOS 钥匙串', text)
        self.assertIn('Scopus API 尚未验证', text)
        self.assertIn('human-project', text)
        for field in ('project_id', 'database_path', 'key_alias', 'keychain_label'):
            self.assertNotIn(row[field], text)
        code, reused, text = self.invoke_init()
        self.assertEqual(code, 0)
        self.assertEqual(reused['project_id'], row['project_id'])
        self.assertIn('已复用当前项目配置', text)
        self.assertEqual(len(self.writer.added), 1)
        self.assertEqual(reused['network_calls'], 0)
        self.assertEqual(reused['secret_reads'], 0)

    def test_noninteractive_init_keeps_json_and_silent_stderr(self):
        code, row, text = self.invoke_init(False)
        self.assertEqual(code, 0)
        self.assertEqual(text, '')
        self.assertIn('database_path', row)
        self.assertIn('keychain_label', row)
        self.assertEqual(row['quota_state'], 'UNVERIFIED')

    def test_interactive_and_noninteractive_control_json_are_identical(self):
        record = cli._result('init', 'initialized', display_name='Synthetic project', quota_state='UNVERIFIED')
        outputs = []
        for interactive in (False, True):
            out, err = io.StringIO(), TtyBuffer() if interactive else io.StringIO()
            with redirect_stderr(err), mock.patch('sys.stdin.isatty', return_value=interactive):
                cli._write_control(out, record)
            outputs.append(out.getvalue())
        self.assertEqual(outputs[0], outputs[1])

    def test_write_failure_preserves_error_code_exit_and_reason_without_secret(self):
        self.writer.add_api_key = mock.Mock(side_effect=SecretProviderError(
            init_fixtures.SECRET.decode(), reason='access_denied', stage='credential_write',
            backend='macos_security_framework', system_error_code=-128))
        code, row, text = self.invoke_init()
        self.assertEqual(code, 4)
        self.assertEqual(row['code'], 'SECRET_UNAVAILABLE')
        self.assertEqual(row['provider_reason'], 'access_denied')
        self.assertEqual(row['failure_stage'], 'credential_write')
        self.assertEqual(row['system_error_code'], -128)
        self.assertFalse(row['network_request_sent'])
        self.assertIn('钥匙串保存失败', text)
        self.assertIn('OSStatus -128', text)

    def test_local_publish_failure_reports_step_preserves_exit_and_can_retry(self):
        original = project._atomic_write

        def fail_ready(path, data):
            if path.name == 'policy.json' and json.loads(data).get('project_binding', {}).get('state') == 'ready':
                raise OSError(init_fixtures.SECRET.decode())
            return original(path, data)

        with mock.patch.object(project, '_atomic_write', side_effect=fail_ready):
            code, row, text = self.invoke_init()
        self.assertEqual(code, 1)
        self.assertEqual(row['failure_stage'], 'local_publish')
        self.assertIn('本地配置发布失败', text)
        code, row, text = self.invoke_init()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.writer.added), 1)

    def test_other_common_results_have_content_safe_human_summaries(self):
        for record in (
            {'status': 'previewed', 'planned_requests': 2, 'page_size': 25},
            {'command': 'run-status', 'requests_attempted': 1},
            {'command': 'export-records', 'status': 'completed', 'records_count': 1},
            {'event': 'run_completed', 'status': 'paused', 'requests_attempted': 1, 'pages_completed': 1},
        ):
            self.assertTrue(terminal.human_message(record))
