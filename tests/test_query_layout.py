"""Lossless layout, provenance, errors and wire encoding; fully synthetic."""

import hashlib
import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from scopus_access.errors import QueryValidationError
from scopus_access.query import search_operation, validate_query, validate_search_operation
import test_local_cli as local_fixtures


class QueryTextTests(unittest.TestCase):
    def test_lf_crlf_tabs_and_outer_whitespace_are_lossless(self):
        for text in ('\nSYNTHETIC\n  AND\tOTHER\n', '\r\nSYNTHETIC\r\nAND\tOTHER\r\n'):
            operation = search_operation(text)
            self.assertEqual(operation['query'], text)
            self.assertEqual(operation['provenance']['source_text'], text)
            digest = hashlib.sha256(text.encode()).hexdigest()
            self.assertEqual(operation['provenance']['source_sha256'], digest)
            self.assertEqual(operation['provenance']['transport_sha256'], digest)
            self.assertEqual(operation['provenance']['transformation'], 'identity-utf8-v1')
            validate_search_operation(operation)

    def test_quoted_and_exact_phrase_whitespace_is_never_rewritten(self):
        for text in ('TITLE("SYNTHETIC  PHRASE\tTEXT")\nAND X',
                     'TITLE("SYNTHETIC\nPHRASE")', 'TITLE({SYNTHETIC\r\nPHRASE})'):
            self.assertEqual(search_operation(text)['query'], text)
            self.assertNotEqual(text, ' '.join(text.split()))

    def test_nul_other_control_and_del_report_only_codepoint_and_location(self):
        for character in ('\0', '\x01', '\x0b', '\x7f'):
            text = 'SYNTHETIC_SECRET_QUERY\r\nAB' + character + 'RESTRICTED'
            with self.assertRaises(QueryValidationError) as caught:
                validate_query(text)
            error = caught.exception
            self.assertEqual((error.line, error.column), (2, 3))
            self.assertEqual(error.position, text.index(character) + 1)
            self.assertEqual(error.codepoint, 'U+%04X' % ord(character))
            self.assertNotIn('SYNTHETIC_SECRET_QUERY', str(error))
            self.assertNotIn('RESTRICTED', str(error))

    def test_legacy_query_only_package_remains_supported(self):
        validate_search_operation({'query': 'SYNTHETIC_LEGACY'})
        validate_search_operation({'query': 'SYNTHETIC\nMULTILINE'})

    def test_mismatched_provenance_hash_text_or_rule_fails_closed(self):
        for field, value in (('source_sha256', '0' * 64), ('transport_sha256', '0' * 64),
                             ('source_text', 'OTHER'), ('transformation', 'unknown-v2')):
            operation = search_operation('SYNTHETIC\nQUERY')
            operation['provenance'][field] = value
            with self.assertRaises(QueryValidationError):
                validate_search_operation(operation)


class QueryCliTests(unittest.TestCase):
    setUp = local_fixtures.LocalCliTests.setUp
    invoke = local_fixtures.LocalCliTests.invoke

    def test_multiline_preview_execute_wire_and_export(self):
        text = '\r\nSYNTHETIC_LAYOUT\r\nAND\tTITLE("TWO  SPACES")\n'
        self.query.write_bytes(text.encode())
        code, rows = self.invoke('check', '--query-file', str(self.query), local=True)
        self.assertEqual(code, 0, rows)
        info = json.loads(Path(rows[0]['run_info_path']).read_text())
        task = json.loads(Path(info['manifest_path']).read_text())
        package = json.loads(Path(task['query_manifest_path']).read_text())
        self.assertEqual(package['queries']['scopus_search'], search_operation(text))
        code, rows = self.invoke('execute', '--run-info', rows[0]['run_info_path'], '--execute-live')
        self.assertEqual(code, 0, rows)
        self.assertEqual(parse_qs(urlsplit(self.wire.urls[0]).query)['query'], [text])
        self.assertIn('%0D%0A', self.wire.urls[0])
        self.assertIn('%09', self.wire.urls[0])
        for action in ('status', 'export'):
            code, result = self.invoke(action, '--run-info', rows[0]['run_info_path'], local=True)
            self.assertEqual(code, 0, result)
        self.assertEqual(len(self.wire.urls), 1)

    def test_illegal_control_cli_reports_precise_safe_error_without_provider(self):
        self.query.write_bytes(b'SYNTHETIC_PRIVATE\r\nAB\0REST')
        code, rows = self.invoke('check', '--query-file', str(self.query), local=True)
        self.assertEqual(code, 2)
        self.assertEqual(rows[0]['code'], 'QUERY_INVALID_CONTROL')
        self.assertEqual((rows[0]['line'], rows[0]['column'], rows[0]['codepoint']), (2, 3, 'U+0000'))
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(rows))
        self.assertEqual(rows[0]['network_calls'], 0)
        self.assertEqual(self.ledger.request_attempt_count(self.policy.project_binding.project_id), 0)

    def test_oversize_and_invalid_utf8_report_specific_safe_errors(self):
        for content, expected in ((b'SYNTHETIC' * 4097, 'QUERY_TOO_LARGE'),
                                  (b'SYNTHETIC\xff', 'QUERY_INVALID_UTF8')):
            self.query.write_bytes(content)
            code, rows = self.invoke('check', '--query-file', str(self.query), local=True)
            self.assertEqual(code, 2, rows)
            self.assertEqual(rows[0]['code'], expected)
            self.assertNotIn('SYNTHETIC', json.dumps(rows))
            self.assertEqual(rows[0]['network_calls'], 0)
