"""Native structured errors and bounded reads, using mocked Keychain only."""

import ctypes
import sys
import threading
import unittest
from unittest import mock

from scopus_access.errors import SecretProviderError, ValidationError, secret_error_details
from scopus_access.secrets import (MacOSKeychainSecretProvider, MacOSKeychainWriter,
                                  SecretValue, _AppleKeychain)


SENTINEL = b'SYNTHETIC_NATIVE_CREDENTIAL'


class KeychainDiagnosticsTests(unittest.TestCase):
    def test_timeout_must_be_finite_bounded_number(self):
        for timeout in (float('nan'), float('inf'), 0, -1, 31, True, '10'):
            with self.assertRaises(ValidationError):
                MacOSKeychainSecretProvider(timeout_seconds=timeout)

    def test_known_osstatus_and_unknown_status_are_not_guessed(self):
        for status, reason in ((-25300, 'credential_not_found'), (-25308, 'interaction_not_allowed'),
                               (-128, 'access_denied'), (-25293, 'access_denied'), (-1234567, 'keychain_error')):
            with self.subTest(status=status), mock.patch('scopus_access.secrets._AppleKeychain') as native:
                native.return_value.read.return_value = (status, None)
                with self.assertRaises(SecretProviderError) as caught:
                    MacOSKeychainSecretProvider().get_api_key('synthetic-alias')
                details = secret_error_details(caught.exception)
                self.assertEqual(details['provider_reason'], reason)
                self.assertEqual(details['system_error_code'], status)
                self.assertEqual(details['failure_stage'], 'credential_read')
                self.assertEqual(details['provider_backend'], 'macos_security_framework')
                native.return_value.read.assert_called_once()

    def test_success_uses_native_backend_with_legacy_service_and_no_subprocess(self):
        with mock.patch('scopus_access.secrets._AppleKeychain') as native, \
                mock.patch('subprocess.run', side_effect=AssertionError('subprocess forbidden')):
            value = SecretValue(SENTINEL)
            native.return_value.read.return_value = (0, value)
            with MacOSKeychainSecretProvider().get_api_key('synthetic-alias') as secret:
                self.assertEqual(secret.reveal().encode(), SENTINEL)
            native.return_value.read.assert_called_once_with('UAEU Survey Research Access Layer', 'synthetic-alias')
            self.assertTrue(value._closed)

    def test_timeout_cannot_send_and_late_credential_is_zeroized(self):
        release, finished = threading.Event(), threading.Event()
        value = SecretValue(SENTINEL)
        original_close = value.close

        def closed():
            original_close()
            finished.set()

        def delayed(*args):
            release.wait(2)
            return 0, value

        with mock.patch('scopus_access.secrets._AppleKeychain') as native, \
                mock.patch.object(SecretValue, 'close', side_effect=closed):
            native.return_value.read.side_effect = delayed
            try:
                with self.assertRaises(SecretProviderError) as caught:
                    MacOSKeychainSecretProvider(timeout_seconds=0.01).get_api_key('synthetic-alias')
                self.assertEqual(caught.exception.reason, 'keychain_timeout')
                self.assertIsNone(caught.exception.system_error_code)
            finally:
                release.set()
            self.assertTrue(finished.wait(2))
            self.assertTrue(value._closed)
            native.return_value.read.assert_called_once()

    def test_writer_reports_exact_stage_status_and_never_replaces(self):
        with mock.patch('scopus_access.secrets._AppleKeychain') as native:
            native.return_value.call.return_value = -25308
            with self.assertRaises(SecretProviderError) as caught:
                MacOSKeychainWriter().contains_api_key('synthetic-alias')
            self.assertEqual(caught.exception.failure_stage, 'credential_metadata')
            self.assertEqual(caught.exception.system_error_code, -25308)
            native.return_value.call.return_value = -25299
            with SecretValue(SENTINEL) as secret, self.assertRaises(SecretProviderError) as caught:
                MacOSKeychainWriter().add_api_key('synthetic-alias', 'Synthetic label', secret)
            self.assertEqual(caught.exception.reason, 'credential_already_exists')
            self.assertEqual(caught.exception.failure_stage, 'credential_write')
            self.assertEqual(caught.exception.system_error_code, -25299)

    def test_arbitrary_exception_text_and_invalid_metadata_are_not_serialized(self):
        with mock.patch('scopus_access.secrets._AppleKeychain') as native:
            native.return_value.read.side_effect = RuntimeError(SENTINEL.decode())
            with self.assertRaises(SecretProviderError) as caught:
                MacOSKeychainSecretProvider().get_api_key('synthetic-alias')
            self.assertNotIn(SENTINEL.decode(), str(caught.exception))
            self.assertEqual(secret_error_details(caught.exception)['provider_reason'], 'keychain_error')
            self.assertIsNone(caught.exception.system_error_code)
        error = SecretProviderError(SENTINEL.decode(), reason=[], stage=[], backend=[], system_error_code=SENTINEL)
        self.assertNotIn(SENTINEL.decode(), str(error))
        self.assertNotIn(SENTINEL.decode(), str(secret_error_details(error)))

    @unittest.skipUnless(sys.platform == 'darwin', 'CoreFoundation ABI test')
    def test_native_read_uses_cfdata_and_releases_result_without_real_keychain(self):
        native = _AppleKeychain()
        cf = native.cf
        cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cf.CFDictionaryGetValue.restype = ctypes.c_void_p
        result_pointers = []

        def lookup(dictionary, result):
            self.assertTrue(cf.CFDictionaryGetValue(dictionary, native._constant('kSecReturnData')))
            buffer = ctypes.create_string_buffer(SENTINEL)
            data = cf.CFDataCreate(None, ctypes.cast(buffer, ctypes.c_void_p), len(SENTINEL))
            ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = data
            result_pointers.append(data)
            return 0

        with mock.patch.object(native.security, 'SecItemCopyMatching', side_effect=lookup), \
                mock.patch.object(cf, 'CFRelease', wraps=cf.CFRelease) as released:
            status, value = native.read('Synthetic service', 'synthetic-alias')
            self.assertEqual(status, 0)
            with value:
                self.assertEqual(value.reveal().encode(), SENTINEL)
            self.assertTrue(any(getattr(call.args[0], 'value', call.args[0]) == result_pointers[0]
                                for call in released.call_args_list))
