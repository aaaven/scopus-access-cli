"""Project initialization tests: no real credentials, Keychain writes, or HTTP."""

import ctypes
import io
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from scopus_access import cli, fetch, project
from scopus_access.errors import SecretProviderError, ValidationError
from scopus_access.ledger import Ledger
from scopus_access.policy import load_policy
from scopus_access.quota import ReservationRequest, utc_now
from scopus_access.secrets import MacOSKeychainWriter, SecretValue, _AppleKeychain, prompt_api_key
from scopus_access.security import resolve_restricted_output_dir


SECRET = b"SYNTHETIC_INITIALIZATION_CREDENTIAL"
QUERY = "SYNTHETIC_PROJECT_SEARCH_QUERY"


class FakeWriter:
    def __init__(self):
        self.items = set()
        self.added = []
        self.checks = 0
        self.handles = []

    def contains_api_key(self, alias):
        self.checks += 1
        return alias in self.items

    def add_api_key(self, alias, label, secret):
        if alias in self.items:
            raise AssertionError("an existing item must not be replaced")
        if secret.reveal().encode() != SECRET:
            raise AssertionError("unexpected mock secret")
        self.handles.append(secret)
        self.added.append((alias, label))
        self.items.add(alias)


def _initialize_worker(root, result_name):
    # Fork inherits the test runner's socket guards. The fake writer records
    # only a marker, never even the synthetic credential value, on disk.
    class Writer:
        def contains_api_key(self, alias):
            return True

        def add_api_key(self, alias, label, secret):
            with (Path(root) / "mock-writes.txt").open("ab") as stream:
                stream.write(b"write\n")

    result = project.initialize_project(root, writer=Writer(), prompt=lambda: SecretValue(SECRET))
    (Path(root) / result_name).write_text(json.dumps(result))


def _reservation_worker(root, name):
    path = project.discover_project_policy(root)
    policy = load_policy(str(path))
    binding = policy.project_binding
    ledger = Ledger(policy.control_database_path, require_existing_identity=True)
    result = ledger._admit_task(
        binding.project_id, "task_" + name, "run_" + name, "release_" + name,
        "a" * 64, [ReservationRequest(
            api_name="scopus_search", view="STANDARD", page_size=25,
            forecast_pagination=60, forecast_detail_retrieval=0,
            forecast_validation=0, retry_allowance=0,
        )], utc_now(), expected_api_key_alias=binding.alias,
    )
    (Path(root) / (name + ".json")).write_text(json.dumps({"admitted": result.admitted}))


class ProjectInitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "survey"
        self.root.mkdir()
        self.writer = FakeWriter()
        self.prompt = mock.Mock(side_effect=lambda: SecretValue(SECRET))

    def initialize(self, root=None):
        return project.initialize_project(root or self.root, writer=self.writer, prompt=self.prompt)

    def invoke(self, root, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
                mock.patch.object(Path, "cwd", return_value=root), \
                mock.patch("scopus_access.secrets.MacOSKeychainWriter", return_value=self.writer), \
                mock.patch("scopus_access.secrets.prompt_api_key", self.prompt), \
                mock.patch.object(cli, "MacOSKeychainSecretProvider",
                                  side_effect=AssertionError("credential read forbidden")), \
                mock.patch.object(cli, "UrllibTransport", side_effect=AssertionError("HTTP forbidden")):
            code = cli.main(arguments)
        self.assertNotIn(SECRET.decode(), output.getvalue() + errors.getvalue())
        self.assertNotIn(QUERY, output.getvalue() + errors.getvalue())
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def assert_no_secret_files(self):
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET, path.read_bytes(), str(path))

    def test_init_is_offline_and_publishes_only_bound_nonsecret_configuration(self):
        code, rows = self.invoke(self.root, ["init"])
        self.assertEqual(code, 0, rows)
        result = rows[0]
        self.assertEqual(result["quota_state"], "UNVERIFIED")
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["secret_reads"], 0)
        path = Path(result["policy_path"])
        policy = load_policy(str(path))
        binding = policy.project_binding
        self.assertEqual(binding.database, self.root / ".scopus-access/control.sqlite")
        self.assertEqual(binding.output, self.root / "restricted_metadata/scopus")
        self.assertTrue(binding.output.is_dir())
        self.assertTrue((path.parent / "runs").is_dir())
        self.assertTrue(policy.live_capability_enabled)
        self.assertEqual(self.writer.added, [(binding.alias, binding.keychain_label)])
        self.assertNotIn(self.root.name, binding.project_id)
        ledger = Ledger(binding.database, require_existing_identity=True)
        self.assertIsNone(ledger.quota_status(binding.alias, "scopus_search"))
        self.assertIsNone(ledger.quota_status(binding.alias, "abstract_retrieval"))
        self.assertEqual(ledger.ledger_count("request_usage"), 0)
        self.assertEqual(ledger.ledger_count("task_reservation"), 0)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(binding.database.stat().st_mode & 0o777, 0o600)
        self.assertIn("/.scopus-access/", (self.root / ".gitignore").read_text())
        self.assertIn("/restricted_metadata/", (self.root / ".gitignore").read_text())
        with self.assertRaises(SecretProviderError):
            self.writer.handles[0].reveal()
        self.assert_no_secret_files()

    def test_repeat_from_descendant_never_prompts_or_reads_or_overwrites_key(self):
        first = self.initialize()
        path = Path(first["policy_path"])
        original = path.read_bytes()
        child = self.root / "notes" / "drafts"
        child.mkdir(parents=True)
        result = self.initialize(child)
        self.assertEqual(result["status"], "reused")
        self.assertEqual(result["quota_states"], {
            "scopus_search": "UNVERIFIED", "abstract_retrieval": "UNVERIFIED",
        })
        self.assertEqual(result["project_id"], first["project_id"])
        self.assertFalse(result["credential_written"])
        self.assertEqual(path.read_bytes(), original)
        self.prompt.assert_called_once()
        self.assertEqual(self.writer.checks, 0)
        self.assertEqual(len(self.writer.added), 1)

    def test_missing_existing_database_is_not_silently_recreated(self):
        result = self.initialize()
        Path(result["database_path"]).unlink()
        from scopus_access.ledger import LedgerError
        with self.assertRaises(LedgerError):
            self.initialize()
        self.assertFalse(Path(result["database_path"]).exists())
        self.assertEqual(len(self.writer.added), 1)

    def test_cli_does_not_accept_secret_arguments_or_echo_them(self):
        code, rows = self.invoke(self.root, ["init", "--api-key", SECRET.decode()])
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertEqual(rows[0]["code"], "INVALID_ARGUMENTS")
        self.assertFalse((self.root / ".scopus-access").exists())
        self.prompt.assert_not_called()

    def test_new_binding_cannot_admit_search_with_unverified_quota(self):
        self.initialize()
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        code, rows = self.invoke(self.root, ["search", "--query-file", str(query), "--execute-live"])
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED, rows)
        self.assertEqual(rows[-1]["network_calls"], 0)
        self.assertEqual(rows[-1]["secret_reads"], 0)

    def test_same_folder_names_are_independent_and_rename_preserves_binding(self):
        first = self.initialize()
        other = self.base / "other" / self.root.name
        other.mkdir(parents=True)
        second = self.initialize(other)
        self.assertEqual(first["display_name"], second["display_name"])
        for field in ("project_id", "key_alias", "keychain_label"):
            self.assertNotEqual(first[field], second[field])
        renamed = self.base / "renamed-survey"
        self.root.rename(renamed)
        result = self.initialize(renamed)
        self.assertEqual(result["project_id"], first["project_id"])
        self.assertEqual(result["key_alias"], first["key_alias"])
        self.assertEqual(result["display_name"], renamed.name)
        self.assertEqual(len(self.writer.added), 2)
        policy = load_policy(str(renamed / ".scopus-access/policy.json"))
        self.assertEqual(policy.project_binding.root, renamed)

    def test_copied_binding_cannot_create_an_independent_quota_account(self):
        self.initialize()
        copied = self.base / "copy"
        shutil.copytree(self.root, copied)
        with self.assertRaisesRegex(ValidationError, "different folder"):
            self.initialize(copied)
        self.assertEqual(len(self.writer.added), 1)

    def test_nearest_configuration_wins_over_environment_and_parent(self):
        self.initialize()
        child = self.root / "nested"
        child.mkdir()
        control = child / ".scopus-access"
        control.mkdir()
        # An incomplete nearer project stops lookup; never use its parent's key.
        with self.assertRaises(ValidationError):
            project.discover_project_policy(child)
        second = self.initialize(child)
        self.assertNotEqual(second["project_id"], load_policy(str(self.root / ".scopus-access/policy.json")).project_binding.project_id)
        with mock.patch.object(Path, "cwd", return_value=child), \
                mock.patch.dict(os.environ, {"SCOPUS_ACCESS_POLICY": "/foreign/policy.json"}):
            self.assertEqual(fetch._default_policy(), str(control / "policy.json"))

    def test_preview_uses_shared_database_and_restricted_project_subdirectory(self):
        first = self.initialize()
        child = self.root / "notes"
        child.mkdir()
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        code, rows = self.invoke(child, ["search", "--query-file", str(query)])
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[-1]["quota_state"], "UNVERIFIED")
        self.assertEqual(rows[-1]["database_path"], first["database_path"])
        info = json.loads(Path(rows[-1]["run_info_path"]).read_text())
        self.assertEqual(info["project_id"], first["project_id"])
        self.assertEqual(info["project_output_dir"], first["output_dir"])
        self.assertEqual(Path(rows[-1]["manifest_path"]).parent.parent.name, "runs")
        for control in (self.root / ".scopus-access/runs").rglob("*.json"):
            self.assertNotIn(QUERY, control.read_text())
        self.assertTrue(list(Path(first["output_dir"]).glob("operations/*.json")))
        self.assert_no_secret_files()

    def test_root_and_three_descendants_use_identical_project_state(self):
        first = self.initialize()
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        deepest = self.root / "notes/drafts/figures"
        deepest.mkdir(parents=True)
        for directory in (self.root, self.root / "notes", self.root / "notes/drafts", deepest):
            code, rows = self.invoke(directory, ["search", "--query-file", str(query)])
            self.assertEqual(code, 0, rows)
            self.assertEqual(rows[-1]["database_path"], first["database_path"])
            info = json.loads(Path(rows[-1]["run_info_path"]).read_text())
            self.assertEqual(info["project_id"], first["project_id"])
            self.assertEqual(info["project_output_dir"], first["output_dir"])
        self.assertEqual(len(self.writer.added), 1)

    def test_malformed_or_missing_nearer_policy_cannot_use_parent_or_explicit_foreign_key(self):
        parent = self.initialize()
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        child = self.root / "child"
        control = child / ".scopus-access"
        control.mkdir(parents=True)
        for content in (None, b"{malformed", b"{}"):
            policy = control / "policy.json"
            if content is not None:
                policy.write_bytes(content)
            elif policy.exists():
                policy.unlink()
            for extra in ([], ["--policy", parent["policy_path"]]):
                code, rows = self.invoke(child, ["search", "--query-file", str(query)] + extra)
                self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertFalse(list((self.root / ".scopus-access/runs").iterdir()))

    def test_uninitialized_folder_cannot_use_an_explicit_foreign_bound_policy(self):
        first = self.initialize()
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        other = self.base / "uninitialized"
        other.mkdir()
        code, rows = self.invoke(other, ["search", "--query-file", str(query), "--policy", first["policy_path"]])
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertEqual(rows[-1]["code"], "PROJECT_NOT_INITIALIZED")
        self.assertFalse(list((self.root / ".scopus-access/runs").iterdir()))

    @unittest.skipUnless(shutil.which("git"), "requires local Git")
    def test_repeat_init_repairs_gitignore_after_negations_without_resetting_state(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (self.root / ".gitignore").write_text("/.scopus-access/\n/restricted_metadata/\n!/.scopus-access/\n!/restricted_metadata/\n")
        result = self.initialize()
        policy = Path(result["policy_path"]).read_bytes()
        (self.root / ".gitignore").unlink()
        self.initialize()
        for path in (".scopus-access/policy.json", "restricted_metadata/scopus/test.json"):
            check = subprocess.run(["git", "-C", str(self.root), "check-ignore", path],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(check.returncode, 0)
        self.assertEqual(Path(result["policy_path"]).read_bytes(), policy)
        self.assertEqual(len(self.writer.added), 1)

    @unittest.skipUnless(shutil.which("git"), "requires local Git")
    def test_already_tracked_runtime_refuses_init_without_changing_index_or_key(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.initialize()
        subprocess.run(["git", "-C", str(self.root), "add", "-f", ".scopus-access/policy.json"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        code, rows = self.invoke(self.root, ["init"])
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertEqual(rows[-1]["code"], "PROJECT_RUNTIME_TRACKED")
        self.assertEqual(len(self.writer.added), 1)
        query = self.root / "restricted_metadata/query.txt"
        query.write_text(QUERY)
        code, rows = self.invoke(self.root, ["search", "--query-file", str(query), "--execute-live"])
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertFalse(list((self.root / ".scopus-access/runs").iterdir()))

    def test_generic_search_requires_project_and_rejects_foreign_explicit_policy(self):
        query = self.base / "query.txt"
        query.write_text(QUERY)
        self.assertEqual(self.invoke(self.root, ["search", "--query-file", str(query)])[0], cli.EXIT_VALIDATION)
        self.initialize()
        other = self.base / "other"
        other.mkdir()
        foreign = self.initialize(other)
        code, rows = self.invoke(self.root, ["search", "--query-file", str(query),
                                           "--policy", foreign["policy_path"]])
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertFalse(list((self.root / ".scopus-access/runs").iterdir()))

    def test_cancelled_prompt_resumes_same_pending_id_without_network(self):
        self.prompt.side_effect = SecretProviderError("Cancelled.")
        with self.assertRaises(SecretProviderError):
            self.initialize()
        path = self.root / ".scopus-access/policy.json"
        before = json.loads(path.read_text())["project_binding"]
        with self.assertRaises(ValidationError):
            load_policy(str(path))
        self.prompt.side_effect = lambda: SecretValue(SECRET)
        result = self.initialize()
        self.assertEqual(result["project_id"], before["project_id"])
        self.assertEqual(result["key_alias"], before["alias"])
        self.assertEqual(len(self.writer.added), 1)

    def test_crash_after_key_write_recovers_without_second_prompt_or_overwrite(self):
        original = project._atomic_write

        def fail_final(path, data):
            if path.name == "policy.json" and b'"ready"' in data:
                raise OSError("synthetic publication failure")
            return original(path, data)

        with mock.patch.object(project, "_atomic_write", side_effect=fail_final):
            with self.assertRaises(OSError):
                self.initialize()
        result = self.initialize()
        self.assertEqual(result["status"], "initialized")
        self.assertFalse(result["credential_written"])
        self.prompt.assert_called_once()
        self.assertEqual(len(self.writer.added), 1)
        self.assertEqual(Ledger(result["database_path"]).ledger_count("project_alias"), 1)

    def test_legacy_configuration_and_alias_are_preserved(self):
        control = self.root / ".scopus-access"
        control.mkdir()
        path = control / "policy.json"
        value = {"schema_version": "1.0", "project_output_roots": {"legacy": [str(self.root)]},
                 "project_api_key_aliases": {"legacy": {"scopus_search": "uaeu-scopus-preflight"}}}
        path.write_text(json.dumps(value))
        before = path.read_bytes()
        result = self.initialize()
        self.assertEqual(result["status"], "legacy_reused")
        self.assertEqual(path.read_bytes(), before)
        self.prompt.assert_not_called()
        self.assertEqual(self.writer.added, [])

    def test_symlinks_and_changed_paths_fail_before_credential_write(self):
        control = self.root / ".scopus-access"
        control.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValidationError):
            self.initialize()
        control.unlink()
        (self.root / ".gitignore").symlink_to(self.base / "outside")
        with self.assertRaises(ValidationError):
            self.initialize()
        self.prompt.assert_not_called()
        (self.root / ".gitignore").unlink()
        self.initialize()
        path = control / "policy.json"
        value = json.loads(path.read_text())
        value["control_database_path"] = "../../foreign.sqlite"
        path.write_text(json.dumps(value))
        with self.assertRaises(ValidationError):
            self.initialize()
        self.assertEqual(len(self.writer.added), 1)

    def test_secret_provider_errors_are_sanitized_and_secret_handle_is_closed(self):
        self.writer.add_api_key = mock.Mock(side_effect=RuntimeError(SECRET.decode()))
        code, rows = self.invoke(self.root, ["init"])
        self.assertNotEqual(code, 0)
        self.assertEqual(rows[0]["code"], "SECRET_UNAVAILABLE")
        self.assert_no_secret_files()

    def test_nested_restricted_directory_is_allowed_but_symlink_escape_is_not(self):
        self.initialize()
        root = self.root / "restricted_metadata"
        self.assertEqual(resolve_restricted_output_dir(str(root / "scopus"), [root]), root / "scopus")
        link = root / "escaped"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValidationError):
            resolve_restricted_output_dir(str(link / "scopus"), [root])

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX local process locking")
    def test_two_processes_initialize_same_binding_and_write_key_once(self):
        context = multiprocessing.get_context("fork")
        children = [context.Process(target=_initialize_worker, args=(str(self.root), name + ".json"))
                    for name in ("first", "second")]
        for child in children:
            child.start()
        for child in children:
            child.join(15)
            if child.is_alive():
                child.terminate()
                child.join()
            self.assertEqual(child.exitcode, 0)
        results = [json.loads((self.root / (name + ".json")).read_text()) for name in ("first", "second")]
        self.assertEqual(results[0]["project_id"], results[1]["project_id"])
        self.assertEqual((self.root / "mock-writes.txt").read_text(), "write\n")
        self.assert_no_secret_files()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX local process locking")
    def test_two_project_callers_share_one_atomic_quota_reservation(self):
        result = self.initialize()
        policy = load_policy(result["policy_path"])
        binding = policy.project_binding
        ledger = Ledger(binding.database)
        now = utc_now()
        # Establish only synthetic test telemetry through the normal mock
        # preflight attempt/response path, never by seeding a production balance.
        admission = ledger._admit_preflight(
            binding.project_id, "seed_task", "seed_run", "seed_release", "c" * 64,
            ReservationRequest("scopus_search", "STANDARD", 25, 1, 0, 0, 0), now,
            expected_api_key_alias=binding.alias,
        )
        attempt = ledger.record_request_attempt(admission.buckets[0].reservation_id, "scopus_search", "seed_page", 0, now)
        ledger.record_response(attempt.attempt_id, 200, {
            "X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99", "X-RateLimit-Reset": "4102444800",
        }, "c" * 64, 0, now)
        ledger.complete_reservation(admission.buckets[0].reservation_id, now)
        before = ledger.rows("quota_window")
        self.initialize()
        self.assertEqual(ledger.rows("quota_window"), before)
        context = multiprocessing.get_context("fork")
        children = [context.Process(target=_reservation_worker, args=(str(self.root), name)) for name in ("a", "b")]
        for child in children:
            child.start()
        for child in children:
            child.join(15)
            if child.is_alive():
                child.terminate()
                child.join()
            self.assertEqual(child.exitcode, 0)
        results = [json.loads((self.root / (name + ".json")).read_text()) for name in ("a", "b")]
        self.assertEqual(sum(row["admitted"] for row in results), 1)


class KeychainWriteTests(unittest.TestCase):
    def test_prompt_requires_non_echoing_terminal_and_rejects_echo_fallback(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
                mock.patch("getpass.getpass") as prompt:
            with self.assertRaises(SecretProviderError):
                prompt_api_key()
            prompt.assert_not_called()
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("getpass.getpass", return_value=SECRET.decode()):
            with prompt_api_key() as value:
                self.assertEqual(value.reveal().encode(), SECRET)
        import warnings

        def echo_warning(*args, **kwargs):
            warnings.warn("synthetic echo fallback", __import__("getpass").GetPassWarning)

        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("getpass.getpass", side_effect=echo_warning):
            with self.assertRaises(SecretProviderError):
                prompt_api_key()

    def test_writer_uses_native_api_and_never_subprocess_or_environment(self):
        with mock.patch("scopus_access.secrets._AppleKeychain") as native, \
                mock.patch("subprocess.run", side_effect=AssertionError("argv transport forbidden")):
            writer = MacOSKeychainWriter()
            native.return_value.call.return_value = 0
            with SecretValue(SECRET) as secret:
                writer.add_api_key("mock-alias", "Mock label", secret)
                self.assertIs(native.return_value.call.call_args.kwargs["secret"], secret)
            native.return_value.call.return_value = -25300
            self.assertFalse(writer.contains_api_key("mock-alias"))
            native.return_value.call.return_value = -25299
            with self.assertRaises(SecretProviderError):
                with SecretValue(SECRET) as secret:
                    writer.add_api_key("mock-alias", "Mock label", secret)

    @unittest.skipUnless(sys.platform == "darwin", "Apple framework ABI test")
    def test_native_bridge_constructs_cfdata_but_mocks_every_keychain_operation(self):
        # Exercise the real CF ABI using memory only. Both Security entry points
        # are replaced before a secret is constructed; no real Keychain access.
        native = _AppleKeychain()
        cf = native.cf
        cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cf.CFDictionaryGetValue.restype = ctypes.c_void_p
        cf.CFDataGetLength.argtypes = [ctypes.c_void_p]
        cf.CFDataGetLength.restype = ctypes.c_ssize_t
        cf.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        cf.CFDataGetBytePtr.restype = ctypes.c_void_p

        def inspect_add(dictionary, result):
            data = cf.CFDictionaryGetValue(dictionary, native._constant("kSecValueData"))
            self.assertEqual(ctypes.string_at(cf.CFDataGetBytePtr(data), cf.CFDataGetLength(data)), SECRET)
            return 0

        def inspect_lookup(dictionary, result):
            self.assertFalse(cf.CFDictionaryGetValue(dictionary, native._constant("kSecReturnData")))
            return -25300

        with mock.patch.object(native.security, "SecItemAdd", side_effect=inspect_add), \
                mock.patch.object(native.security, "SecItemCopyMatching", side_effect=inspect_lookup):
            with SecretValue(SECRET) as secret:
                self.assertEqual(native.call("Mock service", "mock-alias", label="Mock label", secret=secret), 0)
            self.assertEqual(native.call("Mock service", "mock-alias"), -25300)
