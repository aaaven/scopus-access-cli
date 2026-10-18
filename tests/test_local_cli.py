"""Installed-shape local CLI loop with injected secrets and HTTP only."""

import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scopus_access import cli, project
from scopus_access.client import TransportResponse
from scopus_access.integration import LedgerExecutionAdapter
from scopus_access.ledger import Ledger
from scopus_access.policy import load_policy
from scopus_access.secrets import SecretValue
from scopus_access.errors import SecretProviderError


SECRET = b"SYNTHETIC_LOCAL_CLI_CREDENTIAL"
QUERY = "SYNTHETIC_LOCAL_CLI_QUERY"
TITLE = "SYNTHETIC_RESTRICTED_TITLE"


class Writer:
    def add_api_key(self, alias, label, secret):
        assert secret.reveal().encode() == SECRET


class Secrets:
    def __init__(self):
        self.aliases = []
        self.callback = None

    def get_api_key(self, alias):
        self.aliases.append(alias)
        if self.callback:
            self.callback()
        return SecretValue(SECRET)


class Wire:
    def __init__(self, ledger):
        self.ledger = ledger
        self.urls = []
        self.total = 1
        self.status = 200
        self.headers = True

    def send(self, request, *, wire_capability=None):
        attempts = [r for r in self.ledger.rows("request_usage") if r["record_kind"] == "ATTEMPT"]
        assert len(attempts) == len(self.urls) + 1
        assert request.headers["X-ELS-APIKey"] == SECRET.decode()
        self.urls.append(request.url)
        params = parse_qs(urlsplit(request.url).query)
        start, count = int(params["start"][0]), int(params["count"][0])
        body = {"search-results": {
            "entry": [{"dc:identifier": "SYNTHETIC-%d" % index, "dc:title": TITLE}
                      for index in range(start, min(start + count, self.total))],
            "opensearch:totalResults": str(self.total), "opensearch:startIndex": str(start),
        }} if self.status == 200 else {"service-error": {"status": {"statusCode": "AUTHENTICATION_ERROR"}}}
        headers = {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": str(100 - len(self.urls)),
                   "X-RateLimit-Reset": "2000000000"} if self.headers else {}
        return TransportResponse(status=self.status, headers=headers, body=json.dumps(body).encode())


class LocalCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "project"
        self.root.mkdir()
        project.initialize_project(self.root, writer=Writer(), prompt=lambda: SecretValue(SECRET))
        self.policy_path = self.root / ".scopus-access/policy.json"
        self.policy = load_policy(str(self.policy_path))
        self.ledger = Ledger(self.policy.control_database_path, require_existing_identity=True)
        self.secret = Secrets()
        self.wire = Wire(self.ledger)
        self.query = self.root / "restricted_metadata/query.txt"
        self.query.write_text(QUERY)

    def invoke(self, *arguments, local=False, root=None):
        output, errors = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(errors))
            stack.enter_context(mock.patch.object(Path, "cwd", return_value=root or self.root))
            provider = stack.enter_context(mock.patch.object(cli, "MacOSKeychainSecretProvider",
                return_value=self.secret, side_effect=AssertionError("unexpected credential lookup") if local else None))
            transport = stack.enter_context(mock.patch.object(cli, "UrllibTransport",
                return_value=self.wire, side_effect=AssertionError("unexpected transport") if local else None))
            code = cli.main(list(arguments))
            if local:
                provider.assert_not_called()
                transport.assert_not_called()
        for forbidden in (SECRET.decode(), QUERY, TITLE):
            self.assertNotIn(forbidden, output.getvalue() + errors.getvalue())
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        for line in output.getvalue().splitlines():
            self.assertLessEqual(len(line.encode()), cli.MAX_CONTROL_LINE_BYTES)
        return code, rows

    def check(self):
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, 0, rows)
        return rows[0]["run_info_path"]

    def test_fresh_project_full_loop_uses_bound_key_and_shared_quota(self):
        code, rows = self.invoke("check", "--query-file", str(self.query), local=True)
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["page_size"], 1)
        self.assertEqual(rows[0]["quota_state"], "UNVERIFIED")
        self.assertFalse(self.ledger.rows("request_usage"))
        info = self.check()
        for command in ("status", "export"):
            code, result = self.invoke(command, "--run-info", info, local=True)
            self.assertEqual(code, 0, result)
        code, result = self.invoke("usage", local=True)
        self.assertEqual(code, 0, result)
        self.assertEqual(result[0]["requests_attempted"], 1)
        buckets = {b["api_name"]: b for b in result[1]["buckets"]}
        self.assertEqual(buckets["scopus_search"]["state"], "NORMAL")
        code, result = self.invoke("search", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, 0, result)
        self.assertEqual(len(self.wire.urls), 2)
        self.assertEqual(self.secret.aliases, [self.policy.project_binding.alias] * 2)
        ledger_data = json.dumps({table: self.ledger.rows(table)
                                 for table in ("request_usage", "quota_window", "task_reservation", "quota_event")})
        for forbidden in (SECRET.decode(), QUERY, TITLE):
            self.assertNotIn(forbidden, ledger_data)
        for file in (self.root / ".scopus-access").rglob("*"):
            if file.is_file():
                for forbidden in (SECRET, QUERY.encode(), TITLE.encode()):
                    self.assertNotIn(forbidden, file.read_bytes())

    def test_check_after_initial_observation_reserves_normal_quota(self):
        self.check()
        self.check()
        self.assertEqual(len(self.wire.urls), 2)
        self.assertEqual([parse_qs(urlsplit(url).query)["count"] for url in self.wire.urls], [["1"], ["1"]])

    def test_native_credential_failure_is_structured_persisted_and_pre_send(self):
        self.secret.get_api_key = mock.Mock(side_effect=SecretProviderError(
            SECRET.decode(), reason="credential_not_found", stage="credential_read",
            backend="macos_security_framework", system_error_code=-25300))
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, 6)
        failure = next(r for r in rows if r.get("code") == "secret_unavailable")
        self.assertEqual(failure["provider_reason"], "credential_not_found")
        self.assertEqual(failure["system_error_code"], -25300)
        self.assertFalse(failure["network_request_sent"])
        self.assertEqual(failure["provider_backend"], "macos_security_framework")
        self.assertEqual(self.wire.urls, [])
        self.assertEqual(self.ledger.request_attempt_count(self.policy.project_binding.project_id), 0)
        logs = list(self.policy.control_database_path.parent.glob("events/*.jsonl"))
        self.assertEqual(len(logs), 1)
        saved = [json.loads(line) for line in logs[0].read_text().splitlines()]
        self.assertIn(failure, saved)
        from scopus_access.events import validate_event, UnsafeEvent
        for field, value in (("provider_reason", SECRET.decode()), ("system_error_code", SECRET.decode()),
                             ("provider_backend", SECRET.decode()), ("network_request_sent", "false")):
            changed = dict(failure, **{field: value})
            with self.assertRaises(UnsafeEvent) as caught:
                validate_event(changed)
            self.assertNotIn(SECRET.decode(), str(caught.exception))

    def test_untyped_provider_exception_remains_generic_without_leaking_message(self):
        self.secret.get_api_key = mock.Mock(side_effect=RuntimeError(SECRET.decode()))
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, 6)
        failure = next(r for r in rows if r.get("code") == "secret_unavailable")
        self.assertEqual(failure["provider_reason"], "keychain_error")
        self.assertEqual(failure["provider_backend"], "unknown")
        self.assertIsNone(failure["system_error_code"])
        self.assertFalse(failure["network_request_sent"])
        self.assertEqual(self.wire.urls, [])

    def test_advanced_read_commands_default_to_same_bound_project_database(self):
        self.check()
        child = self.root / "notes/drafts"
        child.mkdir(parents=True)
        for command in ("doctor", "quota-status"):
            code, rows = self.invoke(command, "--policy", str(self.policy_path), local=True, root=child)
            self.assertEqual(code, 0, rows)
            if command == "quota-status":
                buckets = {row["api_name"]: row for row in rows[0]["buckets"]}
                self.assertEqual(buckets["scopus_search"]["state"], "NORMAL")
        self.assertFalse((child / "runtime/control.sqlite").exists())

    def test_doctor_and_status_cannot_recreate_a_missing_bound_database(self):
        self.policy.control_database_path.unlink()
        for command in ("doctor", "quota-status"):
            code, rows = self.invoke(command, "--policy", str(self.policy_path), local=True)
            self.assertNotEqual(code, 0, rows)
            self.assertFalse(self.policy.control_database_path.exists())

    def test_advanced_live_command_cannot_bypass_folder_binding(self):
        _, rows = self.invoke("check", "--query-file", str(self.query), local=True)
        info = json.loads(Path(rows[0]["run_info_path"]).read_text())
        other = self.root.parent / "uninitialized"
        other.mkdir()
        code, rows = self.invoke("preflight", info["manifest_path"], "--policy", info["policy_path"],
                                 "--execute-live", local=True, root=other)
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertEqual(rows[-1]["code"], "PROJECT_NOT_INITIALIZED")
        self.assertFalse(self.ledger.rows("task_reservation"))

    def test_frozen_preview_executes_same_query_even_after_input_file_changes(self):
        code, rows = self.invoke("check", "--query-file", str(self.query), local=True)
        self.assertEqual(code, 0, rows)
        preview = rows[0]["run_info_path"]
        digest = rows[0]["query_package_sha256"]
        self.query.write_text("SYNTHETIC_CHANGED_INPUT")
        code, rows = self.invoke("execute", "--run-info", preview, "--execute-live")
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0]["query_package_sha256"], digest)
        self.assertEqual(parse_qs(urlsplit(self.wire.urls[0]).query)["query"], [QUERY])
        self.assertEqual(json.loads(Path(preview).read_text())["mode"], "preview")
        code, rows = self.invoke("execute", "--run-info", preview, "--execute-live", local=True)
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED, rows)
        self.assertEqual(len(self.wire.urls), 1)

    def test_execute_requires_explicit_consent_and_no_replacement_arguments(self):
        _, rows = self.invoke("check", "--query-file", str(self.query), local=True)
        preview = rows[0]["run_info_path"]
        code, rows = self.invoke("execute", "--run-info", preview, local=True)
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertFalse(self.ledger.rows("task_reservation"))

    def test_tampered_preview_query_is_rejected_before_any_reservation(self):
        _, rows = self.invoke("check", "--query-file", str(self.query), local=True)
        preview = rows[0]["run_info_path"]
        task = json.loads(Path(rows[0]["manifest_path"]).read_text())
        Path(task["query_manifest_path"]).write_text("{}")
        code, rows = self.invoke("execute", "--run-info", preview, "--execute-live", local=True)
        self.assertEqual(code, cli.EXIT_VALIDATION, rows)
        self.assertFalse(self.ledger.rows("task_reservation"))

    def test_resume_preview_and_execution_reuse_original_reservation_and_offset(self):
        self.check()
        self.wire.total = 2
        with mock.patch.object(LedgerExecutionAdapter, "assess_running_forecast", return_value=False):
            code, rows = self.invoke("search", "--query-file", str(self.query), "--pages", "2",
                                     "--page-size", "1", "--execute-live")
        self.assertEqual(code, cli.EXIT_PAUSED, rows)
        info = rows[0]["run_info_path"]
        before = self.ledger.rows("task_reservation")
        code, rows = self.invoke("resume", "--run-info", info, local=True)
        self.assertEqual(code, 0, rows)
        self.assertEqual(before, self.ledger.rows("task_reservation"))
        code, rows = self.invoke("resume", "--run-info", info, "--execute-live")
        self.assertEqual(code, 0, rows)
        params = [parse_qs(urlsplit(url).query) for url in self.wire.urls]
        self.assertEqual([p["start"] for p in params], [["0"], ["0"], ["1"]])
        info_data = json.loads(Path(info).read_text())
        seeds = [r for r in self.ledger.rows("task_reservation")
                 if r["run_id"] == info_data["parent_run_id"] and r["event_seq"] == 1]
        self.assertEqual(len(seeds), 1)

    def test_resume_cannot_expand_exhausted_request_budget(self):
        self.check()
        self.wire.total = 2
        code, rows = self.invoke("search", "--query-file", str(self.query), "--page-size", "1", "--execute-live")
        self.assertEqual(code, cli.EXIT_PAUSED, rows)
        code, result = self.invoke("resume", "--run-info", rows[0]["run_info_path"], "--execute-live", local=True)
        self.assertNotEqual(code, 0, result)
        self.assertEqual(len(self.wire.urls), 2)

    def test_other_project_cannot_inspect_or_export_this_run(self):
        info = self.check()
        other = self.root.parent / "other"
        other.mkdir()
        project.initialize_project(other, writer=Writer(), prompt=lambda: SecretValue(SECRET))
        for command in ("status", "export", "resume"):
            code, rows = self.invoke(command, "--run-info", info, local=True, root=other)
            self.assertEqual(code, cli.EXIT_VALIDATION, rows)

    def test_policy_disabled_before_send_blocks_wire_even_after_secret_lookup(self):
        def disable():
            value = json.loads(self.policy_path.read_text())
            value["live_capability_enabled"] = False
            self.policy_path.write_text(json.dumps(value))
        self.secret.callback = disable
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertNotEqual(code, 0, rows)
        self.assertEqual(len(self.secret.aliases), 1)
        self.assertFalse(self.wire.urls)

    def test_no_retry_after_authentication_failure_and_local_event_only(self):
        self.wire.status = 403
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, cli.EXIT_FAILED, rows)
        self.assertEqual(len(self.wire.urls), 1)
        for event in self.ledger.rows("quota_event"):
            self.assertEqual(event["notification_evidence"], "LOCAL_RECORD_ONLY")
            self.assertIsNone(event["src_notified_at_utc"])
            self.assertIsNone(event["pi_notified_at_utc"])

    def test_success_without_quota_headers_never_fabricates_a_balance(self):
        self.wire.headers = False
        code, rows = self.invoke("check", "--query-file", str(self.query), "--execute-live")
        self.assertEqual(code, cli.EXIT_PAUSED, rows)
        snapshot = self.ledger.quota_status(self.policy.project_binding.alias, "scopus_search")
        self.assertEqual(snapshot.state.value, "QUOTA_TELEMETRY_UNKNOWN")
        self.assertIsNone(snapshot.limit)
        self.assertIsNone(snapshot.effective_remaining)
        code, rows = self.invoke("search", "--query-file", str(self.query), "--execute-live", local=True)
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED, rows)


if __name__ == "__main__":
    unittest.main()
