"""The short user-facing script uses the same offline-tested execution gates."""

import importlib.util
import io
import json
import os
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest import mock

import test_survey_cli as fixtures
from scopus_access import cli, fetch, ledger as ledger_module
from scopus_access.integration import LedgerExecutionAdapter


QUERY = "SYNTHETIC_SIMPLE_SCRIPT_QUERY"


class SimpleScriptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SurveyCliTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture._prepare()
        self.script = fetch
        self.query_file = self.fixture.root / "query.txt"
        self.query_file.write_text(QUERY + "\n", encoding="utf-8")

    def invoke(self, *extra, local_only=False):
        return self.invoke_arguments(
            [str(self.query_file), "--policy", str(self.fixture.policy_path)] + list(extra),
            local_only=local_only,
        )

    def invoke_arguments(self, arguments, *, local_only=False):
        output, errors = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(errors))
            stack.enter_context(mock.patch.object(ledger_module, "utc_now", return_value=fixtures.fixtures.NOW))
            stack.enter_context(mock.patch.object(cli, "utc_now", return_value=fixtures.fixtures.NOW))
            stack.enter_context(mock.patch.object(cli, "GovernedRunner", fixtures._FixedClockRunner))
            stack.enter_context(mock.patch.object(cli, "MacOSKeychainSecretProvider",
                return_value=self.fixture.secret,
                side_effect=AssertionError("preview read a credential") if local_only else None))
            stack.enter_context(mock.patch.object(cli, "UrllibTransport",
                return_value=self.fixture.wire,
                side_effect=AssertionError("preview constructed a transport") if local_only else None))
            code = self.script.main(arguments)
        for sentinel in (QUERY, fixtures.CONTENT_SENTINEL, "offline-mock-credential"):
            self.assertNotIn(sentinel, output.getvalue() + errors.getvalue())
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_default_is_offline_preview_without_admission(self):
        before = self.fixture.ledger.rows("task_reservation")
        code, records = self.invoke("--pages", "2", local_only=True)
        self.assertEqual(code, cli.EXIT_OK, records)
        self.assertFalse(records[-1]["executed"])
        self.assertEqual(before, self.fixture.ledger.rows("task_reservation"))
        operations = list(self.fixture.manifest.project_output_dir.glob("operations/*.json"))
        self.assertEqual(len(operations), 1)
        self.assertEqual(json.loads(operations[0].read_text())["queries"]["scopus_search"]["query"], QUERY + "\n")
        for control in (self.fixture.database.parent / ".scopus-access" / "fetch").rglob("*.json"):
            self.assertNotIn(QUERY, control.read_text())
        self.assertTrue(list((self.fixture.database.parent / ".scopus-access" / "fetch").glob("*/task.json")))
        self.assertFalse((self.fixture.root / "runtime" / "fetch").exists())

    def test_explicit_execution_uses_mock_keychain_client_and_restricted_results(self):
        code, records = self.invoke("--execute-live")
        self.assertEqual(code, cli.EXIT_OK, records)
        self.assertEqual(self.fixture.wire.calls, 1)
        event = next(row for row in records if row.get("event") == "run_completed")
        receipt = json.loads((self.fixture.manifest.project_output_dir / event["receipt_ref"]).read_text())
        self.assertEqual(receipt["records_count"], 1)
        sent = urlsplit(self.fixture.wire.urls[0])
        self.assertEqual(sent.scheme, "https")
        self.assertEqual(sent.netloc, "api.elsevier.com")
        self.assertEqual(sent.path, "/content/search/scopus")
        self.assertEqual(parse_qs(sent.query), {
            "query": [QUERY + "\n"], "view": ["STANDARD"], "count": ["200"], "start": ["0"],
        })

    def test_bounds_and_invalid_query_fail_before_secret_or_transport(self):
        for extra in (("--pages", "0"), ("--pages", "26"), ("--page-size", "201")):
            code, _ = self.invoke(*extra, local_only=True)
            self.assertEqual(code, cli.EXIT_VALIDATION)
        self.query_file.write_bytes(b"\xff")
        self.assertEqual(self.invoke(local_only=True)[0], cli.EXIT_VALIDATION)
        self.query_file.write_text("first\x00second")
        self.assertEqual(self.invoke(local_only=True)[0], cli.EXIT_VALIDATION)

    def test_two_offset_pages_advance_start_without_enabling_cursor(self):
        first = self.fixture.wire.response()
        first_payload = json.loads(first.body)
        first_payload["search-results"].update({
            "entry": [{"dc:identifier": "SYNTHETIC-%d" % index} for index in range(200)],
            "opensearch:totalResults": "201", "opensearch:startIndex": "0",
        })
        last = self.fixture.wire.response()
        last_payload = json.loads(last.body)
        last_payload["search-results"].update({
            "opensearch:totalResults": "201", "opensearch:startIndex": "200",
        })
        self.fixture.wire.responses.extend([
            replace(first, body=json.dumps(first_payload).encode("utf-8")),
            replace(last, body=json.dumps(last_payload).encode("utf-8"),
                    headers={**last.headers, "X-RateLimit-Remaining": "97"}),
        ])
        code, records = self.invoke("--pages", "2", "--execute-live")
        self.assertEqual(code, cli.EXIT_OK, records)
        parameters = [parse_qs(urlsplit(url).query) for url in self.fixture.wire.urls]
        self.assertEqual([item["start"] for item in parameters], [["0"], ["200"]])
        self.assertTrue(all("cursor" not in item for item in parameters))
        event = next(row for row in records if row.get("event") == "run_completed")
        receipt = json.loads((self.fixture.manifest.project_output_dir / event["receipt_ref"]).read_text())
        self.assertEqual(receipt["records_count"], 201)
        self.assertEqual(receipt["requests_attempted"], 2)

    def test_query_symlink_is_rejected(self):
        original = self.query_file
        self.query_file = self.fixture.root / "query-link.txt"
        self.query_file.symlink_to(original)
        self.assertEqual(self.invoke(local_only=True)[0], cli.EXIT_VALIDATION)

    def test_partial_pilot_stops_at_page_bound_without_claiming_quota_risk(self):
        for page in range(2):
            response = self.fixture.wire.response()
            body = {"search-results": {
                "entry": [{"dc:identifier": "SYNTHETIC-%d" % (page * 2 + row)} for row in range(2)],
                "opensearch:totalResults": "100", "opensearch:startIndex": str(page * 2),
            }}
            self.fixture.wire.responses.append(replace(
                response, body=json.dumps(body).encode(),
                headers={**response.headers, "X-RateLimit-Remaining": str(98 - page)},
            ))
        code, events = self.invoke("--pages", "2", "--page-size", "2", "--execute-live")
        self.assertEqual(code, cli.EXIT_PAUSED)
        completed = next(row for row in events if row.get("event") == "run_completed")
        self.assertEqual(completed["stop_reason"], "request_boundary_reached")
        self.assertEqual(completed["completeness"], "partial")
        self.assertEqual(completed["requests_attempted"], 2)
        self.assertEqual(self.fixture.wire.calls, 2)
        quota = self.fixture.ledger.quota_status(fixtures.fixtures.API_ALIAS, "scopus_search", fixtures.fixtures.NOW)
        self.assertEqual(quota.state.value, "NORMAL")
        self.assertFalse(any(row.get("code") == "running_task_quota_risk" for row in events))

    def test_live_policy_stays_independent_of_script_execution_flag(self):
        value = json.loads(self.fixture.policy_path.read_text())
        value["live_capability_enabled"] = False
        self.fixture.policy_path.write_text(json.dumps(value))
        code, records = self.invoke("--execute-live", local_only=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED, records)
        self.assertEqual(self.fixture.wire.calls, 0)

    def test_tool_repository_selection_is_never_an_implicit_credential_source(self):
        selected = self.fixture.root / "runtime" / "local-preflight" / "selected-preflight.json"
        selected.parent.mkdir(parents=True)
        selected.write_text(json.dumps({"policy_path": str(self.fixture.policy_path)}))
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(Path, "cwd", return_value=self.fixture.root), \
             mock.patch.object(Path, "home", return_value=self.fixture.root / "home"):
            from scopus_access.errors import ValidationError
            with self.assertRaises(ValidationError):
                self.script._default_policy()

    def test_only_nearest_project_is_implicit_not_user_or_environment_configuration(self):
        home = self.fixture.root / "home"
        user_policy = home / ".config/scopus-access/policy.json"
        project_policy = self.fixture.root / ".scopus-access/policy.json"
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(Path, "cwd", return_value=self.fixture.root), \
             mock.patch.object(Path, "home", return_value=home):
            from scopus_access.errors import ValidationError
            with self.assertRaises(ValidationError):
                self.script._default_policy()
            user_policy.parent.mkdir(parents=True)
            user_policy.write_text("{}")
            with mock.patch.dict(os.environ, {"SCOPUS_ACCESS_POLICY": str(self.fixture.policy_path)}):
                with self.assertRaises(ValidationError):
                    self.script._default_policy()
            project_policy.parent.mkdir()
            project_policy.write_text("{}")
            self.assertEqual(self.script._default_policy(), str(project_policy.resolve()))
            with mock.patch.dict(os.environ, {"SCOPUS_ACCESS_POLICY": "explicit-policy.json"}):
                self.assertEqual(self.script._default_policy(), str(project_policy.resolve()))

    def test_policy_argument_overrides_environment_configuration(self):
        with mock.patch.dict(os.environ, {"SCOPUS_ACCESS_POLICY": "/missing/policy.json"}):
            code, records = self.invoke(local_only=True)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(records[-1]["network_calls"], 0)

    def test_source_wrapper_delegates_to_packaged_command(self):
        path = Path(__file__).resolve().parent.parent / "scripts/scopus_fetch.py"
        spec = importlib.util.spec_from_file_location("scopus_fetch_script", path)
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        self.assertIs(wrapper.main, fetch.main)

    def test_help_documents_configuration_without_stdout_or_execution(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            with self.assertRaises(SystemExit) as exit_status:
                self.script.main(["--help"])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("scopus-fetch", errors.getvalue())
        self.assertIn("--policy", errors.getvalue())
        self.assertNotIn("SCOPUS_ACCESS_POLICY", errors.getvalue())
        self.assertEqual(self.fixture.wire.calls, 0)
        self.assertEqual(self.fixture.secret.aliases, [])

    def test_preview_run_info_is_content_free_and_is_not_an_executable_run(self):
        code, rows = self.invoke(local_only=True)
        self.assertEqual(code, cli.EXIT_OK)
        path = Path(rows[-1]["run_info_path"])
        info = json.loads(path.read_text())
        self.assertEqual(info["mode"], "preview")
        self.assertIsNone(info["parent_run_id"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(info["manifest_path"], rows[-1]["manifest_path"])
        for sentinel in (QUERY, fixtures.CONTENT_SENTINEL, "offline-mock-credential"):
            self.assertNotIn(sentinel, path.read_text())
        before = self.fixture.ledger.rows("task_reservation")
        for action in ("--status", "--resume", "--export-records"):
            status, _ = self.invoke_arguments([action, str(path)], local_only=True)
            self.assertEqual(status, cli.EXIT_VALIDATION)
        self.assertEqual(before, self.fixture.ledger.rows("task_reservation"))

    def test_live_run_info_retains_parent_identity_and_pins_task_files(self):
        import hashlib

        code, rows = self.invoke("--execute-live")
        self.assertEqual(code, cli.EXIT_OK)
        prepared = rows[0]
        self.assertEqual(prepared["status"], "prepared")
        info = json.loads(Path(prepared["run_info_path"]).read_text())
        admitted = next(row for row in rows if row.get("command") == "run" and row.get("status") == "admitted")
        self.assertEqual(info["parent_run_id"], admitted["parent_run_id"])
        for kind in ("manifest", "policy"):
            content = Path(info[kind + "_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), info[kind + "_sha256"])
        self.assertEqual(info["planned_requests"], 1)
        self.assertEqual(info["page_size"], 200)
        self.assertEqual(self.fixture.wire.calls, 1)

    def test_status_and_export_use_run_info_offline_without_new_tasks_or_admission(self):
        code, rows = self.invoke("--execute-live")
        self.assertEqual(code, cli.EXIT_OK)
        path = rows[0]["run_info_path"]
        before = self.fixture.ledger.rows("task_reservation")
        usage = self.fixture.ledger.rows("request_usage")
        packages = list(self.fixture.manifest.project_output_dir.glob("operations/*.json"))
        for action in ("--status", "--export-records"):
            status, output = self.invoke_arguments([action, path], local_only=True)
            self.assertEqual(status, cli.EXIT_OK, output)
            self.assertEqual(output[-1]["network_calls"], 0)
            self.assertEqual(output[-1]["secret_reads"], 0)
        self.assertEqual(self.fixture.ledger.rows("task_reservation"), before)
        self.assertEqual(self.fixture.ledger.rows("request_usage"), usage)
        self.assertEqual(list(self.fixture.manifest.project_output_dir.glob("operations/*.json")), packages)
        self.assertEqual(self.fixture.wire.calls, 1)

    def test_run_info_resume_continues_original_reservation_and_needs_explicit_consent(self):
        for page in range(2):
            response = self.fixture.wire.response()
            payload = {"search-results": {
                "entry": [{"dc:identifier": "SYNTHETIC-HANDOFF-%d" % page}],
                "opensearch:totalResults": "2", "opensearch:startIndex": str(page),
            }}
            self.fixture.wire.responses.append(replace(
                response, body=json.dumps(payload).encode(),
                headers={**response.headers, "X-RateLimit-Remaining": str(98 - page)},
            ))
        with mock.patch.object(LedgerExecutionAdapter, "assess_running_forecast", return_value=False):
            code, rows = self.invoke("--pages", "2", "--page-size", "1", "--execute-live")
        self.assertEqual(code, cli.EXIT_PAUSED, rows)
        path = rows[0]["run_info_path"]
        before = self.fixture.ledger.rows("task_reservation")
        code, _ = self.invoke_arguments(["--resume", path], local_only=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        self.assertEqual(before, self.fixture.ledger.rows("task_reservation"))
        code, resumed = self.invoke_arguments(["--resume", path, "--execute-live"])
        self.assertEqual(code, cli.EXIT_OK, resumed)
        first_receipt = next(row for row in rows if row.get("event") == "run_completed")
        last_receipt = next(row for row in resumed if row.get("event") == "run_completed")
        self.assertEqual(first_receipt["reservation_id"], last_receipt["reservation_id"])
        self.assertEqual(last_receipt["requests_attempted"], 2)
        self.assertEqual(self.fixture.wire.calls, 2)
        self.assertEqual([parse_qs(urlsplit(url).query)["start"] for url in self.fixture.wire.urls], [["0"], ["1"]])
        seeds = [row for row in self.fixture.ledger.rows("task_reservation")
                 if row["reservation_id"] == last_receipt["reservation_id"] and row["event_seq"] == 1]
        self.assertEqual(len(seeds), 1)

    def test_run_info_rejects_modified_pins_linkage_or_bounds_before_execution(self):
        code, rows = self.invoke("--execute-live")
        self.assertEqual(code, cli.EXIT_OK)
        path = Path(rows[0]["run_info_path"])
        original = path.read_bytes()
        for change in (
            {"manifest_sha256": "0" * 64}, {"policy_sha256": "0" * 64},
            {"parent_run_id": "../escape"}, {"task_id": "different-task"},
            {"project_output_dir": "/private/tmp/not-this-project"},
            {"query_package_sha256": "0" * 64}, {"page_size": 2},
            {"database_path": "/private/tmp/not-this-database.sqlite"},
            {"query": QUERY}, {"planned_requests": False},
        ):
            with self.subTest(fields=list(change)):
                info = json.loads(original)
                info.update(change)
                path.write_text(json.dumps(info))
                code, _ = self.invoke_arguments(["--resume", str(path), "--execute-live"], local_only=True)
                self.assertEqual(code, cli.EXIT_VALIDATION)
                self.assertEqual(self.fixture.wire.calls, 1)
        path.write_bytes(original)

    def test_run_info_rejects_symlink_and_corrupt_or_overlarge_documents(self):
        _, rows = self.invoke("--execute-live")
        path = Path(rows[0]["run_info_path"])
        link = path.with_name("linked-info.json")
        link.symlink_to(path)
        self.assertEqual(self.invoke_arguments(["--status", str(link)], local_only=True)[0], cli.EXIT_VALIDATION)
        for data in (b"{incomplete", b"x" * 16385):
            path.write_bytes(data)
            self.assertEqual(self.invoke_arguments(["--status", str(path)], local_only=True)[0], cli.EXIT_VALIDATION)

    def test_continuation_cannot_override_original_query_policy_or_bounds(self):
        _, rows = self.invoke("--execute-live")
        path = rows[0]["run_info_path"]
        for extra in (
            ["--policy", str(self.fixture.policy_path)], ["--pages", "2"],
            ["--page-size", "2"], [str(self.query_file)], ["--execute-live"],
        ):
            self.assertEqual(self.invoke_arguments(["--status", path] + extra, local_only=True)[0], cli.EXIT_VALIDATION)

    def test_run_info_failure_is_before_admission_and_reports_evidenced_zero(self):
        original = fetch._save
        before = self.fixture.ledger.rows("task_reservation")

        def fail_info(path, value):
            if path.name == "run-info.json":
                raise OSError("SYNTHETIC-PRIVATE-WRITE-FAILURE")
            return original(path, value)

        with mock.patch.object(fetch, "_save", side_effect=fail_info):
            code, rows = self.invoke("--execute-live", local_only=True)
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertEqual(rows[-1]["network_calls"], 0)
        self.assertEqual(rows[-1]["secret_reads"], 0)
        self.assertNotIn("SYNTHETIC-PRIVATE-WRITE-FAILURE", json.dumps(rows))
        self.assertEqual(before, self.fixture.ledger.rows("task_reservation"))

    def test_invalid_arguments_are_safe_jsonl_before_any_configuration_read(self):
        with mock.patch.object(fetch, "prepare", side_effect=AssertionError("configuration read")):
            for arguments in ([], ["--unknown", QUERY], ["--pages", QUERY],
                              ["--status", "one", "--resume", "two"]):
                code, rows = self.invoke_arguments(arguments, local_only=True)
                self.assertEqual(code, cli.EXIT_VALIDATION)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["network_calls"], 0)


if __name__ == "__main__":
    unittest.main()
