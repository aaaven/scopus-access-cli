"""Offline CLI acceptance through real manifests, ledger, client and runner."""

import io
import json
import unittest
from dataclasses import replace
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest import mock

import test_integration as fixtures
from scopus_access import cli
from scopus_access import ledger as ledger_module
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.client import TransportResponse
from scopus_access.integration import LedgerExecutionAdapter
from scopus_access.runner import GovernedRunner
from scopus_access.security import execution_run_id


CONTENT_SENTINEL = "SYNTHETIC_CLI_CONTENT_NOT_FOR_CONTROL"
ERROR_SENTINEL = "SYNTHETIC_UNSAFE_LOCAL_EXCEPTION"


class _Wire:
    def __init__(self, ledger):
        self.ledger = ledger
        self.initial_attempts = self._attempt_count()
        self.calls = 0
        self.urls = []
        self.responses = []

    def _attempt_count(self):
        return sum(row["record_kind"] == "ATTEMPT"
                   for row in self.ledger.rows("request_usage"))

    def response(self, *, abstract=False, next_cursor=None, status=200):
        payload = {"abstracts-retrieval-response": {"coredata": {
            "dc:identifier": "SYNTHETIC-CLI-ID", "dc:title": CONTENT_SENTINEL,
        }}} if abstract else {"search-results": {
            "entry": [{"dc:identifier": "SYNTHETIC-CLI-ID", "dc:title": CONTENT_SENTINEL}],
            "cursor": {"@next": next_cursor},
            "opensearch:totalResults": "1", "opensearch:startIndex": "0",
        }}
        return TransportResponse(status=status, headers={
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": str(99 - max(1, self.calls)),
            "X-RateLimit-Reset": str(fixtures.RESET_EPOCH),
        }, body=json.dumps(payload).encode("utf-8"))

    def send(self, request, *, wire_capability=None):
        if self._attempt_count() != self.initial_attempts + self.calls + 1:
            raise AssertionError("request requires a durable attempt charge")
        self.calls += 1
        self.urls.append(request.url)
        if self.responses:
            return self.responses.pop(0)
        return self.response(abstract="/content/abstract/" in request.url)


class _FixedClockRunner(GovernedRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs, clock=lambda: fixtures.NOW,
                         epoch_clock=lambda: 1_893_456_000)


class SurveyCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.IntegrationTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.database = self.root / "control.sqlite"
        self.ledger = fixtures.Ledger(self.database)
        self.secret = fixtures._TrackingSecretProvider()
        self.wire = None

    def _prepare(self, *, include_abstract=False, seed_abstract=True, two_pages=False,
                 seed_search=True, task_type="survey_run", pagination_mode=None):
        topology = self.fixture.policy.license_topology_evidence
        self.ledger.register_project_key_alias(fixtures.PROJECT_ID, fixtures.API_ALIAS,
                                               topology.sha256, fixtures.NOW)
        if seed_search:
            self.fixture._seed_quota(self.ledger, "scopus_search")
        if include_abstract and seed_abstract:
            self.fixture._seed_quota(self.ledger, "abstract_retrieval")
        updates = {
            "anticipated_result_count": 3, "forecast_pagination": 2,
            "estimated_requests_with_margin": 2, "request_limit": 2,
        } if two_pages else None
        if pagination_mode is not None:
            updates = dict(updates or {}, pagination_mode=pagination_mode)
        self.manifest, _ = self.fixture._manifest(
            task_type, "-cli", include_abstract=include_abstract, request_updates=updates,
        )
        self.manifest_path = self.root / (self.manifest.task_id + "-task.json")
        self.policy_path = self.root / "cli-policy.json"
        policy = self.fixture.policy
        fixtures._write_json(self.policy_path, {
            "schema_version": "1.0",
            "project_output_roots": {project: [str(root) for root in roots]
                                     for project, roots in policy.project_output_roots.items()},
            "project_api_key_aliases": {project: dict(aliases)
                                        for project, aliases in policy.project_api_key_aliases.items()},
            "live_capability_enabled": policy.live_capability_enabled,
            "control_database_path": str(policy.control_database_path),
            "license_topology_evidence": {"path": str(topology.path), "sha256": topology.sha256},
            "approved_release_evidence": {project: {
                release: {"path": str(pin.path), "sha256": pin.sha256}
                for release, pin in releases.items()
            } for project, releases in policy.approved_release_evidence.items()},
        })
        self.wire = _Wire(self.ledger)

    def _invoke(self, command, *extra, execute=False, local_only=False):
        arguments = [command, str(self.manifest_path), "--policy", str(self.policy_path)]
        if command != "export-records":
            arguments.extend(["--db", str(self.database)])
        arguments.extend(extra)
        if execute:
            arguments.append("--execute-live")
        output, errors = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(errors))
            stack.enter_context(mock.patch.object(ledger_module, "utc_now", return_value=fixtures.NOW))
            stack.enter_context(mock.patch.object(cli, "utc_now", return_value=fixtures.NOW))
            stack.enter_context(mock.patch.object(cli, "GovernedRunner", _FixedClockRunner))
            secrets = stack.enter_context(mock.patch.object(
                cli, "MacOSKeychainSecretProvider", return_value=self.secret,
                side_effect=AssertionError("local command constructed a secret provider")
                if local_only else None,
            ))
            transport = stack.enter_context(mock.patch.object(
                cli, "UrllibTransport", return_value=self.wire,
                side_effect=AssertionError("local command constructed a transport")
                if local_only else None,
            ))
            code = cli.main(arguments)
            if local_only:
                secrets.assert_not_called()
                transport.assert_not_called()
        for forbidden in (CONTENT_SENTINEL, ERROR_SENTINEL, "offline-mock-credential",
                          "SYNTHETIC-OFFLINE-QUERY"):
            self.assertNotIn(forbidden, output.getvalue() + errors.getvalue())
        lines = output.getvalue().splitlines()
        self.assertTrue(all(len(line.encode("utf-8")) <= cli.MAX_CONTROL_LINE_BYTES for line in lines))
        return code, [json.loads(line) for line in lines]

    def _run(self):
        code, records = self._invoke("run", execute=True)
        return code, records, records[0]["parent_run_id"]

    def _rows(self, name="task_reservation"):
        return [row for row in self.ledger.rows(name)
                if row["task_id"] == self.manifest.task_id]

    def _pause(self, *, include_abstract=False):
        self._prepare(include_abstract=include_abstract, two_pages=True)
        self.wire.responses.append(self.wire.response(next_cursor="synthetic-next-cursor"))
        # A local forecast assessment refuses continuation at a safe boundary.
        with mock.patch.object(LedgerExecutionAdapter, "assess_running_forecast", return_value=False):
            code, records, parent = self._run()
        self.assertEqual(code, cli.EXIT_PAUSED)
        self.assertEqual(self.wire.calls, 1)
        return records, parent

    def test_run_requires_explicit_consent_before_execution_or_admission(self):
        self._prepare()
        code, records = self._invoke("run", local_only=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        self.assertEqual(records[-1]["execution_counts_status"], "not_started")
        self.assertEqual(self._rows(), [])

    def test_empty_result_placeholder_reports_zero_in_ledger_export_and_receipt(self):
        self._prepare(pagination_mode="offset")
        response = self.wire.response()
        payload = {"search-results": {
            "opensearch:totalResults": "0", "opensearch:startIndex": "0",
            "entry": [{"@_fa": "true", "error": "Result set was empty"}],
        }}
        self.wire.responses.append(replace(response, body=json.dumps(payload).encode()))
        code, records, parent = self._run()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.wire.calls, 1)
        page = next(row for row in records if row.get("event") == "page_completed")
        self.assertEqual(page["result_count"], 0)
        outcomes = [row for row in self._rows("request_usage") if row["record_kind"] == "OUTCOME"]
        self.assertEqual([row["result_count"] for row in outcomes], [0])
        completed = next(row for row in records if row.get("event") == "run_completed")
        root = self.manifest.project_output_dir
        receipt = json.loads((root / completed["receipt_ref"]).read_text())
        self.assertEqual(receipt["records_count"], 0)
        self.assertEqual((root / receipt["records_ref"]).read_bytes(), b"")

    def test_locked_policy_cannot_execute_survey(self):
        self._prepare()
        value = json.loads(self.policy_path.read_text())
        value["live_capability_enabled"] = False
        fixtures._write_json(self.policy_path, value)
        code, _ = self._invoke("run", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        self.assertEqual(self._rows(), [])

    def test_task_types_cannot_replace_preflight_with_survey(self):
        self._prepare(task_type="preflight", seed_search=False)
        code, records = self._invoke("run", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertEqual(records[-1]["code"], "WRONG_TASK_TYPE")
        code, _ = self._invoke("resume", "--run-id", "missing-run", "--api-name",
                               "scopus_search", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_VALIDATION)

    def test_unverified_survey_never_bootstraps_quota(self):
        self._prepare(seed_search=False)
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED)
        self.assertEqual(records[0]["status"], "not_admitted")
        self.assertEqual(self.wire.calls, 0)
        self.assertEqual(self.secret.aliases, [])
        self.assertIsNone(self.ledger.quota_status(fixtures.API_ALIAS, "scopus_search"))

    def test_all_api_buckets_must_fit_before_first_send(self):
        self._prepare(include_abstract=True, seed_abstract=False)
        code, _, _ = self._run()
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED)
        self.assertEqual(self.wire.calls, 0)
        self.assertTrue(all(row["admission_decision"] != "ADMITTED" for row in self._rows()))
        self.assertEqual(self.ledger.quota_status(fixtures.API_ALIAS, "scopus_search",
                                                fixtures.NOW).committed_in_progress, 0)

    def test_two_api_run_persists_separate_records_and_bounded_control(self):
        self._prepare(include_abstract=True)
        code, records, parent = self._run()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(records[-1]["api_names_completed"], ["scopus_search", "abstract_retrieval"])
        self.assertEqual(self.wire.calls, 2)
        self.assertEqual(len(self.secret.aliases), 2)
        events = [row for row in records if row.get("event") == "run_completed"]
        self.assertEqual(len({row["run_id"] for row in events}), 2)
        for event in events:
            self.assertEqual(event["parent_run_id"], parent)
            receipt_path = self.manifest.project_output_dir / event["receipt_ref"]
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt["records_count"], 1)
            data_path = self.manifest.project_output_dir / receipt["records_ref"]
            self.assertIn(CONTENT_SENTINEL, data_path.read_text())
            event_path = self.root / "events" / (event["run_id"] + ".jsonl")
            self.assertNotIn(CONTENT_SENTINEL, event_path.read_text())
        self.assertEqual(sum(row["admission_decision"] == "COMPLETED" for row in self._rows()), 2)

    def test_release_cannot_be_rerun_as_a_new_admission(self):
        self._prepare()
        self.assertEqual(self._run()[0], cli.EXIT_OK)
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_QUOTA_DEFERRED)
        self.assertEqual(records[0]["status"], "not_admitted")
        self.assertEqual(self.wire.calls, 1)

    def test_http_failure_stops_before_next_api(self):
        self._prepare(include_abstract=True)
        self.wire.responses.append(self.wire.response(status=403))
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_FAILED)
        self.assertEqual(records[-1]["stopped_api_name"], "scopus_search")
        self.assertEqual(self.wire.calls, 1)
        self.assertEqual(len(self.secret.aliases), 1)

    def test_known_server_code_is_reported_without_remote_error_message(self):
        self._prepare()
        response = self.wire.response(status=403)
        response = replace(response, body=json.dumps({"service-error": {"status": {
            "statusCode": "AUTHORIZATION_ERROR", "statusText": ERROR_SENTINEL,
        }}}).encode("utf-8"))
        self.wire.responses.append(response)
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_FAILED)
        failed = next(row for row in records if row.get("event") == "failed")
        self.assertEqual(failed["remote_error_code"], "authorization_error")
        self.assertEqual(failed["http_status"], 403)
        self.assertEqual(self.wire.calls, 1)

    def test_authentication_error_envelope_is_classified_without_retry(self):
        self._prepare()
        self.wire.responses.append(replace(self.wire.response(status=401), body=json.dumps({
            "error-response": {"error-code": "AUTHENTICATION_ERROR", "error-message": ERROR_SENTINEL}
        }).encode("utf-8")))
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_FAILED)
        failed = next(row for row in records if row.get("event") == "failed")
        self.assertEqual(failed["remote_error_code"], "authentication_error")
        self.assertEqual(self.wire.calls, 1)

    def test_unrecognized_server_code_cannot_enter_control_output(self):
        self._prepare()
        self.wire.responses.append(replace(self.wire.response(status=403), body=json.dumps({
            "error-response": {"error-code": ERROR_SENTINEL, "error-message": CONTENT_SENTINEL}
        }).encode("utf-8")))
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_FAILED)
        failed = next(row for row in records if row.get("event") == "failed")
        self.assertEqual(failed["remote_error_code"], "unclassified")
        self.assertEqual(self.wire.calls, 1)

    def test_invalid_error_body_preserves_http_failure(self):
        self._prepare()
        self.wire.responses.append(replace(self.wire.response(status=403), body=b"not-json"))
        code, records, _ = self._run()
        self.assertEqual(code, cli.EXIT_FAILED)
        failed = next(row for row in records if row.get("event") == "failed")
        self.assertEqual(failed["remote_error_code"], "unclassified")
        self.assertEqual(failed["http_status"], 403)

    def test_resume_reuses_reservation_cursor_and_attempt_budget(self):
        _, parent = self._pause()
        initial_reservations = {row["reservation_id"] for row in self._rows()}
        code, records = self._invoke("resume", "--run-id", parent, "--api-name",
                                     "scopus_search", execute=True)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.wire.calls, 2)
        self.assertIn("cursor=synthetic-next-cursor", self.wire.urls[-1])
        self.assertEqual({row["reservation_id"] for row in self._rows()}, initial_reservations)
        self.assertEqual(records[-1]["requests_attempted"], 2)
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "scopus_search", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.wire.calls, 2)

    def test_unused_second_api_can_continue_original_atomic_reservation(self):
        _, parent = self._pause(include_abstract=True)
        reserved = [row for row in self._rows() if row["api_name"] == "abstract_retrieval"]
        self.assertEqual(len(reserved), 1)
        code, records = self._invoke("resume", "--run-id", parent, "--api-name",
                                     "abstract_retrieval", execute=True)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(self.wire.calls, 2)
        self.assertEqual(records[-1]["reservation_id"], reserved[0]["reservation_id"])
        self.assertEqual(records[-1]["requests_attempted"], 1)

    def test_resume_requires_new_explicit_consent(self):
        _, parent = self._pause()
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "scopus_search", local_only=True)
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        self.assertEqual(self.wire.calls, 1)

    def test_resume_refuses_missing_checkpoint_after_a_send(self):
        self._prepare()
        with mock.patch.object(RestrictedArtifactStore, "write_checkpoint",
                               side_effect=OSError(ERROR_SENTINEL)):
            code, records, parent = self._run()
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIsNone(records[-1]["network_calls"])
        self.assertEqual(records[-1]["execution_counts_status"], "unknown")
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "scopus_search", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.wire.calls, 1)
        self.assertEqual(len(self.secret.aliases), 1)

    def test_resume_refuses_raw_failure_after_a_charged_attempt(self):
        self._prepare()
        with mock.patch.object(RestrictedArtifactStore, "write_response",
                               side_effect=OSError(ERROR_SENTINEL)):
            code, records, parent = self._run()
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIsNone(records[-1]["secret_reads"])
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "scopus_search", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.wire.calls, 1)

    def test_resume_refuses_tampered_page_before_secret_lookup(self):
        _, parent = self._pause()
        execution = execution_run_id(self.manifest.project_id, self.manifest.task_id,
                                     self.manifest.release_id, parent, "scopus_search")
        store = RestrictedArtifactStore(self.manifest.project_output_dir,
                                        allowed_roots=(self.fixture.project_root,))
        page = store.load_response_records(execution)[0]
        (self.manifest.project_output_dir / page.artifact_ref).write_bytes(b"{}")
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "scopus_search", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.wire.calls, 1)

    def test_unused_resume_rejects_unmanifested_raw_bytes(self):
        _, parent = self._pause(include_abstract=True)
        execution = execution_run_id(self.manifest.project_id, self.manifest.task_id,
                                     self.manifest.release_id, parent, "abstract_retrieval")
        raw_dir = self.manifest.project_output_dir / "raw" / execution
        raw_dir.mkdir(parents=True)
        (raw_dir / "orphan.json").write_bytes(b"{}")
        code, _ = self._invoke("resume", "--run-id", parent, "--api-name",
                               "abstract_retrieval", execute=True, local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(self.wire.calls, 1)

    def test_resume_refuses_unknown_parent_or_api(self):
        self._prepare()
        for parent, api in (("missing-parent", "scopus_search"), ("missing-parent", "abstract_retrieval")):
            code, _ = self._invoke("resume", "--run-id", parent, "--api-name", api,
                                   execute=True, local_only=True)
            self.assertNotEqual(code, cli.EXIT_OK)
        self.assertEqual(self.wire.calls, 0)

    def test_run_status_reads_only_counters_and_does_not_create_evidence(self):
        _, parent = self._pause(include_abstract=True)
        before = {name: self.ledger.rows(name) for name in (
            "quota_window", "task_reservation", "request_usage", "quota_event")}
        code, records = self._invoke("run-status", "--run-id", parent, local_only=True)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual([row["requests_attempted"] for row in records], [1, 0])
        self.assertEqual([row["reserved_remaining"] for row in records], [1, 1])
        self.assertTrue(all(row["network_calls"] == 0 for row in records))
        for name, rows in before.items():
            self.assertEqual(self.ledger.rows(name), rows)

    def test_local_export_rebuilds_records_without_live_policy_or_ledger_mutation(self):
        self._prepare()
        code, _, parent = self._run()
        self.assertEqual(code, cli.EXIT_OK)
        execution = execution_run_id(self.manifest.project_id, self.manifest.task_id,
                                     self.manifest.release_id, parent, "scopus_search")
        store = RestrictedArtifactStore(self.manifest.project_output_dir,
                                        allowed_roots=(self.fixture.project_root,))
        records_path = self.manifest.project_output_dir / store.records_ref(execution)
        expected = records_path.read_bytes()
        records_path.write_bytes(b"interrupted derived output")
        policy = json.loads(self.policy_path.read_text())
        policy["live_capability_enabled"] = False
        fixtures._write_json(self.policy_path, policy)
        before = self.ledger.rows("request_usage")
        code, records = self._invoke("export-records", "--run-id", parent, "--api-name",
                                     "scopus_search", local_only=True)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(records_path.read_bytes(), expected)
        self.assertEqual(records[0]["records_count"], 1)
        self.assertEqual(records[0]["records_pages"], 1)
        self.assertEqual(self.ledger.rows("request_usage"), before)
        self.assertEqual(self.wire.calls, 1)

    def test_local_export_preserves_previous_records_when_raw_changes(self):
        self._prepare()
        _, _, parent = self._run()
        execution = execution_run_id(self.manifest.project_id, self.manifest.task_id,
                                     self.manifest.release_id, parent, "scopus_search")
        store = RestrictedArtifactStore(self.manifest.project_output_dir,
                                        allowed_roots=(self.fixture.project_root,))
        target = self.manifest.project_output_dir / store.records_ref(execution)
        previous = target.read_bytes()
        page = store.load_response_records(execution)[0]
        (self.manifest.project_output_dir / page.artifact_ref).write_bytes(b"{}")
        code, _ = self._invoke("export-records", "--run-id", parent, "--api-name",
                               "scopus_search", local_only=True)
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(target.read_bytes(), previous)

    def test_unknown_run_status_or_export_never_claims_completion(self):
        self._prepare()
        for command in ("run-status", "export-records"):
            arguments = ["--run-id", "missing-run"]
            if command == "export-records":
                arguments.extend(["--api-name", "scopus_search"])
            code, records = self._invoke(command, *arguments, local_only=True)
            self.assertEqual(code, cli.EXIT_VALIDATION)
            self.assertEqual(records[0]["code"], "RUN_NOT_FOUND" if command == "run-status" else "NO_RAW_PAGES")

    def test_wrong_database_is_rejected_without_provisioning_it(self):
        self._prepare()
        original = self.database
        self.database = self.root / "other.sqlite"
        for command, extra in (("run", ()), ("run-status", ("--run-id", "missing-run"))):
            code, _ = self._invoke(command, *extra, execute=command == "run", local_only=True)
            self.assertNotEqual(code, cli.EXIT_OK)
            self.assertFalse(self.database.exists())
        self.database = original


if __name__ == "__main__":
    unittest.main()
