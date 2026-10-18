import io
import json
import os
import socket
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scopus_access.artifacts import (
    ArtifactError,
    Checkpoint,
    RestrictedArtifactStore,
    RunReceipt,
    UnsafeArtifactPath,
    validate_restricted_root,
)
from scopus_access.events import ControlEventWriter, UnsafeEvent, make_event
from scopus_access.runner import (
    GovernedRunner,
    QuotaObservationResult,
    RunAuthorization,
    RunnerGateError,
    TransportResponse,
    _issue_run_authorization,
    execution_run_id,
)


NOW = "2026-09-23T00:00:00Z"
KEY_SENTINEL = "NEVER-PERSIST-THIS-API-KEY"
CONTENT_SENTINEL = "LICENSED-TITLE-SENTINEL"


def linked_run_id(
    *,
    project_id="project-1",
    task_id="task-1",
    release_id="release-1",
    parent_run_id="parent-run-1",
    api_name="scopus_search",
):
    return execution_run_id(
        project_id, task_id, release_id, parent_run_id, api_name
    )


class FakeSecretProvider:
    def __init__(self, secret=KEY_SENTINEL):
        self.secret = secret
        self.calls = 0
        self.closed = 0

    def get_api_key(self, alias):
        self.calls += 1
        provider = self

        class Value:
            def __enter__(self):
                return self

            def reveal(self):
                return provider.secret

            def __exit__(self, exc_type, exc, traceback):
                provider.closed += 1

        return Value()


class FakeLedger:
    def __init__(self):
        self.started = []
        self.finished = []
        self.observations = []
        self.sequence = []
        self.telemetry_accepted = True
        self.telemetry_state = "normal"
        self.forecast_safe = True

    def record_attempt_started(self, record):
        self.started.append(record)
        self.sequence.append(("started", record.attempt_id))
        return object()

    def record_attempt_finished(self, record):
        self.finished.append(record)
        self.sequence.append(("finished", record.attempt_id))

    def record_quota_observation(self, record):
        self.observations.append(record)
        self.sequence.append(("quota", record.attempt_id))
        return QuotaObservationResult(
            self.telemetry_accepted,
            self.telemetry_state
            if self.telemetry_accepted
            else "quota_telemetry_unknown",
        )

    def assess_running_forecast(
        self, reservation_id, revised_requests_remaining, safe_checkpoint, observed_at_utc
    ):
        self.sequence.append(("forecast", revised_requests_remaining))
        return self.forecast_safe

    def release_throttle_backoff(self, attempt_id):
        self.sequence.append(("backoff_released", attempt_id))


class FakeTransport:
    def __init__(self, ledger, responses):
        self.ledger = ledger
        self.responses = list(responses)
        self.requests = []
        self.call_count = 0
        self.initial_started = len(ledger.started)

    def send(self, request, *, api_key, request_capability):
        # This is the critical attempt-before-send assertion: the transport can
        # only be entered after the durable-start callback returned.
        self.call_count += 1
        self.assertion = len(self.ledger.started) == self.initial_started + self.call_count
        if not self.assertion:
            raise AssertionError("transport entered before attempt record")
        if api_key != KEY_SENTINEL:
            raise AssertionError("secret provider value was not used")
        if request_capability is None:
            raise AssertionError("attempt capability was not propagated")
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def quota_headers(remaining="99"):
    return {
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": remaining,
        "X-RateLimit-Reset": "2000000000",
    }


def search_body(*entries):
    return json.dumps(
        {"search-results": {"entry": list(entries)}},
        separators=(",", ":"),
    ).encode("utf-8")


class EventTests(unittest.TestCase):
    def test_remote_error_field_rejects_unrecognized_response_text(self):
        fields = dict(
            event_type="failed", run_id=linked_run_id(), parent_run_id="parent-run-1",
            project_id="project-1", task_id="task-1", release_id="release-1",
            reservation_id="reservation-1", api_name="scopus_search", timestamp=NOW,
            code="authorization_failed", completeness="not_started",
            checkpoint_ref="checkpoints/local.checkpoint.json", http_status=403,
        )
        for value in (KEY_SENTINEL, "some-unreviewed-server-message"):
            with self.assertRaises(UnsafeEvent) as raised:
                make_event(**fields, remote_error_code=value)
            self.assertNotIn(value, str(raised.exception))

    def test_control_event_is_one_json_line(self):
        event = make_event(
            "task_admitted",
            run_id=linked_run_id(),
            parent_run_id="parent-run-1",
            project_id="project-1",
            task_id="task-1",
            timestamp=NOW,
            release_id="release-1",
            reservation_id="reservation-1",
            api_name="scopus_search",
            max_requests=3,
            retry_allowance=1,
            content_egress="local_file_only",
        )
        stream = io.StringIO()
        writer = ControlEventWriter(stream, clock=lambda: NOW)
        writer.emit(
            "task_admitted",
            run_id=linked_run_id(),
            parent_run_id="parent-run-1",
            project_id="project-1",
            task_id="task-1",
            release_id="release-1",
            reservation_id="reservation-1",
            api_name="scopus_search",
            max_requests=3,
            retry_allowance=1,
            content_egress="local_file_only",
        )
        self.assertEqual(event, json.loads(stream.getvalue()))
        self.assertEqual(stream.getvalue().count("\n"), 1)

    def test_event_requires_complete_consistent_execution_linkage(self):
        fields = dict(
            event_type="warning",
            run_id=linked_run_id(),
            parent_run_id="parent-run-1",
            project_id="project-1",
            task_id="task-1",
            release_id="release-1",
            reservation_id="reservation-1",
            api_name="scopus_search",
            timestamp=NOW,
            code="throttled",
        )
        missing_release = dict(fields)
        missing_release.pop("release_id")
        with self.assertRaisesRegex(UnsafeEvent, "missing required"):
            make_event(**missing_release)

        mismatched = dict(fields)
        mismatched["api_name"] = "abstract_retrieval"
        with self.assertRaisesRegex(UnsafeEvent, "namespace"):
            make_event(**mismatched)

    def test_abstract_event_views_match_policy_allowlist(self):
        run_id = linked_run_id(api_name="abstract_retrieval")
        for view in ("FULL", "META", "META_ABS", "REF"):
            with self.subTest(view=view):
                event = make_event(
                    "request_started",
                    run_id=run_id,
                    parent_run_id="parent-run-1",
                    project_id="project-1",
                    task_id="task-1",
                    release_id="release-1",
                    reservation_id="reservation-1",
                    api_name="abstract_retrieval",
                    timestamp=NOW,
                    attempt_id=run_id + ".p1.a1",
                    endpoint_class="abstract_retrieval",
                    view=view,
                    page_size=1,
                    page_number=1,
                    retry_number=0,
                )
                self.assertEqual(event["view"], view)

    def test_forbidden_and_unknown_fields_are_rejected_without_echo(self):
        base = dict(
            event_type="warning",
            run_id=linked_run_id(),
            parent_run_id="parent-run-1",
            project_id="project-1",
            task_id="task-1",
            release_id="release-1",
            reservation_id="reservation-1",
            api_name="scopus_search",
            timestamp=NOW,
            code="throttled",
        )
        for field in (
            "title",
            "abstract",
            "references",
            "payload",
            "query",
            "token",
            "api_key",
            "cookie",
            "unknown_field",
        ):
            with self.subTest(field=field):
                with self.assertRaises(UnsafeEvent) as caught:
                    make_event(**base, **{field: KEY_SENTINEL})
                self.assertNotIn(KEY_SENTINEL, str(caught.exception))

    def test_nested_values_and_absolute_refs_are_rejected(self):
        with self.assertRaises(UnsafeEvent):
            make_event(
                "warning",
                run_id=linked_run_id(),
                parent_run_id="parent-run-1",
                project_id="project-1",
                task_id="task-1",
                release_id="release-1",
                reservation_id="reservation-1",
                api_name="scopus_search",
                timestamp=NOW,
                code={"value": "throttled"},
            )
        with self.assertRaises(UnsafeEvent):
            make_event(
                "paused",
                run_id=linked_run_id(),
                parent_run_id="parent-run-1",
                project_id="project-1",
                task_id="task-1",
                release_id="release-1",
                reservation_id="reservation-1",
                api_name="scopus_search",
                timestamp=NOW,
                reason="quota_exhausted",
                completeness="partial",
                checkpoint_ref="/outside/checkpoint.json",
            )


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.allowed = self.base / "project" / "restricted_metadata"
        self.allowed.mkdir(parents=True)
        self.store = RestrictedArtifactStore(
            self.allowed,
            allowed_roots=[self.allowed],
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_relative_traversal_prefix_and_symlink_escape(self):
        outside = self.base / "outside"
        outside.mkdir()
        with self.assertRaises(UnsafeArtifactPath):
            validate_restricted_root(
                self.allowed / ".." / ".." / "outside",
                [self.allowed],
            )
        prefix = self.base / "project" / "restricted_metadata-other"
        prefix.mkdir()
        with self.assertRaises(UnsafeArtifactPath):
            validate_restricted_root(prefix, [self.allowed])
        link = self.allowed / "escape"
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(UnsafeArtifactPath):
            validate_restricted_root(link, [self.allowed])
        with self.assertRaises(UnsafeArtifactPath):
            validate_restricted_root(Path("relative"), [self.allowed])

    def test_root_identity_swap_cannot_redirect_a_later_write(self):
        outside = self.base / "outside-write-target"
        outside.mkdir()
        moved = self.base / "original-restricted-root"
        self.allowed.rename(moved)
        self.allowed.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(UnsafeArtifactPath):
            self.store.write_response(
                run_id="run-swap",
                attempt_id="run-swap.p1.a1",
                page_number=1,
                body=b"must-not-escape",
                timestamp=NOW,
            )
        self.assertFalse((outside / "raw").exists())

    def test_intermediate_parent_symlink_swap_cannot_redirect_write(self):
        project = self.base / "project"
        moved = self.base / "moved-project-outside-allowlist"
        project.rename(moved)
        project.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(UnsafeArtifactPath):
            self.store.write_response(
                run_id="run-parent-swap",
                attempt_id="run-parent-swap.p1.a1",
                page_number=1,
                body=b"RAW-LICENSED-PAYLOAD",
                timestamp=NOW,
            )
        self.assertFalse((moved / "restricted_metadata" / "raw").exists())

    def test_control_artifact_metadata_rejects_content_and_bad_references(self):
        metadata_run_id = linked_run_id(parent_run_id="parent-run-metadata")
        with self.assertRaises(ArtifactError):
            self.store.write_response(
                run_id="run-metadata",
                attempt_id="run-metadata.p1.a1",
                page_number=1,
                body=b"RAW-LICENSED-PAYLOAD",
                timestamp=CONTENT_SENTINEL,
            )
        self.assertFalse((self.allowed / "raw").exists())

        with self.assertRaises(ArtifactError):
            self.store.write_checkpoint(
                Checkpoint(
                    run_id="run-metadata",
                    next_page=1,
                    next_cursor=None,
                    completed_pages=0,
                    requests_attempted=0,
                    retries_used=0,
                    complete=False,
                    last_artifact_sha256=None,
                    saved_at_utc=CONTENT_SENTINEL,
                )
            )
        with self.assertRaises(ArtifactError):
            self.store.write_receipt(
                RunReceipt(
                    run_id=metadata_run_id,
                    parent_run_id="parent-run-metadata",
                    project_id="project-1",
                    task_id="task-1",
                    release_id="release-1",
                    reservation_id="reservation-1",
                    api_name="scopus_search",
                    status="paused",
                    completeness="not_started",
                    pages_completed=0,
                    requests_attempted=0,
                    retries_used=0,
                    stop_reason="quota_telemetry_unknown",
                    checkpoint_ref=CONTENT_SENTINEL,
                    receipt_ref=CONTENT_SENTINEL,
                    artifact_manifest_ref=None,
                    artifact_manifest_sha256=None,
                    started_at_utc=NOW,
                    completed_at_utc=NOW,
                )
            )

    def test_raw_bytes_manifest_checkpoint_and_receipt_are_separated(self):
        run_id = linked_run_id()
        body = search_body({"dc:title": CONTENT_SENTINEL})
        artifact = self.store.write_response(
            run_id=run_id,
            attempt_id=run_id + ".p1.a1",
            page_number=1,
            body=body,
            timestamp=NOW,
        )
        raw_path = self.allowed / artifact.artifact_ref
        self.assertEqual(raw_path.read_bytes(), body)
        self.assertEqual(oct(raw_path.stat().st_mode & 0o777), "0o600")

        manifest_path = self.allowed / self.store.manifest_ref(run_id)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["sha256"], artifact.sha256)
        self.assertEqual(manifest["size_bytes"], len(body))
        self.assertNotIn(CONTENT_SENTINEL, manifest_path.read_text(encoding="utf-8"))

        checkpoint_ref = self.store.write_checkpoint(
            Checkpoint(
                run_id=run_id,
                next_page=2,
                next_cursor="cursor-2",
                completed_pages=1,
                requests_attempted=1,
                retries_used=0,
                complete=False,
                last_artifact_sha256=artifact.sha256,
                saved_at_utc=NOW,
            )
        )
        loaded = self.store.load_checkpoint(run_id)
        self.assertEqual(loaded.next_page, 2)
        self.assertEqual(loaded.next_cursor, "cursor-2")

        manifest_ref, manifest_sha = self.store.manifest_digest(run_id)
        receipt = RunReceipt(
            run_id=run_id,
            parent_run_id="parent-run-1",
            project_id="project-1",
            task_id="task-1",
            release_id="release-1",
            reservation_id="reservation-1",
            api_name="scopus_search",
            status="paused",
            completeness="partial",
            pages_completed=1,
            requests_attempted=1,
            retries_used=0,
            stop_reason="quota_telemetry_unknown",
            checkpoint_ref=checkpoint_ref,
            receipt_ref=self.store.receipt_ref(run_id),
            artifact_manifest_ref=manifest_ref,
            artifact_manifest_sha256=manifest_sha,
            started_at_utc=NOW,
            completed_at_utc=NOW,
        )
        with self.assertRaisesRegex(ArtifactError, "namespace"):
            self.store.write_receipt(
                replace(receipt, parent_run_id="different-parent-run")
            )
        receipt_ref = self.store.write_receipt(receipt)
        receipt_bytes = (self.allowed / receipt_ref).read_bytes()
        self.assertLess(len(receipt_bytes), 8192)
        self.assertNotIn(CONTENT_SENTINEL.encode(), receipt_bytes)
        self.assertNotIn(body, receipt_bytes)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "restricted_metadata"
        self.root.mkdir()
        self.store = RestrictedArtifactStore(self.root, allowed_roots=[self.root])
        self.stream = io.StringIO()
        self.events = ControlEventWriter(self.stream, clock=lambda: NOW)
        self.secret = FakeSecretProvider()
        self.ledger = FakeLedger()

    def tearDown(self):
        self.temp.cleanup()

    def auth(self, **overrides):
        parent_run_id = overrides.pop("run_id", "parent-run-1")
        values = dict(
            run_id=execution_run_id(
                "project-1", "task-1", "release-1", parent_run_id, "scopus_search"
            ),
            parent_run_id=parent_run_id,
            project_id="project-1",
            task_id="task-1",
            release_id="release-1",
            reservation_id="reservation-1",
            api_key_alias="portfolio-primary",
            api_name="scopus_search",
            endpoint_class="search",
            view="STANDARD",
            page_size=25,
            max_pages=3,
            max_requests=4,
            retry_allowance=1,
            content_egress="local_file_only",
            admitted=True,
            release_validated=True,
            query_manifest_sha256="a" * 64,
            execution_control_sha256="b" * 64,
            control_database_path=str(
                (Path(self.temp.name) / "control.sqlite").resolve()
            ),
            control_database_instance_id="12345678-1234-4123-8123-123456789abc",
            control_database_device=1,
            control_database_inode=1,
            release_evidence_path="/offline/release.json",
            release_evidence_sha256="c" * 64,
            release_approved_at_utc="2025-01-01T00:00:00Z",
            release_expires_at_utc=None,
            topology_evidence_path=str(
                (Path(self.temp.name) / "topology.json").resolve()
            ),
            topology_evidence_sha256="d" * 64,
            ai_license_evidence_path=None,
            ai_license_evidence_sha256=None,
            ai_route_evidence_path=None,
            ai_route_evidence_sha256=None,
            license_evidence_verified=False,
            ai_route_released=False,
        )
        values.update(overrides)
        values["run_id"] = execution_run_id(
            values["project_id"],
            values["task_id"],
            values["release_id"],
            values["parent_run_id"],
            values["api_name"],
        )
        return _issue_run_authorization(**values)

    def runner(self, responses, **overrides):
        transport = FakeTransport(self.ledger, responses)
        sleeps = []
        runner = GovernedRunner(
            transport=transport,
            secret_provider=self.secret,
            ledger=self.ledger,
            artifacts=self.store,
            events=self.events,
            sleeper=sleeps.append,
            clock=lambda: NOW,
            epoch_clock=lambda: 1_000,
            max_retry_after_seconds=5,
            **overrides,
        )
        return runner, transport, sleeps

    def lines(self):
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def test_two_page_success_is_attempt_first_and_content_never_reaches_control(self):
        body1 = search_body(
            {"dc:identifier": "SYNTHETIC-1", "dc:title": CONTENT_SENTINEL}
        )
        body2 = search_body({"dc:identifier": "SYNTHETIC-2"})
        responses = [
            TransportResponse(
                status=200,
                headers=quota_headers("99"),
                body=body1,
                result_count=1,
                has_more=True,
                next_cursor="cursor-2",
            ),
            TransportResponse(
                status=200,
                headers=quota_headers("98"),
                body=body2,
                result_count=1,
                has_more=False,
            ),
        ]
        runner, transport, _ = self.runner(responses)
        authorization = self.auth()
        with mock.patch.object(
            socket, "create_connection", side_effect=AssertionError("network forbidden")
        ):
            receipt = runner.run(authorization)
        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.completeness, "complete")
        self.assertEqual(receipt.pages_completed, 2)
        self.assertEqual(receipt.requests_attempted, 2)
        self.assertTrue(all(getattr(transport, "assertion", False) for _ in [0]))
        self.assertEqual([item.page_number for item in transport.requests], [1, 2])
        self.assertEqual(len(self.ledger.started), 2)
        self.assertEqual(len(self.ledger.finished), 2)
        self.assertEqual(self.secret.calls, 2)
        self.assertEqual(self.secret.closed, 2)

        control_text = self.stream.getvalue()
        receipt_text = (self.root / receipt.receipt_ref).read_text(encoding="utf-8")
        manifest_text = (
            self.root / self.store.manifest_ref(authorization.run_id)
        ).read_text(encoding="utf-8")
        for text in (control_text, receipt_text, manifest_text, repr(self.ledger.started)):
            self.assertNotIn(KEY_SENTINEL, text)
            self.assertNotIn(CONTENT_SENTINEL, text)
        raw = list((self.root / "raw").rglob("*.json"))
        self.assertEqual(len(raw), 2)
        self.assertTrue(
            any(CONTENT_SENTINEL in path.read_text(encoding="utf-8") for path in raw)
        )
        event_types = [line["event"] for line in self.lines()]
        self.assertEqual(event_types[0], "task_admitted")
        self.assertEqual(event_types[-1], "run_completed")
        self.assertEqual(event_types.count("request_started"), 2)
        self.assertEqual(event_types.count("page_completed"), 2)

    def test_missing_headers_pauses_at_checkpoint_then_resume_starts_next_page(self):
        first = TransportResponse(
            status=200,
            headers={},
            body=search_body({"dc:identifier": "SYNTHETIC-1"}),
            result_count=1,
            has_more=True,
            next_cursor="cursor-2",
        )
        runner, transport, _ = self.runner([first])
        authorization = self.auth()
        receipt1 = runner.run(authorization)
        self.assertEqual(receipt1.status, "paused")
        self.assertEqual(receipt1.stop_reason, "quota_telemetry_unknown")
        self.assertEqual(transport.call_count, 1)
        checkpoint = self.store.load_checkpoint(authorization.run_id)
        self.assertEqual(checkpoint.next_page, 2)
        self.assertEqual(checkpoint.next_cursor, "cursor-2")

        second = TransportResponse(
            status=200,
            headers=quota_headers("98"),
            body=search_body({"dc:identifier": "SYNTHETIC-2"}),
            result_count=1,
            has_more=False,
        )
        runner2, transport2, _ = self.runner([second])
        receipt2 = runner2.run(authorization)
        self.assertEqual(receipt2.status, "completed")
        self.assertEqual(receipt2.pages_completed, 2)
        self.assertEqual(receipt2.requests_attempted, 2)
        self.assertEqual(transport2.requests[0].page_number, 2)
        self.assertEqual(transport2.requests[0].cursor, "cursor-2")

    def test_throttle_retry_is_bounded_counted_and_clamped(self):
        responses = [
            TransportResponse(
                status=429,
                headers={
                    "X-ELS-Status": "THROTTLED",
                    "Retry-After": "999",
                    **quota_headers("99"),
                },
                body=b"ignored error body",
                result_count=0,
                has_more=False,
            ),
            TransportResponse(
                status=200,
                headers=quota_headers(),
                body=search_body(),
                result_count=0,
                has_more=False,
            ),
        ]
        runner, transport, sleeps = self.runner(responses)
        authorization = self.auth(max_pages=1, max_requests=2, retry_allowance=1)
        receipt = runner.run(authorization)
        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.requests_attempted, 2)
        self.assertEqual(receipt.retries_used, 1)
        self.assertEqual(transport.call_count, 2)
        self.assertEqual(sleeps, [5])
        self.assertEqual(
            [record.outcome for record in self.ledger.finished],
            ["throttled", "page_completed"],
        )
        release_index = self.ledger.sequence.index(
            ("backoff_released", authorization.run_id + ".p1.a1")
        )
        retry_index = self.ledger.sequence.index(
            ("started", authorization.run_id + ".p1.a2")
        )
        self.assertLess(release_index, retry_index)

    def test_exact_eighty_percent_emits_warning_but_reserved_run_completes(self):
        self.ledger.telemetry_state = "quota_warning_80"
        response = TransportResponse(
            status=200,
            headers=quota_headers("20"),
            body=search_body(),
            result_count=0,
            has_more=False,
        )
        runner, _, _ = self.runner([response])
        receipt = runner.run(self.auth(max_pages=1, max_requests=1))
        self.assertEqual(receipt.status, "completed")
        lines = self.lines()
        quota_event = next(line for line in lines if line["event"] == "quota_updated")
        self.assertEqual(quota_event["quota_state"], "quota_warning_80")
        self.assertTrue(
            any(
                line["event"] == "warning" and line["code"] == "quota_warning_80"
                for line in lines
            )
        )

    def test_reservation_close_failure_writes_a_paused_receipt(self):
        self.ledger.record_run_completed = mock.Mock(
            side_effect=RuntimeError("untrusted close failure")
        )
        response = TransportResponse(
            status=200,
            headers=quota_headers("99"),
            body=search_body(),
            result_count=0,
            has_more=False,
        )
        runner, transport, _ = self.runner([response])
        receipt = runner.run(self.auth(max_pages=1, max_requests=1))
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.completeness, "complete")
        self.assertEqual(receipt.stop_reason, "reservation_close_failed")
        stored = json.loads((self.root / receipt.receipt_ref).read_text())
        self.assertEqual(stored["stop_reason"], "reservation_close_failed")
        self.assertEqual(self.lines()[-1]["event"], "run_completed")
        self.assertEqual(self.lines()[-1]["status"], "paused")

    def test_successful_page_with_zero_remaining_pauses_before_next_request(self):
        self.ledger.telemetry_state = "quota_exhausted"
        response = TransportResponse(
            status=200,
            headers=quota_headers("0"),
            body=search_body({"dc:identifier": "SYNTHETIC-1"}),
            result_count=1,
            has_more=True,
            next_cursor="cursor-2",
        )
        runner, transport, _ = self.runner([response])
        receipt = runner.run(self.auth(max_pages=2, max_requests=2))
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.stop_reason, "quota_exhausted")
        self.assertEqual(transport.call_count, 1)

    def test_revised_forecast_risk_is_recorded_at_safe_page_boundary(self):
        self.ledger.forecast_safe = False
        response = TransportResponse(
            status=200,
            headers=quota_headers("99"),
            body=search_body({"dc:identifier": "SYNTHETIC-1"}),
            result_count=1,
            has_more=True,
            next_cursor="cursor-2",
        )
        runner, transport, _ = self.runner([response])
        # Forecast risk is assessed while another request remains authorized.
        receipt = runner.run(self.auth(max_pages=2, max_requests=2))
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.stop_reason, "running_task_quota_risk")
        self.assertEqual(transport.call_count, 1)
        self.assertTrue(
            any(
                line["event"] == "warning"
                and line["code"] == "running_task_quota_risk"
                for line in self.lines()
            )
        )

    def test_throttle_without_complete_quota_headers_pauses_without_retry(self):
        response = TransportResponse(
            status=429,
            headers={"X-ELS-Status": "THROTTLED", "Retry-After": "1"},
            body=b"ignored error body",
            result_count=0,
            has_more=False,
        )
        runner, transport, sleeps = self.runner([response])
        receipt = runner.run(self.auth())
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.stop_reason, "quota_telemetry_unknown")
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(sleeps, [])
        self.assertEqual(self.ledger.finished[0].outcome, "quota_telemetry_unknown")

    def test_quota_exceeded_429_is_never_retried(self):
        response = TransportResponse(
            status=429,
            headers={"X-ELS-Status": "QUOTA_EXCEEDED", **quota_headers("0")},
            body=b"ignored",
            result_count=0,
            has_more=False,
        )
        runner, transport, sleeps = self.runner([response])
        receipt = runner.run(self.auth())
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.stop_reason, "quota_exhausted")
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_401_and_403_fail_closed_without_retry_or_error_body(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.stream = io.StringIO()
                self.events = ControlEventWriter(self.stream, clock=lambda: NOW)
                self.secret = FakeSecretProvider()
                self.ledger = FakeLedger()
                response = TransportResponse(
                    status=status,
                    headers={},
                    body=(KEY_SENTINEL + CONTENT_SENTINEL).encode(),
                    result_count=0,
                    has_more=False,
                )
                runner, transport, sleeps = self.runner([response])
                receipt = runner.run(self.auth(run_id="run-%d" % status))
                self.assertEqual(receipt.status, "failed")
                self.assertEqual(receipt.stop_reason, "authorization_failed")
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(sleeps, [])
                self.assertNotIn(KEY_SENTINEL, self.stream.getvalue())
                self.assertNotIn(CONTENT_SENTINEL, self.stream.getvalue())
                self.assertFalse((self.root / "raw" / ("run-%d" % status)).exists())

    def test_transport_exception_text_is_not_exposed(self):
        error = RuntimeError(KEY_SENTINEL + " " + CONTENT_SENTINEL)
        runner, transport, _ = self.runner([error])
        receipt = runner.run(self.auth())
        self.assertEqual(receipt.status, "failed")
        self.assertEqual(transport.call_count, 1)
        self.assertNotIn(KEY_SENTINEL, self.stream.getvalue())
        self.assertNotIn(CONTENT_SENTINEL, self.stream.getvalue())

    def test_release_and_ai_egress_gates_precede_secret_and_transport(self):
        runner, transport, _ = self.runner([])
        with self.assertRaises(RunnerGateError):
            runner.run(self.auth(admitted=False))
        self.assertEqual(self.secret.calls, 0)
        self.assertEqual(transport.call_count, 0)

        with self.assertRaises(RunnerGateError):
            runner.run(
                self.auth(
                    content_egress="authorized_ai_session",
                    license_evidence_verified=False,
                    ai_route_released=True,
                )
            )
        self.assertEqual(self.secret.calls, 0)
        self.assertEqual(transport.call_count, 0)


if __name__ == "__main__":
    unittest.main()
