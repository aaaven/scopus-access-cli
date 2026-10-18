from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scopus_access.ledger import AliasBindingError, Ledger, LedgerError
from scopus_access.quota import (
    ABSTRACT_RETRIEVAL,
    SCOPUS_SEARCH,
    QuotaState,
    ReservationRequest,
    classify_http_response,
    evaluate_headers,
)


OBSERVED = "2026-09-23T09:00:00Z"
RESET_2100 = 4102444800
RESET_2099 = 4070908800


def headers(limit: int = 100, remaining: int = 100, reset: int = RESET_2100):
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset),
    }


def requirement(api_name: str, estimate: int, retries: int = 0) -> ReservationRequest:
    return ReservationRequest(
        api_name=api_name,
        view="STANDARD" if api_name == SCOPUS_SEARCH else "FULL",
        page_size=25,
        forecast_pagination=estimate - retries,
        forecast_detail_retrieval=0,
        forecast_validation=0,
        retry_allowance=retries,
    )


class LedgerQuotaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "control.sqlite3"
        self.ledger = Ledger(self.db_path)
        self.flow_index = 0
        self.ledger.register_project_key_alias(
            "project-alpha", "institutional-primary", "d" * 64, OBSERVED
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def next_flow(self, label: str) -> str:
        self.flow_index += 1
        return "%s-%d" % (label, self.flow_index)

    def seed(
        self,
        api_name: str,
        limit: int = 100,
        remaining: int = 100,
        reset: int = RESET_2100,
        observed_at_utc: str = OBSERVED,
    ):
        flow = self.next_flow("preflight")
        admission = self.ledger._admit_preflight(
            "project-alpha",
            "%s-task" % flow,
            "%s-run" % flow,
            "%s-release" % flow,
            "c" * 64,
            requirement(api_name, 1),
            observed_at_utc,
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(admission.admitted)
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id,
            api_name,
            "%s-page" % flow,
            0,
            observed_at_utc,
        )
        self.assertTrue(attempt.allowed)
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            headers(limit, remaining, reset),
            "c" * 64,
            0,
            observed_at_utc,
        )
        status = self.ledger.quota_status(
            "institutional-primary", api_name, observed_at_utc
        )
        self.assertEqual(result.quota_state, status.state)
        return status

    def charged_response(
        self,
        api_name: str,
        response_headers,
        observed_at_utc: str,
        admission_at_utc: str = "2026-09-23T09:01:00Z",
    ):
        flow = self.next_flow("task")
        admission = self.ledger._admit_task(
            "project-alpha",
            "%s-task" % flow,
            "%s-run" % flow,
            "%s-release" % flow,
            "a" * 64,
            [requirement(api_name, 1)],
            admission_at_utc,
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(admission.admitted)
        reservation_id = admission.buckets[0].reservation_id
        attempt = self.ledger.record_request_attempt(
            reservation_id,
            api_name,
            "%s-page" % flow,
            0,
            admission_at_utc,
        )
        self.assertTrue(attempt.allowed)
        before_response = self.ledger.quota_status(
            "institutional-primary", api_name, admission_at_utc
        )
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            response_headers,
            "c" * 64,
            0,
            observed_at_utc,
        )
        after_response = self.ledger.quota_status(
            "institutional-primary", api_name, admission_at_utc
        )
        return result, before_response, after_response

    def admit_one(self, estimate: int = 4, retries: int = 1):
        self.seed(SCOPUS_SEARCH)
        result = self.ledger._admit_task(
            "project-alpha",
            "task-1",
            "run-1",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, estimate, retries)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(result.admitted)
        return result.buckets[0].reservation_id

    def test_initialization_creates_no_live_records(self) -> None:
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)
        self.assertEqual(self.ledger.ledger_count("task_reservation"), 0)
        self.assertEqual(self.ledger.ledger_count("request_usage"), 0)
        self.assertEqual(self.ledger.ledger_count("quota_event"), 0)

    def test_free_text_cannot_enter_digest_or_evidence_fields(self) -> None:
        sentinel = "APIKEY licensed title abstract reference payload"
        with self.assertRaises(ValueError) as alias_error:
            self.ledger.register_project_key_alias(
                "project-beta", "institutional-secondary", sentinel, OBSERVED
            )
        preflight = self.ledger._admit_preflight(
            "project-alpha",
            "preflight-content-rejection",
            "preflight-content-run",
            "preflight-content-release",
            "c" * 64,
            requirement(SCOPUS_SEARCH, 1),
            OBSERVED,
            expected_api_key_alias="institutional-primary",
        )
        attempt = self.ledger.record_request_attempt(
            preflight.buckets[0].reservation_id,
            SCOPUS_SEARCH,
            "preflight-content-page",
            0,
            OBSERVED,
        )
        with self.assertRaises(ValueError) as header_error:
            self.ledger.record_response(
                attempt.attempt_id,
                200,
                headers(),
                sentinel,
                0,
                OBSERVED,
            )
        with self.assertRaises(ValueError) as query_error:
            self.ledger._admit_task(
                "project-alpha",
                "task-content-rejection",
                "run-content-rejection",
                "release-content-rejection",
                sentinel,
                [requirement(SCOPUS_SEARCH, 1)],
                OBSERVED,
                expected_api_key_alias="institutional-primary",
            )
        for error in (alias_error, header_error, query_error):
            self.assertNotIn(sentinel, str(error.exception))
        self.assertEqual(self.ledger.ledger_count("project_alias"), 1)
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)
        self.assertEqual(self.ledger.ledger_count("task_reservation"), 2)
        self.assertEqual(self.ledger.ledger_count("request_usage"), 1)

    def test_unverified_rejects_without_fabricating_records(self) -> None:
        self.assertFalse(hasattr(self.ledger, "record_quota_observation"))
        self.assertFalse(hasattr(self.ledger, "admit_preflight"))
        self.assertFalse(hasattr(self.ledger, "admit_task"))
        result = self.ledger._admit_task(
            "project-alpha",
            "task-unverified",
            "run-unverified",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 1)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason_code, "UNVERIFIED")
        self.assertEqual(result.buckets[0].state, QuotaState.UNVERIFIED)
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)
        self.assertEqual(self.ledger.ledger_count("task_reservation"), 0)
        self.assertEqual(self.ledger.ledger_count("request_usage"), 0)

    def test_search_and_abstract_are_independent_buckets(self) -> None:
        search = self.seed(SCOPUS_SEARCH, 100, 95)
        abstract = self.seed(ABSTRACT_RETRIEVAL, 10, 1)
        self.assertEqual(search.state, QuotaState.NORMAL)
        self.assertEqual(abstract.state, QuotaState.QUOTA_WARNING_80)
        self.assertEqual(
            self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH).used, 5
        )
        self.assertEqual(
            self.ledger.quota_status("institutional-primary", ABSTRACT_RETRIEVAL).used, 9
        )

    def test_multi_bucket_admission_is_all_or_nothing(self) -> None:
        self.seed(SCOPUS_SEARCH)
        self.seed(ABSTRACT_RETRIEVAL)
        result = self.ledger._admit_task(
            "project-alpha",
            "task-too-large",
            "run-too-large",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 5), requirement(ABSTRACT_RETRIEVAL, 101)],
            "2026-09-23T09:02:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(result.admitted)
        self.assertEqual(result.decision, "NEW_TASK_DEFERRED_QUOTA")
        rows = [
            row
            for row in self.ledger.rows("task_reservation")
            if row["task_id"] == "task-too-large"
        ]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["event_kind"] == "DEFERRED" for row in rows))
        search = self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH)
        self.assertEqual(search.committed_in_progress, 0)
        event_types = [row["event_type"] for row in self.ledger.rows("quota_event")]
        self.assertIn("NEW_TASK_DEFERRED_QUOTA", event_types)
        self.assertIn("QUOTA_WARNING_80", event_types)

    def test_candidate_at_eighty_percent_freezes_new_task(self) -> None:
        self.seed(SCOPUS_SEARCH)
        result = self.ledger._admit_task(
            "project-alpha",
            "task-warning",
            "run-warning",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 80)],
            "2026-09-23T09:02:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(result.admitted)
        self.assertEqual(result.decision, "QUOTA_WARNING_80")
        status = self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH)
        self.assertEqual(status.state, QuotaState.QUOTA_WARNING_80)
        self.assertEqual(status.committed_in_progress, 0)

    def test_successful_multi_bucket_admission_has_two_reservations(self) -> None:
        self.seed(SCOPUS_SEARCH)
        self.seed(ABSTRACT_RETRIEVAL)
        result = self.ledger._admit_task(
            "project-alpha",
            "task-both",
            "run-both",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 5), requirement(ABSTRACT_RETRIEVAL, 7)],
            "2026-09-23T09:02:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(result.admitted)
        self.assertEqual(len(result.buckets), 2)
        self.assertEqual(
            self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH).committed_in_progress,
            5,
        )
        self.assertEqual(
            self.ledger.quota_status(
                "institutional-primary", ABSTRACT_RETRIEVAL
            ).committed_in_progress,
            7,
        )

    def test_attempt_and_reservation_decrement_are_one_transaction(self) -> None:
        reservation_id = self.admit_one(4, 1)
        result = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:00Z"
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.reserved_remaining, 3)
        reservation_rows = [
            row
            for row in self.ledger.rows("task_reservation")
            if row["reservation_id"] == reservation_id
        ]
        self.assertEqual(reservation_rows[-1]["reserved_remaining"], 3)
        self.assertEqual(reservation_rows[-1]["actual_requests"], 1)
        request_rows = [
            row
            for row in self.ledger.rows("request_usage")
            if row["reservation_id"] == reservation_id
        ]
        self.assertEqual(len(request_rows), 1)
        self.assertEqual(request_rows[0]["record_kind"], "ATTEMPT")
        self.assertEqual(request_rows[0]["reservation_delta"], -1)

    def test_valid_response_appends_predecessor_reconciliation(self) -> None:
        reservation_id = self.admit_one(4, 1)
        attempt = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:00Z"
        )
        before = self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH)
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            headers(100, 99),
            "1" * 64,
            25,
            "2026-09-23T09:02:01Z",
        )
        self.assertEqual(result.quota_state, QuotaState.NORMAL)
        after = self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH)
        self.assertEqual(after.reconciliation_predecessor, before.record_id)
        self.assertEqual(after.local_attempts_since_header, 0)
        self.assertEqual(after.server_remaining, 99)
        kinds = [
            row["record_kind"]
            for row in self.ledger.rows("request_usage")
            if row["reservation_id"] == reservation_id
        ]
        self.assertEqual(kinds, ["ATTEMPT", "OUTCOME"])

    def test_same_window_header_cannot_refund_a_locally_charged_attempt(self) -> None:
        reservation_id = self.admit_one(2, 0)
        attempt = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:00Z"
        )
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            headers(100, 100),
            "2" * 64,
            1,
            "2026-09-23T09:02:01Z",
        )
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        self.assertEqual(
            result.header_reason_code,
            "RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING",
        )
        self.assertEqual(
            self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH).effective_remaining,
            99,
        )

    def test_append_order_not_caller_timestamp_selects_current_snapshot(self) -> None:
        self.seed(SCOPUS_SEARCH)
        result, before, status = self.charged_response(
            SCOPUS_SEARCH,
            {},
            "2026-09-23T08:59:00Z",
        )
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        self.assertEqual(status.state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        self.assertEqual(status.reconciliation_predecessor, before.record_id)

    def test_missing_invalid_and_stale_headers_become_unknown(self) -> None:
        first = self.seed(SCOPUS_SEARCH)
        result, before, missing = self.charged_response(
            SCOPUS_SEARCH,
            {"X-RateLimit-Limit": "100"},
            "2026-09-23T09:03:00Z",
        )
        self.assertEqual(result.header_reason_code, "RATE_LIMIT_HEADERS_MISSING")
        self.assertEqual(missing.state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        self.assertEqual(missing.reconciliation_predecessor, before.record_id)

        invalid = evaluate_headers(
            {"X-RateLimit-Limit": "x", "X-RateLimit-Remaining": "1", "X-RateLimit-Reset": "2"},
            OBSERVED,
        )
        self.assertFalse(invalid.valid)
        self.assertEqual(invalid.reason_code, "RATE_LIMIT_HEADERS_INVALID")

        stale = evaluate_headers(headers(100, 99, RESET_2099), OBSERVED, first)
        self.assertFalse(stale.valid)
        self.assertEqual(stale.reason_code, "RATE_LIMIT_RESET_REGRESSED")

    def test_passed_reset_is_reset_verify_not_automatic_refill(self) -> None:
        self.seed(SCOPUS_SEARCH)
        status = self.ledger.quota_status(
            "institutional-primary", SCOPUS_SEARCH, "2100-01-01T00:00:00Z"
        )
        self.assertEqual(status.state, QuotaState.RESET_VERIFY)

    def test_cross_window_continuation_requires_matching_append_only_disposition(self) -> None:
        self.seed(SCOPUS_SEARCH, reset=RESET_2099)
        admitted = self.ledger._admit_task(
            "project-alpha",
            "cross-window-task",
            "cross-window-run",
            "cross-window-release",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 2)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(admitted.admitted)
        reservation_id = admitted.buckets[0].reservation_id
        diagnostic = self.ledger._admit_preflight(
            "project-alpha",
            "cross-window-diagnostic",
            "cross-window-diagnostic-run",
            "cross-window-diagnostic-release",
            "b" * 64,
            requirement(SCOPUS_SEARCH, 1),
            "2099-01-01T00:00:01Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(diagnostic.admitted)
        transition_attempt = self.ledger.record_request_attempt(
            diagnostic.buckets[0].reservation_id,
            SCOPUS_SEARCH,
            "page:window-transition",
            0,
            "2099-01-01T00:00:01Z",
        )
        self.assertTrue(transition_attempt.allowed)
        transition = self.ledger.record_response(
            transition_attempt.attempt_id,
            200,
            headers(100, 99, RESET_2100),
            "c" * 64,
            0,
            "2099-01-01T00:00:01Z",
        )
        self.assertEqual(transition.quota_state, QuotaState.NORMAL)
        blocked = self.ledger.record_request_attempt(
            reservation_id,
            "SCOPUS_SEARCH",
            "page:1",
            0,
            "2099-01-01T00:00:02Z",
        )
        self.assertFalse(blocked.allowed)
        self.assertEqual(
            blocked.reason_code, "CROSS_WINDOW_CONTINUATION_NOT_AUTHORIZED"
        )
        event = self.ledger.rows("quota_event")[-1]
        group_id = event["event_group_id"]
        disposition_id = self.ledger.append_quota_disposition(
            group_id,
            "APPROVE_CROSS_WINDOW_CONTINUATION",
            "APPROVE_CROSS_WINDOW_CONTINUATION",
            "e" * 64,
            "2099-01-01T00:00:03Z",
            "2099-01-01T00:00:03Z",
            "2099-01-01T00:00:03Z",
        )
        self.ledger.authorize_cross_window_continuation(
            reservation_id, group_id, "2099-01-01T00:00:04Z"
        )
        allowed = self.ledger.record_request_attempt(
            reservation_id,
            "SCOPUS_SEARCH",
            "page:1",
            0,
            "2099-01-01T00:00:05Z",
        )
        self.assertTrue(allowed.allowed)
        closure_id = self.ledger.close_quota_event(
            group_id, "f" * 64, "2099-01-01T00:00:06Z"
        )
        rows = [
            row
            for row in self.ledger.rows("quota_event")
            if row["event_group_id"] == group_id
        ]
        self.assertEqual(
            [row["record_kind"] for row in rows], ["EVENT", "DISPOSITION", "CLOSURE"]
        )
        self.assertEqual(rows[1]["quota_event_id"], disposition_id)
        self.assertEqual(rows[2]["quota_event_id"], closure_id)
        self.assertEqual(rows[2]["predecessor_event_id"], disposition_id)

    def test_401_403_429_and_throttle_dispositions(self) -> None:
        for status in (401, 403):
            item = classify_http_response(status, None, None, 0, 3)
            self.assertFalse(item.retry_allowed)
            self.assertEqual(item.event_type, "AUTHORIZATION_FAILED")
            self.assertEqual(item.state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        exhausted = classify_http_response(429, "QUOTA_EXCEEDED", "1", 0, 3)
        self.assertFalse(exhausted.retry_allowed)
        self.assertEqual(exhausted.state, QuotaState.QUOTA_EXHAUSTED)
        throttled = classify_http_response(429, "RATE_EXCEEDED", "999", 0, 2)
        self.assertTrue(throttled.retry_allowed)
        self.assertEqual(throttled.retry_after_seconds, 60)
        final = classify_http_response(429, "RATE_EXCEEDED", None, 2, 2)
        self.assertFalse(final.retry_allowed)

    def test_http_fail_closed_and_quota_exhausted_are_persisted(self) -> None:
        reservation_id = self.admit_one(5, 1)
        attempt = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:00Z"
        )
        response = self.ledger.record_response(
            attempt.attempt_id,
            401,
            headers(100, 99),
            "3" * 64,
            None,
            "2026-09-23T09:02:01Z",
        )
        self.assertEqual(response.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        blocked = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:2", 1, "2026-09-23T09:02:02Z"
        )
        self.assertFalse(blocked.allowed)

        # A fresh bucket/run demonstrates terminal QUOTA_EXCEEDED handling.
        self.seed(ABSTRACT_RETRIEVAL)
        admitted = self.ledger._admit_task(
            "project-alpha",
            "task-abstract",
            "run-abstract",
            "release-1",
            "a" * 64,
            [requirement(ABSTRACT_RETRIEVAL, 3, 1)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        second_attempt = self.ledger.record_request_attempt(
            admitted.buckets[0].reservation_id,
            "ABSTRACT_RETRIEVAL",
            "record:1",
            0,
            "2026-09-23T09:02:00Z",
        )
        stopped = self.ledger.record_response(
            second_attempt.attempt_id,
            429,
            {**headers(100, 0), "X-ELS-Status": "QUOTA_EXCEEDED"},
            "4" * 64,
            None,
            "2026-09-23T09:02:01Z",
        )
        self.assertEqual(stopped.quota_state, QuotaState.QUOTA_EXHAUSTED)
        self.assertFalse(stopped.disposition.retry_allowed)

    def test_zero_remaining_overrides_retryable_throttle(self) -> None:
        reservation_id = self.admit_one(2, 1)
        attempt = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:00Z"
        )
        stopped = self.ledger.record_response(
            attempt.attempt_id,
            429,
            {**headers(100, 0), "X-ELS-Status": "RATE_EXCEEDED", "Retry-After": "1"},
            "5" * 64,
            None,
            "2026-09-23T09:02:01Z",
        )
        self.assertEqual(stopped.quota_state, QuotaState.QUOTA_EXHAUSTED)
        self.assertFalse(stopped.disposition.retry_allowed)
        self.assertEqual(
            self.ledger.rows("quota_event")[-1]["event_type"], "QUOTA_EXHAUSTED"
        )

    def test_revised_forecast_pauses_at_safe_boundary(self) -> None:
        reservation_id = self.admit_one(4, 1)
        okay = self.ledger.assess_running_forecast(
            reservation_id, 4, "checkpoint:page0", "2026-09-23T09:02:00Z"
        )
        self.assertTrue(okay)
        paused = self.ledger.assess_running_forecast(
            reservation_id, 5, "checkpoint:page0", "2026-09-23T09:02:01Z"
        )
        self.assertFalse(paused)
        event = self.ledger.rows("quota_event")[-1]
        self.assertEqual(event["event_type"], "RUNNING_TASK_QUOTA_RISK")
        self.assertEqual(event["safe_checkpoint"], "checkpoint:page0")
        denied = self.ledger.record_request_attempt(
            reservation_id,
            "SCOPUS_SEARCH",
            "page:after-pause",
            0,
            "2026-09-23T09:02:02Z",
        )
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason_code, "RESERVATION_NOT_ACTIVE")

    def test_release_and_run_identifiers_are_single_consumption_authority(self) -> None:
        self.admit_one(2, 0)
        replay = self.ledger._admit_task(
            "project-alpha",
            "task-1",
            "run-replay",
            "release-1",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 1)],
            "2026-09-23T09:02:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(replay.admitted)
        self.assertEqual(replay.reason_code, "TASK_RELEASE_ALREADY_CONSUMED")
        reused_run = self.ledger._admit_task(
            "project-alpha",
            "different-task",
            "run-1",
            "different-release",
            "b" * 64,
            [requirement(SCOPUS_SEARCH, 1)],
            "2026-09-23T09:02:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(reused_run.admitted)
        self.assertEqual(reused_run.reason_code, "TASK_RELEASE_ALREADY_CONSUMED")

    def test_active_commitments_exceeding_live_remaining_pause_before_send(self) -> None:
        reservation_id = self.admit_one(5, 0)
        telemetry_attempt = self.ledger.record_request_attempt(
            reservation_id,
            SCOPUS_SEARCH,
            "page:telemetry",
            0,
            "2026-09-23T09:02:00Z",
        )
        self.assertTrue(telemetry_attempt.allowed)
        self.ledger.record_response(
            telemetry_attempt.attempt_id,
            200,
            headers(100, 3),
            "c" * 64,
            0,
            "2026-09-23T09:02:00Z",
        )
        blocked = self.ledger.record_request_attempt(
            reservation_id, "SCOPUS_SEARCH", "page:1", 0, "2026-09-23T09:02:01Z"
        )
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.state, QuotaState.RUNNING_TASK_QUOTA_RISK)
        self.assertEqual(
            self.ledger.rows("quota_event")[-1]["forecast_reason"],
            "ACTIVE_COMMITMENTS_EXCEED_LIVE_REMAINING",
        )

    def test_warning_hold_is_sticky_within_window_and_not_duplicated(self) -> None:
        self.seed(SCOPUS_SEARCH)
        holder = self.ledger._admit_task(
            "project-alpha",
            "task-warning-holder",
            "run-warning-holder",
            "release-warning-holder",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 1)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertTrue(holder.admitted)
        rejected = self.ledger._admit_task(
            "project-alpha",
            "task-warning-sticky",
            "run-warning-sticky",
            "release-warning-sticky",
            "a" * 64,
            [requirement(SCOPUS_SEARCH, 79)],
            "2026-09-23T09:01:00Z",
            expected_api_key_alias="institutional-primary",
        )
        self.assertFalse(rejected.admitted)
        warning_count = sum(
            row["event_type"] == "QUOTA_WARNING_80"
            for row in self.ledger.rows("quota_event")
        )
        attempt = self.ledger.record_request_attempt(
            holder.buckets[0].reservation_id,
            SCOPUS_SEARCH,
            "page:warning-holder",
            0,
            "2026-09-23T09:02:00Z",
        )
        self.assertTrue(attempt.allowed)
        self.ledger.record_response(
            attempt.attempt_id,
            200,
            headers(100, 99),
            "c" * 64,
            0,
            "2026-09-23T09:02:00Z",
        )
        self.assertEqual(
            self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH).state,
            QuotaState.QUOTA_WARNING_80,
        )
        self.assertEqual(
            sum(
                row["event_type"] == "QUOTA_WARNING_80"
                for row in self.ledger.rows("quota_event")
            ),
            warning_count,
        )

    def test_alias_history_blocks_silent_rotation(self) -> None:
        with self.assertRaises(AliasBindingError):
            self.ledger.register_project_key_alias(
                "project-alpha", "alternate-key", "d" * 64, "2026-09-24T09:00:00Z"
            )
        event_id = self.ledger.register_project_key_alias(
            "project-alpha",
            "alternate-key",
            "d" * 64,
            "2026-09-24T09:00:00Z",
            "e" * 64,
        )
        self.assertTrue(event_id.startswith("binding_"))
        rows = self.ledger.rows("project_alias")
        self.assertEqual(rows[-1]["event_type"], "AUTHORIZED_CHANGE")
        self.assertEqual(rows[-1]["predecessor_event_id"], rows[0]["binding_event_id"])

    def test_append_only_triggers_reject_update_and_delete(self) -> None:
        self.seed(SCOPUS_SEARCH)
        connection = sqlite3.connect(str(self.db_path))
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE quota_window_ledger SET used = 99")
            connection.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM quota_window_ledger")
        finally:
            connection.close()

    def test_database_identity_is_stable_singleton_and_immutable(self) -> None:
        identity = self.ledger.database_identity()
        reopened = Ledger(self.db_path, require_existing_identity=True)
        self.assertEqual(reopened.database_identity(), identity)

        connection = sqlite3.connect(str(self.db_path))
        try:
            for statement, parameters in (
                (
                    """
                    INSERT INTO schema_meta(
                        singleton, schema_version, installed_at_utc,
                        database_instance_id, database_device, database_inode
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (1, 1, OBSERVED, "12345678-1234-4123-8123-123456789abc", 1, 1),
                ),
                ("UPDATE schema_meta SET schema_version = ?", (2,)),
                ("DELETE FROM schema_meta", ()),
            ):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement, parameters)
                connection.rollback()
        finally:
            connection.close()
        self.assertEqual(self.ledger.database_identity(), identity)

    def test_legacy_identity_schema_fails_closed_without_migration(self) -> None:
        legacy_path = Path(self.temporary.name) / "legacy.sqlite3"
        with sqlite3.connect(str(legacy_path)) as connection:
            connection.execute(
                """
                CREATE TABLE schema_meta(
                    schema_version INTEGER NOT NULL,
                    installed_at_utc TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT INTO schema_meta VALUES (?, ?)", (1, OBSERVED)
            )
        with self.assertRaisesRegex(LedgerError, "identity metadata"):
            Ledger(legacy_path, require_existing_identity=True)
        with sqlite3.connect(str(legacy_path)) as connection:
            columns = tuple(
                str(row[1])
                for row in connection.execute("PRAGMA table_info(schema_meta)")
            )
            objects = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                )
            )
        self.assertEqual(columns, ("schema_version", "installed_at_utc"))
        self.assertEqual(objects, ("schema_meta",))
        self.assertFalse(Path(str(legacy_path) + "-wal").exists())

    def test_preexisting_view_is_rejected_without_schema_mutation(self) -> None:
        occupied_path = Path(self.temporary.name) / "occupied-by-view.sqlite3"
        with sqlite3.connect(str(occupied_path)) as connection:
            connection.execute(
                "CREATE VIEW preexisting_control_view AS SELECT 1 AS marker"
            )
            before = tuple(
                connection.execute(
                    """
                    SELECT type, name, tbl_name, rootpage, sql
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    ORDER BY type, name
                    """
                )
            )

        with self.assertRaises(LedgerError):
            Ledger(occupied_path)

        with sqlite3.connect(str(occupied_path)) as connection:
            after = tuple(
                connection.execute(
                    """
                    SELECT type, name, tbl_name, rootpage, sql
                    FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    ORDER BY type, name
                    """
                )
            )
        self.assertEqual(after, before)

    def test_require_existing_identity_does_not_repair_missing_index(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute("DROP INDEX idx_reservation_run_consumed")
        for require_existing in (True, False):
            with self.assertRaisesRegex(LedgerError, "schema definition"):
                Ledger(
                    self.db_path,
                    require_existing_identity=require_existing,
                )
        with sqlite3.connect(str(self.db_path)) as connection:
            names = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
        self.assertNotIn("idx_reservation_run_consumed", names)

    def test_unexpected_user_schema_object_is_rejected(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute(
                """
                CREATE TRIGGER injected_request_trigger
                AFTER INSERT ON request_usage_log BEGIN
                    SELECT 1;
                END
                """
            )
        with self.assertRaisesRegex(LedgerError, "schema definition"):
            self.ledger.database_identity()
        for require_existing in (True, False):
            with self.assertRaisesRegex(LedgerError, "schema definition"):
                Ledger(
                    self.db_path,
                    require_existing_identity=require_existing,
                )

    def test_regular_reopen_does_not_repair_missing_trigger(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute("DROP TRIGGER no_update_request_usage")
        for require_existing in (True, False):
            with self.assertRaisesRegex(LedgerError, "schema definition"):
                Ledger(
                    self.db_path,
                    require_existing_identity=require_existing,
                )
        with sqlite3.connect(str(self.db_path)) as connection:
            names = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                )
            }
        self.assertNotIn("no_update_request_usage", names)

    def test_same_named_noop_identity_trigger_is_rejected(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute("DROP TRIGGER no_update_schema_meta")
            connection.execute(
                """
                CREATE TRIGGER no_update_schema_meta
                BEFORE UPDATE ON schema_meta BEGIN
                    SELECT 1;
                END
                """
            )
        with self.assertRaisesRegex(LedgerError, "schema definition"):
            self.ledger.database_identity()
        for require_existing in (True, False):
            with self.assertRaisesRegex(LedgerError, "schema definition"):
                Ledger(
                    self.db_path,
                    require_existing_identity=require_existing,
                )

    def test_same_named_weakened_unique_index_is_rejected(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute("DROP INDEX idx_reservation_run_consumed")
            connection.execute(
                """
                CREATE INDEX idx_reservation_run_consumed
                ON task_reservation_ledger(run_id)
                """
            )
        with self.assertRaisesRegex(LedgerError, "schema definition"):
            self.ledger.database_identity()
        for require_existing in (True, False):
            with self.assertRaisesRegex(LedgerError, "schema definition"):
                Ledger(
                    self.db_path,
                    require_existing_identity=require_existing,
                )

    def test_partial_index_literal_case_cannot_bypass_schema_validation(self) -> None:
        with sqlite3.connect(str(self.db_path)) as connection:
            connection.execute("DROP INDEX idx_reservation_run_consumed")
            connection.execute(
                """
                CREATE UNIQUE INDEX idx_reservation_run_consumed
                ON task_reservation_ledger(run_id, api_name)
                WHERE event_seq = 1 AND admission_decision = 'admitted'
                """
            )
        with self.assertRaisesRegex(LedgerError, "schema definition"):
            self.ledger.database_identity()
        with self.assertRaisesRegex(LedgerError, "schema definition"):
            Ledger(self.db_path, require_existing_identity=True)

    def test_concurrent_admission_cannot_overreserve(self) -> None:
        self.seed(SCOPUS_SEARCH)
        barrier = threading.Barrier(2)

        def submit(index: int):
            local = Ledger(self.db_path)
            barrier.wait(timeout=5)
            return local._admit_task(
                "project-alpha",
                "task-concurrent-%d" % index,
                "run-concurrent-%d" % index,
                "release-1",
                "a" * 64,
                [requirement(SCOPUS_SEARCH, 60)],
                "2026-09-23T09:02:00Z",
                expected_api_key_alias="institutional-primary",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, (1, 2)))
        self.assertEqual(sum(1 for result in results if result.admitted), 1)
        status = self.ledger.quota_status("institutional-primary", SCOPUS_SEARCH)
        self.assertEqual(status.committed_in_progress, 60)
        self.assertGreaterEqual(status.free_to_admit, 0)


if __name__ == "__main__":
    unittest.main()
