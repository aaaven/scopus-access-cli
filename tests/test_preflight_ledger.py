import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scopus_access.ledger import Ledger, LedgerError
from scopus_access.quota import QuotaState, ReservationRequest, SCOPUS_SEARCH


NOW = "2030-01-01T00:00:00Z"
RESET = 1893542400  # 2030-01-02T00:00:00Z
BINDING_TIME = "2029-01-01T00:00:00Z"


class InitialPreflightLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = Ledger(Path(self.temporary.name) / "control.sqlite")
        self.ledger.register_project_key_alias(
            "SYNTHETIC-DEMO", "demo-alias", "d" * 64, BINDING_TIME
        )
        self.flow_index = 0
        self.requirement = ReservationRequest(
            SCOPUS_SEARCH, "STANDARD", 1, 1, 0, 0, 0
        )

    def _diagnostic(self, name, predecessor=None, requirement=None):
        return self.ledger._admit_preflight(
            "SYNTHETIC-DEMO", name, "RUN-" + name, "RELEASE-" + name,
            "c" * 64, requirement or self.requirement, NOW,
            expected_api_key_alias="demo-alias",
            diagnostic_predecessor_reservation_id=predecessor,
        )

    def _finish_403(self, admission):
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id, "search", "page-1", 0, NOW
        )
        self.assertTrue(attempt.allowed)
        self.ledger.record_response(
            attempt.attempt_id, 403,
            {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99",
             "X-RateLimit-Reset": str(RESET)},
            "b" * 64, result_count=0, observed_at_utc=NOW,
        )

    def _failed_diagnostic(self):
        self._finish_403(self._diagnostic("INITIAL"))
        diagnostic = self._diagnostic("DIAGNOSTIC")
        self._finish_403(diagnostic)
        return diagnostic.buckets[0].reservation_id

    def test_approved_correction_links_history_without_resetting_quota(self):
        predecessor = self._failed_diagnostic()
        history = self.ledger.rows("task_reservation")
        snapshots = self.ledger.rows("quota_window")
        successor = self._diagnostic("CORRECTION", predecessor)
        self.assertTrue(successor.admitted)
        after = self.ledger.rows("task_reservation")
        self.assertEqual(after[:-1], history)
        self.assertEqual(after[-1]["predecessor_event_id"], history[-1]["reservation_event_id"])
        self.assertEqual(self.ledger.rows("quota_window"), snapshots)
        self.assertEqual(len(self.ledger.rows("request_usage")), 4)
        self._finish_403(successor)
        extra = self.ledger.record_request_attempt(
            successor.buckets[0].reservation_id, "search", "page-1", 1, NOW
        )
        self.assertFalse(extra.allowed)
        with self.assertRaisesRegex(LedgerError, "PREDECESSOR_MISMATCH"):
            self._diagnostic("REPLAY", predecessor)
        self.assertFalse(self._diagnostic("NO-GRANT").admitted)

    def test_correction_requires_existing_completed_diagnostic(self):
        with self.assertRaisesRegex(LedgerError, "REQUIRES_EXISTING_DIAGNOSTIC"):
            self._diagnostic("UNVERIFIED", "missing")
        self._finish_403(self._diagnostic("INITIAL"))
        pending = self._diagnostic("PENDING")
        predecessor = pending.buckets[0].reservation_id
        with self.assertRaisesRegex(LedgerError, "REQUIRES_COMPLETED_RESPONSE"):
            self._diagnostic("UNFINISHED", predecessor)
        attempt = self.ledger.record_request_attempt(
            predecessor, "search", "page-1", 0, NOW
        )
        self.ledger.record_transport_failure(attempt.attempt_id, NOW)
        with self.assertRaisesRegex(LedgerError, "REQUIRES_COMPLETED_RESPONSE"):
            self._diagnostic("NO-HTTP-RESULT", predecessor)

    def test_explicit_query_correction_after_200_preserves_unknown_quota(self):
        self._finish_403(self._diagnostic("INITIAL"))
        diagnostic = self._diagnostic("EMPTY-QUERY")
        predecessor = diagnostic.buckets[0].reservation_id
        attempt = self.ledger.record_request_attempt(
            predecessor, "search", "page-1", 0, NOW
        )
        self.ledger.record_response(
            attempt.attempt_id, 200, {}, "b" * 64,
            result_count=0, observed_at_utc=NOW,
        )
        before = self.ledger.rows("quota_window")
        self.assertFalse(self._diagnostic("NO-EXPLICIT-GRANT").admitted)
        successor = self._diagnostic("REAL-QUERY", predecessor)
        self.assertTrue(successor.admitted)
        self.assertEqual(self.ledger.rows("quota_window"), before)
        self.assertEqual(
            self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW).state,
            QuotaState.QUOTA_TELEMETRY_UNKNOWN,
        )
        with self.assertRaisesRegex(LedgerError, "PREDECESSOR_MISMATCH"):
            self._diagnostic("REPLAY", predecessor)

    def test_failed_401_does_not_authorize_a_successor(self):
        self._finish_403(self._diagnostic("INITIAL"))
        diagnostic = self._diagnostic("FAILED-AUTH")
        predecessor = diagnostic.buckets[0].reservation_id
        attempt = self.ledger.record_request_attempt(
            predecessor, "search", "page-1", 0, NOW
        )
        self.ledger.record_response(
            attempt.attempt_id, 401, {}, "b" * 64,
            result_count=0, observed_at_utc=NOW,
        )
        with self.assertRaisesRegex(LedgerError, "REQUIRES_COMPLETED_RESPONSE"):
            self._diagnostic("WRONG-SUCCESSOR", predecessor)

    def _changed_window_response(self, admission, status=200, remaining=98):
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id, "search", "page-1", 0, NOW
        )
        self.assertTrue(attempt.allowed)
        return self.ledger.record_response(
            attempt.attempt_id, status,
            {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": str(remaining),
             "X-RateLimit-Reset": str(RESET + 3600)},
            "b" * 64, result_count=1, observed_at_utc=NOW,
        )

    def test_first_successful_diagnostic_establishes_real_window_after_403(self):
        self._finish_403(self._diagnostic("INITIAL"))
        diagnostic = self._diagnostic("FIRST-SUCCESS")
        before_rows = self.ledger.rows("quota_window")
        result = self._changed_window_response(diagnostic)
        after = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW)
        self.assertEqual(result.quota_state, QuotaState.NORMAL)
        self.assertEqual(result.header_reason_code, "RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC")
        self.assertNotEqual(after.window_id, before_rows[-1]["window_id"])
        # Charging and response reconciliation append; prior history survives.
        self.assertEqual(self.ledger.rows("quota_window")[:len(before_rows)], before_rows)
        self.assertEqual(after.server_remaining, 98)
        self.assertEqual(after.reset_at_utc, "2030-01-02T01:00:00Z")
        self.assertEqual(self.ledger.rows("request_usage")[-1]["rate_limit_remaining"], 98)

    def test_failed_or_contradictory_diagnostic_never_establishes_new_window(self):
        self._finish_403(self._diagnostic("INITIAL"))
        failed = self._diagnostic("STILL-403")
        old_window = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW).window_id
        result = self._changed_window_response(failed, status=403)
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        successor = self._diagnostic("INVALID-HEADERS", failed.buckets[0].reservation_id)
        result = self._changed_window_response(successor, remaining=101)
        self.assertEqual(result.header_reason_code, "RATE_LIMIT_HEADERS_CONTRADICTORY")
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        self.assertEqual(self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW).window_id, old_window)

    def test_prior_successful_window_remains_strict_after_later_403(self):
        self.establish_window(100, 99, RESET, NOW)
        admission = self.ledger._admit_task(
            "SYNTHETIC-DEMO", "SURVEY", "RUN-SURVEY", "RELEASE-SURVEY", "c" * 64,
            [self.requirement], NOW, expected_api_key_alias="demo-alias",
        )
        self._finish_403(admission)
        diagnostic = self._diagnostic("LATER-DIAGNOSTIC")
        result = self._changed_window_response(diagnostic)
        self.assertEqual(result.header_reason_code, "RATE_LIMIT_WINDOW_CHANGED_EARLY")
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)

    def test_correction_rejects_wrong_predecessor_and_larger_request(self):
        predecessor = self._failed_diagnostic()
        with self.assertRaisesRegex(LedgerError, "PREDECESSOR_MISMATCH"):
            self._diagnostic("WRONG", "another-reservation")
        larger = ReservationRequest(SCOPUS_SEARCH, "STANDARD", 2, 1, 0, 0, 0)
        with self.assertRaisesRegex(LedgerError, "PREDECESSOR_MISMATCH"):
            self._diagnostic("LARGER", predecessor, larger)

    def test_concurrent_correction_grants_for_one_predecessor_admit_once(self):
        predecessor = self._failed_diagnostic()

        def admit(index):
            try:
                return self._diagnostic("CONCURRENT-%d" % index, predecessor).admitted
            except LedgerError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(admit, range(2))), 1)
        self.assertEqual(len(self.ledger.rows("request_usage")), 4)

    def establish_window(
        self,
        limit: int,
        remaining: int,
        reset: int,
        observed_at_utc: str,
    ):
        self.flow_index += 1
        flow = "WINDOW-%d" % self.flow_index
        admission = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "%s-PREFLIGHT" % flow,
            "%s-RUN" % flow,
            "%s-RELEASE" % flow,
            "c" * 64,
            self.requirement,
            observed_at_utc,
            expected_api_key_alias="demo-alias",
        )
        self.assertTrue(admission.admitted)
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id,
            "search",
            "%s-PAGE" % flow,
            0,
            observed_at_utc,
        )
        self.assertTrue(attempt.allowed)
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset),
            },
            "c" * 64,
            result_count=0,
            observed_at_utc=observed_at_utc,
        )
        status = self.ledger.quota_status(
            "demo-alias", SCOPUS_SEARCH, observed_at_utc
        )
        self.assertEqual(result.quota_state, status.state)
        return status

    def test_minimal_preflight_attempt_establishes_first_window(self):
        admission = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "PREFLIGHT-1",
            "RUN-1",
            "RELEASE-1",
            "a" * 64,
            self.requirement,
            NOW,
            expected_api_key_alias="demo-alias",
        )
        self.assertTrue(admission.admitted)
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)
        reservation_id = admission.buckets[0].reservation_id
        attempt = self.ledger.record_request_attempt(
            reservation_id, "search", "page-1", 0, NOW
        )
        self.assertTrue(attempt.allowed)
        self.assertEqual(attempt.state, QuotaState.UNVERIFIED)
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)

        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            {
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "99",
                "X-RateLimit-Reset": str(RESET),
            },
            "b" * 64,
            result_count=0,
            observed_at_utc=NOW,
        )
        self.assertEqual(result.quota_state, QuotaState.NORMAL)
        status = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW)
        self.assertIsNotNone(status)
        self.assertEqual(status.server_remaining, 99)

    def test_preflight_is_one_attempt_only_and_no_retry(self):
        admission = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "PREFLIGHT-2",
            "RUN-2",
            "RELEASE-2",
            "c" * 64,
            self.requirement,
            NOW,
            expected_api_key_alias="demo-alias",
        )
        reservation_id = admission.buckets[0].reservation_id
        first = self.ledger.record_request_attempt(
            reservation_id, "search", "page-1", 0, NOW
        )
        self.assertTrue(first.allowed)
        second = self.ledger.record_request_attempt(
            reservation_id, "search", "page-1", 1, NOW
        )
        self.assertFalse(second.allowed)
        self.assertEqual(self.ledger.ledger_count("request_usage"), 1)

    def test_normal_task_remains_blocked_when_unverified(self):
        result = self.ledger._admit_task(
            "SYNTHETIC-DEMO",
            "SURVEY-1",
            "RUN-3",
            "RELEASE-3",
            "d" * 64,
            [self.requirement],
            NOW,
            expected_api_key_alias="demo-alias",
        )
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason_code, "UNVERIFIED")
        self.assertEqual(self.ledger.ledger_count("quota_window"), 0)

    def test_transport_failure_records_no_fake_http_status_and_freezes(self):
        admission = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "PREFLIGHT-4",
            "RUN-4",
            "RELEASE-4",
            "e" * 64,
            self.requirement,
            NOW,
            expected_api_key_alias="demo-alias",
        )
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id, "search", "page-1", 0, NOW
        )
        result = self.ledger.record_transport_failure(attempt.attempt_id, NOW)
        self.assertEqual(result.quota_state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        outcomes = [
            row
            for row in self.ledger.rows("request_usage")
            if row["record_kind"] == "OUTCOME"
        ]
        self.assertEqual(len(outcomes), 1)
        self.assertIsNone(outcomes[0]["http_status"])
        self.assertEqual(outcomes[0]["outcome"], "TRANSPORT_ERROR")
        status = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW)
        self.assertEqual(status.state, QuotaState.QUOTA_TELEMETRY_UNKNOWN)
        events = self.ledger.rows("quota_event")
        self.assertEqual(events[-1]["notification_evidence"], "LOCAL_RECORD_ONLY")
        self.assertIsNone(events[-1]["src_notified_at_utc"])
        self.assertIsNone(events[-1]["pi_notified_at_utc"])

    def test_completion_releases_only_unused_reservation_append_only(self):
        self.establish_window(100, 90, RESET, NOW)
        requirement = ReservationRequest(
            SCOPUS_SEARCH, "STANDARD", 10, 2, 0, 1, 0
        )
        admission = self.ledger._admit_task(
            "SYNTHETIC-DEMO",
            "SURVEY-COMPLETE",
            "RUN-COMPLETE",
            "RELEASE-COMPLETE",
            "f" * 64,
            [requirement],
            NOW,
            expected_api_key_alias="demo-alias",
        )
        self.assertTrue(admission.admitted)
        reservation_id = admission.buckets[0].reservation_id
        attempt = self.ledger.record_request_attempt(
            reservation_id, "search", "page-1", 0, NOW
        )
        self.ledger.record_response(
            attempt.attempt_id,
            200,
            {
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "89",
                "X-RateLimit-Reset": str(RESET),
            },
            "1" * 64,
            result_count=1,
            observed_at_utc=NOW,
        )
        before = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW)
        self.assertEqual(before.committed_in_progress, 2)
        row_count = self.ledger.ledger_count("task_reservation")

        self.ledger.complete_reservation(reservation_id, NOW)

        after = self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, NOW)
        self.assertEqual(after.committed_in_progress, 0)
        latest = [
            row
            for row in self.ledger.rows("task_reservation")
            if row["reservation_id"] == reservation_id
        ][-1]
        self.assertEqual(latest["reserved_remaining"], 0)
        self.assertEqual(latest["actual_requests"], 1)
        self.assertEqual(latest["admission_decision"], "COMPLETED")
        self.assertEqual(latest["completed_or_released_at_utc"], NOW)
        self.assertEqual(self.ledger.ledger_count("task_reservation"), row_count + 1)

    def test_reset_verify_allows_one_released_bounded_diagnostic(self):
        old_reset = 1893456000  # 2030-01-01T00:00:00Z
        after_reset = "2030-01-01T00:00:01Z"
        self.establish_window(
            100, 80, old_reset, "2029-12-31T23:59:00Z"
        )
        self.assertEqual(
            self.ledger.quota_status("demo-alias", SCOPUS_SEARCH, after_reset).state,
            QuotaState.RESET_VERIFY,
        )
        admission = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "RESET-DIAGNOSTIC",
            "RUN-RESET-DIAGNOSTIC",
            "RELEASE-RESET-DIAGNOSTIC",
            "2" * 64,
            self.requirement,
            after_reset,
            expected_api_key_alias="demo-alias",
        )
        self.assertTrue(admission.admitted)
        self.assertEqual(admission.reason_code, "AUTHORIZED_BOUNDED_DIAGNOSTIC")
        attempt = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id,
            "search",
            "page-1",
            0,
            after_reset,
        )
        self.assertTrue(attempt.allowed)
        self.assertEqual(attempt.state, QuotaState.RESET_VERIFY)
        duplicate = self.ledger._admit_preflight(
            "SYNTHETIC-DEMO",
            "RESET-DIAGNOSTIC-2",
            "RUN-RESET-DIAGNOSTIC-2",
            "RELEASE-RESET-DIAGNOSTIC-2",
            "3" * 64,
            self.requirement,
            after_reset,
            expected_api_key_alias="demo-alias",
        )
        # A new release does not bypass the per-window diagnostic ceiling.
        # The first result must resolve telemetry or coordination must escalate.
        self.assertFalse(duplicate.admitted)
        self.assertEqual(
            duplicate.reason_code, "DIAGNOSTIC_ALREADY_USED_FOR_WINDOW"
        )
        retry = self.ledger.record_request_attempt(
            admission.buckets[0].reservation_id,
            "search",
            "page-1",
            1,
            after_reset,
        )
        self.assertFalse(retry.allowed)
        result = self.ledger.record_response(
            attempt.attempt_id,
            200,
            {
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": "99",
                "X-RateLimit-Reset": str(RESET),
            },
            "4" * 64,
            result_count=0,
            observed_at_utc=after_reset,
        )
        self.assertEqual(result.quota_state, QuotaState.NORMAL)


if __name__ == "__main__":
    unittest.main()
