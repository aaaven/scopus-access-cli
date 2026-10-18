"""Synthetic real-runner regressions for failures after execution begins."""

import dataclasses
import io
import json
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest import mock

import test_integration as fixtures
from scopus_access import cli
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.events import ControlEventWriter
from scopus_access.integration import IntegrationError, LedgerExecutionAdapter
from scopus_access.runner import GovernedRunner


TITLE_SENTINEL = "SYNTHETIC_FAILURE_RECORD_TITLE"
ABSTRACT_SENTINEL = "SYNTHETIC_FAILURE_RECORD_ABSTRACT"
ERROR_SENTINEL = "UNSAFE_EXCEPTION_DETAIL_NOT_FOR_CONTROL"


class _SyntheticWire(fixtures._MockWireTransport):
    def send(self, request, *, wire_capability=None):
        response = super().send(request, wire_capability=wire_capability)
        value = json.loads(response.body)
        value["search-results"]["entry"][0].update(
            {"dc:title": TITLE_SENTINEL, "dc:description": ABSTRACT_SENTINEL}
        )
        return dataclasses.replace(response, body=json.dumps(value).encode("utf-8"))


class FailureAccountingTests(unittest.TestCase):
    def setUp(self):
        # Reuse fixture builders, without inheriting their test methods.
        self.fixture = fixtures.IntegrationTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _invoke_failure(self, operation, *, deny_before_send=False):
        manifest, _ = self.fixture._manifest("preflight", "-disk-failure")
        # CLI itself registers the policy-pinned alias/topology.  The lower
        # level fixture helper deliberately uses a different synthetic pin.
        ledger = fixtures.Ledger(self.fixture.root / "control.sqlite")
        secret = fixtures._TrackingSecretProvider()
        wire = _SyntheticWire(ledger)
        output, errors = io.StringIO(), io.StringIO()
        captured = []

        class CapturingRunner(GovernedRunner):
            def run(self, authorization):
                captured.append((authorization, self))
                return super().run(authorization)

        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(output))
            stack.enter_context(redirect_stderr(errors))
            stack.enter_context(mock.patch.object(
                cli, "_load_inputs", return_value=(self.fixture.policy, manifest)
            ))
            stack.enter_context(mock.patch.object(
                cli, "MacOSKeychainSecretProvider", return_value=secret
            ))
            stack.enter_context(mock.patch.object(cli, "UrllibTransport", return_value=wire))
            stack.enter_context(mock.patch.object(cli, "GovernedRunner", CapturingRunner))
            stack.enter_context(mock.patch.object(
                RestrictedArtifactStore, operation,
                side_effect=OSError(ERROR_SENTINEL),
            ))
            if deny_before_send:
                stack.enter_context(mock.patch.object(
                    LedgerExecutionAdapter, "record_attempt_started",
                    side_effect=RuntimeError(ERROR_SENTINEL),
                ))
            code = cli.main([
                "preflight", "unused-fixture-path", "--policy", "unused-fixture-policy",
                "--db", str(self.fixture.root / "control.sqlite"), "--execute-live",
            ])

        self.assertEqual(code, cli.EXIT_ERROR)
        control = [json.loads(line) for line in output.getvalue().splitlines()]
        fallback = control[-1]
        self.assertEqual(fallback["code"], "LOCAL_CONTROL_ERROR")
        self.assertIsNone(fallback["network_calls"])
        self.assertIsNone(fallback["secret_reads"])
        self.assertEqual(fallback["execution_counts_status"], "unknown")
        self.assertEqual(len(secret.aliases), 1)
        self.assertEqual(wire.calls, 0 if deny_before_send else 1)
        failure = [row for row in control if row.get("event") == "local_control_failed"]
        self.assertEqual(len(failure), 1)
        self.assertEqual(failure[0]["status"], "failed")
        self.assertNotIn("checkpoint_ref", failure[0])
        authorization, first_runner = captured[0]
        event_text = (self.fixture.root / "events" / (
            authorization.run_id + ".jsonl"
        )).read_text(encoding="utf-8")
        self.assertIn('"event":"local_control_failed"', event_text)
        ledger_text = json.dumps(ledger.rows("request_usage"))
        for forbidden in (
            TITLE_SENTINEL, ABSTRACT_SENTINEL, ERROR_SENTINEL,
            "offline-mock-credential", "SYNTHETIC-OFFLINE-QUERY",
        ):
            for text in (output.getvalue(), errors.getvalue(), event_text, ledger_text):
                self.assertNotIn(forbidden, text)
        return ledger, wire, secret, authorization, first_runner

    def _assert_storage_failure_has_no_resend(self, operation):
        ledger, wire, secret, authorization, first_runner = self._invoke_failure(operation)
        attempts = [row for row in ledger.rows("request_usage")
                    if row["record_kind"] == "ATTEMPT"]
        self.assertEqual(len(attempts), 1)
        outcomes = [row for row in ledger.rows("request_usage")
                    if row["record_kind"] == "OUTCOME"]
        self.assertEqual(len(outcomes), 0 if operation in {
            "write_response", "export_records"
        } else 1)

        # Receipt writing follows completion of the request reservation.  A
        # fresh execution adapter must reject that completed reservation,
        # even if receipt persistence then failed.
        if operation == "write_receipt":
            with self.assertRaisesRegex(
                IntegrationError, "RUN_CAPABILITY_RESERVATION_NOT_ACTIVE"
            ):
                LedgerExecutionAdapter(ledger, authorization)
            self.assertTrue(first_runner._artifacts.load_checkpoint(
                authorization.run_id
            ).complete)
            self.assertEqual(wire.calls, 1)
            self.assertEqual(len(secret.aliases), 1)
            return

        # A new process-equivalent adapter with the same sealed run still
        # cannot spend the already-sent attempt after disk recovery.
        resumed = GovernedRunner(
            transport=first_runner._transport,
            secret_provider=secret,
            ledger=LedgerExecutionAdapter(ledger, authorization),
            artifacts=first_runner._artifacts,
            events=ControlEventWriter(io.StringIO()),
        ).run(authorization)
        self.assertEqual(wire.calls, 1)
        self.assertEqual(len([row for row in ledger.rows("request_usage")
                              if row["record_kind"] == "ATTEMPT"]), 1)
        self.assertEqual(resumed.status, "failed")
        self.assertEqual(resumed.stop_reason, "attempt_record_failed")

    def test_raw_write_failure_reports_unknown_and_does_not_resend(self):
        self._assert_storage_failure_has_no_resend("write_response")

    def test_record_export_failure_reports_unknown_and_does_not_resend(self):
        self._assert_storage_failure_has_no_resend("export_records")

    def test_checkpoint_write_failure_reports_unknown_and_does_not_resend(self):
        self._assert_storage_failure_has_no_resend("write_checkpoint")

    def test_receipt_write_failure_reports_unknown_and_does_not_resend(self):
        self._assert_storage_failure_has_no_resend("write_receipt")

    def test_before_send_denial_after_secret_lookup_does_not_claim_zero(self):
        ledger, _, _, _, _ = self._invoke_failure(
            "write_checkpoint", deny_before_send=True
        )
        self.assertFalse(ledger.rows("request_usage"))

    def test_before_execution_gate_denial_can_assert_zero(self):
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        output = io.StringIO()
        with redirect_stdout(output), mock.patch.object(
            cli, "MacOSKeychainSecretProvider",
            side_effect=AssertionError("real provider forbidden"),
        ), mock.patch.object(
            cli, "UrllibTransport", side_effect=AssertionError("real transport forbidden")
        ):
            code = cli.main([
                "preflight", str(root / "examples" / "synthetic-preflight-task.json"),
                "--policy", str(root / "examples" / "offline-policy.json"),
                "--db", str(self.fixture.root / "control.sqlite"), "--execute-live",
            ])
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        record = json.loads(output.getvalue())
        self.assertEqual(record["network_calls"], 0)
        self.assertEqual(record["secret_reads"], 0)
        self.assertEqual(record["execution_counts_status"], "not_started")


if __name__ == "__main__":
    unittest.main()
