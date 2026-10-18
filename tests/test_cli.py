import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from scopus_access import cli
from scopus_access.ledger import Ledger


REPOSITORY = Path(__file__).resolve().parent.parent
POLICY = REPOSITORY / "examples" / "offline-policy.json"
MANIFEST = REPOSITORY / "examples" / "synthetic-preflight-task.json"
SYNTHETIC_QUERY = "SYNTHETIC_PLACEHOLDER_DO_NOT_EXECUTE"


class CliOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "control.sqlite"

    def invoke(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(list(arguments))
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertNotIn(SYNTHETIC_QUERY, output.getvalue())
        return code, lines, output.getvalue()

    def test_doctor_is_local_only_and_does_not_read_keychain(self):
        with mock.patch(
            "scopus_access.secrets.MacOSKeychainSecretProvider.get_api_key",
            side_effect=AssertionError("credential read is forbidden"),
        ) as secret_read:
            code, records, _ = self.invoke(
                "doctor",
                "--policy",
                str(POLICY),
                "--db",
                str(self.database),
            )
        self.assertEqual(code, 0)
        self.assertEqual(records[0]["status"], "ok")
        self.assertFalse(records[0]["network_probe"])
        self.assertFalse(records[0]["secret_read"])
        secret_read.assert_not_called()

    def test_doctor_only_provisions_the_policy_bound_live_database(self):
        trusted_database = Path(self.temporary.name) / "trusted.sqlite"
        wrong_database = Path(self.temporary.name) / "wrong.sqlite"
        policy_path = Path(self.temporary.name) / "live-policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "project_output_roots": {
                        "SYNTHETIC-DEMO": [str(Path(self.temporary.name))]
                    },
                    "project_api_key_aliases": {
                        "SYNTHETIC-DEMO": {
                            "scopus_search": "synthetic-demo-alias"
                        }
                    },
                    "live_capability_enabled": True,
                    "control_database_path": str(trusted_database),
                    "ai_session_grants": {},
                    "max_preflight_requests": 1,
                }
            ),
            encoding="utf-8",
        )
        code, records, _ = self.invoke(
            "doctor",
            "--policy",
            str(policy_path),
            "--db",
            str(wrong_database),
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertEqual(records[0]["code"], "CONTROL_DATABASE_MISMATCH")
        self.assertFalse(wrong_database.exists())

        code, records, _ = self.invoke(
            "doctor",
            "--policy",
            str(policy_path),
            "--db",
            str(trusted_database),
        )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(records[0]["database"], "ready")
        self.assertTrue(trusted_database.is_file())

    def test_validate_plan_quota_and_dry_run_emit_control_only_jsonl(self):
        code, validation, _ = self.invoke(
            "validate-manifest", str(MANIFEST), "--policy", str(POLICY)
        )
        self.assertEqual(code, 0)
        self.assertEqual(validation[0]["status"], "valid")

        code, plan, _ = self.invoke(
            "plan",
            str(MANIFEST),
            "--policy",
            str(POLICY),
            "--db",
            str(self.database),
        )
        self.assertEqual(code, 0)
        self.assertEqual(plan[0]["status"], "not_admitted")
        self.assertEqual(plan[0]["buckets"][0]["state"], "UNVERIFIED")

        code, quota, _ = self.invoke(
            "quota-status",
            "--policy",
            str(POLICY),
            "--db",
            str(self.database),
        )
        self.assertEqual(code, 0)
        self.assertEqual(quota[0]["buckets"][0]["state"], "UNVERIFIED")

        with mock.patch(
            "scopus_access.secrets.MacOSKeychainSecretProvider.get_api_key",
            side_effect=AssertionError("credential read is forbidden"),
        ) as secret_read, mock.patch(
            "scopus_access.client.UrllibTransport.send",
            side_effect=AssertionError("transport is forbidden"),
        ) as transport:
            code, dry, _ = self.invoke(
                "run-dry",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--db",
                str(self.database),
            )
        self.assertEqual(code, 0)
        self.assertEqual(dry[-1]["status"], "completed")
        self.assertFalse(dry[-1]["executed"])
        secret_read.assert_not_called()
        transport.assert_not_called()

        ledger = Ledger(self.database)
        self.assertEqual(ledger.ledger_count("quota_window"), 0)
        self.assertEqual(ledger.ledger_count("task_reservation"), 0)
        self.assertEqual(ledger.ledger_count("request_usage"), 0)
        self.assertEqual(ledger.ledger_count("quota_event"), 0)

    def test_preflight_is_hard_locked_before_secret_or_transport(self):
        with mock.patch(
            "scopus_access.secrets.MacOSKeychainSecretProvider.get_api_key",
            side_effect=AssertionError("credential read is forbidden"),
        ) as secret_read, mock.patch(
            "scopus_access.client.UrllibTransport.send",
            side_effect=AssertionError("transport is forbidden"),
        ) as transport:
            code, records, _ = self.invoke(
                "preflight",
                str(MANIFEST),
                "--policy",
                str(POLICY),
                "--db",
                str(self.database),
            )
        self.assertEqual(code, cli.EXIT_LIVE_LOCKED)
        self.assertEqual(records[0]["code"], "LIVE_CAPABILITY_LOCKED")
        self.assertEqual(records[0]["status"], "locked")
        secret_read.assert_not_called()
        transport.assert_not_called()

    def test_argument_errors_never_echo_untrusted_values(self):
        sentinel = "SUPER_SECRET_SENTINEL_QUERY_TEXT"
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = cli.main(
                [
                    "doctor",
                    "--policy",
                    str(POLICY),
                    "--api-key",
                    sentinel,
                ]
            )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertNotIn(sentinel, output.getvalue())
        self.assertNotIn(sentinel, errors.getvalue())
        record = json.loads(output.getvalue())
        self.assertEqual(record["code"], "INVALID_ARGUMENTS")

    def test_help_is_human_diagnostic_on_stderr_not_control_stdout(self):
        for arguments in (("--help",), ("plan", "--help")):
            with self.subTest(arguments=arguments):
                output = io.StringIO()
                errors = io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    with self.assertRaises(SystemExit) as raised:
                        cli.main(list(arguments))
                self.assertEqual(raised.exception.code, 0)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("usage:", errors.getvalue())

    def test_preflight_cannot_select_an_arbitrary_event_log(self):
        target = Path(self.temporary.name) / "custom-events.txt"
        code, records, output = self.invoke(
            "preflight",
            str(MANIFEST),
            "--policy",
            str(POLICY),
            "--db",
            str(self.database),
            "--event-log",
            str(target),
        )
        self.assertEqual(code, cli.EXIT_VALIDATION)
        self.assertEqual(records[0]["code"], "INVALID_ARGUMENTS")
        self.assertNotIn(str(target), output)
        self.assertFalse(target.exists())

    def test_event_log_accepts_only_derived_per_api_namespaces(self):
        valid = (
            Path(self.temporary.name).resolve()
            / "events"
            / ("exec_" + "a" * 32 + "_scopus_search.jsonl")
        )
        with cli._open_secure_append(valid) as stream:
            stream.write("{}\n")
        self.assertEqual(valid.read_text(encoding="utf-8"), "{}\n")

        invalid = (
            Path(self.temporary.name).resolve()
            / "events"
            / ("run_" + "b" * 32 + ".jsonl")
        )
        with self.assertRaisesRegex(cli.ValidationError, "derived runtime JSONL path"):
            cli._open_secure_append(invalid)
        self.assertFalse(invalid.exists())


if __name__ == "__main__":
    unittest.main()
