"""CLI routing checks use synthetic summaries, never credentials or sockets."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from scopus_access import cli


class ZoteroCliTests(unittest.TestCase):
    def invoke(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = cli.main(arguments)
        self.assertNotIn("SYNTHETIC_PRIVATE_TITLE", output.getvalue() + errors.getvalue())
        self.assertNotIn("SYNTHETIC_FAKE_KEY", output.getvalue() + errors.getvalue())
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_help_and_invalid_arguments_never_construct_a_remote_client(self):
        from scopus_access import zotero
        with mock.patch.object(zotero, "push", side_effect=AssertionError("unexpected write")):
            for arguments in (["zotero", "push", "--plan", "SYNTHETIC_PRIVATE_TITLE"],
                              ["zotero", "configure", "--api-key", "SYNTHETIC_FAKE_KEY"]):
                code, rows = self.invoke(arguments)
                self.assertEqual(code, 2)
                self.assertEqual(rows[0]["code"], "INVALID_ARGUMENTS")

    def test_push_without_consent_never_reaches_remote_service(self):
        from scopus_access import zotero, zotero_local
        with mock.patch.object(zotero_local.Context, "from_project"), \
                mock.patch.object(zotero, "push", side_effect=AssertionError("unexpected write")):
            code, rows = self.invoke(["zotero", "push", "--plan", "synthetic-plan", "--max-items", "1"])
        self.assertEqual(code, 3)
        self.assertEqual(rows[0]["network_calls"], 0)

    def test_local_prepare_and_dataset_dispatch_only_local_functions(self):
        from scopus_access import zotero, zotero_local
        with mock.patch.object(zotero_local.Context, "from_project"), \
                mock.patch.object(zotero, "plan", side_effect=AssertionError("unexpected network")), \
                mock.patch.object(zotero, "push", side_effect=AssertionError("unexpected write")), \
                mock.patch.object(zotero_local, "prepare", return_value={"network_calls": 0, "records": 2}) as prepare, \
                mock.patch.object(zotero_local, "create_dataset", return_value={"network_calls": 0, "records": 3}) as dataset:
            code, rows = self.invoke(["zotero", "prepare", "--dataset", "frozen", "--selection", "subset"])
            self.assertEqual((code, rows[0]["network_calls"]), (0, 0))
            self.assertEqual(prepare.call_args.kwargs, {"selection": "subset"})
            code, rows = self.invoke(["dataset", "create", "--source", "saved"])
            self.assertEqual((code, rows[0]["records"]), (0, 3))
            dataset.assert_called_once()

    def test_remote_dispatch_outputs_only_service_control_summary(self):
        from scopus_access import zotero, zotero_local
        with mock.patch.object(zotero_local.Context, "from_project"), \
                mock.patch.object(zotero, "check", return_value={"write_test_performed": False}) as check, \
                mock.patch.object(zotero, "plan", return_value={"creates": 2, "holds": 1}) as plan, \
                mock.patch.object(zotero, "push", return_value={"status": "completed_with_failures", "failed": 1}) as push:
            code, rows = self.invoke(["zotero", "check"])
            self.assertEqual((code, rows[0]["write_test_performed"]), (0, False))
            check.assert_called_once()
            code, rows = self.invoke(["zotero", "plan", "--prepared", "frozen"])
            self.assertEqual((code, rows[0]["creates"]), (0, 2))
            plan.assert_called_once()
            code, rows = self.invoke(["zotero", "push", "--plan", "frozen", "--max-items", "4", "--execute-live"])
            self.assertEqual((code, rows[0]["status"]), (6, "completed_with_failures"))
            self.assertEqual(push.call_args.kwargs, {"execute_live": True})

    def test_transport_exception_details_are_not_emitted(self):
        from scopus_access import zotero, zotero_local
        with mock.patch.object(zotero_local.Context, "from_project"), \
                mock.patch.object(zotero, "check", side_effect=OSError("SYNTHETIC_FAKE_KEY SYNTHETIC_PRIVATE_TITLE")):
            code, rows = self.invoke(["zotero", "check"])
        self.assertEqual(code, 1)
        self.assertIsNone(rows[0]["network_calls"])
