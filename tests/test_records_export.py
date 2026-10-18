"""Synthetic whole-runner regressions; licensed content stays in temporary data plane."""

import hashlib
import io
import json
import unittest
from unittest import mock

import test_integration as fixtures
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.client import TransportResponse
from scopus_access.events import ControlEventWriter
from scopus_access.integration import (
    ElsevierRunnerTransport, LedgerExecutionAdapter, admit_authorized_manifest,
    build_resume_authorization, build_run_authorization,
)
from scopus_access.runner import GovernedRunner, RunnerError


TITLE = "SYNTHETIC-RECORD-TITLE-DO-NOT-EMIT"
ABSTRACT = "SYNTHETIC-RECORD-ABSTRACT-DO-NOT-EMIT"


class _Wire:
    def __init__(self, bodies, *, remaining=98):
        self.bodies = list(bodies)
        self.calls = 0
        self.remaining = remaining

    def send(self, request, *, wire_capability=None):
        body = self.bodies[self.calls]
        self.calls += 1
        return TransportResponse(
            status=200,
            headers={
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": str(self.remaining - self.calls + 1),
                "X-RateLimit-Reset": str(fixtures.RESET_EPOCH),
            },
            body=json.dumps(body).encode("utf-8"),
        )


def _search(entries, next_cursor=None):
    return {"search-results": {
        "entry": entries,
        "opensearch:totalResults": str(len(entries)),
        "cursor": {"@next": next_cursor},
    }}


class RecordsExportIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.IntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.ledger = self.fixture._ledger()
        self.store = RestrictedArtifactStore(
            self.fixture.output, allowed_roots=[self.fixture.project_root]
        )
        self.events = io.StringIO()
        self.secrets = fixtures._TrackingSecretProvider()

    def _admit(self, manifest, permit, parent, api):
        admission = admit_authorized_manifest(
            ledger=self.ledger, manifest=manifest, authorization=permit,
            run_id=parent, now_utc=fixtures.NOW,
        )
        self.assertTrue(admission.admitted)
        return build_run_authorization(
            ledger=self.ledger, manifest=manifest, authorization=permit,
            admission=admission, run_id=parent, api_name=api,
        ), admission

    def _runner(self, manifest, permit, capability, wire):
        adapter = LedgerExecutionAdapter(self.ledger, capability)
        runner = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest, authorization=permit, transport=wire
            ),
            secret_provider=self.secrets, ledger=adapter, artifacts=self.store,
            events=ControlEventWriter(self.events, clock=lambda: fixtures.NOW),
            clock=lambda: fixtures.NOW, epoch_clock=lambda: 1_893_456_000,
        )
        return runner, adapter

    def _read(self, receipt):
        encoded = (self.fixture.output / receipt.records_ref).read_bytes()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), receipt.records_sha256)
        rows = [json.loads(line) for line in encoded.splitlines()]
        self.assertEqual(len(rows), receipt.records_count)
        stored = json.loads((self.fixture.output / receipt.receipt_ref).read_text())
        for name in ("records_ref", "records_sha256", "records_count", "records_pages"):
            self.assertEqual(stored[name], getattr(receipt, name))
        control = self.events.getvalue() + json.dumps(stored)
        control += json.dumps(self.ledger.rows("request_usage"))
        control += (self.fixture.output / receipt.artifact_manifest_ref).read_text()
        for sentinel in (TITLE, ABSTRACT, "offline-mock-credential"):
            self.assertNotIn(sentinel, control)
        return rows, encoded

    def test_real_runner_two_api_records_missing_fields_and_receipt_isolation(self):
        self.fixture._seed_quota(self.ledger, "scopus_search")
        self.fixture._seed_quota(self.ledger, "abstract_retrieval")
        manifest, permit = self.fixture._manifest("survey_run", "-records", include_abstract=True)
        search, admission = self._admit(manifest, permit, "records-parent", "scopus_search")
        abstract = build_run_authorization(
            ledger=self.ledger, manifest=manifest, authorization=permit,
            admission=admission, run_id="records-parent", api_name="abstract_retrieval",
        )
        search_wire = _Wire([_search([
            {"eid": "2-s2.0-SYNTHETIC", "dc:title": TITLE, "dc:description": ABSTRACT},
            {},
        ])])
        abstract_wire = _Wire([{"abstracts-retrieval-response": {
            "coredata": {"eid": "2-s2.0-SYNTHETIC", "dc:title": TITLE},
            "item": {"bibrecord": {"head": {"abstracts": {"abstract": ABSTRACT}}}},
        }}])
        receipts = []
        for capability, wire in ((search, search_wire), (abstract, abstract_wire)):
            runner, _ = self._runner(manifest, permit, capability, wire)
            receipts.append(runner.run(capability))
            self.assertEqual(wire.calls, 1)
            self.assertEqual(receipts[-1].status, "completed")
        search_rows, search_bytes = self._read(receipts[0])
        abstract_rows, _ = self._read(receipts[1])
        self.assertEqual(len(search_rows), 2)
        self.assertEqual(search_rows[0]["title"], TITLE)
        self.assertEqual(search_rows[0]["abstract"], ABSTRACT)
        self.assertIsNone(search_rows[1]["abstract"])
        self.assertIsNone(search_rows[1]["title"])
        self.assertIn("abstract", search_rows[1]["missing_fields"])
        self.assertEqual(search_rows[1]["stable_id_source"], "occurrence")
        self.assertEqual(search_rows[1]["page_position"], 1)
        self.assertEqual(abstract_rows[0]["abstract"], {"abstract": ABSTRACT})
        self.assertEqual(abstract_rows[0]["abstract_source_path"], "item.bibrecord.head.abstracts")
        self.assertNotEqual(receipts[0].records_ref, receipts[1].records_ref)
        self.assertNotEqual(search_rows[0]["occurrence_id"], abstract_rows[0]["occurrence_id"])
        self.assertEqual(search_rows[0]["stable_id"], abstract_rows[0]["stable_id"])
        for capability, receipt in zip((search, abstract), receipts):
            rebuilt = self.store.export_records(capability.run_id, capability.api_name)
            self.assertEqual(rebuilt.sha256, receipt.records_sha256)
            for row in self._read(receipt)[0]:
                raw = (self.fixture.output / row["raw_page_ref"]).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), row["raw_page_sha256"])
        self.assertEqual((self.fixture.output / receipts[0].records_ref).read_bytes(), search_bytes)

    def test_real_runner_page_boundary_resume_rebuilds_without_duplicate_or_lost_page(self):
        self.fixture._seed_quota(self.ledger, "scopus_search")
        manifest, permit = self.fixture._manifest("survey_run", "-record-resume", request_updates={
            "forecast_pagination": 2, "estimated_requests_with_margin": 2, "request_limit": 2,
        })
        capability, _ = self._admit(manifest, permit, "record-resume-parent", "scopus_search")
        first_wire = _Wire([_search([{"eid": "SAME-SYNTHETIC-ID", "dc:title": TITLE}], "next-page")])
        runner, adapter = self._runner(manifest, permit, capability, first_wire)
        with mock.patch.object(adapter, "assess_running_forecast", return_value=False):
            first = runner.run(capability)
        self.assertEqual(first.status, "paused")
        original_rows, original = self._read(first)
        self.assertEqual(len(original_rows), 1)
        raw_before = {record.artifact_ref: self.store.read_response_record(record)
                      for record in self.store.load_response_records(capability.run_id)}
        # Mimic an interrupted/damaged derived export; rebuild from immutable pages.
        (self.fixture.output / first.records_ref).write_bytes(b"incomplete derived export")
        rebuilt = self.store.export_records(capability.run_id, capability.api_name)
        self.assertEqual((self.fixture.output / rebuilt.ref).read_bytes(), original)
        resumed = build_resume_authorization(
            ledger=self.ledger, manifest=manifest, authorization=permit, artifacts=self.store,
            run_id="record-resume-parent", api_name="scopus_search",
        )
        second_wire = _Wire([_search([{"eid": "SAME-SYNTHETIC-ID"}, {}])], remaining=97)
        runner, _ = self._runner(manifest, permit, resumed, second_wire)
        final = runner.run(resumed)
        self.assertEqual(final.status, "completed")
        rows, final_bytes = self._read(final)
        self.assertEqual(final.records_pages, 2)
        self.assertEqual(len(rows), 3)
        self.assertEqual([(row["page_number"], row["page_position"]) for row in rows], [(1, 0), (2, 0), (2, 1)])
        self.assertEqual(rows[0]["stable_id"], rows[1]["stable_id"])
        self.assertEqual(len({row["occurrence_id"] for row in rows}), 3)
        self.assertEqual(rows[0], original_rows[0])
        for ref, body in raw_before.items():
            self.assertEqual((self.fixture.output / ref).read_bytes(), body)
        self.assertEqual(first_wire.calls + second_wire.calls, 2)
        completed = runner.run(resumed)
        self.assertEqual(completed.stop_reason, "already_complete")
        self.assertEqual(second_wire.calls, 1)
        self.assertEqual((self.fixture.output / completed.records_ref).read_bytes(), final_bytes)

    def test_export_failure_recovers_raw_offline_without_resending_request(self):
        self.fixture._seed_quota(self.ledger, "scopus_search")
        manifest, permit = self.fixture._manifest("survey_run", "-record-error")
        capability, _ = self._admit(manifest, permit, "record-error-parent", "scopus_search")
        wire = _Wire([_search([{"dc:title": TITLE}])])
        runner, _ = self._runner(manifest, permit, capability, wire)
        with mock.patch.object(self.store, "export_records", side_effect=OSError(TITLE)):
            with self.assertRaises(RunnerError) as failure:
                runner.run(capability)
        self.assertNotIn(TITLE, str(failure.exception))
        self.assertNotIn(TITLE, self.events.getvalue())
        self.assertEqual(wire.calls, 1)
        first = self.store.export_records(capability.run_id, capability.api_name)
        second = self.store.export_records(capability.run_id, capability.api_name)
        self.assertEqual(first, second)
        self.assertEqual(second.record_count, 1)
        self.assertEqual(wire.calls, 1)
        with self.assertRaises(Exception):
            build_resume_authorization(
                ledger=self.ledger, manifest=manifest, authorization=permit, artifacts=self.store,
                run_id="record-error-parent", api_name="scopus_search",
            )
        self.assertEqual(wire.calls, 1)
