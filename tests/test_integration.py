import dataclasses
import hashlib
import io
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from unittest import mock

from scopus_access.artifacts import Checkpoint, RestrictedArtifactStore
from scopus_access.client import TransportResponse as ClientTransportResponse
from scopus_access.errors import LiveCapabilityLocked, UnsafeRequestError
from scopus_access.events import ControlEventWriter
from scopus_access.integration import (
    ElsevierRunnerTransport,
    IntegrationError,
    LedgerExecutionAdapter,
    admit_authorized_manifest,
    build_resume_authorization,
    build_run_authorization,
)
from scopus_access.ledger import Ledger, LedgerError
from scopus_access.manifest import execution_control_sha256, load_task_manifest
from scopus_access.policy import PolicyConfig, authorize_live_execution
from scopus_access.runner import (
    AttemptFinished,
    AttemptStarted,
    GovernedRunner,
    RunnerGateError,
    TransportRequest as RunnerTransportRequest,
)
from scopus_access.secrets import SecretProviderError, SecretValue


NOW = "2030-01-01T00:00:00Z"
RESET_EPOCH = 2_000_000_000
PROJECT_ID = "TEST-PROJECT"
API_ALIAS = "test-project-search"


def _write_json(path: Path, value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


class _TrackingSecretProvider:
    def __init__(self) -> None:
        self.aliases = []
        self.values = []

    def get_api_key(self, alias: str) -> SecretValue:
        self.aliases.append(alias)
        value = SecretValue(b"offline-mock-credential")
        self.values.append(value)
        return value


class _MockWireTransport:
    def __init__(
        self,
        ledger: Ledger,
        *,
        remaining: int = 98,
        next_cursor: Optional[str] = None,
    ) -> None:
        self.ledger = ledger
        self.remaining = remaining
        self.next_cursor = next_cursor
        self.calls = 0
        self.initial_attempts = len(
            [
                row
                for row in self.ledger.rows("request_usage")
                if row["record_kind"] == "ATTEMPT"
            ]
        )
        self.request = None
        self.saw_credential = False

    def send(
        self, request: Any, *, wire_capability: Any = None
    ) -> ClientTransportResponse:
        # A real ledger ATTEMPT row must be committed before this seam can run.
        attempts = [
            row
            for row in self.ledger.rows("request_usage")
            if row["record_kind"] == "ATTEMPT"
        ]
        if len(attempts) != self.initial_attempts + self.calls + 1:
            raise AssertionError("wire transport entered before durable attempt")
        self.calls += 1
        self.saw_credential = bool(request.headers.get("X-ELS-APIKey"))
        self.request = request
        search_results: Dict[str, Any] = {
            "entry": [{"dc:identifier": "SYNTHETIC-OFFLINE-RECORD"}],
            "opensearch:totalResults": "1",
            "opensearch:startIndex": "0",
        }
        if self.next_cursor is not None:
            search_results["cursor"] = {"@next": self.next_cursor}
        payload = (
            {
                "abstracts-retrieval-response": {
                    "coredata": {"dc:identifier": "SYNTHETIC-OFFLINE-RECORD"}
                }
            }
            if "/content/abstract/" in request.url
            else {"search-results": search_results}
        )
        body = json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")
        return ClientTransportResponse(
            status=200,
            headers={
                "X-RateLimit-Limit": "100",
                "X-RateLimit-Remaining": str(self.remaining),
                "X-RateLimit-Reset": str(RESET_EPOCH),
                "X-Ignored-Response-Header": "not-control-metadata",
            },
            body=body,
        )


class _SerializedWireTransport:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls = 0

    def send(
        self, request: Any, *, wire_capability: Any = None
    ) -> ClientTransportResponse:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls += 1
            remaining = 99 - self.calls
        try:
            time.sleep(0.05)
            body = json.dumps(
                {
                    "search-results": {
                        "entry": [],
                        "opensearch:totalResults": "0",
                        "opensearch:startIndex": "0",
                    }
                },
                separators=(",", ":"),
            ).encode("utf-8")
            return ClientTransportResponse(
                status=200,
                headers={
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(RESET_EPOCH),
                },
                body=body,
            )
        finally:
            with self._lock:
                self.active -= 1


class IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project_root = self.root / "project"
        self.output = self.project_root / "restricted_metadata"
        self.output.mkdir(parents=True)
        self.topology_path = self.root / "topology.json"
        topology_hash = _write_json(
            self.topology_path,
            {
                "schema_version": "1.0",
                "evidence_type": "single_controller_license_topology",
                "status": "CONFIRMED",
                "application_name": "UAEU Survey Research Access Layer",
                "single_authorized_user": True,
                "single_application_use_case": True,
            },
        )
        self.policy = PolicyConfig.from_mapping(
            {
                "schema_version": "1.0",
                "project_output_roots": {PROJECT_ID: [str(self.project_root)]},
                "project_api_key_aliases": {
                    PROJECT_ID: {"scopus_search": API_ALIAS}
                },
                "live_capability_enabled": True,
                "control_database_path": str(self.root / "control.sqlite"),
                "approved_release_evidence": {},
                "license_topology_evidence": {
                    "path": str(self.topology_path),
                    "sha256": topology_hash,
                },
                "max_preflight_requests": 1,
            },
            base_dir=self.root,
        )
        # Mirrors the offline doctor provisioning step required before any
        # live execution permit can bind the central ledger identity.
        Ledger(self.root / "control.sqlite")
        self.release_pins: Dict[str, Any] = {}
        self.ai_grants: Dict[str, Any] = {}

    def _manifest(
        self,
        task_type: str,
        suffix: str = "",
        *,
        request_updates: Optional[Mapping[str, Any]] = None,
        content_egress: str = "local_file_only",
        include_abstract: bool = False,
        request_api: str = "scopus_search",
        abstract_alias: str = API_ALIAS,
        diagnostic_predecessor: Optional[str] = None,
    ):
        task_id = "integration-" + task_type.replace("_", "-") + suffix
        release_id = "release-" + task_type.replace("_", "-") + suffix
        query_path = self.root / (task_id + "-query.json")
        query_value: Dict[str, Any] = {
            "schema_version": "1.0",
            "project_id": PROJECT_ID,
            "task_id": task_id,
            "task_type": task_type,
            "release_id": release_id,
        }
        if request_api == "scopus_search":
            query_value["queries"] = {
                "scopus_search": {"query": "SYNTHETIC-OFFLINE-QUERY"}
            }
        elif request_api == "abstract_retrieval":
            query_value["identifiers"] = {
                "abstract_retrieval": ["2-s2.0-123456789"]
            }
        else:
            raise AssertionError("unsupported integration fixture API")
        if include_abstract:
            query_value["identifiers"] = {
                "abstract_retrieval": ["2-s2.0-123456789"]
            }
        query_hash = _write_json(query_path, query_value)
        is_search = request_api == "scopus_search"
        request: Dict[str, Any] = {
            "api_name": request_api,
            "view": "STANDARD" if is_search else "FULL",
            "page_size": 2 if is_search else 1,
            "pagination_mode": "cursor" if is_search else "single",
            "anticipated_result_count": (
                None if task_type == "preflight" and is_search else 1
            ),
            "anticipated_unique_detail_records": 0 if is_search else 1,
            "forecast_pagination": 1 if is_search else 0,
            "forecast_detail_retrieval": 0 if is_search else 1,
            "forecast_validation": 0,
            "retry_allowance": 0,
            "estimated_requests_with_margin": 1,
            "request_limit": 1,
            "assumptions": "One bounded offline fixture request.",
            "estimator": "offline-test",
            "estimated_at_utc": "2025-12-01T00:00:00Z",
        }
        if request_updates:
            request.update(request_updates)
        requests = [request]
        if include_abstract:
            requests.append(
                {
                    "api_name": "abstract_retrieval",
                    "view": "FULL",
                    "page_size": 1,
                    "pagination_mode": "single",
                    "anticipated_result_count": 1,
                    "anticipated_unique_detail_records": 1,
                    "forecast_pagination": 0,
                    "forecast_detail_retrieval": 1,
                    "forecast_validation": 0,
                    "retry_allowance": 0,
                    "estimated_requests_with_margin": 1,
                    "request_limit": 1,
                    "assumptions": "One frozen synthetic identifier.",
                    "estimator": "offline-test",
                    "estimated_at_utc": "2025-12-01T00:00:00Z",
                }
            )
        control_hash = execution_control_sha256(
            project_id=PROJECT_ID,
            task_id=task_id,
            task_type=task_type,
            release_id=release_id,
            query_manifest_sha256=query_hash,
            requests=requests,
            project_output_dir=self.output,
            content_egress=content_egress,
        )
        release_path = self.root / (task_id + "-release.json")
        release_hash = _write_json(
            release_path,
            {
                "schema_version": "1.0",
                "evidence_type": "task_release",
                "project_id": PROJECT_ID,
                "task_id": task_id,
                "task_type": task_type,
                "release_id": release_id,
                "status": "APPROVED",
                "synthetic": False,
                "authority": "OFFLINE_TEST_FIXTURE",
                "approved_at_utc": "2025-12-01T00:00:00Z",
                "query_manifest_sha256": query_hash,
                "execution_control_sha256": control_hash,
                **({"diagnostic_predecessor_reservation_id": diagnostic_predecessor}
                   if diagnostic_predecessor is not None else {}),
            },
        )
        manifest_path = self.root / (task_id + "-task.json")
        _write_json(
            manifest_path,
            {
                "schema_version": "1.0",
                "project_id": PROJECT_ID,
                "task_id": task_id,
                "task_type": task_type,
                "release_id": release_id,
                "release_evidence_path": str(release_path),
                "release_evidence_sha256": release_hash,
                "query_manifest_path": str(query_path),
                "query_manifest_sha256": query_hash,
                "requests": requests,
                "project_output_dir": str(self.output),
                "content_egress": content_egress,
            },
        )
        topology = self.policy.license_topology_evidence
        assert topology is not None
        self.release_pins[release_id] = {
            "path": str(release_path),
            "sha256": release_hash,
        }
        if content_egress == "authorized_ai_session":
            license_path = self.root / (task_id + "-ai-license.json")
            route_path = self.root / (task_id + "-ai-route.json")
            license_hash = _write_json(
                license_path,
                {
                    "schema_version": "1.0",
                    "evidence_type": "licensed_content_ai_egress",
                    "status": "CONFIRMED",
                    "project_id": PROJECT_ID,
                    "release_id": release_id,
                },
            )
            route_hash = _write_json(
                route_path,
                {
                    "schema_version": "1.0",
                    "evidence_type": "authorized_ai_session_route",
                    "status": "APPROVED",
                    "project_id": PROJECT_ID,
                    "release_id": release_id,
                },
            )
            self.ai_grants[PROJECT_ID] = {
                "license_evidence": {
                    "path": str(license_path),
                    "sha256": license_hash,
                },
                "route_approval_evidence": {
                    "path": str(route_path),
                    "sha256": route_hash,
                },
                "release_ids": [release_id],
            }
        self.policy = PolicyConfig.from_mapping(
            {
                "schema_version": "1.0",
                "project_output_roots": {PROJECT_ID: [str(self.project_root)]},
                "project_api_key_aliases": {
                    PROJECT_ID: {
                        request_api: API_ALIAS,
                        **(
                            {"abstract_retrieval": abstract_alias}
                            if include_abstract and request_api != "abstract_retrieval"
                            else {}
                        ),
                    }
                },
                "live_capability_enabled": True,
                "control_database_path": str(self.root / "control.sqlite"),
                "license_topology_evidence": {
                    "path": str(topology.path),
                    "sha256": topology.sha256,
                },
                "approved_release_evidence": {
                    PROJECT_ID: dict(self.release_pins)
                },
                "ai_session_grants": dict(self.ai_grants),
                "max_preflight_requests": 1,
            },
            base_dir=self.root,
        )
        manifest = load_task_manifest(str(manifest_path), self.policy)
        permit = authorize_live_execution(
            manifest, self.policy, explicit_cli_consent=True
        )
        return manifest, permit

    def _ledger(self) -> Ledger:
        ledger = Ledger(self.root / "control.sqlite")
        ledger.register_project_key_alias(
            PROJECT_ID, API_ALIAS, "d" * 64, NOW
        )
        return ledger

    def _seed_quota(
        self,
        ledger: Ledger,
        api_name: str,
        *,
        limit: int = 100,
        remaining: int = 99,
    ) -> None:
        """Establish one live bucket only through an authorized preflight outcome."""

        sequence = getattr(self, "_quota_seed_sequence", 0) + 1
        self._quota_seed_sequence = sequence
        manifest, permit = self._manifest(
            "preflight",
            "-quota-seed-%d" % sequence,
            request_api=api_name,
        )
        parent_run_id = "quota-seed-run-%d" % sequence
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=parent_run_id,
            now_utc=NOW,
        )
        self.assertTrue(admission.admitted)
        reservation_id = admission.buckets[0].reservation_id
        self.assertIsNotNone(reservation_id)
        attempt = ledger.record_request_attempt(
            str(reservation_id),
            "search" if api_name == "scopus_search" else "abstract_retrieval",
            "quota-seed-page-%d" % sequence,
            0,
            NOW,
        )
        self.assertTrue(attempt.allowed)
        self.assertIsNotNone(attempt.attempt_id)
        ledger.record_response(
            str(attempt.attempt_id),
            200,
            {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(RESET_EPOCH),
            },
            hashlib.sha256(
                ("quota-seed-%d" % sequence).encode("ascii")
            ).hexdigest(),
            result_count=0,
            observed_at_utc=NOW,
        )

    def _durable_request(
        self, manifest: Any, permit: Any, *, run_id: str
    ):
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        run_capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        adapter = LedgerExecutionAdapter(ledger, run_capability)
        wire = _MockWireTransport(ledger)
        request_capability = adapter.record_attempt_started(
            AttemptStarted(
                attempt_id=run_capability.run_id + ".p1.a1",
                reservation_id=run_capability.reservation_id,
                run_id=run_capability.run_id,
                project_id=manifest.project_id,
                task_id=manifest.task_id,
                api_key_alias=run_capability.api_key_alias,
                api_name=run_capability.api_name,
                endpoint_class=run_capability.endpoint_class,
                view=run_capability.view,
                page_size=run_capability.page_size,
                page_number=1,
                retry_number=0,
                requested_at_utc=NOW,
            )
        )
        transport = ElsevierRunnerTransport(
            manifest=manifest, authorization=permit, transport=wire
        )
        request = RunnerTransportRequest(
            attempt_id=run_capability.run_id + ".p1.a1",
            reservation_id=run_capability.reservation_id,
            run_id=run_capability.run_id,
            api_name="scopus_search",
            endpoint_class=run_capability.endpoint_class,
            view=run_capability.view,
            page_size=run_capability.page_size,
            page_number=1,
            cursor=None,
            retry_number=0,
        )
        return adapter, request_capability, wire, transport, request

    def test_mock_end_to_end_uses_fixed_client_and_real_ledger(self) -> None:
        manifest, permit = self._manifest("survey_run")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id="run-survey-1",
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id="run-survey-1",
            api_name="scopus_search",
        )
        adapter = LedgerExecutionAdapter(ledger, capability)
        wire = _MockWireTransport(ledger)
        transport = ElsevierRunnerTransport(
            manifest=manifest, authorization=permit, transport=wire
        )
        secret_provider = _TrackingSecretProvider()
        events = io.StringIO()
        runner = GovernedRunner(
            transport=transport,
            secret_provider=secret_provider,
            ledger=adapter,
            artifacts=RestrictedArtifactStore(
                manifest.project_output_dir,
                allowed_roots=self.policy.output_roots_for(PROJECT_ID),
            ),
            events=ControlEventWriter(events, clock=lambda: NOW),
            clock=lambda: NOW,
            epoch_clock=lambda: 1_893_456_000,
        )

        with mock.patch.object(
            socket, "create_connection", side_effect=AssertionError("network forbidden")
        ):
            receipt = runner.run(capability)

        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.pages_completed, 1)
        self.assertEqual(wire.calls, 1)
        self.assertTrue(wire.saw_credential)
        self.assertEqual(wire.request.headers, {})
        self.assertIn("api.elsevier.com/content/search/scopus", wire.request.url)
        self.assertNotIn("X-Ignored-Response-Header", events.getvalue())
        self.assertEqual(secret_provider.aliases, [API_ALIAS])
        with self.assertRaises(SecretProviderError):
            secret_provider.values[0].reveal()

        rows = tuple(
            row
            for row in ledger.rows("request_usage")
            if row["task_id"] == manifest.task_id
        )
        self.assertEqual([row["record_kind"] for row in rows], ["ATTEMPT", "OUTCOME"])
        self.assertIsNone(rows[0]["http_status"])
        self.assertEqual(rows[1]["http_status"], 200)
        self.assertEqual(rows[1]["outcome"], "COMPLETED")
        self.assertEqual(len(rows[1]["response_receipt_hash_or_ref"]), 64)
        self.assertTrue(rows[0]["cursor_or_page_ref"].startswith("page-000001-"))
        reservation_rows = ledger.rows("task_reservation")
        self.assertEqual(reservation_rows[-1]["admission_decision"], "COMPLETED")
        self.assertIsNotNone(reservation_rows[-1]["completed_or_released_at_utc"])

    def test_two_api_survey_uses_distinct_execution_namespaces(self) -> None:
        manifest, permit = self._manifest(
            "survey_run", "-two-api", include_abstract=True
        )
        ledger = self._ledger()
        for api_name in ("scopus_search", "abstract_retrieval"):
            self._seed_quota(ledger, api_name)
        parent_run_id = "run-two-api-survey"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=parent_run_id,
            now_utc=NOW,
        )
        self.assertTrue(admission.admitted)
        capabilities = {
            api_name: build_run_authorization(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                admission=admission,
                run_id=parent_run_id,
                api_name=api_name,
            )
            for api_name in ("scopus_search", "abstract_retrieval")
        }
        search_capability = capabilities["scopus_search"]
        abstract_capability = capabilities["abstract_retrieval"]
        self.assertEqual(search_capability.parent_run_id, parent_run_id)
        self.assertEqual(abstract_capability.parent_run_id, parent_run_id)
        self.assertNotEqual(search_capability.run_id, abstract_capability.run_id)
        self.assertNotEqual(
            search_capability.reservation_id, abstract_capability.reservation_id
        )

        store = RestrictedArtifactStore(
            manifest.project_output_dir,
            allowed_roots=self.policy.output_roots_for(PROJECT_ID),
        )
        event_stream = io.StringIO()
        receipts = {}
        wires = {}
        for api_name in ("scopus_search", "abstract_retrieval"):
            capability = capabilities[api_name]
            wire = _MockWireTransport(ledger, remaining=98)
            wires[api_name] = wire
            receipts[api_name] = GovernedRunner(
                transport=ElsevierRunnerTransport(
                    manifest=manifest,
                    authorization=permit,
                    transport=wire,
                ),
                secret_provider=_TrackingSecretProvider(),
                ledger=LedgerExecutionAdapter(ledger, capability),
                artifacts=store,
                events=ControlEventWriter(event_stream, clock=lambda: NOW),
                clock=lambda: NOW,
                epoch_clock=lambda: 1_893_456_000,
            ).run(capability)

        self.assertEqual(sum(wire.calls for wire in wires.values()), 2)
        for api_name, receipt in receipts.items():
            capability = capabilities[api_name]
            self.assertEqual(receipt.status, "completed")
            self.assertEqual(receipt.parent_run_id, parent_run_id)
            self.assertEqual(receipt.run_id, capability.run_id)
            self.assertEqual(receipt.api_name, api_name)
            self.assertEqual(receipt.reservation_id, capability.reservation_id)
            self.assertTrue((self.output / receipt.checkpoint_ref).is_file())
            self.assertTrue((self.output / receipt.receipt_ref).is_file())
            self.assertTrue((self.output / receipt.artifact_manifest_ref).is_file())
        self.assertNotEqual(
            receipts["scopus_search"].checkpoint_ref,
            receipts["abstract_retrieval"].checkpoint_ref,
        )
        self.assertNotEqual(
            receipts["scopus_search"].artifact_manifest_ref,
            receipts["abstract_retrieval"].artifact_manifest_ref,
        )
        response_records = {
            api_name: store.load_response_records(capability.run_id)
            for api_name, capability in capabilities.items()
        }
        self.assertTrue(
            all(len(records) == 1 for records in response_records.values())
        )
        raw_refs = {
            records[0].artifact_ref for records in response_records.values()
        }
        self.assertEqual(len(raw_refs), 2)
        self.assertTrue(all((self.output / ref).is_file() for ref in raw_refs))

        latest_by_reservation = {}
        for row in ledger.rows("task_reservation"):
            latest_by_reservation[row["reservation_id"]] = row
        for capability in capabilities.values():
            row = latest_by_reservation[capability.reservation_id]
            self.assertEqual(row["admission_decision"], "COMPLETED")
            self.assertEqual(row["actual_requests"], 1)
            self.assertEqual(row["run_id"], parent_run_id)

        completed = [
            json.loads(line)
            for line in event_stream.getvalue().splitlines()
            if json.loads(line)["event"] == "run_completed"
        ]
        self.assertEqual(len(completed), 2)
        self.assertEqual({item["parent_run_id"] for item in completed}, {parent_run_id})
        self.assertEqual(
            {item["run_id"] for item in completed},
            {capability.run_id for capability in capabilities.values()},
        )
        self.assertEqual(
            {item["api_name"] for item in completed},
            {"scopus_search", "abstract_retrieval"},
        )
        self.assertEqual(
            {item["reservation_id"] for item in completed},
            {capability.reservation_id for capability in capabilities.values()},
        )

    def test_two_api_resume_state_is_isolated_by_execution_namespace(self) -> None:
        manifest, permit = self._manifest(
            "survey_run",
            "-two-api-resume",
            include_abstract=True,
            request_updates={
                "anticipated_result_count": 3,
                "forecast_pagination": 2,
                "estimated_requests_with_margin": 2,
                "request_limit": 2,
            },
        )
        ledger = self._ledger()
        for api_name in ("scopus_search", "abstract_retrieval"):
            self._seed_quota(ledger, api_name)
        parent_run_id = "run-two-api-resume"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=parent_run_id,
            now_utc=NOW,
        )
        search_capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=parent_run_id,
            api_name="scopus_search",
        )
        abstract_capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=parent_run_id,
            api_name="abstract_retrieval",
        )
        store = RestrictedArtifactStore(
            manifest.project_output_dir,
            allowed_roots=self.policy.output_roots_for(PROJECT_ID),
        )

        search_adapter = LedgerExecutionAdapter(ledger, search_capability)
        search_attempt_id = search_capability.run_id + ".p1.a1"
        search_adapter.record_attempt_started(
            AttemptStarted(
                attempt_id=search_attempt_id,
                reservation_id=search_capability.reservation_id,
                run_id=search_capability.run_id,
                project_id=manifest.project_id,
                task_id=manifest.task_id,
                api_key_alias=search_capability.api_key_alias,
                api_name=search_capability.api_name,
                endpoint_class=search_capability.endpoint_class,
                view=search_capability.view,
                page_size=search_capability.page_size,
                page_number=1,
                retry_number=0,
                requested_at_utc=NOW,
            )
        )
        search_artifact = store.write_response(
            run_id=search_capability.run_id,
            attempt_id=search_attempt_id,
            page_number=1,
            body=json.dumps(
                {
                    "search-results": {
                        "entry": [{"dc:identifier": "SYNTHETIC-FIRST-PAGE"}],
                        "cursor": {"@next": "isolated-search-cursor"},
                    }
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            timestamp=NOW,
        )
        search_adapter.record_attempt_finished(
            AttemptFinished(
                attempt_id=search_attempt_id,
                run_id=search_capability.run_id,
                api_name="scopus_search",
                http_status=200,
                result_count=1,
                retry_number=0,
                outcome="page_completed",
                stop_reason="none",
                response_sha256=search_artifact.sha256,
                artifact_ref=search_artifact.artifact_ref,
                rate_limit_limit=100,
                rate_limit_remaining=98,
                rate_limit_reset_epoch=RESET_EPOCH,
                completed_at_utc=NOW,
            )
        )
        store.write_checkpoint(
            Checkpoint(
                run_id=search_capability.run_id,
                next_page=2,
                next_cursor="isolated-search-cursor",
                completed_pages=1,
                requests_attempted=1,
                retries_used=0,
                complete=False,
                last_artifact_sha256=search_artifact.sha256,
                saved_at_utc=NOW,
            )
        )

        abstract_wire = _MockWireTransport(ledger, remaining=98)
        abstract_receipt = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest,
                authorization=permit,
                transport=abstract_wire,
            ),
            secret_provider=_TrackingSecretProvider(),
            ledger=LedgerExecutionAdapter(ledger, abstract_capability),
            artifacts=store,
            events=ControlEventWriter(io.StringIO(), clock=lambda: NOW),
            clock=lambda: NOW,
            epoch_clock=lambda: 1_893_456_000,
        ).run(abstract_capability)
        self.assertEqual(abstract_wire.calls, 1)
        self.assertEqual(abstract_wire.request.url.count("/abstract/"), 1)
        self.assertEqual(abstract_receipt.pages_completed, 1)
        self.assertNotEqual(
            abstract_receipt.checkpoint_ref,
            store.checkpoint_ref(search_capability.run_id),
        )

        resumed_search = build_resume_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            artifacts=store,
            run_id=parent_run_id,
            api_name="scopus_search",
        )
        self.assertEqual(resumed_search.run_id, search_capability.run_id)
        self.assertEqual(resumed_search.reservation_id, search_capability.reservation_id)
        search_checkpoint = store.load_checkpoint(resumed_search.run_id)
        self.assertEqual(search_checkpoint.next_page, 2)
        self.assertEqual(search_checkpoint.next_cursor, "isolated-search-cursor")

    def test_restart_rebuilds_capability_from_checkpoint_and_existing_reservation(self) -> None:
        manifest, permit = self._manifest(
            "survey_run",
            "-resume",
            request_updates={
                "anticipated_result_count": 3,
                "forecast_pagination": 2,
                "estimated_requests_with_margin": 2,
                "request_limit": 2,
            },
        )
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-restart-resume"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        initial = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        adapter = LedgerExecutionAdapter(ledger, initial)
        attempt_id = initial.run_id + ".p1.a1"
        adapter.record_attempt_started(
            AttemptStarted(
                attempt_id=attempt_id,
                reservation_id=initial.reservation_id,
                run_id=initial.run_id,
                project_id=manifest.project_id,
                task_id=manifest.task_id,
                api_key_alias=initial.api_key_alias,
                api_name=initial.api_name,
                endpoint_class=initial.endpoint_class,
                view=initial.view,
                page_size=initial.page_size,
                page_number=1,
                retry_number=0,
                requested_at_utc=NOW,
            )
        )
        store = RestrictedArtifactStore(
            manifest.project_output_dir,
            allowed_roots=self.policy.output_roots_for(PROJECT_ID),
        )
        artifact = store.write_response(
            run_id=initial.run_id,
            attempt_id=attempt_id,
            page_number=1,
            body=json.dumps(
                {
                    "search-results": {
                        "entry": [{"dc:identifier": "SYNTHETIC-FIRST-PAGE"}],
                        "cursor": {"@next": "resume-cursor"},
                    }
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            timestamp=NOW,
        )
        adapter.record_attempt_finished(
            AttemptFinished(
                attempt_id=attempt_id,
                run_id=initial.run_id,
                api_name="scopus_search",
                http_status=200,
                result_count=2,
                retry_number=0,
                outcome="page_completed",
                stop_reason="none",
                response_sha256=artifact.sha256,
                artifact_ref=artifact.artifact_ref,
                rate_limit_limit=100,
                rate_limit_remaining=98,
                rate_limit_reset_epoch=RESET_EPOCH,
                completed_at_utc=NOW,
            )
        )
        restarted_ledger = Ledger(ledger.database_path)
        checkpoint_values = dict(
            run_id=initial.run_id,
            next_page=2,
            next_cursor="resume-cursor",
            completed_pages=1,
            requests_attempted=1,
            retries_used=0,
            complete=False,
            last_artifact_sha256=artifact.sha256,
            saved_at_utc=NOW,
        )
        store.write_checkpoint(Checkpoint(**{**checkpoint_values, "next_page": 1}))
        with self.assertRaisesRegex(
            IntegrationError, "RESUME_CHECKPOINT_STATE_MISMATCH"
        ):
            build_resume_authorization(
                ledger=restarted_ledger,
                manifest=manifest,
                authorization=permit,
                artifacts=store,
                run_id=run_id,
                api_name="scopus_search",
            )
        store.write_checkpoint(
            Checkpoint(**{**checkpoint_values, "last_artifact_sha256": "0" * 64})
        )
        with self.assertRaisesRegex(
            IntegrationError, "RESUME_ARTIFACT_CHAIN_MISMATCH"
        ):
            build_resume_authorization(
                ledger=restarted_ledger,
                manifest=manifest,
                authorization=permit,
                artifacts=store,
                run_id=run_id,
                api_name="scopus_search",
            )
        store.write_checkpoint(
            Checkpoint(**{**checkpoint_values, "next_cursor": "wrong-cursor"})
        )
        with self.assertRaisesRegex(
            IntegrationError, "RESUME_CHECKPOINT_CURSOR_MISMATCH"
        ):
            build_resume_authorization(
                ledger=restarted_ledger,
                manifest=manifest,
                authorization=permit,
                artifacts=store,
                run_id=run_id,
                api_name="scopus_search",
            )
        store.write_checkpoint(Checkpoint(**checkpoint_values))
        resumed = build_resume_authorization(
            ledger=restarted_ledger,
            manifest=manifest,
            authorization=permit,
            artifacts=store,
            run_id=run_id,
            api_name="scopus_search",
        )
        self.assertEqual(resumed.reservation_id, initial.reservation_id)
        replay = admit_authorized_manifest(
            ledger=restarted_ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        self.assertFalse(replay.admitted)
        self.assertEqual(replay.reason_code, "TASK_RELEASE_ALREADY_CONSUMED")

        wire = _MockWireTransport(restarted_ledger, remaining=97)
        receipt = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest, authorization=permit, transport=wire
            ),
            secret_provider=_TrackingSecretProvider(),
            ledger=LedgerExecutionAdapter(restarted_ledger, resumed),
            artifacts=store,
            events=ControlEventWriter(io.StringIO(), clock=lambda: NOW),
            clock=lambda: NOW,
            epoch_clock=lambda: 1_893_456_000,
        ).run(resumed)
        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.pages_completed, 2)
        self.assertEqual(receipt.requests_attempted, 2)
        self.assertIn("cursor=resume-cursor", wire.request.url)

    def test_two_real_adapters_serialize_transport_across_workers(self) -> None:
        manifest_a, permit_a = self._manifest("survey_run", "-a")
        manifest_b, permit_b = self._manifest("survey_run", "-b")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        runners = []
        capabilities = []
        wire = _SerializedWireTransport()
        for index, (manifest, permit) in enumerate(
            ((manifest_a, permit_a), (manifest_b, permit_b)), start=1
        ):
            run_id = "run-concurrent-%d" % index
            admission = admit_authorized_manifest(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                run_id=run_id,
                now_utc=NOW,
            )
            capability = build_run_authorization(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                admission=admission,
                run_id=run_id,
                api_name="scopus_search",
            )
            capabilities.append(capability)
            runners.append(
                GovernedRunner(
                    transport=ElsevierRunnerTransport(
                        manifest=manifest, authorization=permit, transport=wire
                    ),
                    secret_provider=_TrackingSecretProvider(),
                    ledger=LedgerExecutionAdapter(ledger, capability),
                    artifacts=RestrictedArtifactStore(
                        manifest.project_output_dir,
                        allowed_roots=self.policy.output_roots_for(PROJECT_ID),
                    ),
                    events=ControlEventWriter(io.StringIO(), clock=lambda: NOW),
                    clock=lambda: NOW,
                    epoch_clock=lambda: 1_893_456_000,
                )
            )

        barrier = threading.Barrier(3)
        receipts = []
        failures = []

        def worker(index: int) -> None:
            try:
                barrier.wait()
                receipts.append(runners[index].run(capabilities[index]))
            except BaseException as exc:
                failures.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual([receipt.status for receipt in receipts], ["completed", "completed"])
        self.assertEqual(wire.calls, 2)
        self.assertEqual(wire.max_active, 1)
        self.assertEqual(
            [
                row["record_kind"]
                for row in ledger.rows("request_usage")
                if row["task_id"] in {manifest_a.task_id, manifest_b.task_id}
            ].count("ATTEMPT"),
            2,
        )

    def test_throttle_backoff_blocks_other_worker_until_global_release(self) -> None:
        manifest_a, permit_a = self._manifest(
            "survey_run",
            "-throttle-a",
            request_updates={
                "retry_allowance": 1,
                "estimated_requests_with_margin": 2,
                "request_limit": 2,
            },
        )
        manifest_b, permit_b = self._manifest("survey_run", "-throttle-b")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")

        capabilities = []
        adapters = []
        for index, (manifest, permit) in enumerate(
            ((manifest_a, permit_a), (manifest_b, permit_b)), start=1
        ):
            run_id = "run-throttle-lock-%d" % index
            admission = admit_authorized_manifest(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                run_id=run_id,
                now_utc=NOW,
            )
            capability = build_run_authorization(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                admission=admission,
                run_id=run_id,
                api_name="scopus_search",
            )
            capabilities.append(capability)
            adapters.append(LedgerExecutionAdapter(ledger, capability))

        def started_record(capability: Any) -> AttemptStarted:
            return AttemptStarted(
                attempt_id=capability.run_id + ".p1.a1",
                reservation_id=capability.reservation_id,
                run_id=capability.run_id,
                project_id=capability.project_id,
                task_id=capability.task_id,
                api_key_alias=capability.api_key_alias,
                api_name=capability.api_name,
                endpoint_class=capability.endpoint_class,
                view=capability.view,
                page_size=capability.page_size,
                page_number=1,
                retry_number=0,
                requested_at_utc=NOW,
            )

        first = started_record(capabilities[0])
        adapters[0].record_attempt_started(first)
        adapters[0].record_attempt_finished(
            AttemptFinished(
                attempt_id=first.attempt_id,
                run_id=first.run_id,
                api_name=first.api_name,
                http_status=429,
                result_count=0,
                retry_number=0,
                outcome="throttled",
                stop_reason="throttled",
                response_sha256=None,
                artifact_ref=None,
                rate_limit_limit=100,
                rate_limit_remaining=98,
                rate_limit_reset_epoch=RESET_EPOCH,
                completed_at_utc=NOW,
            )
        )

        entered = threading.Event()
        finished = threading.Event()
        failures = []
        second = started_record(capabilities[1])

        def start_second() -> None:
            try:
                entered.set()
                adapters[1].record_attempt_started(second)
                finished.set()
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=start_second)
        thread.start()
        self.assertTrue(entered.wait(timeout=1))
        time.sleep(0.05)
        self.assertFalse(finished.is_set())
        adapters[0].release_throttle_backoff(first.attempt_id)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(finished.is_set())
        adapters[1].record_attempt_finished(
            AttemptFinished(
                attempt_id=second.attempt_id,
                run_id=second.run_id,
                api_name=second.api_name,
                http_status=200,
                result_count=0,
                retry_number=0,
                outcome="page_completed",
                stop_reason="none",
                response_sha256="a" * 64,
                artifact_ref=None,
                rate_limit_limit=100,
                rate_limit_remaining=97,
                rate_limit_reset_epoch=RESET_EPOCH,
                completed_at_utc=NOW,
            )
        )

    def test_real_runner_surfaces_exact_eighty_percent_warning(self) -> None:
        manifest, permit = self._manifest("survey_run", "-warning")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-warning-integration"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        stream = io.StringIO()
        runner = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest,
                authorization=permit,
                transport=_MockWireTransport(ledger, remaining=20),
            ),
            secret_provider=_TrackingSecretProvider(),
            ledger=LedgerExecutionAdapter(ledger, capability),
            artifacts=RestrictedArtifactStore(
                manifest.project_output_dir,
                allowed_roots=self.policy.output_roots_for(PROJECT_ID),
            ),
            events=ControlEventWriter(stream, clock=lambda: NOW),
            clock=lambda: NOW,
            epoch_clock=lambda: 1_893_456_000,
        )
        receipt = runner.run(capability)
        self.assertEqual(receipt.status, "completed")
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertTrue(
            any(
                row["event"] == "warning" and row["code"] == "quota_warning_80"
                for row in records
            )
        )
        self.assertEqual(
            ledger.quota_status(API_ALIAS, "scopus_search", NOW).state.value,
            "QUOTA_WARNING_80",
        )

    def test_real_runner_stops_at_bound_when_another_page_exists(self) -> None:
        manifest, permit = self._manifest("survey_run", "-risk")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-risk-integration"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        runner = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest,
                authorization=permit,
                transport=_MockWireTransport(
                    ledger, remaining=98, next_cursor="cursor-next"
                ),
            ),
            secret_provider=_TrackingSecretProvider(),
            ledger=LedgerExecutionAdapter(ledger, capability),
            artifacts=RestrictedArtifactStore(
                manifest.project_output_dir,
                allowed_roots=self.policy.output_roots_for(PROJECT_ID),
            ),
            events=ControlEventWriter(io.StringIO(), clock=lambda: NOW),
            clock=lambda: NOW,
            epoch_clock=lambda: 1_893_456_000,
        )
        receipt = runner.run(capability)
        self.assertEqual(receipt.status, "paused")
        self.assertEqual(receipt.stop_reason, "request_boundary_reached")
        latest_reservation = [
            row
            for row in ledger.rows("task_reservation")
            if row["reservation_id"] == capability.reservation_id
        ][-1]
        self.assertEqual(
            latest_reservation["admission_decision"], "ADMITTED"
        )
        self.assertEqual(latest_reservation["reserved_remaining"], 0)
        self.assertEqual(latest_reservation["actual_requests"], 1)
        self.assertEqual(ledger.quota_status(API_ALIAS, "scopus_search", NOW).state.value, "NORMAL")

    def test_preflight_uses_separate_one_attempt_admission(self) -> None:
        manifest, permit = self._manifest("preflight")
        ledger = self._ledger()
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id="run-preflight-1",
            now_utc=NOW,
        )
        self.assertEqual(admission.reason_code, "AUTHORIZED_MINIMAL_PREFLIGHT")
        self.assertEqual(ledger.ledger_count("quota_window"), 0)
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id="run-preflight-1",
            api_name="scopus_search",
        )
        self.assertEqual(capability.max_pages, 1)
        self.assertEqual(capability.max_requests, 1)
        self.assertEqual(capability.retry_allowance, 0)

    def test_first_successful_diagnostic_completes_with_real_header_reconciliation(self):
        ledger = self._ledger()
        initial, initial_permit = self._manifest("preflight", "-rejected-quota")
        admission = admit_authorized_manifest(
            ledger=ledger, manifest=initial, authorization=initial_permit,
            run_id="rejected-quota-run", now_utc=NOW,
        )
        attempt = ledger.record_request_attempt(
            admission.buckets[0].reservation_id, "search", "page-1", 0, NOW
        )
        ledger.record_response(
            attempt.attempt_id, 403,
            {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "100",
             "X-RateLimit-Reset": str(RESET_EPOCH - 3600)},
            "a" * 64, result_count=0, observed_at_utc=NOW,
        )
        manifest, permit = self._manifest(
            "preflight", "-successful-quota",
            request_updates={"page_size": 1, "pagination_mode": "offset"},
        )
        admission = admit_authorized_manifest(
            ledger=ledger, manifest=manifest, authorization=permit,
            run_id="successful-quota-run", now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger, manifest=manifest, authorization=permit, admission=admission,
            run_id="successful-quota-run", api_name="scopus_search",
        )
        wire = _MockWireTransport(ledger)
        receipt = GovernedRunner(
            transport=ElsevierRunnerTransport(manifest=manifest, authorization=permit, transport=wire),
            secret_provider=_TrackingSecretProvider(), ledger=LedgerExecutionAdapter(ledger, capability),
            artifacts=RestrictedArtifactStore(self.output, allowed_roots=[self.output]),
            events=ControlEventWriter(io.StringIO(), clock=lambda: NOW),
            clock=lambda: NOW, epoch_clock=lambda: 1_893_456_000,
        ).run(capability)
        self.assertEqual((receipt.status, receipt.records_count, receipt.requests_attempted), ("completed", 1, 1))
        self.assertEqual(wire.calls, 1)
        quota = ledger.quota_status(API_ALIAS, "scopus_search", NOW)
        self.assertEqual(quota.state.value, "NORMAL")
        self.assertEqual(quota.server_remaining, 98)
        self.assertEqual(quota.reason_code, "RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC")

    def test_corrected_diagnostic_requires_pinned_minimal_offset_grant(self):
        ledger = self._ledger()
        predecessor = None
        for suffix in ("-initial-403", "-diagnostic-200"):
            manifest, permit = self._manifest("preflight", suffix)
            admission = admit_authorized_manifest(
                ledger=ledger, manifest=manifest, authorization=permit,
                run_id="run" + suffix, now_utc=NOW,
            )
            self.assertTrue(admission.admitted)
            predecessor = admission.buckets[0].reservation_id
            attempt = ledger.record_request_attempt(predecessor, "search", "page-1", 0, NOW)
            ledger.record_response(
                attempt.attempt_id, 403 if suffix == "-initial-403" else 200,
                {},
                "a" * 64, result_count=0, observed_at_utc=NOW,
            )
        manifest, permit = self._manifest(
            "preflight", "-cursor-correction", diagnostic_predecessor=predecessor,
            request_updates={"page_size": 1},
        )
        with self.assertRaisesRegex(IntegrationError, "MINIMAL_OFFSET_SEARCH"):
            admit_authorized_manifest(
                ledger=ledger, manifest=manifest, authorization=permit,
                run_id="run-invalid-correction", now_utc=NOW,
            )
        manifest, permit = self._manifest(
            "preflight", "-offset-correction", diagnostic_predecessor=predecessor,
            request_updates={"page_size": 1, "pagination_mode": "offset"},
        )
        admission = admit_authorized_manifest(
            ledger=ledger, manifest=manifest, authorization=permit,
            run_id="run-offset-correction", now_utc=NOW,
        )
        self.assertTrue(admission.admitted)
        capability = build_run_authorization(
            ledger=ledger, manifest=manifest, authorization=permit,
            admission=admission, run_id="run-offset-correction", api_name="scopus_search",
        )
        self.assertEqual((capability.max_pages, capability.max_requests, capability.retry_allowance), (1, 1, 0))
        duplicate = admit_authorized_manifest(
            ledger=ledger, manifest=manifest, authorization=permit,
            run_id="run-offset-replay", now_utc=NOW,
        )
        self.assertFalse(duplicate.admitted)
        self.assertEqual(duplicate.reason_code, "TASK_RELEASE_ALREADY_CONSUMED")
        # A changed predecessor is no longer the independently approved release.
        release_path = manifest.release_evidence.path
        changed = json.loads(release_path.read_text())
        changed["diagnostic_predecessor_reservation_id"] = "other-reservation"
        _write_json(release_path, changed)
        with self.assertRaisesRegex(IntegrationError, "RELEASE_EVIDENCE_CHANGED"):
            admit_authorized_manifest(
                ledger=ledger, manifest=manifest, authorization=permit,
                run_id="run-tampered-correction", now_utc=NOW,
            )

    def test_only_authorized_integration_path_can_bootstrap_live_quota(self) -> None:
        ledger = self._ledger()
        self.assertFalse(hasattr(ledger, "record_quota_observation"))
        self.assertFalse(hasattr(ledger, "admit_preflight"))
        self.assertFalse(hasattr(ledger, "admit_task"))

        survey, survey_permit = self._manifest("survey_run", "-before-bootstrap")
        blocked = admit_authorized_manifest(
            ledger=ledger,
            manifest=survey,
            authorization=survey_permit,
            run_id="run-before-bootstrap",
            now_utc=NOW,
        )
        self.assertFalse(blocked.admitted)
        self.assertEqual(blocked.reason_code, "UNVERIFIED")
        self.assertEqual(ledger.ledger_count("request_usage"), 0)

        self._seed_quota(ledger, "scopus_search")
        admitted = admit_authorized_manifest(
            ledger=ledger,
            manifest=survey,
            authorization=survey_permit,
            run_id="run-after-bootstrap",
            now_utc=NOW,
        )
        self.assertTrue(admitted.admitted)
        usage = ledger.rows("request_usage")
        self.assertEqual(
            [row["record_kind"] for row in usage], ["ATTEMPT", "OUTCOME"]
        )

    def test_admission_rejects_multi_alias_and_atomic_binding_mismatch(self) -> None:
        multi_manifest, multi_permit = self._manifest(
            "survey_run",
            "-multi-alias",
            include_abstract=True,
            abstract_alias="different-approved-alias",
        )
        ledger = self._ledger()
        with self.assertRaisesRegex(IntegrationError, "MULTI_ALIAS_TASK_DENIED"):
            admit_authorized_manifest(
                ledger=ledger,
                manifest=multi_manifest,
                authorization=multi_permit,
                run_id="run-multi-alias",
                now_utc=NOW,
            )
        self.assertEqual(ledger.ledger_count("task_reservation"), 0)

        manifest, permit = self._manifest("survey_run", "-stale-binding")
        ledger.register_project_key_alias(
            PROJECT_ID,
            "replacement-approved-alias",
            "e" * 64,
            NOW,
            "f" * 64,
        )
        # Simulate a binding change between the integration pre-read and the
        # ledger's BEGIN IMMEDIATE transaction.  The in-transaction comparison
        # remains authoritative and must create no reservation.
        with mock.patch.object(
            ledger, "current_project_key_alias", return_value=API_ALIAS
        ):
            rejected = admit_authorized_manifest(
                ledger=ledger,
                manifest=manifest,
                authorization=permit,
                run_id="run-stale-binding",
                now_utc=NOW,
            )
        self.assertFalse(rejected.admitted)
        self.assertEqual(rejected.reason_code, "PROJECT_KEY_ALIAS_MISMATCH")
        self.assertEqual(ledger.ledger_count("task_reservation"), 0)

    def test_authorization_mismatch_fails_before_admission_or_transport(self) -> None:
        manifest, permit = self._manifest("survey_run")
        ledger = self._ledger()
        mismatched = dataclasses.replace(manifest, task_id="different-task")
        with self.assertRaisesRegex(IntegrationError, "MANIFEST_AUTHORIZATION_MISMATCH"):
            admit_authorized_manifest(
                ledger=ledger,
                manifest=mismatched,
                authorization=permit,
                run_id="run-gate-fail",
                now_utc=NOW,
            )
        self.assertEqual(ledger.ledger_count("task_reservation"), 0)
        self.assertEqual(ledger.ledger_count("request_usage"), 0)

    def test_post_authorization_execution_control_tamper_is_rejected(self) -> None:
        manifest, permit = self._manifest("survey_run")
        plan = dataclasses.replace(
            manifest.requests[0],
            forecast_pagination=2,
            estimated_requests_with_margin=2,
            request_limit=2,
        )
        mutated = dataclasses.replace(manifest, requests=(plan,))
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        with self.assertRaisesRegex(IntegrationError, "MANIFEST_AUTHORIZATION_MISMATCH"):
            admit_authorized_manifest(
                ledger=ledger,
                manifest=mutated,
                authorization=permit,
                run_id="run-tampered-controls",
                now_utc=NOW,
            )
        self.assertFalse(
            any(
                row["task_id"] == mutated.task_id
                for row in ledger.rows("task_reservation")
            )
        )

    def test_post_build_run_capability_cannot_repurpose_retry_as_pagination(self) -> None:
        manifest, permit = self._manifest(
            "survey_run",
            "-sealed-run",
            request_updates={
                "retry_allowance": 1,
                "estimated_requests_with_margin": 2,
                "request_limit": 2,
            },
        )
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id="run-sealed-bounds",
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id="run-sealed-bounds",
            api_name="scopus_search",
        )
        tampered = dataclasses.replace(
            capability, max_pages=2, retry_allowance=0
        )
        wire = _MockWireTransport(ledger)
        with self.assertRaisesRegex(RunnerGateError, "integrity"):
            LedgerExecutionAdapter(ledger, tampered)
        self.assertEqual(wire.calls, 0)

    def test_run_capability_rejects_cloned_control_database(self) -> None:
        manifest, permit = self._manifest("survey_run", "-cloned-ledger")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-cloned-ledger"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )

        clone_path = self.root / "cloned-control.sqlite"
        with sqlite3.connect(ledger.database_path) as source, sqlite3.connect(
            str(clone_path)
        ) as clone_connection:
            source.backup(clone_connection)
        with self.assertRaisesRegex(LedgerError, "identity"):
            Ledger(clone_path)

        tampered = dataclasses.replace(
            capability,
            control_database_path=str(clone_path.resolve()),
        )
        with self.assertRaisesRegex(RunnerGateError, "integrity"):
            LedgerExecutionAdapter(ledger, tampered)

    def test_permit_and_adapter_reject_same_path_database_replacement(self) -> None:
        manifest, permit = self._manifest("survey_run", "-db-replaced")
        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-db-replaced"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        adapter = LedgerExecutionAdapter(ledger, capability)

        replacement_path = self.root / "replacement-control.sqlite"
        with sqlite3.connect(ledger.database_path) as source, sqlite3.connect(
            str(replacement_path)
        ) as replacement:
            source.backup(replacement)
        with sqlite3.connect(ledger.database_path) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        os.replace(str(replacement_path), ledger.database_path)

        with self.assertRaisesRegex(
            IntegrationError, "RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH"
        ):
            LedgerExecutionAdapter(ledger, capability)
        with self.assertRaisesRegex(
            IntegrationError, "RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH"
        ):
            adapter.record_attempt_started(
                AttemptStarted(
                    attempt_id=capability.run_id + ".p1.a1",
                    reservation_id=capability.reservation_id,
                    run_id=capability.run_id,
                    project_id=capability.project_id,
                    task_id=capability.task_id,
                    api_key_alias=capability.api_key_alias,
                    api_name=capability.api_name,
                    endpoint_class=capability.endpoint_class,
                    view=capability.view,
                    page_size=capability.page_size,
                    page_number=1,
                    retry_number=0,
                    requested_at_utc=NOW,
                )
            )
        self.assertFalse(
            any(
                row["task_id"] == manifest.task_id
                for row in ledger.rows("request_usage")
            )
        )

    def test_permit_rejects_fresh_same_path_database_before_admission(self) -> None:
        manifest, permit = self._manifest("survey_run", "-db-reset")
        original_path = Path(permit.control_database_path)
        replacement_path = self.root / "fresh-control.sqlite"
        Ledger(replacement_path)
        with sqlite3.connect(str(replacement_path)) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        os.replace(str(replacement_path), str(original_path))
        replacement = Ledger(original_path, require_existing_identity=True)

        with self.assertRaisesRegex(
            IntegrationError, "CONTROL_DATABASE_IDENTITY_MISMATCH"
        ):
            admit_authorized_manifest(
                ledger=replacement,
                manifest=manifest,
                authorization=permit,
                run_id="run-db-reset",
                now_utc=NOW,
            )
        self.assertEqual(replacement.rows("task_reservation"), ())

    def test_adapter_rejects_database_replacement_before_outcome_append(self) -> None:
        manifest, permit = self._manifest("survey_run", "-db-outcome-swap")
        adapter, _, wire, _, request = self._durable_request(
            manifest, permit, run_id="run-db-outcome-swap"
        )
        ledger = adapter._ledger
        replacement_path = self.root / "outcome-replacement.sqlite"
        with sqlite3.connect(ledger.database_path) as source, sqlite3.connect(
            str(replacement_path)
        ) as replacement:
            source.backup(replacement)
        with sqlite3.connect(ledger.database_path) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        os.replace(str(replacement_path), ledger.database_path)

        with self.assertRaisesRegex(
            IntegrationError, "RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH"
        ):
            adapter.record_attempt_finished(
                AttemptFinished(
                    attempt_id=request.attempt_id,
                    run_id=request.run_id,
                    api_name=request.api_name,
                    http_status=200,
                    result_count=0,
                    retry_number=0,
                    outcome="success",
                    stop_reason="page_complete",
                    response_sha256="a" * 64,
                    artifact_ref=None,
                    rate_limit_limit=100,
                    rate_limit_remaining=98,
                    rate_limit_reset_epoch=RESET_EPOCH,
                    completed_at_utc=NOW,
                )
            )
        self.assertEqual(
            [
                row["record_kind"]
                for row in ledger.rows("request_usage")
                if row["task_id"] == manifest.task_id
            ],
            ["ATTEMPT"],
        )
        self.assertEqual(wire.calls, 0)

    def test_database_replacement_after_charge_fails_before_wire(self) -> None:
        manifest, permit = self._manifest("survey_run", "-db-wire-swap")
        adapter, request_capability, wire, transport, request = self._durable_request(
            manifest, permit, run_id="run-db-wire-swap"
        )
        ledger = adapter._ledger
        replacement_path = self.root / "wire-replacement.sqlite"
        with sqlite3.connect(ledger.database_path) as source, sqlite3.connect(
            str(replacement_path)
        ) as replacement:
            source.backup(replacement)
        with sqlite3.connect(ledger.database_path) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        os.replace(str(replacement_path), ledger.database_path)

        try:
            with self.assertRaisesRegex(UnsafeRequestError, "database identity"):
                transport.send(
                    request,
                    api_key="offline-mock-credential",
                    request_capability=request_capability,
                )
        finally:
            adapter.release_all_execution_locks()
        self.assertEqual(wire.calls, 0)

    def test_forged_permit_and_revoked_release_fail_before_wire(self) -> None:
        manifest, permit = self._manifest("survey_run", "-revoked")
        with self.assertRaises(LiveCapabilityLocked):
            ElsevierRunnerTransport(
                manifest=manifest,
                authorization=dataclasses.replace(
                    permit, query_manifest_sha256="b" * 64
                ),
                transport=_MockWireTransport(self._ledger()),
            )

        ledger = self._ledger()
        self._seed_quota(ledger, "scopus_search")
        run_id = "run-release-revoked"
        admission = admit_authorized_manifest(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            run_id=run_id,
            now_utc=NOW,
        )
        run_capability = build_run_authorization(
            ledger=ledger,
            manifest=manifest,
            authorization=permit,
            admission=admission,
            run_id=run_id,
            api_name="scopus_search",
        )
        adapter = LedgerExecutionAdapter(ledger, run_capability)
        started = AttemptStarted(
            attempt_id=run_capability.run_id + ".p1.a1",
            reservation_id=run_capability.reservation_id,
            run_id=run_capability.run_id,
            project_id=manifest.project_id,
            task_id=manifest.task_id,
            api_key_alias=run_capability.api_key_alias,
            api_name=run_capability.api_name,
            endpoint_class=run_capability.endpoint_class,
            view=run_capability.view,
            page_size=run_capability.page_size,
            page_number=1,
            retry_number=0,
            requested_at_utc=NOW,
        )
        request_capability = adapter.record_attempt_started(started)
        wire = _MockWireTransport(ledger)
        transport = ElsevierRunnerTransport(
            manifest=manifest, authorization=permit, transport=wire
        )
        release_value = json.loads(
            manifest.release_evidence.path.read_text(encoding="utf-8")
        )
        release_value["status"] = "REVOKED"
        _write_json(manifest.release_evidence.path, release_value)
        try:
            with self.assertRaises(UnsafeRequestError):
                transport.send(
                    RunnerTransportRequest(
                        attempt_id=run_capability.run_id + ".p1.a1",
                        reservation_id=run_capability.reservation_id,
                        run_id=run_capability.run_id,
                        api_name="scopus_search",
                        endpoint_class=run_capability.endpoint_class,
                        view=run_capability.view,
                        page_size=run_capability.page_size,
                        page_number=1,
                        cursor=None,
                        retry_number=0,
                    ),
                    api_key="offline-mock-credential",
                    request_capability=request_capability,
                )
        finally:
            adapter.release_all_execution_locks()
        self.assertEqual(wire.calls, 0)

    def test_topology_revocation_after_durable_attempt_fails_before_wire(self) -> None:
        manifest, permit = self._manifest("survey_run", "-topology-revoked")
        adapter, request_capability, wire, transport, request = self._durable_request(
            manifest, permit, run_id="run-topology-revoked"
        )
        topology_value = json.loads(self.topology_path.read_text(encoding="utf-8"))
        topology_value["status"] = "REVOKED"
        _write_json(self.topology_path, topology_value)
        try:
            with self.assertRaises(UnsafeRequestError):
                transport.send(
                    request,
                    api_key="offline-mock-credential",
                    request_capability=request_capability,
                )
        finally:
            adapter.release_all_execution_locks()
        self.assertEqual(wire.calls, 0)

    def test_ai_evidence_revocation_after_durable_attempt_fails_before_wire(self) -> None:
        manifest, permit = self._manifest(
            "survey_run",
            "-ai-revoked",
            content_egress="authorized_ai_session",
        )
        adapter, request_capability, wire, transport, request = self._durable_request(
            manifest, permit, run_id="run-ai-revoked"
        )
        self.assertIsNotNone(permit.ai_license_evidence_path)
        self.assertIsNotNone(permit.ai_route_evidence_path)
        license_path = Path(permit.ai_license_evidence_path or "")
        route_path = Path(permit.ai_route_evidence_path or "")
        license_bytes = license_path.read_bytes()
        route_bytes = route_path.read_bytes()
        try:
            route_value = json.loads(route_bytes.decode("utf-8"))
            route_value["status"] = "REVOKED"
            _write_json(route_path, route_value)
            with self.assertRaises(UnsafeRequestError):
                transport.send(
                    request,
                    api_key="offline-mock-credential",
                    request_capability=request_capability,
                )
            self.assertEqual(wire.calls, 0)

            route_path.write_bytes(route_bytes)
            license_value = json.loads(license_bytes.decode("utf-8"))
            license_value["status"] = "REVOKED"
            _write_json(license_path, license_value)
            with self.assertRaises(UnsafeRequestError):
                transport.send(
                    request,
                    api_key="offline-mock-credential",
                    request_capability=request_capability,
                )
        finally:
            adapter.release_all_execution_locks()
        self.assertEqual(wire.calls, 0)


if __name__ == "__main__":
    unittest.main()
