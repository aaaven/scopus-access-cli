"""Offline tests for manifests, policy gates, secrets, and fixed API requests."""

from __future__ import annotations

import dataclasses
import io
import json
import socket
import sqlite3
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from unittest import mock

from scopus_access.client import (
    ElsevierApiClient,
    SEARCH_ENDPOINT,
    TransportRequest,
    TransportResponse,
    USER_AGENT,
    UrllibTransport,
    _issue_request_execution_capability,
    _issue_wire_execution_capability,
)
from scopus_access.errors import (
    AuthenticationRejected,
    LiveCapabilityLocked,
    ManifestValidationError,
    QuotaExceeded,
    Throttled,
    TransportError,
    UnsafeRequestError,
)
from scopus_access.ledger import Ledger
from scopus_access.manifest import execution_control_sha256, load_task_manifest
from scopus_access.ledger import Ledger
from scopus_access.policy import (
    PolicyConfig,
    authorize_live_execution,
    require_execution_authorization,
)
from scopus_access.secrets import SecretValue
from scopus_access.security import canonical_json_bytes, sha256_bytes


FAKE_SECRET = "FAKE_OFFLINE_SECRET_DO_NOT_USE"
SYNTHETIC_QUERY = "SYNTHETIC_PLACEHOLDER_QUERY"


def _write_json(path: Path, value: Mapping[str, Any]) -> str:
    data = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return sha256_bytes(data)


class _MockSecretProvider:
    def __init__(self) -> None:
        self.aliases = []

    def get_api_key(self, api_key_alias: str) -> SecretValue:
        self.aliases.append(api_key_alias)
        return SecretValue(FAKE_SECRET.encode("utf-8"))


class _MockTransport:
    def __init__(
        self,
        *,
        status: int = 200,
        headers: Optional[Mapping[str, str]] = None,
        body: bytes = b'{"synthetic":"response"}',
    ) -> None:
        self.status = status
        self.headers = headers or {
            "X-RateLimit-Limit": "20000",
            "X-RateLimit-Remaining": "19999",
            "X-RateLimit-Reset": "1800000000",
        }
        self.body = body
        self.request: Optional[TransportRequest] = None
        self.wire_capability: Any = None
        self.saw_secret_header = False
        self.safe_repr = ""

    def send(
        self, request: TransportRequest, *, wire_capability: Any = None
    ) -> TransportResponse:
        self.request = request
        self.wire_capability = wire_capability
        self.saw_secret_header = request.headers.get("X-ELS-APIKey") == FAKE_SECRET
        self.safe_repr = repr(request)
        return TransportResponse(self.status, dict(self.headers), self.body)


class ManifestPolicyClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="infra-scopus-offline-")
        self.root = Path(self.temporary.name)
        self.project_a = self.root / "project-a"
        self.project_b = self.root / "project-b"
        (self.project_a / "restricted_metadata").mkdir(parents=True)
        (self.project_b / "restricted_metadata").mkdir(parents=True)
        self.wire_ledger = Ledger(self.root / "wire-control.sqlite")
        # The local-only doctor provisions this immutable identity before a
        # live permit can be issued.
        Ledger(self.root / "central-control.sqlite")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _wire_capability(self, request: TransportRequest):
        instance_id, device, inode = self.wire_ledger.database_identity()
        return _issue_wire_execution_capability(
            request,
            control_database_path=self.wire_ledger.database_path,
            control_database_instance_id=instance_id,
            control_database_device=device,
            control_database_inode=inode,
        )

    def _query_evidence(
        self,
        *,
        project_id: str,
        release_id: str,
        task_id: str,
        task_type: str,
        include_search: bool = True,
        include_abstracts: bool = False,
    ) -> tuple[Path, str]:
        value: Dict[str, Any] = {
            "schema_version": "1.0",
            "project_id": project_id,
            "release_id": release_id,
            "task_id": task_id,
            "task_type": task_type,
        }
        if include_search:
            value["queries"] = {"scopus_search": {"query": SYNTHETIC_QUERY}}
        if include_abstracts:
            value["identifiers"] = {"abstract_retrieval": ["2-s2.0-123456789"]}
        path = self.root / (task_id + "-query.json")
        return path, _write_json(path, value)

    def _release_evidence(
        self,
        *,
        project_id: str,
        release_id: str,
        task_id: str,
        task_type: str,
        synthetic: bool,
        query_hash: str,
        control_hash: str,
    ) -> tuple[Path, str]:
        value = {
            "schema_version": "1.0",
            "evidence_type": "task_release",
            "project_id": project_id,
            "task_id": task_id,
            "task_type": task_type,
            "release_id": release_id,
            "status": "OFFLINE_DEMO_ONLY" if synthetic else "APPROVED",
            "synthetic": synthetic,
            "authority": "SYNTHETIC_TEST" if synthetic else "PI",
            "approved_at_utc": "2025-09-23T00:00:00Z",
            "query_manifest_sha256": query_hash,
            "execution_control_sha256": control_hash,
        }
        path = self.root / (task_id + "-release.json")
        return path, _write_json(path, value)

    def _request(self, *, task_type: str, count: Optional[int] = None) -> Dict[str, Any]:
        if count is None and task_type != "preflight":
            count = 1
        return {
            "api_name": "scopus_search",
            "view": "STANDARD",
            "page_size": 200,
            "pagination_mode": "cursor",
            "anticipated_result_count": count,
            "anticipated_unique_detail_records": 0,
            "forecast_pagination": 1,
            "forecast_detail_retrieval": 0,
            "forecast_validation": 0,
            "retry_allowance": 0,
            "estimated_requests_with_margin": 1,
            "request_limit": 1,
            "assumptions": "One bounded synthetic request.",
            "estimator": "offline-test",
            "estimated_at_utc": "2026-09-23T00:00:00Z",
        }

    def _abstract_request(self) -> Dict[str, Any]:
        return {
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
            "estimated_at_utc": "2026-09-23T00:00:00Z",
        }

    def _policy_mapping(
        self,
        *,
        live: bool = False,
        topology: Optional[Mapping[str, str]] = None,
        ai_grants: Optional[Mapping[str, Any]] = None,
        approved_releases: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        value: Dict[str, Any] = {
            "schema_version": "1.0",
            "project_output_roots": {
                "SYNTHETIC-DEMO": [str(self.project_a)],
                "PROJECT-A": [str(self.project_a)],
                "PROJECT-B": [str(self.project_b)],
            },
            "project_api_key_aliases": {
                "SYNTHETIC-DEMO": {"scopus_search": "synthetic-alias"},
                "PROJECT-A": {
                    "scopus_search": "project-a-search",
                    "abstract_retrieval": "project-a-abstract",
                },
                "PROJECT-B": {"scopus_search": "project-b-search"},
            },
            "live_capability_enabled": live,
            "max_preflight_requests": 1,
        }
        if topology is not None:
            value["license_topology_evidence"] = dict(topology)
        if live:
            value["control_database_path"] = str(self.root / "central-control.sqlite")
            value["approved_release_evidence"] = dict(approved_releases or {})
        if ai_grants is not None:
            value["ai_session_grants"] = dict(ai_grants)
        return value

    @staticmethod
    def _release_registry(manifest_value: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            str(manifest_value["project_id"]): {
                str(manifest_value["release_id"]): {
                    "path": str(manifest_value["release_evidence_path"]),
                    "sha256": str(manifest_value["release_evidence_sha256"]),
                }
            }
        }

    def _manifest_file(
        self,
        *,
        project_id: str = "SYNTHETIC-DEMO",
        task_id: str = "offline-preflight",
        release_id: str = "release-001",
        task_type: str = "preflight",
        synthetic: bool = True,
        output: Optional[Path] = None,
        content_egress: str = "control_only",
        requests: Optional[list[Dict[str, Any]]] = None,
        include_abstracts: bool = False,
    ) -> tuple[Path, Dict[str, Any]]:
        request_values = requests or [self._request(task_type=task_type)]
        query_path, query_hash = self._query_evidence(
            project_id=project_id,
            release_id=release_id,
            task_id=task_id,
            task_type=task_type,
            include_search=any(
                request["api_name"] == "scopus_search" for request in request_values
            ),
            include_abstracts=include_abstracts,
        )
        output_path = output or (self.project_a / "restricted_metadata")
        control_hash = execution_control_sha256(
            project_id=project_id,
            task_id=task_id,
            task_type=task_type,
            release_id=release_id,
            query_manifest_sha256=query_hash,
            requests=request_values,
            project_output_dir=output_path,
            content_egress=content_egress,
        )
        release_path, release_hash = self._release_evidence(
            project_id=project_id,
            release_id=release_id,
            task_id=task_id,
            task_type=task_type,
            synthetic=synthetic,
            query_hash=query_hash,
            control_hash=control_hash,
        )
        value: Dict[str, Any] = {
            "schema_version": "1.0",
            "project_id": project_id,
            "task_id": task_id,
            "task_type": task_type,
            "release_id": release_id,
            "release_evidence_path": str(release_path),
            "release_evidence_sha256": release_hash,
            "query_manifest_path": str(query_path),
            "query_manifest_sha256": query_hash,
            "requests": request_values,
            "project_output_dir": str(output_path),
            "content_egress": content_egress,
        }
        path = self.root / (task_id + "-task.json")
        _write_json(path, value)
        return path, value

    def _topology_pin(self) -> Dict[str, str]:
        path = self.root / "topology.json"
        digest = _write_json(
            path,
            {
                "schema_version": "1.0",
                "evidence_type": "single_controller_license_topology",
                "status": "CONFIRMED",
                "application_name": "UAEU Survey Research Access Layer",
                "single_authorized_user": True,
                "single_application_use_case": True,
            },
        )
        return {"path": str(path), "sha256": digest}

    def _real_preflight(self) -> tuple[Any, PolicyConfig]:
        manifest_path, manifest_value = self._manifest_file(
            project_id="PROJECT-A",
            task_id="real-preflight",
            release_id="real-release",
            task_type="preflight",
            synthetic=False,
        )
        policy = PolicyConfig.from_mapping(
            self._policy_mapping(
                live=True,
                topology=self._topology_pin(),
                approved_releases=self._release_registry(manifest_value),
            ),
            base_dir=self.root,
        )
        return load_task_manifest(str(manifest_path), policy), policy

    @staticmethod
    def _charged_client_context(manifest: Any, permit: Any, api_name: str):
        plan = manifest.request_for_api(api_name)
        context = {
            "attempt_id": "unit-run.p1.a1",
            "reservation_id": "unit-reservation",
            "run_id": "unit-run",
            "api_name": api_name,
            "endpoint_class": api_name,
            "view": plan.view,
            "page_size": plan.page_size,
            "page_number": 1,
            "retry_number": 0,
        }
        capability = _issue_request_execution_capability(
            project_id=manifest.project_id,
            task_id=manifest.task_id,
            release_id=manifest.release_id,
            api_key_alias=permit.key_aliases[api_name],
            query_manifest_sha256=manifest.query_manifest_sha256,
            execution_control_sha256=manifest.execution_control_sha256,
            control_database_path=permit.control_database_path,
            control_database_instance_id=permit.control_database_instance_id,
            control_database_device=permit.control_database_device,
            control_database_inode=permit.control_database_inode,
            release_evidence_path=str(manifest.release_evidence.path),
            release_evidence_sha256=manifest.release_evidence.sha256,
            release_approved_at_utc=manifest.release_evidence.approved_at_utc,
            release_expires_at_utc=manifest.release_evidence.expires_at_utc,
            topology_evidence_path=permit.topology_evidence_path,
            topology_evidence_sha256=permit.topology_evidence_sha256,
            ai_license_evidence_path=permit.ai_license_evidence_path,
            ai_license_evidence_sha256=permit.ai_license_evidence_sha256,
            ai_route_evidence_path=permit.ai_route_evidence_path,
            ai_route_evidence_sha256=permit.ai_route_evidence_sha256,
            **context,
        )
        return capability, context

    def test_synthetic_manifest_valid_structurally_but_live_locked(self) -> None:
        path, _ = self._manifest_file()
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        manifest = load_task_manifest(str(path), policy)
        summary = manifest.control_summary()
        self.assertEqual(summary["project_id"], "SYNTHETIC-DEMO")
        self.assertNotIn(SYNTHETIC_QUERY, json.dumps(summary))
        self.assertNotIn("alias", json.dumps(summary))
        with self.assertRaises(LiveCapabilityLocked):
            authorize_live_execution(manifest, policy, explicit_cli_consent=True)

    def test_pending_operator_placeholder_cannot_receive_live_authorization(self):
        with mock.patch(__name__ + ".SYNTHETIC_QUERY", "PENDING_OPERATOR_SELECTED_QUERY"):
            manifest, policy = self._real_preflight()
        with self.assertRaisesRegex(LiveCapabilityLocked, "real operator-selected"):
            authorize_live_execution(manifest, policy, explicit_cli_consent=True)

    def test_manifest_rejects_embedded_key_or_alias(self) -> None:
        path, value = self._manifest_file()
        value["api_key_alias"] = "not-allowed"
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaises(ManifestValidationError) as raised:
            load_task_manifest(str(path), policy)
        self.assertNotIn("not-allowed", str(raised.exception))

    def test_release_and_query_hashes_are_enforced(self) -> None:
        path, value = self._manifest_file()
        value["query_manifest_sha256"] = "0" * 64
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaisesRegex(ManifestValidationError, "hash"):
            load_task_manifest(str(path), policy)

    def test_release_digest_binds_query_and_every_execution_control(self) -> None:
        path, value = self._manifest_file(
            project_id="PROJECT-A",
            task_id="bound-task",
            release_id="bound-release",
            task_type="preflight",
            synthetic=False,
        )
        query_path = Path(value["query_manifest_path"])
        query_value = json.loads(query_path.read_text(encoding="utf-8"))
        query_value["queries"]["scopus_search"]["query"] = "DIFFERENT_UNRELEASED_QUERY"
        value["query_manifest_sha256"] = _write_json(query_path, query_value)
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaisesRegex(ManifestValidationError, "frozen query digest"):
            load_task_manifest(str(path), policy)

        path2, value2 = self._manifest_file(
            project_id="PROJECT-A",
            task_id="bound-controls",
            release_id="bound-controls-release",
            task_type="preflight",
            synthetic=False,
        )
        value2["requests"][0]["page_size"] = 1
        _write_json(path2, value2)
        with self.assertRaisesRegex(ManifestValidationError, "execution controls"):
            load_task_manifest(str(path2), policy)

    def test_query_package_rejects_unlicensed_content_fields(self) -> None:
        path, value = self._manifest_file()
        query_path = Path(value["query_manifest_path"])
        query_value = json.loads(query_path.read_text(encoding="utf-8"))
        query_value["payload"] = {"title": "licensed content must not be here"}
        query_hash = _write_json(query_path, query_value)
        value["query_manifest_sha256"] = query_hash
        release_path = Path(value["release_evidence_path"])
        release_value = json.loads(release_path.read_text(encoding="utf-8"))
        release_value["query_manifest_sha256"] = query_hash
        release_value["execution_control_sha256"] = execution_control_sha256(
            project_id=value["project_id"],
            task_id=value["task_id"],
            task_type=value["task_type"],
            release_id=value["release_id"],
            query_manifest_sha256=query_hash,
            requests=value["requests"],
            project_output_dir=value["project_output_dir"],
            content_egress=value["content_egress"],
        )
        value["release_evidence_sha256"] = _write_json(
            release_path, release_value
        )
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaises(ManifestValidationError):
            load_task_manifest(str(path), policy)

    def test_release_task_type_must_match(self) -> None:
        path, value = self._manifest_file()
        value["task_type"] = "survey_run"
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaises(ManifestValidationError):
            load_task_manifest(str(path), policy)

    def test_view_page_size_and_non_cursor_ceiling(self) -> None:
        request = self._request(task_type="preflight", count=5001)
        request["pagination_mode"] = "offset"
        request["forecast_pagination"] = 26
        request["estimated_requests_with_margin"] = 26
        request["request_limit"] = 26
        path, _ = self._manifest_file(requests=[request])
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaisesRegex(ManifestValidationError, "ceiling"):
            load_task_manifest(str(path), policy)

        request["anticipated_result_count"] = 1
        request["forecast_pagination"] = 1
        request["estimated_requests_with_margin"] = 1
        request["request_limit"] = 1
        request["page_size"] = 201
        path, _ = self._manifest_file(requests=[request])
        with self.assertRaisesRegex(ManifestValidationError, "Page size"):
            load_task_manifest(str(path), policy)

    def test_project_scoped_output_roots_reject_cross_project_path(self) -> None:
        path, _ = self._manifest_file(
            project_id="PROJECT-A",
            task_id="cross-project",
            release_id="cross-release",
            task_type="survey_run",
            synthetic=False,
            output=self.project_b / "restricted_metadata",
        )
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaisesRegex(ManifestValidationError, "allow-list"):
            load_task_manifest(str(path), policy)

    def test_global_output_root_list_is_rejected(self) -> None:
        value = self._policy_mapping()
        value["allowed_output_roots"] = [str(self.project_a)]
        del value["project_output_roots"]
        with self.assertRaisesRegex(Exception, "project-scoped"):
            PolicyConfig.from_mapping(value, base_dir=self.root)

    def test_output_traversal_and_symlink_are_rejected(self) -> None:
        traversal = str(self.project_a / ".." / "project-b" / "restricted_metadata")
        path, value = self._manifest_file()
        value["project_output_dir"] = traversal
        _write_json(path, value)
        policy = PolicyConfig.from_mapping(self._policy_mapping(), base_dir=self.root)
        with self.assertRaises(ManifestValidationError):
            load_task_manifest(str(path), policy)

        link = self.project_a / "escape"
        link.symlink_to(self.project_b, target_is_directory=True)
        value["project_output_dir"] = str(link / "restricted_metadata")
        _write_json(path, value)
        with self.assertRaisesRegex(ManifestValidationError, "Symlink"):
            load_task_manifest(str(path), policy)

    def test_authorized_ai_session_requires_two_independent_evidence_files(self) -> None:
        project_id = "PROJECT-A"
        release_id = "ai-release"
        license_path = self.root / "ai-license.json"
        route_path = self.root / "ai-route.json"
        license_hash = _write_json(
            license_path,
            {
                "schema_version": "1.0",
                "evidence_type": "licensed_content_ai_egress",
                "status": "CONFIRMED",
                "project_id": project_id,
                "release_id": release_id,
            },
        )
        route_hash = _write_json(
            route_path,
            {
                "schema_version": "1.0",
                "evidence_type": "authorized_ai_session_route",
                "status": "APPROVED",
                "project_id": project_id,
                "release_id": release_id,
            },
        )
        grants = {
            project_id: {
                "license_evidence": {"path": str(license_path), "sha256": license_hash},
                "route_approval_evidence": {"path": str(route_path), "sha256": route_hash},
                "release_ids": [release_id],
            }
        }
        policy = PolicyConfig.from_mapping(
            self._policy_mapping(ai_grants=grants), base_dir=self.root
        )
        path, _ = self._manifest_file(
            project_id=project_id,
            task_id="ai-task",
            release_id=release_id,
            task_type="survey_run",
            synthetic=False,
            content_egress="authorized_ai_session",
        )
        manifest = load_task_manifest(str(path), policy)
        self.assertEqual(manifest.content_egress, "authorized_ai_session")

        route_path.write_text("{}", encoding="utf-8")
        with self.assertRaises(ManifestValidationError):
            load_task_manifest(str(path), policy)

    def test_live_gate_requires_policy_topology_release_and_explicit_consent(self) -> None:
        manifest, policy = self._real_preflight()
        with self.assertRaisesRegex(LiveCapabilityLocked, "consent"):
            authorize_live_execution(manifest, policy, explicit_cli_consent=False)
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        self.assertEqual(permit.key_aliases["scopus_search"], "project-a-search")
        self.assertNotIn(FAKE_SECRET, repr(permit))

    def test_live_gate_requires_preprovisioned_database_and_seals_identity(self) -> None:
        manifest, policy = self._real_preflight()
        unprovisioned_path = self.root / "unprovisioned-control.sqlite"
        unprovisioned = dataclasses.replace(
            policy, control_database_path=unprovisioned_path
        )
        with self.assertRaisesRegex(LiveCapabilityLocked, "not provisioned"):
            authorize_live_execution(
                manifest, unprovisioned, explicit_cli_consent=True
            )
        self.assertFalse(unprovisioned_path.exists())

        permit = authorize_live_execution(
            manifest, policy, explicit_cli_consent=True
        )
        with self.assertRaises(LiveCapabilityLocked):
            require_execution_authorization(
                dataclasses.replace(
                    permit,
                    control_database_inode=permit.control_database_inode + 1,
                )
            )

    def test_live_gate_requires_trusted_release_registry_and_current_approval(self) -> None:
        manifest_path, manifest_value = self._manifest_file(
            project_id="PROJECT-A",
            task_id="registry-task",
            release_id="registry-release",
            task_type="preflight",
            synthetic=False,
        )
        untrusted_policy = PolicyConfig.from_mapping(
            self._policy_mapping(live=True, topology=self._topology_pin()),
            base_dir=self.root,
        )
        manifest = load_task_manifest(str(manifest_path), untrusted_policy)
        with self.assertRaisesRegex(LiveCapabilityLocked, "trusted policy registry"):
            authorize_live_execution(
                manifest, untrusted_policy, explicit_cli_consent=True
            )

        release_path = Path(manifest_value["release_evidence_path"])
        release_value = json.loads(release_path.read_text(encoding="utf-8"))
        release_value["approved_at_utc"] = "2099-01-01T00:00:00Z"
        release_hash = _write_json(release_path, release_value)
        manifest_value["release_evidence_sha256"] = release_hash
        _write_json(manifest_path, manifest_value)
        future_policy = PolicyConfig.from_mapping(
            self._policy_mapping(
                live=True,
                topology=self._topology_pin(),
                approved_releases={
                    "PROJECT-A": {
                        "registry-release": {
                            "path": str(release_path),
                            "sha256": release_hash,
                        }
                    }
                },
            ),
            base_dir=self.root,
        )
        future_manifest = load_task_manifest(str(manifest_path), future_policy)
        with self.assertRaisesRegex(LiveCapabilityLocked, "currently effective"):
            authorize_live_execution(
                future_manifest, future_policy, explicit_cli_consent=True
            )

    def test_live_gate_rechecks_pinned_evidence_before_issuing_permit(self) -> None:
        manifest, policy = self._real_preflight()
        manifest.release_evidence.path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(LiveCapabilityLocked, "changed"):
            authorize_live_execution(manifest, policy, explicit_cli_consent=True)

    def test_client_uses_only_frozen_query_and_clears_secret_header(self) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        secret_provider = _MockSecretProvider()
        transport = _MockTransport(body=b'{"entry":[{"title":"never in repr"}]}')
        capability, context = self._charged_client_context(
            manifest, permit, "scopus_search"
        )
        client = ElsevierApiClient(
            secret_provider=secret_provider,
            transport=transport,
            authorization=permit,
            request_capability=capability,
            request_context=context,
        )
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            response = client.search(manifest)
        self.assertTrue(transport.saw_secret_header)
        self.assertIsNotNone(transport.wire_capability)
        self.assertNotIn(FAKE_SECRET, repr(transport.wire_capability))
        self.assertEqual(secret_provider.aliases, ["project-a-search"])
        self.assertNotIn(SYNTHETIC_QUERY, transport.safe_repr)
        self.assertNotIn(FAKE_SECRET, transport.safe_repr)
        self.assertNotIn("title", repr(response))
        self.assertEqual(transport.request.headers, {})  # type: ignore[union-attr]
        self.assertEqual(response.control_headers["x-ratelimit-remaining"], "19999")

    def test_client_fails_closed_for_auth_quota_and_throttle(self) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)

        def call(status: int, headers: Mapping[str, str]) -> None:
            capability, context = self._charged_client_context(
                manifest, permit, "scopus_search"
            )
            client = ElsevierApiClient(
                secret_provider=_MockSecretProvider(),
                transport=_MockTransport(status=status, headers=headers),
                authorization=permit,
                request_capability=capability,
                request_context=context,
            )
            client.search(manifest)

        for status in (401, 403):
            with self.assertRaises(AuthenticationRejected):
                call(status, {})
        with self.assertRaises(QuotaExceeded):
            call(429, {"X-ELS-Status": "QUOTA_EXCEEDED"})
        with self.assertRaises(Throttled) as raised:
            call(429, {"Retry-After": "2"})
        self.assertEqual(raised.exception.retry_after_seconds, 2.0)
        for error in (str(raised.exception), repr(raised.exception)):
            self.assertNotIn(FAKE_SECRET, error)
            self.assertNotIn(SYNTHETIC_QUERY, error)

    def test_client_suppresses_untrusted_transport_exception_text(self) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)

        class LeakyTransport:
            def send(
                self, request: TransportRequest, *, wire_capability: Any = None
            ) -> TransportResponse:
                raise RuntimeError(FAKE_SECRET + SYNTHETIC_QUERY)

        capability, context = self._charged_client_context(
            manifest, permit, "scopus_search"
        )
        client = ElsevierApiClient(
            secret_provider=_MockSecretProvider(),
            transport=LeakyTransport(),
            authorization=permit,
            request_capability=capability,
            request_context=context,
        )
        with self.assertRaises(TransportError) as raised:
            client.search(manifest)
        self.assertNotIn(FAKE_SECRET, str(raised.exception))
        self.assertNotIn(SYNTHETIC_QUERY, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_abstract_client_uses_only_pinned_identifier_by_ordinal(self) -> None:
        manifest_path, manifest_value = self._manifest_file(
            project_id="PROJECT-A",
            task_id="abstract-preflight",
            release_id="abstract-release",
            task_type="preflight",
            synthetic=False,
            requests=[self._abstract_request()],
            include_abstracts=True,
        )
        policy = PolicyConfig.from_mapping(
            self._policy_mapping(
                live=True,
                topology=self._topology_pin(),
                approved_releases=self._release_registry(manifest_value),
            ),
            base_dir=self.root,
        )
        manifest = load_task_manifest(str(manifest_path), policy)
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        provider = _MockSecretProvider()
        transport = _MockTransport()
        capability, context = self._charged_client_context(
            manifest, permit, "abstract_retrieval"
        )
        client = ElsevierApiClient(
            secret_provider=provider,
            transport=transport,
            authorization=permit,
            request_capability=capability,
            request_context=context,
        )
        response = client.retrieve_abstract(manifest, ordinal=0)
        self.assertEqual(response.status, 200)
        self.assertEqual(provider.aliases, ["project-a-abstract"])
        self.assertNotIn("2-s2.0-123456789", transport.safe_repr)
        with self.assertRaises(UnsafeRequestError):
            client.retrieve_abstract(manifest, ordinal=1)
        self.assertEqual(provider.aliases, ["project-a-abstract"])

    def test_direct_client_without_durable_attempt_capability_cannot_send(self) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        provider = _MockSecretProvider()
        transport = _MockTransport()
        client = ElsevierApiClient(
            secret_provider=provider,
            transport=transport,
            authorization=permit,
        )
        with self.assertRaisesRegex(UnsafeRequestError, "durable request capability"):
            client.search(manifest)
        self.assertEqual(provider.aliases, [])
        self.assertIsNone(transport.request)
        self.assertTrue(Path(permit.control_database_path).is_file())

    def test_request_capability_rejects_cross_run_context_before_secret_or_wire(
        self,
    ) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        capability, context = self._charged_client_context(
            manifest, permit, "scopus_search"
        )
        for field, value in (
            ("attempt_id", "other-run.p1.a1"),
            ("reservation_id", "other-reservation"),
            ("run_id", "other-run"),
        ):
            provider = _MockSecretProvider()
            transport = _MockTransport()
            changed = dict(context)
            changed[field] = value
            client = ElsevierApiClient(
                secret_provider=provider,
                transport=transport,
                authorization=permit,
                request_capability=capability,
                request_context=changed,
            )
            with self.assertRaisesRegex(UnsafeRequestError, "does not match"):
                client.search(manifest)
            self.assertEqual(provider.aliases, [])
            self.assertIsNone(transport.request)

    def test_client_rechecks_controls_after_authorization_before_send(self) -> None:
        manifest, policy = self._real_preflight()
        permit = authorize_live_execution(manifest, policy, explicit_cli_consent=True)
        capability, context = self._charged_client_context(
            manifest, permit, "scopus_search"
        )
        mutated_plan = dataclasses.replace(manifest.requests[0], page_size=1)
        mutated = dataclasses.replace(manifest, requests=(mutated_plan,))
        provider = _MockSecretProvider()
        transport = _MockTransport()
        client = ElsevierApiClient(
            secret_provider=provider,
            transport=transport,
            authorization=permit,
            request_capability=capability,
            request_context=context,
        )
        with self.assertRaises(UnsafeRequestError):
            client.search(mutated)
        self.assertEqual(provider.aliases, [])
        self.assertIsNone(transport.request)

    def test_transport_rejects_arbitrary_url_before_network(self) -> None:
        transport = UrllibTransport()
        request = TransportRequest(
            method="GET",
            url="https://example.invalid/content/search/scopus?query=x&view=STANDARD&count=1&cursor=*",
            headers={
                "Accept": "application/json",
                "User-Agent": "UAEU-Survey-Research-Access-Layer/1.0",
                "X-ELS-APIKey": FAKE_SECRET,
            },
        )
        capability = self._wire_capability(request)
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            with self.assertRaises(UnsafeRequestError):
                transport.send(request, wire_capability=capability)

    def test_transport_rejects_direct_send_without_wire_capability(self) -> None:
        transport = UrllibTransport()
        request = TransportRequest(
            method="GET",
            url=(
                SEARCH_ENDPOINT
                + "?query=SYNTHETIC&view=STANDARD&count=1&cursor=%2A"
            ),
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "X-ELS-APIKey": FAKE_SECRET,
            },
        )
        with mock.patch.object(
            transport._opener, "open", side_effect=AssertionError("network")
        ) as network:
            with self.assertRaisesRegex(UnsafeRequestError, "wire capability"):
                transport.send(request)
        network.assert_not_called()

        class HostileRequest:
            @property
            def method(self):
                raise AssertionError("request state was read without a capability")

        with self.assertRaisesRegex(UnsafeRequestError, "wire capability"):
            transport.send(HostileRequest())  # type: ignore[arg-type]

    def test_malformed_query_error_does_not_echo_query_content(self) -> None:
        sentinel = "LICENSED_TITLE_SENTINEL"
        transport = UrllibTransport()
        request = TransportRequest(
            method="GET",
            url=SEARCH_ENDPOINT + "?" + sentinel,
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "X-ELS-APIKey": FAKE_SECRET,
            },
        )
        capability = self._wire_capability(request)
        with self.assertRaises(UnsafeRequestError) as raised:
            transport.send(request, wire_capability=capability)
        self.assertNotIn(sentinel, str(raised.exception))

    def test_wire_capability_is_request_bound_and_one_use(self) -> None:
        transport = UrllibTransport()
        request = TransportRequest(
            method="GET",
            url=(
                SEARCH_ENDPOINT
                + "?query=SYNTHETIC&view=STANDARD&count=1&cursor=%2A"
            ),
            headers={
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
                "X-ELS-APIKey": FAKE_SECRET,
            },
        )

        class Response:
            status = 200
            headers: Mapping[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return None

            def read(self, limit):
                return b"{}"

        capability = self._wire_capability(request)
        with mock.patch.object(
            transport._opener, "open", return_value=Response()
        ) as network:
            response = transport.send(request, wire_capability=capability)
            self.assertEqual(response.status, 200)
            with self.assertRaisesRegex(UnsafeRequestError, "already consumed"):
                transport.send(request, wire_capability=capability)
        self.assertEqual(network.call_count, 1)

        changed = TransportRequest(
            method=request.method,
            url=request.url.replace("count=1", "count=2"),
            headers=dict(request.headers),
        )
        bound = self._wire_capability(request)
        with mock.patch.object(
            transport._opener, "open", side_effect=AssertionError("network")
        ) as network:
            with self.assertRaisesRegex(UnsafeRequestError, "does not match"):
                transport.send(changed, wire_capability=bound)
        network.assert_not_called()

        tampered = self._wire_capability(request)
        tampered._request_sha256 = "0" * 64
        with mock.patch.object(
            transport._opener, "open", side_effect=AssertionError("network")
        ) as network:
            with self.assertRaisesRegex(UnsafeRequestError, "does not match"):
                transport.send(request, wire_capability=tampered)
        network.assert_not_called()

        late_identity = self._wire_capability(request)
        replacement = Ledger(self.root / "wire-replacement.sqlite")
        with sqlite3.connect(replacement.database_path) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        Path(replacement.database_path).replace(
            Path(self.wire_ledger.database_path)
        )
        with mock.patch.object(
            transport._opener, "open", side_effect=AssertionError("network")
        ) as network:
            with self.assertRaisesRegex(UnsafeRequestError, "database identity"):
                transport.send(request, wire_capability=late_identity)
        network.assert_not_called()

    def test_production_transport_ignores_environment_proxies(self) -> None:
        with mock.patch.dict(
            "os.environ", {"HTTPS_PROXY": "http://127.0.0.1:43210"}, clear=False
        ):
            transport = UrllibTransport()
        proxy_handlers = [
            handler
            for handler in transport._opener.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        # An explicit empty ProxyHandler suppresses build_opener's default
        # environment-derived handler; urllib omits the empty handler itself.
        self.assertEqual(proxy_handlers, [])

    def test_transport_validates_and_uses_one_immutable_request_snapshot(self) -> None:
        good_url = (
            SEARCH_ENDPOINT
            + "?query=SYNTHETIC&view=STANDARD&count=1&cursor=%2A"
        )
        good_headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-ELS-APIKey": FAKE_SECRET,
        }

        class FlippingRequest:
            method = "GET"

            def __init__(self) -> None:
                self.url_reads = 0
                self.header_reads = 0

            @property
            def url(self):
                self.url_reads += 1
                return good_url if self.url_reads == 1 else "https://example.invalid/"

            @property
            def headers(self):
                self.header_reads += 1
                if self.header_reads == 1:
                    return good_headers
                return {**good_headers, "Authorization": "must-not-reach-wire"}

        class Response:
            status = 200
            headers: Mapping[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return None

            def read(self, limit):
                return b"{}"

        class CaptureOpener:
            def __init__(self) -> None:
                self.request = None

            def open(self, request, timeout):
                self.request = request
                self.headers_at_open = {key.lower(): value for key, value in request.header_items()}
                return Response()

        transport = UrllibTransport()
        capture = CaptureOpener()
        transport._opener = capture
        source = FlippingRequest()
        capability = self._wire_capability(
            TransportRequest(method="GET", url=good_url, headers=good_headers)
        )
        response = transport.send(  # type: ignore[arg-type]
            source, wire_capability=capability
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(source.url_reads, 1)
        self.assertEqual(source.header_reads, 1)
        self.assertEqual(capture.request.full_url, good_url)
        wire_headers = capture.headers_at_open
        self.assertNotIn("authorization", wire_headers)
        self.assertEqual(wire_headers["x-els-apikey"], FAKE_SECRET)
        self.assertEqual(wire_headers["accept"], "application/json")
        self.assertEqual(capture.request.get_method(), "GET")
        self.assertEqual(capture.request.header_items(), [])

    def test_http_error_status_is_preserved_by_real_urllib_request_construction(self) -> None:
        request = TransportRequest(
            method="GET", url=SEARCH_ENDPOINT + "?query=SYNTHETIC&view=STANDARD&count=1&start=0",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT,
                     "X-ELS-APIKey": FAKE_SECRET},
        )
        for status in (401, 403):
            with self.subTest(status=status):
                captured = []
                body = b'{"error-response":{"error-code":"AUTHORIZATION_ERROR"}}'

                class Opener:
                    def open(self, outgoing, timeout):
                        captured.append(outgoing)
                        assert dict((k.lower(),v) for k,v in outgoing.header_items())["x-els-apikey"] == FAKE_SECRET
                        raise urllib.error.HTTPError(
                            outgoing.full_url, status, "mock rejection", {}, io.BytesIO(body)
                        )

                transport = UrllibTransport()
                transport._opener = Opener()
                response = transport.send(request, wire_capability=self._wire_capability(request))
                self.assertEqual(response.status, status)
                self.assertEqual(response.body, body)
                self.assertEqual(captured[0].header_items(), [])
                self.assertEqual(captured[0].full_url, request.url)

    def test_secret_value_repr_is_redacted_and_close_is_final(self) -> None:
        secret = SecretValue(FAKE_SECRET.encode("utf-8"))
        self.assertNotIn(FAKE_SECRET, repr(secret))
        self.assertEqual(str(secret), "<redacted>")
        self.assertEqual(secret.reveal(), FAKE_SECRET)
        secret.close()
        with self.assertRaises(Exception) as raised:
            secret.reveal()
        self.assertNotIn(FAKE_SECRET, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
