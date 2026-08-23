#!/usr/bin/env python3
"""Adversarial RED tests for the public/private and side-effect boundary."""

from __future__ import annotations

from dataclasses import fields
import importlib
import inspect
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_authority_store import (  # noqa: E402
    AuthorityStatusOperationEntry,
    AuthorityStatusProjectionInspection,
)
from ask_herdr_project_read_epoch import ProjectReadEpoch  # noqa: E402
from ask_herdr_project_status import (  # noqa: E402
    ProjectStatusInspection,
    ProjectStatusLaneHead,
    ProjectStatusOperationMetadata,
)
from ask_herdr_topology_store import (  # noqa: E402
    TopologyStatusOperationEntry,
    TopologyStatusProjectionInspection,
)


UUID = "123e4567-e89b-42d3-a456-426614174000"
AUTHORITY_ID = "123e4567-e89b-42d3-a456-426614174002"
LANE_ID = "123e4567-e89b-42d3-a456-426614174001"
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64
OBSERVED_AT = "2026-08-22T01:02:03Z"


def _public_module():
    try:
        return importlib.import_module("ask_herdr_public_status")
    except ModuleNotFoundError as error:
        raise AssertionError(
            "RED: ask_herdr_public_status is absent; "
            "the explicit public/private adapter is not implemented"
        ) from error


def _selector(kind="operation"):
    selector = {
        "schema": "ask_herdr.query.status.selector.v1",
        "kind": kind,
    }
    if kind == "operation":
        selector["operation_id"] = UUID
    elif kind == "lane":
        selector["lane_id"] = LANE_ID
    elif kind == "key":
        selector["consultant_key"] = "biology"
    return selector


def _epoch():
    return ProjectReadEpoch(
        schema="ask_herdr.project_read_epoch.v1",
        project_authority_id=AUTHORITY_ID,
        authority_store_head_digest=DIGEST,
        project_state_digest=REQUEST_DIGEST,
        lane_index_digest=DIGEST,
        topology_ledger_head_digest=DIGEST,
        observed_at=OBSERVED_AT,
        acquisition_attempt=1,
        epoch_digest=DIGEST,
    )


def _lane():
    return ProjectStatusLaneHead(
        lane_id=LANE_ID,
        lane_generation=1,
        lane_binding_digest=DIGEST,
        event_sequence=7,
        event_digest=REQUEST_DIGEST,
        state_digest=DIGEST,
        response_digest=None,
    )


def _private_operation_metadata():
    return ProjectStatusOperationMetadata(
        operation_id=UUID,
        operation="turn.consult",
        canonical_request_digest=REQUEST_DIGEST,
        authority_record_digest="PRIVATE_AUTHORITY_RECORD_DIGEST",
        lane_association="bound",
    )


def _inspection(*, detail_code="private_store.internal_secret", entries=(), metadata=None):
    return ProjectStatusInspection(
        status="active",
        detail_code=detail_code,
        normalized_read_contract_digest=DIGEST,
        project_read_epoch=_epoch(),
        entries=tuple(entries),
        next_cursor="mcv1.safe-cursor",
        operation_metadata=metadata,
    )


def _request(root="/private/secret/PROJECT_ROOT_CANARY"):
    return {
        "schema": "ask_herdr.request.v1",
        "operation": "query.status",
        "operation_id": UUID,
        "project": {
            "schema": "ask_herdr.project_binding.v1",
            "binding": "bound",
            "root": root,
            "authority_id": AUTHORITY_ID,
        },
        "payload": {
            "selector": _selector("operation"),
            "advisory": "none",
            "limit": 1,
            "cursor": None,
        },
        "observation": {
            "schema": "ask_herdr.observation.v1",
            "mode": "immediate",
            "timeout_ms": None,
        },
    }


class PublicPrivateLeakTest(unittest.TestCase):
    def test_existing_frozen_private_projection_dataclass_shapes_are_unchanged(self):
        self.assertEqual(
            [field.name for field in fields(ProjectStatusLaneHead)],
            [
                "lane_id",
                "lane_generation",
                "lane_binding_digest",
                "event_sequence",
                "event_digest",
                "state_digest",
                "response_digest",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(ProjectStatusOperationMetadata)],
            [
                "operation_id",
                "operation",
                "canonical_request_digest",
                "authority_record_digest",
                "lane_association",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(ProjectStatusInspection)],
            [
                "status",
                "detail_code",
                "normalized_read_contract_digest",
                "project_read_epoch",
                "entries",
                "next_cursor",
                "operation_metadata",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(ProjectReadEpoch)],
            [
                "schema",
                "project_authority_id",
                "authority_store_head_digest",
                "project_state_digest",
                "lane_index_digest",
                "topology_ledger_head_digest",
                "observed_at",
                "acquisition_attempt",
                "epoch_digest",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(AuthorityStatusProjectionInspection)],
            [
                "status",
                "detail_code",
                "authority_store_head_digest",
                "operation_entries",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(TopologyStatusProjectionInspection)],
            [
                "status",
                "detail_code",
                "topology_ledger_head_digest",
                "key_entries",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(AuthorityStatusOperationEntry)],
            [
                "operation_id",
                "operation",
                "canonical_request_digest",
                "authority_record_digest",
                "lane_scope",
                "lane_id",
                "lane_generation",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(TopologyStatusOperationEntry)],
            [
                "operation_id",
                "canonical_request_digest",
                "policy_record_digest",
                "lane_id",
                "lane_generation",
                "lane_binding_digest",
            ],
        )

    def test_adapter_projects_explicit_public_fields_and_excludes_private_digest(self):
        module = _public_module()
        adapter = getattr(module, "adapt_status", None)
        if not callable(adapter):
            raise AssertionError("ask_herdr_public_status must expose adapt_status")
        result = adapter(
            _inspection(entries=(_lane(),), metadata=_private_operation_metadata()),
            _selector("operation"),
        )
        self.assertEqual(
            list(result),
            [
                "schema",
                "selector",
                "read_status",
                "detail_code",
                "normalized_read_contract_digest",
                "project_read_epoch",
                "entries",
                "next_cursor",
                "operation_metadata",
            ],
        )
        self.assertEqual(
            list(result["operation_metadata"]),
            [
                "operation_id",
                "operation",
                "canonical_request_digest",
                "lane_association",
            ],
        )
        self.assertNotIn(
            "authority_record_digest", result["operation_metadata"]
        )

    def test_path_filesystem_access_credential_token_record_and_evidence_canaries_stay_out(self):
        module = _public_module()
        adapter = getattr(module, "adapt_status", None)
        if not callable(adapter):
            raise AssertionError("ask_herdr_public_status must expose adapt_status")
        result = adapter(
            _inspection(
                detail_code=(
                    "private_store.path=/private/secret/ROOT "
                    "ACCESS_ID_CANARY filesystem_device=7 "
                    "CREDENTIAL_CANARY TOKEN_CANARY "
                    "RAW_PRIVATE_RECORD_CANARY EVIDENCE_BYTES_CANARY"
                ),
                entries=(_lane(),),
                metadata=_private_operation_metadata(),
            ),
            _selector("operation"),
        )
        serialized = json.dumps(result, sort_keys=True)
        for canary in (
            "PRIVATE_AUTHORITY_RECORD_DIGEST",
            "PROJECT_ROOT_CANARY",
            "filesystem_device",
            "filesystem_inode",
            "ACCESS_ID_CANARY",
            "CREDENTIAL_CANARY",
            "TOKEN_CANARY",
            "RAW_PRIVATE_RECORD_CANARY",
            "EVIDENCE_BYTES_CANARY",
        ):
            with self.subTest(canary=canary):
                self.assertNotIn(canary, serialized)

    def test_diagnostics_redact_private_exception_and_caller_values(self):
        module = _public_module()
        dispatch = getattr(module, "dispatch_query_status", None)
        if not callable(dispatch):
            raise AssertionError(
                "ask_herdr_public_status must expose dispatch_query_status"
            )
        secret = (
            "/private/secret/PROJECT_ROOT_CANARY "
            "caller=CALLER_SECRET credential=CREDENTIAL_CANARY"
        )
        with mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("provider process")
        ), mock.patch.object(
            socket, "socket", side_effect=AssertionError("network")
        ):
            outcome = dispatch(
                _request(),
                project_inspector=mock.Mock(side_effect=RuntimeError(secret)),
                status_readers={
                    kind: mock.Mock() for kind in ("project", "lane", "key", "operation")
                },
                clock=lambda: OBSERVED_AT,
            )
        serialized = json.dumps(outcome, sort_keys=True)
        for canary in (
            "PROJECT_ROOT_CANARY",
            "CALLER_SECRET",
            "CREDENTIAL_CANARY",
            secret,
        ):
            self.assertNotIn(canary, serialized)
        self.assertEqual(len(outcome["diagnostics"]), 1)

    def test_public_adapter_has_no_provider_transport_or_remote_import_boundary(self):
        module = _public_module()
        source = inspect.getsource(module)
        forbidden = (
            "ask_herdr_provider_adapter",
            "ask_herdr_herdr_transport",
            "subprocess",
            "socket",
            "urllib",
            "requests",
            "paramiko",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_dispatcher_creates_no_process_network_store_or_remote_effect(self):
        module = _public_module()
        dispatch = getattr(module, "dispatch_query_status", None)
        if not callable(dispatch):
            raise AssertionError(
                "ask_herdr_public_status must expose dispatch_query_status"
            )
        readers = {
            kind: mock.Mock(return_value=_inspection())
            for kind in ("project", "lane", "key", "operation")
        }
        with mock.patch.object(
            subprocess, "Popen", side_effect=AssertionError("process")
        ), mock.patch.object(
            socket, "socket", side_effect=AssertionError("network")
        ), mock.patch.object(
            subprocess, "run", side_effect=AssertionError("process")
        ), mock.patch(
            "builtins.open", side_effect=AssertionError("file")
        ):
            outcome = dispatch(
                _request(),
                project_inspector=mock.Mock(return_value=True),
                status_readers=readers,
                clock=lambda: OBSERVED_AT,
            )
        self.assertEqual(outcome["operation"], "query.status")
        for reader in readers.values():
            self.assertLessEqual(reader.call_count, 1)


if __name__ == "__main__":
    unittest.main()
