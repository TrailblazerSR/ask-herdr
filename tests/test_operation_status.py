#!/usr/bin/env python3
"""Strict TDD for the private provider-free operation-status selector."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import importlib
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import ask_herdr_authority_store as authority_store  # noqa: E402
from ask_herdr_json import canonical_json  # noqa: E402
from ask_herdr_lane_index import LaneIndexEntry, LaneIndexInspection  # noqa: E402
from ask_herdr_project_mutation_lease import (  # noqa: E402
    ValidatedProjectMutationBinding,
)


OBSERVED_AT = datetime(2026, 8, 22, 1, 2, 3, tzinfo=timezone.utc)
PROJECT_AUTHORITY_ID = "11111111-1111-4111-8111-111111111111"
PROJECT_INIT_OPERATION_ID = "22222222-2222-4222-8222-222222222222"
LANE_ID = "33333333-3333-4333-8333-333333333333"
HUMAN_UNRESOLVED_OPERATION_ID = "44444444-4444-4444-8444-444444444444"
HUMAN_BOUND_OPERATION_ID = "55555555-5555-4555-8555-555555555555"
RECOVERY_OPERATION_ID = "66666666-6666-4666-8666-666666666666"
EVIDENCE_OPERATION_ID = "77777777-7777-4777-8777-777777777777"
PROJECT_INIT_REQUEST_DIGEST = "sha256:" + "d" * 64
PROJECT_INIT_AUTHORITY_DIGEST = "sha256:" + "e" * 64
HUMAN_UNRESOLVED_REQUEST_DIGEST = "sha256:" + "1" * 64
HUMAN_UNRESOLVED_AUTHORITY_DIGEST = "sha256:" + "2" * 64
HUMAN_BOUND_REQUEST_DIGEST = "sha256:" + "3" * 64
HUMAN_BOUND_AUTHORITY_DIGEST = "sha256:" + "4" * 64
RECOVERY_REQUEST_DIGEST = "sha256:" + "5" * 64
RECOVERY_AUTHORITY_DIGEST = "sha256:" + "6" * 64
EVIDENCE_REQUEST_DIGEST = "sha256:" + "7" * 64
EVIDENCE_AUTHORITY_DIGEST = "sha256:" + "8" * 64
OPERATION_READ_CONTRACT_DIGEST = (
    "sha256:19d721eebbef1d60fb9be6f524f4a33e459f6f903ae6aee3e83bca1b4229b8b6"
)


def _canonical_authority_record(
    sequence: int,
    record_kind: str,
    **payload,
):
    record = {
        "schema": "ask_herdr.policy_ledger_record.v1",
        "sequence": sequence,
        "record_kind": record_kind,
        **payload,
    }
    record["record_digest"] = (
        "sha256:" + hashlib.sha256(canonical_json(record)).hexdigest()
    )
    return record, canonical_json(record) + b"\n"


def _vector_binding() -> ValidatedProjectMutationBinding:
    return ValidatedProjectMutationBinding(
        canonical_root="/private/tmp/ask-herdr-read-epoch-vector",
        filesystem_device=1,
        filesystem_inode=2,
        owner_uid=501,
        project_authority_id=PROJECT_AUTHORITY_ID,
    )


def _authority_operation(
    *,
    operation_id: str = PROJECT_INIT_OPERATION_ID,
    operation: str = "project.init",
    canonical_request_digest: str = PROJECT_INIT_REQUEST_DIGEST,
    authority_record_digest: str = PROJECT_INIT_AUTHORITY_DIGEST,
    lane_scope: str = "not_applicable",
    lane_id: str | None = None,
    lane_generation: int | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        operation_id=operation_id,
        operation=operation,
        canonical_request_digest=canonical_request_digest,
        authority_record_digest=authority_record_digest,
        lane_scope=lane_scope,
        lane_id=lane_id,
        lane_generation=lane_generation,
    )


def _lane_entry() -> LaneIndexEntry:
    return LaneIndexEntry(
        lane_id=LANE_ID,
        lane_generation=1,
        lane_binding_digest="sha256:" + "f" * 64,
        event_sequence=7,
        event_digest="sha256:" + "1" * 64,
        state_digest="sha256:" + "2" * 64,
        response_digest=None,
    )


def _topology_mapping(
    *,
    operation_id=HUMAN_BOUND_OPERATION_ID,
    canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
    policy_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
    lane_id=LANE_ID,
    lane_generation=1,
    lane_binding_digest="sha256:" + "f" * 64,
):
    return SimpleNamespace(
        operation_id=operation_id,
        canonical_request_digest=canonical_request_digest,
        policy_record_digest=policy_record_digest,
        lane_id=lane_id,
        lane_generation=lane_generation,
        lane_binding_digest=lane_binding_digest,
    )


def _authority_projection(
    entries=(),
    *,
    status="active",
    detail_code="authority_store_head.active",
    candidate_entries=(),
):
    return SimpleNamespace(
        status=status,
        detail_code=detail_code,
        authority_store_head_digest="sha256:" + "a" * 64,
        operation_entries=tuple(entries),
        candidate_operation_entries=tuple(candidate_entries),
    )


def _topology_projection(
    entries=(),
    *,
    status="active",
    detail_code="topology_ledger_head.active",
    candidate_entries=(),
):
    return SimpleNamespace(
        status=status,
        detail_code=detail_code,
        topology_ledger_head_digest="sha256:" + "c" * 64,
        key_entries=(),
        operation_entries=tuple(entries),
        candidate_operation_entries=tuple(candidate_entries),
    )


@contextmanager
def _observations(
    *,
    authority_entries=(),
    topology_entries=(),
    lane_entries=(),
    authority_status="active",
    authority_detail="authority_store_head.active",
    topology_status="active",
    topology_detail="topology_ledger_head.active",
    authority_candidate_entries=(),
    topology_candidate_entries=(),
    topology_side_effect=None,
):
    epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
    topology_patch = (
        {"side_effect": tuple(topology_side_effect)}
        if topology_side_effect is not None
        else {
            "return_value": _topology_projection(
                topology_entries,
                status=topology_status,
                detail_code=topology_detail,
                candidate_entries=topology_candidate_entries,
            )
        }
    )
    with mock.patch.object(
        epoch_api,
        "inspect_authority_store_head",
        return_value=_authority_projection(
            authority_entries,
            status=authority_status,
            detail_code=authority_detail,
            candidate_entries=authority_candidate_entries,
        ),
    ), mock.patch.object(
        epoch_api,
        "inspect_lane_index",
        return_value=LaneIndexInspection(
            "active",
            "lane_index.active",
            "sha256:" + "b" * 64,
            tuple(lane_entries),
        ),
    ), mock.patch.object(
        epoch_api,
        "inspect_topology_status_projection",
        **topology_patch,
    ):
        yield


class OperationStatusTest(unittest.TestCase):
    def test_authority_replay_projects_closed_operation_paths_and_cache(self):
        access_id = "88888888-8888-4888-8888-888888888888"
        genesis, genesis_bytes = _canonical_authority_record(
            0,
            "project_genesis",
            operation_id=PROJECT_INIT_OPERATION_ID,
            canonical_request_digest=PROJECT_INIT_REQUEST_DIGEST,
        )
        settlement, settlement_bytes = _canonical_authority_record(
            1,
            "evidence_content_access_settlement",
            content_access={"access_id": access_id},
            canonical_request_projection={"operation": "query.evidence"},
            settlement={
                "access_id": access_id,
                "content_read_operation_id": EVIDENCE_OPERATION_ID,
                "canonical_request_digest": EVIDENCE_REQUEST_DIGEST,
            },
        )
        human, human_bytes = _canonical_authority_record(
            2,
            "human_admission",
            operation={
                "operation": "turn.consult",
                "operation_id": HUMAN_UNRESOLVED_OPERATION_ID,
                "canonical_request_digest": HUMAN_UNRESOLVED_REQUEST_DIGEST,
            },
        )
        admission, admission_bytes = _canonical_authority_record(
            3,
            "evidence_content_access_admission",
            content_access={"access_id": access_id},
        )
        recovery, recovery_bytes = _canonical_authority_record(
            4,
            "recovery_operation_admission",
            canonical_operation={
                "operation": "recovery.reconcile",
                "operation_id": RECOVERY_OPERATION_ID,
                "canonical_request_digest": RECOVERY_REQUEST_DIGEST,
                "recovery_scope_selector": {
                    "lane_id": LANE_ID,
                    "generation": 7,
                },
            },
        )
        records = (genesis, settlement, human, admission, recovery)
        inspection = authority_store.AuthorityStoreInspection(
            status="active",
            detail_code="authority_store.active",
            head_sequence=len(records) - 1,
            head_digest=recovery["record_digest"],
            ledger_record_bytes=(
                genesis_bytes,
                settlement_bytes,
                human_bytes,
                admission_bytes,
                recovery_bytes,
            ),
        )
        expected_entries = (
            authority_store.AuthorityStatusOperationEntry(
                operation_id=PROJECT_INIT_OPERATION_ID,
                operation="project.init",
                canonical_request_digest=PROJECT_INIT_REQUEST_DIGEST,
                authority_record_digest=genesis["record_digest"],
                lane_scope="not_applicable",
                lane_id=None,
                lane_generation=None,
            ),
            authority_store.AuthorityStatusOperationEntry(
                operation_id=HUMAN_UNRESOLVED_OPERATION_ID,
                operation="turn.consult",
                canonical_request_digest=HUMAN_UNRESOLVED_REQUEST_DIGEST,
                authority_record_digest=human["record_digest"],
                lane_scope="required",
                lane_id=None,
                lane_generation=None,
            ),
            authority_store.AuthorityStatusOperationEntry(
                operation_id=RECOVERY_OPERATION_ID,
                operation="recovery.reconcile",
                canonical_request_digest=RECOVERY_REQUEST_DIGEST,
                authority_record_digest=recovery["record_digest"],
                lane_scope="required",
                lane_id=LANE_ID,
                lane_generation=7,
            ),
            authority_store.AuthorityStatusOperationEntry(
                operation_id=EVIDENCE_OPERATION_ID,
                operation="query.evidence",
                canonical_request_digest=EVIDENCE_REQUEST_DIGEST,
                authority_record_digest=settlement["record_digest"],
                lane_scope="not_applicable",
                lane_id=None,
                lane_generation=None,
            ),
        )

        projection = authority_store._authority_status_projection(inspection)

        self.assertEqual(
            projection,
            authority_store.AuthorityStatusProjectionInspection(
                status="active",
                detail_code="authority_store_head.active",
                authority_store_head_digest=recovery["record_digest"],
                operation_entries=expected_entries,
            ),
        )
        self.assertEqual(
            tuple(entry.operation_id for entry in projection.operation_entries),
            (
                PROJECT_INIT_OPERATION_ID,
                HUMAN_UNRESOLVED_OPERATION_ID,
                RECOVERY_OPERATION_ID,
                EVIDENCE_OPERATION_ID,
            ),
        )
        self.assertEqual(
            tuple(entry.lane_scope for entry in projection.operation_entries),
            ("not_applicable", "required", "required", "not_applicable"),
        )
        self.assertNotIn(
            access_id,
            tuple(entry.operation_id for entry in projection.operation_entries),
        )
        self.assertTrue(
            all("access_id" not in vars(entry) for entry in expected_entries)
        )

        head = authority_store._authority_store_head_with_operation_projection(
            inspection
        )
        self.assertEqual(
            authority_store._authority_status_operation_entries_from_head(head),
            expected_entries,
        )
        self.assertEqual(
            authority_store._authority_status_operation_entries_from_head(
                authority_store.AuthorityStoreHeadInspection(
                    "active",
                    "authority_store_head.active",
                    recovery["record_digest"],
                )
            ),
            (),
        )
        self.assertEqual(
            tuple(
                field.name
                for field in fields(authority_store.AuthorityStoreHeadInspection)
            ),
            ("status", "detail_code", "authority_store_head_digest"),
        )
        self.assertEqual(
            tuple(
                field.name
                for field in fields(
                    authority_store.AuthorityStatusProjectionInspection
                )
            ),
            (
                "status",
                "detail_code",
                "authority_store_head_digest",
                "operation_entries",
            ),
        )

    def test_all_four_record_families_have_closed_metadata_and_lane_states(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        authority_entries = (
            _authority_operation(),
            _authority_operation(
                operation_id=HUMAN_UNRESOLVED_OPERATION_ID,
                operation="turn.consult",
                canonical_request_digest=HUMAN_UNRESOLVED_REQUEST_DIGEST,
                authority_record_digest=HUMAN_UNRESOLVED_AUTHORITY_DIGEST,
                lane_scope="required",
            ),
            _authority_operation(
                operation_id=HUMAN_BOUND_OPERATION_ID,
                operation="turn.answer",
                canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
                authority_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
                lane_scope="required",
            ),
            _authority_operation(
                operation_id=RECOVERY_OPERATION_ID,
                operation="recovery.reconcile",
                canonical_request_digest=RECOVERY_REQUEST_DIGEST,
                authority_record_digest=RECOVERY_AUTHORITY_DIGEST,
                lane_scope="required",
                lane_id=LANE_ID,
                lane_generation=1,
            ),
            _authority_operation(
                operation_id=EVIDENCE_OPERATION_ID,
                operation="query.evidence",
                canonical_request_digest=EVIDENCE_REQUEST_DIGEST,
                authority_record_digest=EVIDENCE_AUTHORITY_DIGEST,
                lane_scope="not_applicable",
            ),
        )
        cases = (
            (
                PROJECT_INIT_OPERATION_ID,
                "project.init",
                PROJECT_INIT_REQUEST_DIGEST,
                PROJECT_INIT_AUTHORITY_DIGEST,
                "not_applicable",
                0,
            ),
            (
                HUMAN_UNRESOLVED_OPERATION_ID,
                "turn.consult",
                HUMAN_UNRESOLVED_REQUEST_DIGEST,
                HUMAN_UNRESOLVED_AUTHORITY_DIGEST,
                "unresolved",
                0,
            ),
            (
                HUMAN_BOUND_OPERATION_ID,
                "turn.answer",
                HUMAN_BOUND_REQUEST_DIGEST,
                HUMAN_BOUND_AUTHORITY_DIGEST,
                "bound",
                1,
            ),
            (
                RECOVERY_OPERATION_ID,
                "recovery.reconcile",
                RECOVERY_REQUEST_DIGEST,
                RECOVERY_AUTHORITY_DIGEST,
                "bound",
                1,
            ),
            (
                EVIDENCE_OPERATION_ID,
                "query.evidence",
                EVIDENCE_REQUEST_DIGEST,
                EVIDENCE_AUTHORITY_DIGEST,
                "not_applicable",
                0,
            ),
        )

        with _observations(
            authority_entries=authority_entries,
            topology_entries=(_topology_mapping(),),
            lane_entries=(_lane_entry(),),
        ):
            for (
                operation_id,
                operation,
                request_digest,
                authority_digest,
                lane_association,
                entry_count,
            ) in cases:
                with self.subTest(operation_id=operation_id):
                    result = status_api.read_operation_status(
                        _vector_binding(),
                        operation_id=operation_id,
                        limit=1,
                        cursor=None,
                        clock=lambda: OBSERVED_AT,
                    )

                    self.assertEqual(
                        (result.status, result.detail_code),
                        ("active", "query_status.operation_active"),
                    )
                    self.assertTrue(
                        result.normalized_read_contract_digest.startswith(
                            "sha256:"
                        )
                    )
                    self.assertIsNotNone(result.project_read_epoch)
                    self.assertEqual(result.next_cursor, None)
                    self.assertEqual(
                        vars(result.operation_metadata),
                        {
                            "operation_id": operation_id,
                            "operation": operation,
                            "canonical_request_digest": request_digest,
                            "authority_record_digest": authority_digest,
                            "lane_association": lane_association,
                        },
                    )
                    self.assertEqual(len(result.entries), entry_count)
                    if entry_count:
                        self.assertEqual(
                            vars(result.entries[0]),
                            {
                                "lane_id": LANE_ID,
                                "lane_generation": 1,
                                "lane_binding_digest": "sha256:" + "f" * 64,
                                "event_sequence": 7,
                                "event_digest": "sha256:" + "1" * 64,
                                "state_digest": "sha256:" + "2" * 64,
                                "response_digest": None,
                            },
                        )

    def test_project_init_operation_is_returned_as_non_lane_metadata(self):
        status_api = importlib.import_module("ask_herdr_project_status")

        with _observations(
            authority_entries=(_authority_operation(),),
            lane_entries=(_lane_entry(),),
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=PROJECT_INIT_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertIsInstance(result, status_api.ProjectStatusInspection)
        self.assertEqual(
            tuple(field.name for field in fields(result)),
            (
                "status",
                "detail_code",
                "normalized_read_contract_digest",
                "project_read_epoch",
                "entries",
                "next_cursor",
                "operation_metadata",
            ),
        )
        self.assertEqual(
            (result.status, result.detail_code),
            ("active", "query_status.operation_active"),
        )
        self.assertEqual(
            result.normalized_read_contract_digest,
            OPERATION_READ_CONTRACT_DIGEST,
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(
            vars(result.project_read_epoch),
            {
                "schema": "ask_herdr.project_read_epoch.v1",
                "project_authority_id": PROJECT_AUTHORITY_ID,
                "authority_store_head_digest": "sha256:" + "a" * 64,
                "project_state_digest": (
                    "sha256:70704fd23ef26da4b98d9afa98902ff7db462db39797bf19327667a15ef468ee"
                ),
                "lane_index_digest": "sha256:" + "b" * 64,
                "topology_ledger_head_digest": "sha256:" + "c" * 64,
                "observed_at": "2026-08-22T01:02:03.000000Z",
                "acquisition_attempt": 1,
                "epoch_digest": (
                    "sha256:b81634ec5d9f5e04b843a2fcfacb3774aaf00eb640a3528945e4069de4c07048"
                ),
            },
        )
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)
        self.assertEqual(
            vars(result.operation_metadata),
            {
                "operation_id": PROJECT_INIT_OPERATION_ID,
                "operation": "project.init",
                "canonical_request_digest": PROJECT_INIT_REQUEST_DIGEST,
                "authority_record_digest": PROJECT_INIT_AUTHORITY_DIGEST,
                "lane_association": "not_applicable",
            },
        )
        self.assertNotIn("runtime", vars(result.operation_metadata))
        self.assertNotIn("result", vars(result.operation_metadata))

    def test_active_absence_is_authenticated_by_the_same_project_read_epoch(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        missing_operation_id = "88888888-8888-4888-8888-888888888888"

        with _observations(
            authority_entries=(_authority_operation(),),
            lane_entries=(_lane_entry(),),
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=missing_operation_id,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("absent", "query_status.operation_absent"),
        )
        self.assertIsNotNone(result.normalized_read_contract_digest)
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.operation_metadata)
        self.assertIsNone(result.next_cursor)

    def test_promoted_head_boundary_does_not_project_candidate_operation(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        candidate_operation_id = "99999999-9999-4999-8999-999999999999"

        with _observations(
            authority_entries=(),
            authority_candidate_entries=(
                _authority_operation(
                    operation_id=candidate_operation_id,
                    operation="turn.consult",
                    canonical_request_digest=HUMAN_UNRESOLVED_REQUEST_DIGEST,
                    authority_record_digest=HUMAN_UNRESOLVED_AUTHORITY_DIGEST,
                    lane_scope="required",
                ),
            ),
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=candidate_operation_id,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("absent", "query_status.operation_absent"),
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())

    def test_invalid_uuid_is_rejected_before_clock_or_epoch(self):
        status_api = importlib.import_module("ask_herdr_project_status")

        with _observations():
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id="not-a-uuid",
                limit=1,
                cursor=None,
                clock=lambda: (_ for _ in ()).throw(
                    AssertionError("invalid UUID consumed the clock")
                ),
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.read_contract_invalid"),
        )
        self.assertIsNone(result.normalized_read_contract_digest)
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_bool_non_int_and_out_of_range_limits_are_rejected_before_epoch(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        for limit in (True, "1", 0, 201):
            with self.subTest(limit=repr(limit)), _observations():
                result = status_api.read_operation_status(
                    _vector_binding(),
                    operation_id=PROJECT_INIT_OPERATION_ID,
                    limit=limit,
                    cursor=None,
                    clock=lambda: (_ for _ in ()).throw(
                        AssertionError("invalid limit consumed the clock")
                    ),
                )
                self.assertEqual(
                    (result.status, result.detail_code),
                    ("quarantined", "query_status.read_contract_invalid"),
                )
                self.assertIsNone(result.normalized_read_contract_digest)
                self.assertIsNone(result.project_read_epoch)
                self.assertIsNone(result.operation_metadata)
                self.assertEqual(result.entries, ())
                self.assertIsNone(result.next_cursor)

    def test_non_null_cursor_is_rejected_after_contract_validation_before_epoch(self):
        status_api = importlib.import_module("ask_herdr_project_status")

        with _observations():
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=PROJECT_INIT_OPERATION_ID,
                limit=1,
                cursor="mcv1.any-operation-cursor-is-stale",
                clock=lambda: (_ for _ in ()).throw(
                    AssertionError("operation cursor consumed the clock")
                ),
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("cursor_stale", "query_status.cursor_stale"),
        )
        self.assertEqual(
            result.normalized_read_contract_digest,
            OPERATION_READ_CONTRACT_DIGEST,
        )
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_unexpected_acquired_epoch_status_is_closed_without_operation_payload(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        unexpected_snapshot = SimpleNamespace(
            inspection=SimpleNamespace(
                status="future_status",
                detail_code="project_read_epoch.future_status",
                epoch=object(),
            )
        )

        with mock.patch.object(
            status_api,
            "_acquire_project_read_epoch_snapshot",
            return_value=unexpected_snapshot,
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=PROJECT_INIT_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.epoch_status_invalid"),
        )
        self.assertEqual(
            result.normalized_read_contract_digest,
            OPERATION_READ_CONTRACT_DIGEST,
        )
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_reconciliation_preserves_detail_and_only_retained_lane_joins(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        authority_entries = (
            _authority_operation(
                operation_id=HUMAN_BOUND_OPERATION_ID,
                operation="turn.answer",
                canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
                authority_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
                lane_scope="required",
            ),
            _authority_operation(
                operation_id=HUMAN_UNRESOLVED_OPERATION_ID,
                operation="turn.consult",
                canonical_request_digest=HUMAN_UNRESOLVED_REQUEST_DIGEST,
                authority_record_digest=HUMAN_UNRESOLVED_AUTHORITY_DIGEST,
                lane_scope="required",
            ),
        )

        with _observations(
            authority_entries=authority_entries,
            topology_entries=(_topology_mapping(),),
            lane_entries=(_lane_entry(),),
            topology_status="reconciliation_required",
            topology_detail="topology_ledger_head.pending_candidate",
        ):
            bound = status_api.read_operation_status(
                _vector_binding(),
                operation_id=HUMAN_BOUND_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            unresolved = status_api.read_operation_status(
                _vector_binding(),
                operation_id=HUMAN_UNRESOLVED_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            absent = status_api.read_operation_status(
                _vector_binding(),
                operation_id=EVIDENCE_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        for result in (bound, unresolved, absent):
            self.assertEqual(
                (result.status, result.detail_code),
                (
                    "reconciliation_required",
                    "topology_ledger_head.pending_candidate",
                ),
            )
            self.assertIsNotNone(result.project_read_epoch)
            self.assertIsNone(result.next_cursor)

        self.assertEqual(bound.operation_metadata.lane_association, "bound")
        self.assertEqual(len(bound.entries), 1)
        self.assertEqual(
            unresolved.operation_metadata.lane_association,
            "unresolved",
        )
        self.assertEqual(unresolved.entries, ())
        self.assertIsNone(absent.operation_metadata)
        self.assertEqual(absent.entries, ())

    def test_reconciliation_quarantines_not_applicable_digest_contradiction(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        mapping = _topology_mapping(
            operation_id=PROJECT_INIT_OPERATION_ID,
            canonical_request_digest="sha256:" + "0" * 64,
            policy_record_digest=PROJECT_INIT_AUTHORITY_DIGEST,
        )

        with _observations(
            authority_entries=(_authority_operation(),),
            topology_entries=(mapping,),
            lane_entries=(_lane_entry(),),
            topology_status="reconciliation_required",
            topology_detail="topology_ledger_head.pending_candidate",
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=PROJECT_INIT_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.operation_mapping_invalid"),
        )
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_reconciliation_quarantines_topology_only_retained_lane_binding_mismatch(
        self,
    ):
        status_api = importlib.import_module("ask_herdr_project_status")
        mapping = _topology_mapping(
            lane_binding_digest="sha256:" + "0" * 64,
        )

        with _observations(
            authority_entries=(),
            topology_entries=(mapping,),
            lane_entries=(_lane_entry(),),
            topology_status="reconciliation_required",
            topology_detail="topology_ledger_head.pending_candidate",
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=HUMAN_BOUND_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.operation_mapping_invalid"),
        )
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_recovery_reconciliation_without_retained_lane_join_stays_unresolved(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        recovery = _authority_operation(
            operation_id=RECOVERY_OPERATION_ID,
            operation="recovery.reconcile",
            canonical_request_digest=RECOVERY_REQUEST_DIGEST,
            authority_record_digest=RECOVERY_AUTHORITY_DIGEST,
            lane_scope="required",
            lane_id=LANE_ID,
            lane_generation=1,
        )

        with _observations(
            authority_entries=(recovery,),
            lane_entries=(),
            topology_status="reconciliation_required",
            topology_detail="topology_ledger_head.pending_candidate",
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=RECOVERY_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            (
                "reconciliation_required",
                "topology_ledger_head.pending_candidate",
            ),
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(
            vars(result.operation_metadata),
            {
                "operation_id": RECOVERY_OPERATION_ID,
                "operation": "recovery.reconcile",
                "canonical_request_digest": RECOVERY_REQUEST_DIGEST,
                "authority_record_digest": RECOVERY_AUTHORITY_DIGEST,
                "lane_association": "unresolved",
            },
        )
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_recovery_active_without_embedded_lane_join_is_a_mapping_failure(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        recovery = _authority_operation(
            operation_id=RECOVERY_OPERATION_ID,
            operation="recovery.reconcile",
            canonical_request_digest=RECOVERY_REQUEST_DIGEST,
            authority_record_digest=RECOVERY_AUTHORITY_DIGEST,
            lane_scope="required",
            lane_id=LANE_ID,
            lane_generation=1,
        )

        with _observations(authority_entries=(recovery,), lane_entries=()):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=RECOVERY_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.operation_mapping_invalid"),
        )
        self.assertIsNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_request_policy_and_binding_digest_contradictions_quarantine(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        human = _authority_operation(
            operation_id=HUMAN_BOUND_OPERATION_ID,
            operation="turn.answer",
            canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
            authority_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
            lane_scope="required",
        )
        cases = (
            (
                "request",
                _topology_mapping(
                    canonical_request_digest="sha256:" + "0" * 64
                ),
            ),
            (
                "policy",
                _topology_mapping(
                    policy_record_digest="sha256:" + "0" * 64
                ),
            ),
            (
                "binding",
                _topology_mapping(
                    lane_binding_digest="sha256:" + "0" * 64
                ),
            ),
        )

        for name, mapping in cases:
            with self.subTest(case=name), _observations(
                authority_entries=(human,),
                topology_entries=(mapping,),
                lane_entries=(_lane_entry(),),
            ):
                result = status_api.read_operation_status(
                    _vector_binding(),
                    operation_id=HUMAN_BOUND_OPERATION_ID,
                    limit=1,
                    cursor=None,
                        clock=lambda: OBSERVED_AT,
                    )
                self.assertEqual(
                    (result.status, result.detail_code),
                    ("quarantined", "query_status.operation_mapping_invalid"),
                )
                self.assertIsNotNone(result.normalized_read_contract_digest)
                self.assertIsNone(result.project_read_epoch)
                self.assertIsNone(result.operation_metadata)
                self.assertEqual(result.entries, ())
                self.assertIsNone(result.next_cursor)

    def test_duplicate_mappings_are_self_contradictions_in_every_epoch_state(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        human = _authority_operation(
            operation_id=HUMAN_BOUND_OPERATION_ID,
            operation="turn.answer",
            canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
            authority_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
            lane_scope="required",
        )
        duplicate = _topology_mapping()

        for topology_status, topology_detail in (
            ("active", "topology_ledger_head.active"),
            (
                "reconciliation_required",
                "topology_ledger_head.pending_candidate",
            ),
        ):
            with self.subTest(status=topology_status), _observations(
                authority_entries=(human,),
                topology_entries=(duplicate, duplicate),
                lane_entries=(_lane_entry(),),
                topology_status=topology_status,
                topology_detail=topology_detail,
            ):
                result = status_api.read_operation_status(
                    _vector_binding(),
                    operation_id=HUMAN_BOUND_OPERATION_ID,
                    limit=1,
                    cursor=None,
                        clock=lambda: OBSERVED_AT,
                    )
                self.assertEqual(
                    (result.status, result.detail_code),
                    ("quarantined", "query_status.operation_mapping_invalid"),
                )
                self.assertIsNone(result.project_read_epoch)
                self.assertIsNone(result.operation_metadata)
                self.assertEqual(result.entries, ())
                self.assertIsNone(result.next_cursor)

    def test_active_only_completeness_rejects_unknown_and_non_lane_mappings(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        unknown_operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        cases = (
            (
                "topology_only",
                (),
                _topology_mapping(operation_id=unknown_operation_id),
                unknown_operation_id,
            ),
            (
                "not_applicable",
                (_authority_operation(),),
                _topology_mapping(
                    operation_id=PROJECT_INIT_OPERATION_ID,
                    canonical_request_digest=PROJECT_INIT_REQUEST_DIGEST,
                    policy_record_digest=PROJECT_INIT_AUTHORITY_DIGEST,
                ),
                PROJECT_INIT_OPERATION_ID,
            ),
        )

        for name, authority_entries, mapping, operation_id in cases:
            with self.subTest(case=name), _observations(
                authority_entries=authority_entries,
                topology_entries=(mapping,),
                lane_entries=(_lane_entry(),),
            ):
                result = status_api.read_operation_status(
                    _vector_binding(),
                    operation_id=operation_id,
                    limit=1,
                    cursor=None,
                        clock=lambda: OBSERVED_AT,
                    )
                self.assertEqual(
                    (result.status, result.detail_code),
                    ("quarantined", "query_status.operation_mapping_invalid"),
                )
                self.assertIsNone(result.project_read_epoch)
                self.assertIsNone(result.operation_metadata)
                self.assertEqual(result.entries, ())

    def test_reconciliation_does_not_widen_operation_universe_from_unmatched_mapping(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        unknown_operation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

        with _observations(
            authority_entries=(),
            topology_entries=(_topology_mapping(operation_id=unknown_operation_id),),
            topology_status="reconciliation_required",
            topology_detail="topology_ledger_head.pending_candidate",
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=unknown_operation_id,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            (
                "reconciliation_required",
                "topology_ledger_head.pending_candidate",
            ),
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)

    def test_operation_result_uses_revalidated_epoch_and_retained_promoted_join(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        human = _authority_operation(
            operation_id=HUMAN_BOUND_OPERATION_ID,
            operation="turn.answer",
            canonical_request_digest=HUMAN_BOUND_REQUEST_DIGEST,
            authority_record_digest=HUMAN_BOUND_AUTHORITY_DIGEST,
            lane_scope="required",
        )
        drifted = _topology_projection(
            (
                _topology_mapping(
                    lane_binding_digest="sha256:" + "0" * 64
                ),
            )
        )
        stable = _topology_projection((_topology_mapping(),))

        with _observations(
            authority_entries=(human,),
            lane_entries=(_lane_entry(),),
            topology_side_effect=(drifted, stable, stable, stable),
        ):
            result = status_api.read_operation_status(
                _vector_binding(),
                operation_id=HUMAN_BOUND_OPERATION_ID,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (result.status, result.detail_code),
            ("active", "query_status.operation_active"),
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(result.project_read_epoch.acquisition_attempt, 2)
        self.assertEqual(result.operation_metadata.lane_association, "bound")
        self.assertEqual(len(result.entries), 1)
        self.assertIsNone(result.next_cursor)


if __name__ == "__main__":
    unittest.main()
