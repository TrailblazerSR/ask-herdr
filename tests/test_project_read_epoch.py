#!/usr/bin/env python3
"""Strict TDD for private Project Read Epoch acquisition."""

from __future__ import annotations

from dataclasses import fields, FrozenInstanceError
from datetime import datetime, timezone
import hashlib
import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_json import canonical_json  # noqa: E402
from ask_herdr_authority_store import (  # noqa: E402
    AuthorityStoreHeadInspection,
    inspect_authority_store_head,
)
from ask_herdr_lane_index import (  # noqa: E402
    LaneIndexInspection,
    inspect_lane_index,
)
from ask_herdr_project_mutation_lease import (  # noqa: E402
    ValidatedProjectMutationBinding,
)
from ask_herdr_topology_store import (  # noqa: E402
    TopologyStatusProjectionInspection,
    inspect_topology_ledger_head,
)
from tests.test_cross_store_claim_ports import (  # noqa: E402
    ADMISSION_TIME,
    DECISION_ID,
)
from tests.test_human_first_lane_coordinator import _Fixture  # noqa: E402
from tests.test_machine_validate_v1 import snapshot_tree  # noqa: E402


OBSERVED_AT = datetime(2026, 8, 21, 4, 5, 6, tzinfo=timezone.utc)


def _digest(value):
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _vector_binding():
    return ValidatedProjectMutationBinding(
        canonical_root="/private/tmp/ask-herdr-read-epoch-vector",
        filesystem_device=1,
        filesystem_inode=2,
        owner_uid=501,
        project_authority_id="11111111-1111-4111-8111-111111111111",
    )


def _authority(status="active", detail="authority_store_head.active"):
    return AuthorityStoreHeadInspection(
        status,
        detail,
        "sha256:" + "a" * 64,
    )


def _lane(status="active", detail="lane_index.active", digest=True):
    return LaneIndexInspection(
        status,
        detail,
        "sha256:" + "b" * 64 if digest else None,
    )


def _topology(
    digest_character="c",
    status="active",
    detail="topology_ledger_head.active",
):
    return TopologyStatusProjectionInspection(
        status,
        detail,
        "sha256:" + digest_character * 64,
    )


class ProjectReadEpochTest(unittest.TestCase):
    def test_stable_project_heads_form_one_path_free_epoch(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        human_api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )

        authority = inspect_authority_store_head(fixture.project_binding)
        lane_index = inspect_lane_index(fixture.project_binding)
        topology = inspect_topology_ledger_head(fixture.project_binding)
        self.assertEqual(authority.status, "active")
        self.assertEqual(lane_index.status, "active")
        self.assertEqual(topology.status, "active")
        before = snapshot_tree(fixture.root)

        epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
        clock_calls = []

        def clock():
            clock_calls.append(True)
            return OBSERVED_AT

        first = epoch_api.acquire_project_read_epoch(
            fixture.project_binding,
            clock=clock,
        )
        second = epoch_api.acquire_project_read_epoch(
            fixture.project_binding,
            clock=clock,
        )

        self.assertEqual(first, second)
        self.assertIsInstance(first, epoch_api.ProjectReadEpochInspection)
        self.assertEqual(
            tuple(field.name for field in fields(first)),
            ("status", "detail_code", "epoch"),
        )
        self.assertEqual(first.status, "active")
        self.assertEqual(first.detail_code, "project_read_epoch.active")
        self.assertIsInstance(first.epoch, epoch_api.ProjectReadEpoch)
        self.assertEqual(
            tuple(field.name for field in fields(first.epoch)),
            (
                "schema",
                "project_authority_id",
                "authority_store_head_digest",
                "project_state_digest",
                "lane_index_digest",
                "topology_ledger_head_digest",
                "observed_at",
                "acquisition_attempt",
                "epoch_digest",
            ),
        )
        binding = fixture.project_binding
        expected_project_state_digest = _digest(
            {
                "schema": "ask_herdr.project_state.identity.v1",
                "canonical_root": binding.canonical_root,
                "filesystem_device": binding.filesystem_device,
                "filesystem_inode": binding.filesystem_inode,
                "owner_uid": binding.owner_uid,
                "project_authority_id": binding.project_authority_id,
            }
        )
        expected_epoch_digest = _digest(
            {
                "schema": "ask_herdr.project_read_epoch.identity.v1",
                "project_authority_id": binding.project_authority_id,
                "authority_store_head_digest": (
                    authority.authority_store_head_digest
                ),
                "project_state_digest": expected_project_state_digest,
                "lane_index_digest": lane_index.lane_index_digest,
                "topology_ledger_head_digest": (
                    topology.topology_ledger_head_digest
                ),
            }
        )
        self.assertEqual(
            vars(first.epoch),
            {
                "schema": "ask_herdr.project_read_epoch.v1",
                "project_authority_id": binding.project_authority_id,
                "authority_store_head_digest": (
                    authority.authority_store_head_digest
                ),
                "project_state_digest": expected_project_state_digest,
                "lane_index_digest": lane_index.lane_index_digest,
                "topology_ledger_head_digest": (
                    topology.topology_ledger_head_digest
                ),
                "observed_at": "2026-08-21T04:05:06.000000Z",
                "acquisition_attempt": 1,
                "epoch_digest": expected_epoch_digest,
            },
        )
        self.assertEqual(clock_calls, [True, True])
        self.assertNotIn(str(fixture.root), repr(first))
        self.assertEqual(
            epoch_api.__all__,
            (
                "ProjectReadEpoch",
                "ProjectReadEpochInspection",
                "acquire_project_read_epoch",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            first.epoch.epoch_digest = "sha256:" + "0" * 64
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_one_complete_head_drift_retries_the_whole_tuple_once(self):
        epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
        topology_reads = (
            _topology("0"),
            _topology("c"),
            _topology("c"),
            _topology("c"),
        )
        clock_calls = []

        with mock.patch.object(
            epoch_api,
            "inspect_authority_store_head",
            return_value=_authority(),
        ) as authority_reader, mock.patch.object(
            epoch_api,
            "inspect_lane_index",
            return_value=_lane(),
        ) as lane_reader, mock.patch.object(
            epoch_api,
            "inspect_topology_status_projection",
            side_effect=topology_reads,
        ) as topology_reader:
            result = epoch_api.acquire_project_read_epoch(
                _vector_binding(),
                clock=lambda: (
                    clock_calls.append(True) or OBSERVED_AT
                ),
            )

        self.assertEqual(result.status, "active")
        self.assertEqual(result.detail_code, "project_read_epoch.active")
        self.assertIsNotNone(result.epoch)
        self.assertEqual(result.epoch.acquisition_attempt, 2)
        self.assertEqual(
            result.epoch.project_state_digest,
            "sha256:70704fd23ef26da4b98d9afa98902ff7db462db39797bf19327667a15ef468ee",
        )
        self.assertEqual(
            result.epoch.epoch_digest,
            "sha256:b81634ec5d9f5e04b843a2fcfacb3774aaf00eb640a3528945e4069de4c07048",
        )
        self.assertEqual(authority_reader.call_count, 4)
        self.assertEqual(lane_reader.call_count, 4)
        self.assertEqual(topology_reader.call_count, 4)
        self.assertEqual(clock_calls, [True])

    def test_three_changed_complete_tuples_stop_busy_without_clock(self):
        epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
        topology_reads = tuple(
            _topology(character)
            for character in ("0", "1", "2", "3", "4", "5")
        )

        def forbidden_clock():
            raise AssertionError("drifting acquisition consumed the clock")

        with mock.patch.object(
            epoch_api,
            "inspect_authority_store_head",
            return_value=_authority(),
        ) as authority_reader, mock.patch.object(
            epoch_api,
            "inspect_lane_index",
            return_value=_lane(),
        ) as lane_reader, mock.patch.object(
            epoch_api,
            "inspect_topology_status_projection",
            side_effect=topology_reads,
        ) as topology_reader:
            result = epoch_api.acquire_project_read_epoch(
                _vector_binding(),
                clock=forbidden_clock,
            )

        self.assertEqual(
            result,
            epoch_api.ProjectReadEpochInspection(
                "busy",
                "project_read_epoch.head_drift",
            ),
        )
        self.assertEqual(authority_reader.call_count, 6)
        self.assertEqual(lane_reader.call_count, 6)
        self.assertEqual(topology_reader.call_count, 6)

    def test_coherent_reconciliation_retains_an_authenticated_epoch(self):
        epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
        reconciled_topology = _topology(
            "c",
            "reconciliation_required",
            "topology_ledger_head.pending_candidate",
        )

        with mock.patch.object(
            epoch_api,
            "inspect_authority_store_head",
            return_value=_authority(),
        ), mock.patch.object(
            epoch_api,
            "inspect_lane_index",
            return_value=_lane(),
        ), mock.patch.object(
            epoch_api,
            "inspect_topology_status_projection",
            return_value=reconciled_topology,
        ):
            result = epoch_api.acquire_project_read_epoch(
                _vector_binding(),
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(result.status, "reconciliation_required")
        self.assertEqual(
            result.detail_code,
            "topology_ledger_head.pending_candidate",
        )
        self.assertIsNotNone(result.epoch)
        self.assertEqual(result.epoch.acquisition_attempt, 1)
        self.assertEqual(
            result.epoch.topology_ledger_head_digest,
            "sha256:" + "c" * 64,
        )

    def test_quarantine_and_absence_never_synthesize_an_epoch(self):
        epoch_api = importlib.import_module("ask_herdr_project_read_epoch")

        cases = (
            (
                _lane(
                    "quarantined",
                    "lane_index.membership_conflict",
                    digest=False,
                ),
                "quarantined",
                "lane_index.membership_conflict",
            ),
            (
                _lane("absent", "lane_index.absent", digest=False),
                "absent",
                "lane_index.absent",
            ),
        )
        for lane_result, status, detail_code in cases:
            with self.subTest(status=status), mock.patch.object(
                epoch_api,
                "inspect_authority_store_head",
                return_value=_authority(),
            ), mock.patch.object(
                epoch_api,
                "inspect_lane_index",
                return_value=lane_result,
            ), mock.patch.object(
                epoch_api,
                "inspect_topology_status_projection",
                return_value=_topology(),
            ):
                result = epoch_api.acquire_project_read_epoch(
                    _vector_binding(),
                    clock=lambda: (_ for _ in ()).throw(
                        AssertionError("non-epoch status consumed the clock")
                    ),
                )

            self.assertEqual(result.status, status)
            self.assertEqual(result.detail_code, detail_code)
            self.assertIsNone(result.epoch)


if __name__ == "__main__":
    unittest.main()
