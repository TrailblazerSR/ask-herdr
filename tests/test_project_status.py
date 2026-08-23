#!/usr/bin/env python3
"""Strict TDD for the private metadata-only project status seam."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields, FrozenInstanceError
from datetime import datetime, timezone
import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from tests.test_cross_store_claim_ports import (  # noqa: E402
    ADMISSION_TIME,
    DECISION_ID,
)
from tests.test_human_first_lane_coordinator import _Fixture  # noqa: E402
from tests.test_journaled_provision import ProjectScriptedHerdr  # noqa: E402
from tests.test_machine_validate_v1 import snapshot_tree  # noqa: E402

from ask_herdr_authority_store import (  # noqa: E402
    AuthorityStoreHeadInspection,
)
from ask_herdr_herdr_transport import ProvisionIntent  # noqa: E402
from ask_herdr_journaled_provision import (  # noqa: E402
    lane_workspace_binding_digest,
    provision_postcondition_digest,
)
from ask_herdr_lane_index import LaneIndexEntry, LaneIndexInspection  # noqa: E402
import ask_herdr_lane_store as lane_store  # noqa: E402
from ask_herdr_lane_store import ValidatedLaneGenerationBinding  # noqa: E402
from ask_herdr_lane_turn import (  # noqa: E402
    BeginDispatch,
    NativeIdentityMode,
    PrepareAdmittedAttempt,
)
from ask_herdr_project_mutation_lease import (  # noqa: E402
    ValidatedProjectMutationBinding,
)
from ask_herdr_topology_store import (  # noqa: E402
    TopologyMutationIntent,
    TopologyStatusKeyEntry,
    TopologyStatusProjectionInspection,
    commit_mutation_intent,
)


OBSERVED_AT = datetime(2026, 8, 21, 5, 6, 7, tzinfo=timezone.utc)
PROJECT_READ_CONTRACT_DIGEST = (
    "sha256:c9a4016fa0bbc969fc36e6652733b69a09ea30ef18896ecaaf55a66f959e6050"
)
LANE_READ_CONTRACT_DIGEST = (
    "sha256:f8037d1d702147f220cc19fefd4895cf8f74d3755f4aa3b80b0eb9682f27b974"
)
KEY_READ_CONTRACT_DIGEST = (
    "sha256:e56c1d01eef78863778f2d435a6023a6f3617f9941899c0b975be967ff531713"
)
PROJECT_STATUS_ORDERING_DIGEST = (
    "sha256:eeac110e74bea1e3a3734329382d369488cbd83e2b678d6e4908bf5e28c58c4e"
)


def _vector_binding():
    return ValidatedProjectMutationBinding(
        canonical_root="/private/tmp/ask-herdr-key-status-vector",
        filesystem_device=1,
        filesystem_inode=2,
        owner_uid=501,
        project_authority_id="11111111-1111-4111-8111-111111111111",
    )


def _lane_head(generation, *, binding_character="d"):
    return LaneIndexEntry(
        lane_id="22222222-2222-4222-8222-222222222222",
        lane_generation=generation,
        lane_binding_digest="sha256:" + binding_character * 64,
        event_sequence=generation,
        event_digest="sha256:" + "e" * 64,
        state_digest="sha256:" + "f" * 64,
        response_digest=None,
    )


def _key_mapping(
    entry,
    *,
    consultant_key="beta",
    lane_binding_digest=None,
):
    return TopologyStatusKeyEntry(
        consultant_key=consultant_key,
        lane_id=entry.lane_id,
        lane_generation=entry.lane_generation,
        lane_binding_digest=(
            entry.lane_binding_digest
            if lane_binding_digest is None
            else lane_binding_digest
        ),
    )


@contextmanager
def _status_observations(
    *,
    lane_entries,
    topology_entries,
    topology_status="active",
    topology_detail="topology_ledger_head.active",
):
    epoch_api = importlib.import_module("ask_herdr_project_read_epoch")
    with mock.patch.object(
        epoch_api,
        "inspect_authority_store_head",
        return_value=AuthorityStoreHeadInspection(
            "active",
            "authority_store_head.active",
            "sha256:" + "a" * 64,
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
        return_value=TopologyStatusProjectionInspection(
            topology_status,
            topology_detail,
            "sha256:" + "c" * 64,
            tuple(topology_entries),
        ),
    ):
        yield


class ProjectStatusTest(unittest.TestCase):
    def _prepare_two_lanes(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        first = human_api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        runner = ProjectScriptedHerdr(str(fixture.root))
        executed = human_api.execute_prepared_journaled_provision(
            first,
            runner=runner,
        )

        second_lane_id = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        second_workspace = fixture.root / "lane-workspaces" / second_lane_id
        second_workspace.mkdir(mode=0o700)
        second_binding = ValidatedLaneGenerationBinding(
            canonical_root=str(fixture.root),
            filesystem_device=fixture.project_binding.filesystem_device,
            filesystem_inode=fixture.project_binding.filesystem_inode,
            owner_uid=fixture.project_binding.owner_uid,
            project_authority_id=fixture.project_binding.project_authority_id,
            lane_id=second_lane_id,
            lane_generation=1,
            lane_binding_digest="sha256:" + "d" * 64,
        )
        second_operation_id = "12121212-1212-4212-8212-121212121212"
        second_request_digest = "sha256:" + "e" * 64
        second_attempt_id = "15151515-1515-4515-8515-151515151515"
        second_marker = "<<<ASK_HERDR_TURN_DONE:project-status-second-lane>>>"
        second_event = PrepareAdmittedAttempt(
            operation="turn.consult",
            operation_id=second_operation_id,
            canonical_request_digest=second_request_digest,
            lane_id=second_lane_id,
            lane_generation=1,
            attempt_id=second_attempt_id,
            expected_head_digest=fixture.request.expected_head_digest,
            native_identity_mode=NativeIdentityMode.ESTABLISH_NEW,
            expected_native_correlation_digest=None,
            expected_turn_sequence=1,
            expected_completion_marker=second_marker,
            reservation_id=None,
            direct_human_policy_record_digest=(
                first.policy_proof.policy_record_digest
            ),
        )
        committed = lane_store.apply_lane_turn_event(
            second_binding,
            second_event,
        )
        self.assertEqual(committed.outcome_kind, "lane_event_committed")

        second_provision = ProvisionIntent(
            project_id=fixture.project_binding.project_authority_id,
            lane_id=second_lane_id,
            consultant_key="beta",
            project_root=str(fixture.root),
            topology_nonce="topology-nonce-project-status-2",
            lane_workspace_cwd=str(second_workspace),
        )
        second_mutation = TopologyMutationIntent(
            mutation_id="16161616-1616-4616-8616-161616161616",
            operation_id=second_operation_id,
            canonical_request_digest=second_request_digest,
            policy_record_digest=first.policy_proof.policy_record_digest,
            lane_state_digest="sha256:" + "b" * 64,
            lane_id=second_lane_id,
            lane_generation=1,
            lane_binding_digest=second_binding.lane_binding_digest,
            lane_workspace_binding_digest=lane_workspace_binding_digest(
                fixture.topology_binding,
                second_provision,
            ),
            consultant_key="beta",
            topology_nonce="topology-nonce-project-status-2",
            lane_workspace_cwd=str(second_workspace),
            prior_topology_digest=executed.project_topology_digest,
            intended_action="reconcile_or_provision",
            precondition_digest="sha256:" + "a" * 64,
            expected_postcondition_digest=provision_postcondition_digest(
                second_provision
            ),
        )
        prepared_mutation = commit_mutation_intent(
            fixture.topology_binding,
            second_mutation,
        )
        self.assertEqual(
            prepared_mutation.outcome_kind,
            "topology_mutation_prepared",
        )
        return fixture, second_lane_id, first, executed

    def test_project_status_returns_one_stable_path_free_lane_head(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        prepared = human_api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        before = snapshot_tree(fixture.root)

        status_api = importlib.import_module("ask_herdr_project_status")
        result = status_api.read_project_status(
            fixture.project_binding,
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
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(result.status, "active")
        self.assertEqual(result.detail_code, "query_status.active")
        self.assertEqual(
            result.normalized_read_contract_digest,
            PROJECT_READ_CONTRACT_DIGEST,
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(result.project_read_epoch.acquisition_attempt, 1)
        self.assertEqual(
            result.project_read_epoch.observed_at,
            "2026-08-21T05:06:07.000000Z",
        )
        self.assertEqual(
            result.entries,
            (
                status_api.ProjectStatusLaneHead(
                    lane_id=fixture.lane_binding.lane_id,
                    lane_generation=fixture.lane_binding.lane_generation,
                    lane_binding_digest=(
                        fixture.lane_binding.lane_binding_digest
                    ),
                    event_sequence=2,
                    event_digest=(
                        prepared.lane_proof.topology_claim_record_digest
                    ),
                    state_digest=prepared.lane_proof.lane_state_digest,
                    response_digest=None,
                ),
            ),
        )
        self.assertIsNone(result.next_cursor)
        self.assertNotIn(str(fixture.root), repr(result))
        self.assertEqual(
            status_api.__all__,
            (
                "ProjectStatusLaneHead",
                "ProjectStatusOperationMetadata",
                "ProjectStatusInspection",
                "read_project_status",
                "read_lane_status",
                "read_key_status",
                "read_operation_status",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            result.entries[0].event_sequence = 3
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_lane_status_filters_same_epoch_to_exact_lane_id(self):
        fixture, second_lane_id, _prepared, _executed = (
            self._prepare_two_lanes()
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_lane_status(
            fixture.project_binding,
            lane_id=second_lane_id,
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("active", "query_status.lane_active"),
        )
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(
            result.normalized_read_contract_digest,
            LANE_READ_CONTRACT_DIGEST,
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0].lane_id, second_lane_id)
        self.assertEqual(result.entries[0].lane_generation, 1)
        self.assertIsNone(result.next_cursor)
        self.assertNotIn(str(fixture.root), repr(result))
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_key_status_uses_authenticated_open_topology_mapping(self):
        fixture, second_lane_id, _prepared, _executed = (
            self._prepare_two_lanes()
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_key_status(
            fixture.project_binding,
            consultant_key="beta",
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("active", "query_status.key_active"),
        )
        self.assertIsNone(result.operation_metadata)
        self.assertEqual(
            result.normalized_read_contract_digest,
            KEY_READ_CONTRACT_DIGEST,
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(result.entries[0].lane_id, second_lane_id)
        self.assertEqual(result.entries[0].lane_generation, 1)
        self.assertIsNone(result.next_cursor)
        self.assertNotIn(str(fixture.root), repr(result))
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_key_status_rejects_invalid_key_before_epoch_acquisition(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_key_status(
            fixture.project_binding,
            consultant_key="Reviewer",
            limit=1,
            cursor=None,
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("invalid Consultant Key consumed the clock")
            ),
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.read_contract_invalid"),
        )
        self.assertIsNone(result.normalized_read_contract_digest)
        self.assertIsNone(result.project_read_epoch)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_key_status_authenticates_absence_in_active_epoch(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        human_api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_key_status(
            fixture.project_binding,
            consultant_key="missing",
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("absent", "query_status.key_absent"),
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_key_status_quarantines_active_mapping_contradictions(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        lane_entry = _lane_head(1)
        cases = (
            (
                "binding_digest",
                (
                    _key_mapping(
                        lane_entry,
                        lane_binding_digest="sha256:" + "0" * 64,
                    ),
                ),
            ),
            ("missing_mapping", ()),
        )

        for name, topology_entries in cases:
            with self.subTest(case=name), _status_observations(
                lane_entries=(lane_entry,),
                topology_entries=topology_entries,
            ):
                result = status_api.read_key_status(
                    _vector_binding(),
                    consultant_key="beta",
                    limit=1,
                    cursor=None,
                    clock=lambda: OBSERVED_AT,
                )

            self.assertEqual(
                (result.status, result.detail_code),
                ("quarantined", "query_status.key_mapping_invalid"),
            )
            self.assertEqual(
                result.normalized_read_contract_digest,
                KEY_READ_CONTRACT_DIGEST,
            )
            self.assertIsNone(result.project_read_epoch)
            self.assertEqual(result.entries, ())
            self.assertIsNone(result.next_cursor)

    def test_key_status_reconciliation_returns_only_joined_entries(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        first_entry = _lane_head(1)
        second_entry = _lane_head(2, binding_character="7")

        with _status_observations(
            lane_entries=(first_entry, second_entry),
            topology_entries=(_key_mapping(second_entry),),
            topology_status="reconciliation_required",
            topology_detail="topology_store.pending_candidate",
        ):
            matched = status_api.read_key_status(
                _vector_binding(),
                consultant_key="beta",
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            missing = status_api.read_key_status(
                _vector_binding(),
                consultant_key="missing",
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )

        self.assertEqual(
            (matched.status, matched.detail_code),
            ("reconciliation_required", "topology_store.pending_candidate"),
        )
        self.assertIsNotNone(matched.project_read_epoch)
        self.assertEqual(len(matched.entries), 1)
        self.assertEqual(matched.entries[0].lane_generation, 2)
        self.assertIsNone(matched.next_cursor)
        self.assertEqual(
            (missing.status, missing.detail_code),
            ("reconciliation_required", "topology_store.pending_candidate"),
        )
        self.assertIsNotNone(missing.project_read_epoch)
        self.assertEqual(missing.entries, ())
        self.assertIsNone(missing.next_cursor)

    def test_key_status_pages_same_key_and_rejects_cross_contract_cursor(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        first_entry = _lane_head(1)
        second_entry = _lane_head(2, binding_character="7")

        with _status_observations(
            lane_entries=(first_entry, second_entry),
            topology_entries=(
                _key_mapping(first_entry),
                _key_mapping(second_entry),
            ),
        ):
            first = status_api.read_key_status(
                _vector_binding(),
                consultant_key="beta",
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            second = status_api.read_key_status(
                _vector_binding(),
                consultant_key="beta",
                limit=1,
                cursor=first.next_cursor,
                clock=lambda: OBSERVED_AT,
            )
            wrong_key = status_api.read_key_status(
                _vector_binding(),
                consultant_key="alpha",
                limit=1,
                cursor=first.next_cursor,
                clock=lambda: (_ for _ in ()).throw(
                    AssertionError("cross-key cursor consumed the clock")
                ),
            )
            wrong_selector = status_api.read_project_status(
                _vector_binding(),
                limit=1,
                cursor=first.next_cursor,
                clock=lambda: (_ for _ in ()).throw(
                    AssertionError("cross-selector cursor consumed the clock")
                ),
            )

        self.assertEqual(
            (first.status, first.detail_code),
            ("active", "query_status.key_active"),
        )
        self.assertEqual(
            first.normalized_read_contract_digest,
            KEY_READ_CONTRACT_DIGEST,
        )
        self.assertEqual(len(first.entries), 1)
        self.assertEqual(first.entries[0].lane_generation, 1)
        self.assertIsNotNone(first.next_cursor)
        self.assertEqual(
            (second.status, second.detail_code),
            ("active", "query_status.key_active"),
        )
        self.assertEqual(len(second.entries), 1)
        self.assertEqual(second.entries[0].lane_generation, 2)
        self.assertIsNone(second.next_cursor)
        self.assertEqual(
            second.project_read_epoch.epoch_digest,
            first.project_read_epoch.epoch_digest,
        )
        for stale in (wrong_key, wrong_selector):
            self.assertEqual(
                (stale.status, stale.detail_code),
                ("cursor_stale", "query_status.cursor_stale"),
            )
            self.assertIsNone(stale.project_read_epoch)
            self.assertEqual(stale.entries, ())
            self.assertIsNone(stale.next_cursor)

    def test_terminal_lane_and_key_cursors_are_stale(self):
        status_api = importlib.import_module("ask_herdr_project_status")
        first_entry = _lane_head(1)
        second_entry = _lane_head(2, binding_character="7")

        with _status_observations(
            lane_entries=(first_entry, second_entry),
            topology_entries=(
                _key_mapping(first_entry),
                _key_mapping(second_entry),
            ),
        ):
            lane_page = status_api.read_lane_status(
                _vector_binding(),
                lane_id=first_entry.lane_id,
                limit=2,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            lane_terminal = status_api.read_lane_status(
                _vector_binding(),
                lane_id=first_entry.lane_id,
                limit=2,
                cursor=status_api._encode_cursor(
                    epoch_digest=(
                        lane_page.project_read_epoch.epoch_digest
                    ),
                    read_contract_digest=(
                        lane_page.normalized_read_contract_digest
                    ),
                    last_identity_digest=(
                        status_api._lane_identity_digest(second_entry)
                    ),
                ),
                clock=lambda: OBSERVED_AT,
            )
            key_page = status_api.read_key_status(
                _vector_binding(),
                consultant_key="beta",
                limit=2,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
            key_terminal = status_api.read_key_status(
                _vector_binding(),
                consultant_key="beta",
                limit=2,
                cursor=status_api._encode_cursor(
                    epoch_digest=key_page.project_read_epoch.epoch_digest,
                    read_contract_digest=(
                        key_page.normalized_read_contract_digest
                    ),
                    last_identity_digest=(
                        status_api._lane_identity_digest(second_entry)
                    ),
                ),
                clock=lambda: OBSERVED_AT,
            )

        for page in (lane_page, key_page):
            self.assertEqual(page.status, "active")
            self.assertEqual(len(page.entries), 2)
            self.assertIsNone(page.next_cursor)
        for stale in (lane_terminal, key_terminal):
            self.assertEqual(
                (stale.status, stale.detail_code),
                ("cursor_stale", "query_status.cursor_stale"),
            )
            self.assertIsNone(stale.project_read_epoch)
            self.assertEqual(stale.entries, ())
            self.assertIsNone(stale.next_cursor)

    def test_lane_status_authenticates_absence_in_active_epoch(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        human_api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_lane_status(
            fixture.project_binding,
            lane_id="ffffffff-ffff-4fff-8fff-ffffffffffff",
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("absent", "query_status.lane_absent"),
        )
        self.assertEqual(
            result.normalized_read_contract_digest,
            LANE_READ_CONTRACT_DIGEST,
        )
        self.assertIsNotNone(result.project_read_epoch)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_lane_status_rejects_invalid_lane_id_before_epoch_acquisition(self):
        human_api = importlib.import_module("ask_herdr_human_first_lane")
        fixture = _Fixture(human_api)
        self.addCleanup(fixture.close)
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        result = status_api.read_lane_status(
            fixture.project_binding,
            lane_id="not-a-lane-id",
            limit=1,
            cursor=None,
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("invalid Lane ID consumed the clock")
            ),
        )

        self.assertEqual(
            (result.status, result.detail_code),
            ("quarantined", "query_status.read_contract_invalid"),
        )
        self.assertIsNone(result.normalized_read_contract_digest)
        self.assertIsNone(result.project_read_epoch)
        self.assertEqual(result.entries, ())
        self.assertIsNone(result.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_metadata_cursor_pages_exact_epoch_and_rejects_contract_drift(self):
        fixture, second_lane_id, _prepared, _executed = (
            self._prepare_two_lanes()
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        first = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )
        self.assertEqual(first.status, "active")
        self.assertEqual(len(first.entries), 1)
        self.assertEqual(first.entries[0].lane_id, fixture.lane_binding.lane_id)
        self.assertIsNotNone(first.next_cursor)
        self.assertLessEqual(len(first.next_cursor), 1024)
        decoded = status_api._decode_cursor(
            first.next_cursor,
            read_contract_digest=PROJECT_READ_CONTRACT_DIGEST,
        )
        self.assertEqual(
            set(decoded),
            {
                "schema",
                "project_read_epoch_digest",
                "normalized_read_contract_digest",
                "ordering_digest",
                "last_identity_digest",
                "cursor_binding_digest",
            },
        )
        self.assertEqual(decoded["schema"], "ask_herdr.metadata_cursor.v1")
        self.assertEqual(
            decoded["ordering_digest"],
            PROJECT_STATUS_ORDERING_DIGEST,
        )
        self.assertEqual(
            decoded["normalized_read_contract_digest"],
            PROJECT_READ_CONTRACT_DIGEST,
        )

        second = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=first.next_cursor,
            clock=lambda: OBSERVED_AT,
        )
        self.assertEqual(second.status, "active")
        self.assertEqual(len(second.entries), 1)
        self.assertEqual(second.entries[0].lane_id, second_lane_id)
        self.assertIsNone(second.next_cursor)
        self.assertEqual(
            second.project_read_epoch.epoch_digest,
            first.project_read_epoch.epoch_digest,
        )

        stale = status_api.read_project_status(
            fixture.project_binding,
            limit=2,
            cursor=first.next_cursor,
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("contract-drifted cursor consumed the clock")
            ),
        )
        self.assertEqual(stale.status, "cursor_stale")
        self.assertEqual(stale.detail_code, "query_status.cursor_stale")
        self.assertIsNone(stale.project_read_epoch)
        self.assertEqual(stale.entries, ())
        self.assertIsNone(stale.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), before)

    def test_cursor_tamper_and_epoch_drift_never_return_a_page(self):
        fixture, _second_lane_id, prepared, executed = (
            self._prepare_two_lanes()
        )
        status_api = importlib.import_module("ask_herdr_project_status")
        before = snapshot_tree(fixture.root)

        malformed = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor="mcv1.\ud800",
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("malformed cursor consumed the clock")
            ),
        )
        self.assertEqual(
            (malformed.status, malformed.detail_code),
            ("cursor_stale", "query_status.cursor_stale"),
        )
        self.assertIsNone(malformed.project_read_epoch)
        self.assertEqual(malformed.entries, ())

        first = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )
        repeated = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=None,
            clock=lambda: OBSERVED_AT,
        )
        self.assertEqual(repeated, first)
        self.assertIsNotNone(first.next_cursor)
        alphabet = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        last_index = alphabet.index(first.next_cursor[-1])
        self.assertEqual(last_index % 16, 0)
        alias_value = first.next_cursor[:-1] + alphabet[last_index + 1]
        aliased = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=alias_value,
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("noncanonical base64url consumed the clock")
            ),
        )
        self.assertEqual(
            (aliased.status, aliased.detail_code),
            ("cursor_stale", "query_status.cursor_stale"),
        )
        replacement = "A" if first.next_cursor[-1] != "A" else "B"
        tampered_value = first.next_cursor[:-1] + replacement
        tampered = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=tampered_value,
            clock=lambda: (_ for _ in ()).throw(
                AssertionError("self-binding failure consumed the clock")
            ),
        )
        self.assertEqual(
            (tampered.status, tampered.detail_code),
            ("cursor_stale", "query_status.cursor_stale"),
        )
        self.assertEqual(snapshot_tree(fixture.root), before)

        dispatch = lane_store.apply_lane_turn_event(
            fixture.lane_binding,
            BeginDispatch(
                operation_id=prepared.lane_proof.operation_id,
                canonical_request_digest=(
                    prepared.lane_proof.canonical_request_digest
                ),
                attempt_id=prepared.lane_proof.attempt_id,
                dispatch_nonce="project-status-epoch-drift",
                project_topology_digest=executed.project_topology_digest,
            ),
        )
        self.assertEqual(dispatch.outcome_kind, "lane_event_committed")
        after_drift = snapshot_tree(fixture.root)
        clock_calls = []
        stale = status_api.read_project_status(
            fixture.project_binding,
            limit=1,
            cursor=first.next_cursor,
            clock=lambda: clock_calls.append(OBSERVED_AT) or OBSERVED_AT,
        )
        self.assertEqual(clock_calls, [OBSERVED_AT])
        self.assertEqual(
            (stale.status, stale.detail_code),
            ("cursor_stale", "query_status.cursor_stale"),
        )
        self.assertIsNone(stale.project_read_epoch)
        self.assertEqual(stale.entries, ())
        self.assertIsNone(stale.next_cursor)
        self.assertEqual(snapshot_tree(fixture.root), after_drift)


if __name__ == "__main__":
    unittest.main()
