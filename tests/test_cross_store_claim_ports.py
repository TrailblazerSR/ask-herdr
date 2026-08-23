#!/usr/bin/env python3
"""RED contract for lock-aware Policy -> Lane -> Topology mutation ports.

The interface under test is deliberately private and provider-free.  One
``ProjectMutationLease`` owns the already validated/locked project-root
descriptor.  Each store port borrows that lease; none may reopen, relock,
close, duplicate, or unlock the root descriptor.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import importlib
import inspect
import os
from pathlib import Path
import sys
import tempfile
from typing import Iterator, Optional
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import ask_herdr_authority_store as authority_store  # noqa: E402
import ask_herdr_lane_store as lane_store  # noqa: E402
import ask_herdr_policy_ledger as policy_ledger  # noqa: E402
import ask_herdr_topology_store as topology_store  # noqa: E402
from ask_herdr_authority_store import (  # noqa: E402
    ConfirmedProjectGenesis,
    ValidatedBootstrapReceipt,
    initialize_authority_store,
)
from ask_herdr_lane_store import (  # noqa: E402
    ValidatedLaneGenerationBinding,
    apply_lane_turn_event,
    inspect_lane_turn,
)
from ask_herdr_lane_turn import (  # noqa: E402
    BeginDispatch,
    NativeIdentityMode,
    PrepareAdmittedAttempt,
    TurnPhase,
)
from ask_herdr_policy_ledger import (  # noqa: E402
    ConfirmedHumanAdmission,
    ValidatedHumanApprovalReceipt,
    commit_human_admission,
)
from ask_herdr_topology_store import (  # noqa: E402
    TopologyMutationIntent,
    ValidatedTopologyStoreBinding,
    inspect_topology_store,
)


GENESIS_OPERATION_ID = "11111111-1111-4111-8111-111111111111"
BOOTSTRAP_RECEIPT_ID = "22222222-2222-4222-8222-222222222222"
AUTHORITY_ID = "33333333-3333-4333-8333-333333333333"
PROFILE_ID = "44444444-4444-4444-8444-444444444444"
LEDGER_ID = "55555555-5555-4555-8555-555555555555"
OPERATION_ID = "66666666-6666-4666-8666-666666666666"
APPROVAL_RECEIPT_ID = "77777777-7777-4777-8777-777777777777"
DECISION_ID = "88888888-8888-4888-8888-888888888888"
LANE_ID = "99999999-9999-4999-8999-999999999999"
ATTEMPT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TOPOLOGY_MUTATION_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

OTHER_OPERATION_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
OTHER_RECEIPT_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
OTHER_TOPOLOGY_MUTATION_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

GENESIS_REQUEST_DIGEST = "sha256:" + "1" * 64
REQUEST_DIGEST = "sha256:" + "2" * 64
OTHER_REQUEST_DIGEST = "sha256:" + "3" * 64
HEAD_DIGEST = "sha256:" + "4" * 64
LANE_BINDING_DIGEST = "sha256:" + "5" * 64
LANE_WORKSPACE_BINDING_DIGEST = "sha256:" + "6" * 64
PRECONDITION_DIGEST = "sha256:" + "7" * 64
POSTCONDITION_DIGEST = "sha256:" + "8" * 64
NONEXISTENT_PRIOR_TOPOLOGY_DIGEST = "sha256:" + "9" * 64

TOPOLOGY_NONCE = "topology-nonce-cross-store-1"
OTHER_TOPOLOGY_NONCE = "topology-nonce-cross-store-2"
COMPLETION_MARKER = "<<<ASK_HERDR_TURN_DONE:cross-store-claim-1>>>"
DISPATCH_NONCE = "dispatch-cross-store-claim-1"

GENESIS_TIME = datetime(2026, 8, 13, 2, 0, 0, tzinfo=timezone.utc)
ADMISSION_TIME = datetime(2026, 8, 13, 2, 2, 0, tzinfo=timezone.utc)


def _lease_module():
    """Load the intended seam lazily so the missing module is genuine RED."""

    return importlib.import_module("ask_herdr_project_mutation_lease")


def _genesis(root: Path) -> ConfirmedProjectGenesis:
    metadata = root.stat()
    receipt = ValidatedBootstrapReceipt(
        receipt_id=BOOTSTRAP_RECEIPT_ID,
        operation_id=GENESIS_OPERATION_ID,
        canonical_request_digest=GENESIS_REQUEST_DIGEST,
        canonical_root=str(root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        confirmed_at="2026-08-13T01:59:00.000000Z",
    )
    return ConfirmedProjectGenesis(
        canonical_root=str(root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        operation_id=GENESIS_OPERATION_ID,
        canonical_request_digest=GENESIS_REQUEST_DIGEST,
        bootstrap_receipt=receipt,
        lifetime="initial",
    )


def _admission(
    *,
    operation_id: str = OPERATION_ID,
    request_digest: str = REQUEST_DIGEST,
    receipt_id: str = APPROVAL_RECEIPT_ID,
) -> ConfirmedHumanAdmission:
    receipt = ValidatedHumanApprovalReceipt(
        receipt_id=receipt_id,
        project_authority_id=AUTHORITY_ID,
        policy_profile_id=PROFILE_ID,
        operation="turn.consult",
        action_reason="initial",
        provider="claude",
        operation_id=operation_id,
        canonical_request_digest=request_digest,
        confirmed_at="2026-08-13T02:01:00.000000Z",
        expires_at="2026-08-13T02:10:00.000000Z",
    )
    return ConfirmedHumanAdmission(
        project_authority_id=AUTHORITY_ID,
        policy_profile_id=PROFILE_ID,
        operation="turn.consult",
        action_reason="initial",
        provider="claude",
        operation_id=operation_id,
        canonical_request_digest=request_digest,
        approval_receipt=receipt,
    )


def _prepare(
    policy_record_digest: str,
    *,
    reservation_id: Optional[str] = None,
) -> PrepareAdmittedAttempt:
    return PrepareAdmittedAttempt(
        operation="turn.consult",
        operation_id=OPERATION_ID,
        canonical_request_digest=REQUEST_DIGEST,
        lane_id=LANE_ID,
        lane_generation=1,
        attempt_id=ATTEMPT_ID,
        expected_head_digest=HEAD_DIGEST,
        native_identity_mode=NativeIdentityMode.ESTABLISH_NEW,
        expected_native_correlation_digest=None,
        expected_turn_sequence=1,
        expected_completion_marker=COMPLETION_MARKER,
        reservation_id=reservation_id,
        direct_human_policy_record_digest=policy_record_digest,
    )


def _dispatch() -> BeginDispatch:
    return BeginDispatch(
        operation_id=OPERATION_ID,
        canonical_request_digest=REQUEST_DIGEST,
        attempt_id=ATTEMPT_ID,
        dispatch_nonce=DISPATCH_NONCE,
        project_topology_digest=POSTCONDITION_DIGEST,
    )


@dataclass
class _Fixture:
    temporary: tempfile.TemporaryDirectory
    root: Path
    admission: ConfirmedHumanAdmission
    policy_record_digest: Optional[str]
    lane_binding: ValidatedLaneGenerationBinding
    topology_binding: ValidatedTopologyStoreBinding
    prepared_record_digest: Optional[str]
    workspace: Path

    def close(self) -> None:
        self.temporary.cleanup()


def _fixture(
    *,
    commit_policy: bool = True,
    prepare_lane: bool = True,
    reservation_id: Optional[str] = None,
) -> _Fixture:
    temporary = tempfile.TemporaryDirectory(
        prefix="ask-herdr-cross-store-red-",
    )
    root = Path(temporary.name).resolve()
    os.chmod(root, 0o700)
    generated = iter((AUTHORITY_ID, PROFILE_ID, LEDGER_ID))
    initialized = initialize_authority_store(
        _genesis(root),
        uuid_factory=lambda: next(generated),
        clock=lambda: GENESIS_TIME,
    )
    if initialized.outcome_kind != "project_initialized":
        temporary.cleanup()
        raise AssertionError(f"authority fixture failed: {initialized!r}")

    admission = _admission()
    policy_record_digest: Optional[str] = None
    if commit_policy:
        admitted = commit_human_admission(
            str(root),
            admission,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        if admitted.outcome_kind != "human_admission_committed":
            temporary.cleanup()
            raise AssertionError(f"policy fixture failed: {admitted!r}")
        policy_record_digest = admitted.record_digest

    metadata = root.stat()
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=str(root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        project_authority_id=AUTHORITY_ID,
        lane_id=LANE_ID,
        lane_generation=1,
        lane_binding_digest=LANE_BINDING_DIGEST,
    )
    prepared_record_digest: Optional[str] = None
    if prepare_lane:
        if policy_record_digest is None:
            temporary.cleanup()
            raise AssertionError("prepared Lane requires a committed policy record")
        prepared = apply_lane_turn_event(
            lane_binding,
            _prepare(policy_record_digest, reservation_id=reservation_id),
        )
        if prepared.outcome_kind != "lane_event_committed":
            temporary.cleanup()
            raise AssertionError(f"lane fixture failed: {prepared!r}")
        prepared_record_digest = prepared.record_digest

    workspace_parent = root / "lane-workspaces"
    workspace_parent.mkdir(mode=0o700)
    workspace = workspace_parent / LANE_ID
    workspace.mkdir(mode=0o700)
    topology_binding = ValidatedTopologyStoreBinding(
        canonical_project_root=str(root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        project_authority_id=AUTHORITY_ID,
        namespace="ask-pipeline",
    )
    return _Fixture(
        temporary,
        root,
        admission,
        policy_record_digest,
        lane_binding,
        topology_binding,
        prepared_record_digest,
        workspace,
    )


def _lease_binding(api, fixture: _Fixture):
    metadata = fixture.root.stat()
    return api.ValidatedProjectMutationBinding(
        canonical_project_root=str(fixture.root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        project_authority_id=AUTHORITY_ID,
    )


@contextmanager
def _forbid_nested_root_open(root: Path) -> Iterator[None]:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("under-lease port reopened or relocked project root")

    root_metadata = root.stat()
    root_identity = (root_metadata.st_dev, root_metadata.st_ino)
    real_flock = policy_ledger.fcntl.flock

    def forbid_root_relock(descriptor, operation):
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == root_identity:
            raise AssertionError("under-lease port relocked project root")
        return real_flock(descriptor, operation)

    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(
                authority_store,
                "_open_canonical_root",
                side_effect=forbidden,
            )
        )
        stack.enter_context(
            mock.patch.object(
                policy_ledger,
                "_open_canonical_root",
                side_effect=forbidden,
            )
        )
        stack.enter_context(
            mock.patch.object(lane_store, "_open_root", side_effect=forbidden)
        )
        stack.enter_context(
            mock.patch.object(
                topology_store,
                "_open_root",
                side_effect=forbidden,
            )
        )
        stack.enter_context(
            mock.patch.object(
                policy_ledger.fcntl,
                "flock",
                side_effect=forbid_root_relock,
            )
        )
        yield


def _intent(fixture: _Fixture, policy_proof, lane_proof, *, bad_prior=False):
    return TopologyMutationIntent(
        mutation_id=lane_proof.topology_mutation_id,
        operation_id=policy_proof.operation_id,
        canonical_request_digest=policy_proof.canonical_request_digest,
        policy_record_digest=policy_proof.policy_record_digest,
        lane_state_digest=lane_proof.lane_state_digest,
        lane_id=lane_proof.lane_id,
        lane_generation=lane_proof.lane_generation,
        lane_binding_digest=fixture.lane_binding.lane_binding_digest,
        lane_workspace_binding_digest=LANE_WORKSPACE_BINDING_DIGEST,
        consultant_key="alpha",
        topology_nonce=lane_proof.topology_nonce,
        lane_workspace_cwd=str(fixture.workspace),
        prior_topology_digest=(
            NONEXISTENT_PRIOR_TOPOLOGY_DIGEST if bad_prior else None
        ),
        intended_action="reconcile_or_provision",
        precondition_digest=PRECONDITION_DIGEST,
        expected_postcondition_digest=POSTCONDITION_DIGEST,
    )


class CrossStoreClaimPortContractTest(unittest.TestCase):
    def test_one_lease_drives_typed_policy_claim_and_topology_proofs_without_reopen(self):
        fixture = _fixture()
        self.addCleanup(fixture.close)
        api = _lease_module()

        with api.hold_project_mutation_lease(_lease_binding(api, fixture)) as lease:
            self.assertIsInstance(lease, api.ProjectMutationLease)
            with _forbid_nested_root_open(fixture.root):
                policy_proof = (
                    policy_ledger.validate_committed_human_admission_under_lease(
                        lease,
                        fixture.admission,
                    )
                )
                self.assertIsInstance(
                    policy_proof,
                    policy_ledger.CommittedHumanAdmissionProof,
                )
                self.assertEqual(policy_proof.operation_id, OPERATION_ID)
                self.assertEqual(
                    policy_proof.canonical_request_digest,
                    REQUEST_DIGEST,
                )
                self.assertEqual(
                    policy_proof.policy_record_digest,
                    fixture.policy_record_digest,
                )

                lane_proof = lane_store.claim_topology_provisioning_under_lease(
                    lease,
                    fixture.lane_binding,
                    policy_proof=policy_proof,
                    topology_mutation_id=TOPOLOGY_MUTATION_ID,
                    topology_nonce=TOPOLOGY_NONCE,
                )
                self.assertIsInstance(
                    lane_proof,
                    lane_store.ClaimedLaneProof,
                )
                self.assertEqual(
                    lane_proof.prepared_lane_record_digest,
                    fixture.prepared_record_digest,
                )
                self.assertRegex(
                    lane_proof.topology_claim_record_digest,
                    r"\Asha256:[0-9a-f]{64}\Z",
                )
                self.assertRegex(
                    lane_proof.lane_state_digest,
                    r"\Asha256:[0-9a-f]{64}\Z",
                )

                port = topology_store.commit_mutation_intent_under_lease
                self.assertNotIn("runner", inspect.signature(port).parameters)
                topology_result = port(
                    lease,
                    fixture.topology_binding,
                    _intent(fixture, policy_proof, lane_proof),
                    policy_proof=policy_proof,
                    lane_proof=lane_proof,
                )

        self.assertEqual(
            topology_result.outcome_kind,
            "topology_mutation_prepared",
        )
        lane = inspect_lane_turn(fixture.lane_binding)
        topology = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(lane.event_count, 2)
        self.assertEqual(
            lane.state.topology_provisioning_claim.prepared_lane_record_digest,
            fixture.prepared_record_digest,
        )
        self.assertEqual(
            topology.unfinished_mutation_ids,
            (TOPOLOGY_MUTATION_ID,),
        )
        self.assertFalse(topology.resend_allowed)

    def test_absent_or_mismatched_committed_policy_never_claims_lane_or_topology(self):
        for case in ("absent", "mismatched"):
            with self.subTest(case=case):
                fixture = _fixture(
                    commit_policy=(case != "absent"),
                    prepare_lane=False,
                )
                self.addCleanup(fixture.close)
                api = _lease_module()
                candidate = (
                    fixture.admission
                    if case == "absent"
                    else _admission(
                        operation_id=OTHER_OPERATION_ID,
                        request_digest=OTHER_REQUEST_DIGEST,
                        receipt_id=OTHER_RECEIPT_ID,
                    )
                )

                with api.hold_project_mutation_lease(
                    _lease_binding(api, fixture)
                ) as lease:
                    with _forbid_nested_root_open(fixture.root):
                        with self.assertRaises(
                            api.ProjectMutationLeaseError
                        ) as caught:
                            policy_ledger.validate_committed_human_admission_under_lease(
                                lease,
                                candidate,
                            )

                self.assertIn(
                    caught.exception.detail_code,
                    {
                        "policy_ledger.human_admission_absent",
                        "policy_ledger.human_admission_mismatch",
                    },
                )
                self.assertEqual(
                    inspect_lane_turn(fixture.lane_binding).status,
                    "absent",
                )
                self.assertEqual(
                    inspect_topology_store(fixture.topology_binding).status,
                    "absent",
                )

    def test_wrong_lane_state_cannot_be_claimed_and_topology_remains_absent(self):
        fixture = _fixture(reservation_id="automatic-budget-hold-1")
        self.addCleanup(fixture.close)
        api = _lease_module()

        with api.hold_project_mutation_lease(_lease_binding(api, fixture)) as lease:
            with _forbid_nested_root_open(fixture.root):
                policy_proof = (
                    policy_ledger.validate_committed_human_admission_under_lease(
                        lease,
                        fixture.admission,
                    )
                )
                with self.assertRaises(api.ProjectMutationLeaseError) as caught:
                    lane_store.claim_topology_provisioning_under_lease(
                        lease,
                        fixture.lane_binding,
                        policy_proof=policy_proof,
                        topology_mutation_id=TOPOLOGY_MUTATION_ID,
                        topology_nonce=TOPOLOGY_NONCE,
                    )

        self.assertEqual(
            caught.exception.detail_code,
            "lane_store.topology_claim_not_admissible",
        )
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).event_count, 1)
        self.assertEqual(
            inspect_topology_store(fixture.topology_binding).status,
            "absent",
        )

    def test_exact_replay_returns_same_proofs_without_duplicate_records(self):
        fixture = _fixture()
        self.addCleanup(fixture.close)
        api = _lease_module()

        with api.hold_project_mutation_lease(_lease_binding(api, fixture)) as lease:
            with _forbid_nested_root_open(fixture.root):
                policy_first = (
                    policy_ledger.validate_committed_human_admission_under_lease(
                        lease,
                        fixture.admission,
                    )
                )
                policy_replay = (
                    policy_ledger.validate_committed_human_admission_under_lease(
                        lease,
                        fixture.admission,
                    )
                )
                claim_first = lane_store.claim_topology_provisioning_under_lease(
                    lease,
                    fixture.lane_binding,
                    policy_proof=policy_first,
                    topology_mutation_id=TOPOLOGY_MUTATION_ID,
                    topology_nonce=TOPOLOGY_NONCE,
                )
                claim_replay = lane_store.claim_topology_provisioning_under_lease(
                    lease,
                    fixture.lane_binding,
                    policy_proof=policy_replay,
                    topology_mutation_id=TOPOLOGY_MUTATION_ID,
                    topology_nonce=TOPOLOGY_NONCE,
                )
                intent = _intent(fixture, policy_first, claim_first)
                topology_first = (
                    topology_store.commit_mutation_intent_under_lease(
                        lease,
                        fixture.topology_binding,
                        intent,
                        policy_proof=policy_first,
                        lane_proof=claim_first,
                    )
                )
                topology_replay = (
                    topology_store.commit_mutation_intent_under_lease(
                        lease,
                        fixture.topology_binding,
                        intent,
                        policy_proof=policy_replay,
                        lane_proof=claim_replay,
                    )
                )

        self.assertEqual(policy_replay, policy_first)
        self.assertEqual(claim_replay, claim_first)
        self.assertEqual(topology_first.outcome_kind, "topology_mutation_prepared")
        self.assertEqual(
            topology_replay.outcome_kind,
            "topology_mutation_already_prepared",
        )
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).event_count, 2)
        transactions = fixture.root / ".ask-herdr-topology" / "transactions"
        self.assertEqual(len(tuple(transactions.glob("event.*.txn"))), 1)

    def test_topology_failure_leaves_claim_blocking_dispatch_and_runner_unreached(self):
        fixture = _fixture()
        self.addCleanup(fixture.close)
        api = _lease_module()
        runner_calls = []

        def runner_must_not_run(*args):
            runner_calls.append(args)
            raise AssertionError("runner reached after topology intent failure")

        with api.hold_project_mutation_lease(_lease_binding(api, fixture)) as lease:
            with _forbid_nested_root_open(fixture.root):
                policy_proof = (
                    policy_ledger.validate_committed_human_admission_under_lease(
                        lease,
                        fixture.admission,
                    )
                )
                lane_proof = lane_store.claim_topology_provisioning_under_lease(
                    lease,
                    fixture.lane_binding,
                    policy_proof=policy_proof,
                    topology_mutation_id=TOPOLOGY_MUTATION_ID,
                    topology_nonce=TOPOLOGY_NONCE,
                )
                topology_failure = (
                    topology_store.commit_mutation_intent_under_lease(
                        lease,
                        fixture.topology_binding,
                        _intent(
                            fixture,
                            policy_proof,
                            lane_proof,
                            bad_prior=True,
                        ),
                        policy_proof=policy_proof,
                        lane_proof=lane_proof,
                    )
                )
                if topology_failure.outcome_kind == "topology_mutation_prepared":
                    runner_must_not_run("unreachable")

        self.assertEqual(
            topology_failure.outcome_kind,
            "topology_mutation_conflict",
        )
        self.assertEqual(
            topology_failure.detail_code,
            "topology_store.prior_topology_mismatch",
        )
        self.assertEqual(runner_calls, [])

        lane = inspect_lane_turn(fixture.lane_binding)
        self.assertIsNotNone(lane.state.topology_provisioning_claim)
        self.assertIsNone(lane.state.topology_provisioned)
        self.assertEqual(lane.state.phase, TurnPhase.PREPARED)
        blocked = apply_lane_turn_event(fixture.lane_binding, _dispatch())
        self.assertEqual(blocked.outcome_kind, "lane_event_conflict")
        self.assertEqual(
            blocked.detail_code,
            "lane_turn.topology_provisioning_not_settled",
        )
        self.assertIsNone(inspect_lane_turn(fixture.lane_binding).state.dispatch_intent)

        # The changed replay also cannot silently retarget the durable claim.
        with api.hold_project_mutation_lease(_lease_binding(api, fixture)) as lease:
            with _forbid_nested_root_open(fixture.root):
                with self.assertRaises(api.ProjectMutationLeaseError):
                    lane_store.claim_topology_provisioning_under_lease(
                        lease,
                        fixture.lane_binding,
                        policy_proof=policy_proof,
                        topology_mutation_id=OTHER_TOPOLOGY_MUTATION_ID,
                        topology_nonce=OTHER_TOPOLOGY_NONCE,
                    )


if __name__ == "__main__":
    unittest.main()
