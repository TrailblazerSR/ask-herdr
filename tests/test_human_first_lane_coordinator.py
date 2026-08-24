#!/usr/bin/env python3
"""TDD contract for one leased direct-human first-Lane prerequisite unit."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import importlib
import inspect
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Iterator
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import ask_herdr_lane_store as lane_store  # noqa: E402
import ask_herdr_policy_ledger as policy_ledger  # noqa: E402
import ask_herdr_project_mutation_lease as project_lease  # noqa: E402
import ask_herdr_topology_store as topology_store  # noqa: E402
from ask_herdr_authority_store import initialize_authority_store  # noqa: E402
from ask_herdr_herdr_transport import ProvisionIntent  # noqa: E402
from ask_herdr_journaled_provision import (  # noqa: E402
    JournaledProvisionRequest,
    JournaledProvisionOutcome,
    lane_workspace_binding_digest,
    provision_postcondition_digest,
)
from ask_herdr_lane_store import (  # noqa: E402
    ValidatedLaneGenerationBinding,
    inspect_lane_turn,
)
from ask_herdr_policy_ledger import inspect_policy_authority  # noqa: E402
from ask_herdr_project_mutation_lease import (  # noqa: E402
    ValidatedProjectMutationBinding,
)
from ask_herdr_topology_store import (  # noqa: E402
    ValidatedTopologyStoreBinding,
    inspect_topology_store,
)
from tests.test_cross_store_claim_ports import (  # noqa: E402
    ADMISSION_TIME,
    ATTEMPT_ID,
    AUTHORITY_ID,
    COMPLETION_MARKER,
    DECISION_ID,
    GENESIS_TIME,
    HEAD_DIGEST,
    LANE_BINDING_DIGEST,
    LANE_ID,
    OPERATION_ID,
    PROFILE_ID,
    REQUEST_DIGEST,
    TOPOLOGY_MUTATION_ID,
    TOPOLOGY_NONCE,
    _admission,
    _genesis,
)
from tests.test_journaled_provision import (  # noqa: E402
    ProjectScriptedHerdr,
    SESSION_STEP_ID,
    WORKSPACE_STEP_ID,
    _is_server_start,
    _is_workspace_create,
)


CONSULTANT_KEY = "alpha"


def _api():
    return importlib.import_module("ask_herdr_human_first_lane")


def _commit_claimed_command(fixture, prepared, command):
    """Seed an anchored pending command through its only authority port."""

    with project_lease.hold_project_mutation_lease(
        fixture.project_binding
    ) as lease:
        return topology_store.commit_claimed_command_intent_under_lease(
            lease,
            fixture.topology_binding,
            command,
            mutation_intent=prepared.mutation_intent,
            policy_proof=prepared.policy_proof,
            lane_proof=prepared.lane_proof,
        )


class _Fixture:
    def __init__(self, api: Any) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ask-herdr-human-first-lane-",
        )
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        identifiers = iter(
            (
                AUTHORITY_ID,
                PROFILE_ID,
                "55555555-5555-4555-8555-555555555555",
            )
        )
        initialized = initialize_authority_store(
            _genesis(self.root),
            uuid_factory=lambda: next(identifiers),
            clock=lambda: GENESIS_TIME,
        )
        if initialized.outcome_kind != "project_initialized":
            self.close()
            raise AssertionError(initialized)

        metadata = self.root.stat()
        self.project_binding = ValidatedProjectMutationBinding(
            canonical_root=str(self.root),
            filesystem_device=metadata.st_dev,
            filesystem_inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            project_authority_id=AUTHORITY_ID,
        )
        self.lane_binding = ValidatedLaneGenerationBinding(
            canonical_root=str(self.root),
            filesystem_device=metadata.st_dev,
            filesystem_inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            project_authority_id=AUTHORITY_ID,
            lane_id=LANE_ID,
            lane_generation=1,
            lane_binding_digest=LANE_BINDING_DIGEST,
        )
        self.topology_binding = ValidatedTopologyStoreBinding(
            canonical_project_root=str(self.root),
            filesystem_device=metadata.st_dev,
            filesystem_inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            project_authority_id=AUTHORITY_ID,
            namespace="ask-pipeline",
        )
        workspace_parent = self.root / "lane-workspaces"
        workspace_parent.mkdir(mode=0o700)
        self.workspace = workspace_parent / LANE_ID
        self.workspace.mkdir(mode=0o700)
        self.provision_intent = ProvisionIntent(
            project_id=AUTHORITY_ID,
            lane_id=LANE_ID,
            consultant_key=CONSULTANT_KEY,
            project_root=str(self.root),
            topology_nonce=TOPOLOGY_NONCE,
            lane_workspace_cwd=str(self.workspace),
        )
        self.request = api.HumanFirstLanePreparationRequest(
            project_binding=self.project_binding,
            admission=_admission(),
            lane_binding=self.lane_binding,
            topology_binding=self.topology_binding,
            attempt_id=ATTEMPT_ID,
            expected_head_digest=HEAD_DIGEST,
            expected_completion_marker=COMPLETION_MARKER,
            topology_mutation_id=TOPOLOGY_MUTATION_ID,
            topology_nonce=TOPOLOGY_NONCE,
            provision_intent=self.provision_intent,
            session_start_step_id=SESSION_STEP_ID,
            workspace_create_step_id=WORKSPACE_STEP_ID,
        )

    def close(self) -> None:
        self.temporary.cleanup()


@contextmanager
def _prove_no_nested_project_root_lock(api: Any) -> Iterator[None]:
    real_hold = project_lease.hold_project_mutation_lease

    @contextmanager
    def instrumented_hold(binding):
        with real_hold(binding) as lease:
            root_metadata = os.fstat(
                project_lease._borrow_validated_root(lease, binding)
            )
            root_identity = (root_metadata.st_dev, root_metadata.st_ino)
            real_flock = lane_store.fcntl.flock

            def forbidden(*_args, **_kwargs):
                raise AssertionError("store reopened the project root")

            def guarded_flock(descriptor, operation):
                metadata = os.fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) == root_identity:
                    raise AssertionError("store relocked the project root")
                return real_flock(descriptor, operation)

            with mock.patch.object(
                policy_ledger,
                "_open_canonical_root",
                side_effect=forbidden,
            ), mock.patch.object(
                lane_store,
                "_open_root",
                side_effect=forbidden,
            ), mock.patch.object(
                topology_store,
                "_open_root",
                side_effect=forbidden,
            ), mock.patch.object(
                lane_store.fcntl,
                "flock",
                side_effect=guarded_flock,
            ):
                yield lease

    with mock.patch.object(
        api,
        "hold_project_mutation_lease",
        side_effect=instrumented_hold,
    ):
        yield


class HumanFirstLaneCoordinatorTest(unittest.TestCase):
    def test_one_lease_derives_policy_lane_workspace_and_topology_facts(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        self.assertNotIn(
            "runner",
            inspect.signature(api.prepare_human_first_lane).parameters,
        )

        with _prove_no_nested_project_root_lock(api):
            prepared = api.prepare_human_first_lane(
                fixture.request,
                clock=lambda: ADMISSION_TIME,
                uuid_factory=lambda: DECISION_ID,
            )

        self.assertIsInstance(prepared, api.PreparedFirstLaneProvision)
        self.assertIsInstance(
            prepared.journaled_request,
            JournaledProvisionRequest,
        )
        self.assertEqual(
            prepared.mutation_intent.policy_record_digest,
            prepared.policy_proof.policy_record_digest,
        )
        self.assertEqual(
            prepared.mutation_intent.lane_state_digest,
            prepared.lane_proof.lane_state_digest,
        )
        self.assertEqual(
            prepared.mutation_intent.lane_workspace_binding_digest,
            lane_workspace_binding_digest(
                fixture.topology_binding,
                fixture.provision_intent,
            ),
        )
        self.assertEqual(
            prepared.mutation_intent.expected_postcondition_digest,
            provision_postcondition_digest(fixture.provision_intent),
        )
        self.assertEqual(
            prepared.journaled_request.mutation_intent,
            prepared.mutation_intent,
        )
        self.assertEqual(inspect_policy_authority(str(fixture.root)).head_sequence, 1)
        lane = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane.event_count, 2)
        self.assertIsNotNone(lane.state.topology_provisioning_claim)
        topology = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(topology.unfinished_mutation_ids, (TOPOLOGY_MUTATION_ID,))
        self.assertFalse(topology.resend_allowed)

    def test_exact_replay_is_identical_and_consumes_no_new_clock_or_uuid(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        first = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )

        def forbidden_dependency():
            raise AssertionError("exact replay consumed a fresh dependency")

        replay = api.prepare_human_first_lane(
            fixture.request,
            clock=forbidden_dependency,
            uuid_factory=forbidden_dependency,
        )
        self.assertEqual(replay, first)
        self.assertEqual(inspect_policy_authority(str(fixture.root)).head_sequence, 1)
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).event_count, 2)
        transactions = fixture.root / ".ask-herdr-topology" / "transactions"
        self.assertEqual(len(tuple(transactions.glob("event.*.txn"))), 1)

    def test_coordinator_never_reopens_filesystem_root_during_live_lease(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        real_hold = project_lease.hold_project_mutation_lease

        @contextmanager
        def instrumented_hold(binding):
            with real_hold(binding) as lease:
                real_open = os.open

                def guarded_open(path, *args, **kwargs):
                    if path == "/":
                        raise AssertionError(
                            "coordinator reopened the filesystem root"
                        )
                    return real_open(path, *args, **kwargs)

                with mock.patch.object(
                    os,
                    "open",
                    side_effect=guarded_open,
                ):
                    yield lease

        with mock.patch.object(
            api,
            "hold_project_mutation_lease",
            side_effect=instrumented_hold,
        ):
            prepared = api.prepare_human_first_lane(
                fixture.request,
                clock=lambda: ADMISSION_TIME,
                uuid_factory=lambda: DECISION_ID,
            )

        self.assertIsInstance(prepared, api.PreparedFirstLaneProvision)

    def test_workspace_swap_before_intent_commit_returns_no_prepared_authority(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        real_digest = api._lane_workspace_binding_digest_from_root
        displaced = fixture.workspace.with_name(fixture.workspace.name + ".old")
        swap_count = 0

        def swap_before_commit(
            root,
            store_binding,
            intent,
            *,
            before_return=None,
        ):
            def wrapped_before_return(workspace_digest):
                nonlocal swap_count
                fixture.workspace.rename(displaced)
                fixture.workspace.mkdir(mode=0o700)
                swap_count += 1
                before_return(workspace_digest)

            return real_digest(
                root,
                store_binding,
                intent,
                before_return=wrapped_before_return,
            )

        with mock.patch.object(
            api,
            "_lane_workspace_binding_digest_from_root",
            side_effect=swap_before_commit,
        ):
            with self.assertRaises(
                api.HumanFirstLanePreparationError
            ) as caught:
                api.prepare_human_first_lane(
                    fixture.request,
                    clock=lambda: ADMISSION_TIME,
                    uuid_factory=lambda: DECISION_ID,
                )

        self.assertEqual(
            caught.exception.detail_code,
            "human_first_lane.input_invalid",
        )
        self.assertEqual(swap_count, 1)
        topology = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(topology.status, "reconciliation_required")
        self.assertEqual(
            topology.unfinished_mutation_ids,
            (TOPOLOGY_MUTATION_ID,),
        )

    def test_prepared_request_enters_one_explicit_effect_continuation_exactly_once(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        runner = ProjectScriptedHerdr(str(fixture.root))

        executed = api.execute_prepared_journaled_provision(
            prepared,
            runner=runner,
        )

        self.assertEqual(
            executed.outcome,
            JournaledProvisionOutcome.CREATED_EPHEMERAL,
        )
        self.assertEqual(
            sum(_is_server_start(call) for call in runner.calls),
            1,
        )
        self.assertEqual(
            sum(_is_workspace_create(call) for call in runner.calls),
            1,
        )
        topology = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(topology.status, "active")
        self.assertEqual(topology.unfinished_mutation_ids, ())
        lane = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane.event_count, 5)
        self.assertIsNotNone(lane.state.topology_effect_started)
        self.assertEqual(len(lane.state.topology_command_effects_started), 1)
        self.assertIsNone(lane.state.topology_provisioning_claim)
        self.assertIsNotNone(lane.state.topology_provisioned)
        self.assertEqual(
            lane.state.topology_provisioned.project_topology_digest,
            executed.project_topology_digest,
        )
        runner_calls = tuple(runner.calls)
        with project_lease.hold_project_mutation_lease(
            fixture.project_binding
        ) as lease:
            replayed_provisioning = (
                lane_store.record_topology_provisioned_under_lease(
                    lease,
                    fixture.lane_binding,
                    fixture.topology_binding,
                    policy_proof=prepared.policy_proof,
                    lane_proof=prepared.lane_proof,
                )
            )
        replayed_lane = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(replayed_lane.event_count, 5)
        self.assertEqual(
            replayed_provisioning.project_topology_digest,
            executed.project_topology_digest,
        )
        self.assertEqual(
            replayed_lane.state.topology_provisioned,
            lane.state.topology_provisioned,
        )
        self.assertEqual(tuple(runner.calls), runner_calls)

    def test_anchored_command_claim_is_durable_and_lease_released_before_runner(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        runner = ProjectScriptedHerdr(str(fixture.root))
        boundaries = []

        def inspect_before_effect(argv):
            lane = inspect_lane_turn(fixture.lane_binding)
            topology = inspect_topology_store(fixture.topology_binding)
            with project_lease.hold_project_mutation_lease(
                fixture.project_binding
            ):
                lease_reacquired = True
            boundaries.append(
                (
                    tuple(argv),
                    lane.state.topology_effect_started,
                    topology.pending_step_ids,
                    lease_reacquired,
                )
            )

        runner.before_mutation = inspect_before_effect

        executed = api.execute_prepared_journaled_provision(
            prepared,
            runner=runner,
        )

        self.assertEqual(
            executed.outcome,
            JournaledProvisionOutcome.CREATED_EPHEMERAL,
        )
        self.assertEqual(len(boundaries), 2)
        self.assertIsNotNone(boundaries[0][1])
        self.assertEqual(boundaries[0][2], (SESSION_STEP_ID,))
        self.assertTrue(boundaries[0][3])
        self.assertIsNotNone(boundaries[1][1])
        self.assertEqual(boundaries[1][2], (WORKSPACE_STEP_ID,))
        self.assertTrue(boundaries[1][3])

    def test_forged_prepared_proofs_without_authority_or_lane_invoke_no_runner(self):
        api = _api()
        temporary = tempfile.TemporaryDirectory(
            prefix="ask-herdr-forged-prepared-continuation-",
        )
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        os.chmod(root, 0o700)
        workspace = root / "lane-workspaces" / LANE_ID
        workspace.mkdir(parents=True, mode=0o700)
        metadata = root.stat()
        topology_binding = ValidatedTopologyStoreBinding(
            canonical_project_root=str(root),
            filesystem_device=metadata.st_dev,
            filesystem_inode=metadata.st_ino,
            owner_uid=metadata.st_uid,
            project_authority_id=AUTHORITY_ID,
            namespace="ask-pipeline",
        )
        provision_intent = ProvisionIntent(
            project_id=AUTHORITY_ID,
            lane_id=LANE_ID,
            consultant_key=CONSULTANT_KEY,
            project_root=str(root),
            topology_nonce=TOPOLOGY_NONCE,
            lane_workspace_cwd=str(workspace),
        )
        policy_record_digest = "sha256:" + "a" * 64
        lane_state_digest = "sha256:" + "b" * 64
        policy_proof = policy_ledger.CommittedHumanAdmissionProof(
            project_authority_id=AUTHORITY_ID,
            policy_profile_id=PROFILE_ID,
            ledger_id="55555555-5555-4555-8555-555555555555",
            sequence=1,
            operation="turn.consult",
            action_reason="initial",
            provider="claude",
            operation_id=OPERATION_ID,
            canonical_request_digest=REQUEST_DIGEST,
            approval_receipt_id="77777777-7777-4777-8777-777777777777",
            policy_record_digest=policy_record_digest,
            provider_budget_effect="not_counted",
            project_budget_effect="not_counted",
        )
        lane_proof = lane_store.ClaimedLaneProof(
            operation_id=OPERATION_ID,
            canonical_request_digest=REQUEST_DIGEST,
            lane_id=LANE_ID,
            lane_generation=1,
            attempt_id=ATTEMPT_ID,
            policy_record_digest=policy_record_digest,
            prepared_lane_record_digest="sha256:" + "c" * 64,
            topology_mutation_id=TOPOLOGY_MUTATION_ID,
            topology_nonce=TOPOLOGY_NONCE,
            topology_claim_record_digest="sha256:" + "d" * 64,
            lane_state_digest=lane_state_digest,
            lane_binding_digest=LANE_BINDING_DIGEST,
        )
        mutation_intent = topology_store.TopologyMutationIntent(
            mutation_id=TOPOLOGY_MUTATION_ID,
            operation_id=OPERATION_ID,
            canonical_request_digest=REQUEST_DIGEST,
            policy_record_digest=policy_record_digest,
            lane_state_digest=lane_state_digest,
            lane_id=LANE_ID,
            lane_generation=1,
            lane_binding_digest=LANE_BINDING_DIGEST,
            lane_workspace_binding_digest=lane_workspace_binding_digest(
                topology_binding,
                provision_intent,
            ),
            consultant_key=CONSULTANT_KEY,
            topology_nonce=TOPOLOGY_NONCE,
            lane_workspace_cwd=str(workspace),
            prior_topology_digest=None,
            intended_action="reconcile_or_provision",
            precondition_digest="sha256:" + "e" * 64,
            expected_postcondition_digest=provision_postcondition_digest(
                provision_intent
            ),
        )
        committed = topology_store.commit_mutation_intent(
            topology_binding,
            mutation_intent,
        )
        self.assertEqual(
            committed.outcome_kind,
            "topology_mutation_prepared",
        )
        self.assertFalse((root / ".ask-herdr").exists())
        self.assertFalse((root / ".ask-herdr-lanes").exists())
        journaled_request = JournaledProvisionRequest(
            store_binding=topology_binding,
            mutation_intent=mutation_intent,
            provision_intent=provision_intent,
            session_start_step_id=SESSION_STEP_ID,
            workspace_create_step_id=WORKSPACE_STEP_ID,
        )
        prepared = api.PreparedFirstLaneProvision(
            policy_proof=policy_proof,
            lane_proof=lane_proof,
            mutation_intent=mutation_intent,
            journaled_request=journaled_request,
        )
        runner = ProjectScriptedHerdr(str(root))
        caught = None

        try:
            api.execute_prepared_journaled_provision(
                prepared,
                runner=runner,
            )
        except api.HumanFirstLanePreparationError as error:
            caught = error

        self.assertEqual(
            (
                sum(_is_server_start(call) for call in runner.calls),
                sum(_is_workspace_create(call) for call in runner.calls),
            ),
            (0, 0),
        )
        self.assertIsNotNone(caught)

    def test_missing_precommitted_topology_store_is_not_recreated_or_executed(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        topology_path = fixture.root / ".ask-herdr-topology"
        displaced_path = fixture.root / ".ask-herdr-topology.displaced"
        topology_path.rename(displaced_path)
        runner = ProjectScriptedHerdr(str(fixture.root))

        with self.assertRaises(
            api.HumanFirstLanePreparationError
        ) as caught:
            api.execute_prepared_journaled_provision(
                prepared,
                runner=runner,
            )

        self.assertFalse(caught.exception.resend_allowed)
        self.assertEqual(
            (
                sum(_is_server_start(call) for call in runner.calls),
                sum(_is_workspace_create(call) for call in runner.calls),
            ),
            (0, 0),
        )
        self.assertFalse(topology_path.exists())
        self.assertTrue(displaced_path.is_dir())

    def test_replacement_store_cannot_erase_pending_command_and_reauthorize_effect(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        topology_path = fixture.root / ".ask-herdr-topology"
        pristine_copy = fixture.root / ".ask-herdr-topology.pristine-copy"
        shutil.copytree(topology_path, pristine_copy)
        pending = topology_store.TopologyCommandIntent(
            mutation_id=prepared.mutation_intent.mutation_id,
            step_id=SESSION_STEP_ID,
            command_kind="session_start",
            command_argv_digest="sha256:" + "9" * 64,
            step_sequence=1,
            prior_step_id=None,
        )
        command = _commit_claimed_command(
            fixture,
            prepared,
            pending,
        )
        self.assertEqual(
            command.outcome_kind,
            "topology_command_prepared",
        )
        lane_with_marker = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_with_marker.event_count, 3)
        self.assertIsNotNone(lane_with_marker.state.topology_effect_started)

        displaced_path = fixture.root / ".ask-herdr-topology.with-command"
        topology_path.rename(displaced_path)
        pristine_copy.rename(topology_path)
        runner = ProjectScriptedHerdr(str(fixture.root))
        caught = None

        try:
            api.execute_prepared_journaled_provision(
                prepared,
                runner=runner,
            )
        except api.HumanFirstLanePreparationError as error:
            caught = error

        self.assertEqual(
            (
                sum(_is_server_start(call) for call in runner.calls),
                sum(_is_workspace_create(call) for call in runner.calls),
            ),
            (0, 0),
        )
        self.assertIsInstance(caught, api.HumanFirstLanePreparationError)
        self.assertFalse(caught.resend_allowed)
        replacement_state = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(replacement_state.status, "quarantined")
        self.assertEqual(
            replacement_state.detail_code,
            "topology_store.incarnation_conflict",
        )
        self.assertFalse(replacement_state.resend_allowed)
        self.assertTrue(displaced_path.is_dir())
        lane_after_replacement = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_after_replacement.event_count, 3)
        self.assertEqual(
            lane_after_replacement.state.topology_effect_started,
            lane_with_marker.state.topology_effect_started,
        )

    def test_replacement_transactions_directory_cannot_erase_pending_command_and_reauthorize_effect(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        topology_path = fixture.root / ".ask-herdr-topology"
        transactions_path = topology_path / "transactions"
        topology_inode = topology_path.stat().st_ino
        original_transactions_inode = transactions_path.stat().st_ino
        pristine_copy = (
            fixture.root / ".ask-herdr-topology-transactions.pristine-copy"
        )
        shutil.copytree(transactions_path, pristine_copy)
        pending = topology_store.TopologyCommandIntent(
            mutation_id=prepared.mutation_intent.mutation_id,
            step_id=SESSION_STEP_ID,
            command_kind="session_start",
            command_argv_digest="sha256:" + "9" * 64,
            step_sequence=1,
            prior_step_id=None,
        )
        command = _commit_claimed_command(
            fixture,
            prepared,
            pending,
        )
        self.assertEqual(
            command.outcome_kind,
            "topology_command_prepared",
        )
        lane_with_marker = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_with_marker.event_count, 3)
        self.assertIsNotNone(lane_with_marker.state.topology_effect_started)

        displaced_path = (
            fixture.root / ".ask-herdr-topology-transactions.with-command"
        )
        transactions_path.rename(displaced_path)
        pristine_copy.rename(transactions_path)
        self.assertEqual(topology_path.stat().st_ino, topology_inode)
        self.assertNotEqual(
            transactions_path.stat().st_ino,
            original_transactions_inode,
        )
        self.assertEqual(
            len(tuple(displaced_path.glob("event.*.txn"))),
            2,
        )
        self.assertEqual(
            len(tuple(transactions_path.glob("event.*.txn"))),
            1,
        )
        runner = ProjectScriptedHerdr(str(fixture.root))
        caught = None

        try:
            api.execute_prepared_journaled_provision(
                prepared,
                runner=runner,
            )
        except api.HumanFirstLanePreparationError as error:
            caught = error

        self.assertEqual(
            (
                sum(_is_server_start(call) for call in runner.calls),
                sum(_is_workspace_create(call) for call in runner.calls),
            ),
            (0, 0),
        )
        self.assertIsInstance(caught, api.HumanFirstLanePreparationError)
        self.assertFalse(caught.resend_allowed)
        replacement_state = inspect_topology_store(fixture.topology_binding)
        self.assertIsNone(replacement_state.project_topology_digest)
        self.assertFalse(replacement_state.resend_allowed)
        self.assertTrue(displaced_path.is_dir())
        lane_after_replacement = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_after_replacement.event_count, 3)
        self.assertEqual(
            lane_after_replacement.state.topology_effect_started,
            lane_with_marker.state.topology_effect_started,
        )

    def test_removed_pending_command_tail_cannot_reauthorize_effect_with_same_transactions_inode(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        prepared = api.prepare_human_first_lane(
            fixture.request,
            clock=lambda: ADMISSION_TIME,
            uuid_factory=lambda: DECISION_ID,
        )
        transactions_path = (
            fixture.root / ".ask-herdr-topology" / "transactions"
        )
        transactions_inode = transactions_path.stat().st_ino
        pending = topology_store.TopologyCommandIntent(
            mutation_id=prepared.mutation_intent.mutation_id,
            step_id=SESSION_STEP_ID,
            command_kind="session_start",
            command_argv_digest="sha256:" + "9" * 64,
            step_sequence=1,
            prior_step_id=None,
        )
        command = _commit_claimed_command(
            fixture,
            prepared,
            pending,
        )
        self.assertEqual(
            command.outcome_kind,
            "topology_command_prepared",
        )
        lane_with_marker = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_with_marker.event_count, 3)
        self.assertIsNotNone(lane_with_marker.state.topology_effect_started)
        events = tuple(sorted(transactions_path.glob("event.*.txn")))
        self.assertEqual(len(events), 2)

        removed_tail = fixture.root / (events[-1].name + ".removed")
        events[-1].rename(removed_tail)
        self.assertEqual(transactions_path.stat().st_ino, transactions_inode)
        self.assertEqual(
            len(tuple(transactions_path.glob("event.*.txn"))),
            1,
        )
        runner = ProjectScriptedHerdr(str(fixture.root))
        caught = None

        try:
            api.execute_prepared_journaled_provision(
                prepared,
                runner=runner,
            )
        except api.HumanFirstLanePreparationError as error:
            caught = error

        self.assertEqual(
            (
                sum(_is_server_start(call) for call in runner.calls),
                sum(_is_workspace_create(call) for call in runner.calls),
            ),
            (0, 0),
        )
        self.assertIsInstance(caught, api.HumanFirstLanePreparationError)
        self.assertFalse(caught.resend_allowed)
        replacement_state = inspect_topology_store(fixture.topology_binding)
        self.assertIsNone(replacement_state.project_topology_digest)
        self.assertFalse(replacement_state.resend_allowed)
        self.assertTrue(removed_tail.is_dir())
        lane_after_removal = inspect_lane_turn(fixture.lane_binding)
        self.assertEqual(lane_after_removal.event_count, 3)
        self.assertEqual(
            lane_after_removal.state.topology_effect_started,
            lane_with_marker.state.topology_effect_started,
        )

    def test_expired_human_receipt_creates_no_lane_or_topology_authority(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        expired = replace(
            fixture.request.admission.approval_receipt,
            expires_at="2026-08-13T02:01:30.000000Z",
        )
        request = replace(
            fixture.request,
            admission=replace(
                fixture.request.admission,
                approval_receipt=expired,
            ),
        )
        with self.assertRaises(api.HumanFirstLanePreparationError) as caught:
            api.prepare_human_first_lane(
                request,
                clock=lambda: ADMISSION_TIME,
                uuid_factory=lambda: DECISION_ID,
            )
        self.assertEqual(
            caught.exception.detail_code,
            "policy_ledger.human_approval_receipt_expired",
        )
        self.assertEqual(inspect_policy_authority(str(fixture.root)).head_sequence, 0)
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).status, "absent")
        self.assertEqual(inspect_topology_store(fixture.topology_binding).status, "absent")

    def test_interrupted_claim_replays_forward_without_duplicate_or_effect(self):
        api = _api()
        fixture = _Fixture(api)
        self.addCleanup(fixture.close)
        with self.assertRaises(api.HumanFirstLanePreparationFailpoint):
            api.prepare_human_first_lane(
                fixture.request,
                clock=lambda: ADMISSION_TIME,
                uuid_factory=lambda: DECISION_ID,
                failpoint="after_lane_claim",
            )
        self.assertEqual(inspect_policy_authority(str(fixture.root)).head_sequence, 1)
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).event_count, 2)
        topology_before_intent = inspect_topology_store(
            fixture.topology_binding
        )
        self.assertEqual(topology_before_intent.status, "active")
        self.assertEqual(topology_before_intent.unfinished_mutation_ids, ())

        def forbidden_dependency():
            raise AssertionError("restart consumed a committed admission dependency")

        recovered = api.prepare_human_first_lane(
            fixture.request,
            clock=forbidden_dependency,
            uuid_factory=forbidden_dependency,
        )
        self.assertIsInstance(recovered, api.PreparedFirstLaneProvision)
        self.assertEqual(inspect_lane_turn(fixture.lane_binding).event_count, 2)
        topology = inspect_topology_store(fixture.topology_binding)
        self.assertEqual(topology.unfinished_mutation_ids, (TOPOLOGY_MUTATION_ID,))
        self.assertFalse(topology.resend_allowed)


if __name__ == "__main__":
    unittest.main()
