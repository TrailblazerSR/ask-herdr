"""Private coordinator for one direct-human first-Lane prerequisite unit.

This module owns no external-effect surface.  It composes the private Policy,
Lane, workspace, and Topology ports under one exact Project Mutation Lease and
returns a fully derived journaled-provision request for a later effect phase.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Callable, Optional

from ask_herdr_herdr_transport import (
    ProvisionIntent,
)
from ask_herdr_json import canonical_json
from ask_herdr_journaled_provision import (
    JournaledProvisionRequest,
    JournaledProvisionResult,
    _provision_command_intents,
    _lane_workspace_binding_digest_from_root,
    provision_prepared_journaled,
    provision_postcondition_digest,
)
from ask_herdr_lane_store import (
    ClaimedLaneProof,
    ProvisionedLaneProof,
    ValidatedLaneGenerationBinding,
    _inspect_topology_recovery_lane_for_content_access_under_lease,
    _inspect_topology_recovery_lane_for_evidence_anchor_under_lease,
    _inspect_topology_recovery_lane_under_lease,
    claim_topology_provisioning_under_lease,
    record_topology_provisioned_under_lease,
)
from ask_herdr_lane_turn import NativeIdentityMode, PrepareAdmittedAttempt
from ask_herdr_policy_ledger import (
    CommittedHumanAdmissionProof,
    ConfirmedHumanAdmission,
    ValidatedHumanApprovalReceipt,
    validate_committed_human_admission_under_lease,
)
from ask_herdr_project_mutation_lease import (
    ProjectMutationLeaseError,
    ValidatedProjectMutationBinding,
    _borrow_validated_root,
    hold_project_mutation_lease,
)
from ask_herdr_topology_store import (
    TopologyMutationIntent,
    ValidatedTopologyStoreBinding,
    _authenticate_pristine_mutation_under_lease,
    _ensure_topology_store_incarnation_under_lease,
    _inspect_open_mutation_reconciliation_under_lease,
    commit_mutation_intent_under_lease,
)


@dataclass(frozen=True)
class HumanFirstLanePreparationRequest:
    """Core-validated facts for one initial direct-human Lane."""

    project_binding: ValidatedProjectMutationBinding
    admission: ConfirmedHumanAdmission
    lane_binding: ValidatedLaneGenerationBinding
    topology_binding: ValidatedTopologyStoreBinding
    attempt_id: str
    expected_head_digest: str
    expected_completion_marker: str
    topology_mutation_id: str
    topology_nonce: str
    provision_intent: ProvisionIntent
    session_start_step_id: str
    workspace_create_step_id: str


@dataclass(frozen=True)
class PreparedFirstLaneProvision:
    """Record-derived prerequisite authority for a later effect phase."""

    policy_proof: CommittedHumanAdmissionProof
    lane_proof: ClaimedLaneProof
    mutation_intent: TopologyMutationIntent
    journaled_request: JournaledProvisionRequest


@dataclass(frozen=True)
class OpenTopologyReconciliation:
    """Non-authorizing classification of one exact interrupted mutation."""

    status: str
    detail_code: str
    mutation_id: str
    recovery_scope: str
    confirmed_step_ids: tuple[str, ...]
    pending_step_ids: tuple[str, ...]
    unresolved_witness_digests: tuple[str, ...]
    recovery_state_digest: str
    resend_allowed: bool = False
    effect_authority: str = "none"


@dataclass(frozen=True)
class TopologyRecoveryFinalizationResult:
    """Verified result of one evidence-monotonic local finalization."""

    outcome_kind: str
    detail_code: str
    mutation_id: str
    recovery_scope: str
    expected_recovery_state_digest: str
    current_recovery: OpenTopologyReconciliation
    topology_provisioned_record_digest: str
    project_topology_digest: str
    resend_allowed: bool = False
    effect_authority: str = "none"


class HumanFirstLanePreparationError(RuntimeError):
    resend_allowed = False

    def __init__(self, detail_code: str) -> None:
        super().__init__(detail_code)
        self.detail_code = detail_code


class HumanFirstLanePreparationFailpoint(RuntimeError):
    pass


def _barrier_recovery_result(
    snapshot: PreparedFirstLaneProvision,
    *,
    detail_code: str,
    expected_commands: tuple[
        tuple[str, str, str, str, int, Optional[str]], ...
    ],
) -> OpenTopologyReconciliation:
    """Return one non-authorizing result when the outer lease is busy."""

    evidence_digest = "sha256:" + hashlib.sha256(
        canonical_json(
            {
                "schema": "ask_herdr.recovery_lease_barrier.internal.v1",
                "detail_code": detail_code,
                "project_authority_id": (
                    snapshot.journaled_request.store_binding.project_authority_id
                ),
                "mutation_id": snapshot.mutation_intent.mutation_id,
                "policy_record_digest": snapshot.policy_proof.policy_record_digest,
                "topology_claim_record_digest": (
                    snapshot.lane_proof.topology_claim_record_digest
                ),
                "expected_commands": [
                    list(command) for command in expected_commands
                ],
            }
        )
    ).hexdigest()
    return _reconciliation_result(
        status="reconciliation_required",
        detail_code="topology_recovery.writer_busy",
        mutation_id=snapshot.mutation_intent.mutation_id,
        confirmed_step_ids=(),
        pending_step_ids=(),
        unresolved_witness_digests=(),
        evidence_digest=evidence_digest,
    )


def _snapshot_request(
    request: HumanFirstLanePreparationRequest,
) -> HumanFirstLanePreparationRequest:
    if type(request) is not HumanFirstLanePreparationRequest:
        raise HumanFirstLanePreparationError(
            "human_first_lane.request_type_invalid"
        )
    try:
        if type(request.admission) is not ConfirmedHumanAdmission or type(
            request.admission.approval_receipt
        ) is not ValidatedHumanApprovalReceipt:
            raise ValueError
        receipt = ValidatedHumanApprovalReceipt(
            **dict(vars(request.admission.approval_receipt))
        )
        admission = ConfirmedHumanAdmission(
            **{
                **dict(vars(request.admission)),
                "approval_receipt": receipt,
            }
        )
        if type(request.project_binding) is not ValidatedProjectMutationBinding:
            raise ValueError
        project_binding = ValidatedProjectMutationBinding(
            **dict(vars(request.project_binding))
        )
        if type(request.lane_binding) is not ValidatedLaneGenerationBinding:
            raise ValueError
        lane_binding = ValidatedLaneGenerationBinding(
            **dict(vars(request.lane_binding))
        )
        if type(request.topology_binding) is not ValidatedTopologyStoreBinding:
            raise ValueError
        topology_binding = ValidatedTopologyStoreBinding(
            **dict(vars(request.topology_binding))
        )
        if type(request.provision_intent) is not ProvisionIntent:
            raise ValueError
        provision_intent = ProvisionIntent(
            **dict(vars(request.provision_intent))
        )
        return HumanFirstLanePreparationRequest(
            project_binding=project_binding,
            admission=admission,
            lane_binding=lane_binding,
            topology_binding=topology_binding,
            attempt_id=request.attempt_id,
            expected_head_digest=request.expected_head_digest,
            expected_completion_marker=request.expected_completion_marker,
            topology_mutation_id=request.topology_mutation_id,
            topology_nonce=request.topology_nonce,
            provision_intent=provision_intent,
            session_start_step_id=request.session_start_step_id,
            workspace_create_step_id=request.workspace_create_step_id,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "human_first_lane.request_type_invalid"
        ) from error


def _validate_correlations(request: HumanFirstLanePreparationRequest) -> None:
    project = request.project_binding
    admission = request.admission
    lane = request.lane_binding
    topology = request.topology_binding
    provision = request.provision_intent
    if not all(
        (
            admission.operation == "turn.consult",
            admission.action_reason == "initial",
            project.project_authority_id == admission.project_authority_id,
            project.project_authority_id == lane.project_authority_id,
            project.project_authority_id == topology.project_authority_id,
            project.canonical_root == lane.canonical_root,
            project.canonical_root == topology.canonical_project_root,
            project.canonical_root == provision.project_root,
            project.project_authority_id == provision.project_id,
            lane.lane_id == provision.lane_id,
            lane.lane_generation == 1,
            request.topology_nonce == provision.topology_nonce,
            request.session_start_step_id
            != request.workspace_create_step_id,
        )
    ):
        raise HumanFirstLanePreparationError(
            "human_first_lane.authority_binding_mismatch"
        )


def _precondition_digest(
    policy: CommittedHumanAdmissionProof,
    lane: ClaimedLaneProof,
    workspace_digest: str,
) -> str:
    value = {
        "schema": "ask_herdr.first_lane_precondition.internal.v2",
        "policy_record_digest": policy.policy_record_digest,
        "prepared_lane_record_digest": lane.prepared_lane_record_digest,
        "topology_claim_record_digest": lane.topology_claim_record_digest,
        "lane_state_digest": lane.lane_state_digest,
        "lane_binding_digest": lane.lane_binding_digest,
        "topology_store_incarnation_digest": (
            lane.topology_store_incarnation_digest
        ),
        "lane_workspace_binding_digest": workspace_digest,
        "prior_topology_digest": None,
    }
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _trip(failpoint: Any, point: str) -> None:
    if failpoint == point:
        raise HumanFirstLanePreparationFailpoint(point)
    if callable(failpoint):
        failpoint(point)


def _raise_result(detail_code: str) -> None:
    raise HumanFirstLanePreparationError(detail_code)


def _snapshot_prepared_reconciliation(
    prepared: PreparedFirstLaneProvision,
) -> PreparedFirstLaneProvision:
    """Freeze one exact base-value snapshot before replaying authority."""

    if type(prepared) is not PreparedFirstLaneProvision:
        raise HumanFirstLanePreparationError(
            "topology_recovery.prepared_type_invalid"
        )
    try:
        if (
            type(prepared.policy_proof)
            is not CommittedHumanAdmissionProof
            or type(prepared.lane_proof) is not ClaimedLaneProof
            or type(prepared.mutation_intent) is not TopologyMutationIntent
            or type(prepared.journaled_request)
            is not JournaledProvisionRequest
            or type(prepared.journaled_request.store_binding)
            is not ValidatedTopologyStoreBinding
            or type(prepared.journaled_request.provision_intent)
            is not ProvisionIntent
            or type(prepared.journaled_request.mutation_intent)
            is not TopologyMutationIntent
        ):
            raise ValueError
        request = JournaledProvisionRequest(
            store_binding=ValidatedTopologyStoreBinding(
                **dict(vars(prepared.journaled_request.store_binding))
            ),
            mutation_intent=TopologyMutationIntent(
                **dict(vars(prepared.journaled_request.mutation_intent))
            ),
            provision_intent=ProvisionIntent(
                **dict(vars(prepared.journaled_request.provision_intent))
            ),
            session_start_step_id=(
                prepared.journaled_request.session_start_step_id
            ),
            workspace_create_step_id=(
                prepared.journaled_request.workspace_create_step_id
            ),
        )
        snapshot = PreparedFirstLaneProvision(
            policy_proof=CommittedHumanAdmissionProof(
                **dict(vars(prepared.policy_proof))
            ),
            lane_proof=ClaimedLaneProof(**dict(vars(prepared.lane_proof))),
            mutation_intent=TopologyMutationIntent(
                **dict(vars(prepared.mutation_intent))
            ),
            journaled_request=request,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.prepared_type_invalid"
        ) from error
    if snapshot.journaled_request.mutation_intent != snapshot.mutation_intent:
        raise HumanFirstLanePreparationError(
            "topology_recovery.prepared_binding_mismatch"
        )
    provision = snapshot.journaled_request.provision_intent
    mutation = snapshot.mutation_intent
    if not all(
        (
            provision.project_id
            == snapshot.journaled_request.store_binding.project_authority_id,
            provision.project_root
            == snapshot.journaled_request.store_binding.canonical_project_root,
            provision.lane_id == mutation.lane_id,
            provision.consultant_key == mutation.consultant_key,
            provision.topology_nonce == mutation.topology_nonce,
            provision.lane_workspace_cwd == mutation.lane_workspace_cwd,
            provision_postcondition_digest(provision)
            == mutation.expected_postcondition_digest,
            snapshot.journaled_request.session_start_step_id
            != snapshot.journaled_request.workspace_create_step_id,
        )
    ):
        raise HumanFirstLanePreparationError(
            "topology_recovery.prepared_binding_mismatch"
        )
    return snapshot


def _reconciliation_result(
    *,
    status: str,
    detail_code: str,
    mutation_id: str,
    confirmed_step_ids: tuple[str, ...],
    pending_step_ids: tuple[str, ...],
    unresolved_witness_digests: tuple[str, ...],
    evidence_digest: str,
) -> OpenTopologyReconciliation:
    payload = {
        "schema": "ask_herdr.open_topology_reconciliation.internal.v1",
        "status": status,
        "detail_code": detail_code,
        "mutation_id": mutation_id,
        "recovery_scope": "managed_topology_namespace",
        "confirmed_step_ids": list(confirmed_step_ids),
        "pending_step_ids": list(pending_step_ids),
        "unresolved_witness_digests": list(unresolved_witness_digests),
        "evidence_digest": evidence_digest,
        "resend_allowed": False,
        "effect_authority": "none",
    }
    return OpenTopologyReconciliation(
        status=status,
        detail_code=detail_code,
        mutation_id=mutation_id,
        recovery_scope="managed_topology_namespace",
        confirmed_step_ids=confirmed_step_ids,
        pending_step_ids=pending_step_ids,
        unresolved_witness_digests=unresolved_witness_digests,
        recovery_state_digest=(
            "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()
        ),
    )


def _expected_recovery_commands(
    snapshot: PreparedFirstLaneProvision,
) -> tuple[tuple[str, str, str, str, int, Optional[str]], ...]:
    """Derive the exact two-command plan from the prepared request."""

    return tuple(
        (
            command.step_id,
            command.command_kind,
            command.command_argv_digest,
            command.expected_postcondition_digest,
            command.step_sequence,
            command.prior_step_id,
        )
        for command in _provision_command_intents(
            snapshot.journaled_request
        )
    )


def _inspect_prepared_topology_reconciliation(
    prepared: PreparedFirstLaneProvision,
    *,
    lease: Any = None,
    allow_pending_policy_content_access: bool = False,
) -> OpenTopologyReconciliation:
    """Classify one interrupted prefix, optionally under a retained lease."""

    snapshot = _snapshot_prepared_reconciliation(prepared)
    try:
        expected_commands = _expected_recovery_commands(snapshot)
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.prepared_type_invalid"
        ) from error
    binding = snapshot.journaled_request.store_binding
    project_binding = ValidatedProjectMutationBinding(
        canonical_project_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
    )
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
        lane_id=snapshot.lane_proof.lane_id,
        lane_generation=snapshot.lane_proof.lane_generation,
        lane_binding_digest=snapshot.lane_proof.lane_binding_digest,
    )
    try:
        lease_context = (
            hold_project_mutation_lease(project_binding)
            if lease is None
            else nullcontext(lease)
        )
        with lease_context as active_lease:
            lane_inspection_port = (
                _inspect_topology_recovery_lane_for_content_access_under_lease
                if allow_pending_policy_content_access
                else _inspect_topology_recovery_lane_under_lease
            )
            lane_inspection = lane_inspection_port(
                active_lease,
                lane_binding,
                policy_proof=snapshot.policy_proof,
                lane_proof=snapshot.lane_proof,
            )
            if lane_inspection.status != "active":
                status = (
                    "quarantined"
                    if lane_inspection.status == "quarantined"
                    else "reconciliation_required"
                )
                evidence_digest = "sha256:" + hashlib.sha256(
                    canonical_json(
                        {
                            "schema": (
                                "ask_herdr.lane_recovery_barrier.internal.v1"
                            ),
                            "status": status,
                            "detail_code": lane_inspection.detail_code,
                            "residue_state_digest": (
                                lane_inspection.residue_state_digest
                            ),
                            "policy_record_digest": (
                                snapshot.policy_proof.policy_record_digest
                            ),
                            "topology_claim_record_digest": (
                                snapshot.lane_proof.topology_claim_record_digest
                            ),
                            "expected_commands": [
                                list(command)
                                for command in expected_commands
                            ],
                        }
                    )
                ).hexdigest()
                return _reconciliation_result(
                    status=status,
                    detail_code=(
                        "topology_recovery.lane_reconciliation_required"
                        if status == "reconciliation_required"
                        else "topology_recovery.lane_history_quarantined"
                    ),
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    confirmed_step_ids=(),
                    pending_step_ids=(),
                    unresolved_witness_digests=(),
                    evidence_digest=evidence_digest,
                )
            lane_evidence = lane_inspection.evidence
            if lane_evidence is None:
                raise HumanFirstLanePreparationError(
                    "topology_recovery.lane_replay_invalid"
                )
            topology_inspection = (
                _inspect_open_mutation_reconciliation_under_lease(
                    active_lease,
                    binding,
                        snapshot.mutation_intent,
                        policy_proof=snapshot.policy_proof,
                        lane_proof=snapshot.lane_proof,
                        allow_pending_policy_content_access=(
                            allow_pending_policy_content_access
                        ),
                    )
            )
            if topology_inspection.status != "active":
                status = (
                    "quarantined"
                    if topology_inspection.status == "quarantined"
                    else "reconciliation_required"
                )
                return _reconciliation_result(
                    status=status,
                    detail_code=(
                        "topology_recovery.topology_reconciliation_required"
                        if status == "reconciliation_required"
                        else "topology_recovery.topology_history_quarantined"
                    ),
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    confirmed_step_ids=(),
                    pending_step_ids=(),
                    unresolved_witness_digests=(),
                    evidence_digest="sha256:" + hashlib.sha256(
                        canonical_json(
                            {
                                "schema": (
                                    "ask_herdr.topology_recovery_barrier.internal.v1"
                                ),
                                "detail_code": (
                                    topology_inspection.detail_code
                                ),
                                "residue_state_digest": (
                                    topology_inspection.residue_state_digest
                                ),
                                "mutation_id": (
                                    snapshot.mutation_intent.mutation_id
                                ),
                                "lane_head_record_digest": (
                                    lane_evidence.head_record_digest
                                ),
                                "expected_commands": [
                                    list(command)
                                    for command in expected_commands
                                ],
                            }
                        )
                    ).hexdigest(),
                )
            replay = topology_inspection.evidence
            if replay is None:
                raise HumanFirstLanePreparationError(
                    "topology_recovery.topology_replay_invalid"
                )
            evidence_digest = "sha256:" + hashlib.sha256(
                canonical_json(
                    {
                        "schema": (
                            "ask_herdr.open_topology_recovery_evidence.internal.v1"
                        ),
                        "project_authority_id": binding.project_authority_id,
                        "namespace": binding.namespace,
                        "topology_store_incarnation_digest": (
                            snapshot.mutation_intent.topology_store_incarnation_digest
                        ),
                        "policy_record_digest": (
                            snapshot.policy_proof.policy_record_digest
                        ),
                        "topology_claim_record_digest": (
                            snapshot.lane_proof.topology_claim_record_digest
                        ),
                        "mutation_record_digest": (
                            replay.mutation_record_digest
                        ),
                        "record_digests": list(replay.record_digests),
                        "settlement_record_digest": (
                            replay.settlement_record_digest
                        ),
                        "lane_record_digests": list(
                            lane_evidence.lane_record_digests
                        ),
                        "lane_head_record_digest": (
                            lane_evidence.head_record_digest
                        ),
                        "lane_head_state_digest": (
                            lane_evidence.head_state_digest
                        ),
                        "expected_commands": [
                            list(command) for command in expected_commands
                        ],
                        "receipts": [
                            {
                                "step_id": receipt.step_id,
                                "command_receipt_digest": (
                                    receipt.command_receipt_digest
                                ),
                                "request_id": receipt.request_id,
                                "disposition": receipt.disposition.value,
                                "session_dir": receipt.session_dir,
                                "socket_path": receipt.socket_path,
                                "session_generation_id": (
                                    receipt.session_generation_id
                                ),
                                "resource_binding_digests": list(
                                    receipt.resource_binding_digests
                                ),
                            }
                            for receipt in replay.receipts
                        ],
                    }
                )
            ).hexdigest()
            if not replay.commands:
                if (
                    lane_evidence.claim == snapshot.lane_proof
                    and lane_evidence.first_effect is None
                    and not lane_evidence.later_effects
                    and lane_evidence.provisioned is None
                ):
                    return _reconciliation_result(
                        status="not_interrupted",
                        detail_code="topology_recovery.not_interrupted",
                        mutation_id=snapshot.mutation_intent.mutation_id,
                        confirmed_step_ids=(),
                        pending_step_ids=(),
                        unresolved_witness_digests=(),
                        evidence_digest=evidence_digest,
                    )
            marker = lane_evidence.first_effect
            later_witnesses = lane_evidence.later_effects
        if marker is None:
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=(),
                pending_step_ids=(),
                unresolved_witness_digests=tuple(
                    digest for _, digest in replay.command_record_digests[:1]
                ),
                evidence_digest=evidence_digest,
            )
        if (
            marker.topology_mutation_record_digest
            != replay.mutation_record_digest
        ):
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=(),
                pending_step_ids=(),
                unresolved_witness_digests=(
                    marker.topology_mutation_record_digest,
                    replay.mutation_record_digest,
                ),
                evidence_digest=evidence_digest,
            )
        command_record_digests = {
            digest for _, digest in replay.command_record_digests
        }
        if not replay.command_record_digests:
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code=(
                    "topology_recovery.witnessed_command_unresolved"
                ),
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=(),
                pending_step_ids=(),
                unresolved_witness_digests=(
                    marker.first_topology_command_record_digest,
                ),
                evidence_digest=evidence_digest,
            )
        if (
            marker.first_topology_command_record_digest
            != replay.command_record_digests[0][1]
        ):
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=(),
                pending_step_ids=(),
                unresolved_witness_digests=(
                    marker.first_topology_command_record_digest,
                    replay.command_record_digests[0][1],
                ),
                evidence_digest=evidence_digest,
            )
        receipt_by_step = {
            receipt.step_id: receipt for receipt in replay.receipts
        }
        confirmed_step_ids = tuple(
            command.step_id
            for command in replay.commands
            if command.step_id in receipt_by_step
            and receipt_by_step[command.step_id].disposition.value
            == "confirmed"
        )
        actual_commands = tuple(
            (
                command.step_id,
                command.command_kind,
                command.command_argv_digest,
                command.expected_postcondition_digest,
                command.step_sequence,
                command.prior_step_id,
            )
            for command in replay.commands
        )
        if actual_commands != expected_commands[: len(actual_commands)]:
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.command_spec_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        missing_later_witnesses = tuple(
            witness.topology_command_record_digest
            for witness in later_witnesses
            if witness.topology_command_record_digest
            not in command_record_digests
        )
        if missing_later_witnesses:
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=missing_later_witnesses,
                evidence_digest=evidence_digest,
            )
        expected_later_commands = replay.command_record_digests[1:]
        if len(later_witnesses) != len(expected_later_commands):
            unmatched = tuple(
                digest
                for index, (_, digest) in enumerate(
                    expected_later_commands
                )
                if index >= len(later_witnesses)
            ) + tuple(
                witness.topology_command_record_digest
                for witness in later_witnesses[
                    len(expected_later_commands) :
                ]
            )
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=unmatched,
                evidence_digest=evidence_digest,
            )
        unwitnessed_topology_commands = tuple(
            digest
            for index, (step_id, digest) in enumerate(
                expected_later_commands
            )
            if index >= len(later_witnesses)
            or later_witnesses[index].command_sequence != index + 2
            or later_witnesses[index].topology_command_step_id != step_id
            or later_witnesses[index].topology_command_record_digest
            != digest
        )
        if unwitnessed_topology_commands:
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=(
                    unwitnessed_topology_commands
                ),
                evidence_digest=evidence_digest,
            )
        if (
            replay.settlement is None
            and lane_evidence.provisioned is not None
        ):
            return _reconciliation_result(
                status="quarantined",
                detail_code="topology_recovery.cross_journal_mismatch",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=(
                    lane_evidence.provisioned
                    .topology_settlement_record_digest,
                ),
                evidence_digest=evidence_digest,
            )
        if replay.settlement is not None:
            if replay.settlement.outcome != "created":
                return _reconciliation_result(
                    status="quarantined",
                    detail_code=(
                        "topology_recovery.settlement_outcome_mismatch"
                    ),
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    confirmed_step_ids=confirmed_step_ids,
                    pending_step_ids=(),
                    unresolved_witness_digests=(),
                    evidence_digest=evidence_digest,
                )
            if replay.settlement.project_topology_proof is None:
                return _reconciliation_result(
                    status="reconciliation_required",
                    detail_code=(
                        "topology_recovery.confirmed_postcondition_proof_unavailable"
                    ),
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    confirmed_step_ids=confirmed_step_ids,
                    pending_step_ids=(),
                    unresolved_witness_digests=(),
                    evidence_digest=evidence_digest,
                )
            provisioned = lane_evidence.provisioned
            last_witness_digest = (
                later_witnesses[-1]
                .topology_command_effect_started_record_digest
                if later_witnesses
                else None
            )
            if provisioned is not None:
                if not all(
                    (
                        provisioned.topology_settlement_record_digest
                        == replay.settlement_record_digest,
                        provisioned.project_topology_digest
                        == replay.settlement.project_topology_digest,
                        provisioned.topology_effect_started_record_digest
                        == marker.topology_effect_started_record_digest,
                        provisioned.topology_last_command_effect_started_record_digest
                        == last_witness_digest,
                    )
                ):
                    return _reconciliation_result(
                        status="quarantined",
                        detail_code="topology_recovery.cross_journal_mismatch",
                        mutation_id=snapshot.mutation_intent.mutation_id,
                        confirmed_step_ids=confirmed_step_ids,
                        pending_step_ids=(),
                        unresolved_witness_digests=(),
                        evidence_digest=evidence_digest,
                    )
                return _reconciliation_result(
                    status="not_interrupted",
                    detail_code="topology_recovery.already_complete",
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    confirmed_step_ids=confirmed_step_ids,
                    pending_step_ids=(),
                    unresolved_witness_digests=(),
                    evidence_digest=evidence_digest,
                )
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code="topology_recovery.lane_finalization_required",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        pending_step_ids = tuple(
            command.step_id
            for command in replay.commands
            if command.step_id not in receipt_by_step
        )
        if pending_step_ids:
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code="topology_recovery.command_outcome_unresolved",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=tuple(
                    command.step_id
                    for command in replay.commands
                    if command.step_id in receipt_by_step
                    and receipt_by_step[command.step_id].disposition.value
                    == "confirmed"
                ),
                pending_step_ids=pending_step_ids,
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        uncertain_step_ids = tuple(
            command.step_id
            for command in replay.commands
            if command.step_id in receipt_by_step
            and receipt_by_step[command.step_id].disposition.value
            == "delivery_uncertain"
        )
        if uncertain_step_ids:
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code="topology_recovery.delivery_uncertain",
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=uncertain_step_ids,
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        definite_non_start_step_ids = tuple(
            command.step_id
            for command in replay.commands
            if command.step_id in receipt_by_step
            and receipt_by_step[command.step_id].disposition.value
            == "definite_non_start"
        )
        if definite_non_start_step_ids:
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code=(
                    "topology_recovery.definite_non_start_resolution_required"
                ),
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=definite_non_start_step_ids,
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        if confirmed_step_ids:
            expected_step_ids = (
                snapshot.journaled_request.session_start_step_id,
                snapshot.journaled_request.workspace_create_step_id,
            )
            return _reconciliation_result(
                status="reconciliation_required",
                detail_code=(
                    "topology_recovery.confirmed_postcondition_proof_unavailable"
                    if confirmed_step_ids == expected_step_ids
                    else "topology_recovery.confirmed_prefix_observation_required"
                ),
                mutation_id=snapshot.mutation_intent.mutation_id,
                confirmed_step_ids=confirmed_step_ids,
                pending_step_ids=(),
                unresolved_witness_digests=(),
                evidence_digest=evidence_digest,
            )
        raise HumanFirstLanePreparationError(
            "topology_recovery.classification_not_implemented"
        )
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        if error.detail_code == "project_mutation_lease.writer_busy":
            return _barrier_recovery_result(
                snapshot,
                detail_code=error.detail_code,
                expected_commands=expected_commands,
            )
        raise HumanFirstLanePreparationError(error.detail_code) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.replay_invalid"
        ) from error


def inspect_prepared_topology_reconciliation(
    prepared: PreparedFirstLaneProvision,
) -> OpenTopologyReconciliation:
    """Classify one interrupted Topology prefix without writes or effects."""

    return _inspect_prepared_topology_reconciliation(prepared)


def _historical_completed_recovery_state_digest_under_lease(
    lease: Any,
    prepared: PreparedFirstLaneProvision,
    *,
    allow_evidence_anchor_candidate: bool = False,
    allow_pending_policy_content_access: bool = False,
) -> str:
    """Derive the completed Recovery State at the Lane provision prefix.

    The ordinary classifier always binds the current full Lane head.  Durable
    operation-result replay instead needs the immutable historical state that
    ended exactly at ``RecordTopologyProvisioned``.  Reconstruct that prefix
    from one authenticated current replay without weakening the public
    classifier or trusting a result record's self hash.
    """

    snapshot = _snapshot_prepared_reconciliation(prepared)
    binding = snapshot.journaled_request.store_binding
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
        lane_id=snapshot.lane_proof.lane_id,
        lane_generation=snapshot.lane_proof.lane_generation,
        lane_binding_digest=snapshot.lane_proof.lane_binding_digest,
    )
    lane_inspection_port = (
        _inspect_topology_recovery_lane_for_content_access_under_lease
        if allow_pending_policy_content_access
        else _inspect_topology_recovery_lane_for_evidence_anchor_under_lease
        if allow_evidence_anchor_candidate
        else _inspect_topology_recovery_lane_under_lease
    )
    lane_inspection = lane_inspection_port(
        lease,
        lane_binding,
        policy_proof=snapshot.policy_proof,
        lane_proof=snapshot.lane_proof,
    )
    lane_evidence = lane_inspection.evidence
    if (
        lane_inspection.status != "active"
        or lane_evidence is None
        or lane_evidence.provisioned is None
    ):
        raise HumanFirstLanePreparationError(
            "topology_recovery.historical_finalization_unavailable"
        )
    provisioned = lane_evidence.provisioned
    try:
        provisioned_index = lane_evidence.lane_record_digests.index(
            provisioned.topology_provisioned_record_digest
        )
    except ValueError as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.lane_replay_invalid"
        ) from error
    if provisioned_index + 1 > len(lane_evidence.lane_record_digests):
        raise HumanFirstLanePreparationError(
            "topology_recovery.lane_replay_invalid"
        )

    current = _inspect_prepared_topology_reconciliation(
        snapshot,
        lease=lease,
        allow_pending_policy_content_access=(
            allow_pending_policy_content_access
        ),
    )
    expected_commands = _expected_recovery_commands(snapshot)
    topology_inspection = _inspect_open_mutation_reconciliation_under_lease(
        lease,
        binding,
        snapshot.mutation_intent,
        policy_proof=snapshot.policy_proof,
        lane_proof=snapshot.lane_proof,
        allow_pending_policy_content_access=(
            allow_pending_policy_content_access
        ),
    )
    replay = topology_inspection.evidence
    current_complete = (
        current.status == "not_interrupted"
        and current.detail_code == "topology_recovery.already_complete"
    )
    current_anchor_candidate = bool(
        allow_evidence_anchor_candidate
        and type(allow_evidence_anchor_candidate) is bool
        and current.status == "reconciliation_required"
        and current.detail_code
        == "topology_recovery.lane_reconciliation_required"
    )
    if (
        (not current_complete and not current_anchor_candidate)
        or topology_inspection.status != "active"
        or replay is None
    ):
        raise HumanFirstLanePreparationError(
            "topology_recovery.historical_finalization_unavailable"
        )
    receipt_by_step = {
        receipt.step_id: receipt for receipt in replay.receipts
    }
    historical_confirmed_step_ids = tuple(
        command.step_id
        for command in replay.commands
        if command.step_id in receipt_by_step
        and receipt_by_step[command.step_id].disposition.value == "confirmed"
    )
    historical_evidence_digest = "sha256:" + hashlib.sha256(
        canonical_json(
            {
                "schema": (
                    "ask_herdr.open_topology_recovery_evidence.internal.v1"
                ),
                "project_authority_id": binding.project_authority_id,
                "namespace": binding.namespace,
                "topology_store_incarnation_digest": (
                    snapshot.mutation_intent.topology_store_incarnation_digest
                ),
                "policy_record_digest": (
                    snapshot.policy_proof.policy_record_digest
                ),
                "topology_claim_record_digest": (
                    snapshot.lane_proof.topology_claim_record_digest
                ),
                "mutation_record_digest": replay.mutation_record_digest,
                "record_digests": list(replay.record_digests),
                "settlement_record_digest": replay.settlement_record_digest,
                "lane_record_digests": list(
                    lane_evidence.lane_record_digests[
                        : provisioned_index + 1
                    ]
                ),
                "lane_head_record_digest": (
                    provisioned.topology_provisioned_record_digest
                ),
                "lane_head_state_digest": provisioned.lane_state_digest,
                "expected_commands": [
                    list(command) for command in expected_commands
                ],
                "receipts": [
                    {
                        "step_id": receipt.step_id,
                        "command_receipt_digest": (
                            receipt.command_receipt_digest
                        ),
                        "request_id": receipt.request_id,
                        "disposition": receipt.disposition.value,
                        "session_dir": receipt.session_dir,
                        "socket_path": receipt.socket_path,
                        "session_generation_id": (
                            receipt.session_generation_id
                        ),
                        "resource_binding_digests": list(
                            receipt.resource_binding_digests
                        ),
                    }
                    for receipt in replay.receipts
                ],
            }
        )
    ).hexdigest()
    historical = _reconciliation_result(
        status="not_interrupted",
        detail_code="topology_recovery.already_complete",
        mutation_id=snapshot.mutation_intent.mutation_id,
        confirmed_step_ids=historical_confirmed_step_ids,
        pending_step_ids=(),
        unresolved_witness_digests=(),
        evidence_digest=historical_evidence_digest,
    )
    return historical.recovery_state_digest


def _finalize_prepared_topology_reconciliation_under_lease(
    lease: Any,
    prepared: PreparedFirstLaneProvision,
    *,
    expected_recovery_state_digest: str,
    recovery_result_store_binding_digest: Optional[str] = None,
    failpoint: Any = None,
) -> TopologyRecoveryFinalizationResult:
    """Apply the one proved local Lane finalization for an exact state."""

    snapshot = _snapshot_prepared_reconciliation(prepared)
    if (
        type(expected_recovery_state_digest) is not str
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            expected_recovery_state_digest,
        )
        is None
    ):
        raise HumanFirstLanePreparationError(
            "topology_recovery.expected_state_digest_invalid"
        )
    binding = snapshot.journaled_request.store_binding
    project_binding = ValidatedProjectMutationBinding(
        canonical_project_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
    )
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
        lane_id=snapshot.lane_proof.lane_id,
        lane_generation=snapshot.lane_proof.lane_generation,
        lane_binding_digest=snapshot.lane_proof.lane_binding_digest,
    )
    try:
        with nullcontext(lease) as lease:
            current = _inspect_prepared_topology_reconciliation(
                snapshot,
                lease=lease,
            )
            if (
                current.status == "not_interrupted"
                and current.detail_code
                == "topology_recovery.already_complete"
            ):
                provisioned = record_topology_provisioned_under_lease(
                    lease,
                    lane_binding,
                    binding,
                    policy_proof=snapshot.policy_proof,
                    lane_proof=snapshot.lane_proof,
                    recovery_state_digest=(
                        expected_recovery_state_digest
                    ),
                    recovery_result_store_binding_digest=(
                        recovery_result_store_binding_digest
                    ),
                    failpoint=failpoint,
                )
                verified = _inspect_prepared_topology_reconciliation(
                    snapshot,
                    lease=lease,
                )
                if (
                    verified.status != "not_interrupted"
                    or verified.detail_code
                    != "topology_recovery.already_complete"
                ):
                    raise HumanFirstLanePreparationError(
                        "topology_recovery.finalization_unverified"
                    )
                return TopologyRecoveryFinalizationResult(
                    outcome_kind="recovery_finalized",
                    detail_code="topology_recovery.already_finalized",
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    recovery_scope="managed_topology_namespace",
                    expected_recovery_state_digest=(
                        expected_recovery_state_digest
                    ),
                    current_recovery=verified,
                    topology_provisioned_record_digest=(
                        provisioned.topology_provisioned_record_digest
                    ),
                    project_topology_digest=(
                        provisioned.project_topology_digest
                    ),
                )
            if (
                current.status == "reconciliation_required"
                and current.detail_code
                == "topology_recovery.lane_reconciliation_required"
            ):
                provisioned = record_topology_provisioned_under_lease(
                    lease,
                    lane_binding,
                    binding,
                    policy_proof=snapshot.policy_proof,
                    lane_proof=snapshot.lane_proof,
                    recovery_state_digest=(
                        expected_recovery_state_digest
                    ),
                    recovery_result_store_binding_digest=(
                        recovery_result_store_binding_digest
                    ),
                    failpoint=failpoint,
                )
                verified = _inspect_prepared_topology_reconciliation(
                    snapshot,
                    lease=lease,
                )
                if (
                    verified.status != "not_interrupted"
                    or verified.detail_code
                    != "topology_recovery.already_complete"
                ):
                    raise HumanFirstLanePreparationError(
                        "topology_recovery.finalization_unverified"
                    )
                return TopologyRecoveryFinalizationResult(
                    outcome_kind="recovery_finalized",
                    detail_code="topology_recovery.finalized",
                    mutation_id=snapshot.mutation_intent.mutation_id,
                    recovery_scope="managed_topology_namespace",
                    expected_recovery_state_digest=(
                        expected_recovery_state_digest
                    ),
                    current_recovery=verified,
                    topology_provisioned_record_digest=(
                        provisioned.topology_provisioned_record_digest
                    ),
                    project_topology_digest=(
                        provisioned.project_topology_digest
                    ),
                )
            if current.recovery_state_digest != expected_recovery_state_digest:
                raise HumanFirstLanePreparationError(
                    "topology_recovery.expected_state_changed"
                )
            if (
                current.status != "reconciliation_required"
                or current.detail_code
                != "topology_recovery.lane_finalization_required"
            ):
                raise HumanFirstLanePreparationError(
                    "topology_recovery.finalization_not_admissible"
                )
            provisioned = record_topology_provisioned_under_lease(
                lease,
                lane_binding,
                binding,
                policy_proof=snapshot.policy_proof,
                lane_proof=snapshot.lane_proof,
                recovery_state_digest=expected_recovery_state_digest,
                recovery_result_store_binding_digest=(
                    recovery_result_store_binding_digest
                ),
                failpoint=failpoint,
            )
            verified = _inspect_prepared_topology_reconciliation(
                snapshot,
                lease=lease,
            )
            if (
                verified.status != "not_interrupted"
                or verified.detail_code
                != "topology_recovery.already_complete"
            ):
                raise HumanFirstLanePreparationError(
                    "topology_recovery.finalization_unverified"
                )
            return TopologyRecoveryFinalizationResult(
                outcome_kind="recovery_finalized",
                detail_code="topology_recovery.finalized",
                mutation_id=snapshot.mutation_intent.mutation_id,
                recovery_scope="managed_topology_namespace",
                expected_recovery_state_digest=(
                    expected_recovery_state_digest
                ),
                current_recovery=verified,
                topology_provisioned_record_digest=(
                    provisioned.topology_provisioned_record_digest
                ),
                project_topology_digest=provisioned.project_topology_digest,
            )
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        raise HumanFirstLanePreparationError(error.detail_code) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.finalization_invalid"
        ) from error


def finalize_prepared_topology_reconciliation(
    prepared: PreparedFirstLaneProvision,
    *,
    expected_recovery_state_digest: str,
    failpoint: Any = None,
) -> TopologyRecoveryFinalizationResult:
    """Apply one proved local finalization under a fresh Project lease."""

    snapshot = _snapshot_prepared_reconciliation(prepared)
    if (
        type(expected_recovery_state_digest) is not str
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            expected_recovery_state_digest,
        )
        is None
    ):
        raise HumanFirstLanePreparationError(
            "topology_recovery.expected_state_digest_invalid"
        )
    binding = snapshot.journaled_request.store_binding
    project_binding = ValidatedProjectMutationBinding(
        canonical_project_root=binding.canonical_project_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
    )
    try:
        with hold_project_mutation_lease(project_binding) as lease:
            return _finalize_prepared_topology_reconciliation_under_lease(
                lease,
                snapshot,
                expected_recovery_state_digest=(
                    expected_recovery_state_digest
                ),
                failpoint=failpoint,
            )
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        raise HumanFirstLanePreparationError(error.detail_code) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "topology_recovery.finalization_invalid"
        ) from error


def prepare_human_first_lane(
    request: HumanFirstLanePreparationRequest,
    *,
    clock: Callable[[], Any],
    uuid_factory: Callable[[], Any],
    failpoint: Optional[Any] = None,
) -> PreparedFirstLaneProvision:
    """Commit and derive all local prerequisites before any external effect."""

    snapshot = _snapshot_request(request)
    _validate_correlations(snapshot)
    try:
        with hold_project_mutation_lease(snapshot.project_binding) as lease:
            # These two private write ports deliberately borrow the exact live
            # project-root descriptor.  They are implemented in their owning
            # stores so this coordinator never handles storage layout.
            from ask_herdr_policy_ledger import (  # noqa: PLC0415
                commit_human_admission_under_lease,
            )
            from ask_herdr_lane_store import (  # noqa: PLC0415
                prepare_admitted_attempt_under_lease,
            )

            admission_result = commit_human_admission_under_lease(
                lease,
                snapshot.admission,
                clock=clock,
                uuid_factory=uuid_factory,
            )
            if admission_result.outcome_kind not in {
                "human_admission_committed",
                "human_admission_already_committed",
            }:
                _raise_result(admission_result.detail_code)
            policy = validate_committed_human_admission_under_lease(
                lease,
                snapshot.admission,
            )
            _trip(failpoint, "after_policy_admission")

            prepare = PrepareAdmittedAttempt(
                operation="turn.consult",
                operation_id=policy.operation_id,
                canonical_request_digest=policy.canonical_request_digest,
                lane_id=snapshot.lane_binding.lane_id,
                lane_generation=snapshot.lane_binding.lane_generation,
                attempt_id=snapshot.attempt_id,
                expected_head_digest=snapshot.expected_head_digest,
                native_identity_mode=NativeIdentityMode.ESTABLISH_NEW,
                expected_native_correlation_digest=None,
                expected_turn_sequence=1,
                expected_completion_marker=(
                    snapshot.expected_completion_marker
                ),
                reservation_id=None,
                direct_human_policy_record_digest=(
                    policy.policy_record_digest
                ),
            )
            prepared = prepare_admitted_attempt_under_lease(
                lease,
                snapshot.lane_binding,
                prepare,
            )
            if prepared.outcome_kind not in {
                "lane_event_committed",
                "lane_event_already_committed",
            }:
                _raise_result(prepared.detail_code)
            _trip(failpoint, "after_lane_prepare")

            topology_store_incarnation_digest = (
                _ensure_topology_store_incarnation_under_lease(
                    lease,
                    snapshot.topology_binding,
                )
            )
            lane = claim_topology_provisioning_under_lease(
                lease,
                snapshot.lane_binding,
                policy_proof=policy,
                topology_mutation_id=snapshot.topology_mutation_id,
                topology_nonce=snapshot.topology_nonce,
                topology_store_incarnation_digest=(
                    topology_store_incarnation_digest
                ),
            )
            if (
                lane.topology_store_incarnation_digest
                != topology_store_incarnation_digest
            ):
                _raise_result(
                    "human_first_lane.topology_store_incarnation_mismatch"
                )
            _trip(failpoint, "after_lane_claim")

            mutation_box = []  # type: list[TopologyMutationIntent]
            result_box = []  # type: list[Any]

            def commit_while_workspace_is_bound(
                workspace_digest: str,
            ) -> None:
                mutation = TopologyMutationIntent(
                    mutation_id=lane.topology_mutation_id,
                    operation_id=policy.operation_id,
                    canonical_request_digest=policy.canonical_request_digest,
                    policy_record_digest=policy.policy_record_digest,
                    lane_state_digest=lane.lane_state_digest,
                    lane_id=lane.lane_id,
                    lane_generation=lane.lane_generation,
                    lane_binding_digest=lane.lane_binding_digest,
                    lane_workspace_binding_digest=workspace_digest,
                    consultant_key=snapshot.provision_intent.consultant_key,
                    topology_nonce=lane.topology_nonce,
                    lane_workspace_cwd=(
                        snapshot.provision_intent.lane_workspace_cwd
                    ),
                    prior_topology_digest=None,
                    intended_action="reconcile_or_provision",
                    precondition_digest=_precondition_digest(
                        policy,
                        lane,
                        workspace_digest,
                    ),
                    expected_postcondition_digest=(
                        provision_postcondition_digest(
                            snapshot.provision_intent
                        )
                    ),
                    topology_store_incarnation_digest=(
                        topology_store_incarnation_digest
                    ),
                )
                mutation_box.append(mutation)
                result_box.append(
                    commit_mutation_intent_under_lease(
                        lease,
                        snapshot.topology_binding,
                        mutation,
                        policy_proof=policy,
                        lane_proof=lane,
                    )
                )

            root = _borrow_validated_root(
                lease,
                snapshot.topology_binding,
            )
            _lane_workspace_binding_digest_from_root(
                root,
                snapshot.topology_binding,
                snapshot.provision_intent,
                before_return=commit_while_workspace_is_bound,
            )
            if len(mutation_box) != 1 or len(result_box) != 1:
                _raise_result("human_first_lane.workspace_binding_failed")
            mutation = mutation_box[0]
            mutation_result = result_box[0]
            if mutation_result.outcome_kind not in {
                "topology_mutation_prepared",
                "topology_mutation_already_prepared",
            }:
                _raise_result(mutation_result.detail_code)
            _trip(failpoint, "after_topology_intent")

            journaled_request = JournaledProvisionRequest(
                store_binding=snapshot.topology_binding,
                mutation_intent=mutation,
                provision_intent=snapshot.provision_intent,
                session_start_step_id=snapshot.session_start_step_id,
                workspace_create_step_id=(
                    snapshot.workspace_create_step_id
                ),
            )
            return PreparedFirstLaneProvision(
                policy_proof=policy,
                lane_proof=lane,
                mutation_intent=mutation,
                journaled_request=journaled_request,
            )
    except HumanFirstLanePreparationFailpoint:
        raise
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        raise HumanFirstLanePreparationError(
            error.detail_code
        ) from error
    except (TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "human_first_lane.input_invalid"
        ) from error


def execute_prepared_journaled_provision(
    prepared: PreparedFirstLaneProvision,
    *,
    runner: Any,
) -> JournaledProvisionResult:
    """Execute one effect chain from the exact precommitted mutation intent."""

    if type(prepared) is not PreparedFirstLaneProvision:
        raise HumanFirstLanePreparationError(
            "human_first_lane.prepared_type_invalid"
        )
    try:
        if (
            type(prepared.policy_proof)
            is not CommittedHumanAdmissionProof
            or type(prepared.lane_proof) is not ClaimedLaneProof
            or type(prepared.mutation_intent) is not TopologyMutationIntent
            or type(prepared.journaled_request)
            is not JournaledProvisionRequest
            or type(prepared.journaled_request.store_binding)
            is not ValidatedTopologyStoreBinding
            or type(prepared.journaled_request.provision_intent)
            is not ProvisionIntent
            or type(prepared.journaled_request.mutation_intent)
            is not TopologyMutationIntent
        ):
            raise ValueError
        store_binding = ValidatedTopologyStoreBinding(
            **dict(vars(prepared.journaled_request.store_binding))
        )
        provision_intent = ProvisionIntent(
            **dict(vars(prepared.journaled_request.provision_intent))
        )
        journaled_mutation = TopologyMutationIntent(
            **dict(vars(prepared.journaled_request.mutation_intent))
        )
        journaled_request = JournaledProvisionRequest(
            store_binding=store_binding,
            mutation_intent=journaled_mutation,
            provision_intent=provision_intent,
            session_start_step_id=(
                prepared.journaled_request.session_start_step_id
            ),
            workspace_create_step_id=(
                prepared.journaled_request.workspace_create_step_id
            ),
        )
        snapshot = PreparedFirstLaneProvision(
            policy_proof=CommittedHumanAdmissionProof(
                **dict(vars(prepared.policy_proof))
            ),
            lane_proof=ClaimedLaneProof(**dict(vars(prepared.lane_proof))),
            mutation_intent=TopologyMutationIntent(
                **dict(vars(prepared.mutation_intent))
            ),
            journaled_request=journaled_request,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "human_first_lane.prepared_type_invalid"
        ) from error
    if (
        snapshot.journaled_request.mutation_intent
        != snapshot.mutation_intent
    ):
        raise HumanFirstLanePreparationError(
            "human_first_lane.prepared_binding_mismatch"
        )

    # Prepared proofs are correlation values, never capabilities.  Replay the
    # exact Policy admission, pending Lane claim, and precommitted Topology
    # intent under one fresh project lease before any runner can be reached.
    # The authenticated Topology port owns the cross-store correlation rules;
    # this continuation only accepts its exact prepared/replay outcomes.
    try:
        binding = snapshot.journaled_request.store_binding
        project_binding = ValidatedProjectMutationBinding(
            canonical_project_root=binding.canonical_project_root,
            filesystem_device=binding.filesystem_device,
            filesystem_inode=binding.filesystem_inode,
            owner_uid=binding.owner_uid,
            project_authority_id=binding.project_authority_id,
        )
        with hold_project_mutation_lease(project_binding) as lease:
            authenticated = _authenticate_pristine_mutation_under_lease(
                lease,
                binding,
                snapshot.mutation_intent,
                policy_proof=snapshot.policy_proof,
                lane_proof=snapshot.lane_proof,
            )
        if authenticated.outcome_kind != "topology_mutation_prepared":
            raise HumanFirstLanePreparationError(
                authenticated.detail_code
            )
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        raise HumanFirstLanePreparationError(
            error.detail_code
        ) from error
    except (TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "human_first_lane.prepared_binding_mismatch"
        ) from error

    provisioned_result = provision_prepared_journaled(
        snapshot.journaled_request,
        runner=runner,
        policy_proof=snapshot.policy_proof,
        lane_proof=snapshot.lane_proof,
    )

    # Transport settlement is durable Topology evidence, not yet Lane
    # authority.  Publish the record-derived Lane fact under a fresh lease;
    # the provider runner is no longer reachable from this provider-free port.
    try:
        binding = snapshot.journaled_request.store_binding
        project_binding = ValidatedProjectMutationBinding(
            canonical_project_root=binding.canonical_project_root,
            filesystem_device=binding.filesystem_device,
            filesystem_inode=binding.filesystem_inode,
            owner_uid=binding.owner_uid,
            project_authority_id=binding.project_authority_id,
        )
        lane_binding = ValidatedLaneGenerationBinding(
            canonical_root=binding.canonical_project_root,
            filesystem_device=binding.filesystem_device,
            filesystem_inode=binding.filesystem_inode,
            owner_uid=binding.owner_uid,
            project_authority_id=binding.project_authority_id,
            lane_id=snapshot.lane_proof.lane_id,
            lane_generation=snapshot.lane_proof.lane_generation,
            lane_binding_digest=snapshot.lane_proof.lane_binding_digest,
        )
        with hold_project_mutation_lease(project_binding) as lease:
            provisioned_lane = record_topology_provisioned_under_lease(
                lease,
                lane_binding,
                binding,
                policy_proof=snapshot.policy_proof,
                lane_proof=snapshot.lane_proof,
            )
        if (
            type(provisioned_lane) is not ProvisionedLaneProof
            or provisioned_lane.operation_id
            != snapshot.policy_proof.operation_id
            or provisioned_lane.canonical_request_digest
            != snapshot.policy_proof.canonical_request_digest
            or provisioned_lane.policy_record_digest
            != snapshot.policy_proof.policy_record_digest
            or provisioned_lane.lane_id != snapshot.lane_proof.lane_id
            or provisioned_lane.lane_generation
            != snapshot.lane_proof.lane_generation
            or provisioned_lane.attempt_id
            != snapshot.lane_proof.attempt_id
            or provisioned_lane.prepared_lane_record_digest
            != snapshot.lane_proof.prepared_lane_record_digest
            or provisioned_lane.topology_mutation_id
            != snapshot.lane_proof.topology_mutation_id
            or provisioned_lane.topology_nonce
            != snapshot.lane_proof.topology_nonce
            or provisioned_lane.topology_claim_record_digest
            != snapshot.lane_proof.topology_claim_record_digest
            or provisioned_lane.lane_binding_digest
            != snapshot.lane_proof.lane_binding_digest
            or provisioned_lane.project_topology_digest
            != provisioned_result.project_topology_digest
            or provisioned_lane.topology_effect_started_record_digest is None
        ):
            raise HumanFirstLanePreparationError(
                "human_first_lane.topology_settlement_binding_mismatch"
            )
    except HumanFirstLanePreparationError:
        raise
    except ProjectMutationLeaseError as error:
        raise HumanFirstLanePreparationError(error.detail_code) from error
    except (AttributeError, TypeError, ValueError) as error:
        raise HumanFirstLanePreparationError(
            "human_first_lane.topology_settlement_binding_mismatch"
        ) from error

    return provisioned_result


__all__ = (
    "HumanFirstLanePreparationError",
    "HumanFirstLanePreparationFailpoint",
    "HumanFirstLanePreparationRequest",
    "OpenTopologyReconciliation",
    "PreparedFirstLaneProvision",
    "TopologyRecoveryFinalizationResult",
    "execute_prepared_journaled_provision",
    "finalize_prepared_topology_reconciliation",
    "inspect_prepared_topology_reconciliation",
    "prepare_human_first_lane",
)
