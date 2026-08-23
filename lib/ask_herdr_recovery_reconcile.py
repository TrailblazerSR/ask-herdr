"""Record-derived, read-only compilation for Recovery Reconciliation.

The public request carries only a tagged Recovery Scope selector and one
expected-state digest.  This module therefore reconstructs every other fact
from the authoritative Policy, Lane, and Topology journals under one retained
Project Mutation Lease.  It never accepts a caller-provided Prepared value,
never creates authority, and never appends a recovery conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping, Optional, Tuple

from ask_herdr_herdr_transport import ProvisionIntent, TransportError
from ask_herdr_human_first_lane import (
    HumanFirstLanePreparationError,
    OpenTopologyReconciliation,
    PreparedFirstLaneProvision,
    _inspect_prepared_topology_reconciliation,
)
from ask_herdr_json import canonical_json
from ask_herdr_journaled_provision import JournaledProvisionRequest
from ask_herdr_lane_store import (
    ProvisionedLaneProof,
    _inspect_topology_recovery_lane_for_content_access_under_lease,
    _inspect_topology_recovery_lane_for_evidence_anchor_under_lease,
    _inspect_topology_recovery_lane_under_lease,
    _resolve_topology_recovery_lane_under_lease,
)
from ask_herdr_policy_ledger import (
    _derive_committed_human_admission_proof_under_lease,
)
from ask_herdr_project_mutation_lease import (
    ProjectMutationLeaseError,
    ValidatedProjectMutationBinding,
    hold_project_mutation_lease,
)
from ask_herdr_topology_store import (
    _resolve_topology_recovery_mutation_under_lease,
)


@dataclass(frozen=True)
class RecoveryReconcilePreview:
    """Non-authorizing compilation of one exact Lane recovery request."""

    canonical_request_digest: str
    canonical_projection_bytes: bytes
    policy_profile_id: str
    current_recovery: OpenTopologyReconciliation
    current_preconditions: Tuple[str, ...]


@dataclass(frozen=True)
class _DerivedLaneRecoveryContext:
    """Exact prepared value and current facts reconstructed under one lease."""

    prepared: PreparedFirstLaneProvision
    current_recovery: OpenTopologyReconciliation
    policy_profile_id: str
    provisioned: Optional[ProvisionedLaneProof]
    topology_mutation_record_digest: str


class RecoveryReconcileCompileError(RuntimeError):
    """Typed, redacted failure from record-derived recovery compilation."""

    resend_allowed = False

    def __init__(
        self,
        detail_code: str,
        outcome_kind: str,
        *,
        canonical_request_digest: Optional[str] = None,
        current_preconditions: Tuple[str, ...] = (),
    ) -> None:
        super().__init__(detail_code)
        self.detail_code = detail_code
        self.outcome_kind = outcome_kind
        self.canonical_request_digest = canonical_request_digest
        self.current_preconditions = current_preconditions


def _canonical_projection(
    request: Mapping[str, Any],
    binding: ValidatedProjectMutationBinding,
) -> tuple[bytes, str]:
    payload = request["payload"]
    projection = {
        "schema": "ask_herdr.canonical_request_projection.v1",
        "operation": "recovery.reconcile",
        "project": {
            "binding": "bound",
            "root": binding.canonical_root,
            "authority_id": binding.project_authority_id,
            "filesystem_identity": {
                "device": binding.filesystem_device,
                "inode": binding.filesystem_inode,
                "owner_uid": binding.owner_uid,
            },
        },
        "payload": {
            "selector": dict(payload["selector"]),
            "expected_recovery_state_digest": payload[
                "expected_recovery_state_digest"
            ],
        },
    }
    encoded = canonical_json(projection)
    return encoded, "sha256:" + hashlib.sha256(encoded).hexdigest()


def _mapped_error(detail_code: str) -> RecoveryReconcileCompileError:
    if detail_code in {
        "project_mutation_lease.writer_busy",
        "lane_store.writer_active",
        "topology_store.writer_active",
    }:
        outcome = "request_not_currently_admissible"
    elif any(
        token in detail_code
        for token in (
            "candidate",
            "pending",
            "reconciliation",
            "store_changed",
        )
    ):
        outcome = "request_reconciliation_required"
    else:
        outcome = "request_quarantined"
    return RecoveryReconcileCompileError(detail_code, outcome)


def _after_projection_error(
    error: RecoveryReconcileCompileError,
    canonical_request_digest: Optional[str],
) -> RecoveryReconcileCompileError:
    """Retain semantic identity on every failure after projection."""

    if canonical_request_digest is None:
        return error
    return RecoveryReconcileCompileError(
        error.detail_code,
        error.outcome_kind,
        canonical_request_digest=(
            error.canonical_request_digest or canonical_request_digest
        ),
        current_preconditions=tuple(
            sorted(
                {
                    *error.current_preconditions,
                    "semantic.projection_compiled",
                }
            )
        ),
    )


def _require_exact_lane_plan(
    command_intents: tuple[Any, ...],
) -> tuple[Any, Any]:
    if (
        len(command_intents) != 2
        or command_intents[0].step_sequence != 1
        or command_intents[0].prior_step_id is not None
        or command_intents[1].step_sequence != 2
        or command_intents[1].prior_step_id != command_intents[0].step_id
    ):
        raise RecoveryReconcileCompileError(
            "topology_recovery.command_plan_unavailable",
            "request_reconciliation_required",
        )
    return command_intents[0], command_intents[1]


def _derive_lane_recovery_context_under_lease(
    request: Mapping[str, Any],
    project_binding: ValidatedProjectMutationBinding,
    lease: Any,
    *,
    allow_lane_finalization_candidate: bool = False,
    allow_evidence_anchor_candidate: bool = False,
    allow_pending_policy_content_access: bool = False,
) -> _DerivedLaneRecoveryContext:
    """Reconstruct privileged Lane Recovery inputs without applying a token.

    The caller must already hold the exact Project Mutation Lease.  This seam
    derives every proof and command-plan field from durable records; it does
    not decide whether the request's expected recovery-state token is current.
    """

    selector = request["payload"]["selector"]
    if selector["kind"] != "lane":
        raise RecoveryReconcileCompileError(
            "topology_recovery.scope_not_implemented",
            "request_not_currently_admissible",
        )
    resolved_lane = _resolve_topology_recovery_lane_under_lease(
        lease,
        project_binding,
        lane_id=selector["lane_id"],
        lane_generation=selector["generation"],
        allow_single_event_candidate=(
            allow_lane_finalization_candidate
            or allow_evidence_anchor_candidate
        ),
    )
    policy_proof = _derive_committed_human_admission_proof_under_lease(
        lease,
        project_authority_id=project_binding.project_authority_id,
        policy_record_digest=resolved_lane.lane_proof.policy_record_digest,
        allow_pending_content_access=allow_pending_policy_content_access,
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
        resolved_lane.binding,
        policy_proof=policy_proof,
        lane_proof=resolved_lane.lane_proof,
    )
    if lane_inspection.status != "active" and not (
        allow_lane_finalization_candidate
        and type(allow_lane_finalization_candidate) is bool
        and lane_inspection.status == "reconciliation_required"
        and lane_inspection.detail_code
        == "lane_store.topology_recovery_candidate_residue"
    ):
        raise RecoveryReconcileCompileError(
            lane_inspection.detail_code,
            (
                "request_reconciliation_required"
                if lane_inspection.status == "reconciliation_required"
                else "request_quarantined"
            ),
        )
    resolved_topology = _resolve_topology_recovery_mutation_under_lease(
        lease,
        project_binding,
        policy_proof=policy_proof,
        lane_proof=resolved_lane.lane_proof,
        allow_pending_policy_content_access=(
            allow_pending_policy_content_access
        ),
    )
    first, second = _require_exact_lane_plan(
        resolved_topology.command_intents
    )
    mutation = resolved_topology.mutation_intent
    provision_intent = ProvisionIntent(
        project_id=project_binding.project_authority_id,
        lane_id=mutation.lane_id,
        consultant_key=mutation.consultant_key,
        project_root=project_binding.canonical_root,
        topology_nonce=mutation.topology_nonce,
        lane_workspace_cwd=mutation.lane_workspace_cwd,
    )
    journaled_request = JournaledProvisionRequest(
        store_binding=resolved_topology.binding,
        mutation_intent=mutation,
        provision_intent=provision_intent,
        session_start_step_id=first.step_id,
        workspace_create_step_id=second.step_id,
    )
    prepared = PreparedFirstLaneProvision(
        policy_proof=policy_proof,
        lane_proof=resolved_lane.lane_proof,
        mutation_intent=mutation,
        journaled_request=journaled_request,
    )
    return _DerivedLaneRecoveryContext(
        prepared=prepared,
        current_recovery=_inspect_prepared_topology_reconciliation(
            prepared,
            lease=lease,
            allow_pending_policy_content_access=(
                allow_pending_policy_content_access
            ),
        ),
        policy_profile_id=policy_proof.policy_profile_id,
        provisioned=(
            lane_inspection.evidence.provisioned
            if lane_inspection.evidence is not None
            else None
        ),
        topology_mutation_record_digest=(
            resolved_topology.mutation_record_digest
        ),
    )


def _compile_lane_recovery_reconcile_preview_under_lease(
    request: Mapping[str, Any],
    project_binding: ValidatedProjectMutationBinding,
    lease: Any,
    *,
    canonical_bytes: Optional[bytes] = None,
    canonical_digest: Optional[str] = None,
) -> RecoveryReconcilePreview:
    """Compile one Lane recovery request through an already-held root lease.

    This private composition seam deliberately does not acquire or release the
    Project Mutation Lease.  Authority-record callers can therefore classify
    exact replay first, then recompile the current Lane/Topology evidence and
    append one Policy record without a lock gap or nested root lock.
    """

    if canonical_bytes is None or canonical_digest is None:
        canonical_bytes, canonical_digest = _canonical_projection(
            request,
            project_binding,
        )
    context = _derive_lane_recovery_context_under_lease(
        request,
        project_binding,
        lease,
    )
    current = context.current_recovery
    if (
        current.recovery_state_digest
        != request["payload"]["expected_recovery_state_digest"]
    ):
        raise RecoveryReconcileCompileError(
            "topology_recovery.expected_state_changed",
            "request_not_currently_admissible",
            canonical_request_digest=canonical_digest,
            current_preconditions=(
                "recovery.expected_state_changed",
                "recovery.scope_resolved",
                "semantic.projection_compiled",
            ),
        )
    preconditions = {
        "recovery.expected_state_verified",
        "recovery.scope_resolved",
    }
    if (
        current.status == "reconciliation_required"
        and current.detail_code
        == "topology_recovery.lane_finalization_required"
    ):
        preconditions.add("recovery.local_finalization_available")
    else:
        preconditions.add("recovery.state_classified")
    return RecoveryReconcilePreview(
        canonical_request_digest=canonical_digest,
        canonical_projection_bytes=canonical_bytes,
        policy_profile_id=context.policy_profile_id,
        current_recovery=current,
        current_preconditions=tuple(sorted(preconditions)),
    )


def compile_lane_recovery_reconcile_preview(
    request: Mapping[str, Any],
    project_binding: ValidatedProjectMutationBinding,
) -> RecoveryReconcilePreview:
    """Compile one exact Lane scope solely from current durable records."""

    if type(request) is not dict or type(project_binding) is not (
        ValidatedProjectMutationBinding
    ):
        raise RecoveryReconcileCompileError(
            "topology_recovery.request_type_invalid",
            "request_invalid",
        )
    canonical_digest: Optional[str] = None
    try:
        selector = request["payload"]["selector"]
        canonical_bytes, canonical_digest = _canonical_projection(
            request,
            project_binding,
        )
        if selector["kind"] != "lane":
            raise RecoveryReconcileCompileError(
                "topology_recovery.scope_not_implemented",
                "request_not_currently_admissible",
            )
        with hold_project_mutation_lease(project_binding) as lease:
            return _compile_lane_recovery_reconcile_preview_under_lease(
                request,
                project_binding,
                lease,
                canonical_bytes=canonical_bytes,
                canonical_digest=canonical_digest,
            )
    except RecoveryReconcileCompileError as error:
        enriched = _after_projection_error(error, canonical_digest)
        if enriched is error:
            raise
        raise enriched from error
    except ProjectMutationLeaseError as error:
        raise _after_projection_error(
            _mapped_error(error.detail_code),
            canonical_digest,
        ) from error
    except HumanFirstLanePreparationError as error:
        raise _after_projection_error(
            RecoveryReconcileCompileError(
                error.detail_code,
                "request_quarantined",
            ),
            canonical_digest,
        ) from error
    except TransportError as error:
        raise _after_projection_error(
            RecoveryReconcileCompileError(
                "topology_recovery.record_derived_compilation_invalid",
                "request_quarantined",
            ),
            canonical_digest,
        ) from error
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise _after_projection_error(
            RecoveryReconcileCompileError(
                "topology_recovery.record_derived_compilation_invalid",
                "request_quarantined",
            ),
            canonical_digest,
        ) from error


__all__ = [
    "RecoveryReconcileCompileError",
    "RecoveryReconcilePreview",
    "compile_lane_recovery_reconcile_preview",
]
