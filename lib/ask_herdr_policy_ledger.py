"""Private, provider-free Policy Ledger admission for direct-human operations.

The two public functions in this module deliberately expose no filesystem
layout.  They consume core-validated immutable facts, and the commit function
owns correlation, replay classification, sequencing, hashing, durable staging,
and publication of the new ledger head.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import fcntl
import os
from typing import Any, Callable, Optional

from ask_herdr_authority_store import (
    ACTIVE_NAME,
    DIGEST_PATTERN,
    OBJECTS_NAME,
    STAGING_NAME,
    STORE_NAME,
    UUID4_PATTERN,
    AuthorityStoreInspection,
    _canonical_timestamp,
    _digest,
    _head_sources_still_bound,
    _identity,
    _inspect_locked,
    _ledger_object_name,
    _matches,
    _new_uuid,
    _open_canonical_root,
    _open_private_directory,
    _parse_canonical_timestamp,
    _pending_head_name,
    _private_file_identity,
    _read_private_json,
    _read_private_json_with_identity,
    _record_consumed_receipt_id,
    _record_owner_operation_id,
    _trip,
    _validate_evidence_content_access_admission_record,
    _validate_evidence_content_access_settlement_record,
    _validate_recovery_operation_admission_record,
    _write_new_file,
    inspect_authority_store,
)
from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object


@dataclass(frozen=True)
class ValidatedHumanApprovalReceipt:
    """Trusted-human approval already bound to one exact operation."""

    receipt_id: str
    project_authority_id: str
    policy_profile_id: str
    operation: str
    action_reason: str
    provider: str
    operation_id: str
    canonical_request_digest: str
    confirmed_at: str
    expires_at: str


@dataclass(frozen=True)
class ConfirmedHumanAdmission:
    """Core-established operation facts and their trusted approval receipt."""

    project_authority_id: str
    policy_profile_id: str
    operation: str
    action_reason: str
    provider: str
    operation_id: str
    canonical_request_digest: str
    approval_receipt: ValidatedHumanApprovalReceipt


@dataclass(frozen=True)
class PolicyAuthorityInspection:
    """Path-free projection of the currently authoritative Policy Ledger head."""

    status: str
    detail_code: str
    authority_id: Optional[str] = None
    profile_id: Optional[str] = None
    ledger_id: Optional[str] = None
    head_sequence: Optional[int] = None
    head_digest: Optional[str] = None
    head_record_bytes: Optional[bytes] = None
    ledger_record_bytes: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class HumanAdmissionResult:
    """Typed result for one attempted direct-human ledger admission."""

    outcome_kind: str
    detail_code: str
    decision: Optional[str] = None
    ledger_id: Optional[str] = None
    sequence: Optional[int] = None
    previous_record_digest: Optional[str] = None
    record_digest: Optional[str] = None
    record_bytes: Optional[bytes] = None


@dataclass(frozen=True)
class CommittedHumanAdmissionProof:
    """Exact durable direct-human admission authenticated under one lease.

    This is deliberately a path-free capability fact.  Downstream Lane and
    Topology ports can correlate their immutable records to the Policy Ledger
    record without receiving a filesystem descriptor or trusting caller-made
    strings for the direct-human budget treatment.
    """

    project_authority_id: str
    policy_profile_id: str
    ledger_id: str
    sequence: int
    operation: str
    action_reason: str
    provider: str
    operation_id: str
    canonical_request_digest: str
    approval_receipt_id: str
    policy_record_digest: str
    provider_budget_effect: str
    project_budget_effect: str


@dataclass(frozen=True)
class _CommittedRecoveryOperationAuthorityProof:
    """Record-derived authority for one provider-neutral Recovery operation.

    The proof is private and may be created only by replaying the complete
    active mixed Policy Ledger under a retained Project Mutation Lease.  Its
    canonical projection is retained as bytes so downstream composition never
    trusts a caller-owned mutable mapping.
    """

    project_authority_id: str
    policy_profile_id: str
    ledger_id: str
    sequence: int
    operation_id: str
    authority_ref: str
    canonical_request_digest: str
    recovery_operation_admission_record_digest: str
    lane_id: str
    lane_generation: int
    expected_recovery_state_digest: str
    current_recovery_state_digest: str
    current_preconditions: tuple[str, ...]
    canonical_projection_bytes: bytes


@dataclass(frozen=True)
class _EvidenceContentAccessAdmissionProof:
    """Durable Policy-owned admission for one exact access UUID."""

    project_authority_id: str
    policy_profile_id: str
    ledger_id: str
    sequence: int
    access_id: str
    evidence_id: str
    expected_content_digest: str
    relationship_operation_id: str
    permitted_selection: dict
    source_relationship_digest: str
    evidence_registry_record_digest: str
    policy_record_digest: str


@dataclass(frozen=True)
class _EvidenceContentAccessSettlementProof:
    """Authenticated consume-before-exposure Policy fact."""

    project_authority_id: str
    policy_profile_id: str
    ledger_id: str
    sequence: int
    access_id: str
    content_read_operation_id: str
    canonical_request_digest: str
    evidence_id: str
    content_digest: str
    selection: dict
    access_admission_record_digest: str
    policy_record_digest: str


def _project(inspection: AuthorityStoreInspection) -> PolicyAuthorityInspection:
    return PolicyAuthorityInspection(
        inspection.status,
        inspection.detail_code,
        authority_id=inspection.authority_id,
        profile_id=inspection.profile_id,
        ledger_id=inspection.ledger_id,
        head_sequence=inspection.head_sequence,
        head_digest=inspection.head_digest,
        head_record_bytes=inspection.head_record_bytes,
        ledger_record_bytes=inspection.ledger_record_bytes,
    )


def inspect_policy_authority(canonical_root: str) -> PolicyAuthorityInspection:
    """Inspect the ledger without creating, repairing, or consuming authority."""

    return _project(inspect_authority_store(canonical_root))


def _validate_admission(admission: ConfirmedHumanAdmission) -> None:
    if not isinstance(admission, ConfirmedHumanAdmission):
        raise ValueError("policy_ledger.admission_type_invalid")
    receipt = admission.approval_receipt
    if not isinstance(receipt, ValidatedHumanApprovalReceipt):
        raise ValueError("policy_ledger.receipt_type_invalid")
    uuid_values = (
        admission.project_authority_id,
        admission.policy_profile_id,
        admission.operation_id,
        receipt.receipt_id,
    )
    if any(not _matches(UUID4_PATTERN, value) for value in uuid_values):
        raise ValueError("policy_ledger.identity_invalid")
    if not _matches(DIGEST_PATTERN, admission.canonical_request_digest):
        raise ValueError("policy_ledger.request_digest_invalid")
    scalar_values = (
        admission.operation,
        admission.action_reason,
        admission.provider,
    )
    if any(type(value) is not str or not value for value in scalar_values):
        raise ValueError("policy_ledger.operation_invalid")
    correlated = {
        "project_authority_id": admission.project_authority_id,
        "policy_profile_id": admission.policy_profile_id,
        "operation": admission.operation,
        "action_reason": admission.action_reason,
        "provider": admission.provider,
        "operation_id": admission.operation_id,
        "canonical_request_digest": admission.canonical_request_digest,
    }
    for field, value in correlated.items():
        receipt_value = getattr(receipt, field)
        if field in {"project_authority_id", "policy_profile_id", "operation_id"}:
            if not _matches(UUID4_PATTERN, receipt_value):
                raise ValueError("policy_ledger.receipt_identity_invalid")
        elif field == "canonical_request_digest":
            if not _matches(DIGEST_PATTERN, receipt_value):
                raise ValueError("policy_ledger.receipt_digest_invalid")
        elif type(receipt_value) is not str or not receipt_value:
            raise ValueError("policy_ledger.receipt_operation_invalid")
    confirmed_at = _parse_canonical_timestamp(receipt.confirmed_at)
    expires_at = _parse_canonical_timestamp(receipt.expires_at)
    if expires_at < confirmed_at:
        raise ValueError("policy_ledger.receipt_interval_invalid")


def _receipt_correlates(admission: ConfirmedHumanAdmission) -> bool:
    receipt = admission.approval_receipt
    return all(
        getattr(receipt, field) == getattr(admission, field)
        for field in (
            "project_authority_id",
            "policy_profile_id",
            "operation",
            "action_reason",
            "provider",
            "operation_id",
            "canonical_request_digest",
        )
    )


def _receipt_payload(receipt: ValidatedHumanApprovalReceipt) -> dict:
    return {
        "schema": "ask_herdr.human_approval_receipt.v1",
        "receipt_id": receipt.receipt_id,
        "project_authority_id": receipt.project_authority_id,
        "policy_profile_id": receipt.policy_profile_id,
        "operation": receipt.operation,
        "action_reason": receipt.action_reason,
        "provider": receipt.provider,
        "operation_id": receipt.operation_id,
        "canonical_request_digest": receipt.canonical_request_digest,
        "confirmed_at": receipt.confirmed_at,
        "expires_at": receipt.expires_at,
        "consumption": "consumed",
    }


def _operation_payload(admission: ConfirmedHumanAdmission) -> dict:
    return {
        "operation": admission.operation,
        "action_reason": admission.action_reason,
        "provider": admission.provider,
        "operation_id": admission.operation_id,
        "canonical_request_digest": admission.canonical_request_digest,
    }


def validate_committed_human_admission_under_lease(
    lease: Any,
    admission: ConfirmedHumanAdmission,
) -> CommittedHumanAdmissionProof:
    """Authenticate one exact committed human admission under ``lease``.

    The Project Mutation Lease owns and keeps the project-root descriptor
    locked.  This port only borrows that exact descriptor: it neither reopens
    the canonical root nor acquires another root lock.  The complete Authority
    Store inspection authenticates the immutable ledger chain before this
    function exports a narrow, path-free proof to another store.
    """

    # Keep the existing type/shape validation for trusted core facts.  The
    # import is intentionally local so the established public Policy API does
    # not gain a module-import dependency on this private composition seam.
    _validate_admission(admission)
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    binding = _validated_binding_for_authority(
        lease,
        admission.project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    inspection = _inspect_locked(root, binding.canonical_root)

    detail_code: Optional[str] = None
    proof: Optional[CommittedHumanAdmissionProof] = None
    if inspection.status != "active":
        detail_code = inspection.detail_code
    elif (
        inspection.authority_id != admission.project_authority_id
        or inspection.profile_id != admission.policy_profile_id
        or not _receipt_correlates(admission)
    ):
        detail_code = "policy_ledger.human_admission_mismatch"
    else:
        expected_operation = _operation_payload(admission)
        expected_receipt = _receipt_payload(admission.approval_receipt)
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if record.get("record_kind") != "human_admission":
                continue
            if (
                record["operation"] == expected_operation
                and record["human_approval_receipt"] == expected_receipt
            ):
                proof = CommittedHumanAdmissionProof(
                    project_authority_id=admission.project_authority_id,
                    policy_profile_id=admission.policy_profile_id,
                    ledger_id=record["ledger_id"],
                    sequence=record["sequence"],
                    operation=admission.operation,
                    action_reason=admission.action_reason,
                    provider=admission.provider,
                    operation_id=admission.operation_id,
                    canonical_request_digest=admission.canonical_request_digest,
                    approval_receipt_id=admission.approval_receipt.receipt_id,
                    policy_record_digest=record["record_digest"],
                    provider_budget_effect="not_counted",
                    project_budget_effect="not_counted",
                )
                break
        if proof is None:
            detail_code = (
                "policy_ledger.human_admission_absent"
                if len(inspection.ledger_record_bytes) == 1
                else "policy_ledger.human_admission_mismatch"
            )

    # Revalidate the process-local token and complete named path chain after
    # reading.  A concurrent path rebind therefore cannot escape as a proof.
    _borrow_validated_root(lease, binding)
    if proof is None:
        raise ProjectMutationLeaseError(
            detail_code or "policy_ledger.human_admission_mismatch"
        )
    return proof


def _derive_committed_human_admission_proof_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    policy_record_digest: str,
    allow_pending_content_access: bool = False,
) -> CommittedHumanAdmissionProof:
    """Derive one admission proof solely from the complete live ledger.

    The two caller values select durable authority; they do not contribute any
    proof fields.  The retained Project Mutation Lease supplies the exact root
    descriptor, and the Authority Store replay authenticates the complete
    active Policy chain before this port projects one admitted record.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    if not _matches(UUID4_PATTERN, project_authority_id) or not _matches(
        DIGEST_PATTERN,
        policy_record_digest,
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )

    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    inspection = _inspect_locked(root, binding.canonical_root)
    pending_content_access = False
    if (
        allow_pending_content_access is True
        and type(allow_pending_content_access) is bool
        and inspection.status == "reconciliation_required"
        and inspection.detail_code
        in {
            "policy_ledger.pending_head_publication",
            "policy_ledger.orphaned_record",
            "policy_ledger.stale_head_publication",
        }
        and inspection.ledger_record_bytes
    ):
        pending = parse_json_object(
            inspection.ledger_record_bytes[-1][:-1]
            if inspection.ledger_record_bytes[-1].endswith(b"\n")
            else inspection.ledger_record_bytes[-1]
        )
        pending_content_access = pending.get("record_kind") in {
            "evidence_content_access_admission",
            "evidence_content_access_settlement",
        }
    if inspection.status != "active" and not pending_content_access:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(inspection.detail_code)
    if inspection.authority_id != project_authority_id:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )

    try:
        matching_records = []
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if record.get("record_digest") == policy_record_digest:
                matching_records.append(record)
    except (StrictJsonError, TypeError, ValueError) as error:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        ) from error

    if not matching_records:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_absent"
        )
    if len(matching_records) != 1:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )

    record = matching_records[0]
    operation = record.get("operation")
    receipt = record.get("human_approval_receipt")
    decision = record.get("policy_decision")
    if (
        type(operation) is not dict
        or type(receipt) is not dict
        or type(decision) is not dict
    ):
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        )
    expected_effects = [
        {
            "scope": "provider",
            "provider": operation.get("provider"),
            "budget_effect": "not_counted",
        },
        {"scope": "project", "budget_effect": "not_counted"},
    ]
    correlated_fields = (
        "operation",
        "action_reason",
        "provider",
        "operation_id",
        "canonical_request_digest",
    )
    if (
        record.get("record_kind") != "human_admission"
        or record.get("ledger_id") != inspection.ledger_id
        or receipt.get("schema")
        != "ask_herdr.human_approval_receipt.v1"
        or receipt.get("project_authority_id") != inspection.authority_id
        or receipt.get("policy_profile_id") != inspection.profile_id
        or receipt.get("consumption") != "consumed"
        or any(
            receipt.get(field) != operation.get(field)
            for field in correlated_fields
        )
        or decision.get("decision") != "admitted"
        or decision.get("automatic_budget_effects") != expected_effects
    ):
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )

    effects = decision["automatic_budget_effects"]
    try:
        proof = CommittedHumanAdmissionProof(
            project_authority_id=receipt["project_authority_id"],
            policy_profile_id=receipt["policy_profile_id"],
            ledger_id=record["ledger_id"],
            sequence=record["sequence"],
            operation=operation["operation"],
            action_reason=operation["action_reason"],
            provider=operation["provider"],
            operation_id=operation["operation_id"],
            canonical_request_digest=operation[
                "canonical_request_digest"
            ],
            approval_receipt_id=receipt["receipt_id"],
            policy_record_digest=record["record_digest"],
            provider_budget_effect=effects[0]["budget_effect"],
            project_budget_effect=effects[1]["budget_effect"],
        )
    except (IndexError, KeyError, TypeError, ValueError) as error:
        _borrow_validated_root(lease, binding)
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        ) from error

    # A proof may escape only while the retained descriptor and every named
    # component still identify the exact leased project root.
    _borrow_validated_root(lease, binding)
    return proof


def _authenticate_committed_human_admission_proof_under_lease(
    lease: Any,
    proof: CommittedHumanAdmissionProof,
    *,
    allow_pending_content_access: bool = False,
) -> CommittedHumanAdmissionProof:
    """Re-authenticate an exported proof against the complete live ledger.

    Proof objects are transport values, not capabilities.  Every downstream
    mutation port must call this function under the same project lease before
    trusting their fields.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    if type(proof) is not CommittedHumanAdmissionProof:
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )
    # Freeze one exact base-value snapshot before touching durable state.  The
    # exported dataclass is correlation data, never a capability: subclasses
    # and caller-owned instances must not be returned to downstream ports.
    try:
        submitted = CommittedHumanAdmissionProof(**dict(vars(proof)))
    except (TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        submitted.project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    inspection = _inspect_locked(root, binding.canonical_root)
    pending_content_access = False
    if (
        allow_pending_content_access is True
        and type(allow_pending_content_access) is bool
        and inspection.status == "reconciliation_required"
        and inspection.detail_code
        in {
            "policy_ledger.pending_head_publication",
            "policy_ledger.orphaned_record",
            "policy_ledger.stale_head_publication",
        }
        and inspection.ledger_record_bytes
    ):
        pending = parse_json_object(
            inspection.ledger_record_bytes[-1][:-1]
            if inspection.ledger_record_bytes[-1].endswith(b"\n")
            else inspection.ledger_record_bytes[-1]
        )
        pending_content_access = pending.get("record_kind") in {
            "evidence_content_access_admission",
            "evidence_content_access_settlement",
        }
    if (
        (inspection.status != "active" and not pending_content_access)
        or inspection.authority_id != submitted.project_authority_id
        or inspection.profile_id != submitted.policy_profile_id
        or inspection.ledger_id != submitted.ledger_id
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )
    matched: Optional[CommittedHumanAdmissionProof] = None
    for payload in inspection.ledger_record_bytes[1:]:
        record = parse_json_object(
            payload[:-1] if payload.endswith(b"\n") else payload
        )
        operation = record.get("operation", {})
        receipt = record.get("human_approval_receipt", {})
        decision = record.get("policy_decision", {})
        if record.get("record_digest") != submitted.policy_record_digest:
            continue
        expected_effects = [
            {
                "scope": "provider",
                "provider": operation.get("provider"),
                "budget_effect": "not_counted",
            },
            {"scope": "project", "budget_effect": "not_counted"},
        ]
        if (
            record.get("record_kind") == "human_admission"
            and receipt.get("project_authority_id")
            == inspection.authority_id
            and receipt.get("policy_profile_id") == inspection.profile_id
            and receipt.get("consumption") == "consumed"
            and decision.get("decision") == "admitted"
            and decision.get("automatic_budget_effects") == expected_effects
        ):
            derived = CommittedHumanAdmissionProof(
                project_authority_id=receipt["project_authority_id"],
                policy_profile_id=receipt["policy_profile_id"],
                ledger_id=record["ledger_id"],
                sequence=record["sequence"],
                operation=operation["operation"],
                action_reason=operation["action_reason"],
                provider=operation["provider"],
                operation_id=operation["operation_id"],
                canonical_request_digest=operation[
                    "canonical_request_digest"
                ],
                approval_receipt_id=receipt["receipt_id"],
                policy_record_digest=record["record_digest"],
                provider_budget_effect="not_counted",
                project_budget_effect="not_counted",
            )
            if derived == submitted:
                matched = derived
        break
    _borrow_validated_root(lease, binding)
    if matched is None:
        raise ProjectMutationLeaseError(
            "policy_ledger.human_admission_mismatch"
        )
    return matched


def _classify_existing(
    inspection: AuthorityStoreInspection,
    admission: ConfirmedHumanAdmission,
) -> Optional[HumanAdmissionResult]:
    """Classify replay and conflicts before requesting clock or UUID facts."""

    expected_operation = _operation_payload(admission)
    expected_receipt = _receipt_payload(admission.approval_receipt)
    for payload in inspection.ledger_record_bytes:
        record = parse_json_object(payload[:-1] if payload.endswith(b"\n") else payload)
        operation_id = _record_owner_operation_id(record)
        receipt_id = _record_consumed_receipt_id(record)
        if operation_id == admission.operation_id:
            if (
                record.get("record_kind") == "human_admission"
                and record.get("operation") == expected_operation
                and record.get("human_approval_receipt") == expected_receipt
            ):
                return HumanAdmissionResult(
                    "human_admission_already_committed",
                    "policy_ledger.exact_replay",
                    decision="admitted",
                    ledger_id=record["ledger_id"],
                    sequence=record["sequence"],
                    previous_record_digest=record["previous_record_digest"],
                    record_digest=record["record_digest"],
                    record_bytes=payload,
                )
            return HumanAdmissionResult(
                "human_admission_conflict",
                "policy_ledger.operation_identity_conflict",
                ledger_id=inspection.ledger_id,
            )
        if receipt_id == admission.approval_receipt.receipt_id:
            return HumanAdmissionResult(
                "human_admission_conflict",
                "policy_ledger.receipt_already_consumed",
                ledger_id=inspection.ledger_id,
            )
    return None


def _recovery_inactive_result(
    inspection: AuthorityStoreInspection,
) -> HumanAdmissionResult:
    outcome = (
        "recovery_operation_admission_conflict"
        if inspection.status == "quarantined"
        else "recovery_operation_admission_reconciliation_required"
    )
    return HumanAdmissionResult(
        outcome,
        inspection.detail_code,
        ledger_id=inspection.ledger_id,
    )


def _classify_recovery_existing(
    inspection: AuthorityStoreInspection,
    *,
    operation_id: str,
    canonical_request_digest: str,
    canonical_projection: dict,
    receipt_payload: dict,
) -> Optional[HumanAdmissionResult]:
    """Classify Recovery replay/conflict across the complete mixed ledger."""

    requested_receipt_id = receipt_payload.get("receipt_id")
    for payload in inspection.ledger_record_bytes:
        record = parse_json_object(
            payload[:-1] if payload.endswith(b"\n") else payload
        )
        owner_operation_id = _record_owner_operation_id(record)
        consumed_receipt_id = _record_consumed_receipt_id(record)
        if owner_operation_id == operation_id:
            operation = record.get("canonical_operation")
            if (
                record.get("record_kind")
                == "recovery_operation_admission"
                and type(operation) is dict
                and operation.get("canonical_request_digest")
                == canonical_request_digest
                and operation.get("canonical_projection")
                == canonical_projection
                and record.get("human_approval_receipt")
                == receipt_payload
            ):
                return HumanAdmissionResult(
                    "recovery_operation_admission_already_committed",
                    "policy_ledger.exact_replay",
                    decision="admitted",
                    ledger_id=record["ledger_id"],
                    sequence=record["sequence"],
                    previous_record_digest=record[
                        "previous_record_digest"
                    ],
                    record_digest=record["record_digest"],
                    record_bytes=payload,
                )
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.operation_identity_conflict",
                ledger_id=inspection.ledger_id,
            )
        if consumed_receipt_id == requested_receipt_id:
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.receipt_already_consumed",
                ledger_id=inspection.ledger_id,
            )
    return None


def _classify_recovery_operation_authority_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    policy_profile_id: str,
    operation_id: str,
    canonical_request_digest: str,
    canonical_projection: dict,
    receipt_payload: dict,
) -> Optional[HumanAdmissionResult]:
    """Return exact replay/conflict before recompilation, clock, or UUID."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if inspection.status != "active":
            return _recovery_inactive_result(inspection)
        if (
            inspection.authority_id != project_authority_id
            or inspection.profile_id != policy_profile_id
        ):
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.authority_binding_mismatch",
                ledger_id=inspection.ledger_id,
            )
        return _classify_recovery_existing(
            inspection,
            operation_id=operation_id,
            canonical_request_digest=canonical_request_digest,
            canonical_projection=canonical_projection,
            receipt_payload=receipt_payload,
        )
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _resolve_recovery_operation_authority_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    authority_ref: str,
    operation_id: str,
    canonical_request_digest: str,
    canonical_projection: dict,
) -> Optional[HumanAdmissionResult]:
    """Resolve one exact committed Recovery admission before prompting.

    ``None`` means the authenticated active ledger contains neither the
    operation identity nor the opaque authority reference.  Any collision,
    pending publication, or integrity barrier returns a typed non-authorizing
    result instead.  The helper owns no clock, UUID, write, or effect seam.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    if (
        not _matches(UUID4_PATTERN, project_authority_id)
        or not _matches(UUID4_PATTERN, authority_ref)
        or not _matches(UUID4_PATTERN, operation_id)
        or not _matches(DIGEST_PATTERN, canonical_request_digest)
        or type(canonical_projection) is not dict
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.recovery_operation_resolution_invalid"
        )
    try:
        projection = parse_json_object(canonical_json(canonical_projection))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.recovery_operation_resolution_invalid"
        ) from error

    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if inspection.status != "active":
            return _recovery_inactive_result(inspection)
        if inspection.authority_id != project_authority_id:
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.authority_binding_mismatch",
                ledger_id=inspection.ledger_id,
            )
        for payload in inspection.ledger_record_bytes:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            owner_operation_id = _record_owner_operation_id(record)
            consumed_receipt_id = _record_consumed_receipt_id(record)
            if (
                owner_operation_id != operation_id
                and consumed_receipt_id != authority_ref
            ):
                continue
            operation = record.get("canonical_operation")
            receipt = record.get("human_approval_receipt")
            if (
                record.get("record_kind")
                == "recovery_operation_admission"
                and type(operation) is dict
                and type(receipt) is dict
                and owner_operation_id == operation_id
                and consumed_receipt_id == authority_ref
                and operation.get("canonical_request_digest")
                == canonical_request_digest
                and operation.get("canonical_projection") == projection
            ):
                return HumanAdmissionResult(
                    "recovery_operation_admission_already_committed",
                    "policy_ledger.exact_replay",
                    decision="admitted",
                    ledger_id=record["ledger_id"],
                    sequence=record["sequence"],
                    previous_record_digest=record[
                        "previous_record_digest"
                    ],
                    record_digest=record["record_digest"],
                    record_bytes=payload,
                )
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.operation_identity_conflict",
                ledger_id=inspection.ledger_id,
            )
        return None
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _derive_committed_recovery_operation_authority_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    operation_id: str,
    allow_pending_content_access: bool = False,
) -> _CommittedRecoveryOperationAuthorityProof:
    """Derive one committed Recovery authority solely from durable records.

    ``operation_id`` selects a record; it contributes no authority fields.  A
    provider-bound human admission or genesis operation with the same selector
    is intentionally reported as absent Recovery authority.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    if (
        type(project_authority_id) is not str
        or not _matches(UUID4_PATTERN, project_authority_id)
        or type(operation_id) is not str
        or not _matches(UUID4_PATTERN, operation_id)
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.recovery_operation_authority_input_invalid"
        )

    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        pending_content_access = False
        if (
            allow_pending_content_access is True
            and type(allow_pending_content_access) is bool
            and inspection.status == "reconciliation_required"
            and inspection.detail_code
            in {
                "policy_ledger.pending_head_publication",
                "policy_ledger.orphaned_record",
                "policy_ledger.stale_head_publication",
            }
            and inspection.ledger_record_bytes
        ):
            pending = parse_json_object(
                inspection.ledger_record_bytes[-1][:-1]
                if inspection.ledger_record_bytes[-1].endswith(b"\n")
                else inspection.ledger_record_bytes[-1]
            )
            pending_content_access = pending.get("record_kind") in {
                "evidence_content_access_admission",
                "evidence_content_access_settlement",
            }
        if inspection.status != "active" and not pending_content_access:
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        if inspection.authority_id != project_authority_id:
            raise ProjectMutationLeaseError(
                "policy_ledger.authority_binding_mismatch"
            )

        matches = []
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if _record_owner_operation_id(record) == operation_id:
                matches.append(record)
        if len(matches) != 1:
            raise ProjectMutationLeaseError(
                "policy_ledger.recovery_operation_authority_absent"
                if not matches
                else "policy_ledger.identity_reuse"
            )

        record = matches[0]
        operation = record.get("canonical_operation")
        receipt = record.get("human_approval_receipt")
        decision = record.get("policy_decision")
        if (
            record.get("record_kind") != "recovery_operation_admission"
            or type(operation) is not dict
            or type(receipt) is not dict
            or type(decision) is not dict
        ):
            raise ProjectMutationLeaseError(
                "policy_ledger.recovery_operation_authority_absent"
            )

        projection = operation.get("canonical_projection")
        selector = operation.get("recovery_scope_selector")
        project = operation.get("project")
        projection_project = (
            projection.get("project") if type(projection) is dict else None
        )
        projection_payload = (
            projection.get("payload") if type(projection) is dict else None
        )
        filesystem_identity = {
            "device": binding.filesystem_device,
            "inode": binding.filesystem_inode,
            "owner_uid": binding.owner_uid,
        }
        expected_preconditions = (
            "recovery.expected_state_verified",
            "recovery.local_finalization_available",
            "recovery.scope_resolved",
        )
        if (
            operation.get("operation") != "recovery.reconcile"
            or operation.get("action_reason") != "recover"
            or operation.get("operation_id") != operation_id
            or project
            != {
                "authority_id": project_authority_id,
                "filesystem_identity": filesystem_identity,
            }
            or type(projection) is not dict
            or type(projection_project) is not dict
            or projection_project.get("root") != binding.canonical_root
            or projection_project.get("authority_id")
            != project_authority_id
            or projection_project.get("filesystem_identity")
            != filesystem_identity
            or type(projection_payload) is not dict
            or type(selector) is not dict
            or projection_payload.get("selector") != selector
            or selector.get("kind") != "lane"
            or receipt.get("receipt_id")
            != _record_consumed_receipt_id(record)
            or receipt.get("operation_id") != operation_id
            or receipt.get("project_authority_id")
            != project_authority_id
            or receipt.get("policy_profile_id") != inspection.profile_id
            or receipt.get("consumption") != "consumed"
            or decision.get("decision") != "admitted"
            or decision.get("automatic_budget_effects")
            != [{"scope": "project", "budget_effect": "not_counted"}]
            or tuple(operation.get("current_preconditions", ()))
            != expected_preconditions
            or operation.get("expected_recovery_state_digest")
            != operation.get("current_recovery_state_digest")
            or projection_payload.get("expected_recovery_state_digest")
            != operation.get("expected_recovery_state_digest")
        ):
            raise ProjectMutationLeaseError(
                "policy_ledger.recovery_operation_authority_mismatch"
            )

        projection_bytes = canonical_json(projection)
        request_digest = operation.get("canonical_request_digest")
        if (
            not _matches(DIGEST_PATTERN, request_digest)
            or receipt.get("canonical_request_digest") != request_digest
            or not _matches(UUID4_PATTERN, receipt.get("receipt_id"))
            or not _matches(UUID4_PATTERN, selector.get("lane_id"))
            or type(selector.get("generation")) is not int
            or selector.get("generation") < 1
            or not _matches(
                DIGEST_PATTERN,
                operation.get("expected_recovery_state_digest"),
            )
            or not _matches(DIGEST_PATTERN, record.get("record_digest"))
        ):
            raise ProjectMutationLeaseError(
                "policy_ledger.recovery_operation_authority_mismatch"
            )

        return _CommittedRecoveryOperationAuthorityProof(
            project_authority_id=project_authority_id,
            policy_profile_id=inspection.profile_id,
            ledger_id=record["ledger_id"],
            sequence=record["sequence"],
            operation_id=operation_id,
            authority_ref=receipt["receipt_id"],
            canonical_request_digest=request_digest,
            recovery_operation_admission_record_digest=record[
                "record_digest"
            ],
            lane_id=selector["lane_id"],
            lane_generation=selector["generation"],
            expected_recovery_state_digest=operation[
                "expected_recovery_state_digest"
            ],
            current_recovery_state_digest=operation[
                "current_recovery_state_digest"
            ],
            current_preconditions=expected_preconditions,
            canonical_projection_bytes=projection_bytes,
        )
    except ProjectMutationLeaseError:
        raise
    except (KeyError, StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.integrity_failure"
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _inactive_result(inspection: AuthorityStoreInspection) -> HumanAdmissionResult:
    if inspection.status == "quarantined":
        outcome = "human_admission_conflict"
    else:
        outcome = "human_admission_reconciliation_required"
    return HumanAdmissionResult(
        outcome,
        inspection.detail_code,
        ledger_id=inspection.ledger_id,
    )


def _directory_binding_matches(parent: int, name: str, child: int) -> bool:
    """Prove one retained directory descriptor is still canonically bound."""

    try:
        bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(child)
    except OSError:
        return False
    return _identity(bound) == _identity(opened)


def _store_bindings_match(
    root: int,
    store: int,
    objects: int,
    staging: int,
) -> bool:
    """Prove the exact retained root-to-store directory chain remains visible."""

    return (
        _directory_binding_matches(root, STORE_NAME, store)
        and _directory_binding_matches(store, OBJECTS_NAME, objects)
        and _directory_binding_matches(store, STAGING_NAME, staging)
    )


def _store_matches_inspection(
    inspection: AuthorityStoreInspection,
    store: int,
    objects: int,
    staging: int,
) -> bool:
    """Bind mutation descriptors to the exact store inspected under the lock."""

    return (
        inspection.store_identity is not None
        and inspection.objects_identity is not None
        and inspection.staging_identity is not None
        and _identity(os.fstat(store)) == inspection.store_identity
        and _identity(os.fstat(objects)) == inspection.objects_identity
        and _identity(os.fstat(staging)) == inspection.staging_identity
    )


def _commit_recovery_operation_authority_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    policy_profile_id: str,
    canonical_operation: dict,
    receipt_payload: dict,
    clock: Callable[[], datetime],
    uuid_factory: Callable[[], Any],
    failpoint: Any = None,
) -> HumanAdmissionResult:
    """Append one provider-neutral Recovery authority record under ``lease``."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    try:
        operation = parse_json_object(canonical_json(canonical_operation))
        receipt = parse_json_object(canonical_json(receipt_payload))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.recovery_operation_type_invalid"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if inspection.status != "active":
            return _recovery_inactive_result(inspection)
        if (
            inspection.authority_id != project_authority_id
            or inspection.profile_id != policy_profile_id
        ):
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.authority_binding_mismatch",
                ledger_id=inspection.ledger_id,
            )
        existing = _classify_recovery_existing(
            inspection,
            operation_id=operation.get("operation_id"),
            canonical_request_digest=operation.get(
                "canonical_request_digest"
            ),
            canonical_projection=operation.get("canonical_projection"),
            receipt_payload=receipt,
        )
        if existing is not None:
            return existing
        correlated = (
            receipt.get("project_authority_id") == project_authority_id
            and receipt.get("policy_profile_id") == policy_profile_id
            and all(
                receipt.get(field) == operation.get(field)
                for field in (
                    "operation",
                    "action_reason",
                    "operation_id",
                    "canonical_request_digest",
                )
            )
        )
        if not correlated:
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.receipt_correlation_mismatch",
                ledger_id=inspection.ledger_id,
            )

        recorded_at = _canonical_timestamp(clock())
        now = _parse_canonical_timestamp(recorded_at)
        confirmed_at = _parse_canonical_timestamp(receipt.get("confirmed_at"))
        expires_at = _parse_canonical_timestamp(receipt.get("expires_at"))
        if now >= expires_at:
            return HumanAdmissionResult(
                "recovery_operation_admission_denied",
                "policy_ledger.recovery_human_approval_receipt_expired",
                decision="denied",
                ledger_id=inspection.ledger_id,
            )
        if now < confirmed_at:
            return HumanAdmissionResult(
                "recovery_operation_admission_denied",
                "policy_ledger.recovery_human_approval_receipt_not_yet_valid",
                decision="denied",
                ledger_id=inspection.ledger_id,
            )

        decision_id = _new_uuid(uuid_factory)
        sequence = (inspection.head_sequence or 0) + 1
        previous_digest = inspection.head_digest
        if previous_digest is None or inspection.profile_digest is None:
            return _recovery_inactive_result(inspection)
        record = {
            "schema": "ask_herdr.policy_ledger_record.v1",
            "ledger_id": inspection.ledger_id,
            "sequence": sequence,
            "previous_record_digest": previous_digest,
            "record_kind": "recovery_operation_admission",
            "recorded_at": recorded_at,
            "active_policy": {
                "profile_id": inspection.profile_id,
                "profile_digest": inspection.profile_digest,
            },
            "canonical_operation": operation,
            "policy_decision": {
                "decision_id": decision_id,
                "decision": "admitted",
                "automatic_budget_effects": [
                    {"scope": "project", "budget_effect": "not_counted"}
                ],
            },
            "human_approval_receipt": receipt,
        }
        record_digest = _digest(record)
        record["record_digest"] = record_digest
        record_bytes = canonical_json(record) + b"\n"
        profile_payload = inspection.profile_record_bytes
        if profile_payload is None:
            return _recovery_inactive_result(inspection)
        profile = parse_json_object(
            profile_payload[:-1]
            if profile_payload.endswith(b"\n")
            else profile_payload
        )
        root_metadata = os.fstat(root)
        active_projection = {
            "authority_id": inspection.authority_id,
            "profile_id": inspection.profile_id,
            "profile_digest": inspection.profile_digest,
            "ledger_id": inspection.ledger_id,
        }
        if not _validate_recovery_operation_admission_record(
            record,
            active=active_projection,
            profile=profile,
            sequence=sequence,
            previous_record_digest=previous_digest,
            canonical_root=binding.canonical_root,
            filesystem_identity={
                "device": root_metadata.st_dev,
                "inode": root_metadata.st_ino,
                "owner_uid": root_metadata.st_uid,
            },
        ):
            return HumanAdmissionResult(
                "recovery_operation_admission_conflict",
                "policy_ledger.recovery_operation_invalid",
                ledger_id=inspection.ledger_id,
            )

        store: Optional[int] = None
        objects: Optional[int] = None
        staging: Optional[int] = None
        try:
            store = _open_private_directory(root, STORE_NAME)
            objects = _open_private_directory(store, OBJECTS_NAME)
            staging = _open_private_directory(store, STAGING_NAME)
            try:
                if not _store_matches_inspection(
                    inspection,
                    store,
                    objects,
                    staging,
                ):
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "authority_store.store_changed",
                        ledger_id=inspection.ledger_id,
                    )
                active, active_bytes = _read_private_json(store, ACTIVE_NAME)
                if active.get("ledger_head_digest") != previous_digest:
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "policy_ledger.head_changed",
                        ledger_id=inspection.ledger_id,
                    )
                object_name = _ledger_object_name(
                    inspection.ledger_id,
                    sequence,
                    record_digest,
                )
                _write_new_file(objects, object_name, record_bytes)
                os.fsync(objects)
                next_active = dict(active)
                next_active["ledger_head_digest"] = record_digest
                stage_name = _pending_head_name(
                    operation["operation_id"],
                    record_digest,
                )
                _write_new_file(
                    staging,
                    stage_name,
                    canonical_json(next_active) + b"\n",
                )
                os.fsync(staging)
                _trip(failpoint, "before_head_publication")
                if not _store_bindings_match(root, store, objects, staging):
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "authority_store.store_changed",
                        ledger_id=inspection.ledger_id,
                    )
                current, current_bytes = _read_private_json(store, ACTIVE_NAME)
                if current != active or current_bytes != active_bytes:
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "policy_ledger.head_changed",
                        ledger_id=inspection.ledger_id,
                    )
                os.rename(
                    stage_name,
                    ACTIVE_NAME,
                    src_dir_fd=staging,
                    dst_dir_fd=store,
                )
                os.fsync(store)
                os.fsync(staging)
                if not _store_bindings_match(root, store, objects, staging):
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "authority_store.store_changed",
                        ledger_id=inspection.ledger_id,
                    )
                published, published_bytes = _read_private_json(
                    store,
                    ACTIVE_NAME,
                )
                if (
                    published != next_active
                    or published_bytes
                    != canonical_json(next_active) + b"\n"
                ):
                    return HumanAdmissionResult(
                        "recovery_operation_admission_reconciliation_required",
                        "policy_ledger.head_publication_unverified",
                        ledger_id=inspection.ledger_id,
                    )
            finally:
                if staging is not None:
                    os.close(staging)
                    staging = None
        finally:
            if objects is not None:
                os.close(objects)
            if store is not None:
                os.close(store)
        return HumanAdmissionResult(
            "recovery_operation_admission_committed",
            "policy_ledger.recovery_operation_admitted",
            decision="admitted",
            ledger_id=inspection.ledger_id,
            sequence=sequence,
            previous_record_digest=previous_digest,
            record_digest=record_digest,
            record_bytes=record_bytes,
        )
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.recovery_operation_type_invalid"
        ) from error
    except OSError:
        return HumanAdmissionResult(
            "recovery_operation_admission_reconciliation_required",
            "policy_ledger.write_or_root_failure",
        )
    finally:
        _borrow_validated_root(lease, binding)


def _access_admission_proof(
    inspection: AuthorityStoreInspection,
    record: dict,
) -> _EvidenceContentAccessAdmissionProof:
    access = record["content_access"]
    source = record["source"]
    return _EvidenceContentAccessAdmissionProof(
        project_authority_id=access["project_authority_id"],
        policy_profile_id=inspection.profile_id,
        ledger_id=record["ledger_id"],
        sequence=record["sequence"],
        access_id=access["access_id"],
        evidence_id=access["evidence_id"],
        expected_content_digest=access["expected_content_digest"],
        relationship_operation_id=access["relationship_operation_id"],
        permitted_selection=parse_json_object(
            canonical_json(access["permitted_selection"])
        ),
        source_relationship_digest=source["source_relationship_digest"],
        evidence_registry_record_digest=source[
            "evidence_registry_record_digest"
        ],
        policy_record_digest=record["record_digest"],
    )


def _access_settlement_proof(
    inspection: AuthorityStoreInspection,
    record: dict,
) -> _EvidenceContentAccessSettlementProof:
    settlement = record["settlement"]
    return _EvidenceContentAccessSettlementProof(
        project_authority_id=record["content_access"][
            "project_authority_id"
        ],
        policy_profile_id=inspection.profile_id,
        ledger_id=record["ledger_id"],
        sequence=record["sequence"],
        access_id=settlement["access_id"],
        content_read_operation_id=settlement[
            "content_read_operation_id"
        ],
        canonical_request_digest=settlement["canonical_request_digest"],
        evidence_id=settlement["evidence_id"],
        content_digest=settlement["content_digest"],
        selection=parse_json_object(canonical_json(settlement["selection"])),
        access_admission_record_digest=record[
            "access_admission_record_digest"
        ],
        policy_record_digest=record["record_digest"],
    )


def _publish_policy_append_under_lease(
    lease: Any,
    binding: Any,
    inspection: AuthorityStoreInspection,
    record: dict,
    *,
    failpoint: Any,
    after_object_fullsync_point: str,
    after_head_destination_fullsync_point: str,
    before_publication_point: str,
) -> None:
    """Publish one already validated Policy append through retained handles."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    root = _borrow_validated_root(lease, binding)
    record_bytes = canonical_json(record) + b"\n"
    store: Optional[int] = None
    objects: Optional[int] = None
    staging: Optional[int] = None
    operation_error: Optional[BaseException] = None
    try:
        store = _open_private_directory(root, STORE_NAME)
        objects = _open_private_directory(store, OBJECTS_NAME)
        staging = _open_private_directory(store, STAGING_NAME)
        if not _store_matches_inspection(
            inspection,
            store,
            objects,
            staging,
        ):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        active, active_bytes = _read_private_json(store, ACTIVE_NAME)
        if active.get("ledger_head_digest") != record[
            "previous_record_digest"
        ]:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        object_name = _ledger_object_name(
            record["ledger_id"],
            record["sequence"],
            record["record_digest"],
        )
        _write_new_file(objects, object_name, record_bytes)
        os.fsync(objects)
        _trip(failpoint, after_object_fullsync_point)
        next_active = dict(active)
        next_active["ledger_head_digest"] = record["record_digest"]
        stage_name = _pending_head_name(
            _record_owner_operation_id(record),
            record["record_digest"],
        )
        _write_new_file(
            staging,
            stage_name,
            canonical_json(next_active) + b"\n",
        )
        os.fsync(staging)
        _trip(failpoint, before_publication_point)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        current, current_bytes = _read_private_json(store, ACTIVE_NAME)
        if current != active or current_bytes != active_bytes:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        os.rename(
            stage_name,
            ACTIVE_NAME,
            src_dir_fd=staging,
            dst_dir_fd=store,
        )
        os.fsync(store)
        _trip(failpoint, after_head_destination_fullsync_point)
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        published, published_bytes = _read_private_json(store, ACTIVE_NAME)
        if (
            published != next_active
            or published_bytes != canonical_json(next_active) + b"\n"
        ):
            raise ProjectMutationLeaseError(
                "policy_ledger.head_publication_unverified",
                state_status="reconciliation_required",
            )
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: Optional[OSError] = None
        for descriptor in (staging, objects, store):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and operation_error is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.cleanup_unverified",
                state_status="reconciliation_required",
            ) from cleanup_error
    _borrow_validated_root(lease, binding)


def _fullsync_exact_policy_file(
    parent: int,
    name: str,
    expected_bytes: bytes,
    *,
    expected_identity: Any = None,
) -> None:
    """Restore durability for one exact already-authenticated Policy file."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
    )

    _parsed, actual_bytes, identity = _read_private_json_with_identity(
        parent,
        name,
    )
    if actual_bytes != expected_bytes or (
        expected_identity is not None and identity != expected_identity
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.pending_head_changed",
            state_status="quarantined",
        )
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    operation_error: Optional[BaseException] = None
    try:
        if _private_file_identity(os.fstat(descriptor)) != identity:
            raise ProjectMutationLeaseError(
                "policy_ledger.pending_head_changed",
                state_status="quarantined",
            )
        os.fsync(descriptor)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            if operation_error is None:
                raise ProjectMutationLeaseError(
                    "policy_ledger.cleanup_unverified",
                    state_status="reconciliation_required",
                ) from error
    _parsed, final_bytes, final_identity = _read_private_json_with_identity(
        parent,
        name,
    )
    if final_bytes != expected_bytes or final_identity != identity:
        raise ProjectMutationLeaseError(
            "policy_ledger.pending_head_changed",
            state_status="quarantined",
        )


def _recover_pending_policy_append_under_lease(
    lease: Any,
    binding: Any,
    inspection: AuthorityStoreInspection,
    record: dict,
) -> AuthorityStoreInspection:
    """Promote one exact staged Policy head after restoring its barriers."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    if (
        inspection.status != "reconciliation_required"
        or inspection.detail_code
        != "policy_ledger.pending_head_publication"
        or not inspection.ledger_record_bytes
        or record.get("record_digest") is None
        or record.get("previous_record_digest") != inspection.head_digest
        or record.get("sequence") != (inspection.head_sequence or 0) + 1
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.pending_head_conflict",
            state_status="quarantined",
        )
    expected_record_bytes = canonical_json(record) + b"\n"
    if inspection.ledger_record_bytes[-1] != expected_record_bytes:
        raise ProjectMutationLeaseError(
            "policy_ledger.pending_head_conflict",
            state_status="quarantined",
        )

    root = _borrow_validated_root(lease, binding)
    store: Optional[int] = None
    objects: Optional[int] = None
    staging: Optional[int] = None
    operation_error: Optional[BaseException] = None
    try:
        store = _open_private_directory(root, STORE_NAME)
        objects = _open_private_directory(store, OBJECTS_NAME)
        staging = _open_private_directory(store, STAGING_NAME)
        if not _store_matches_inspection(
            inspection,
            store,
            objects,
            staging,
        ) or not _head_sources_still_bound(store, objects, inspection):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )

        object_name = _ledger_object_name(
            record["ledger_id"],
            record["sequence"],
            record["record_digest"],
        )
        object_identities = dict(inspection.object_identities)
        if object_name not in object_identities:
            raise ProjectMutationLeaseError(
                "policy_ledger.pending_head_conflict",
                state_status="quarantined",
            )
        operation_id = _record_owner_operation_id(record)
        if operation_id is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.pending_head_conflict",
                state_status="quarantined",
            )
        stage_name = _pending_head_name(
            operation_id,
            record["record_digest"],
        )
        active, active_bytes = _read_private_json(store, ACTIVE_NAME)
        if active.get("ledger_head_digest") != inspection.head_digest:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        next_active = dict(active)
        next_active["ledger_head_digest"] = record["record_digest"]
        staged_bytes = canonical_json(next_active) + b"\n"
        _fullsync_exact_policy_file(
            objects,
            object_name,
            expected_record_bytes,
            expected_identity=object_identities[object_name],
        )
        os.fsync(objects)
        _fullsync_exact_policy_file(
            staging,
            stage_name,
            staged_bytes,
        )
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        current, current_bytes = _read_private_json(store, ACTIVE_NAME)
        if current != active or current_bytes != active_bytes:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        os.rename(
            stage_name,
            ACTIVE_NAME,
            src_dir_fd=staging,
            dst_dir_fd=store,
        )
        os.fsync(store)
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: Optional[OSError] = None
        for descriptor in (staging, objects, store):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and operation_error is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.cleanup_unverified",
                state_status="reconciliation_required",
            ) from cleanup_error

    verified = _inspect_locked(root, binding.canonical_root)
    if (
        verified.status != "active"
        or verified.head_digest != record["record_digest"]
        or verified.ledger_record_bytes[-1] != expected_record_bytes
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.head_publication_unverified",
            state_status="reconciliation_required",
        )
    _borrow_validated_root(lease, binding)
    return verified


def _recover_orphaned_policy_append_under_lease(
    lease: Any,
    binding: Any,
    inspection: AuthorityStoreInspection,
    record: dict,
) -> AuthorityStoreInspection:
    """Stage and promote one exact durable object lacking its head candidate."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    expected_record_bytes = canonical_json(record) + b"\n"
    if (
        inspection.status != "reconciliation_required"
        or inspection.detail_code != "policy_ledger.orphaned_record"
        or not inspection.ledger_record_bytes
        or inspection.ledger_record_bytes[-1] != expected_record_bytes
        or record.get("previous_record_digest") != inspection.head_digest
        or record.get("sequence") != (inspection.head_sequence or 0) + 1
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.orphaned_record_conflict",
            state_status="quarantined",
        )

    root = _borrow_validated_root(lease, binding)
    store: Optional[int] = None
    objects: Optional[int] = None
    staging: Optional[int] = None
    operation_error: Optional[BaseException] = None
    try:
        store = _open_private_directory(root, STORE_NAME)
        objects = _open_private_directory(store, OBJECTS_NAME)
        staging = _open_private_directory(store, STAGING_NAME)
        if (
            not _store_matches_inspection(
                inspection,
                store,
                objects,
                staging,
            )
            or not _head_sources_still_bound(store, objects, inspection)
            or os.listdir(staging)
        ):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )

        object_name = _ledger_object_name(
            record["ledger_id"],
            record["sequence"],
            record["record_digest"],
        )
        object_identities = dict(inspection.object_identities)
        if object_name not in object_identities:
            raise ProjectMutationLeaseError(
                "policy_ledger.orphaned_record_conflict",
                state_status="quarantined",
            )
        operation_id = _record_owner_operation_id(record)
        if operation_id is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.orphaned_record_conflict",
                state_status="quarantined",
            )
        active, active_bytes = _read_private_json(store, ACTIVE_NAME)
        if active.get("ledger_head_digest") != inspection.head_digest:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        next_active = dict(active)
        next_active["ledger_head_digest"] = record["record_digest"]
        stage_name = _pending_head_name(
            operation_id,
            record["record_digest"],
        )
        staged_bytes = canonical_json(next_active) + b"\n"
        _fullsync_exact_policy_file(
            objects,
            object_name,
            expected_record_bytes,
            expected_identity=object_identities[object_name],
        )
        os.fsync(objects)
        _write_new_file(staging, stage_name, staged_bytes)
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        current, current_bytes = _read_private_json(store, ACTIVE_NAME)
        if current != active or current_bytes != active_bytes:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: Optional[OSError] = None
        for descriptor in (staging, objects, store):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and operation_error is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.cleanup_unverified",
                state_status="reconciliation_required",
            ) from cleanup_error

    pending = _inspect_locked(root, binding.canonical_root)
    if (
        pending.status != "reconciliation_required"
        or pending.detail_code != "policy_ledger.pending_head_publication"
        or pending.ledger_record_bytes[-1] != expected_record_bytes
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.orphan_recovery_unverified",
            state_status="reconciliation_required",
        )
    return _recover_pending_policy_append_under_lease(
        lease,
        binding,
        pending,
        record,
    )


def _recover_stale_policy_stage_under_lease(
    lease: Any,
    binding: Any,
    inspection: AuthorityStoreInspection,
    record: dict,
) -> AuthorityStoreInspection:
    """Remove one exact source-side rename residue after head publication."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    expected_record_bytes = canonical_json(record) + b"\n"
    if (
        inspection.status != "reconciliation_required"
        or inspection.detail_code
        != "policy_ledger.stale_head_publication"
        or inspection.head_digest != record.get("record_digest")
        or not inspection.ledger_record_bytes
        or inspection.ledger_record_bytes[-1] != expected_record_bytes
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.stale_head_conflict",
            state_status="quarantined",
        )

    root = _borrow_validated_root(lease, binding)
    store: Optional[int] = None
    objects: Optional[int] = None
    staging: Optional[int] = None
    operation_error: Optional[BaseException] = None
    try:
        store = _open_private_directory(root, STORE_NAME)
        objects = _open_private_directory(store, OBJECTS_NAME)
        staging = _open_private_directory(store, STAGING_NAME)
        if (
            not _store_matches_inspection(
                inspection,
                store,
                objects,
                staging,
            )
            or not _head_sources_still_bound(store, objects, inspection)
        ):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )

        object_name = _ledger_object_name(
            record["ledger_id"],
            record["sequence"],
            record["record_digest"],
        )
        object_identities = dict(inspection.object_identities)
        operation_id = _record_owner_operation_id(record)
        if object_name not in object_identities or operation_id is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.stale_head_conflict",
                state_status="quarantined",
            )
        stage_name = _pending_head_name(operation_id, record["record_digest"])
        active, active_bytes = _read_private_json(store, ACTIVE_NAME)
        if active.get("ledger_head_digest") != record["record_digest"]:
            raise ProjectMutationLeaseError(
                "policy_ledger.head_changed",
                state_status="reconciliation_required",
            )
        _fullsync_exact_policy_file(
            objects,
            object_name,
            expected_record_bytes,
            expected_identity=object_identities[object_name],
        )
        _fullsync_exact_policy_file(store, ACTIVE_NAME, active_bytes)
        _fullsync_exact_policy_file(staging, stage_name, active_bytes)
        os.fsync(objects)
        os.fsync(store)
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
        current, current_bytes = _read_private_json(store, ACTIVE_NAME)
        staged, staged_bytes = _read_private_json(staging, stage_name)
        if (
            current != active
            or current_bytes != active_bytes
            or staged != active
            or staged_bytes != active_bytes
        ):
            raise ProjectMutationLeaseError(
                "policy_ledger.stale_head_conflict",
                state_status="quarantined",
            )
        os.unlink(stage_name, dir_fd=staging)
        os.fsync(staging)
        if not _store_bindings_match(root, store, objects, staging):
            raise ProjectMutationLeaseError(
                "authority_store.store_changed",
                state_status="reconciliation_required",
            )
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: Optional[OSError] = None
        for descriptor in (staging, objects, store):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and operation_error is None:
            raise ProjectMutationLeaseError(
                "policy_ledger.cleanup_unverified",
                state_status="reconciliation_required",
            ) from cleanup_error

    verified = _inspect_locked(root, binding.canonical_root)
    if (
        verified.status != "active"
        or verified.head_digest != record["record_digest"]
        or verified.ledger_record_bytes[-1] != expected_record_bytes
    ):
        raise ProjectMutationLeaseError(
            "policy_ledger.stale_head_recovery_unverified",
            state_status="reconciliation_required",
        )
    _borrow_validated_root(lease, binding)
    return verified


def _record_or_replay_evidence_content_access_admission_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    content_access: dict,
    source: dict,
    clock: Callable[[], datetime],
    failpoint: Any = None,
) -> _EvidenceContentAccessAdmissionProof:
    """Record or replay one Human-Entry access authority in Policy."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    try:
        access = parse_json_object(canonical_json(content_access))
        source_value = parse_json_object(canonical_json(source))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.authority_invalid"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if (
            inspection.status == "reconciliation_required"
            and inspection.detail_code
            in {
                "policy_ledger.pending_head_publication",
                "policy_ledger.orphaned_record",
                "policy_ledger.stale_head_publication",
            }
            and inspection.ledger_record_bytes
        ):
            pending = parse_json_object(
                inspection.ledger_record_bytes[-1][:-1]
                if inspection.ledger_record_bytes[-1].endswith(b"\n")
                else inspection.ledger_record_bytes[-1]
            )
            if _record_owner_operation_id(pending) == access.get(
                "access_id"
            ):
                if (
                    pending.get("record_kind")
                    == "evidence_content_access_admission"
                    and pending.get("content_access") == access
                    and pending.get("source") == source_value
                ):
                    recover = {
                        "policy_ledger.orphaned_record": (
                            _recover_orphaned_policy_append_under_lease
                        ),
                        "policy_ledger.stale_head_publication": (
                            _recover_stale_policy_stage_under_lease
                        ),
                    }.get(
                        inspection.detail_code,
                        _recover_pending_policy_append_under_lease,
                    )
                    verified = recover(lease, binding, inspection, pending)
                    return _access_admission_proof(verified, pending)
                raise ProjectMutationLeaseError(
                    "evidence_content_access.access_identity_conflict"
                )
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status="reconciliation_required",
            )
        if inspection.status != "active":
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        if inspection.authority_id != project_authority_id:
            raise ProjectMutationLeaseError(
                "policy_ledger.authority_binding_mismatch"
            )
        access_id = access.get("access_id")
        expected_source = source_value
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if _record_owner_operation_id(record) == access_id:
                if (
                    record.get("record_kind")
                    == "evidence_content_access_admission"
                    and record.get("content_access") == access
                    and record.get("source") == expected_source
                ):
                    return _access_admission_proof(inspection, record)
                raise ProjectMutationLeaseError(
                    "evidence_content_access.access_identity_conflict"
                )
            if _record_consumed_receipt_id(record) == access_id:
                raise ProjectMutationLeaseError(
                    "evidence_content_access.already_consumed"
                )
        recorded_at = _canonical_timestamp(clock())
        sequence = (inspection.head_sequence or 0) + 1
        previous_digest = inspection.head_digest
        if previous_digest is None or inspection.profile_digest is None:
            raise ProjectMutationLeaseError(inspection.detail_code)
        record = {
            "schema": "ask_herdr.policy_ledger_record.v1",
            "ledger_id": inspection.ledger_id,
            "sequence": sequence,
            "previous_record_digest": previous_digest,
            "record_kind": "evidence_content_access_admission",
            "recorded_at": recorded_at,
            "active_policy": {
                "profile_id": inspection.profile_id,
                "profile_digest": inspection.profile_digest,
            },
            "content_access": access,
            "source": source_value,
        }
        record["record_digest"] = _digest(record)
        active = {
            "authority_id": inspection.authority_id,
            "profile_id": inspection.profile_id,
            "profile_digest": inspection.profile_digest,
            "ledger_id": inspection.ledger_id,
        }
        if not _validate_evidence_content_access_admission_record(
            record,
            active=active,
            sequence=sequence,
            previous_record_digest=previous_digest,
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.authority_invalid"
            )
        _publish_policy_append_under_lease(
            lease,
            binding,
            inspection,
            record,
            failpoint=failpoint,
            after_object_fullsync_point=(
                "after_content_access_admission_object_fullsync"
            ),
            after_head_destination_fullsync_point=(
                "after_content_access_admission_head_destination_fullsync"
            ),
            before_publication_point=(
                "before_content_access_admission_publication"
            ),
        )
        verified = _inspect_locked(root, binding.canonical_root)
        if (
            verified.status != "active"
            or verified.head_digest != record["record_digest"]
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.admission_unverified",
                state_status="reconciliation_required",
            )
        return _access_admission_proof(verified, record)
    except ProjectMutationLeaseError:
        raise
    except (OSError, StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.storage_failure",
            state_status="reconciliation_required",
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _derive_evidence_content_access_admission_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    access_id: str,
) -> _EvidenceContentAccessAdmissionProof:
    """Resolve one access selector solely from the authenticated Ledger."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    if not _matches(UUID4_PATTERN, access_id):
        raise ProjectMutationLeaseError(
            "evidence_content_access.authority_ref_invalid"
        )
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        pending_for_access = False
        if (
            inspection.status == "reconciliation_required"
            and inspection.detail_code
            in {
                "policy_ledger.pending_head_publication",
                "policy_ledger.orphaned_record",
                "policy_ledger.stale_head_publication",
            }
            and inspection.ledger_record_bytes
        ):
            pending = parse_json_object(
                inspection.ledger_record_bytes[-1][:-1]
                if inspection.ledger_record_bytes[-1].endswith(b"\n")
                else inspection.ledger_record_bytes[-1]
            )
            pending_for_access = (
                pending.get("record_kind")
                == "evidence_content_access_settlement"
                and pending.get("content_access", {}).get("access_id")
                == access_id
            )
        if inspection.status != "active" and not pending_for_access:
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        matches = []
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if (
                record.get("record_kind")
                == "evidence_content_access_admission"
                and record.get("content_access", {}).get("access_id")
                == access_id
            ):
                matches.append(record)
        if len(matches) != 1:
            raise ProjectMutationLeaseError(
                (
                    "evidence_content_access.admission_absent"
                    if not matches
                    else "evidence_content_access.access_identity_conflict"
                )
            )
        proof = _access_admission_proof(inspection, matches[0])
        _borrow_validated_root(lease, binding)
        return proof
    except ProjectMutationLeaseError:
        raise
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.storage_failure",
            state_status="reconciliation_required",
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _recover_pending_evidence_content_access_settlement_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    access_id: str,
    canonical_request_projection: dict,
    settlement: dict,
) -> Optional[_EvidenceContentAccessSettlementProof]:
    """Recover only an exact pending settlement; never create a new one."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    try:
        projection = parse_json_object(
            canonical_json(canonical_request_projection)
        )
        expected_settlement = parse_json_object(canonical_json(settlement))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.settlement_invalid"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if inspection.status == "active":
            return None
        if (
            inspection.status != "reconciliation_required"
            or inspection.detail_code
            not in {
                "policy_ledger.pending_head_publication",
                "policy_ledger.orphaned_record",
                "policy_ledger.stale_head_publication",
            }
        ):
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        records = [
            parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            for payload in inspection.ledger_record_bytes[1:]
        ]
        pending = records[-1]
        admission = next(
            (
                record
                for record in records[:-1]
                if record.get("record_kind")
                == "evidence_content_access_admission"
                and record.get("content_access", {}).get("access_id")
                == access_id
            ),
            None,
        )
        operation_id = expected_settlement.get(
            "content_read_operation_id"
        )
        if (
            admission is not None
            and pending.get("record_kind")
            == "evidence_content_access_settlement"
            and _record_owner_operation_id(pending) == operation_id
            and pending.get("content_access")
            == admission.get("content_access")
            and pending.get("canonical_request_projection") == projection
            and pending.get("settlement") == expected_settlement
            and pending.get("access_admission_record_digest")
            == admission.get("record_digest")
        ):
            recover = {
                "policy_ledger.orphaned_record": (
                    _recover_orphaned_policy_append_under_lease
                ),
                "policy_ledger.stale_head_publication": (
                    _recover_stale_policy_stage_under_lease
                ),
            }.get(
                inspection.detail_code,
                _recover_pending_policy_append_under_lease,
            )
            verified = recover(lease, binding, inspection, pending)
            return _access_settlement_proof(verified, pending)
        if (
            _record_owner_operation_id(pending) == operation_id
            or _record_consumed_receipt_id(pending) == access_id
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.operation_identity_conflict"
            )
        raise ProjectMutationLeaseError(
            inspection.detail_code,
            state_status="reconciliation_required",
        )
    except ProjectMutationLeaseError:
        raise
    except (OSError, StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.storage_failure",
            state_status="reconciliation_required",
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _authenticate_evidence_content_access_settlement_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    access_id: str,
    canonical_request_projection: dict,
    settlement: dict,
) -> _EvidenceContentAccessSettlementProof:
    """Authenticate one exact committed settlement without mutation."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    try:
        projection = parse_json_object(
            canonical_json(canonical_request_projection)
        )
        expected_settlement = parse_json_object(canonical_json(settlement))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.settlement_invalid"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        if inspection.status != "active":
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        admission_record: Optional[dict] = None
        match: Optional[dict] = None
        operation_id = expected_settlement.get(
            "content_read_operation_id"
        )
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if (
                record.get("record_kind")
                == "evidence_content_access_admission"
                and record.get("content_access", {}).get("access_id")
                == access_id
            ):
                if admission_record is not None:
                    raise ProjectMutationLeaseError(
                        "evidence_content_access.access_identity_conflict"
                    )
                admission_record = record
            if _record_owner_operation_id(record) == operation_id:
                if match is not None:
                    raise ProjectMutationLeaseError(
                        "evidence_content_access.operation_identity_conflict"
                    )
                match = record
            if (
                _record_consumed_receipt_id(record) == access_id
                and _record_owner_operation_id(record) != operation_id
            ):
                raise ProjectMutationLeaseError(
                    "evidence_content_access.already_consumed"
                )
        if admission_record is None:
            raise ProjectMutationLeaseError(
                "evidence_content_access.admission_absent"
            )
        if match is None:
            raise ProjectMutationLeaseError(
                "evidence_content_access.settlement_absent"
            )
        if (
            match.get("record_kind")
            != "evidence_content_access_settlement"
            or match.get("content_access")
            != admission_record.get("content_access")
            or match.get("canonical_request_projection") != projection
            or match.get("settlement") != expected_settlement
            or match.get("access_admission_record_digest")
            != admission_record.get("record_digest")
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.operation_identity_conflict"
            )
        proof = _access_settlement_proof(inspection, match)
        _borrow_validated_root(lease, binding)
        return proof
    except ProjectMutationLeaseError:
        raise
    except (OSError, StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.storage_failure",
            state_status="reconciliation_required",
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _record_or_replay_evidence_content_access_settlement_under_lease(
    lease: Any,
    *,
    project_authority_id: str,
    access_id: str,
    canonical_request_projection: dict,
    settlement: dict,
    clock: Callable[[], datetime],
    failpoint: Any = None,
) -> tuple[_EvidenceContentAccessSettlementProof, bool]:
    """Consume one admitted access and return proof plus replay disposition."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    try:
        projection = parse_json_object(
            canonical_json(canonical_request_projection)
        )
        expected_settlement = parse_json_object(canonical_json(settlement))
    except (StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.settlement_invalid"
        ) from error
    binding = _validated_binding_for_authority(
        lease,
        project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        inspection = _inspect_locked(root, binding.canonical_root)
        pending_publication = (
            inspection.status == "reconciliation_required"
            and inspection.detail_code
            in {
                "policy_ledger.pending_head_publication",
                "policy_ledger.orphaned_record",
                "policy_ledger.stale_head_publication",
            }
        )
        if inspection.status != "active" and not pending_publication:
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status=(
                    "quarantined"
                    if inspection.status == "quarantined"
                    else "reconciliation_required"
                ),
            )
        if inspection.authority_id != project_authority_id:
            raise ProjectMutationLeaseError(
                "policy_ledger.authority_binding_mismatch"
            )
        admission_record: Optional[dict] = None
        content_read_operation_id = expected_settlement.get(
            "content_read_operation_id"
        )
        for payload in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                payload[:-1] if payload.endswith(b"\n") else payload
            )
            if (
                record.get("record_kind")
                == "evidence_content_access_admission"
                and record.get("content_access", {}).get("access_id")
                == access_id
            ):
                if admission_record is not None:
                    raise ProjectMutationLeaseError(
                        "evidence_content_access.access_identity_conflict"
                    )
                admission_record = record
            if _record_owner_operation_id(record) == content_read_operation_id:
                if (
                    record.get("record_kind")
                    == "evidence_content_access_settlement"
                    and record.get("content_access")
                    == (
                        admission_record.get("content_access")
                        if admission_record is not None
                        else None
                    )
                    and record.get("canonical_request_projection")
                    == projection
                    and record.get("settlement") == expected_settlement
                    and record.get("access_admission_record_digest")
                    == (
                        admission_record.get("record_digest")
                        if admission_record is not None
                        else None
                    )
                ):
                    if pending_publication:
                        recover = {
                            "policy_ledger.orphaned_record": (
                                _recover_orphaned_policy_append_under_lease
                            ),
                            "policy_ledger.stale_head_publication": (
                                _recover_stale_policy_stage_under_lease
                            ),
                        }.get(
                            inspection.detail_code,
                            _recover_pending_policy_append_under_lease,
                        )
                        verified = recover(lease, binding, inspection, record)
                        return _access_settlement_proof(
                            verified,
                            record,
                        ), True
                    return _access_settlement_proof(inspection, record), True
                raise ProjectMutationLeaseError(
                    "evidence_content_access.operation_identity_conflict"
                )
            if (
                _record_consumed_receipt_id(record) == access_id
                and _record_owner_operation_id(record)
                != content_read_operation_id
            ):
                raise ProjectMutationLeaseError(
                    "evidence_content_access.already_consumed"
                )
        if admission_record is None:
            raise ProjectMutationLeaseError(
                "evidence_content_access.admission_absent"
            )
        if pending_publication:
            raise ProjectMutationLeaseError(
                inspection.detail_code,
                state_status="reconciliation_required",
            )
        access = admission_record["content_access"]
        recorded_at = _canonical_timestamp(clock())
        sequence = (inspection.head_sequence or 0) + 1
        previous_digest = inspection.head_digest
        if previous_digest is None or inspection.profile_digest is None:
            raise ProjectMutationLeaseError(inspection.detail_code)
        record = {
            "schema": "ask_herdr.policy_ledger_record.v1",
            "ledger_id": inspection.ledger_id,
            "sequence": sequence,
            "previous_record_digest": previous_digest,
            "record_kind": "evidence_content_access_settlement",
            "recorded_at": recorded_at,
            "active_policy": {
                "profile_id": inspection.profile_id,
                "profile_digest": inspection.profile_digest,
            },
            "access_admission_record_digest": admission_record[
                "record_digest"
            ],
            "content_access": access,
            "canonical_request_projection": projection,
            "settlement": expected_settlement,
        }
        record["record_digest"] = _digest(record)
        root_metadata = os.fstat(root)
        active = {
            "authority_id": inspection.authority_id,
            "profile_id": inspection.profile_id,
            "profile_digest": inspection.profile_digest,
            "ledger_id": inspection.ledger_id,
        }
        if not _validate_evidence_content_access_settlement_record(
            record,
            active=active,
            sequence=sequence,
            previous_record_digest=previous_digest,
            canonical_root=binding.canonical_root,
            filesystem_identity={
                "device": root_metadata.st_dev,
                "inode": root_metadata.st_ino,
                "owner_uid": root_metadata.st_uid,
            },
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.settlement_invalid"
            )
        _publish_policy_append_under_lease(
            lease,
            binding,
            inspection,
            record,
            failpoint=failpoint,
            after_object_fullsync_point=(
                "after_content_access_settlement_object_fullsync"
            ),
            after_head_destination_fullsync_point=(
                "after_content_access_settlement_head_destination_fullsync"
            ),
            before_publication_point=(
                "before_content_access_settlement_publication"
            ),
        )
        verified = _inspect_locked(root, binding.canonical_root)
        if (
            verified.status != "active"
            or verified.head_digest != record["record_digest"]
        ):
            raise ProjectMutationLeaseError(
                "evidence_content_access.settlement_unverified",
                state_status="reconciliation_required",
            )
        return _access_settlement_proof(verified, record), False
    except ProjectMutationLeaseError:
        raise
    except (OSError, StrictJsonError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "evidence_content_access.storage_failure",
            state_status="reconciliation_required",
        ) from error
    finally:
        _borrow_validated_root(lease, binding)


def _commit_human_admission_locked(
    root: int,
    canonical_root: str,
    admission: ConfirmedHumanAdmission,
    *,
    clock: Callable[[], datetime],
    uuid_factory: Callable[[], Any],
    failpoint: Any = None,
) -> HumanAdmissionResult:
    """Apply the established Policy mutation to one already-locked root."""

    inspection = _inspect_locked(root, canonical_root)
    if inspection.status != "active":
        return _inactive_result(inspection)
    receipt = admission.approval_receipt
    if (
        inspection.authority_id != admission.project_authority_id
        or inspection.profile_id != admission.policy_profile_id
        or inspection.authority_id != receipt.project_authority_id
        or inspection.profile_id != receipt.policy_profile_id
    ):
        return HumanAdmissionResult(
            "human_admission_conflict",
            "policy_ledger.authority_binding_mismatch",
            ledger_id=inspection.ledger_id,
        )
    if inspection.operation_id == admission.operation_id:
        return HumanAdmissionResult(
            "human_admission_conflict",
            "policy_ledger.operation_identity_conflict",
            ledger_id=inspection.ledger_id,
        )
    existing = _classify_existing(inspection, admission)
    if existing is not None:
        return existing
    if not _receipt_correlates(admission):
        return HumanAdmissionResult(
            "human_admission_conflict",
            "policy_ledger.receipt_correlation_mismatch",
            ledger_id=inspection.ledger_id,
        )

    profile_payload = inspection.profile_record_bytes
    if profile_payload is None:
        return _inactive_result(inspection)
    profile = parse_json_object(
        profile_payload[:-1]
        if profile_payload.endswith(b"\n")
        else profile_payload
    )
    known_reasons = profile["automatic_enablement"]["operation_reasons"]
    known_providers = profile["automatic_enablement"]["providers"]
    if (
        admission.action_reason not in known_reasons.get(admission.operation, {})
        or admission.provider not in known_providers
    ):
        return HumanAdmissionResult(
            "human_admission_denied",
            "policy_ledger.operation_not_supported",
            decision="denied",
            ledger_id=inspection.ledger_id,
        )

    recorded_at_value = clock()
    recorded_at = _canonical_timestamp(recorded_at_value)
    now = _parse_canonical_timestamp(recorded_at)
    confirmed_at = _parse_canonical_timestamp(
        admission.approval_receipt.confirmed_at
    )
    expires_at = _parse_canonical_timestamp(admission.approval_receipt.expires_at)
    if now >= expires_at:
        return HumanAdmissionResult(
            "human_admission_denied",
            "policy_ledger.human_approval_receipt_expired",
            decision="denied",
            ledger_id=inspection.ledger_id,
        )
    if now < confirmed_at:
        return HumanAdmissionResult(
            "human_admission_denied",
            "policy_ledger.human_approval_receipt_not_yet_valid",
            decision="denied",
            ledger_id=inspection.ledger_id,
        )

    decision_id = _new_uuid(uuid_factory)
    sequence = (inspection.head_sequence or 0) + 1
    previous_digest = inspection.head_digest
    if previous_digest is None or inspection.profile_digest is None:
        return _inactive_result(inspection)
    record = {
        "schema": "ask_herdr.policy_ledger_record.v1",
        "ledger_id": inspection.ledger_id,
        "sequence": sequence,
        "previous_record_digest": previous_digest,
        "record_kind": "human_admission",
        "recorded_at": recorded_at,
        "active_policy": {
            "profile_id": inspection.profile_id,
            "profile_digest": inspection.profile_digest,
        },
        "operation": _operation_payload(admission),
        "policy_decision": {
            "decision_id": decision_id,
            "decision": "admitted",
            "automatic_budget_effects": [
                {
                    "scope": "provider",
                    "provider": admission.provider,
                    "budget_effect": "not_counted",
                },
                {"scope": "project", "budget_effect": "not_counted"},
            ],
        },
        "human_approval_receipt": _receipt_payload(
            admission.approval_receipt
        ),
    }
    record_digest = _digest(record)
    record["record_digest"] = record_digest
    record_bytes = canonical_json(record) + b"\n"

    store = _open_private_directory(root, STORE_NAME)
    try:
        objects = _open_private_directory(store, OBJECTS_NAME)
        staging = _open_private_directory(store, STAGING_NAME)
        try:
            if not _store_matches_inspection(
                inspection,
                store,
                objects,
                staging,
            ):
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "authority_store.store_changed",
                    ledger_id=inspection.ledger_id,
                )
            active, active_bytes = _read_private_json(store, ACTIVE_NAME)
            if active["ledger_head_digest"] != previous_digest:
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "policy_ledger.head_changed",
                    ledger_id=inspection.ledger_id,
                )
            object_name = _ledger_object_name(
                inspection.ledger_id,
                sequence,
                record_digest,
            )
            _write_new_file(objects, object_name, record_bytes)
            os.fsync(objects)
            next_active = dict(active)
            next_active["ledger_head_digest"] = record_digest
            stage_name = _pending_head_name(admission.operation_id, record_digest)
            _write_new_file(
                staging,
                stage_name,
                canonical_json(next_active) + b"\n",
            )
            os.fsync(staging)
            _trip(failpoint, "before_head_publication")
            if not _store_bindings_match(root, store, objects, staging):
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "authority_store.store_changed",
                    ledger_id=inspection.ledger_id,
                )
            current, current_bytes = _read_private_json(store, ACTIVE_NAME)
            if current != active or current_bytes != active_bytes:
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "policy_ledger.head_changed",
                    ledger_id=inspection.ledger_id,
                )
            os.rename(
                stage_name,
                ACTIVE_NAME,
                src_dir_fd=staging,
                dst_dir_fd=store,
            )
            os.fsync(store)
            os.fsync(staging)
            if not _store_bindings_match(root, store, objects, staging):
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "authority_store.store_changed",
                    ledger_id=inspection.ledger_id,
                )
            published, published_bytes = _read_private_json(
                store,
                ACTIVE_NAME,
            )
            if (
                published != next_active
                or published_bytes != canonical_json(next_active) + b"\n"
            ):
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "policy_ledger.head_publication_unverified",
                    ledger_id=inspection.ledger_id,
                )
        finally:
            os.close(staging)
            os.close(objects)
    finally:
        os.close(store)
    return HumanAdmissionResult(
        "human_admission_committed",
        "policy_ledger.human_admitted",
        decision="admitted",
        ledger_id=inspection.ledger_id,
        sequence=sequence,
        previous_record_digest=previous_digest,
        record_digest=record_digest,
        record_bytes=record_bytes,
    )


def _snapshot_human_admission_under_lease(
    admission: ConfirmedHumanAdmission,
) -> ConfirmedHumanAdmission:
    """Freeze exact base transport values before borrowing durable authority."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
    )

    if type(admission) is not ConfirmedHumanAdmission:
        raise ProjectMutationLeaseError("policy_ledger.admission_type_invalid")
    try:
        receipt = admission.approval_receipt
    except BaseException as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.receipt_type_invalid"
        ) from error
    if type(receipt) is not ValidatedHumanApprovalReceipt:
        raise ProjectMutationLeaseError("policy_ledger.receipt_type_invalid")
    try:
        receipt_snapshot = ValidatedHumanApprovalReceipt(**dict(vars(receipt)))
        admission_values = dict(vars(admission))
        admission_values["approval_receipt"] = receipt_snapshot
        submitted = ConfirmedHumanAdmission(**admission_values)
        _validate_admission(submitted)
    except ValueError as error:
        detail_code = str(error) or "policy_ledger.admission_type_invalid"
        raise ProjectMutationLeaseError(detail_code) from error
    except (AttributeError, TypeError) as error:
        raise ProjectMutationLeaseError(
            "policy_ledger.admission_type_invalid"
        ) from error
    return submitted


def commit_human_admission_under_lease(
    lease: Any,
    admission: ConfirmedHumanAdmission,
    *,
    clock: Callable[[], datetime],
    uuid_factory: Callable[[], Any],
    failpoint: Any = None,
) -> HumanAdmissionResult:
    """Commit one Policy admission through an already-held project lease.

    This port borrows the lease's exact root descriptor. It never reopens,
    relocks, closes, or duplicates that root and revalidates the complete lease
    path after every result or raised failure.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        _borrow_validated_root,
        _validated_binding_for_authority,
    )

    submitted = _snapshot_human_admission_under_lease(admission)
    binding = _validated_binding_for_authority(
        lease,
        submitted.project_authority_id,
    )
    root = _borrow_validated_root(lease, binding)
    try:
        try:
            return _commit_human_admission_locked(
                root,
                binding.canonical_root,
                submitted,
                clock=clock,
                uuid_factory=uuid_factory,
                failpoint=failpoint,
            )
        except OSError:
            return HumanAdmissionResult(
                "human_admission_reconciliation_required",
                "policy_ledger.write_or_root_failure",
            )
    finally:
        _borrow_validated_root(lease, binding)


def commit_human_admission(
    canonical_root: str,
    admission: ConfirmedHumanAdmission,
    *,
    clock: Callable[[], datetime],
    uuid_factory: Callable[[], Any],
    failpoint: Any = None,
) -> HumanAdmissionResult:
    """Append one direct-human admission and atomically publish its new head.

    Injected failpoints intentionally preserve every already-fsynced object and
    staging record so inspection can require reconciliation after interruption.
    """

    _validate_admission(admission)
    try:
        with _open_canonical_root(canonical_root) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return HumanAdmissionResult(
                    "human_admission_reconciliation_required",
                    "authority_store.writer_active",
                )
            return _commit_human_admission_locked(
                root,
                canonical_root,
                admission,
                clock=clock,
                uuid_factory=uuid_factory,
                failpoint=failpoint,
            )
    except OSError:
        return HumanAdmissionResult(
            "human_admission_reconciliation_required",
            "policy_ledger.write_or_root_failure",
        )
