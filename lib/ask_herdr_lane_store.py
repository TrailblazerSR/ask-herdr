"""Private descriptor-safe durable lane journal and response authority.

This module is intentionally disconnected from the public CLI, Herdr, and every
provider adapter.  It persists already validated lane facts and one normalized
final response, then derives Turn Authority from the durable bytes.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
import fcntl
import hashlib
import os
import re
import stat
import sys
import uuid
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ask_herdr_darwin_capsule import (
    CommitDisposition,
    commit_exclusive,
    fullsync_file,
    probe_capability,
)

from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_lane_turn import (
    AttemptPromotion,
    BeginDispatch,
    ClaimTopologyProvisioning,
    DefiniteNonStartProof,
    DispatchIntent,
    FinalTurnAuthority,
    LaneTurnEvent,
    LaneTurnState,
    NativeIdentityMode,
    PrepareAdmittedAttempt,
    RecordAdvisoryWaitTimeout,
    RecordDefiniteNonStart,
    RecordDeliveryUncertain,
    RecordProviderStarted,
    RecordRecoveryResultEvidenceAnchor,
    RecordResponseValidationConflict,
    RecordTopologyProvisioned,
    RecoveryState,
    ReservationState,
    RetryDisposition,
    TurnOutcomeKind,
    TurnPhase,
    TurnTransitionError,
    TopologyCommandEffectStarted,
    TopologyEffectStarted,
    reduce_turn,
)


STORE_NAME = ".ask-herdr-lanes"
LAYOUT_NAME = "layout.json"
BINDING_NAME = "binding.json"
GENERATIONS_NAME = "generations"
TRANSACTIONS_NAME = "transactions"
MAX_RECORD_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = MAX_BODY_BYTES + MAX_HEADER_BYTES + 515

UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TOKEN_PATTERN = re.compile(r"[\x21-\x7e]{1,512}")
EVENT_CAPSULE_PATTERN = re.compile(r"event\.([0-9]{16})\.txn")
RESPONSE_CAPSULE_PATTERN = re.compile(
    r"response\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.txn"
)
CANDIDATE_PATTERN = re.compile(r"candidate\.(event|response)\..+\.[0-9a-f]{32}\.tmp")
EVENT_CANDIDATE_PATTERN = re.compile(
    r"candidate\.event\.([0-9]{16})\.([0-9a-f]{64})\.([0-9a-f]{32})\.tmp"
)
EVIDENCE_ANCHOR_CANDIDATE_PATTERN = re.compile(
    r"candidate\.evidence-anchor\."
    r"(?P<operation_id>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.event\."
    r"(?P<sequence>[0-9]{16})\.(?P<digest>[0-9a-f]{64})\."
    r"(?P<token>[0-9a-f]{32})\.tmp"
)
RESPONSE_CANDIDATE_PATTERN = re.compile(
    r"candidate\.response\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([0-9a-f]{64})\.([0-9a-f]{32})\.tmp"
)
BOOTSTRAP_PATTERN = re.compile(r"ask-herdr-lanes\.bootstrap\.[0-9a-f]{32}\.tmp")
GENERATION_CANDIDATE_PATTERN = re.compile(
    r"generation\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.g[1-9][0-9]*)\.([0-9a-f]{32})\.tmp"
)
GENERATION_NAME_PATTERN = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.g([1-9][0-9]*)"
)


class LaneStoreFailpoint(RuntimeError):
    """Test-only interruption after durable evidence has been written."""


class _IntegrityError(RuntimeError):
    def __init__(self, code: str, *, quarantine: bool = True) -> None:
        self.code = code
        self.quarantine = quarantine
        super().__init__(code)


class _RootChangedError(OSError):
    pass


@dataclass(frozen=True)
class ValidatedLaneGenerationBinding:
    canonical_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int
    project_authority_id: str
    lane_id: str
    lane_generation: int
    lane_binding_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.canonical_root) is not str
            or not self.canonical_root.startswith("/")
            or os.path.normpath(self.canonical_root) != self.canonical_root
            or os.path.realpath(self.canonical_root) != self.canonical_root
        ):
            raise ValueError("lane_store.root_not_canonical")
        if any(
            type(value) is not int or value < 0
            for value in (
                self.filesystem_device,
                self.filesystem_inode,
                self.owner_uid,
            )
        ):
            raise ValueError("lane_store.filesystem_identity_invalid")
        _require_uuid(self.project_authority_id, "lane_store.authority_id_invalid")
        _require_uuid(self.lane_id, "lane_store.lane_id_invalid")
        if type(self.lane_generation) is not int or self.lane_generation < 1:
            raise ValueError("lane_store.lane_generation_invalid")
        _require_digest(
            self.lane_binding_digest,
            "lane_store.lane_binding_digest_invalid",
        )


@dataclass(frozen=True)
class ValidatedFinalResponse:
    operation: str
    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    expected_head_digest: str
    source_native_correlation_digest: Optional[str]
    native_correlation_digest: str
    turn_id: str
    turn_sequence: int
    body: str
    validated_stream_digest: str
    terminal_envelope_receipt_digest: str
    stream_eof_receipt_digest: str
    evidence_ref_id: str

    def __post_init__(self) -> None:
        if self.operation not in {
            "turn.consult",
            "turn.answer",
            "turn.review",
            "turn.safe_retry",
            "turn.recovery_continue",
        }:
            raise ValueError("lane_store.operation_invalid")
        for value, code in (
            (self.operation_id, "lane_store.operation_id_invalid"),
            (self.lane_id, "lane_store.lane_id_invalid"),
            (self.attempt_id, "lane_store.attempt_id_invalid"),
            (self.turn_id, "lane_store.turn_id_invalid"),
            (self.evidence_ref_id, "lane_store.evidence_ref_id_invalid"),
        ):
            _require_uuid(value, code)
        for value, code in (
            (self.canonical_request_digest, "lane_store.request_digest_invalid"),
            (self.expected_head_digest, "lane_store.head_digest_invalid"),
            (self.native_correlation_digest, "lane_store.native_digest_invalid"),
            (self.validated_stream_digest, "lane_store.stream_digest_invalid"),
            (
                self.terminal_envelope_receipt_digest,
                "lane_store.terminal_receipt_digest_invalid",
            ),
            (self.stream_eof_receipt_digest, "lane_store.eof_receipt_digest_invalid"),
        ):
            _require_digest(value, code)
        if self.source_native_correlation_digest is not None:
            _require_digest(
                self.source_native_correlation_digest,
                "lane_store.source_native_digest_invalid",
            )
        if type(self.lane_generation) is not int or self.lane_generation < 1:
            raise ValueError("lane_store.lane_generation_invalid")
        if type(self.turn_sequence) is not int or self.turn_sequence < 1:
            raise ValueError("lane_store.turn_sequence_invalid")
        if type(self.body) is not str:
            raise ValueError("lane_store.response_body_invalid")
        try:
            encoded = self.body.encode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ValueError("lane_store.response_body_invalid") from error
        if len(encoded) > MAX_BODY_BYTES:
            raise ValueError("lane_store.response_body_too_large")


@dataclass(frozen=True)
class LaneStoreInspection:
    status: str
    detail_code: str
    state: Optional[LaneTurnState] = None
    event_count: int = 0
    head_sequence: Optional[int] = None
    head_digest: Optional[str] = None


@dataclass(frozen=True)
class LaneMutationResult:
    outcome_kind: str
    detail_code: str
    state: Optional[LaneTurnState] = None
    event_sequence: Optional[int] = None
    record_digest: Optional[str] = None


@dataclass(frozen=True)
class ClaimedLaneProof:
    """Path-free proof of the exact durable Lane provisioning claim."""

    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_claim_record_digest: str
    lane_state_digest: str
    lane_binding_digest: str
    topology_store_incarnation_digest: Optional[str] = None


@dataclass(frozen=True)
class _ResolvedTopologyRecoveryLane:
    """Record-derived Lane inputs for one exact recovery classification."""

    binding: ValidatedLaneGenerationBinding
    lane_proof: ClaimedLaneProof


@dataclass(frozen=True)
class _LaneIndexGenerationMembershipEntry:
    """One descriptor-authenticated managed Lane Generation identity."""

    lane_id: str
    lane_generation: int
    lane_binding_digest: str


@dataclass(frozen=True)
class _LaneIndexGenerationMembershipInspection:
    """Structural membership cross-check; never an Index authority source."""

    status: str
    detail_code: str
    entries: Tuple[_LaneIndexGenerationMembershipEntry, ...] = ()


@dataclass(frozen=True)
class TopologyEffectStartedLaneProof:
    """Record-derived proof of the durable first-Topology-command marker."""

    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_store_incarnation_digest: str
    topology_claim_record_digest: str
    topology_mutation_record_digest: str
    first_topology_command_record_digest: str
    topology_effect_started_record_digest: str
    lane_state_digest: str
    lane_binding_digest: str


@dataclass(frozen=True)
class TopologyCommandEffectStartedLaneProof:
    """Record-derived proof preceding one later Topology command."""

    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_store_incarnation_digest: str
    topology_claim_record_digest: str
    topology_mutation_record_digest: str
    topology_effect_started_record_digest: str
    command_sequence: int
    topology_command_step_id: str
    topology_command_record_digest: str
    previous_topology_effect_record_digest: str
    topology_command_effect_started_record_digest: str
    lane_state_digest: str
    lane_binding_digest: str


@dataclass(frozen=True)
class ProvisionedLaneProof:
    """Record-derived proof that one claimed Lane has settled topology."""

    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_claim_record_digest: str
    topology_settlement_record_digest: str
    project_topology_digest: str
    topology_provisioned_record_digest: str
    lane_state_digest: str
    lane_binding_digest: str
    topology_effect_started_record_digest: Optional[str] = None
    topology_last_command_effect_started_record_digest: Optional[str] = None
    recovery_state_digest: Optional[str] = None
    recovery_result_store_binding_digest: Optional[str] = None


@dataclass(frozen=True)
class _RecoveryResultEvidenceAnchorLaneProof:
    """Record-derived Lane anchor for one exact Evidence-link digest."""

    project_authority_id: str
    recovery_operation_id: str
    recovery_canonical_request_digest: str
    source_lane_operation_id: str
    source_lane_canonical_request_digest: str
    attempt_id: str
    lane_id: str
    lane_generation: int
    topology_mutation_id: str
    expected_lane_head_record_digest: str
    topology_provisioned_record_digest: str
    source_result_record_digest: str
    recovery_result_store_binding_digest: str
    evidence_registry_binding_digest: str
    source_relationship_digest: str
    evidence_link_record_digest: str
    anchor_event_sequence: int
    lane_anchor_record_digest: str
    lane_state_digest: str
    lane_binding_digest: str


@dataclass(frozen=True)
class _RecoveryResultEvidenceAnchorLaneInspection:
    """Tagged read-only projection of one Lane Evidence anchor."""

    status: str
    detail_code: str
    proof: Optional[_RecoveryResultEvidenceAnchorLaneProof] = None


@dataclass(frozen=True)
class _TopologyRecoveryLaneEvidence:
    """Exact Lane facts for reconciliation, never effect authority."""

    claim: ClaimedLaneProof
    first_effect: Optional[TopologyEffectStartedLaneProof]
    later_effects: Tuple[TopologyCommandEffectStartedLaneProof, ...]
    provisioned: Optional[ProvisionedLaneProof]
    lane_record_digests: Tuple[str, ...]
    head_record_digest: str
    head_state_digest: str
    lane_binding_digest: str


@dataclass(frozen=True)
class _TopologyRecoveryLaneInspection:
    """Tagged, non-authorizing result of one retained-lease Lane replay."""

    status: str
    detail_code: str
    evidence: Optional[_TopologyRecoveryLaneEvidence]
    residue_state_digest: Optional[str] = None


@dataclass(frozen=True)
class ResponsePublishResult:
    outcome_kind: str
    detail_code: str
    response_digest: Optional[str] = None
    frame_digest: Optional[str] = None


@dataclass(frozen=True)
class _Scan:
    status: str
    detail_code: str
    state: Optional[LaneTurnState]
    active_records: Tuple[Dict[str, Any], ...]
    pending_record: Optional[Dict[str, Any]]
    head: Optional[Dict[str, Any]]
    event_candidates: Tuple[str, ...] = ()
    response_candidates: Tuple[str, ...] = ()
    response_attempts: Tuple[str, ...] = ()


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _require_uuid(value: Any, code: str) -> None:
    if not _matches(UUID4_PATTERN, value):
        raise ValueError(code)


def _require_digest(value: Any, code: str) -> None:
    if not _matches(DIGEST_PATTERN, value):
        raise ValueError(code)


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest_json(value: Dict[str, Any]) -> str:
    return _digest_bytes(canonical_json(value))


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _state_digest(state: LaneTurnState) -> str:
    state_value = _json_value(state)
    if state.topology_effect_started is None:
        state_value.pop("topology_effect_started", None)
    if not state.topology_command_effects_started:
        state_value.pop("topology_command_effects_started", None)
    if not state.recovery_result_evidence_anchors:
        state_value.pop("recovery_result_evidence_anchors", None)
    if (
        state.direct_human_policy_record_digest is None
        and state.topology_provisioning_claim is None
        and state.topology_provisioned is None
    ):
        state_value.pop("direct_human_policy_record_digest", None)
        state_value.pop("topology_provisioning_claim", None)
        state_value.pop("topology_provisioned", None)
        dispatch = state_value.get("dispatch_intent")
        if isinstance(dispatch, dict):
            dispatch.pop("project_topology_digest", None)
    claim = state_value.get("topology_provisioning_claim")
    if (
        isinstance(claim, dict)
        and claim.get("topology_store_incarnation_digest") is None
    ):
        claim.pop("topology_store_incarnation_digest", None)
    provisioned = state_value.get("topology_provisioned")
    if (
        isinstance(provisioned, dict)
        and provisioned.get("topology_effect_started_record_digest") is None
    ):
        provisioned.pop("topology_effect_started_record_digest", None)
    if (
        isinstance(provisioned, dict)
        and provisioned.get(
            "topology_last_command_effect_started_record_digest"
        )
        is None
    ):
        provisioned.pop(
            "topology_last_command_effect_started_record_digest",
            None,
        )
    if (
        isinstance(provisioned, dict)
        and provisioned.get("recovery_state_digest") is None
    ):
        provisioned.pop("recovery_state_digest", None)
    if (
        isinstance(provisioned, dict)
        and provisioned.get("recovery_result_store_binding_digest") is None
    ):
        provisioned.pop("recovery_result_store_binding_digest", None)
    return _digest_json(
        {
            "schema": "ask_herdr.lane_turn_state.internal.v1",
            "state": state_value,
        }
    )


def _event_payload(event: LaneTurnEvent) -> Dict[str, Any]:
    event_fields = _json_value(event)
    if (
        isinstance(event, PrepareAdmittedAttempt)
        and event.direct_human_policy_record_digest is None
    ):
        event_fields.pop("direct_human_policy_record_digest", None)
    if (
        isinstance(event, BeginDispatch)
        and event.project_topology_digest is None
    ):
        event_fields.pop("project_topology_digest", None)
    if (
        isinstance(event, ClaimTopologyProvisioning)
        and event.topology_store_incarnation_digest is None
    ):
        event_fields.pop("topology_store_incarnation_digest", None)
    if (
        isinstance(event, RecordTopologyProvisioned)
        and event.topology_effect_started_record_digest is None
    ):
        event_fields.pop("topology_effect_started_record_digest", None)
    if (
        isinstance(event, RecordTopologyProvisioned)
        and event.topology_last_command_effect_started_record_digest is None
    ):
        event_fields.pop(
            "topology_last_command_effect_started_record_digest",
            None,
        )
    if (
        isinstance(event, RecordTopologyProvisioned)
        and event.recovery_state_digest is None
    ):
        event_fields.pop("recovery_state_digest", None)
    if (
        isinstance(event, RecordTopologyProvisioned)
        and event.recovery_result_store_binding_digest is None
    ):
        event_fields.pop("recovery_result_store_binding_digest", None)
    return {
        "schema": "ask_herdr.lane_turn_event.internal.v1",
        "event_type": type(event).__name__,
        "fields": event_fields,
    }


def _event_from_payload(payload: Dict[str, Any]) -> LaneTurnEvent:
    if set(payload) != {"schema", "event_type", "fields"} or payload.get(
        "schema"
    ) != "ask_herdr.lane_turn_event.internal.v1":
        raise _IntegrityError("lane_store.event_payload_invalid")
    name = payload.get("event_type")
    values = payload.get("fields")
    if type(values) is not dict:
        raise _IntegrityError("lane_store.event_payload_invalid")
    constructors = {
        "PrepareAdmittedAttempt": PrepareAdmittedAttempt,
        "ClaimTopologyProvisioning": ClaimTopologyProvisioning,
        "TopologyEffectStarted": TopologyEffectStarted,
        "TopologyCommandEffectStarted": TopologyCommandEffectStarted,
        "RecordTopologyProvisioned": RecordTopologyProvisioned,
        "RecordRecoveryResultEvidenceAnchor": (
            RecordRecoveryResultEvidenceAnchor
        ),
        "BeginDispatch": BeginDispatch,
        "RecordDeliveryUncertain": RecordDeliveryUncertain,
        "RecordDefiniteNonStart": RecordDefiniteNonStart,
        "RecordProviderStarted": RecordProviderStarted,
        "RecordResponseValidationConflict": RecordResponseValidationConflict,
        "RecordAdvisoryWaitTimeout": RecordAdvisoryWaitTimeout,
        "FinalTurnAuthority": FinalTurnAuthority,
    }
    constructor = constructors.get(name)
    if constructor is None:
        raise _IntegrityError("lane_store.event_type_invalid")
    values = dict(values)
    if name == "PrepareAdmittedAttempt":
        values["native_identity_mode"] = NativeIdentityMode(
            values["native_identity_mode"]
        )
    elif name == "RecordDefiniteNonStart":
        values["proof"] = DefiniteNonStartProof(values["proof"])
    try:
        return constructor(**values)
    except (KeyError, TypeError, ValueError) as error:
        raise _IntegrityError("lane_store.event_payload_invalid") from error


def _event_fingerprint(event: LaneTurnEvent) -> str:
    return _digest_json(_event_payload(event))


def _topology_record_linkage_error(
    event: LaneTurnEvent,
    previous_digest: Optional[str],
    previous_event: Optional[LaneTurnEvent],
) -> Optional[str]:
    """Bind topology facts to the exact preceding Lane journal record."""

    if isinstance(event, ClaimTopologyProvisioning):
        if (
            not isinstance(previous_event, PrepareAdmittedAttempt)
            or event.prepared_lane_record_digest != previous_digest
        ):
            return "lane_store.topology_claim_prepared_record_conflict"
    elif isinstance(event, TopologyEffectStarted):
        if (
            not isinstance(previous_event, ClaimTopologyProvisioning)
            or event.topology_claim_record_digest != previous_digest
        ):
            return "lane_store.topology_effect_claim_record_conflict"
    elif isinstance(event, TopologyCommandEffectStarted):
        if event.command_sequence == 2:
            if (
                not isinstance(previous_event, TopologyEffectStarted)
                or event.topology_effect_started_record_digest
                != previous_digest
                or event.previous_topology_effect_record_digest
                != previous_digest
            ):
                return "lane_store.topology_command_effect_record_conflict"
        elif (
            not isinstance(previous_event, TopologyCommandEffectStarted)
            or event.command_sequence != previous_event.command_sequence + 1
            or event.topology_effect_started_record_digest
            != previous_event.topology_effect_started_record_digest
            or event.previous_topology_effect_record_digest
            != previous_digest
        ):
            return "lane_store.topology_command_effect_record_conflict"
    elif isinstance(event, RecordTopologyProvisioned):
        if (
            event.topology_last_command_effect_started_record_digest
            is not None
        ):
            if (
                not isinstance(
                    previous_event,
                    TopologyCommandEffectStarted,
                )
                or event.topology_last_command_effect_started_record_digest
                != previous_digest
                or event.topology_effect_started_record_digest
                != previous_event.topology_effect_started_record_digest
            ):
                return "lane_store.topology_command_effect_started_record_conflict"
        elif event.topology_effect_started_record_digest is None:
            if (
                not isinstance(previous_event, ClaimTopologyProvisioning)
                or event.topology_claim_record_digest != previous_digest
            ):
                return "lane_store.topology_claim_record_conflict"
        elif (
            not isinstance(previous_event, TopologyEffectStarted)
            or event.topology_effect_started_record_digest != previous_digest
        ):
            return "lane_store.topology_effect_started_record_conflict"
    return None


def _topology_record_linkage_is_authoritative_next(
    event: LaneTurnEvent,
    previous_state: Optional[LaneTurnState],
) -> bool:
    if previous_state is None:
        return isinstance(
            event,
            (
                ClaimTopologyProvisioning,
                TopologyEffectStarted,
                TopologyCommandEffectStarted,
                RecordTopologyProvisioned,
            ),
        )
    if isinstance(event, ClaimTopologyProvisioning):
        return (
            previous_state.topology_provisioning_claim is None
            and previous_state.topology_provisioned is None
        )
    if isinstance(event, TopologyEffectStarted):
        return (
            previous_state.topology_effect_started is None
            and previous_state.topology_provisioned is None
        )
    if isinstance(event, TopologyCommandEffectStarted):
        return previous_state.topology_provisioned is None
    if isinstance(event, RecordTopologyProvisioned):
        return previous_state.topology_provisioned is None
    return False


def _recovery_result_evidence_linkage_error(
    event: LaneTurnEvent,
    prior_records: Tuple[Dict[str, Any], ...],
    binding: ValidatedLaneGenerationBinding,
) -> Optional[str]:
    """Bind an Evidence-link anchor to its historical Lane finalization."""

    if type(event) is not RecordRecoveryResultEvidenceAnchor:
        return None
    provisioned_records = tuple(
        record
        for record in prior_records
        if record.get("event", {}).get("event_type")
        == "RecordTopologyProvisioned"
    )
    if (
        event.project_authority_id != binding.project_authority_id
        or not prior_records
        or prior_records[-1].get("record_digest")
        != event.expected_lane_head_record_digest
        or len(provisioned_records) != 1
        or provisioned_records[0].get("record_digest")
        != event.topology_provisioned_record_digest
    ):
        return "lane_store.recovery_result_evidence_link_source_conflict"
    provisioned = _event_from_payload(provisioned_records[0]["event"])
    if (
        type(provisioned) is not RecordTopologyProvisioned
        or provisioned.operation_id != event.source_lane_operation_id
        or provisioned.canonical_request_digest
        != event.source_lane_canonical_request_digest
        or provisioned.attempt_id != event.attempt_id
        or provisioned.lane_id != event.lane_id
        or provisioned.lane_generation != event.lane_generation
        or provisioned.topology_mutation_id != event.topology_mutation_id
        or provisioned.recovery_result_store_binding_digest
        != event.recovery_result_store_binding_digest
    ):
        return "lane_store.recovery_result_evidence_link_source_conflict"
    return None


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _file_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    return _identity(metadata) + (
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


@contextmanager
def _open_root(binding: ValidatedLaneGenerationBinding) -> Iterator[int]:
    if not isinstance(binding, ValidatedLaneGenerationBinding):
        raise ValueError("lane_store.binding_type_invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: List[int] = []
    snapshots: List[os.stat_result] = []
    links: List[Tuple[int, str, int]] = []
    try:
        current = os.open(os.path.sep, flags)
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        for component in filter(None, binding.canonical_root.split(os.path.sep)[1:]):
            parent = current
            current = os.open(component, flags, dir_fd=parent)
            descriptors.append(current)
            snapshots.append(os.fstat(current))
            links.append((parent, component, current))
        root_metadata = os.fstat(current)
        if (
            root_metadata.st_dev != binding.filesystem_device
            or root_metadata.st_ino != binding.filesystem_inode
            or root_metadata.st_uid != binding.owner_uid
            or binding.owner_uid != os.getuid()
        ):
            raise _RootChangedError("lane_store.root_binding_conflict")
        yield current
        for descriptor, snapshot in zip(descriptors, snapshots):
            if _identity(os.fstat(descriptor)) != _identity(snapshot):
                raise _RootChangedError("lane_store.root_changed")
        for parent, component, child in links:
            bound = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _identity(bound) != _identity(os.fstat(child)):
                raise _RootChangedError("lane_store.root_changed")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_directory(parent: int, name: str) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if _identity(bound) != _identity(opened) or not _private_directory(opened):
            raise _IntegrityError("lane_store.directory_integrity")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _mkdir_open(parent: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    descriptor = _open_directory(parent, name)
    os.fchmod(descriptor, 0o700)
    return descriptor


def _write_new(parent: int, name: str, payload: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("lane_store.write_failed")
            view = view[written:]
        fullsync_file(descriptor)
    finally:
        os.close(descriptor)


def _read_file(parent: int, name: str, maximum: int) -> bytes:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise _IntegrityError("lane_store.file_integrity")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise _IntegrityError("lane_store.file_binding_changed")
        remaining = before.st_size
        chunks: List[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise _IntegrityError("lane_store.file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _IntegrityError("lane_store.file_grew")
        after_fd = os.fstat(descriptor)
        after_entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(after_fd) != _file_identity(opened)
            or _file_identity(after_entry) != _file_identity(opened)
        ):
            raise _IntegrityError("lane_store.file_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_json(parent: int, name: str) -> Tuple[Dict[str, Any], bytes]:
    payload = _read_file(parent, name, MAX_RECORD_BYTES)
    try:
        parsed = parse_json_object(payload[:-1] if payload.endswith(b"\n") else payload)
    except StrictJsonError as error:
        raise _IntegrityError("lane_store.json_invalid") from error
    if payload != canonical_json(parsed) + b"\n":
        raise _IntegrityError("lane_store.json_not_canonical")
    return parsed, payload


def _directory_binding(parent: int, name: str, child: int) -> bool:
    try:
        return _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _identity(
            os.fstat(child)
        )
    except OSError:
        return False


def _trip(failpoint: Any, point: str) -> None:
    if failpoint == point:
        raise LaneStoreFailpoint(point)
    if callable(failpoint):
        failpoint(point)


def _binding_payload(binding: ValidatedLaneGenerationBinding) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_store_binding.internal.v1",
        "project_authority_id": binding.project_authority_id,
        "filesystem_device": binding.filesystem_device,
        "filesystem_inode": binding.filesystem_inode,
        "owner_uid": binding.owner_uid,
    }


def _layout_payload() -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_store_layout.internal.v2",
        "storage_protocol": "exclusive_capsule_journal",
    }


def _generation_binding_payload(
    binding: ValidatedLaneGenerationBinding,
) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_generation_binding.internal.v2",
        "project_authority_id": binding.project_authority_id,
        "lane_id": binding.lane_id,
        "lane_generation": binding.lane_generation,
        "lane_binding_digest": binding.lane_binding_digest,
    }


def _generation_name(binding: ValidatedLaneGenerationBinding) -> str:
    return "{}.g{}".format(binding.lane_id, binding.lane_generation)


def _response_name(attempt_id: str) -> str:
    return "response.{}.txn".format(attempt_id)


def _candidate_token(factory: Any = None) -> str:
    value = factory() if callable(factory) else uuid.uuid4()
    token = str(value).replace("-", "")
    if re.fullmatch(r"[0-9a-f]{32}", token) is None:
        raise ValueError("lane_store.candidate_id_invalid")
    return token


def _event_candidate_name(
    sequence: int,
    record_digest: str,
    factory: Any = None,
    *,
    evidence_anchor: bool = False,
    recovery_operation_id: Optional[str] = None,
) -> str:
    if evidence_anchor:
        _require_uuid(
            recovery_operation_id,
            "lane_store.recovery_operation_id_invalid",
        )
        prefix = "candidate.evidence-anchor.{}.event".format(
            recovery_operation_id
        )
    else:
        prefix = "candidate.event"
    return "{}.{:016d}.{}.{}.tmp".format(
        prefix,
        sequence,
        record_digest.removeprefix("sha256:"),
        _candidate_token(factory),
    )


def _response_candidate_name(
    attempt_id: str,
    frame_digest: str,
    factory: Any = None,
) -> str:
    return "candidate.response.{}.{}.{}.tmp".format(
        attempt_id,
        frame_digest.removeprefix("sha256:"),
        _candidate_token(factory),
    )


def _response_candidate_attempt(name: str) -> Optional[str]:
    prefix = "candidate.response."
    if not name.startswith(prefix) or not name.endswith(".tmp"):
        return None
    rest = name[len(prefix) :]
    attempt_id = rest[:36]
    if not _matches(UUID4_PATTERN, attempt_id):
        return None
    suffix = rest[36:]
    if re.fullmatch(r"\.[0-9a-f]{64}\.[0-9a-f]{32}\.tmp", suffix) is None:
        return None
    return attempt_id


def _attempt_artifacts(
    handles: "_Handles",
    attempt_id: str,
) -> Tuple[bool, bool, Tuple[str, ...]]:
    entries = set(os.listdir(handles.transactions))
    authoritative = _response_name(attempt_id) in entries
    stages = tuple(sorted(
        name for name in entries
        if _response_candidate_attempt(name) == attempt_id
    ))
    return (
        authoritative,
        False,
        stages,
    )


def _has_attempt_artifact(artifacts: Tuple[bool, bool, Tuple[str, ...]]) -> bool:
    return artifacts[0] or artifacts[1] or bool(artifacts[2])


@dataclass
class _Handles:
    root: int
    store: int
    generations: int
    generation: int
    transactions: int


def _close_handles(handles: _Handles) -> None:
    # ``sys.exc_info`` alone also exposes an unrelated exception handled by a
    # caller further up the stack.  Suppress cleanup failure only while the
    # function that owns these handles is itself unwinding that exception.
    caller_frame = sys._getframe(1)
    active_traceback = sys.exc_info()[2]
    primary_error_active = False
    while active_traceback is not None:
        if active_traceback.tb_frame is caller_frame:
            primary_error_active = True
            break
        active_traceback = active_traceback.tb_next
    first_close_error: Optional[OSError] = None
    for descriptor in (
        handles.transactions,
        handles.generation,
        handles.generations,
        handles.store,
    ):
        try:
            os.close(descriptor)
        except OSError as error:
            if first_close_error is None:
                first_close_error = error
    if first_close_error is not None and not primary_error_active:
        raise first_close_error


def _validate_store_binding(
    store: int,
    binding: ValidatedLaneGenerationBinding,
) -> None:
    entries = set(os.listdir(store))
    if entries != {LAYOUT_NAME, BINDING_NAME, GENERATIONS_NAME}:
        raise _IntegrityError("lane_store.unknown_layout")
    layout, _ = _read_json(store, LAYOUT_NAME)
    if layout != _layout_payload():
        raise _IntegrityError("lane_store.layout_invalid")
    payload, _ = _read_json(store, BINDING_NAME)
    if payload != _binding_payload(binding):
        raise _IntegrityError("lane_store.binding_conflict")


def _detect_legacy_v1(root: int) -> bool:
    try:
        metadata = os.stat(STORE_NAME, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    descriptor = os.open(
        STORE_NAME,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=root,
    )
    try:
        entries = set(os.listdir(descriptor))
        return (
            LAYOUT_NAME not in entries
            and BINDING_NAME in entries
            and GENERATIONS_NAME in entries
        )
    finally:
        os.close(descriptor)


def _open_existing_handles(
    root: int,
    binding: ValidatedLaneGenerationBinding,
) -> Optional[_Handles]:
    if _detect_legacy_v1(root):
        raise _IntegrityError("layout_v1_migration_required", quarantine=False)
    opened: List[int] = []
    try:
        store = _open_directory(root, STORE_NAME)
    except FileNotFoundError:
        return None
    opened.append(store)
    try:
        _validate_store_binding(store, binding)
        generations = _open_directory(store, GENERATIONS_NAME)
        opened.append(generations)
        try:
            generation = _open_directory(generations, _generation_name(binding))
        except FileNotFoundError:
            for descriptor in reversed(opened):
                os.close(descriptor)
            return None
        opened.append(generation)
        if set(os.listdir(generation)) != {BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError("lane_store.generation_layout_invalid")
        generation_binding, _ = _read_json(generation, BINDING_NAME)
        if generation_binding != _generation_binding_payload(binding):
            raise _IntegrityError("lane_store.generation_binding_conflict")
        transactions = _open_directory(generation, TRANSACTIONS_NAME)
        opened.append(transactions)
        handles = _Handles(
            root,
            store,
            generations,
            generation,
            transactions,
        )
        opened.clear()
        return handles
    except Exception:
        for descriptor in reversed(opened):
            os.close(descriptor)
        raise


def _sync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _probe_v2_durability_capability(anchor: int) -> bool:
    """Prove all v2 primitives with one exact disposable local capsule."""

    if probe_capability(anchor) is not True:
        return False
    probe_name = ".ask-herdr-durability-probe.{}.tmp".format(
        _candidate_token()
    )
    probe = file_descriptor = -1
    operation_error: Optional[BaseException] = None
    cleanup_error: Optional[BaseException] = None
    created = False
    try:
        os.mkdir(probe_name, 0o700, dir_fd=anchor)
        created = True
        probe = _open_directory(anchor, probe_name)
        file_descriptor = os.open(
            "regular",
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=probe,
        )
        os.fchmod(file_descriptor, 0o600)
        payload = b"ask-herdr durability probe\n"
        if os.write(file_descriptor, payload) != len(payload):
            raise OSError("lane_store.probe_write_failed")
        fullsync_file(file_descriptor)
        _sync_directory(probe)
        _sync_directory(anchor)
    except (OSError, ValueError) as error:
        operation_error = error
    finally:
        try:
            if file_descriptor >= 0:
                opened = os.fstat(file_descriptor)
                bound = os.stat(
                    "regular",
                    dir_fd=probe,
                    follow_symlinks=False,
                )
                if (
                    opened.st_dev != bound.st_dev
                    or opened.st_ino != bound.st_ino
                    or not stat.S_ISREG(bound.st_mode)
                    or bound.st_uid != os.getuid()
                    or stat.S_IMODE(bound.st_mode) != 0o600
                    or bound.st_nlink != 1
                ):
                    raise OSError("lane_store.probe_file_changed")
                os.unlink("regular", dir_fd=probe)
                try:
                    _sync_directory(probe)
                except OSError as error:
                    cleanup_error = error
            if probe >= 0:
                if not _directory_binding(anchor, probe_name, probe):
                    raise OSError("lane_store.probe_directory_changed")
                if os.listdir(probe):
                    raise OSError("lane_store.probe_directory_not_empty")
                os.rmdir(probe_name, dir_fd=anchor)
                try:
                    _sync_directory(anchor)
                except OSError as error:
                    cleanup_error = cleanup_error or error
            elif created:
                raise OSError("lane_store.probe_directory_unverified")
        except OSError as error:
            cleanup_error = cleanup_error or error
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            if probe >= 0:
                os.close(probe)
    if operation_error is not None:
        raise operation_error
    if cleanup_error is not None:
        raise cleanup_error
    return True


_v2_durability_capability_probe = _probe_v2_durability_capability


def _fullsync_bound_file(parent: int, name: str) -> None:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
    ):
        raise _IntegrityError("lane_store.file_integrity")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise _IntegrityError("lane_store.file_binding_changed")
        fullsync_file(descriptor)
        after_fd = os.fstat(descriptor)
        after_entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(after_fd) != _file_identity(opened)
            or _file_identity(after_entry) != _file_identity(opened)
        ):
            raise _IntegrityError("lane_store.file_changed")
    finally:
        os.close(descriptor)


def _barrier_promoted_capsule(
    parent: int,
    slot_name: str,
    capsule: int,
    file_names: Tuple[str, ...],
) -> None:
    try:
        if not _directory_binding(parent, slot_name, capsule):
            raise _IntegrityError(
                "lane_store.capsule_binding_changed", quarantine=False
            )
        _sync_directory(capsule)
        _sync_directory(parent)
        for file_name in file_names:
            _fullsync_bound_file(capsule, file_name)
        if not _directory_binding(parent, slot_name, capsule):
            raise _IntegrityError(
                "lane_store.capsule_binding_changed", quarantine=False
            )
    except _IntegrityError:
        raise
    except OSError as error:
        raise _IntegrityError(
            "durability_not_supported", quarantine=False
        ) from error


def _barrier_existing_capsule(
    parent: int,
    slot_name: str,
    expected_entries: Tuple[str, ...],
) -> None:
    capsule = _open_directory(parent, slot_name)
    try:
        if set(os.listdir(capsule)) != set(expected_entries):
            raise _IntegrityError("lane_store.capsule_invalid")
        _barrier_promoted_capsule(
            parent,
            slot_name,
            capsule,
            expected_entries,
        )
    finally:
        os.close(capsule)


def _barrier_store_tree(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
) -> None:
    try:
        if not _handles_still_bound(handles, binding):
            raise _IntegrityError("lane_store.store_changed", quarantine=False)
        for descriptor in (
            handles.transactions,
            handles.generation,
            handles.generations,
            handles.store,
            handles.root,
        ):
            _sync_directory(descriptor)
        _fullsync_bound_file(handles.store, LAYOUT_NAME)
        _fullsync_bound_file(handles.store, BINDING_NAME)
        _fullsync_bound_file(handles.generation, BINDING_NAME)
        if not _handles_still_bound(handles, binding):
            raise _IntegrityError("lane_store.store_changed", quarantine=False)
    except _IntegrityError:
        raise
    except OSError as error:
        raise _IntegrityError(
            "durability_not_supported", quarantine=False
        ) from error


def _mkdir_new_open(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    return _open_directory(parent, name)


def _write_bootstrap_file(
    parent: int,
    name: str,
    payload: Dict[str, Any],
    failpoint: Any,
    point: str,
) -> None:
    _write_new(parent, name, canonical_json(payload) + b"\n")
    _trip(failpoint, point)


def _open_or_create_private_directory(parent: int, name: str) -> int:
    try:
        return _open_directory(parent, name)
    except FileNotFoundError:
        return _mkdir_new_open(parent, name)


def _ensure_bootstrap_file(
    parent: int,
    name: str,
    payload: Dict[str, Any],
    failpoint: Any,
    point: str,
) -> None:
    expected = canonical_json(payload) + b"\n"
    try:
        actual, actual_bytes = _read_json(parent, name)
    except FileNotFoundError:
        _write_new(parent, name, expected)
    else:
        if actual != payload or actual_bytes != expected:
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _fullsync_bound_file(parent, name)
    _trip(failpoint, point)


def _binding_candidate_token(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()[:32]


def _build_store_candidate(
    root: int,
    binding: ValidatedLaneGenerationBinding,
    failpoint: Any,
) -> str:
    candidate = "ask-herdr-lanes.bootstrap.{}.tmp".format(
        _binding_candidate_token(_binding_payload(binding))
    )
    store = _open_or_create_private_directory(root, candidate)
    generations = generation = transactions = -1
    try:
        if set(os.listdir(store)) - {
            LAYOUT_NAME,
            BINDING_NAME,
            GENERATIONS_NAME,
        }:
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _ensure_bootstrap_file(
            store,
            LAYOUT_NAME,
            _layout_payload(),
            failpoint,
            "after_store_layout_fullsync",
        )
        _ensure_bootstrap_file(
            store,
            BINDING_NAME,
            _binding_payload(binding),
            failpoint,
            "after_store_binding_fullsync",
        )
        generations = _open_or_create_private_directory(
            store, GENERATIONS_NAME
        )
        if set(os.listdir(generations)) - {_generation_name(binding)}:
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        generation = _open_or_create_private_directory(
            generations, _generation_name(binding)
        )
        if set(os.listdir(generation)) - {BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _ensure_bootstrap_file(
            generation,
            BINDING_NAME,
            _generation_binding_payload(binding),
            failpoint,
            "after_generation_binding_fullsync",
        )
        transactions = _open_or_create_private_directory(
            generation, TRANSACTIONS_NAME
        )
        if os.listdir(transactions):
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _sync_directory(transactions)
        _sync_directory(generation)
        _sync_directory(generations)
        _sync_directory(store)
        _trip(failpoint, "after_bootstrap_candidate_fullsync")
        return candidate
    finally:
        for descriptor in (transactions, generation, generations, store):
            if descriptor >= 0:
                os.close(descriptor)


def _build_generation_candidate(
    generations: int,
    binding: ValidatedLaneGenerationBinding,
    failpoint: Any,
) -> str:
    candidate = "generation.{}.{}.tmp".format(
        _generation_name(binding),
        _binding_candidate_token(_generation_binding_payload(binding)),
    )
    generation = _open_or_create_private_directory(generations, candidate)
    transactions = -1
    try:
        if set(os.listdir(generation)) - {BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _ensure_bootstrap_file(
            generation,
            BINDING_NAME,
            _generation_binding_payload(binding),
            failpoint,
            "after_generation_binding_fullsync",
        )
        transactions = _open_or_create_private_directory(
            generation, TRANSACTIONS_NAME
        )
        if os.listdir(transactions):
            raise _IntegrityError(
                "lane_store.bootstrap_candidate_conflict",
                quarantine=False,
            )
        _sync_directory(transactions)
        _sync_directory(generation)
        _trip(failpoint, "after_bootstrap_candidate_fullsync")
        return candidate
    finally:
        if transactions >= 0:
            os.close(transactions)
        os.close(generation)


def _ensure_handles(
    root: int,
    binding: ValidatedLaneGenerationBinding,
    *,
    failpoint: Any = None,
) -> _Handles:
    existing = _open_existing_handles(root, binding)
    if existing is not None:
        return existing
    try:
        store = _open_directory(root, STORE_NAME)
    except FileNotFoundError:
        try:
            supported = _v2_durability_capability_probe(root)
        except (OSError, ValueError) as error:
            raise _IntegrityError(
                "durability_not_supported", quarantine=False
            ) from error
        if supported is not True:
            raise _IntegrityError("durability_not_supported", quarantine=False)
        candidate = _build_store_candidate(root, binding, failpoint)
        disposition = commit_exclusive(root, candidate, STORE_NAME)
        if disposition is CommitDisposition.OCCUPIED:
            existing = _open_existing_handles(root, binding)
            if existing is None:
                raise _IntegrityError("lane_store.store_creation_conflict")
            return existing
        _trip(failpoint, "after_store_capsule_promote")
        _sync_directory(root)
        existing = _open_existing_handles(root, binding)
        if existing is None:
            raise _IntegrityError("lane_store.store_creation_unverified")
        return existing
    try:
        _validate_store_binding(store, binding)
        generations = _open_directory(store, GENERATIONS_NAME)
        try:
            candidate = _build_generation_candidate(
                generations, binding, failpoint
            )
            disposition = commit_exclusive(
                generations, candidate, _generation_name(binding)
            )
            if disposition is CommitDisposition.COMMITTED:
                _trip(failpoint, "after_generation_capsule_promote")
                _sync_directory(generations)
        finally:
            os.close(generations)
    finally:
        os.close(store)
    existing = _open_existing_handles(root, binding)
    if existing is None:
        raise _IntegrityError("lane_store.generation_creation_unverified")
    return existing


def _handles_still_bound(handles: _Handles, binding: ValidatedLaneGenerationBinding) -> bool:
    return (
        _directory_binding(handles.root, STORE_NAME, handles.store)
        and _directory_binding(handles.store, GENERATIONS_NAME, handles.generations)
        and _directory_binding(
            handles.generations,
            _generation_name(binding),
            handles.generation,
        )
        and _directory_binding(
            handles.generation,
            TRANSACTIONS_NAME,
            handles.transactions,
        )
    )


def _event_record(
    binding: ValidatedLaneGenerationBinding,
    sequence: int,
    previous_digest: Optional[str],
    event: LaneTurnEvent,
    state: LaneTurnState,
    *,
    response_absent_before_dispatch: Optional[bool] = None,
    response_frame_digest: Optional[str] = None,
    lane_index_transition_intent_digest: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {
        "schema": "ask_herdr.lane_event_record.internal.v1",
        "project_authority_id": binding.project_authority_id,
        "lane_id": binding.lane_id,
        "lane_generation": binding.lane_generation,
        "lane_binding_digest": binding.lane_binding_digest,
        "event_sequence": sequence,
        "previous_event_digest": previous_digest,
        "event_kind": "lane_turn_event",
        "event_fingerprint": _event_fingerprint(event),
        "event": _event_payload(event),
        "state_after_digest": _state_digest(state),
        "response_absent_before_dispatch": response_absent_before_dispatch,
        "response_frame_digest": response_frame_digest,
    }
    if lane_index_transition_intent_digest is not None:
        _require_digest(
            lane_index_transition_intent_digest,
            "lane_store.lane_index_transition_intent_invalid",
        )
        payload["lane_index_transition_intent_digest"] = (
            lane_index_transition_intent_digest
        )
    payload["record_digest"] = _digest_json(payload)
    return payload


def _event_name(record: Dict[str, Any]) -> str:
    return "event.{:016d}.txn".format(record["event_sequence"])


def _discard_recoverable_event_candidate(
    parent: int,
    name: str,
    candidate: int,
    expected_payload: bytes,
) -> bool:
    """Discard only an exact empty or strict-prefix crash candidate."""

    entries = set(os.listdir(candidate))
    remove_event_file = False
    if entries:
        if entries != {"event.json"}:
            return False
        payload = _read_file(candidate, "event.json", MAX_RECORD_BYTES)
        if payload == expected_payload:
            return False
        if len(payload) >= len(expected_payload) or not expected_payload.startswith(
            payload
        ):
            return False
        remove_event_file = True
    if not _directory_binding(parent, name, candidate):
        raise _IntegrityError("lane_store.event_candidate_changed")
    if remove_event_file:
        os.unlink("event.json", dir_fd=candidate)
        _sync_directory(candidate)
        if os.listdir(candidate):
            raise _IntegrityError("lane_store.event_candidate_changed")
    os.rmdir(name, dir_fd=parent)
    _sync_directory(parent)
    return True


def _validate_event_record(
    binding: ValidatedLaneGenerationBinding,
    record: Dict[str, Any],
    filename: str,
    expected_sequence: int,
    previous_digest: Optional[str],
    previous_state: Optional[LaneTurnState],
    previous_event: Optional[LaneTurnEvent],
    prior_records: Tuple[Dict[str, Any], ...],
) -> Tuple[LaneTurnEvent, LaneTurnState]:
    required = {
        "schema",
        "project_authority_id",
        "lane_id",
        "lane_generation",
        "lane_binding_digest",
        "event_sequence",
        "previous_event_digest",
        "event_kind",
        "event_fingerprint",
        "event",
        "state_after_digest",
        "response_absent_before_dispatch",
        "response_frame_digest",
        "record_digest",
    }
    optional = {"lane_index_transition_intent_digest"}
    if (
        not required.issubset(record)
        or set(record) - required != (
            optional if "lane_index_transition_intent_digest" in record else set()
        )
        or record.get("schema") != "ask_herdr.lane_event_record.internal.v1"
        or record.get("project_authority_id") != binding.project_authority_id
        or record.get("lane_id") != binding.lane_id
        or record.get("lane_generation") != binding.lane_generation
        or record.get("lane_binding_digest") != binding.lane_binding_digest
        or record.get("event_sequence") != expected_sequence
        or record.get("previous_event_digest") != previous_digest
        or record.get("event_kind") != "lane_turn_event"
    ):
        raise _IntegrityError("lane_store.event_record_invalid")
    if (
        "lane_index_transition_intent_digest" in record
        and not _matches(
            DIGEST_PATTERN,
            record.get("lane_index_transition_intent_digest"),
        )
    ):
        raise _IntegrityError(
            "lane_store.lane_index_transition_intent_invalid"
        )
    digest = record.get("record_digest")
    unsigned = dict(record)
    unsigned.pop("record_digest", None)
    if not _matches(DIGEST_PATTERN, digest) or _digest_json(unsigned) != digest:
        raise _IntegrityError("lane_store.record_hash_mismatch")
    if filename != _event_name(record):
        raise _IntegrityError("lane_store.record_name_mismatch")
    event = _event_from_payload(record["event"])
    if record.get("event_fingerprint") != _event_fingerprint(event):
        raise _IntegrityError("lane_store.event_fingerprint_mismatch")
    linkage_error = (
        _topology_record_linkage_error(
            event,
            previous_digest,
            previous_event,
        )
        if _topology_record_linkage_is_authoritative_next(
            event,
            previous_state,
        )
        else None
    )
    if linkage_error is not None:
        raise _IntegrityError(linkage_error)
    evidence_linkage_error = _recovery_result_evidence_linkage_error(
        event,
        prior_records,
        binding,
    )
    if evidence_linkage_error is not None:
        raise _IntegrityError(evidence_linkage_error)
    try:
        state = reduce_turn(previous_state, event)
    except (TurnTransitionError, ValueError) as error:
        raise _IntegrityError("lane_store.state_replay_failed") from error
    if record.get("state_after_digest") != _state_digest(state):
        raise _IntegrityError("lane_store.state_replay_mismatch")
    if isinstance(event, BeginDispatch):
        if record.get("response_absent_before_dispatch") is not True:
            raise _IntegrityError("lane_store.response_absence_barrier_invalid")
    elif record.get("response_absent_before_dispatch") is not None:
        raise _IntegrityError("lane_store.event_record_invalid")
    if isinstance(event, FinalTurnAuthority):
        if not _matches(DIGEST_PATTERN, record.get("response_frame_digest")):
            raise _IntegrityError("lane_store.final_frame_digest_invalid")
    elif record.get("response_frame_digest") is not None:
        raise _IntegrityError("lane_store.event_record_invalid")
    return event, state


def _read_event_records(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
) -> Tuple[Tuple[Dict[str, Any], ...], Tuple[LaneTurnState, ...]]:
    filenames = [
        name
        for name in os.listdir(handles.transactions)
        if EVENT_CAPSULE_PATTERN.fullmatch(name) is not None
    ]
    indexed: List[Tuple[int, str]] = []
    for filename in filenames:
        match = EVENT_CAPSULE_PATTERN.fullmatch(filename)
        assert match is not None
        indexed.append((int(match.group(1)), filename))
    indexed.sort()
    records: List[Dict[str, Any]] = []
    states: List[LaneTurnState] = []
    previous_digest: Optional[str] = None
    previous_state: Optional[LaneTurnState] = None
    previous_event: Optional[LaneTurnEvent] = None
    for expected, (sequence, filename) in enumerate(indexed, start=1):
        if sequence != expected:
            raise _IntegrityError("lane_store.sequence_gap")
        capsule = _open_directory(handles.transactions, filename)
        try:
            if set(os.listdir(capsule)) != {"event.json"}:
                raise _IntegrityError("lane_store.event_capsule_invalid")
            record, _ = _read_json(capsule, "event.json")
            if not _directory_binding(
                handles.transactions,
                filename,
                capsule,
            ):
                raise _IntegrityError("lane_store.event_capsule_changed")
        finally:
            os.close(capsule)
        event, state = _validate_event_record(
            binding,
            record,
            filename,
            expected,
            previous_digest,
            previous_state,
            previous_event,
            tuple(records),
        )
        records.append(record)
        states.append(state)
        previous_digest = record["record_digest"]
        previous_state = state
        previous_event = event
    return tuple(records), tuple(states)


def _response_authority_scan_conflict(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
    response_attempts: Tuple[str, ...],
) -> Optional[str]:
    """Validate the complete authoritative response-capsule set."""

    authoritative_attempts = set(response_attempts)
    if len(authoritative_attempts) > 1:
        return "response_authority.multiple_authoritative_capsules"
    if authoritative_attempts and authoritative_attempts != {state.attempt_id}:
        return "response_authority.authoritative_attempt_mismatch"
    if authoritative_attempts:
        try:
            _read_response_capsule(handles, binding, state)
        except _IntegrityError as error:
            return error.code
    return None


def _scan_generation(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    *,
    validate_response_authority: bool = True,
) -> _Scan:
    entries = tuple(os.listdir(handles.transactions))
    event_candidates: List[str] = []
    response_candidates: List[str] = []
    response_attempts: List[str] = []
    for name in entries:
        event_match = EVENT_CAPSULE_PATTERN.fullmatch(name)
        response_match = RESPONSE_CAPSULE_PATTERN.fullmatch(name)
        event_candidate = EVENT_CANDIDATE_PATTERN.fullmatch(name)
        evidence_anchor_candidate = (
            EVIDENCE_ANCHOR_CANDIDATE_PATTERN.fullmatch(name)
        )
        response_candidate = RESPONSE_CANDIDATE_PATTERN.fullmatch(name)
        if event_match is not None:
            continue
        if response_match is not None:
            response_attempts.append(response_match.group(1))
            continue
        if event_candidate is not None or evidence_anchor_candidate is not None:
            candidate = _open_directory(handles.transactions, name)
            os.close(candidate)
            event_candidates.append(name)
            continue
        if response_candidate is not None:
            candidate = _open_directory(handles.transactions, name)
            os.close(candidate)
            response_candidates.append(name)
            continue
        raise _IntegrityError("lane_store.unknown_transaction_entry")
    records, states = _read_event_records(handles, binding)
    if not records:
        detail = (
            "lane_store.event_candidate_residue"
            if event_candidates
            else "lane_store.empty"
        )
        status = "reconciliation_required" if event_candidates else "empty"
        return _Scan(
            status,
            detail,
            None,
            (),
            None,
            None,
            tuple(sorted(event_candidates)),
            tuple(sorted(response_candidates)),
            tuple(sorted(response_attempts)),
        )
    final_record = records[-1]
    head = {
        "event_sequence": final_record["event_sequence"],
        "event_digest": final_record["record_digest"],
        "state_digest": final_record["state_after_digest"],
    }
    state = states[-1]
    response_conflict = (
        _response_authority_scan_conflict(
            handles,
            binding,
            state,
            tuple(sorted(response_attempts)),
        )
        if validate_response_authority
        else None
    )
    if response_conflict is not None:
        return _Scan(
            "quarantined",
            response_conflict,
            _quarantined_state(state),
            records,
            None,
            head,
            tuple(sorted(event_candidates)),
            tuple(sorted(response_candidates)),
            tuple(sorted(response_attempts)),
        )
    has_event_residue = bool(event_candidates)
    return _Scan(
        "reconciliation_required" if has_event_residue else "active",
        (
            "lane_store.event_candidate_residue"
            if has_event_residue
            else "lane_store.active"
        ),
        state,
        records,
        None,
        head,
        tuple(sorted(event_candidates)),
        tuple(sorted(response_candidates)),
        tuple(sorted(response_attempts)),
    )


def _indexed_response_digest(
    records: Tuple[Dict[str, Any], ...],
) -> Optional[str]:
    """Return the latest Lane-authoritative response content digest."""

    for record in reversed(records):
        event = record.get("event", {})
        if event.get("event_type") != "FinalTurnAuthority":
            continue
        fields_value = event.get("fields")
        if not isinstance(fields_value, dict):
            raise _IntegrityError("lane_store.event_payload_invalid")
        digest = fields_value.get("response_digest")
        if not _matches(DIGEST_PATTERN, digest):
            raise _IntegrityError("lane_store.final_response_digest_invalid")
        return digest
    return None


def _lane_index_error_result(
    error: Any,
    *,
    state: Optional[LaneTurnState],
    event_sequence: Optional[int],
    record_digest: Optional[str] = None,
) -> LaneMutationResult:
    quarantined = getattr(error, "state_status", None) == "quarantined"
    visible_state = state
    if visible_state is not None:
        visible_state = (
            _quarantined_state(visible_state)
            if quarantined
            else _reconciliation_state(visible_state)
        )
    return LaneMutationResult(
        (
            "lane_event_quarantined"
            if quarantined
            else "lane_event_reconciliation_required"
        ),
        getattr(error, "detail_code", "lane_index.storage_integrity_failure"),
        state=visible_state,
        event_sequence=event_sequence,
        record_digest=record_digest,
    )


def _finalize_lane_index_for_record(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    record: Dict[str, Any],
    *,
    state: Optional[LaneTurnState],
    failpoint: Any,
    allow_pending_successor: bool = False,
) -> Optional[LaneMutationResult]:
    from ask_herdr_lane_index import (  # noqa: PLC0415
        LaneIndexError,
        _finalize_lane_index_transition_under_root,
    )

    try:
        _finalize_lane_index_transition_under_root(
            handles.root,
            binding,
            record,
            failpoint=failpoint,
            allow_pending_successor=allow_pending_successor,
        )
    except LaneIndexError as error:
        return _lane_index_error_result(
            error,
            state=state,
            event_sequence=record.get("event_sequence"),
            record_digest=record.get("record_digest"),
        )
    return None


def _commit_event_locked(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    scan: _Scan,
    event: LaneTurnEvent,
    *,
    failpoint: Any = None,
    response_frame_digest: Optional[str] = None,
) -> LaneMutationResult:
    if scan.active_records:
        prior_index_failure = _finalize_lane_index_for_record(
            handles,
            binding,
            scan.active_records[-1],
            state=scan.state,
            failpoint=failpoint,
            allow_pending_successor=True,
        )
        if prior_index_failure is not None:
            return prior_index_failure
    artifacts = _attempt_artifacts(handles, event.attempt_id)
    if isinstance(event, BeginDispatch) and _has_attempt_artifact(artifacts):
        response_present, receipt_present, stages = artifacts
        if response_present and scan.state is not None:
            try:
                _read_response_capsule(handles, binding, scan.state)
            except _IntegrityError as error:
                return LaneMutationResult(
                    "lane_event_quarantined",
                    error.code,
                    state=_quarantined_state(scan.state),
                    event_sequence=(scan.head or {}).get("event_sequence"),
                )
        return LaneMutationResult(
            "lane_event_reconciliation_required",
            (
                "response_authority.preexisting_final"
                if response_present
                else (
                    "response_authority.preexisting_receipt"
                    if receipt_present
                    else "response_authority.preexisting_stage"
                )
            ),
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    if isinstance(event, RecordDefiniteNonStart) and _has_attempt_artifact(
        artifacts
    ):
        return LaneMutationResult(
            "lane_event_quarantined",
            "response_authority.contradicts_definite_non_start",
            state=(
                _quarantined_state(scan.state)
                if scan.state is not None
                else None
            ),
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    fingerprint = _event_fingerprint(event)
    for record in scan.active_records:
        if record["event_fingerprint"] == fingerprint:
            if record.get("response_frame_digest") != response_frame_digest:
                return LaneMutationResult(
                    "lane_event_conflict",
                    "response_authority.settled_frame_conflict",
                    state=scan.state,
                    event_sequence=record["event_sequence"],
                    record_digest=record["record_digest"],
                )
            if scan.status != "active":
                return LaneMutationResult(
                    "lane_event_reconciliation_required",
                    scan.detail_code,
                    state=(
                        _reconciliation_state(scan.state)
                        if scan.state is not None
                        else None
                    ),
                    event_sequence=record["event_sequence"],
                    record_digest=record["record_digest"],
                )
            slot_name = _event_name(record)
            _barrier_existing_capsule(
                handles.transactions,
                slot_name,
                ("event.json",),
            )
            verified = _scan_generation(handles, binding)
            if verified.status != "active" or record not in verified.active_records:
                raise _IntegrityError(
                    "lane_store.event_publication_unverified",
                    quarantine=False,
                )
            index_failure = _finalize_lane_index_for_record(
                handles,
                binding,
                record,
                state=verified.state,
                failpoint=failpoint,
            )
            if index_failure is not None:
                return index_failure
            return LaneMutationResult(
                "lane_event_already_committed",
                "lane_store.exact_replay",
                state=verified.state,
                event_sequence=record["event_sequence"],
                record_digest=record["record_digest"],
            )

    if isinstance(event, BeginDispatch) and scan.status != "active":
        return LaneMutationResult(
            "lane_event_reconciliation_required",
            scan.detail_code,
            state=(
                _reconciliation_state(scan.state)
                if scan.state is not None
                else None
            ),
            event_sequence=(scan.head or {}).get("event_sequence"),
        )

    previous_record = (
        scan.active_records[-1] if scan.active_records else None
    )
    previous_event = (
        _event_from_payload(previous_record["event"])
        if previous_record is not None
        else None
    )
    linkage_error = (
        _topology_record_linkage_error(
            event,
            (
                previous_record.get("record_digest")
                if previous_record is not None
                else None
            ),
            previous_event,
        )
        if _topology_record_linkage_is_authoritative_next(
            event,
            scan.state,
        )
        else None
    )
    if linkage_error is not None:
        return LaneMutationResult(
            "lane_event_conflict",
            linkage_error,
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    evidence_linkage_error = _recovery_result_evidence_linkage_error(
        event,
        scan.active_records,
        binding,
    )
    if evidence_linkage_error is not None:
        return LaneMutationResult(
            "lane_event_conflict",
            evidence_linkage_error,
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )

    try:
        next_state = reduce_turn(scan.state, event)
    except TurnTransitionError as error:
        return LaneMutationResult(
            "lane_event_conflict",
            error.detail_code,
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    sequence = len(scan.active_records) + 1
    previous_digest = (
        scan.active_records[-1]["record_digest"]
        if scan.active_records
        else None
    )
    previous_response_digest = _indexed_response_digest(scan.active_records)
    next_response_digest = (
        event.response_digest
        if type(event) is FinalTurnAuthority
        else previous_response_digest
    )
    from ask_herdr_lane_index import (  # noqa: PLC0415
        LaneIndexError,
        _prepare_lane_index_transition_under_root,
    )

    try:
        prepared_index = _prepare_lane_index_transition_under_root(
            handles.root,
            binding,
            previous_event_sequence=(scan.head or {}).get("event_sequence"),
            previous_event_digest=(scan.head or {}).get("event_digest"),
            previous_state_digest=(scan.head or {}).get("state_digest"),
            previous_response_digest=previous_response_digest,
            previous_index_intent_digest=(
                scan.active_records[-1].get(
                    "lane_index_transition_intent_digest"
                )
                if scan.active_records
                else None
            ),
            next_event_sequence=sequence,
            next_state_digest=_state_digest(next_state),
            next_response_digest=next_response_digest,
            failpoint=failpoint,
        )
    except LaneIndexError as error:
        return _lane_index_error_result(
            error,
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    record = _event_record(
        binding,
        sequence,
        previous_digest,
        event,
        next_state,
        response_absent_before_dispatch=(
            True if isinstance(event, BeginDispatch) else None
        ),
        response_frame_digest=response_frame_digest,
        lane_index_transition_intent_digest=(
            prepared_index.intent_digest
        ),
    )
    slot_name = _event_name(record)
    expected_candidate_payload = canonical_json(record) + b"\n"
    candidate_pattern = (
        EVIDENCE_ANCHOR_CANDIDATE_PATTERN
        if type(event) is RecordRecoveryResultEvidenceAnchor
        else EVENT_CANDIDATE_PATTERN
    )
    matching_candidates = tuple(
        name
        for name in scan.event_candidates
        if (
            (match := candidate_pattern.fullmatch(name)) is not None
            and int(
                match.group("sequence")
                if candidate_pattern is EVIDENCE_ANCHOR_CANDIDATE_PATTERN
                else match.group(1)
            )
            == sequence
            and "sha256:"
            + (
                match.group("digest")
                if candidate_pattern is EVIDENCE_ANCHOR_CANDIDATE_PATTERN
                else match.group(2)
            )
            == record["record_digest"]
        )
    )
    if len(matching_candidates) > 1:
        return LaneMutationResult(
            "lane_event_reconciliation_required",
            "lane_store.multiple_exact_event_candidates",
            state=scan.state,
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    if scan.event_candidates and (
        len(scan.event_candidates) != 1 or len(matching_candidates) != 1
    ):
        return LaneMutationResult(
            "lane_event_reconciliation_required",
            "lane_store.event_candidate_residue",
            state=(
                _reconciliation_state(scan.state)
                if scan.state is not None
                else None
            ),
            event_sequence=(scan.head or {}).get("event_sequence"),
        )
    candidate_name = (
        matching_candidates[0]
        if matching_candidates
        else _event_candidate_name(
            sequence,
            record["record_digest"],
            evidence_anchor=(
                type(event) is RecordRecoveryResultEvidenceAnchor
            ),
            recovery_operation_id=(
                event.recovery_operation_id
                if type(event) is RecordRecoveryResultEvidenceAnchor
                else None
            ),
        )
    )
    reusing_candidate = bool(matching_candidates)
    if reusing_candidate:
        candidate = _open_directory(handles.transactions, candidate_name)
        if _discard_recoverable_event_candidate(
            handles.transactions,
            candidate_name,
            candidate,
            expected_candidate_payload,
        ):
            os.close(candidate)
            reusing_candidate = False
            candidate_name = _event_candidate_name(
                sequence,
                record["record_digest"],
                evidence_anchor=(
                    type(event) is RecordRecoveryResultEvidenceAnchor
                ),
                recovery_operation_id=(
                    event.recovery_operation_id
                    if type(event) is RecordRecoveryResultEvidenceAnchor
                    else None
                ),
            )
            candidate = _mkdir_new_open(
                handles.transactions,
                candidate_name,
            )
    else:
        candidate = _mkdir_new_open(handles.transactions, candidate_name)
    try:
        if reusing_candidate:
            if set(os.listdir(candidate)) != {"event.json"}:
                raise _IntegrityError("lane_store.event_candidate_changed")
        else:
            _trip(failpoint, "after_event_candidate_create")
            _write_new(candidate, "event.json", expected_candidate_payload)
            _trip(failpoint, "after_event_capsule_file_fullsync")
        _sync_directory(candidate)
        try:
            reread, reread_bytes = _read_json(candidate, "event.json")
        except _IntegrityError as error:
            if reusing_candidate:
                raise _IntegrityError(
                    "lane_store.event_candidate_changed"
                ) from error
            raise
        if reread != record or reread_bytes != expected_candidate_payload:
            raise _IntegrityError("lane_store.event_candidate_changed")
        if os.fstat(candidate).st_dev != os.fstat(handles.transactions).st_dev:
            raise _IntegrityError(
                "lane_store.store_changed", quarantine=False
            )
        if not _handles_still_bound(handles, binding):
            raise _IntegrityError("lane_store.store_changed", quarantine=False)
        _trip(failpoint, "before_event_capsule_promote")
        disposition = commit_exclusive(
            handles.transactions, candidate_name, slot_name
        )
        if disposition is CommitDisposition.OCCUPIED:
            try:
                winner = _open_directory(handles.transactions, slot_name)
                try:
                    if set(os.listdir(winner)) != {"event.json"}:
                        raise _IntegrityError("lane_store.event_slot_collision")
                    winner_record, winner_bytes = _read_json(
                        winner, "event.json"
                    )
                finally:
                    os.close(winner)
            except (OSError, _IntegrityError):
                return LaneMutationResult(
                    "lane_event_quarantined",
                    "lane_store.event_slot_collision",
                    state=(
                        _quarantined_state(scan.state)
                        if scan.state is not None
                        else None
                    ),
                    event_sequence=sequence,
                )
            if (
                winner_record != record
                or winner_bytes != expected_candidate_payload
            ):
                return LaneMutationResult(
                    "lane_event_quarantined",
                    "lane_store.event_slot_collision",
                    state=(
                        _quarantined_state(scan.state)
                        if scan.state is not None
                        else None
                    ),
                    event_sequence=sequence,
                )
            _barrier_existing_capsule(
                handles.transactions,
                slot_name,
                ("event.json",),
            )
            verified = _scan_generation(handles, binding)
            if verified.status != "active":
                return LaneMutationResult(
                    "lane_event_reconciliation_required",
                    verified.detail_code,
                    state=(
                        _reconciliation_state(verified.state)
                        if verified.state is not None
                        else None
                    ),
                    event_sequence=sequence,
                    record_digest=record["record_digest"],
                )
            index_failure = _finalize_lane_index_for_record(
                handles,
                binding,
                record,
                state=verified.state,
                failpoint=failpoint,
            )
            if index_failure is not None:
                return index_failure
            return LaneMutationResult(
                "lane_event_already_committed",
                "lane_store.exact_replay",
                state=verified.state,
                event_sequence=sequence,
                record_digest=record["record_digest"],
            )
        _trip(failpoint, "after_event_capsule_promote")
        _barrier_promoted_capsule(
            handles.transactions,
            slot_name,
            candidate,
            ("event.json",),
        )
    finally:
        os.close(candidate)
    try:
        committed = _scan_generation(
            handles,
            binding,
            validate_response_authority=False,
        )
    except _IntegrityError as error:
        raise _IntegrityError(
            "lane_store.event_publication_unverified"
        ) from error
    if (
        committed.status != "active"
        or committed.state != next_state
        or not committed.active_records
        or committed.active_records[-1] != record
        or (committed.head or {}).get("event_digest")
        != record["record_digest"]
    ):
        raise _IntegrityError("lane_store.event_publication_unverified")
    index_failure = _finalize_lane_index_for_record(
        handles,
        binding,
        record,
        state=committed.state,
        failpoint=failpoint,
    )
    if index_failure is not None:
        return index_failure
    try:
        verified = _scan_generation(
            handles,
            binding,
            validate_response_authority=False,
        )
    except _IntegrityError as error:
        raise _IntegrityError(
            "lane_store.event_publication_unverified"
        ) from error
    post_artifacts = _attempt_artifacts(handles, event.attempt_id)
    if isinstance(event, BeginDispatch) and _has_attempt_artifact(
        post_artifacts
    ):
        return LaneMutationResult(
            "lane_event_reconciliation_required",
            "response_authority.freshness_race",
            state=_reconciliation_state(next_state),
            event_sequence=sequence,
            record_digest=record["record_digest"],
        )
    if isinstance(event, RecordDefiniteNonStart) and _has_attempt_artifact(
        post_artifacts
    ):
        return LaneMutationResult(
            "lane_event_quarantined",
            "response_authority.contradicts_definite_non_start",
            state=_quarantined_state(next_state),
            event_sequence=sequence,
            record_digest=record["record_digest"],
        )
    if verified.status != "active":
        quarantined = verified.status == "quarantined"
        visible_state = verified.state
        if visible_state is not None and not quarantined:
            visible_state = _reconciliation_state(visible_state)
        return LaneMutationResult(
            (
                "lane_event_quarantined"
                if quarantined
                else "lane_event_reconciliation_required"
            ),
            verified.detail_code,
            state=visible_state,
            event_sequence=sequence,
            record_digest=record["record_digest"],
        )
    if (
        verified.state != next_state
        or not verified.active_records
        or verified.active_records[-1] != record
        or (verified.head or {}).get("event_digest") != record["record_digest"]
    ):
        raise _IntegrityError("lane_store.event_publication_unverified")
    return LaneMutationResult(
        "lane_event_committed",
        "lane_store.event_committed",
        state=next_state,
        event_sequence=sequence,
        record_digest=record["record_digest"],
    )


def _inactive_result(
    status: str,
    detail_code: str,
    state: Optional[LaneTurnState] = None,
) -> LaneMutationResult:
    return LaneMutationResult(
        "lane_event_reconciliation_required"
        if status != "quarantined"
        else "lane_event_quarantined",
        detail_code,
        state=state,
    )


def _read_bootstrap_prefix(
    parent: int,
    name: str,
    expected: bytes,
) -> bool:
    payload = _read_file(parent, name, MAX_RECORD_BYTES)
    if payload == expected:
        return True
    if len(payload) < len(expected) and expected.startswith(payload):
        return False
    raise _IntegrityError("lane_store.bootstrap_candidate_conflict")


def _validate_lane_store_bootstrap_candidate(
    root: int,
    name: str,
    project_binding: Any,
) -> None:
    candidate = _open_directory(root, name)
    opened: List[int] = []
    try:
        entries = set(os.listdir(candidate))
        if entries - {LAYOUT_NAME, BINDING_NAME, GENERATIONS_NAME}:
            raise _IntegrityError("lane_store.bootstrap_candidate_conflict")
        if LAYOUT_NAME in entries:
            complete = _read_bootstrap_prefix(
                candidate,
                LAYOUT_NAME,
                canonical_json(_layout_payload()) + b"\n",
            )
            if not complete and entries != {LAYOUT_NAME}:
                raise _IntegrityError(
                    "lane_store.bootstrap_candidate_conflict"
                )
        elif entries:
            raise _IntegrityError("lane_store.bootstrap_candidate_conflict")
        binding_complete = False
        if BINDING_NAME in entries:
            binding_complete = _read_bootstrap_prefix(
                candidate,
                BINDING_NAME,
                canonical_json(_binding_payload(project_binding)) + b"\n",
            )
        if GENERATIONS_NAME in entries:
            if not binding_complete:
                raise _IntegrityError(
                    "lane_store.bootstrap_candidate_conflict"
                )
            generations = _open_directory(candidate, GENERATIONS_NAME)
            opened.append(generations)
            generation_names = tuple(os.listdir(generations))
            if len(generation_names) > 1:
                raise _IntegrityError(
                    "lane_store.bootstrap_candidate_conflict"
                )
            if generation_names:
                generation_name = generation_names[0]
                match = GENERATION_NAME_PATTERN.fullmatch(generation_name)
                if match is None:
                    raise _IntegrityError(
                        "lane_store.bootstrap_candidate_conflict"
                    )
                generation = _open_directory(generations, generation_name)
                opened.append(generation)
                generation_entries = set(os.listdir(generation))
                if generation_entries - {BINDING_NAME, TRANSACTIONS_NAME}:
                    raise _IntegrityError(
                        "lane_store.bootstrap_candidate_conflict"
                    )
                if BINDING_NAME in generation_entries:
                    payload, _ = _read_json(generation, BINDING_NAME)
                    if (
                        payload.get("schema")
                        != "ask_herdr.lane_generation_binding.internal.v2"
                        or payload.get("project_authority_id")
                        != project_binding.project_authority_id
                        or payload.get("lane_id") != match.group(1)
                        or payload.get("lane_generation")
                        != int(match.group(2))
                        or not _matches(
                            DIGEST_PATTERN,
                            payload.get("lane_binding_digest"),
                        )
                        or set(payload)
                        != {
                            "schema",
                            "project_authority_id",
                            "lane_id",
                            "lane_generation",
                            "lane_binding_digest",
                        }
                    ):
                        raise _IntegrityError(
                            "lane_store.bootstrap_candidate_conflict"
                        )
                elif TRANSACTIONS_NAME in generation_entries:
                    raise _IntegrityError(
                        "lane_store.bootstrap_candidate_conflict"
                    )
                if TRANSACTIONS_NAME in generation_entries:
                    transactions = _open_directory(
                        generation,
                        TRANSACTIONS_NAME,
                    )
                    opened.append(transactions)
                    if os.listdir(transactions):
                        raise _IntegrityError(
                            "lane_store.bootstrap_candidate_conflict"
                        )
                    if not _directory_binding(
                        generation,
                        TRANSACTIONS_NAME,
                        transactions,
                    ):
                        raise _IntegrityError(
                            "lane_store.bootstrap_candidate_conflict"
                        )
                if not _directory_binding(
                    generations,
                    generation_name,
                    generation,
                ):
                    raise _IntegrityError(
                        "lane_store.bootstrap_candidate_conflict"
                    )
            if not _directory_binding(
                candidate,
                GENERATIONS_NAME,
                generations,
            ):
                raise _IntegrityError(
                    "lane_store.bootstrap_candidate_conflict"
                )
        if not _directory_binding(root, name, candidate):
            raise _IntegrityError("lane_store.bootstrap_candidate_conflict")
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(candidate)


def _validate_legacy_v1_lane_store(
    root: int,
    project_binding: Any,
) -> None:
    """Authenticate the closed legacy envelope before migration status."""

    opened: List[int] = []
    try:
        store = _open_directory(root, STORE_NAME)
        opened.append(store)
        if set(os.listdir(store)) != {BINDING_NAME, GENERATIONS_NAME}:
            raise _IntegrityError("lane_store.legacy_layout_invalid")
        stored_binding, _ = _read_json(store, BINDING_NAME)
        if stored_binding != _binding_payload(project_binding):
            raise _IntegrityError("lane_store.legacy_binding_invalid")
        generations = _open_directory(store, GENERATIONS_NAME)
        opened.append(generations)
        generation_names = tuple(sorted(os.listdir(generations)))
        if not generation_names:
            raise _IntegrityError("lane_store.legacy_layout_invalid")
        for name in generation_names:
            if GENERATION_NAME_PATTERN.fullmatch(name) is None:
                raise _IntegrityError("lane_store.legacy_layout_invalid")
            generation = _open_directory(generations, name)
            opened.append(generation)
            if set(os.listdir(generation)) != {
                "events",
                "responses",
                "staging",
                "head.json",
            }:
                raise _IntegrityError("lane_store.legacy_layout_invalid")
            for child_name in ("events", "responses", "staging"):
                child = _open_directory(generation, child_name)
                opened.append(child)
                if os.listdir(child):
                    raise _IntegrityError("lane_store.legacy_layout_invalid")
                if not _directory_binding(generation, child_name, child):
                    raise _IntegrityError("lane_store.legacy_layout_invalid")
            _read_file(generation, "head.json", MAX_RECORD_BYTES)
            if not _directory_binding(generations, name, generation):
                raise _IntegrityError("lane_store.legacy_layout_invalid")
        if (
            not _directory_binding(root, STORE_NAME, store)
            or not _directory_binding(store, GENERATIONS_NAME, generations)
        ):
            raise _IntegrityError("lane_store.legacy_layout_invalid")
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _inspect_lane_index_generation_membership_from_root(
    root: int,
    project_binding: Any,
) -> _LaneIndexGenerationMembershipInspection:
    """Authenticate managed Generation identities without reading Lane facts.

    This is a negative completeness cross-check for the sibling Lane Index.
    Its directory enumeration must never be used to construct Index entries.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ValidatedProjectMutationBinding,
    )

    if type(project_binding) is not ValidatedProjectMutationBinding:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_binding_invalid",
        )
    try:
        root_metadata = os.fstat(root)
    except OSError:
        return _LaneIndexGenerationMembershipInspection(
            "reconciliation_required",
            "lane_index.lane_store_changed",
        )
    if (
        root_metadata.st_dev != project_binding.filesystem_device
        or root_metadata.st_ino != project_binding.filesystem_inode
        or root_metadata.st_uid != project_binding.owner_uid
    ):
        return _LaneIndexGenerationMembershipInspection(
            "reconciliation_required",
            "lane_index.lane_store_changed",
        )
    try:
        bootstrap_entries = tuple(
            sorted(
                name
                for name in os.listdir(root)
                if name.startswith("ask-herdr-lanes.bootstrap.")
            )
        )
        if bootstrap_entries:
            expected_bootstrap = "ask-herdr-lanes.bootstrap.{}.tmp".format(
                _binding_candidate_token(_binding_payload(project_binding))
            )
            if bootstrap_entries != (expected_bootstrap,):
                return _LaneIndexGenerationMembershipInspection(
                    "quarantined",
                    "lane_index.lane_store_bootstrap_conflict",
                )
            _validate_lane_store_bootstrap_candidate(
                root,
                expected_bootstrap,
                project_binding,
            )
            return _LaneIndexGenerationMembershipInspection(
                "reconciliation_required",
                "lane_index.lane_store_bootstrap_pending",
            )
    except _IntegrityError as error:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError, ValueError):
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_bootstrap_conflict",
        )
    try:
        store_metadata = os.stat(
            STORE_NAME,
            dir_fd=root,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return _LaneIndexGenerationMembershipInspection(
            "absent",
            "lane_index.lane_store_absent",
        )
    except OSError:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_conflict",
        )
    if not _private_directory(store_metadata):
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_conflict",
        )
    try:
        if _detect_legacy_v1(root):
            _validate_legacy_v1_lane_store(root, project_binding)
            return _LaneIndexGenerationMembershipInspection(
                "reconciliation_required",
                "lane_index.migration_required",
            )
    except _IntegrityError as error:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except OSError:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_conflict",
        )

    opened: List[int] = []
    operation_error: Optional[BaseException] = None
    cleanup_error: Optional[OSError] = None
    result: Optional[_LaneIndexGenerationMembershipInspection] = None
    try:
        store = _open_directory(root, STORE_NAME)
        opened.append(store)
        if set(os.listdir(store)) != {
            LAYOUT_NAME,
            BINDING_NAME,
            GENERATIONS_NAME,
        }:
            raise _IntegrityError("lane_store.unknown_layout")
        layout, _ = _read_json(store, LAYOUT_NAME)
        if layout != _layout_payload():
            raise _IntegrityError("lane_store.layout_invalid")
        binding_payload, _ = _read_json(store, BINDING_NAME)
        expected_store_binding = {
            "schema": "ask_herdr.lane_store_binding.internal.v1",
            "project_authority_id": project_binding.project_authority_id,
            "filesystem_device": project_binding.filesystem_device,
            "filesystem_inode": project_binding.filesystem_inode,
            "owner_uid": project_binding.owner_uid,
        }
        if binding_payload != expected_store_binding:
            raise _IntegrityError("lane_store.binding_conflict")
        generations = _open_directory(store, GENERATIONS_NAME)
        opened.append(generations)
        names = tuple(sorted(os.listdir(generations)))
        generation_namespace_bindings: Dict[
            str, Tuple[int, int, int, int, int]
        ] = {}
        generation_names: List[str] = []
        candidate_names: List[str] = []
        for name in names:
            if GENERATION_NAME_PATTERN.fullmatch(name) is not None:
                generation_names.append(name)
                continue
            if GENERATION_CANDIDATE_PATTERN.fullmatch(name) is not None:
                candidate_names.append(name)
                continue
            raise _IntegrityError("lane_store.generation_namespace_invalid")
        if len(candidate_names) > 1:
            raise _IntegrityError("lane_store.generation_candidate_conflict")
        if candidate_names:
            candidate_match = GENERATION_CANDIDATE_PATTERN.fullmatch(
                candidate_names[0]
            )
            if (
                candidate_match is None
                or candidate_match.group(1) in set(generation_names)
            ):
                raise _IntegrityError(
                    "lane_store.generation_candidate_conflict"
                )
            candidate = _open_directory(generations, candidate_names[0])
            opened.append(candidate)
            generation_namespace_bindings[candidate_names[0]] = _identity(
                os.fstat(candidate)
            )
            candidate_entries = set(os.listdir(candidate))
            if candidate_entries - {BINDING_NAME, TRANSACTIONS_NAME}:
                raise _IntegrityError(
                    "lane_store.generation_candidate_conflict"
                )
            if BINDING_NAME in candidate_entries:
                candidate_payload, _ = _read_json(candidate, BINDING_NAME)
                candidate_lane_id, generation_text = (
                    candidate_match.group(1).rsplit(".g", 1)
                )
                if (
                    set(candidate_payload)
                    != {
                        "schema",
                        "project_authority_id",
                        "lane_id",
                        "lane_generation",
                        "lane_binding_digest",
                    }
                    or candidate_payload.get("schema")
                    != "ask_herdr.lane_generation_binding.internal.v2"
                    or candidate_payload.get("project_authority_id")
                    != project_binding.project_authority_id
                    or candidate_payload.get("lane_id")
                    != candidate_lane_id
                    or candidate_payload.get("lane_generation")
                    != int(generation_text)
                    or not _matches(
                        DIGEST_PATTERN,
                        candidate_payload.get("lane_binding_digest"),
                    )
                    or candidate_names[0]
                    != "generation.{}.{}.tmp".format(
                        candidate_match.group(1),
                        _binding_candidate_token(candidate_payload),
                    )
                ):
                    raise _IntegrityError(
                        "lane_store.generation_candidate_conflict"
                    )
            if TRANSACTIONS_NAME in candidate_entries:
                candidate_transactions = _open_directory(
                    candidate,
                    TRANSACTIONS_NAME,
                )
                opened.append(candidate_transactions)
                if os.listdir(candidate_transactions):
                    raise _IntegrityError(
                        "lane_store.generation_candidate_conflict"
                    )
                if not _directory_binding(
                    candidate,
                    TRANSACTIONS_NAME,
                    candidate_transactions,
                ):
                    raise _IntegrityError(
                        "lane_store.generation_candidate_conflict"
                    )
            if not _directory_binding(
                generations,
                candidate_names[0],
                candidate,
            ):
                raise _IntegrityError(
                    "lane_store.generation_candidate_conflict"
                )

        entries: List[_LaneIndexGenerationMembershipEntry] = []
        for generation_name in generation_names:
            match = GENERATION_NAME_PATTERN.fullmatch(generation_name)
            if match is None:
                raise _IntegrityError(
                    "lane_store.generation_namespace_invalid"
                )
            lane_id = match.group(1)
            lane_generation = int(match.group(2))
            generation = _open_directory(generations, generation_name)
            opened.append(generation)
            generation_namespace_bindings[generation_name] = _identity(
                os.fstat(generation)
            )
            if set(os.listdir(generation)) != {
                BINDING_NAME,
                TRANSACTIONS_NAME,
            }:
                raise _IntegrityError(
                    "lane_store.generation_layout_invalid"
                )
            generation_payload, _ = _read_json(
                generation,
                BINDING_NAME,
            )
            if (
                set(generation_payload) != {
                    "schema",
                    "project_authority_id",
                    "lane_id",
                    "lane_generation",
                    "lane_binding_digest",
                }
                or generation_payload.get("schema")
                != "ask_herdr.lane_generation_binding.internal.v2"
                or generation_payload.get("project_authority_id")
                != project_binding.project_authority_id
                or generation_payload.get("lane_id") != lane_id
                or generation_payload.get("lane_generation")
                != lane_generation
                or not _matches(
                    DIGEST_PATTERN,
                    generation_payload.get("lane_binding_digest"),
                )
            ):
                raise _IntegrityError(
                    "lane_store.generation_binding_conflict"
                )
            transactions = _open_directory(
                generation,
                TRANSACTIONS_NAME,
            )
            opened.append(transactions)
            if (
                not _directory_binding(
                    generations,
                    generation_name,
                    generation,
                )
                or not _directory_binding(
                    generation,
                    TRANSACTIONS_NAME,
                    transactions,
                )
            ):
                raise _IntegrityError(
                    "lane_store.generation_binding_changed",
                    quarantine=False,
                )
            entries.append(
                _LaneIndexGenerationMembershipEntry(
                    lane_id=lane_id,
                    lane_generation=lane_generation,
                    lane_binding_digest=generation_payload[
                        "lane_binding_digest"
                    ],
                )
            )
        if (
            tuple(sorted(os.listdir(generations))) != names
            or any(
                _identity(
                    os.stat(
                        name,
                        dir_fd=generations,
                        follow_symlinks=False,
                    )
                )
                != expected
                for name, expected in generation_namespace_bindings.items()
            )
            or not _directory_binding(root, STORE_NAME, store)
            or not _directory_binding(store, GENERATIONS_NAME, generations)
        ):
            raise _IntegrityError(
                "lane_store.generation_binding_changed",
                quarantine=False,
            )
        result = _LaneIndexGenerationMembershipInspection(
            (
                "reconciliation_required"
                if candidate_names
                else "active"
            ),
            (
                "lane_index.generation_membership_pending"
                if candidate_names
                else "lane_index.generation_membership_active"
            ),
            tuple(entries),
        )
    except BaseException as error:
        operation_error = error
        if isinstance(error, _IntegrityError):
            result = _LaneIndexGenerationMembershipInspection(
                (
                    "quarantined"
                    if error.quarantine
                    else "reconciliation_required"
                ),
                error.code,
            )
        elif isinstance(error, (OSError, StrictJsonError, ValueError)):
            result = _LaneIndexGenerationMembershipInspection(
                "quarantined",
                "lane_index.lane_store_conflict",
            )
        else:
            raise
    finally:
        for descriptor in reversed(opened):
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
    if cleanup_error is not None and operation_error is None:
        return _LaneIndexGenerationMembershipInspection(
            "reconciliation_required",
            "lane_index.lane_store_cleanup_unverified",
        )
    if result is None:
        return _LaneIndexGenerationMembershipInspection(
            "quarantined",
            "lane_index.lane_store_conflict",
        )
    return result


def _authenticate_lane_index_entry_from_root(
    root: int,
    binding: ValidatedLaneGenerationBinding,
    *,
    event_sequence: int,
    event_digest: str,
    state_digest: str,
    response_digest: Optional[str],
    intent_digest: str,
) -> Tuple[str, str]:
    """Authenticate one indexed head using an already bound project root."""

    handles: Optional[_Handles] = None
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            return "quarantined", "lane_index.indexed_lane_missing"
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            return "reconciliation_required", "lane_index.lane_writer_active"
        namespace_names = tuple(sorted(os.listdir(handles.transactions)))
        namespace_identities = {
            name: _identity(
                os.stat(
                    name,
                    dir_fd=handles.transactions,
                    follow_symlinks=False,
                )
            )
            for name in namespace_names
        }
        scan = _scan_generation(handles, binding)
        if scan.status == "quarantined":
            return "quarantined", scan.detail_code
        if scan.head is None:
            return "quarantined", "lane_index.lane_head_conflict"
        actual_sequence = scan.head.get("event_sequence")
        if actual_sequence != event_sequence:
            return "quarantined", "lane_index.lane_head_conflict"
        if (
            scan.head.get("event_digest") != event_digest
            or scan.head.get("state_digest") != state_digest
            or _indexed_response_digest(scan.active_records) != response_digest
            or not scan.active_records
            or scan.active_records[-1].get(
                "lane_index_transition_intent_digest"
            )
            != intent_digest
        ):
            return "quarantined", "lane_index.lane_head_conflict"
        if not _handles_still_bound(handles, binding):
            return "reconciliation_required", "lane_index.lane_store_changed"
        if tuple(sorted(os.listdir(handles.transactions))) != namespace_names:
            return "quarantined", "lane_index.lane_head_conflict"
        if any(
            _identity(
                os.stat(
                    name,
                    dir_fd=handles.transactions,
                    follow_symlinks=False,
                )
            )
            != expected
            for name, expected in namespace_identities.items()
        ):
            return "quarantined", "lane_index.lane_head_conflict"
        if scan.status != "active":
            return "reconciliation_required", scan.detail_code
        return "active", "lane_index.lane_head_authenticated"
    except _IntegrityError as error:
        operation_error = error
        return (
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError, ValueError) as error:
        operation_error = error
        return "quarantined", "lane_index.lane_storage_integrity_failure"
    finally:
        if handles is not None:
            try:
                _close_handles(handles)
            except OSError:
                if operation_error is None:
                    raise


def _authenticate_pending_lane_index_transition_from_root(
    root: int,
    binding: ValidatedLaneGenerationBinding,
    *,
    prior_event_sequence: Optional[int],
    prior_event_digest: Optional[str],
    prior_state_digest: Optional[str],
    prior_response_digest: Optional[str],
    prior_intent_digest: Optional[str],
    candidate_intent: Dict[str, Any],
    candidate_transition: Optional[Dict[str, Any]],
    candidate_transition_present: bool,
) -> Tuple[str, str]:
    """Authenticate one coherent pending Index transition against Lane facts."""

    handles: Optional[_Handles] = None
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            return "quarantined", "lane_index.indexed_lane_missing"
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            return "reconciliation_required", "lane_index.lane_writer_active"
        namespace_names = tuple(sorted(os.listdir(handles.transactions)))
        namespace_identities = {
            name: _identity(
                os.stat(
                    name,
                    dir_fd=handles.transactions,
                    follow_symlinks=False,
                )
            )
            for name in namespace_names
        }
        scan = _scan_generation(handles, binding)
        if scan.status == "quarantined":
            return "quarantined", scan.detail_code
        records = scan.active_records
        if (
            candidate_intent.get("project_authority_id")
            != binding.project_authority_id
            or candidate_intent.get("lane_id") != binding.lane_id
            or candidate_intent.get("lane_generation")
            != binding.lane_generation
            or candidate_intent.get("lane_binding_digest")
            != binding.lane_binding_digest
        ):
            return "quarantined", "lane_index.candidate_changed"
        if prior_event_sequence is None:
            if any(
                value is not None
                for value in (
                    prior_event_digest,
                    prior_state_digest,
                    prior_response_digest,
                    prior_intent_digest,
                )
            ):
                return "quarantined", "lane_index.lane_head_conflict"
            prior_matches = True
        else:
            if prior_event_sequence < 1 or len(records) < prior_event_sequence:
                return "quarantined", "lane_index.lane_head_conflict"
            prior = records[prior_event_sequence - 1]
            prior_matches = (
                prior.get("event_sequence") == prior_event_sequence
                and prior.get("record_digest") == prior_event_digest
                and prior.get("state_after_digest") == prior_state_digest
                and prior.get("lane_index_transition_intent_digest")
                == prior_intent_digest
                and _indexed_response_digest(
                    records[:prior_event_sequence]
                )
                == prior_response_digest
            )
        if not prior_matches:
            return "quarantined", "lane_index.lane_head_conflict"

        candidate_sequence = candidate_intent.get("event_head_sequence")
        if candidate_sequence != (prior_event_sequence or 0) + 1:
            return "quarantined", "lane_index.candidate_changed"
        head_sequence = (scan.head or {}).get("event_sequence")
        if head_sequence == prior_event_sequence:
            if candidate_transition_present:
                return "quarantined", "lane_index.candidate_changed"
        elif head_sequence == candidate_sequence:
            candidate_record = records[-1]
            if (
                candidate_record.get("record_digest")
                != (scan.head or {}).get("event_digest")
                or candidate_record.get("state_after_digest")
                != candidate_intent.get("lane_state_digest")
                or candidate_record.get(
                    "lane_index_transition_intent_digest"
                )
                != candidate_intent.get("intent_digest")
                or _indexed_response_digest(records)
                != candidate_intent.get("authoritative_response_digest")
            ):
                return "quarantined", "lane_index.lane_head_conflict"
            if candidate_transition is not None:
                projection = candidate_transition.get(
                    "lane_head_projection",
                    {},
                )
                if (
                    projection.get("event_head_record_digest")
                    != candidate_record.get("record_digest")
                    or projection.get("lane_state_digest")
                    != candidate_record.get("state_after_digest")
                ):
                    return "quarantined", "lane_index.candidate_changed"
        else:
            return "quarantined", "lane_index.lane_head_conflict"
        if not _handles_still_bound(handles, binding):
            return "reconciliation_required", "lane_index.lane_store_changed"
        if tuple(sorted(os.listdir(handles.transactions))) != namespace_names:
            return "quarantined", "lane_index.lane_head_conflict"
        if any(
            _identity(
                os.stat(
                    name,
                    dir_fd=handles.transactions,
                    follow_symlinks=False,
                )
            )
            != expected
            for name, expected in namespace_identities.items()
        ):
            return "quarantined", "lane_index.lane_head_conflict"
        if scan.status != "active":
            return "reconciliation_required", scan.detail_code
        return "active", "lane_index.pending_transition_authenticated"
    except _IntegrityError as error:
        operation_error = error
        return (
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError, ValueError) as error:
        operation_error = error
        return "quarantined", "lane_index.lane_storage_integrity_failure"
    finally:
        if handles is not None:
            try:
                _close_handles(handles)
            except OSError:
                if operation_error is None:
                    raise


def inspect_lane_turn(
    binding: ValidatedLaneGenerationBinding,
) -> LaneStoreInspection:
    """Read and replay one exact Lane Generation without mutation."""

    try:
        with _open_root(binding) as root:
            handles = _open_existing_handles(root, binding)
            if handles is None:
                return LaneStoreInspection("absent", "lane_store.absent")
            try:
                try:
                    fcntl.flock(
                        handles.generation,
                        fcntl.LOCK_SH | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    return LaneStoreInspection(
                        "busy",
                        "lane_store.writer_active",
                    )
                scan = _scan_generation(handles, binding)
                if not _handles_still_bound(handles, binding):
                    return LaneStoreInspection(
                        "reconciliation_required",
                        "lane_store.store_changed",
                    )
                if (
                    scan.status == "active"
                    and scan.state is not None
                    and scan.state.phase is TurnPhase.SETTLED
                    and scan.state.outcome_kind is TurnOutcomeKind.TURN_FINAL
                ):
                    try:
                        frame = _read_publication(handles, binding, scan.state)
                        authority = _parse_authoritative_frame(
                            binding,
                            scan.state,
                            frame,
                        )
                        final_records = tuple(
                            record
                            for record in scan.active_records
                            if record.get("event", {}).get("event_type")
                            == "FinalTurnAuthority"
                        )
                        if len(final_records) != 1:
                            raise _IntegrityError(
                                "response_authority.settled_frame_conflict"
                            )
                        final_record = final_records[0]
                        if (
                            final_record.get("event_fingerprint")
                            != _event_fingerprint(authority)
                            or final_record.get("response_frame_digest")
                            != _digest_bytes(frame)
                        ):
                            raise _IntegrityError(
                                "response_authority.settled_frame_conflict"
                            )
                    except _IntegrityError as error:
                        return LaneStoreInspection(
                            "quarantined",
                            error.code,
                            state=_quarantined_state(scan.state),
                            event_count=len(scan.active_records),
                            head_sequence=(scan.head or {}).get(
                                "event_sequence"
                            ),
                            head_digest=(scan.head or {}).get("event_digest"),
                        )
                if (
                    scan.status == "active"
                    and scan.state is not None
                    and scan.state.phase is TurnPhase.SETTLED
                    and scan.state.outcome_kind
                    is TurnOutcomeKind.TURN_DEFINITE_NON_START
                    and _has_attempt_artifact(
                        _attempt_artifacts(handles, scan.state.attempt_id)
                    )
                ):
                    return LaneStoreInspection(
                        "quarantined",
                        "response_authority.contradicts_definite_non_start",
                        state=_quarantined_state(scan.state),
                        event_count=len(scan.active_records),
                        head_sequence=(scan.head or {}).get("event_sequence"),
                        head_digest=(scan.head or {}).get("event_digest"),
                    )
                if (
                    scan.status == "active"
                    and scan.state is not None
                    and scan.state.phase is TurnPhase.SETTLED
                    and scan.response_candidates
                ):
                    return LaneStoreInspection(
                        "reconciliation_required",
                        "response_authority.post_settlement_candidate_residue",
                        state=_reconciliation_state(scan.state),
                        event_count=len(scan.active_records),
                        head_sequence=(scan.head or {}).get("event_sequence"),
                        head_digest=(scan.head or {}).get("event_digest"),
                    )
                if scan.status == "empty":
                    return LaneStoreInspection(
                        "reconciliation_required",
                        "lane_store.empty_generation",
                    )
                count = len(scan.active_records) + (
                    1 if scan.pending_record is not None else 0
                )
                visible_state = scan.state
                if (
                    scan.status == "reconciliation_required"
                    and visible_state is not None
                ):
                    visible_state = _reconciliation_state(visible_state)
                return LaneStoreInspection(
                    scan.status,
                    scan.detail_code,
                    state=visible_state,
                    event_count=count,
                    head_sequence=(scan.head or {}).get("event_sequence"),
                    head_digest=(scan.head or {}).get("event_digest"),
                )
            finally:
                _close_handles(handles)
    except _IntegrityError as error:
        return LaneStoreInspection(
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, ValueError, StrictJsonError):
        return LaneStoreInspection(
            "quarantined",
            "lane_store.storage_integrity_failure",
        )


def _apply_lane_turn_event_raw(
    binding: ValidatedLaneGenerationBinding,
    event: LaneTurnEvent,
    *,
    failpoint: Any = None,
) -> LaneMutationResult:
    """Durably apply one non-final already-validated lane event."""

    if type(event) is FinalTurnAuthority:
        raise ValueError("lane_store.final_authority_is_internal")
    allowed = (
        PrepareAdmittedAttempt,
        ClaimTopologyProvisioning,
        TopologyEffectStarted,
        TopologyCommandEffectStarted,
        RecordTopologyProvisioned,
        BeginDispatch,
        RecordDeliveryUncertain,
        RecordDefiniteNonStart,
        RecordProviderStarted,
        RecordResponseValidationConflict,
        RecordAdvisoryWaitTimeout,
    )
    if type(event) not in allowed:
        raise ValueError("lane_store.event_type_invalid")
    try:
        with _open_root(binding) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return _inactive_result("busy", "lane_store.writer_active")
            handles = _open_existing_handles(root, binding)
            if handles is None:
                if type(event) is not PrepareAdmittedAttempt:
                    return _inactive_result("absent", "lane_store.absent")
                handles = _ensure_handles(root, binding, failpoint=failpoint)
            try:
                try:
                    fcntl.flock(
                        handles.generation,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    return _inactive_result("busy", "lane_store.writer_active")
                _barrier_store_tree(handles, binding)
                scan = _scan_generation(handles, binding)
                if scan.status not in {
                    "empty",
                    "active",
                    "reconciliation_required",
                }:
                    return _inactive_result(scan.status, scan.detail_code, scan.state)
                return _commit_event_locked(
                    handles,
                    binding,
                    scan,
                    event,
                    failpoint=failpoint,
                )
            finally:
                _close_handles(handles)
    except LaneStoreFailpoint:
        raise
    except _IntegrityError as error:
        return _inactive_result(
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError):
        return _inactive_result(
            "quarantined",
            "lane_store.storage_integrity_failure",
        )


def apply_lane_turn_event(
    binding: ValidatedLaneGenerationBinding,
    event: LaneTurnEvent,
    *,
    failpoint: Any = None,
) -> LaneMutationResult:
    """Apply ordinary Lane facts; cross-store authority uses leased ports."""

    if isinstance(
        event,
        (
            ClaimTopologyProvisioning,
            TopologyEffectStarted,
            TopologyCommandEffectStarted,
            RecordTopologyProvisioned,
        ),
    ):
        return LaneMutationResult(
            "lane_event_conflict",
            "lane_store.topology_authority_requires_project_lease",
        )
    if type(event) is RecordRecoveryResultEvidenceAnchor:
        return LaneMutationResult(
            "lane_event_conflict",
            "lane_store.recovery_evidence_authority_requires_project_lease",
        )
    return _apply_lane_turn_event_raw(
        binding,
        event,
        failpoint=failpoint,
    )


def claim_topology_provisioning_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    topology_mutation_id: str,
    topology_nonce: str,
    topology_store_incarnation_digest: Optional[str] = None,
) -> ClaimedLaneProof:
    """Commit the exact Lane provisioning claim under a retained root lease.

    This private port deliberately does not open or lock the project root.  It
    borrows the lease's descriptor, locks only the exact Lane Generation, and
    derives every returned digest from the replayed journal.
    """

    from ask_herdr_policy_ledger import (
        CommittedHumanAdmissionProof,
        _authenticate_committed_human_admission_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    if not isinstance(binding, ValidatedLaneGenerationBinding):
        raise ValueError("lane_store.binding_type_invalid")
    if not isinstance(policy_proof, CommittedHumanAdmissionProof):
        raise ProjectMutationLeaseError(
            "lane_store.topology_claim_not_admissible"
        )
    policy_proof = _authenticate_committed_human_admission_proof_under_lease(
        lease,
        policy_proof,
    )
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_not_admissible"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        if scan.status not in {"active", "reconciliation_required"} or scan.state is None:
            raise ProjectMutationLeaseError(scan.detail_code)
        state = scan.state
        if (
            policy_proof.project_authority_id
            != binding.project_authority_id
            or policy_proof.operation != "turn.consult"
            or policy_proof.action_reason != "initial"
            or policy_proof.operation_id != state.operation_id
            or policy_proof.canonical_request_digest
            != state.canonical_request_digest
            or policy_proof.policy_record_digest
            != state.direct_human_policy_record_digest
            or policy_proof.provider_budget_effect != "not_counted"
            or policy_proof.project_budget_effect != "not_counted"
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_not_admissible"
            )
        existing_claim = state.topology_provisioning_claim
        if existing_claim is not None:
            prepared_digest = existing_claim.prepared_lane_record_digest
        else:
            if not scan.active_records:
                raise ProjectMutationLeaseError(
                    "lane_store.topology_claim_not_admissible"
                )
            prior = scan.active_records[-1]
            if prior.get("event", {}).get("event_type") != "PrepareAdmittedAttempt":
                raise ProjectMutationLeaseError(
                    "lane_store.topology_claim_not_admissible"
                )
            prepared_digest = prior.get("record_digest")
        if not _matches(DIGEST_PATTERN, prepared_digest):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_not_admissible"
            )
        if (
            existing_claim is not None
            and existing_claim.topology_store_incarnation_digest
            != topology_store_incarnation_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_store_incarnation_mismatch"
            )
        event = ClaimTopologyProvisioning(
            operation_id=policy_proof.operation_id,
            canonical_request_digest=policy_proof.canonical_request_digest,
            attempt_id=state.attempt_id,
            lane_id=binding.lane_id,
            lane_generation=binding.lane_generation,
            policy_record_digest=policy_proof.policy_record_digest,
            prepared_lane_record_digest=prepared_digest,
            topology_mutation_id=topology_mutation_id,
            topology_nonce=topology_nonce,
            topology_store_incarnation_digest=(
                topology_store_incarnation_digest
            ),
        )
        result = _commit_event_locked(handles, binding, scan, event)
        if result.outcome_kind not in {
            "lane_event_committed",
            "lane_event_already_committed",
        } or result.state is None or result.record_digest is None:
            detail_code = (
                "lane_store.topology_claim_not_admissible"
                if result.detail_code
                == "lane_turn.topology_provisioning_claim_not_admissible"
                else result.detail_code
            )
            raise ProjectMutationLeaseError(detail_code)
        claimed = result.state.topology_provisioning_claim
        if claimed != event:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_not_admissible"
            )
        return ClaimedLaneProof(
            operation_id=event.operation_id,
            canonical_request_digest=event.canonical_request_digest,
            lane_id=event.lane_id,
            lane_generation=event.lane_generation,
            attempt_id=event.attempt_id,
            policy_record_digest=event.policy_record_digest,
            prepared_lane_record_digest=event.prepared_lane_record_digest,
            topology_mutation_id=event.topology_mutation_id,
            topology_nonce=event.topology_nonce,
            topology_claim_record_digest=result.record_digest,
            lane_state_digest=_state_digest(result.state),
            lane_binding_digest=binding.lane_binding_digest,
            topology_store_incarnation_digest=(
                event.topology_store_incarnation_digest
            ),
        )
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = error.code if isinstance(error, _IntegrityError) else (
            "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _authenticate_claimed_lane_proof_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> ClaimedLaneProof:
    """Re-authenticate one Lane claim proof against its durable journal."""

    from ask_herdr_policy_ledger import (
        _authenticate_committed_human_admission_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    policy_proof = _authenticate_committed_human_admission_proof_under_lease(
        lease,
        policy_proof,
    )
    if not isinstance(lane_proof, ClaimedLaneProof):
        raise ProjectMutationLeaseError(
            "lane_store.topology_claim_proof_mismatch"
        )
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active",
                state_status="reconciliation_required",
            ) from error
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        if (
            scan.status != "active"
            or scan.state is None
            or scan.state.topology_provisioning_claim is None
            or scan.state.topology_provisioned is not None
            or not scan.active_records
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        claim = scan.state.topology_provisioning_claim
        record = scan.active_records[-1]
        if record.get("event", {}).get("event_type") != "ClaimTopologyProvisioning":
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        derived = ClaimedLaneProof(
            operation_id=claim.operation_id,
            canonical_request_digest=claim.canonical_request_digest,
            lane_id=claim.lane_id,
            lane_generation=claim.lane_generation,
            attempt_id=claim.attempt_id,
            policy_record_digest=claim.policy_record_digest,
            prepared_lane_record_digest=claim.prepared_lane_record_digest,
            topology_mutation_id=claim.topology_mutation_id,
            topology_nonce=claim.topology_nonce,
            topology_claim_record_digest=record["record_digest"],
            lane_state_digest=_state_digest(scan.state),
            lane_binding_digest=binding.lane_binding_digest,
            topology_store_incarnation_digest=(
                claim.topology_store_incarnation_digest
            ),
        )
        if derived != lane_proof:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        if (
            policy_proof.project_authority_id != binding.project_authority_id
            or policy_proof.operation_id != derived.operation_id
            or policy_proof.canonical_request_digest
            != derived.canonical_request_digest
            or policy_proof.policy_record_digest
            != derived.policy_record_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        _borrow_validated_root(lease, binding)
        return derived
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = error.code if isinstance(error, _IntegrityError) else (
            "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _snapshot_validated_lane_binding(
    binding: ValidatedLaneGenerationBinding,
) -> ValidatedLaneGenerationBinding:
    if type(binding) is not ValidatedLaneGenerationBinding:
        raise ValueError("lane_store.binding_type_invalid")
    try:
        return ValidatedLaneGenerationBinding(**dict(vars(binding)))
    except (TypeError, ValueError) as error:
        raise ValueError("lane_store.binding_type_invalid") from error


def _snapshot_prepare_admitted_attempt(
    event: PrepareAdmittedAttempt,
) -> PrepareAdmittedAttempt:
    if type(event) is not PrepareAdmittedAttempt:
        raise ValueError("lane_store.event_type_invalid")
    try:
        return PrepareAdmittedAttempt(**dict(vars(event)))
    except (TypeError, ValueError) as error:
        raise ValueError("lane_store.event_type_invalid") from error


def prepare_admitted_attempt_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    event: PrepareAdmittedAttempt,
    *,
    failpoint: Any = None,
) -> LaneMutationResult:
    """Prepare one admitted attempt while borrowing the project-root lease.

    The caller retains sole ownership of the already locked project-root
    descriptor.  This port opens only Lane Store descendants, locks only the
    exact Lane Generation, and returns only the ordinary Lane mutation result.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    try:
        event_snapshot = _snapshot_prepare_admitted_attempt(event)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.event_type_invalid"
        ) from error

    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            handles = _ensure_handles(
                root,
                binding_snapshot,
                failpoint=failpoint,
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error

        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        if scan.status not in {
            "empty",
            "active",
            "reconciliation_required",
        }:
            raise ProjectMutationLeaseError(scan.detail_code)
        result = _commit_event_locked(
            handles,
            binding_snapshot,
            scan,
            event_snapshot,
            failpoint=failpoint,
        )
        if not _handles_still_bound(handles, binding_snapshot):
            raise ProjectMutationLeaseError("lane_store.store_changed")
        _borrow_validated_root(lease, binding_snapshot)
        return result
    except (ProjectMutationLeaseError, LaneStoreFailpoint):
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _historical_claim_from_scan(
    scan: _Scan,
    binding: ValidatedLaneGenerationBinding,
) -> ClaimedLaneProof:
    """Reconstruct the unique claim from its own authoritative record."""

    if (
        scan.status not in {"active", "reconciliation_required"}
        or scan.state is None
    ):
        raise _IntegrityError(
            "lane_store.topology_claim_proof_mismatch",
            quarantine=False,
        )
    claim_records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "ClaimTopologyProvisioning"
    )
    if len(claim_records) != 1:
        raise _IntegrityError(
            "lane_store.topology_claim_proof_mismatch",
            quarantine=False,
        )
    claim_record = claim_records[0]
    claim = _event_from_payload(claim_record["event"])
    if type(claim) is not ClaimTopologyProvisioning:
        raise _IntegrityError(
            "lane_store.topology_claim_proof_mismatch",
            quarantine=False,
        )
    return ClaimedLaneProof(
        operation_id=claim.operation_id,
        canonical_request_digest=claim.canonical_request_digest,
        lane_id=claim.lane_id,
        lane_generation=claim.lane_generation,
        attempt_id=claim.attempt_id,
        policy_record_digest=claim.policy_record_digest,
        prepared_lane_record_digest=claim.prepared_lane_record_digest,
        topology_mutation_id=claim.topology_mutation_id,
        topology_nonce=claim.topology_nonce,
        topology_claim_record_digest=claim_record["record_digest"],
        lane_state_digest=claim_record["state_after_digest"],
        lane_binding_digest=binding.lane_binding_digest,
        topology_store_incarnation_digest=(
            claim.topology_store_incarnation_digest
        ),
    )


def _authenticate_historical_claimed_lane_proof_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
    allow_pending_policy_content_access: bool = False,
) -> ClaimedLaneProof:
    """Authenticate a pending or already-consumed historical Lane claim."""

    from ask_herdr_policy_ledger import (  # noqa: PLC0415
        _authenticate_committed_human_admission_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    if type(lane_proof) is not ClaimedLaneProof:
        raise ProjectMutationLeaseError(
            "lane_store.topology_claim_proof_mismatch"
        )
    lane_snapshot = ClaimedLaneProof(**dict(vars(lane_proof)))
    policy = _authenticate_committed_human_admission_proof_under_lease(
        lease,
        policy_proof,
        allow_pending_content_access=(
            allow_pending_policy_content_access
        ),
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        derived = _historical_claim_from_scan(
            _scan_generation(handles, binding_snapshot),
            binding_snapshot,
        )
        if derived != lane_snapshot or (
            policy.project_authority_id
            != binding_snapshot.project_authority_id
            or policy.operation_id != derived.operation_id
            or policy.canonical_request_digest
            != derived.canonical_request_digest
            or policy.policy_record_digest != derived.policy_record_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return derived
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _topology_effect_started_proof_from_record(
    binding: ValidatedLaneGenerationBinding,
    event: TopologyEffectStarted,
    record: Dict[str, Any],
) -> TopologyEffectStartedLaneProof:
    return TopologyEffectStartedLaneProof(
        operation_id=event.operation_id,
        canonical_request_digest=event.canonical_request_digest,
        lane_id=event.lane_id,
        lane_generation=event.lane_generation,
        attempt_id=event.attempt_id,
        policy_record_digest=event.policy_record_digest,
        prepared_lane_record_digest=event.prepared_lane_record_digest,
        topology_mutation_id=event.topology_mutation_id,
        topology_nonce=event.topology_nonce,
        topology_store_incarnation_digest=(
            event.topology_store_incarnation_digest
        ),
        topology_claim_record_digest=event.topology_claim_record_digest,
        topology_mutation_record_digest=(
            event.topology_mutation_record_digest
        ),
        first_topology_command_record_digest=(
            event.first_topology_command_record_digest
        ),
        topology_effect_started_record_digest=record["record_digest"],
        lane_state_digest=record["state_after_digest"],
        lane_binding_digest=binding.lane_binding_digest,
    )


def _commit_topology_effect_started_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
    topology_mutation_record_digest: str,
    first_topology_command_record_digest: str,
    failpoint: Any = None,
) -> TopologyEffectStartedLaneProof:
    """Freshly append the one-shot marker preceding a first Topology command.

    An existing marker never returns authority from this write seam.  Later
    Topology commands and settlement must use the separate authentication port.
    """

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        current_claim = _historical_claim_from_scan(scan, binding_snapshot)
        if current_claim != authenticated_claim:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        marker_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "TopologyEffectStarted"
        )
        if marker_records or (
            scan.state is not None
            and scan.state.topology_effect_started is not None
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_already_recorded"
            )
        if scan.status != "active" or scan.state is None:
            raise ProjectMutationLeaseError(scan.detail_code)
        if (
            authenticated_claim.topology_store_incarnation_digest is None
            or scan.state.topology_provisioning_claim is None
            or scan.state.topology_provisioning_claim
            != _event_from_payload(scan.active_records[-1]["event"])
            or scan.active_records[-1].get("event", {}).get("event_type")
            != "ClaimTopologyProvisioning"
            or scan.active_records[-1].get("record_digest")
            != authenticated_claim.topology_claim_record_digest
            or scan.state.topology_provisioned is not None
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        try:
            event = TopologyEffectStarted(
                operation_id=authenticated_claim.operation_id,
                canonical_request_digest=(
                    authenticated_claim.canonical_request_digest
                ),
                attempt_id=authenticated_claim.attempt_id,
                lane_id=authenticated_claim.lane_id,
                lane_generation=authenticated_claim.lane_generation,
                policy_record_digest=authenticated_claim.policy_record_digest,
                prepared_lane_record_digest=(
                    authenticated_claim.prepared_lane_record_digest
                ),
                topology_mutation_id=(
                    authenticated_claim.topology_mutation_id
                ),
                topology_nonce=authenticated_claim.topology_nonce,
                topology_store_incarnation_digest=(
                    authenticated_claim.topology_store_incarnation_digest
                ),
                topology_claim_record_digest=(
                    authenticated_claim.topology_claim_record_digest
                ),
                topology_mutation_record_digest=(
                    topology_mutation_record_digest
                ),
                first_topology_command_record_digest=(
                    first_topology_command_record_digest
                ),
            )
        except (TypeError, ValueError) as error:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            ) from error
        result = _commit_event_locked(
            handles,
            binding_snapshot,
            scan,
            event,
            failpoint=failpoint,
        )
        if (
            result.outcome_kind != "lane_event_committed"
            or result.record_digest is None
        ):
            raise ProjectMutationLeaseError(result.detail_code)
        verified = _scan_generation(handles, binding_snapshot)
        records = tuple(
            record
            for record in verified.active_records
            if record.get("record_digest") == result.record_digest
        )
        if verified.status != "active" or len(records) != 1:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_publication_unverified"
            )
        recorded_event = _event_from_payload(records[0]["event"])
        if (
            type(recorded_event) is not TopologyEffectStarted
            or recorded_event != event
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_publication_unverified"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return _topology_effect_started_proof_from_record(
            binding_snapshot,
            recorded_event,
            records[0],
        )
    except (ProjectMutationLeaseError, LaneStoreFailpoint):
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _topology_command_effect_started_proof_from_record(
    binding: ValidatedLaneGenerationBinding,
    event: TopologyCommandEffectStarted,
    record: Dict[str, Any],
) -> TopologyCommandEffectStartedLaneProof:
    return TopologyCommandEffectStartedLaneProof(
        operation_id=event.operation_id,
        canonical_request_digest=event.canonical_request_digest,
        lane_id=event.lane_id,
        lane_generation=event.lane_generation,
        attempt_id=event.attempt_id,
        policy_record_digest=event.policy_record_digest,
        prepared_lane_record_digest=event.prepared_lane_record_digest,
        topology_mutation_id=event.topology_mutation_id,
        topology_nonce=event.topology_nonce,
        topology_store_incarnation_digest=(
            event.topology_store_incarnation_digest
        ),
        topology_claim_record_digest=event.topology_claim_record_digest,
        topology_mutation_record_digest=(
            event.topology_mutation_record_digest
        ),
        topology_effect_started_record_digest=(
            event.topology_effect_started_record_digest
        ),
        command_sequence=event.command_sequence,
        topology_command_step_id=event.topology_command_step_id,
        topology_command_record_digest=(
            event.topology_command_record_digest
        ),
        previous_topology_effect_record_digest=(
            event.previous_topology_effect_record_digest
        ),
        topology_command_effect_started_record_digest=record[
            "record_digest"
        ],
        lane_state_digest=record["state_after_digest"],
        lane_binding_digest=binding.lane_binding_digest,
    )


def _commit_topology_command_effect_started_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
    command_sequence: int,
    topology_command_step_id: str,
    topology_command_record_digest: str,
    failpoint: Any = None,
) -> TopologyCommandEffectStartedLaneProof:
    """Freshly append the witness preceding one later Topology command."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    first_proof = (
        _authenticate_historical_topology_effect_started_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=authenticated_claim,
        )
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        current_claim = _historical_claim_from_scan(scan, binding_snapshot)
        command_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "TopologyCommandEffectStarted"
        )
        command_events = tuple(
            _event_from_payload(record["event"])
            for record in command_records
        )
        if any(
            type(event) is TopologyCommandEffectStarted
            and (
                event.command_sequence == command_sequence
                or event.topology_command_step_id
                == topology_command_step_id
            )
            for event in command_events
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_already_recorded"
            )
        if (
            scan.status != "active"
            or scan.state is None
            or current_claim != authenticated_claim
            or scan.state.topology_provisioning_claim is None
            or scan.state.topology_provisioned is not None
            or scan.state.topology_effect_started is None
            or tuple(scan.state.topology_command_effects_started)
            != command_events
            or command_sequence != len(command_events) + 2
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        first_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "TopologyEffectStarted"
        )
        if (
            len(first_records) != 1
            or first_records[0]["record_digest"]
            != first_proof.topology_effect_started_record_digest
            or first_proof.topology_mutation_record_digest
            != scan.state.topology_effect_started.topology_mutation_record_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        previous_record_digest = (
            command_records[-1]["record_digest"]
            if command_records
            else first_records[0]["record_digest"]
        )
        if scan.active_records[-1]["record_digest"] != previous_record_digest:
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        try:
            event = TopologyCommandEffectStarted(
                operation_id=authenticated_claim.operation_id,
                canonical_request_digest=(
                    authenticated_claim.canonical_request_digest
                ),
                attempt_id=authenticated_claim.attempt_id,
                lane_id=authenticated_claim.lane_id,
                lane_generation=authenticated_claim.lane_generation,
                policy_record_digest=authenticated_claim.policy_record_digest,
                prepared_lane_record_digest=(
                    authenticated_claim.prepared_lane_record_digest
                ),
                topology_mutation_id=(
                    authenticated_claim.topology_mutation_id
                ),
                topology_nonce=authenticated_claim.topology_nonce,
                topology_store_incarnation_digest=(
                    authenticated_claim.topology_store_incarnation_digest
                ),
                topology_claim_record_digest=(
                    authenticated_claim.topology_claim_record_digest
                ),
                topology_mutation_record_digest=(
                    first_proof.topology_mutation_record_digest
                ),
                topology_effect_started_record_digest=(
                    first_proof.topology_effect_started_record_digest
                ),
                command_sequence=command_sequence,
                topology_command_step_id=topology_command_step_id,
                topology_command_record_digest=(
                    topology_command_record_digest
                ),
                previous_topology_effect_record_digest=(
                    previous_record_digest
                ),
            )
        except (TypeError, ValueError) as error:
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            ) from error
        result = _commit_event_locked(
            handles,
            binding_snapshot,
            scan,
            event,
            failpoint=failpoint,
        )
        if (
            result.outcome_kind != "lane_event_committed"
            or result.record_digest is None
        ):
            raise ProjectMutationLeaseError(result.detail_code)
        verified = _scan_generation(handles, binding_snapshot)
        records = tuple(
            record
            for record in verified.active_records
            if record.get("record_digest") == result.record_digest
        )
        if verified.status != "active" or len(records) != 1:
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_publication_unverified"
            )
        recorded_event = _event_from_payload(records[0]["event"])
        if (
            type(recorded_event) is not TopologyCommandEffectStarted
            or recorded_event != event
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_publication_unverified"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return _topology_command_effect_started_proof_from_record(
            binding_snapshot,
            recorded_event,
            records[0],
        )
    except (ProjectMutationLeaseError, LaneStoreFailpoint):
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def authenticate_topology_effect_started_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> TopologyEffectStartedLaneProof:
    """Derive the unique active Topology-effect marker from Lane history."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        if (
            scan.status != "active"
            or scan.state is None
            or scan.state.topology_provisioned is not None
            or scan.state.topology_provisioning_claim is None
            or scan.state.topology_effect_started is None
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        current_claim = _historical_claim_from_scan(scan, binding_snapshot)
        marker_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "TopologyEffectStarted"
        )
        marker_index = (
            scan.active_records.index(marker_records[0])
            if len(marker_records) == 1
            else -1
        )
        later_records = (
            tuple(scan.active_records[marker_index + 1 :])
            if marker_index >= 0
            else ()
        )
        if (
            current_claim != authenticated_claim
            or len(marker_records) != 1
            or len(later_records)
            != len(scan.state.topology_command_effects_started)
            or any(
                record.get("event", {}).get("event_type")
                != "TopologyCommandEffectStarted"
                for record in later_records
            )
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        event = _event_from_payload(marker_records[0]["event"])
        if (
            type(event) is not TopologyEffectStarted
            or event != scan.state.topology_effect_started
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return _topology_effect_started_proof_from_record(
            binding_snapshot,
            event,
            marker_records[0],
        )
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _historical_topology_effect_started_from_scan(
    scan: _Scan,
    binding: ValidatedLaneGenerationBinding,
    *,
    allow_reconciliation: bool = False,
) -> TopologyEffectStartedLaneProof:
    """Reconstruct the unique marker even after provisioning consumed claim."""

    allowed_statuses = (
        {"active", "reconciliation_required"}
        if allow_reconciliation
        else {"active"}
    )
    if scan.status not in allowed_statuses or scan.state is None:
        raise _IntegrityError(
            "lane_store.topology_effect_started_proof_mismatch",
            quarantine=False,
        )
    marker_records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "TopologyEffectStarted"
    )
    if len(marker_records) != 1:
        raise _IntegrityError(
            "lane_store.topology_effect_started_proof_mismatch",
            quarantine=False,
        )
    marker_record = marker_records[0]
    event = _event_from_payload(marker_record["event"])
    if (
        type(event) is not TopologyEffectStarted
        or event != scan.state.topology_effect_started
    ):
        raise _IntegrityError(
            "lane_store.topology_effect_started_proof_mismatch",
            quarantine=False,
        )
    return _topology_effect_started_proof_from_record(
        binding,
        event,
        marker_record,
    )


def _authenticate_historical_topology_effect_started_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> TopologyEffectStartedLaneProof:
    """Authenticate the marker for settlement publication or exact replay."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        current_claim = _historical_claim_from_scan(scan, binding_snapshot)
        marker = _historical_topology_effect_started_from_scan(
            scan,
            binding_snapshot,
            allow_reconciliation=True,
        )
        if (
            current_claim != authenticated_claim
            or marker.operation_id != authenticated_claim.operation_id
            or marker.canonical_request_digest
            != authenticated_claim.canonical_request_digest
            or marker.lane_id != authenticated_claim.lane_id
            or marker.lane_generation
            != authenticated_claim.lane_generation
            or marker.attempt_id != authenticated_claim.attempt_id
            or marker.policy_record_digest
            != authenticated_claim.policy_record_digest
            or marker.prepared_lane_record_digest
            != authenticated_claim.prepared_lane_record_digest
            or marker.topology_mutation_id
            != authenticated_claim.topology_mutation_id
            or marker.topology_nonce != authenticated_claim.topology_nonce
            or marker.topology_store_incarnation_digest
            != authenticated_claim.topology_store_incarnation_digest
            or marker.topology_claim_record_digest
            != authenticated_claim.topology_claim_record_digest
            or marker.lane_binding_digest
            != authenticated_claim.lane_binding_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_effect_started_proof_mismatch"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return marker
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _historical_topology_command_effects_started_from_scan(
    scan: _Scan,
    binding: ValidatedLaneGenerationBinding,
    *,
    allow_reconciliation: bool = False,
) -> Tuple[TopologyCommandEffectStartedLaneProof, ...]:
    allowed_statuses = (
        {"active", "reconciliation_required"}
        if allow_reconciliation
        else {"active"}
    )
    if scan.status not in allowed_statuses or scan.state is None:
        raise _IntegrityError(
            "lane_store.topology_command_effect_started_proof_mismatch",
            quarantine=False,
        )
    records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "TopologyCommandEffectStarted"
    )
    events = tuple(
        _event_from_payload(record["event"])
        for record in records
    )
    if (
        any(type(event) is not TopologyCommandEffectStarted for event in events)
        or events != tuple(scan.state.topology_command_effects_started)
    ):
        raise _IntegrityError(
            "lane_store.topology_command_effect_started_proof_mismatch",
            quarantine=False,
        )
    return tuple(
        _topology_command_effect_started_proof_from_record(
            binding,
            event,
            record,
        )
        for event, record in zip(events, records)
    )


def _authenticate_historical_topology_command_effects_started_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> Tuple[TopologyCommandEffectStartedLaneProof, ...]:
    """Authenticate the ordered later-command witnesses for settlement."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding_snapshot,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    first = _authenticate_historical_topology_effect_started_under_lease(
        lease,
        binding_snapshot,
        policy_proof=policy_proof,
        lane_proof=authenticated_claim,
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding_snapshot)
        scan = _scan_generation(handles, binding_snapshot)
        current_claim = _historical_claim_from_scan(scan, binding_snapshot)
        proofs = _historical_topology_command_effects_started_from_scan(
            scan,
            binding_snapshot,
            allow_reconciliation=True,
        )
        if current_claim != authenticated_claim or any(
            proof.operation_id != first.operation_id
            or proof.canonical_request_digest
            != first.canonical_request_digest
            or proof.lane_id != first.lane_id
            or proof.lane_generation != first.lane_generation
            or proof.attempt_id != first.attempt_id
            or proof.policy_record_digest != first.policy_record_digest
            or proof.prepared_lane_record_digest
            != first.prepared_lane_record_digest
            or proof.topology_mutation_id != first.topology_mutation_id
            or proof.topology_nonce != first.topology_nonce
            or proof.topology_store_incarnation_digest
            != first.topology_store_incarnation_digest
            or proof.topology_claim_record_digest
            != first.topology_claim_record_digest
            or proof.topology_mutation_record_digest
            != first.topology_mutation_record_digest
            or proof.topology_effect_started_record_digest
            != first.topology_effect_started_record_digest
            or proof.lane_binding_digest != first.lane_binding_digest
            for proof in proofs
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return proofs
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _provisioned_proof_from_record(
    binding: ValidatedLaneGenerationBinding,
    event: RecordTopologyProvisioned,
    record: Dict[str, Any],
) -> ProvisionedLaneProof:
    return ProvisionedLaneProof(
        operation_id=event.operation_id,
        canonical_request_digest=event.canonical_request_digest,
        lane_id=event.lane_id,
        lane_generation=event.lane_generation,
        attempt_id=event.attempt_id,
        policy_record_digest=event.policy_record_digest,
        prepared_lane_record_digest=event.prepared_lane_record_digest,
        topology_mutation_id=event.topology_mutation_id,
        topology_nonce=event.topology_nonce,
        topology_claim_record_digest=event.topology_claim_record_digest,
        topology_settlement_record_digest=(
            event.topology_settlement_record_digest
        ),
        project_topology_digest=event.project_topology_digest,
        topology_provisioned_record_digest=record["record_digest"],
        lane_state_digest=record["state_after_digest"],
        lane_binding_digest=binding.lane_binding_digest,
        topology_effect_started_record_digest=(
            event.topology_effect_started_record_digest
        ),
        topology_last_command_effect_started_record_digest=(
            event.topology_last_command_effect_started_record_digest
        ),
        recovery_state_digest=event.recovery_state_digest,
        recovery_result_store_binding_digest=(
            event.recovery_result_store_binding_digest
        ),
    )


def _recovery_result_evidence_anchor_proof_from_record(
    binding: ValidatedLaneGenerationBinding,
    event: RecordRecoveryResultEvidenceAnchor,
    record: Dict[str, Any],
) -> _RecoveryResultEvidenceAnchorLaneProof:
    return _RecoveryResultEvidenceAnchorLaneProof(
        project_authority_id=event.project_authority_id,
        recovery_operation_id=event.recovery_operation_id,
        recovery_canonical_request_digest=(
            event.recovery_canonical_request_digest
        ),
        source_lane_operation_id=event.source_lane_operation_id,
        source_lane_canonical_request_digest=(
            event.source_lane_canonical_request_digest
        ),
        attempt_id=event.attempt_id,
        lane_id=event.lane_id,
        lane_generation=event.lane_generation,
        topology_mutation_id=event.topology_mutation_id,
        expected_lane_head_record_digest=(
            event.expected_lane_head_record_digest
        ),
        topology_provisioned_record_digest=(
            event.topology_provisioned_record_digest
        ),
        source_result_record_digest=event.source_result_record_digest,
        recovery_result_store_binding_digest=(
            event.recovery_result_store_binding_digest
        ),
        evidence_registry_binding_digest=(
            event.evidence_registry_binding_digest
        ),
        source_relationship_digest=event.source_relationship_digest,
        evidence_link_record_digest=event.evidence_link_record_digest,
        anchor_event_sequence=record["event_sequence"],
        lane_anchor_record_digest=record["record_digest"],
        lane_state_digest=record["state_after_digest"],
        lane_binding_digest=binding.lane_binding_digest,
    )


def _recovery_result_evidence_anchor_records(
    scan: _Scan,
) -> Tuple[Tuple[Dict[str, Any], RecordRecoveryResultEvidenceAnchor], ...]:
    records: List[
        Tuple[Dict[str, Any], RecordRecoveryResultEvidenceAnchor]
    ] = []
    for record in scan.active_records:
        if record.get("event", {}).get("event_type") != (
            "RecordRecoveryResultEvidenceAnchor"
        ):
            continue
        event = _event_from_payload(record["event"])
        if type(event) is not RecordRecoveryResultEvidenceAnchor:
            raise _IntegrityError(
                "lane_store.recovery_result_evidence_anchor_invalid"
            )
        records.append((record, event))
    return tuple(records)


def _topology_recovery_lane_evidence_from_scan(
    scan: _Scan,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> _TopologyRecoveryLaneEvidence:
    """Project one active scan into exact, non-authorizing recovery facts."""

    if scan.status != "active" or scan.state is None:
        raise _IntegrityError("lane_store.topology_recovery_history_invalid")

    claim_records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "ClaimTopologyProvisioning"
    )
    if len(claim_records) != 1:
        raise _IntegrityError("lane_store.topology_claim_proof_mismatch")
    claim_event = _event_from_payload(claim_records[0]["event"])
    if type(claim_event) is not ClaimTopologyProvisioning:
        raise _IntegrityError("lane_store.topology_claim_proof_mismatch")
    try:
        claim = _historical_claim_from_scan(scan, binding)
    except _IntegrityError as error:
        raise _IntegrityError(error.code) from error
    if claim != lane_proof or (
        policy_proof.project_authority_id != binding.project_authority_id
        or policy_proof.operation_id != claim.operation_id
        or policy_proof.canonical_request_digest
        != claim.canonical_request_digest
        or policy_proof.policy_record_digest != claim.policy_record_digest
    ):
        raise _IntegrityError("lane_store.topology_claim_proof_mismatch")

    marker_records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "TopologyEffectStarted"
    )
    if len(marker_records) > 1:
        raise _IntegrityError(
            "lane_store.topology_effect_started_proof_mismatch"
        )
    if marker_records:
        try:
            first_effect = _historical_topology_effect_started_from_scan(
                scan,
                binding,
            )
        except _IntegrityError as error:
            raise _IntegrityError(error.code) from error
    else:
        first_effect = None
        if scan.state.topology_effect_started is not None:
            raise _IntegrityError(
                "lane_store.topology_effect_started_proof_mismatch"
            )

    try:
        later_effects = (
            _historical_topology_command_effects_started_from_scan(
                scan,
                binding,
            )
        )
    except _IntegrityError as error:
        raise _IntegrityError(error.code) from error

    common_fields = (
        "operation_id",
        "canonical_request_digest",
        "lane_id",
        "lane_generation",
        "attempt_id",
        "policy_record_digest",
        "prepared_lane_record_digest",
        "topology_mutation_id",
        "topology_nonce",
        "topology_claim_record_digest",
        "lane_binding_digest",
    )
    if first_effect is not None and (
        any(
            getattr(first_effect, field) != getattr(claim, field)
            for field in common_fields
        )
        or first_effect.topology_store_incarnation_digest
        != claim.topology_store_incarnation_digest
        or first_effect.topology_effect_started_record_digest
        != marker_records[0]["record_digest"]
    ):
        raise _IntegrityError(
            "lane_store.topology_effect_started_proof_mismatch"
        )
    if later_effects and first_effect is None:
        raise _IntegrityError(
            "lane_store.topology_command_effect_started_proof_mismatch"
        )

    seen_step_ids = set()
    previous_effect_record_digest = (
        first_effect.topology_effect_started_record_digest
        if first_effect is not None
        else None
    )
    for index, effect in enumerate(later_effects, start=2):
        if (
            first_effect is None
            or any(
                getattr(effect, field) != getattr(claim, field)
                for field in common_fields
            )
            or effect.topology_store_incarnation_digest
            != claim.topology_store_incarnation_digest
            or effect.topology_mutation_record_digest
            != first_effect.topology_mutation_record_digest
            or effect.topology_effect_started_record_digest
            != first_effect.topology_effect_started_record_digest
            or effect.command_sequence != index
            or effect.topology_command_step_id in seen_step_ids
            or effect.previous_topology_effect_record_digest
            != previous_effect_record_digest
        ):
            raise _IntegrityError(
                "lane_store.topology_command_effect_started_proof_mismatch"
            )
        seen_step_ids.add(effect.topology_command_step_id)
        previous_effect_record_digest = (
            effect.topology_command_effect_started_record_digest
        )

    provisioned_records = tuple(
        record
        for record in scan.active_records
        if record.get("event", {}).get("event_type")
        == "RecordTopologyProvisioned"
    )
    if len(provisioned_records) > 1:
        raise _IntegrityError(
            "lane_store.topology_provisioned_proof_mismatch"
        )
    if provisioned_records:
        provisioned_event = _event_from_payload(
            provisioned_records[0]["event"]
        )
        if (
            type(provisioned_event) is not RecordTopologyProvisioned
            or provisioned_event != scan.state.topology_provisioned
        ):
            raise _IntegrityError(
                "lane_store.topology_provisioned_proof_mismatch"
            )
        provisioned = _provisioned_proof_from_record(
            binding,
            provisioned_event,
            provisioned_records[0],
        )
        if (
            any(
                getattr(provisioned, field) != getattr(claim, field)
                for field in common_fields
            )
            or provisioned.topology_effect_started_record_digest
            != (
                first_effect.topology_effect_started_record_digest
                if first_effect is not None
                else None
            )
            or provisioned.topology_last_command_effect_started_record_digest
            != (
                later_effects[-1]
                .topology_command_effect_started_record_digest
                if later_effects
                else None
            )
        ):
            raise _IntegrityError(
                "lane_store.topology_provisioned_proof_mismatch"
            )
        if scan.state.topology_provisioning_claim is not None:
            raise _IntegrityError(
                "lane_store.topology_provisioned_proof_mismatch"
            )
    else:
        provisioned = None
        if (
            scan.state.topology_provisioned is not None
            or scan.state.topology_provisioning_claim != claim_event
        ):
            raise _IntegrityError("lane_store.topology_claim_proof_mismatch")

    record_digests = tuple(
        record["record_digest"] for record in scan.active_records
    )
    head = scan.head
    if (
        not record_digests
        or head is None
        or head.get("event_sequence") != len(record_digests)
        or head.get("event_digest") != record_digests[-1]
        or head.get("state_digest")
        != scan.active_records[-1].get("state_after_digest")
    ):
        raise _IntegrityError("lane_store.topology_recovery_history_invalid")
    return _TopologyRecoveryLaneEvidence(
        claim=claim,
        first_effect=first_effect,
        later_effects=later_effects,
        provisioned=provisioned,
        lane_record_digests=record_digests,
        head_record_digest=head["event_digest"],
        head_state_digest=head["state_digest"],
        lane_binding_digest=binding.lane_binding_digest,
    )


def _topology_recovery_residue_state_digest(scan: _Scan) -> str:
    """Digest candidate observations without treating their names as proof."""

    return _digest_json(
        {
            "schema": "ask_herdr.lane_recovery_residue.internal.v1",
            "event_candidate_names": list(scan.event_candidates),
            "response_candidate_names": list(scan.response_candidates),
            "pending_record_observed": scan.pending_record is not None,
            "pending_record_digest": (
                _digest_json(scan.pending_record)
                if scan.pending_record is not None
                else None
            ),
        }
    )


def _resolve_topology_recovery_lane_under_lease(
    lease: Any,
    project_binding: Any,
    *,
    lane_id: str,
    lane_generation: int,
    allow_single_event_candidate: bool = False,
) -> _ResolvedTopologyRecoveryLane:
    """Derive one historical Lane claim solely from its named generation."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        ValidatedProjectMutationBinding,
        _borrow_validated_root,
    )

    if type(project_binding) is not ValidatedProjectMutationBinding:
        raise ProjectMutationLeaseError("lane_store.recovery_input_invalid")
    try:
        project_snapshot = ValidatedProjectMutationBinding(
            **dict(vars(project_binding))
        )
        _require_uuid(lane_id, "lane_store.lane_id_invalid")
        if type(lane_generation) is not int or lane_generation < 1:
            raise ValueError("lane_store.lane_generation_invalid")
    except (AttributeError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "lane_store.recovery_input_invalid"
        ) from error

    root = _borrow_validated_root(lease, project_snapshot)
    opened: List[int] = []
    handles: Optional[_Handles] = None
    try:
        if _detect_legacy_v1(root):
            raise _IntegrityError(
                "layout_v1_migration_required",
                quarantine=False,
            )
        try:
            store = _open_directory(root, STORE_NAME)
        except FileNotFoundError as error:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_store_missing"
            ) from error
        opened.append(store)
        _validate_store_binding(store, project_snapshot)

        generations = _open_directory(store, GENERATIONS_NAME)
        opened.append(generations)
        generation_name = "{}.g{}".format(lane_id, lane_generation)
        try:
            generation = _open_directory(generations, generation_name)
        except FileNotFoundError as error:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_generation_missing"
            ) from error
        opened.append(generation)
        if set(os.listdir(generation)) != {BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError("lane_store.generation_layout_invalid")
        generation_payload, _ = _read_json(generation, BINDING_NAME)
        try:
            binding = ValidatedLaneGenerationBinding(
                canonical_root=project_snapshot.canonical_root,
                filesystem_device=project_snapshot.filesystem_device,
                filesystem_inode=project_snapshot.filesystem_inode,
                owner_uid=project_snapshot.owner_uid,
                project_authority_id=project_snapshot.project_authority_id,
                lane_id=lane_id,
                lane_generation=lane_generation,
                lane_binding_digest=generation_payload[
                    "lane_binding_digest"
                ],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise _IntegrityError(
                "lane_store.generation_binding_conflict"
            ) from error
        if generation_payload != _generation_binding_payload(binding):
            raise _IntegrityError(
                "lane_store.generation_binding_conflict"
            )

        transactions = _open_directory(generation, TRANSACTIONS_NAME)
        opened.append(transactions)
        handles = _Handles(
            root,
            store,
            generations,
            generation,
            transactions,
        )
        opened.clear()
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active",
                state_status="reconciliation_required",
            ) from error

        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        candidate_retry = bool(
            allow_single_event_candidate
            and type(allow_single_event_candidate) is bool
            and len(scan.event_candidates) == 1
            and not scan.response_candidates
            and scan.pending_record is None
        )
        if (
            scan.event_candidates
            or scan.response_candidates
            or scan.pending_record is not None
        ) and not candidate_retry:
            raise ProjectMutationLeaseError(
                "lane_store.topology_recovery_candidate_residue",
                state_status="reconciliation_required",
            )
        if scan.status != "active" and not (
            candidate_retry and scan.status == "reconciliation_required"
        ):
            raise ProjectMutationLeaseError(
                scan.detail_code,
                state_status=(
                    "reconciliation_required"
                    if scan.status == "reconciliation_required"
                    else "quarantined"
                ),
            )
        lane_proof = _historical_claim_from_scan(scan, binding)
        if (
            lane_proof.lane_id != lane_id
            or lane_proof.lane_generation != lane_generation
            or lane_proof.lane_binding_digest
            != binding.lane_binding_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        _validate_store_binding(handles.store, binding)
        current_generation_payload, _ = _read_json(
            handles.generation,
            BINDING_NAME,
        )
        if current_generation_payload != _generation_binding_payload(binding):
            raise ProjectMutationLeaseError(
                "lane_store.generation_binding_conflict"
            )
        if not _handles_still_bound(handles, binding):
            raise ProjectMutationLeaseError("lane_store.store_changed")
        _borrow_validated_root(lease, project_snapshot)
        return _ResolvedTopologyRecoveryLane(
            binding=binding,
            lane_proof=lane_proof,
        )
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(
            code,
            state_status=(
                "quarantined"
                if isinstance(error, _IntegrityError) and error.quarantine
                else "reconciliation_required"
                if isinstance(error, _IntegrityError)
                else "quarantined"
            ),
        ) from error
    finally:
        if handles is not None:
            _close_handles(handles)
        else:
            for descriptor in reversed(opened):
                os.close(descriptor)


def _inspect_topology_recovery_lane_under_lease_impl(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
    allow_single_evidence_anchor_candidate: bool,
    allow_pending_policy_content_access: bool,
) -> _TopologyRecoveryLaneInspection:
    """Replay one Lane Generation once without granting recovery authority."""

    from ask_herdr_policy_ledger import (  # noqa: PLC0415
        _authenticate_committed_human_admission_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_lane_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    if type(lane_proof) is not ClaimedLaneProof:
        raise ProjectMutationLeaseError(
            "lane_store.topology_claim_proof_mismatch"
        )
    try:
        lane_snapshot = ClaimedLaneProof(**dict(vars(lane_proof)))
    except (TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "lane_store.topology_claim_proof_mismatch"
        ) from error
    authenticated_policy = (
        _authenticate_committed_human_admission_proof_under_lease(
            lease,
            policy_proof,
            allow_pending_content_access=(
                allow_pending_policy_content_access
            ),
        )
    )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        try:
            handles = _open_existing_handles(root, binding_snapshot)
            if handles is None:
                result = _TopologyRecoveryLaneInspection(
                    "quarantined",
                    "lane_store.topology_claim_proof_mismatch",
                    None,
                )
            else:
                try:
                    fcntl.flock(
                        handles.generation,
                        fcntl.LOCK_SH | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    result = _TopologyRecoveryLaneInspection(
                        "reconciliation_required",
                        "lane_store.writer_active",
                        None,
                    )
                else:
                    _barrier_store_tree(handles, binding_snapshot)
                    scan = _scan_generation(handles, binding_snapshot)
                    has_residue = bool(
                        scan.event_candidates
                        or scan.response_candidates
                        or scan.pending_record is not None
                    )
                    allowed_anchor_residue = bool(
                        allow_single_evidence_anchor_candidate
                        and type(allow_single_evidence_anchor_candidate)
                        is bool
                        and len(scan.event_candidates) == 1
                        and EVIDENCE_ANCHOR_CANDIDATE_PATTERN.fullmatch(
                            scan.event_candidates[0]
                        )
                        is not None
                        and not scan.response_candidates
                        and scan.pending_record is None
                    )
                    if has_residue and not allowed_anchor_residue:
                        result = _TopologyRecoveryLaneInspection(
                            "reconciliation_required",
                            "lane_store.topology_recovery_candidate_residue",
                            None,
                            _topology_recovery_residue_state_digest(scan),
                        )
                    elif (
                        scan.status == "reconciliation_required"
                        and not allowed_anchor_residue
                    ):
                        result = _TopologyRecoveryLaneInspection(
                            "reconciliation_required",
                            scan.detail_code,
                            None,
                        )
                    elif scan.status == "quarantined":
                        result = _TopologyRecoveryLaneInspection(
                            "quarantined",
                            scan.detail_code,
                            None,
                        )
                    elif scan.status != "active" and not allowed_anchor_residue:
                        result = _TopologyRecoveryLaneInspection(
                            "quarantined",
                            "lane_store.topology_claim_proof_mismatch",
                            None,
                        )
                    else:
                        result = _TopologyRecoveryLaneInspection(
                            "active",
                            "lane_store.topology_recovery_active",
                            _topology_recovery_lane_evidence_from_scan(
                                (
                                    replace(
                                        scan,
                                        status="active",
                                        detail_code=(
                                            "lane_store."
                                            "topology_recovery_active"
                                        ),
                                    )
                                    if allowed_anchor_residue
                                    else scan
                                ),
                                binding_snapshot,
                                policy_proof=authenticated_policy,
                                lane_proof=lane_snapshot,
                            ),
                        )
        except _IntegrityError as error:
            result = _TopologyRecoveryLaneInspection(
                "quarantined"
                if error.quarantine
                else "reconciliation_required",
                error.code,
                None,
            )
        except (OSError, StrictJsonError):
            result = _TopologyRecoveryLaneInspection(
                "quarantined",
                "lane_store.storage_integrity_failure",
                None,
            )

        if handles is not None and not _handles_still_bound(
            handles,
            binding_snapshot,
        ):
            result = _TopologyRecoveryLaneInspection(
                "reconciliation_required",
                "lane_store.store_changed",
                None,
            )
        _borrow_validated_root(lease, binding_snapshot)
        return result
    finally:
        if handles is not None:
            _close_handles(handles)


def _inspect_topology_recovery_lane_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> _TopologyRecoveryLaneInspection:
    """Replay the ordinary Recovery Lane contract without candidate waiver."""

    return _inspect_topology_recovery_lane_under_lease_impl(
        lease,
        binding,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
        allow_single_evidence_anchor_candidate=False,
        allow_pending_policy_content_access=False,
    )


def _inspect_topology_recovery_lane_for_evidence_anchor_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> _TopologyRecoveryLaneInspection:
    """Replay historical Recovery facts across one anchor-only candidate."""

    return _inspect_topology_recovery_lane_under_lease_impl(
        lease,
        binding,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
        allow_single_evidence_anchor_candidate=True,
        allow_pending_policy_content_access=False,
    )


def _inspect_topology_recovery_lane_for_content_access_under_lease(
    lease: Any,
    binding: ValidatedLaneGenerationBinding,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
) -> _TopologyRecoveryLaneInspection:
    """Replay historical Recovery facts across one pending access tail."""

    return _inspect_topology_recovery_lane_under_lease_impl(
        lease,
        binding,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
        allow_single_evidence_anchor_candidate=False,
        allow_pending_policy_content_access=True,
    )


def _inspect_recovery_result_evidence_anchor_under_lease(
    lease: Any,
    lane_binding: ValidatedLaneGenerationBinding,
    recovery_operation_id: str,
) -> _RecoveryResultEvidenceAnchorLaneInspection:
    """Inspect one historical Lane-owned Evidence-link anchor."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding = _snapshot_validated_lane_binding(lane_binding)
        _require_uuid(
            recovery_operation_id,
            "lane_store.recovery_operation_id_invalid",
        )
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.recovery_evidence_input_invalid"
        ) from error
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            return _RecoveryResultEvidenceAnchorLaneInspection(
                "quarantined",
                "lane_store.recovery_evidence_lane_missing",
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_SH | fcntl.LOCK_NB,
            )
        except BlockingIOError:
            return _RecoveryResultEvidenceAnchorLaneInspection(
                "reconciliation_required",
                "lane_store.writer_active",
            )
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        if scan.status != "active":
            return _RecoveryResultEvidenceAnchorLaneInspection(
                (
                    "reconciliation_required"
                    if scan.status == "reconciliation_required"
                    else "quarantined"
                ),
                scan.detail_code,
            )
        anchors = _recovery_result_evidence_anchor_records(scan)
        if scan.state is None or tuple(
            event for _, event in anchors
        ) != scan.state.recovery_result_evidence_anchors:
            return _RecoveryResultEvidenceAnchorLaneInspection(
                "quarantined",
                "lane_store.recovery_result_evidence_anchor_invalid",
            )
        matching = tuple(
            item
            for item in anchors
            if item[1].recovery_operation_id == recovery_operation_id
        )
        if not matching:
            result = _RecoveryResultEvidenceAnchorLaneInspection(
                "absent",
                "lane_store.recovery_result_evidence_anchor_absent",
            )
        elif len(matching) != 1:
            result = _RecoveryResultEvidenceAnchorLaneInspection(
                "quarantined",
                "lane_store.recovery_result_evidence_anchor_conflict",
            )
        else:
            record, event = matching[0]
            result = _RecoveryResultEvidenceAnchorLaneInspection(
                "anchored",
                "lane_store.recovery_result_evidence_anchored",
                _recovery_result_evidence_anchor_proof_from_record(
                    binding,
                    event,
                    record,
                ),
            )
        if not _handles_still_bound(handles, binding):
            return _RecoveryResultEvidenceAnchorLaneInspection(
                "reconciliation_required",
                "lane_store.store_changed",
            )
        _borrow_validated_root(lease, binding)
        return result
    except (_IntegrityError, OSError, StrictJsonError) as error:
        return _RecoveryResultEvidenceAnchorLaneInspection(
            (
                "quarantined"
                if not isinstance(error, _IntegrityError) or error.quarantine
                else "reconciliation_required"
            ),
            (
                error.code
                if isinstance(error, _IntegrityError)
                else "lane_store.storage_integrity_failure"
            ),
        )
    finally:
        if handles is not None:
            _close_handles(handles)


def _record_recovery_result_evidence_anchor_under_lease(
    lease: Any,
    lane_binding: ValidatedLaneGenerationBinding,
    *,
    provisioned_proof: ProvisionedLaneProof,
    recovery_operation_id: str,
    recovery_canonical_request_digest: str,
    source_result_record_digest: str,
    evidence_registry_binding_digest: str,
    source_relationship_digest: str,
    evidence_link_record_digest: str,
    failpoint: Any = None,
) -> _RecoveryResultEvidenceAnchorLaneProof:
    """Append or exactly replay one pre-publication Evidence-link anchor."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding = _snapshot_validated_lane_binding(lane_binding)
        if type(provisioned_proof) is not ProvisionedLaneProof:
            raise ValueError
        provisioned = ProvisionedLaneProof(
            **dict(vars(provisioned_proof))
        )
        _require_uuid(
            recovery_operation_id,
            "lane_store.recovery_operation_id_invalid",
        )
        for value, code in (
            (
                recovery_canonical_request_digest,
                "lane_store.recovery_request_digest_invalid",
            ),
            (
                source_result_record_digest,
                "lane_store.source_result_record_digest_invalid",
            ),
            (
                evidence_registry_binding_digest,
                "lane_store.evidence_registry_binding_digest_invalid",
            ),
            (
                source_relationship_digest,
                "lane_store.source_relationship_digest_invalid",
            ),
            (
                evidence_link_record_digest,
                "lane_store.evidence_link_record_digest_invalid",
            ),
        ):
            _require_digest(value, code)
    except (AttributeError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "lane_store.recovery_evidence_input_invalid"
        ) from error
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_lane_missing"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active",
                state_status="reconciliation_required",
            ) from error
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        has_residue = bool(
            scan.event_candidates
            or scan.response_candidates
            or scan.pending_record is not None
        )
        if (
            scan.status != "active"
            or has_residue
        ):
            raise ProjectMutationLeaseError(
                (
                    scan.detail_code
                    if scan.status != "active"
                    else "lane_store.recovery_evidence_candidate_residue"
                ),
                state_status=(
                    "reconciliation_required"
                    if scan.status == "reconciliation_required" or has_residue
                    else "quarantined"
                ),
            )
        if scan.state is None or not scan.active_records:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_source_mismatch"
            )
        provisioned_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "RecordTopologyProvisioned"
        )
        if len(provisioned_records) != 1:
            raise ProjectMutationLeaseError(
                "lane_store.topology_provisioned_proof_mismatch"
            )
        provisioned_event = _event_from_payload(
            provisioned_records[0]["event"]
        )
        if (
            type(provisioned_event) is not RecordTopologyProvisioned
            or _provisioned_proof_from_record(
                binding,
                provisioned_event,
                provisioned_records[0],
            )
            != provisioned
            or provisioned.recovery_result_store_binding_digest is None
        ):
            raise ProjectMutationLeaseError(
                "lane_store.topology_provisioned_proof_mismatch"
            )
        matching_anchors = tuple(
            (record, recorded_event)
            for record, recorded_event in (
                _recovery_result_evidence_anchor_records(scan)
            )
            if recorded_event.recovery_operation_id
            == recovery_operation_id
        )
        if len(matching_anchors) > 1:
            raise ProjectMutationLeaseError(
                "lane_turn.recovery_result_evidence_link_conflict"
            )
        expected_lane_head_record_digest = (
            matching_anchors[0][1].expected_lane_head_record_digest
            if matching_anchors
            else scan.active_records[-1]["record_digest"]
        )
        event = RecordRecoveryResultEvidenceAnchor(
            project_authority_id=binding.project_authority_id,
            recovery_operation_id=recovery_operation_id,
            recovery_canonical_request_digest=(
                recovery_canonical_request_digest
            ),
            source_lane_operation_id=provisioned.operation_id,
            source_lane_canonical_request_digest=(
                provisioned.canonical_request_digest
            ),
            attempt_id=provisioned.attempt_id,
            lane_id=provisioned.lane_id,
            lane_generation=provisioned.lane_generation,
            topology_mutation_id=provisioned.topology_mutation_id,
            expected_lane_head_record_digest=(
                expected_lane_head_record_digest
            ),
            topology_provisioned_record_digest=(
                provisioned.topology_provisioned_record_digest
            ),
            source_result_record_digest=source_result_record_digest,
            recovery_result_store_binding_digest=(
                provisioned.recovery_result_store_binding_digest
            ),
            evidence_registry_binding_digest=(
                evidence_registry_binding_digest
            ),
            source_relationship_digest=source_relationship_digest,
            evidence_link_record_digest=evidence_link_record_digest,
        )
        if matching_anchors:
            record, recorded_event = matching_anchors[0]
            if recorded_event != event:
                raise ProjectMutationLeaseError(
                    "lane_turn.recovery_result_evidence_link_conflict"
                )
            proof = _recovery_result_evidence_anchor_proof_from_record(
                binding,
                recorded_event,
                record,
            )
            if not _handles_still_bound(handles, binding):
                raise ProjectMutationLeaseError(
                    "lane_store.store_changed",
                    state_status="reconciliation_required",
                )
            _borrow_validated_root(lease, binding)
            return proof
        result = _commit_event_locked(
            handles,
            binding,
            scan,
            event,
            failpoint=failpoint,
        )
        if (
            result.outcome_kind
            not in {"lane_event_committed", "lane_event_already_committed"}
            or result.record_digest is None
        ):
            raise ProjectMutationLeaseError(
                result.detail_code,
                state_status=(
                    "reconciliation_required"
                    if "reconciliation" in result.outcome_kind
                    else "quarantined"
                ),
            )
        verified = _scan_generation(handles, binding)
        matching = tuple(
            (record, recorded_event)
            for record, recorded_event in (
                _recovery_result_evidence_anchor_records(verified)
            )
            if recorded_event.recovery_operation_id
            == recovery_operation_id
        )
        if (
            verified.status != "active"
            or len(matching) != 1
            or matching[0][1] != event
            or matching[0][0].get("record_digest")
            != result.record_digest
        ):
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_anchor_unverified"
            )
        proof = _recovery_result_evidence_anchor_proof_from_record(
            binding,
            matching[0][1],
            matching[0][0],
        )
        if not _handles_still_bound(handles, binding):
            raise ProjectMutationLeaseError(
                "lane_store.store_changed",
                state_status="reconciliation_required",
            )
        _borrow_validated_root(lease, binding)
        return proof
    except (ProjectMutationLeaseError, LaneStoreFailpoint):
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        raise ProjectMutationLeaseError(
            (
                error.code
                if isinstance(error, _IntegrityError)
                else "lane_store.storage_integrity_failure"
            ),
            state_status=(
                "quarantined"
                if not isinstance(error, _IntegrityError) or error.quarantine
                else "reconciliation_required"
            ),
        ) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _discard_unanchored_recovery_result_evidence_anchor_candidate_under_lease(
    lease: Any,
    lane_binding: ValidatedLaneGenerationBinding,
    recovery_operation_id: str,
) -> None:
    """Discard only one operation-bound, nonauthoritative anchor candidate."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding = _snapshot_validated_lane_binding(lane_binding)
        _require_uuid(
            recovery_operation_id,
            "lane_store.recovery_operation_id_invalid",
        )
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.recovery_evidence_input_invalid"
        ) from error
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    candidate = -1
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_lane_missing"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active",
                state_status="reconciliation_required",
            ) from error
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        if any(
            event.recovery_operation_id == recovery_operation_id
            for _, event in _recovery_result_evidence_anchor_records(scan)
        ):
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_anchor_already_committed"
            )
        matching = tuple(
            name
            for name in scan.event_candidates
            if (
                (match := EVIDENCE_ANCHOR_CANDIDATE_PATTERN.fullmatch(name))
                is not None
                and match.group("operation_id") == recovery_operation_id
            )
        )
        if (
            len(matching) != 1
            or len(scan.event_candidates) != 1
            or scan.response_candidates
            or scan.pending_record is not None
        ):
            raise ProjectMutationLeaseError(
                "lane_store.recovery_evidence_candidate_residue",
                state_status="reconciliation_required",
            )
        candidate_name = matching[0]
        candidate = _open_directory(handles.transactions, candidate_name)
        if not _directory_binding(
            handles.transactions,
            candidate_name,
            candidate,
        ):
            raise _IntegrityError(
                "lane_store.recovery_evidence_candidate_changed"
            )
        entries = set(os.listdir(candidate))
        if entries not in (set(), {"event.json"}):
            raise _IntegrityError(
                "lane_store.recovery_evidence_candidate_changed"
            )
        if entries:
            _read_file(candidate, "event.json", MAX_RECORD_BYTES)
            os.unlink("event.json", dir_fd=candidate)
            _sync_directory(candidate)
        os.rmdir(candidate_name, dir_fd=handles.transactions)
        _sync_directory(handles.transactions)
        if not _handles_still_bound(handles, binding):
            raise ProjectMutationLeaseError(
                "lane_store.store_changed",
                state_status="reconciliation_required",
            )
        verified = _scan_generation(handles, binding)
        if verified.status != "active":
            raise ProjectMutationLeaseError(
                verified.detail_code,
                state_status="reconciliation_required",
            )
        _borrow_validated_root(lease, binding)
    except (ProjectMutationLeaseError, _IntegrityError, OSError, StrictJsonError) as error:
        operation_error = error
        if isinstance(error, ProjectMutationLeaseError):
            raise
        raise ProjectMutationLeaseError(
            (
                error.code
                if isinstance(error, _IntegrityError)
                else "lane_store.storage_integrity_failure"
            ),
            state_status=(
                "quarantined"
                if not isinstance(error, _IntegrityError) or error.quarantine
                else "reconciliation_required"
            ),
        ) from error
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if candidate >= 0:
            try:
                os.close(candidate)
            except OSError:
                if operation_error is None:
                    raise
        if handles is not None:
            _close_handles(handles)


def record_topology_provisioned_under_lease(
    lease: Any,
    lane_binding: ValidatedLaneGenerationBinding,
    topology_binding: Any,
    *,
    policy_proof: Any,
    lane_proof: ClaimedLaneProof,
    recovery_state_digest: Optional[str] = None,
    recovery_result_store_binding_digest: Optional[str] = None,
    failpoint: Any = None,
) -> ProvisionedLaneProof:
    """Append one Lane provisioning fact from replayed Topology settlement."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )
    from ask_herdr_topology_store import (  # noqa: PLC0415
        _authenticate_lane_settlement_under_lease,
    )

    if recovery_state_digest is not None:
        try:
            _require_digest(
                recovery_state_digest,
                "lane_store.recovery_state_digest_invalid",
            )
        except ValueError as error:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_state_digest_invalid"
            ) from error
    if recovery_result_store_binding_digest is not None:
        try:
            _require_digest(
                recovery_result_store_binding_digest,
                "lane_store.recovery_result_store_binding_digest_invalid",
            )
        except ValueError as error:
            raise ProjectMutationLeaseError(
                "lane_store.recovery_result_store_binding_digest_invalid"
            ) from error
    try:
        binding = _snapshot_validated_lane_binding(lane_binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "lane_store.binding_type_invalid"
        ) from error
    authenticated_claim = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            binding,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    effect_started_proof = None
    command_effect_started_proofs: Tuple[
        TopologyCommandEffectStartedLaneProof, ...
    ] = ()
    if authenticated_claim.topology_store_incarnation_digest is not None:
        effect_started_proof = (
            _authenticate_historical_topology_effect_started_under_lease(
                lease,
                binding,
                policy_proof=policy_proof,
                lane_proof=authenticated_claim,
            )
        )
        command_effect_started_proofs = (
            _authenticate_historical_topology_command_effects_started_under_lease(
                lease,
                binding,
                policy_proof=policy_proof,
                lane_proof=authenticated_claim,
            )
        )
    settlement = _authenticate_lane_settlement_under_lease(
        lease,
        topology_binding,
        lane_proof=authenticated_claim,
        effect_started_proof=effect_started_proof,
        command_effect_started_proofs=command_effect_started_proofs,
    )
    if settlement.mutation_id != authenticated_claim.topology_mutation_id:
        raise ProjectMutationLeaseError(
            "topology_store.settlement_lane_mismatch"
        )
    root = _borrow_validated_root(lease, binding)
    handles: Optional[_Handles] = None
    try:
        handles = _open_existing_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        try:
            fcntl.flock(
                handles.generation,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        except BlockingIOError as error:
            raise ProjectMutationLeaseError(
                "lane_store.writer_active"
            ) from error
        _barrier_store_tree(handles, binding)
        scan = _scan_generation(handles, binding)
        if scan.response_candidates:
            raise ProjectMutationLeaseError(
                "lane_store.response_candidate_residue"
            )
        current_claim = _historical_claim_from_scan(scan, binding)
        if current_claim != authenticated_claim:
            raise ProjectMutationLeaseError(
                "lane_store.topology_claim_proof_mismatch"
            )
        effect_started_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "TopologyEffectStarted"
        )
        current_command_effect_started_proofs = (
            _historical_topology_command_effects_started_from_scan(
                scan,
                binding,
                allow_reconciliation=True,
            )
        )
        if authenticated_claim.topology_store_incarnation_digest is None:
            if (
                effect_started_records
                or current_command_effect_started_proofs
                or command_effect_started_proofs
            ):
                raise ProjectMutationLeaseError(
                    "lane_store.topology_effect_started_proof_mismatch"
                )
            effect_started_record_digest = None
            last_command_effect_started_record_digest = None
        else:
            if len(effect_started_records) != 1:
                raise ProjectMutationLeaseError(
                    "lane_store.topology_effect_started_proof_mismatch"
                )
            if (
                current_command_effect_started_proofs
                != command_effect_started_proofs
            ):
                raise ProjectMutationLeaseError(
                    "lane_store.topology_command_effect_started_proof_mismatch"
                )
            last_command_effect_started_record_digest = (
                command_effect_started_proofs[-1]
                .topology_command_effect_started_record_digest
                if command_effect_started_proofs
                else None
            )
            effect_started = _event_from_payload(
                effect_started_records[0]["event"]
            )
            if (
                type(effect_started) is not TopologyEffectStarted
                or effect_started
                != scan.state.topology_effect_started
            ):
                raise ProjectMutationLeaseError(
                    "lane_store.topology_effect_started_proof_mismatch"
                )
            effect_started_record_digest = effect_started_records[0][
                "record_digest"
            ]
            if (
                effect_started_proof is None
                or effect_started_record_digest
                != effect_started_proof.topology_effect_started_record_digest
                or effect_started_proof.topology_mutation_record_digest
                != settlement.mutation_record_digest
                or effect_started_proof.first_topology_command_record_digest
                != settlement.first_command_record_digest
                or effect_started_proof.topology_store_incarnation_digest
                != settlement.topology_store_incarnation_digest
            ):
                raise ProjectMutationLeaseError(
                    "lane_store.topology_effect_started_proof_mismatch"
                )
        event = RecordTopologyProvisioned(
            operation_id=authenticated_claim.operation_id,
            canonical_request_digest=(
                authenticated_claim.canonical_request_digest
            ),
            attempt_id=authenticated_claim.attempt_id,
            lane_id=authenticated_claim.lane_id,
            lane_generation=authenticated_claim.lane_generation,
            policy_record_digest=authenticated_claim.policy_record_digest,
            prepared_lane_record_digest=(
                authenticated_claim.prepared_lane_record_digest
            ),
            topology_mutation_id=authenticated_claim.topology_mutation_id,
            topology_nonce=authenticated_claim.topology_nonce,
            topology_claim_record_digest=(
                authenticated_claim.topology_claim_record_digest
            ),
            topology_settlement_record_digest=(
                settlement.settlement_record_digest
            ),
            project_topology_digest=settlement.project_topology_digest,
            topology_effect_started_record_digest=(
                effect_started_record_digest
            ),
            topology_last_command_effect_started_record_digest=(
                last_command_effect_started_record_digest
            ),
            recovery_state_digest=recovery_state_digest,
            recovery_result_store_binding_digest=(
                recovery_result_store_binding_digest
            ),
        )
        provisioned_records = tuple(
            record
            for record in scan.active_records
            if record.get("event", {}).get("event_type")
            == "RecordTopologyProvisioned"
        )
        if provisioned_records:
            if len(provisioned_records) != 1:
                raise ProjectMutationLeaseError(
                    "lane_store.topology_provisioned_proof_mismatch"
                )
            recorded_event = _event_from_payload(
                provisioned_records[0]["event"]
            )
            if recorded_event != event:
                raise ProjectMutationLeaseError(
                    "lane_store.topology_provisioned_proof_mismatch"
                )
            # Do not return directly from the historical-record branch.
            # Exact replay must pass through the Lane Store's ordinary commit
            # verifier so a promoted winner receives its recovery durability
            # barriers and any unrelated candidate residue fails closed.
        result = _commit_event_locked(
            handles,
            binding,
            scan,
            event,
            failpoint=failpoint,
        )
        if (
            result.outcome_kind
            not in {"lane_event_committed", "lane_event_already_committed"}
            or result.record_digest is None
            or result.state is None
        ):
            raise ProjectMutationLeaseError(result.detail_code)
        verified = _scan_generation(handles, binding)
        records = tuple(
            record
            for record in verified.active_records
            if record.get("record_digest") == result.record_digest
        )
        if len(records) != 1:
            raise ProjectMutationLeaseError(
                "lane_store.topology_provisioned_publication_unverified"
            )
        recorded_event = _event_from_payload(records[0]["event"])
        if recorded_event != event:
            raise ProjectMutationLeaseError(
                "lane_store.topology_provisioned_publication_unverified"
            )
        _borrow_validated_root(lease, binding)
        return _provisioned_proof_from_record(
            binding,
            recorded_event,
            records[0],
        )
    except (ProjectMutationLeaseError, LaneStoreFailpoint):
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "lane_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _new_dialogue_head(
    state: LaneTurnState,
    final: ValidatedFinalResponse,
    response_digest: str,
) -> str:
    return _digest_json(
        {
            "schema": "ask_herdr.dialogue_head_derivation.internal.v1",
            "previous_head_digest": state.expected_head_digest,
            "operation_id": state.operation_id,
            "turn_id": final.turn_id,
            "turn_sequence": final.turn_sequence,
            "native_correlation_digest": final.native_correlation_digest,
            "response_digest": response_digest,
        }
    )


def _authority_for_final(
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
    final: ValidatedFinalResponse,
    response_digest: str,
    new_head_digest: str,
) -> FinalTurnAuthority:
    return FinalTurnAuthority(
        response_present=True,
        response_fresh=True,
        response_stable=True,
        eof_validated=True,
        terminal_envelope_valid=True,
        completion_marker=state.expected_completion_marker,
        marker_is_final_line=True,
        operation=final.operation,
        operation_id=final.operation_id,
        canonical_request_digest=final.canonical_request_digest,
        lane_id=final.lane_id,
        lane_generation=final.lane_generation,
        attempt_id=final.attempt_id,
        expected_head_digest=final.expected_head_digest,
        native_correlation_digest=final.native_correlation_digest,
        source_native_correlation_digest=(
            final.source_native_correlation_digest
        ),
        turn_id=final.turn_id,
        turn_sequence=final.turn_sequence,
        response_digest=response_digest,
        new_head_digest=new_head_digest,
        evidence_ref_id=final.evidence_ref_id,
    )


def _build_frame(
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
    final: ValidatedFinalResponse,
) -> Tuple[bytes, str, str]:
    body = final.body.encode("utf-8")
    marker = state.expected_completion_marker.encode("ascii")
    if marker in body:
        raise _IntegrityError(
            "response_authority.marker_duplicated_in_body",
            quarantine=False,
        )
    response_digest = _digest_bytes(body)
    new_head_digest = _new_dialogue_head(state, final, response_digest)
    authority = _authority_for_final(
        binding,
        state,
        final,
        response_digest,
        new_head_digest,
    )
    candidate = reduce_turn(state, authority)
    if (
        candidate.recovery_state is RecoveryState.QUARANTINED
        or candidate.outcome_kind is not TurnOutcomeKind.TURN_FINAL
    ):
        raise _IntegrityError("response_authority.correlation_conflict")
    header = {
        "schema": "ask_herdr.normalized_final_frame.internal.v1",
        "response_kind": "final",
        "project_authority_id": binding.project_authority_id,
        "operation": final.operation,
        "operation_id": final.operation_id,
        "canonical_request_digest": final.canonical_request_digest,
        "lane_id": final.lane_id,
        "lane_generation": final.lane_generation,
        "attempt_id": final.attempt_id,
        "expected_head_digest": final.expected_head_digest,
        "source_native_correlation_digest": (
            final.source_native_correlation_digest
        ),
        "native_correlation_digest": final.native_correlation_digest,
        "turn_id": final.turn_id,
        "turn_sequence": final.turn_sequence,
        "body_bytes": len(body),
        "response_digest": response_digest,
        "new_head_digest": new_head_digest,
        "validated_stream_digest": final.validated_stream_digest,
        "terminal_envelope_receipt_digest": (
            final.terminal_envelope_receipt_digest
        ),
        "stream_eof_receipt_digest": final.stream_eof_receipt_digest,
        "evidence_ref_id": final.evidence_ref_id,
        "completion_marker": state.expected_completion_marker,
    }
    header_bytes = canonical_json(header)
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise _IntegrityError("response_authority.header_too_large")
    frame = header_bytes + b"\n" + body + b"\n" + marker + b"\n"
    if len(frame) > MAX_FRAME_BYTES:
        raise _IntegrityError("response_authority.frame_too_large")
    return frame, response_digest, _digest_bytes(frame)


def _publication_receipt(
    binding: ValidatedLaneGenerationBinding,
    attempt_id: str,
    frame_digest: str,
    frame_size: int,
) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.response_publication_receipt.internal.v1",
        "project_authority_id": binding.project_authority_id,
        "lane_id": binding.lane_id,
        "lane_generation": binding.lane_generation,
        "lane_binding_digest": binding.lane_binding_digest,
        "attempt_id": attempt_id,
        "final_name": _response_name(attempt_id),
        "frame_digest": frame_digest,
        "frame_bytes": frame_size,
    }


def _read_response_capsule(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
) -> Tuple[bytes, Dict[str, Any], bytes]:
    capsule_name = _response_name(state.attempt_id)
    try:
        capsule = _open_directory(handles.transactions, capsule_name)
    except FileNotFoundError as error:
        raise _IntegrityError(
            "response_authority.missing", quarantine=False
        ) from error
    try:
        entries = set(os.listdir(capsule))
        if entries == {"receipt.json"}:
            raise _IntegrityError("response_authority.receipt_without_frame")
        if entries == {"frame"}:
            raise _IntegrityError("response_authority.frame_without_receipt")
        if entries != {"frame", "receipt.json"}:
            raise _IntegrityError("response_authority.capsule_invalid")
        receipt, receipt_bytes = _read_json(capsule, "receipt.json")
        frame = _read_file(capsule, "frame", MAX_FRAME_BYTES)
    finally:
        os.close(capsule)
    required = {
        "schema",
        "project_authority_id",
        "lane_id",
        "lane_generation",
        "lane_binding_digest",
        "attempt_id",
        "final_name",
        "frame_digest",
        "frame_bytes",
    }
    if (
        set(receipt) != required
        or receipt.get("schema")
        != "ask_herdr.response_publication_receipt.internal.v1"
        or receipt.get("project_authority_id") != binding.project_authority_id
        or receipt.get("lane_id") != binding.lane_id
        or receipt.get("lane_generation") != binding.lane_generation
        or receipt.get("lane_binding_digest") != binding.lane_binding_digest
        or receipt.get("attempt_id") != state.attempt_id
        or receipt.get("final_name") != capsule_name
        or not _matches(DIGEST_PATTERN, receipt.get("frame_digest"))
        or type(receipt.get("frame_bytes")) is not int
        or not 0 < receipt["frame_bytes"] <= MAX_FRAME_BYTES
    ):
        raise _IntegrityError("response_authority.receipt_invalid")
    if (
        len(frame) != receipt["frame_bytes"]
        or _digest_bytes(frame) != receipt["frame_digest"]
    ):
        raise _IntegrityError("response_authority.published_frame_conflict")
    return frame, receipt, receipt_bytes


def _response_candidate_matches(
    handles: _Handles,
    attempt_id: str,
    frame: bytes,
    receipt_bytes: bytes,
) -> Tuple[str, ...]:
    matches: List[str] = []
    frame_digest = _digest_bytes(frame).removeprefix("sha256:")
    for name in os.listdir(handles.transactions):
        if _response_candidate_attempt(name) != attempt_id:
            continue
        match = RESPONSE_CANDIDATE_PATTERN.fullmatch(name)
        if match is None or match.group(2) != frame_digest:
            raise _IntegrityError(
                "response_authority.staging_conflict",
                quarantine=False,
            )
        candidate = _open_directory(handles.transactions, name)
        try:
            entries = set(os.listdir(candidate))
            if not entries or entries - {"frame", "receipt.json"}:
                raise _IntegrityError(
                    "response_authority.staging_conflict",
                    quarantine=False,
                )
            if "frame" in entries:
                if _read_file(candidate, "frame", MAX_FRAME_BYTES) != frame:
                    raise _IntegrityError(
                        "response_authority.staging_conflict",
                        quarantine=False,
                    )
            if "receipt.json" in entries:
                if (
                    _read_file(candidate, "receipt.json", MAX_RECORD_BYTES)
                    != receipt_bytes
                ):
                    raise _IntegrityError(
                        "response_authority.staging_conflict",
                        quarantine=False,
                    )
                if "frame" not in entries:
                    raise _IntegrityError(
                        "response_authority.staging_conflict",
                        quarantine=False,
                    )
            matches.append(name)
        finally:
            os.close(candidate)
    return tuple(sorted(matches))


def _remove_exact_response_candidate(
    handles: _Handles,
    name: str,
    frame: bytes,
    receipt_bytes: bytes,
) -> None:
    candidate = _open_directory(handles.transactions, name)
    try:
        entries = set(os.listdir(candidate))
        if entries != {"frame", "receipt.json"}:
            raise _IntegrityError(
                "response_authority.staging_conflict",
                quarantine=False,
            )
        if (
            _read_file(candidate, "frame", MAX_FRAME_BYTES) != frame
            or _read_file(candidate, "receipt.json", MAX_RECORD_BYTES)
            != receipt_bytes
            or not _directory_binding(handles.transactions, name, candidate)
        ):
            raise _IntegrityError(
                "response_authority.staging_conflict",
                quarantine=False,
            )
        os.unlink("frame", dir_fd=candidate)
        os.unlink("receipt.json", dir_fd=candidate)
        _sync_directory(candidate)
    finally:
        os.close(candidate)
    os.rmdir(name, dir_fd=handles.transactions)
    _sync_directory(handles.transactions)


def publish_validated_final(
    binding: ValidatedLaneGenerationBinding,
    normalized: ValidatedFinalResponse,
    *,
    uuid_factory: Any = None,
    failpoint: Any = None,
) -> ResponsePublishResult:
    """No-overwrite publish one core-normalized final response frame."""

    if not isinstance(normalized, ValidatedFinalResponse):
        raise ValueError("lane_store.normalized_final_type_invalid")
    try:
        with _open_root(binding) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return ResponsePublishResult(
                    "response_reconciliation_required",
                    "lane_store.writer_active",
                )
            handles = _open_existing_handles(root, binding)
            if handles is None:
                return ResponsePublishResult(
                    "response_reconciliation_required",
                    "lane_store.absent",
                )
            try:
                try:
                    fcntl.flock(
                        handles.generation,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    return ResponsePublishResult(
                        "response_reconciliation_required",
                        "lane_store.writer_active",
                    )
                _barrier_store_tree(handles, binding)
                scan = _scan_generation(handles, binding)
                if scan.status != "active" or scan.state is None:
                    return ResponsePublishResult(
                        "response_reconciliation_required",
                        scan.detail_code,
                    )
                state = scan.state
                if (
                    state.dispatch_intent is None
                    or state.recovery_state is RecoveryState.QUARANTINED
                    or state.phase not in {
                        TurnPhase.DISPATCHING,
                        TurnPhase.IN_FLIGHT,
                        TurnPhase.VALIDATING,
                    }
                ):
                    return ResponsePublishResult(
                        "response_conflict",
                        "response_authority.not_admissible",
                    )
                try:
                    frame, response_digest, frame_digest = _build_frame(
                        binding,
                        state,
                        normalized,
                    )
                except _IntegrityError as error:
                    if error.code != "response_authority.correlation_conflict":
                        raise
                    conflict = RecordResponseValidationConflict(
                        operation_id=state.operation_id,
                        canonical_request_digest=state.canonical_request_digest,
                        attempt_id=state.attempt_id,
                        evidence_ref_id=normalized.evidence_ref_id,
                        detail_code=error.code,
                    )
                    durable_conflict = _commit_event_locked(
                        handles,
                        binding,
                        scan,
                        conflict,
                    )
                    if durable_conflict.outcome_kind not in {
                        "lane_event_committed",
                        "lane_event_already_committed",
                    }:
                        return ResponsePublishResult(
                            "response_reconciliation_required",
                            durable_conflict.detail_code,
                        )
                    return ResponsePublishResult(
                        "response_conflict",
                        error.code,
                    )
                final_name = _response_name(state.attempt_id)
                receipt = _publication_receipt(
                    binding,
                    state.attempt_id,
                    frame_digest,
                    len(frame),
                )
                receipt_bytes = canonical_json(receipt) + b"\n"
                if final_name in set(os.listdir(handles.transactions)):
                    try:
                        existing, _, existing_receipt = _read_response_capsule(
                            handles, binding, state
                        )
                    except _IntegrityError as error:
                        return ResponsePublishResult(
                            "response_conflict", error.code
                        )
                    if existing != frame:
                        return ResponsePublishResult(
                            "response_conflict",
                            "response_authority.final_collision",
                        )
                    if existing_receipt != receipt_bytes:
                        return ResponsePublishResult(
                            "response_conflict",
                            "response_authority.receipt_conflict",
                        )
                    _barrier_existing_capsule(
                        handles.transactions,
                        final_name,
                        ("frame", "receipt.json"),
                    )
                    existing_after, _, receipt_after = _read_response_capsule(
                        handles, binding, state
                    )
                    if existing_after != frame or receipt_after != receipt_bytes:
                        raise _IntegrityError(
                            "response_authority.publication_unverified",
                            quarantine=False,
                        )
                    return ResponsePublishResult(
                        "response_already_published",
                        "response_authority.exact_replay",
                        response_digest=response_digest,
                        frame_digest=frame_digest,
                    )
                try:
                    matching_response_candidates = _response_candidate_matches(
                        handles,
                        state.attempt_id,
                        frame,
                        receipt_bytes,
                    )
                except _IntegrityError:
                    return ResponsePublishResult(
                        "response_conflict",
                        "response_authority.staging_conflict",
                    )

                if len(matching_response_candidates) > 1:
                    return ResponsePublishResult(
                        "response_reconciliation_required",
                        "response_authority.multiple_exact_candidates",
                    )
                candidate_name = (
                    matching_response_candidates[0]
                    if matching_response_candidates
                    else _response_candidate_name(
                        state.attempt_id, frame_digest, uuid_factory
                    )
                )
                candidate = (
                    _open_directory(handles.transactions, candidate_name)
                    if matching_response_candidates
                    else _mkdir_new_open(handles.transactions, candidate_name)
                )
                try:
                    candidate_entries = set(os.listdir(candidate))
                    if "frame" not in candidate_entries:
                        _write_new(candidate, "frame", frame)
                    _trip(
                        failpoint,
                        "after_response_capsule_frame_fullsync",
                    )
                    if "receipt.json" not in candidate_entries:
                        _write_new(candidate, "receipt.json", receipt_bytes)
                    _trip(
                        failpoint,
                        "after_response_capsule_receipt_fullsync",
                    )
                    _sync_directory(candidate)
                    if (
                        _read_file(candidate, "frame", MAX_FRAME_BYTES) != frame
                        or _read_file(
                            candidate, "receipt.json", MAX_RECORD_BYTES
                        ) != receipt_bytes
                    ):
                        raise _IntegrityError(
                            "response_authority.candidate_changed"
                        )
                    if not _handles_still_bound(handles, binding):
                        raise _IntegrityError(
                            "lane_store.store_changed", quarantine=False
                        )
                    _trip(failpoint, "before_response_capsule_promote")
                    disposition = commit_exclusive(
                        handles.transactions, candidate_name, final_name
                    )
                    if disposition is CommitDisposition.OCCUPIED:
                        try:
                            existing, _, existing_receipt = (
                                _read_response_capsule(
                                    handles, binding, state
                                )
                            )
                        except _IntegrityError:
                            return ResponsePublishResult(
                                "response_conflict",
                                "response_authority.final_collision",
                            )
                        if existing != frame or existing_receipt != receipt_bytes:
                            return ResponsePublishResult(
                                "response_conflict",
                                "response_authority.final_collision",
                            )
                        _barrier_existing_capsule(
                            handles.transactions,
                            final_name,
                            ("frame", "receipt.json"),
                        )
                        if _directory_binding(
                            handles.transactions,
                            candidate_name,
                            candidate,
                        ):
                            os.close(candidate)
                            candidate = -1
                            _remove_exact_response_candidate(
                                handles,
                                candidate_name,
                                frame,
                                receipt_bytes,
                            )
                        return ResponsePublishResult(
                            "response_already_published",
                            "response_authority.exact_replay",
                            response_digest=response_digest,
                            frame_digest=frame_digest,
                        )
                    _trip(failpoint, "after_response_capsule_promote")
                    _barrier_promoted_capsule(
                        handles.transactions,
                        final_name,
                        candidate,
                        ("frame", "receipt.json"),
                    )
                finally:
                    if candidate >= 0:
                        os.close(candidate)
                if not _handles_still_bound(handles, binding):
                    raise _IntegrityError(
                        "lane_store.store_changed",
                        quarantine=False,
                    )
                if not _handles_still_bound(handles, binding):
                    raise _IntegrityError(
                        "lane_store.store_changed",
                        quarantine=False,
                    )
                try:
                    verified_scan = _scan_generation(handles, binding)
                except _IntegrityError as error:
                    raise _IntegrityError(
                        "response_authority.source_state_changed"
                    ) from error
                if (
                    verified_scan.status != "active"
                    or verified_scan.state != scan.state
                    or verified_scan.head != scan.head
                    or verified_scan.active_records != scan.active_records
                ):
                    raise _IntegrityError(
                        "response_authority.source_state_changed"
                    )
                if (
                    _read_response_capsule(handles, binding, state)[0]
                    != frame
                ):
                    raise _IntegrityError(
                        "response_authority.publication_unverified",
                        quarantine=False,
                    )
                return ResponsePublishResult(
                    "response_published",
                    "response_authority.published",
                    response_digest=response_digest,
                    frame_digest=frame_digest,
                )
            finally:
                _close_handles(handles)
    except LaneStoreFailpoint:
        raise
    except _IntegrityError as error:
        return ResponsePublishResult(
            "response_conflict"
            if error.quarantine
            else "response_reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError):
        return ResponsePublishResult(
            "response_conflict",
            "response_authority.storage_integrity_failure",
        )


def _quarantined_state(state: LaneTurnState) -> LaneTurnState:
    return replace(
        state,
        phase=(
            TurnPhase.SETTLED
            if state.phase is TurnPhase.SETTLED
            else TurnPhase.VALIDATING
        ),
        recovery_state=RecoveryState.QUARANTINED,
        outcome_kind=TurnOutcomeKind.TURN_QUARANTINED,
        retry_disposition=RetryDisposition.NONE,
        resend_allowed=False,
        release_allowed=False,
    )


def _reconciliation_state(state: LaneTurnState) -> LaneTurnState:
    return replace(
        state,
        phase=(
            TurnPhase.SETTLED
            if state.phase is TurnPhase.SETTLED
            else TurnPhase.VALIDATING
        ),
        recovery_state=RecoveryState.RECONCILIATION_REQUIRED,
        outcome_kind=TurnOutcomeKind.TURN_RECONCILIATION_REQUIRED,
        retry_disposition=RetryDisposition.RECONCILE_FIRST,
        resend_allowed=False,
        release_allowed=False,
    )


def _read_publication(
    handles: _Handles,
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
) -> bytes:
    return _read_response_capsule(handles, binding, state)[0]


def _parse_authoritative_frame(
    binding: ValidatedLaneGenerationBinding,
    state: LaneTurnState,
    frame: bytes,
) -> FinalTurnAuthority:
    first_newline = frame.find(b"\n")
    if first_newline < 1 or first_newline > MAX_HEADER_BYTES:
        raise _IntegrityError(
            "response_authority.frame_invalid",
            quarantine=False,
        )
    header_bytes = frame[:first_newline]
    try:
        header = parse_json_object(header_bytes)
    except StrictJsonError as error:
        raise _IntegrityError(
            "response_authority.frame_invalid",
            quarantine=False,
        ) from error
    if canonical_json(header) != header_bytes:
        raise _IntegrityError(
            "response_authority.header_not_canonical",
            quarantine=False,
        )
    required = {
        "schema",
        "response_kind",
        "project_authority_id",
        "operation",
        "operation_id",
        "canonical_request_digest",
        "lane_id",
        "lane_generation",
        "attempt_id",
        "expected_head_digest",
        "source_native_correlation_digest",
        "native_correlation_digest",
        "turn_id",
        "turn_sequence",
        "body_bytes",
        "response_digest",
        "new_head_digest",
        "validated_stream_digest",
        "terminal_envelope_receipt_digest",
        "stream_eof_receipt_digest",
        "evidence_ref_id",
        "completion_marker",
    }
    if set(header) != required:
        raise _IntegrityError(
            "response_authority.frame_invalid",
            quarantine=False,
        )
    protected = {
        "schema": "ask_herdr.normalized_final_frame.internal.v1",
        "response_kind": "final",
        "project_authority_id": binding.project_authority_id,
        "operation": state.operation,
        "operation_id": state.operation_id,
        "canonical_request_digest": state.canonical_request_digest,
        "lane_id": state.lane_id,
        "lane_generation": state.lane_generation,
        "attempt_id": state.attempt_id,
        "expected_head_digest": state.expected_head_digest,
        "turn_sequence": state.expected_turn_sequence,
        "completion_marker": state.expected_completion_marker,
    }
    if any(header.get(key) != value for key, value in protected.items()):
        raise _IntegrityError("response_authority.correlation_conflict")
    for key in (
        "response_digest",
        "new_head_digest",
        "native_correlation_digest",
        "validated_stream_digest",
        "terminal_envelope_receipt_digest",
        "stream_eof_receipt_digest",
    ):
        if not _matches(DIGEST_PATTERN, header.get(key)):
            raise _IntegrityError(
                "response_authority.frame_invalid",
                quarantine=False,
            )
    if header.get("source_native_correlation_digest") is not None and not _matches(
        DIGEST_PATTERN,
        header.get("source_native_correlation_digest"),
    ):
        raise _IntegrityError(
            "response_authority.frame_invalid",
            quarantine=False,
        )
    for key in ("turn_id", "evidence_ref_id"):
        if not _matches(UUID4_PATTERN, header.get(key)):
            raise _IntegrityError(
                "response_authority.frame_invalid",
                quarantine=False,
            )
    body_size = header.get("body_bytes")
    if type(body_size) is not int or not 0 <= body_size <= MAX_BODY_BYTES:
        raise _IntegrityError(
            "response_authority.frame_invalid",
            quarantine=False,
        )
    body_start = first_newline + 1
    body_end = body_start + body_size
    marker = state.expected_completion_marker.encode("ascii")
    expected_suffix = b"\n" + marker + b"\n"
    if body_end > len(frame) or frame[body_end:] != expected_suffix:
        raise _IntegrityError(
            "response_authority.marker_mismatch",
            quarantine=False,
        )
    body = frame[body_start:body_end]
    if marker in body or _digest_bytes(body) != header["response_digest"]:
        raise _IntegrityError(
            "response_authority.body_integrity_failure",
            quarantine=False,
        )
    try:
        body_text = body.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise _IntegrityError(
            "response_authority.body_invalid_utf8",
            quarantine=False,
        ) from error
    normalized = ValidatedFinalResponse(
        operation=header["operation"],
        operation_id=header["operation_id"],
        canonical_request_digest=header["canonical_request_digest"],
        lane_id=header["lane_id"],
        lane_generation=header["lane_generation"],
        attempt_id=header["attempt_id"],
        expected_head_digest=header["expected_head_digest"],
        source_native_correlation_digest=header[
            "source_native_correlation_digest"
        ],
        native_correlation_digest=header["native_correlation_digest"],
        turn_id=header["turn_id"],
        turn_sequence=header["turn_sequence"],
        body=body_text,
        validated_stream_digest=header["validated_stream_digest"],
        terminal_envelope_receipt_digest=header[
            "terminal_envelope_receipt_digest"
        ],
        stream_eof_receipt_digest=header["stream_eof_receipt_digest"],
        evidence_ref_id=header["evidence_ref_id"],
    )
    expected_new_head = _new_dialogue_head(
        state,
        normalized,
        header["response_digest"],
    )
    if header["new_head_digest"] != expected_new_head:
        raise _IntegrityError("response_authority.self_digest_conflict")
    authority = _authority_for_final(
        binding,
        state,
        normalized,
        header["response_digest"],
        expected_new_head,
    )
    candidate = reduce_turn(state, authority)
    if (
        candidate.recovery_state is RecoveryState.QUARANTINED
        or candidate.outcome_kind is not TurnOutcomeKind.TURN_FINAL
    ):
        raise _IntegrityError("response_authority.correlation_conflict")
    return authority


def settle_expected_response(
    binding: ValidatedLaneGenerationBinding,
    *,
    failpoint: Any = None,
) -> LaneMutationResult:
    """Validate the one durable expected frame and append Final Turn Authority."""

    try:
        with _open_root(binding) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return LaneMutationResult(
                    "lane_response_reconciliation_required",
                    "lane_store.writer_active",
                )
            handles = _open_existing_handles(root, binding)
            if handles is None:
                return LaneMutationResult(
                    "lane_response_reconciliation_required",
                    "lane_store.absent",
                )
            try:
                try:
                    fcntl.flock(
                        handles.generation,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                except BlockingIOError:
                    return LaneMutationResult(
                        "lane_response_reconciliation_required",
                        "lane_store.writer_active",
                    )
                _barrier_store_tree(handles, binding)
                scan = _scan_generation(handles, binding)
                if scan.status == "quarantined":
                    return LaneMutationResult(
                        "lane_response_quarantined",
                        scan.detail_code,
                        state=scan.state,
                        event_sequence=(scan.head or {}).get("event_sequence"),
                    )
                if (
                    scan.state is None
                    or scan.status not in {
                        "active",
                        "reconciliation_required",
                    }
                ):
                    return LaneMutationResult(
                        "lane_response_reconciliation_required",
                        scan.detail_code,
                        state=scan.state,
                    )
                try:
                    frame = _read_publication(handles, binding, scan.state)
                    frame_digest = _digest_bytes(frame)
                    authority = _parse_authoritative_frame(
                        binding,
                        scan.state,
                        frame,
                    )
                except _IntegrityError as error:
                    if error.quarantine:
                        return LaneMutationResult(
                            "lane_response_quarantined",
                            error.code,
                            state=_quarantined_state(scan.state),
                            event_sequence=(scan.head or {}).get(
                                "event_sequence"
                            ),
                        )
                    return LaneMutationResult(
                        "lane_response_reconciliation_required",
                        error.code,
                        state=_reconciliation_state(scan.state),
                        event_sequence=(scan.head or {}).get("event_sequence"),
                    )
                committed = _commit_event_locked(
                    handles,
                    binding,
                    scan,
                    authority,
                    failpoint=failpoint,
                    response_frame_digest=frame_digest,
                )
                if committed.outcome_kind in {
                    "lane_event_committed",
                    "lane_event_already_committed",
                }:
                    committed_state = committed.state or scan.state
                    try:
                        verified_frame = _read_publication(
                            handles,
                            binding,
                            committed_state,
                        )
                        if _digest_bytes(verified_frame) != frame_digest:
                            raise _IntegrityError(
                                "response_authority.settlement_changed"
                            )
                        verified_authority = _parse_authoritative_frame(
                            binding,
                            committed_state,
                            verified_frame,
                        )
                        verified_scan = _scan_generation(handles, binding)
                        final_records = tuple(
                            record
                            for record in verified_scan.active_records
                            if record.get("event", {}).get("event_type")
                            == "FinalTurnAuthority"
                        )
                        if (
                            verified_scan.status != "active"
                            or verified_scan.state != committed_state
                            or len(final_records) != 1
                            or final_records[0].get("event_fingerprint")
                            != _event_fingerprint(verified_authority)
                            or final_records[0].get("response_frame_digest")
                            != frame_digest
                        ):
                            raise _IntegrityError(
                                "response_authority.settlement_changed"
                            )
                    except _IntegrityError as error:
                        return LaneMutationResult(
                            "lane_response_quarantined",
                            error.code,
                            state=_quarantined_state(committed_state),
                            event_sequence=committed.event_sequence,
                            record_digest=committed.record_digest,
                        )
                if committed.outcome_kind == "lane_event_committed":
                    return replace(
                        committed,
                        outcome_kind="lane_response_settled",
                        detail_code="response_authority.authoritative",
                    )
                return committed
            finally:
                _close_handles(handles)
    except LaneStoreFailpoint:
        raise
    except _IntegrityError as error:
        return LaneMutationResult(
            "lane_response_quarantined"
            if error.quarantine
            else "lane_response_reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError, ValueError):
        return LaneMutationResult(
            "lane_response_quarantined",
            "response_authority.storage_integrity_failure",
        )


__all__ = (
    "ClaimedLaneProof",
    "LaneMutationResult",
    "LaneStoreFailpoint",
    "LaneStoreInspection",
    "ProvisionedLaneProof",
    "TopologyCommandEffectStartedLaneProof",
    "TopologyEffectStartedLaneProof",
    "ResponsePublishResult",
    "ValidatedFinalResponse",
    "ValidatedLaneGenerationBinding",
    "apply_lane_turn_event",
    "claim_topology_provisioning_under_lease",
    "authenticate_topology_effect_started_under_lease",
    "inspect_lane_turn",
    "prepare_admitted_attempt_under_lease",
    "publish_validated_final",
    "record_topology_provisioned_under_lease",
    "settle_expected_response",
)
