"""Private, unactivated, provider-free lane/turn authority reducer.

This module contains no filesystem, Herdr, provider, network, release, or retry
adapter.  It reduces already validated immutable facts into immutable lane/turn
state.  Durable storage and external-effect execution belong to later seams.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import re
from typing import Any, Optional, Tuple, Union


_UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_TOKEN_PATTERN = re.compile(r"[\x21-\x7e]+")
_TURN_OPERATIONS: Tuple[str, ...] = (
    "turn.answer",
    "turn.consult",
    "turn.recovery_continue",
    "turn.review",
    "turn.safe_retry",
)


class TurnPhase(str, Enum):
    PREPARED = "prepared"
    DISPATCHING = "dispatching"
    IN_FLIGHT = "in_flight"
    VALIDATING = "validating"
    SETTLED = "settled"


class RecoveryState(str, Enum):
    CLEAR = "clear"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    QUARANTINED = "quarantined"


class AttemptPromotion(str, Enum):
    ATTEMPT_ONLY = "attempt_only"
    CONSULTANT_TURN = "consultant_turn"


class ReservationState(str, Enum):
    NOT_COUNTED = "not_counted"
    HELD = "held"
    COUNTED = "counted"
    RELEASED = "released"


class RetryDisposition(str, Enum):
    NONE = "none"
    SAFE_RETRY_ELIGIBLE = "safe_retry_eligible"
    RECONCILE_FIRST = "reconcile_first"
    NEW_OPERATION_REQUIRED = "new_operation_required"


class TurnOutcomeKind(str, Enum):
    DELIVERY_UNCERTAIN = "delivery_uncertain"
    TURN_DEFINITE_NON_START = "turn_definite_non_start"
    TURN_FINAL = "turn_final"
    TURN_QUARANTINED = "turn_quarantined"
    TURN_RECONCILIATION_REQUIRED = "turn_reconciliation_required"


class DefiniteNonStartProof(str, Enum):
    STOPPED_BEFORE_DISPATCH_COMMAND = "stopped_before_dispatch_command"
    RUNNER_STARTED_NO_PROVIDER_CHILD = "runner_started_no_provider_child"


class NativeIdentityMode(str, Enum):
    ESTABLISH_NEW = "establish_new"
    EXACT_RESUME = "exact_resume"
    FORK_FROM = "fork_from"


class TurnTransitionError(ValueError):
    """A caller attempted a state transition that the closed reducer forbids."""

    def __init__(self, detail_code: str):
        self.detail_code = detail_code
        super().__init__(detail_code)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _require_uuid(value: Any, detail_code: str) -> None:
    if not _matches(_UUID4_PATTERN, value):
        raise ValueError(detail_code)


def _require_digest(value: Any, detail_code: str) -> None:
    if not _matches(_DIGEST_PATTERN, value):
        raise ValueError(detail_code)


def _require_token(value: Any, detail_code: str, maximum: int = 256) -> None:
    if (
        not _matches(_TOKEN_PATTERN, value)
        or len(value.encode("ascii")) > maximum
    ):
        raise ValueError(detail_code)


def _require_positive_integer(value: Any, detail_code: str) -> None:
    if type(value) is not int or value < 1:
        raise ValueError(detail_code)


def _require_bool(value: Any, detail_code: str) -> None:
    if type(value) is not bool:
        raise ValueError(detail_code)


def _require_operation(value: Any) -> None:
    if type(value) is not str or value not in _TURN_OPERATIONS:
        raise ValueError("lane_turn.operation_invalid")


def _validate_common_operation(
    operation_id: Any,
    canonical_request_digest: Any,
    attempt_id: Any,
) -> None:
    _require_uuid(operation_id, "lane_turn.operation_id_invalid")
    _require_digest(
        canonical_request_digest,
        "lane_turn.canonical_request_digest_invalid",
    )
    _require_uuid(attempt_id, "lane_turn.attempt_id_invalid")


@dataclass(frozen=True)
class DispatchIntent:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    dispatch_nonce: str
    project_topology_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_token(
            self.dispatch_nonce,
            "lane_turn.dispatch_nonce_invalid",
        )
        if self.project_topology_digest is not None:
            _require_digest(
                self.project_topology_digest,
                "lane_turn.project_topology_digest_invalid",
            )


@dataclass(frozen=True)
class PrepareAdmittedAttempt:
    operation: str
    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    expected_head_digest: str
    native_identity_mode: NativeIdentityMode
    expected_native_correlation_digest: Optional[str]
    expected_turn_sequence: int
    expected_completion_marker: str
    reservation_id: Optional[str]
    direct_human_policy_record_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _require_operation(self.operation)
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        _require_digest(
            self.expected_head_digest,
            "lane_turn.expected_head_digest_invalid",
        )
        if type(self.native_identity_mode) is not NativeIdentityMode:
            raise ValueError("lane_turn.native_identity_mode_invalid")
        allowed_modes = {
            "turn.consult": (NativeIdentityMode.ESTABLISH_NEW,),
            "turn.answer": (NativeIdentityMode.EXACT_RESUME,),
            "turn.recovery_continue": (NativeIdentityMode.EXACT_RESUME,),
            "turn.review": (NativeIdentityMode.FORK_FROM,),
            "turn.safe_retry": tuple(NativeIdentityMode),
        }
        if self.native_identity_mode not in allowed_modes[self.operation]:
            raise ValueError("lane_turn.native_identity_mode_not_allowed")
        if self.native_identity_mode is NativeIdentityMode.ESTABLISH_NEW:
            if self.expected_native_correlation_digest is not None:
                raise ValueError(
                    "lane_turn.establish_new_native_identity_must_be_null"
                )
        else:
            _require_digest(
                self.expected_native_correlation_digest,
                "lane_turn.expected_native_correlation_digest_invalid",
            )
        _require_positive_integer(
            self.expected_turn_sequence,
            "lane_turn.expected_turn_sequence_invalid",
        )
        _require_token(
            self.expected_completion_marker,
            "lane_turn.expected_completion_marker_invalid",
            maximum=512,
        )
        if self.reservation_id is not None:
            _require_token(
                self.reservation_id,
                "lane_turn.reservation_id_invalid",
            )
        if self.direct_human_policy_record_digest is not None:
            _require_digest(
                self.direct_human_policy_record_digest,
                "lane_turn.direct_human_policy_record_digest_invalid",
            )


@dataclass(frozen=True)
class ClaimTopologyProvisioning:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    lane_id: str
    lane_generation: int
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_store_incarnation_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        _require_digest(
            self.policy_record_digest,
            "lane_turn.policy_record_digest_invalid",
        )
        _require_digest(
            self.prepared_lane_record_digest,
            "lane_turn.prepared_lane_record_digest_invalid",
        )
        _require_uuid(
            self.topology_mutation_id,
            "lane_turn.topology_mutation_id_invalid",
        )
        _require_token(
            self.topology_nonce,
            "lane_turn.topology_nonce_invalid",
        )
        if self.topology_store_incarnation_digest is not None:
            _require_digest(
                self.topology_store_incarnation_digest,
                "lane_turn.topology_store_incarnation_digest_invalid",
            )


@dataclass(frozen=True)
class TopologyEffectStarted:
    """Durable Lane fact preceding the first external Topology command."""

    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    lane_id: str
    lane_generation: int
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_store_incarnation_digest: str
    topology_claim_record_digest: str
    topology_mutation_record_digest: str
    first_topology_command_record_digest: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        for value, detail_code in (
            (
                self.policy_record_digest,
                "lane_turn.policy_record_digest_invalid",
            ),
            (
                self.prepared_lane_record_digest,
                "lane_turn.prepared_lane_record_digest_invalid",
            ),
            (
                self.topology_store_incarnation_digest,
                "lane_turn.topology_store_incarnation_digest_invalid",
            ),
            (
                self.topology_claim_record_digest,
                "lane_turn.topology_claim_record_digest_invalid",
            ),
            (
                self.topology_mutation_record_digest,
                "lane_turn.topology_mutation_record_digest_invalid",
            ),
            (
                self.first_topology_command_record_digest,
                "lane_turn.first_topology_command_record_digest_invalid",
            ),
        ):
            _require_digest(value, detail_code)
        _require_uuid(
            self.topology_mutation_id,
            "lane_turn.topology_mutation_id_invalid",
        )
        _require_token(
            self.topology_nonce,
            "lane_turn.topology_nonce_invalid",
        )


@dataclass(frozen=True)
class TopologyCommandEffectStarted:
    """Durable Lane fact preceding one later external Topology command."""

    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    lane_id: str
    lane_generation: int
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

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        if (
            type(self.command_sequence) is not int
            or self.command_sequence < 2
        ):
            raise ValueError("lane_turn.topology_command_sequence_invalid")
        _require_uuid(
            self.topology_command_step_id,
            "lane_turn.topology_command_step_id_invalid",
        )
        for value, detail_code in (
            (
                self.policy_record_digest,
                "lane_turn.policy_record_digest_invalid",
            ),
            (
                self.prepared_lane_record_digest,
                "lane_turn.prepared_lane_record_digest_invalid",
            ),
            (
                self.topology_store_incarnation_digest,
                "lane_turn.topology_store_incarnation_digest_invalid",
            ),
            (
                self.topology_claim_record_digest,
                "lane_turn.topology_claim_record_digest_invalid",
            ),
            (
                self.topology_mutation_record_digest,
                "lane_turn.topology_mutation_record_digest_invalid",
            ),
            (
                self.topology_effect_started_record_digest,
                "lane_turn.topology_effect_started_record_digest_invalid",
            ),
            (
                self.topology_command_record_digest,
                "lane_turn.topology_command_record_digest_invalid",
            ),
            (
                self.previous_topology_effect_record_digest,
                "lane_turn.previous_topology_effect_record_digest_invalid",
            ),
        ):
            _require_digest(value, detail_code)
        _require_uuid(
            self.topology_mutation_id,
            "lane_turn.topology_mutation_id_invalid",
        )
        _require_token(
            self.topology_nonce,
            "lane_turn.topology_nonce_invalid",
        )


@dataclass(frozen=True)
class RecordTopologyProvisioned:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    lane_id: str
    lane_generation: int
    policy_record_digest: str
    prepared_lane_record_digest: str
    topology_mutation_id: str
    topology_nonce: str
    topology_claim_record_digest: str
    topology_settlement_record_digest: str
    project_topology_digest: str
    topology_effect_started_record_digest: Optional[str] = None
    topology_last_command_effect_started_record_digest: Optional[str] = None
    recovery_state_digest: Optional[str] = None
    recovery_result_store_binding_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        for value, detail_code in (
            (
                self.policy_record_digest,
                "lane_turn.policy_record_digest_invalid",
            ),
            (
                self.prepared_lane_record_digest,
                "lane_turn.prepared_lane_record_digest_invalid",
            ),
            (
                self.topology_claim_record_digest,
                "lane_turn.topology_claim_record_digest_invalid",
            ),
            (
                self.topology_settlement_record_digest,
                "lane_turn.topology_settlement_record_digest_invalid",
            ),
            (
                self.project_topology_digest,
                "lane_turn.project_topology_digest_invalid",
            ),
        ):
            _require_digest(value, detail_code)
        _require_uuid(
            self.topology_mutation_id,
            "lane_turn.topology_mutation_id_invalid",
        )
        _require_token(
            self.topology_nonce,
            "lane_turn.topology_nonce_invalid",
        )
        if self.topology_effect_started_record_digest is not None:
            _require_digest(
                self.topology_effect_started_record_digest,
                "lane_turn.topology_effect_started_record_digest_invalid",
            )
        if (
            self.topology_last_command_effect_started_record_digest
            is not None
        ):
            _require_digest(
                self.topology_last_command_effect_started_record_digest,
                (
                    "lane_turn."
                    "topology_last_command_effect_started_record_digest_invalid"
                ),
            )
        if self.recovery_state_digest is not None:
            _require_digest(
                self.recovery_state_digest,
                "lane_turn.recovery_state_digest_invalid",
            )
        if self.recovery_result_store_binding_digest is not None:
            _require_digest(
                self.recovery_result_store_binding_digest,
                "lane_turn.recovery_result_store_binding_digest_invalid",
            )


@dataclass(frozen=True)
class RecordRecoveryResultEvidenceAnchor:
    """Anchor one exact Recovery result Evidence link in Lane history."""

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

    def __post_init__(self) -> None:
        _require_uuid(
            self.project_authority_id,
            "lane_turn.project_authority_id_invalid",
        )
        _require_uuid(
            self.recovery_operation_id,
            "lane_turn.recovery_operation_id_invalid",
        )
        _require_digest(
            self.recovery_canonical_request_digest,
            "lane_turn.recovery_request_digest_invalid",
        )
        _validate_common_operation(
            self.source_lane_operation_id,
            self.source_lane_canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        _require_uuid(
            self.topology_mutation_id,
            "lane_turn.topology_mutation_id_invalid",
        )
        for value, detail_code in (
            (
                self.expected_lane_head_record_digest,
                "lane_turn.expected_lane_head_record_digest_invalid",
            ),
            (
                self.topology_provisioned_record_digest,
                "lane_turn.topology_provisioned_record_digest_invalid",
            ),
            (
                self.source_result_record_digest,
                "lane_turn.source_result_record_digest_invalid",
            ),
            (
                self.recovery_result_store_binding_digest,
                "lane_turn.recovery_result_store_binding_digest_invalid",
            ),
            (
                self.evidence_registry_binding_digest,
                "lane_turn.evidence_registry_binding_digest_invalid",
            ),
            (
                self.source_relationship_digest,
                "lane_turn.source_relationship_digest_invalid",
            ),
            (
                self.evidence_link_record_digest,
                "lane_turn.evidence_link_record_digest_invalid",
            ),
        ):
            _require_digest(value, detail_code)


@dataclass(frozen=True)
class BeginDispatch:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    dispatch_nonce: str
    project_topology_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_token(
            self.dispatch_nonce,
            "lane_turn.dispatch_nonce_invalid",
        )
        if self.project_topology_digest is not None:
            _require_digest(
                self.project_topology_digest,
                "lane_turn.project_topology_digest_invalid",
            )

    def intent(self) -> DispatchIntent:
        return DispatchIntent(
            operation_id=self.operation_id,
            canonical_request_digest=self.canonical_request_digest,
            attempt_id=self.attempt_id,
            dispatch_nonce=self.dispatch_nonce,
            project_topology_digest=self.project_topology_digest,
        )


@dataclass(frozen=True)
class RecordDeliveryUncertain:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    evidence_ref_id: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")


@dataclass(frozen=True)
class RecordResponseValidationConflict:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    evidence_ref_id: str
    detail_code: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")
        _require_token(
            self.detail_code,
            "lane_turn.response_conflict_detail_code_invalid",
        )


@dataclass(frozen=True)
class RecordDefiniteNonStart:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    proof: DefiniteNonStartProof
    evidence_ref_id: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        if type(self.proof) is not DefiniteNonStartProof:
            raise ValueError("lane_turn.definite_non_start_proof_invalid")
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")


@dataclass(frozen=True)
class RecordProviderStarted:
    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    turn_id: str
    turn_sequence: int
    native_correlation_digest: str
    source_native_correlation_digest: Optional[str]
    evidence_ref_id: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        _require_uuid(self.turn_id, "lane_turn.turn_id_invalid")
        _require_positive_integer(
            self.turn_sequence,
            "lane_turn.turn_sequence_invalid",
        )
        _require_digest(
            self.native_correlation_digest,
            "lane_turn.native_correlation_digest_invalid",
        )
        if self.source_native_correlation_digest is not None:
            _require_digest(
                self.source_native_correlation_digest,
                "lane_turn.source_native_correlation_digest_invalid",
            )
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")


@dataclass(frozen=True)
class RecordAdvisoryWaitTimeout:
    operation_id: str
    canonical_request_digest: str
    attempt_id: str
    evidence_ref_id: str

    def __post_init__(self) -> None:
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")


@dataclass(frozen=True)
class FinalTurnAuthority:
    response_present: bool
    response_fresh: bool
    response_stable: bool
    eof_validated: bool
    terminal_envelope_valid: bool
    completion_marker: Optional[str]
    marker_is_final_line: bool
    operation: str
    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    expected_head_digest: str
    native_correlation_digest: str
    source_native_correlation_digest: Optional[str]
    turn_id: str
    turn_sequence: int
    response_digest: str
    new_head_digest: str
    evidence_ref_id: str

    def __post_init__(self) -> None:
        for name in (
            "response_present",
            "response_fresh",
            "response_stable",
            "eof_validated",
            "terminal_envelope_valid",
            "marker_is_final_line",
        ):
            _require_bool(getattr(self, name), f"lane_turn.{name}_invalid")
        if self.completion_marker is not None:
            _require_token(
                self.completion_marker,
                "lane_turn.completion_marker_invalid",
                maximum=512,
            )
        _require_operation(self.operation)
        _validate_common_operation(
            self.operation_id,
            self.canonical_request_digest,
            self.attempt_id,
        )
        _require_uuid(self.lane_id, "lane_turn.lane_id_invalid")
        _require_positive_integer(
            self.lane_generation,
            "lane_turn.lane_generation_invalid",
        )
        _require_digest(
            self.expected_head_digest,
            "lane_turn.expected_head_digest_invalid",
        )
        _require_digest(
            self.native_correlation_digest,
            "lane_turn.native_correlation_digest_invalid",
        )
        if self.source_native_correlation_digest is not None:
            _require_digest(
                self.source_native_correlation_digest,
                "lane_turn.source_native_correlation_digest_invalid",
            )
        _require_uuid(self.turn_id, "lane_turn.turn_id_invalid")
        _require_positive_integer(
            self.turn_sequence,
            "lane_turn.turn_sequence_invalid",
        )
        _require_digest(self.response_digest, "lane_turn.response_digest_invalid")
        _require_digest(self.new_head_digest, "lane_turn.new_head_digest_invalid")
        _require_uuid(self.evidence_ref_id, "lane_turn.evidence_ref_id_invalid")


@dataclass(frozen=True)
class LaneTurnState:
    operation: str
    operation_id: str
    canonical_request_digest: str
    lane_id: str
    lane_generation: int
    attempt_id: str
    expected_head_digest: str
    native_identity_mode: NativeIdentityMode
    expected_native_correlation_digest: Optional[str]
    established_native_correlation_digest: Optional[str]
    expected_turn_sequence: int
    expected_completion_marker: str
    reservation_id: Optional[str]
    phase: TurnPhase
    recovery_state: RecoveryState
    promotion: AttemptPromotion
    reservation_state: ReservationState
    retry_disposition: RetryDisposition
    outcome_kind: Optional[TurnOutcomeKind]
    head_digest: str
    response_digest: Optional[str]
    turn_id: Optional[str]
    turn_sequence: Optional[int]
    dispatch_intent: Optional[DispatchIntent]
    advisory_wait_timed_out: bool
    possible_provider_effect_observed: bool
    resend_allowed: bool
    release_allowed: bool
    direct_human_policy_record_digest: Optional[str] = None
    topology_provisioning_claim: Optional[ClaimTopologyProvisioning] = None
    topology_provisioned: Optional[RecordTopologyProvisioned] = None
    topology_effect_started: Optional[TopologyEffectStarted] = None
    topology_command_effects_started: Tuple[
        TopologyCommandEffectStarted, ...
    ] = ()
    recovery_result_evidence_anchors: Tuple[
        RecordRecoveryResultEvidenceAnchor, ...
    ] = ()


LaneTurnEvent = Union[
    PrepareAdmittedAttempt,
    ClaimTopologyProvisioning,
    TopologyEffectStarted,
    TopologyCommandEffectStarted,
    RecordTopologyProvisioned,
    RecordRecoveryResultEvidenceAnchor,
    BeginDispatch,
    RecordDeliveryUncertain,
    RecordResponseValidationConflict,
    RecordDefiniteNonStart,
    RecordProviderStarted,
    RecordAdvisoryWaitTimeout,
    FinalTurnAuthority,
]


def _prepare(event: PrepareAdmittedAttempt) -> LaneTurnState:
    reservation_state = (
        ReservationState.HELD
        if event.reservation_id is not None
        else ReservationState.NOT_COUNTED
    )
    return LaneTurnState(
        operation=event.operation,
        operation_id=event.operation_id,
        canonical_request_digest=event.canonical_request_digest,
        lane_id=event.lane_id,
        lane_generation=event.lane_generation,
        attempt_id=event.attempt_id,
        expected_head_digest=event.expected_head_digest,
        native_identity_mode=event.native_identity_mode,
        expected_native_correlation_digest=(
            event.expected_native_correlation_digest
        ),
        established_native_correlation_digest=None,
        expected_turn_sequence=event.expected_turn_sequence,
        expected_completion_marker=event.expected_completion_marker,
        reservation_id=event.reservation_id,
        phase=TurnPhase.PREPARED,
        recovery_state=RecoveryState.CLEAR,
        promotion=AttemptPromotion.ATTEMPT_ONLY,
        reservation_state=reservation_state,
        retry_disposition=RetryDisposition.NONE,
        outcome_kind=None,
        head_digest=event.expected_head_digest,
        response_digest=None,
        turn_id=None,
        turn_sequence=None,
        dispatch_intent=None,
        advisory_wait_timed_out=False,
        possible_provider_effect_observed=False,
        resend_allowed=False,
        release_allowed=False,
        direct_human_policy_record_digest=(
            event.direct_human_policy_record_digest
        ),
        topology_provisioning_claim=None,
        topology_provisioned=None,
        topology_effect_started=None,
        topology_command_effects_started=(),
    )


def _prepare_matches(state: LaneTurnState, event: PrepareAdmittedAttempt) -> bool:
    return (
        state.operation == event.operation
        and state.operation_id == event.operation_id
        and state.canonical_request_digest == event.canonical_request_digest
        and state.lane_id == event.lane_id
        and state.lane_generation == event.lane_generation
        and state.attempt_id == event.attempt_id
        and state.expected_head_digest == event.expected_head_digest
        and state.native_identity_mode is event.native_identity_mode
        and state.expected_native_correlation_digest
        == event.expected_native_correlation_digest
        and state.expected_turn_sequence == event.expected_turn_sequence
        and state.expected_completion_marker == event.expected_completion_marker
        and state.reservation_id == event.reservation_id
        and state.direct_human_policy_record_digest
        == event.direct_human_policy_record_digest
    )


def _common_correlates(
    state: LaneTurnState,
    operation_id: str,
    canonical_request_digest: str,
    attempt_id: str,
) -> bool:
    return (
        state.operation_id == operation_id
        and state.canonical_request_digest == canonical_request_digest
        and state.attempt_id == attempt_id
    )


def _require_common_correlation(
    state: LaneTurnState,
    operation_id: str,
    canonical_request_digest: str,
    attempt_id: str,
) -> None:
    if not _common_correlates(
        state,
        operation_id,
        canonical_request_digest,
        attempt_id,
    ):
        raise TurnTransitionError("lane_turn.event_correlation_conflict")


def _reserve_started(state: ReservationState) -> ReservationState:
    if state is ReservationState.HELD:
        return ReservationState.COUNTED
    return state


def _reserve_non_start(state: ReservationState) -> ReservationState:
    if state is ReservationState.HELD:
        return ReservationState.RELEASED
    return state


_PHASE_RANK = {
    TurnPhase.PREPARED: 0,
    TurnPhase.DISPATCHING: 1,
    TurnPhase.IN_FLIGHT: 2,
    TurnPhase.VALIDATING: 3,
    TurnPhase.SETTLED: 4,
}


def _monotonic_phase(current: TurnPhase, candidate: TurnPhase) -> TurnPhase:
    if _PHASE_RANK[current] >= _PHASE_RANK[candidate]:
        return current
    return candidate


def _native_identity_correlates(
    state: LaneTurnState,
    native_correlation_digest: str,
    source_native_correlation_digest: Optional[str],
) -> bool:
    admitted = state.expected_native_correlation_digest
    established = state.established_native_correlation_digest
    if state.native_identity_mode is NativeIdentityMode.ESTABLISH_NEW:
        return (
            source_native_correlation_digest is None
            and (established is None or established == native_correlation_digest)
        )
    if state.native_identity_mode is NativeIdentityMode.EXACT_RESUME:
        return (
            admitted is not None
            and source_native_correlation_digest == admitted
            and native_correlation_digest == admitted
            and (established is None or established == native_correlation_digest)
        )
    return (
        admitted is not None
        and source_native_correlation_digest == admitted
        and native_correlation_digest != admitted
        and (established is None or established == native_correlation_digest)
    )


def _quarantine(state: LaneTurnState) -> LaneTurnState:
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


def _authority_correlates(
    state: LaneTurnState,
    event: FinalTurnAuthority,
) -> bool:
    if not (
        state.operation == event.operation
        and _common_correlates(
            state,
            event.operation_id,
            event.canonical_request_digest,
            event.attempt_id,
        )
        and state.lane_id == event.lane_id
        and state.lane_generation == event.lane_generation
        and state.expected_head_digest == event.expected_head_digest
        and state.expected_turn_sequence == event.turn_sequence
        and _native_identity_correlates(
            state,
            event.native_correlation_digest,
            event.source_native_correlation_digest,
        )
    ):
        return False
    if state.promotion is AttemptPromotion.CONSULTANT_TURN:
        return (
            state.turn_id == event.turn_id
            and state.turn_sequence == event.turn_sequence
        )
    return True


def _authority_complete(
    state: LaneTurnState,
    event: FinalTurnAuthority,
) -> bool:
    return (
        event.response_present
        and event.response_fresh
        and event.response_stable
        and event.eof_validated
        and event.terminal_envelope_valid
        and event.completion_marker == state.expected_completion_marker
        and event.marker_is_final_line
    )


def _settled_authority_replay(
    state: LaneTurnState,
    event: FinalTurnAuthority,
) -> bool:
    return (
        state.phase is TurnPhase.SETTLED
        and state.outcome_kind is TurnOutcomeKind.TURN_FINAL
        and _authority_correlates(state, event)
        and _authority_complete(state, event)
        and state.turn_id == event.turn_id
        and state.turn_sequence == event.turn_sequence
        and state.response_digest == event.response_digest
        and state.head_digest == event.new_head_digest
    )


def _claim_matches_provisioned(
    claim: ClaimTopologyProvisioning,
    provisioned: RecordTopologyProvisioned,
) -> bool:
    return all(
        getattr(claim, field) == getattr(provisioned, field)
        for field in (
            "operation_id",
            "canonical_request_digest",
            "attempt_id",
            "lane_id",
            "lane_generation",
            "policy_record_digest",
            "prepared_lane_record_digest",
            "topology_mutation_id",
            "topology_nonce",
        )
    )


def _claim_matches_effect_started(
    claim: ClaimTopologyProvisioning,
    effect_started: Union[
        TopologyEffectStarted,
        TopologyCommandEffectStarted,
    ],
) -> bool:
    return all(
        getattr(claim, field) == getattr(effect_started, field)
        for field in (
            "operation_id",
            "canonical_request_digest",
            "attempt_id",
            "lane_id",
            "lane_generation",
            "policy_record_digest",
            "prepared_lane_record_digest",
            "topology_mutation_id",
            "topology_nonce",
            "topology_store_incarnation_digest",
        )
    )


def _claim_is_admissible(
    state: LaneTurnState,
    event: ClaimTopologyProvisioning,
) -> bool:
    return (
        state.operation == "turn.consult"
        and state.native_identity_mode is NativeIdentityMode.ESTABLISH_NEW
        and state.expected_turn_sequence == 1
        and state.phase is TurnPhase.PREPARED
        and state.recovery_state is RecoveryState.CLEAR
        and state.promotion is AttemptPromotion.ATTEMPT_ONLY
        and state.reservation_id is None
        and state.reservation_state is ReservationState.NOT_COUNTED
        and state.dispatch_intent is None
        and state.outcome_kind is None
        and not state.possible_provider_effect_observed
        and not state.resend_allowed
        and not state.release_allowed
        and state.direct_human_policy_record_digest is not None
        and state.direct_human_policy_record_digest
        == event.policy_record_digest
        and _common_correlates(
            state,
            event.operation_id,
            event.canonical_request_digest,
            event.attempt_id,
        )
        and state.lane_id == event.lane_id
        and state.lane_generation == event.lane_generation
    )


def _reduce_topology_claim(
    state: LaneTurnState,
    event: ClaimTopologyProvisioning,
) -> LaneTurnState:
    if state.topology_provisioned is not None:
        if _claim_matches_provisioned(event, state.topology_provisioned):
            return state
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_claim_conflict"
        )
    if state.topology_provisioning_claim is not None:
        if state.topology_provisioning_claim == event:
            return state
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_claim_conflict"
        )
    if not _claim_is_admissible(state, event):
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_claim_not_admissible"
        )
    return replace(
        state,
        topology_provisioning_claim=event,
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_topology_effect_started(
    state: LaneTurnState,
    event: TopologyEffectStarted,
) -> LaneTurnState:
    existing = state.topology_effect_started
    if existing is not None:
        if existing == event:
            return state
        raise TurnTransitionError("lane_turn.topology_effect_started_conflict")
    claim = state.topology_provisioning_claim
    if (
        claim is None
        or state.topology_provisioned is not None
        or claim.topology_store_incarnation_digest is None
        or not _claim_matches_effect_started(claim, event)
    ):
        raise TurnTransitionError(
            "lane_turn.topology_effect_started_not_admissible"
        )
    return replace(
        state,
        topology_effect_started=event,
        resend_allowed=False,
        release_allowed=False,
    )


def _command_effect_correlates(
    first: TopologyEffectStarted,
    event: TopologyCommandEffectStarted,
) -> bool:
    return all(
        getattr(first, field) == getattr(event, field)
        for field in (
            "operation_id",
            "canonical_request_digest",
            "attempt_id",
            "lane_id",
            "lane_generation",
            "policy_record_digest",
            "prepared_lane_record_digest",
            "topology_mutation_id",
            "topology_nonce",
            "topology_store_incarnation_digest",
            "topology_claim_record_digest",
            "topology_mutation_record_digest",
        )
    )


def _reduce_topology_command_effect_started(
    state: LaneTurnState,
    event: TopologyCommandEffectStarted,
) -> LaneTurnState:
    claim = state.topology_provisioning_claim
    first = state.topology_effect_started
    existing = state.topology_command_effects_started
    if existing and existing[-1] == event:
        return state
    if (
        claim is None
        or first is None
        or state.topology_provisioned is not None
        or not _claim_matches_effect_started(claim, event)
        or not _command_effect_correlates(first, event)
        or event.command_sequence != len(existing) + 2
        or any(
            prior.topology_command_step_id == event.topology_command_step_id
            for prior in existing
        )
    ):
        raise TurnTransitionError(
            "lane_turn.topology_command_effect_started_not_admissible"
        )
    if existing:
        prior = existing[-1]
        if (
            event.topology_effect_started_record_digest
            != prior.topology_effect_started_record_digest
        ):
            raise TurnTransitionError(
                "lane_turn.topology_command_effect_started_not_admissible"
            )
    elif (
        event.previous_topology_effect_record_digest
        != event.topology_effect_started_record_digest
    ):
        raise TurnTransitionError(
            "lane_turn.topology_command_effect_started_not_admissible"
        )
    return replace(
        state,
        topology_command_effects_started=existing + (event,),
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_topology_provisioned(
    state: LaneTurnState,
    event: RecordTopologyProvisioned,
) -> LaneTurnState:
    if state.topology_provisioned is not None:
        if state.topology_provisioned == event:
            return state
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_proof_conflict"
        )
    claim = state.topology_provisioning_claim
    if claim is None or not _claim_matches_provisioned(claim, event):
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_proof_conflict"
        )
    effect_started = state.topology_effect_started
    command_effects_started = state.topology_command_effects_started
    if claim.topology_store_incarnation_digest is not None:
        if (
            effect_started is None
            or event.topology_effect_started_record_digest is None
        ):
            raise TurnTransitionError(
                "lane_turn.topology_effect_started_record_required"
            )
        if command_effects_started:
            if (
                event.topology_last_command_effect_started_record_digest
                is None
            ):
                raise TurnTransitionError(
                    "lane_turn.topology_command_effect_started_record_required"
                )
        elif (
            event.topology_last_command_effect_started_record_digest
            is not None
        ):
            raise TurnTransitionError(
                "lane_turn.topology_provisioning_proof_conflict"
            )
    elif (
        effect_started is not None
        or event.topology_effect_started_record_digest is not None
        or command_effects_started
        or event.topology_last_command_effect_started_record_digest
        is not None
    ):
        raise TurnTransitionError(
            "lane_turn.topology_provisioning_proof_conflict"
        )
    return replace(
        state,
        topology_provisioning_claim=None,
        topology_provisioned=event,
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_recovery_result_evidence_link(
    state: LaneTurnState,
    event: RecordRecoveryResultEvidenceAnchor,
) -> LaneTurnState:
    existing = state.recovery_result_evidence_anchors
    for prior in existing:
        if prior.recovery_operation_id == event.recovery_operation_id:
            if prior == event:
                return state
            raise TurnTransitionError(
                "lane_turn.recovery_result_evidence_link_conflict"
            )
        if prior.evidence_link_record_digest == event.evidence_link_record_digest:
            raise TurnTransitionError(
                "lane_turn.recovery_result_evidence_link_conflict"
            )
        if (
            prior.source_relationship_digest
            == event.source_relationship_digest
            or prior.evidence_registry_binding_digest
            != event.evidence_registry_binding_digest
        ):
            raise TurnTransitionError(
                "lane_turn.recovery_result_evidence_link_conflict"
            )
    provisioned = state.topology_provisioned
    if (
        provisioned is None
        or provisioned.recovery_result_store_binding_digest is None
        or event.source_lane_operation_id != state.operation_id
        or event.source_lane_canonical_request_digest
        != state.canonical_request_digest
        or event.attempt_id != state.attempt_id
        or event.lane_id != state.lane_id
        or event.lane_generation != state.lane_generation
        or event.topology_mutation_id != provisioned.topology_mutation_id
        or event.recovery_result_store_binding_digest
        != provisioned.recovery_result_store_binding_digest
    ):
        raise TurnTransitionError(
            "lane_turn.recovery_result_evidence_link_not_admissible"
        )
    return replace(
        state,
        recovery_result_evidence_anchors=existing + (event,),
    )


def _reduce_dispatch(
    state: LaneTurnState,
    event: BeginDispatch,
) -> LaneTurnState:
    _require_common_correlation(
        state,
        event.operation_id,
        event.canonical_request_digest,
        event.attempt_id,
    )
    if state.direct_human_policy_record_digest is not None:
        if state.topology_provisioned is None:
            raise TurnTransitionError(
                "lane_turn.topology_provisioning_not_settled"
            )
        if (
            event.project_topology_digest
            != state.topology_provisioned.project_topology_digest
        ):
            raise TurnTransitionError(
                "lane_turn.topology_provisioning_digest_mismatch"
            )
    elif event.project_topology_digest is not None:
        raise TurnTransitionError(
            "lane_turn.project_topology_digest_not_admissible"
        )
    intended = event.intent()
    if state.dispatch_intent is not None:
        if state.dispatch_intent == intended:
            return state
        raise TurnTransitionError("lane_turn.dispatch_intent_conflict")
    if (
        state.phase is not TurnPhase.PREPARED
        or state.recovery_state is not RecoveryState.CLEAR
        or state.outcome_kind is not None
    ):
        raise TurnTransitionError("lane_turn.dispatch_not_admissible")
    return replace(
        state,
        phase=_monotonic_phase(state.phase, TurnPhase.DISPATCHING),
        dispatch_intent=intended,
    )


def _reduce_uncertain(
    state: LaneTurnState,
    event: RecordDeliveryUncertain,
) -> LaneTurnState:
    _require_common_correlation(
        state,
        event.operation_id,
        event.canonical_request_digest,
        event.attempt_id,
    )
    if state.recovery_state is RecoveryState.QUARANTINED:
        return state
    if state.dispatch_intent is None or state.phase is TurnPhase.SETTLED:
        raise TurnTransitionError("lane_turn.delivery_observation_not_admissible")
    if state.promotion is AttemptPromotion.CONSULTANT_TURN:
        raise TurnTransitionError("lane_turn.delivery_already_started")
    return replace(
        state,
        phase=_monotonic_phase(state.phase, TurnPhase.DISPATCHING),
        recovery_state=RecoveryState.RECONCILIATION_REQUIRED,
        outcome_kind=TurnOutcomeKind.DELIVERY_UNCERTAIN,
        retry_disposition=RetryDisposition.RECONCILE_FIRST,
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_non_start(
    state: LaneTurnState,
    event: RecordDefiniteNonStart,
) -> LaneTurnState:
    _require_common_correlation(
        state,
        event.operation_id,
        event.canonical_request_digest,
        event.attempt_id,
    )
    if state.dispatch_intent is None:
        raise TurnTransitionError("lane_turn.non_start_without_dispatch_intent")
    if state.possible_provider_effect_observed:
        return _quarantine(state)
    if state.promotion is not AttemptPromotion.ATTEMPT_ONLY:
        return _quarantine(state)
    if state.phase is TurnPhase.SETTLED:
        if state.outcome_kind is TurnOutcomeKind.TURN_DEFINITE_NON_START:
            return state
        return _quarantine(state)
    return replace(
        state,
        phase=TurnPhase.SETTLED,
        recovery_state=RecoveryState.CLEAR,
        reservation_state=_reserve_non_start(state.reservation_state),
        outcome_kind=TurnOutcomeKind.TURN_DEFINITE_NON_START,
        retry_disposition=RetryDisposition.SAFE_RETRY_ELIGIBLE,
        resend_allowed=False,
        release_allowed=True,
    )


def _reduce_response_conflict(
    state: LaneTurnState,
    event: RecordResponseValidationConflict,
) -> LaneTurnState:
    _require_common_correlation(
        state,
        event.operation_id,
        event.canonical_request_digest,
        event.attempt_id,
    )
    if state.dispatch_intent is None:
        raise TurnTransitionError(
            "lane_turn.response_conflict_without_dispatch_intent"
        )
    if state.recovery_state is RecoveryState.QUARANTINED:
        return state
    return replace(
        _quarantine(state),
        possible_provider_effect_observed=True,
    )


def _reduce_started(
    state: LaneTurnState,
    event: RecordProviderStarted,
) -> LaneTurnState:
    if state.recovery_state is RecoveryState.QUARANTINED:
        return state
    if not (
        _common_correlates(
            state,
            event.operation_id,
            event.canonical_request_digest,
            event.attempt_id,
        )
        and state.lane_id == event.lane_id
        and state.lane_generation == event.lane_generation
        and state.expected_turn_sequence == event.turn_sequence
        and _native_identity_correlates(
            state,
            event.native_correlation_digest,
            event.source_native_correlation_digest,
        )
    ):
        return replace(
            _quarantine(state),
            possible_provider_effect_observed=True,
        )
    if state.dispatch_intent is None:
        raise TurnTransitionError("lane_turn.provider_start_without_dispatch_intent")
    if state.promotion is AttemptPromotion.CONSULTANT_TURN:
        if (
            state.turn_id == event.turn_id
            and state.turn_sequence == event.turn_sequence
            and state.established_native_correlation_digest
            == event.native_correlation_digest
        ):
            return state
        return _quarantine(state)
    if state.phase is TurnPhase.SETTLED:
        return _quarantine(state)
    recovery = state.recovery_state
    outcome = state.outcome_kind
    retry = state.retry_disposition
    if recovery is RecoveryState.CLEAR:
        outcome = None
        retry = RetryDisposition.NONE
    elif recovery is RecoveryState.RECONCILIATION_REQUIRED:
        outcome = TurnOutcomeKind.TURN_RECONCILIATION_REQUIRED
        retry = RetryDisposition.RECONCILE_FIRST
    return replace(
        state,
        phase=_monotonic_phase(state.phase, TurnPhase.IN_FLIGHT),
        promotion=AttemptPromotion.CONSULTANT_TURN,
        reservation_state=_reserve_started(state.reservation_state),
        outcome_kind=outcome,
        retry_disposition=retry,
        turn_id=event.turn_id,
        turn_sequence=event.turn_sequence,
        established_native_correlation_digest=event.native_correlation_digest,
        possible_provider_effect_observed=True,
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_wait_timeout(
    state: LaneTurnState,
    event: RecordAdvisoryWaitTimeout,
) -> LaneTurnState:
    _require_common_correlation(
        state,
        event.operation_id,
        event.canonical_request_digest,
        event.attempt_id,
    )
    if state.recovery_state is RecoveryState.QUARANTINED:
        return state
    if state.dispatch_intent is None or state.phase is TurnPhase.SETTLED:
        raise TurnTransitionError("lane_turn.wait_observation_not_admissible")
    return replace(
        state,
        recovery_state=RecoveryState.RECONCILIATION_REQUIRED,
        outcome_kind=TurnOutcomeKind.TURN_RECONCILIATION_REQUIRED,
        retry_disposition=RetryDisposition.RECONCILE_FIRST,
        advisory_wait_timed_out=True,
        resend_allowed=False,
        release_allowed=False,
    )


def _reduce_final(
    state: LaneTurnState,
    event: FinalTurnAuthority,
) -> LaneTurnState:
    if state.dispatch_intent is None:
        raise TurnTransitionError("lane_turn.authority_without_dispatch_intent")
    if state.recovery_state is RecoveryState.QUARANTINED:
        return state
    if _settled_authority_replay(state, event):
        return state
    if not _authority_correlates(state, event):
        return _quarantine(state)
    if not _authority_complete(state, event):
        if state.phase is TurnPhase.SETTLED:
            return _quarantine(state)
        return replace(
            state,
            phase=TurnPhase.VALIDATING,
            recovery_state=RecoveryState.RECONCILIATION_REQUIRED,
            outcome_kind=TurnOutcomeKind.TURN_RECONCILIATION_REQUIRED,
            retry_disposition=RetryDisposition.RECONCILE_FIRST,
            possible_provider_effect_observed=(
                state.possible_provider_effect_observed
                or (event.response_present and event.response_fresh)
            ),
            resend_allowed=False,
            release_allowed=False,
        )
    if event.new_head_digest == state.expected_head_digest:
        return _quarantine(state)
    if state.phase is TurnPhase.SETTLED:
        return _quarantine(state)
    return replace(
        state,
        phase=TurnPhase.SETTLED,
        recovery_state=RecoveryState.CLEAR,
        promotion=AttemptPromotion.CONSULTANT_TURN,
        reservation_state=_reserve_started(state.reservation_state),
        retry_disposition=RetryDisposition.NONE,
        outcome_kind=TurnOutcomeKind.TURN_FINAL,
        head_digest=event.new_head_digest,
        response_digest=event.response_digest,
        turn_id=event.turn_id,
        turn_sequence=event.turn_sequence,
        established_native_correlation_digest=event.native_correlation_digest,
        possible_provider_effect_observed=True,
        resend_allowed=False,
        release_allowed=True,
    )


def reduce_turn(
    state: Optional[LaneTurnState],
    event: LaneTurnEvent,
) -> LaneTurnState:
    """Apply one closed event without performing or authorizing external work."""

    if state is None:
        if type(event) is not PrepareAdmittedAttempt:
            raise TurnTransitionError("lane_turn.prepare_required")
        return _prepare(event)
    if type(state) is not LaneTurnState:
        raise ValueError("lane_turn.state_type_invalid")
    if type(event) is PrepareAdmittedAttempt:
        if _prepare_matches(state, event):
            return state
        raise TurnTransitionError("lane_turn.prepare_conflict")
    if type(event) is ClaimTopologyProvisioning:
        return _reduce_topology_claim(state, event)
    if type(event) is TopologyEffectStarted:
        return _reduce_topology_effect_started(state, event)
    if type(event) is TopologyCommandEffectStarted:
        return _reduce_topology_command_effect_started(state, event)
    if type(event) is RecordTopologyProvisioned:
        return _reduce_topology_provisioned(state, event)
    if type(event) is RecordRecoveryResultEvidenceAnchor:
        return _reduce_recovery_result_evidence_link(state, event)
    if type(event) is BeginDispatch:
        return _reduce_dispatch(state, event)
    if type(event) is RecordDeliveryUncertain:
        return _reduce_uncertain(state, event)
    if type(event) is RecordResponseValidationConflict:
        return _reduce_response_conflict(state, event)
    if type(event) is RecordDefiniteNonStart:
        return _reduce_non_start(state, event)
    if type(event) is RecordProviderStarted:
        return _reduce_started(state, event)
    if type(event) is RecordAdvisoryWaitTimeout:
        return _reduce_wait_timeout(state, event)
    if type(event) is FinalTurnAuthority:
        return _reduce_final(state, event)
    raise ValueError("lane_turn.event_type_invalid")


__all__ = (
    "AttemptPromotion",
    "BeginDispatch",
    "ClaimTopologyProvisioning",
    "DefiniteNonStartProof",
    "DispatchIntent",
    "FinalTurnAuthority",
    "LaneTurnEvent",
    "LaneTurnState",
    "NativeIdentityMode",
    "PrepareAdmittedAttempt",
    "RecordAdvisoryWaitTimeout",
    "RecordDefiniteNonStart",
    "RecordDeliveryUncertain",
    "RecordProviderStarted",
    "RecordResponseValidationConflict",
    "RecordRecoveryResultEvidenceAnchor",
    "RecordTopologyProvisioned",
    "TopologyEffectStarted",
    "TopologyCommandEffectStarted",
    "RecoveryState",
    "ReservationState",
    "RetryDisposition",
    "TurnOutcomeKind",
    "TurnPhase",
    "TurnTransitionError",
    "reduce_turn",
)
