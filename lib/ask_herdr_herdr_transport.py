"""Provider-free Herdr command orchestration and topology ownership proofs.

This module deliberately has no subprocess, filesystem, provider, or lane-store
implementation.  A caller supplies an exact command runner and persists the
immutable proofs returned here.  Herdr lifecycle data remains evidence only.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import posixpath
import re
import shlex
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Tuple

from ask_herdr_topology_contract import (
    LaneTopologyProof,
    ProjectTopologyProof,
    SessionBinding,
    TopologySideEffectProof,
    WorkspaceProof,
    topology_resource_fingerprint,
)


SESSION_NAMESPACE = "ask-pipeline"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONSULTANT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class CommandResponse:
    """Raw result returned by the injected Herdr command runner."""

    exit_code: int
    stdout: str
    stderr: str = ""


class ReceiptKind(str, Enum):
    SESSION_LIST = "session_list"
    SESSION_START = "session_start"
    SESSION_STOP = "session_stop"
    SESSION_DELETE = "session_delete"
    SNAPSHOT = "snapshot"
    WORKSPACE_CREATE = "workspace_create"
    WORKSPACE_CLOSE = "workspace_close"
    PANE_RUN = "pane_run"


class ReceiptAuthority(str, Enum):
    TOPOLOGY_EVIDENCE = "topology_evidence"
    ADVISORY = "advisory"


@dataclass(frozen=True)
class CommandReceipt:
    """Typed, content-addressed receipt parsed from one Herdr JSON response."""

    kind: ReceiptKind
    argv: Tuple[str, ...]
    exit_code: int
    request_id: Optional[str]
    result_type: Optional[str]
    payload: Mapping[str, Any]
    error_code: Optional[str]
    stderr: str
    receipt_digest: str
    authority: ReceiptAuthority


@dataclass(frozen=True)
class TransportTrustSeed:
    """Minimal typed trust reconstructed from the durable topology journal."""

    receipt_kinds: Tuple[Tuple[str, ReceiptKind], ...]
    seen_request_ids: Tuple[str, ...]
    session_generations: Tuple[Tuple[str, str, str], ...]
    resource_receipt_bindings: Tuple[
        Tuple[str, Tuple[Tuple[str, ...], ...]], ...
    ]

    def __post_init__(self) -> None:
        if self.receipt_kinds != tuple(sorted(set(self.receipt_kinds))):
            raise ValueError("herdr_transport.trust_seed_invalid")
        if self.seen_request_ids != tuple(sorted(set(self.seen_request_ids))):
            raise ValueError("herdr_transport.trust_seed_invalid")
        if self.session_generations != tuple(
            sorted(set(self.session_generations))
        ):
            raise ValueError("herdr_transport.trust_seed_invalid")
        if self.resource_receipt_bindings != tuple(
            sorted(self.resource_receipt_bindings)
        ):
            raise ValueError("herdr_transport.trust_seed_invalid")


class TransportErrorKind(str, Enum):
    INVALID_INTENT = "invalid_intent"
    INVALID_RECEIPT = "invalid_receipt"
    NAMESPACE_UNOWNED = "namespace_unowned"
    TOPOLOGY_MUTATION_AMBIGUOUS = "topology_mutation_ambiguous"
    TOPOLOGY_OWNERSHIP_MISMATCH = "topology_ownership_mismatch"
    RELEASE_OWNERSHIP_MISMATCH = "release_ownership_mismatch"
    RELEASE_AMBIGUOUS = "release_ambiguous"


class TransportError(Exception):
    """Fail-closed transport error retaining every command receipt obtained."""

    def __init__(
        self,
        kind: TransportErrorKind,
        message: str,
        *,
        receipts: Sequence[CommandReceipt] = (),
        delivery_uncertain: bool = False,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.receipts = tuple(receipts)
        self.delivery_uncertain = delivery_uncertain


@dataclass(frozen=True)
class ProvisionIntent:
    project_id: str
    lane_id: str
    consultant_key: str
    project_root: str
    topology_nonce: str
    lane_workspace_cwd: Optional[str] = None


class ProvisionOutcome(str, Enum):
    CREATED = "created"
    ADOPTED = "adopted"


@dataclass(frozen=True)
class ProvisionResult:
    outcome: ProvisionOutcome
    project: ProjectTopologyProof
    lane: LaneTopologyProof
    receipts: Tuple[CommandReceipt, ...]


@dataclass(frozen=True, init=False)
class DispatchIntent:
    """One exact immutable adapter launch; prompt content stays outside Herdr."""

    project_id: str
    lane_id: str
    operation_id: str
    response_evidence_ref: str
    response_nonce: str
    launch_argv: Tuple[str, ...]
    packet_evidence_ref: str
    profile_binding_digest: str

    def __init__(
        self,
        project_id: str,
        lane_id: str,
        operation_id: str,
        response_evidence_ref: str,
        response_nonce: str,
        launch_argv: Optional[Tuple[str, ...]] = None,
        packet_evidence_ref: Optional[str] = None,
        profile_binding_digest: Optional[str] = None,
        *,
        launch_command: Optional[str] = None,
    ) -> None:
        """Normalize the old non-shell test fixture into the immutable seam.

        ``launch_command`` is not retained as data.  Its compatibility parser
        accepts only the exact three-token launcher/``--packet`` form and can
        therefore never preserve shell operators or expansions.
        """

        if launch_command is not None:
            if launch_argv is not None or packet_evidence_ref is not None:
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    "legacy launch text cannot accompany immutable launch fields",
                )
            try:
                parsed = tuple(shlex.split(launch_command, posix=True))
            except ValueError as exc:
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    "legacy launch text is not a valid exact command",
                ) from exc
            if len(parsed) != 3 or parsed[1] != "--packet":
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    "legacy launch text must contain only launcher --packet reference",
                )
            launch_argv = parsed
            packet_evidence_ref = parsed[2]
            profile_binding_digest = "sha256:" + hashlib.sha256(
                json.dumps(parsed, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(self, "lane_id", lane_id)
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "response_evidence_ref", response_evidence_ref)
        object.__setattr__(self, "response_nonce", response_nonce)
        object.__setattr__(self, "launch_argv", launch_argv)
        object.__setattr__(self, "packet_evidence_ref", packet_evidence_ref)
        object.__setattr__(self, "profile_binding_digest", profile_binding_digest)


class ResponseAuthority(str, Enum):
    DURABLE_RESPONSE_AND_TERMINAL_MARKER = (
        "durable_response_and_terminal_marker"
    )


@dataclass(frozen=True)
class ResponseExpectation:
    response_evidence_ref: str
    terminal_marker: str
    authority: ResponseAuthority
    freshness_required: bool = True
    terminal_marker_must_be_final_line: bool = True
    herdr_lifecycle_authoritative: bool = False


class DispatchOutcome(str, Enum):
    SUBMITTED_AWAITING_RESPONSE = "submitted_awaiting_response"
    DELIVERY_UNCONFIRMED = "delivery_unconfirmed"


class RetryDisposition(str, Enum):
    NONE = "none"
    RECONCILE_FIRST = "reconcile_first"


@dataclass(frozen=True)
class DispatchResult:
    outcome: DispatchOutcome
    lane: LaneTopologyProof
    response_expectation: ResponseExpectation
    retry_disposition: RetryDisposition
    resend_allowed: bool
    completion_established: bool
    receipts: Tuple[CommandReceipt, ...]


class ReleaseScope(str, Enum):
    WORKSPACE = "workspace"
    SESSION = "session"


@dataclass(frozen=True)
class ReleaseIntent:
    project_id: str
    operation_id: str
    scope: ReleaseScope
    lane_ids: Tuple[str, ...]
    side_effect_workspace_ids: Tuple[str, ...]


class ReleaseOutcome(str, Enum):
    WORKSPACE_RELEASED = "workspace_released"
    SESSION_RELEASED = "session_released"


@dataclass(frozen=True)
class ReleaseResult:
    outcome: ReleaseOutcome
    released_lane_ids: Tuple[str, ...]
    released_workspace_ids: Tuple[str, ...]
    project: Optional[ProjectTopologyProof]
    receipts: Tuple[CommandReceipt, ...]


Runner = Callable[[Tuple[str, ...]], CommandResponse]


@dataclass(frozen=True)
class PlannedTopologyCommand:
    """One exact mutating command that must be durable before invocation."""

    kind: ReceiptKind
    argv: Tuple[str, ...]


def provision_planned_commands(
    intent: ProvisionIntent,
) -> Tuple[PlannedTopologyCommand, PlannedTopologyCommand]:
    """Return the one canonical first-Lane provision command sequence."""

    HerdrTransport._validate_intent(intent)
    lane_workspace_cwd = intent.lane_workspace_cwd or intent.project_root
    label = HerdrTransport._lane_label(
        intent.project_id,
        intent.lane_id,
        intent.consultant_key,
        intent.topology_nonce,
    )
    return (
        PlannedTopologyCommand(
            kind=ReceiptKind.SESSION_START,
            argv=("--session", SESSION_NAMESPACE, "server"),
        ),
        PlannedTopologyCommand(
            kind=ReceiptKind.WORKSPACE_CREATE,
            argv=(
                "--session",
                SESSION_NAMESPACE,
                "workspace",
                "create",
                "--cwd",
                lane_workspace_cwd,
                "--label",
                label,
                "--no-focus",
            ),
        ),
    )


@dataclass(frozen=True)
class ProvenTopologyCommand:
    """A command effect after Transport has proved its live postcondition."""

    ticket: object
    planned: PlannedTopologyCommand
    receipt: CommandReceipt
    session_binding: SessionBinding
    resources: Tuple[object, ...]
    project: ProjectTopologyProof


class ProvisionJournalPort(Protocol):
    """Narrow write-ahead/confirmation port for provision effects only."""

    def before_command(self, command: PlannedTopologyCommand) -> object:
        ...

    def after_command(self, proof: ProvenTopologyCommand) -> None:
        ...


class HerdrTransport:
    """Deep transport seam over one injected Herdr command runner."""

    def __init__(
        self,
        runner: Runner,
        *,
        trust_seed: Optional[TransportTrustSeed] = None,
    ) -> None:
        if not callable(runner):
            raise TypeError("runner must be callable")
        self._runner = runner
        self._receipts_by_digest = {}  # type: Dict[str, CommandReceipt]
        self._trusted_receipt_kinds = {}  # type: Dict[str, ReceiptKind]
        self._seen_request_ids = set()  # type: set[str]
        self._session_generations = {}  # type: Dict[Tuple[str, str], str]
        self._resource_receipt_bindings = {}  # type: Dict[str, Tuple[Tuple[str, ...], ...]]
        if trust_seed is not None:
            if not isinstance(trust_seed, TransportTrustSeed):
                raise TypeError("trust_seed must be TransportTrustSeed")
            self._trusted_receipt_kinds.update(trust_seed.receipt_kinds)
            self._seen_request_ids.update(trust_seed.seen_request_ids)
            self._session_generations.update(
                {
                    (session_dir, socket_path): generation
                    for session_dir, socket_path, generation
                    in trust_seed.session_generations
                }
            )
            self._resource_receipt_bindings.update(
                trust_seed.resource_receipt_bindings
            )

    def provision(
        self,
        intent: ProvisionIntent,
        *,
        known: Optional[ProjectTopologyProof] = None,
        journal_port: Optional[ProvisionJournalPort] = None,
    ) -> ProvisionResult:
        """Create or exactly re-prove one isolated lane workspace and pane."""

        self._validate_intent(intent)
        lane_workspace_cwd = intent.lane_workspace_cwd or intent.project_root
        receipts = []  # type: list[CommandReceipt]
        session_list, sessions = self._session_list(receipts)
        live_session = self._named_session(sessions)

        if known is None:
            if live_session is not None:
                self._fail(
                    TransportErrorKind.NAMESPACE_UNOWNED,
                    "ask-pipeline already exists without a supplied project proof",
                    receipts,
                )
            start_plan = provision_planned_commands(intent)[0]
            start_ticket = (
                journal_port.before_command(start_plan)
                if journal_port is not None
                else None
            )
            try:
                start = self._command(
                    start_plan.kind,
                    start_plan.argv,
                )
            except TransportError as exc:
                raise TransportError(
                    TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
                    "dedicated Herdr session start has an uncertain effect",
                    receipts=tuple(receipts) + exc.receipts,
                ) from exc
            receipts.append(start)
            self._require_success(
                start,
                TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
                "dedicated Herdr session start was not confirmed",
                receipts,
            )
            start_result = start.payload.get("result")
            if (
                not isinstance(start_result, dict)
                or start_result.get("type") != "server_started"
                or not isinstance(start_result.get("session"), dict)
            ):
                self._fail(
                    TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
                    "dedicated Herdr session start lacks its exact result receipt",
                    receipts,
                )
            _, sessions = self._session_list(receipts)
            live_session = self._named_session(sessions)
            if live_session is None:
                self._fail(
                    TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
                    "started namespace is absent from the session receipt",
                    receipts,
                )
            binding = self._started_session_binding(
                start,
                start_result["session"],
                live_session,
                receipts,
            )
            snapshot_receipt, snapshot = self._snapshot(receipts)
            side_effects = self._startup_side_effects(
                intent,
                snapshot,
                start.receipt_digest,
                receipts,
            )
            known = ProjectTopologyProof(
                project_id=intent.project_id,
                project_root=intent.project_root,
                namespace=SESSION_NAMESPACE,
                topology_epoch_id=intent.topology_nonce,
                session_binding=binding,
                lanes=(),
                side_effects=side_effects,
            )
            self._verify_snapshot(known, snapshot, receipts)
            if journal_port is not None:
                journal_port.after_command(
                    ProvenTopologyCommand(
                        ticket=start_ticket,
                        planned=start_plan,
                        receipt=start,
                        session_binding=binding,
                        resources=tuple(side_effects),
                        project=known,
                    )
                )
        else:
            self._validate_project_identity(known, intent, receipts)
            if live_session is None:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "recorded ask-pipeline namespace is not live",
                    receipts,
                )
            if self._session_binding(live_session, receipts) != known.session_binding:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "live session binding differs from the supplied project proof",
                    receipts,
                )
            _, snapshot = self._snapshot(receipts)
            self._verify_project(known, snapshot, receipts)

        existing = self._lane_for_key(known, intent.consultant_key)
        if existing is not None:
            if (
                existing.project_id != intent.project_id
                or existing.project_root != intent.project_root
                or existing.lane_id != intent.lane_id
                or existing.topology_nonce != intent.topology_nonce
                or existing.workspace.cwd != lane_workspace_cwd
            ):
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "consultant key is bound to a different lane proof",
                    receipts,
                )
            return ProvisionResult(
                outcome=ProvisionOutcome.ADOPTED,
                project=known,
                lane=existing,
                receipts=tuple(receipts),
            )

        if any(item.lane_id == intent.lane_id for item in known.lanes):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "lane_id is already bound to another consultant key",
                receipts,
            )

        create_plan = provision_planned_commands(intent)[1]
        label = create_plan.argv[create_plan.argv.index("--label") + 1]
        create_ticket = (
            journal_port.before_command(create_plan)
            if journal_port is not None
            else None
        )
        try:
            create = self._command(
                create_plan.kind,
                create_plan.argv,
            )
        except TransportError as exc:
            raise TransportError(
                TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
                "workspace creation has an uncertain effect",
                receipts=tuple(receipts) + exc.receipts,
            ) from exc
        receipts.append(create)
        self._require_success(
            create,
            TransportErrorKind.TOPOLOGY_MUTATION_AMBIGUOUS,
            "workspace creation was not confirmed",
            receipts,
        )
        workspace = self._workspace_from_create(
            create, lane_workspace_cwd, label, receipts
        )
        lane = LaneTopologyProof(
            project_id=intent.project_id,
            lane_id=intent.lane_id,
            consultant_key=intent.consultant_key,
            project_root=intent.project_root,
            topology_nonce=intent.topology_nonce,
            workspace=workspace,
        )
        updated = ProjectTopologyProof(
            project_id=known.project_id,
            project_root=known.project_root,
            namespace=known.namespace,
            topology_epoch_id=known.topology_epoch_id,
            session_binding=known.session_binding,
            lanes=known.lanes + (lane,),
            side_effects=known.side_effects,
        )
        _, snapshot = self._snapshot(receipts)
        self._verify_project(updated, snapshot, receipts)
        if journal_port is not None:
            journal_port.after_command(
                ProvenTopologyCommand(
                    ticket=create_ticket,
                    planned=create_plan,
                    receipt=create,
                    session_binding=updated.session_binding,
                    resources=(workspace,),
                    project=updated,
                )
            )
        return ProvisionResult(
            outcome=ProvisionOutcome.CREATED,
            project=updated,
            lane=lane,
            receipts=tuple(receipts),
        )

    def dispatch(
        self,
        intent: DispatchIntent,
        *,
        project: ProjectTopologyProof,
    ) -> DispatchResult:
        """Submit one adapter command without inferring delivery or completion."""

        self._validate_dispatch_intent(intent)
        receipts = []  # type: list[CommandReceipt]
        if (
            not isinstance(project, ProjectTopologyProof)
            or project.project_id != intent.project_id
            or project.namespace != SESSION_NAMESPACE
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "dispatch project identity differs from the topology proof",
                receipts,
            )
        lane_matches = [
            item for item in project.lanes if item.lane_id == intent.lane_id
        ]
        if len(lane_matches) != 1:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "dispatch lane is not exactly represented in the project proof",
                receipts,
            )
        lane = lane_matches[0]
        _, sessions = self._session_list(receipts)
        session = self._named_session(sessions)
        if session is None or self._session_binding(session, receipts) != project.session_binding:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "dispatch session binding is absent or changed",
                receipts,
            )
        _, snapshot = self._snapshot(receipts)
        self._verify_project(project, snapshot, receipts)

        terminal_marker = (
            "<<<ASK_HERDR_RESPONSE_COMPLETE:"
            + intent.operation_id
            + ":"
            + intent.response_nonce
            + ">>>"
        )
        launch_command = shlex.join(intent.launch_argv)
        if (
            terminal_marker in launch_command
            or intent.response_evidence_ref in launch_command
        ):
            self._fail(
                TransportErrorKind.INVALID_INTENT,
                "launch command must not expose response authority tokens",
                receipts,
            )
        expectation = ResponseExpectation(
            response_evidence_ref=intent.response_evidence_ref,
            terminal_marker=terminal_marker,
            authority=ResponseAuthority.DURABLE_RESPONSE_AND_TERMINAL_MARKER,
        )
        try:
            pane_run = self._command(
                ReceiptKind.PANE_RUN,
                (
                    "--session",
                    SESSION_NAMESPACE,
                    "pane",
                    "run",
                    lane.workspace.pane_id,
                    launch_command,
                ),
            )
        except TransportError as exc:
            # _command has already invoked the pane runner.  A thrown runner,
            # malformed/uncorrelated response, duplicate request id, or any
            # other missing accepted receipt is therefore delivery-uncertain.
            # None of those cases may escape as a resendable validation error.
            return DispatchResult(
                outcome=DispatchOutcome.DELIVERY_UNCONFIRMED,
                lane=lane,
                response_expectation=expectation,
                retry_disposition=RetryDisposition.RECONCILE_FIRST,
                resend_allowed=False,
                completion_established=False,
                receipts=tuple(receipts) + exc.receipts,
            )
        receipts.append(pane_run)
        payload_result = pane_run.payload.get("result")
        confirmed_control_receipt = (
            pane_run.exit_code == 0
            and pane_run.error_code is None
            and isinstance(payload_result, dict)
            and payload_result.get("type") == "command_sent"
            and payload_result.get("pane_id") == lane.workspace.pane_id
        )
        return DispatchResult(
            outcome=(
                DispatchOutcome.SUBMITTED_AWAITING_RESPONSE
                if confirmed_control_receipt
                else DispatchOutcome.DELIVERY_UNCONFIRMED
            ),
            lane=lane,
            response_expectation=expectation,
            retry_disposition=(
                RetryDisposition.NONE
                if confirmed_control_receipt
                else RetryDisposition.RECONCILE_FIRST
            ),
            resend_allowed=False,
            completion_established=False,
            receipts=tuple(receipts),
        )

    def release(
        self,
        intent: ReleaseIntent,
        *,
        project: ProjectTopologyProof,
    ) -> ReleaseResult:
        """Release only the exact workspace or dedicated session proved live."""

        self._validate_release_intent(intent)
        receipts = []  # type: list[CommandReceipt]
        if (
            not isinstance(project, ProjectTopologyProof)
            or project.project_id != intent.project_id
            or project.namespace != SESSION_NAMESPACE
        ):
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "release project identity differs from the topology proof",
                receipts,
            )
        _, sessions = self._session_list(receipts)
        session = self._named_session(sessions)
        if session is None or self._session_binding(session, receipts) != project.session_binding:
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "release session binding is absent or changed",
                receipts,
            )
        _, snapshot = self._snapshot(receipts)
        try:
            self._verify_project(project, snapshot, receipts)
        except TransportError as exc:
            raise TransportError(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                exc.message,
                receipts=exc.receipts,
            ) from exc

        if intent.scope is ReleaseScope.SESSION:
            expected_lane_ids = tuple(sorted(item.lane_id for item in project.lanes))
            expected_side_effect_ids = tuple(
                sorted(item.workspace_id for item in project.side_effects)
            )
            if (
                intent.lane_ids != expected_lane_ids
                or intent.side_effect_workspace_ids != expected_side_effect_ids
            ):
                self._fail(
                    TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                    "session Release Set does not exactly acknowledge the proved live set",
                    receipts,
                )
            try:
                stop = self._command(
                    ReceiptKind.SESSION_STOP,
                    ("session", "stop", "--json", SESSION_NAMESPACE),
                )
            except TransportError as exc:
                raise TransportError(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "session stop has an uncertain effect",
                    receipts=tuple(receipts) + exc.receipts,
                ) from exc
            receipts.append(stop)
            if (
                stop.exit_code != 0
                or stop.error_code is not None
                or stop.payload.get("session") != SESSION_NAMESPACE
                or stop.payload.get("status") != "stopped"
            ):
                self._fail(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "session stop lacks an exact success receipt",
                    receipts,
                )
            try:
                _, stopped_sessions = self._session_list(receipts)
                stopped_session = self._named_session(stopped_sessions)
            except TransportError as exc:
                raise TransportError(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "cannot prove the exact session-stop postcondition",
                    receipts=exc.receipts,
                ) from exc
            if (
                stopped_session is None
                or stopped_session.get("running") is not False
                or self._session_binding(stopped_session, receipts)
                != project.session_binding
            ):
                self._fail(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "dedicated session did not retain its exact stopped binding",
                    receipts,
                )
            try:
                delete = self._command(
                    ReceiptKind.SESSION_DELETE,
                    ("session", "delete", "--json", SESSION_NAMESPACE),
                )
            except TransportError as exc:
                raise TransportError(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "session delete has an uncertain effect",
                    receipts=tuple(receipts) + exc.receipts,
                ) from exc
            receipts.append(delete)
            if (
                delete.exit_code != 0
                or delete.error_code is not None
                or delete.payload.get("session") != SESSION_NAMESPACE
                or delete.payload.get("status") != "deleted"
            ):
                self._fail(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "session delete lacks an exact success receipt",
                    receipts,
                )
            try:
                _, final_sessions = self._session_list(receipts)
                final_session = self._named_session(final_sessions)
            except TransportError as exc:
                raise TransportError(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "cannot prove the exact session-delete postcondition",
                    receipts=exc.receipts,
                ) from exc
            if final_session is not None:
                self._fail(
                    TransportErrorKind.RELEASE_AMBIGUOUS,
                    "deleted ask-pipeline session remains present",
                    receipts,
                )
            released_workspace_ids = tuple(
                sorted(
                    [item.workspace.workspace_id for item in project.lanes]
                    + [item.workspace_id for item in project.side_effects]
                )
            )
            return ReleaseResult(
                outcome=ReleaseOutcome.SESSION_RELEASED,
                released_lane_ids=expected_lane_ids,
                released_workspace_ids=released_workspace_ids,
                project=None,
                receipts=tuple(receipts),
            )
        if len(intent.lane_ids) != 1 or intent.side_effect_workspace_ids:
            self._fail(
                TransportErrorKind.INVALID_INTENT,
                "workspace release names exactly one lane and no side effects",
                receipts,
            )
        lane = next(
            (item for item in project.lanes if item.lane_id == intent.lane_ids[0]),
            None,
        )
        if lane is None:
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "workspace release lane is absent from the project proof",
                receipts,
            )

        try:
            close = self._command(
                ReceiptKind.WORKSPACE_CLOSE,
                (
                    "--session",
                    SESSION_NAMESPACE,
                    "workspace",
                    "close",
                    lane.workspace.workspace_id,
                ),
            )
        except TransportError as exc:
            raise TransportError(
                TransportErrorKind.RELEASE_AMBIGUOUS,
                "workspace close has an uncertain effect",
                receipts=tuple(receipts) + exc.receipts,
            ) from exc
        receipts.append(close)
        close_result = close.payload.get("result")
        if (
            close.exit_code != 0
            or close.error_code is not None
            or not isinstance(close_result, dict)
            or close_result.get("type") != "workspace_closed"
            or close_result.get("workspace_id") != lane.workspace.workspace_id
        ):
            self._fail(
                TransportErrorKind.RELEASE_AMBIGUOUS,
                "workspace close lacks an exact success receipt",
                receipts,
            )

        _, after = self._snapshot(receipts)
        remaining_lanes = tuple(
            item for item in project.lanes if item.lane_id != lane.lane_id
        )
        base_project = ProjectTopologyProof(
            project_id=project.project_id,
            project_root=project.project_root,
            namespace=project.namespace,
            topology_epoch_id=project.topology_epoch_id,
            session_binding=project.session_binding,
            lanes=remaining_lanes,
            side_effects=project.side_effects,
        )
        expected_ids = {
            item.workspace.workspace_id for item in base_project.lanes
        } | {item.workspace_id for item in base_project.side_effects}
        live_ids = self._id_set(after["workspaces"], "workspace_id", receipts)
        if not expected_ids.issubset(live_ids):
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "workspace release changed another proved workspace",
                receipts,
            )
        new_ids = live_ids - expected_ids
        if new_ids and (expected_ids or len(new_ids) != 1):
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "workspace release produced an unbounded topology side effect",
                receipts,
            )
        new_side_effects = tuple(
            self._side_effect_from_project_snapshot(
                project,
                after,
                workspace_id,
                close.receipt_digest,
                receipts,
            )
            for workspace_id in sorted(new_ids)
        )
        if any(
            item.label != "Workspace 1" or item.cwd != project.project_root
            for item in new_side_effects
        ):
            self._fail(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                "workspace close produced an uncorrelated replacement",
                receipts,
            )
        self._record_resource_receipt_binding(
            close.receipt_digest,
            new_side_effects,
            receipts,
        )
        updated = ProjectTopologyProof(
            project_id=base_project.project_id,
            project_root=base_project.project_root,
            namespace=base_project.namespace,
            topology_epoch_id=base_project.topology_epoch_id,
            session_binding=base_project.session_binding,
            lanes=base_project.lanes,
            side_effects=base_project.side_effects + new_side_effects,
        )
        try:
            self._verify_project(updated, after, receipts)
        except TransportError as exc:
            raise TransportError(
                TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
                exc.message,
                receipts=exc.receipts,
            ) from exc
        return ReleaseResult(
            outcome=ReleaseOutcome.WORKSPACE_RELEASED,
            released_lane_ids=(lane.lane_id,),
            released_workspace_ids=(lane.workspace.workspace_id,),
            project=updated,
            receipts=tuple(receipts),
        )

    @staticmethod
    def _validate_intent(intent: ProvisionIntent) -> None:
        if not isinstance(intent, ProvisionIntent):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "intent must be ProvisionIntent",
            )
        for label, value in (
            ("project_id", intent.project_id),
            ("lane_id", intent.lane_id),
            ("topology_nonce", intent.topology_nonce),
        ):
            if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    f"{label} is not a valid stable identifier",
                )
        if (
            not isinstance(intent.consultant_key, str)
            or _CONSULTANT_KEY.fullmatch(intent.consultant_key) is None
        ):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "consultant_key is invalid",
            )
        if (
            not isinstance(intent.project_root, str)
            or not intent.project_root.startswith("/")
            or "\x00" in intent.project_root
            or posixpath.normpath(intent.project_root) != intent.project_root
        ):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "project_root must be an absolute canonical path supplied by the core",
            )
        if intent.lane_workspace_cwd is not None:
            if (
                not isinstance(intent.lane_workspace_cwd, str)
                or not intent.lane_workspace_cwd.startswith("/")
                or "\x00" in intent.lane_workspace_cwd
                or posixpath.normpath(intent.lane_workspace_cwd)
                != intent.lane_workspace_cwd
                or intent.lane_workspace_cwd == intent.project_root
            ):
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    "lane_workspace_cwd must be a distinct absolute canonical path",
                )

    @staticmethod
    def _validate_dispatch_intent(intent: DispatchIntent) -> None:
        if not isinstance(intent, DispatchIntent):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "intent must be DispatchIntent",
            )
        for label, value in (
            ("project_id", intent.project_id),
            ("lane_id", intent.lane_id),
            ("operation_id", intent.operation_id),
            ("response_nonce", intent.response_nonce),
        ):
            if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    f"{label} is not a valid stable identifier",
                )
        if (
            not isinstance(intent.response_evidence_ref, str)
            or not intent.response_evidence_ref
            or len(intent.response_evidence_ref) > 512
            or "\x00" in intent.response_evidence_ref
        ):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "response_evidence_ref is invalid",
            )
        if (
            not isinstance(intent.launch_argv, tuple)
            or len(intent.launch_argv) != 3
            or intent.launch_argv[1] != "--packet"
            or any(
                not isinstance(value, str)
                or not value
                or "\x00" in value
                or "\n" in value
                or "\r" in value
                for value in intent.launch_argv
            )
            or intent.packet_evidence_ref != intent.launch_argv[2]
            or not isinstance(intent.packet_evidence_ref, str)
            or not intent.packet_evidence_ref
        ):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "launch_argv must be the exact launcher --packet reference tuple",
            )
        digest = intent.profile_binding_digest
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "profile_binding_digest is invalid",
            )

    @staticmethod
    def _validate_release_intent(intent: ReleaseIntent) -> None:
        if not isinstance(intent, ReleaseIntent):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "intent must be ReleaseIntent",
            )
        for label, value in (
            ("project_id", intent.project_id),
            ("operation_id", intent.operation_id),
        ):
            if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    f"{label} is not a valid stable identifier",
                )
        if not isinstance(intent.scope, ReleaseScope):
            raise TransportError(
                TransportErrorKind.INVALID_INTENT,
                "release scope is invalid",
            )
        for label, values in (
            ("lane_ids", intent.lane_ids),
            ("side_effect_workspace_ids", intent.side_effect_workspace_ids),
        ):
            if (
                not isinstance(values, tuple)
                or tuple(sorted(values)) != values
                or len(values) != len(set(values))
                or any(
                    not isinstance(value, str)
                    or _IDENTIFIER.fullmatch(value) is None
                    for value in values
                )
            ):
                raise TransportError(
                    TransportErrorKind.INVALID_INTENT,
                    f"{label} must be a sorted unique tuple of stable identifiers",
                )

    def _command(self, kind: ReceiptKind, argv: Tuple[str, ...]) -> CommandReceipt:
        try:
            response = self._runner(argv)
        except Exception as exc:
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr runner raised before returning a receipt: {exc}",
                delivery_uncertain=True,
            ) from exc
        if not isinstance(response, CommandResponse):
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                "Herdr runner returned an unsupported response object",
            )
        def closed_object(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
            value = {}  # type: Dict[str, Any]
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"duplicate JSON object key: {key}")
                value[key] = item
            return value

        try:
            payload = json.loads(response.stdout, object_pairs_hook=closed_object)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} response is not JSON: {exc}",
            ) from exc
        if not isinstance(payload, dict):
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} response is not an object",
            )
        if "result" in payload and "error" in payload:
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} response contains both result and error",
            )
        if "result" in payload and not isinstance(payload["result"], dict):
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} result is not an object",
            )
        if "error" in payload and not isinstance(payload["error"], dict):
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} error is not an object",
            )
        result = payload.get("result", payload)
        error = payload.get("error")
        result_type = result.get("type") if isinstance(result, dict) else None
        error_code = error.get("code") if isinstance(error, dict) else None
        request_id = payload.get("id")
        if request_id is not None and not isinstance(request_id, str):
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} request id is not a string",
            )
        if request_id is not None:
            if not request_id or request_id in self._seen_request_ids:
                raise TransportError(
                    TransportErrorKind.INVALID_RECEIPT,
                    f"Herdr {kind.value} request id is absent or stale",
                )
            self._seen_request_ids.add(request_id)
        elif kind in {
            ReceiptKind.SESSION_START,
            ReceiptKind.SNAPSHOT,
            ReceiptKind.WORKSPACE_CREATE,
            ReceiptKind.WORKSPACE_CLOSE,
            ReceiptKind.PANE_RUN,
        }:
            raise TransportError(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr {kind.value} response omitted request correlation",
            )
        digest_input = json.dumps(
            {
                "argv": argv,
                "exit_code": response.exit_code,
                "stdout": response.stdout,
                "stderr": response.stderr,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        receipt = CommandReceipt(
            kind=kind,
            argv=argv,
            exit_code=response.exit_code,
            request_id=request_id,
            result_type=result_type if isinstance(result_type, str) else None,
            payload=payload,
            error_code=error_code if isinstance(error_code, str) else None,
            stderr=response.stderr,
            receipt_digest="sha256:" + hashlib.sha256(digest_input).hexdigest(),
            authority=(
                ReceiptAuthority.ADVISORY
                if kind is ReceiptKind.PANE_RUN
                else ReceiptAuthority.TOPOLOGY_EVIDENCE
            ),
        )
        self._receipts_by_digest[receipt.receipt_digest] = receipt
        self._trusted_receipt_kinds[receipt.receipt_digest] = receipt.kind
        return receipt

    def _session_list(
        self, receipts: list
    ) -> Tuple[CommandReceipt, Sequence[Mapping[str, Any]]]:
        receipt = self._command(
            ReceiptKind.SESSION_LIST, ("session", "list", "--json")
        )
        receipts.append(receipt)
        self._require_success(
            receipt,
            TransportErrorKind.INVALID_RECEIPT,
            "Herdr session list failed",
            receipts,
        )
        sessions = receipt.payload.get("sessions")
        if not isinstance(sessions, list) or not all(
            isinstance(item, dict) for item in sessions
        ):
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                "Herdr session list omitted its sessions array",
                receipts,
            )
        return receipt, sessions

    def _snapshot(
        self, receipts: list
    ) -> Tuple[CommandReceipt, Mapping[str, Sequence[Mapping[str, Any]]]]:
        receipt = self._command(
            ReceiptKind.SNAPSHOT,
            ("--session", SESSION_NAMESPACE, "api", "snapshot"),
        )
        receipts.append(receipt)
        self._require_success(
            receipt,
            TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
            "Herdr topology snapshot failed",
            receipts,
        )
        result = receipt.payload.get("result", receipt.payload)
        snapshot = result.get("snapshot") if isinstance(result, dict) else None
        if not isinstance(snapshot, dict):
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                "Herdr snapshot result omitted the snapshot object",
                receipts,
            )
        for collection in ("workspaces", "tabs", "panes"):
            values = snapshot.get(collection)
            if not isinstance(values, list) or not all(
                isinstance(item, dict) for item in values
            ):
                self._fail(
                    TransportErrorKind.INVALID_RECEIPT,
                    f"Herdr snapshot {collection} is not an object array",
                    receipts,
                )
        return receipt, snapshot

    @staticmethod
    def _named_session(
        sessions: Sequence[Mapping[str, Any]],
    ) -> Optional[Mapping[str, Any]]:
        matches = [item for item in sessions if item.get("name") == SESSION_NAMESPACE]
        if len(matches) > 1:
            raise TransportError(
                TransportErrorKind.NAMESPACE_UNOWNED,
                "multiple ask-pipeline session records were returned",
            )
        return matches[0] if matches else None

    def _session_binding(
        self,
        session: Mapping[str, Any],
        receipts: Sequence[CommandReceipt],
        *,
        generation_receipt: Optional[CommandReceipt] = None,
    ) -> SessionBinding:
        values = (
            session.get("name"),
            session.get("session_dir"),
            session.get("socket_path"),
        )
        if (
            values[0] != SESSION_NAMESPACE
            or session.get("default") is not False
            or any(not isinstance(value, str) or not value for value in values[1:])
        ):
            self._fail(
                TransportErrorKind.NAMESPACE_UNOWNED,
                "session is not the dedicated non-default ask-pipeline namespace",
                receipts,
            )
        generation_key = (values[1], values[2])
        explicit_generation = session.get("generation_id")
        if explicit_generation is not None:
            if (
                not isinstance(explicit_generation, str)
                or _IDENTIFIER.fullmatch(explicit_generation) is None
            ):
                self._fail(
                    TransportErrorKind.NAMESPACE_UNOWNED,
                    "session generation identity is invalid",
                    receipts,
                )
            generation_id = explicit_generation
            self._session_generations[generation_key] = generation_id
        elif generation_receipt is not None:
            generation_id = generation_receipt.receipt_digest
            self._session_generations[generation_key] = generation_id
        else:
            # Stable Herdr directory/socket paths are not a generation
            # identity: a deleted and recreated session can reuse both.  A
            # later controller must present an explicit live generation (or,
            # in the durable integration, a separately verified trust seed).
            # Process-local fallback would silently replay old ownership.
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "session generation cannot be proved from the live receipt",
                receipts,
            )
        return SessionBinding(
            name=SESSION_NAMESPACE,
            default=False,
            session_dir=values[1],
            socket_path=values[2],
            generation_id=generation_id,
        )

    def _started_session_binding(
        self,
        start_receipt: CommandReceipt,
        receipt_session: Mapping[str, Any],
        live_session: Mapping[str, Any],
        receipts: Sequence[CommandReceipt],
    ) -> SessionBinding:
        """Bind session-start authority to the exact session named by receipt."""

        identity_fields = (
            "name",
            "default",
            "running",
            "session_dir",
            "socket_path",
        )
        if (
            receipt_session.get("running") is not True
            or live_session.get("running") is not True
            or any(
            receipt_session.get(field) != live_session.get(field)
            for field in identity_fields
            )
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "post-start session differs from the exact start receipt",
                receipts,
            )
        receipt_generation = receipt_session.get("generation_id")
        live_generation = live_session.get("generation_id")
        if (receipt_generation is None) != (live_generation is None) or (
            receipt_generation is not None
            and receipt_generation != live_generation
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "post-start session generation differs from the exact start receipt",
                receipts,
            )
        binding = self._session_binding(
            receipt_session,
            receipts,
            generation_receipt=start_receipt,
        )
        generation_key = (binding.session_dir, binding.socket_path)
        self._session_generations[generation_key] = binding.generation_id
        return binding

    def _workspace_from_create(
        self,
        receipt: CommandReceipt,
        expected_cwd: str,
        expected_label: str,
        receipts: Sequence[CommandReceipt],
    ) -> WorkspaceProof:
        result = receipt.payload.get("result")
        if not isinstance(result, dict) or result.get("type") != "workspace_created":
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                "workspace create receipt has the wrong result type",
                receipts,
            )
        workspace = result.get("workspace")
        tab = result.get("tab")
        pane = result.get("root_pane")
        if not all(isinstance(item, dict) for item in (workspace, tab, pane)):
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                "workspace create receipt omitted stable topology records",
                receipts,
            )
        proof = self._workspace_proof(
            workspace, tab, pane, receipt.receipt_digest, receipts
        )
        if proof.cwd != expected_cwd or proof.label != expected_label:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "created workspace did not preserve the recorded cwd and label",
                receipts,
            )
        self._record_resource_receipt_binding(
            receipt.receipt_digest,
            (proof,),
            receipts,
        )
        return proof

    def _side_effect_from_snapshot(
        self,
        intent: ProvisionIntent,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        workspace_id: str,
        receipt_digest: str,
        receipts: Sequence[CommandReceipt],
    ) -> TopologySideEffectProof:
        proof = self._observed_workspace(
            snapshot, workspace_id, receipt_digest, receipts
        )
        return TopologySideEffectProof(
            project_id=intent.project_id,
            project_root=intent.project_root,
            workspace_id=proof.workspace_id,
            tab_id=proof.tab_id,
            pane_id=proof.pane_id,
            label=proof.label,
            cwd=proof.cwd,
            creation_receipt_digest=proof.creation_receipt_digest,
        )

    def _startup_side_effects(
        self,
        intent: ProvisionIntent,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        receipt_digest: str,
        receipts: Sequence[CommandReceipt],
    ) -> Tuple[TopologySideEffectProof, ...]:
        """Correlate only Herdr's one exact documented startup workspace."""

        workspace_ids = self._workspace_ids(snapshot, receipts)
        if len(workspace_ids) > 1:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "startup produced an uncorrelated workspace set",
                receipts,
            )
        if not workspace_ids:
            self._record_resource_receipt_binding(receipt_digest, (), receipts)
            return ()
        side_effect = self._side_effect_from_snapshot(
            intent,
            snapshot,
            workspace_ids[0],
            receipt_digest,
            receipts,
        )
        if side_effect.label != "Workspace 1" or side_effect.cwd != intent.project_root:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "startup workspace is not the exact documented Herdr side effect",
                receipts,
            )
        self._record_resource_receipt_binding(
            receipt_digest,
            (side_effect,),
            receipts,
        )
        return (side_effect,)

    def _side_effect_from_project_snapshot(
        self,
        project: ProjectTopologyProof,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        workspace_id: str,
        receipt_digest: str,
        receipts: Sequence[CommandReceipt],
    ) -> TopologySideEffectProof:
        proof = self._observed_workspace(
            snapshot, workspace_id, receipt_digest, receipts
        )
        return TopologySideEffectProof(
            project_id=project.project_id,
            project_root=project.project_root,
            workspace_id=proof.workspace_id,
            tab_id=proof.tab_id,
            pane_id=proof.pane_id,
            label=proof.label,
            cwd=proof.cwd,
            creation_receipt_digest=proof.creation_receipt_digest,
        )

    def _observed_workspace(
        self,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        workspace_id: str,
        receipt_digest: str,
        receipts: Sequence[CommandReceipt],
    ) -> WorkspaceProof:
        workspaces = [
            item
            for item in snapshot["workspaces"]
            if item.get("workspace_id") == workspace_id
        ]
        tabs = [
            item
            for item in snapshot["tabs"]
            if item.get("workspace_id") == workspace_id
        ]
        panes = [
            item
            for item in snapshot["panes"]
            if item.get("workspace_id") == workspace_id
        ]
        if len(workspaces) != 1 or len(tabs) != 1 or len(panes) != 1:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "workspace does not have exactly one stable tab and root pane",
                receipts,
            )
        return self._workspace_proof(
            workspaces[0], tabs[0], panes[0], receipt_digest, receipts
        )

    def _workspace_proof(
        self,
        workspace: Mapping[str, Any],
        tab: Mapping[str, Any],
        pane: Mapping[str, Any],
        receipt_digest: str,
        receipts: Sequence[CommandReceipt],
    ) -> WorkspaceProof:
        workspace_id = workspace.get("workspace_id")
        tab_id = tab.get("tab_id")
        pane_id = pane.get("pane_id")
        label = workspace.get("label")
        cwd = workspace.get("cwd")
        if not all(
            isinstance(value, str) and value
            for value in (workspace_id, tab_id, pane_id, label, cwd)
        ):
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                "workspace receipt omitted a non-empty stable identifier",
                receipts,
            )
        if (
            tab.get("workspace_id") != workspace_id
            or pane.get("workspace_id") != workspace_id
            or pane.get("tab_id") != tab_id
            or ("cwd" in pane and pane.get("cwd") != cwd)
            or ("label" in pane and pane.get("label") != label)
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "workspace, tab, and pane relationships do not agree",
                receipts,
            )
        return WorkspaceProof(
            workspace_id=workspace_id,
            tab_id=tab_id,
            pane_id=pane_id,
            label=label,
            cwd=cwd,
            creation_receipt_digest=receipt_digest,
        )

    @staticmethod
    def _resource_fingerprint(
        proof: object,
    ) -> Tuple[str, ...]:
        return topology_resource_fingerprint(proof)

    def _record_resource_receipt_binding(
        self,
        receipt_digest: str,
        proofs: Sequence[object],
        receipts: Sequence[CommandReceipt],
    ) -> None:
        binding = tuple(sorted(self._resource_fingerprint(item) for item in proofs))
        existing = self._resource_receipt_bindings.get(receipt_digest)
        if existing is not None and existing != binding:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "one mutation receipt was rebound to different topology",
                receipts,
            )
        self._resource_receipt_bindings[receipt_digest] = binding

    def _verify_project(
        self,
        project: ProjectTopologyProof,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        receipts: Sequence[CommandReceipt],
    ) -> None:
        if project.namespace != SESSION_NAMESPACE:
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "project proof names a different Herdr namespace",
                receipts,
            )
        lane_ids = [item.lane_id for item in project.lanes]
        keys = [item.consultant_key for item in project.lanes]
        if len(lane_ids) != len(set(lane_ids)) or len(keys) != len(set(keys)):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "project proof duplicates a lane or consultant key",
                receipts,
            )
        resources_by_receipt = {}  # type: Dict[str, list[object]]
        for lane in project.lanes:
            if (
                lane.project_id != project.project_id
                or lane.project_root != project.project_root
            ):
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "lane proof belongs to a different project",
                    receipts,
                )
            expected_label = self._lane_label(
                lane.project_id,
                lane.lane_id,
                lane.consultant_key,
                lane.topology_nonce,
            )
            if lane.workspace.label != expected_label:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "lane label is not derived from its immutable ownership tuple",
                    receipts,
                )
            creation_kind = self._trusted_receipt_kinds.get(
                lane.workspace.creation_receipt_digest
            )
            if creation_kind is not ReceiptKind.WORKSPACE_CREATE:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "lane creation receipt is not present in the trusted receipt chain",
                    receipts,
                )
            resources_by_receipt.setdefault(
                lane.workspace.creation_receipt_digest, []
            ).append(lane.workspace)
        for side_effect in project.side_effects:
            if (
                side_effect.project_id != project.project_id
                or side_effect.project_root != project.project_root
            ):
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "topology side effect belongs to a different project",
                    receipts,
                )
            creation_kind = self._trusted_receipt_kinds.get(
                side_effect.creation_receipt_digest
            )
            if creation_kind not in {
                ReceiptKind.SESSION_START,
                ReceiptKind.WORKSPACE_CLOSE,
            }:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "side-effect receipt is not present in the trusted receipt chain",
                    receipts,
                )
            resources_by_receipt.setdefault(
                side_effect.creation_receipt_digest, []
            ).append(side_effect)
        for receipt_digest, resources in resources_by_receipt.items():
            expected_binding = tuple(
                sorted(self._resource_fingerprint(item) for item in resources)
            )
            if self._resource_receipt_bindings.get(receipt_digest) != expected_binding:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "topology resource is not exactly bound to its mutation receipt",
                    receipts,
                )
        self._verify_snapshot(project, snapshot, receipts)

    def _verify_snapshot(
        self,
        project: ProjectTopologyProof,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        receipts: Sequence[CommandReceipt],
    ) -> None:
        expected = [item.workspace for item in project.lanes]
        expected.extend(
            WorkspaceProof(
                workspace_id=item.workspace_id,
                tab_id=item.tab_id,
                pane_id=item.pane_id,
                label=item.label,
                cwd=item.cwd,
                creation_receipt_digest=item.creation_receipt_digest,
            )
            for item in project.side_effects
        )
        expected_workspace_ids = {item.workspace_id for item in expected}
        expected_tab_ids = {item.tab_id for item in expected}
        expected_pane_ids = {item.pane_id for item in expected}
        live_workspace_ids = self._id_set(
            snapshot["workspaces"], "workspace_id", receipts
        )
        live_tab_ids = self._id_set(snapshot["tabs"], "tab_id", receipts)
        live_pane_ids = self._id_set(snapshot["panes"], "pane_id", receipts)
        if (
            live_workspace_ids != expected_workspace_ids
            or live_tab_ids != expected_tab_ids
            or live_pane_ids != expected_pane_ids
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "complete live topology differs from the supplied project proof",
                receipts,
            )
        for proof in expected:
            observed = self._observed_workspace(
                snapshot,
                proof.workspace_id,
                proof.creation_receipt_digest,
                receipts,
            )
            if observed != proof:
                self._fail(
                    TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                    "live workspace fields differ from the exact ownership proof",
                    receipts,
                )

    def _validate_project_identity(
        self,
        known: ProjectTopologyProof,
        intent: ProvisionIntent,
        receipts: Sequence[CommandReceipt],
    ) -> None:
        if not isinstance(known, ProjectTopologyProof):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "known topology must be a ProjectTopologyProof",
                receipts,
            )
        if (
            known.namespace != SESSION_NAMESPACE
            or known.project_id != intent.project_id
            or known.project_root != intent.project_root
        ):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                "project proof identity differs from the provision intent",
                receipts,
            )

    @staticmethod
    def _lane_for_key(
        project: ProjectTopologyProof, consultant_key: str
    ) -> Optional[LaneTopologyProof]:
        return next(
            (
                item
                for item in project.lanes
                if item.consultant_key == consultant_key
            ),
            None,
        )

    @staticmethod
    def _lane_label(
        project_id: str,
        lane_id: str,
        consultant_key: str,
        topology_nonce: str,
    ) -> str:
        digest = hashlib.sha256(
            (
                project_id
                + "\x00"
                + lane_id
                + "\x00"
                + topology_nonce
            ).encode("utf-8")
        ).hexdigest()[:16]
        return f"{SESSION_NAMESPACE}:{consultant_key}:{digest}"

    def _workspace_ids(
        self,
        snapshot: Mapping[str, Sequence[Mapping[str, Any]]],
        receipts: Sequence[CommandReceipt],
    ) -> Tuple[str, ...]:
        return tuple(
            sorted(self._id_set(snapshot["workspaces"], "workspace_id", receipts))
        )

    def _id_set(
        self,
        records: Sequence[Mapping[str, Any]],
        field: str,
        receipts: Sequence[CommandReceipt],
    ) -> set:
        values = [item.get(field) for item in records]
        if any(not isinstance(value, str) or not value for value in values):
            self._fail(
                TransportErrorKind.INVALID_RECEIPT,
                f"Herdr snapshot contains an invalid {field}",
                receipts,
            )
        if len(values) != len(set(values)):
            self._fail(
                TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
                f"Herdr snapshot duplicates {field}",
                receipts,
            )
        return set(values)

    def _require_success(
        self,
        receipt: CommandReceipt,
        kind: TransportErrorKind,
        message: str,
        receipts: Sequence[CommandReceipt],
    ) -> None:
        if receipt.exit_code != 0 or receipt.error_code is not None:
            self._fail(kind, message, receipts)

    @staticmethod
    def _fail(
        kind: TransportErrorKind,
        message: str,
        receipts: Sequence[CommandReceipt],
    ) -> None:
        raise TransportError(kind, message, receipts=receipts)


__all__ = [
    "CommandReceipt",
    "CommandResponse",
    "DispatchIntent",
    "DispatchOutcome",
    "DispatchResult",
    "HerdrTransport",
    "LaneTopologyProof",
    "ProjectTopologyProof",
    "PlannedTopologyCommand",
    "provision_planned_commands",
    "ProvenTopologyCommand",
    "ProvisionJournalPort",
    "ProvisionIntent",
    "ProvisionOutcome",
    "ProvisionResult",
    "ReceiptAuthority",
    "ReceiptKind",
    "ReleaseIntent",
    "ReleaseOutcome",
    "ReleaseResult",
    "ReleaseScope",
    "ResponseAuthority",
    "ResponseExpectation",
    "RetryDisposition",
    "SESSION_NAMESPACE",
    "SessionBinding",
    "TopologySideEffectProof",
    "TransportTrustSeed",
    "TransportError",
    "TransportErrorKind",
    "WorkspaceProof",
]
