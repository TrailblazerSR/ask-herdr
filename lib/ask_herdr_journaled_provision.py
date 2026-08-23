"""Private write-ahead coordinator for one fake-Herdr provision operation.

This Module joins the durable Topology Effect Journal to the injected-runner
Herdr Transport.  It is deliberately creation-only and process-local: a
settled result cannot be adopted after restart until the complete topology
proof and compatible receipt/resource trust are themselves reconstructable.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import os
import stat
from typing import Any, Optional, Tuple

from ask_herdr_herdr_transport import (
    HerdrTransport,
    PlannedTopologyCommand,
    ProjectTopologyProof,
    ProvenTopologyCommand,
    ProvisionIntent,
    ProvisionOutcome,
    ProvisionResult,
    ReceiptKind,
    Runner,
    SESSION_NAMESPACE,
    TransportError,
    TransportTrustSeed,
    provision_planned_commands,
)
from ask_herdr_json import canonical_json
from ask_herdr_project_mutation_lease import (
    ProjectMutationLeaseError,
    ValidatedProjectMutationBinding,
    hold_project_mutation_lease,
)
from ask_herdr_topology_contract import (
    project_topology_digest as _durable_project_topology_digest,
    topology_resource_binding_digest,
)
from ask_herdr_topology_store import (
    CommandEffectDisposition,
    TopologyCommandIntent,
    TopologyCommandReceipt,
    TopologyMutationIntent,
    TopologyMutationSettlement,
    TopologyStoreMutationResult,
    ValidatedTopologyStoreBinding,
    _authenticate_pristine_mutation_for_effect,
    _authenticate_pristine_mutation_under_lease,
    commit_claimed_command_intent_under_lease,
    commit_command_intent,
    commit_command_receipt,
    commit_mutation_intent,
    inspect_topology_store,
    settle_topology_mutation,
)


class JournaledProvisionOutcome(str, Enum):
    CREATED_EPHEMERAL = "created_ephemeral"
    ADOPTED = "adopted"


@dataclass(frozen=True)
class JournaledProvisionRequest:
    store_binding: ValidatedTopologyStoreBinding
    mutation_intent: TopologyMutationIntent
    provision_intent: ProvisionIntent
    session_start_step_id: str
    workspace_create_step_id: str


@dataclass(frozen=True)
class JournaledProvisionResult:
    outcome: JournaledProvisionOutcome
    provision: ProvisionResult
    project_topology_digest: str


class JournaledProvisionError(RuntimeError):
    """Typed fail-closed result for a private provision attempt."""

    def __init__(
        self,
        detail_code: str,
        *,
        reconciliation_required: bool = True,
    ) -> None:
        super().__init__(detail_code)
        self.detail_code = detail_code
        self.reconciliation_required = reconciliation_required
        self.resend_allowed = False


@dataclass(frozen=True)
class _CommandTicket:
    step_id: str
    step_sequence: int
    prior_step_id: Optional[str]
    kind: ReceiptKind
    argv: Tuple[str, ...]
    argv_digest: str
    expected_postcondition_digest: str


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in fields(value)
        }
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is list:
        return [_json_value(item) for item in value]
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    if value is None or type(value) in {str, int, bool}:
        return value
    raise ValueError("journaled_provision.value_not_canonical")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(_json_value(value))
    ).hexdigest()


def provision_postcondition_digest(intent: ProvisionIntent) -> str:
    """Digest the precomputable final-lane predicate, not live Herdr IDs."""

    if not isinstance(intent, ProvisionIntent):
        raise ValueError("journaled_provision.provision_intent_invalid")
    return _digest(
        {
            "schema": "ask_herdr.provision_postcondition.v1",
            "namespace": SESSION_NAMESPACE,
            "project_id": intent.project_id,
            "project_root": intent.project_root,
            "lane_id": intent.lane_id,
            "consultant_key": intent.consultant_key,
            "topology_nonce": intent.topology_nonce,
            "lane_workspace_cwd": intent.lane_workspace_cwd,
        }
    )


def lane_workspace_binding_digest(
    store_binding: ValidatedTopologyStoreBinding,
    intent: ProvisionIntent,
) -> str:
    """Bind and revalidate the exact nonsymlink Lane Workspace chain."""

    if not isinstance(store_binding, ValidatedTopologyStoreBinding) or not isinstance(
        intent, ProvisionIntent
    ):
        raise ValueError("journaled_provision.lane_workspace_binding_invalid")
    expected = os.path.join(
        store_binding.canonical_project_root,
        "lane-workspaces",
        intent.lane_id,
    )
    if intent.lane_workspace_cwd != expected:
        raise ValueError("journaled_provision.lane_workspace_binding_invalid")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
    )
    descriptors = []  # type: list[int]
    snapshots = []  # type: list[os.stat_result]
    links = []  # type: list[tuple[int, str, int]]

    def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )

    def open_child(parent: int, name: str) -> int:
        child = os.open(name, flags, dir_fd=parent)
        descriptors.append(child)
        snapshots.append(os.fstat(child))
        links.append((parent, name, child))
        return child

    try:
        current = os.open(os.path.sep, flags)
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        for component in filter(
            None,
            store_binding.canonical_project_root.split(os.path.sep)[1:],
        ):
            current = open_child(current, component)
        root = current
        root_stat = os.fstat(root)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_dev != store_binding.filesystem_device
            or root_stat.st_ino != store_binding.filesystem_inode
            or root_stat.st_uid != store_binding.owner_uid
            or store_binding.owner_uid != os.getuid()
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        parent = open_child(root, "lane-workspaces")
        parent_stat = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != store_binding.owner_uid
            or parent_stat.st_dev != root_stat.st_dev
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        workspace = open_child(parent, intent.lane_id)
        workspace_stat = os.fstat(workspace)
        if (
            not stat.S_ISDIR(workspace_stat.st_mode)
            or workspace_stat.st_uid != store_binding.owner_uid
            or workspace_stat.st_dev != root_stat.st_dev
            or stat.S_IMODE(workspace_stat.st_mode) != 0o700
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        digest = _digest(
            {
                "schema": "ask_herdr.lane_workspace_binding.v1",
                "canonical_path": expected,
                "project_device": root_stat.st_dev,
                "project_inode": root_stat.st_ino,
                "parent_device": parent_stat.st_dev,
                "parent_inode": parent_stat.st_ino,
                "workspace_device": workspace_stat.st_dev,
                "workspace_inode": workspace_stat.st_ino,
                "owner_uid": workspace_stat.st_uid,
                "mode": stat.S_IMODE(workspace_stat.st_mode),
            }
        )
        for descriptor, snapshot in zip(descriptors, snapshots):
            if identity(os.fstat(descriptor)) != identity(snapshot):
                raise ValueError(
                    "journaled_provision.lane_workspace_binding_invalid"
                )
        for parent_descriptor, name, child_descriptor in links:
            bound = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if identity(bound) != identity(os.fstat(child_descriptor)):
                raise ValueError(
                    "journaled_provision.lane_workspace_binding_invalid"
                )
        return digest
    except OSError as error:
        raise ValueError(
            "journaled_provision.lane_workspace_binding_invalid"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _lane_workspace_binding_digest_from_root(
    root: int,
    store_binding: ValidatedTopologyStoreBinding,
    intent: ProvisionIntent,
    *,
    before_return: Any = None,
) -> str:
    """Bind a Lane Workspace below an already validated retained root fd.

    The descriptors stay live through the optional final callback and the
    named entries are revalidated afterwards.  This lets a caller commit the
    digest-bound authority while the exact workspace chain is still held.
    """

    if type(store_binding) is not ValidatedTopologyStoreBinding or type(
        intent
    ) is not ProvisionIntent:
        raise ValueError("journaled_provision.lane_workspace_binding_invalid")
    expected = os.path.join(
        store_binding.canonical_project_root,
        "lane-workspaces",
        intent.lane_id,
    )
    if intent.lane_workspace_cwd != expected:
        raise ValueError("journaled_provision.lane_workspace_binding_invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors = []  # type: list[int]

    def identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )

    try:
        root_stat = os.fstat(root)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_dev != store_binding.filesystem_device
            or root_stat.st_ino != store_binding.filesystem_inode
            or root_stat.st_uid != store_binding.owner_uid
            or store_binding.owner_uid != os.getuid()
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        parent = os.open("lane-workspaces", flags, dir_fd=root)
        descriptors.append(parent)
        parent_stat = os.fstat(parent)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != store_binding.owner_uid
            or parent_stat.st_dev != root_stat.st_dev
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        workspace = os.open(intent.lane_id, flags, dir_fd=parent)
        descriptors.append(workspace)
        workspace_stat = os.fstat(workspace)
        if (
            not stat.S_ISDIR(workspace_stat.st_mode)
            or workspace_stat.st_uid != store_binding.owner_uid
            or workspace_stat.st_dev != root_stat.st_dev
            or stat.S_IMODE(workspace_stat.st_mode) != 0o700
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        digest = _digest(
            {
                "schema": "ask_herdr.lane_workspace_binding.v1",
                "canonical_path": expected,
                "project_device": root_stat.st_dev,
                "project_inode": root_stat.st_ino,
                "parent_device": parent_stat.st_dev,
                "parent_inode": parent_stat.st_ino,
                "workspace_device": workspace_stat.st_dev,
                "workspace_inode": workspace_stat.st_ino,
                "owner_uid": workspace_stat.st_uid,
                "mode": stat.S_IMODE(workspace_stat.st_mode),
            }
        )
        if before_return is not None:
            before_return(digest)
        parent_bound = os.stat(
            "lane-workspaces",
            dir_fd=root,
            follow_symlinks=False,
        )
        workspace_bound = os.stat(
            intent.lane_id,
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (
            identity(parent_bound) != identity(parent_stat)
            or identity(workspace_bound) != identity(workspace_stat)
            or identity(os.fstat(parent)) != identity(parent_stat)
            or identity(os.fstat(workspace)) != identity(workspace_stat)
        ):
            raise ValueError(
                "journaled_provision.lane_workspace_binding_invalid"
            )
        return digest
    except OSError as error:
        raise ValueError(
            "journaled_provision.lane_workspace_binding_invalid"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _session_postcondition_digest(intent: ProvisionIntent) -> str:
    return _digest(
        {
            "schema": "ask_herdr.session_start_postcondition.v1",
            "namespace": SESSION_NAMESPACE,
            "project_id": intent.project_id,
            "project_root": intent.project_root,
            "topology_nonce": intent.topology_nonce,
            "startup_side_effect": "zero_or_exact_documented_default",
        }
    )


def _provision_command_intents(
    request: JournaledProvisionRequest,
) -> Tuple[TopologyCommandIntent, TopologyCommandIntent]:
    """Derive the complete durable command plan from one prepared request."""

    if (
        type(request) is not JournaledProvisionRequest
        or type(request.provision_intent) is not ProvisionIntent
        or type(request.mutation_intent) is not TopologyMutationIntent
    ):
        raise ValueError("journaled_provision.command_plan_invalid")
    plans = provision_planned_commands(request.provision_intent)
    step_ids = (
        request.session_start_step_id,
        request.workspace_create_step_id,
    )
    postconditions = (
        _session_postcondition_digest(request.provision_intent),
        request.mutation_intent.expected_postcondition_digest,
    )
    return tuple(
        TopologyCommandIntent(
            mutation_id=request.mutation_intent.mutation_id,
            step_id=step_ids[index],
            command_kind=plan.kind.value,
            command_argv_digest=_digest(list(plan.argv)),
            expected_postcondition_digest=postconditions[index],
            step_sequence=index + 1,
            prior_step_id=None if index == 0 else step_ids[index - 1],
        )
        for index, plan in enumerate(plans)
    )  # type: ignore[return-value]


def project_topology_digest(project: ProjectTopologyProof) -> str:
    """Content-address one complete in-memory topology proof."""

    try:
        return _durable_project_topology_digest(project)
    except ValueError as error:
        raise ValueError("journaled_provision.project_proof_invalid") from error


def resource_binding_digest(resource: object) -> str:
    """Digest the exact stable workspace/tab/pane ownership fingerprint."""

    try:
        return topology_resource_binding_digest(resource)
    except (AttributeError, ValueError) as error:
        raise ValueError("journaled_provision.resource_binding_invalid") from error


def _raise_store_failure(result: TopologyStoreMutationResult) -> None:
    raise JournaledProvisionError(
        result.detail_code,
        reconciliation_required=result.outcome_kind != "durability_not_supported",
    )


class _JournalPort:
    def __init__(
        self,
        request: JournaledProvisionRequest,
        *,
        policy_proof: Any = None,
        lane_proof: Any = None,
    ) -> None:
        self.request = request
        self.policy_proof = policy_proof
        self.lane_proof = lane_proof
        self._next_index = 0
        self._pending = None  # type: Optional[_CommandTicket]
        self.receipts = []  # type: list[TopologyCommandReceipt]
        self.final_project = None  # type: Optional[ProjectTopologyProof]

    def _assert_workspace_binding(self) -> None:
        try:
            current = lane_workspace_binding_digest(
                self.request.store_binding,
                self.request.provision_intent,
            )
        except ValueError as error:
            raise JournaledProvisionError(
                "journaled_provision.lane_workspace_changed"
            ) from error
        if (
            current
            != self.request.mutation_intent.lane_workspace_binding_digest
        ):
            raise JournaledProvisionError(
                "journaled_provision.lane_workspace_changed"
            )

    def before_command(self, command: PlannedTopologyCommand) -> object:
        self._assert_workspace_binding()
        if self._pending is not None or self._next_index >= 2:
            raise JournaledProvisionError(
                "journaled_provision.command_order_invalid"
            )
        command_intent = _provision_command_intents(self.request)[
            self._next_index
        ]
        argv_digest = _digest(list(command.argv))
        if (
            command.kind.value != command_intent.command_kind
            or argv_digest != command_intent.command_argv_digest
        ):
            raise JournaledProvisionError(
                "journaled_provision.command_order_invalid"
            )
        ticket = _CommandTicket(
            step_id=command_intent.step_id,
            step_sequence=command_intent.step_sequence,
            prior_step_id=command_intent.prior_step_id,
            kind=command.kind,
            argv=command.argv,
            argv_digest=argv_digest,
            expected_postcondition_digest=(
                command_intent.expected_postcondition_digest
            ),
        )
        if (
            self.request.mutation_intent.topology_store_incarnation_digest
            is None
        ):
            result = commit_command_intent(
                self.request.store_binding,
                command_intent,
            )
        else:
            binding = self.request.store_binding
            project_binding = ValidatedProjectMutationBinding(
                canonical_project_root=binding.canonical_project_root,
                filesystem_device=binding.filesystem_device,
                filesystem_inode=binding.filesystem_inode,
                owner_uid=binding.owner_uid,
                project_authority_id=binding.project_authority_id,
            )
            try:
                with hold_project_mutation_lease(project_binding) as lease:
                    result = commit_claimed_command_intent_under_lease(
                        lease,
                        binding,
                        command_intent,
                        mutation_intent=self.request.mutation_intent,
                        policy_proof=self.policy_proof,
                        lane_proof=self.lane_proof,
                    )
            except ProjectMutationLeaseError as error:
                raise JournaledProvisionError(error.detail_code) from error
        if result.outcome_kind != "topology_command_prepared":
            _raise_store_failure(result)
        self._pending = ticket
        return ticket

    def after_command(self, proof: ProvenTopologyCommand) -> None:
        self._assert_workspace_binding()
        ticket = self._pending
        if (
            ticket is None
            or proof.ticket != ticket
            or proof.planned.kind is not ticket.kind
            or proof.planned.argv != ticket.argv
            or proof.receipt.kind is not ticket.kind
            or proof.receipt.argv != ticket.argv
            or proof.receipt.request_id is None
            or proof.project.session_binding != proof.session_binding
        ):
            raise JournaledProvisionError(
                "journaled_provision.proven_command_mismatch"
            )
        bindings = tuple(
            sorted(set(resource_binding_digest(item) for item in proof.resources))
        )
        receipt = TopologyCommandReceipt(
            mutation_id=self.request.mutation_intent.mutation_id,
            step_id=ticket.step_id,
            command_kind=ticket.kind.value,
            command_argv_digest=ticket.argv_digest,
            command_receipt_digest=proof.receipt.receipt_digest,
            request_id=proof.receipt.request_id,
            exit_code=proof.receipt.exit_code,
            disposition=CommandEffectDisposition.CONFIRMED,
            observed_postcondition_digest=(
                ticket.expected_postcondition_digest
            ),
            session_dir=proof.session_binding.session_dir,
            socket_path=proof.session_binding.socket_path,
            session_generation_id=proof.session_binding.generation_id,
            resource_binding_digests=bindings,
        )
        result = commit_command_receipt(self.request.store_binding, receipt)
        if result.outcome_kind != "topology_command_receipt_recorded":
            _raise_store_failure(result)
        self.receipts.append(receipt)
        self.final_project = proof.project
        self._pending = None
        self._next_index += 1


def _validate_request(request: JournaledProvisionRequest) -> None:
    if not isinstance(request, JournaledProvisionRequest):
        raise JournaledProvisionError(
            "journaled_provision.request_invalid",
            reconciliation_required=False,
        )
    binding = request.store_binding
    mutation = request.mutation_intent
    provision = request.provision_intent
    if not isinstance(binding, ValidatedTopologyStoreBinding):
        raise JournaledProvisionError(
            "journaled_provision.binding_invalid",
            reconciliation_required=False,
        )
    if not isinstance(mutation, TopologyMutationIntent) or not isinstance(
        provision, ProvisionIntent
    ):
        raise JournaledProvisionError(
            "journaled_provision.intent_invalid",
            reconciliation_required=False,
        )
    try:
        current_workspace_digest = lane_workspace_binding_digest(
            binding,
            provision,
        )
    except ValueError as error:
        raise JournaledProvisionError(
            "journaled_provision.lane_workspace_binding_invalid",
            reconciliation_required=False,
        ) from error
    correlations = (
        binding.canonical_project_root == provision.project_root,
        mutation.lane_id == provision.lane_id,
        mutation.consultant_key == provision.consultant_key,
        mutation.topology_nonce == provision.topology_nonce,
        mutation.lane_workspace_cwd == provision.lane_workspace_cwd,
        mutation.intended_action == "reconcile_or_provision",
        mutation.expected_postcondition_digest
        == provision_postcondition_digest(provision),
        mutation.lane_workspace_binding_digest == current_workspace_digest,
        provision.lane_workspace_cwd is not None,
        provision.lane_workspace_cwd != provision.project_root,
        request.session_start_step_id != request.workspace_create_step_id,
    )
    if not all(correlations):
        raise JournaledProvisionError(
            "journaled_provision.authority_binding_mismatch",
            reconciliation_required=False,
        )


def provision_journaled(
    request: JournaledProvisionRequest,
    *,
    runner: Runner,
) -> JournaledProvisionResult:
    """Create one first lane with every possible effect durably write-ahead."""

    _validate_request(request)
    inspection = inspect_topology_store(request.store_binding)
    if inspection.status == "active":
        raise JournaledProvisionError(
            "journaled_provision.project_topology_proof_unavailable"
        )
    if inspection.status != "absent":
        raise JournaledProvisionError(inspection.detail_code)

    prepared = commit_mutation_intent(
        request.store_binding,
        request.mutation_intent,
    )
    if prepared.outcome_kind != "topology_mutation_prepared":
        _raise_store_failure(prepared)

    return _execute_prepared_effect(request, runner=runner)


def provision_prepared_journaled(
    request: JournaledProvisionRequest,
    *,
    runner: Runner,
    policy_proof: Any = None,
    lane_proof: Any = None,
) -> JournaledProvisionResult:
    """Continue one exact pristine precommitted mutation without resending."""

    _validate_request(request)
    if request.mutation_intent.topology_store_incarnation_digest is None:
        prepared = _authenticate_pristine_mutation_for_effect(
            request.store_binding,
            request.mutation_intent,
        )
    else:
        binding = request.store_binding
        project_binding = ValidatedProjectMutationBinding(
            canonical_project_root=binding.canonical_project_root,
            filesystem_device=binding.filesystem_device,
            filesystem_inode=binding.filesystem_inode,
            owner_uid=binding.owner_uid,
            project_authority_id=binding.project_authority_id,
        )
        try:
            with hold_project_mutation_lease(project_binding) as lease:
                prepared = _authenticate_pristine_mutation_under_lease(
                    lease,
                    binding,
                    request.mutation_intent,
                    policy_proof=policy_proof,
                    lane_proof=lane_proof,
                )
        except ProjectMutationLeaseError as error:
            raise JournaledProvisionError(error.detail_code) from error
    if prepared.outcome_kind != "topology_mutation_prepared":
        _raise_store_failure(prepared)
    return _execute_prepared_effect(
        request,
        runner=runner,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
    )


def _execute_prepared_effect(
    request: JournaledProvisionRequest,
    *,
    runner: Runner,
    policy_proof: Any = None,
    lane_proof: Any = None,
) -> JournaledProvisionResult:
    """Run the effect phase after the exact pristine intent is authoritative."""

    port = _JournalPort(
        request,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
    )
    transport = HerdrTransport(runner)
    try:
        provision = transport.provision(
            request.provision_intent,
            known=None,
            journal_port=port,
        )
    except JournaledProvisionError:
        raise
    except TransportError as error:
        raise JournaledProvisionError(
            "journaled_provision.transport_" + error.kind.value
        ) from error
    except Exception as error:
        raise JournaledProvisionError(
            "journaled_provision.transport_failure"
        ) from error

    if (
        provision.outcome is not ProvisionOutcome.CREATED
        or port._pending is not None
        or len(port.receipts) != 2
        or port.final_project != provision.project
    ):
        raise JournaledProvisionError(
            "journaled_provision.incomplete_effect_chain"
        )
    topology_digest = project_topology_digest(provision.project)
    port._assert_workspace_binding()
    binding = provision.project.session_binding
    settlement = TopologyMutationSettlement(
        mutation_id=request.mutation_intent.mutation_id,
        outcome="created",
        project_topology_digest=topology_digest,
        session_dir=binding.session_dir,
        socket_path=binding.socket_path,
        session_generation_id=binding.generation_id,
        command_receipt_digests=tuple(
            sorted(item.command_receipt_digest for item in port.receipts)
        ),
        project_topology_proof=provision.project,
    )
    settled = settle_topology_mutation(request.store_binding, settlement)
    if settled.outcome_kind != "topology_mutation_settled":
        _raise_store_failure(settled)
    final_inspection = inspect_topology_store(request.store_binding)
    if (
        final_inspection.status != "active"
        or final_inspection.project_topology_digest != topology_digest
        or final_inspection.trust_seed is None
    ):
        raise JournaledProvisionError(
            "journaled_provision.settlement_unverified"
        )
    return JournaledProvisionResult(
        outcome=JournaledProvisionOutcome.CREATED_EPHEMERAL,
        provision=provision,
        project_topology_digest=topology_digest,
    )


def rehydrate_journaled_provision(
    request: JournaledProvisionRequest,
    *,
    runner: Runner,
) -> JournaledProvisionResult:
    """Read-only re-prove one settled exact lane from durable topology trust."""

    _validate_request(request)
    inspection = inspect_topology_store(request.store_binding)
    proof = inspection.project_topology_proof
    seed = inspection.trust_seed
    if (
        inspection.status != "active"
        or proof is None
        or seed is None
        or inspection.project_topology_digest != project_topology_digest(proof)
    ):
        raise JournaledProvisionError(
            "journaled_provision.project_topology_proof_unavailable"
        )
    intent = request.provision_intent
    matching_lanes = tuple(
        lane
        for lane in proof.lanes
        if lane.project_id == intent.project_id
        and lane.project_root == intent.project_root
        and lane.lane_id == intent.lane_id
        and lane.consultant_key == intent.consultant_key
        and lane.topology_nonce == intent.topology_nonce
        and lane.workspace.cwd == intent.lane_workspace_cwd
    )
    if (
        proof.project_id != intent.project_id
        or proof.project_root != intent.project_root
        or proof.namespace != SESSION_NAMESPACE
        or len(matching_lanes) != 1
        or sum(
            lane.lane_id == intent.lane_id
            or lane.consultant_key == intent.consultant_key
            for lane in proof.lanes
        )
        != 1
    ):
        # This boundary is deliberately checked before constructing Transport:
        # a recovery request may only re-prove an already durable lane and can
        # never fall through to Transport's workspace-create branch.
        raise JournaledProvisionError(
            "journaled_provision.topology_reproof_mismatch"
        )
    try:
        transport_seed = TransportTrustSeed(
            receipt_kinds=tuple(
                (digest, ReceiptKind(kind))
                for digest, kind in seed.receipt_kinds
            ),
            seen_request_ids=seed.seen_request_ids,
            session_generations=seed.session_generations,
            resource_receipt_bindings=seed.resource_fingerprint_bindings,
        )
    except (TypeError, ValueError) as error:
        raise JournaledProvisionError(
            "journaled_provision.topology_trust_invalid"
        ) from error
    port = _JournalPort(request)
    port._assert_workspace_binding()
    try:
        provision = HerdrTransport(
            runner,
            trust_seed=transport_seed,
        ).provision(
            request.provision_intent,
            known=proof,
        )
    except TransportError as error:
        raise JournaledProvisionError(
            "journaled_provision.transport_" + error.kind.value
        ) from error
    port._assert_workspace_binding()
    if (
        provision.outcome is not ProvisionOutcome.ADOPTED
        or provision.project != proof
    ):
        raise JournaledProvisionError(
            "journaled_provision.topology_reproof_mismatch"
        )
    return JournaledProvisionResult(
        outcome=JournaledProvisionOutcome.ADOPTED,
        provision=provision,
        project_topology_digest=inspection.project_topology_digest,
    )


__all__ = [
    "JournaledProvisionError",
    "JournaledProvisionOutcome",
    "JournaledProvisionRequest",
    "JournaledProvisionResult",
    "lane_workspace_binding_digest",
    "project_topology_digest",
    "provision_journaled",
    "provision_prepared_journaled",
    "provision_postcondition_digest",
    "resource_binding_digest",
    "rehydrate_journaled_provision",
]
