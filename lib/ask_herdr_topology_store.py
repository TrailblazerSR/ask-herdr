"""Private durable journal for topology intents, receipts, and settlement.

The module owns no command execution.  It records immutable, canonical events
under one project-bound exclusive-capsule journal and reconstructs restart
trust only by replaying the complete validated history.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
import fcntl
import hashlib
import errno
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import weakref
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from ask_herdr_darwin_capsule import (
    CommitDisposition,
    commit_exclusive,
    fullsync_file,
    probe_capability,
)
from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_project_mutation_lease import ValidatedProjectMutationBinding
from ask_herdr_topology_contract import (
    ProjectTopologyProof,
    project_topology_digest,
    project_topology_from_payload,
    project_topology_payload,
    topology_resource_binding_digest,
    topology_resource_fingerprint,
)


STORE_NAME = ".ask-herdr-topology"
BOOTSTRAP_PREFIX = ".ask-herdr-topology.bootstrap."
BOOTSTRAP_NAME = re.compile(
    r"\.ask-herdr-topology\.bootstrap\.([0-9a-f]{24})\.([0-9a-f]{16})\.tmp"
)
LAYOUT_NAME = "layout.json"
BINDING_NAME = "binding.json"
TRANSACTIONS_NAME = "transactions"
RECORD_NAME = "record.json"
MAX_RECORD_BYTES = 1024 * 1024
EVENT_NAME = re.compile(r"event\.([0-9]{16})\.txn")
CANDIDATE_NAME = re.compile(
    r"\.candidate\.event\.([0-9]{16})\.([0-9a-f]{64})\.tmp"
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")


class CommandEffectDisposition(str, Enum):
    CONFIRMED = "confirmed"
    DELIVERY_UNCERTAIN = "delivery_uncertain"
    DEFINITE_NON_START = "definite_non_start"


def _is_int(value: Any) -> bool:
    return type(value) is int


def _require_uuid(value: Any, code: str) -> None:
    if type(value) is not str or UUID4.fullmatch(value) is None:
        raise ValueError(code)


def _require_digest(value: Any, code: str) -> None:
    if type(value) is not str or DIGEST.fullmatch(value) is None:
        raise ValueError(code)


def _require_token(value: Any, code: str) -> None:
    if type(value) is not str or TOKEN.fullmatch(value) is None:
        raise ValueError(code)


def _require_absolute_canonical(value: Any, code: str) -> None:
    if (
        type(value) is not str
        or not os.path.isabs(value)
        or "\x00" in value
        or os.path.normpath(value) != value
    ):
        raise ValueError(code)


def _require_digest_tuple(values: Any, code: str) -> None:
    if type(values) is not tuple:
        raise ValueError(code)
    for value in values:
        _require_digest(value, code)
    if values != tuple(sorted(set(values))):
        raise ValueError(code)


@dataclass(frozen=True)
class ValidatedTopologyStoreBinding:
    canonical_project_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int
    project_authority_id: str
    namespace: str

    def __post_init__(self) -> None:
        _require_absolute_canonical(
            self.canonical_project_root,
            "topology_store.project_root_invalid",
        )
        if os.path.realpath(self.canonical_project_root) != self.canonical_project_root:
            raise ValueError("topology_store.project_root_invalid")
        for value in (
            self.filesystem_device,
            self.filesystem_inode,
            self.owner_uid,
        ):
            if not _is_int(value) or value < 0:
                raise ValueError("topology_store.binding_invalid")
        _require_uuid(
            self.project_authority_id,
            "topology_store.project_authority_id_invalid",
        )
        if self.namespace != "ask-pipeline":
            raise ValueError("topology_store.namespace_invalid")


@dataclass(frozen=True)
class TopologyMutationIntent:
    mutation_id: str
    operation_id: str
    canonical_request_digest: str
    policy_record_digest: str
    lane_state_digest: str
    lane_id: str
    lane_generation: int
    lane_binding_digest: str
    lane_workspace_binding_digest: str
    consultant_key: str
    topology_nonce: str
    lane_workspace_cwd: str
    prior_topology_digest: Optional[str]
    intended_action: str
    precondition_digest: str
    expected_postcondition_digest: str
    topology_store_incarnation_digest: Optional[str] = None

    def __post_init__(self) -> None:
        _require_uuid(self.mutation_id, "topology_store.mutation_id_invalid")
        _require_uuid(self.operation_id, "topology_store.operation_id_invalid")
        _require_uuid(self.lane_id, "topology_store.lane_id_invalid")
        for value in (
            self.canonical_request_digest,
            self.policy_record_digest,
            self.lane_state_digest,
            self.lane_binding_digest,
            self.lane_workspace_binding_digest,
            self.precondition_digest,
            self.expected_postcondition_digest,
        ):
            _require_digest(value, "topology_store.digest_invalid")
        if self.prior_topology_digest is not None:
            _require_digest(
                self.prior_topology_digest,
                "topology_store.prior_topology_digest_invalid",
            )
        if self.topology_store_incarnation_digest is not None:
            _require_digest(
                self.topology_store_incarnation_digest,
                "topology_store.incarnation_digest_invalid",
            )
        if not _is_int(self.lane_generation) or self.lane_generation < 1:
            raise ValueError("topology_store.lane_generation_invalid")
        _require_token(
            self.consultant_key,
            "topology_store.consultant_key_invalid",
        )
        _require_token(
            self.topology_nonce,
            "topology_store.topology_nonce_invalid",
        )
        _require_token(
            self.intended_action,
            "topology_store.intended_action_invalid",
        )
        _require_absolute_canonical(
            self.lane_workspace_cwd,
            "topology_store.lane_workspace_invalid",
        )
        workspace = Path(self.lane_workspace_cwd)
        if workspace.name != self.lane_id or workspace.parent.name != "lane-workspaces":
            raise ValueError("topology_store.lane_workspace_invalid")


@dataclass(frozen=True)
class TopologyCommandIntent:
    mutation_id: str
    step_id: str
    command_kind: str
    command_argv_digest: str
    expected_postcondition_digest: Optional[str] = None
    step_sequence: Optional[int] = None
    prior_step_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_uuid(self.mutation_id, "topology_store.mutation_id_invalid")
        _require_uuid(self.step_id, "topology_store.step_id_invalid")
        _require_token(self.command_kind, "topology_store.command_kind_invalid")
        _require_digest(
            self.command_argv_digest,
            "topology_store.command_argv_digest_invalid",
        )
        if self.expected_postcondition_digest is not None:
            _require_digest(
                self.expected_postcondition_digest,
                "topology_store.expected_postcondition_digest_invalid",
            )
        if self.step_sequence is not None and (
            not _is_int(self.step_sequence) or self.step_sequence < 1
        ):
            raise ValueError("topology_store.step_sequence_invalid")
        if self.prior_step_id is not None:
            _require_uuid(
                self.prior_step_id,
                "topology_store.prior_step_id_invalid",
            )


@dataclass(frozen=True)
class TopologyCommandReceipt:
    mutation_id: str
    step_id: str
    command_kind: str
    command_argv_digest: str
    command_receipt_digest: str
    request_id: str
    exit_code: int
    disposition: CommandEffectDisposition
    observed_postcondition_digest: str
    session_dir: str
    socket_path: str
    session_generation_id: str
    resource_binding_digests: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_uuid(self.mutation_id, "topology_store.mutation_id_invalid")
        _require_uuid(self.step_id, "topology_store.step_id_invalid")
        _require_token(self.command_kind, "topology_store.command_kind_invalid")
        _require_digest(
            self.command_argv_digest,
            "topology_store.command_argv_digest_invalid",
        )
        _require_digest(
            self.command_receipt_digest,
            "topology_store.command_receipt_digest_invalid",
        )
        _require_token(self.request_id, "topology_store.request_id_invalid")
        if not _is_int(self.exit_code):
            raise ValueError("topology_store.exit_code_invalid")
        if not isinstance(self.disposition, CommandEffectDisposition):
            raise ValueError("topology_store.disposition_invalid")
        _require_digest(
            self.observed_postcondition_digest,
            "topology_store.observed_postcondition_digest_invalid",
        )
        _require_absolute_canonical(
            self.session_dir,
            "topology_store.session_dir_invalid",
        )
        _require_absolute_canonical(
            self.socket_path,
            "topology_store.socket_path_invalid",
        )
        _require_token(
            self.session_generation_id,
            "topology_store.session_generation_id_invalid",
        )
        _require_digest_tuple(
            self.resource_binding_digests,
            "topology_store.resource_binding_digests_invalid",
        )


@dataclass(frozen=True)
class TopologyMutationSettlement:
    mutation_id: str
    outcome: str
    project_topology_digest: str
    session_dir: str
    socket_path: str
    session_generation_id: str
    command_receipt_digests: Tuple[str, ...]
    project_topology_proof: Optional[ProjectTopologyProof] = None

    def __post_init__(self) -> None:
        _require_uuid(self.mutation_id, "topology_store.mutation_id_invalid")
        _require_token(self.outcome, "topology_store.settlement_outcome_invalid")
        _require_digest(
            self.project_topology_digest,
            "topology_store.project_topology_digest_invalid",
        )
        _require_absolute_canonical(
            self.session_dir,
            "topology_store.session_dir_invalid",
        )
        _require_absolute_canonical(
            self.socket_path,
            "topology_store.socket_path_invalid",
        )
        _require_token(
            self.session_generation_id,
            "topology_store.session_generation_id_invalid",
        )
        _require_digest_tuple(
            self.command_receipt_digests,
            "topology_store.command_receipt_digests_invalid",
        )
        if self.project_topology_proof is not None:
            if (
                not isinstance(self.project_topology_proof, ProjectTopologyProof)
                or project_topology_digest(self.project_topology_proof)
                != self.project_topology_digest
                or self.project_topology_proof.session_binding.session_dir
                != self.session_dir
                or self.project_topology_proof.session_binding.socket_path
                != self.socket_path
                or self.project_topology_proof.session_binding.generation_id
                != self.session_generation_id
            ):
                raise ValueError("topology_store.project_topology_proof_invalid")


@dataclass(frozen=True)
class TopologyTrustSeed:
    receipt_digests: Tuple[str, ...]
    seen_request_ids: Tuple[str, ...]
    session_generations: Tuple[Tuple[str, str, str], ...]
    resource_receipt_bindings: Tuple[Tuple[str, Tuple[str, ...]], ...]
    receipt_kinds: Tuple[Tuple[str, str], ...]
    resource_fingerprint_bindings: Tuple[
        Tuple[str, Tuple[Tuple[str, ...], ...]], ...
    ]


@dataclass(frozen=True)
class TopologyStoreInspection:
    status: str
    detail_code: str
    unfinished_mutation_ids: Tuple[str, ...]
    pending_step_ids: Tuple[str, ...]
    resend_allowed: bool
    project_topology_digest: Optional[str]
    trust_seed: Optional[TopologyTrustSeed]
    project_topology_proof: Optional[ProjectTopologyProof] = None


@dataclass(frozen=True)
class TopologyLedgerHeadInspection:
    """Path-free immutable identity of the promoted Topology journal head."""

    status: str
    detail_code: str
    topology_ledger_head_digest: Optional[str] = None


@dataclass(frozen=True)
class TopologyStatusKeyEntry:
    """Path-free Consultant Key binding from one authenticated intent."""

    consultant_key: str
    lane_id: str
    lane_generation: int
    lane_binding_digest: str


@dataclass(frozen=True)
class TopologyStatusOperationEntry:
    """Path-free operation-to-Lane mapping from one promoted intent."""

    operation_id: str
    canonical_request_digest: str
    policy_record_digest: str
    lane_id: str
    lane_generation: int
    lane_binding_digest: str


@dataclass(frozen=True)
class TopologyStatusProjectionInspection:
    """Observation-only Topology head and deterministic key projection."""

    status: str
    detail_code: str
    topology_ledger_head_digest: Optional[str] = None
    key_entries: Tuple[TopologyStatusKeyEntry, ...] = ()


_TOPOLOGY_STATUS_OPERATION_CACHE: Dict[
    int,
    Tuple[
        Any,
        Tuple[TopologyStatusOperationEntry, ...],
    ],
] = {}


def _remember_topology_status_operation_entries(
    projection: TopologyStatusProjectionInspection,
    entries: Tuple[TopologyStatusOperationEntry, ...],
) -> None:
    """Keep a private same-replay tuple out of the frozen status shape."""

    key = id(projection)

    def _release(reference: object) -> None:
        cached = _TOPOLOGY_STATUS_OPERATION_CACHE.get(key)
        if cached is not None and cached[0] is reference:
            _TOPOLOGY_STATUS_OPERATION_CACHE.pop(key, None)

    _TOPOLOGY_STATUS_OPERATION_CACHE[key] = (
        weakref.ref(projection, _release),
        entries,
    )


def _topology_status_operation_entries_from_projection(
    value: object,
) -> Tuple[TopologyStatusOperationEntry, ...]:
    """Return the tuple only for the exact just-observed status projection."""

    if type(value) is not TopologyStatusProjectionInspection:
        return ()
    cached = _TOPOLOGY_STATUS_OPERATION_CACHE.get(id(value))
    if cached is None or cached[0]() is not value:
        return ()
    return cached[1]


@dataclass(frozen=True)
class _LaneIndexMembershipEntry:
    """Path-free Lane identity derived from one Topology mutation intent."""

    lane_id: str
    lane_generation: int
    lane_binding_digest: str


@dataclass(frozen=True)
class _LaneIndexMembershipInspection:
    """Private complete-journal projection for Lane Index cross-checking."""

    status: str
    detail_code: str
    entries: Tuple[_LaneIndexMembershipEntry, ...] = ()
    topology_ledger_head_digest: Optional[str] = None


@dataclass(frozen=True)
class TopologyStoreMutationResult:
    outcome_kind: str
    detail_code: str


@dataclass(frozen=True)
class _AuthenticatedLaneSettlement:
    """Record-derived settlement facts for one exact claimed Lane."""

    mutation_id: str
    settlement_record_digest: str
    project_topology_digest: str
    mutation_record_digest: Optional[str] = None
    first_command_record_digest: Optional[str] = None
    topology_store_incarnation_digest: Optional[str] = None


@dataclass(frozen=True)
class _ClaimedCommandPlan:
    """Record-derived plan for one not-yet-published Topology command."""

    resolved_command: TopologyCommandIntent
    mutation_record_digest: str
    prospective_command_record_digest: str
    first_command_record_digest: Optional[str]
    prior_command_count: int
    record_digests: Tuple[str, ...]


class _IntegrityError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _WriterBusy(_IntegrityError):
    pass


class _HeadCleanupError(Exception):
    pass


class _CommandOrderInvalid(_IntegrityError):
    pass


class _PendingCandidate(_IntegrityError):
    def __init__(
        self,
        code: str,
        residue_state_digest: str,
        promoted_head_digest: Optional[str] = None,
        transaction_identities: Tuple[
            Tuple[str, Tuple[int, ...]], ...
        ] = (),
        record_sources: Tuple[
            Tuple[str, Tuple[int, ...], bytes], ...
        ] = (),
        empty_candidate_name: Optional[str] = None,
        promoted_key_entries: Tuple[TopologyStatusKeyEntry, ...] = (),
        promoted_operation_entries: Tuple[
            TopologyStatusOperationEntry, ...
        ] = (),
    ) -> None:
        super().__init__(code)
        self.residue_state_digest = residue_state_digest
        self.promoted_head_digest = promoted_head_digest
        self.transaction_identities = transaction_identities
        self.record_sources = record_sources
        self.empty_candidate_name = empty_candidate_name
        self.promoted_key_entries = promoted_key_entries
        self.promoted_operation_entries = promoted_operation_entries


@dataclass
class _Replay:
    records: List[Dict[str, Any]]
    mutations: Dict[str, TopologyMutationIntent]
    commands: Dict[Tuple[str, str], TopologyCommandIntent]
    receipts: Dict[Tuple[str, str], TopologyCommandReceipt]
    settlements: Dict[str, TopologyMutationSettlement]
    request_ids: Dict[str, Tuple[str, str]]
    receipt_digests: Dict[str, Tuple[str, str]]
    recovered_candidate: bool = False


@dataclass(frozen=True)
class _HeadReplay:
    replay: _Replay
    transaction_identities: Tuple[Tuple[str, Tuple[int, ...]], ...]
    record_sources: Tuple[Tuple[str, Tuple[int, ...], bytes], ...]


@dataclass(frozen=True)
class _OpenMutationReplayEvidence:
    """Lossless, non-authorizing projection for Recovery Reconciliation."""

    mutation_record_digest: str
    command_record_digests: Tuple[Tuple[str, str], ...]
    commands: Tuple[TopologyCommandIntent, ...]
    receipts: Tuple[TopologyCommandReceipt, ...]
    settlement: Optional[TopologyMutationSettlement]
    settlement_record_digest: Optional[str]
    record_digests: Tuple[str, ...]


@dataclass(frozen=True)
class _OpenMutationReplayInspection:
    """Tagged read-only replay result for Recovery Reconciliation."""

    status: str
    detail_code: str
    evidence: Optional[_OpenMutationReplayEvidence]
    residue_state_digest: Optional[str] = None


@dataclass(frozen=True)
class _ResolvedTopologyRecoveryMutation:
    """Record-derived mutation inputs for one exact recovery classification."""

    binding: ValidatedTopologyStoreBinding
    mutation_intent: TopologyMutationIntent
    mutation_record_digest: str
    command_intents: Tuple[TopologyCommandIntent, ...]


@dataclass
class _Handles:
    root: int
    store: int
    transactions: int


@dataclass
class _HeadHandles(_Handles):
    layout_identity: Tuple[int, ...]
    binding_identity: Tuple[int, ...]


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


def _digest_json(value: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _binding_payload(binding: ValidatedTopologyStoreBinding) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.topology_store_binding.internal.v1",
        "canonical_project_root": binding.canonical_project_root,
        "filesystem_device": binding.filesystem_device,
        "filesystem_inode": binding.filesystem_inode,
        "owner_uid": binding.owner_uid,
        "project_authority_id": binding.project_authority_id,
        "namespace": binding.namespace,
    }


def _layout_payload() -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.topology_store_layout.internal.v1",
        "storage_protocol": "exclusive_capsule_journal",
    }


def _binding_digest(binding: ValidatedTopologyStoreBinding) -> str:
    return _digest_json(_binding_payload(binding))


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
            raise _IntegrityError("topology_store.directory_integrity")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _directory_binding(parent: int, name: str, child: int) -> bool:
    try:
        return _identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        ) == _identity(os.fstat(child))
    except OSError:
        return False


@contextmanager
def _open_head_root(
    binding: ValidatedTopologyStoreBinding,
) -> Iterator[int]:
    """Open one exact project root under a nonblocking shared read lock."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: List[int] = []
    snapshots: List[os.stat_result] = []
    links: List[Tuple[int, str, int]] = []
    locked = False
    operation_error: Optional[BaseException] = None
    cleanup_error: Optional[OSError] = None
    try:
        current = os.open(os.path.sep, flags)
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        for component in filter(
            None,
            binding.canonical_project_root.split(os.path.sep)[1:],
        ):
            parent = current
            try:
                current = os.open(component, flags, dir_fd=parent)
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise _IntegrityError(
                        "topology_store.root_binding_conflict"
                    ) from error
                raise
            descriptors.append(current)
            snapshots.append(os.fstat(current))
            links.append((parent, component, current))
        root_metadata = os.fstat(current)
        if (
            root_metadata.st_dev != binding.filesystem_device
            or root_metadata.st_ino != binding.filesystem_inode
            or root_metadata.st_uid != binding.owner_uid
            or binding.owner_uid != os.getuid()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or bool(stat.S_IMODE(root_metadata.st_mode) & 0o022)
        ):
            raise _IntegrityError("topology_store.root_binding_conflict")
        try:
            fcntl.flock(current, fcntl.LOCK_SH | fcntl.LOCK_NB)
            locked = True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise _WriterBusy(
                    "topology_ledger_head.writer_active"
                ) from error
            raise
        yield current
        for descriptor, snapshot in zip(descriptors, snapshots):
            if _identity(os.fstat(descriptor)) != _identity(snapshot):
                raise _IntegrityError("topology_store.root_changed")
        for parent, component, child in links:
            bound = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _identity(bound) != _identity(os.fstat(child)):
                raise _IntegrityError("topology_store.root_changed")
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if descriptors and locked:
            try:
                fcntl.flock(descriptors[-1], fcntl.LOCK_UN)
            except OSError as error:
                cleanup_error = error
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and operation_error is None:
            raise _HeadCleanupError from cleanup_error


@contextmanager
def _open_root(binding: ValidatedTopologyStoreBinding) -> Iterator[int]:
    if not isinstance(binding, ValidatedTopologyStoreBinding):
        raise ValueError("topology_store.binding_type_invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: List[int] = []
    snapshots: List[os.stat_result] = []
    links: List[Tuple[int, str, int]] = []
    locked = False
    try:
        current = os.open(os.path.sep, flags)
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        for component in filter(
            None,
            binding.canonical_project_root.split(os.path.sep)[1:],
        ):
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
            or not stat.S_ISDIR(root_metadata.st_mode)
            or bool(stat.S_IMODE(root_metadata.st_mode) & 0o022)
        ):
            raise _IntegrityError("topology_store.root_binding_conflict")
        try:
            fcntl.flock(current, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise _WriterBusy("topology_store.writer_busy") from error
            raise
        yield current
        for descriptor, snapshot in zip(descriptors, snapshots):
            if _identity(os.fstat(descriptor)) != _identity(snapshot):
                raise _IntegrityError("topology_store.root_changed")
        for parent, component, child in links:
            bound = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _identity(bound) != _identity(os.fstat(child)):
                raise _IntegrityError("topology_store.root_changed")
    finally:
        if descriptors and locked:
            try:
                fcntl.flock(descriptors[-1], fcntl.LOCK_UN)
            except OSError:
                pass
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _sync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("topology_store.write_failed")
        view = view[written:]


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
        _write_all(descriptor, payload)
        fullsync_file(descriptor)
    finally:
        os.close(descriptor)


def _read_file(parent: int, name: str) -> bytes:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size > MAX_RECORD_BYTES
    ):
        raise _IntegrityError("topology_store.file_integrity")
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
            raise _IntegrityError("topology_store.file_binding_changed")
        remaining = before.st_size
        chunks: List[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise _IntegrityError("topology_store.file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _IntegrityError("topology_store.file_grew")
        after_fd = os.fstat(descriptor)
        after_entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(after_fd) != _file_identity(opened)
            or _file_identity(after_entry) != _file_identity(opened)
        ):
            raise _IntegrityError("topology_store.file_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_json(parent: int, name: str) -> Tuple[Dict[str, Any], bytes]:
    payload = _read_file(parent, name)
    try:
        parsed = parse_json_object(
            payload[:-1] if payload.endswith(b"\n") else payload
        )
    except StrictJsonError as error:
        raise _IntegrityError("topology_store.json_invalid") from error
    if payload != canonical_json(parsed) + b"\n":
        raise _IntegrityError("topology_store.json_not_canonical")
    return parsed, payload


def _fullsync_bound_file(parent: int, name: str) -> None:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or _file_identity(os.fstat(descriptor)) != _file_identity(before)
        ):
            raise _IntegrityError("topology_store.file_integrity")
        fullsync_file(descriptor)
    finally:
        os.close(descriptor)


def _probe_durability(anchor: int) -> bool:
    if probe_capability(anchor) is not True:
        return False
    name = ".ask-herdr-topology.probe.{}.tmp".format(secrets.token_hex(8))
    capsule = file_descriptor = -1
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=anchor)
        created = True
        capsule = _open_directory(anchor, name)
        file_descriptor = os.open(
            "regular",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=capsule,
        )
        os.fchmod(file_descriptor, 0o600)
        _write_all(file_descriptor, b"ask-herdr topology durability probe\n")
        fullsync_file(file_descriptor)
        _sync_directory(capsule)
        _sync_directory(anchor)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if capsule >= 0:
            try:
                if _directory_binding(anchor, name, capsule):
                    try:
                        os.unlink("regular", dir_fd=capsule)
                    except FileNotFoundError:
                        pass
                    _sync_directory(capsule)
            finally:
                os.close(capsule)
        if created:
            try:
                os.rmdir(name, dir_fd=anchor)
                _sync_directory(anchor)
            except FileNotFoundError:
                pass
    return True


_topology_durability_capability_probe = _probe_durability


def _mkdir_open(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    return _open_directory(parent, name)


def _discard_bootstrap_candidate(root: int, name: str) -> None:
    candidate = _open_directory(root, name)
    transactions = -1
    try:
        entries = set(os.listdir(candidate))
        if entries != {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError("topology_store.bootstrap_candidate_changed")
        transactions = _open_directory(candidate, TRANSACTIONS_NAME)
        if os.listdir(transactions):
            raise _IntegrityError("topology_store.bootstrap_candidate_changed")
        os.close(transactions)
        transactions = -1
        os.rmdir(TRANSACTIONS_NAME, dir_fd=candidate)
        os.unlink(LAYOUT_NAME, dir_fd=candidate)
        os.unlink(BINDING_NAME, dir_fd=candidate)
        _sync_directory(candidate)
    finally:
        if transactions >= 0:
            os.close(transactions)
        os.close(candidate)
    os.rmdir(name, dir_fd=root)
    _sync_directory(root)


def _create_store(root: int, binding: ValidatedTopologyStoreBinding) -> None:
    try:
        supported = _topology_durability_capability_probe(root)
    except (OSError, ValueError, _IntegrityError) as error:
        raise _IntegrityError("durability_not_supported") from error
    if supported is not True:
        raise _IntegrityError("durability_not_supported")
    token = hashlib.sha256(canonical_json(_binding_payload(binding))).hexdigest()[:24]
    candidate_name = ".ask-herdr-topology.bootstrap.{}.{}.tmp".format(
        token,
        secrets.token_hex(8),
    )
    candidate = transactions = -1
    try:
        candidate = _mkdir_open(root, candidate_name)
        _write_new(
            candidate,
            LAYOUT_NAME,
            canonical_json(_layout_payload()) + b"\n",
        )
        _write_new(
            candidate,
            BINDING_NAME,
            canonical_json(_binding_payload(binding)) + b"\n",
        )
        transactions = _mkdir_open(candidate, TRANSACTIONS_NAME)
        _sync_directory(transactions)
        _sync_directory(candidate)
        disposition = commit_exclusive(root, candidate_name, STORE_NAME)
    finally:
        if transactions >= 0:
            os.close(transactions)
        if candidate >= 0:
            os.close(candidate)
    if disposition is CommitDisposition.OCCUPIED:
        _discard_bootstrap_candidate(root, candidate_name)
    _sync_directory(root)


def _open_handles(
    root: int,
    binding: ValidatedTopologyStoreBinding,
) -> Optional[_Handles]:
    try:
        store = _open_directory(root, STORE_NAME)
    except FileNotFoundError:
        return None
    transactions = -1
    try:
        if set(os.listdir(store)) != {
            LAYOUT_NAME,
            BINDING_NAME,
            TRANSACTIONS_NAME,
        }:
            raise _IntegrityError("topology_store.layout_invalid")
        layout, _ = _read_json(store, LAYOUT_NAME)
        if layout != _layout_payload():
            raise _IntegrityError("topology_store.layout_invalid")
        stored_binding, _ = _read_json(store, BINDING_NAME)
        if stored_binding != _binding_payload(binding):
            raise _IntegrityError("topology_store.binding_conflict")
        transactions = _open_directory(store, TRANSACTIONS_NAME)
        _fullsync_bound_file(store, LAYOUT_NAME)
        _fullsync_bound_file(store, BINDING_NAME)
        _sync_directory(transactions)
        _sync_directory(store)
        _sync_directory(root)
        if (
            not _directory_binding(root, STORE_NAME, store)
            or not _directory_binding(
                store,
                TRANSACTIONS_NAME,
                transactions,
            )
            or set(os.listdir(store))
            != {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}
            or _read_json(store, LAYOUT_NAME)[0] != _layout_payload()
            or _read_json(store, BINDING_NAME)[0]
            != _binding_payload(binding)
        ):
            raise _IntegrityError("topology_store.bootstrap_winner_changed")
        return _Handles(root=root, store=store, transactions=transactions)
    except Exception:
        if transactions >= 0:
            os.close(transactions)
        os.close(store)
        raise


def _open_head_handles(
    root: int,
    binding: ValidatedTopologyStoreBinding,
) -> Optional[_HeadHandles]:
    """Open and authenticate the journal envelope without durability writes."""

    try:
        store = _open_directory(root, STORE_NAME)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _IntegrityError(
            "topology_store.directory_integrity"
        ) from error
    transactions = -1
    try:
        if set(os.listdir(store)) != {
            LAYOUT_NAME,
            BINDING_NAME,
            TRANSACTIONS_NAME,
        }:
            raise _IntegrityError("topology_store.layout_invalid")
        try:
            layout_identity = _file_identity(
                os.stat(
                    LAYOUT_NAME,
                    dir_fd=store,
                    follow_symlinks=False,
                )
            )
            binding_identity = _file_identity(
                os.stat(
                    BINDING_NAME,
                    dir_fd=store,
                    follow_symlinks=False,
                )
            )
        except OSError as error:
            raise _IntegrityError(
                "topology_store.layout_invalid"
            ) from error
        layout, _ = _read_head_json(store, LAYOUT_NAME)
        if layout != _layout_payload():
            raise _IntegrityError("topology_store.layout_invalid")
        stored_binding, _ = _read_head_json(store, BINDING_NAME)
        if stored_binding != _binding_payload(binding):
            raise _IntegrityError("topology_store.binding_conflict")
        try:
            transactions = _open_directory(store, TRANSACTIONS_NAME)
        except OSError as error:
            raise _IntegrityError(
                "topology_store.directory_integrity"
            ) from error
        if (
            not _directory_binding(root, STORE_NAME, store)
            or not _directory_binding(
                store,
                TRANSACTIONS_NAME,
                transactions,
            )
            or set(os.listdir(store))
            != {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}
            or _read_head_json(store, LAYOUT_NAME)[0] != _layout_payload()
            or _read_head_json(store, BINDING_NAME)[0]
            != _binding_payload(binding)
            or _file_identity(
                os.stat(
                    LAYOUT_NAME,
                    dir_fd=store,
                    follow_symlinks=False,
                )
            )
            != layout_identity
            or _file_identity(
                os.stat(
                    BINDING_NAME,
                    dir_fd=store,
                    follow_symlinks=False,
                )
            )
            != binding_identity
        ):
            raise _IntegrityError("topology_store.bootstrap_winner_changed")
        return _HeadHandles(
            root=root,
            store=store,
            transactions=transactions,
            layout_identity=layout_identity,
            binding_identity=binding_identity,
        )
    except BaseException:
        if transactions >= 0:
            try:
                os.close(transactions)
            except OSError:
                pass
        try:
            os.close(store)
        except OSError:
            pass
        raise


def _validate_head_envelope(
    handles: _HeadHandles,
    binding: ValidatedTopologyStoreBinding,
) -> None:
    """Rebind the exact immutable envelope before projecting a head."""

    try:
        bootstrap_names = tuple(
            name
            for name in os.listdir(handles.root)
            if name.startswith(BOOTSTRAP_PREFIX)
        )
        if bootstrap_names:
            raise _IntegrityError(
                "topology_ledger_head.bootstrap_invalid"
            )
        changed = (
            not _directory_binding(handles.root, STORE_NAME, handles.store)
            or not _directory_binding(
                handles.store,
                TRANSACTIONS_NAME,
                handles.transactions,
            )
            or set(os.listdir(handles.store))
            != {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}
            or _file_identity(
                os.stat(
                    LAYOUT_NAME,
                    dir_fd=handles.store,
                    follow_symlinks=False,
                )
            )
            != handles.layout_identity
            or _file_identity(
                os.stat(
                    BINDING_NAME,
                    dir_fd=handles.store,
                    follow_symlinks=False,
                )
            )
            != handles.binding_identity
            or _read_head_file(handles.store, LAYOUT_NAME)
            != canonical_json(_layout_payload()) + b"\n"
            or _read_head_file(handles.store, BINDING_NAME)
            != canonical_json(_binding_payload(binding)) + b"\n"
        )
    except _IntegrityError as error:
        if error.code == "topology_ledger_head.bootstrap_invalid":
            raise
        raise _IntegrityError("topology_store.store_changed") from error
    except OSError as error:
        raise _IntegrityError("topology_store.store_changed") from error
    if changed:
        raise _IntegrityError("topology_store.store_changed")


def _validate_head_transaction_namespace(
    handles: _HeadHandles,
    expected_identities: Tuple[Tuple[str, Tuple[int, ...]], ...],
) -> None:
    """Require the exact transaction names and identities just replayed."""

    expected = dict(expected_identities)
    try:
        names = tuple(sorted(os.listdir(handles.transactions)))
        if names != tuple(sorted(expected)):
            raise _IntegrityError(
                "topology_store.transaction_namespace_changed"
            )
        for name in names:
            if _identity(
                os.stat(
                    name,
                    dir_fd=handles.transactions,
                    follow_symlinks=False,
                )
            ) != expected[name]:
                raise _IntegrityError(
                    "topology_store.transaction_namespace_changed"
                )
    except OSError as error:
        raise _IntegrityError(
            "topology_store.transaction_namespace_changed"
        ) from error


def _close_head_descriptors(
    descriptors: Sequence[int],
    operation_error: Optional[BaseException] = None,
) -> None:
    """Attempt every reader-owned close without replacing a primary error."""

    first_error: Optional[OSError] = None
    for descriptor in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None and operation_error is None:
        raise _HeadCleanupError from first_error


@contextmanager
def _head_descriptor(descriptor: int) -> Iterator[int]:
    """Close one reader-owned descriptor while preserving a body failure."""

    operation_error: Optional[BaseException] = None
    try:
        yield descriptor
    except BaseException as error:
        operation_error = error
        raise
    finally:
        _close_head_descriptors((descriptor,), operation_error)


def _read_head_file(parent: int, name: str) -> bytes:
    """Read one immutable head source with primary-preserving cleanup."""

    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size > MAX_RECORD_BYTES
    ):
        raise _IntegrityError("topology_store.file_integrity")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    with _head_descriptor(descriptor):
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise _IntegrityError("topology_store.file_binding_changed")
        remaining = before.st_size
        chunks: List[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise _IntegrityError("topology_store.file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _IntegrityError("topology_store.file_grew")
        after_fd = os.fstat(descriptor)
        after_entry = os.stat(
            name,
            dir_fd=parent,
            follow_symlinks=False,
        )
        if (
            _file_identity(after_fd) != _file_identity(opened)
            or _file_identity(after_entry) != _file_identity(opened)
        ):
            raise _IntegrityError("topology_store.file_changed")
        return b"".join(chunks)


def _read_head_json(parent: int, name: str) -> Tuple[Dict[str, Any], bytes]:
    payload = _read_head_file(parent, name)
    try:
        parsed = parse_json_object(
            payload[:-1] if payload.endswith(b"\n") else payload
        )
    except StrictJsonError as error:
        raise _IntegrityError("topology_store.json_invalid") from error
    if payload != canonical_json(parsed) + b"\n":
        raise _IntegrityError("topology_store.json_not_canonical")
    return parsed, payload


def _head_bootstrap_residue(
    root: int,
    binding: ValidatedTopologyStoreBinding,
) -> bool:
    """Validate one coherent read-only store-bootstrap construction prefix."""

    def managed_root_entries() -> Tuple[str, ...]:
        return tuple(
            sorted(
                name
                for name in os.listdir(root)
                if name == STORE_NAME
                or name.startswith(BOOTSTRAP_PREFIX)
            )
        )

    try:
        managed_entries = managed_root_entries()
    except OSError as error:
        raise _IntegrityError(
            "topology_ledger_head.bootstrap_invalid"
        ) from error
    if STORE_NAME in managed_entries:
        raise _IntegrityError("topology_ledger_head.bootstrap_invalid")
    names = tuple(
        name
        for name in managed_entries
        if name.startswith(BOOTSTRAP_PREFIX)
    )
    if not names:
        try:
            if managed_root_entries() != managed_entries:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
        except OSError as error:
            raise _IntegrityError(
                "topology_ledger_head.bootstrap_invalid"
            ) from error
        return False
    if len(names) != 1:
        raise _IntegrityError("topology_ledger_head.bootstrap_invalid")
    name = names[0]
    match = BOOTSTRAP_NAME.fullmatch(name)
    expected_token = hashlib.sha256(
        canonical_json(_binding_payload(binding))
    ).hexdigest()[:24]
    if match is None or match.group(1) != expected_token:
        raise _IntegrityError("topology_ledger_head.bootstrap_invalid")

    try:
        candidate = _open_directory(root, name)
    except OSError as error:
        raise _IntegrityError(
            "topology_ledger_head.bootstrap_invalid"
        ) from error
    transactions = -1
    operation_error: Optional[BaseException] = None
    try:
        entries = set(os.listdir(candidate))
        file_sources: Dict[str, Tuple[Tuple[int, ...], bytes]] = {}
        valid_entries = (
            set(),
            {LAYOUT_NAME},
            {LAYOUT_NAME, BINDING_NAME},
            {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME},
        )
        if entries not in valid_entries:
            raise _IntegrityError("topology_ledger_head.bootstrap_invalid")
        expected_layout = canonical_json(_layout_payload()) + b"\n"
        expected_binding = canonical_json(_binding_payload(binding)) + b"\n"
        if LAYOUT_NAME in entries:
            try:
                layout_identity = _file_identity(
                    os.stat(
                        LAYOUT_NAME,
                        dir_fd=candidate,
                        follow_symlinks=False,
                    )
                )
                actual_layout = _read_head_file(candidate, LAYOUT_NAME)
                if _file_identity(
                    os.stat(
                        LAYOUT_NAME,
                        dir_fd=candidate,
                        follow_symlinks=False,
                    )
                ) != layout_identity:
                    raise _IntegrityError(
                        "topology_ledger_head.bootstrap_invalid"
                    )
            except OSError as error:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                ) from error
            file_sources[LAYOUT_NAME] = (
                layout_identity,
                actual_layout,
            )
            if not expected_layout.startswith(actual_layout) or (
                (BINDING_NAME in entries or TRANSACTIONS_NAME in entries)
                and actual_layout != expected_layout
            ):
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
        if BINDING_NAME in entries:
            try:
                binding_identity = _file_identity(
                    os.stat(
                        BINDING_NAME,
                        dir_fd=candidate,
                        follow_symlinks=False,
                    )
                )
                actual_binding = _read_head_file(candidate, BINDING_NAME)
                if _file_identity(
                    os.stat(
                        BINDING_NAME,
                        dir_fd=candidate,
                        follow_symlinks=False,
                    )
                ) != binding_identity:
                    raise _IntegrityError(
                        "topology_ledger_head.bootstrap_invalid"
                    )
            except OSError as error:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                ) from error
            file_sources[BINDING_NAME] = (
                binding_identity,
                actual_binding,
            )
            if not expected_binding.startswith(actual_binding) or (
                TRANSACTIONS_NAME in entries
                and actual_binding != expected_binding
            ):
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
        transactions_identity: Optional[Tuple[int, ...]] = None
        if TRANSACTIONS_NAME in entries:
            try:
                transactions = _open_directory(
                    candidate,
                    TRANSACTIONS_NAME,
                )
                transactions_identity = _identity(
                    os.fstat(transactions)
                )
                transaction_entries = os.listdir(transactions)
            except (OSError, _IntegrityError) as error:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                ) from error
            if transaction_entries:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
        try:
            if set(os.listdir(candidate)) != entries:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
            for file_name, (identity, source_bytes) in file_sources.items():
                if (
                    _file_identity(
                        os.stat(
                            file_name,
                            dir_fd=candidate,
                            follow_symlinks=False,
                        )
                    )
                    != identity
                    or _read_head_file(candidate, file_name) != source_bytes
                ):
                    raise _IntegrityError(
                        "topology_ledger_head.bootstrap_invalid"
                    )
            if transactions >= 0 and (
                transactions_identity != _identity(os.fstat(transactions))
                or not _directory_binding(
                    candidate,
                    TRANSACTIONS_NAME,
                    transactions,
                )
                or os.listdir(transactions)
            ):
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
            if not _directory_binding(root, name, candidate):
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
            if managed_root_entries() != managed_entries:
                raise _IntegrityError(
                    "topology_ledger_head.bootstrap_invalid"
                )
        except OSError as error:
            raise _IntegrityError("topology_ledger_head.bootstrap_invalid")
        return True
    except BaseException as error:
        operation_error = error
        raise
    finally:
        _close_head_descriptors(
            (transactions, candidate),
            operation_error,
        )


def _close_handles(handles: _Handles) -> None:
    caller_frame = sys._getframe(1)
    active_traceback = sys.exc_info()[2]
    primary_error_active = False
    while active_traceback is not None:
        if active_traceback.tb_frame is caller_frame:
            primary_error_active = True
            break
        active_traceback = active_traceback.tb_next

    first_close_error: Optional[OSError] = None
    for descriptor in (handles.transactions, handles.store):
        try:
            os.close(descriptor)
        except OSError as error:
            if first_close_error is None:
                first_close_error = error
    if first_close_error is not None and not primary_error_active:
        raise first_close_error


def _store_incarnation_digest(
    handles: _Handles,
    binding: ValidatedTopologyStoreBinding,
) -> str:
    """Bind an authoritative journal to its stable named directory identity."""

    metadata = os.fstat(handles.store)
    if (
        not _private_directory(metadata)
        or metadata.st_dev != os.fstat(handles.root).st_dev
        or not _directory_binding(handles.root, STORE_NAME, handles.store)
        or not _directory_binding(
            handles.store,
            TRANSACTIONS_NAME,
            handles.transactions,
        )
    ):
        raise _IntegrityError("topology_store.incarnation_changed")
    return _digest_json(
        {
            "schema": "ask_herdr.topology_store_incarnation.internal.v1",
            "binding_digest": _binding_digest(binding),
            "store_device": metadata.st_dev,
            "store_inode": metadata.st_ino,
            "owner_uid": metadata.st_uid,
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    )


def _validate_replay_incarnation(
    handles: _Handles,
    binding: ValidatedTopologyStoreBinding,
    replay: _Replay,
) -> None:
    current = _store_incarnation_digest(handles, binding)
    if any(
        mutation.topology_store_incarnation_digest is not None
        and mutation.topology_store_incarnation_digest != current
        for mutation in replay.mutations.values()
    ):
        raise _IntegrityError("topology_store.incarnation_conflict")


def _ensure_handles(
    root: int,
    binding: ValidatedTopologyStoreBinding,
) -> _Handles:
    handles = _open_handles(root, binding)
    if handles is not None:
        return handles
    _create_store(root, binding)
    handles = _open_handles(root, binding)
    if handles is None:
        raise _IntegrityError("topology_store.creation_unverified")
    return handles


def _ensure_topology_store_incarnation_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
) -> str:
    """Create or open one journal and return its replay-validated incarnation."""

    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.binding_type_invalid"
        ) from error
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _ensure_handles(root, binding_snapshot)
        replay = _read_records(handles, binding_snapshot)
        _validate_replay_incarnation(handles, binding_snapshot, replay)
        return _store_incarnation_digest(handles, binding_snapshot)
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "topology_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _mutation_payload(value: TopologyMutationIntent) -> Dict[str, Any]:
    payload = _json_value(value)
    if value.topology_store_incarnation_digest is None:
        payload.pop("topology_store_incarnation_digest", None)
    return payload


def _snapshot_validated_topology_binding(
    value: ValidatedTopologyStoreBinding,
) -> ValidatedTopologyStoreBinding:
    """Return one fresh exact base-value snapshot of a store binding."""

    if type(value) is not ValidatedTopologyStoreBinding:
        raise ValueError("topology_store.binding_type_invalid")
    try:
        return ValidatedTopologyStoreBinding(**dict(vars(value)))
    except (TypeError, ValueError) as error:
        raise ValueError("topology_store.binding_type_invalid") from error


def _snapshot_topology_mutation_intent(
    value: TopologyMutationIntent,
) -> TopologyMutationIntent:
    """Return one fresh exact base-value snapshot of a mutation intent.

    Under-lease callers supply correlation data, not authority-bearing
    objects.  Reject subclasses and ensure every later read and durable byte is
    derived from one immutable base instance.
    """

    if type(value) is not TopologyMutationIntent:
        raise ValueError("topology_store.mutation_type_invalid")
    try:
        return TopologyMutationIntent(**dict(vars(value)))
    except (TypeError, ValueError) as error:
        raise ValueError("topology_store.mutation_type_invalid") from error


def _snapshot_topology_command_intent(
    value: TopologyCommandIntent,
) -> TopologyCommandIntent:
    """Return one immutable exact-base command correlation snapshot."""

    if type(value) is not TopologyCommandIntent:
        raise ValueError("topology_store.command_type_invalid")
    try:
        return TopologyCommandIntent(**dict(vars(value)))
    except (TypeError, ValueError) as error:
        raise ValueError("topology_store.command_type_invalid") from error


def _command_payload(value: TopologyCommandIntent) -> Dict[str, Any]:
    return _json_value(value)


def _receipt_payload(value: TopologyCommandReceipt) -> Dict[str, Any]:
    return _json_value(value)


def _settlement_payload(value: TopologyMutationSettlement) -> Dict[str, Any]:
    payload = _json_value(value)
    if value.project_topology_proof is not None:
        payload["project_topology_proof"] = project_topology_payload(
            value.project_topology_proof
        )
    return payload


def _event_record(
    binding: ValidatedTopologyStoreBinding,
    sequence: int,
    previous_digest: Optional[str],
    event_kind: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    record = {
        "schema": "ask_herdr.topology_event.internal.v1",
        "binding_digest": _binding_digest(binding),
        "event_sequence": sequence,
        "previous_record_digest": previous_digest,
        "event_kind": event_kind,
        "payload": payload,
    }
    record["record_digest"] = _digest_json(record)
    return record


def _event_name(sequence: int) -> str:
    return "event.{:016d}.txn".format(sequence)


def _mutation_from_payload(payload: Mapping[str, Any]) -> TopologyMutationIntent:
    try:
        return TopologyMutationIntent(**dict(payload))
    except (TypeError, ValueError) as error:
        raise _IntegrityError("topology_store.mutation_record_invalid") from error


def _command_from_payload(payload: Mapping[str, Any]) -> TopologyCommandIntent:
    try:
        return TopologyCommandIntent(**dict(payload))
    except (TypeError, ValueError) as error:
        raise _IntegrityError("topology_store.command_record_invalid") from error


def _receipt_from_payload(payload: Mapping[str, Any]) -> TopologyCommandReceipt:
    values = dict(payload)
    try:
        values["disposition"] = CommandEffectDisposition(values["disposition"])
        values["resource_binding_digests"] = tuple(
            values["resource_binding_digests"]
        )
        return TopologyCommandReceipt(**values)
    except (KeyError, TypeError, ValueError) as error:
        raise _IntegrityError("topology_store.receipt_record_invalid") from error


def _settlement_from_payload(
    payload: Mapping[str, Any],
) -> TopologyMutationSettlement:
    values = dict(payload)
    try:
        values["command_receipt_digests"] = tuple(
            values["command_receipt_digests"]
        )
        proof = values.get("project_topology_proof")
        if proof is not None:
            values["project_topology_proof"] = project_topology_from_payload(
                proof
            )
        return TopologyMutationSettlement(**values)
    except (KeyError, TypeError, ValueError) as error:
        raise _IntegrityError("topology_store.settlement_record_invalid") from error


def _proof_correlates(
    value: TopologyMutationSettlement,
    mutation: TopologyMutationIntent,
    receipts: Sequence[TopologyCommandReceipt],
    prior_proof: Optional[ProjectTopologyProof],
) -> bool:
    proof = value.project_topology_proof
    if proof is None:
        return True
    try:
        matching_lanes = tuple(
            item
            for item in proof.lanes
            if item.lane_id == mutation.lane_id
            and item.consultant_key == mutation.consultant_key
            and item.topology_nonce == mutation.topology_nonce
            and item.workspace.cwd == mutation.lane_workspace_cwd
        )
        project_root = str(Path(mutation.lane_workspace_cwd).parents[1])
        lane_ids = tuple(item.lane_id for item in proof.lanes)
        consultant_keys = tuple(item.consultant_key for item in proof.lanes)
        if mutation.prior_topology_digest is None:
            continuity_valid = (
                prior_proof is None
                and proof.topology_epoch_id == mutation.topology_nonce
                and len(proof.lanes) == 1
            )
        else:
            prior_lanes = set(prior_proof.lanes) if prior_proof is not None else set()
            current_lanes = set(proof.lanes)
            continuity_valid = (
                prior_proof is not None
                and project_topology_digest(prior_proof)
                == mutation.prior_topology_digest
                and proof.project_id == prior_proof.project_id
                and proof.project_root == prior_proof.project_root
                and proof.namespace == prior_proof.namespace
                and proof.topology_epoch_id == prior_proof.topology_epoch_id
                and proof.session_binding == prior_proof.session_binding
                and set(proof.side_effects) == set(prior_proof.side_effects)
                and prior_lanes.issubset(current_lanes)
                and len(current_lanes) == len(prior_lanes) + 1
            )
        if (
            proof.namespace != "ask-pipeline"
            or proof.session_binding.name != "ask-pipeline"
            or proof.session_binding.default is not False
            or proof.project_root != project_root
            or len(matching_lanes) != 1
            or mutation.intended_action != "reconcile_or_provision"
            or not continuity_valid
            or len(lane_ids) != len(set(lane_ids))
            or len(consultant_keys) != len(set(consultant_keys))
            or any(
                lane.project_id != proof.project_id
                or lane.project_root != proof.project_root
                for lane in proof.lanes
            )
            or any(
                item.project_id != proof.project_id
                or item.project_root != proof.project_root
                for item in proof.side_effects
            )
        ):
            return False

        receipt_by_digest = {
            item.command_receipt_digest: item for item in receipts
        }
        resources: Dict[str, List[str]] = {}
        roles: Dict[str, str] = {}
        fingerprint_owners: Dict[Tuple[str, ...], str] = {}
        workspace_ids = set()
        tab_ids = set()
        pane_ids = set()
        for lane_proof in proof.lanes:
            digest = lane_proof.workspace.creation_receipt_digest
            if roles.get(digest, "lane") != "lane":
                return False
            roles[digest] = "lane"
            fingerprint = topology_resource_fingerprint(lane_proof.workspace)
            prior_owner = fingerprint_owners.get(fingerprint)
            if prior_owner is not None and prior_owner != digest:
                return False
            fingerprint_owners[fingerprint] = digest
            if (
                lane_proof.workspace.workspace_id in workspace_ids
                or lane_proof.workspace.tab_id in tab_ids
                or lane_proof.workspace.pane_id in pane_ids
            ):
                return False
            workspace_ids.add(lane_proof.workspace.workspace_id)
            tab_ids.add(lane_proof.workspace.tab_id)
            pane_ids.add(lane_proof.workspace.pane_id)
            resources.setdefault(digest, []).append(
                topology_resource_binding_digest(lane_proof.workspace)
            )
        for side_effect in proof.side_effects:
            digest = side_effect.creation_receipt_digest
            if roles.get(digest, "side_effect") != "side_effect":
                return False
            roles[digest] = "side_effect"
            fingerprint = topology_resource_fingerprint(side_effect)
            prior_owner = fingerprint_owners.get(fingerprint)
            if prior_owner is not None and prior_owner != digest:
                return False
            fingerprint_owners[fingerprint] = digest
            if (
                side_effect.workspace_id in workspace_ids
                or side_effect.tab_id in tab_ids
                or side_effect.pane_id in pane_ids
            ):
                return False
            workspace_ids.add(side_effect.workspace_id)
            tab_ids.add(side_effect.tab_id)
            pane_ids.add(side_effect.pane_id)
            resources.setdefault(digest, []).append(
                topology_resource_binding_digest(side_effect)
            )

        if set(resources) - set(receipt_by_digest):
            return False
        for receipt in receipts:
            digest = receipt.command_receipt_digest
            expected_resources = tuple(sorted(resources.get(digest, ())))
            role = roles.get(digest)
            if receipt.resource_binding_digests != expected_resources:
                return False
            if role == "lane" and receipt.command_kind != "workspace_create":
                return False
            if role == "side_effect" and receipt.command_kind not in {
                "session_start",
                "workspace_close",
            }:
                return False
            if role is None and receipt.command_kind == "workspace_create":
                return False
        return True
    except (AttributeError, TypeError, ValueError):
        return False


def _empty_replay() -> _Replay:
    return _Replay([], {}, {}, {}, {}, {}, {})


def _commands_for_mutation(
    replay: _Replay,
    mutation_id: str,
) -> List[TopologyCommandIntent]:
    return [
        command
        for (recorded_mutation_id, _), command in replay.commands.items()
        if recorded_mutation_id == mutation_id
    ]


def _open_mutation_ids(replay: _Replay) -> Tuple[str, ...]:
    return tuple(
        mutation_id
        for mutation_id in replay.mutations
        if mutation_id not in replay.settlements
    )


def _mutation_identity_conflict(
    replay: _Replay,
    value: TopologyMutationIntent,
) -> Optional[str]:
    for existing in replay.mutations.values():
        if existing.operation_id == value.operation_id:
            return "topology_store.operation_id_replayed"
        if existing.topology_nonce == value.topology_nonce:
            return "topology_store.topology_nonce_replayed"
        if (
            existing.lane_id == value.lane_id
            and existing.lane_generation == value.lane_generation
        ):
            return "topology_store.lane_generation_replayed"
    return None


def _latest_project_topology_digest(replay: _Replay) -> Optional[str]:
    if not replay.settlements:
        return None
    return list(replay.settlements.values())[-1].project_topology_digest


def _latest_project_topology_proof(
    replay: _Replay,
) -> Optional[ProjectTopologyProof]:
    if not replay.settlements:
        return None
    return list(replay.settlements.values())[-1].project_topology_proof


def _resolve_command_intent(
    replay: _Replay,
    value: TopologyCommandIntent,
) -> TopologyCommandIntent:
    """Fill legacy omissions but bind every persisted step to exact order/state."""

    mutation = replay.mutations.get(value.mutation_id)
    if mutation is None or value.mutation_id in replay.settlements:
        raise _CommandOrderInvalid("topology_store.mutation_not_open")
    key = (value.mutation_id, value.step_id)
    existing = replay.commands.get(key)
    if existing is not None:
        return replace(
            value,
            expected_postcondition_digest=(
                value.expected_postcondition_digest
                if value.expected_postcondition_digest is not None
                else existing.expected_postcondition_digest
            ),
            step_sequence=(
                value.step_sequence
                if value.step_sequence is not None
                else existing.step_sequence
            ),
            prior_step_id=(
                value.prior_step_id
                if value.prior_step_id is not None
                else existing.prior_step_id
            ),
        )
    prior_commands = _commands_for_mutation(replay, value.mutation_id)
    expected_sequence = len(prior_commands) + 1
    expected_prior = prior_commands[-1].step_id if prior_commands else None
    if value.step_sequence not in (None, expected_sequence):
        raise _CommandOrderInvalid("topology_store.command_order_invalid")
    if value.prior_step_id not in (None, expected_prior):
        raise _CommandOrderInvalid("topology_store.command_order_invalid")
    if prior_commands:
        prior_key = (value.mutation_id, expected_prior)
        prior_receipt = replay.receipts.get(prior_key)
        if (
            prior_receipt is None
            or prior_receipt.disposition is not CommandEffectDisposition.CONFIRMED
        ):
            raise _CommandOrderInvalid("topology_store.command_order_invalid")
    return replace(
        value,
        expected_postcondition_digest=(
            value.expected_postcondition_digest
            if value.expected_postcondition_digest is not None
            else mutation.expected_postcondition_digest
        ),
        step_sequence=expected_sequence,
        prior_step_id=expected_prior,
    )


def _public_command_payload(
    replay: _Replay,
    value: TopologyCommandIntent,
) -> Dict[str, Any]:
    """Resolve a legacy command only when its mutation is unanchored."""

    mutation = replay.mutations.get(value.mutation_id)
    if (
        mutation is not None
        and mutation.topology_store_incarnation_digest is not None
    ):
        raise _CommandOrderInvalid(
            "topology_store.project_lease_required"
        )
    return _command_payload(_resolve_command_intent(replay, value))


def _apply_event(replay: _Replay, kind: str, payload: Mapping[str, Any]) -> None:
    if kind == "mutation_intent":
        value = _mutation_from_payload(payload)
        identity_conflict = _mutation_identity_conflict(replay, value)
        if (
            value.mutation_id in replay.mutations
            or identity_conflict is not None
            or _open_mutation_ids(replay)
            or value.prior_topology_digest
            != _latest_project_topology_digest(replay)
        ):
            raise _IntegrityError("topology_store.mutation_order_invalid")
        replay.mutations[value.mutation_id] = value
        return
    if kind == "command_intent":
        value = _command_from_payload(payload)
        key = (value.mutation_id, value.step_id)
        commands = _commands_for_mutation(replay, value.mutation_id)
        expected_sequence = len(commands) + 1
        expected_prior = commands[-1].step_id if commands else None
        prior_receipt = (
            replay.receipts.get((value.mutation_id, expected_prior))
            if expected_prior is not None
            else None
        )
        if (
            value.mutation_id not in replay.mutations
            or value.mutation_id in replay.settlements
            or key in replay.commands
            or value.expected_postcondition_digest is None
            or value.step_sequence != expected_sequence
            or value.prior_step_id != expected_prior
            or (
                expected_prior is not None
                and (
                    prior_receipt is None
                    or prior_receipt.disposition
                    is not CommandEffectDisposition.CONFIRMED
                )
            )
        ):
            raise _IntegrityError("topology_store.command_order_invalid")
        replay.commands[key] = value
        return
    if kind == "command_receipt":
        value = _receipt_from_payload(payload)
        key = (value.mutation_id, value.step_id)
        command = replay.commands.get(key)
        if (
            command is None
            or key in replay.receipts
            or value.mutation_id in replay.settlements
            or value.command_kind != command.command_kind
            or value.command_argv_digest != command.command_argv_digest
            or value.observed_postcondition_digest
            != command.expected_postcondition_digest
            or value.request_id in replay.request_ids
            or value.command_receipt_digest in replay.receipt_digests
        ):
            raise _IntegrityError("topology_store.receipt_order_invalid")
        replay.receipts[key] = value
        replay.request_ids[value.request_id] = key
        replay.receipt_digests[value.command_receipt_digest] = key
        return
    if kind == "mutation_settlement":
        value = _settlement_from_payload(payload)
        mutation = replay.mutations.get(value.mutation_id)
        receipts = tuple(
            item.command_receipt_digest
            for key, item in replay.receipts.items()
            if key[0] == value.mutation_id
        )
        pending = any(
            key[0] == value.mutation_id and key not in replay.receipts
            for key in replay.commands
        )
        mutation_receipts = [
            item
            for key, item in replay.receipts.items()
            if key[0] == value.mutation_id
        ]
        matching_generation = bool(mutation_receipts) and all(
            item.session_dir == value.session_dir
            and item.socket_path == value.socket_path
            and item.session_generation_id == value.session_generation_id
                    for item in mutation_receipts
        )
        mutation_commands = _commands_for_mutation(replay, value.mutation_id)
        final_command = mutation_commands[-1] if mutation_commands else None
        proof_correlated = (
            mutation is not None
            and _proof_correlates(
                value,
                mutation,
                tuple(replay.receipts.values()),
                _latest_project_topology_proof(replay),
            )
        )
        if (
            mutation is None
            or value.mutation_id in replay.settlements
            or _open_mutation_ids(replay) != (value.mutation_id,)
            or pending
            or tuple(sorted(receipts)) != value.command_receipt_digests
            or not matching_generation
            or any(
                item.disposition is not CommandEffectDisposition.CONFIRMED
                for item in mutation_receipts
            )
            or final_command is None
            or final_command.expected_postcondition_digest
            != mutation.expected_postcondition_digest
            or not proof_correlated
        ):
            raise _IntegrityError(
                "topology_store.settlement_resource_binding_mismatch"
                if mutation is not None and not proof_correlated
                else "topology_store.settlement_order_invalid"
            )
        replay.settlements[value.mutation_id] = value
        return
    raise _IntegrityError("topology_store.event_kind_invalid")


def _validate_record(
    record: Mapping[str, Any],
    binding: ValidatedTopologyStoreBinding,
    sequence: int,
    previous_digest: Optional[str],
) -> Dict[str, Any]:
    required = {
        "schema",
        "binding_digest",
        "event_sequence",
        "previous_record_digest",
        "event_kind",
        "payload",
        "record_digest",
    }
    value = dict(record)
    digest = value.get("record_digest")
    unsigned = dict(value)
    unsigned.pop("record_digest", None)
    if (
        set(value) != required
        or value.get("schema") != "ask_herdr.topology_event.internal.v1"
        or value.get("binding_digest") != _binding_digest(binding)
        or value.get("event_sequence") != sequence
        or value.get("previous_record_digest") != previous_digest
        or type(value.get("event_kind")) is not str
        or type(value.get("payload")) is not dict
        or type(digest) is not str
        or DIGEST.fullmatch(digest) is None
        or digest != _digest_json(unsigned)
    ):
        raise _IntegrityError("topology_store.record_invalid")
    return value


def _clone_replay(replay: _Replay) -> _Replay:
    return _Replay(
        records=list(replay.records),
        mutations=dict(replay.mutations),
        commands=dict(replay.commands),
        receipts=dict(replay.receipts),
        settlements=dict(replay.settlements),
        request_ids=dict(replay.request_ids),
        receipt_digests=dict(replay.receipt_digests),
        recovered_candidate=replay.recovered_candidate,
    )


def _candidate_name(record: Mapping[str, Any]) -> str:
    return ".candidate.event.{:016d}.{}.tmp".format(
        record["event_sequence"],
        record["record_digest"][len("sha256:") :],
    )


def _restore_event_barriers(
    transactions: int,
    slot_name: str,
    capsule: int,
) -> None:
    _fullsync_bound_file(capsule, RECORD_NAME)
    _sync_directory(capsule)
    _sync_directory(transactions)
    if not _directory_binding(transactions, slot_name, capsule):
        raise _IntegrityError("topology_store.capsule_changed")


def _invoke_failpoint(
    failpoint: Optional[Callable[[str], None]],
    stage: str,
) -> None:
    if failpoint is not None:
        failpoint(stage)


def _possible_event_record_prefix(payload: bytes) -> bool:
    canonical_start = b'{"binding_digest":"sha256:'
    return (
        len(payload) < MAX_RECORD_BYTES
        and b"\n" not in payload
        and (
            canonical_start.startswith(payload)
            or payload.startswith(canonical_start)
        )
    )


def _possible_json_document_prefix(
    payload: bytes,
    event_kind: str,
    binding: ValidatedTopologyStoreBinding,
    sequence: int,
    previous_digest: Optional[str],
    candidate_digest: Optional[str],
    replay: Optional[_Replay],
) -> bool:
    """Return whether bytes can still become one whitespace-free JSON value."""

    class _Incomplete(Exception):
        pass

    class _Invalid(Exception):
        pass

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        if (
            error.end != len(payload)
            or error.reason != "unexpected end of data"
        ):
            return False
        text = payload[: error.start].decode("utf-8") + "\ufffd"
    length = len(text)

    def exact_value_prefix(remainder: str, expected: Any) -> bool:
        encoded = canonical_json(expected).decode("utf-8")
        if encoded.startswith(remainder):
            return True
        return (
            remainder.startswith(encoded)
            and len(remainder) > len(encoded)
            and remainder[len(encoded)] in ",}]"
        )

    def quoted_digest_prefix(remainder: str) -> bool:
        if not remainder.startswith('"'):
            return False
        content = remainder[1:]
        closing = content.find('"')
        if closing >= 0:
            candidate = content[:closing]
            return DIGEST.fullmatch(candidate) is not None
        fixed = "sha256:"
        if fixed.startswith(content):
            return True
        if not content.startswith(fixed):
            return False
        hexadecimal = content[len(fixed) :]
        return len(hexadecimal) <= 64 and all(
            character in "0123456789abcdef"
            for character in hexadecimal
        )

    def quoted_uuid_prefix(remainder: str) -> bool:
        if not remainder.startswith('"'):
            return False
        content = remainder[1:]
        closing = content.find('"')
        candidate = content if closing < 0 else content[:closing]
        if len(candidate) > 36:
            return False
        for position, character in enumerate(candidate):
            if position in {8, 13, 18, 23}:
                if character != "-":
                    return False
            elif position == 14:
                if character != "4":
                    return False
            elif position == 19:
                if character not in "89ab":
                    return False
            elif character not in "0123456789abcdef":
                return False
        return closing < 0 or len(candidate) == 36

    def quoted_token_prefix(remainder: str) -> bool:
        if not remainder.startswith('"'):
            return False
        content = remainder[1:]
        closing = content.find('"')
        candidate = content if closing < 0 else content[:closing]
        if len(candidate) > 256:
            return False
        initial = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        continuation = initial + "._:-"
        if candidate and candidate[0] not in initial:
            return False
        if any(
            character not in continuation
            for character in candidate
        ):
            return False
        return closing < 0 or TOKEN.fullmatch(candidate) is not None

    def decoded_string_prefix(
        remainder: str,
    ) -> Optional[Tuple[str, bool]]:
        if not remainder.startswith('"'):
            return None
        content = remainder[1:]
        decoded: List[str] = []
        position = 0
        short_escapes = {
            '"': '"',
            "\\": "\\",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        unicode_escapes = tuple(
            f"{code:04x}"
            for code in (*range(0x08), 0x0B, *range(0x0E, 0x20))
        )
        while position < len(content):
            character = content[position]
            if character == '"':
                return "".join(decoded), True
            if ord(character) < 0x20:
                return None
            if character != "\\":
                decoded.append(character)
                position += 1
                continue
            position += 1
            if position == len(content):
                return "".join(decoded), False
            escape = content[position]
            if escape in short_escapes:
                decoded.append(short_escapes[escape])
                position += 1
                continue
            if escape != "u":
                return None
            hexadecimal = content[position + 1 : position + 5]
            if len(hexadecimal) < 4:
                if not any(
                    item.startswith(hexadecimal)
                    for item in unicode_escapes
                ):
                    return None
                return "".join(decoded), False
            if hexadecimal not in unicode_escapes:
                return None
            decoded.append(chr(int(hexadecimal, 16)))
            position += 5
        return "".join(decoded), False

    def quoted_path_prefix(remainder: str) -> bool:
        parsed = decoded_string_prefix(remainder)
        if parsed is None:
            return False
        candidate, closed = parsed
        if closed:
            return True
        if not candidate:
            return True
        if (
            not candidate.startswith("/")
            or "\x00" in candidate
            or "//" in candidate
        ):
            return False
        completed_parts = candidate[1:].split("/")[:-1]
        return not any(
            part in {"", ".", ".."}
            for part in completed_parts
        )

    def integer_prefix(remainder: str, *, positive: bool) -> bool:
        if not remainder:
            return False
        position = 0
        if not positive and remainder.startswith("-"):
            position = 1
            if position == len(remainder):
                return True
        if position >= len(remainder):
            return False
        first = remainder[position]
        if positive:
            if first not in "123456789":
                return False
        elif first not in "0123456789":
            return False
        position += 1
        if first == "0" and position < len(remainder):
            return remainder[position] in ",}]"
        while (
            position < len(remainder)
            and remainder[position] in "0123456789"
        ):
            position += 1
        return (
            position == len(remainder)
            or remainder[position] in ",}]"
        )

    def value_prefix(path: Tuple[str, ...], index: int) -> bool:
        remainder = text[index:]
        has_expected, expected = _topology_prefix_expected_value(
            event_kind,
            path,
            binding,
            sequence,
            previous_digest,
            candidate_digest,
            replay,
        )
        if has_expected:
            return exact_value_prefix(remainder, expected)
        kind = _topology_prefix_value_kind(event_kind, path)
        if kind == "any":
            return True
        if kind == "object":
            return remainder.startswith("{")
        if kind == "optional_object":
            return (
                remainder.startswith("{")
                or "null".startswith(remainder)
                or remainder.startswith("null")
            )
        if kind == "array":
            return remainder.startswith("[")
        if kind == "digest":
            return quoted_digest_prefix(remainder)
        if kind == "optional_digest":
            return (
                quoted_digest_prefix(remainder)
                or "null".startswith(remainder)
                or remainder.startswith("null")
            )
        if kind == "uuid":
            return quoted_uuid_prefix(remainder)
        if kind == "optional_uuid":
            return (
                quoted_uuid_prefix(remainder)
                or "null".startswith(remainder)
                or remainder.startswith("null")
            )
        if kind == "token":
            return quoted_token_prefix(remainder)
        if kind == "path":
            return quoted_path_prefix(remainder)
        if kind == "positive_int":
            return integer_prefix(remainder, positive=True)
        if kind == "optional_positive_int":
            return (
                integer_prefix(remainder, positive=True)
                or "null".startswith(remainder)
                or remainder.startswith("null")
            )
        if kind == "int":
            return integer_prefix(remainder, positive=False)
        if kind == "bool":
            return any(
                literal.startswith(remainder)
                or remainder.startswith(literal)
                for literal in ("true", "false")
            )
        if kind == "string":
            return decoded_string_prefix(remainder) is not None
        return False

    def completed_value(
        start: int,
        end: int,
        path: Tuple[str, ...],
    ) -> Any:
        encoded = text[start:end].encode("utf-8")
        try:
            value = parse_json_object(
                b'{"value":' + encoded + b"}"
            )["value"]
            if canonical_json(value) != encoded:
                raise _Invalid
        except StrictJsonError as error:
            raise _Invalid from error
        if len(path) == 1 and not _topology_outer_prefix_value_valid(
            event_kind,
            path[-1],
            value,
            previous_digest,
            candidate_digest,
            replay,
        ):
            raise _Invalid
        if (
            len(path) == 2
            and path[0] == "payload"
            and not _topology_payload_prefix_value_valid(
                event_kind,
                path[-1],
                value,
                replay,
            )
        ):
            raise _Invalid
        if not _topology_nested_prefix_value_valid(
            event_kind,
            path,
            value,
        ):
            raise _Invalid
        return value

    def parse_string(index: int) -> int:
        index += 1
        while True:
            if index >= length:
                raise _Incomplete
            character = text[index]
            if character == '"':
                return index + 1
            if ord(character) < 0x20:
                raise _Invalid
            if character != "\\":
                index += 1
                continue
            index += 1
            if index >= length:
                raise _Incomplete
            escape = text[index]
            if escape in '"\\/bfnrt':
                index += 1
                continue
            if escape != "u":
                raise _Invalid
            for _ in range(4):
                index += 1
                if index >= length:
                    raise _Incomplete
                if text[index] not in "0123456789abcdefABCDEF":
                    raise _Invalid
            index += 1

    def parse_literal(index: int, literal: str) -> int:
        remainder = text[index:]
        if remainder.startswith(literal):
            return index + len(literal)
        if literal.startswith(remainder):
            raise _Incomplete
        raise _Invalid

    def parse_number(index: int) -> int:
        if text[index] == "-":
            index += 1
            if index >= length:
                raise _Incomplete
        if text[index] == "0":
            index += 1
            if index < length and text[index] in "0123456789":
                raise _Invalid
        elif text[index] in "123456789":
            index += 1
            while index < length and text[index] in "0123456789":
                index += 1
        else:
            raise _Invalid
        if index < length and text[index] == ".":
            index += 1
            if index >= length:
                raise _Incomplete
            if text[index] not in "0123456789":
                raise _Invalid
            while index < length and text[index] in "0123456789":
                index += 1
        if index < length and text[index] in "eE":
            index += 1
            if index >= length:
                raise _Incomplete
            if text[index] in "+-":
                index += 1
                if index >= length:
                    raise _Incomplete
            if text[index] not in "0123456789":
                raise _Invalid
            while index < length and text[index] in "0123456789":
                index += 1
        return index

    def parse_value(index: int, path: Tuple[str, ...]) -> int:
        if len(path) > 128:
            raise _Invalid
        if index >= length:
            raise _Incomplete
        if not value_prefix(path, index):
            raise _Invalid
        character = text[index]
        if character == '"':
            return parse_string(index)
        if character == "{":
            return parse_object(index, path)
        if character == "[":
            return parse_array(index, path)
        if character == "t":
            return parse_literal(index, "true")
        if character == "f":
            return parse_literal(index, "false")
        if character == "n":
            return parse_literal(index, "null")
        if character == "-" or character in "0123456789":
            return parse_number(index)
        raise _Invalid

    def parse_object(index: int, path: Tuple[str, ...]) -> int:
        variants = _topology_prefix_key_variants(event_kind, path)
        key_position = 0
        completed_fields: Dict[str, Any] = {}
        index += 1
        if index >= length:
            raise _Incomplete
        if text[index] == "}":
            if variants is not None and not any(
                len(variant) == 0 for variant in variants
            ):
                raise _Invalid
            return index + 1
        while True:
            if text[index] != '"':
                raise _Invalid
            key: Optional[str] = None
            if variants is None:
                key_start = index
                index = parse_string(index)
                encoded_key = text[key_start:index].encode("utf-8")
                try:
                    key = next(
                        iter(
                            parse_json_object(
                                b"{" + encoded_key + b":null}"
                            )
                        )
                    )
                    if canonical_json(key) != encoded_key:
                        raise _Invalid
                except StrictJsonError as error:
                    raise _Invalid from error
            else:
                remainder = text[index:]
                matches = tuple(
                    variant
                    for variant in variants
                    if key_position < len(variant)
                    and remainder.startswith(
                        '"' + variant[key_position] + '"'
                    )
                )
                if not matches:
                    if any(
                        key_position < len(variant)
                        and (
                            '"' + variant[key_position] + '"'
                        ).startswith(remainder)
                        for variant in variants
                    ):
                        raise _Incomplete
                    raise _Invalid
                key = matches[0][key_position]
                literal = '"' + matches[0][key_position] + '"'
                index += len(literal)
                variants = matches
                key_position += 1
            if index >= length:
                raise _Incomplete
            if text[index] != ":":
                raise _Invalid
            value_start = index + 1
            child_path = path + (key,)
            index = parse_value(value_start, child_path)
            value = completed_value(value_start, index, child_path)
            completed_fields[key] = value
            if (
                path == ("payload",)
                and event_kind == "mutation_intent"
                and replay is not None
                and "lane_generation" in completed_fields
                and "lane_id" in completed_fields
                and any(
                    existing.lane_generation
                    == completed_fields["lane_generation"]
                    and existing.lane_id == completed_fields["lane_id"]
                    for existing in replay.mutations.values()
                )
            ):
                raise _Invalid
            if (
                path == ()
                and key == "payload"
                and candidate_digest is not None
            ):
                unsigned = dict(completed_fields)
                unsigned["previous_record_digest"] = previous_digest
                unsigned["schema"] = (
                    "ask_herdr.topology_event.internal.v1"
                )
                if _digest_json(unsigned) != "sha256:" + candidate_digest:
                    raise _Invalid
            if path == () and key == "record_digest":
                unsigned = dict(completed_fields)
                unsigned.pop("record_digest")
                unsigned["schema"] = (
                    "ask_herdr.topology_event.internal.v1"
                )
                if value != _digest_json(unsigned):
                    raise _Invalid
            if index >= length:
                raise _Incomplete
            if text[index] == "}":
                if variants is not None and not any(
                    len(variant) == key_position
                    for variant in variants
                ):
                    raise _Invalid
                return index + 1
            if text[index] != ",":
                raise _Invalid
            if variants is not None and not any(
                len(variant) > key_position for variant in variants
            ):
                raise _Invalid
            index += 1
            if index >= length:
                raise _Incomplete

    def parse_array(index: int, path: Tuple[str, ...]) -> int:
        completed_items: List[Any] = []
        index += 1
        if index >= length:
            raise _Incomplete
        if text[index] == "]":
            return index + 1
        while True:
            item_start = index
            item_path = path + ("[]",)
            index = parse_value(index, item_path)
            item = completed_value(item_start, index, item_path)
            if path and path[-1].endswith("_digests"):
                if completed_items and item <= completed_items[-1]:
                    raise _Invalid
                completed_items.append(item)
            if index >= length:
                raise _Incomplete
            if text[index] == "]":
                return index + 1
            if text[index] != ",":
                raise _Invalid
            index += 1
            if index >= length:
                raise _Incomplete

    try:
        return parse_value(0, ()) == length
    except _Incomplete:
        return True
    except _Invalid:
        return False


def _topology_payload_key_variants(
    event_kind: str,
) -> Tuple[Tuple[str, ...], ...]:
    record_types = {
        "command_intent": TopologyCommandIntent,
        "command_receipt": TopologyCommandReceipt,
        "mutation_intent": TopologyMutationIntent,
        "mutation_settlement": TopologyMutationSettlement,
    }
    record_type = record_types[event_kind]
    complete = tuple(sorted(field.name for field in fields(record_type)))
    if event_kind != "mutation_intent":
        return (complete,)
    without_incarnation = tuple(
        name
        for name in complete
        if name != "topology_store_incarnation_digest"
    )
    return (without_incarnation, complete)


def _topology_prefix_key_variants(
    event_kind: str,
    path: Tuple[str, ...],
) -> Optional[Tuple[Tuple[str, ...], ...]]:
    if path == ():
        return (
            (
                "binding_digest",
                "event_kind",
                "event_sequence",
                "payload",
                "previous_record_digest",
                "record_digest",
                "schema",
            ),
        )
    if path == ("payload",):
        return _topology_payload_key_variants(event_kind)
    nested = {
        ("payload", "project_topology_proof"): (
            "lanes",
            "namespace",
            "project_id",
            "project_root",
            "schema",
            "session_binding",
            "side_effects",
            "topology_epoch_id",
        ),
        ("payload", "project_topology_proof", "session_binding"): (
            "default",
            "generation_id",
            "name",
            "session_dir",
            "socket_path",
        ),
        ("payload", "project_topology_proof", "lanes", "[]"): (
            "consultant_key",
            "lane_id",
            "project_id",
            "project_root",
            "topology_nonce",
            "workspace",
        ),
        (
            "payload",
            "project_topology_proof",
            "lanes",
            "[]",
            "workspace",
        ): (
            "creation_receipt_digest",
            "cwd",
            "label",
            "pane_id",
            "tab_id",
            "workspace_id",
        ),
        (
            "payload",
            "project_topology_proof",
            "side_effects",
            "[]",
        ): (
            "creation_receipt_digest",
            "cwd",
            "label",
            "pane_id",
            "project_id",
            "project_root",
            "tab_id",
            "workspace_id",
        ),
    }
    keys = nested.get(path)
    return None if keys is None else (keys,)


def _topology_prefix_value_kind(
    event_kind: str,
    path: Tuple[str, ...],
) -> str:
    if path == ():
        return "object"
    key = path[-1]
    if len(path) == 1:
        return {
            "binding_digest": "digest",
            "event_kind": "token",
            "event_sequence": "positive_int",
            "payload": "object",
            "previous_record_digest": "optional_digest",
            "record_digest": "digest",
            "schema": "token",
        }.get(key, "any")
    if len(path) == 2 and path[0] == "payload":
        if key == "project_topology_proof":
            return "optional_object"
        if key.endswith("_digests"):
            return "array"
        if key == "lane_generation":
            return "positive_int"
        if key == "step_sequence":
            return "optional_positive_int"
        if key == "exit_code":
            return "int"
        if key == "prior_step_id":
            return "optional_uuid"
        if key in {"mutation_id", "operation_id", "lane_id", "step_id"}:
            return "uuid"
        if key.endswith("_digest"):
            optional = key in {
                "prior_topology_digest",
                "topology_store_incarnation_digest",
            } or (
                event_kind == "command_intent"
                and key == "expected_postcondition_digest"
            )
            return "optional_digest" if optional else "digest"
        if key in {"lane_workspace_cwd", "session_dir", "socket_path"}:
            return "path"
        return "token"
    if key == "[]" and len(path) >= 2:
        if path[-2] in {
            "command_receipt_digests",
            "resource_binding_digests",
        }:
            return "digest"
        if path[-2] in {"lanes", "side_effects"}:
            return "object"
    if path[:2] == ("payload", "project_topology_proof"):
        if key in {"session_binding", "workspace"}:
            return "object"
        if key in {"lanes", "side_effects"}:
            return "array"
        if key == "default":
            return "bool"
        if key in {
            "cwd",
            "project_root",
            "session_dir",
            "socket_path",
        }:
            return "path"
        if key == "creation_receipt_digest":
            return "digest"
        return "string"
    if key in {"session_binding", "workspace"}:
        return "object"
    if key in {"lanes", "side_effects"}:
        return "array"
    if key == "schema" and path[:-1] == (
        "payload",
        "project_topology_proof",
    ):
        return "token"
    return "any"


def _topology_prefix_expected_value(
    event_kind: str,
    path: Tuple[str, ...],
    binding: ValidatedTopologyStoreBinding,
    sequence: int,
    previous_digest: Optional[str],
    candidate_digest: Optional[str],
    replay: Optional[_Replay],
) -> Tuple[bool, Any]:
    if len(path) == 1:
        expected = {
            "binding_digest": _binding_digest(binding),
            "event_kind": event_kind,
            "event_sequence": sequence,
            "schema": "ask_herdr.topology_event.internal.v1",
        }
        if replay is not None:
            expected["previous_record_digest"] = previous_digest
        if candidate_digest is not None:
            expected["record_digest"] = "sha256:" + candidate_digest
        if path[-1] in expected:
            return True, expected[path[-1]]
    if path == (
        "payload",
        "project_topology_proof",
        "schema",
    ):
        return True, "ask_herdr.project_topology_proof.v1"
    if replay is None or len(path) != 2 or path[0] != "payload":
        return False, None
    key = path[-1]
    open_mutations = _open_mutation_ids(replay)
    if event_kind == "mutation_intent":
        if key == "prior_topology_digest":
            return True, _latest_project_topology_digest(replay)
        return False, None
    if len(open_mutations) != 1:
        return False, None
    mutation_id = open_mutations[0]
    mutation = replay.mutations[mutation_id]
    if event_kind == "command_intent":
        commands = _commands_for_mutation(replay, mutation_id)
        expected = {
            "mutation_id": mutation_id,
            "expected_postcondition_digest": (
                mutation.expected_postcondition_digest
            ),
            "step_sequence": len(commands) + 1,
            "prior_step_id": commands[-1].step_id if commands else None,
        }
        if key in expected:
            return True, expected[key]
    if event_kind == "command_receipt":
        pending = tuple(
            key_value
            for key_value in replay.commands
            if key_value[0] == mutation_id
            and key_value not in replay.receipts
        )
        if len(pending) == 1:
            command = replay.commands[pending[0]]
            expected = {
                "mutation_id": command.mutation_id,
                "step_id": command.step_id,
                "command_kind": command.command_kind,
                "command_argv_digest": command.command_argv_digest,
                "observed_postcondition_digest": (
                    command.expected_postcondition_digest
                ),
            }
            if key in expected:
                return True, expected[key]
    if event_kind == "mutation_settlement":
        receipts = tuple(
            item
            for key_value, item in replay.receipts.items()
            if key_value[0] == mutation_id
        )
        expected = {
            "mutation_id": mutation_id,
            "command_receipt_digests": sorted(
                item.command_receipt_digest for item in receipts
            ),
        }
        if receipts:
            for name in (
                "session_dir",
                "socket_path",
                "session_generation_id",
            ):
                values = {getattr(item, name) for item in receipts}
                if len(values) == 1:
                    expected[name] = next(iter(values))
        if key in expected:
            return True, expected[key]
    return False, None


def _topology_nested_prefix_value_valid(
    event_kind: str,
    path: Tuple[str, ...],
    value: Any,
) -> bool:
    del event_kind
    if path and path[-1] == "[]" and len(path) >= 2 and path[-2] in {
        "command_receipt_digests",
        "resource_binding_digests",
    }:
        try:
            _require_digest(value, "topology_store.digest_invalid")
        except ValueError:
            return False
    return True


def _topology_payload_prefix_value_valid(
    event_kind: str,
    key: Optional[str],
    value: Any,
    replay: Optional[_Replay],
) -> bool:
    if key is None:
        return False
    try:
        if key == "project_topology_proof":
            if value is not None:
                if type(value) is not dict:
                    return False
                project_topology_from_payload(value)
        elif key.endswith("_digests"):
            if type(value) is not list:
                return False
            _require_digest_tuple(
                tuple(value),
                "topology_store.digest_invalid",
            )
        elif key == "lane_generation":
            if not _is_int(value) or value < 1:
                return False
        elif key == "step_sequence":
            if value is not None and (
                not _is_int(value) or value < 1
            ):
                return False
        elif key == "exit_code":
            if not _is_int(value):
                return False
        elif key == "disposition":
            CommandEffectDisposition(value)
        elif key == "prior_step_id":
            if value is not None:
                _require_uuid(value, "topology_store.uuid_invalid")
        elif key in {
            "mutation_id",
            "operation_id",
            "lane_id",
            "step_id",
        }:
            _require_uuid(value, "topology_store.uuid_invalid")
        elif key.endswith("_digest"):
            optional = key in {
                "prior_topology_digest",
                "topology_store_incarnation_digest",
            } or (
                event_kind == "command_intent"
                and key == "expected_postcondition_digest"
            )
            if value is not None or not optional:
                _require_digest(value, "topology_store.digest_invalid")
        elif key in {"lane_workspace_cwd", "session_dir", "socket_path"}:
            _require_absolute_canonical(
                value,
                "topology_store.path_invalid",
            )
        else:
            _require_token(value, "topology_store.token_invalid")
    except (TypeError, ValueError):
        return False
    if replay is None:
        return True
    open_mutations = _open_mutation_ids(replay)
    if event_kind == "mutation_intent":
        if open_mutations:
            return False
        if key == "mutation_id" and value in replay.mutations:
            return False
        if key == "operation_id" and any(
            item.operation_id == value for item in replay.mutations.values()
        ):
            return False
        if key == "topology_nonce" and any(
            item.topology_nonce == value for item in replay.mutations.values()
        ):
            return False
        if key == "prior_topology_digest":
            return value == _latest_project_topology_digest(replay)
        return True
    if len(open_mutations) != 1:
        return False
    mutation_id = open_mutations[0]
    mutation = replay.mutations[mutation_id]
    if event_kind == "command_intent":
        commands = _commands_for_mutation(replay, mutation_id)
        expected_prior = commands[-1].step_id if commands else None
        expected_sequence = len(commands) + 1
        expected = {
            "mutation_id": mutation_id,
            "expected_postcondition_digest": (
                mutation.expected_postcondition_digest
            ),
            "step_sequence": expected_sequence,
            "prior_step_id": expected_prior,
        }
        if key in expected:
            return value == expected[key]
        if key == "step_id":
            return (mutation_id, value) not in replay.commands
        return True
    if event_kind == "command_receipt":
        pending = tuple(
            key_value
            for key_value in replay.commands
            if key_value[0] == mutation_id
            and key_value not in replay.receipts
        )
        if len(pending) != 1:
            return False
        command_key = pending[0]
        command = replay.commands[command_key]
        expected = {
            "mutation_id": command.mutation_id,
            "step_id": command.step_id,
            "command_kind": command.command_kind,
            "command_argv_digest": command.command_argv_digest,
            "observed_postcondition_digest": (
                command.expected_postcondition_digest
            ),
        }
        if key in expected:
            return value == expected[key]
        if key == "request_id":
            return value not in replay.request_ids
        if key == "command_receipt_digest":
            return value not in replay.receipt_digests
        return True
    if event_kind == "mutation_settlement":
        receipts = tuple(
            item
            for key_value, item in replay.receipts.items()
            if key_value[0] == mutation_id
        )
        if not receipts:
            return False
        if key == "mutation_id":
            return value == mutation_id
        if key == "command_receipt_digests":
            return value == sorted(
                item.command_receipt_digest for item in receipts
            )
        if key in {"session_dir", "socket_path", "session_generation_id"}:
            return all(getattr(item, key) == value for item in receipts)
        return True
    return False


def _topology_outer_prefix_value_valid(
    event_kind: str,
    key: Optional[str],
    value: Any,
    previous_digest: Optional[str],
    candidate_digest: Optional[str],
    replay: Optional[_Replay],
) -> bool:
    try:
        if key == "binding_digest":
            _require_digest(value, "topology_store.digest_invalid")
        elif key == "record_digest":
            _require_digest(value, "topology_store.digest_invalid")
            if (
                candidate_digest is not None
                and value != "sha256:" + candidate_digest
            ):
                return False
        elif key == "event_kind":
            return value == event_kind
        elif key == "event_sequence":
            return _is_int(value) and value >= 1
        elif key == "previous_record_digest":
            if value is not None:
                _require_digest(value, "topology_store.digest_invalid")
            if replay is not None and value != previous_digest:
                return False
        elif key == "schema":
            return value == "ask_herdr.topology_event.internal.v1"
        elif key == "payload":
            if type(value) is not dict:
                return False
            validators = {
                "command_intent": _command_from_payload,
                "command_receipt": _receipt_from_payload,
                "mutation_intent": _mutation_from_payload,
                "mutation_settlement": _settlement_from_payload,
            }
            validators[event_kind](value)
            if replay is not None:
                candidate_replay = _clone_replay(replay)
                _apply_event(candidate_replay, event_kind, value)
        else:
            return False
    except (KeyError, TypeError, ValueError, _IntegrityError):
        return False
    return True


def _topology_event_prefix_possible(
    replay: _Replay,
    event_kind: str,
) -> bool:
    open_mutations = _open_mutation_ids(replay)
    if event_kind == "mutation_intent":
        return not open_mutations
    if len(open_mutations) != 1:
        return False
    mutation_id = open_mutations[0]
    commands = _commands_for_mutation(replay, mutation_id)
    if event_kind == "command_intent":
        if not commands:
            return True
        prior_key = (mutation_id, commands[-1].step_id)
        prior_receipt = replay.receipts.get(prior_key)
        return (
            prior_receipt is not None
            and prior_receipt.disposition
            is CommandEffectDisposition.CONFIRMED
        )
    pending = tuple(
        key
        for key in replay.commands
        if key[0] == mutation_id and key not in replay.receipts
    )
    if event_kind == "command_receipt":
        return len(pending) == 1
    if event_kind == "mutation_settlement":
        receipts = tuple(
            item
            for key, item in replay.receipts.items()
            if key[0] == mutation_id
        )
        return (
            bool(commands)
            and not pending
            and bool(receipts)
            and all(
                item.disposition is CommandEffectDisposition.CONFIRMED
                for item in receipts
            )
            and commands[-1].expected_postcondition_digest
            == replay.mutations[mutation_id].expected_postcondition_digest
        )
    return False


def _possible_head_event_record_prefix(
    payload: bytes,
    binding: ValidatedTopologyStoreBinding,
    sequence: int,
    *,
    previous_digest: Optional[str] = None,
    candidate_digest: Optional[str] = None,
    replay: Optional[_Replay] = None,
) -> bool:
    """Recognize a torn prefix of one binding- and sequence-bound record."""

    if len(payload) >= MAX_RECORD_BYTES or b"\n" in payload:
        return False
    for event_kind in (
        "command_intent",
        "command_receipt",
        "mutation_intent",
        "mutation_settlement",
    ):
        if replay is not None and not _topology_event_prefix_possible(
            replay,
            event_kind,
        ):
            continue
        fixed = (
            b'{"binding_digest":'
            + canonical_json(_binding_digest(binding))
            + b',"event_kind":'
            + canonical_json(event_kind)
            + b',"event_sequence":'
            + str(sequence).encode("ascii")
            + b',"payload":'
        )
        if fixed.startswith(payload):
            return True
        if payload.startswith(fixed):
            remainder = payload[len(fixed) :]
            return (
                not remainder
                or (
                    remainder.startswith(b"{")
                    and _possible_json_document_prefix(
                        payload,
                        event_kind,
                        binding,
                        sequence,
                        previous_digest,
                        candidate_digest,
                        replay,
                    )
                )
            )
    return False


def _recover_candidate(
    handles: _Handles,
    name: str,
    existing_record: Optional[Dict[str, Any]],
    existing_prefix: Optional[bytes],
    expected_record: Dict[str, Any],
    failpoint: Optional[Callable[[str], None]],
) -> None:
    expected_bytes = canonical_json(expected_record) + b"\n"
    expected_name = _candidate_name(expected_record)
    if name != expected_name or (
        existing_record is not None and existing_record != expected_record
    ):
        raise _IntegrityError("topology_store.candidate_conflict")
    capsule = _open_directory(handles.transactions, name)
    try:
        entries = set(os.listdir(capsule))
        if not entries:
            _write_new(capsule, RECORD_NAME, expected_bytes)
            _invoke_failpoint(failpoint, "after_event_capsule_file_fullsync")
            _sync_directory(capsule)
        elif entries != {RECORD_NAME}:
            raise _IntegrityError("topology_store.candidate_changed")
        elif existing_prefix is not None:
            if (
                len(existing_prefix) >= len(expected_bytes)
                or not expected_bytes.startswith(existing_prefix)
            ):
                raise _IntegrityError("topology_store.candidate_changed")
            os.unlink(RECORD_NAME, dir_fd=capsule)
            _sync_directory(capsule)
            _write_new(capsule, RECORD_NAME, expected_bytes)
            _invoke_failpoint(failpoint, "after_event_capsule_file_fullsync")
            _sync_directory(capsule)
        reread, reread_bytes = _read_json(capsule, RECORD_NAME)
        if reread != expected_record or reread_bytes != expected_bytes:
            raise _IntegrityError("topology_store.candidate_changed")
        if os.fstat(capsule).st_dev != os.fstat(handles.transactions).st_dev:
            raise _IntegrityError("topology_store.filesystem_changed")
        _fullsync_bound_file(capsule, RECORD_NAME)
        _sync_directory(capsule)
        _invoke_failpoint(failpoint, "before_event_capsule_promote")
        slot_name = _event_name(expected_record["event_sequence"])
        disposition = commit_exclusive(
            handles.transactions,
            name,
            slot_name,
        )
        if disposition is CommitDisposition.OCCUPIED:
            raise _IntegrityError("topology_store.event_slot_occupied")
        _invoke_failpoint(failpoint, "after_event_capsule_promote")
        _restore_event_barriers(handles.transactions, slot_name, capsule)
    finally:
        os.close(capsule)


def _read_records(
    handles: _Handles,
    binding: ValidatedTopologyStoreBinding,
    pending_resolver: Optional[
        Callable[[_Replay], Tuple[str, Dict[str, Any]]]
    ] = None,
    failpoint: Optional[Callable[[str], None]] = None,
) -> _Replay:
    entries = os.listdir(handles.transactions)
    indexed: List[Tuple[int, str]] = []
    candidates: List[Tuple[int, str, str]] = []
    for name in entries:
        match = EVENT_NAME.fullmatch(name)
        if match is not None:
            indexed.append((int(match.group(1)), name))
            continue
        candidate_match = CANDIDATE_NAME.fullmatch(name)
        if candidate_match is not None:
            candidates.append(
                (
                    int(candidate_match.group(1)),
                    candidate_match.group(2),
                    name,
                )
            )
            continue
        raise _IntegrityError("topology_store.unknown_transaction_entry")
    if len(candidates) > 1:
        raise _IntegrityError("topology_store.candidate_conflict")
    indexed.sort()
    replay = _empty_replay()
    previous_digest: Optional[str] = None
    for expected, (sequence, name) in enumerate(indexed, start=1):
        if sequence != expected:
            raise _IntegrityError("topology_store.sequence_gap")
        capsule = _open_directory(handles.transactions, name)
        try:
            if set(os.listdir(capsule)) != {RECORD_NAME}:
                raise _IntegrityError("topology_store.capsule_invalid")
            record, _ = _read_json(capsule, RECORD_NAME)
            record = _validate_record(
                record,
                binding,
                expected,
                previous_digest,
            )
            _restore_event_barriers(handles.transactions, name, capsule)
        finally:
            os.close(capsule)
        _apply_event(replay, record["event_kind"], record["payload"])
        replay.records.append(record)
        previous_digest = record["record_digest"]
    if not candidates:
        _validate_replay_incarnation(handles, binding, replay)
        return replay

    candidate_sequence, candidate_digest, candidate_name = candidates[0]
    expected_sequence = len(replay.records) + 1
    if candidate_sequence != expected_sequence:
        raise _IntegrityError("topology_store.candidate_sequence_invalid")
    candidate_capsule = _open_directory(handles.transactions, candidate_name)
    try:
        candidate_entries = set(os.listdir(candidate_capsule))
        if not candidate_entries:
            candidate_record = None
            candidate_prefix = None
        elif candidate_entries == {RECORD_NAME}:
            candidate_bytes = _read_file(candidate_capsule, RECORD_NAME)
            try:
                candidate_parsed = parse_json_object(
                    candidate_bytes[:-1]
                    if candidate_bytes.endswith(b"\n")
                    else candidate_bytes
                )
            except StrictJsonError as error:
                if not _possible_event_record_prefix(candidate_bytes):
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    ) from error
                candidate_record = None
                candidate_prefix = candidate_bytes
            else:
                if candidate_bytes == canonical_json(candidate_parsed) + b"\n":
                    candidate_record = _validate_record(
                        candidate_parsed,
                        binding,
                        expected_sequence,
                        previous_digest,
                    )
                    if (
                        candidate_record["record_digest"]
                        != "sha256:" + candidate_digest
                    ):
                        raise _IntegrityError("topology_store.candidate_changed")
                    candidate_replay = _clone_replay(replay)
                    _apply_event(
                        candidate_replay,
                        candidate_record["event_kind"],
                        candidate_record["payload"],
                    )
                    candidate_prefix = None
                elif _possible_event_record_prefix(candidate_bytes):
                    candidate_record = None
                    candidate_prefix = candidate_bytes
                else:
                    raise _IntegrityError("topology_store.candidate_changed")
        else:
            raise _IntegrityError("topology_store.candidate_changed")
    finally:
        os.close(candidate_capsule)
    if pending_resolver is None:
        raise _PendingCandidate(
            "topology_store.pending_candidate",
            "sha256:" + hashlib.sha256(
                canonical_json(
                    {
                        "schema": (
                            "ask_herdr.topology_pending_candidate.internal.v1"
                        ),
                        "candidate_name": candidate_name,
                        "candidate_sequence": candidate_sequence,
                        "candidate_digest": candidate_digest,
                    }
                )
            ).hexdigest(),
        )
    event_kind, payload = pending_resolver(replay)
    expected_record = _event_record(
        binding,
        expected_sequence,
        previous_digest,
        event_kind,
        payload,
    )
    expected_replay = _clone_replay(replay)
    _apply_event(expected_replay, event_kind, payload)
    _recover_candidate(
        handles,
        candidate_name,
        candidate_record,
        candidate_prefix,
        expected_record,
        failpoint,
    )
    recovered = _read_records(handles, binding)
    recovered.recovered_candidate = True
    return recovered


def _open_head_capsule(parent: int, name: str, code: str) -> int:
    """Translate a managed capsule path/type conflict to head integrity."""

    try:
        return _open_directory(parent, name)
    except (OSError, _IntegrityError) as error:
        raise _IntegrityError(code) from error


def _validate_head_record_sources(
    handles: _HeadHandles,
    sources: Tuple[Tuple[str, Tuple[int, ...], bytes], ...],
    empty_candidate_name: Optional[str] = None,
) -> None:
    """Rebind every immutable record source used by the head projection."""

    for name, expected_identity, expected_bytes in sources:
        candidate = CANDIDATE_NAME.fullmatch(name) is not None
        capsule_code = (
            "topology_store.candidate_changed"
            if candidate
            else "topology_store.capsule_changed"
        )
        record_code = (
            "topology_store.candidate_changed"
            if candidate
            else "topology_store.record_changed"
        )
        capsule = _open_head_capsule(
            handles.transactions,
            name,
            capsule_code,
        )
        with _head_descriptor(capsule):
            if set(os.listdir(capsule)) != {RECORD_NAME}:
                raise _IntegrityError(record_code)
            try:
                current_identity = _file_identity(
                    os.stat(
                        RECORD_NAME,
                        dir_fd=capsule,
                        follow_symlinks=False,
                    )
                )
            except OSError as error:
                raise _IntegrityError(record_code) from error
            if (
                current_identity != expected_identity
                or _read_head_file(capsule, RECORD_NAME)
                != expected_bytes
            ):
                raise _IntegrityError(record_code)
            if not _directory_binding(
                handles.transactions,
                name,
                capsule,
            ):
                raise _IntegrityError(capsule_code)

    if empty_candidate_name is None:
        return
    capsule = _open_head_capsule(
        handles.transactions,
        empty_candidate_name,
        "topology_store.candidate_changed",
    )
    with _head_descriptor(capsule):
        if os.listdir(capsule) or not _directory_binding(
            handles.transactions,
            empty_candidate_name,
            capsule,
        ):
            raise _IntegrityError("topology_store.candidate_changed")


def _validate_head_terminal_state(
    handles: _HeadHandles,
    binding: ValidatedTopologyStoreBinding,
    transaction_identities: Tuple[Tuple[str, Tuple[int, ...]], ...],
    record_sources: Tuple[Tuple[str, Tuple[int, ...], bytes], ...],
    empty_candidate_name: Optional[str] = None,
) -> None:
    """Perform the final envelope, source, and namespace read barrier."""

    _validate_head_envelope(handles, binding)
    _validate_head_record_sources(
        handles,
        record_sources,
        empty_candidate_name,
    )
    _validate_head_transaction_namespace(
        handles,
        transaction_identities,
    )


def _read_head_records(
    handles: _Handles,
    binding: ValidatedTopologyStoreBinding,
) -> _HeadReplay:
    """Replay promoted records without repairing candidates or barriers."""

    names = tuple(sorted(os.listdir(handles.transactions)))
    identities = {
        name: _identity(
            os.stat(
                name,
                dir_fd=handles.transactions,
                follow_symlinks=False,
            )
        )
        for name in names
    }
    indexed: List[Tuple[int, str]] = []
    candidates: List[Tuple[int, str, str]] = []
    for name in names:
        match = EVENT_NAME.fullmatch(name)
        if match is not None:
            indexed.append((int(match.group(1)), name))
            continue
        candidate_match = CANDIDATE_NAME.fullmatch(name)
        if candidate_match is not None:
            candidates.append(
                (
                    int(candidate_match.group(1)),
                    candidate_match.group(2),
                    name,
                )
            )
            continue
        raise _IntegrityError("topology_store.unknown_transaction_entry")
    if len(candidates) > 1:
        raise _IntegrityError("topology_store.candidate_conflict")

    replay = _empty_replay()
    record_sources: Dict[str, Tuple[Tuple[int, ...], bytes]] = {}
    previous_digest: Optional[str] = None
    for expected, (sequence, name) in enumerate(sorted(indexed), start=1):
        if sequence != expected:
            raise _IntegrityError("topology_store.sequence_gap")
        capsule = _open_head_capsule(
            handles.transactions,
            name,
            "topology_store.capsule_changed",
        )
        with _head_descriptor(capsule):
            if set(os.listdir(capsule)) != {RECORD_NAME}:
                raise _IntegrityError("topology_store.capsule_invalid")
            try:
                record_identity = _file_identity(
                    os.stat(
                        RECORD_NAME,
                        dir_fd=capsule,
                        follow_symlinks=False,
                    )
                )
            except OSError as error:
                raise _IntegrityError(
                    "topology_store.record_changed"
                ) from error
            record, record_bytes = _read_head_json(capsule, RECORD_NAME)
            try:
                if _file_identity(
                    os.stat(
                        RECORD_NAME,
                        dir_fd=capsule,
                        follow_symlinks=False,
                    )
                ) != record_identity:
                    raise _IntegrityError("topology_store.record_changed")
            except OSError as error:
                raise _IntegrityError(
                    "topology_store.record_changed"
                ) from error
            record = _validate_record(
                record,
                binding,
                expected,
                previous_digest,
            )
            if not _directory_binding(handles.transactions, name, capsule):
                raise _IntegrityError("topology_store.capsule_changed")
        record_sources[name] = (record_identity, record_bytes)
        _apply_event(replay, record["event_kind"], record["payload"])
        replay.records.append(record)
        previous_digest = record["record_digest"]

    _validate_replay_incarnation(handles, binding, replay)
    candidate_source: Optional[Tuple[Tuple[int, ...], bytes]] = None
    candidate_was_empty = False
    if candidates:
        candidate_sequence, candidate_digest, candidate_name = candidates[0]
        if candidate_sequence != len(replay.records) + 1:
            raise _IntegrityError("topology_store.candidate_sequence_invalid")
        candidate = _open_head_capsule(
            handles.transactions,
            candidate_name,
            "topology_store.candidate_changed",
        )
        with _head_descriptor(candidate):
            candidate_entries = set(os.listdir(candidate))
            if not candidate_entries:
                candidate_was_empty = True
            elif candidate_entries == {RECORD_NAME}:
                try:
                    candidate_record_identity = _file_identity(
                        os.stat(
                            RECORD_NAME,
                            dir_fd=candidate,
                            follow_symlinks=False,
                        )
                    )
                except OSError as error:
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    ) from error
                candidate_bytes = _read_head_file(candidate, RECORD_NAME)
                try:
                    if (
                        _file_identity(
                            os.stat(
                                RECORD_NAME,
                                dir_fd=candidate,
                                follow_symlinks=False,
                            )
                        )
                        != candidate_record_identity
                        or set(os.listdir(candidate)) != {RECORD_NAME}
                    ):
                        raise _IntegrityError(
                            "topology_store.candidate_changed"
                        )
                except OSError as error:
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    ) from error
                candidate_source = (
                    candidate_record_identity,
                    candidate_bytes,
                )
                try:
                    candidate_parsed = parse_json_object(
                        candidate_bytes[:-1]
                        if candidate_bytes.endswith(b"\n")
                        else candidate_bytes
                    )
                except StrictJsonError as error:
                    if not _possible_head_event_record_prefix(
                        candidate_bytes,
                        binding,
                        candidate_sequence,
                        previous_digest=previous_digest,
                        candidate_digest=candidate_digest,
                        replay=replay,
                    ):
                        raise _IntegrityError(
                            "topology_store.candidate_changed"
                        ) from error
                else:
                    canonical_candidate = canonical_json(candidate_parsed)
                    if candidate_bytes in (
                        canonical_candidate,
                        canonical_candidate + b"\n",
                    ):
                        candidate_record = _validate_record(
                            candidate_parsed,
                            binding,
                            candidate_sequence,
                            previous_digest,
                        )
                        if (
                            candidate_record["record_digest"]
                            != "sha256:" + candidate_digest
                        ):
                            raise _IntegrityError(
                                "topology_store.candidate_changed"
                            )
                        candidate_replay = _clone_replay(replay)
                        _apply_event(
                            candidate_replay,
                            candidate_record["event_kind"],
                            candidate_record["payload"],
                        )
                    elif not _possible_head_event_record_prefix(
                        candidate_bytes,
                        binding,
                        candidate_sequence,
                        previous_digest=previous_digest,
                        candidate_digest=candidate_digest,
                        replay=replay,
                    ):
                        raise _IntegrityError(
                            "topology_store.candidate_changed"
                        )
            else:
                raise _IntegrityError("topology_store.candidate_changed")
            if not _directory_binding(
                handles.transactions,
                candidate_name,
                candidate,
            ):
                raise _IntegrityError("topology_store.candidate_changed")

    for name, (record_identity, record_bytes) in record_sources.items():
        capsule = _open_head_capsule(
            handles.transactions,
            name,
            "topology_store.capsule_changed",
        )
        with _head_descriptor(capsule):
            if (
                _identity(os.fstat(capsule)) != identities[name]
                or set(os.listdir(capsule)) != {RECORD_NAME}
            ):
                raise _IntegrityError("topology_store.capsule_changed")
            try:
                current_identity = _file_identity(
                    os.stat(
                        RECORD_NAME,
                        dir_fd=capsule,
                        follow_symlinks=False,
                    )
                )
            except OSError as error:
                raise _IntegrityError(
                    "topology_store.record_changed"
                ) from error
            if (
                current_identity != record_identity
                or _read_head_file(capsule, RECORD_NAME) != record_bytes
            ):
                raise _IntegrityError("topology_store.record_changed")
            if not _directory_binding(handles.transactions, name, capsule):
                raise _IntegrityError("topology_store.capsule_changed")

    if candidates:
        candidate = _open_head_capsule(
            handles.transactions,
            candidate_name,
            "topology_store.candidate_changed",
        )
        with _head_descriptor(candidate):
            if (
                _identity(os.fstat(candidate)) != identities[candidate_name]
                or not _directory_binding(
                    handles.transactions,
                    candidate_name,
                    candidate,
                )
            ):
                raise _IntegrityError("topology_store.candidate_changed")
            if candidate_was_empty:
                if os.listdir(candidate):
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    )
            else:
                if candidate_source is None:
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    )
                candidate_identity, candidate_bytes = candidate_source
                try:
                    current_identity = _file_identity(
                        os.stat(
                            RECORD_NAME,
                            dir_fd=candidate,
                            follow_symlinks=False,
                        )
                    )
                except OSError as error:
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    ) from error
                if (
                    set(os.listdir(candidate)) != {RECORD_NAME}
                    or current_identity != candidate_identity
                    or _read_head_file(candidate, RECORD_NAME)
                    != candidate_bytes
                ):
                    raise _IntegrityError(
                        "topology_store.candidate_changed"
                    )

    if tuple(sorted(os.listdir(handles.transactions))) != names:
        raise _IntegrityError("topology_store.transaction_namespace_changed")
    if any(
        _identity(
            os.stat(
                name,
                dir_fd=handles.transactions,
                follow_symlinks=False,
            )
        )
        != expected_identity
        for name, expected_identity in identities.items()
    ):
        raise _IntegrityError("topology_store.transaction_namespace_changed")
    if (
        not _directory_binding(handles.root, STORE_NAME, handles.store)
        or not _directory_binding(
            handles.store,
            TRANSACTIONS_NAME,
            handles.transactions,
        )
    ):
        raise _IntegrityError("topology_store.incarnation_changed")
    if candidates:
        pending_sources = tuple(
            (name, identity, payload)
            for name, (identity, payload) in sorted(record_sources.items())
        )
        if candidate_source is not None:
            pending_sources += (
                (
                    candidate_name,
                    candidate_source[0],
                    candidate_source[1],
                ),
            )
        promoted_projection = _topology_status_projection(replay)
        raise _PendingCandidate(
            "topology_store.pending_candidate",
            "sha256:" + hashlib.sha256(
                canonical_json(
                    {
                        "schema": (
                            "ask_herdr.topology_pending_candidate.internal.v1"
                        ),
                        "candidate_name": candidate_name,
                        "candidate_sequence": candidate_sequence,
                        "candidate_digest": candidate_digest,
                    }
                )
            ).hexdigest(),
            promoted_head_digest=previous_digest,
            transaction_identities=tuple(sorted(identities.items())),
            record_sources=pending_sources,
            empty_candidate_name=(
                candidate_name if candidate_was_empty else None
            ),
            promoted_key_entries=promoted_projection.key_entries,
            promoted_operation_entries=(
                _topology_status_operation_entries_from_projection(
                    promoted_projection
                )
            ),
        )
    return _HeadReplay(
        replay=replay,
        transaction_identities=tuple(sorted(identities.items())),
        record_sources=tuple(
            (name, identity, payload)
            for name, (identity, payload) in sorted(record_sources.items())
        ),
    )


def _publish_record(
    handles: _Handles,
    binding: ValidatedTopologyStoreBinding,
    replay: _Replay,
    event_kind: str,
    payload: Dict[str, Any],
    failpoint: Optional[Callable[[str], None]] = None,
) -> None:
    sequence = len(replay.records) + 1
    previous_digest = (
        replay.records[-1]["record_digest"] if replay.records else None
    )
    record = _event_record(
        binding,
        sequence,
        previous_digest,
        event_kind,
        payload,
    )
    expected = canonical_json(record) + b"\n"
    candidate_name = _candidate_name(record)
    capsule = _mkdir_open(handles.transactions, candidate_name)
    try:
        _invoke_failpoint(failpoint, "after_event_candidate_create")
        _write_new(capsule, RECORD_NAME, expected)
        _invoke_failpoint(failpoint, "after_event_capsule_file_fullsync")
        _sync_directory(capsule)
        reread, reread_bytes = _read_json(capsule, RECORD_NAME)
        if reread != record or reread_bytes != expected:
            raise _IntegrityError("topology_store.candidate_changed")
        if os.fstat(capsule).st_dev != os.fstat(handles.transactions).st_dev:
            raise _IntegrityError("topology_store.filesystem_changed")
        _invoke_failpoint(failpoint, "before_event_capsule_promote")
        slot_name = _event_name(sequence)
        disposition = commit_exclusive(
            handles.transactions,
            candidate_name,
            slot_name,
        )
        if disposition is CommitDisposition.OCCUPIED:
            raise _IntegrityError("topology_store.event_slot_occupied")
        _invoke_failpoint(failpoint, "after_event_capsule_promote")
        _restore_event_barriers(handles.transactions, slot_name, capsule)
    finally:
        os.close(capsule)
    verified = _read_records(handles, binding)
    if len(verified.records) != sequence or verified.records[-1] != record:
        raise _IntegrityError("topology_store.publication_unverified")


def _project(
    replay: _Replay,
    *,
    absent: bool = False,
) -> TopologyStoreInspection:
    if absent:
        return TopologyStoreInspection(
            status="absent",
            detail_code="topology_store.absent",
            unfinished_mutation_ids=(),
            pending_step_ids=(),
            resend_allowed=False,
            project_topology_digest=None,
            trust_seed=None,
        )
    unfinished = tuple(
        sorted(
            mutation_id
            for mutation_id in replay.mutations
            if mutation_id not in replay.settlements
        )
    )
    pending = tuple(
        sorted(
            step_id
            for (mutation_id, step_id) in replay.commands
            if mutation_id in unfinished
            and (mutation_id, step_id) not in replay.receipts
        )
    )
    if unfinished:
        return TopologyStoreInspection(
            status="reconciliation_required",
            detail_code="topology_store.unfinished_mutation",
            unfinished_mutation_ids=unfinished,
            pending_step_ids=pending,
            resend_allowed=False,
            project_topology_digest=None,
            trust_seed=None,
        )
    settlements = list(replay.settlements.values())
    project_topology_digest = (
        settlements[-1].project_topology_digest if settlements else None
    )
    project_topology_proof = (
        settlements[-1].project_topology_proof if settlements else None
    )
    receipt_values = [
        item
        for (mutation_id, _), item in replay.receipts.items()
        if mutation_id in replay.settlements
        and item.disposition is CommandEffectDisposition.CONFIRMED
    ]
    resource_fingerprints: Dict[str, List[Tuple[str, ...]]] = {}
    if project_topology_proof is not None:
        for lane in project_topology_proof.lanes:
            resource_fingerprints.setdefault(
                lane.workspace.creation_receipt_digest,
                [],
            ).append(topology_resource_fingerprint(lane.workspace))
        for side_effect in project_topology_proof.side_effects:
            resource_fingerprints.setdefault(
                side_effect.creation_receipt_digest,
                [],
            ).append(topology_resource_fingerprint(side_effect))
    trust_seed = TopologyTrustSeed(
        receipt_digests=tuple(
            sorted(item.command_receipt_digest for item in receipt_values)
        ),
        seen_request_ids=tuple(sorted(item.request_id for item in receipt_values)),
        session_generations=tuple(
            sorted(
                set(
                    (
                        item.session_dir,
                        item.socket_path,
                        item.session_generation_id,
                    )
                    for item in receipt_values
                )
            )
        ),
        resource_receipt_bindings=tuple(
            sorted(
                (
                    item.command_receipt_digest,
                    item.resource_binding_digests,
                )
                for item in receipt_values
            )
        ),
        receipt_kinds=tuple(
            sorted(
                (item.command_receipt_digest, item.command_kind)
                for item in receipt_values
            )
        ),
        resource_fingerprint_bindings=tuple(
            sorted(
                (
                    digest,
                    tuple(sorted(fingerprints)),
                )
                for digest, fingerprints in resource_fingerprints.items()
            )
        ),
    )
    return TopologyStoreInspection(
        status="active",
        detail_code="topology_store.active",
        unfinished_mutation_ids=(),
        pending_step_ids=(),
        resend_allowed=False,
        project_topology_digest=project_topology_digest,
        trust_seed=trust_seed,
        project_topology_proof=project_topology_proof,
    )


def _quarantined(code: str) -> TopologyStoreInspection:
    return TopologyStoreInspection(
        status="quarantined",
        detail_code=code,
        unfinished_mutation_ids=(),
        pending_step_ids=(),
        resend_allowed=False,
        project_topology_digest=None,
        trust_seed=None,
    )


def _reconciliation_required(code: str) -> TopologyStoreInspection:
    return TopologyStoreInspection(
        status="reconciliation_required",
        detail_code=code,
        unfinished_mutation_ids=(),
        pending_step_ids=(),
        resend_allowed=False,
        project_topology_digest=None,
        trust_seed=None,
    )


def _writer_busy_result() -> TopologyStoreMutationResult:
    return TopologyStoreMutationResult(
        "topology_store_reconciliation_required",
        "topology_store.writer_busy",
    )


def inspect_topology_store(
    binding: ValidatedTopologyStoreBinding,
) -> TopologyStoreInspection:
    """Replay the exact journal without creating or repairing state."""

    try:
        with _open_root(binding) as root:
            handles = _open_handles(root, binding)
            if handles is None:
                return _project(_empty_replay(), absent=True)
            try:
                replay = _read_records(handles, binding)
                return _project(replay)
            finally:
                _close_handles(handles)
    except _PendingCandidate as error:
        return _reconciliation_required(error.code)
    except _WriterBusy as error:
        return _reconciliation_required(error.code)
    except _IntegrityError as error:
        return _quarantined(error.code)


def _exact_project_mutation_binding(
    value: object,
) -> Optional[ValidatedProjectMutationBinding]:
    """Revalidate and snapshot the one exact caller binding type."""

    if type(value) is not ValidatedProjectMutationBinding:
        return None
    try:
        payload = vars(value)
        if set(payload) != {
            "canonical_root",
            "filesystem_device",
            "filesystem_inode",
            "owner_uid",
            "project_authority_id",
        }:
            return None
        return ValidatedProjectMutationBinding(
            canonical_root=payload["canonical_root"],
            filesystem_device=payload["filesystem_device"],
            filesystem_inode=payload["filesystem_inode"],
            owner_uid=payload["owner_uid"],
            project_authority_id=payload["project_authority_id"],
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _topology_head_binding(
    binding: ValidatedProjectMutationBinding,
) -> ValidatedTopologyStoreBinding:
    return ValidatedTopologyStoreBinding(
        canonical_project_root=binding.canonical_root,
        filesystem_device=binding.filesystem_device,
        filesystem_inode=binding.filesystem_inode,
        owner_uid=binding.owner_uid,
        project_authority_id=binding.project_authority_id,
        namespace="ask-pipeline",
    )


def _close_head_handles(handles: _Handles) -> None:
    _close_head_descriptors((handles.transactions, handles.store))


def _topology_status_projection(
    replay: _Replay,
) -> TopologyStatusProjectionInspection:
    if not replay.records:
        return TopologyStatusProjectionInspection(
            "reconciliation_required",
            "topology_ledger_head.empty_store",
        )
    by_generation: Dict[Tuple[str, int], TopologyStatusKeyEntry] = {}
    by_operation: Dict[str, TopologyStatusOperationEntry] = {}
    for mutation in replay.mutations.values():
        identity = (mutation.lane_id, mutation.lane_generation)
        entry = TopologyStatusKeyEntry(
            consultant_key=mutation.consultant_key,
            lane_id=mutation.lane_id,
            lane_generation=mutation.lane_generation,
            lane_binding_digest=mutation.lane_binding_digest,
        )
        existing = by_generation.get(identity)
        if existing is not None and existing != entry:
            raise _IntegrityError(
                "topology_store.status_key_mapping_conflict"
            )
        by_generation[identity] = entry
        operation_entry = TopologyStatusOperationEntry(
            operation_id=mutation.operation_id,
            canonical_request_digest=mutation.canonical_request_digest,
            policy_record_digest=mutation.policy_record_digest,
            lane_id=mutation.lane_id,
            lane_generation=mutation.lane_generation,
            lane_binding_digest=mutation.lane_binding_digest,
        )
        if mutation.operation_id in by_operation:
            raise _IntegrityError(
                "topology_store.status_operation_mapping_conflict"
            )
        by_operation[mutation.operation_id] = operation_entry
    entries = tuple(
        sorted(
            by_generation.values(),
            key=lambda entry: (
                entry.consultant_key,
                entry.lane_id,
                entry.lane_generation,
            ),
        )
    )
    operation_entries = tuple(
        sorted(
            by_operation.values(),
            key=lambda entry: (
                entry.operation_id,
                entry.canonical_request_digest,
                entry.policy_record_digest,
                entry.lane_id,
                entry.lane_generation,
                entry.lane_binding_digest,
            ),
        )
    )
    projection = TopologyStatusProjectionInspection(
        "active",
        "topology_ledger_head.active",
        replay.records[-1]["record_digest"],
        entries,
    )
    _remember_topology_status_operation_entries(projection, operation_entries)
    return projection


def inspect_topology_status_projection(
    binding: ValidatedProjectMutationBinding,
) -> TopologyStatusProjectionInspection:
    """Inspect one promoted head and its same-replay key projection."""

    exact_binding = _exact_project_mutation_binding(binding)
    if exact_binding is None:
        return TopologyStatusProjectionInspection(
            "quarantined",
            "topology_ledger_head.binding_invalid",
        )
    store_binding = _topology_head_binding(exact_binding)
    result: Optional[TopologyStatusProjectionInspection] = None
    try:
        with _open_head_root(store_binding) as root:
            handles = _open_head_handles(root, store_binding)
            if handles is None:
                if _head_bootstrap_residue(root, store_binding):
                    result = TopologyStatusProjectionInspection(
                        "reconciliation_required",
                        "topology_ledger_head.bootstrap_residue",
                    )
                else:
                    result = TopologyStatusProjectionInspection(
                        "absent",
                        "topology_ledger_head.absent",
                    )
            else:
                operation_error: Optional[BaseException] = None
                try:
                    try:
                        head_replay = _read_head_records(
                            handles,
                            store_binding,
                        )
                    except _PendingCandidate as error:
                        _validate_head_terminal_state(
                            handles,
                            store_binding,
                            error.transaction_identities,
                            error.record_sources,
                            error.empty_candidate_name,
                        )
                        raise
                    _validate_head_terminal_state(
                        handles,
                        store_binding,
                        head_replay.transaction_identities,
                        head_replay.record_sources,
                    )
                    result = _topology_status_projection(
                        head_replay.replay
                    )
                except BaseException as error:
                    operation_error = error
                    raise
                finally:
                    try:
                        _close_head_handles(handles)
                    except _HeadCleanupError:
                        if operation_error is None and (
                            result is None or result.status == "active"
                        ):
                            result = TopologyStatusProjectionInspection(
                                "reconciliation_required",
                                (
                                    "topology_ledger_head."
                                    "cleanup_unverified"
                                ),
                            )
        return result
    except _PendingCandidate as error:
        projection = TopologyStatusProjectionInspection(
            "reconciliation_required",
            error.code,
            error.promoted_head_digest,
            error.promoted_key_entries,
        )
        _remember_topology_status_operation_entries(
            projection,
            error.promoted_operation_entries,
        )
        return projection
    except _WriterBusy as error:
        return TopologyStatusProjectionInspection(
            "busy",
            error.code,
        )
    except _IntegrityError as error:
        return TopologyStatusProjectionInspection(
            "quarantined",
            error.code,
        )
    except _HeadCleanupError:
        if result is not None and result.status != "active":
            return result
        return TopologyStatusProjectionInspection(
            "reconciliation_required",
            "topology_ledger_head.cleanup_unverified",
        )
    except OSError:
        return TopologyStatusProjectionInspection(
            "reconciliation_required",
            "topology_ledger_head.storage_unavailable",
        )


def inspect_topology_ledger_head(
    binding: ValidatedProjectMutationBinding,
) -> TopologyLedgerHeadInspection:
    """Inspect the promoted Topology journal head without repair or barriers."""

    projection = inspect_topology_status_projection(binding)
    return TopologyLedgerHeadInspection(
        projection.status,
        projection.detail_code,
        projection.topology_ledger_head_digest,
    )


def _lane_index_membership_projection(
    replay: _Replay,
) -> _LaneIndexMembershipInspection:
    """Project the complete authenticated mutation-intent membership set."""

    by_generation: Dict[Tuple[str, int], _LaneIndexMembershipEntry] = {}
    for mutation in replay.mutations.values():
        key = (mutation.lane_id, mutation.lane_generation)
        entry = _LaneIndexMembershipEntry(
            lane_id=mutation.lane_id,
            lane_generation=mutation.lane_generation,
            lane_binding_digest=mutation.lane_binding_digest,
        )
        existing = by_generation.get(key)
        if existing is not None and existing != entry:
            raise _IntegrityError(
                "topology_store.lane_membership_binding_conflict"
            )
        by_generation[key] = entry

    entries = tuple(
        by_generation[key]
        for key in sorted(by_generation)
    )
    head_digest = (
        replay.records[-1]["record_digest"] if replay.records else None
    )
    if _open_mutation_ids(replay):
        return _LaneIndexMembershipInspection(
            status="reconciliation_required",
            detail_code="topology_store.unfinished_mutation",
            entries=entries,
            topology_ledger_head_digest=head_digest,
        )
    return _LaneIndexMembershipInspection(
        status="active",
        detail_code="topology_store.active",
        entries=entries,
        topology_ledger_head_digest=head_digest,
    )


def _inspect_lane_index_membership_from_root(
    root: int,
    binding: ValidatedTopologyStoreBinding,
) -> _LaneIndexMembershipInspection:
    """Replay membership using a caller-retained exact project root."""

    handles: Optional[_Handles] = None
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_handles(root, binding)
        if handles is None:
            return _LaneIndexMembershipInspection(
                status="absent",
                detail_code="topology_store.absent",
            )
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
        replay = _read_records(handles, binding)
        if tuple(sorted(os.listdir(handles.transactions))) != namespace_names:
            raise _IntegrityError(
                "topology_store.transaction_namespace_changed"
            )
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
            raise _IntegrityError(
                "topology_store.transaction_namespace_changed"
            )
        return _lane_index_membership_projection(replay)
    except _PendingCandidate as error:
        operation_error = error
        return _LaneIndexMembershipInspection(
            status="reconciliation_required",
            detail_code=error.code,
        )
    except _WriterBusy as error:
        operation_error = error
        return _LaneIndexMembershipInspection(
            status="reconciliation_required",
            detail_code=error.code,
        )
    except _IntegrityError as error:
        operation_error = error
        return _LaneIndexMembershipInspection(
            status="quarantined",
            detail_code=error.code,
        )
    finally:
        if handles is not None:
            try:
                _close_handles(handles)
            except OSError:
                if operation_error is None:
                    raise


def _inspect_lane_index_membership(
    binding: ValidatedTopologyStoreBinding,
) -> _LaneIndexMembershipInspection:
    """Replay Topology without repair and expose mutation-backed Lane members."""

    try:
        with _open_root(binding) as root:
            return _inspect_lane_index_membership_from_root(root, binding)
    except _WriterBusy as error:
        return _LaneIndexMembershipInspection(
            status="reconciliation_required",
            detail_code=error.code,
        )
    except _IntegrityError as error:
        return _LaneIndexMembershipInspection(
            status="quarantined",
            detail_code=error.code,
        )


def _workspace_matches_binding(
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
) -> bool:
    return intent.lane_workspace_cwd == os.path.join(
        binding.canonical_project_root,
        "lane-workspaces",
        intent.lane_id,
    )


def _commit_mutation_intent_locked(
    root: int,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
) -> TopologyStoreMutationResult:
    """Commit one intent while the caller retains the project writer lease."""

    try:
        handles = _ensure_handles(root, binding)
    except _IntegrityError as error:
        if error.code == "durability_not_supported":
            return TopologyStoreMutationResult(
                "durability_not_supported",
                "topology_store.durability_not_supported",
            )
        raise
    try:
        replay = _read_records(
            handles,
            binding,
            pending_resolver=lambda _: (
                "mutation_intent",
                _mutation_payload(intent),
            ),
        )
        if (
            intent.topology_store_incarnation_digest is not None
            and intent.topology_store_incarnation_digest
            != _store_incarnation_digest(handles, binding)
        ):
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.incarnation_mismatch",
            )
        existing = replay.mutations.get(intent.mutation_id)
        if existing is not None:
            if existing == intent:
                return TopologyStoreMutationResult(
                    (
                        "topology_mutation_prepared"
                        if replay.recovered_candidate
                        else "topology_mutation_already_prepared"
                    ),
                    "topology_store.exact_replay",
                )
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.mutation_changed",
            )
        identity_conflict = _mutation_identity_conflict(replay, intent)
        if identity_conflict is not None:
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                identity_conflict,
            )
        if _open_mutation_ids(replay):
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.open_mutation_exists",
            )
        if intent.prior_topology_digest != (
            _latest_project_topology_digest(replay)
        ):
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.prior_topology_mismatch",
            )
        _publish_record(
            handles,
            binding,
            replay,
            "mutation_intent",
            _mutation_payload(intent),
        )
        return TopologyStoreMutationResult(
            "topology_mutation_prepared",
            "topology_store.committed",
        )
    finally:
        _close_handles(handles)


def commit_mutation_intent(
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
) -> TopologyStoreMutationResult:
    """Durably record one write-ahead mutation intent or exact replay."""

    if not isinstance(intent, TopologyMutationIntent):
        raise ValueError("topology_store.mutation_type_invalid")
    if not _workspace_matches_binding(binding, intent):
        raise ValueError("topology_store.lane_workspace_invalid")
    if intent.topology_store_incarnation_digest is not None:
        return TopologyStoreMutationResult(
            "topology_mutation_conflict",
            "topology_store.project_lease_required",
        )
    try:
        with _open_root(binding) as root:
            return _commit_mutation_intent_locked(root, binding, intent)
    except _WriterBusy:
        return _writer_busy_result()
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def _authenticate_pristine_mutation_for_effect(
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
) -> TopologyStoreMutationResult:
    """Require one exact open mutation with no effect command yet recorded."""

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
        intent_snapshot = _snapshot_topology_mutation_intent(intent)
    except ValueError as error:
        raise ValueError("topology_store.prepared_intent_invalid") from error
    if not _workspace_matches_binding(binding_snapshot, intent_snapshot):
        raise ValueError("topology_store.lane_workspace_invalid")
    try:
        with _open_root(binding_snapshot) as root:
            return _authenticate_pristine_mutation_locked(
                root,
                binding_snapshot,
                intent_snapshot,
            )
    except _WriterBusy:
        return _writer_busy_result()
    except _PendingCandidate as error:
        return TopologyStoreMutationResult(
            "topology_store_reconciliation_required",
            error.code,
        )
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def _authenticate_pristine_mutation_locked(
    root: int,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
) -> TopologyStoreMutationResult:
    """Authenticate an existing pristine intent without creating a store."""

    handles = _open_handles(root, binding)
    if handles is None:
        return TopologyStoreMutationResult(
            "topology_mutation_conflict",
            "topology_store.mutation_missing",
        )
    try:
        replay = _read_records(handles, binding)
        existing = replay.mutations.get(intent.mutation_id)
        related_commands = tuple(
            key for key in replay.commands if key[0] == intent.mutation_id
        )
        related_receipts = tuple(
            key for key in replay.receipts if key[0] == intent.mutation_id
        )
        if existing != intent:
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.mutation_changed",
            )
        if (
            _open_mutation_ids(replay) != (intent.mutation_id,)
            or related_commands
            or related_receipts
            or intent.mutation_id in replay.settlements
        ):
            return TopologyStoreMutationResult(
                "topology_mutation_conflict",
                "topology_store.mutation_not_pristine",
            )
        return TopologyStoreMutationResult(
            "topology_mutation_prepared",
            "topology_store.pristine_intent_authenticated",
        )
    finally:
        _close_handles(handles)


def _authenticate_intent_authority_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    *,
    policy_proof: Any,
    lane_proof: Any,
) -> Tuple[ValidatedTopologyStoreBinding, TopologyMutationIntent, int]:
    """Replay cross-store authority and return one borrowed-root snapshot."""

    from ask_herdr_lane_store import (
        ValidatedLaneGenerationBinding,
        _authenticate_claimed_lane_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.binding_type_invalid"
        ) from error
    try:
        intent_snapshot = _snapshot_topology_mutation_intent(intent)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.mutation_type_invalid"
        ) from error
    if not _workspace_matches_binding(binding_snapshot, intent_snapshot):
        raise ValueError("topology_store.lane_workspace_invalid")
    if policy_proof is None or lane_proof is None:
        raise ProjectMutationLeaseError(
            "topology_store.cross_store_proof_required"
        )
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding_snapshot.canonical_project_root,
        filesystem_device=binding_snapshot.filesystem_device,
        filesystem_inode=binding_snapshot.filesystem_inode,
        owner_uid=binding_snapshot.owner_uid,
        project_authority_id=binding_snapshot.project_authority_id,
        lane_id=intent_snapshot.lane_id,
        lane_generation=intent_snapshot.lane_generation,
        lane_binding_digest=intent_snapshot.lane_binding_digest,
    )
    authenticated_lane = _authenticate_claimed_lane_proof_under_lease(
        lease,
        lane_binding,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
    )
    if not all(
        (
            intent_snapshot.mutation_id
            == authenticated_lane.topology_mutation_id,
            intent_snapshot.operation_id == authenticated_lane.operation_id,
            intent_snapshot.canonical_request_digest
            == authenticated_lane.canonical_request_digest,
            intent_snapshot.policy_record_digest
            == authenticated_lane.policy_record_digest,
            intent_snapshot.lane_state_digest
            == authenticated_lane.lane_state_digest,
            intent_snapshot.lane_id == authenticated_lane.lane_id,
            intent_snapshot.lane_generation
            == authenticated_lane.lane_generation,
            intent_snapshot.lane_binding_digest
            == authenticated_lane.lane_binding_digest,
            intent_snapshot.topology_nonce
            == authenticated_lane.topology_nonce,
            intent_snapshot.topology_store_incarnation_digest
            == authenticated_lane.topology_store_incarnation_digest,
        )
    ):
        raise ProjectMutationLeaseError(
            "topology_store.cross_store_proof_mismatch"
        )
    root = _borrow_validated_root(lease, binding_snapshot)
    return binding_snapshot, intent_snapshot, root


def _authenticate_claimed_intent_authority_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    command: TopologyCommandIntent,
    *,
    policy_proof: Any,
    lane_proof: Any,
) -> Tuple[
    ValidatedTopologyStoreBinding,
    TopologyMutationIntent,
    TopologyCommandIntent,
    Any,
    int,
]:
    """Authenticate the historical anchored Claim for a fresh command."""

    from ask_herdr_lane_store import (  # noqa: PLC0415
        ValidatedLaneGenerationBinding,
        _authenticate_historical_claimed_lane_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
        intent_snapshot = _snapshot_topology_mutation_intent(intent)
        command_snapshot = _snapshot_topology_command_intent(command)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.command_authority_invalid"
        ) from error
    if not _workspace_matches_binding(binding_snapshot, intent_snapshot):
        raise ProjectMutationLeaseError(
            "topology_store.lane_workspace_invalid"
        )
    if policy_proof is None or lane_proof is None:
        raise ProjectMutationLeaseError(
            "topology_store.cross_store_proof_required"
        )
    if (
        intent_snapshot.topology_store_incarnation_digest is None
        or command_snapshot.mutation_id != intent_snapshot.mutation_id
    ):
        raise ProjectMutationLeaseError(
            "topology_store.cross_store_proof_mismatch"
        )
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding_snapshot.canonical_project_root,
        filesystem_device=binding_snapshot.filesystem_device,
        filesystem_inode=binding_snapshot.filesystem_inode,
        owner_uid=binding_snapshot.owner_uid,
        project_authority_id=binding_snapshot.project_authority_id,
        lane_id=intent_snapshot.lane_id,
        lane_generation=intent_snapshot.lane_generation,
        lane_binding_digest=intent_snapshot.lane_binding_digest,
    )
    authenticated_lane = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            lane_binding,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    if not all(
        (
            intent_snapshot.mutation_id
            == authenticated_lane.topology_mutation_id,
            intent_snapshot.operation_id == authenticated_lane.operation_id,
            intent_snapshot.canonical_request_digest
            == authenticated_lane.canonical_request_digest,
            intent_snapshot.policy_record_digest
            == authenticated_lane.policy_record_digest,
            intent_snapshot.lane_state_digest
            == authenticated_lane.lane_state_digest,
            intent_snapshot.lane_id == authenticated_lane.lane_id,
            intent_snapshot.lane_generation
            == authenticated_lane.lane_generation,
            intent_snapshot.lane_binding_digest
            == authenticated_lane.lane_binding_digest,
            intent_snapshot.topology_nonce
            == authenticated_lane.topology_nonce,
            intent_snapshot.topology_store_incarnation_digest
            == authenticated_lane.topology_store_incarnation_digest,
        )
    ):
        raise ProjectMutationLeaseError(
            "topology_store.cross_store_proof_mismatch"
        )
    root = _borrow_validated_root(lease, binding_snapshot)
    return (
        binding_snapshot,
        intent_snapshot,
        command_snapshot,
        lane_binding,
        root,
    )


def commit_mutation_intent_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    *,
    policy_proof: Any = None,
    lane_proof: Any = None,
) -> TopologyStoreMutationResult:
    """Commit an intent only after replaying its Policy and Lane authority."""

    binding_snapshot, intent_snapshot, root = (
        _authenticate_intent_authority_under_lease(
            lease,
            binding,
            intent,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    try:
        return _commit_mutation_intent_locked(
            root,
            binding_snapshot,
            intent_snapshot,
        )
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def _authenticate_pristine_mutation_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    *,
    policy_proof: Any,
    lane_proof: Any,
) -> TopologyStoreMutationResult:
    """Require existing cross-store authority and an exact pristine intent."""

    binding_snapshot, intent_snapshot, root = (
        _authenticate_intent_authority_under_lease(
            lease,
            binding,
            intent,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
    )
    if intent_snapshot.topology_store_incarnation_digest is None:
        return TopologyStoreMutationResult(
            "topology_mutation_conflict",
            "topology_store.incarnation_required",
        )
    try:
        return _authenticate_pristine_mutation_locked(
            root,
            binding_snapshot,
            intent_snapshot,
        )
    except _PendingCandidate as error:
        return TopologyStoreMutationResult(
            "topology_store_reconciliation_required",
            error.code,
        )
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def _resolve_topology_recovery_mutation_under_lease(
    lease: Any,
    project_binding: Any,
    *,
    policy_proof: Any,
    lane_proof: Any,
    allow_pending_policy_content_access: bool = False,
) -> _ResolvedTopologyRecoveryMutation:
    """Derive one recovery mutation solely from authenticated durable records."""

    from ask_herdr_lane_store import (  # noqa: PLC0415
        ClaimedLaneProof,
        ValidatedLaneGenerationBinding,
        _authenticate_historical_claimed_lane_proof_under_lease,
    )
    from ask_herdr_policy_ledger import (  # noqa: PLC0415
        _authenticate_committed_human_admission_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        ValidatedProjectMutationBinding,
        _borrow_validated_root,
    )

    if type(project_binding) is not ValidatedProjectMutationBinding:
        raise ProjectMutationLeaseError(
            "topology_store.recovery_input_invalid"
        )
    if type(lane_proof) is not ClaimedLaneProof:
        raise ProjectMutationLeaseError(
            "topology_store.recovery_authority_mismatch"
        )
    try:
        project_snapshot = ValidatedProjectMutationBinding(
            **dict(vars(project_binding))
        )
        lane_snapshot = ClaimedLaneProof(**dict(vars(lane_proof)))
        binding = ValidatedTopologyStoreBinding(
            canonical_project_root=project_snapshot.canonical_root,
            filesystem_device=project_snapshot.filesystem_device,
            filesystem_inode=project_snapshot.filesystem_inode,
            owner_uid=project_snapshot.owner_uid,
            project_authority_id=project_snapshot.project_authority_id,
            namespace="ask-pipeline",
        )
        lane_binding = ValidatedLaneGenerationBinding(
            canonical_root=project_snapshot.canonical_root,
            filesystem_device=project_snapshot.filesystem_device,
            filesystem_inode=project_snapshot.filesystem_inode,
            owner_uid=project_snapshot.owner_uid,
            project_authority_id=project_snapshot.project_authority_id,
            lane_id=lane_snapshot.lane_id,
            lane_generation=lane_snapshot.lane_generation,
            lane_binding_digest=lane_snapshot.lane_binding_digest,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ProjectMutationLeaseError(
            "topology_store.recovery_input_invalid"
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
    authenticated_lane = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            lane_binding,
            policy_proof=authenticated_policy,
            lane_proof=lane_snapshot,
            allow_pending_policy_content_access=(
                allow_pending_policy_content_access
            ),
        )
    )
    root = _borrow_validated_root(lease, project_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_handles(root, binding)
        if handles is None:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_store_missing"
            )
        incarnation_digest = _store_incarnation_digest(handles, binding)
        replay = _read_records(handles, binding)
        mutation_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "mutation_intent"
            and record.get("payload", {}).get("mutation_id")
            == authenticated_lane.topology_mutation_id
        )
        if len(mutation_records) != 1:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_mutation_mismatch"
            )
        mutation = replay.mutations.get(
            authenticated_lane.topology_mutation_id
        )
        if mutation is None:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_mutation_mismatch"
            )
        mutation_snapshot = _snapshot_topology_mutation_intent(mutation)
        command_intents = tuple(
            _snapshot_topology_command_intent(
                _command_from_payload(record["payload"])
            )
            for record in replay.records
            if record.get("event_kind") == "command_intent"
            and record.get("payload", {}).get("mutation_id")
            == mutation_snapshot.mutation_id
        )
        if not all(
            (
                authenticated_policy.project_authority_id
                == project_snapshot.project_authority_id,
                mutation_snapshot.mutation_id
                == authenticated_lane.topology_mutation_id,
                mutation_snapshot.operation_id
                == authenticated_policy.operation_id
                == authenticated_lane.operation_id,
                mutation_snapshot.canonical_request_digest
                == authenticated_policy.canonical_request_digest
                == authenticated_lane.canonical_request_digest,
                mutation_snapshot.policy_record_digest
                == authenticated_policy.policy_record_digest
                == authenticated_lane.policy_record_digest,
                mutation_snapshot.lane_state_digest
                == authenticated_lane.lane_state_digest,
                mutation_snapshot.lane_id == authenticated_lane.lane_id,
                mutation_snapshot.lane_generation
                == authenticated_lane.lane_generation,
                mutation_snapshot.lane_binding_digest
                == authenticated_lane.lane_binding_digest,
                mutation_snapshot.topology_nonce
                == authenticated_lane.topology_nonce,
                mutation_snapshot.topology_store_incarnation_digest
                is not None,
                mutation_snapshot.topology_store_incarnation_digest
                == authenticated_lane.topology_store_incarnation_digest
                == incarnation_digest,
                _workspace_matches_binding(binding, mutation_snapshot),
                all(
                    command.mutation_id == mutation_snapshot.mutation_id
                    for command in command_intents
                ),
            )
        ):
            raise ProjectMutationLeaseError(
                "topology_store.recovery_authority_mismatch"
            )
        if _store_incarnation_digest(handles, binding) != incarnation_digest:
            raise ProjectMutationLeaseError(
                "topology_store.store_changed",
                state_status="reconciliation_required",
            )
        _borrow_validated_root(lease, project_snapshot)
        return _ResolvedTopologyRecoveryMutation(
            binding=binding,
            mutation_intent=mutation_snapshot,
            mutation_record_digest=mutation_records[0]["record_digest"],
            command_intents=command_intents,
        )
    except ProjectMutationLeaseError:
        raise
    except _PendingCandidate as error:
        raise ProjectMutationLeaseError(
            error.code,
            state_status="reconciliation_required",
        ) from error
    except _WriterBusy as error:
        raise ProjectMutationLeaseError(
            error.code,
            state_status="reconciliation_required",
        ) from error
    except (_IntegrityError, OSError, StrictJsonError, ValueError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "topology_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _inspect_open_mutation_replay_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    *,
    policy_proof: Any,
    lane_proof: Any,
    allow_pending_policy_content_access: bool = False,
) -> _OpenMutationReplayEvidence:
    """Replay one anchored mutation without granting effect authority."""

    from ask_herdr_lane_store import (  # noqa: PLC0415
        ValidatedLaneGenerationBinding,
        _authenticate_historical_claimed_lane_proof_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
        intent_snapshot = _snapshot_topology_mutation_intent(intent)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.recovery_input_invalid"
        ) from error
    if (
        not _workspace_matches_binding(binding_snapshot, intent_snapshot)
        or intent_snapshot.topology_store_incarnation_digest is None
        or policy_proof is None
        or lane_proof is None
    ):
        raise ProjectMutationLeaseError(
            "topology_store.recovery_authority_mismatch"
        )
    lane_binding = ValidatedLaneGenerationBinding(
        canonical_root=binding_snapshot.canonical_project_root,
        filesystem_device=binding_snapshot.filesystem_device,
        filesystem_inode=binding_snapshot.filesystem_inode,
        owner_uid=binding_snapshot.owner_uid,
        project_authority_id=binding_snapshot.project_authority_id,
        lane_id=intent_snapshot.lane_id,
        lane_generation=intent_snapshot.lane_generation,
        lane_binding_digest=intent_snapshot.lane_binding_digest,
    )
    authenticated_lane = (
        _authenticate_historical_claimed_lane_proof_under_lease(
            lease,
            lane_binding,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
            allow_pending_policy_content_access=(
                allow_pending_policy_content_access
            ),
        )
    )
    if not all(
        (
            intent_snapshot.mutation_id
            == authenticated_lane.topology_mutation_id,
            intent_snapshot.operation_id == authenticated_lane.operation_id,
            intent_snapshot.canonical_request_digest
            == authenticated_lane.canonical_request_digest,
            intent_snapshot.policy_record_digest
            == authenticated_lane.policy_record_digest,
            intent_snapshot.lane_state_digest
            == authenticated_lane.lane_state_digest,
            intent_snapshot.lane_id == authenticated_lane.lane_id,
            intent_snapshot.lane_generation
            == authenticated_lane.lane_generation,
            intent_snapshot.lane_binding_digest
            == authenticated_lane.lane_binding_digest,
            intent_snapshot.topology_nonce
            == authenticated_lane.topology_nonce,
            intent_snapshot.topology_store_incarnation_digest
            == authenticated_lane.topology_store_incarnation_digest,
        )
    ):
        raise ProjectMutationLeaseError(
            "topology_store.recovery_authority_mismatch"
        )

    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_store_missing"
            )
        replay = _read_records(handles, binding_snapshot)
        if replay.mutations.get(intent_snapshot.mutation_id) != intent_snapshot:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_mutation_mismatch"
            )
        mutation_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "mutation_intent"
            and record.get("payload", {}).get("mutation_id")
            == intent_snapshot.mutation_id
        )
        command_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "command_intent"
            and record.get("payload", {}).get("mutation_id")
            == intent_snapshot.mutation_id
        )
        if len(mutation_records) != 1:
            raise ProjectMutationLeaseError(
                "topology_store.recovery_history_invalid"
            )
        settlement_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "mutation_settlement"
            and record.get("payload", {}).get("mutation_id")
            == intent_snapshot.mutation_id
        )
        settlement = replay.settlements.get(intent_snapshot.mutation_id)
        if len(settlement_records) != (1 if settlement is not None else 0):
            raise ProjectMutationLeaseError(
                "topology_store.recovery_history_invalid"
            )
        commands = tuple(
            _command_from_payload(record["payload"])
            for record in command_records
        )
        receipts = tuple(
            replay.receipts[(intent_snapshot.mutation_id, command.step_id)]
            for command in commands
            if (intent_snapshot.mutation_id, command.step_id)
            in replay.receipts
        )
        _borrow_validated_root(lease, binding_snapshot)
        return _OpenMutationReplayEvidence(
            mutation_record_digest=mutation_records[0]["record_digest"],
            command_record_digests=tuple(
                (
                    command.step_id,
                    record["record_digest"],
                )
                for command, record in zip(commands, command_records)
            ),
            commands=commands,
            receipts=receipts,
            settlement=settlement,
            settlement_record_digest=(
                settlement_records[0]["record_digest"]
                if settlement_records
                else None
            ),
            record_digests=tuple(
                record["record_digest"] for record in replay.records
            ),
        )
    except ProjectMutationLeaseError:
        raise
    except (_IntegrityError, OSError, StrictJsonError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "topology_store.storage_integrity_failure"
        )
        mapped = ProjectMutationLeaseError(code)
        if isinstance(error, _PendingCandidate):
            mapped.residue_state_digest = error.residue_state_digest
        raise mapped from error
    finally:
        if handles is not None:
            _close_handles(handles)


def _inspect_open_mutation_reconciliation_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyMutationIntent,
    *,
    policy_proof: Any,
    lane_proof: Any,
    allow_pending_policy_content_access: bool = False,
) -> _OpenMutationReplayInspection:
    """Tag durable replay barriers without resolving or publishing them."""

    try:
        evidence = _inspect_open_mutation_replay_under_lease(
            lease,
            binding,
            intent,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
            allow_pending_policy_content_access=(
                allow_pending_policy_content_access
            ),
        )
        return _OpenMutationReplayInspection(
            "active",
            "topology_store.recovery_active",
            evidence,
        )
    except Exception as error:
        from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
            ProjectMutationLeaseError,
        )

        if not isinstance(error, ProjectMutationLeaseError):
            raise
        if error.detail_code in {
            "topology_store.pending_candidate",
            "topology_store.writer_active",
            "topology_store.store_changed",
        }:
            residue_digest = "sha256:" + hashlib.sha256(
                canonical_json(
                    {
                        "schema": (
                            "ask_herdr.topology_recovery_barrier.internal.v1"
                        ),
                        "detail_code": error.detail_code,
                        "mutation_id": intent.mutation_id,
                        "incarnation_digest": (
                            intent.topology_store_incarnation_digest
                        ),
                        "observed_residue_digest": getattr(
                            error,
                            "residue_state_digest",
                            None,
                        ),
                    }
                )
            ).hexdigest()
            return _OpenMutationReplayInspection(
                "reconciliation_required",
                error.detail_code,
                None,
                residue_digest,
            )
        return _OpenMutationReplayInspection(
            "quarantined",
            error.detail_code,
            None,
        )


def _derive_claimed_command_plan(
    replay: _Replay,
    binding: ValidatedTopologyStoreBinding,
    mutation_intent: TopologyMutationIntent,
    command_intent: TopologyCommandIntent,
) -> _ClaimedCommandPlan:
    """Derive a fresh command record without granting publication authority."""

    mutation = replay.mutations.get(mutation_intent.mutation_id)
    if mutation != mutation_intent:
        raise _CommandOrderInvalid("topology_store.mutation_changed")
    if mutation.topology_store_incarnation_digest is None:
        raise _CommandOrderInvalid("topology_store.incarnation_required")
    if (
        _open_mutation_ids(replay) != (mutation_intent.mutation_id,)
        or mutation_intent.mutation_id in replay.settlements
    ):
        raise _CommandOrderInvalid("topology_store.mutation_not_open")

    mutation_records = tuple(
        record
        for record in replay.records
        if record.get("event_kind") == "mutation_intent"
        and record.get("payload", {}).get("mutation_id")
        == mutation_intent.mutation_id
    )
    command_records = tuple(
        record
        for record in replay.records
        if record.get("event_kind") == "command_intent"
        and record.get("payload", {}).get("mutation_id")
        == mutation_intent.mutation_id
    )
    prior_commands = tuple(
        _commands_for_mutation(replay, mutation_intent.mutation_id)
    )
    if (
        len(mutation_records) != 1
        or len(command_records) != len(prior_commands)
    ):
        raise _IntegrityError("topology_store.command_history_invalid")
    if not prior_commands:
        related_receipts = tuple(
            key
            for key in replay.receipts
            if key[0] == mutation_intent.mutation_id
        )
        if related_receipts or mutation_records[0] is not replay.records[-1]:
            raise _CommandOrderInvalid(
                "topology_store.mutation_not_pristine"
            )

    key = (command_intent.mutation_id, command_intent.step_id)
    if key in replay.commands:
        raise _CommandOrderInvalid(
            "topology_store.command_already_recorded"
        )
    resolved = _resolve_command_intent(replay, command_intent)
    previous_digest = (
        replay.records[-1]["record_digest"] if replay.records else None
    )
    prospective_record = _event_record(
        binding,
        len(replay.records) + 1,
        previous_digest,
        "command_intent",
        _command_payload(resolved),
    )
    return _ClaimedCommandPlan(
        resolved_command=resolved,
        mutation_record_digest=mutation_records[0]["record_digest"],
        prospective_command_record_digest=(
            prospective_record["record_digest"]
        ),
        first_command_record_digest=(
            command_records[0]["record_digest"]
            if command_records
            else None
        ),
        prior_command_count=len(prior_commands),
        record_digests=tuple(
            record["record_digest"] for record in replay.records
        ),
    )


def _effect_started_proof_matches_plan(
    proof: Any,
    intent: TopologyMutationIntent,
    plan: _ClaimedCommandPlan,
) -> bool:
    from ask_herdr_lane_store import (  # noqa: PLC0415
        TopologyEffectStartedLaneProof,
    )

    if type(proof) is not TopologyEffectStartedLaneProof:
        return False
    proof = TopologyEffectStartedLaneProof(**dict(vars(proof)))
    expected_first = (
        plan.prospective_command_record_digest
        if plan.prior_command_count == 0
        else plan.first_command_record_digest
    )
    return (
        proof.topology_mutation_id == intent.mutation_id
        and proof.topology_store_incarnation_digest
        == intent.topology_store_incarnation_digest
        and proof.topology_mutation_record_digest
        == plan.mutation_record_digest
        and proof.first_topology_command_record_digest
        == expected_first
    )


def _command_effect_started_proof_matches_plan(
    proof: Any,
    first_proof: Any,
    intent: TopologyMutationIntent,
    plan: _ClaimedCommandPlan,
) -> bool:
    """Require one exact Lane witness for this prospective later command."""

    from ask_herdr_lane_store import (  # noqa: PLC0415
        TopologyCommandEffectStartedLaneProof,
        TopologyEffectStartedLaneProof,
    )

    if (
        type(proof) is not TopologyCommandEffectStartedLaneProof
        or type(first_proof) is not TopologyEffectStartedLaneProof
    ):
        return False
    proof = TopologyCommandEffectStartedLaneProof(**dict(vars(proof)))
    first_proof = TopologyEffectStartedLaneProof(**dict(vars(first_proof)))
    resolved = plan.resolved_command
    return (
        plan.prior_command_count >= 1
        and proof.topology_mutation_id == intent.mutation_id
        and proof.topology_store_incarnation_digest
        == intent.topology_store_incarnation_digest
        and proof.topology_mutation_record_digest
        == plan.mutation_record_digest
        and proof.topology_effect_started_record_digest
        == first_proof.topology_effect_started_record_digest
        and proof.command_sequence == plan.prior_command_count + 1
        and proof.topology_command_step_id == resolved.step_id
        and proof.topology_command_record_digest
        == plan.prospective_command_record_digest
    )


def commit_claimed_command_intent_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    command_intent: TopologyCommandIntent,
    *,
    mutation_intent: TopologyMutationIntent,
    policy_proof: Any,
    lane_proof: Any,
) -> TopologyStoreMutationResult:
    """Commit one fresh anchored command after its durable Lane marker.

    The first command derives and freshly appends ``TopologyEffectStarted``
    before publishing the Topology record.  Every later command freshly
    appends its own Lane witness before publishing its exact Topology record.
    No exact replay from this write seam grants command or resend authority.
    """

    from ask_herdr_lane_store import (  # noqa: PLC0415
        authenticate_topology_effect_started_under_lease,
        _commit_topology_command_effect_started_under_lease,
        _commit_topology_effect_started_under_lease,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    (
        binding_snapshot,
        mutation_snapshot,
        command_snapshot,
        lane_binding,
        root,
    ) = _authenticate_claimed_intent_authority_under_lease(
        lease,
        binding,
        mutation_intent,
        command_intent,
        policy_proof=policy_proof,
        lane_proof=lane_proof,
    )

    handles: Optional[_Handles] = None
    try:
        handles = _open_handles(root, binding_snapshot)
        if handles is None:
            return TopologyStoreMutationResult(
                "topology_command_conflict",
                "topology_store.mutation_missing",
            )
        replay = _read_records(handles, binding_snapshot)
        plan = _derive_claimed_command_plan(
            replay,
            binding_snapshot,
            mutation_snapshot,
            command_snapshot,
        )
    except _PendingCandidate as error:
        return TopologyStoreMutationResult(
            "topology_store_reconciliation_required",
            error.code,
        )
    except _CommandOrderInvalid as error:
        return TopologyStoreMutationResult(
            "topology_command_conflict",
            error.code,
        )
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )
    finally:
        if handles is not None:
            _close_handles(handles)

    if plan.prior_command_count == 0:
        marker_proof = _commit_topology_effect_started_under_lease(
            lease,
            lane_binding,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
            topology_mutation_record_digest=(
                plan.mutation_record_digest
            ),
            first_topology_command_record_digest=(
                plan.prospective_command_record_digest
            ),
        )
        command_marker_proof = None
    else:
        marker_proof = authenticate_topology_effect_started_under_lease(
            lease,
            lane_binding,
            policy_proof=policy_proof,
            lane_proof=lane_proof,
        )
        command_marker_proof = (
            _commit_topology_command_effect_started_under_lease(
                lease,
                lane_binding,
                policy_proof=policy_proof,
                lane_proof=lane_proof,
                command_sequence=plan.prior_command_count + 1,
                topology_command_step_id=(
                    plan.resolved_command.step_id
                ),
                topology_command_record_digest=(
                    plan.prospective_command_record_digest
                ),
            )
        )
    if not _effect_started_proof_matches_plan(
        marker_proof,
        mutation_snapshot,
        plan,
    ):
        raise ProjectMutationLeaseError(
            "topology_store.effect_started_proof_mismatch"
        )
    if plan.prior_command_count > 0 and not (
        _command_effect_started_proof_matches_plan(
            command_marker_proof,
            marker_proof,
            mutation_snapshot,
            plan,
        )
    ):
        raise ProjectMutationLeaseError(
            "topology_store.command_effect_started_proof_mismatch"
        )

    _borrow_validated_root(lease, binding_snapshot)
    handles = None
    try:
        handles = _open_handles(root, binding_snapshot)
        if handles is None:
            return TopologyStoreMutationResult(
                "topology_command_conflict",
                "topology_store.mutation_missing",
            )
        replay = _read_records(handles, binding_snapshot)
        current_plan = _derive_claimed_command_plan(
            replay,
            binding_snapshot,
            mutation_snapshot,
            command_snapshot,
        )
        if current_plan != plan or not _effect_started_proof_matches_plan(
            marker_proof,
            mutation_snapshot,
            current_plan,
        ):
            return TopologyStoreMutationResult(
                "topology_command_conflict",
                "topology_store.command_plan_changed",
            )
        if current_plan.prior_command_count > 0 and not (
            _command_effect_started_proof_matches_plan(
                command_marker_proof,
                marker_proof,
                mutation_snapshot,
                current_plan,
            )
        ):
            return TopologyStoreMutationResult(
                "topology_command_conflict",
                "topology_store.command_plan_changed",
            )
        _publish_record(
            handles,
            binding_snapshot,
            replay,
            "command_intent",
            _command_payload(current_plan.resolved_command),
        )
        return TopologyStoreMutationResult(
            "topology_command_prepared",
            "topology_store.committed",
        )
    except _PendingCandidate as error:
        return TopologyStoreMutationResult(
            "topology_store_reconciliation_required",
            error.code,
        )
    except _CommandOrderInvalid as error:
        return TopologyStoreMutationResult(
            "topology_command_conflict",
            error.code,
        )
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )
    finally:
        if handles is not None:
            _close_handles(handles)


def _authenticate_lane_settlement_under_lease(
    lease: Any,
    binding: ValidatedTopologyStoreBinding,
    *,
    lane_proof: Any,
    effect_started_proof: Any = None,
    command_effect_started_proofs: Any = (),
) -> _AuthenticatedLaneSettlement:
    """Replay and derive the current complete settlement for one Lane claim.

    This is a private cross-store port.  It deliberately exposes neither the
    Topology journal layout nor a caller-selectable settlement digest.
    """

    from ask_herdr_lane_store import (  # noqa: PLC0415
        ClaimedLaneProof,
        TopologyCommandEffectStartedLaneProof,
        TopologyEffectStartedLaneProof,
    )
    from ask_herdr_project_mutation_lease import (  # noqa: PLC0415
        ProjectMutationLeaseError,
        _borrow_validated_root,
    )

    try:
        binding_snapshot = _snapshot_validated_topology_binding(binding)
    except ValueError as error:
        raise ProjectMutationLeaseError(
            "topology_store.binding_type_invalid"
        ) from error
    if type(lane_proof) is not ClaimedLaneProof:
        raise ProjectMutationLeaseError(
            "topology_store.settlement_lane_mismatch"
        )
    lane_snapshot = ClaimedLaneProof(**dict(vars(lane_proof)))
    if lane_snapshot.topology_store_incarnation_digest is None:
        if effect_started_proof is not None:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_lane_mismatch"
            )
        marker_snapshot = None
    else:
        if type(effect_started_proof) is not TopologyEffectStartedLaneProof:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_effect_started_required"
            )
        marker_snapshot = TopologyEffectStartedLaneProof(
            **dict(vars(effect_started_proof))
        )
    if type(command_effect_started_proofs) is not tuple or any(
        type(item) is not TopologyCommandEffectStartedLaneProof
        for item in command_effect_started_proofs
    ):
        raise ProjectMutationLeaseError(
            "topology_store.settlement_command_effect_started_mismatch"
        )
    command_marker_snapshots = tuple(
        TopologyCommandEffectStartedLaneProof(**dict(vars(item)))
        for item in command_effect_started_proofs
    )
    if marker_snapshot is None and command_marker_snapshots:
        raise ProjectMutationLeaseError(
            "topology_store.settlement_command_effect_started_mismatch"
        )
    root = _borrow_validated_root(lease, binding_snapshot)
    handles: Optional[_Handles] = None
    try:
        handles = _open_handles(root, binding_snapshot)
        if handles is None:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_missing"
            )
        replay = _read_records(handles, binding_snapshot)
        if _open_mutation_ids(replay):
            raise ProjectMutationLeaseError(
                "topology_store.settlement_not_complete"
            )
        mutation = replay.mutations.get(lane_snapshot.topology_mutation_id)
        settlement = replay.settlements.get(
            lane_snapshot.topology_mutation_id
        )
        if mutation is None or settlement is None:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_missing"
            )
        if (
            mutation.operation_id != lane_snapshot.operation_id
            or mutation.canonical_request_digest
            != lane_snapshot.canonical_request_digest
            or mutation.policy_record_digest
            != lane_snapshot.policy_record_digest
            or mutation.lane_state_digest != lane_snapshot.lane_state_digest
            or mutation.lane_id != lane_snapshot.lane_id
            or mutation.lane_generation != lane_snapshot.lane_generation
            or mutation.lane_binding_digest
            != lane_snapshot.lane_binding_digest
            or mutation.topology_store_incarnation_digest
            != lane_snapshot.topology_store_incarnation_digest
            or mutation.topology_nonce != lane_snapshot.topology_nonce
            or settlement.outcome != "created"
            or settlement.project_topology_proof is None
            or project_topology_digest(settlement.project_topology_proof)
            != settlement.project_topology_digest
            or list(replay.settlements)[-1] != mutation.mutation_id
        ):
            raise ProjectMutationLeaseError(
                "topology_store.settlement_lane_mismatch"
            )
        mutation_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "mutation_intent"
            and record.get("payload", {}).get("mutation_id")
            == mutation.mutation_id
        )
        command_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "command_intent"
            and record.get("payload", {}).get("mutation_id")
            == mutation.mutation_id
        )
        if len(mutation_records) != 1:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_lane_mismatch"
            )
        first_command_record_digest = (
            command_records[0]["record_digest"] if command_records else None
        )
        if marker_snapshot is not None and (
            marker_snapshot.operation_id != lane_snapshot.operation_id
            or marker_snapshot.canonical_request_digest
            != lane_snapshot.canonical_request_digest
            or marker_snapshot.lane_id != lane_snapshot.lane_id
            or marker_snapshot.lane_generation
            != lane_snapshot.lane_generation
            or marker_snapshot.attempt_id != lane_snapshot.attempt_id
            or marker_snapshot.policy_record_digest
            != lane_snapshot.policy_record_digest
            or marker_snapshot.prepared_lane_record_digest
            != lane_snapshot.prepared_lane_record_digest
            or marker_snapshot.topology_mutation_id
            != lane_snapshot.topology_mutation_id
            or marker_snapshot.topology_nonce != lane_snapshot.topology_nonce
            or marker_snapshot.topology_claim_record_digest
            != lane_snapshot.topology_claim_record_digest
            or marker_snapshot.lane_binding_digest
            != lane_snapshot.lane_binding_digest
            or marker_snapshot.topology_store_incarnation_digest
            != lane_snapshot.topology_store_incarnation_digest
            or marker_snapshot.topology_store_incarnation_digest
            != mutation.topology_store_incarnation_digest
            or marker_snapshot.topology_mutation_record_digest
            != mutation_records[0]["record_digest"]
            or marker_snapshot.first_topology_command_record_digest
            != first_command_record_digest
        ):
            raise ProjectMutationLeaseError(
                "topology_store.settlement_effect_started_mismatch"
            )
        expected_later_count = (
            max(0, len(command_records) - 1)
            if marker_snapshot is not None
            else 0
        )
        if len(command_marker_snapshots) != expected_later_count:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_command_effect_started_mismatch"
            )
        previous_lane_witness_digest = (
            marker_snapshot.topology_effect_started_record_digest
            if marker_snapshot is not None
            else None
        )
        for index, (proof, command_record) in enumerate(
            zip(command_marker_snapshots, command_records[1:]),
            start=2,
        ):
            command = _command_from_payload(command_record["payload"])
            if (
                marker_snapshot is None
                or proof.operation_id != lane_snapshot.operation_id
                or proof.canonical_request_digest
                != lane_snapshot.canonical_request_digest
                or proof.lane_id != lane_snapshot.lane_id
                or proof.lane_generation != lane_snapshot.lane_generation
                or proof.attempt_id != lane_snapshot.attempt_id
                or proof.policy_record_digest
                != lane_snapshot.policy_record_digest
                or proof.prepared_lane_record_digest
                != lane_snapshot.prepared_lane_record_digest
                or proof.topology_mutation_id
                != lane_snapshot.topology_mutation_id
                or proof.topology_nonce != lane_snapshot.topology_nonce
                or proof.topology_claim_record_digest
                != lane_snapshot.topology_claim_record_digest
                or proof.lane_binding_digest
                != lane_snapshot.lane_binding_digest
                or proof.topology_store_incarnation_digest
                != lane_snapshot.topology_store_incarnation_digest
                or proof.topology_mutation_record_digest
                != mutation_records[0]["record_digest"]
                or proof.topology_effect_started_record_digest
                != marker_snapshot.topology_effect_started_record_digest
                or proof.command_sequence != index
                or proof.topology_command_step_id != command.step_id
                or proof.topology_command_record_digest
                != command_record["record_digest"]
                or proof.previous_topology_effect_record_digest
                != previous_lane_witness_digest
            ):
                raise ProjectMutationLeaseError(
                    "topology_store.settlement_command_effect_started_mismatch"
                )
            previous_lane_witness_digest = (
                proof.topology_command_effect_started_record_digest
            )
        matching_lanes = tuple(
            item
            for item in settlement.project_topology_proof.lanes
            if item.lane_id == lane_snapshot.lane_id
            and item.topology_nonce == lane_snapshot.topology_nonce
            and item.consultant_key == mutation.consultant_key
            and item.workspace.cwd == mutation.lane_workspace_cwd
        )
        if len(matching_lanes) != 1:
            raise ProjectMutationLeaseError(
                "topology_store.settlement_lane_mismatch"
            )
        settlement_records = tuple(
            record
            for record in replay.records
            if record.get("event_kind") == "mutation_settlement"
            and record.get("payload", {}).get("mutation_id")
            == mutation.mutation_id
        )
        if (
            len(settlement_records) != 1
            or replay.records[-1] != settlement_records[0]
        ):
            raise ProjectMutationLeaseError(
                "topology_store.settlement_not_current"
            )
        _borrow_validated_root(lease, binding_snapshot)
        return _AuthenticatedLaneSettlement(
            mutation_id=mutation.mutation_id,
            settlement_record_digest=settlement_records[0]["record_digest"],
            project_topology_digest=settlement.project_topology_digest,
            mutation_record_digest=mutation_records[0]["record_digest"],
            first_command_record_digest=first_command_record_digest,
            topology_store_incarnation_digest=(
                mutation.topology_store_incarnation_digest
            ),
        )
    except ProjectMutationLeaseError:
        raise
    except _PendingCandidate as error:
        raise ProjectMutationLeaseError(error.code) from error
    except (_IntegrityError, OSError, StrictJsonError, ValueError) as error:
        code = (
            error.code
            if isinstance(error, _IntegrityError)
            else "topology_store.storage_integrity_failure"
        )
        raise ProjectMutationLeaseError(code) from error
    finally:
        if handles is not None:
            _close_handles(handles)


def commit_command_intent(
    binding: ValidatedTopologyStoreBinding,
    intent: TopologyCommandIntent,
) -> TopologyStoreMutationResult:
    """Durably record one command intent before any possible external effect."""

    if not isinstance(intent, TopologyCommandIntent):
        raise ValueError("topology_store.command_type_invalid")
    try:
        with _open_root(binding) as root:
            handles = _open_handles(root, binding)
            if handles is None:
                return TopologyStoreMutationResult(
                    "topology_command_conflict",
                    "topology_store.mutation_missing",
                )
            try:
                try:
                    replay = _read_records(
                        handles,
                        binding,
                        pending_resolver=lambda pending_replay: (
                            "command_intent",
                            _public_command_payload(
                                pending_replay,
                                intent,
                            ),
                        ),
                    )
                except _CommandOrderInvalid as error:
                    return TopologyStoreMutationResult(
                        "topology_command_conflict",
                        error.code,
                    )
                mutation = replay.mutations.get(intent.mutation_id)
                if (
                    mutation is not None
                    and mutation.topology_store_incarnation_digest
                    is not None
                ):
                    return TopologyStoreMutationResult(
                        "topology_command_conflict",
                        "topology_store.project_lease_required",
                    )
                try:
                    resolved = _resolve_command_intent(replay, intent)
                except _CommandOrderInvalid as error:
                    return TopologyStoreMutationResult(
                        "topology_command_conflict",
                        error.code,
                    )
                key = (resolved.mutation_id, resolved.step_id)
                existing = replay.commands.get(key)
                if existing is not None:
                    if existing == resolved:
                        return TopologyStoreMutationResult(
                            (
                                "topology_command_prepared"
                                if replay.recovered_candidate
                                else "topology_command_already_prepared"
                            ),
                            "topology_store.exact_replay",
                        )
                    return TopologyStoreMutationResult(
                        "topology_command_conflict",
                        "topology_store.command_changed",
                    )
                _publish_record(
                    handles,
                    binding,
                    replay,
                    "command_intent",
                    _command_payload(resolved),
                )
                return TopologyStoreMutationResult(
                    "topology_command_prepared",
                    "topology_store.committed",
                )
            finally:
                _close_handles(handles)
    except _WriterBusy:
        return _writer_busy_result()
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def commit_command_receipt(
    binding: ValidatedTopologyStoreBinding,
    value: TopologyCommandReceipt,
) -> TopologyStoreMutationResult:
    """Append one exact receipt without creating dispatch or retry authority."""

    if not isinstance(value, TopologyCommandReceipt):
        raise ValueError("topology_store.receipt_type_invalid")
    try:
        with _open_root(binding) as root:
            handles = _open_handles(root, binding)
            if handles is None:
                return TopologyStoreMutationResult(
                    "topology_command_receipt_conflict",
                    "topology_store.mutation_missing",
                )
            try:
                replay = _read_records(
                    handles,
                    binding,
                    pending_resolver=lambda _: (
                        "command_receipt",
                        _receipt_payload(value),
                    ),
                )
                key = (value.mutation_id, value.step_id)
                existing = replay.receipts.get(key)
                if existing is not None:
                    if existing == value:
                        return TopologyStoreMutationResult(
                            (
                                "topology_command_receipt_recorded"
                                if replay.recovered_candidate
                                else "topology_command_receipt_already_recorded"
                            ),
                            "topology_store.exact_replay",
                        )
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.receipt_changed",
                    )
                command = replay.commands.get(key)
                if command is None:
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.command_missing",
                    )
                if value.mutation_id in replay.settlements:
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.mutation_not_open",
                    )
                if value.request_id in replay.request_ids:
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.request_id_replayed",
                    )
                if value.command_receipt_digest in replay.receipt_digests:
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.receipt_digest_replayed",
                    )
                if (
                    value.command_kind != command.command_kind
                    or value.command_argv_digest != command.command_argv_digest
                    or value.observed_postcondition_digest
                    != command.expected_postcondition_digest
                ):
                    return TopologyStoreMutationResult(
                        "topology_command_receipt_conflict",
                        "topology_store.receipt_binding_mismatch",
                    )
                _publish_record(
                    handles,
                    binding,
                    replay,
                    "command_receipt",
                    _receipt_payload(value),
                )
                return TopologyStoreMutationResult(
                    "topology_command_receipt_recorded",
                    "topology_store.committed",
                )
            finally:
                _close_handles(handles)
    except _WriterBusy:
        return _writer_busy_result()
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


def settle_topology_mutation(
    binding: ValidatedTopologyStoreBinding,
    value: TopologyMutationSettlement,
) -> TopologyStoreMutationResult:
    """Settle one mutation only from its exact complete receipt set."""

    if not isinstance(value, TopologyMutationSettlement):
        raise ValueError("topology_store.settlement_type_invalid")
    try:
        with _open_root(binding) as root:
            handles = _open_handles(root, binding)
            if handles is None:
                return TopologyStoreMutationResult(
                    "topology_mutation_settlement_conflict",
                    "topology_store.mutation_missing",
                )
            try:
                replay = _read_records(
                    handles,
                    binding,
                    pending_resolver=lambda _: (
                        "mutation_settlement",
                        _settlement_payload(value),
                    ),
                )
                existing = replay.settlements.get(value.mutation_id)
                if existing is not None:
                    if existing == value:
                        return TopologyStoreMutationResult(
                            (
                                "topology_mutation_settled"
                                if replay.recovered_candidate
                                else "topology_mutation_already_settled"
                            ),
                            "topology_store.exact_replay",
                        )
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.settlement_changed",
                    )
                if value.mutation_id not in replay.mutations:
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.mutation_missing",
                    )
                if _open_mutation_ids(replay) != (value.mutation_id,):
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.settlement_not_sole_open",
                    )
                receipts = tuple(
                    sorted(
                        receipt.command_receipt_digest
                        for key, receipt in replay.receipts.items()
                        if key[0] == value.mutation_id
                    )
                )
                pending = any(
                    key[0] == value.mutation_id and key not in replay.receipts
                    for key in replay.commands
                )
                mutation_receipts = [
                    receipt
                    for key, receipt in replay.receipts.items()
                    if key[0] == value.mutation_id
                ]
                mutation_commands = _commands_for_mutation(
                    replay,
                    value.mutation_id,
                )
                final_command = (
                    mutation_commands[-1] if mutation_commands else None
                )
                if any(
                    receipt.disposition
                    is not CommandEffectDisposition.CONFIRMED
                    for receipt in mutation_receipts
                ):
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.settlement_disposition_unconfirmed",
                    )
                matching_generation = bool(mutation_receipts) and all(
                    receipt.session_dir == value.session_dir
                    and receipt.socket_path == value.socket_path
                    and receipt.session_generation_id
                    == value.session_generation_id
                    for receipt in mutation_receipts
                )
                if (
                    pending
                    or receipts != value.command_receipt_digests
                    or not matching_generation
                    or final_command is None
                    or final_command.expected_postcondition_digest
                    != replay.mutations[
                        value.mutation_id
                    ].expected_postcondition_digest
                ):
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.settlement_evidence_mismatch",
                    )
                if not _proof_correlates(
                    value,
                    replay.mutations[value.mutation_id],
                    tuple(replay.receipts.values()),
                    _latest_project_topology_proof(replay),
                ):
                    return TopologyStoreMutationResult(
                        "topology_mutation_settlement_conflict",
                        "topology_store.settlement_resource_binding_mismatch",
                    )
                _publish_record(
                    handles,
                    binding,
                    replay,
                    "mutation_settlement",
                    _settlement_payload(value),
                )
                return TopologyStoreMutationResult(
                    "topology_mutation_settled",
                    "topology_store.committed",
                )
            finally:
                _close_handles(handles)
    except _WriterBusy:
        return _writer_busy_result()
    except _IntegrityError as error:
        return TopologyStoreMutationResult(
            "topology_store_quarantined",
            error.code,
        )


__all__ = [
    "CommandEffectDisposition",
    "TopologyCommandIntent",
    "TopologyCommandReceipt",
    "TopologyMutationIntent",
    "TopologyMutationSettlement",
    "TopologyLedgerHeadInspection",
    "TopologyStatusKeyEntry",
    "TopologyStatusOperationEntry",
    "TopologyStatusProjectionInspection",
    "TopologyStoreInspection",
    "TopologyStoreMutationResult",
    "TopologyTrustSeed",
    "ValidatedTopologyStoreBinding",
    "commit_claimed_command_intent_under_lease",
    "commit_command_intent",
    "commit_command_receipt",
    "commit_mutation_intent",
    "commit_mutation_intent_under_lease",
    "inspect_topology_store",
    "inspect_topology_ledger_head",
    "inspect_topology_status_projection",
    "settle_topology_mutation",
]
