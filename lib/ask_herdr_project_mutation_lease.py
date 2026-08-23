"""Private, provider-free project-scoped mutation lease.

The lease owns one nonblocking exclusive lock on the exact canonical project
root.  Store-specific ports may borrow the already-open descriptor, but only
after this module has revalidated the live token, project binding, process, and
complete named path chain.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import os
import re
import stat
from typing import Iterator, Optional, Tuple
from weakref import WeakKeyDictionary


UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


class ProjectMutationLeaseError(RuntimeError):
    """Typed fail-closed error from the private mutation-lease seam."""

    resend_allowed = False

    def __init__(
        self,
        detail_code: str,
        *,
        state_status: Optional[str] = None,
    ) -> None:
        super().__init__(detail_code)
        self.detail_code = detail_code
        if state_status not in {
            None,
            "reconciliation_required",
            "quarantined",
        }:
            raise ValueError("project_mutation_lease.state_status_invalid")
        self.state_status = state_status


@dataclass(frozen=True, init=False)
class ValidatedProjectMutationBinding:
    """Exact Project Authority and filesystem identity guarded by a lease.

    ``canonical_project_root`` is accepted as a construction alias for the
    Topology Store vocabulary.  The stored identity has one canonical field.
    """

    canonical_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int
    project_authority_id: str

    def __init__(
        self,
        canonical_root: Optional[str] = None,
        filesystem_device: Optional[int] = None,
        filesystem_inode: Optional[int] = None,
        owner_uid: Optional[int] = None,
        project_authority_id: Optional[str] = None,
        *,
        canonical_project_root: Optional[str] = None,
    ) -> None:
        roots = tuple(
            value
            for value in (canonical_root, canonical_project_root)
            if value is not None
        )
        if (
            len(roots) == 0
            or any(type(value) is not str for value in roots)
            or any(value != roots[0] for value in roots[1:])
        ):
            raise ValueError("project_mutation_lease.root_alias_conflict")
        root = roots[0]
        if (
            type(root) is not str
            or not root.startswith(os.path.sep)
            or os.path.normpath(root) != root
            or os.path.realpath(root) != root
        ):
            raise ValueError("project_mutation_lease.root_not_canonical")
        filesystem_facts = (
            filesystem_device,
            filesystem_inode,
            owner_uid,
        )
        if any(type(value) is not int or value < 0 for value in filesystem_facts):
            raise ValueError("project_mutation_lease.filesystem_identity_invalid")
        if (
            type(project_authority_id) is not str
            or UUID4_PATTERN.fullmatch(project_authority_id) is None
        ):
            raise ValueError("project_mutation_lease.authority_id_invalid")

        object.__setattr__(self, "canonical_root", root)
        object.__setattr__(self, "filesystem_device", filesystem_device)
        object.__setattr__(self, "filesystem_inode", filesystem_inode)
        object.__setattr__(self, "owner_uid", owner_uid)
        object.__setattr__(self, "project_authority_id", project_authority_id)

    @property
    def canonical_project_root(self) -> str:
        """Topology-vocabulary alias for the one stored canonical root."""

        return self.canonical_root


_TOKEN_SEAL = object()


class ProjectMutationLease:
    """Opaque, process-local capability valid only inside its context."""

    __slots__ = ("__weakref__",)

    def __new__(cls, seal: object = None) -> "ProjectMutationLease":
        if seal is not _TOKEN_SEAL:
            raise TypeError("ProjectMutationLease tokens are context-owned")
        return super().__new__(cls)

    def __reduce__(self):
        raise TypeError("ProjectMutationLease tokens cannot be serialized")

    def __copy__(self):
        raise TypeError("ProjectMutationLease tokens cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("ProjectMutationLease tokens cannot be copied")


@dataclass
class _LeaseState:
    binding: ValidatedProjectMutationBinding
    owner_pid: int
    descriptors: Tuple[int, ...]
    snapshots: Tuple[os.stat_result, ...]
    links: Tuple[Tuple[int, str, int], ...]
    active: bool = True

    @property
    def root_fd(self) -> int:
        return self.descriptors[-1]


_LEASE_STATES: "WeakKeyDictionary[ProjectMutationLease, _LeaseState]" = (
    WeakKeyDictionary()
)


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _root_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_path_chain(
    canonical_root: str,
) -> Tuple[
    Tuple[int, ...],
    Tuple[os.stat_result, ...],
    Tuple[Tuple[int, str, int], ...],
]:
    descriptors = []
    snapshots = []
    links = []
    try:
        current = os.open(os.path.sep, _root_flags())
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        for component in filter(None, canonical_root.split(os.path.sep)[1:]):
            parent = current
            current = os.open(component, _root_flags(), dir_fd=parent)
            descriptors.append(current)
            snapshots.append(os.fstat(current))
            links.append((parent, component, current))
        return tuple(descriptors), tuple(snapshots), tuple(links)
    except BaseException:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _validate_named_path(state: _LeaseState) -> None:
    try:
        for descriptor, snapshot in zip(state.descriptors, state.snapshots):
            if _identity(os.fstat(descriptor)) != _identity(snapshot):
                raise ProjectMutationLeaseError(
                    "project_mutation_lease.root_changed"
                )
        for parent, component, child in state.links:
            bound = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _identity(bound) != _identity(os.fstat(child)):
                raise ProjectMutationLeaseError(
                    "project_mutation_lease.root_changed"
                )
    except ProjectMutationLeaseError:
        raise
    except OSError as error:
        raise ProjectMutationLeaseError(
            "project_mutation_lease.root_changed"
        ) from error


def _state_for_live_token(lease: object) -> _LeaseState:
    if not isinstance(lease, ProjectMutationLease):
        raise ProjectMutationLeaseError("project_mutation_lease.token_invalid")
    try:
        state = _LEASE_STATES.get(lease)
    except (TypeError, AttributeError):
        state = None
    if state is None:
        raise ProjectMutationLeaseError("project_mutation_lease.token_invalid")
    if state.owner_pid != os.getpid():
        raise ProjectMutationLeaseError("project_mutation_lease.process_mismatch")
    if not state.active:
        raise ProjectMutationLeaseError("project_mutation_lease.expired")
    _validate_named_path(state)
    return state


def _binding_root(binding: object) -> str:
    sentinel = object()
    try:
        canonical_root = getattr(binding, "canonical_root", sentinel)
        topology_root = getattr(binding, "canonical_project_root", sentinel)
    except BaseException as error:
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        ) from error
    roots = tuple(
        value
        for value in (canonical_root, topology_root)
        if value is not sentinel and value is not None
    )
    if (
        len(roots) == 0
        or any(type(value) is not str for value in roots)
        or any(value != roots[0] for value in roots[1:])
    ):
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        )
    return roots[0]


def _binding_facts(binding: object) -> Tuple[str, int, int, int, str]:
    try:
        facts = (
            _binding_root(binding),
            getattr(binding, "filesystem_device"),
            getattr(binding, "filesystem_inode"),
            getattr(binding, "owner_uid"),
            getattr(binding, "project_authority_id"),
        )
    except ProjectMutationLeaseError:
        raise
    except BaseException as error:
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        ) from error
    if (
        any(type(value) is not int or value < 0 for value in facts[1:4])
        or type(facts[4]) is not str
    ):
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        )
    return facts


def _expected_facts(
    binding: ValidatedProjectMutationBinding,
) -> Tuple[str, int, int, int, str]:
    return (
        binding.canonical_root,
        binding.filesystem_device,
        binding.filesystem_inode,
        binding.owner_uid,
        binding.project_authority_id,
    )


def _validated_binding_for_authority(
    lease: object,
    project_authority_id: str,
) -> ValidatedProjectMutationBinding:
    """Project the immutable binding for an exact Authority under a live lease."""

    state = _state_for_live_token(lease)
    if (
        type(project_authority_id) is not str
        or project_authority_id != state.binding.project_authority_id
    ):
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        )
    return state.binding


def _borrow_validated_root(lease: object, binding: object) -> int:
    """Borrow the exact retained root fd after full lease/binding validation."""

    state = _state_for_live_token(lease)
    if _binding_facts(binding) != _expected_facts(state.binding):
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_mismatch"
        )
    return state.root_fd


@contextmanager
def hold_project_mutation_lease(
    binding: ValidatedProjectMutationBinding,
) -> Iterator[ProjectMutationLease]:
    """Hold the exact project-root writer lease for one local mutation unit."""

    if not isinstance(binding, ValidatedProjectMutationBinding):
        raise ProjectMutationLeaseError(
            "project_mutation_lease.binding_invalid"
        )

    try:
        descriptors, snapshots, links = _open_path_chain(binding.canonical_root)
    except OSError as error:
        raise ProjectMutationLeaseError(
            "project_mutation_lease.root_binding_conflict"
        ) from error

    locked = False
    lease = None
    state = None
    operation_error: Optional[BaseException] = None
    try:
        root_metadata = os.fstat(descriptors[-1])
        if (
            root_metadata.st_dev != binding.filesystem_device
            or root_metadata.st_ino != binding.filesystem_inode
            or root_metadata.st_uid != binding.owner_uid
            or binding.owner_uid != os.getuid()
            or not stat.S_ISDIR(root_metadata.st_mode)
            or bool(stat.S_IMODE(root_metadata.st_mode) & 0o022)
        ):
            raise ProjectMutationLeaseError(
                "project_mutation_lease.root_binding_conflict"
            )
        try:
            fcntl.flock(descriptors[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                raise ProjectMutationLeaseError(
                    "project_mutation_lease.writer_busy",
                    state_status="reconciliation_required",
                ) from error
            raise

        state = _LeaseState(
            binding=binding,
            owner_pid=os.getpid(),
            descriptors=descriptors,
            snapshots=snapshots,
            links=links,
        )
        _validate_named_path(state)
        lease = ProjectMutationLease(_TOKEN_SEAL)
        _LEASE_STATES[lease] = state
        try:
            yield lease
        finally:
            try:
                _validate_named_path(state)
            finally:
                state.active = False
    except BaseException as error:
        operation_error = error
        raise
    finally:
        first_cleanup_error: Optional[OSError] = None
        if locked:
            try:
                fcntl.flock(descriptors[-1], fcntl.LOCK_UN)
            except OSError as error:
                first_cleanup_error = error
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if first_cleanup_error is None:
                    first_cleanup_error = error
        if first_cleanup_error is not None and operation_error is None:
            raise first_cleanup_error
