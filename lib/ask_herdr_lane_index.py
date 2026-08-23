"""Private Lane-anchored project Lane Index.

Lane History remains authoritative.  This module owns only the durable,
path-free projection needed to discover and authenticate current Lane heads;
it grants no turn, effect, retry, query, or content authority.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
import re
import stat
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ask_herdr_darwin_capsule import (
    CommitDisposition,
    commit_exclusive,
    fullsync_file,
    probe_capability,
)
from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_project_mutation_lease import ValidatedProjectMutationBinding


STORE_NAME = ".ask-herdr-lane-index"
LANE_STORE_NAME = ".ask-herdr-lanes"
LAYOUT_NAME = "layout.json"
BINDING_NAME = "binding.json"
TRANSACTIONS_NAME = "transactions"
INTENT_NAME = "intent.json"
TRANSITION_NAME = "transition.json"
MAX_RECORD_BYTES = 1024 * 1024

DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
TRANSITION_PATTERN = re.compile(r"transition\.([0-9]{16})\.txn")
CANDIDATE_PATTERN = re.compile(
    r"candidate\.lane-index\."
    r"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.g"
    r"([1-9][0-9]*)\.([0-9a-f]{64})\.tmp"
)
BOOTSTRAP_PREFIX = ".ask-herdr-lane-index.bootstrap."


class LaneIndexFailpoint(RuntimeError):
    """Test-only interruption at one Lane Index durability boundary."""


class LaneIndexError(RuntimeError):
    """Typed, non-authorizing Lane Index failure."""

    resend_allowed = False
    effect_authority = "none"

    def __init__(self, detail_code: str, *, state_status: str) -> None:
        if state_status not in {"reconciliation_required", "quarantined"}:
            raise ValueError("lane_index.state_status_invalid")
        super().__init__(detail_code)
        self.detail_code = detail_code
        self.state_status = state_status


class _IntegrityError(RuntimeError):
    def __init__(self, code: str, *, quarantine: bool = True) -> None:
        super().__init__(code)
        self.code = code
        self.quarantine = quarantine


@dataclass(frozen=True)
class LaneIndexEntry:
    """Path-free current head of one indexed Lane Generation."""

    lane_id: str
    lane_generation: int
    lane_binding_digest: str
    event_sequence: int
    event_digest: str
    state_digest: str
    response_digest: Optional[str]


@dataclass(frozen=True)
class LaneIndexInspection:
    """Tagged read-only projection of the complete Lane Index."""

    status: str
    detail_code: str
    lane_index_digest: Optional[str] = None
    entries: Tuple[LaneIndexEntry, ...] = ()


@dataclass(frozen=True)
class _PreparedTransition:
    candidate_name: str
    intent: Dict[str, Any]
    intent_digest: str


@dataclass
class _Handles:
    root: int
    store: int
    transactions: int
    binding_digest: str


@dataclass(frozen=True)
class _IndexState:
    records: Tuple[Dict[str, Any], ...]
    projections: Tuple[Dict[str, Any], ...]
    intents: Tuple[str, ...]
    lane_index_digest: str
    candidates: Tuple[str, ...]
    candidate_intent: Optional[Dict[str, Any]]
    candidate_transition: Optional[Dict[str, Any]]
    candidate_intent_present: bool
    candidate_transition_present: bool


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _digest_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest_json(payload: Dict[str, Any]) -> str:
    return _digest_bytes(canonical_json(payload))


def _snapshot_binding(
    binding: ValidatedProjectMutationBinding,
) -> ValidatedProjectMutationBinding:
    if type(binding) is not ValidatedProjectMutationBinding:
        raise LaneIndexError(
            "lane_index.binding_invalid",
            state_status="quarantined",
        )
    try:
        return ValidatedProjectMutationBinding(**dict(vars(binding)))
    except (AttributeError, TypeError, ValueError) as error:
        raise LaneIndexError(
            "lane_index.binding_invalid",
            state_status="quarantined",
        ) from error


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


def _safe_project_root(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and not bool(stat.S_IMODE(metadata.st_mode) & 0o022)
    )


@contextmanager
def _open_root(
    binding: ValidatedProjectMutationBinding,
) -> Iterator[int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors: List[int] = []
    snapshots: List[os.stat_result] = []
    links: List[Tuple[int, str, int]] = []
    operation_error: Optional[BaseException] = None
    try:
        current = os.open(os.path.sep, flags)
        descriptors.append(current)
        snapshots.append(os.fstat(current))
        components = filter(
            None,
            binding.canonical_root.split(os.path.sep)[1:],
        )
        for component in components:
            parent = current
            current = os.open(component, flags, dir_fd=parent)
            descriptors.append(current)
            snapshots.append(os.fstat(current))
            links.append((parent, component, current))
        root = os.fstat(current)
        if (
            root.st_dev != binding.filesystem_device
            or root.st_ino != binding.filesystem_inode
            or root.st_uid != binding.owner_uid
            or binding.owner_uid != os.getuid()
            or not _safe_project_root(root)
        ):
            raise _IntegrityError("lane_index.root_binding_conflict")
        yield current
        for descriptor, snapshot in zip(descriptors, snapshots):
            if _identity(os.fstat(descriptor)) != _identity(snapshot):
                raise _IntegrityError("lane_index.root_changed", quarantine=False)
        for parent, component, child in links:
            named = os.stat(component, dir_fd=parent, follow_symlinks=False)
            if _identity(named) != _identity(os.fstat(child)):
                raise _IntegrityError("lane_index.root_changed", quarantine=False)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        first_error: Optional[OSError] = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None and operation_error is None:
            raise first_error


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
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if _identity(named) != _identity(opened) or not _private_directory(opened):
            raise _IntegrityError("lane_index.directory_integrity")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _mkdir_new_open(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    return _open_directory(parent, name)


def _directory_binding(parent: int, name: str, child: int) -> bool:
    try:
        return _identity(
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        ) == _identity(os.fstat(child))
    except OSError:
        return False


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
                raise OSError("lane_index.write_failed")
            view = view[written:]
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
        raise _IntegrityError("lane_index.file_integrity")
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
            raise _IntegrityError("lane_index.file_changed")
        remaining = before.st_size
        chunks: List[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise _IntegrityError("lane_index.file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _IntegrityError("lane_index.file_grew")
        after_fd = os.fstat(descriptor)
        after_name = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(after_fd) != _file_identity(opened)
            or _file_identity(after_name) != _file_identity(opened)
        ):
            raise _IntegrityError("lane_index.file_changed")
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
        raise _IntegrityError("lane_index.json_invalid") from error
    if payload != canonical_json(parsed) + b"\n":
        raise _IntegrityError("lane_index.json_not_canonical")
    return parsed, payload


def _repair_strict_prefix_file(
    parent: int,
    name: str,
    expected: bytes,
) -> None:
    """Repair only an absent or exact strict-prefix candidate file."""

    try:
        actual = _read_file(parent, name)
    except FileNotFoundError:
        _write_new(parent, name, expected)
        return
    if actual == expected:
        return
    if len(actual) < len(expected) and expected.startswith(actual):
        os.unlink(name, dir_fd=parent)
        _sync_directory(parent)
        _write_new(parent, name, expected)
        return
    raise _IntegrityError("lane_index.candidate_changed")


class _IncompleteJsonPrefix(Exception):
    pass


def _canonical_json_prefix_possible(payload: bytes) -> bool:
    """Recognize a syntactically possible whitespace-free JSON prefix."""

    length = len(payload)

    def string(index: int) -> int:
        index += 1
        while index < length:
            byte = payload[index]
            if byte == ord('"'):
                return index + 1
            if byte == ord("\\"):
                index += 1
                if index >= length:
                    raise _IncompleteJsonPrefix
                escaped = payload[index]
                if escaped == ord("u"):
                    for _ in range(4):
                        index += 1
                        if index >= length:
                            raise _IncompleteJsonPrefix
                        if payload[index] not in b"0123456789abcdefABCDEF":
                            raise ValueError
                elif escaped not in b'"\\/bfnrt':
                    raise ValueError
            elif byte < 0x20:
                raise ValueError
            index += 1
        raise _IncompleteJsonPrefix

    def literal(index: int, expected: bytes) -> int:
        remaining = payload[index : index + len(expected)]
        if expected.startswith(remaining):
            if len(remaining) < len(expected):
                raise _IncompleteJsonPrefix
            return index + len(expected)
        raise ValueError

    def number(index: int) -> int:
        if payload[index] == ord("-"):
            index += 1
            if index >= length:
                raise _IncompleteJsonPrefix
        if payload[index] == ord("0"):
            index += 1
        elif payload[index] in b"123456789":
            index += 1
            while index < length and payload[index] in b"0123456789":
                index += 1
        else:
            raise ValueError
        if index < length and payload[index] == ord("."):
            index += 1
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] not in b"0123456789":
                raise ValueError
            while index < length and payload[index] in b"0123456789":
                index += 1
        if index < length and payload[index] in b"eE":
            index += 1
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] in b"+-":
                index += 1
                if index >= length:
                    raise _IncompleteJsonPrefix
            if payload[index] not in b"0123456789":
                raise ValueError
            while index < length and payload[index] in b"0123456789":
                index += 1
        return index

    def value(index: int, depth: int) -> int:
        if depth > 8:
            raise ValueError
        if index >= length:
            raise _IncompleteJsonPrefix
        byte = payload[index]
        if byte == ord('"'):
            return string(index)
        if byte == ord("{"):
            return object_value(index, depth + 1)
        if byte == ord("["):
            return array_value(index, depth + 1)
        if byte == ord("t"):
            return literal(index, b"true")
        if byte == ord("f"):
            return literal(index, b"false")
        if byte == ord("n"):
            return literal(index, b"null")
        if byte == ord("-") or byte in b"0123456789":
            return number(index)
        raise ValueError

    def object_value(index: int, depth: int) -> int:
        index += 1
        if index >= length:
            raise _IncompleteJsonPrefix
        if payload[index] == ord("}"):
            return index + 1
        while True:
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] != ord('"'):
                raise ValueError
            index = string(index)
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] != ord(":"):
                raise ValueError
            index = value(index + 1, depth)
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] == ord("}"):
                return index + 1
            if payload[index] != ord(","):
                raise ValueError
            index += 1

    def array_value(index: int, depth: int) -> int:
        index += 1
        if index >= length:
            raise _IncompleteJsonPrefix
        if payload[index] == ord("]"):
            return index + 1
        while True:
            index = value(index, depth)
            if index >= length:
                raise _IncompleteJsonPrefix
            if payload[index] == ord("]"):
                return index + 1
            if payload[index] != ord(","):
                raise ValueError
            index += 1

    try:
        return value(0, 0) == length
    except _IncompleteJsonPrefix:
        return True
    except (IndexError, ValueError):
        return False


def _possible_intent_prefix(payload: bytes) -> bool:
    fixed = b'{"authoritative_response_digest":'
    return (
        fixed.startswith(payload)
        if len(payload) <= len(fixed)
        else payload.startswith(fixed)
        and _canonical_json_prefix_possible(payload)
    )


def _possible_transition_prefix(payload: bytes) -> bool:
    fixed = b'{"index_sequence":'
    return (
        fixed.startswith(payload)
        if len(payload) <= len(fixed)
        else payload.startswith(fixed)
        and _canonical_json_prefix_possible(payload)
    )


def _read_exact_or_strict_prefix(
    parent: int,
    name: str,
    expected: bytes,
) -> bool:
    """Return whether a managed file is complete; reject impossible residue."""

    payload = _read_file(parent, name)
    if payload == expected:
        return True
    if len(payload) < len(expected) and expected.startswith(payload):
        return False
    raise _IntegrityError("lane_index.bootstrap_conflict")


def _validate_bootstrap_candidate(
    root: int,
    binding: ValidatedProjectMutationBinding,
    name: str,
) -> None:
    """Read-only validation of the one deterministic bootstrap prefix."""

    candidate = _open_directory(root, name)
    transactions = -1
    try:
        entries = set(os.listdir(candidate))
        if entries - {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError("lane_index.bootstrap_conflict")
        if LAYOUT_NAME not in entries:
            if entries:
                raise _IntegrityError("lane_index.bootstrap_conflict")
            return
        layout_complete = _read_exact_or_strict_prefix(
            candidate,
            LAYOUT_NAME,
            canonical_json(_layout_payload()) + b"\n",
        )
        if not layout_complete:
            if entries != {LAYOUT_NAME}:
                raise _IntegrityError("lane_index.bootstrap_conflict")
            return
        if TRANSACTIONS_NAME not in entries:
            if entries != {LAYOUT_NAME}:
                raise _IntegrityError("lane_index.bootstrap_conflict")
            return
        transactions = _open_directory(candidate, TRANSACTIONS_NAME)
        if os.listdir(transactions):
            raise _IntegrityError("lane_index.bootstrap_conflict")
        if BINDING_NAME in entries:
            expected_binding = _binding_payload(
                binding,
                os.fstat(candidate),
                os.fstat(transactions),
            )
            _read_exact_or_strict_prefix(
                candidate,
                BINDING_NAME,
                canonical_json(expected_binding) + b"\n",
            )
        if (
            not _directory_binding(root, name, candidate)
            or not _directory_binding(
                candidate,
                TRANSACTIONS_NAME,
                transactions,
            )
        ):
            raise _IntegrityError("lane_index.bootstrap_conflict")
    except (OSError, StrictJsonError, ValueError) as error:
        raise _IntegrityError("lane_index.bootstrap_conflict") from error
    finally:
        if transactions >= 0:
            os.close(transactions)
        os.close(candidate)


def _sync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _fullsync_bound_file(parent: int, name: str) -> None:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(opened) != _file_identity(named)
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
        ):
            raise _IntegrityError("lane_index.file_changed")
        fullsync_file(descriptor)
    finally:
        os.close(descriptor)


def _trip(failpoint: Any, point: str) -> None:
    if failpoint == point:
        raise LaneIndexFailpoint(point)
    if callable(failpoint):
        failpoint(point)


def _layout_payload() -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_index_layout.internal.v1",
        "storage_protocol": "exclusive_transition_capsules",
    }


def _binding_unsigned(
    binding: ValidatedProjectMutationBinding,
    store: os.stat_result,
    transactions: os.stat_result,
) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_index_binding.internal.v1",
        "project_authority_id": binding.project_authority_id,
        "filesystem_device": binding.filesystem_device,
        "filesystem_inode": binding.filesystem_inode,
        "owner_uid": binding.owner_uid,
        "lane_index_store_device": store.st_dev,
        "lane_index_store_inode": store.st_ino,
        "lane_index_store_owner_uid": store.st_uid,
        "transactions_device": transactions.st_dev,
        "transactions_inode": transactions.st_ino,
        "transactions_owner_uid": transactions.st_uid,
    }


def _binding_payload(
    binding: ValidatedProjectMutationBinding,
    store: os.stat_result,
    transactions: os.stat_result,
) -> Dict[str, Any]:
    payload = _binding_unsigned(binding, store, transactions)
    payload["binding_digest"] = _digest_json(payload)
    return payload


def _bootstrap_name(binding: ValidatedProjectMutationBinding) -> str:
    token = hashlib.sha256(
        canonical_json(
            {
                "schema": "ask_herdr.lane_index_bootstrap_name.internal.v1",
                "project_authority_id": binding.project_authority_id,
                "filesystem_device": binding.filesystem_device,
                "filesystem_inode": binding.filesystem_inode,
                "owner_uid": binding.owner_uid,
            }
        )
    ).hexdigest()[:32]
    return BOOTSTRAP_PREFIX + token + ".tmp"


def _bootstrap_root_entries(root: int) -> Tuple[str, ...]:
    return tuple(
        sorted(name for name in os.listdir(root) if name.startswith(BOOTSTRAP_PREFIX))
    )


def _close_handles(handles: _Handles) -> None:
    first: Optional[OSError] = None
    for descriptor in (handles.transactions, handles.store):
        try:
            os.close(descriptor)
        except OSError as error:
            if first is None:
                first = error
    if first is not None:
        raise first


def _close_handles_preserving_primary(
    handles: _Handles,
    operation_error: Optional[BaseException],
) -> None:
    try:
        _close_handles(handles)
    except OSError:
        if operation_error is None:
            raise


def _handles_bound(handles: _Handles) -> bool:
    return (
        set(os.listdir(handles.store))
        == {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}
        and _directory_binding(handles.root, STORE_NAME, handles.store)
        and _directory_binding(
            handles.store,
            TRANSACTIONS_NAME,
            handles.transactions,
        )
    )


def _barrier_store(
    handles: _Handles,
    binding: ValidatedProjectMutationBinding,
) -> None:
    """Restore the immutable store envelope and parent durability barriers."""

    _fullsync_bound_file(handles.store, LAYOUT_NAME)
    _fullsync_bound_file(handles.store, BINDING_NAME)
    _sync_directory(handles.transactions)
    _sync_directory(handles.store)
    _sync_directory(handles.root)
    stored, _ = _read_json(handles.store, BINDING_NAME)
    expected = _binding_payload(
        binding,
        os.fstat(handles.store),
        os.fstat(handles.transactions),
    )
    if (
        _read_json(handles.store, LAYOUT_NAME)[0] != _layout_payload()
        or stored != expected
        or not _handles_bound(handles)
    ):
        raise _IntegrityError("lane_index.store_changed", quarantine=False)


def _open_store(
    root: int,
    binding: ValidatedProjectMutationBinding,
) -> Optional[_Handles]:
    try:
        store = _open_directory(root, STORE_NAME)
    except FileNotFoundError:
        return None
    transactions = -1
    try:
        if _bootstrap_root_entries(root):
            raise _IntegrityError("lane_index.bootstrap_conflict")
        if set(os.listdir(store)) != {
            LAYOUT_NAME,
            BINDING_NAME,
            TRANSACTIONS_NAME,
        }:
            raise _IntegrityError("lane_index.layout_invalid")
        layout, _ = _read_json(store, LAYOUT_NAME)
        if layout != _layout_payload():
            raise _IntegrityError("lane_index.layout_invalid")
        transactions = _open_directory(store, TRANSACTIONS_NAME)
        stored, _ = _read_json(store, BINDING_NAME)
        expected = _binding_payload(
            binding,
            os.fstat(store),
            os.fstat(transactions),
        )
        if stored != expected:
            raise _IntegrityError("lane_index.binding_conflict")
        if (
            not _directory_binding(root, STORE_NAME, store)
            or not _directory_binding(
                store,
                TRANSACTIONS_NAME,
                transactions,
            )
        ):
            raise _IntegrityError("lane_index.store_changed", quarantine=False)
        return _Handles(
            root=root,
            store=store,
            transactions=transactions,
            binding_digest=stored["binding_digest"],
        )
    except BaseException:
        if transactions >= 0:
            os.close(transactions)
        os.close(store)
        raise


def _ensure_store(
    root: int,
    binding: ValidatedProjectMutationBinding,
    *,
    failpoint: Any = None,
) -> _Handles:
    handles = _open_store(root, binding)
    if handles is not None:
        _barrier_store(handles, binding)
        return handles
    try:
        if probe_capability(root) is not True:
            raise _IntegrityError(
                "lane_index.durability_not_supported",
                quarantine=False,
            )
    except (OSError, ValueError) as error:
        raise _IntegrityError(
            "lane_index.durability_not_supported",
            quarantine=False,
        ) from error
    candidate_name = _bootstrap_name(binding)
    bootstrap_entries = _bootstrap_root_entries(root)
    if bootstrap_entries not in ((), (candidate_name,)):
        raise _IntegrityError("lane_index.bootstrap_conflict")
    try:
        candidate = _open_directory(root, candidate_name)
    except FileNotFoundError:
        candidate = _mkdir_new_open(root, candidate_name)
    transactions = -1
    try:
        entries = set(os.listdir(candidate))
        if entries - {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}:
            raise _IntegrityError("lane_index.bootstrap_conflict")
        expected_layout_bytes = canonical_json(_layout_payload()) + b"\n"
        _repair_strict_prefix_file(
            candidate,
            LAYOUT_NAME,
            expected_layout_bytes,
        )
        if _read_json(candidate, LAYOUT_NAME)[0] != _layout_payload():
            raise _IntegrityError("lane_index.bootstrap_conflict")
        if TRANSACTIONS_NAME not in entries:
            transactions = _mkdir_new_open(candidate, TRANSACTIONS_NAME)
        else:
            transactions = _open_directory(candidate, TRANSACTIONS_NAME)
        if os.listdir(transactions):
            raise _IntegrityError("lane_index.bootstrap_conflict")
        expected_binding = _binding_payload(
            binding,
            os.fstat(candidate),
            os.fstat(transactions),
        )
        expected_binding_bytes = canonical_json(expected_binding) + b"\n"
        _repair_strict_prefix_file(
            candidate,
            BINDING_NAME,
            expected_binding_bytes,
        )
        if _read_json(candidate, BINDING_NAME)[0] != expected_binding:
            raise _IntegrityError("lane_index.bootstrap_conflict")
        _sync_directory(transactions)
        _sync_directory(candidate)
        _trip(failpoint, "before_lane_index_bootstrap_promote")
        if (
            not _directory_binding(root, candidate_name, candidate)
            or not _directory_binding(
                candidate,
                TRANSACTIONS_NAME,
                transactions,
            )
            or set(os.listdir(candidate))
            != {LAYOUT_NAME, BINDING_NAME, TRANSACTIONS_NAME}
            or os.listdir(transactions)
            or _read_json(candidate, LAYOUT_NAME)[0] != _layout_payload()
            or _read_json(candidate, BINDING_NAME)[0] != expected_binding
        ):
            raise _IntegrityError("lane_index.bootstrap_changed")
        disposition = commit_exclusive(root, candidate_name, STORE_NAME)
        if disposition is CommitDisposition.OCCUPIED:
            raise _IntegrityError("lane_index.bootstrap_occupied")
        _trip(failpoint, "after_lane_index_bootstrap_promote")
        _sync_directory(root)
    finally:
        if transactions >= 0:
            os.close(transactions)
        os.close(candidate)
    handles = _open_store(root, binding)
    if handles is None:
        raise _IntegrityError("lane_index.bootstrap_unverified")
    _barrier_store(handles, binding)
    return handles


def _projection_unsigned(projection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.lane_head_projection.internal.v1",
        "project_authority_id": projection["project_authority_id"],
        "lane_id": projection["lane_id"],
        "lane_generation": projection["lane_generation"],
        "lane_binding_digest": projection["lane_binding_digest"],
        "event_head_sequence": projection["event_head_sequence"],
        "event_head_record_digest": projection["event_head_record_digest"],
        "lane_state_digest": projection["lane_state_digest"],
        "authoritative_response_digest": projection[
            "authoritative_response_digest"
        ],
    }


def _projection_digest(projection: Dict[str, Any]) -> str:
    return _digest_json(_projection_unsigned(projection))


def _index_digest(
    authority_id: str,
    projections: Tuple[Dict[str, Any], ...],
) -> str:
    return _digest_json(
        {
            "schema": "ask_herdr.lane_index_state.internal.v1",
            "project_authority_id": authority_id,
            "entries": list(projections),
        }
    )


def _intent_plan(
    *,
    authority_id: str,
    previous_lane_index_digest: str,
    previous_projection_digest: Optional[str],
    lane_id: str,
    lane_generation: int,
    lane_binding_digest: str,
    event_sequence: int,
    state_digest: str,
    response_digest: Optional[str],
) -> Dict[str, Any]:
    payload = {
        "schema": "ask_herdr.lane_index_transition_plan.internal.v1",
        "project_authority_id": authority_id,
        "previous_lane_index_digest": previous_lane_index_digest,
        "previous_projection_digest": previous_projection_digest,
        "lane_id": lane_id,
        "lane_generation": lane_generation,
        "lane_binding_digest": lane_binding_digest,
        "event_head_sequence": event_sequence,
        "lane_state_digest": state_digest,
        "authoritative_response_digest": response_digest,
    }
    payload["transition_plan_digest"] = _digest_json(payload)
    return payload


def _intent_payload(
    *,
    candidate_device: int,
    candidate_inode: int,
    candidate_owner_uid: int,
    **kwargs: Any,
) -> Dict[str, Any]:
    plan = _intent_plan(**kwargs)
    payload = {
        "schema": "ask_herdr.lane_index_transition_intent.internal.v1",
        **{
            key: value
            for key, value in plan.items()
            if key != "schema"
        },
        "candidate_device": candidate_device,
        "candidate_inode": candidate_inode,
        "candidate_owner_uid": candidate_owner_uid,
    }
    payload["intent_digest"] = _digest_json(payload)
    return payload


def _candidate_name(intent: Dict[str, Any]) -> str:
    return "candidate.lane-index.{}.g{}.{}.tmp".format(
        intent["lane_id"],
        intent["lane_generation"],
        intent["transition_plan_digest"].removeprefix("sha256:"),
    )


def _transition_slot(sequence: int) -> str:
    return "transition.{:016d}.txn".format(sequence)


def _validate_intent(payload: Dict[str, Any]) -> None:
    required = {
        "schema",
        "project_authority_id",
        "previous_lane_index_digest",
        "previous_projection_digest",
        "lane_id",
        "lane_generation",
        "lane_binding_digest",
        "event_head_sequence",
        "lane_state_digest",
        "authoritative_response_digest",
        "transition_plan_digest",
        "candidate_device",
        "candidate_inode",
        "candidate_owner_uid",
        "intent_digest",
    }
    if set(payload) != required:
        raise _IntegrityError("lane_index.intent_invalid")
    digest = payload.get("intent_digest")
    unsigned = dict(payload)
    unsigned.pop("intent_digest", None)
    plan = _intent_plan(
        authority_id=payload.get("project_authority_id"),
        previous_lane_index_digest=payload.get("previous_lane_index_digest"),
        previous_projection_digest=payload.get("previous_projection_digest"),
        lane_id=payload.get("lane_id"),
        lane_generation=payload.get("lane_generation"),
        lane_binding_digest=payload.get("lane_binding_digest"),
        event_sequence=payload.get("event_head_sequence"),
        state_digest=payload.get("lane_state_digest"),
        response_digest=payload.get("authoritative_response_digest"),
    )
    if (
        payload.get("schema")
        != "ask_herdr.lane_index_transition_intent.internal.v1"
        or not _matches(UUID4_PATTERN, payload.get("project_authority_id"))
        or not _matches(UUID4_PATTERN, payload.get("lane_id"))
        or type(payload.get("lane_generation")) is not int
        or payload["lane_generation"] < 1
        or type(payload.get("event_head_sequence")) is not int
        or payload["event_head_sequence"] < 1
        or not _matches(DIGEST_PATTERN, payload.get("previous_lane_index_digest"))
        or (
            payload.get("previous_projection_digest") is not None
            and not _matches(
                DIGEST_PATTERN,
                payload.get("previous_projection_digest"),
            )
        )
        or not _matches(DIGEST_PATTERN, payload.get("lane_binding_digest"))
        or not _matches(DIGEST_PATTERN, payload.get("lane_state_digest"))
        or (
            payload.get("authoritative_response_digest") is not None
            and not _matches(
                DIGEST_PATTERN,
                payload.get("authoritative_response_digest"),
            )
        )
        or not _matches(
            DIGEST_PATTERN,
            payload.get("transition_plan_digest"),
        )
        or payload.get("transition_plan_digest")
        != plan["transition_plan_digest"]
        or any(
            type(payload.get(field)) is not int
            or payload[field] < 0
            for field in (
                "candidate_device",
                "candidate_inode",
                "candidate_owner_uid",
            )
        )
        or not _matches(DIGEST_PATTERN, digest)
        or _digest_json(unsigned) != digest
    ):
        raise _IntegrityError("lane_index.intent_invalid")


def _intent_matches_capsule(
    intent: Dict[str, Any],
    metadata: os.stat_result,
) -> bool:
    return (
        intent.get("candidate_device") == metadata.st_dev
        and intent.get("candidate_inode") == metadata.st_ino
        and intent.get("candidate_owner_uid") == metadata.st_uid
    )


def _validate_projection(projection: Dict[str, Any]) -> None:
    required = {
        "project_authority_id",
        "lane_id",
        "lane_generation",
        "lane_binding_digest",
        "event_head_sequence",
        "event_head_record_digest",
        "lane_state_digest",
        "authoritative_response_digest",
        "projection_digest",
    }
    if (
        set(projection) != required
        or not _matches(UUID4_PATTERN, projection.get("project_authority_id"))
        or not _matches(UUID4_PATTERN, projection.get("lane_id"))
        or type(projection.get("lane_generation")) is not int
        or projection["lane_generation"] < 1
        or type(projection.get("event_head_sequence")) is not int
        or projection["event_head_sequence"] < 1
        or any(
            not _matches(DIGEST_PATTERN, projection.get(field))
            for field in (
                "lane_binding_digest",
                "event_head_record_digest",
                "lane_state_digest",
                "projection_digest",
            )
        )
        or (
            projection.get("authoritative_response_digest") is not None
            and not _matches(
                DIGEST_PATTERN,
                projection.get("authoritative_response_digest"),
            )
        )
        or _projection_digest(projection) != projection["projection_digest"]
    ):
        raise _IntegrityError("lane_index.projection_invalid")


def _validate_pending_transition(
    payload: Dict[str, Any],
    intent: Dict[str, Any],
    binding: ValidatedProjectMutationBinding,
) -> None:
    required = {
        "schema",
        "project_authority_id",
        "index_sequence",
        "previous_index_record_digest",
        "transition_intent_digest",
        "lane_head_projection",
        "resulting_lane_index_digest",
        "record_digest",
    }
    if set(payload) != required:
        raise _IntegrityError("lane_index.candidate_changed")
    projection = payload.get("lane_head_projection")
    if type(projection) is not dict:
        raise _IntegrityError("lane_index.candidate_changed")
    try:
        _validate_projection(projection)
    except _IntegrityError as error:
        raise _IntegrityError("lane_index.candidate_changed") from error
    index_sequence = payload.get("index_sequence")
    previous_record_digest = payload.get("previous_index_record_digest")
    unsigned = dict(payload)
    record_digest = unsigned.pop("record_digest", None)
    if (
        payload.get("schema")
        != "ask_herdr.lane_index_transition.internal.v1"
        or payload.get("project_authority_id")
        != binding.project_authority_id
        or type(index_sequence) is not int
        or index_sequence < 1
        or (index_sequence == 1) != (previous_record_digest is None)
        or (
            previous_record_digest is not None
            and not _matches(DIGEST_PATTERN, previous_record_digest)
        )
        or payload.get("transition_intent_digest")
        != intent.get("intent_digest")
        or projection.get("project_authority_id")
        != binding.project_authority_id
        or projection.get("lane_id") != intent.get("lane_id")
        or projection.get("lane_generation")
        != intent.get("lane_generation")
        or projection.get("lane_binding_digest")
        != intent.get("lane_binding_digest")
        or projection.get("event_head_sequence")
        != intent.get("event_head_sequence")
        or projection.get("lane_state_digest")
        != intent.get("lane_state_digest")
        or projection.get("authoritative_response_digest")
        != intent.get("authoritative_response_digest")
        or not _matches(
            DIGEST_PATTERN,
            payload.get("resulting_lane_index_digest"),
        )
        or not _matches(DIGEST_PATTERN, record_digest)
        or _digest_json(unsigned) != record_digest
    ):
        raise _IntegrityError("lane_index.candidate_changed")


def _validate_candidate_against_index_state(
    *,
    binding: ValidatedProjectMutationBinding,
    records: Tuple[Dict[str, Any], ...],
    projections: Tuple[Dict[str, Any], ...],
    lane_index_digest: str,
    intent: Dict[str, Any],
    transition: Optional[Dict[str, Any]],
) -> None:
    """Authenticate a complete candidate against its committed predecessor."""

    mapping = {
        (item["lane_id"], item["lane_generation"]): item
        for item in projections
    }
    key = (intent["lane_id"], intent["lane_generation"])
    previous = mapping.get(key)
    expected_intent = _intent_payload(
        authority_id=binding.project_authority_id,
        previous_lane_index_digest=lane_index_digest,
        previous_projection_digest=(
            previous["projection_digest"] if previous is not None else None
        ),
        lane_id=intent["lane_id"],
        lane_generation=intent["lane_generation"],
        lane_binding_digest=intent["lane_binding_digest"],
        event_sequence=intent["event_head_sequence"],
        state_digest=intent["lane_state_digest"],
        response_digest=intent["authoritative_response_digest"],
        candidate_device=intent["candidate_device"],
        candidate_inode=intent["candidate_inode"],
        candidate_owner_uid=intent["candidate_owner_uid"],
    )
    if intent != expected_intent:
        raise _IntegrityError("lane_index.candidate_changed")
    if transition is None:
        return
    projection = transition["lane_head_projection"]
    updated = dict(mapping)
    updated[key] = projection
    expected_resulting_digest = _index_digest(
        binding.project_authority_id,
        _sorted_projections(updated),
    )
    if (
        transition["index_sequence"] != len(records) + 1
        or transition["previous_index_record_digest"]
        != (records[-1]["record_digest"] if records else None)
        or transition["resulting_lane_index_digest"]
        != expected_resulting_digest
    ):
        raise _IntegrityError("lane_index.candidate_changed")


def _sorted_projections(
    mapping: Dict[Tuple[str, int], Dict[str, Any]],
) -> Tuple[Dict[str, Any], ...]:
    return tuple(mapping[key] for key in sorted(mapping))


def _scan(handles: _Handles, binding: ValidatedProjectMutationBinding) -> _IndexState:
    names = tuple(sorted(os.listdir(handles.transactions)))
    transitions: List[Tuple[int, str]] = []
    candidates: List[str] = []
    candidate_intents: Dict[str, Optional[Dict[str, Any]]] = {}
    candidate_transitions: Dict[str, Optional[Dict[str, Any]]] = {}
    candidate_intent_presence: Dict[str, bool] = {}
    candidate_transition_presence: Dict[str, bool] = {}
    namespace_bindings: Dict[str, Tuple[int, int, int, int, int]] = {}
    for name in names:
        transition = TRANSITION_PATTERN.fullmatch(name)
        candidate = CANDIDATE_PATTERN.fullmatch(name)
        if transition is not None:
            transitions.append((int(transition.group(1)), name))
        elif candidate is not None:
            descriptor = _open_directory(handles.transactions, name)
            try:
                descriptor_metadata = os.fstat(descriptor)
                namespace_bindings[name] = _identity(descriptor_metadata)
                entries = set(os.listdir(descriptor))
                parsed_intent: Optional[Dict[str, Any]] = None
                parsed_transition: Optional[Dict[str, Any]] = None
                if entries not in (
                    set(),
                    {INTENT_NAME},
                    {INTENT_NAME, TRANSITION_NAME},
                ):
                    raise _IntegrityError("lane_index.candidate_changed")
                if INTENT_NAME in entries:
                    payload = _read_file(descriptor, INTENT_NAME)
                    try:
                        parsed = parse_json_object(
                            payload[:-1] if payload.endswith(b"\n") else payload
                        )
                    except StrictJsonError:
                        if not _possible_intent_prefix(payload):
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                        if TRANSITION_NAME in entries:
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                    else:
                        if payload not in (
                            canonical_json(parsed),
                            canonical_json(parsed) + b"\n",
                        ):
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                        try:
                            _validate_intent(parsed)
                        except _IntegrityError as error:
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            ) from error
                        if (
                            _candidate_name(parsed) != name
                            or not _intent_matches_capsule(
                                parsed,
                                descriptor_metadata,
                            )
                        ):
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                        parsed_intent = parsed
                if TRANSITION_NAME in entries:
                    payload = _read_file(descriptor, TRANSITION_NAME)
                    try:
                        parsed_transition = parse_json_object(
                            payload[:-1]
                            if payload.endswith(b"\n")
                            else payload
                        )
                    except StrictJsonError:
                        if not _possible_transition_prefix(payload):
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                    else:
                        if payload not in (
                            canonical_json(parsed_transition),
                            canonical_json(parsed_transition) + b"\n",
                        ):
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                        if parsed_intent is None:
                            raise _IntegrityError(
                                "lane_index.candidate_changed"
                            )
                        _validate_pending_transition(
                            parsed_transition,
                            parsed_intent,
                            binding,
                        )
                if not _directory_binding(handles.transactions, name, descriptor):
                    raise _IntegrityError("lane_index.candidate_changed")
            finally:
                os.close(descriptor)
            candidates.append(name)
            candidate_intents[name] = parsed_intent
            candidate_transitions[name] = parsed_transition
            candidate_intent_presence[name] = INTENT_NAME in entries
            candidate_transition_presence[name] = TRANSITION_NAME in entries
        else:
            raise _IntegrityError("lane_index.unknown_transaction_entry")
    if len(candidates) > 1:
        raise _IntegrityError("lane_index.candidate_conflict")
    transitions.sort()
    records: List[Dict[str, Any]] = []
    projections: Dict[Tuple[str, int], Dict[str, Any]] = {}
    intents: Dict[Tuple[str, int], str] = {}
    previous_record_digest: Optional[str] = None
    current_digest = _index_digest(binding.project_authority_id, ())
    for expected, (sequence, name) in enumerate(transitions, start=1):
        if sequence != expected:
            raise _IntegrityError("lane_index.sequence_gap")
        capsule = _open_directory(handles.transactions, name)
        try:
            capsule_metadata = os.fstat(capsule)
            namespace_bindings[name] = _identity(capsule_metadata)
            if set(os.listdir(capsule)) != {INTENT_NAME, TRANSITION_NAME}:
                raise _IntegrityError("lane_index.transition_capsule_invalid")
            intent, _ = _read_json(capsule, INTENT_NAME)
            transition, _ = _read_json(capsule, TRANSITION_NAME)
            if not _directory_binding(handles.transactions, name, capsule):
                raise _IntegrityError("lane_index.transition_changed")
        finally:
            os.close(capsule)
        _validate_intent(intent)
        if not _intent_matches_capsule(intent, capsule_metadata):
            raise _IntegrityError("lane_index.transition_changed")
        projection = transition.get("lane_head_projection")
        if type(projection) is not dict:
            raise _IntegrityError("lane_index.transition_invalid")
        _validate_projection(projection)
        if projection["project_authority_id"] != binding.project_authority_id:
            raise _IntegrityError("lane_index.projection_invalid")
        required = {
            "schema",
            "project_authority_id",
            "index_sequence",
            "previous_index_record_digest",
            "transition_intent_digest",
            "lane_head_projection",
            "resulting_lane_index_digest",
            "record_digest",
        }
        unsigned = dict(transition)
        record_digest = unsigned.pop("record_digest", None)
        key = (projection["lane_id"], projection["lane_generation"])
        prior = projections.get(key)
        expected_intent = _intent_payload(
            authority_id=binding.project_authority_id,
            previous_lane_index_digest=current_digest,
            previous_projection_digest=(
                prior["projection_digest"] if prior is not None else None
            ),
            lane_id=projection["lane_id"],
            lane_generation=projection["lane_generation"],
            lane_binding_digest=projection["lane_binding_digest"],
            event_sequence=projection["event_head_sequence"],
            state_digest=projection["lane_state_digest"],
            response_digest=projection["authoritative_response_digest"],
            candidate_device=capsule_metadata.st_dev,
            candidate_inode=capsule_metadata.st_ino,
            candidate_owner_uid=capsule_metadata.st_uid,
        )
        updated = dict(projections)
        updated[key] = projection
        resulting = _index_digest(
            binding.project_authority_id,
            _sorted_projections(updated),
        )
        if (
            set(transition) != required
            or transition.get("schema")
            != "ask_herdr.lane_index_transition.internal.v1"
            or transition.get("project_authority_id")
            != binding.project_authority_id
            or transition.get("index_sequence") != expected
            or transition.get("previous_index_record_digest")
            != previous_record_digest
            or transition.get("transition_intent_digest")
            != intent.get("intent_digest")
            or intent != expected_intent
            or transition.get("resulting_lane_index_digest") != resulting
            or not _matches(DIGEST_PATTERN, record_digest)
            or _digest_json(unsigned) != record_digest
        ):
            raise _IntegrityError("lane_index.transition_invalid")
        records.append(transition)
        projections = updated
        intents[key] = intent["intent_digest"]
        previous_record_digest = record_digest
        current_digest = resulting
    sorted_candidates = tuple(sorted(candidates))
    candidate_intent = (
        candidate_intents[sorted_candidates[0]]
        if len(sorted_candidates) == 1
        else None
    )
    candidate_transition = (
        candidate_transitions[sorted_candidates[0]]
        if len(sorted_candidates) == 1
        else None
    )
    candidate_intent_present = (
        candidate_intent_presence[sorted_candidates[0]]
        if len(sorted_candidates) == 1
        else False
    )
    candidate_transition_present = (
        candidate_transition_presence[sorted_candidates[0]]
        if len(sorted_candidates) == 1
        else False
    )
    if candidate_intent is not None:
        _validate_candidate_against_index_state(
            binding=binding,
            records=tuple(records),
            projections=_sorted_projections(projections),
            lane_index_digest=current_digest,
            intent=candidate_intent,
            transition=candidate_transition,
        )
    if tuple(sorted(os.listdir(handles.transactions))) != names:
        raise _IntegrityError("lane_index.transaction_namespace_changed")
    for name, expected_identity in namespace_bindings.items():
        if _identity(
            os.stat(name, dir_fd=handles.transactions, follow_symlinks=False)
        ) != expected_identity:
            raise _IntegrityError("lane_index.transition_changed")
    if not _handles_bound(handles):
        raise _IntegrityError("lane_index.store_changed", quarantine=False)
    return _IndexState(
        records=tuple(records),
        projections=_sorted_projections(projections),
        intents=tuple(intents[key] for key in sorted(intents)),
        lane_index_digest=current_digest,
        candidates=sorted_candidates,
        candidate_intent=candidate_intent,
        candidate_transition=candidate_transition,
        candidate_intent_present=candidate_intent_present,
        candidate_transition_present=candidate_transition_present,
    )


def _lane_binding_to_project(binding: Any) -> ValidatedProjectMutationBinding:
    try:
        return ValidatedProjectMutationBinding(
            canonical_root=binding.canonical_root,
            filesystem_device=binding.filesystem_device,
            filesystem_inode=binding.filesystem_inode,
            owner_uid=binding.owner_uid,
            project_authority_id=binding.project_authority_id,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise LaneIndexError(
            "lane_index.lane_binding_invalid",
            state_status="quarantined",
        ) from error


def _current_projection_for_lane(
    state: _IndexState,
    lane_id: str,
    lane_generation: int,
) -> Optional[Dict[str, Any]]:
    for projection in state.projections:
        if (
            projection["lane_id"] == lane_id
            and projection["lane_generation"] == lane_generation
        ):
            return projection
    return None


def _prepare_lane_index_transition_under_root(
    root: int,
    lane_binding: Any,
    *,
    previous_event_sequence: Optional[int],
    previous_event_digest: Optional[str],
    previous_state_digest: Optional[str],
    previous_response_digest: Optional[str],
    previous_index_intent_digest: Optional[str],
    next_event_sequence: int,
    next_state_digest: str,
    next_response_digest: Optional[str],
    failpoint: Any = None,
) -> _PreparedTransition:
    """Prepare the exact non-authorizing transition before a Lane commit."""

    binding = _lane_binding_to_project(lane_binding)
    handles: Optional[_Handles] = None
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_store(root, binding)
        if handles is None:
            if previous_event_sequence is not None:
                raise LaneIndexError(
                    (
                        "lane_index.store_missing"
                        if previous_index_intent_digest is not None
                        else "lane_index.migration_required"
                    ),
                    state_status=(
                        "quarantined"
                        if previous_index_intent_digest is not None
                        else "reconciliation_required"
                    ),
                )
            handles = _ensure_store(root, binding, failpoint=failpoint)
        else:
            _barrier_store(handles, binding)
        state = _scan(handles, binding)
        current = _current_projection_for_lane(
            state,
            lane_binding.lane_id,
            lane_binding.lane_generation,
        )
        if current is None:
            if any(
                value is not None
                for value in (
                    previous_event_sequence,
                    previous_event_digest,
                    previous_state_digest,
                    previous_response_digest,
                )
            ):
                raise LaneIndexError(
                    (
                        "lane_index.index_omission"
                        if previous_index_intent_digest is not None
                        else "lane_index.migration_required"
                    ),
                    state_status=(
                        "quarantined"
                        if previous_index_intent_digest is not None
                        else "reconciliation_required"
                    ),
                )
        else:
            expected_previous = (
                current["event_head_sequence"],
                current["event_head_record_digest"],
                current["lane_state_digest"],
                current["authoritative_response_digest"],
            )
            if expected_previous != (
                previous_event_sequence,
                previous_event_digest,
                previous_state_digest,
                previous_response_digest,
            ):
                raise LaneIndexError(
                    "lane_index.predecessor_mismatch",
                    state_status="quarantined",
                )
        intent_fields = dict(
            authority_id=binding.project_authority_id,
            previous_lane_index_digest=state.lane_index_digest,
            previous_projection_digest=(
                current["projection_digest"] if current is not None else None
            ),
            lane_id=lane_binding.lane_id,
            lane_generation=lane_binding.lane_generation,
            lane_binding_digest=lane_binding.lane_binding_digest,
            event_sequence=next_event_sequence,
            state_digest=next_state_digest,
            response_digest=next_response_digest,
        )
        plan = _intent_plan(**intent_fields)
        name = _candidate_name(plan)
        if state.candidates:
            if state.candidates != (name,):
                raise LaneIndexError(
                    "lane_index.pending_transition",
                    state_status="reconciliation_required",
                )
            candidate = _open_directory(handles.transactions, name)
            try:
                candidate_metadata = os.fstat(candidate)
                intent = _intent_payload(
                    candidate_device=candidate_metadata.st_dev,
                    candidate_inode=candidate_metadata.st_ino,
                    candidate_owner_uid=candidate_metadata.st_uid,
                    **intent_fields,
                )
                entries = set(os.listdir(candidate))
                if entries not in (
                    set(),
                    {INTENT_NAME},
                    {INTENT_NAME, TRANSITION_NAME},
                ):
                    raise _IntegrityError("lane_index.candidate_changed")
                if TRANSITION_NAME in entries:
                    raise _IntegrityError("lane_index.candidate_changed")
                expected_intent_bytes = canonical_json(intent) + b"\n"
                _repair_strict_prefix_file(
                    candidate,
                    INTENT_NAME,
                    expected_intent_bytes,
                )
                _sync_directory(candidate)
                if not _directory_binding(
                    handles.transactions,
                    name,
                    candidate,
                ):
                    raise _IntegrityError("lane_index.candidate_changed")
            finally:
                os.close(candidate)
            _sync_directory(handles.transactions)
            return _PreparedTransition(name, intent, intent["intent_digest"])
        candidate = _mkdir_new_open(handles.transactions, name)
        try:
            candidate_metadata = os.fstat(candidate)
            intent = _intent_payload(
                candidate_device=candidate_metadata.st_dev,
                candidate_inode=candidate_metadata.st_ino,
                candidate_owner_uid=candidate_metadata.st_uid,
                **intent_fields,
            )
            _trip(failpoint, "after_lane_index_candidate_create")
            _write_new(candidate, INTENT_NAME, canonical_json(intent) + b"\n")
            _sync_directory(candidate)
            if (
                _read_json(candidate, INTENT_NAME)[0] != intent
                or not _directory_binding(handles.transactions, name, candidate)
            ):
                raise _IntegrityError("lane_index.candidate_changed")
        finally:
            os.close(candidate)
        _sync_directory(handles.transactions)
        return _PreparedTransition(name, intent, intent["intent_digest"])
    except LaneIndexError as error:
        operation_error = error
        raise
    except _IntegrityError as error:
        operation_error = error
        raise LaneIndexError(
            error.code,
            state_status=(
                "quarantined" if error.quarantine else "reconciliation_required"
            ),
        ) from error
    except (OSError, StrictJsonError, ValueError) as error:
        operation_error = error
        raise LaneIndexError(
            "lane_index.storage_integrity_failure",
            state_status="quarantined",
        ) from error
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if handles is not None:
            _close_handles_preserving_primary(handles, operation_error)


def _transition_from_lane_record(
    binding: ValidatedProjectMutationBinding,
    state: _IndexState,
    intent: Dict[str, Any],
    lane_record: Dict[str, Any],
) -> Dict[str, Any]:
    if (
        lane_record.get("project_authority_id") != binding.project_authority_id
        or lane_record.get("lane_id") != intent["lane_id"]
        or lane_record.get("lane_generation") != intent["lane_generation"]
        or lane_record.get("lane_binding_digest")
        != intent["lane_binding_digest"]
        or lane_record.get("event_sequence")
        != intent["event_head_sequence"]
        or lane_record.get("state_after_digest") != intent["lane_state_digest"]
        or lane_record.get("lane_index_transition_intent_digest")
        != intent["intent_digest"]
        or not _matches(DIGEST_PATTERN, lane_record.get("record_digest"))
    ):
        raise _IntegrityError("lane_index.lane_record_mismatch")
    projection = {
        "project_authority_id": binding.project_authority_id,
        "lane_id": intent["lane_id"],
        "lane_generation": intent["lane_generation"],
        "lane_binding_digest": intent["lane_binding_digest"],
        "event_head_sequence": intent["event_head_sequence"],
        "event_head_record_digest": lane_record["record_digest"],
        "lane_state_digest": intent["lane_state_digest"],
        "authoritative_response_digest": intent[
            "authoritative_response_digest"
        ],
    }
    projection["projection_digest"] = _projection_digest(projection)
    current = _current_projection_for_lane(
        state,
        projection["lane_id"],
        projection["lane_generation"],
    )
    expected_intent = _intent_payload(
        authority_id=binding.project_authority_id,
        previous_lane_index_digest=state.lane_index_digest,
        previous_projection_digest=(
            current["projection_digest"] if current is not None else None
        ),
        lane_id=projection["lane_id"],
        lane_generation=projection["lane_generation"],
        lane_binding_digest=projection["lane_binding_digest"],
        event_sequence=projection["event_head_sequence"],
        state_digest=projection["lane_state_digest"],
        response_digest=projection["authoritative_response_digest"],
        candidate_device=intent["candidate_device"],
        candidate_inode=intent["candidate_inode"],
        candidate_owner_uid=intent["candidate_owner_uid"],
    )
    if intent != expected_intent:
        raise _IntegrityError("lane_index.predecessor_mismatch")
    mapping = {
        (item["lane_id"], item["lane_generation"]): item
        for item in state.projections
    }
    mapping[(projection["lane_id"], projection["lane_generation"])] = projection
    resulting_digest = _index_digest(
        binding.project_authority_id,
        _sorted_projections(mapping),
    )
    transition = {
        "schema": "ask_herdr.lane_index_transition.internal.v1",
        "project_authority_id": binding.project_authority_id,
        "index_sequence": len(state.records) + 1,
        "previous_index_record_digest": (
            state.records[-1]["record_digest"] if state.records else None
        ),
        "transition_intent_digest": intent["intent_digest"],
        "lane_head_projection": projection,
        "resulting_lane_index_digest": resulting_digest,
    }
    transition["record_digest"] = _digest_json(transition)
    return transition


def _barrier_existing_transition(
    handles: _Handles,
    transition: Dict[str, Any],
) -> None:
    """Restore durability and reauthenticate one committed transition."""

    slot = _transition_slot(transition["index_sequence"])
    capsule = _open_directory(handles.transactions, slot)
    try:
        capsule_metadata = os.fstat(capsule)
        if set(os.listdir(capsule)) != {INTENT_NAME, TRANSITION_NAME}:
            raise _IntegrityError("lane_index.transition_capsule_invalid")
        intent, _ = _read_json(capsule, INTENT_NAME)
        stored, _ = _read_json(capsule, TRANSITION_NAME)
        _validate_intent(intent)
        if (
            stored != transition
            or intent.get("intent_digest")
            != transition.get("transition_intent_digest")
            or not _intent_matches_capsule(intent, capsule_metadata)
            or not _directory_binding(handles.transactions, slot, capsule)
        ):
            raise _IntegrityError("lane_index.transition_changed")
        _fullsync_bound_file(capsule, INTENT_NAME)
        _fullsync_bound_file(capsule, TRANSITION_NAME)
        _sync_directory(capsule)
        _sync_directory(handles.transactions)
        if (
            _read_json(capsule, INTENT_NAME)[0] != intent
            or _read_json(capsule, TRANSITION_NAME)[0] != transition
            or not _directory_binding(handles.transactions, slot, capsule)
            or not _directory_binding(handles.root, STORE_NAME, handles.store)
            or not _directory_binding(
                handles.store,
                TRANSACTIONS_NAME,
                handles.transactions,
            )
        ):
            raise _IntegrityError("lane_index.transition_changed")
    finally:
        os.close(capsule)


def _finalize_lane_index_transition_under_root(
    root: int,
    lane_binding: Any,
    lane_record: Dict[str, Any],
    *,
    failpoint: Any = None,
    allow_pending_successor: bool = False,
) -> None:
    """Promote or exactly replay the transition anchored by a Lane record."""

    binding = _lane_binding_to_project(lane_binding)
    intent_digest = lane_record.get("lane_index_transition_intent_digest")
    if intent_digest is None:
        return
    if not _matches(DIGEST_PATTERN, intent_digest):
        raise LaneIndexError(
            "lane_index.intent_invalid",
            state_status="quarantined",
        )
    handles: Optional[_Handles] = None
    operation_error: Optional[BaseException] = None
    try:
        handles = _open_store(root, binding)
        if handles is None:
            raise _IntegrityError("lane_index.store_missing")
        state = _scan(handles, binding)
        historical_matches = tuple(
            transition
            for transition in state.records
            if transition.get("lane_head_projection", {}).get(
                "event_head_record_digest"
            )
            == lane_record.get("record_digest")
        )
        if historical_matches:
            if state.candidates:
                candidate_match = CANDIDATE_PATTERN.fullmatch(
                    state.candidates[0]
                )
                if (
                    candidate_match is None
                    or candidate_match.group(1) != lane_binding.lane_id
                    or int(candidate_match.group(2))
                    != lane_binding.lane_generation
                ):
                    raise _IntegrityError("lane_index.candidate_changed")
                if (
                    allow_pending_successor
                    and state.candidate_transition_present
                ):
                    raise _IntegrityError("lane_index.candidate_changed")
                if not allow_pending_successor:
                    raise _IntegrityError(
                        "lane_index.pending_transition",
                        quarantine=False,
                    )
            if (
                len(historical_matches) != 1
                or historical_matches[0].get("transition_intent_digest")
                != intent_digest
            ):
                raise _IntegrityError("lane_index.exact_replay_conflict")
            _barrier_existing_transition(handles, historical_matches[0])
            return
        current = _current_projection_for_lane(
            state,
            lane_binding.lane_id,
            lane_binding.lane_generation,
        )
        if (
            current is not None
            and current["event_head_record_digest"]
            == lane_record.get("record_digest")
        ):
            key_order = [
                (item["lane_id"], item["lane_generation"])
                for item in state.projections
            ]
            key = (lane_binding.lane_id, lane_binding.lane_generation)
            intent_by_key = dict(zip(key_order, state.intents))
            if intent_by_key.get(key) != intent_digest:
                raise _IntegrityError("lane_index.exact_replay_conflict")
            matching = tuple(
                transition
                for transition in state.records
                if transition.get("lane_head_projection", {}).get(
                    "event_head_record_digest"
                )
                == lane_record.get("record_digest")
            )
            if len(matching) != 1:
                raise _IntegrityError("lane_index.exact_replay_conflict")
            _barrier_existing_transition(handles, matching[0])
            return
        if len(state.candidates) != 1:
            raise _IntegrityError("lane_index.pending_transition_missing")
        candidate_name = state.candidates[0]
        candidate = _open_directory(handles.transactions, candidate_name)
        try:
            candidate_metadata = os.fstat(candidate)
            entries = set(os.listdir(candidate))
            if entries not in ({INTENT_NAME}, {INTENT_NAME, TRANSITION_NAME}):
                raise _IntegrityError("lane_index.candidate_changed")
            intent, _ = _read_json(candidate, INTENT_NAME)
            _validate_intent(intent)
            if (
                intent.get("intent_digest") != intent_digest
                or _candidate_name(intent) != candidate_name
                or not _intent_matches_capsule(intent, candidate_metadata)
            ):
                raise _IntegrityError("lane_index.candidate_changed")
            transition = _transition_from_lane_record(
                binding,
                state,
                intent,
                lane_record,
            )
            expected_bytes = canonical_json(transition) + b"\n"
            _repair_strict_prefix_file(
                candidate,
                TRANSITION_NAME,
                expected_bytes,
            )
            actual, actual_bytes = _read_json(candidate, TRANSITION_NAME)
            if actual != transition or actual_bytes != expected_bytes:
                raise _IntegrityError("lane_index.candidate_changed")
            _sync_directory(candidate)
            if not _directory_binding(
                handles.transactions,
                candidate_name,
                candidate,
            ):
                raise _IntegrityError("lane_index.candidate_changed")
            _trip(failpoint, "before_lane_index_transition_promote")
            if (
                not _handles_bound(handles)
                or not _directory_binding(
                    handles.transactions,
                    candidate_name,
                    candidate,
                )
            ):
                raise _IntegrityError("lane_index.store_changed")
            slot = _transition_slot(transition["index_sequence"])
            disposition = commit_exclusive(
                handles.transactions,
                candidate_name,
                slot,
            )
            if disposition is CommitDisposition.OCCUPIED:
                raise _IntegrityError("lane_index.transition_slot_occupied")
            _trip(failpoint, "after_lane_index_transition_promote")
            _fullsync_bound_file(candidate, INTENT_NAME)
            _fullsync_bound_file(candidate, TRANSITION_NAME)
            _sync_directory(candidate)
            _sync_directory(handles.transactions)
            if not _handles_bound(handles):
                raise _IntegrityError("lane_index.store_changed")
        finally:
            os.close(candidate)
        verified = _scan(handles, binding)
        exact = _current_projection_for_lane(
            verified,
            lane_binding.lane_id,
            lane_binding.lane_generation,
        )
        if (
            verified.candidates
            or exact is None
            or exact["event_head_record_digest"]
            != lane_record.get("record_digest")
        ):
            raise _IntegrityError("lane_index.publication_unverified")
    except LaneIndexError as error:
        operation_error = error
        raise
    except _IntegrityError as error:
        operation_error = error
        raise LaneIndexError(
            error.code,
            state_status=(
                "quarantined" if error.quarantine else "reconciliation_required"
            ),
        ) from error
    except (OSError, StrictJsonError, ValueError) as error:
        operation_error = error
        raise LaneIndexError(
            "lane_index.storage_integrity_failure",
            state_status="quarantined",
        ) from error
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if handles is not None:
            _close_handles_preserving_primary(handles, operation_error)


def _entry_from_projection(projection: Dict[str, Any]) -> LaneIndexEntry:
    return LaneIndexEntry(
        lane_id=projection["lane_id"],
        lane_generation=projection["lane_generation"],
        lane_binding_digest=projection["lane_binding_digest"],
        event_sequence=projection["event_head_sequence"],
        event_digest=projection["event_head_record_digest"],
        state_digest=projection["lane_state_digest"],
        response_digest=projection["authoritative_response_digest"],
    )


def _inactive(status: str, detail_code: str) -> LaneIndexInspection:
    return LaneIndexInspection(status=status, detail_code=detail_code)


def inspect_lane_index(
    binding: ValidatedProjectMutationBinding,
) -> LaneIndexInspection:
    """Read and authenticate the complete project Lane Index without mutation."""

    try:
        snapshot = _snapshot_binding(binding)
        with _open_root(snapshot) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return _inactive(
                    "reconciliation_required",
                    "lane_index.writer_active",
                )
            from ask_herdr_lane_store import (  # noqa: PLC0415
                ValidatedLaneGenerationBinding,
                _authenticate_lane_index_entry_from_root,
                _authenticate_pending_lane_index_transition_from_root,
                _inspect_lane_index_generation_membership_from_root,
            )
            generation_membership = (
                _inspect_lane_index_generation_membership_from_root(
                    root,
                    snapshot,
                )
            )
            if generation_membership.status == "quarantined":
                return _inactive(
                    "quarantined",
                    generation_membership.detail_code,
                )
            handles = _open_store(root, snapshot)
            if handles is None:
                bootstrap_entries = _bootstrap_root_entries(root)
                if bootstrap_entries:
                    if bootstrap_entries != (_bootstrap_name(snapshot),):
                        return _inactive(
                            "quarantined",
                            "lane_index.bootstrap_conflict",
                        )
                    if generation_membership.status == "absent":
                        return _inactive(
                            "quarantined",
                            "lane_index.bootstrap_conflict",
                        )
                    _validate_bootstrap_candidate(
                        root,
                        snapshot,
                        bootstrap_entries[0],
                    )
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.bootstrap_pending",
                    )
                if generation_membership.status == "absent":
                    return _inactive("absent", "lane_index.absent")
                return _inactive(
                    "reconciliation_required",
                    (
                        generation_membership.detail_code
                        if generation_membership.status
                        == "reconciliation_required"
                        else "lane_index.migration_required"
                    ),
                )
            operation_error: Optional[BaseException] = None
            try:
                state = _scan(handles, snapshot)
                if generation_membership.status == "absent":
                    return _inactive(
                        "quarantined",
                        "lane_index.generation_membership_conflict",
                    )
                if generation_membership.detail_code == (
                    "lane_index.migration_required"
                ):
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.migration_required",
                    )
                for projection, intent_digest in zip(
                    state.projections,
                    state.intents,
                ):
                    lane_binding = ValidatedLaneGenerationBinding(
                        canonical_root=snapshot.canonical_root,
                        filesystem_device=snapshot.filesystem_device,
                        filesystem_inode=snapshot.filesystem_inode,
                        owner_uid=snapshot.owner_uid,
                        project_authority_id=snapshot.project_authority_id,
                        lane_id=projection["lane_id"],
                        lane_generation=projection["lane_generation"],
                        lane_binding_digest=projection[
                            "lane_binding_digest"
                        ],
                    )
                    candidate_is_for_projection = (
                        state.candidate_intent is not None
                        and state.candidate_intent.get("lane_id")
                        == projection["lane_id"]
                        and state.candidate_intent.get("lane_generation")
                        == projection["lane_generation"]
                    )
                    if candidate_is_for_projection:
                        lane_status, lane_detail = (
                            _authenticate_pending_lane_index_transition_from_root(
                                root,
                                lane_binding,
                                prior_event_sequence=projection[
                                    "event_head_sequence"
                                ],
                                prior_event_digest=projection[
                                    "event_head_record_digest"
                                ],
                                prior_state_digest=projection[
                                    "lane_state_digest"
                                ],
                                prior_response_digest=projection[
                                    "authoritative_response_digest"
                                ],
                                prior_intent_digest=intent_digest,
                                candidate_intent=state.candidate_intent,
                                candidate_transition=(
                                    state.candidate_transition
                                ),
                                candidate_transition_present=(
                                    state.candidate_transition_present
                                ),
                            )
                        )
                    else:
                        lane_status, lane_detail = (
                            _authenticate_lane_index_entry_from_root(
                                root,
                                lane_binding,
                                event_sequence=projection[
                                    "event_head_sequence"
                                ],
                                event_digest=projection[
                                    "event_head_record_digest"
                                ],
                                state_digest=projection["lane_state_digest"],
                                response_digest=projection[
                                    "authoritative_response_digest"
                                ],
                                intent_digest=intent_digest,
                            )
                        )
                    if lane_status != "active":
                        return _inactive(lane_status, lane_detail)
                if state.candidate_intent is not None and not any(
                    item["lane_id"] == state.candidate_intent["lane_id"]
                    and item["lane_generation"]
                    == state.candidate_intent["lane_generation"]
                    for item in state.projections
                ):
                    candidate_lane_binding = ValidatedLaneGenerationBinding(
                        canonical_root=snapshot.canonical_root,
                        filesystem_device=snapshot.filesystem_device,
                        filesystem_inode=snapshot.filesystem_inode,
                        owner_uid=snapshot.owner_uid,
                        project_authority_id=snapshot.project_authority_id,
                        lane_id=state.candidate_intent["lane_id"],
                        lane_generation=state.candidate_intent[
                            "lane_generation"
                        ],
                        lane_binding_digest=state.candidate_intent[
                            "lane_binding_digest"
                        ],
                    )
                    lane_status, lane_detail = (
                        _authenticate_pending_lane_index_transition_from_root(
                            root,
                            candidate_lane_binding,
                            prior_event_sequence=None,
                            prior_event_digest=None,
                            prior_state_digest=None,
                            prior_response_digest=None,
                            prior_intent_digest=None,
                            candidate_intent=state.candidate_intent,
                            candidate_transition=state.candidate_transition,
                            candidate_transition_present=(
                                state.candidate_transition_present
                            ),
                        )
                    )
                    if lane_status != "active":
                        return _inactive(lane_status, lane_detail)
                generation_set = {
                    (
                        item.lane_id,
                        item.lane_generation,
                        item.lane_binding_digest,
                    )
                    for item in generation_membership.entries
                }
                if state.candidates:
                    candidate_match = CANDIDATE_PATTERN.fullmatch(
                        state.candidates[0]
                    )
                    if candidate_match is None:
                        return _inactive(
                            "quarantined",
                            "lane_index.candidate_changed",
                        )
                    candidate_lane = (
                        candidate_match.group(1),
                        int(candidate_match.group(2)),
                    )
                    generation_candidates = tuple(
                        item
                        for item in generation_set
                        if item[:2] == candidate_lane
                    )
                    if len(generation_candidates) != 1:
                        return _inactive(
                            "quarantined",
                            "lane_index.candidate_changed",
                        )
                    if (
                        state.candidate_intent is not None
                        and generation_candidates[0][2]
                        != state.candidate_intent["lane_binding_digest"]
                    ):
                        return _inactive(
                            "quarantined",
                            "lane_index.candidate_changed",
                        )
                    if generation_membership.status != "active":
                        return _inactive(
                            "reconciliation_required",
                            generation_membership.detail_code,
                        )
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.pending_transition",
                    )
                from ask_herdr_topology_store import (  # noqa: PLC0415
                    ValidatedTopologyStoreBinding,
                    _inspect_lane_index_membership_from_root,
                )
                topology_binding = ValidatedTopologyStoreBinding(
                    canonical_project_root=snapshot.canonical_root,
                    filesystem_device=snapshot.filesystem_device,
                    filesystem_inode=snapshot.filesystem_inode,
                    owner_uid=snapshot.owner_uid,
                    project_authority_id=snapshot.project_authority_id,
                    namespace="ask-pipeline",
                )
                membership = _inspect_lane_index_membership_from_root(
                    root,
                    topology_binding,
                )
                if membership.status == "quarantined":
                    return _inactive("quarantined", membership.detail_code)
                membership_is_complete = (
                    membership.status == "active"
                    or (
                        membership.status == "reconciliation_required"
                        and membership.detail_code
                        == "topology_store.unfinished_mutation"
                    )
                )
                if not membership_is_complete:
                    return _inactive(
                        "reconciliation_required",
                        membership.detail_code,
                    )
                indexed = tuple(
                    sorted(
                        (
                            item["lane_id"],
                            item["lane_generation"],
                            item["lane_binding_digest"],
                        )
                        for item in state.projections
                    )
                )
                anchored = tuple(
                    sorted(
                        (
                            item.lane_id,
                            item.lane_generation,
                            item.lane_binding_digest,
                        )
                        for item in membership.entries
                    )
                )
                indexed_set = set(indexed)
                anchored_set = set(anchored)
                if not anchored_set.issubset(indexed_set):
                    return _inactive(
                        "quarantined",
                        "lane_index.membership_conflict",
                    )
                if indexed_set != anchored_set:
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.membership_reconciliation_required",
                    )
                if not indexed_set.issubset(generation_set):
                    return _inactive(
                        "quarantined",
                        "lane_index.generation_membership_conflict",
                    )
                if indexed_set != generation_set:
                    return _inactive(
                        "reconciliation_required",
                        (
                            "lane_index."
                            "generation_membership_reconciliation_required"
                        ),
                    )
                if generation_membership.status != "active":
                    return _inactive(
                        "reconciliation_required",
                        generation_membership.detail_code,
                    )
                if state.candidates:
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.pending_transition",
                    )
                if set(os.listdir(handles.store)) != {
                    LAYOUT_NAME,
                    BINDING_NAME,
                    TRANSACTIONS_NAME,
                }:
                    return _inactive(
                        "quarantined",
                        "lane_index.layout_invalid",
                    )
                if (
                    not _directory_binding(root, STORE_NAME, handles.store)
                    or not _directory_binding(
                        handles.store,
                        TRANSACTIONS_NAME,
                        handles.transactions,
                    )
                ):
                    return _inactive(
                        "reconciliation_required",
                        "lane_index.store_changed",
                    )
                return LaneIndexInspection(
                    status="active",
                    detail_code="lane_index.active",
                    lane_index_digest=state.lane_index_digest,
                    entries=tuple(
                        _entry_from_projection(item)
                        for item in state.projections
                    ),
                )
            except BaseException as error:
                operation_error = error
                raise
            finally:
                _close_handles_preserving_primary(
                    handles,
                    operation_error,
                )
    except LaneIndexError as error:
        return _inactive(error.state_status, error.detail_code)
    except _IntegrityError as error:
        return _inactive(
            "quarantined" if error.quarantine else "reconciliation_required",
            error.code,
        )
    except (OSError, StrictJsonError, ValueError):
        return _inactive(
            "quarantined",
            "lane_index.storage_integrity_failure",
        )


__all__ = (
    "LaneIndexEntry",
    "LaneIndexInspection",
    "inspect_lane_index",
)
