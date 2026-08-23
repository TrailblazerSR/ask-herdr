"""Private, provider-free project Authority Store.

The two-function interface hides identifier generation, the genesis policy,
the on-disk layout, locking, durable activation, and integrity inspection.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import os
import re
import stat
import weakref
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_project_mutation_lease import ValidatedProjectMutationBinding


STORE_NAME = ".ask-herdr"
OBJECTS_NAME = "objects"
STAGING_NAME = "staging"
ACTIVE_NAME = "active.json"
MAX_RECORD_BYTES = 1024 * 1024
UUID4_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)


class AuthorityStoreFailpoint(RuntimeError):
    """A test-only injected interruption that leaves durable evidence intact."""


class _RootChangedError(OSError):
    pass


class _RootCleanupError(OSError):
    pass


@dataclass(frozen=True)
class ValidatedBootstrapReceipt:
    """Core-validated founding approval correlated to one exact genesis."""

    receipt_id: str
    operation_id: str
    canonical_request_digest: str
    canonical_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int
    confirmed_at: str


@dataclass(frozen=True)
class ConfirmedProjectGenesis:
    """Only core-established facts needed to found the first project lifetime."""

    canonical_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int
    operation_id: str
    canonical_request_digest: str
    bootstrap_receipt: ValidatedBootstrapReceipt
    lifetime: str


@dataclass(frozen=True)
class AuthorityStoreInspection:
    """One fail-closed, read-only projection of Authority Store state."""

    status: str
    detail_code: str
    authority_id: Optional[str] = None
    profile_id: Optional[str] = None
    ledger_id: Optional[str] = None
    operation_id: Optional[str] = None
    canonical_request_digest: Optional[str] = None
    genesis_digest: Optional[str] = None
    genesis_record_bytes: Optional[bytes] = None
    profile_digest: Optional[str] = None
    profile_record_bytes: Optional[bytes] = None
    head_sequence: Optional[int] = None
    head_digest: Optional[str] = None
    head_record_bytes: Optional[bytes] = None
    ledger_record_bytes: Tuple[bytes, ...] = ()
    store_identity: Optional[Tuple[int, int, int, int, int]] = None
    objects_identity: Optional[Tuple[int, int, int, int, int]] = None
    staging_identity: Optional[Tuple[int, int, int, int, int]] = None
    active_identity: Optional[Tuple[int, int, int, int, int, int, int]] = None
    object_identities: Tuple[
        Tuple[str, Tuple[int, int, int, int, int, int, int]],
        ...,
    ] = ()


@dataclass(frozen=True)
class AuthorityStoreHeadInspection:
    """Path-free immutable head metadata for one exact Project binding."""

    status: str
    detail_code: str
    authority_store_head_digest: Optional[str] = None


@dataclass(frozen=True)
class AuthorityStatusOperationEntry:
    """One promoted durable operation in the closed private status universe."""

    operation_id: str
    operation: str
    canonical_request_digest: str
    authority_record_digest: str
    lane_scope: str
    lane_id: Optional[str]
    lane_generation: Optional[int]


@dataclass(frozen=True)
class AuthorityStatusProjectionInspection:
    """Observation-only Authority head and promoted operation projection."""

    status: str
    detail_code: str
    authority_store_head_digest: Optional[str] = None
    operation_entries: Tuple[AuthorityStatusOperationEntry, ...] = ()


_AUTHORITY_STATUS_OPERATION_CACHE: Dict[
    int,
    Tuple[
        Any,
        Tuple[AuthorityStatusOperationEntry, ...],
    ],
] = {}


@dataclass(frozen=True)
class ProjectInitializationResult:
    """Typed initialization result; immutable record bytes support idempotency."""

    outcome_kind: str
    detail_code: str
    authority_id: Optional[str] = None
    profile_id: Optional[str] = None
    ledger_id: Optional[str] = None
    genesis_digest: Optional[str] = None
    genesis_record_bytes: Optional[bytes] = None


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _canonical_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("authority_store.clock_not_aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_canonical_timestamp(value: Any) -> datetime:
    """Parse the one exact UTC timestamp form used by durable records."""

    if not _matches(TIMESTAMP_PATTERN, value):
        raise ValueError("authority_store.timestamp_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError("authority_store.timestamp_invalid") from error
    if _canonical_timestamp(parsed) != value:
        raise ValueError("authority_store.timestamp_invalid")
    return parsed


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _private_file_identity(
    metadata: os.stat_result,
) -> Tuple[int, int, int, int, int, int, int]:
    """Identity plus link/size facts that must remain stable while reading."""

    return _identity(metadata) + (metadata.st_nlink, metadata.st_size)


@contextmanager
def _open_canonical_root(canonical_root: str) -> Iterator[int]:
    if (
        type(canonical_root) is not str
        or not canonical_root.startswith("/")
        or os.path.normpath(canonical_root) != canonical_root
        or os.path.realpath(canonical_root) != canonical_root
    ):
        raise ValueError("authority_store.root_not_canonical")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptors = []
    snapshots = []
    bindings = []
    primary_error: Optional[BaseException] = None
    try:
        try:
            current = os.open(os.path.sep, flags)
            descriptors.append(current)
            snapshots.append(os.fstat(current))
            for component in filter(None, canonical_root.split(os.path.sep)[1:]):
                parent = current
                current = os.open(component, flags, dir_fd=parent)
                descriptors.append(current)
                snapshots.append(os.fstat(current))
                bindings.append((parent, component, current))
            yield current
            for descriptor, snapshot in zip(descriptors, snapshots):
                if _identity(os.fstat(descriptor)) != _identity(snapshot):
                    raise _RootChangedError("authority_store.root_changed")
            for parent, component, child in bindings:
                bound = os.stat(component, dir_fd=parent, follow_symlinks=False)
                if _identity(bound) != _identity(os.fstat(child)):
                    raise _RootChangedError("authority_store.root_changed")
        except _RootChangedError:
            raise
        except OSError as error:
            if descriptors:
                raise _RootChangedError(
                    "authority_store.root_unobservable"
                ) from error
            raise
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_error = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None and primary_error is None:
            raise _RootCleanupError(
                "authority_store.root_cleanup_unverified"
            ) from cleanup_error


def _safe_directory_metadata(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _open_private_directory(parent: int, name: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent)
    try:
        bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if _identity(bound) != _identity(opened) or not (
            _safe_directory_metadata(opened)
        ):
            raise PermissionError("authority_store.directory_integrity")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return descriptor


def _directory_still_bound(parent: int, name: str, descriptor: int) -> bool:
    """Return whether one opened private directory still owns its exact name."""

    try:
        bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError:
        return False
    return _identity(bound) == _identity(opened) and _safe_directory_metadata(opened)


def _head_sources_still_bound(
    store: int,
    objects: int,
    inspection: AuthorityStoreInspection,
) -> bool:
    """Rebind the promoted-head sources used by one completed inspection."""

    if inspection.head_digest is None:
        return True
    if inspection.staging_identity is None or inspection.active_identity is None:
        return False
    try:
        staging = os.stat(
            STAGING_NAME,
            dir_fd=store,
            follow_symlinks=False,
        )
        active = os.stat(
            ACTIVE_NAME,
            dir_fd=store,
            follow_symlinks=False,
        )
        active_payload, _ = _read_private_json(store, ACTIVE_NAME)
        active_after = os.stat(
            ACTIVE_NAME,
            dir_fd=store,
            follow_symlinks=False,
        )
    except (OSError, StrictJsonError, ValueError):
        return False
    if (
        _identity(staging) != inspection.staging_identity
        or not _safe_directory_metadata(staging)
        or _private_file_identity(active) != inspection.active_identity
        or _private_file_identity(active_after) != inspection.active_identity
    ):
        return False
    expected_active = {
        "schema": "ask_herdr.authority_store_active.v1",
        "authority_id": inspection.authority_id,
        "profile_id": inspection.profile_id,
        "profile_digest": inspection.profile_digest,
        "ledger_id": inspection.ledger_id,
        "ledger_head_digest": inspection.head_digest,
        "operation_id": inspection.operation_id,
        "canonical_request_digest": inspection.canonical_request_digest,
        "profile_object": "policy.{}.json".format(inspection.profile_id),
        "genesis_object": "genesis.{}.json".format(inspection.ledger_id),
    }
    if active_payload != expected_active:
        return False
    try:
        expected_objects = {
            expected_active["profile_object"],
            expected_active["genesis_object"],
        }
        if (
            inspection.profile_record_bytes is None
            or inspection.genesis_record_bytes is None
        ):
            return False
        expected_object_bytes = {
            expected_active["profile_object"]: inspection.profile_record_bytes,
            expected_active["genesis_object"]: inspection.genesis_record_bytes,
        }
        parsed_records = []
        for record_bytes in inspection.ledger_record_bytes[1:]:
            record = parse_json_object(
                record_bytes[:-1]
                if record_bytes.endswith(b"\n")
                else record_bytes
            )
            parsed_records.append(record)
            object_name = _ledger_object_name(
                inspection.ledger_id,
                record["sequence"],
                record["record_digest"],
            )
            expected_objects.add(object_name)
            expected_object_bytes[object_name] = record_bytes
        if set(os.listdir(objects)) != expected_objects:
            return False
        object_identities = dict(inspection.object_identities)
        if (
            len(object_identities) != len(inspection.object_identities)
            or set(object_identities) != expected_objects
        ):
            return False
        for object_name in sorted(expected_objects):
            _, current_bytes, current_identity = _read_private_json_with_identity(
                objects,
                object_name,
            )
            if (
                current_identity != object_identities[object_name]
                or current_bytes != expected_object_bytes[object_name]
            ):
                return False
        staging_descriptor = _open_private_directory(store, STAGING_NAME)
        try:
            if _identity(os.fstat(staging_descriptor)) != (
                inspection.staging_identity
            ):
                return False
            staging_entries = set(os.listdir(staging_descriptor))
            if inspection.status == "active":
                return not staging_entries
            if (
                inspection.detail_code
                == "policy_ledger.stale_head_publication"
                and parsed_records
            ):
                stale = parsed_records[-1]
                operation_id = _record_owner_operation_id(stale)
                if operation_id is None:
                    return False
                expected_name = _pending_head_name(
                    operation_id,
                    stale["record_digest"],
                )
                if staging_entries != {expected_name}:
                    return False
                staged_active, _ = _read_private_json(
                    staging_descriptor,
                    expected_name,
                )
                return staged_active == expected_active
            if (
                inspection.detail_code == "policy_ledger.orphaned_record"
                and parsed_records
            ):
                orphan = parsed_records[-1]
                return (
                    not staging_entries
                    and orphan.get("previous_record_digest")
                    == inspection.head_digest
                    and orphan.get("sequence")
                    == (inspection.head_sequence or 0) + 1
                )
            if (
                inspection.detail_code
                != "policy_ledger.pending_head_publication"
                or not parsed_records
            ):
                return False
            pending = parsed_records[-1]
            operation_id = _record_owner_operation_id(pending)
            if operation_id is None:
                return False
            expected_name = _pending_head_name(
                operation_id,
                pending["record_digest"],
            )
            if staging_entries != {expected_name}:
                return False
            staged_active, _ = _read_private_json(
                staging_descriptor,
                expected_name,
            )
            expected_staged_active = dict(expected_active)
            expected_staged_active["ledger_head_digest"] = pending[
                "record_digest"
            ]
            return staged_active == expected_staged_active
        finally:
            os.close(staging_descriptor)
    except (OSError, PermissionError, StrictJsonError, ValueError, KeyError):
        return False


def _read_private_json(parent: int, name: str) -> Tuple[Dict[str, Any], bytes]:
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_RECORD_BYTES
    ):
        raise PermissionError("authority_store.file_integrity")
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        if _private_file_identity(opened) != _private_file_identity(metadata):
            raise PermissionError("authority_store.file_binding_changed")
        remaining = metadata.st_size
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise OSError("authority_store.file_truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("authority_store.file_grew")
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            _private_file_identity(after) != _private_file_identity(opened)
            or opened.st_nlink != 1
        ):
            raise PermissionError("authority_store.file_binding_changed")
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    parsed = parse_json_object(payload[:-1] if payload.endswith(b"\n") else payload)
    if payload != canonical_json(parsed) + b"\n":
        raise StrictJsonError("authority_store.json_not_canonical")
    return parsed, payload


def _read_private_json_with_identity(
    parent: int,
    name: str,
) -> Tuple[
    Dict[str, Any],
    bytes,
    Tuple[int, int, int, int, int, int, int],
]:
    """Read one immutable object and retain its exact final file identity."""

    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    parsed, payload = _read_private_json(parent, name)
    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if _private_file_identity(before) != _private_file_identity(after):
        raise PermissionError("authority_store.file_binding_changed")
    return parsed, payload, _private_file_identity(after)


def _digest(value: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _reconciliation(code: str) -> AuthorityStoreInspection:
    return AuthorityStoreInspection("reconciliation_required", code)


def _quarantine(code: str) -> AuthorityStoreInspection:
    return AuthorityStoreInspection("quarantined", code)


def _ledger_object_name(ledger_id: str, sequence: int, record_digest: str) -> str:
    """Return the one path-free immutable filename for an appended record."""

    return "ledger.{}.{}.{}.json".format(
        ledger_id,
        sequence,
        record_digest.removeprefix("sha256:"),
    )


def _pending_head_name(operation_id: str, record_digest: str) -> str:
    """Return the one staging filename for a not-yet-published ledger head."""

    return "head.{}.{}.json".format(
        operation_id,
        record_digest.removeprefix("sha256:"),
    )


def _validate_human_admission_record(
    record: Dict[str, Any],
    *,
    active: Dict[str, Any],
    profile: Dict[str, Any],
    sequence: int,
    previous_record_digest: str,
) -> bool:
    """Validate one complete direct-human ledger record without ambient facts."""

    required_record = {
        "schema",
        "ledger_id",
        "sequence",
        "previous_record_digest",
        "record_kind",
        "recorded_at",
        "active_policy",
        "operation",
        "policy_decision",
        "human_approval_receipt",
        "record_digest",
    }
    if (
        set(record) != required_record
        or record.get("schema") != "ask_herdr.policy_ledger_record.v1"
        or record.get("ledger_id") != active["ledger_id"]
        or record.get("sequence") != sequence
        or record.get("previous_record_digest") != previous_record_digest
        or record.get("record_kind") != "human_admission"
        or record.get("active_policy")
        != {
            "profile_id": active["profile_id"],
            "profile_digest": active["profile_digest"],
        }
    ):
        return False
    operation = record.get("operation")
    decision = record.get("policy_decision")
    receipt = record.get("human_approval_receipt")
    if (
        type(operation) is not dict
        or set(operation)
        != {
            "operation",
            "action_reason",
            "provider",
            "operation_id",
            "canonical_request_digest",
        }
        or type(decision) is not dict
        or set(decision)
        != {
            "decision_id",
            "decision",
            "automatic_budget_effects",
        }
        or type(receipt) is not dict
        or set(receipt)
        != {
            "schema",
            "receipt_id",
            "project_authority_id",
            "policy_profile_id",
            "operation",
            "action_reason",
            "provider",
            "operation_id",
            "canonical_request_digest",
            "confirmed_at",
            "expires_at",
            "consumption",
        }
    ):
        return False
    operation_name = operation.get("operation")
    action_reason = operation.get("action_reason")
    provider = operation.get("provider")
    enabled_reasons = profile.get("automatic_enablement", {}).get(
        "operation_reasons", {}
    )
    known_providers = profile.get("automatic_enablement", {}).get("providers", {})
    if (
        type(operation_name) is not str
        or type(action_reason) is not str
        or type(provider) is not str
        or action_reason not in enabled_reasons.get(operation_name, {})
        or provider not in known_providers
        or not _matches(UUID4_PATTERN, operation.get("operation_id"))
        or not _matches(
            DIGEST_PATTERN,
            operation.get("canonical_request_digest"),
        )
        or not _matches(UUID4_PATTERN, decision.get("decision_id"))
        or decision.get("decision") != "admitted"
        or decision.get("automatic_budget_effects")
        != [
            {
                "scope": "provider",
                "provider": provider,
                "budget_effect": "not_counted",
            },
            {"scope": "project", "budget_effect": "not_counted"},
        ]
        or receipt.get("schema") != "ask_herdr.human_approval_receipt.v1"
        or not _matches(UUID4_PATTERN, receipt.get("receipt_id"))
        or receipt.get("project_authority_id") != active["authority_id"]
        or receipt.get("policy_profile_id") != active["profile_id"]
        or receipt.get("consumption") != "consumed"
        or any(
            receipt.get(field) != operation.get(field)
            for field in (
                "operation",
                "action_reason",
                "provider",
                "operation_id",
                "canonical_request_digest",
            )
        )
    ):
        return False
    try:
        confirmed_at = _parse_canonical_timestamp(receipt.get("confirmed_at"))
        expires_at = _parse_canonical_timestamp(receipt.get("expires_at"))
        recorded_at = _parse_canonical_timestamp(record.get("recorded_at"))
    except ValueError:
        return False
    if not confirmed_at <= recorded_at <= expires_at:
        return False
    unsigned = dict(record)
    record_digest = unsigned.pop("record_digest", None)
    return _matches(DIGEST_PATTERN, record_digest) and _digest(unsigned) == record_digest


def _validate_recovery_operation_admission_record(
    record: Dict[str, Any],
    *,
    active: Dict[str, Any],
    profile: Dict[str, Any],
    sequence: int,
    previous_record_digest: str,
    canonical_root: str,
    filesystem_identity: Dict[str, int],
) -> bool:
    """Validate one provider-neutral Recovery Reconciliation authority record."""

    required_record = {
        "schema",
        "ledger_id",
        "sequence",
        "previous_record_digest",
        "record_kind",
        "recorded_at",
        "active_policy",
        "canonical_operation",
        "policy_decision",
        "human_approval_receipt",
        "record_digest",
    }
    if (
        set(record) != required_record
        or record.get("schema") != "ask_herdr.policy_ledger_record.v1"
        or record.get("ledger_id") != active["ledger_id"]
        or record.get("sequence") != sequence
        or record.get("previous_record_digest") != previous_record_digest
        or record.get("record_kind") != "recovery_operation_admission"
        or record.get("active_policy")
        != {
            "profile_id": active["profile_id"],
            "profile_digest": active["profile_digest"],
        }
    ):
        return False

    operation = record.get("canonical_operation")
    decision = record.get("policy_decision")
    receipt = record.get("human_approval_receipt")
    operation_keys = {
        "schema",
        "operation",
        "action_reason",
        "operation_id",
        "canonical_request_digest",
        "project",
        "recovery_scope_selector",
        "expected_recovery_state_digest",
        "current_recovery_state_digest",
        "canonical_projection",
        "current_preconditions",
    }
    receipt_keys = {
        "schema",
        "receipt_id",
        "project_authority_id",
        "policy_profile_id",
        "operation",
        "action_reason",
        "operation_id",
        "canonical_request_digest",
        "confirmation_challenge",
        "confirmed_at",
        "expires_at",
        "consumption",
    }
    if (
        type(operation) is not dict
        or set(operation) != operation_keys
        or type(decision) is not dict
        or set(decision)
        != {"decision_id", "decision", "automatic_budget_effects"}
        or type(receipt) is not dict
        or set(receipt) != receipt_keys
    ):
        return False

    projection = operation.get("canonical_projection")
    project = operation.get("project")
    selector = operation.get("recovery_scope_selector")
    preconditions = operation.get("current_preconditions")
    if (
        type(projection) is not dict
        or set(projection) != {"schema", "operation", "project", "payload"}
        or projection.get("schema")
        != "ask_herdr.canonical_request_projection.v1"
        or projection.get("operation") != "recovery.reconcile"
        or type(project) is not dict
        or set(project) != {"authority_id", "filesystem_identity"}
        or project.get("authority_id") != active["authority_id"]
        or project.get("filesystem_identity") != filesystem_identity
        or type(selector) is not dict
        or set(selector)
        != {"schema", "kind", "lane_id", "generation"}
        or selector.get("schema")
        != "ask_herdr.recovery_scope_selector.v1"
        or selector.get("kind") != "lane"
        or not _matches(UUID4_PATTERN, selector.get("lane_id"))
        or type(selector.get("generation")) is not int
        or selector.get("generation") < 1
        or type(preconditions) is not list
        or preconditions
        != [
            "recovery.expected_state_verified",
            "recovery.local_finalization_available",
            "recovery.scope_resolved",
        ]
    ):
        return False

    projection_project = projection.get("project")
    projection_payload = projection.get("payload")
    if (
        type(projection_project) is not dict
        or set(projection_project)
        != {
            "binding",
            "root",
            "authority_id",
            "filesystem_identity",
        }
        or projection_project.get("binding") != "bound"
        or projection_project.get("root") != canonical_root
        or projection_project.get("authority_id") != active["authority_id"]
        or projection_project.get("filesystem_identity") != filesystem_identity
        or type(projection_payload) is not dict
        or set(projection_payload)
        != {"selector", "expected_recovery_state_digest"}
        or projection_payload.get("selector") != selector
        or projection_payload.get("expected_recovery_state_digest")
        != operation.get("expected_recovery_state_digest")
        or operation.get("current_recovery_state_digest")
        != operation.get("expected_recovery_state_digest")
    ):
        return False

    request_digest = operation.get("canonical_request_digest")
    expected_challenge = (
        "approve " + request_digest.removeprefix("sha256:")[:12]
        if _matches(DIGEST_PATTERN, request_digest)
        else None
    )
    if (
        operation.get("schema")
        != "ask_herdr.canonical_operation_record.v1"
        or operation.get("operation") != "recovery.reconcile"
        or operation.get("action_reason") != "recover"
        or not _matches(UUID4_PATTERN, operation.get("operation_id"))
        or not _matches(DIGEST_PATTERN, request_digest)
        or "sha256:" + hashlib.sha256(canonical_json(projection)).hexdigest()
        != request_digest
        or not _matches(
            DIGEST_PATTERN,
            operation.get("expected_recovery_state_digest"),
        )
        or not _matches(UUID4_PATTERN, decision.get("decision_id"))
        or decision.get("decision") != "admitted"
        or decision.get("automatic_budget_effects")
        != [{"scope": "project", "budget_effect": "not_counted"}]
        or receipt.get("schema")
        != "ask_herdr.recovery_human_approval_receipt.v1"
        or not _matches(UUID4_PATTERN, receipt.get("receipt_id"))
        or receipt.get("project_authority_id") != active["authority_id"]
        or receipt.get("policy_profile_id") != active["profile_id"]
        or receipt.get("confirmation_challenge") != expected_challenge
        or receipt.get("consumption") != "consumed"
        or any(
            receipt.get(field) != operation.get(field)
            for field in (
                "operation",
                "action_reason",
                "operation_id",
                "canonical_request_digest",
            )
        )
    ):
        return False
    try:
        confirmed_at = _parse_canonical_timestamp(receipt.get("confirmed_at"))
        expires_at = _parse_canonical_timestamp(receipt.get("expires_at"))
        recorded_at = _parse_canonical_timestamp(record.get("recorded_at"))
    except ValueError:
        return False
    if not confirmed_at <= recorded_at < expires_at:
        return False
    unsigned = dict(record)
    record_digest = unsigned.pop("record_digest", None)
    return _matches(DIGEST_PATTERN, record_digest) and _digest(unsigned) == record_digest


def _valid_evidence_selection(value: Any) -> bool:
    """Validate the closed Evidence selection shared by access records."""

    if type(value) is not dict or value.get("schema") != (
        "ask_herdr.evidence_selection.v1"
    ):
        return False
    mode = value.get("mode")
    if mode == "whole":
        return set(value) == {"schema", "mode"}
    return (
        mode == "range"
        and set(value) == {"schema", "mode", "offset", "length"}
        and type(value.get("offset")) is int
        and value["offset"] >= 0
        and type(value.get("length")) is int
        and 1 <= value["length"] <= 1_048_576
    )


def _valid_human_content_access(value: Any) -> bool:
    """Validate the first human-only access-authority shape."""

    required = {
        "schema",
        "access_id",
        "authority_kind",
        "project_authority_id",
        "evidence_id",
        "expected_content_digest",
        "relationship_operation_id",
        "permitted_selection",
    }
    return (
        type(value) is dict
        and set(value) == required
        and value.get("schema")
        == "ask_herdr.evidence_content_access.v1"
        and value.get("authority_kind")
        == "human_content_access_receipt"
        and all(
            _matches(UUID4_PATTERN, value.get(field))
            for field in (
                "access_id",
                "project_authority_id",
                "evidence_id",
                "relationship_operation_id",
            )
        )
        and _matches(DIGEST_PATTERN, value.get("expected_content_digest"))
        and _valid_evidence_selection(value.get("permitted_selection"))
    )


def _validate_evidence_content_access_admission_record(
    record: Dict[str, Any],
    *,
    active: Dict[str, Any],
    sequence: int,
    previous_record_digest: str,
) -> bool:
    """Validate one durable Human-Entry content-access admission."""

    required = {
        "schema",
        "ledger_id",
        "sequence",
        "previous_record_digest",
        "record_kind",
        "recorded_at",
        "active_policy",
        "content_access",
        "source",
        "record_digest",
    }
    access = record.get("content_access")
    source = record.get("source")
    if (
        set(record) != required
        or record.get("schema") != "ask_herdr.policy_ledger_record.v1"
        or record.get("ledger_id") != active["ledger_id"]
        or record.get("sequence") != sequence
        or record.get("previous_record_digest") != previous_record_digest
        or record.get("record_kind")
        != "evidence_content_access_admission"
        or record.get("active_policy")
        != {
            "profile_id": active["profile_id"],
            "profile_digest": active["profile_digest"],
        }
        or not _valid_human_content_access(access)
        or access.get("project_authority_id") != active["authority_id"]
        or type(source) is not dict
        or set(source)
        != {
            "schema",
            "source_kind",
            "source_operation_id",
            "source_relationship_digest",
            "evidence_registry_record_digest",
        }
        or source.get("schema")
        != "ask_herdr.evidence_content_access_source.internal.v1"
        or source.get("source_kind") != "recovery_reconcile_result"
        or source.get("source_operation_id")
        != access.get("relationship_operation_id")
        or not _matches(
            UUID4_PATTERN,
            source.get("source_operation_id"),
        )
        or not _matches(
            DIGEST_PATTERN,
            source.get("source_relationship_digest"),
        )
        or not _matches(
            DIGEST_PATTERN,
            source.get("evidence_registry_record_digest"),
        )
    ):
        return False
    try:
        _parse_canonical_timestamp(record.get("recorded_at"))
    except ValueError:
        return False
    unsigned = dict(record)
    record_digest = unsigned.pop("record_digest", None)
    return _matches(DIGEST_PATTERN, record_digest) and _digest(unsigned) == record_digest


def _validate_evidence_content_access_settlement_record(
    record: Dict[str, Any],
    *,
    active: Dict[str, Any],
    sequence: int,
    previous_record_digest: str,
    canonical_root: str,
    filesystem_identity: Dict[str, int],
) -> bool:
    """Validate one consume-before-exposure settlement record."""

    required = {
        "schema",
        "ledger_id",
        "sequence",
        "previous_record_digest",
        "record_kind",
        "recorded_at",
        "active_policy",
        "access_admission_record_digest",
        "content_access",
        "canonical_request_projection",
        "settlement",
        "record_digest",
    }
    access = record.get("content_access")
    projection = record.get("canonical_request_projection")
    settlement = record.get("settlement")
    if (
        set(record) != required
        or record.get("schema") != "ask_herdr.policy_ledger_record.v1"
        or record.get("ledger_id") != active["ledger_id"]
        or record.get("sequence") != sequence
        or record.get("previous_record_digest") != previous_record_digest
        or record.get("record_kind")
        != "evidence_content_access_settlement"
        or record.get("active_policy")
        != {
            "profile_id": active["profile_id"],
            "profile_digest": active["profile_digest"],
        }
        or not _matches(
            DIGEST_PATTERN,
            record.get("access_admission_record_digest"),
        )
        or not _valid_human_content_access(access)
        or access.get("project_authority_id") != active["authority_id"]
        or type(projection) is not dict
        or set(projection) != {"schema", "operation", "project", "payload"}
        or projection.get("schema")
        != "ask_herdr.canonical_request_projection.v1"
        or projection.get("operation") != "query.evidence"
        or type(settlement) is not dict
        or set(settlement)
        != {
            "schema",
            "access_id",
            "content_read_operation_id",
            "canonical_request_digest",
            "evidence_id",
            "content_digest",
            "selection",
            "state",
        }
        or settlement.get("schema")
        != "ask_herdr.evidence_content_access.settlement.v1"
        or settlement.get("state") != "consumed"
        or not _matches(UUID4_PATTERN, settlement.get("access_id"))
        or not _matches(
            UUID4_PATTERN,
            settlement.get("content_read_operation_id"),
        )
        or not _matches(
            DIGEST_PATTERN,
            settlement.get("canonical_request_digest"),
        )
        or not _matches(UUID4_PATTERN, settlement.get("evidence_id"))
        or not _matches(DIGEST_PATTERN, settlement.get("content_digest"))
        or not _valid_evidence_selection(settlement.get("selection"))
    ):
        return False
    project = projection.get("project")
    payload = projection.get("payload")
    if (
        type(project) is not dict
        or set(project)
        != {
            "binding",
            "root",
            "authority_id",
            "filesystem_identity",
        }
        or project.get("binding") != "bound"
        or project.get("root") != canonical_root
        or project.get("authority_id") != active["authority_id"]
        or project.get("filesystem_identity") != filesystem_identity
        or type(payload) is not dict
        or set(payload)
        != {
            "evidence_ref_id",
            "expected_evidence_digest",
            "selection",
        }
        or payload.get("evidence_ref_id") != access.get("evidence_id")
        or payload.get("expected_evidence_digest")
        != access.get("expected_content_digest")
        or payload.get("selection") != access.get("permitted_selection")
        or settlement.get("access_id") != access.get("access_id")
        or settlement.get("evidence_id") != access.get("evidence_id")
        or settlement.get("content_digest")
        != access.get("expected_content_digest")
        or settlement.get("selection") != access.get("permitted_selection")
        or "sha256:"
        + hashlib.sha256(canonical_json(projection)).hexdigest()
        != settlement.get("canonical_request_digest")
    ):
        return False
    try:
        _parse_canonical_timestamp(record.get("recorded_at"))
    except ValueError:
        return False
    unsigned = dict(record)
    record_digest = unsigned.pop("record_digest", None)
    return _matches(DIGEST_PATTERN, record_digest) and _digest(unsigned) == record_digest


def _validate_ledger_append_record(
    record: Dict[str, Any],
    *,
    active: Dict[str, Any],
    profile: Dict[str, Any],
    sequence: int,
    previous_record_digest: str,
    canonical_root: str,
    filesystem_identity: Dict[str, int],
) -> bool:
    """Dispatch one append record to its exact kind-owned validator."""

    kind = record.get("record_kind") if type(record) is dict else None
    if kind == "human_admission":
        return _validate_human_admission_record(
            record,
            active=active,
            profile=profile,
            sequence=sequence,
            previous_record_digest=previous_record_digest,
        )
    if kind == "recovery_operation_admission":
        return _validate_recovery_operation_admission_record(
            record,
            active=active,
            profile=profile,
            sequence=sequence,
            previous_record_digest=previous_record_digest,
            canonical_root=canonical_root,
            filesystem_identity=filesystem_identity,
        )
    if kind == "evidence_content_access_admission":
        return _validate_evidence_content_access_admission_record(
            record,
            active=active,
            sequence=sequence,
            previous_record_digest=previous_record_digest,
        )
    if kind == "evidence_content_access_settlement":
        return _validate_evidence_content_access_settlement_record(
            record,
            active=active,
            sequence=sequence,
            previous_record_digest=previous_record_digest,
            canonical_root=canonical_root,
            filesystem_identity=filesystem_identity,
        )
    return False


def _record_owner_operation_id(record: Dict[str, Any]) -> Optional[str]:
    """Return the kind-owned operation identity used by pending heads."""

    if type(record) is not dict:
        return None
    kind = record.get("record_kind")
    if kind == "project_genesis":
        value = record.get("operation_id")
    elif kind == "human_admission":
        operation = record.get("operation")
        value = operation.get("operation_id") if type(operation) is dict else None
    elif kind == "recovery_operation_admission":
        operation = record.get("canonical_operation")
        value = operation.get("operation_id") if type(operation) is dict else None
    elif kind == "evidence_content_access_admission":
        access = record.get("content_access")
        value = access.get("access_id") if type(access) is dict else None
    elif kind == "evidence_content_access_settlement":
        settlement = record.get("settlement")
        value = (
            settlement.get("content_read_operation_id")
            if type(settlement) is dict
            else None
        )
    else:
        return None
    return value if _matches(UUID4_PATTERN, value) else None


def _record_consumed_receipt_id(record: Dict[str, Any]) -> Optional[str]:
    """Return the exact one-use receipt identity for any known ledger kind."""

    if type(record) is not dict:
        return None
    if record.get("record_kind") == "project_genesis":
        receipt = record.get("bootstrap_receipt")
    elif record.get("record_kind") in {
        "human_admission",
        "recovery_operation_admission",
    }:
        receipt = record.get("human_approval_receipt")
    elif record.get("record_kind") == "evidence_content_access_settlement":
        access = record.get("content_access")
        value = access.get("access_id") if type(access) is dict else None
        return value if _matches(UUID4_PATTERN, value) else None
    else:
        return None
    value = receipt.get("receipt_id") if type(receipt) is dict else None
    return value if _matches(UUID4_PATTERN, value) else None


def _inspection_with_head(
    status: str,
    detail_code: str,
    *,
    active: Dict[str, Any],
    profile_bytes: bytes,
    genesis_digest: str,
    genesis_bytes: bytes,
    head_sequence: int,
    head_digest: str,
    head_bytes: bytes,
    ledger_bytes: Tuple[bytes, ...],
    store_identity: Tuple[int, int, int, int, int],
    objects_identity: Tuple[int, int, int, int, int],
    staging_identity: Tuple[int, int, int, int, int],
    active_identity: Tuple[int, int, int, int, int, int, int],
    object_identities: Tuple[
        Tuple[str, Tuple[int, int, int, int, int, int, int]],
        ...,
    ],
) -> AuthorityStoreInspection:
    return AuthorityStoreInspection(
        status,
        detail_code,
        authority_id=active["authority_id"],
        profile_id=active["profile_id"],
        ledger_id=active["ledger_id"],
        operation_id=active["operation_id"],
        canonical_request_digest=active["canonical_request_digest"],
        genesis_digest=genesis_digest,
        genesis_record_bytes=genesis_bytes,
        profile_digest=active["profile_digest"],
        profile_record_bytes=profile_bytes,
        head_sequence=head_sequence,
        head_digest=head_digest,
        head_record_bytes=head_bytes,
        ledger_record_bytes=ledger_bytes,
        store_identity=store_identity,
        objects_identity=objects_identity,
        staging_identity=staging_identity,
        active_identity=active_identity,
        object_identities=object_identities,
    )


def _validate_active_records(
    store: int,
    objects: int,
    root: int,
    canonical_root: str,
) -> AuthorityStoreInspection:
    try:
        store_identity = _identity(os.fstat(store))
        objects_identity = _identity(os.fstat(objects))
        store_entries = set(os.listdir(store))
        if store_entries != {OBJECTS_NAME, STAGING_NAME, ACTIVE_NAME}:
            return _reconciliation("authority_store.unknown_layout")
        staging = _open_private_directory(store, STAGING_NAME)
        try:
            staging_identity = _identity(os.fstat(staging))
            staging_entries = set(os.listdir(staging))
        finally:
            os.close(staging)
        active, _, active_identity = _read_private_json_with_identity(
            store,
            ACTIVE_NAME,
        )
        required_active = {
            "schema",
            "authority_id",
            "profile_id",
            "profile_digest",
            "ledger_id",
            "ledger_head_digest",
            "operation_id",
            "canonical_request_digest",
            "profile_object",
            "genesis_object",
        }
        if set(active) != required_active or active.get("schema") != (
            "ask_herdr.authority_store_active.v1"
        ):
            return _reconciliation("authority_store.active_invalid")
        uuid_fields = ("authority_id", "profile_id", "ledger_id", "operation_id")
        digest_fields = (
            "profile_digest",
            "ledger_head_digest",
            "canonical_request_digest",
        )
        if any(not _matches(UUID4_PATTERN, active.get(field)) for field in uuid_fields):
            return _reconciliation("authority_store.active_invalid")
        if any(not _matches(DIGEST_PATTERN, active.get(field)) for field in digest_fields):
            return _reconciliation("authority_store.active_invalid")
        expected_profile_name = "policy." + active["profile_id"] + ".json"
        expected_genesis_name = "genesis." + active["ledger_id"] + ".json"
        if active.get("profile_object") != expected_profile_name or active.get(
            "genesis_object"
        ) != expected_genesis_name:
            return _reconciliation("authority_store.active_invalid")
        object_entries = set(os.listdir(objects))
        if not {expected_profile_name, expected_genesis_name}.issubset(object_entries):
            return _reconciliation("authority_store.object_set_mismatch")
        profile, profile_bytes, profile_identity = (
            _read_private_json_with_identity(objects, expected_profile_name)
        )
        genesis, genesis_bytes, genesis_identity = (
            _read_private_json_with_identity(objects, expected_genesis_name)
        )
        object_identities = {
            expected_profile_name: profile_identity,
            expected_genesis_name: genesis_identity,
        }
        if _digest(profile) != active["profile_digest"]:
            return _quarantine("authority_store.profile_hash_mismatch")
        record_without_digest = dict(genesis)
        record_digest = record_without_digest.pop("record_digest", None)
        if not _matches(DIGEST_PATTERN, record_digest) or _digest(
            record_without_digest
        ) != record_digest:
            return _quarantine("authority_store.genesis_hash_mismatch")
        required_genesis = {
            "schema",
            "ledger_id",
            "sequence",
            "previous_record_digest",
            "record_kind",
            "recorded_at",
            "operation_id",
            "canonical_request_digest",
            "project_authority",
            "bootstrap_receipt",
            "active_policy",
            "record_digest",
        }
        if (
            set(genesis) != required_genesis
            or genesis.get("schema") != "ask_herdr.policy_ledger_record.v1"
            or genesis.get("ledger_id") != active["ledger_id"]
            or genesis.get("sequence") != 0
            or genesis.get("previous_record_digest") is not None
            or genesis.get("record_kind") != "project_genesis"
            or genesis.get("operation_id") != active["operation_id"]
            or genesis.get("canonical_request_digest")
            != active["canonical_request_digest"]
            or genesis.get("active_policy")
            != {
                "profile_id": active["profile_id"],
                "profile_digest": active["profile_digest"],
            }
        ):
            return _reconciliation("authority_store.genesis_invalid")
        authority = genesis.get("project_authority")
        receipt = genesis.get("bootstrap_receipt")
        root_metadata = os.fstat(root)
        expected_filesystem_identity = {
            "device": root_metadata.st_dev,
            "inode": root_metadata.st_ino,
            "owner_uid": root_metadata.st_uid,
        }
        if (
            type(authority) is not dict
            or set(authority)
            != {
                "authority_id",
                "canonical_root",
                "filesystem_identity",
                "lifetime",
            }
            or authority.get("authority_id") != active["authority_id"]
            or authority.get("canonical_root") != canonical_root
            or authority.get("filesystem_identity")
            != expected_filesystem_identity
            or authority.get("lifetime") != "initial"
        ):
            return _quarantine("authority_store.project_binding_mismatch")
        if (
            type(receipt) is not dict
            or set(receipt)
            != {
                "schema",
                "receipt_id",
                "operation_id",
                "canonical_request_digest",
                "canonical_root",
                "filesystem_identity",
                "confirmed_at",
            }
            or receipt.get("schema") != "ask_herdr.bootstrap_receipt.v1"
            or not _matches(UUID4_PATTERN, receipt.get("receipt_id"))
        ):
            return _reconciliation("authority_store.genesis_invalid")
        try:
            confirmed_at = _parse_canonical_timestamp(receipt.get("confirmed_at"))
            recorded_at = _parse_canonical_timestamp(genesis.get("recorded_at"))
        except ValueError:
            return _reconciliation("authority_store.timestamp_invalid")
        if confirmed_at > recorded_at:
            return _quarantine("authority_store.bootstrap_after_genesis")
        correlated = (
            receipt.get("operation_id") == active["operation_id"]
            and receipt.get("canonical_request_digest")
            == active["canonical_request_digest"]
            and receipt.get("canonical_root") == authority.get("canonical_root")
            and receipt.get("filesystem_identity") == authority.get(
                "filesystem_identity"
            )
        )
        if not correlated:
            return _quarantine("authority_store.bootstrap_correlation_mismatch")
        if profile != _genesis_policy(active["profile_id"], genesis["recorded_at"]):
            return _quarantine("authority_store.genesis_policy_mismatch")
        append_entries = object_entries - {
            expected_profile_name,
            expected_genesis_name,
        }
        parsed_appends = {}
        for name in append_entries:
            parts = name.split(".")
            if (
                len(parts) != 5
                or parts[0] != "ledger"
                or parts[1] != active["ledger_id"]
                or not parts[2].isdigit()
                or parts[2] == "0"
                or str(int(parts[2])) != parts[2]
                or len(parts[3]) != 64
                or any(character not in "0123456789abcdef" for character in parts[3])
                or parts[4] != "json"
            ):
                return _reconciliation("authority_store.object_set_mismatch")
            sequence = int(parts[2])
            if sequence in parsed_appends:
                return _reconciliation("policy_ledger.sequence_conflict")
            record, record_bytes, object_identity = (
                _read_private_json_with_identity(objects, name)
            )
            object_identities[name] = object_identity
            parsed_appends[sequence] = (name, record, record_bytes)

        ledger_records = [(record_digest, genesis_bytes)]
        owned_operation_ids = {active["operation_id"]}
        consumed_receipt_ids = {receipt["receipt_id"]}
        access_admissions: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        previous_digest = record_digest
        for sequence in range(1, len(parsed_appends) + 1):
            if sequence not in parsed_appends:
                return _reconciliation("policy_ledger.sequence_gap")
            name, record, record_bytes = parsed_appends[sequence]
            if not _validate_ledger_append_record(
                record,
                active=active,
                profile=profile,
                sequence=sequence,
                previous_record_digest=previous_digest,
                canonical_root=canonical_root,
                filesystem_identity=expected_filesystem_identity,
            ):
                return _quarantine("policy_ledger.record_integrity_failure")
            owner_operation_id = _record_owner_operation_id(record)
            consumed_receipt_id = _record_consumed_receipt_id(record)
            if (
                owner_operation_id is None
                or owner_operation_id in owned_operation_ids
                or (
                    consumed_receipt_id is not None
                    and consumed_receipt_id in consumed_receipt_ids
                )
            ):
                return _quarantine("policy_ledger.identity_reuse")
            kind = record.get("record_kind")
            if kind == "evidence_content_access_admission":
                access = record["content_access"]
                access_id = access["access_id"]
                if access_id in access_admissions:
                    return _quarantine("policy_ledger.identity_reuse")
                access_admissions[access_id] = (
                    record["record_digest"],
                    access,
                )
            elif kind == "evidence_content_access_settlement":
                access = record["content_access"]
                admission = access_admissions.get(access["access_id"])
                if (
                    admission is None
                    or admission[0]
                    != record.get("access_admission_record_digest")
                    or admission[1] != access
                ):
                    return _quarantine(
                        "policy_ledger.content_access_admission_mismatch"
                    )
            owned_operation_ids.add(owner_operation_id)
            if consumed_receipt_id is not None:
                consumed_receipt_ids.add(consumed_receipt_id)
            current_digest = record["record_digest"]
            if name != _ledger_object_name(active["ledger_id"], sequence, current_digest):
                return _reconciliation("policy_ledger.record_name_mismatch")
            ledger_records.append((current_digest, record_bytes))
            previous_digest = current_digest

        active_head_index = next(
            (
                index
                for index, (digest, _bytes) in enumerate(ledger_records)
                if digest == active["ledger_head_digest"]
            ),
            None,
        )
        if active_head_index is None:
            return _quarantine("policy_ledger.head_hash_mismatch")
        active_head_digest, active_head_bytes = ledger_records[active_head_index]
        all_record_bytes = tuple(record_bytes for _digest_value, record_bytes in ledger_records)
        if active_head_index != len(ledger_records) - 1:
            latest_digest, latest_bytes = ledger_records[-1]
            latest = parse_json_object(
                latest_bytes[:-1] if latest_bytes.endswith(b"\n") else latest_bytes
            )
            latest_operation_id = _record_owner_operation_id(latest)
            if latest_operation_id is None:
                return _quarantine("policy_ledger.record_integrity_failure")
            expected_stage_name = _pending_head_name(
                latest_operation_id,
                latest_digest,
            )
            expected_staged_active = dict(active)
            expected_staged_active["ledger_head_digest"] = latest_digest
            if (
                active_head_index + 1 == len(ledger_records) - 1
                and staging_entries == {expected_stage_name}
            ):
                staging = _open_private_directory(store, STAGING_NAME)
                try:
                    staged_active, _ = _read_private_json(
                        staging,
                        expected_stage_name,
                    )
                finally:
                    os.close(staging)
                if staged_active == expected_staged_active:
                    return _inspection_with_head(
                        "reconciliation_required",
                        "policy_ledger.pending_head_publication",
                        active=active,
                        profile_bytes=profile_bytes,
                        genesis_digest=record_digest,
                        genesis_bytes=genesis_bytes,
                        head_sequence=active_head_index,
                        head_digest=active_head_digest,
                        head_bytes=active_head_bytes,
                        ledger_bytes=all_record_bytes,
                        store_identity=store_identity,
                        objects_identity=objects_identity,
                        staging_identity=staging_identity,
                        active_identity=active_identity,
                        object_identities=tuple(sorted(object_identities.items())),
                    )
            if (
                active_head_index + 1 == len(ledger_records) - 1
                and not staging_entries
            ):
                return _inspection_with_head(
                    "reconciliation_required",
                    "policy_ledger.orphaned_record",
                    active=active,
                    profile_bytes=profile_bytes,
                    genesis_digest=record_digest,
                    genesis_bytes=genesis_bytes,
                    head_sequence=active_head_index,
                    head_digest=active_head_digest,
                    head_bytes=active_head_bytes,
                    ledger_bytes=all_record_bytes,
                    store_identity=store_identity,
                    objects_identity=objects_identity,
                    staging_identity=staging_identity,
                    active_identity=active_identity,
                    object_identities=tuple(
                        sorted(object_identities.items())
                    ),
                )
            return _reconciliation("policy_ledger.orphaned_record")
        if staging_entries:
            latest = parse_json_object(
                all_record_bytes[-1][:-1]
                if all_record_bytes[-1].endswith(b"\n")
                else all_record_bytes[-1]
            )
            latest_operation_id = _record_owner_operation_id(latest)
            expected_stage_name = (
                _pending_head_name(
                    latest_operation_id,
                    active_head_digest,
                )
                if latest_operation_id is not None
                else None
            )
            if (
                expected_stage_name is not None
                and staging_entries == {expected_stage_name}
            ):
                staging = _open_private_directory(store, STAGING_NAME)
                try:
                    staged_active, _ = _read_private_json(
                        staging,
                        expected_stage_name,
                    )
                finally:
                    os.close(staging)
                if staged_active == active:
                    return _inspection_with_head(
                        "reconciliation_required",
                        "policy_ledger.stale_head_publication",
                        active=active,
                        profile_bytes=profile_bytes,
                        genesis_digest=record_digest,
                        genesis_bytes=genesis_bytes,
                        head_sequence=active_head_index,
                        head_digest=active_head_digest,
                        head_bytes=active_head_bytes,
                        ledger_bytes=all_record_bytes,
                        store_identity=store_identity,
                        objects_identity=objects_identity,
                        staging_identity=staging_identity,
                        active_identity=active_identity,
                        object_identities=tuple(
                            sorted(object_identities.items())
                        ),
                    )
            return _reconciliation("authority_store.staging_present")
        return _inspection_with_head(
            "active",
            "authority_store.active",
            active=active,
            profile_bytes=profile_bytes,
            genesis_digest=record_digest,
            genesis_bytes=genesis_bytes,
            head_sequence=active_head_index,
            head_digest=active_head_digest,
            head_bytes=active_head_bytes,
            ledger_bytes=all_record_bytes,
            store_identity=store_identity,
            objects_identity=objects_identity,
            staging_identity=staging_identity,
            active_identity=active_identity,
            object_identities=tuple(sorted(object_identities.items())),
        )
    except (OSError, PermissionError, StrictJsonError, ValueError):
        return _quarantine("authority_store.integrity_failure")


def _inspect_locked(root: int, canonical_root: str) -> AuthorityStoreInspection:
    root_metadata = os.fstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != os.getuid():
        return _quarantine("authority_store.root_owner_mismatch")
    try:
        os.stat(STORE_NAME, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return AuthorityStoreInspection("absent", "authority_store.absent")
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return _quarantine("authority_store.unsafe_path")
        return _reconciliation("authority_store.unobservable")
    try:
        store = _open_private_directory(root, STORE_NAME)
    except (OSError, PermissionError):
        return _quarantine("authority_store.store_integrity")
    objects = None
    inspection = None
    cleanup_error = None
    try:
        try:
            objects = _open_private_directory(store, OBJECTS_NAME)
        except FileNotFoundError:
            inspection = _reconciliation("authority_store.partial")
        except (OSError, PermissionError):
            inspection = _quarantine(
                "authority_store.object_directory_integrity"
            )
        if objects is not None:
            inspection = _validate_active_records(
                store,
                objects,
                root,
                canonical_root,
            )
            bindings_valid = _directory_still_bound(
                root,
                STORE_NAME,
                store,
            ) and _directory_still_bound(store, OBJECTS_NAME, objects)
            sources_valid = _head_sources_still_bound(
                store,
                objects,
                inspection,
            )
            bindings_still_valid = _directory_still_bound(
                root,
                STORE_NAME,
                store,
            ) and _directory_still_bound(store, OBJECTS_NAME, objects)
            if not bindings_valid or not sources_valid or not bindings_still_valid:
                inspection = _quarantine("authority_store.store_changed")
    finally:
        for descriptor in (objects, store):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
    if cleanup_error is not None and (
        inspection is None or inspection.status == "active"
    ):
        return _reconciliation("authority_store.cleanup_unverified")
    if inspection is None:
        return _reconciliation("authority_store.unobservable")
    return inspection


def inspect_authority_store(canonical_root: str) -> AuthorityStoreInspection:
    """Inspect the private store without creating, repairing, or deleting it."""

    try:
        with _open_canonical_root(canonical_root) as root:
            try:
                fcntl.flock(root, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return AuthorityStoreInspection(
                    "busy", "authority_store.writer_active"
                )
            inspection = _inspect_locked(root, canonical_root)
        return inspection
    except _RootChangedError:
        return _reconciliation("authority_store.root_changed")
    except OSError:
        return _reconciliation("authority_store.root_unobservable")


def _authority_store_head_projection(
    inspection: AuthorityStoreInspection,
) -> AuthorityStoreHeadInspection:
    digest = (
        inspection.head_digest
        if inspection.status in {"active", "reconciliation_required"}
        else None
    )
    if digest is not None and not _matches(DIGEST_PATTERN, digest):
        return AuthorityStoreHeadInspection(
            "quarantined",
            "authority_store_head.digest_invalid",
        )
    detail_code = inspection.detail_code
    if detail_code == "authority_store.store_changed":
        detail_code = "authority_store_head.store_changed"
    return AuthorityStoreHeadInspection(
        inspection.status,
        (
            "authority_store_head.active"
            if inspection.status == "active"
            else detail_code
        ),
        digest,
    )


_HUMAN_OPERATION_NAMES = frozenset(
    {"turn.answer", "turn.consult", "turn.review"}
)


def _authority_status_record(value: object) -> Optional[Dict[str, Any]]:
    """Parse one exact canonical record retained by an authenticated replay."""

    if type(value) is not bytes:
        return None
    raw = value[:-1] if value.endswith(b"\n") else value
    try:
        record = parse_json_object(raw)
        if type(record) is not dict or canonical_json(record) != raw:
            return None
        unsigned = dict(record)
        record_digest = unsigned.pop("record_digest", None)
        if (
            not _matches(DIGEST_PATTERN, record_digest)
            or _digest(unsigned) != record_digest
        ):
            return None
        return record
    except StrictJsonError:
        return None


def _authority_status_operation_entry(
    record: Dict[str, Any],
) -> Optional[AuthorityStatusOperationEntry]:
    """Project one closed operation-bearing Policy record, or fail closed."""

    record_digest = record.get("record_digest")
    if not _matches(DIGEST_PATTERN, record_digest):
        return None
    kind = record.get("record_kind")
    if kind == "project_genesis":
        operation_id = record.get("operation_id")
        request_digest = record.get("canonical_request_digest")
        if (
            not _matches(UUID4_PATTERN, operation_id)
            or not _matches(DIGEST_PATTERN, request_digest)
        ):
            return None
        return AuthorityStatusOperationEntry(
            operation_id,
            "project.init",
            request_digest,
            record_digest,
            "not_applicable",
            None,
            None,
        )
    if kind == "human_admission":
        operation = record.get("operation")
        if type(operation) is not dict:
            return None
        operation_id = operation.get("operation_id")
        operation_name = operation.get("operation")
        request_digest = operation.get("canonical_request_digest")
        if (
            operation_name not in _HUMAN_OPERATION_NAMES
            or not _matches(UUID4_PATTERN, operation_id)
            or not _matches(DIGEST_PATTERN, request_digest)
        ):
            return None
        return AuthorityStatusOperationEntry(
            operation_id,
            operation_name,
            request_digest,
            record_digest,
            "required",
            None,
            None,
        )
    if kind == "recovery_operation_admission":
        operation = record.get("canonical_operation")
        if type(operation) is not dict:
            return None
        selector = operation.get("recovery_scope_selector")
        operation_id = operation.get("operation_id")
        operation_name = operation.get("operation")
        request_digest = operation.get("canonical_request_digest")
        if (
            type(selector) is not dict
            or operation_name != "recovery.reconcile"
            or not _matches(UUID4_PATTERN, operation_id)
            or not _matches(DIGEST_PATTERN, request_digest)
            or not _matches(UUID4_PATTERN, selector.get("lane_id"))
            or type(selector.get("generation")) is not int
            or selector["generation"] < 1
        ):
            return None
        return AuthorityStatusOperationEntry(
            operation_id,
            operation_name,
            request_digest,
            record_digest,
            "required",
            selector["lane_id"],
            selector["generation"],
        )
    if kind == "evidence_content_access_settlement":
        settlement = record.get("settlement")
        projection = record.get("canonical_request_projection")
        if type(settlement) is not dict or type(projection) is not dict:
            return None
        operation_id = settlement.get("content_read_operation_id")
        request_digest = settlement.get("canonical_request_digest")
        if (
            projection.get("operation") != "query.evidence"
            or not _matches(UUID4_PATTERN, operation_id)
            or not _matches(DIGEST_PATTERN, request_digest)
        ):
            return None
        return AuthorityStatusOperationEntry(
            operation_id,
            "query.evidence",
            request_digest,
            record_digest,
            "not_applicable",
            None,
            None,
        )
    return None


def _authority_status_projection(
    inspection: AuthorityStoreInspection,
) -> AuthorityStatusProjectionInspection:
    """Retain the closed promoted operation universe from one head replay."""

    head = _authority_store_head_projection(inspection)
    if head.status not in {"active", "reconciliation_required"}:
        return AuthorityStatusProjectionInspection(
            head.status,
            head.detail_code,
            head.authority_store_head_digest,
        )
    if head.authority_store_head_digest is None:
        if head.status == "reconciliation_required":
            return AuthorityStatusProjectionInspection(
                head.status,
                head.detail_code,
            )
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store.operation_projection_invalid",
        )
    if (
        type(inspection.head_sequence) is not int
        or inspection.head_sequence < 0
        or type(inspection.ledger_record_bytes) is not tuple
        or len(inspection.ledger_record_bytes) <= inspection.head_sequence
    ):
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store.operation_projection_invalid",
        )
    records = tuple(
        _authority_status_record(value)
        for value in inspection.ledger_record_bytes[
            : inspection.head_sequence + 1
        ]
    )
    if (
        any(record is None for record in records)
        or records[-1] is None
        or records[-1].get("record_digest")
        != head.authority_store_head_digest
        or any(
            record is None or record.get("sequence") != index
            for index, record in enumerate(records)
        )
    ):
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store.operation_projection_invalid",
        )
    entries: Dict[str, AuthorityStatusOperationEntry] = {}
    for record in records:
        assert record is not None
        if record.get("record_kind") == "evidence_content_access_admission":
            continue
        entry = _authority_status_operation_entry(record)
        if entry is None:
            return AuthorityStatusProjectionInspection(
                "quarantined",
                "authority_store.operation_projection_invalid",
            )
        if entry.operation_id in entries:
            return AuthorityStatusProjectionInspection(
                "quarantined",
                "authority_store.operation_projection_invalid",
            )
        entries[entry.operation_id] = entry
    return AuthorityStatusProjectionInspection(
        head.status,
        head.detail_code,
        head.authority_store_head_digest,
        tuple(entries[operation_id] for operation_id in sorted(entries)),
    )


def _remember_authority_status_operation_entries(
    head: AuthorityStoreHeadInspection,
    entries: Tuple[AuthorityStatusOperationEntry, ...],
) -> None:
    """Keep the private same-replay tuple out of the frozen head wire shape."""

    key = id(head)

    def _release(reference: object) -> None:
        cached = _AUTHORITY_STATUS_OPERATION_CACHE.get(key)
        if cached is not None and cached[0] is reference:
            _AUTHORITY_STATUS_OPERATION_CACHE.pop(key, None)

    _AUTHORITY_STATUS_OPERATION_CACHE[key] = (weakref.ref(head, _release), entries)


def _authority_status_operation_entries_from_head(
    value: object,
) -> Tuple[AuthorityStatusOperationEntry, ...]:
    """Return the projected tuple only for the exact just-observed head value."""

    if type(value) is not AuthorityStoreHeadInspection:
        return ()
    cached = _AUTHORITY_STATUS_OPERATION_CACHE.get(id(value))
    if cached is None or cached[0]() is not value:
        return ()
    return cached[1]


def _authority_store_head_with_operation_projection(
    inspection: AuthorityStoreInspection,
) -> AuthorityStoreHeadInspection:
    """Preserve the frozen head type while retaining its private replay tuple."""

    projection = _authority_status_projection(inspection)
    head = AuthorityStoreHeadInspection(
        projection.status,
        projection.detail_code,
        projection.authority_store_head_digest,
    )
    _remember_authority_status_operation_entries(
        head,
        projection.operation_entries,
    )
    return head


def _exact_project_mutation_binding(
    value: object,
) -> Optional[ValidatedProjectMutationBinding]:
    """Revalidate and snapshot the one exact caller binding type."""

    if type(value) is not ValidatedProjectMutationBinding:
        return None
    try:
        fields = vars(value)
        if set(fields) != {
            "canonical_root",
            "filesystem_device",
            "filesystem_inode",
            "owner_uid",
            "project_authority_id",
        }:
            return None
        return ValidatedProjectMutationBinding(
            canonical_root=fields["canonical_root"],
            filesystem_device=fields["filesystem_device"],
            filesystem_inode=fields["filesystem_inode"],
            owner_uid=fields["owner_uid"],
            project_authority_id=fields["project_authority_id"],
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _inspect_authority_store_head_from_root(
    root: int,
    binding: ValidatedProjectMutationBinding,
) -> AuthorityStoreHeadInspection:
    """Project the exact head while one canonical root descriptor is held."""

    try:
        fcntl.flock(root, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return AuthorityStoreHeadInspection(
            "busy",
            "authority_store_head.writer_active",
        )
    metadata = os.fstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != binding.filesystem_device
        or metadata.st_ino != binding.filesystem_inode
        or metadata.st_uid != binding.owner_uid
        or binding.owner_uid != os.getuid()
        or bool(stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        return AuthorityStoreHeadInspection(
            "quarantined",
            "authority_store_head.binding_mismatch",
        )
    inspection = _inspect_locked(root, binding.canonical_root)
    if (
        inspection.authority_id is not None
        and inspection.authority_id != binding.project_authority_id
    ):
        return AuthorityStoreHeadInspection(
            "quarantined",
            "authority_store_head.binding_mismatch",
        )
    return _authority_store_head_with_operation_projection(inspection)


def inspect_authority_store_head(
    binding: ValidatedProjectMutationBinding,
) -> AuthorityStoreHeadInspection:
    """Inspect the promoted Policy Ledger head for one exact Project binding."""

    exact_binding = _exact_project_mutation_binding(binding)
    if exact_binding is None:
        return AuthorityStoreHeadInspection(
            "quarantined",
            "authority_store_head.binding_invalid",
        )
    binding = exact_binding
    result = None
    try:
        with _open_canonical_root(binding.canonical_root) as root:
            result = _inspect_authority_store_head_from_root(root, binding)
        return result
    except _RootCleanupError:
        if result is not None and result.status != "active":
            return result
        return AuthorityStoreHeadInspection(
            "reconciliation_required",
            "authority_store_head.root_cleanup_unverified",
        )
    except _RootChangedError:
        return AuthorityStoreHeadInspection(
            "reconciliation_required",
            "authority_store_head.root_changed",
        )
    except OSError:
        return AuthorityStoreHeadInspection(
            "reconciliation_required",
            "authority_store_head.root_unobservable",
        )


def _inspect_authority_status_projection_from_root(
    root: int,
    binding: ValidatedProjectMutationBinding,
) -> AuthorityStatusProjectionInspection:
    """Project one promoted Authority head while its root descriptor is held."""

    try:
        fcntl.flock(root, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return AuthorityStatusProjectionInspection(
            "busy",
            "authority_store_head.writer_active",
        )
    metadata = os.fstat(root)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != binding.filesystem_device
        or metadata.st_ino != binding.filesystem_inode
        or metadata.st_uid != binding.owner_uid
        or binding.owner_uid != os.getuid()
        or bool(stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store_head.binding_mismatch",
        )
    inspection = _inspect_locked(root, binding.canonical_root)
    if (
        inspection.authority_id is not None
        and inspection.authority_id != binding.project_authority_id
    ):
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store_head.binding_mismatch",
        )
    return _authority_status_projection(inspection)


def inspect_authority_status_projection(
    binding: ValidatedProjectMutationBinding,
) -> AuthorityStatusProjectionInspection:
    """Inspect a promoted Authority head and its closed operation universe."""

    exact_binding = _exact_project_mutation_binding(binding)
    if exact_binding is None:
        return AuthorityStatusProjectionInspection(
            "quarantined",
            "authority_store_head.binding_invalid",
        )
    result: Optional[AuthorityStatusProjectionInspection] = None
    try:
        with _open_canonical_root(exact_binding.canonical_root) as root:
            result = _inspect_authority_status_projection_from_root(
                root,
                exact_binding,
            )
        return result
    except _RootCleanupError:
        if result is not None and result.status != "active":
            return result
        return AuthorityStatusProjectionInspection(
            "reconciliation_required",
            "authority_store_head.root_cleanup_unverified",
        )
    except _RootChangedError:
        return AuthorityStatusProjectionInspection(
            "reconciliation_required",
            "authority_store_head.root_changed",
        )
    except OSError:
        return AuthorityStatusProjectionInspection(
            "reconciliation_required",
            "authority_store_head.root_unobservable",
        )


def _validate_genesis(genesis: ConfirmedProjectGenesis) -> None:
    if not isinstance(genesis, ConfirmedProjectGenesis):
        raise ValueError("authority_store.genesis_type_invalid")
    if genesis.lifetime != "initial":
        raise ValueError("authority_store.lifetime_not_initial")
    if not _matches(UUID4_PATTERN, genesis.operation_id) or not _matches(
        DIGEST_PATTERN, genesis.canonical_request_digest
    ):
        raise ValueError("authority_store.genesis_identity_invalid")
    receipt = genesis.bootstrap_receipt
    if not isinstance(receipt, ValidatedBootstrapReceipt) or not _matches(
        UUID4_PATTERN, receipt.receipt_id
    ):
        raise ValueError("authority_store.bootstrap_receipt_invalid")
    if (
        receipt.operation_id != genesis.operation_id
        or receipt.canonical_request_digest != genesis.canonical_request_digest
        or receipt.canonical_root != genesis.canonical_root
        or receipt.filesystem_device != genesis.filesystem_device
        or receipt.filesystem_inode != genesis.filesystem_inode
        or receipt.owner_uid != genesis.owner_uid
    ):
        raise ValueError("authority_store.bootstrap_receipt_mismatch")
    _parse_canonical_timestamp(receipt.confirmed_at)


def _new_uuid(uuid_factory: Callable[[], Any]) -> str:
    value = str(uuid_factory())
    if not _matches(UUID4_PATTERN, value):
        raise ValueError("authority_store.generated_uuid_invalid")
    return value


def _genesis_policy(profile_id: str, created_at: str) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.policy_profile.v1",
        "profile_id": profile_id,
        "profile_version": 1,
        "predecessor_profile_digest": None,
        "created_at": created_at,
        "automatic_enablement": {
            "providers": {"claude": False, "codex": False, "deepseek": False},
            "operation_reasons": {
                "turn.answer": {
                    "clarification_answer": False,
                    "review_clarification_answer": False,
                },
                "turn.consult": {"initial": False},
                "turn.review": {"review_fork": False},
            },
        },
        "automation_enrollments": [],
        "automatic_limits": {
            "provider_starts_per_window": 4,
            "project_starts_per_window": 9,
            "rolling_window_seconds": 86400,
            "continuations_per_root": 6,
            "authority_window_seconds": 86400,
        },
        "storage_admission": {
            "maximum_owned_bytes": 536870912,
            "minimum_free_bytes": 536870912,
            "automatic_cleanup": False,
        },
        "accepted_profile_check_receipts": [],
        "clock_rollback": {"action": "defer", "watermark_required": True},
    }


def _mkdir_private(parent: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent)
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent,
    )
    os.fchmod(descriptor, 0o700)
    metadata = os.fstat(descriptor)
    if not _safe_directory_metadata(metadata):
        os.close(descriptor)
        raise PermissionError("authority_store.created_directory_integrity")
    return descriptor


def _write_new_file(parent: int, name: str, payload: bytes) -> None:
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
                raise OSError("authority_store.write_failed")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("authority_store.created_file_integrity")
    finally:
        os.close(descriptor)


def _trip(failpoint: Any, point: str) -> None:
    if failpoint is None:
        return
    if callable(failpoint):
        failpoint(point)
        return
    if failpoint == point:
        raise AuthorityStoreFailpoint(point)


def _from_inspection(inspection: AuthorityStoreInspection) -> ProjectInitializationResult:
    if inspection.status == "active":
        outcome = "project_already_initialized"
    elif inspection.status == "quarantined":
        outcome = "project_initialization_conflict"
    else:
        outcome = "project_initialization_reconciliation_required"
    return ProjectInitializationResult(
        outcome,
        inspection.detail_code,
        inspection.authority_id,
        inspection.profile_id,
        inspection.ledger_id,
        inspection.genesis_digest,
        inspection.genesis_record_bytes,
    )


def _matches_promoted_bootstrap(
    inspection: AuthorityStoreInspection,
    genesis: ConfirmedProjectGenesis,
) -> bool:
    """Require exact founding correlation for an idempotent operation replay."""

    payload = inspection.genesis_record_bytes
    if payload is None:
        return False
    try:
        record = parse_json_object(payload[:-1] if payload.endswith(b"\n") else payload)
    except StrictJsonError:
        return False
    stored_receipt = record.get("bootstrap_receipt")
    stored_authority = record.get("project_authority")
    receipt = genesis.bootstrap_receipt
    filesystem_identity = {
        "device": genesis.filesystem_device,
        "inode": genesis.filesystem_inode,
        "owner_uid": genesis.owner_uid,
    }
    return (
        type(stored_receipt) is dict
        and type(stored_authority) is dict
        and record.get("operation_id") == genesis.operation_id
        and record.get("canonical_request_digest")
        == genesis.canonical_request_digest
        and stored_receipt
        == {
            "schema": "ask_herdr.bootstrap_receipt.v1",
            "receipt_id": receipt.receipt_id,
            "operation_id": receipt.operation_id,
            "canonical_request_digest": receipt.canonical_request_digest,
            "canonical_root": receipt.canonical_root,
            "filesystem_identity": filesystem_identity,
            "confirmed_at": receipt.confirmed_at,
        }
        and stored_authority.get("canonical_root") == genesis.canonical_root
        and stored_authority.get("filesystem_identity") == filesystem_identity
        and stored_authority.get("lifetime") == genesis.lifetime
    )


def initialize_authority_store(
    genesis: ConfirmedProjectGenesis,
    *,
    uuid_factory: Callable[[], Any],
    clock: Callable[[], datetime],
    failpoint: Any = None,
) -> ProjectInitializationResult:
    """Durably initialize or idempotently inspect one exact first lifetime.

    Injected failpoints raise without cleanup.  No failpoint path re-inspects or
    treats the not-yet-activated staging state as authority.
    """

    _validate_genesis(genesis)
    try:
        with _open_canonical_root(genesis.canonical_root) as root:
            fcntl.flock(root, fcntl.LOCK_EX)
            metadata = os.fstat(root)
            if (
                metadata.st_dev != genesis.filesystem_device
                or metadata.st_ino != genesis.filesystem_inode
                or metadata.st_uid != genesis.owner_uid
                or metadata.st_uid != os.getuid()
            ):
                return ProjectInitializationResult(
                    "project_initialization_conflict",
                    "authority_store.root_identity_mismatch",
                )
            current = _inspect_locked(root, genesis.canonical_root)
            if current.status != "absent":
                if (
                    current.status == "active"
                    and current.operation_id == genesis.operation_id
                    and current.canonical_request_digest
                    == genesis.canonical_request_digest
                ):
                    if _matches_promoted_bootstrap(current, genesis):
                        return _from_inspection(current)
                    return ProjectInitializationResult(
                        "project_initialization_conflict",
                        "authority_store.bootstrap_replay_mismatch",
                        current.authority_id,
                        current.profile_id,
                        current.ledger_id,
                        current.genesis_digest,
                        current.genesis_record_bytes,
                    )
                if current.status == "active":
                    if current.operation_id != genesis.operation_id:
                        return _from_inspection(current)
                    return ProjectInitializationResult(
                        "project_initialization_conflict",
                        "authority_store.initialization_identity_conflict",
                        current.authority_id,
                        current.profile_id,
                        current.ledger_id,
                        current.genesis_digest,
                        current.genesis_record_bytes,
                    )
                return _from_inspection(current)

            authority_id = _new_uuid(uuid_factory)
            profile_id = _new_uuid(uuid_factory)
            ledger_id = _new_uuid(uuid_factory)
            if len({authority_id, profile_id, ledger_id}) != 3:
                raise ValueError("authority_store.generated_uuid_collision")
            recorded_at = _canonical_timestamp(clock())
            policy = _genesis_policy(profile_id, recorded_at)
            policy_digest = _digest(policy)
            filesystem_identity = {
                "device": genesis.filesystem_device,
                "inode": genesis.filesystem_inode,
                "owner_uid": genesis.owner_uid,
            }
            receipt = genesis.bootstrap_receipt
            genesis_record = {
                "schema": "ask_herdr.policy_ledger_record.v1",
                "ledger_id": ledger_id,
                "sequence": 0,
                "previous_record_digest": None,
                "record_kind": "project_genesis",
                "recorded_at": recorded_at,
                "operation_id": genesis.operation_id,
                "canonical_request_digest": genesis.canonical_request_digest,
                "project_authority": {
                    "authority_id": authority_id,
                    "canonical_root": genesis.canonical_root,
                    "filesystem_identity": filesystem_identity,
                    "lifetime": "initial",
                },
                "bootstrap_receipt": {
                    "schema": "ask_herdr.bootstrap_receipt.v1",
                    "receipt_id": receipt.receipt_id,
                    "operation_id": receipt.operation_id,
                    "canonical_request_digest": receipt.canonical_request_digest,
                    "canonical_root": receipt.canonical_root,
                    "filesystem_identity": filesystem_identity,
                    "confirmed_at": receipt.confirmed_at,
                },
                "active_policy": {
                    "profile_id": profile_id,
                    "profile_digest": policy_digest,
                },
            }
            genesis_digest = _digest(genesis_record)
            genesis_record["record_digest"] = genesis_digest
            genesis_bytes = canonical_json(genesis_record) + b"\n"
            active = {
                "schema": "ask_herdr.authority_store_active.v1",
                "authority_id": authority_id,
                "profile_id": profile_id,
                "profile_digest": policy_digest,
                "ledger_id": ledger_id,
                "ledger_head_digest": genesis_digest,
                "operation_id": genesis.operation_id,
                "canonical_request_digest": genesis.canonical_request_digest,
                "profile_object": "policy." + profile_id + ".json",
                "genesis_object": "genesis." + ledger_id + ".json",
            }

            store = _mkdir_private(root, STORE_NAME)
            try:
                objects = _mkdir_private(store, OBJECTS_NAME)
                staging = _mkdir_private(store, STAGING_NAME)
                try:
                    os.fsync(store)
                    os.fsync(root)
                    _trip(failpoint, "after_store_created")
                    _write_new_file(
                        objects,
                        active["profile_object"],
                        canonical_json(policy) + b"\n",
                    )
                    os.fsync(objects)
                    _trip(failpoint, "after_profile_written")
                    _write_new_file(objects, active["genesis_object"], genesis_bytes)
                    os.fsync(objects)
                    _trip(failpoint, "after_genesis_written")
                    stage_name = "active." + genesis.operation_id + ".json"
                    _write_new_file(staging, stage_name, canonical_json(active) + b"\n")
                    os.fsync(staging)
                    _trip(failpoint, "before_activation")
                    try:
                        os.stat(ACTIVE_NAME, dir_fd=store, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        return ProjectInitializationResult(
                            "project_initialization_reconciliation_required",
                            "authority_store.activation_target_present",
                        )
                    os.link(
                        stage_name,
                        ACTIVE_NAME,
                        src_dir_fd=staging,
                        dst_dir_fd=store,
                        follow_symlinks=False,
                    )
                    os.fsync(store)
                    os.unlink(stage_name, dir_fd=staging)
                    os.fsync(staging)
                    if os.stat(
                        ACTIVE_NAME, dir_fd=store, follow_symlinks=False
                    ).st_nlink != 1:
                        return ProjectInitializationResult(
                            "project_initialization_reconciliation_required",
                            "authority_store.activation_link_count",
                        )
                finally:
                    os.close(staging)
                    os.close(objects)
            finally:
                os.close(store)
            result = ProjectInitializationResult(
                "project_initialized",
                "authority_store.initialized",
                authority_id,
                profile_id,
                ledger_id,
                genesis_digest,
                genesis_bytes,
            )
        return result
    except _RootChangedError:
        return ProjectInitializationResult(
            "project_initialization_reconciliation_required",
            "authority_store.root_changed",
        )
    except OSError:
        return ProjectInitializationResult(
            "project_initialization_reconciliation_required",
            "authority_store.write_failed",
        )
