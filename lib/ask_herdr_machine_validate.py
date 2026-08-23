"""Provider-free validation for one strict Machine Core request.

The module is intentionally read-only.  It validates the public request
schema, compiles the currently implemented ``project.init`` semantic slice,
and reports every other operation as not currently admissible until its
authority-backed semantic compiler is available.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import os
import re
import stat
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Tuple

from ask_herdr_authority_store import (
    AuthorityStoreInspection,
    inspect_authority_store,
)
from ask_herdr_json import canonical_json
from ask_herdr_machine_semantics import (
    CandidateProjectFacts,
    SemanticValidationError,
    compile_project_init_request,
)
from ask_herdr_operation_contract import OPERATION_CONTRACTS
from ask_herdr_outcome_contract import (
    OUTCOME_MAP,
    OUTCOME_SCHEMA_ID,
    build_validation_outcome_schema,
)
from ask_herdr_request_schema import (
    CANONICAL_ABSOLUTE_PATH_PATTERN,
    REQUEST_SCHEMA_ID,
    UUID4_PATTERN,
    build_request_schema,
)
from ask_herdr_project_mutation_lease import (
    ValidatedProjectMutationBinding,
)
from ask_herdr_recovery_reconcile import (
    RecoveryReconcileCompileError,
    compile_lane_recovery_reconcile_preview,
)
from ask_herdr_schema_validator import SchemaViolation, validate


VALIDATION_RESULT_SCHEMA_ID = "ask_herdr.validation_result.v1"
PROJECT_BINDING_SCHEMA_ID = "ask_herdr.project_binding.v1"
RETRY_SCHEMA_ID = "ask_herdr.retry.v1"


class TrustedHeaderError(ValueError):
    """The input cannot safely identify an outcome envelope."""

    code = "request.header_invalid"


@dataclass(frozen=True)
class ValidationDecision:
    outcome_kind: str
    request_digest: Optional[str]
    canonical_bytes: Optional[int]
    current_preconditions: Tuple[str, ...]
    diagnostic_code: Optional[str]
    diagnostic_pointer: Optional[str]
    diagnostic_message: Optional[str]


class _ProjectInspectionError(ValueError):
    def __init__(
        self,
        outcome_kind: str,
        code: str,
        pointer: str,
        message: str,
        precondition: str,
    ) -> None:
        super().__init__(code)
        self.outcome_kind = outcome_kind
        self.code = code
        self.pointer = pointer
        self.message = message
        self.precondition = precondition


class _ProjectPathChangedError(OSError):
    """The descriptor walk no longer matches the caller-visible path."""


def _is_uuid4(value: Any) -> bool:
    return type(value) is str and re.fullmatch(UUID4_PATTERN, value) is not None


def _is_canonical_absolute_path(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 4096
        and re.fullmatch(CANONICAL_ABSOLUTE_PATH_PATTERN, value) is not None
        and os.path.normpath(value) == value
    )


def trust_request_header(request: Mapping[str, Any]) -> None:
    """Require the four exact values needed to build a safe outcome envelope."""

    if request.get("schema") != REQUEST_SCHEMA_ID:
        raise TrustedHeaderError(TrustedHeaderError.code)
    operation = request.get("operation")
    if type(operation) is not str or operation not in OPERATION_CONTRACTS:
        raise TrustedHeaderError(TrustedHeaderError.code)
    if not _is_uuid4(request.get("operation_id")):
        raise TrustedHeaderError(TrustedHeaderError.code)
    project = request.get("project")
    if type(project) is not dict or set(project) != {
        "schema",
        "binding",
        "root",
        "authority_id",
    }:
        raise TrustedHeaderError(TrustedHeaderError.code)
    if project.get("schema") != PROJECT_BINDING_SCHEMA_ID:
        raise TrustedHeaderError(TrustedHeaderError.code)
    binding = project.get("binding")
    if binding not in {"bound", "candidate"}:
        raise TrustedHeaderError(TrustedHeaderError.code)
    if not _is_canonical_absolute_path(project.get("root")):
        raise TrustedHeaderError(TrustedHeaderError.code)
    authority_id = project.get("authority_id")
    if (binding == "candidate" and authority_id is not None) or (
        binding == "bound" and not _is_uuid4(authority_id)
    ):
        raise TrustedHeaderError(TrustedHeaderError.code)


def _descriptor_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


@contextmanager
def _open_directory_descriptor(raw_path: str) -> Iterator[int]:
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow | close_on_exec
    descriptors = []
    snapshots = []
    bindings = []
    try:
        descriptor = os.open(os.path.sep, flags)
        descriptors.append(descriptor)
        snapshots.append(os.fstat(descriptor))
        for component in filter(None, raw_path.split(os.path.sep)[1:]):
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            bindings.append((descriptor, component, next_descriptor))
            descriptor = next_descriptor
            descriptors.append(descriptor)
            snapshots.append(os.fstat(descriptor))
        yield descriptor
        try:
            for opened_descriptor, snapshot in zip(descriptors, snapshots):
                if _descriptor_identity(
                    os.fstat(opened_descriptor)
                ) != _descriptor_identity(snapshot):
                    raise _ProjectPathChangedError
            for parent_descriptor, component, child_descriptor in bindings:
                current_binding = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if _descriptor_identity(current_binding) != _descriptor_identity(
                    os.fstat(child_descriptor)
                ):
                    raise _ProjectPathChangedError
        except _ProjectPathChangedError:
            raise
        except OSError as error:
            raise _ProjectPathChangedError from error
    finally:
        for opened_descriptor in reversed(descriptors):
            os.close(opened_descriptor)


def inspect_candidate_project_root(raw_root: str) -> CandidateProjectFacts:
    """Resolve one stable, owner-bound Candidate Project root identity."""

    try:
        with _open_directory_descriptor(raw_root) as descriptor:
            before = os.fstat(descriptor)
            if not stat.S_ISDIR(before.st_mode):
                raise _ProjectInspectionError(
                    "request_quarantined",
                    "project.root_not_directory",
                    "/project/root",
                    "candidate project root is not a directory",
                    "project.root_not_directory",
                )
            if hasattr(os, "getuid") and before.st_uid != os.getuid():
                raise _ProjectInspectionError(
                    "request_quarantined",
                    "project.root_owner_mismatch",
                    "/project/root",
                    "candidate project root owner does not match the current user",
                    "project.root_owner_mismatch",
                )
            after = os.fstat(descriptor)
            if any(
                getattr(before, field) != getattr(after, field)
                for field in ("st_dev", "st_ino", "st_mode", "st_uid")
            ):
                raise _ProjectPathChangedError
            facts = CandidateProjectFacts(
                canonical_root=raw_root,
                filesystem_device=before.st_dev,
                filesystem_inode=before.st_ino,
                owner_uid=before.st_uid,
            )
        return facts
    except _ProjectPathChangedError as error:
        raise _ProjectInspectionError(
            "request_reconciliation_required",
            "project.root_changed_during_validation",
            "/project/root",
            "candidate project root changed during validation",
            "project.root_changed",
        ) from error
    except FileNotFoundError as error:
        raise _ProjectInspectionError(
            "request_not_currently_admissible",
            "project.root_missing",
            "/project/root",
            "candidate project root does not exist",
            "project.root_missing",
        ) from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            outcome_kind = "request_quarantined"
            code = "project.root_identity_unsafe"
            precondition = "project.root_identity_unsafe"
            message = "candidate project root identity is not safely resolvable"
        else:
            outcome_kind = "request_reconciliation_required"
            code = "project.root_unobservable"
            precondition = "project.root_unobservable"
            message = "candidate project root cannot be safely inspected"
        raise _ProjectInspectionError(
            outcome_kind,
            code,
            "/project/root",
            message,
            precondition,
        ) from error


def _schema_invalid_decision(violations: Sequence[SchemaViolation]) -> ValidationDecision:
    pointer = next((item.pointer for item in violations if item.pointer), "")
    return ValidationDecision(
        outcome_kind="request_invalid",
        request_digest=None,
        canonical_bytes=None,
        current_preconditions=(),
        diagnostic_code="request.schema_invalid",
        diagnostic_pointer=pointer,
        diagnostic_message="request does not match its declared operation schema",
    )


def _authority_store_failure_decision(
    inspection: AuthorityStoreInspection,
) -> Optional[ValidationDecision]:
    """Translate a fail-closed store observation into a validation outcome."""

    if inspection.status == "quarantined":
        outcome_kind = "request_quarantined"
        precondition = "authority.store_quarantined"
        message = "project Authority Store integrity is contradictory"
    elif inspection.status == "reconciliation_required":
        outcome_kind = "request_reconciliation_required"
        precondition = "authority.store_reconciliation_required"
        message = "project Authority Store requires explicit reconciliation"
    else:
        return None
    return ValidationDecision(
        outcome_kind=outcome_kind,
        request_digest=None,
        canonical_bytes=None,
        current_preconditions=(precondition,),
        diagnostic_code=inspection.detail_code,
        diagnostic_pointer="/project/root",
        diagnostic_message=message,
    )


def _project_init_decision(request: Mapping[str, Any]) -> ValidationDecision:
    try:
        project_facts = inspect_candidate_project_root(request["project"]["root"])
    except _ProjectInspectionError as error:
        return ValidationDecision(
            outcome_kind=error.outcome_kind,
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=(error.precondition,),
            diagnostic_code=error.code,
            diagnostic_pointer=error.pointer,
            diagnostic_message=error.message,
        )
    store = inspect_authority_store(project_facts.canonical_root)
    store_failure = _authority_store_failure_decision(store)
    if store_failure is not None:
        return store_failure
    if store.status == "busy":
        return ValidationDecision(
            outcome_kind="request_not_currently_admissible",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=("authority.store_busy",),
            diagnostic_code=store.detail_code,
            diagnostic_pointer="/project/root",
            diagnostic_message="project Authority Store is currently busy",
        )
    try:
        compiled = compile_project_init_request(request, project_facts)
    except SemanticValidationError as error:
        return ValidationDecision(
            outcome_kind="request_invalid",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=("project.root_identity_verified",),
            diagnostic_code=error.code,
            diagnostic_pointer=error.field_pointer,
            diagnostic_message="request semantic fields are inconsistent",
        )
    preconditions = [
        "project.root_identity_verified",
        "semantic.projection_compiled",
    ]
    if store.status == "active":
        preconditions.extend(
            (
                "authority.store_integrity_verified",
                "project.authority_store_active",
            )
        )
        return ValidationDecision(
            outcome_kind="request_not_currently_admissible",
            request_digest=compiled.canonical_request_digest,
            canonical_bytes=None,
            current_preconditions=tuple(sorted(preconditions)),
            diagnostic_code="project.authority_store_active",
            diagnostic_pointer="/project/root",
            diagnostic_message="candidate project root already has an active authority",
        )
    if request["payload"]["lifetime"] == "after_tombstone":
        preconditions.append("project.predecessor_tombstone_unavailable")
        return ValidationDecision(
            outcome_kind="request_not_currently_admissible",
            request_digest=compiled.canonical_request_digest,
            canonical_bytes=None,
            current_preconditions=tuple(sorted(preconditions)),
            diagnostic_code="project.predecessor_tombstone_unavailable",
            diagnostic_pointer="/payload",
            diagnostic_message="the predecessor tombstone is not currently available",
        )
    preconditions.append("project.authority_store_absent")
    return ValidationDecision(
        outcome_kind="request_valid",
        request_digest=compiled.canonical_request_digest,
        canonical_bytes=None,
        current_preconditions=tuple(sorted(preconditions)),
        diagnostic_code=None,
        diagnostic_pointer=None,
        diagnostic_message=None,
    )


def _authority_backed_deferred_decision(
    request: Mapping[str, Any],
) -> ValidationDecision:
    """Validate project/store correlation before deferring inactive semantics."""

    try:
        project_facts = inspect_candidate_project_root(request["project"]["root"])
    except _ProjectInspectionError as error:
        return ValidationDecision(
            outcome_kind=error.outcome_kind,
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=(error.precondition,),
            diagnostic_code=error.code,
            diagnostic_pointer=error.pointer,
            diagnostic_message=error.message,
        )
    store = inspect_authority_store(project_facts.canonical_root)
    store_failure = _authority_store_failure_decision(store)
    if store_failure is not None:
        return store_failure

    preconditions = ["semantic.compiler_not_active"]
    diagnostic_code = "semantic.compiler_not_active"
    diagnostic_pointer = "/operation"
    diagnostic_message = "operation semantic validation is not active in this build"
    if store.status == "active":
        preconditions.append("authority.store_integrity_verified")
        if request["project"]["binding"] == "bound":
            if request["project"]["authority_id"] != store.authority_id:
                return ValidationDecision(
                    outcome_kind="request_quarantined",
                    request_digest=None,
                    canonical_bytes=None,
                    current_preconditions=(
                        "authority.store_integrity_verified",
                        "project.binding_mismatch",
                    ),
                    diagnostic_code="project.authority_identity_mismatch",
                    diagnostic_pointer="/project/authority_id",
                    diagnostic_message=(
                        "bound Project Authority Identity does not match the store"
                    ),
                )
            preconditions.append("project.binding_verified")
        else:
            preconditions.append("project.authority_store_active")
    elif store.status == "absent":
        preconditions.append("authority.store_absent")
    elif store.status == "busy":
        preconditions = ["authority.store_busy"]
        diagnostic_code = store.detail_code
        diagnostic_pointer = "/project/root"
        diagnostic_message = "project Authority Store is currently busy"
    else:
        return ValidationDecision(
            outcome_kind="request_reconciliation_required",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=("authority.store_state_unknown",),
            diagnostic_code="authority_store.state_unknown",
            diagnostic_pointer="/project/root",
            diagnostic_message="project Authority Store state is not recognized",
        )
    return ValidationDecision(
        outcome_kind="request_not_currently_admissible",
        request_digest=None,
        canonical_bytes=None,
        current_preconditions=tuple(sorted(preconditions)),
        diagnostic_code=diagnostic_code,
        diagnostic_pointer=diagnostic_pointer,
        diagnostic_message=diagnostic_message,
    )


def _recovery_reconcile_decision(
    request: Mapping[str, Any],
) -> ValidationDecision:
    """Compile one exact Lane recovery preview without creating authority."""

    try:
        project_facts = inspect_candidate_project_root(
            request["project"]["root"]
        )
    except _ProjectInspectionError as error:
        return ValidationDecision(
            outcome_kind=error.outcome_kind,
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=(error.precondition,),
            diagnostic_code=error.code,
            diagnostic_pointer=error.pointer,
            diagnostic_message=error.message,
        )
    store = inspect_authority_store(project_facts.canonical_root)
    store_failure = _authority_store_failure_decision(store)
    if store_failure is not None:
        return store_failure
    if store.status == "busy":
        return ValidationDecision(
            outcome_kind="request_not_currently_admissible",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=("authority.store_busy",),
            diagnostic_code=store.detail_code,
            diagnostic_pointer="/project/root",
            diagnostic_message="project Authority Store is currently busy",
        )
    if store.status != "active":
        return ValidationDecision(
            outcome_kind="request_not_currently_admissible",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=("authority.store_absent",),
            diagnostic_code="authority_store.absent",
            diagnostic_pointer="/project/root",
            diagnostic_message="project Authority Store is not active",
        )
    if request["project"]["authority_id"] != store.authority_id:
        return ValidationDecision(
            outcome_kind="request_quarantined",
            request_digest=None,
            canonical_bytes=None,
            current_preconditions=(
                "authority.store_integrity_verified",
                "project.binding_mismatch",
            ),
            diagnostic_code="project.authority_identity_mismatch",
            diagnostic_pointer="/project/authority_id",
            diagnostic_message=(
                "bound Project Authority Identity does not match the store"
            ),
        )
    try:
        binding = ValidatedProjectMutationBinding(
            canonical_root=project_facts.canonical_root,
            filesystem_device=project_facts.filesystem_device,
            filesystem_inode=project_facts.filesystem_inode,
            owner_uid=project_facts.owner_uid,
            project_authority_id=store.authority_id,
        )
        preview = compile_lane_recovery_reconcile_preview(request, binding)
    except RecoveryReconcileCompileError as error:
        preconditions = {
            "authority.store_integrity_verified",
            "project.binding_verified",
            *error.current_preconditions,
        }
        return ValidationDecision(
            outcome_kind=error.outcome_kind,
            request_digest=error.canonical_request_digest,
            canonical_bytes=None,
            current_preconditions=tuple(sorted(preconditions)),
            diagnostic_code=error.detail_code,
            diagnostic_pointer="/payload",
            diagnostic_message=(
                "recovery scope cannot be compiled from current durable state"
            ),
        )
    preconditions = {
        "authority.human_confirmation_not_active",
        "authority.store_integrity_verified",
        "operation.idempotency_record_not_active",
        "project.binding_verified",
        "semantic.projection_compiled",
        *preview.current_preconditions,
    }
    return ValidationDecision(
        outcome_kind="request_not_currently_admissible",
        request_digest=preview.canonical_request_digest,
        canonical_bytes=None,
        current_preconditions=tuple(sorted(preconditions)),
        diagnostic_code="authority.human_confirmation_not_active",
        diagnostic_pointer="/authority_ref",
        diagnostic_message=(
            "trusted human confirmation is not active in this build"
        ),
    )


def _decision_for_request(request: Mapping[str, Any]) -> ValidationDecision:
    violations = validate(request, build_request_schema())
    if violations:
        return _schema_invalid_decision(violations)
    if request["operation"] == "project.init":
        return _project_init_decision(request)
    if request["operation"] == "recovery.reconcile":
        return _recovery_reconcile_decision(request)
    return _authority_backed_deferred_decision(request)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def validate_request(
    request: Mapping[str, Any],
    captured: bytes,
    *,
    started_at: Optional[str] = None,
) -> Tuple[Dict[str, Any], int]:
    """Return one strict validation outcome and its exact exit class."""

    trust_request_header(request)
    started = started_at or _utc_timestamp()
    canonical_request = canonical_json(dict(request))
    decision = _decision_for_request(request)
    if decision.outcome_kind != "request_invalid":
        decision = ValidationDecision(
            outcome_kind=decision.outcome_kind,
            request_digest=decision.request_digest,
            canonical_bytes=len(canonical_request),
            current_preconditions=decision.current_preconditions,
            diagnostic_code=decision.diagnostic_code,
            diagnostic_pointer=decision.diagnostic_pointer,
            diagnostic_message=decision.diagnostic_message,
        )
    mapping = OUTCOME_MAP[decision.outcome_kind]
    diagnostics = []
    if decision.diagnostic_code is not None:
        diagnostics.append(
            {
                "code": decision.diagnostic_code,
                "severity": "error",
                "field_pointer": decision.diagnostic_pointer,
                "safe_message": decision.diagnostic_message,
                "evidence_ref_ids": [],
            }
        )
    outcome = {
        "schema": OUTCOME_SCHEMA_ID,
        "operation": request["operation"],
        "operation_id": request["operation_id"],
        "request_digest": decision.request_digest,
        "project": dict(request["project"]),
        "status": mapping["status"],
        "outcome_kind": decision.outcome_kind,
        "exit_class": mapping["exit_class"],
        "retry": {
            "schema": RETRY_SCHEMA_ID,
            "disposition": "none",
            "original_operation_id": None,
            "basis_evidence_ref_ids": [],
        },
        "policy": None,
        "result": {
            "schema": VALIDATION_RESULT_SCHEMA_ID,
            "captured_bytes": len(captured),
            "captured_sha256": "sha256:" + hashlib.sha256(captured).hexdigest(),
            "canonical_bytes": decision.canonical_bytes,
            "redacted_field_locations": sorted(
                {
                    item
                    for item in (decision.diagnostic_pointer,)
                    if item is not None
                }
            ),
            "current_preconditions": sorted(
                set(decision.current_preconditions)
            ),
        },
        "diagnostics": diagnostics,
        "evidence_refs": [],
        "advisory": {},
        "timestamps": {
            "started_at": started,
            "completed_at": _utc_timestamp(),
        },
    }
    if validate(outcome, build_validation_outcome_schema()):
        raise RuntimeError("validation.outcome_construction_failed")
    return outcome, mapping["exit_class"]
