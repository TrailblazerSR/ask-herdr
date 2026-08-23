"""Closed provider-free metadata for the Machine Core operation surface.

This module is deliberately data-only: importing it performs no filesystem,
provider, Herdr, network, or process action.  The public matrix is immutable so
schema generation and semantic validation can share one exact operation model.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Tuple


@dataclass(frozen=True)
class OperationContract:
    """The closed request-envelope compatibility rules for one operation."""

    operation: str
    payload_schema_id: str
    authority_class: str
    allowed_action_reasons: Tuple[str, ...]
    allowed_project_bindings: Tuple[str, ...]
    allowed_observation_modes: Tuple[str, ...]


OPERATION_NAMES = (
    "cleanup.execute",
    "cleanup.preview",
    "cleanup.resume",
    "cleanup.status",
    "policy.activate.execute",
    "policy.activate.preview",
    "policy.compact.execute",
    "policy.compact.preview",
    "policy.show",
    "policy.status",
    "policy.validate",
    "process.interrupt.force",
    "process.interrupt.graceful",
    "profile.auth.login",
    "profile.auth.logout",
    "profile.auth.status",
    "profile.check",
    "profile.list",
    "profile.show",
    "project.init",
    "project.rebind.execute",
    "project.rebind.preview",
    "project.retire.execute",
    "project.retire.preview",
    "query.evidence",
    "query.result",
    "query.status",
    "recovery.rebuild_topology",
    "recovery.reconcile",
    "recovery.retire.lane.execute",
    "recovery.retire.lane.preview",
    "recovery.retire.namespace.execute",
    "recovery.retire.namespace.preview",
    "system.preflight",
    "topology.release.session.execute",
    "topology.release.session.preview",
    "topology.release.session.resume",
    "topology.release.workspace.execute",
    "topology.release.workspace.preview",
    "topology.release.workspace.resume",
    "turn.answer",
    "turn.consult",
    "turn.recovery_continue",
    "turn.review",
    "turn.safe_retry",
)

_PUBLIC_READ = frozenset(
    {
        "cleanup.status",
        "policy.show",
        "policy.status",
        "policy.validate",
        "profile.auth.status",
        "profile.check",
        "profile.list",
        "profile.show",
        "query.status",
        "system.preflight",
    }
)

_EVIDENCE_CONTENT_READ = frozenset({"query.evidence", "query.result"})

_GRANT_OR_HUMAN = frozenset(
    {
        "topology.release.workspace.execute",
        "topology.release.workspace.preview",
        "topology.release.workspace.resume",
        "turn.answer",
        "turn.consult",
        "turn.recovery_continue",
        "turn.review",
        "turn.safe_retry",
    }
)

_IMMEDIATE_ONLY = frozenset(
    {
        "cleanup.preview",
        "cleanup.status",
        "policy.activate.preview",
        "policy.compact.preview",
        "policy.show",
        "policy.status",
        "policy.validate",
        "profile.auth.status",
        "profile.check",
        "profile.list",
        "profile.show",
        "project.init",
        "project.rebind.preview",
        "project.retire.preview",
        "query.evidence",
        "recovery.retire.lane.preview",
        "recovery.retire.namespace.preview",
        "system.preflight",
        "topology.release.session.preview",
        "topology.release.workspace.preview",
    }
)


def _authority_class(operation: str) -> str:
    if operation in _PUBLIC_READ:
        return "public_read"
    if operation in _EVIDENCE_CONTENT_READ:
        return "evidence_content_read"
    if operation in _GRANT_OR_HUMAN:
        return "grant_or_human"
    if operation == "project.init":
        return "bootstrap_human_only"
    return "direct_human_only"


def _action_reasons(operation: str) -> Tuple[str, ...]:
    if operation in _PUBLIC_READ or operation in _EVIDENCE_CONTENT_READ:
        return ("inspect",)
    if operation == "turn.consult":
        return ("initial",)
    if operation == "turn.answer":
        return ("clarification_answer", "review_clarification_answer")
    if operation == "turn.review":
        return ("review_fork",)
    if operation == "turn.safe_retry":
        return ("safe_retry",)
    if operation == "turn.recovery_continue":
        return ("recovery_continuation",)
    if operation.startswith("topology.release."):
        return ("release",)
    if operation.startswith("recovery."):
        return ("recover",)
    if operation.startswith("process.interrupt."):
        return ("interrupt",)
    if operation.startswith("cleanup."):
        return ("cleanup",)
    if operation.startswith("project."):
        return ("project_admin",)
    if operation.startswith("policy."):
        return ("policy_admin",)
    if operation in {"profile.auth.login", "profile.auth.logout"}:
        return ("authentication",)
    raise AssertionError(f"operation lacks an action-reason rule: {operation}")


def _project_bindings(operation: str) -> Tuple[str, ...]:
    if operation == "project.init":
        return ("candidate",)
    if operation == "system.preflight":
        return ("bound", "candidate")
    return ("bound",)


def _observation_modes(operation: str) -> Tuple[str, ...]:
    if operation in _IMMEDIATE_ONLY:
        return ("immediate",)
    if operation in {"query.result", "query.status"}:
        return ("immediate", "wait")
    return ("submit_only", "wait")


def _build_contract(operation: str) -> OperationContract:
    return OperationContract(
        operation=operation,
        payload_schema_id=f"ask_herdr.{operation}.payload.v1",
        authority_class=_authority_class(operation),
        allowed_action_reasons=_action_reasons(operation),
        allowed_project_bindings=_project_bindings(operation),
        allowed_observation_modes=_observation_modes(operation),
    )


OPERATION_CONTRACTS: Mapping[str, OperationContract] = MappingProxyType(
    {operation: _build_contract(operation) for operation in OPERATION_NAMES}
)


def get_operation_contract(operation: str) -> OperationContract:
    """Return the exact contract or reject an unadvertised operation."""

    return OPERATION_CONTRACTS[operation]


if len(OPERATION_CONTRACTS) != 45:
    raise AssertionError("the operation contract must cover exactly 45 operations")
