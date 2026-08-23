"""Closed provider-free data and JSON Schema for Machine Core outcomes.

This module is deliberately not wired into CLI discovery yet.  It is an
internal preactivation envelope-core seam whose output can be reviewed and
tested before operation-specific result schemas and the request/outcome schema
family are activated atomically.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Tuple


OUTCOME_MAP_SCHEMA_ID = "ask_herdr.outcome_map.v1"
OUTCOME_SCHEMA_ID = "ask_herdr.outcome.v1"
OUTCOME_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "ask_herdr.outcome.v1.schema.json"
)


_TICKET34_OUTCOME_MAP = {
    "authentication_cancelled_before_mutation": ("succeeded", 0),
    "authentication_external_wrapper_managed": ("failed", 20),
    "authentication_failed": ("failed", 30),
    "authentication_in_progress": ("in_progress", 0),
    "authentication_logged_out": ("succeeded", 0),
    "authentication_not_eligible": ("failed", 20),
    "authentication_ready": ("succeeded", 0),
    "authentication_reconciliation_required": ("reconciliation_required", 40),
    "batch_not_started": ("failed", 20),
    "cleanup_blocked": ("failed", 20),
    "cleanup_completed": ("succeeded", 0),
    "cleanup_nothing_to_do": ("succeeded", 0),
    "cleanup_preview_ready": ("succeeded", 0),
    "cleanup_reconciliation_required": ("reconciliation_required", 40),
    "cleanup_unsupported": ("failed", 30),
    "cursor_stale": ("failed", 40),
    "force_approval_required": ("needs_input", 10),
    "forced_exit_observed": ("succeeded", 0),
    "graceful_exit_observed": ("succeeded", 0),
    "interrupt_identity_mismatch": ("quarantined", 50),
    "interrupt_not_needed": ("succeeded", 0),
    "interrupt_reconciliation_required": ("reconciliation_required", 40),
    "interruption_requested": ("in_progress", 0),
    "lane_busy": ("failed", 20),
    "lane_retired": ("succeeded", 0),
    "namespace_retired": ("succeeded", 0),
    "not_admitted": ("failed", 20),
    "preflight_not_ready": ("failed", 20),
    "preflight_quarantined": ("quarantined", 50),
    "preflight_ready": ("succeeded", 0),
    "preflight_ready_with_warnings": ("succeeded", 0),
    "preflight_reconciliation_required": ("reconciliation_required", 40),
    "profile_shown": ("succeeded", 0),
    "profiles_listed": ("succeeded", 0),
    "project_already_initialized": ("failed", 20),
    "project_initialization_conflict": ("quarantined", 50),
    "project_initialization_reconciliation_required": (
        "reconciliation_required",
        40,
    ),
    "project_initialized": ("succeeded", 0),
    "project_new_lifetime_created": ("succeeded", 0),
    "project_rebind_identity_mismatch": ("quarantined", 50),
    "project_rebind_not_eligible": ("failed", 20),
    "project_rebind_preview_ready": ("succeeded", 0),
    "project_rebind_reconciliation_required": ("reconciliation_required", 40),
    "project_rebound": ("succeeded", 0),
    "project_retired": ("succeeded", 0),
    "project_retirement_not_eligible": ("failed", 20),
    "project_retirement_preview_ready": ("succeeded", 0),
    "project_retirement_reconciliation_required": (
        "reconciliation_required",
        40,
    ),
    "provider_output_limit_exceeded": ("failed", 30),
    "recovery_finalized": ("succeeded", 0),
    "recovery_noop": ("succeeded", 0),
    "recovery_quarantined": ("quarantined", 50),
    "recovery_still_required": ("reconciliation_required", 40),
    "release_not_eligible": ("failed", 20),
    "release_ownership_mismatch": ("quarantined", 50),
    "release_preview_ready": ("succeeded", 0),
    "release_reconciliation_required": ("reconciliation_required", 40),
    "request_invalid": ("failed", 64),
    "request_not_currently_admissible": ("failed", 20),
    "request_quarantined": ("quarantined", 50),
    "request_reconciliation_required": ("reconciliation_required", 40),
    "request_valid": ("succeeded", 0),
    "result_not_settled": ("in_progress", 40),
    "retirement_not_eligible": ("failed", 20),
    "retirement_preview_ready": ("succeeded", 0),
    "session_released": ("succeeded", 0),
    "status_busy": ("in_progress", 40),
    "status_reconciliation_required": ("reconciliation_required", 40),
    "topology_rebuild_eligible": ("succeeded", 0),
    "topology_rebuilt": ("succeeded", 0),
    "workspace_released": ("succeeded", 0),
}


_CLOSURE_OUTCOME_MAP = {
    "delivery_uncertain": ("reconciliation_required", 40),
    "observer_detached": ("in_progress", 0),
    "operation_submitted": ("in_progress", 0),
    "policy_deferred": ("deferred", 76),
    "protocol_failed": ("failed", 30),
    "provider_capacity_exhausted": ("failed", 30),
    "provider_failed": ("failed", 30),
    "turn_clarification": ("needs_input", 10),
    "turn_definite_non_start": ("failed", 30),
    "turn_final": ("succeeded", 0),
    "turn_quarantined": ("quarantined", 50),
    "turn_reconciliation_required": ("reconciliation_required", 40),
}


def _freeze_outcome_map() -> Mapping[str, Mapping[str, Any]]:
    merged = dict(_TICKET34_OUTCOME_MAP)
    merged.update(_CLOSURE_OUTCOME_MAP)
    return MappingProxyType(
        {
            kind: MappingProxyType({"status": status, "exit_class": exit_class})
            for kind, (status, exit_class) in sorted(merged.items())
        }
    )


OUTCOME_MAP = _freeze_outcome_map()


OPERATIONS: Tuple[str, ...] = (
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


EVIDENCE_CLASSES: Tuple[str, ...] = (
    "audit_event",
    "completion_marker",
    "manifest",
    "provider_native",
    "request_packet",
    "response",
    "state",
    "topology_observation",
)
SENSITIVITY_CLASSES: Tuple[str, ...] = (
    "metadata",
    "project_sensitive",
    "provider_sensitive",
    "restricted",
)
EVIDENCE_RELATIONSHIPS: Tuple[str, ...] = (
    "basis",
    "diagnostic",
    "primary_result",
    "provider_identity",
    "retry_basis",
    "supporting",
)
RETENTION_STATES: Tuple[str, ...] = (
    "pending_cleanup",
    "retained",
    "tombstoned",
)


_UUID_V4_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_RFC3339_UTC_PATTERN = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?Z$"
)
_TOKEN_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"
_MEDIA_TYPE_PATTERN = (
    r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+"
    r"(?:;[ -~]+)?$"
)
_JSON_POINTER_PATTERN = r"^(?:/(?:[^~/]|~[01])*)*$"


def _strict_object(
    properties: Dict[str, Any],
    required: Tuple[str, ...],
) -> Dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(required),
        "properties": properties,
    }


def _definitions() -> Dict[str, Any]:
    uuid_v4 = {"type": "string", "pattern": _UUID_V4_PATTERN}
    digest = {"type": "string", "pattern": _DIGEST_PATTERN}
    timestamp = {"type": "string", "pattern": _RFC3339_UTC_PATTERN}
    evidence_id_array = {
        "type": "array",
        "items": {"$ref": "#/$defs/uuid_v4"},
        "uniqueItems": True,
    }

    bound_project = _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.project_binding.v1",
            },
            "binding": {"type": "string", "const": "bound"},
            "root": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": r"^/",
            },
            "authority_id": {"$ref": "#/$defs/uuid_v4"},
        },
        ("schema", "binding", "root", "authority_id"),
    )
    candidate_project = _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.project_binding.v1",
            },
            "binding": {"type": "string", "const": "candidate"},
            "root": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": r"^/",
            },
            "authority_id": {"type": "null"},
        },
        ("schema", "binding", "root", "authority_id"),
    )

    retry = _strict_object(
        {
            "schema": {"type": "string", "const": "ask_herdr.retry.v1"},
            "disposition": {
                "type": "string",
                "enum": [
                    "new_operation_required",
                    "none",
                    "reconcile_first",
                    "safe_retry_eligible",
                ],
            },
            "original_operation_id": {
                "oneOf": [
                    {"type": "null"},
                    {"$ref": "#/$defs/uuid_v4"},
                ]
            },
            "basis_evidence_ref_ids": evidence_id_array,
        },
        (
            "schema",
            "disposition",
            "original_operation_id",
            "basis_evidence_ref_ids",
        ),
    )
    retry["allOf"] = [
        {
            "if": {
                "properties": {"disposition": {"const": "none"}},
                "required": ["disposition"],
            },
            "then": {
                "properties": {
                    "original_operation_id": {"type": "null"},
                    "basis_evidence_ref_ids": {"maxItems": 0},
                }
            },
            "else": {
                "properties": {
                    "original_operation_id": {"$ref": "#/$defs/uuid_v4"},
                    "basis_evidence_ref_ids": {"minItems": 1},
                }
            },
        }
    ]

    policy_decision = _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.policy_decision.v1",
            },
            "decision": {
                "type": "string",
                "enum": ["admitted", "deferred", "denied"],
            },
            "profile_id": {"$ref": "#/$defs/uuid_v4"},
            "profile_version": {
                "type": "integer",
                "minimum": 1,
                "maximum": 9_007_199_254_740_991,
            },
            "profile_digest": {"$ref": "#/$defs/digest"},
            "reason_code": {
                "type": "string",
                "pattern": _TOKEN_PATTERN,
            },
            "evidence_ref_ids": evidence_id_array,
        },
        (
            "schema",
            "decision",
            "profile_id",
            "profile_version",
            "profile_digest",
            "reason_code",
            "evidence_ref_ids",
        ),
    )

    diagnostic = _strict_object(
        {
            "code": {"type": "string", "pattern": _TOKEN_PATTERN},
            "severity": {
                "type": "string",
                "enum": ["error", "info", "warning"],
            },
            "field_pointer": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "string",
                        "maxLength": 4096,
                        "pattern": _JSON_POINTER_PATTERN,
                    },
                ]
            },
            "safe_message": {
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
            },
            "evidence_ref_ids": evidence_id_array,
        },
        (
            "code",
            "severity",
            "field_pointer",
            "safe_message",
            "evidence_ref_ids",
        ),
    )

    evidence_ref = _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.evidence_ref.v1",
            },
            "evidence_id": {"$ref": "#/$defs/uuid_v4"},
            "evidence_class": {
                "type": "string",
                "enum": list(EVIDENCE_CLASSES),
            },
            "media_type": {
                "type": "string",
                "maxLength": 255,
                "pattern": _MEDIA_TYPE_PATTERN,
            },
            "byte_size": {
                "type": "integer",
                "minimum": 0,
                "maximum": 9_007_199_254_740_991,
            },
            "content_digest": {"$ref": "#/$defs/digest"},
            "sensitivity_class": {
                "type": "string",
                "enum": list(SENSITIVITY_CLASSES),
            },
            "creator_operation_id": {"$ref": "#/$defs/uuid_v4"},
            "relationship": {
                "type": "string",
                "enum": list(EVIDENCE_RELATIONSHIPS),
            },
            "retention_state": {
                "type": "string",
                "enum": list(RETENTION_STATES),
            },
            "created_at": {"$ref": "#/$defs/timestamp"},
        },
        (
            "schema",
            "evidence_id",
            "evidence_class",
            "media_type",
            "byte_size",
            "content_digest",
            "sensitivity_class",
            "creator_operation_id",
            "relationship",
            "retention_state",
            "created_at",
        ),
    )

    herdr_observation = _strict_object(
        {
            "observed_at": {"$ref": "#/$defs/timestamp"},
            "kind": {"type": "string", "pattern": _TOKEN_PATTERN},
            "state": {"type": "string", "pattern": _TOKEN_PATTERN},
        },
        ("observed_at", "kind", "state"),
    )
    advisory = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "herdr": {
                "type": "array",
                "items": {"$ref": "#/$defs/herdr_observation"},
            }
        },
    }

    timestamps = _strict_object(
        {
            "started_at": {"$ref": "#/$defs/timestamp"},
            "completed_at": {
                "oneOf": [
                    {"type": "null"},
                    {"$ref": "#/$defs/timestamp"},
                ]
            },
        },
        ("started_at", "completed_at"),
    )

    validation_result = _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.validation_result.v1",
            },
            "captured_bytes": {
                "type": "integer",
                "minimum": 0,
                "maximum": 8_388_608,
            },
            "captured_sha256": {"$ref": "#/$defs/digest"},
            "canonical_bytes": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 8_388_608,
                    },
                ]
            },
            "redacted_field_locations": {
                "type": "array",
                "items": {
                    "type": "string",
                    "maxLength": 4096,
                    "pattern": _JSON_POINTER_PATTERN,
                },
                "uniqueItems": True,
            },
            "current_preconditions": {
                "type": "array",
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": _TOKEN_PATTERN,
                },
                "uniqueItems": True,
            },
        },
        (
            "schema",
            "captured_bytes",
            "captured_sha256",
            "canonical_bytes",
            "redacted_field_locations",
            "current_preconditions",
        ),
    )

    return {
        "uuid_v4": uuid_v4,
        "digest": digest,
        "timestamp": timestamp,
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "project_binding": {"oneOf": [bound_project, candidate_project]},
        "retry": retry,
        "policy_decision": policy_decision,
        "diagnostic": diagnostic,
        "evidence_ref": evidence_ref,
        "herdr_observation": herdr_observation,
        "advisory": advisory,
        "timestamps": timestamps,
        "validation_result": validation_result,
    }


_VALIDATION_OUTCOME_KINDS = {
    "request_invalid",
    "request_not_currently_admissible",
    "request_quarantined",
    "request_reconciliation_required",
    "request_valid",
}

VALIDATION_OUTCOME_KINDS = tuple(sorted(_VALIDATION_OUTCOME_KINDS))

_VALIDATION_FAILURE_OUTCOME_KINDS = _VALIDATION_OUTCOME_KINDS - {
    "request_valid"
}


def _mapping_branch(
    kind: str,
    mapping: Mapping[str, Any],
) -> Dict[str, Any]:
    properties: Dict[str, Any] = {
        "outcome_kind": {"type": "string", "const": kind},
        "status": {"type": "string", "const": mapping["status"]},
        "exit_class": {"type": "integer", "const": mapping["exit_class"]},
    }
    if kind not in _VALIDATION_FAILURE_OUTCOME_KINDS:
        properties["request_digest"] = {"$ref": "#/$defs/digest"}
    if kind in _VALIDATION_OUTCOME_KINDS:
        properties.update(
            {
                "policy": {"type": "null"},
                "result": {"$ref": "#/$defs/validation_result"},
                "advisory": {"type": "object", "maxProperties": 0},
            }
        )
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
    }


def build_outcome_schema() -> Dict[str, Any]:
    """Build the strict, unadvertised Draft 2020-12 envelope core."""

    required = (
        "schema",
        "operation",
        "operation_id",
        "request_digest",
        "project",
        "status",
        "outcome_kind",
        "exit_class",
        "retry",
        "policy",
        "result",
        "diagnostics",
        "evidence_refs",
        "advisory",
        "timestamps",
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:ask-herdr:schema:ask_herdr.outcome.v1",
        "title": "ask_herdr.outcome.v1",
        "type": "object",
        "additionalProperties": False,
        "required": list(required),
        "properties": {
            "schema": {"type": "string", "const": OUTCOME_SCHEMA_ID},
            "operation": {"$ref": "#/$defs/operation"},
            "operation_id": {"$ref": "#/$defs/uuid_v4"},
            "request_digest": {
                "oneOf": [
                    {"type": "null"},
                    {"$ref": "#/$defs/digest"},
                ]
            },
            "project": {"$ref": "#/$defs/project_binding"},
            "status": {
                "type": "string",
                "enum": [
                    "deferred",
                    "failed",
                    "in_progress",
                    "needs_input",
                    "quarantined",
                    "reconciliation_required",
                    "succeeded",
                ],
            },
            "outcome_kind": {
                "type": "string",
                "enum": sorted(OUTCOME_MAP),
            },
            "exit_class": {
                "type": "integer",
                "enum": [0, 10, 20, 30, 40, 50, 64, 76],
            },
            "retry": {"$ref": "#/$defs/retry"},
            "policy": {
                "oneOf": [
                    {"type": "null"},
                    {"$ref": "#/$defs/policy_decision"},
                ]
            },
            "result": {
                "oneOf": [
                    {"$ref": "#/$defs/validation_result"},
                    _strict_object(
                        {
                            "schema": {
                                "type": "string",
                                "pattern": (
                                    r"^ask_herdr\.[a-z0-9_.]+\.result\.v1$"
                                ),
                            }
                        },
                        ("schema",),
                    ),
                ]
            },
            "diagnostics": {
                "type": "array",
                "items": {"$ref": "#/$defs/diagnostic"},
            },
            "evidence_refs": {
                "type": "array",
                "items": {"$ref": "#/$defs/evidence_ref"},
            },
            "advisory": {"$ref": "#/$defs/advisory"},
            "timestamps": {"$ref": "#/$defs/timestamps"},
        },
        "allOf": [
            {
                "oneOf": [
                    _mapping_branch(kind, mapping)
                    for kind, mapping in OUTCOME_MAP.items()
                ]
            }
        ],
        "$defs": _definitions(),
    }


def build_validation_outcome_schema() -> Dict[str, Any]:
    """Build public semantic-version 1.0.0 for provider-free validation."""

    schema = build_outcome_schema()
    schema["$comment"] = (
        "ask_herdr.outcome.v1 semantic version 1.0.0: the five provider-free "
        "machine.validate outcomes. Runtime outcome branches are not supported "
        "while machine_run is false."
    )
    schema["properties"]["outcome_kind"]["enum"] = list(
        VALIDATION_OUTCOME_KINDS
    )
    schema["properties"]["result"] = {"$ref": "#/$defs/validation_result"}
    schema["allOf"] = [
        {
            "oneOf": [
                _mapping_branch(kind, OUTCOME_MAP[kind])
                for kind in VALIDATION_OUTCOME_KINDS
            ]
        }
    ]
    return schema
