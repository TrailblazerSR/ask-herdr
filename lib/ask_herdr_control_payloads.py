"""Standalone schemas for the provider-free control/query payload family.

The builder is intentionally unregistered.  It performs no filesystem, Herdr,
provider, process, or network action and returns fresh schema documents so the
complete request union can activate them atomically later.  Array ordering and
set completeness are semantic checks; JSON Schema enforces their closed shape
and duplicate-free representation.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping


JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
UUID4_PATTERN = (
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
CANONICAL_ABSOLUTE_PATH_PATTERN = "^/[^\\u0000]*$"
SAFE_NAME_PATTERN = "^[a-z][a-z0-9-]{0,63}$"
CONSULTANT_KEY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,63}$"
OPAQUE_CURSOR_PATTERN = "^[\\x21-\\x7e]{1,1024}$"


CONTROL_PAYLOAD_OPERATIONS = (
    "process.interrupt.force",
    "process.interrupt.graceful",
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
)


Schema = Dict[str, Any]


def _strict_object(properties: Mapping[str, Any], required: Iterable[str]) -> Schema:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required),
    }


def _tag(schema_id: str) -> Schema:
    return {"type": "string", "const": schema_id}


def _literal(value: str) -> Schema:
    return {"type": "string", "const": value}


def _uuid4() -> Schema:
    return {"type": "string", "pattern": UUID4_PATTERN}


def _digest() -> Schema:
    return {"type": "string", "pattern": SHA256_DIGEST_PATTERN}


def _generation() -> Schema:
    return {"type": "integer", "minimum": 1}


def _payload_schema(
    operation: str, properties: Mapping[str, Any], required: Iterable[str]
) -> Schema:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        **_strict_object(
            {
                "schema": _tag(f"ask_herdr.{operation}.payload.v1"),
                **dict(properties),
            },
            ["schema", *required],
        ),
    }


def _tagged_variant(schema_id: str, kind: str, properties: Mapping[str, Any]) -> Schema:
    return _strict_object(
        {
            "schema": _tag(schema_id),
            "kind": _literal(kind),
            **dict(properties),
        },
        ["schema", "kind", *properties.keys()],
    )


def _query_status_selector() -> Schema:
    schema_id = "ask_herdr.query.status.selector.v1"
    return {
        "oneOf": [
            _tagged_variant(schema_id, "project", {}),
            _tagged_variant(
                schema_id,
                "key",
                {
                    "consultant_key": {
                        "type": "string",
                        "maxLength": 64,
                        "pattern": CONSULTANT_KEY_PATTERN,
                    }
                },
            ),
            _tagged_variant(schema_id, "lane", {"lane_id": _uuid4()}),
            _tagged_variant(
                schema_id, "operation", {"operation_id": _uuid4()}
            ),
        ]
    }


def _query_status() -> Schema:
    return _payload_schema(
        "query.status",
        {
            "selector": _query_status_selector(),
            "advisory": {"type": "string", "enum": ["none", "summary", "full"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            "cursor": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "string", "pattern": OPAQUE_CURSOR_PATTERN},
                ]
            },
        },
        ["selector", "advisory", "limit", "cursor"],
    )


def _query_result() -> Schema:
    return _payload_schema(
        "query.result",
        {
            "operation_id": _uuid4(),
            "expected_request_digest": _digest(),
        },
        ["operation_id", "expected_request_digest"],
    )


def _evidence_selection() -> Schema:
    schema_id = "ask_herdr.evidence_selection.v1"
    return {
        "oneOf": [
            _strict_object(
                {
                    "schema": _tag(schema_id),
                    "mode": _literal("whole"),
                },
                ["schema", "mode"],
            ),
            _strict_object(
                {
                    "schema": _tag(schema_id),
                    "mode": _literal("range"),
                    "offset": {"type": "integer", "minimum": 0},
                    "length": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1_048_576,
                    },
                },
                ["schema", "mode", "offset", "length"],
            ),
        ]
    }


def _query_evidence() -> Schema:
    return _payload_schema(
        "query.evidence",
        {
            "evidence_ref_id": _uuid4(),
            "expected_evidence_digest": _digest(),
            "selection": _evidence_selection(),
        },
        ["evidence_ref_id", "expected_evidence_digest", "selection"],
    )


def _profile_selector() -> Schema:
    return _strict_object(
        {
            "schema": _tag("ask_herdr.profile_selector.v1"),
            "provider": {"type": "string", "pattern": SAFE_NAME_PATTERN},
            "profile": {"type": "string", "pattern": SAFE_NAME_PATTERN},
        },
        ["schema", "provider", "profile"],
    )


def _system_preflight() -> Schema:
    return _payload_schema(
        "system.preflight",
        {
            "profiles": {
                "type": "array",
                "items": _profile_selector(),
                "uniqueItems": True,
                "maxItems": 200,
            }
        },
        [],
    )


def _manifest_ref(kind: str) -> Schema:
    return _strict_object(
        {
            "schema": _tag(f"ask_herdr.{kind}_manifest_ref.v1"),
            "manifest_id": _uuid4(),
            "manifest_digest": _digest(),
        },
        ["schema", "manifest_id", "manifest_digest"],
    )


def _release_workspace_preview() -> Schema:
    return _payload_schema(
        "topology.release.workspace.preview",
        {
            "lane_id": _uuid4(),
            "generation": _generation(),
            "expected_release_eligibility_state_digest": _digest(),
        },
        ["lane_id", "generation", "expected_release_eligibility_state_digest"],
    )


def _manifest_execute(operation: str, kind: str) -> Schema:
    return _payload_schema(
        operation,
        {"manifest": _manifest_ref(kind)},
        ["manifest"],
    )


def _release_resume(operation: str) -> Schema:
    return _payload_schema(
        operation,
        {
            "original_operation_id": _uuid4(),
            "manifest": _manifest_ref("release"),
            "expected_current_release_state_digest": _digest(),
        },
        [
            "original_operation_id",
            "manifest",
            "expected_current_release_state_digest",
        ],
    )


def _release_set_entry() -> Schema:
    return _strict_object(
        {
            "schema": _tag("ask_herdr.release_set.entry.v1"),
            "lane_id": _uuid4(),
            "generation": _generation(),
            "state_digest": _digest(),
        },
        ["schema", "lane_id", "generation", "state_digest"],
    )


def _release_set() -> Schema:
    return _strict_object(
        {
            "schema": _tag("ask_herdr.release_set.v1"),
            "namespace_generation": _generation(),
            "lanes": {
                "type": "array",
                "items": _release_set_entry(),
                "uniqueItems": True,
                "maxItems": 10_000,
            },
        },
        ["schema", "namespace_generation", "lanes"],
    )


def _release_session_preview() -> Schema:
    return _payload_schema(
        "topology.release.session.preview",
        {"release_set": _release_set()},
        ["release_set"],
    )


def _recovery_scope_selector() -> Schema:
    schema_id = "ask_herdr.recovery_scope_selector.v1"
    return {
        "oneOf": [
            _tagged_variant(
                schema_id, "operation", {"operation_id": _uuid4()}
            ),
            _tagged_variant(
                schema_id,
                "lane",
                {"lane_id": _uuid4(), "generation": _generation()},
            ),
            _tagged_variant(
                schema_id,
                "namespace",
                {"namespace_generation": _generation()},
            ),
            _tagged_variant(schema_id, "policy", {}),
        ]
    }


def _recovery_reconcile() -> Schema:
    return _payload_schema(
        "recovery.reconcile",
        {
            "selector": _recovery_scope_selector(),
            "expected_recovery_state_digest": _digest(),
        },
        ["selector", "expected_recovery_state_digest"],
    )


def _expected_namespace() -> Schema:
    schema_id = "ask_herdr.expected_namespace_generation.v1"
    return {
        "oneOf": [
            _strict_object(
                {
                    "schema": _tag(schema_id),
                    "state": _literal("absent"),
                    "generation": {"type": "null"},
                },
                ["schema", "state", "generation"],
            ),
            _strict_object(
                {
                    "schema": _tag(schema_id),
                    "state": _literal("retired"),
                    "generation": _generation(),
                },
                ["schema", "state", "generation"],
            ),
        ]
    }


def _rebuild_topology() -> Schema:
    return _payload_schema(
        "recovery.rebuild_topology",
        {
            "source_reconciliation_operation_id": _uuid4(),
            "topology_rebuild_eligible_state_digest": _digest(),
            "topology_recovery_set_digest": _digest(),
            "expected_namespace": _expected_namespace(),
        },
        [
            "source_reconciliation_operation_id",
            "topology_rebuild_eligible_state_digest",
            "topology_recovery_set_digest",
            "expected_namespace",
        ],
    )


def _retire_lane_preview() -> Schema:
    return _payload_schema(
        "recovery.retire.lane.preview",
        {
            "lane_id": _uuid4(),
            "generation": _generation(),
            "expected_retirement_state_digest": _digest(),
            "acknowledge_abandon_unresolved": {"type": "boolean", "const": True},
        },
        [
            "lane_id",
            "generation",
            "expected_retirement_state_digest",
            "acknowledge_abandon_unresolved",
        ],
    )


def _retirement_set_entry() -> Schema:
    return _strict_object(
        {
            "schema": _tag("ask_herdr.retirement_set.entry.v1"),
            "lane_id": _uuid4(),
            "generation": _generation(),
            "abandoned_unresolved_tombstone_digest": _digest(),
            "topology_binding_digest": _digest(),
        },
        [
            "schema",
            "lane_id",
            "generation",
            "abandoned_unresolved_tombstone_digest",
            "topology_binding_digest",
        ],
    )


def _retirement_set() -> Schema:
    return _strict_object(
        {
            "schema": _tag("ask_herdr.retirement_set.v1"),
            "namespace_generation": _generation(),
            "lanes": {
                "type": "array",
                "items": _retirement_set_entry(),
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 10_000,
            },
        },
        ["schema", "namespace_generation", "lanes"],
    )


def _retire_namespace_preview() -> Schema:
    return _payload_schema(
        "recovery.retire.namespace.preview",
        {
            "retirement_set": _retirement_set(),
            "expected_retirement_state_digest": _digest(),
        },
        ["retirement_set", "expected_retirement_state_digest"],
    )


def _interrupt_graceful() -> Schema:
    return _payload_schema(
        "process.interrupt.graceful",
        {
            "source_operation_id": _uuid4(),
            "expected_active_state_digest": _digest(),
            "expected_adapter_supervisor_start_receipt_digest": _digest(),
        },
        [
            "source_operation_id",
            "expected_active_state_digest",
            "expected_adapter_supervisor_start_receipt_digest",
        ],
    )


def _interrupt_force() -> Schema:
    return _payload_schema(
        "process.interrupt.force",
        {
            "original_interruption_operation_id": _uuid4(),
            "source_operation_id": _uuid4(),
            "graceful_signal_receipt_digest": _digest(),
            "expected_still_running_state_digest": _digest(),
            "graceful_window_elapsed_proof_digest": _digest(),
        },
        [
            "original_interruption_operation_id",
            "source_operation_id",
            "graceful_signal_receipt_digest",
            "expected_still_running_state_digest",
            "graceful_window_elapsed_proof_digest",
        ],
    )


_BUILDERS: Mapping[str, Callable[[], Schema]] = {
    "process.interrupt.force": _interrupt_force,
    "process.interrupt.graceful": _interrupt_graceful,
    "query.evidence": _query_evidence,
    "query.result": _query_result,
    "query.status": _query_status,
    "recovery.rebuild_topology": _rebuild_topology,
    "recovery.reconcile": _recovery_reconcile,
    "recovery.retire.lane.execute": lambda: _manifest_execute(
        "recovery.retire.lane.execute", "retirement"
    ),
    "recovery.retire.lane.preview": _retire_lane_preview,
    "recovery.retire.namespace.execute": lambda: _manifest_execute(
        "recovery.retire.namespace.execute", "retirement"
    ),
    "recovery.retire.namespace.preview": _retire_namespace_preview,
    "system.preflight": _system_preflight,
    "topology.release.session.execute": lambda: _manifest_execute(
        "topology.release.session.execute", "release"
    ),
    "topology.release.session.preview": _release_session_preview,
    "topology.release.session.resume": lambda: _release_resume(
        "topology.release.session.resume"
    ),
    "topology.release.workspace.execute": lambda: _manifest_execute(
        "topology.release.workspace.execute", "release"
    ),
    "topology.release.workspace.preview": _release_workspace_preview,
    "topology.release.workspace.resume": lambda: _release_resume(
        "topology.release.workspace.resume"
    ),
}


def build_control_payload_schemas() -> Dict[str, Schema]:
    """Return the exact 18-operation mapping as fresh standalone documents."""

    return {operation: _BUILDERS[operation]() for operation in CONTROL_PAYLOAD_OPERATIONS}


if tuple(sorted(_BUILDERS)) != CONTROL_PAYLOAD_OPERATIONS:
    raise AssertionError("control payload schema builders must cover exactly 18 operations")
