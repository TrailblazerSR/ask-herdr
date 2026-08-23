"""Closed public-beta schemas for the path-free ``query.status`` route."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Sequence, Tuple


JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
OUTCOME_SCHEMA_ID = "ask_herdr.outcome.v2"
RESULT_SCHEMA_ID = "ask_herdr.query.status.result.v1"
OUTCOME_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "ask_herdr.outcome.v2.schema.json"
)
RESULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "ask_herdr.query.status.result.v1.schema.json"
)

UUID4_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]+)?Z$"
)
CONSULTANT_KEY_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,63}$"
CURSOR_PATTERN = r"^[\x21-\x7e]{1,1024}$"
TOKEN_PATTERN = r"^[a-z][a-z0-9_.-]{0,127}$"


_OUTCOME_MAP = {
    "status_observed": ("succeeded", 0),
    "status_busy": ("in_progress", 40),
    "status_reconciliation_required": ("reconciliation_required", 40),
    "cursor_stale": ("failed", 40),
    "status_quarantined": ("quarantined", 50),
    "status_capability_unavailable": ("failed", 20),
    "request_invalid": ("failed", 64),
    "request_not_currently_admissible": ("failed", 20),
    "request_reconciliation_required": ("reconciliation_required", 40),
    "request_quarantined": ("quarantined", 50),
}
OUTCOME_MAP: Mapping[str, Mapping[str, Any]] = MappingProxyType(
    {
        kind: MappingProxyType({"status": status, "exit_class": exit_class})
        for kind, (status, exit_class) in _OUTCOME_MAP.items()
    }
)


def _strict_object(
    properties: Mapping[str, Any], required: Sequence[str]
) -> Dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required),
    }


def _null_or(reference: Mapping[str, Any]) -> Dict[str, Any]:
    return {"oneOf": [{"type": "null"}, dict(reference)]}


def _selector_schema() -> Dict[str, Any]:
    schema_id = "ask_herdr.query.status.selector.v1"
    return {
        "oneOf": [
            _strict_object(
                {
                    "schema": {"type": "string", "const": schema_id},
                    "kind": {"type": "string", "const": "project"},
                },
                ("schema", "kind"),
            ),
            _strict_object(
                {
                    "schema": {"type": "string", "const": schema_id},
                    "kind": {"type": "string", "const": "lane"},
                    "lane_id": {"$ref": "#/$defs/uuid_v4"},
                },
                ("schema", "kind", "lane_id"),
            ),
            _strict_object(
                {
                    "schema": {"type": "string", "const": schema_id},
                    "kind": {"type": "string", "const": "key"},
                    "consultant_key": {
                        "type": "string",
                        "maxLength": 64,
                        "pattern": CONSULTANT_KEY_PATTERN,
                    },
                },
                ("schema", "kind", "consultant_key"),
            ),
            _strict_object(
                {
                    "schema": {"type": "string", "const": schema_id},
                    "kind": {"type": "string", "const": "operation"},
                    "operation_id": {"$ref": "#/$defs/uuid_v4"},
                },
                ("schema", "kind", "operation_id"),
            ),
        ]
    }


def _lane_head_schema() -> Dict[str, Any]:
    return _strict_object(
        {
            "lane_id": {"$ref": "#/$defs/uuid_v4"},
            "lane_generation": {"type": "integer", "minimum": 1},
            "lane_binding_digest": {"$ref": "#/$defs/digest"},
            "event_sequence": {"type": "integer", "minimum": 0},
            "event_digest": {"$ref": "#/$defs/digest"},
            "state_digest": {"$ref": "#/$defs/digest"},
            "response_digest": _null_or({"$ref": "#/$defs/digest"}),
        },
        (
            "lane_id",
            "lane_generation",
            "lane_binding_digest",
            "event_sequence",
            "event_digest",
            "state_digest",
            "response_digest",
        ),
    )


def _operation_metadata_schema() -> Dict[str, Any]:
    return _strict_object(
        {
            "operation_id": {"$ref": "#/$defs/uuid_v4"},
            "operation": {
                "type": "string",
                "enum": [
                    "project.init",
                    "turn.answer",
                    "turn.consult",
                    "turn.review",
                    "recovery.reconcile",
                    "query.evidence",
                ],
            },
            "canonical_request_digest": {"$ref": "#/$defs/digest"},
            "lane_association": {
                "type": "string",
                "enum": ["not_applicable", "unresolved", "bound"],
            },
        },
        (
            "operation_id",
            "operation",
            "canonical_request_digest",
            "lane_association",
        ),
    )


def _project_read_epoch_schema() -> Dict[str, Any]:
    return _strict_object(
        {
            "schema": {
                "type": "string",
                "const": "ask_herdr.project_read_epoch.v1",
            },
            "project_authority_id": {"$ref": "#/$defs/uuid_v4"},
            "authority_store_head_digest": {"$ref": "#/$defs/digest"},
            "project_state_digest": {"$ref": "#/$defs/digest"},
            "lane_index_digest": {"$ref": "#/$defs/digest"},
            "topology_ledger_head_digest": {"$ref": "#/$defs/digest"},
            "observed_at": {"$ref": "#/$defs/timestamp"},
            "acquisition_attempt": {"type": "integer", "minimum": 1, "maximum": 3},
            "epoch_digest": {"$ref": "#/$defs/digest"},
        },
        (
            "schema",
            "project_authority_id",
            "authority_store_head_digest",
            "project_state_digest",
            "lane_index_digest",
            "topology_ledger_head_digest",
            "observed_at",
            "acquisition_attempt",
            "epoch_digest",
        ),
    )


def _result_definitions() -> Dict[str, Any]:
    return {
        "uuid_v4": {"type": "string", "pattern": UUID4_PATTERN},
        "digest": {"type": "string", "pattern": DIGEST_PATTERN},
        "timestamp": {"type": "string", "pattern": TIMESTAMP_PATTERN},
        "selector": _selector_schema(),
        "lane_head": _lane_head_schema(),
        "operation_metadata": _operation_metadata_schema(),
        "project_read_epoch": _project_read_epoch_schema(),
    }


def _status_branch(
    status: str,
    properties: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "if": {
            "properties": {"read_status": {"const": status}},
            "required": ["read_status"],
        },
        "then": {"properties": dict(properties)},
    }


def _selector_status_branch(
    kind: str,
    status: str,
    detail: str,
) -> Dict[str, Any]:
    return {
        "if": {
            "properties": {
                "selector": {
                    "properties": {"kind": {"const": kind}},
                    "required": ["kind"],
                },
                "read_status": {"const": status},
            },
            "required": ["selector", "read_status"],
        },
        "then": {
            "properties": {"detail_code": {"type": "string", "const": detail}}
        },
    }


def build_query_status_result_schema() -> Dict[str, Any]:
    """Build the closed, path-free public status result contract."""

    required = (
        "schema",
        "selector",
        "read_status",
        "detail_code",
        "normalized_read_contract_digest",
        "project_read_epoch",
        "entries",
        "next_cursor",
        "operation_metadata",
    )
    schema: Dict[str, Any] = {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": "urn:ask-herdr:schema:ask_herdr.query.status.result.v1",
        "title": RESULT_SCHEMA_ID,
        "type": "object",
        "additionalProperties": False,
        "required": list(required),
        "properties": {
            "schema": {"type": "string", "const": RESULT_SCHEMA_ID},
            "selector": {"$ref": "#/$defs/selector"},
            "read_status": {
                "type": "string",
                "enum": [
                    "active",
                    "absent",
                    "busy",
                    "reconciliation_required",
                    "quarantined",
                    "cursor_stale",
                    "unavailable",
                ],
            },
            "detail_code": {
                "type": "string",
                "enum": [
                    "query_status.project_active",
                    "query_status.project_absent",
                    "query_status.lane_active",
                    "query_status.lane_absent",
                    "query_status.key_active",
                    "query_status.key_absent",
                    "query_status.operation_active",
                    "query_status.operation_absent",
                    "query_status.busy",
                    "query_status.reconciliation_required",
                    "query_status.quarantined",
                    "query_status.cursor_stale",
                    "query_status.observation_unavailable",
                    "query_status.advisory_unavailable",
                ],
            },
            "normalized_read_contract_digest": _null_or(
                {"$ref": "#/$defs/digest"}
            ),
            "project_read_epoch": _null_or(
                {"$ref": "#/$defs/project_read_epoch"}
            ),
            "entries": {
                "type": "array",
                "maxItems": 200,
                "items": {"$ref": "#/$defs/lane_head"},
            },
            "next_cursor": _null_or(
                {"type": "string", "pattern": CURSOR_PATTERN}
            ),
            "operation_metadata": _null_or(
                {"$ref": "#/$defs/operation_metadata"}
            ),
        },
        "$defs": _result_definitions(),
    }
    schema["allOf"] = [
        _status_branch(
            "active",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "project_read_epoch": {"$ref": "#/$defs/project_read_epoch"},
            },
        ),
        _status_branch(
            "absent",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "entries": {"maxItems": 0},
                "next_cursor": {"type": "null"},
                "operation_metadata": {"type": "null"},
            },
        ),
        _status_branch(
            "busy",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "project_read_epoch": {"type": "null"},
                "entries": {"maxItems": 0},
                "next_cursor": {"type": "null"},
                "operation_metadata": {"type": "null"},
                "detail_code": {"const": "query_status.busy"},
            },
        ),
        _status_branch(
            "quarantined",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "project_read_epoch": {"type": "null"},
                "entries": {"maxItems": 0},
                "next_cursor": {"type": "null"},
                "operation_metadata": {"type": "null"},
                "detail_code": {"const": "query_status.quarantined"},
            },
        ),
        _status_branch(
            "cursor_stale",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "project_read_epoch": {"type": "null"},
                "entries": {"maxItems": 0},
                "next_cursor": {"type": "null"},
                "operation_metadata": {"type": "null"},
                "detail_code": {"const": "query_status.cursor_stale"},
            },
        ),
        _status_branch(
            "unavailable",
            {
                "normalized_read_contract_digest": {"type": "null"},
                "project_read_epoch": {"type": "null"},
                "entries": {"maxItems": 0},
                "next_cursor": {"type": "null"},
                "operation_metadata": {"type": "null"},
                "detail_code": {
                    "enum": [
                        "query_status.observation_unavailable",
                        "query_status.advisory_unavailable",
                    ]
                },
            },
        ),
        _status_branch(
            "reconciliation_required",
            {
                "normalized_read_contract_digest": {"$ref": "#/$defs/digest"},
                "detail_code": {"const": "query_status.reconciliation_required"},
            },
        ),
        {
            "if": {
                "properties": {
                    "read_status": {"const": "reconciliation_required"},
                    "project_read_epoch": {"type": "null"},
                },
                "required": ["read_status", "project_read_epoch"],
            },
            "then": {
                "properties": {
                    "entries": {"maxItems": 0},
                    "next_cursor": {"type": "null"},
                    "operation_metadata": {"type": "null"},
                }
            },
        },
        *[
            _selector_status_branch(kind, "active", detail)
            for kind, detail in (
                ("project", "query_status.project_active"),
                ("lane", "query_status.lane_active"),
                ("key", "query_status.key_active"),
                ("operation", "query_status.operation_active"),
            )
        ],
        *[
            _selector_status_branch(kind, "absent", detail)
            for kind, detail in (
                ("project", "query_status.project_absent"),
                ("lane", "query_status.lane_absent"),
                ("key", "query_status.key_absent"),
                ("operation", "query_status.operation_absent"),
            )
        ],
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"enum": ["lane", "key"]}},
                        "required": ["kind"],
                    },
                    "read_status": {"const": "active"},
                },
                "required": ["selector", "read_status"],
            },
            "then": {"properties": {"entries": {"minItems": 1}}},
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"const": "operation"}},
                        "required": ["kind"],
                    },
                },
                "required": ["selector"],
            },
            "then": {"properties": {"next_cursor": {"type": "null"}}},
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"const": "operation"}},
                        "required": ["kind"],
                    },
                    "operation_metadata": {"type": "null"},
                },
                "required": ["selector", "operation_metadata"],
            },
            "then": {"properties": {"entries": {"maxItems": 0}}},
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"const": "operation"}},
                        "required": ["kind"],
                    },
                    "read_status": {"const": "active"},
                },
                "required": ["selector", "read_status"],
            },
            "then": {
                "properties": {
                    "operation_metadata": {
                        "$ref": "#/$defs/operation_metadata"
                    }
                }
            },
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {
                            "kind": {"enum": ["project", "lane", "key"]}
                        },
                        "required": ["kind"],
                    },
                },
                "required": ["selector"],
            },
            "then": {
                "properties": {"operation_metadata": {"type": "null"}}
            },
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"const": "operation"}},
                        "required": ["kind"],
                    },
                    "operation_metadata": {
                        "type": "object",
                        "properties": {
                            "lane_association": {"const": "bound"}
                        },
                        "required": ["lane_association"],
                    },
                },
                "required": ["selector", "operation_metadata"],
            },
            "then": {"properties": {"entries": {"minItems": 1, "maxItems": 1}}},
        },
        {
            "if": {
                "properties": {
                    "selector": {
                        "properties": {"kind": {"const": "operation"}},
                        "required": ["kind"],
                    },
                    "operation_metadata": {
                        "type": "object",
                        "properties": {
                            "lane_association": {
                                "enum": ["not_applicable", "unresolved"]
                            }
                        },
                        "required": ["lane_association"],
                    },
                },
                "required": ["selector", "operation_metadata"],
            },
            "then": {"properties": {"entries": {"maxItems": 0}}},
        },
    ]
    return schema


def _outcome_definitions() -> Dict[str, Any]:
    result, result_definitions = _result_schema_body()
    return {
        "uuid_v4": {"type": "string", "pattern": UUID4_PATTERN},
        "digest": {"type": "string", "pattern": DIGEST_PATTERN},
        "timestamp": {"type": "string", "pattern": TIMESTAMP_PATTERN},
        "result": result,
        "result_defs": result_definitions,
        "project_reference": _strict_object(
            {
                "schema": {
                    "type": "string",
                    "const": "ask_herdr.project_reference.v1",
                },
                "authority_id": {"$ref": "#/$defs/uuid_v4"},
            },
            ("schema", "authority_id"),
        ),
        "retry": _strict_object(
            {
                "schema": {"type": "string", "const": "ask_herdr.retry.v1"},
                "disposition": {"type": "string", "const": "none"},
                "original_operation_id": {"type": "null"},
                "basis_evidence_ref_ids": {
                    "type": "array",
                    "maxItems": 0,
                },
            },
            (
                "schema",
                "disposition",
                "original_operation_id",
                "basis_evidence_ref_ids",
            ),
        ),
        "diagnostic": _strict_object(
            {
                "code": {"type": "string", "pattern": TOKEN_PATTERN},
                "severity": {"type": "string", "const": "error"},
                "field_pointer": {"oneOf": [{"type": "null"}, {"type": "string", "maxLength": 4096}]},
                "safe_message": {"type": "string", "minLength": 1, "maxLength": 256},
                "evidence_ref_ids": {"type": "array", "maxItems": 0},
            },
            (
                "code",
                "severity",
                "field_pointer",
                "safe_message",
                "evidence_ref_ids",
            ),
        ),
        "timestamps": _strict_object(
            {
                "started_at": {"$ref": "#/$defs/timestamp"},
                "completed_at": {"$ref": "#/$defs/timestamp"},
            },
            ("started_at", "completed_at"),
        ),
    }


def _result_schema_body() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Embed the result contract with local references for the outcome schema."""

    result = build_query_status_result_schema()
    definitions = result.pop("$defs")

    def rewrite(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    item.replace("#/$defs/", "#/$defs/result_defs/")
                    if key == "$ref"
                    and isinstance(item, str)
                    and item.startswith("#/$defs/")
                    else rewrite(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        return value

    rewritten = rewrite(result)
    rewritten.pop("$schema", None)
    rewritten.pop("$id", None)
    return rewritten, rewrite(definitions)


def _outcome_branch(
    outcome_kind: str,
    result: Mapping[str, Any],
    project: Mapping[str, Any],
    diagnostic_count: int,
) -> Dict[str, Any]:
    mapping = OUTCOME_MAP[outcome_kind]
    return {
        "properties": {
            "outcome_kind": {"const": outcome_kind},
            "status": {"const": mapping["status"]},
            "exit_class": {"const": mapping["exit_class"]},
            "result": dict(result),
            "project": dict(project),
            "diagnostics": {
                "minItems": diagnostic_count,
                "maxItems": diagnostic_count,
            },
        },
        "required": [
            "outcome_kind",
            "status",
            "exit_class",
            "result",
            "project",
            "diagnostics",
        ],
    }


def _result_status_constraint(statuses: Sequence[str]) -> Dict[str, Any]:
    return {
        "allOf": [
            {"$ref": "#/$defs/result"},
            {"properties": {"read_status": {"enum": list(statuses)}}},
        ]
    }


def build_outcome_schema() -> Dict[str, Any]:
    """Build the closed public path-free query-status envelope."""

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
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": "urn:ask-herdr:schema:ask_herdr.outcome.v2",
        "title": OUTCOME_SCHEMA_ID,
        "type": "object",
        "additionalProperties": False,
        "required": list(required),
        "properties": {
            "schema": {"type": "string", "const": OUTCOME_SCHEMA_ID},
            "operation": {"type": "string", "const": "query.status"},
            "operation_id": {"$ref": "#/$defs/uuid_v4"},
            "request_digest": {"$ref": "#/$defs/digest"},
            "project": _null_or({"$ref": "#/$defs/project_reference"}),
            "status": {
                "type": "string",
                "enum": [
                    "succeeded",
                    "in_progress",
                    "reconciliation_required",
                    "failed",
                    "quarantined",
                ],
            },
            "outcome_kind": {"type": "string", "enum": list(OUTCOME_MAP)},
            "exit_class": {"type": "integer", "enum": [0, 20, 40, 50, 64]},
            "retry": {"$ref": "#/$defs/retry"},
            "policy": {"type": "null"},
            "result": _null_or({"$ref": "#/$defs/result"}),
            "diagnostics": {
                "type": "array",
                "items": {"$ref": "#/$defs/diagnostic"},
            },
            "evidence_refs": {"type": "array", "maxItems": 0},
            "advisory": {
                "type": "object",
                "additionalProperties": False,
                "maxProperties": 0,
            },
            "timestamps": {"$ref": "#/$defs/timestamps"},
        },
        "allOf": [
            {
                "oneOf": [
                    _outcome_branch(
                        "status_observed",
                        _result_status_constraint(("active", "absent")),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    _outcome_branch(
                        "status_busy",
                        _result_status_constraint(("busy",)),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    _outcome_branch(
                        "status_reconciliation_required",
                        _result_status_constraint(("reconciliation_required",)),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    _outcome_branch(
                        "cursor_stale",
                        _result_status_constraint(("cursor_stale",)),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    _outcome_branch(
                        "status_quarantined",
                        _result_status_constraint(("quarantined",)),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    _outcome_branch(
                        "status_capability_unavailable",
                        _result_status_constraint(("unavailable",)),
                        {"$ref": "#/$defs/project_reference"},
                        0,
                    ),
                    *[
                        _outcome_branch(
                            outcome_kind,
                            {"type": "null"},
                            {"type": "null"}
                            if outcome_kind == "request_invalid"
                            else {"$ref": "#/$defs/project_reference"},
                            1,
                        )
                        for outcome_kind in (
                            "request_invalid",
                            "request_not_currently_admissible",
                            "request_reconciliation_required",
                            "request_quarantined",
                        )
                    ],
                ]
            }
        ],
        "$defs": _outcome_definitions(),
    }


build_result_schema = build_query_status_result_schema


__all__ = (
    "OUTCOME_MAP",
    "OUTCOME_SCHEMA_ID",
    "OUTCOME_SCHEMA_PATH",
    "RESULT_SCHEMA_ID",
    "RESULT_SCHEMA_PATH",
    "build_outcome_schema",
    "build_query_status_result_schema",
    "build_result_schema",
)
