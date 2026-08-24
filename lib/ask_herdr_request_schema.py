"""Pure assembly of the complete, self-contained Machine Request schema."""

from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, Mapping, Sequence

from ask_herdr_admin_payloads import build_admin_payload_schema
from ask_herdr_control_payloads import build_control_payload_schemas
from ask_herdr_operation_contract import OPERATION_CONTRACTS, OperationContract
from ask_herdr_resources import schema_path
from ask_herdr_turn_payloads import build_turn_payload_schemas


REQUEST_SCHEMA_ID = "ask_herdr.request.v1"
REQUEST_SCHEMA_PATH = schema_path("ask_herdr.request.v1.schema.json")
JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
UUID4_PATTERN = (
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CANONICAL_ABSOLUTE_PATH_PATTERN = (
    r"^(?!.*(?:^|/)\.{1,2}(?:/|$))/(?!.*//)"
    r"(?:[^/\u0000]+(?:/[^/\u0000]+)*)?$"
)
OPAQUE_AUTHORITY_REF_PATTERN = r"^[\x21-\x7e]{1,256}$"
LANE_ORIGIN_REASONS = (
    "comment",
    "consult",
    "diagnose",
    "other",
    "plan",
    "review",
    "suggest",
    "verify",
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


def _const(value: str) -> Dict[str, Any]:
    return {"type": "string", "const": value}


def _uuid4() -> Dict[str, Any]:
    return {"type": "string", "pattern": UUID4_PATTERN}


def _canonical_absolute_path() -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": CANONICAL_ABSOLUTE_PATH_PATTERN,
    }


def _project_variant(binding: str) -> Dict[str, Any]:
    authority = {"type": "null"} if binding == "candidate" else _uuid4()
    return _strict_object(
        {
            "schema": _const("ask_herdr.project_binding.v1"),
            "binding": _const(binding),
            "root": _canonical_absolute_path(),
            "authority_id": authority,
        },
        ("schema", "binding", "root", "authority_id"),
    )


def _project_schema(bindings: Iterable[str]) -> Dict[str, Any]:
    variants = [_project_variant(binding) for binding in bindings]
    return variants[0] if len(variants) == 1 else {"oneOf": variants}


def _authority_schema(contract: OperationContract) -> Dict[str, Any]:
    if contract.authority_class in {"public_read", "bootstrap_human_only"}:
        return {"type": "null"}
    return {
        "type": "string",
        "pattern": OPAQUE_AUTHORITY_REF_PATTERN,
    }


def _reason_schema(operation: str, actions: Sequence[str]) -> Dict[str, Any]:
    properties: Dict[str, Any] = {
        "schema": _const("ask_herdr.reason.v1"),
        "action": {"type": "string", "enum": list(actions)},
        "note": {"type": "string", "maxLength": 4096},
    }
    required = ["schema", "action"]
    if operation == "turn.consult":
        properties["lane_origin"] = {
            "type": "string",
            "enum": list(LANE_ORIGIN_REASONS),
        }
        required.append("lane_origin")
    return _strict_object(properties, required)


def _observation_variant(mode: str) -> Dict[str, Any]:
    timeout = (
        {
            "type": "integer",
            "minimum": 1000,
            "maximum": 86_400_000,
        }
        if mode == "wait"
        else {"type": "null"}
    )
    return _strict_object(
        {
            "schema": _const("ask_herdr.observation.v1"),
            "mode": _const(mode),
            "timeout_ms": timeout,
        },
        ("schema", "mode", "timeout_ms"),
    )


def _observation_schema(modes: Iterable[str]) -> Dict[str, Any]:
    variants = [_observation_variant(mode) for mode in modes]
    return variants[0] if len(variants) == 1 else {"oneOf": variants}


def _payload_schemas() -> Dict[str, Dict[str, Any]]:
    turn_schemas = build_turn_payload_schemas()
    control_schemas = build_control_payload_schemas()
    schemas = {
        **turn_schemas,
        **control_schemas,
        **{
            operation: build_admin_payload_schema(operation)
            for operation in OPERATION_CONTRACTS
            if operation not in turn_schemas and operation not in control_schemas
        },
    }
    if set(schemas) != set(OPERATION_CONTRACTS):
        raise AssertionError("payload schema coverage drift")
    embedded = {}
    for operation, schema in schemas.items():
        body = copy.deepcopy(schema)
        body.pop("$schema", None)
        body.pop("$id", None)
        embedded[operation] = body
    return embedded


def _operation_branch(
    operation: str,
    contract: OperationContract,
    payload_schema: Mapping[str, Any],
) -> Dict[str, Any]:
    return _strict_object(
        {
            "schema": _const(REQUEST_SCHEMA_ID),
            "operation": _const(operation),
            "operation_id": _uuid4(),
            "project": _project_schema(contract.allowed_project_bindings),
            "authority_ref": _authority_schema(contract),
            "reason": _reason_schema(
                operation, contract.allowed_action_reasons
            ),
            "payload": copy.deepcopy(payload_schema),
            "observation": _observation_schema(
                contract.allowed_observation_modes
            ),
        },
        (
            "schema",
            "operation",
            "operation_id",
            "project",
            "authority_ref",
            "reason",
            "payload",
            "observation",
        ),
    )


def build_request_schema() -> Dict[str, Any]:
    """Return a fresh deterministic Draft 2020-12 schema for all 45 requests."""

    payloads = _payload_schemas()
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": "urn:ask-herdr:schema:ask_herdr.request.v1",
        "title": REQUEST_SCHEMA_ID,
        "oneOf": [
            _operation_branch(operation, contract, payloads[operation])
            for operation, contract in OPERATION_CONTRACTS.items()
        ],
    }
