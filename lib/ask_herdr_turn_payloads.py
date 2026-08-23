"""Pure builders for the five strict, pre-activation turn payload schemas.

The schemas in this module describe submitted payloads only.  They contain no
provider-native identity, derived lane/topology identity, or storage locator,
and importing the module performs no I/O.  Cross-object state checks (including
ordered-set canonicality and distinct consultant child IDs) remain semantic
validation concerns.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Tuple


JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SAFE_INTEGER_MAX = 9_007_199_254_740_991
MAX_REQUEST_CONTENT_BYTES = 8 * 1024 * 1024
MAX_CLARIFICATION_ANSWER_BYTES = 1024 * 1024
MAX_TRANSACTION_TEMPORARY_BYTES = 128 * 1024 * 1024
MAX_PROVIDER_TERMINAL_BYTES = 16 * 1024 * 1024

UUID4_PATTERN = (
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
CANONICAL_ABSOLUTE_PATH_PATTERN = (
    "^(?:/|/(?!\\.{1,2}(?:/|$))(?!.*//)"
    "(?!.*?/\\.{1,2}(?:/|$))[^\\u0000]*[^/\\u0000])$"
)
TOKEN_PATTERN = "^[a-z][a-z0-9._-]{0,127}$"
CONSULTANT_KEY_PATTERN = "^[a-z0-9][a-z0-9._-]{0,63}$"
MODEL_VALUE_PATTERN = "^(?!latest$)[^\\u0000-\\u0020\\u007f]{1,256}$"

_HOST_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = f"(?![0-9]+(?:\\.[0-9]+){{3}}(?::|$)){_HOST_LABEL}(?:\\.{_HOST_LABEL})*"
_PORT = (
    "(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|"
    "65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
)

TURN_OPERATION_NAMES: Tuple[str, ...] = (
    "turn.answer",
    "turn.consult",
    "turn.recovery_continue",
    "turn.review",
    "turn.safe_retry",
)
TURN_PAYLOAD_SCHEMA_IDS: Mapping[str, str] = MappingProxyType(
    {
        operation: f"ask_herdr.{operation}.payload.v1"
        for operation in TURN_OPERATION_NAMES
    }
)


def _const_string(value: str) -> Dict[str, Any]:
    return {"type": "string", "const": value}


def _strict_object(
    schema_id: str,
    properties: Dict[str, Any],
    required: Iterable[str],
    **keywords: Any,
) -> Dict[str, Any]:
    complete_properties = {
        "schema": _const_string(schema_id),
        **properties,
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": complete_properties,
        "required": ["schema", *required],
        **keywords,
    }


def _uuid4() -> Dict[str, Any]:
    return {"type": "string", "pattern": UUID4_PATTERN}


def _sha256() -> Dict[str, Any]:
    return {"type": "string", "pattern": SHA256_DIGEST_PATTERN}


def _canonical_absolute_path() -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": CANONICAL_ABSOLUTE_PATH_PATTERN,
    }


def _safe_nonnegative_integer(maximum: int = SAFE_INTEGER_MAX) -> Dict[str, Any]:
    return {"type": "integer", "minimum": 0, "maximum": maximum}


def _positive_safe_integer() -> Dict[str, Any]:
    return {"type": "integer", "minimum": 1, "maximum": SAFE_INTEGER_MAX}


def _token(max_length: int = 128) -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": max_length,
        "pattern": TOKEN_PATTERN,
    }


def _consultant_key() -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "pattern": CONSULTANT_KEY_PATTERN,
    }


def _model_value() -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": MODEL_VALUE_PATTERN,
    }


def _normalized_content(kind: str, maximum_bytes: int) -> Dict[str, Any]:
    return _strict_object(
        f"ask_herdr.normalized_{kind}.v1",
        {
            "text": {
                "type": "string",
                "minLength": 1,
                "maxLength": maximum_bytes,
            },
            "utf8_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
            "content_digest": _sha256(),
        },
        ["text", "utf8_bytes", "content_digest"],
    )


def _material_manifest_ref() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.material_manifest_ref.v1",
        {
            "manifest_id": _uuid4(),
            "manifest_digest": _sha256(),
        },
        ["manifest_id", "manifest_digest"],
    )


def _material_variant(
    expected_kind: str,
    binding: str,
    expected_content_digest: Dict[str, Any],
    directory_manifest_ref: Dict[str, Any],
) -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.material_reference.v1",
        {
            "canonical_path": _canonical_absolute_path(),
            "expected_kind": _const_string(expected_kind),
            "binding": _const_string(binding),
            "follow_symlink": {"type": "boolean"},
            "expected_content_digest": expected_content_digest,
            "directory_manifest_ref": directory_manifest_ref,
        },
        [
            "canonical_path",
            "expected_kind",
            "binding",
            "follow_symlink",
            "expected_content_digest",
            "directory_manifest_ref",
        ],
    )


def _material_reference() -> Dict[str, Any]:
    identity_variants = [
        _material_variant(kind, "identity", {"type": "null"}, {"type": "null"})
        for kind in ("file", "directory")
    ]
    content_file = _material_variant(
        "file", "content", _sha256(), {"type": "null"}
    )
    content_directory = _material_variant(
        "directory", "content", _sha256(), _material_manifest_ref()
    )
    return {"oneOf": [*identity_variants, content_file, content_directory]}


def _materials(*, minimum: int = 0) -> Dict[str, Any]:
    return {
        "type": "array",
        "minItems": minimum,
        "maxItems": 10_000,
        "uniqueItems": True,
        "items": _material_reference(),
    }


def _capability_path() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.capability_path.v1",
        {
            "canonical_path": _canonical_absolute_path(),
            "scope": {"type": "string", "enum": ["object", "subtree"]},
        },
        ["canonical_path", "scope"],
    )


def _canonical_http_origin() -> Dict[str, Any]:
    no_port = {"type": "string", "pattern": f"^https?://{_HOST}$"}
    http_nondefault_port = {
        "allOf": [
            {"type": "string", "pattern": f"^http://{_HOST}:{_PORT}$"},
            {"not": {"pattern": ":80$"}},
        ]
    }
    https_nondefault_port = {
        "allOf": [
            {"type": "string", "pattern": f"^https://{_HOST}:{_PORT}$"},
            {"not": {"pattern": ":443$"}},
        ]
    }
    return {
        "oneOf": [no_port, http_nondefault_port, https_nondefault_port]
    }


def _network_capability() -> Dict[str, Any]:
    no_destinations = {
        "type": "array",
        "maxItems": 0,
        "items": _canonical_http_origin(),
    }
    web_destinations = {
        "type": "array",
        "minItems": 1,
        "maxItems": 256,
        "uniqueItems": True,
        "items": _canonical_http_origin(),
    }
    return {
        "oneOf": [
            _strict_object(
                "ask_herdr.network_capability.v1",
                {
                    "mode": _const_string("none"),
                    "destinations": no_destinations,
                },
                ["mode", "destinations"],
            ),
            _strict_object(
                "ask_herdr.network_capability.v1",
                {
                    "mode": _const_string("web"),
                    "destinations": web_destinations,
                },
                ["mode", "destinations"],
            ),
            _strict_object(
                "ask_herdr.network_capability.v1",
                {
                    "mode": _const_string("full"),
                    "destinations": no_destinations,
                },
                ["mode", "destinations"],
            ),
        ]
    }


def _connector_capability() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.connector_capability.v1",
        {
            "name": _token(),
            "operations": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": _token(),
            },
        },
        ["name", "operations"],
    )


def _transaction_byte_limits() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.transaction_byte_limits.v1",
        {
            "temporary_bytes": _safe_nonnegative_integer(
                MAX_TRANSACTION_TEMPORARY_BYTES
            ),
            "output_bytes": _safe_nonnegative_integer(
                MAX_PROVIDER_TERMINAL_BYTES
            ),
        },
        ["temporary_bytes", "output_bytes"],
    )


def _capability_manifest() -> Dict[str, Any]:
    path_array = {
        "type": "array",
        "maxItems": 10_000,
        "uniqueItems": True,
        "items": _capability_path(),
    }
    return _strict_object(
        "ask_herdr.capability_manifest.v1",
        {
            "read_paths": path_array,
            "write_paths": {
                "type": "array",
                "maxItems": 10_000,
                "uniqueItems": True,
                "items": _capability_path(),
            },
            "network": _network_capability(),
            "tools": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": _token(),
            },
            "connectors": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": _connector_capability(),
            },
            "limits": _transaction_byte_limits(),
        },
        [
            "read_paths",
            "write_paths",
            "network",
            "tools",
            "connectors",
            "limits",
        ],
    )


def _generation_precondition() -> Dict[str, Any]:
    return {
        "oneOf": [
            _strict_object(
                "ask_herdr.generation_precondition.v1",
                {"state": _const_string("unused")},
                ["state"],
            ),
            _strict_object(
                "ask_herdr.generation_precondition.v1",
                {
                    "state": _const_string("after_release"),
                    "predecessor_lane_id": _uuid4(),
                    "predecessor_generation": _positive_safe_integer(),
                    "predecessor_state_digest": _sha256(),
                },
                [
                    "state",
                    "predecessor_lane_id",
                    "predecessor_generation",
                    "predecessor_state_digest",
                ],
            ),
        ]
    }


def _consultant_variant(provider: str, launcher_profile: str) -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.consultant_request.v1",
        {
            "child_operation_id": _uuid4(),
            "consultant_key": _consultant_key(),
            "generation_precondition": _generation_precondition(),
            "provider": _const_string(provider),
            "launcher_profile": _const_string(launcher_profile),
            "requested_model": _model_value(),
            "requested_effort": _model_value(),
            "allowed_auxiliary_models": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": _model_value(),
            },
            "expected_profile_binding_digest": _sha256(),
            "expected_acceptance_digest": _sha256(),
            "post_final_release": {
                "type": "string",
                "enum": ["retain", "lane_workspace"],
            },
        },
        [
            "child_operation_id",
            "consultant_key",
            "generation_precondition",
            "provider",
            "launcher_profile",
            "requested_model",
            "requested_effort",
            "allowed_auxiliary_models",
            "expected_profile_binding_digest",
            "expected_acceptance_digest",
            "post_final_release",
        ],
    )


def _consultant_request() -> Dict[str, Any]:
    return {
        "oneOf": [
            _consultant_variant("claude", "claude"),
            _consultant_variant("claude", "cc-claude"),
            _consultant_variant("deepseek", "cc-deepseek"),
            _consultant_variant("codex", "codex"),
        ]
    }


def _lineage() -> Dict[str, Any]:
    return {
        "oneOf": [
            _strict_object(
                "ask_herdr.turn_lineage.v1",
                {
                    "kind": _const_string("canonical"),
                    "review_branch_id": {"type": "null"},
                },
                ["kind", "review_branch_id"],
            ),
            _strict_object(
                "ask_herdr.turn_lineage.v1",
                {
                    "kind": _const_string("review_branch"),
                    "review_branch_id": _uuid4(),
                },
                ["kind", "review_branch_id"],
            ),
        ]
    }


def _pending_clarification_correlation() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.pending_clarification_correlation.v1",
        {
            "consultant_key": _consultant_key(),
            "lane_id": _uuid4(),
            "lane_generation": _positive_safe_integer(),
            "question_id": _uuid4(),
            "question_sequence": _positive_safe_integer(),
            "originating_turn_id": _uuid4(),
            "lineage": _lineage(),
            "expected_head_digest": _sha256(),
        },
        [
            "consultant_key",
            "lane_id",
            "lane_generation",
            "question_id",
            "question_sequence",
            "originating_turn_id",
            "lineage",
            "expected_head_digest",
        ],
    )


def _review_target() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.review_target.v1",
        {
            "consultant_key": _consultant_key(),
            "target_turn_id": _uuid4(),
            "lane_id": _uuid4(),
            "lane_generation": _positive_safe_integer(),
            "target_response_digest": _sha256(),
            "expected_head_digest": _sha256(),
        },
        [
            "consultant_key",
            "target_turn_id",
            "lane_id",
            "lane_generation",
            "target_response_digest",
            "expected_head_digest",
        ],
    )


def _capability_expansion_ref() -> Dict[str, Any]:
    return _strict_object(
        "ask_herdr.capability_expansion_ref.v1",
        {
            "expansion_id": _uuid4(),
            "expansion_digest": _sha256(),
        },
        ["expansion_id", "expansion_digest"],
    )


def _payload_document(
    operation: str,
    properties: Dict[str, Any],
    required: Iterable[str],
    **keywords: Any,
) -> Dict[str, Any]:
    schema_id = TURN_PAYLOAD_SCHEMA_IDS[operation]
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": f"urn:ask-herdr:schema:{schema_id}",
        **_strict_object(schema_id, properties, required, **keywords),
    }


def _consult_payload() -> Dict[str, Any]:
    return _payload_document(
        "turn.consult",
        {
            "prompt": _normalized_content(
                "prompt", MAX_REQUEST_CONTENT_BYTES
            ),
            "materials": _materials(),
            "capabilities": _capability_manifest(),
            "consultants": {
                "type": "array",
                "minItems": 1,
                "maxItems": 3,
                "items": _consultant_request(),
            },
        },
        ["prompt", "materials", "capabilities", "consultants"],
    )


def _answer_payload() -> Dict[str, Any]:
    return _payload_document(
        "turn.answer",
        {
            "clarification": _pending_clarification_correlation(),
            "answer": _normalized_content(
                "answer", MAX_CLARIFICATION_ANSWER_BYTES
            ),
            "added_materials": _materials(minimum=1),
            "capability_expansion_ref": _capability_expansion_ref(),
            "expected_profile_binding_digest": _sha256(),
            "expected_acceptance_digest": _sha256(),
            "post_final_release": {
                "type": "string",
                "enum": ["retain", "lane_workspace"],
            },
        },
        [
            "clarification",
            "answer",
            "expected_profile_binding_digest",
            "expected_acceptance_digest",
            "post_final_release",
        ],
        dependentRequired={
            "added_materials": ["capability_expansion_ref"],
            "capability_expansion_ref": ["added_materials"],
        },
    )


def _review_payload() -> Dict[str, Any]:
    return _payload_document(
        "turn.review",
        {
            "target": _review_target(),
            "instruction": _normalized_content(
                "review_instruction", MAX_REQUEST_CONTENT_BYTES
            ),
            "materials": _materials(),
            "capabilities": _capability_manifest(),
            "expected_profile_binding_digest": _sha256(),
            "expected_acceptance_digest": _sha256(),
            "post_final_release": {
                "type": "string",
                "enum": ["retain", "lane_workspace"],
            },
        },
        [
            "target",
            "instruction",
            "materials",
            "capabilities",
            "expected_profile_binding_digest",
            "expected_acceptance_digest",
            "post_final_release",
        ],
    )


def _safe_retry_payload() -> Dict[str, Any]:
    return _payload_document(
        "turn.safe_retry",
        {
            "source_operation_id": _uuid4(),
            "expected_source_request_digest": _sha256(),
            "definite_non_start_state_digest": _sha256(),
        },
        [
            "source_operation_id",
            "expected_source_request_digest",
            "definite_non_start_state_digest",
        ],
    )


def _recovery_continue_payload() -> Dict[str, Any]:
    return _payload_document(
        "turn.recovery_continue",
        {
            "source_operation_id": _uuid4(),
            "expected_source_request_digest": _sha256(),
            "interrupted_state_digest": _sha256(),
            "capability_expansion_ref": {
                "oneOf": [
                    {"type": "null"},
                    _capability_expansion_ref(),
                ]
            },
        },
        [
            "source_operation_id",
            "expected_source_request_digest",
            "interrupted_state_digest",
            "capability_expansion_ref",
        ],
    )


def build_turn_payload_schemas() -> Dict[str, Dict[str, Any]]:
    """Return one fresh deterministic schema per exact turn operation."""

    builders = {
        "turn.answer": _answer_payload,
        "turn.consult": _consult_payload,
        "turn.recovery_continue": _recovery_continue_payload,
        "turn.review": _review_payload,
        "turn.safe_retry": _safe_retry_payload,
    }
    if tuple(builders) != TURN_OPERATION_NAMES:
        raise AssertionError("turn payload builder registry drift")
    return {operation: builders[operation]() for operation in TURN_OPERATION_NAMES}


if len(TURN_PAYLOAD_SCHEMA_IDS) != 5:
    raise AssertionError("turn payload schema registry must cover exactly five operations")
