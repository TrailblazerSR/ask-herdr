"""Self-contained JSON Schemas for the Machine Core administration payloads.

The builders in this module are pure and provider-free.  They neither register
nor advertise the schemas: public activation remains an atomic integration step
after every request branch and semantic validator is complete.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Sequence


JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
UUID4_PATTERN = (
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SHA256_DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
CANONICAL_ABSOLUTE_PATH_PATTERN = (
    r"^(?!.*(?:^|/)\.{1,2}(?:/|$))/(?!.*//)"
    r"(?:[^/\u0000]+(?:/[^/\u0000]+)*)?$"
)
OPAQUE_NATIVE_ID_PATTERN = r"^[\x21-\x7e]{1,512}$"

PROFILE_PAIRS = (
    ("claude", "claude"),
    ("claude", "cc-claude"),
    ("deepseek", "cc-deepseek"),
    ("codex", "codex"),
)
PROVIDERS = ("claude", "deepseek", "codex")

ADMIN_OPERATIONS = (
    "profile.list",
    "profile.show",
    "profile.check",
    "profile.auth.status",
    "profile.auth.login",
    "profile.auth.logout",
    "project.init",
    "project.rebind.preview",
    "project.rebind.execute",
    "project.retire.preview",
    "project.retire.execute",
    "cleanup.preview",
    "cleanup.execute",
    "cleanup.resume",
    "cleanup.status",
    "policy.show",
    "policy.status",
    "policy.validate",
    "policy.activate.preview",
    "policy.activate.execute",
    "policy.compact.preview",
    "policy.compact.execute",
)


def _const(value: str) -> Dict[str, Any]:
    return {"type": "string", "const": value}


def _uuid4() -> Dict[str, Any]:
    return {"type": "string", "pattern": UUID4_PATTERN}


def _digest() -> Dict[str, Any]:
    return {"type": "string", "pattern": SHA256_DIGEST_PATTERN}


def _canonical_absolute_path() -> Dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": CANONICAL_ABSOLUTE_PATH_PATTERN,
    }


def _strict_object(
    properties: Mapping[str, Any], required: Sequence[str]
) -> Dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required),
    }


def _payload_object(
    operation: str,
    fields: Mapping[str, Any] | None = None,
    required_fields: Sequence[str] = (),
) -> Dict[str, Any]:
    properties: Dict[str, Any] = {
        "schema": _const(f"ask_herdr.{operation}.payload.v1")
    }
    if fields:
        properties.update(fields)
    return _strict_object(properties, ("schema", *required_fields))


def _document(operation: str, body: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": f"urn:ask-herdr:schema:{operation.replace('.', '-')}-payload:v1",
        **body,
    }


def _profile_pair_payload(
    operation: str,
    extra_fields: Mapping[str, Any] | None = None,
    extra_required: Sequence[str] = (),
) -> Dict[str, Any]:
    branches = []
    for provider, profile in PROFILE_PAIRS:
        fields: Dict[str, Any] = {
            "provider": _const(provider),
            "profile": _const(profile),
        }
        if extra_fields:
            fields.update(extra_fields)
        branches.append(
            _payload_object(
                operation,
                fields,
                ("provider", "profile", *extra_required),
            )
        )
    return _document(operation, {"oneOf": branches})


def _manifest_payload(operation: str) -> Dict[str, Any]:
    return _document(
        operation,
        _payload_object(
            operation,
            {
                "manifest_id": _uuid4(),
                "manifest_digest": _digest(),
                "expected_state_digest": _digest(),
            },
            ("manifest_id", "manifest_digest", "expected_state_digest"),
        ),
    )


def _ledger_manifest_payload(operation: str) -> Dict[str, Any]:
    return _document(
        operation,
        _payload_object(
            operation,
            {
                "manifest_id": _uuid4(),
                "manifest_digest": _digest(),
                "expected_ledger_state_digest": _digest(),
            },
            (
                "manifest_id",
                "manifest_digest",
                "expected_ledger_state_digest",
            ),
        ),
    )


def _schema_only(operation: str) -> Dict[str, Any]:
    return _document(operation, _payload_object(operation))


def _profile_list() -> Dict[str, Any]:
    operation = "profile.list"
    return _document(
        operation,
        _payload_object(
            operation,
            {"provider": {"type": "string", "enum": list(PROVIDERS)}},
        ),
    )


def _profile_show() -> Dict[str, Any]:
    return _profile_pair_payload("profile.show")


def _profile_check() -> Dict[str, Any]:
    return _profile_pair_payload(
        "profile.check",
        {"executable": _canonical_absolute_path()},
        ("executable",),
    )


def _profile_auth_status() -> Dict[str, Any]:
    return _profile_pair_payload("profile.auth.status")


def _profile_auth_login() -> Dict[str, Any]:
    return _profile_pair_payload("profile.auth.login")


def _profile_auth_logout() -> Dict[str, Any]:
    return _profile_pair_payload("profile.auth.logout")


def _project_init() -> Dict[str, Any]:
    operation = "project.init"
    schema = _const(f"ask_herdr.{operation}.payload.v1")
    return _document(
        operation,
        {
            "oneOf": [
                _strict_object(
                    {"schema": schema, "lifetime": _const("initial")},
                    ("schema", "lifetime"),
                ),
                _strict_object(
                    {
                        "schema": schema,
                        "lifetime": _const("after_tombstone"),
                        "predecessor_tombstone_id": _uuid4(),
                        "predecessor_tombstone_digest": _digest(),
                    },
                    (
                        "schema",
                        "lifetime",
                        "predecessor_tombstone_id",
                        "predecessor_tombstone_digest",
                    ),
                ),
            ]
        },
    )


def _project_rebind_preview() -> Dict[str, Any]:
    operation = "project.rebind.preview"
    return _document(
        operation,
        _payload_object(
            operation,
            {"proposed_root": _canonical_absolute_path()},
            ("proposed_root",),
        ),
    )


def _project_rebind_execute() -> Dict[str, Any]:
    return _manifest_payload("project.rebind.execute")


def _project_retire_preview() -> Dict[str, Any]:
    return _schema_only("project.retire.preview")


def _project_retire_execute() -> Dict[str, Any]:
    return _manifest_payload("project.retire.execute")


def _lane_generation_target() -> Dict[str, Any]:
    return _strict_object(
        {
            "schema": _const(
                "ask_herdr.cleanup.durable_evidence_target.v1"
            ),
            "target_type": _const("lane_generation"),
            "lane_id": _uuid4(),
            "generation": {"type": "integer", "minimum": 1},
        },
        ("schema", "target_type", "lane_id", "generation"),
    )


def _review_branch_target() -> Dict[str, Any]:
    return _strict_object(
        {
            "schema": _const(
                "ask_herdr.cleanup.durable_evidence_target.v1"
            ),
            "target_type": _const("review_branch"),
            "review_branch_id": _uuid4(),
        },
        ("schema", "target_type", "review_branch_id"),
    )


def _abandonment_target() -> Dict[str, Any]:
    return _strict_object(
        {
            "schema": _const(
                "ask_herdr.cleanup.abandonment_evidence_target.v1"
            ),
            "lane_id": _uuid4(),
            "generation": {"type": "integer", "minimum": 1},
            "lane_tombstone_digest": _digest(),
        },
        ("schema", "lane_id", "generation", "lane_tombstone_digest"),
    )


def _provider_native_target() -> Dict[str, Any]:
    branches = []
    for provider, profile in PROFILE_PAIRS:
        branches.append(
            _strict_object(
                {
                    "schema": _const(
                        "ask_herdr.cleanup.provider_native_state_target.v1"
                    ),
                    "provider": _const(provider),
                    "profile": _const(profile),
                    "artifact_kind": {
                        "type": "string",
                        "enum": ["session", "thread", "other"],
                    },
                    "artifact_id": {
                        "type": "string",
                        "pattern": OPAQUE_NATIVE_ID_PATTERN,
                    },
                    "artifact_binding_digest": _digest(),
                },
                (
                    "schema",
                    "provider",
                    "profile",
                    "artifact_kind",
                    "artifact_id",
                    "artifact_binding_digest",
                ),
            )
        )
    return {"oneOf": branches}


def _isolated_authentication_target() -> Dict[str, Any]:
    branches = []
    for provider, profile in PROFILE_PAIRS:
        branches.append(
            _strict_object(
                {
                    "schema": _const(
                        "ask_herdr.cleanup.isolated_authentication_target.v1"
                    ),
                    "provider": _const(provider),
                    "profile": _const(profile),
                    "provider_state_root_binding_digest": _digest(),
                },
                (
                    "schema",
                    "provider",
                    "profile",
                    "provider_state_root_binding_digest",
                ),
            )
        )
    return {"oneOf": branches}


def _target_array(items: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "type": "array",
        "minItems": 1,
        "maxItems": 10_000,
        "uniqueItems": True,
        "items": dict(items),
    }


def _cleanup_selection_variants() -> list[Dict[str, Any]]:
    common_schema = _const("ask_herdr.cleanup_selection.v1")
    durable = _strict_object(
        {
            "schema": common_schema,
            "scope": _const("durable_evidence"),
            "targets": _target_array(
                {"oneOf": [_lane_generation_target(), _review_branch_target()]}
            ),
        },
        ("schema", "scope", "targets"),
    )
    abandonment = _strict_object(
        {
            "schema": common_schema,
            "scope": _const("abandonment_evidence"),
            "targets": _target_array(_abandonment_target()),
            "acknowledge_loss_of_future_reconciliation": {
                "type": "boolean",
                "const": True,
            },
        },
        (
            "schema",
            "scope",
            "targets",
            "acknowledge_loss_of_future_reconciliation",
        ),
    )
    provider_native = _strict_object(
        {
            "schema": common_schema,
            "scope": _const("provider_native_state"),
            "targets": _target_array(_provider_native_target()),
        },
        ("schema", "scope", "targets"),
    )
    isolated_authentication = _strict_object(
        {
            "schema": common_schema,
            "scope": _const("isolated_authentication"),
            "target": _isolated_authentication_target(),
        },
        ("schema", "scope", "target"),
    )
    return [durable, abandonment, provider_native, isolated_authentication]


def _cleanup_preview() -> Dict[str, Any]:
    operation = "cleanup.preview"
    return _document(
        operation,
        _payload_object(
            operation,
            {"selection": {"oneOf": _cleanup_selection_variants()}},
            ("selection",),
        ),
    )


def _cleanup_execute() -> Dict[str, Any]:
    operation = "cleanup.execute"
    return _document(
        operation,
        _payload_object(
            operation,
            {
                "manifest_id": _uuid4(),
                "manifest_digest": _digest(),
                "selection_digest": _digest(),
                "expected_state_digest": _digest(),
            },
            (
                "manifest_id",
                "manifest_digest",
                "selection_digest",
                "expected_state_digest",
            ),
        ),
    )


def _cleanup_resume() -> Dict[str, Any]:
    operation = "cleanup.resume"
    return _document(
        operation,
        _payload_object(
            operation,
            {
                "original_operation_id": _uuid4(),
                "manifest_id": _uuid4(),
                "manifest_digest": _digest(),
                "expected_reconciliation_state_digest": _digest(),
                "completed_step_chain_digest": _digest(),
            },
            (
                "original_operation_id",
                "manifest_id",
                "manifest_digest",
                "expected_reconciliation_state_digest",
                "completed_step_chain_digest",
            ),
        ),
    )


def _cleanup_status() -> Dict[str, Any]:
    return _schema_only("cleanup.status")


def _policy_show() -> Dict[str, Any]:
    operation = "policy.show"
    schema = _const(f"ask_herdr.{operation}.payload.v1")
    return _document(
        operation,
        {
            "oneOf": [
                _strict_object(
                    {"schema": schema, "selection": _const("active")},
                    ("schema", "selection"),
                ),
                _strict_object(
                    {
                        "schema": schema,
                        "selection": _const("version"),
                        "policy_profile_id": _uuid4(),
                        "policy_version": {
                            "type": "integer",
                            "minimum": 1,
                        },
                    },
                    (
                        "schema",
                        "selection",
                        "policy_profile_id",
                        "policy_version",
                    ),
                ),
            ]
        },
    )


def _policy_status() -> Dict[str, Any]:
    return _schema_only("policy.status")


def _candidate_policy_payload(operation: str) -> Dict[str, Any]:
    return _document(
        operation,
        _payload_object(
            operation,
            {"candidate_policy": _canonical_absolute_path()},
            ("candidate_policy",),
        ),
    )


def _policy_validate() -> Dict[str, Any]:
    return _candidate_policy_payload("policy.validate")


def _policy_activate_preview() -> Dict[str, Any]:
    return _candidate_policy_payload("policy.activate.preview")


def _policy_activate_execute() -> Dict[str, Any]:
    return _ledger_manifest_payload("policy.activate.execute")


def _policy_compact_preview() -> Dict[str, Any]:
    # The core derives the deterministic maximal eligible ledger prefix.
    return _schema_only("policy.compact.preview")


def _policy_compact_execute() -> Dict[str, Any]:
    return _ledger_manifest_payload("policy.compact.execute")


ADMIN_PAYLOAD_SCHEMA_BUILDERS: Mapping[
    str, Callable[[], Dict[str, Any]]
] = MappingProxyType(
    {
        "profile.list": _profile_list,
        "profile.show": _profile_show,
        "profile.check": _profile_check,
        "profile.auth.status": _profile_auth_status,
        "profile.auth.login": _profile_auth_login,
        "profile.auth.logout": _profile_auth_logout,
        "project.init": _project_init,
        "project.rebind.preview": _project_rebind_preview,
        "project.rebind.execute": _project_rebind_execute,
        "project.retire.preview": _project_retire_preview,
        "project.retire.execute": _project_retire_execute,
        "cleanup.preview": _cleanup_preview,
        "cleanup.execute": _cleanup_execute,
        "cleanup.resume": _cleanup_resume,
        "cleanup.status": _cleanup_status,
        "policy.show": _policy_show,
        "policy.status": _policy_status,
        "policy.validate": _policy_validate,
        "policy.activate.preview": _policy_activate_preview,
        "policy.activate.execute": _policy_activate_execute,
        "policy.compact.preview": _policy_compact_preview,
        "policy.compact.execute": _policy_compact_execute,
    }
)

ADMIN_PAYLOAD_SCHEMA_IDS: Mapping[str, str] = MappingProxyType(
    {
        operation: f"ask_herdr.{operation}.payload.v1"
        for operation in ADMIN_PAYLOAD_SCHEMA_BUILDERS
    }
)


def build_admin_payload_schema(operation: str) -> Dict[str, Any]:
    """Return a fresh self-contained payload schema for one exact operation."""

    return ADMIN_PAYLOAD_SCHEMA_BUILDERS[operation]()


if set(ADMIN_PAYLOAD_SCHEMA_BUILDERS) != set(ADMIN_OPERATIONS):
    raise AssertionError("admin payload builders must cover exactly 22 operations")
