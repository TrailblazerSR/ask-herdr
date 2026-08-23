"""Generated schema contracts for cross-platform Machine discovery.

The v1 and v2 documents remain frozen.  This module owns only the additive v3
discovery and schema-document envelopes that describe the runtime platform
without widening any existing request or storage contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]

DESCRIBE_V3_SCHEMA_ID = "ask_herdr.describe.v3"
DESCRIBE_V3_SCHEMA_PATH = ROOT / "schemas" / f"{DESCRIBE_V3_SCHEMA_ID}.schema.json"
SCHEMA_DOCUMENT_V3_SCHEMA_ID = "ask_herdr.schema_document.v3"
SCHEMA_DOCUMENT_V3_SCHEMA_PATH = (
    ROOT / "schemas" / f"{SCHEMA_DOCUMENT_V3_SCHEMA_ID}.schema.json"
)

PUBLIC_SCHEMA_IDS_V3 = (
    "ask_herdr.describe.v1",
    "ask_herdr.describe.v2",
    DESCRIBE_V3_SCHEMA_ID,
    "ask_herdr.outcome.v1",
    "ask_herdr.outcome.v2",
    "ask_herdr.query.status.result.v1",
    "ask_herdr.request.v1",
    "ask_herdr.schema_document.v1",
    "ask_herdr.schema_document.v2",
    SCHEMA_DOCUMENT_V3_SCHEMA_ID,
)


def _string_array(*, values: tuple[str, ...] | None = None) -> Dict[str, Any]:
    items: Dict[str, Any] = {"type": "string"}
    if values is not None:
        items["enum"] = list(values)
    return {"type": "array", "items": items, "uniqueItems": True}


def _schema_metadata() -> Dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_id", "semantic_version", "sha256"],
        "properties": {
            "schema_id": {"enum": list(PUBLIC_SCHEMA_IDS_V3), "type": "string"},
            "semantic_version": {
                "pattern": r"^[0-9]+\.[0-9]+\.[0-9]+$",
                "type": "string",
            },
            "sha256": {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"},
        },
    }


def _runtime_platform_schema() -> Dict[str, Any]:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema",
            "os_family",
            "path_flavor",
            "execution_tier",
            "storage_profile",
            "supported_operations",
            "limitations",
        ],
        "properties": {
            "schema": {"const": "ask_herdr.runtime_platform.v1", "type": "string"},
            "os_family": {
                "enum": ["macos", "linux", "windows", "other"],
                "type": "string",
            },
            "path_flavor": {"enum": ["posix", "windows"], "type": "string"},
            "execution_tier": {
                "enum": ["full", "contract_only"],
                "type": "string",
            },
            "storage_profile": {
                "enum": [
                    "darwin-exclusive-capsule-v1",
                    "linux-exclusive-capsule-v1",
                    "unavailable",
                ],
                "type": "string",
            },
            "supported_operations": {
                **_string_array(values=("query.status",)),
                "maxItems": 1,
            },
            "limitations": {
                **_string_array(
                    values=(
                        "native_windows_project_store_unavailable",
                        "platform_storage_backend_unavailable",
                    )
                ),
                "maxItems": 1,
            },
        },
    }
    profiles = (
        (
            "macos",
            "posix",
            "full",
            "darwin-exclusive-capsule-v1",
            ["query.status"],
            [],
        ),
        (
            "linux",
            "posix",
            "full",
            "linux-exclusive-capsule-v1",
            ["query.status"],
            [],
        ),
        (
            "windows",
            "windows",
            "contract_only",
            "unavailable",
            [],
            ["native_windows_project_store_unavailable"],
        ),
        (
            "other",
            "posix",
            "contract_only",
            "unavailable",
            [],
            ["platform_storage_backend_unavailable"],
        ),
    )
    schema["oneOf"] = [
        {
            "properties": {
                "os_family": {"const": os_family},
                "path_flavor": {"const": path_flavor},
                "execution_tier": {"const": execution_tier},
                "storage_profile": {"const": storage_profile},
                "supported_operations": {"const": supported_operations},
                "limitations": {"const": limitations},
            }
        }
        for (
            os_family,
            path_flavor,
            execution_tier,
            storage_profile,
            supported_operations,
            limitations,
        ) in profiles
    ]
    return schema


def build_describe_v3_schema() -> Dict[str, Any]:
    """Return the closed active discovery schema for runtime version 0.4.0."""

    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "capability_vocabulary",
            "cli_version",
            "exit_classes",
            "features",
            "launcher_profile_registry",
            "limits",
            "machine_core_contract",
            "runtime_platform",
            "schema",
            "schema_documents",
        ],
        "properties": {
            "schema": {"const": DESCRIBE_V3_SCHEMA_ID, "type": "string"},
            "cli_version": {"const": "0.4.0", "type": "string"},
            "runtime_platform": _runtime_platform_schema(),
            "machine_core_contract": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "action_reasons",
                    "implementation_version",
                    "lane_origin_reasons",
                    "operations",
                    "supported_outcome_versions",
                    "supported_request_versions",
                ],
                "properties": {
                    "implementation_version": {"const": "0.4.0", "type": "string"},
                    "supported_request_versions": {
                        "type": "array",
                        "items": {"const": "ask_herdr.request.v1", "type": "string"},
                        "minItems": 1,
                        "maxItems": 1,
                    },
                    "supported_outcome_versions": {
                        "type": "array",
                        "items": {
                            "enum": ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
                            "type": "string",
                        },
                        "minItems": 2,
                        "maxItems": 2,
                        "uniqueItems": True,
                    },
                    "operations": _string_array(),
                    "action_reasons": _string_array(),
                    "lane_origin_reasons": _string_array(),
                },
            },
            "schema_documents": {
                "type": "array",
                "items": _schema_metadata(),
                "minItems": len(PUBLIC_SCHEMA_IDS_V3),
                "maxItems": len(PUBLIC_SCHEMA_IDS_V3),
                "uniqueItems": True,
            },
            "exit_classes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "meaning"],
                    "properties": {
                        "code": {
                            "enum": [0, 10, 20, 30, 40, 50, 64, 76],
                            "type": "integer",
                        },
                        "meaning": {"type": "string"},
                    },
                },
            },
            "limits": {
                "type": "object",
                "additionalProperties": {"type": "integer"},
            },
            "capability_vocabulary": {
                "type": "object",
                "additionalProperties": False,
                "required": ["manifest_sources", "network_modes", "path_scopes"],
                "properties": {
                    "manifest_sources": _string_array(),
                    "network_modes": _string_array(),
                    "path_scopes": _string_array(),
                },
            },
            "launcher_profile_registry": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profiles", "version"],
                "properties": {
                    "version": {"const": "ask_herdr.launcher_profiles.v1", "type": "string"},
                    "profiles": {
                        "type": "array",
                        "uniqueItems": True,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "default_enabled",
                                "profile",
                                "provider",
                                "registered_command",
                                "required_for_provider",
                            ],
                            "properties": {
                                "default_enabled": {"const": False, "type": "boolean"},
                                "profile": {"type": "string"},
                                "provider": {"type": "string"},
                                "registered_command": {"type": "string"},
                                "required_for_provider": {"type": "boolean"},
                            },
                        },
                    },
                },
            },
            "features": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "human_facade",
                    "machine_describe",
                    "machine_run",
                    "machine_schema",
                    "machine_validate",
                ],
                "properties": {
                    "human_facade": {"const": False, "type": "boolean"},
                    "machine_describe": {"const": True, "type": "boolean"},
                    "machine_run": {"type": "boolean"},
                    "machine_schema": {"const": True, "type": "boolean"},
                    "machine_validate": {"type": "boolean"},
                },
            },
        },
        "allOf": [
            {
                "if": {
                    "properties": {
                        "runtime_platform": {
                            "properties": {"execution_tier": {"const": "full"}},
                            "required": ["execution_tier"],
                        }
                    },
                    "required": ["runtime_platform"],
                },
                "then": {
                    "properties": {
                        "features": {
                            "properties": {
                                "machine_run": {"const": True},
                                "machine_validate": {"const": True},
                            }
                        },
                        "runtime_platform": {
                            "properties": {
                                "supported_operations": {
                                    "const": ["query.status"]
                                },
                                "limitations": {"const": []},
                            }
                        },
                    }
                },
                "else": {
                    "properties": {
                        "features": {
                            "properties": {
                                "machine_run": {"const": False},
                                "machine_validate": {"const": False},
                            }
                        },
                        "runtime_platform": {
                            "properties": {
                                "supported_operations": {"const": []}
                            }
                        },
                    }
                },
            }
        ],
    }


def build_schema_document_v3_schema() -> Dict[str, Any]:
    """Return the closed wrapper for the two additive v3 documents."""

    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["document", "schema", "schema_id", "semantic_version", "sha256"],
        "properties": {
            "schema": {"const": SCHEMA_DOCUMENT_V3_SCHEMA_ID, "type": "string"},
            "schema_id": {"enum": list(PUBLIC_SCHEMA_IDS_V3), "type": "string"},
            "semantic_version": {
                "pattern": r"^[0-9]+\.[0-9]+\.[0-9]+$",
                "type": "string",
            },
            "sha256": {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"},
            "document": {"type": "object"},
        },
    }


__all__ = [
    "DESCRIBE_V3_SCHEMA_ID",
    "DESCRIBE_V3_SCHEMA_PATH",
    "PUBLIC_SCHEMA_IDS_V3",
    "SCHEMA_DOCUMENT_V3_SCHEMA_ID",
    "SCHEMA_DOCUMENT_V3_SCHEMA_PATH",
    "build_describe_v3_schema",
    "build_schema_document_v3_schema",
]
