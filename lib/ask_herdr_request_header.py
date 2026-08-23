"""Pure validation of the request fields needed for a safe outcome envelope."""

from __future__ import annotations

import os
import re
from typing import Any, Mapping

from ask_herdr_operation_contract import OPERATION_CONTRACTS
from ask_herdr_request_schema import (
    CANONICAL_ABSOLUTE_PATH_PATTERN,
    REQUEST_SCHEMA_ID,
    UUID4_PATTERN,
)


PROJECT_BINDING_SCHEMA_ID = "ask_herdr.project_binding.v1"


class TrustedHeaderError(ValueError):
    """The input cannot safely identify an outcome envelope."""

    code = "request.header_invalid"


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


__all__ = (
    "PROJECT_BINDING_SCHEMA_ID",
    "TrustedHeaderError",
    "trust_request_header",
)
