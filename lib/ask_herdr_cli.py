"""Provider-free entry point for the permanent Herdr-Native Interface."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Dict, List, Optional, Tuple


sys.dont_write_bytecode = True


CLI_VERSION = "0.2.0"
CORE_IMPLEMENTATION_VERSION = "0.2.0"
REQUEST_BYTES_MAX = 8_388_608

from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_discovery_contract import (
    DESCRIBE_V3_SCHEMA_ID,
    DESCRIBE_V3_SCHEMA_PATH,
    SCHEMA_DOCUMENT_V3_SCHEMA_ID,
    SCHEMA_DOCUMENT_V3_SCHEMA_PATH,
)
from ask_herdr_platform import runtime_execution_supported, runtime_platform
from ask_herdr_request_header import (
    TrustedHeaderError,
    trust_request_header,
)
from ask_herdr_resources import schema_path


DESCRIBE_SCHEMA_ID = "ask_herdr.describe.v1"
DESCRIBE_SCHEMA_PATH = schema_path("ask_herdr.describe.v1.schema.json")
SCHEMA_DOCUMENT_SCHEMA_ID = "ask_herdr.schema_document.v1"
SCHEMA_DOCUMENT_SCHEMA_PATH = schema_path(
    "ask_herdr.schema_document.v1.schema.json"
)
REQUEST_SCHEMA_ID = "ask_herdr.request.v1"
REQUEST_SCHEMA_PATH = schema_path("ask_herdr.request.v1.schema.json")
OUTCOME_SCHEMA_ID = "ask_herdr.outcome.v1"
OUTCOME_SCHEMA_PATH = schema_path("ask_herdr.outcome.v1.schema.json")
PUBLIC_BETA_ACTIVE = True
PUBLIC_BETA_CLI_VERSION = "0.4.0"
PUBLIC_BETA_IMPLEMENTATION_VERSION = "0.4.0"
DESCRIBE_V2_SCHEMA_ID = "ask_herdr.describe.v2"
DESCRIBE_V2_SCHEMA_PATH = schema_path("ask_herdr.describe.v2.schema.json")
OUTCOME_V2_SCHEMA_ID = "ask_herdr.outcome.v2"
OUTCOME_V2_SCHEMA_PATH = schema_path("ask_herdr.outcome.v2.schema.json")
QUERY_STATUS_RESULT_SCHEMA_ID = "ask_herdr.query.status.result.v1"
QUERY_STATUS_RESULT_SCHEMA_PATH = schema_path(
    "ask_herdr.query.status.result.v1.schema.json"
)
SCHEMA_DOCUMENT_V2_SCHEMA_ID = "ask_herdr.schema_document.v2"
SCHEMA_DOCUMENT_V2_SCHEMA_PATH = schema_path(
    "ask_herdr.schema_document.v2.schema.json"
)
SCHEMA_REGISTRY = {
    DESCRIBE_SCHEMA_ID: (DESCRIBE_SCHEMA_PATH, "1.0.0"),
    OUTCOME_SCHEMA_ID: (OUTCOME_SCHEMA_PATH, "1.0.0"),
    REQUEST_SCHEMA_ID: (REQUEST_SCHEMA_PATH, "1.0.0"),
    SCHEMA_DOCUMENT_SCHEMA_ID: (SCHEMA_DOCUMENT_SCHEMA_PATH, "1.0.0"),
}
PUBLIC_BETA_SCHEMA_REGISTRY = {
    **SCHEMA_REGISTRY,
    DESCRIBE_V2_SCHEMA_ID: (DESCRIBE_V2_SCHEMA_PATH, "2.0.0"),
    DESCRIBE_V3_SCHEMA_ID: (DESCRIBE_V3_SCHEMA_PATH, "3.0.0"),
    OUTCOME_V2_SCHEMA_ID: (OUTCOME_V2_SCHEMA_PATH, "2.0.0"),
    QUERY_STATUS_RESULT_SCHEMA_ID: (QUERY_STATUS_RESULT_SCHEMA_PATH, "1.0.0"),
    SCHEMA_DOCUMENT_V2_SCHEMA_ID: (SCHEMA_DOCUMENT_V2_SCHEMA_PATH, "2.0.0"),
    SCHEMA_DOCUMENT_V3_SCHEMA_ID: (SCHEMA_DOCUMENT_V3_SCHEMA_PATH, "3.0.0"),
}

OPERATIONS = sorted(
    [
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
    ]
)

ACTION_REASONS = sorted(
    [
        "authentication",
        "clarification_answer",
        "cleanup",
        "initial",
        "inspect",
        "interrupt",
        "policy_admin",
        "project_admin",
        "recover",
        "recovery_continuation",
        "release",
        "review_clarification_answer",
        "review_fork",
        "safe_retry",
    ]
)

LANE_ORIGIN_REASONS = sorted(
    [
        "comment",
        "consult",
        "diagnose",
        "other",
        "plan",
        "review",
        "suggest",
        "verify",
    ]
)


class RequestCaptureError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def public_beta_active(activation: Optional[bool] = None) -> bool:
    if activation is None:
        return PUBLIC_BETA_ACTIVE
    if type(activation) is not bool:
        raise ValueError("activation must be a boolean")
    return activation


def schema_registry(
    activation: Optional[bool] = None,
) -> Dict[str, Tuple[Path, str]]:
    return (
        PUBLIC_BETA_SCHEMA_REGISTRY
        if public_beta_active(activation)
        else SCHEMA_REGISTRY
    )


def require_canonical_absolute_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if (
        not path.is_absolute()
        or path.anchor != os.path.sep
        or os.path.normpath(raw_path) != raw_path
        or len(path.parts) < 2
    ):
        raise RequestCaptureError(
            "request.path_not_canonical",
            "request path must be one canonical absolute path",
        )
    return path


def descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def open_request_descriptor(raw_path: str) -> int:
    path = require_canonical_absolute_path(raw_path)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | no_follow
        | close_on_exec
    )
    directory_descriptors = []
    directory_snapshots = []
    path_bindings = []
    request_descriptor = -1
    try:
        try:
            directory_descriptor = os.open(path.anchor, directory_flags)
            directory_descriptors.append(directory_descriptor)
            directory_snapshots.append(os.fstat(directory_descriptor))
            for component in path.parts[1:-1]:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=directory_descriptor,
                )
                path_bindings.append(
                    (directory_descriptor, component, next_descriptor)
                )
                directory_descriptor = next_descriptor
                directory_descriptors.append(directory_descriptor)
                directory_snapshots.append(os.fstat(directory_descriptor))
            request_descriptor = os.open(
                path.parts[-1],
                os.O_RDONLY | no_follow | close_on_exec,
                dir_fd=directory_descriptor,
            )
            path_bindings.append(
                (directory_descriptor, path.parts[-1], request_descriptor)
            )
        except OSError as error:
            raise RequestCaptureError(
                "request.open_failed", "request file cannot be opened safely"
            ) from error

        try:
            for descriptor, snapshot in zip(
                directory_descriptors,
                directory_snapshots,
            ):
                if descriptor_identity(os.fstat(descriptor)) != descriptor_identity(
                    snapshot
                ):
                    raise RequestCaptureError(
                        "request.changed_during_capture",
                        "request source changed during capture",
                    )
            for parent_descriptor, component, child_descriptor in path_bindings:
                current_binding = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if descriptor_identity(current_binding) != descriptor_identity(
                    os.fstat(child_descriptor)
                ):
                    raise RequestCaptureError(
                        "request.changed_during_capture",
                        "request source changed during capture",
                    )
        except OSError as error:
            raise RequestCaptureError(
                "request.changed_during_capture",
                "request source changed during capture",
            ) from error

        opened_descriptor = request_descriptor
        request_descriptor = -1
        return opened_descriptor
    finally:
        if request_descriptor >= 0:
            os.close(request_descriptor)
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)


def capture_request_file(raw_path: str) -> bytes:
    descriptor = open_request_descriptor(raw_path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RequestCaptureError(
                "request.not_regular", "request source must be a regular file"
            )
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise RequestCaptureError(
                "request.owner_mismatch", "request source must be owned by this user"
            )
        if before.st_size > REQUEST_BYTES_MAX:
            raise RequestCaptureError(
                "request.too_large", "request source exceeds the 8 MiB limit"
            )
        chunks = []
        remaining = REQUEST_BYTES_MAX + 1
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > REQUEST_BYTES_MAX:
            raise RequestCaptureError(
                "request.too_large", "request source exceeds the 8 MiB limit"
            )
        after = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            raise RequestCaptureError(
                "request.changed_during_capture",
                "request source changed during capture",
            )
        return payload
    finally:
        os.close(descriptor)


def capture_request_stdin() -> bytes:
    payload = sys.stdin.buffer.read(REQUEST_BYTES_MAX + 1)
    if len(payload) > REQUEST_BYTES_MAX:
        raise RequestCaptureError(
            "request.too_large", "request source exceeds the 8 MiB limit"
        )
    return payload


def parse_captured_request(payload: bytes) -> Dict[str, Any]:
    try:
        return parse_json_object(payload)
    except StrictJsonError as error:
        messages = {
            "json.duplicate_key": "request contains a duplicate JSON key",
            "json.float_forbidden": "request numbers must be schema integers",
            "json.integer_out_of_range": "request integer is outside the safe range",
            "json.invalid": "request must contain exactly one JSON object",
            "json.invalid_unicode_scalar": "request contains an invalid Unicode scalar",
            "json.invalid_utf8": "request must be strict UTF-8",
            "json.nonfinite_forbidden": "request non-finite numbers are forbidden",
            "json.not_object": "request must be a JSON object",
        }
        raise RequestCaptureError(
            error.code,
            messages.get(error.code, "request contains invalid JSON"),
        ) from error


def validate_request_source(
    raw_path: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str], int]:
    try:
        payload = (
            capture_request_stdin()
            if raw_path == "-"
            else capture_request_file(raw_path)
        )
        request = parse_captured_request(payload)
    except RequestCaptureError as error:
        return None, error.code, 64
    from ask_herdr_machine_validate import validate_request

    try:
        outcome, exit_class = validate_request(request, payload)
    except TrustedHeaderError as error:
        return None, error.code, 64
    return outcome, None, exit_class


def run_query_status_source(
    raw_path: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str], int]:
    """Capture one strict request and dispatch only the provider-free status route."""

    try:
        payload = (
            capture_request_stdin()
            if raw_path == "-"
            else capture_request_file(raw_path)
        )
        request = parse_captured_request(payload)
    except RequestCaptureError as error:
        return None, error.code, 64
    try:
        trust_request_header(request)
    except TrustedHeaderError as error:
        return None, error.code, 64
    if request["operation"] != "query.status":
        return None, "request.route_invalid", 64
    from ask_herdr_public_status import dispatch_query_status

    outcome = dispatch_query_status(request)
    return outcome, None, outcome["exit_class"]


def load_schema(path: Path) -> Dict[str, Any]:
    if path.is_symlink():
        raise RuntimeError(f"bundled schema is a symbolic link: {path.name}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"bundled schema is not a regular file: {path.name}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"bundled schema is not a JSON object: {path.name}")
    return document


def schema_digest(document: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document)).hexdigest()


def schema_metadata(
    schema_id: str,
    activation: Optional[bool] = None,
) -> Dict[str, Any]:
    path, semantic_version = schema_registry(activation)[schema_id]
    document = load_schema(path)
    return {
        "schema_id": schema_id,
        "semantic_version": semantic_version,
        "sha256": schema_digest(document),
    }


def static_profiles() -> List[Dict[str, Any]]:
    return [
        {
            "default_enabled": False,
            "profile": "claude/cc-claude",
            "provider": "claude",
            "registered_command": "cc-claude",
            "required_for_provider": False,
        },
        {
            "default_enabled": False,
            "profile": "claude/claude",
            "provider": "claude",
            "registered_command": "claude",
            "required_for_provider": True,
        },
        {
            "default_enabled": False,
            "profile": "codex/codex",
            "provider": "codex",
            "registered_command": "codex",
            "required_for_provider": True,
        },
        {
            "default_enabled": False,
            "profile": "deepseek/cc-deepseek",
            "provider": "deepseek",
            "registered_command": "cc-deepseek",
            "required_for_provider": True,
        },
    ]


def describe(activation: Optional[bool] = None) -> Dict[str, Any]:
    active = public_beta_active(activation)
    platform = runtime_platform()
    execution_supported = platform["execution_tier"] == "full"
    return {
        "schema": DESCRIBE_V3_SCHEMA_ID if active else DESCRIBE_SCHEMA_ID,
        "cli_version": PUBLIC_BETA_CLI_VERSION if active else CLI_VERSION,
        "machine_core_contract": {
            "implementation_version": (
                PUBLIC_BETA_IMPLEMENTATION_VERSION
                if active
                else CORE_IMPLEMENTATION_VERSION
            ),
            "supported_request_versions": [REQUEST_SCHEMA_ID],
            "supported_outcome_versions": (
                [OUTCOME_SCHEMA_ID, OUTCOME_V2_SCHEMA_ID]
                if active
                else [OUTCOME_SCHEMA_ID]
            ),
            "operations": OPERATIONS,
            "action_reasons": ACTION_REASONS,
            "lane_origin_reasons": LANE_ORIGIN_REASONS,
        },
        "schema_documents": [
            schema_metadata(schema_id, active)
            for schema_id in sorted(schema_registry(active))
        ],
        "exit_classes": [
            {"code": 0, "meaning": "handled"},
            {"code": 10, "meaning": "human_input_required"},
            {"code": 20, "meaning": "not_admitted"},
            {"code": 30, "meaning": "settled_runtime_failure"},
            {"code": 40, "meaning": "observation_or_reconciliation"},
            {"code": 50, "meaning": "quarantine_or_ownership_failure"},
            {"code": 64, "meaning": "usage_or_invalid_request"},
            {"code": 76, "meaning": "policy_deferral"},
        ],
        "limits": {
            "batch_children_max": 3,
            "batch_children_min": 2,
            "clarification_bytes_max": 1_048_576,
            "evidence_range_bytes_max": 1_048_576,
            "human_evidence_whole_bytes_max": 8_388_608,
            "material_files_max": 10_000,
            "material_total_bytes_max": 2_147_483_648,
            "metadata_page_limit_max": 200,
            "metadata_page_limit_human_default": 50,
            "outcome_serialized_bytes_max": 33_554_432,
            "provider_terminal_envelope_bytes_max": 16_777_216,
            "provider_transaction_temporary_bytes_max": 134_217_728,
            "request_envelope_bytes_max": 8_388_608,
            "status_read_epoch_attempt_limit": 3,
            "turn_final_bytes_max": 8_388_608,
        },
        "capability_vocabulary": {
            "manifest_sources": ["capabilities_file", "review_readonly"],
            "network_modes": ["full", "none", "web"],
            "path_scopes": ["object", "subtree"],
        },
        "launcher_profile_registry": {
            "version": "ask_herdr.launcher_profiles.v1",
            "profiles": static_profiles(),
        },
        **({"runtime_platform": platform} if active else {}),
        "features": {
            "human_facade": False,
            "machine_describe": True,
            "machine_run": active and execution_supported,
            "machine_schema": True,
            "machine_validate": execution_supported,
        },
    }


def emit_json(value: Dict[str, Any]) -> None:
    sys.stdout.buffer.write(canonical_json(value) + b"\n")


def schema_document(
    schema_id: str,
    activation: Optional[bool] = None,
) -> Dict[str, Any]:
    active = public_beta_active(activation)
    path, semantic_version = schema_registry(active)[schema_id]
    document = load_schema(path)
    if active and schema_id in {
        DESCRIBE_V3_SCHEMA_ID,
        SCHEMA_DOCUMENT_V3_SCHEMA_ID,
    }:
        envelope_schema = SCHEMA_DOCUMENT_V3_SCHEMA_ID
    elif active and schema_id not in SCHEMA_REGISTRY:
        envelope_schema = SCHEMA_DOCUMENT_V2_SCHEMA_ID
    else:
        envelope_schema = SCHEMA_DOCUMENT_SCHEMA_ID
    return {
        "schema": envelope_schema,
        "schema_id": schema_id,
        "semantic_version": semantic_version,
        "sha256": schema_digest(document),
        "document": document,
    }


def main(argv: List[str], *, activation: Optional[bool] = None) -> int:
    try:
        active = public_beta_active(activation)
        if argv == ["machine", "describe", "--json"]:
            emit_json(describe(active))
            return 0
        if len(argv) == 4 and argv[:3] == ["machine", "schema", "--id"]:
            schema_id = argv[3]
            if schema_id not in schema_registry(active):
                print(f"unknown schema id: {schema_id}", file=sys.stderr)
                return 64
            emit_json(schema_document(schema_id, active))
            return 0
        if len(argv) == 4 and argv[:3] == ["machine", "validate", "--request"]:
            if not runtime_execution_supported():
                print(
                    "ask-herdr machine validate failed: runtime.platform_unsupported",
                    file=sys.stderr,
                )
                return 20
            outcome, diagnostic_code, exit_class = validate_request_source(argv[3])
            if outcome is not None:
                emit_json(outcome)
                return exit_class
            print(f"ask-herdr machine validate failed: {diagnostic_code}", file=sys.stderr)
            return exit_class
        if active and len(argv) == 4 and argv[:3] == ["machine", "run", "--request"]:
            if not runtime_execution_supported():
                print(
                    "ask-herdr machine run failed: runtime.platform_unsupported",
                    file=sys.stderr,
                )
                return 20
            outcome, diagnostic_code, exit_class = run_query_status_source(argv[3])
            if outcome is not None:
                emit_json(outcome)
                return exit_class
            print(f"ask-herdr machine run failed: {diagnostic_code}", file=sys.stderr)
            return exit_class
        usage = (
            "usage: ask-herdr machine describe --json | "
            "ask-herdr machine schema --id EXACT_ID | "
            "ask-herdr machine validate --request ABSOLUTE_FILE_OR_-"
        )
        if active:
            usage += " | ask-herdr machine run --request ABSOLUTE_FILE_OR_-"
        print(
            usage,
            file=sys.stderr,
        )
        return 64
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(f"ask-herdr contract discovery failed: {error}", file=sys.stderr)
        return 30


def console_main() -> int:
    """Run the installed console command with the process argument vector."""

    return main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(console_main())
