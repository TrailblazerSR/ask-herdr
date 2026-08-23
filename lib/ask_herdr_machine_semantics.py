"""Pure semantic compilation for structurally valid Machine Core requests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Dict, Mapping

from ask_herdr_json import canonical_json


class SemanticValidationError(ValueError):
    """A stable, content-redacted cross-field semantic rejection."""

    def __init__(self, code: str, field_pointer: str) -> None:
        super().__init__(code)
        self.code = code
        self.field_pointer = field_pointer


@dataclass(frozen=True)
class CompiledRequestSemantics:
    """The deterministic, state-free identity projection of one request."""

    digest_projection: Dict[str, Any]
    canonical_projection_bytes: bytes
    canonical_request_digest: str


@dataclass(frozen=True)
class CandidateProjectFacts:
    """Core-resolved, non-caller-authoritative identity for project genesis."""

    canonical_root: str
    filesystem_device: int
    filesystem_inode: int
    owner_uid: int


def _reject_unless(condition: bool, code: str, field_pointer: str) -> None:
    if not condition:
        raise SemanticValidationError(code, field_pointer)


def _validate_project_init_common_semantics(request: Mapping[str, Any]) -> None:
    project = request["project"]
    reason = request["reason"]
    observation = request["observation"]

    _reject_unless(
        request["operation"] == "project.init",
        "semantic.operation_mismatch",
        "/operation",
    )
    _reject_unless(
        project["binding"] == "candidate",
        "semantic.project_binding_not_candidate",
        "/project/binding",
    )
    _reject_unless(
        project["authority_id"] is None,
        "semantic.candidate_authority_id_not_null",
        "/project/authority_id",
    )
    _reject_unless(
        request["authority_ref"] is None,
        "semantic.bootstrap_authority_ref_not_null",
        "/authority_ref",
    )
    _reject_unless(
        reason["action"] == "project_admin",
        "semantic.action_reason_mismatch",
        "/reason/action",
    )
    _reject_unless(
        "lane_origin" not in reason,
        "semantic.lane_origin_forbidden",
        "/reason/lane_origin",
    )
    _reject_unless(
        observation["mode"] == "immediate",
        "semantic.observation_mode_mismatch",
        "/observation/mode",
    )
    _reject_unless(
        observation["timeout_ms"] is None,
        "semantic.observation_timeout_not_null",
        "/observation/timeout_ms",
    )


def compile_project_init_request(
    request: Mapping[str, Any],
    project_facts: CandidateProjectFacts,
) -> CompiledRequestSemantics:
    """Compile one structurally valid ``project.init`` request without I/O."""

    _validate_project_init_common_semantics(request)
    project = request["project"]
    _reject_unless(
        project["root"] == project_facts.canonical_root,
        "semantic.project_root_mismatch",
        "/project/root",
    )
    payload = request["payload"]
    payload_projection = {"lifetime": payload["lifetime"]}
    if payload["lifetime"] == "after_tombstone":
        payload_projection.update(
            predecessor_tombstone_id=payload["predecessor_tombstone_id"],
            predecessor_tombstone_digest=payload[
                "predecessor_tombstone_digest"
            ],
        )
    projection = {
        "schema": "ask_herdr.canonical_request_projection.v1",
        "operation": "project.init",
        "project": {
            "binding": "candidate",
            "root": project_facts.canonical_root,
            "filesystem_identity": {
                "device": project_facts.filesystem_device,
                "inode": project_facts.filesystem_inode,
                "owner_uid": project_facts.owner_uid,
            },
        },
        "payload": payload_projection,
    }
    canonical_bytes = canonical_json(projection)
    digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    return CompiledRequestSemantics(
        digest_projection=projection,
        canonical_projection_bytes=canonical_bytes,
        canonical_request_digest=digest,
    )
