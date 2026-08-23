"""Transport-neutral immutable topology proof contract."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
from typing import Any, Mapping, Tuple

from ask_herdr_json import canonical_json


@dataclass(frozen=True)
class SessionBinding:
    name: str
    default: bool
    session_dir: str
    socket_path: str
    generation_id: str


@dataclass(frozen=True)
class WorkspaceProof:
    workspace_id: str
    tab_id: str
    pane_id: str
    label: str
    cwd: str
    creation_receipt_digest: str


@dataclass(frozen=True)
class LaneTopologyProof:
    project_id: str
    lane_id: str
    consultant_key: str
    project_root: str
    topology_nonce: str
    workspace: WorkspaceProof


@dataclass(frozen=True)
class TopologySideEffectProof:
    project_id: str
    project_root: str
    workspace_id: str
    tab_id: str
    pane_id: str
    label: str
    cwd: str
    creation_receipt_digest: str


@dataclass(frozen=True)
class ProjectTopologyProof:
    project_id: str
    project_root: str
    namespace: str
    topology_epoch_id: str
    session_binding: SessionBinding
    lanes: Tuple[LaneTopologyProof, ...]
    side_effects: Tuple[TopologySideEffectProof, ...]


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in fields(value)
        }
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is list:
        return [_json_value(item) for item in value]
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    if value is None or type(value) in {str, int, bool}:
        return value
    raise ValueError("topology_contract.value_not_canonical")


def project_topology_payload(project: ProjectTopologyProof) -> Mapping[str, Any]:
    if not isinstance(project, ProjectTopologyProof):
        raise ValueError("topology_contract.project_proof_invalid")
    lanes = tuple(sorted(project.lanes, key=lambda item: item.lane_id))
    side_effects = tuple(
        sorted(project.side_effects, key=lambda item: item.workspace_id)
    )
    return {
        "schema": "ask_herdr.project_topology_proof.v1",
        "project_id": project.project_id,
        "project_root": project.project_root,
        "namespace": project.namespace,
        "topology_epoch_id": project.topology_epoch_id,
        "session_binding": _json_value(project.session_binding),
        "lanes": _json_value(lanes),
        "side_effects": _json_value(side_effects),
    }


def project_topology_digest(project: ProjectTopologyProof) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(project_topology_payload(project))
    ).hexdigest()


def project_topology_from_payload(payload: Mapping[str, Any]) -> ProjectTopologyProof:
    if type(payload) is not dict or set(payload) != {
        "schema",
        "project_id",
        "project_root",
        "namespace",
        "topology_epoch_id",
        "session_binding",
        "lanes",
        "side_effects",
    } or payload.get("schema") != "ask_herdr.project_topology_proof.v1":
        raise ValueError("topology_contract.project_proof_invalid")
    session = payload["session_binding"]
    lanes = payload["lanes"]
    side_effects = payload["side_effects"]
    if type(session) is not dict or type(lanes) is not list or type(side_effects) is not list:
        raise ValueError("topology_contract.project_proof_invalid")
    try:
        session_proof = SessionBinding(**session)
        lane_proofs = tuple(
            LaneTopologyProof(
                **{
                    **item,
                    "workspace": WorkspaceProof(**item["workspace"]),
                }
            )
            for item in lanes
        )
        side_effect_proofs = tuple(
            TopologySideEffectProof(**item) for item in side_effects
        )
        project = ProjectTopologyProof(
            project_id=payload["project_id"],
            project_root=payload["project_root"],
            namespace=payload["namespace"],
            topology_epoch_id=payload["topology_epoch_id"],
            session_binding=session_proof,
            lanes=lane_proofs,
            side_effects=side_effect_proofs,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("topology_contract.project_proof_invalid") from error
    if project_topology_payload(project) != payload:
        raise ValueError("topology_contract.project_proof_invalid")
    return project


def topology_resource_fingerprint(resource: object) -> Tuple[str, ...]:
    try:
        values = (
            getattr(resource, "workspace_id"),
            getattr(resource, "tab_id"),
            getattr(resource, "pane_id"),
            getattr(resource, "label"),
            getattr(resource, "cwd"),
        )
    except AttributeError as error:
        raise ValueError("topology_contract.resource_invalid") from error
    if any(type(value) is not str or not value for value in values):
        raise ValueError("topology_contract.resource_invalid")
    return values


def topology_resource_binding_digest(resource: object) -> str:
    workspace_id, tab_id, pane_id, label, cwd = topology_resource_fingerprint(
        resource
    )
    payload = {
        "schema": "ask_herdr.topology_resource_binding.v1",
        "workspace_id": workspace_id,
        "tab_id": tab_id,
        "pane_id": pane_id,
        "label": label,
        "cwd": cwd,
    }
    return "sha256:" + hashlib.sha256(canonical_json(payload)).hexdigest()


__all__ = [
    "LaneTopologyProof",
    "ProjectTopologyProof",
    "SessionBinding",
    "TopologySideEffectProof",
    "WorkspaceProof",
    "project_topology_digest",
    "project_topology_from_payload",
    "project_topology_payload",
    "topology_resource_fingerprint",
    "topology_resource_binding_digest",
]
