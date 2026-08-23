"""Private, provider-free Project Read Epoch acquisition.

The module composes existing observation-only store-head interfaces. It does
not repair storage, retain a lock while rendering, resolve results or evidence,
or activate a public query surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Callable, Optional, Tuple

from ask_herdr_authority_store import (
    AuthorityStatusOperationEntry,
    _authority_status_operation_entries_from_head,
    inspect_authority_store_head,
)
from ask_herdr_json import StrictJsonError, canonical_json
from ask_herdr_lane_index import LaneIndexEntry, inspect_lane_index
from ask_herdr_project_mutation_lease import (
    ValidatedProjectMutationBinding,
)
from ask_herdr_topology_store import (
    TopologyStatusKeyEntry,
    TopologyStatusOperationEntry,
    _topology_status_operation_entries_from_projection,
    inspect_topology_status_projection,
)


_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_MAXIMUM_COMPLETE_ATTEMPTS = 3


@dataclass(frozen=True)
class ProjectReadEpoch:
    """One immutable, path-free, mutually consistent project read identity."""

    schema: str
    project_authority_id: str
    authority_store_head_digest: str
    project_state_digest: str
    lane_index_digest: str
    topology_ledger_head_digest: str
    observed_at: str
    acquisition_attempt: int
    epoch_digest: str


@dataclass(frozen=True)
class ProjectReadEpochInspection:
    """Closed acquisition result with an epoch only when identity is complete."""

    status: str
    detail_code: str
    epoch: Optional[ProjectReadEpoch] = None


@dataclass(frozen=True)
class _ProjectReadEpochSnapshot:
    inspection: ProjectReadEpochInspection
    lane_entries: Tuple[LaneIndexEntry, ...] = ()
    topology_key_entries: Tuple[TopologyStatusKeyEntry, ...] = ()
    authority_operation_entries: Tuple[AuthorityStatusOperationEntry, ...] = ()
    topology_operation_entries: Tuple[TopologyStatusOperationEntry, ...] = ()


@dataclass(frozen=True)
class _HeadObservation:
    authority_status: str
    authority_detail: str
    authority_digest: Optional[str]
    lane_status: str
    lane_detail: str
    lane_digest: Optional[str]
    lane_entries: Tuple[LaneIndexEntry, ...]
    topology_status: str
    topology_detail: str
    topology_digest: Optional[str]
    topology_key_entries: Tuple[TopologyStatusKeyEntry, ...]
    authority_operation_entries: Tuple[AuthorityStatusOperationEntry, ...] = ()
    topology_operation_entries: Tuple[TopologyStatusOperationEntry, ...] = ()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _snapshot_binding(
    value: object,
) -> Optional[ValidatedProjectMutationBinding]:
    if type(value) is not ValidatedProjectMutationBinding:
        return None
    try:
        fields = vars(value)
        if set(fields) != {
            "canonical_root",
            "filesystem_device",
            "filesystem_inode",
            "owner_uid",
            "project_authority_id",
        }:
            return None
        return ValidatedProjectMutationBinding(
            canonical_root=fields["canonical_root"],
            filesystem_device=fields["filesystem_device"],
            filesystem_inode=fields["filesystem_inode"],
            owner_uid=fields["owner_uid"],
            project_authority_id=fields["project_authority_id"],
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _project_state_digest(binding: ValidatedProjectMutationBinding) -> str:
    return _digest(
        {
            "schema": "ask_herdr.project_state.identity.v1",
            "canonical_root": binding.canonical_root,
            "filesystem_device": binding.filesystem_device,
            "filesystem_inode": binding.filesystem_inode,
            "owner_uid": binding.owner_uid,
            "project_authority_id": binding.project_authority_id,
        }
    )


def _observe(binding: ValidatedProjectMutationBinding) -> _HeadObservation:
    authority = inspect_authority_store_head(binding)
    lane_index = inspect_lane_index(binding)
    topology = inspect_topology_status_projection(binding)
    authority_operation_entries = getattr(
        authority,
        "operation_entries",
        _authority_status_operation_entries_from_head(authority),
    )
    topology_operation_entries = getattr(
        topology,
        "operation_entries",
        _topology_status_operation_entries_from_projection(topology),
    )
    return _HeadObservation(
        authority.status,
        authority.detail_code,
        authority.authority_store_head_digest,
        lane_index.status,
        lane_index.detail_code,
        lane_index.lane_index_digest,
        tuple(lane_index.entries),
        topology.status,
        topology.detail_code,
        topology.topology_ledger_head_digest,
        tuple(topology.key_entries),
        tuple(authority_operation_entries),
        tuple(topology_operation_entries),
    )


def _parts(
    observation: _HeadObservation,
) -> Tuple[Tuple[str, str, Optional[str]], ...]:
    return (
        (
            observation.authority_status,
            observation.authority_detail,
            observation.authority_digest,
        ),
        (
            observation.lane_status,
            observation.lane_detail,
            observation.lane_digest,
        ),
        (
            observation.topology_status,
            observation.topology_detail,
            observation.topology_digest,
        ),
    )


def _writer_busy(observation: _HeadObservation) -> bool:
    return any(
        status == "busy" or detail.endswith(".writer_active")
        for status, detail, _digest_value in _parts(observation)
    )


def _stable_status(
    observation: _HeadObservation,
) -> Tuple[str, str]:
    parts = _parts(observation)
    allowed = {
        "active",
        "absent",
        "busy",
        "quarantined",
        "reconciliation_required",
    }
    if any(status not in allowed for status, _detail, _digest_value in parts):
        return "quarantined", "project_read_epoch.head_status_invalid"
    for selected in ("quarantined", "reconciliation_required", "absent"):
        for status, detail, _digest_value in parts:
            if status == selected:
                return selected, detail
    if all(status == "active" for status, _detail, _digest_value in parts):
        return "active", "project_read_epoch.active"
    return "quarantined", "project_read_epoch.head_status_invalid"


def _canonical_timestamp(value: object) -> Optional[str]:
    if type(value) is not datetime or value.tzinfo is None:
        return None
    try:
        return value.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _epoch(
    binding: ValidatedProjectMutationBinding,
    observation: _HeadObservation,
    *,
    observed_at: str,
    acquisition_attempt: int,
) -> ProjectReadEpoch:
    assert observation.authority_digest is not None
    assert observation.lane_digest is not None
    assert observation.topology_digest is not None
    project_state_digest = _project_state_digest(binding)
    identity = {
        "schema": "ask_herdr.project_read_epoch.identity.v1",
        "project_authority_id": binding.project_authority_id,
        "authority_store_head_digest": observation.authority_digest,
        "project_state_digest": project_state_digest,
        "lane_index_digest": observation.lane_digest,
        "topology_ledger_head_digest": observation.topology_digest,
    }
    return ProjectReadEpoch(
        schema="ask_herdr.project_read_epoch.v1",
        project_authority_id=binding.project_authority_id,
        authority_store_head_digest=observation.authority_digest,
        project_state_digest=project_state_digest,
        lane_index_digest=observation.lane_digest,
        topology_ledger_head_digest=observation.topology_digest,
        observed_at=observed_at,
        acquisition_attempt=acquisition_attempt,
        epoch_digest=_digest(identity),
    )


def acquire_project_read_epoch(
    binding: ValidatedProjectMutationBinding,
    *,
    clock: Callable[[], datetime],
) -> ProjectReadEpochInspection:
    """Acquire one stable complete head tuple within three full attempts."""

    return _acquire_project_read_epoch_snapshot(
        binding,
        clock=clock,
    ).inspection


def _acquire_project_read_epoch_snapshot(
    binding: ValidatedProjectMutationBinding,
    *,
    clock: Callable[[], datetime],
) -> _ProjectReadEpochSnapshot:
    """Acquire the epoch and its exact authenticated status projections."""

    snapshot = _snapshot_binding(binding)
    if snapshot is None:
        return _ProjectReadEpochSnapshot(
            ProjectReadEpochInspection(
                "quarantined",
                "project_read_epoch.binding_invalid",
            )
        )
    if not callable(clock):
        return _ProjectReadEpochSnapshot(
            ProjectReadEpochInspection(
                "reconciliation_required",
                "project_read_epoch.clock_unavailable",
            )
        )
    try:
        for attempt in range(1, _MAXIMUM_COMPLETE_ATTEMPTS + 1):
            first = _observe(snapshot)
            second = _observe(snapshot)
            if _writer_busy(first) or _writer_busy(second) or first != second:
                continue
            status, detail_code = _stable_status(second)
            digests = (
                second.authority_digest,
                second.lane_digest,
                second.topology_digest,
            )
            if status in {"active", "reconciliation_required"} and all(
                type(value) is str
                and _DIGEST_PATTERN.fullmatch(value) is not None
                for value in digests
            ):
                try:
                    observed_at = _canonical_timestamp(clock())
                except Exception:
                    observed_at = None
                if observed_at is None:
                    return _ProjectReadEpochSnapshot(
                        ProjectReadEpochInspection(
                            "reconciliation_required",
                            "project_read_epoch.clock_unavailable",
                        )
                    )
                return _ProjectReadEpochSnapshot(
                    ProjectReadEpochInspection(
                        status,
                        detail_code,
                        _epoch(
                            snapshot,
                            second,
                            observed_at=observed_at,
                            acquisition_attempt=attempt,
                        ),
                    ),
                    second.lane_entries,
                    second.topology_key_entries,
                    second.authority_operation_entries,
                    second.topology_operation_entries,
                )
            if status == "active":
                return _ProjectReadEpochSnapshot(
                    ProjectReadEpochInspection(
                        "quarantined",
                        "project_read_epoch.head_digest_invalid",
                    )
                )
            return _ProjectReadEpochSnapshot(
                ProjectReadEpochInspection(status, detail_code)
            )
    except StrictJsonError:
        return _ProjectReadEpochSnapshot(
            ProjectReadEpochInspection(
                "quarantined",
                "project_read_epoch.project_state_invalid",
            )
        )
    return _ProjectReadEpochSnapshot(
        ProjectReadEpochInspection(
            "busy",
            "project_read_epoch.head_drift",
        )
    )


__all__ = (
    "ProjectReadEpoch",
    "ProjectReadEpochInspection",
    "acquire_project_read_epoch",
)
