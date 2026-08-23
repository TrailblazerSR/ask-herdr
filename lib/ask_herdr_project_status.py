"""Private, provider-free metadata-only project status.

The module renders authenticated Lane Index heads from the same stable Project
Read Epoch acquisition. It does not observe Herdr, resolve result content,
consume Evidence Content Access, or activate a public query route.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
from typing import Callable, Dict, Optional, Tuple

from ask_herdr_control_payloads import CONSULTANT_KEY_PATTERN
from ask_herdr_json import StrictJsonError, canonical_json, parse_json_object
from ask_herdr_lane_index import LaneIndexEntry
from ask_herdr_project_mutation_lease import (
    UUID4_PATTERN,
    ValidatedProjectMutationBinding,
)
from ask_herdr_project_read_epoch import (
    ProjectReadEpoch,
    _ProjectReadEpochSnapshot,
    _acquire_project_read_epoch_snapshot,
)


_CURSOR_PREFIX = "mcv1."
_CURSOR_SCHEMA = "ask_herdr.metadata_cursor.v1"
_CURSOR_IDENTITY_SCHEMA = "ask_herdr.metadata_cursor.identity.v1"
_ORDERING_SCHEMA = "ask_herdr.query.status.ordering.identity.v1"
_LANE_IDENTITY_SCHEMA = "ask_herdr.query.status.lane_identity.v1"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_CONSULTANT_KEY_PATTERN = re.compile(CONSULTANT_KEY_PATTERN)
_MAXIMUM_CURSOR_BYTES = 1024


@dataclass(frozen=True)
class ProjectStatusLaneHead:
    """One path-free authenticated Lane head in the project page."""

    lane_id: str
    lane_generation: int
    lane_binding_digest: str
    event_sequence: int
    event_digest: str
    state_digest: str
    response_digest: Optional[str]


@dataclass(frozen=True)
class ProjectStatusOperationMetadata:
    """Path-free authenticated metadata for one durable operation identity."""

    operation_id: str
    operation: str
    canonical_request_digest: str
    authority_record_digest: str
    lane_association: str


@dataclass(frozen=True)
class ProjectStatusInspection:
    """Closed metadata-only project status result."""

    status: str
    detail_code: str
    normalized_read_contract_digest: Optional[str] = None
    project_read_epoch: Optional[ProjectReadEpoch] = None
    entries: Tuple[ProjectStatusLaneHead, ...] = ()
    next_cursor: Optional[str] = None
    operation_metadata: Optional[ProjectStatusOperationMetadata] = None


@dataclass(frozen=True)
class _StatusSelectorPlan:
    kind: str
    value: Optional[str]
    active_detail: str
    absent_detail: Optional[str]

    def identity(self) -> Dict[str, object]:
        selector: Dict[str, object] = {
            "schema": "ask_herdr.query.status.selector.v1",
            "kind": self.kind,
        }
        if self.kind == "project" and self.value is None:
            return selector
        if self.kind == "lane" and self.value is not None:
            selector["lane_id"] = self.value
            return selector
        if self.kind == "key" and self.value is not None:
            selector["consultant_key"] = self.value
            return selector
        if self.kind == "operation" and self.value is not None:
            selector["operation_id"] = self.value
            return selector
        raise StrictJsonError("query_status.selector_plan_invalid")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _read_contract_digest(
    *,
    selector: Dict[str, object],
    limit: int,
) -> str:
    return _digest(
        {
            "schema": "ask_herdr.query.status.read_contract.identity.v1",
            "selector": selector,
            "advisory": "none",
            "limit": limit,
        }
    )


def _ordering_digest() -> str:
    return _digest(
        {
            "schema": _ORDERING_SCHEMA,
            "order": [
                {"field": "lane_id", "direction": "ascending"},
                {
                    "field": "lane_generation",
                    "direction": "ascending",
                },
            ],
        }
    )


def _lane_identity_digest(entry: LaneIndexEntry) -> str:
    return _digest(
        {
            "schema": _LANE_IDENTITY_SCHEMA,
            "lane_id": entry.lane_id,
            "lane_generation": entry.lane_generation,
            "lane_binding_digest": entry.lane_binding_digest,
        }
    )


def _cursor_identity(payload: Dict[str, object]) -> Dict[str, object]:
    return {
        "schema": _CURSOR_IDENTITY_SCHEMA,
        "project_read_epoch_digest": payload[
            "project_read_epoch_digest"
        ],
        "normalized_read_contract_digest": payload[
            "normalized_read_contract_digest"
        ],
        "ordering_digest": payload["ordering_digest"],
        "last_identity_digest": payload["last_identity_digest"],
    }


def _encode_cursor(
    *,
    epoch_digest: str,
    read_contract_digest: str,
    last_identity_digest: str,
) -> str:
    payload: Dict[str, object] = {
        "schema": _CURSOR_SCHEMA,
        "project_read_epoch_digest": epoch_digest,
        "normalized_read_contract_digest": read_contract_digest,
        "ordering_digest": _ordering_digest(),
        "last_identity_digest": last_identity_digest,
    }
    payload["cursor_binding_digest"] = _digest(_cursor_identity(payload))
    encoded = base64.urlsafe_b64encode(canonical_json(payload)).decode(
        "ascii"
    ).rstrip("=")
    cursor = _CURSOR_PREFIX + encoded
    if len(cursor.encode("ascii")) > _MAXIMUM_CURSOR_BYTES:
        raise StrictJsonError("query_status.cursor_too_large")
    return cursor


def _decode_cursor(
    value: object,
    *,
    read_contract_digest: str,
) -> Optional[Dict[str, object]]:
    if type(value) is not str or not value.startswith(_CURSOR_PREFIX):
        return None
    try:
        cursor_size = len(value.encode("utf-8"))
    except UnicodeError:
        return None
    if not 0 < cursor_size <= _MAXIMUM_CURSOR_BYTES:
        return None
    encoded = value[len(_CURSOR_PREFIX) :]
    if not encoded or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        return None
    try:
        padding = "=" * ((4 - len(encoded) % 4) % 4)
        raw = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
        if (
            base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
            != encoded
        ):
            return None
        payload = parse_json_object(raw)
        if canonical_json(payload) != raw:
            return None
    except (UnicodeError, binascii.Error, StrictJsonError, ValueError):
        return None
    expected_fields = {
        "schema",
        "project_read_epoch_digest",
        "normalized_read_contract_digest",
        "ordering_digest",
        "last_identity_digest",
        "cursor_binding_digest",
    }
    if set(payload) != expected_fields or payload.get("schema") != _CURSOR_SCHEMA:
        return None
    digest_fields = expected_fields - {"schema"}
    if any(
        type(payload.get(field)) is not str
        or _DIGEST_PATTERN.fullmatch(payload[field]) is None
        for field in digest_fields
    ):
        return None
    if (
        payload["normalized_read_contract_digest"] != read_contract_digest
        or payload["ordering_digest"] != _ordering_digest()
        or payload["cursor_binding_digest"]
        != _digest(_cursor_identity(payload))
    ):
        return None
    return payload


def _lane_head(entry: LaneIndexEntry) -> ProjectStatusLaneHead:
    return ProjectStatusLaneHead(
        lane_id=entry.lane_id,
        lane_generation=entry.lane_generation,
        lane_binding_digest=entry.lane_binding_digest,
        event_sequence=entry.event_sequence,
        event_digest=entry.event_digest,
        state_digest=entry.state_digest,
        response_digest=entry.response_digest,
    )


def _select_entries(
    plan: _StatusSelectorPlan,
    snapshot: _ProjectReadEpochSnapshot,
) -> Optional[Tuple[LaneIndexEntry, ...]]:
    project_entries = tuple(
        sorted(
            snapshot.lane_entries,
            key=lambda entry: (entry.lane_id, entry.lane_generation),
        )
    )
    if plan.kind == "project":
        return project_entries
    if plan.kind == "lane":
        return tuple(
            entry
            for entry in project_entries
            if entry.lane_id == plan.value
        )
    if plan.kind != "key":
        return None

    lanes = {
        (entry.lane_id, entry.lane_generation): entry
        for entry in project_entries
    }
    mappings = {
        (entry.lane_id, entry.lane_generation): entry
        for entry in snapshot.topology_key_entries
    }
    if (
        len(lanes) != len(project_entries)
        or len(mappings) != len(snapshot.topology_key_entries)
        or any(
            identity in lanes
            and lanes[identity].lane_binding_digest
            != mapping.lane_binding_digest
            for identity, mapping in mappings.items()
        )
    ):
        return None
    if snapshot.inspection.status == "active" and set(lanes) != set(mappings):
        return None
    selected = tuple(
        lanes[identity]
        for identity, mapping in sorted(mappings.items())
        if mapping.consultant_key == plan.value and identity in lanes
    )
    return selected


_HUMAN_OPERATION_NAMES = frozenset(
    {"turn.answer", "turn.consult", "turn.review"}
)
_NON_LANE_OPERATION_NAMES = frozenset({"project.init", "query.evidence"})


def _operation_value(value: object, field: str) -> object:
    return getattr(value, field, None)


def _valid_authority_operation_entry(value: object) -> bool:
    operation_id = _operation_value(value, "operation_id")
    operation = _operation_value(value, "operation")
    request_digest = _operation_value(value, "canonical_request_digest")
    authority_digest = _operation_value(value, "authority_record_digest")
    lane_scope = _operation_value(value, "lane_scope")
    lane_id = _operation_value(value, "lane_id")
    lane_generation = _operation_value(value, "lane_generation")
    if (
        type(operation_id) is not str
        or UUID4_PATTERN.fullmatch(operation_id) is None
        or type(operation) is not str
        or type(request_digest) is not str
        or _DIGEST_PATTERN.fullmatch(request_digest) is None
        or type(authority_digest) is not str
        or _DIGEST_PATTERN.fullmatch(authority_digest) is None
    ):
        return False
    if operation in _NON_LANE_OPERATION_NAMES:
        return (
            lane_scope == "not_applicable"
            and lane_id is None
            and lane_generation is None
        )
    if operation in _HUMAN_OPERATION_NAMES:
        return (
            lane_scope == "required"
            and lane_id is None
            and lane_generation is None
        )
    return (
        operation == "recovery.reconcile"
        and lane_scope == "required"
        and type(lane_id) is str
        and UUID4_PATTERN.fullmatch(lane_id) is not None
        and type(lane_generation) is int
        and lane_generation >= 1
    )


def _valid_topology_operation_entry(value: object) -> bool:
    operation_id = _operation_value(value, "operation_id")
    request_digest = _operation_value(value, "canonical_request_digest")
    policy_digest = _operation_value(value, "policy_record_digest")
    lane_id = _operation_value(value, "lane_id")
    lane_generation = _operation_value(value, "lane_generation")
    lane_binding_digest = _operation_value(value, "lane_binding_digest")
    return (
        type(operation_id) is str
        and UUID4_PATTERN.fullmatch(operation_id) is not None
        and type(request_digest) is str
        and _DIGEST_PATTERN.fullmatch(request_digest) is not None
        and type(policy_digest) is str
        and _DIGEST_PATTERN.fullmatch(policy_digest) is not None
        and type(lane_id) is str
        and UUID4_PATTERN.fullmatch(lane_id) is not None
        and type(lane_generation) is int
        and lane_generation >= 1
        and type(lane_binding_digest) is str
        and _DIGEST_PATTERN.fullmatch(lane_binding_digest) is not None
    )


def _operation_snapshot_maps(
    snapshot: _ProjectReadEpochSnapshot,
) -> Optional[
    Tuple[
        Dict[str, object],
        Dict[str, object],
        Dict[Tuple[str, int], LaneIndexEntry],
    ]
]:
    """Validate the closed retained operation universe and its joins."""

    authority_entries = getattr(snapshot, "authority_operation_entries", None)
    topology_entries = getattr(snapshot, "topology_operation_entries", None)
    lane_entries = getattr(snapshot, "lane_entries", None)
    if (
        type(authority_entries) is not tuple
        or type(topology_entries) is not tuple
        or type(lane_entries) is not tuple
        or any(
            not _valid_authority_operation_entry(entry)
            for entry in authority_entries
        )
        or any(
            not _valid_topology_operation_entry(entry)
            for entry in topology_entries
        )
    ):
        return None
    authority = {
        _operation_value(entry, "operation_id"): entry
        for entry in authority_entries
    }
    topology = {
        _operation_value(entry, "operation_id"): entry
        for entry in topology_entries
    }
    lanes = {
        (entry.lane_id, entry.lane_generation): entry
        for entry in lane_entries
    }
    if (
        len(authority) != len(authority_entries)
        or len(topology) != len(topology_entries)
        or len(lanes) != len(lane_entries)
    ):
        return None
    active = snapshot.inspection.status == "active"
    for operation_id, mapping in topology.items():
        lane = lanes.get(
            (
                _operation_value(mapping, "lane_id"),
                _operation_value(mapping, "lane_generation"),
            )
        )
        if lane is not None and (
            lane.lane_binding_digest
            != _operation_value(mapping, "lane_binding_digest")
        ):
            return None
        authority_entry = authority.get(operation_id)
        if authority_entry is None:
            if active:
                return None
            continue
        if (
            _operation_value(mapping, "canonical_request_digest")
            != _operation_value(authority_entry, "canonical_request_digest")
            or _operation_value(mapping, "policy_record_digest")
            != _operation_value(authority_entry, "authority_record_digest")
        ):
            return None
        if _operation_value(authority_entry, "operation") == "recovery.reconcile" and (
            _operation_value(mapping, "lane_id")
            != _operation_value(authority_entry, "lane_id")
            or _operation_value(mapping, "lane_generation")
            != _operation_value(authority_entry, "lane_generation")
        ):
            return None
        lane_scope = _operation_value(authority_entry, "lane_scope")
        if lane_scope == "not_applicable":
            if active:
                return None
            continue
        if active and lane is None:
            return None
    return authority, topology, lanes


def _operation_selection(
    snapshot: _ProjectReadEpochSnapshot,
    operation_id: str,
) -> Optional[
    Tuple[
        Optional[ProjectStatusOperationMetadata],
        Tuple[ProjectStatusLaneHead, ...],
    ]
]:
    """Return exactly zero or one authenticated operation metadata result."""

    maps = _operation_snapshot_maps(snapshot)
    if maps is None:
        return None
    authority, topology, lanes = maps
    selected = authority.get(operation_id)
    if selected is None:
        return None, ()
    operation = _operation_value(selected, "operation")
    lane_scope = _operation_value(selected, "lane_scope")
    association = "not_applicable"
    lane: Optional[LaneIndexEntry] = None
    if lane_scope == "required":
        mapping = topology.get(operation_id)
        if operation == "recovery.reconcile":
            lane = lanes.get(
                (
                    _operation_value(selected, "lane_id"),
                    _operation_value(selected, "lane_generation"),
                )
            )
        elif mapping is not None:
            lane = lanes.get(
                (
                    _operation_value(mapping, "lane_id"),
                    _operation_value(mapping, "lane_generation"),
                )
            )
        if lane is None:
            if snapshot.inspection.status == "active" and operation == "recovery.reconcile":
                return None
            if snapshot.inspection.status == "active" and mapping is not None:
                return None
            association = "unresolved"
        else:
            association = "bound"
    metadata = ProjectStatusOperationMetadata(
        operation_id=operation_id,
        operation=operation,
        canonical_request_digest=_operation_value(
            selected,
            "canonical_request_digest",
        ),
        authority_record_digest=_operation_value(
            selected,
            "authority_record_digest",
        ),
        lane_association=association,
    )
    return metadata, ((_lane_head(lane),) if lane is not None else ())


def _read_status(
    binding: ValidatedProjectMutationBinding,
    *,
    plan: _StatusSelectorPlan,
    limit: int,
    cursor: Optional[str],
    clock: Callable[[], datetime],
) -> ProjectStatusInspection:
    if type(limit) is not int or not 1 <= limit <= 200:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    try:
        selector = plan.identity()
        read_contract_digest = _read_contract_digest(
            selector=selector,
            limit=limit,
        )
    except StrictJsonError:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    decoded_cursor = None
    if cursor is not None:
        decoded_cursor = _decode_cursor(
            cursor,
            read_contract_digest=read_contract_digest,
        )
    if cursor is not None and decoded_cursor is None:
        return ProjectStatusInspection(
            "cursor_stale",
            "query_status.cursor_stale",
            read_contract_digest,
        )

    snapshot = _acquire_project_read_epoch_snapshot(binding, clock=clock)
    epoch_inspection = snapshot.inspection
    if epoch_inspection.epoch is None:
        return ProjectStatusInspection(
            epoch_inspection.status,
            epoch_inspection.detail_code,
            read_contract_digest,
        )
    ordered = _select_entries(plan, snapshot)
    if ordered is None:
        return ProjectStatusInspection(
            "quarantined",
            (
                "query_status.key_mapping_invalid"
                if plan.kind == "key"
                else "query_status.read_contract_invalid"
            ),
            read_contract_digest,
        )
    start = 0
    if decoded_cursor is not None:
        if (
            decoded_cursor["project_read_epoch_digest"]
            != epoch_inspection.epoch.epoch_digest
        ):
            return ProjectStatusInspection(
                "cursor_stale",
                "query_status.cursor_stale",
                read_contract_digest,
            )
        positions = tuple(
            index
            for index, entry in enumerate(ordered)
            if _lane_identity_digest(entry)
            == decoded_cursor["last_identity_digest"]
        )
        if len(positions) != 1:
            return ProjectStatusInspection(
                "cursor_stale",
                "query_status.cursor_stale",
                read_contract_digest,
            )
        start = positions[0] + 1
    page_source = ordered[start : start + limit]
    if (
        decoded_cursor is not None
        and not page_source
        and epoch_inspection.status == "active"
        and plan.kind in {"lane", "key"}
    ):
        return ProjectStatusInspection(
            "cursor_stale",
            "query_status.cursor_stale",
            read_contract_digest,
        )
    entries = tuple(_lane_head(entry) for entry in page_source)
    next_cursor = None
    if start + len(page_source) < len(ordered):
        next_cursor = _encode_cursor(
            epoch_digest=epoch_inspection.epoch.epoch_digest,
            read_contract_digest=read_contract_digest,
            last_identity_digest=_lane_identity_digest(page_source[-1]),
        )
    if (
        plan.absent_detail is not None
        and epoch_inspection.status == "active"
        and not ordered
    ):
        return ProjectStatusInspection(
            "absent",
            plan.absent_detail,
            read_contract_digest,
            epoch_inspection.epoch,
        )
    if epoch_inspection.status not in {"active", "reconciliation_required"}:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.epoch_status_invalid",
            read_contract_digest,
        )
    return ProjectStatusInspection(
        epoch_inspection.status,
        (
            plan.active_detail
            if epoch_inspection.status == "active"
            else epoch_inspection.detail_code
        ),
        read_contract_digest,
        epoch_inspection.epoch,
        entries,
        next_cursor,
    )


def read_project_status(
    binding: ValidatedProjectMutationBinding,
    *,
    limit: int,
    cursor: Optional[str],
    clock: Callable[[], datetime],
) -> ProjectStatusInspection:
    """Read one stable project page with no advisory provider observation."""

    return _read_status(
        binding,
        plan=_StatusSelectorPlan(
            "project",
            None,
            "query_status.active",
            None,
        ),
        limit=limit,
        cursor=cursor,
        clock=clock,
    )


def read_lane_status(
    binding: ValidatedProjectMutationBinding,
    *,
    lane_id: str,
    limit: int,
    cursor: Optional[str],
    clock: Callable[[], datetime],
) -> ProjectStatusInspection:
    """Read matching Lane generations without advisory provider observation."""

    if type(lane_id) is not str or UUID4_PATTERN.fullmatch(lane_id) is None:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    return _read_status(
        binding,
        plan=_StatusSelectorPlan(
            "lane",
            lane_id,
            "query_status.lane_active",
            "query_status.lane_absent",
        ),
        limit=limit,
        cursor=cursor,
        clock=clock,
    )


def read_key_status(
    binding: ValidatedProjectMutationBinding,
    *,
    consultant_key: str,
    limit: int,
    cursor: Optional[str],
    clock: Callable[[], datetime],
) -> ProjectStatusInspection:
    """Read matching key generations without advisory provider observation."""

    if (
        type(consultant_key) is not str
        or _CONSULTANT_KEY_PATTERN.fullmatch(consultant_key) is None
    ):
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    return _read_status(
        binding,
        plan=_StatusSelectorPlan(
            "key",
            consultant_key,
            "query_status.key_active",
            "query_status.key_absent",
        ),
        limit=limit,
        cursor=cursor,
        clock=clock,
    )


def read_operation_status(
    binding: ValidatedProjectMutationBinding,
    *,
    operation_id: str,
    limit: int,
    cursor: Optional[str],
    clock: Callable[[], datetime],
) -> ProjectStatusInspection:
    """Read one durable operation's metadata without runtime observation."""

    if (
        type(operation_id) is not str
        or UUID4_PATTERN.fullmatch(operation_id) is None
        or type(limit) is not int
        or not 1 <= limit <= 200
    ):
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    try:
        selector = _StatusSelectorPlan(
            "operation",
            operation_id,
            "query_status.operation_active",
            "query_status.operation_absent",
        ).identity()
        read_contract_digest = _read_contract_digest(
            selector=selector,
            limit=limit,
        )
    except StrictJsonError:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.read_contract_invalid",
        )
    if cursor is not None:
        return ProjectStatusInspection(
            "cursor_stale",
            "query_status.cursor_stale",
            read_contract_digest,
        )
    snapshot = _acquire_project_read_epoch_snapshot(binding, clock=clock)
    epoch_inspection = snapshot.inspection
    if epoch_inspection.epoch is None:
        return ProjectStatusInspection(
            epoch_inspection.status,
            epoch_inspection.detail_code,
            read_contract_digest,
        )
    if epoch_inspection.status not in {"active", "reconciliation_required"}:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.epoch_status_invalid",
            read_contract_digest,
        )
    selection = _operation_selection(snapshot, operation_id)
    if selection is None:
        return ProjectStatusInspection(
            "quarantined",
            "query_status.operation_mapping_invalid",
            read_contract_digest,
        )
    metadata, entries = selection
    if metadata is None:
        if epoch_inspection.status == "active":
            return ProjectStatusInspection(
                "absent",
                "query_status.operation_absent",
                read_contract_digest,
                epoch_inspection.epoch,
            )
        return ProjectStatusInspection(
            epoch_inspection.status,
            epoch_inspection.detail_code,
            read_contract_digest,
            epoch_inspection.epoch,
        )
    return ProjectStatusInspection(
        epoch_inspection.status,
        (
            "query_status.operation_active"
            if epoch_inspection.status == "active"
            else epoch_inspection.detail_code
        ),
        read_contract_digest,
        epoch_inspection.epoch,
        entries,
        None,
        metadata,
    )


__all__ = (
    "ProjectStatusLaneHead",
    "ProjectStatusOperationMetadata",
    "ProjectStatusInspection",
    "read_project_status",
    "read_lane_status",
    "read_key_status",
    "read_operation_status",
)
