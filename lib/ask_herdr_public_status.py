"""Explicit path-free public projection for the active ``query.status`` route."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Dict, Mapping, Optional

from ask_herdr_authority_store import inspect_authority_store
from ask_herdr_json import canonical_json
from ask_herdr_machine_validate import inspect_candidate_project_root
from ask_herdr_request_header import (
    TrustedHeaderError,
    trust_request_header,
)
from ask_herdr_outcome_v2_contract import OUTCOME_MAP, OUTCOME_SCHEMA_ID, RESULT_SCHEMA_ID
from ask_herdr_project_mutation_lease import ValidatedProjectMutationBinding
from ask_herdr_project_status import (
    read_key_status,
    read_lane_status,
    read_operation_status,
    read_project_status,
)
from ask_herdr_request_schema import build_request_schema
from ask_herdr_schema_validator import validate


_STATUS_OUTCOME_KINDS = {
    "active": "status_observed",
    "absent": "status_observed",
    "busy": "status_busy",
    "reconciliation_required": "status_reconciliation_required",
    "cursor_stale": "cursor_stale",
    "quarantined": "status_quarantined",
    "unavailable": "status_capability_unavailable",
}
_REQUEST_FAILURE_KINDS = frozenset(
    {
        "request_invalid",
        "request_not_currently_admissible",
        "request_reconciliation_required",
        "request_quarantined",
    }
)


class _ProjectInspectionFailure(Exception):
    def __init__(self, outcome_kind: str) -> None:
        super().__init__(outcome_kind)
        self.outcome_kind = outcome_kind


def _utc_clock() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: object) -> str:
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
    if isinstance(value, str) and value.endswith("Z") and len(value) <= 64:
        return value
    return _utc_clock().isoformat(timespec="seconds").replace("+00:00", "Z")


def _request_digest(request: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(dict(request))).hexdigest()


def _public_selector(selector: Mapping[str, Any]) -> Dict[str, Any]:
    kind = selector.get("kind")
    base = {
        "schema": "ask_herdr.query.status.selector.v1",
        "kind": kind,
    }
    if kind == "project":
        return base
    if kind == "lane":
        return {**base, "lane_id": selector.get("lane_id")}
    if kind == "key":
        return {**base, "consultant_key": selector.get("consultant_key")}
    if kind == "operation":
        return {**base, "operation_id": selector.get("operation_id")}
    raise ValueError("query_status.selector_invalid")


def _public_epoch(epoch: object) -> Optional[Dict[str, Any]]:
    if epoch is None:
        return None
    return {
        "schema": epoch.schema,
        "project_authority_id": epoch.project_authority_id,
        "authority_store_head_digest": epoch.authority_store_head_digest,
        "project_state_digest": epoch.project_state_digest,
        "lane_index_digest": epoch.lane_index_digest,
        "topology_ledger_head_digest": epoch.topology_ledger_head_digest,
        "observed_at": epoch.observed_at,
        "acquisition_attempt": epoch.acquisition_attempt,
        "epoch_digest": epoch.epoch_digest,
    }


def _public_lane_head(entry: object) -> Dict[str, Any]:
    return {
        "lane_id": entry.lane_id,
        "lane_generation": entry.lane_generation,
        "lane_binding_digest": entry.lane_binding_digest,
        "event_sequence": entry.event_sequence,
        "event_digest": entry.event_digest,
        "state_digest": entry.state_digest,
        "response_digest": entry.response_digest,
    }


def _public_operation_metadata(metadata: object) -> Optional[Dict[str, Any]]:
    if metadata is None:
        return None
    return {
        "operation_id": metadata.operation_id,
        "operation": metadata.operation,
        "canonical_request_digest": metadata.canonical_request_digest,
        "lane_association": metadata.lane_association,
    }


def _detail_code(read_status: str, selector: Mapping[str, Any], source: object) -> str:
    kind = selector["kind"]
    if read_status == "active":
        return {
            "project": "query_status.project_active",
            "lane": "query_status.lane_active",
            "key": "query_status.key_active",
            "operation": "query_status.operation_active",
        }[kind]
    if read_status == "absent":
        return {
            "project": "query_status.project_absent",
            "lane": "query_status.lane_absent",
            "key": "query_status.key_absent",
            "operation": "query_status.operation_absent",
        }[kind]
    if read_status == "busy":
        return "query_status.busy"
    if read_status == "reconciliation_required":
        return "query_status.reconciliation_required"
    if read_status == "quarantined":
        return "query_status.quarantined"
    if read_status == "cursor_stale":
        return "query_status.cursor_stale"
    if read_status == "unavailable" and source == "query_status.advisory_unavailable":
        return "query_status.advisory_unavailable"
    return "query_status.observation_unavailable"


def adapt_status(inspection: object, selector: Mapping[str, Any]) -> Dict[str, Any]:
    """Project one private inspection into the exact public result shape."""

    public_selector = _public_selector(selector)
    raw_status = getattr(inspection, "status", None)
    read_status = raw_status if raw_status in _STATUS_OUTCOME_KINDS else "quarantined"
    detail = _detail_code(
        read_status,
        public_selector,
        getattr(inspection, "detail_code", None),
    )
    normalized = getattr(inspection, "normalized_read_contract_digest", None)
    epoch = _public_epoch(getattr(inspection, "project_read_epoch", None))
    entries = [
        _public_lane_head(entry) for entry in getattr(inspection, "entries", ())
    ]
    next_cursor = getattr(inspection, "next_cursor", None)
    metadata = _public_operation_metadata(
        getattr(inspection, "operation_metadata", None)
    )

    if read_status == "absent":
        entries = []
        next_cursor = None
        metadata = None
    elif read_status in {"busy", "quarantined", "cursor_stale"}:
        epoch = None
        entries = []
        next_cursor = None
        metadata = None
    elif read_status == "unavailable":
        normalized = None
        epoch = None
        entries = []
        next_cursor = None
        metadata = None

    if public_selector["kind"] != "operation":
        metadata = None
    else:
        next_cursor = None
        if metadata is not None and metadata["lane_association"] != "bound":
            entries = []

    if read_status not in {"active", "reconciliation_required"}:
        next_cursor = None

    return {
        "schema": RESULT_SCHEMA_ID,
        "selector": public_selector,
        "read_status": read_status,
        "detail_code": detail,
        "normalized_read_contract_digest": normalized,
        "project_read_epoch": epoch,
        "entries": entries,
        "next_cursor": next_cursor,
        "operation_metadata": metadata,
    }


def _public_project_reference(request: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema": "ask_herdr.project_reference.v1",
        "authority_id": request["project"]["authority_id"],
    }


def _diagnostic(code: str, message: str) -> Dict[str, Any]:
    return {
        "code": code,
        "severity": "error",
        "field_pointer": None,
        "safe_message": message,
        "evidence_ref_ids": [],
    }


def _envelope(
    request: Mapping[str, Any],
    *,
    request_digest: str,
    outcome_kind: str,
    result: Optional[Dict[str, Any]],
    diagnostics: list[Dict[str, Any]],
    clock: Callable[[], object],
) -> Dict[str, Any]:
    mapping = OUTCOME_MAP[outcome_kind]
    observed_at = _timestamp(clock())
    return {
        "schema": OUTCOME_SCHEMA_ID,
        "operation": "query.status",
        "operation_id": request["operation_id"],
        "request_digest": request_digest,
        "project": (
            None
            if outcome_kind == "request_invalid"
            else _public_project_reference(request)
        ),
        "status": mapping["status"],
        "outcome_kind": outcome_kind,
        "exit_class": mapping["exit_class"],
        "retry": {
            "schema": "ask_herdr.retry.v1",
            "disposition": "none",
            "original_operation_id": None,
            "basis_evidence_ref_ids": [],
        },
        "policy": None,
        "result": result,
        "diagnostics": diagnostics,
        "evidence_refs": [],
        "advisory": {},
        "timestamps": {"started_at": observed_at, "completed_at": observed_at},
    }


def _request_failure(
    request: Mapping[str, Any],
    *,
    request_digest: str,
    outcome_kind: str,
    clock: Callable[[], object],
) -> Dict[str, Any]:
    if outcome_kind not in _REQUEST_FAILURE_KINDS:
        outcome_kind = "request_not_currently_admissible"
    return _envelope(
        request,
        request_digest=request_digest,
        outcome_kind=outcome_kind,
        result=None,
        diagnostics=[
            _diagnostic(
                "request.invalid"
                if outcome_kind == "request_invalid"
                else "query_status.project_unavailable",
                "The request is invalid."
                if outcome_kind == "request_invalid"
                else "The Project cannot currently be inspected.",
            )
        ],
        clock=clock,
    )


def _default_project_inspector(
    request: Mapping[str, Any],
) -> ValidatedProjectMutationBinding:
    """Revalidate the bound root before a read-only private status call."""

    try:
        facts = inspect_candidate_project_root(request["project"]["root"])
    except Exception as error:
        outcome_kind = getattr(error, "outcome_kind", None)
        if outcome_kind not in _REQUEST_FAILURE_KINDS:
            outcome_kind = "request_reconciliation_required"
        raise _ProjectInspectionFailure(outcome_kind) from error

    inspection = inspect_authority_store(facts.canonical_root)
    if inspection.status == "active":
        if inspection.authority_id != request["project"]["authority_id"]:
            raise _ProjectInspectionFailure("request_quarantined")
        return ValidatedProjectMutationBinding(
            canonical_root=facts.canonical_root,
            filesystem_device=facts.filesystem_device,
            filesystem_inode=facts.filesystem_inode,
            owner_uid=facts.owner_uid,
            project_authority_id=inspection.authority_id,
        )
    if inspection.status == "busy":
        raise _ProjectInspectionFailure("request_not_currently_admissible")
    if inspection.status == "quarantined":
        raise _ProjectInspectionFailure("request_quarantined")
    raise _ProjectInspectionFailure("request_reconciliation_required")


def _default_status_readers() -> Dict[str, Callable[..., object]]:
    return {
        "project": read_project_status,
        "lane": read_lane_status,
        "key": read_key_status,
        "operation": read_operation_status,
    }


def _read_one_selector(
    request: Mapping[str, Any],
    binding: object,
    readers: Mapping[str, Callable[..., object]],
    clock: Callable[[], object],
) -> object:
    payload = request["payload"]
    selector = payload["selector"]
    kind = selector["kind"]
    reader = readers[kind]
    shared = {
        "limit": payload["limit"],
        "cursor": payload["cursor"],
        "clock": clock,
    }
    if kind == "project":
        return reader(binding, **shared)
    if kind == "lane":
        return reader(binding, lane_id=selector["lane_id"], **shared)
    if kind == "key":
        return reader(binding, consultant_key=selector["consultant_key"], **shared)
    if kind == "operation":
        return reader(binding, operation_id=selector["operation_id"], **shared)
    raise ValueError("query_status.selector_invalid")


def _unavailable_result(
    selector: Mapping[str, Any], detail_code: str
) -> Dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA_ID,
        "selector": _public_selector(selector),
        "read_status": "unavailable",
        "detail_code": detail_code,
        "normalized_read_contract_digest": None,
        "project_read_epoch": None,
        "entries": [],
        "next_cursor": None,
        "operation_metadata": None,
    }


def dispatch_query_status(
    request: Mapping[str, Any],
    *,
    project_inspector: Optional[Callable[[Mapping[str, Any]], object]] = None,
    status_readers: Optional[Mapping[str, Callable[..., object]]] = None,
    clock: Optional[Callable[[], object]] = None,
) -> Dict[str, Any]:
    """Return one public v2 outcome after the closed status precedence."""

    trust_request_header(request)
    if request["operation"] != "query.status":
        raise TrustedHeaderError(TrustedHeaderError.code)
    request_digest = _request_digest(request)
    epoch_clock = clock or _utc_clock

    if validate(request, build_request_schema()):
        return _request_failure(
            request,
            request_digest=request_digest,
            outcome_kind="request_invalid",
            clock=epoch_clock,
        )

    selector = request["payload"]["selector"]
    if request["observation"]["mode"] == "wait":
        return _envelope(
            request,
            request_digest=request_digest,
            outcome_kind="status_capability_unavailable",
            result=_unavailable_result(
                selector, "query_status.observation_unavailable"
            ),
            diagnostics=[],
            clock=epoch_clock,
        )
    if request["payload"]["advisory"] in {"summary", "full"}:
        return _envelope(
            request,
            request_digest=request_digest,
            outcome_kind="status_capability_unavailable",
            result=_unavailable_result(
                selector, "query_status.advisory_unavailable"
            ),
            diagnostics=[],
            clock=epoch_clock,
        )

    inspector = project_inspector or _default_project_inspector
    readers = status_readers or _default_status_readers()
    try:
        binding = inspector(request)
    except _ProjectInspectionFailure as error:
        return _request_failure(
            request,
            request_digest=request_digest,
            outcome_kind=error.outcome_kind,
            clock=epoch_clock,
        )
    except Exception:
        return _request_failure(
            request,
            request_digest=request_digest,
            outcome_kind="request_not_currently_admissible",
            clock=epoch_clock,
        )

    try:
        inspection = _read_one_selector(request, binding, readers, epoch_clock)
        result = adapt_status(inspection, selector)
    except Exception:
        result = _unavailable_result(
            selector, "query_status.observation_unavailable"
        )
    outcome_kind = _STATUS_OUTCOME_KINDS[result["read_status"]]
    return _envelope(
        request,
        request_digest=request_digest,
        outcome_kind=outcome_kind,
        result=result,
        diagnostics=[],
        clock=epoch_clock,
    )


__all__ = ("adapt_status", "dispatch_query_status")
