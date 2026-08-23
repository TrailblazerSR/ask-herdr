#!/usr/bin/env python3
"""RED tests for the frozen public-beta v2 schemas and outcome contract."""

from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_json import canonical_json  # noqa: E402
from ask_herdr_schema_validator import is_valid, validate  # noqa: E402


UUID = "123e4567-e89b-42d3-a456-426614174000"
LANE_ID = "123e4567-e89b-42d3-a456-426614174001"
AUTHORITY_ID = "123e4567-e89b-42d3-a456-426614174002"
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64
EPOCH_DIGEST = "sha256:" + "c" * 64
TIMESTAMP = "2026-08-22T01:02:03Z"
_UNSET = object()


def _contract_module():
    try:
        return importlib.import_module("ask_herdr_outcome_v2_contract")
    except ModuleNotFoundError as error:
        raise AssertionError(
            "RED: ask_herdr_outcome_v2_contract is absent; "
            "the public v2 builder has not been implemented"
        ) from error


def _builder(module, *names):
    for name in names:
        candidate = getattr(module, name, None)
        if callable(candidate):
            return candidate
    raise AssertionError(
        "public v2 contract must expose one of: " + ", ".join(names)
    )


def _epoch():
    return {
        "schema": "ask_herdr.project_read_epoch.v1",
        "project_authority_id": AUTHORITY_ID,
        "authority_store_head_digest": DIGEST,
        "project_state_digest": REQUEST_DIGEST,
        "lane_index_digest": EPOCH_DIGEST,
        "topology_ledger_head_digest": DIGEST,
        "observed_at": TIMESTAMP,
        "acquisition_attempt": 1,
        "epoch_digest": EPOCH_DIGEST,
    }


def _selector(kind="project"):
    selector = {
        "schema": "ask_herdr.query.status.selector.v1",
        "kind": kind,
    }
    if kind == "lane":
        selector["lane_id"] = LANE_ID
    elif kind == "key":
        selector["consultant_key"] = "biology"
    elif kind == "operation":
        selector["operation_id"] = UUID
    return selector


def _lane_entry():
    return {
        "lane_id": LANE_ID,
        "lane_generation": 1,
        "lane_binding_digest": DIGEST,
        "event_sequence": 7,
        "event_digest": REQUEST_DIGEST,
        "state_digest": EPOCH_DIGEST,
        "response_digest": None,
    }


def _operation_metadata(*, lane_association="bound"):
    return {
        "operation_id": UUID,
        "operation": "turn.consult",
        "canonical_request_digest": REQUEST_DIGEST,
        "lane_association": lane_association,
    }


def _result(
    *,
    selector=None,
    read_status="active",
    detail_code="query_status.project_active",
    normalized_digest=DIGEST,
    project_read_epoch=_UNSET,
    entries=None,
    next_cursor=None,
    operation_metadata=None,
):
    return {
        "schema": "ask_herdr.query.status.result.v1",
        "selector": _selector() if selector is None else selector,
        "read_status": read_status,
        "detail_code": detail_code,
        "normalized_read_contract_digest": normalized_digest,
        "project_read_epoch": (
            _epoch() if project_read_epoch is _UNSET else project_read_epoch
        ),
        "entries": [] if entries is None else entries,
        "next_cursor": next_cursor,
        "operation_metadata": operation_metadata,
    }


def _outcome(
    *,
    outcome_kind="status_observed",
    status="succeeded",
    exit_class=0,
    result=None,
    project=None,
    diagnostics=None,
):
    if project is None and outcome_kind != "request_invalid":
        project = {
            "schema": "ask_herdr.project_reference.v1",
            "authority_id": AUTHORITY_ID,
        }
    return {
        "schema": "ask_herdr.outcome.v2",
        "operation": "query.status",
        "operation_id": UUID,
        "request_digest": REQUEST_DIGEST,
        "project": project,
        "status": status,
        "outcome_kind": outcome_kind,
        "exit_class": exit_class,
        "retry": {
            "schema": "ask_herdr.retry.v1",
            "disposition": "none",
            "original_operation_id": None,
            "basis_evidence_ref_ids": [],
        },
        "policy": None,
        "result": result,
        "diagnostics": [] if diagnostics is None else diagnostics,
        "evidence_refs": [],
        "advisory": {},
        "timestamps": {
            "started_at": TIMESTAMP,
            "completed_at": TIMESTAMP,
        },
    }


class OutcomeV2ContractTest(unittest.TestCase):
    def test_builders_are_deterministic_and_match_canonical_bundled_documents(self):
        module = _contract_module()
        outcome_builder = _builder(module, "build_outcome_schema")
        result_builder = _builder(
            module,
            "build_query_status_result_schema",
            "build_result_schema",
        )
        documents = (
            (
                outcome_builder,
                ROOT / "schemas" / "ask_herdr.outcome.v2.schema.json",
            ),
            (
                result_builder,
                ROOT / "schemas" / "ask_herdr.query.status.result.v1.schema.json",
            ),
        )
        for builder, path in documents:
            with self.subTest(path=path.name):
                first = builder()
                second = builder()
                self.assertEqual(canonical_json(first), canonical_json(second))
                self.assertEqual(
                    path.read_bytes(), canonical_json(first) + b"\n"
                )
                self.assertEqual(json.loads(path.read_text()), first)

    def test_both_schema_documents_are_closed_draft_2020_12_contracts(self):
        module = _contract_module()
        outcome = _builder(module, "build_outcome_schema")()
        result = _builder(
            module,
            "build_query_status_result_schema",
            "build_result_schema",
        )()
        Draft202012Validator.check_schema(outcome)
        Draft202012Validator.check_schema(result)
        self.assertFalse(outcome["additionalProperties"])
        self.assertFalse(result["additionalProperties"])
        self.assertEqual(outcome["$id"], "urn:ask-herdr:schema:ask_herdr.outcome.v2")
        self.assertEqual(
            result["$id"],
            "urn:ask-herdr:schema:ask_herdr.query.status.result.v1",
        )
        self.assertEqual(
            outcome["required"],
            [
                "schema",
                "operation",
                "operation_id",
                "request_digest",
                "project",
                "status",
                "outcome_kind",
                "exit_class",
                "retry",
                "policy",
                "result",
                "diagnostics",
                "evidence_refs",
                "advisory",
                "timestamps",
            ],
        )
        self.assertEqual(
            result["required"],
            [
                "schema",
                "selector",
                "read_status",
                "detail_code",
                "normalized_read_contract_digest",
                "project_read_epoch",
                "entries",
                "next_cursor",
                "operation_metadata",
            ],
        )

    def test_exact_ten_outcome_map_preserves_status_and_exit_mapping(self):
        module = _contract_module()
        actual_map = getattr(module, "OUTCOME_MAP", None)
        self.assertIsNotNone(actual_map, "v2 module must publish its closed outcome map")
        expected = {
            "status_observed": ("succeeded", 0),
            "status_busy": ("in_progress", 40),
            "status_reconciliation_required": ("reconciliation_required", 40),
            "cursor_stale": ("failed", 40),
            "status_quarantined": ("quarantined", 50),
            "status_capability_unavailable": ("failed", 20),
            "request_invalid": ("failed", 64),
            "request_not_currently_admissible": ("failed", 20),
            "request_reconciliation_required": ("reconciliation_required", 40),
            "request_quarantined": ("quarantined", 50),
        }
        self.assertEqual(set(actual_map), set(expected))
        self.assertEqual(
            {
                key: (value["status"], value["exit_class"])
                for key, value in actual_map.items()
            },
            expected,
        )

    def test_valid_active_absent_and_invalid_envelopes_pass_both_validators(self):
        module = _contract_module()
        outcome_schema = _builder(module, "build_outcome_schema")()
        result_schema = _builder(
            module,
            "build_query_status_result_schema",
            "build_result_schema",
        )()
        cases = (
            _outcome(result=_result()),
            _outcome(
                outcome_kind="status_observed",
                result=_result(
                    read_status="absent",
                    detail_code="query_status.project_absent",
                    project_read_epoch=_epoch(),
                ),
            ),
            _outcome(
                outcome_kind="request_invalid",
                status="failed",
                exit_class=64,
                project=None,
                result=None,
                diagnostics=[
                    {
                        "code": "request.invalid",
                        "severity": "error",
                        "field_pointer": None,
                        "safe_message": "The request is invalid.",
                        "evidence_ref_ids": [],
                    }
                ],
            ),
        )
        for outcome in cases:
            with self.subTest(kind=outcome["outcome_kind"]):
                self.assertEqual(
                    list(Draft202012Validator(outcome_schema).iter_errors(outcome)),
                    [],
                )
                self.assertEqual(validate(outcome, outcome_schema), ())
        result = _result()
        self.assertEqual(
            list(Draft202012Validator(result_schema).iter_errors(result)), []
        )
        self.assertTrue(is_valid(result, result_schema))

    def test_result_presence_matrix_rejects_unsupported_data_and_accepts_closed_states(self):
        module = _contract_module()
        schema = _builder(
            module,
            "build_query_status_result_schema",
            "build_result_schema",
        )()
        active_project = _result(entries=[])
        active_lane = _result(
            selector=_selector("lane"),
            detail_code="query_status.lane_active",
            entries=[_lane_entry()],
        )
        active_operation = _result(
            selector=_selector("operation"),
            detail_code="query_status.operation_active",
            entries=[_lane_entry()],
            operation_metadata=_operation_metadata(),
        )
        operation_without_lane = _result(
            selector=_selector("operation"),
            detail_code="query_status.operation_active",
            entries=[],
            operation_metadata=_operation_metadata(lane_association="unresolved"),
        )
        reconciliation = _result(
            read_status="reconciliation_required",
            detail_code="query_status.reconciliation_required",
            entries=[_lane_entry()],
            next_cursor="mcv1.cursor",
        )
        absent = _result(
            read_status="absent",
            detail_code="query_status.project_absent",
            entries=[],
            next_cursor=None,
            operation_metadata=None,
        )
        operation_absent = _result(
            selector=_selector("operation"),
            read_status="absent",
            detail_code="query_status.operation_absent",
            entries=[],
            next_cursor=None,
            operation_metadata=None,
        )
        reconciliation_no_epoch_empty = _result(
            read_status="reconciliation_required",
            detail_code="query_status.reconciliation_required",
            project_read_epoch=None,
            entries=[],
            next_cursor=None,
            operation_metadata=None,
        )
        reconciliation_operation_no_epoch_empty = _result(
            selector=_selector("operation"),
            read_status="reconciliation_required",
            detail_code="query_status.reconciliation_required",
            project_read_epoch=None,
            entries=[],
            next_cursor=None,
            operation_metadata=None,
        )
        for result in (
            active_project,
            active_lane,
            active_operation,
            operation_without_lane,
            reconciliation,
            absent,
            operation_absent,
            reconciliation_no_epoch_empty,
            reconciliation_operation_no_epoch_empty,
        ):
            with self.subTest(status=result["read_status"], selector=result["selector"]):
                self.assertEqual(
                    list(Draft202012Validator(schema).iter_errors(result)), []
                )
        self.assertEqual(validate(reconciliation_no_epoch_empty, schema), ())
        self.assertEqual(
            validate(reconciliation_operation_no_epoch_empty, schema), ()
        )

        for status, detail in (
            ("busy", "query_status.busy"),
            ("quarantined", "query_status.quarantined"),
            ("cursor_stale", "query_status.cursor_stale"),
            ("unavailable", "query_status.observation_unavailable"),
        ):
            result = _result(
                read_status=status,
                detail_code=detail,
                normalized_digest=None if status == "unavailable" else DIGEST,
                project_read_epoch=None,
            )
            with self.subTest(status=status):
                self.assertEqual(
                    list(Draft202012Validator(schema).iter_errors(result)), []
                )

        non_operation_with_metadata = _result(
            selector=_selector("project"),
            detail_code="query_status.project_active",
            operation_metadata=_operation_metadata(),
        )
        self.assertNotEqual(
            list(Draft202012Validator(schema).iter_errors(non_operation_with_metadata)),
            [],
        )
        self.assertNotEqual(validate(non_operation_with_metadata, schema), ())

        operation_reconciliation_without_metadata = _result(
            selector=_selector("operation"),
            read_status="reconciliation_required",
            detail_code="query_status.reconciliation_required",
            entries=[_lane_entry()],
            next_cursor=None,
            operation_metadata=None,
        )
        self.assertNotEqual(
            list(
                Draft202012Validator(schema).iter_errors(
                    operation_reconciliation_without_metadata
                )
            ),
            [],
        )
        self.assertNotEqual(
            validate(operation_reconciliation_without_metadata, schema), ()
        )

        no_epoch_invalid_variants = (
            (
                "entries",
                {
                    **reconciliation_no_epoch_empty,
                    "entries": [_lane_entry()],
                },
            ),
            (
                "next_cursor",
                {
                    **reconciliation_no_epoch_empty,
                    "next_cursor": "mcv1.cursor",
                },
            ),
            (
                "operation_metadata",
                {
                    **reconciliation_operation_no_epoch_empty,
                    "operation_metadata": _operation_metadata(
                        lane_association="unresolved"
                    ),
                },
            ),
        )
        for field, result in no_epoch_invalid_variants:
            with self.subTest(no_epoch_field=field):
                self.assertNotEqual(
                    list(Draft202012Validator(schema).iter_errors(result)), []
                )
                self.assertNotEqual(validate(result, schema), ())

        contaminated = deepcopy(active_operation)
        contaminated["operation_metadata"]["authority_record_digest"] = DIGEST
        self.assertNotEqual(
            list(Draft202012Validator(schema).iter_errors(contaminated)), []
        )
        self.assertNotEqual(validate(contaminated, schema), ())

    def test_public_operation_metadata_is_exactly_four_fields(self):
        module = _contract_module()
        schema = _builder(
            module,
            "build_query_status_result_schema",
            "build_result_schema",
        )()
        operation = _operation_metadata()
        self.assertEqual(
            list(operation),
            [
                "operation_id",
                "operation",
                "canonical_request_digest",
                "lane_association",
            ],
        )
        result = _result(
            selector=_selector("operation"),
            detail_code="query_status.operation_active",
            entries=[_lane_entry()],
            operation_metadata=operation,
        )
        self.assertTrue(is_valid(result, schema))


if __name__ == "__main__":
    unittest.main()
