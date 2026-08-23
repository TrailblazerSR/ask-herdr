#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_outcome_contract import (
    OUTCOME_MAP,
    OUTCOME_MAP_SCHEMA_ID,
    OUTCOME_SCHEMA_ID,
    build_outcome_schema,
)


ADDED_CLOSURE = {
    "delivery_uncertain": {
        "status": "reconciliation_required",
        "exit_class": 40,
    },
    "observer_detached": {"status": "in_progress", "exit_class": 0},
    "operation_submitted": {"status": "in_progress", "exit_class": 0},
    "policy_deferred": {"status": "deferred", "exit_class": 76},
    "protocol_failed": {"status": "failed", "exit_class": 30},
    "provider_capacity_exhausted": {"status": "failed", "exit_class": 30},
    "provider_failed": {"status": "failed", "exit_class": 30},
    "turn_clarification": {"status": "needs_input", "exit_class": 10},
    "turn_definite_non_start": {"status": "failed", "exit_class": 30},
    "turn_final": {"status": "succeeded", "exit_class": 0},
    "turn_quarantined": {"status": "quarantined", "exit_class": 50},
    "turn_reconciliation_required": {
        "status": "reconciliation_required",
        "exit_class": 40,
    },
}


def _normal_outcome(outcome_kind, status, exit_class):
    outcome = {
        "schema": "ask_herdr.outcome.v1",
        "operation": "query.status",
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
        "request_digest": "sha256:" + "1" * 64,
        "project": {
            "schema": "ask_herdr.project_binding.v1",
            "binding": "bound",
            "root": "/Users/example/project",
            "authority_id": "123e4567-e89b-42d3-a456-426614174001",
        },
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
        "result": {"schema": "ask_herdr.query.status.result.v1"},
        "diagnostics": [],
        "evidence_refs": [],
        "advisory": {},
        "timestamps": {
            "started_at": "2026-08-13T01:02:03Z",
            "completed_at": "2026-08-13T01:02:04Z",
        },
    }
    if outcome_kind in {
        "request_invalid",
        "request_not_currently_admissible",
        "request_quarantined",
        "request_reconciliation_required",
        "request_valid",
    }:
        outcome["result"] = {
            "schema": "ask_herdr.validation_result.v1",
            "captured_bytes": 12,
            "captured_sha256": "sha256:" + "2" * 64,
            "canonical_bytes": 12,
            "redacted_field_locations": [],
            "current_preconditions": [],
        }
    return outcome


def _invalid_request_outcome():
    outcome = _normal_outcome("request_invalid", "failed", 64)
    outcome.update(
        {
            "request_digest": None,
            "result": {
                "schema": "ask_herdr.validation_result.v1",
                "captured_bytes": 12,
                "captured_sha256": "sha256:" + "2" * 64,
                "canonical_bytes": None,
                "redacted_field_locations": ["/operation"],
                "current_preconditions": [],
            },
        }
    )
    return outcome


class OutcomeSchemaCoreTest(unittest.TestCase):
    def setUp(self):
        self.schema = build_outcome_schema()
        self.validator = Draft202012Validator(self.schema)

    def assertValid(self, instance):
        errors = sorted(self.validator.iter_errors(instance), key=lambda error: list(error.path))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def assertInvalid(self, instance):
        self.assertTrue(list(self.validator.iter_errors(instance)))

    def test_closed_map_preserves_ticket34_and_adds_delegated_semantic_outcomes(self):
        self.assertEqual(OUTCOME_MAP_SCHEMA_ID, "ask_herdr.outcome_map.v1")
        self.assertEqual(len(OUTCOME_MAP), 83)
        self.assertEqual(
            {key: dict(OUTCOME_MAP[key]) for key in ADDED_CLOSURE},
            ADDED_CLOSURE,
        )

        preserved = {
            key: dict(value)
            for key, value in OUTCOME_MAP.items()
            if key not in ADDED_CLOSURE
        }
        canonical = json.dumps(
            preserved,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            "3becd746fa8e384ce94a2a391a8b452ad5049620ee24aa1e49bd52988a47f147",
        )

    def test_built_schema_is_draft_2020_12_strict_preactivation_core(self):
        Draft202012Validator.check_schema(self.schema)
        self.assertEqual(OUTCOME_SCHEMA_ID, "ask_herdr.outcome.v1")
        self.assertEqual(
            self.schema["$id"],
            "urn:ask-herdr:schema:ask_herdr.outcome.v1",
        )
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(
            set(self.schema["required"]),
            {
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
            },
        )
        self.assertNotIn(
            "canonical_request_digest",
            self.schema["$defs"]["validation_result"]["properties"],
        )

    def test_every_outcome_kind_fixes_its_exact_status_and_exit_class(self):
        for kind, mapping in OUTCOME_MAP.items():
            with self.subTest(kind=kind):
                if kind == "request_invalid":
                    instance = _invalid_request_outcome()
                else:
                    instance = _normal_outcome(
                        kind,
                        mapping["status"],
                        mapping["exit_class"],
                    )
                self.assertValid(instance)

                wrong_status = dict(instance)
                wrong_status["status"] = (
                    "failed" if mapping["status"] != "failed" else "succeeded"
                )
                self.assertInvalid(wrong_status)

                wrong_exit = dict(instance)
                wrong_exit["exit_class"] = (
                    30 if mapping["exit_class"] != 30 else 0
                )
                self.assertInvalid(wrong_exit)

    def test_validation_failures_allow_null_until_semantic_projection_compiles(self):
        self.assertValid(_invalid_request_outcome())

        for kind in (
            "request_invalid",
            "request_not_currently_admissible",
            "request_reconciliation_required",
            "request_quarantined",
        ):
            mapping = OUTCOME_MAP[kind]
            outcome = _normal_outcome(
                kind,
                mapping["status"],
                mapping["exit_class"],
            )
            outcome["request_digest"] = None
            outcome["result"]["canonical_bytes"] = None
            self.assertValid(outcome)

        valid = _normal_outcome("turn_final", "succeeded", 0)
        invalid_request = _invalid_request_outcome()
        for field in ("operation", "operation_id", "project"):
            with self.subTest(field=field):
                invalid_normal = dict(valid)
                invalid_normal[field] = None
                self.assertInvalid(invalid_normal)

                invalid_validation = dict(invalid_request)
                invalid_validation[field] = None
                self.assertInvalid(invalid_validation)

        invalid = dict(valid)
        invalid["request_digest"] = None
        self.assertInvalid(invalid)

        request_valid = _normal_outcome("request_valid", "succeeded", 0)
        request_valid["request_digest"] = None
        self.assertInvalid(request_valid)

    def test_nested_contracts_are_closed_and_evidence_refs_are_path_free(self):
        outcome = _normal_outcome("turn_final", "succeeded", 0)
        outcome["diagnostics"] = [
            {
                "code": "provider.capacity_exhausted",
                "severity": "error",
                "field_pointer": "",
                "safe_message": "Provider capacity is currently unavailable.",
                "evidence_ref_ids": [],
            }
        ]
        outcome["evidence_refs"] = [
            {
                "schema": "ask_herdr.evidence_ref.v1",
                "evidence_id": "123e4567-e89b-42d3-a456-426614174002",
                "evidence_class": "response",
                "media_type": "application/json",
                "byte_size": 32,
                "content_digest": "sha256:" + "3" * 64,
                "sensitivity_class": "project_sensitive",
                "creator_operation_id": "123e4567-e89b-42d3-a456-426614174000",
                "relationship": "primary_result",
                "retention_state": "retained",
                "created_at": "2026-08-13T01:02:04Z",
            }
        ]
        self.assertValid(outcome)

        for forbidden in ("path", "relative_path", "storage_locator", "filename"):
            with self.subTest(forbidden=forbidden):
                contaminated = json.loads(json.dumps(outcome))
                contaminated["evidence_refs"][0][forbidden] = "private/location"
                self.assertInvalid(contaminated)

        extra_diagnostic = json.loads(json.dumps(outcome))
        extra_diagnostic["diagnostics"][0]["provider_message"] = "secret"
        self.assertInvalid(extra_diagnostic)

        extra_top_level = dict(outcome)
        extra_top_level["stdout"] = "must not be modeled here"
        self.assertInvalid(extra_top_level)

    def test_non_field_diagnostic_uses_explicit_null_pointer(self):
        outcome = _normal_outcome("provider_failed", "failed", 30)
        outcome["diagnostics"] = [
            {
                "code": "provider.failed",
                "severity": "error",
                "field_pointer": None,
                "safe_message": "The provider transaction failed.",
                "evidence_ref_ids": [],
            }
        ]
        self.assertValid(outcome)

    def test_validation_outcome_is_content_redacted_and_has_no_policy_or_advisory(self):
        outcome = _invalid_request_outcome()
        self.assertValid(outcome)

        with_policy = json.loads(json.dumps(outcome))
        with_policy["policy"] = {
            "schema": "ask_herdr.policy_decision.v1",
            "decision": "denied",
            "profile_id": "123e4567-e89b-42d3-a456-426614174003",
            "profile_version": 1,
            "profile_digest": "sha256:" + "4" * 64,
            "reason_code": "policy.denied",
            "evidence_ref_ids": [],
        }
        self.assertInvalid(with_policy)

        with_advisory = json.loads(json.dumps(outcome))
        with_advisory["advisory"] = {
            "herdr": [
                {
                    "observed_at": "2026-08-13T01:02:04Z",
                    "kind": "lifecycle",
                    "state": "stopped",
                }
            ]
        }
        self.assertInvalid(with_advisory)


if __name__ == "__main__":
    unittest.main()
