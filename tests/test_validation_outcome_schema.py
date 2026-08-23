#!/usr/bin/env python3
"""Public-schema tests for the five provider-free validation outcomes."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_json import canonical_json
from ask_herdr_outcome_contract import (
    OUTCOME_MAP,
    OUTCOME_SCHEMA_PATH,
    VALIDATION_OUTCOME_KINDS,
    build_validation_outcome_schema,
)
from tests.test_outcome_schema_core import _invalid_request_outcome, _normal_outcome


class ValidationOutcomeSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = build_validation_outcome_schema()
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def assert_valid(self, instance):
        errors = sorted(
            self.validator.iter_errors(instance), key=lambda error: list(error.path)
        )
        self.assertEqual(errors, [], [error.message for error in errors])

    def assert_invalid(self, instance):
        self.assertTrue(list(self.validator.iter_errors(instance)))

    def test_public_v1_0_schema_contains_exactly_five_validation_outcomes(self):
        self.assertEqual(
            VALIDATION_OUTCOME_KINDS,
            (
                "request_invalid",
                "request_not_currently_admissible",
                "request_quarantined",
                "request_reconciliation_required",
                "request_valid",
            ),
        )
        self.assertEqual(
            set(self.schema["properties"]["outcome_kind"]["enum"]),
            set(VALIDATION_OUTCOME_KINDS),
        )
        branches = self.schema["allOf"][0]["oneOf"]
        self.assertEqual(len(branches), 5)

    def test_all_five_exact_status_exit_and_digest_variants_validate(self):
        for kind in VALIDATION_OUTCOME_KINDS:
            mapping = OUTCOME_MAP[kind]
            instance = (
                _invalid_request_outcome()
                if kind == "request_invalid"
                else _normal_outcome(kind, mapping["status"], mapping["exit_class"])
            )
            with self.subTest(kind=kind, digest="present"):
                if kind != "request_invalid":
                    self.assert_valid(instance)
            if kind != "request_valid":
                instance["request_digest"] = None
                instance["result"]["canonical_bytes"] = None
                with self.subTest(kind=kind, digest="absent"):
                    self.assert_valid(instance)

    def test_nonvalidation_outcomes_and_nonvalidation_results_are_rejected(self):
        runtime = _normal_outcome("turn_final", "succeeded", 0)
        self.assert_invalid(runtime)

        validation = _normal_outcome("request_valid", "succeeded", 0)
        validation["result"] = {"schema": "ask_herdr.query.status.result.v1"}
        self.assert_invalid(validation)

    def test_validation_result_is_closed_content_redacted_and_digest_nonduplicative(self):
        instance = _normal_outcome("request_valid", "succeeded", 0)
        for forbidden in (
            "canonical_request_digest",
            "prompt",
            "answer",
            "authority_ref",
            "native_session_id",
        ):
            candidate = copy.deepcopy(instance)
            candidate["result"][forbidden] = "secret"
            with self.subTest(forbidden=forbidden):
                self.assert_invalid(candidate)

    def test_builder_is_deterministic_and_matches_canonical_bundled_document(self):
        first = build_validation_outcome_schema()
        second = build_validation_outcome_schema()
        self.assertEqual(canonical_json(first), canonical_json(second))
        on_disk = json.loads(OUTCOME_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, first)
        self.assertEqual(OUTCOME_SCHEMA_PATH.read_bytes(), canonical_json(first) + b"\n")


if __name__ == "__main__":
    unittest.main()
