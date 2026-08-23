#!/usr/bin/env python3
"""Contract tests for the dependency-free Machine Core schema validator."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_schema_validator import SchemaViolation, is_valid, validate
from ask_herdr_operation_contract import OPERATION_CONTRACTS
from ask_herdr_outcome_contract import (
    OUTCOME_MAP,
    VALIDATION_OUTCOME_KINDS,
    build_validation_outcome_schema,
)
from ask_herdr_request_schema import build_request_schema
from tests.test_outcome_schema_core import _invalid_request_outcome, _normal_outcome
from tests.test_request_schema_complete import request_for


class SchemaValidatorTest(unittest.TestCase):
    def assert_violations(self, instance, schema, *expected):
        self.assertEqual(
            validate(instance, schema),
            tuple(SchemaViolation(pointer, code) for pointer, code in expected),
        )

    def test_valid_scalar_has_no_violations(self):
        self.assertEqual(validate("ready", {"type": "string"}), ())
        self.assertTrue(is_valid("ready", {"type": "string"}))

    def test_json_types_are_exact_and_boolean_is_not_an_integer(self):
        valid = (
            (None, "null"),
            (False, "boolean"),
            ({}, "object"),
            ([], "array"),
            ("", "string"),
            (1, "integer"),
            (1.0, "integer"),
            (1, "number"),
            (1.5, "number"),
        )
        for instance, type_name in valid:
            with self.subTest(instance=instance, type_name=type_name):
                self.assertTrue(is_valid(instance, {"type": type_name}))

        for type_name in ("integer", "number"):
            with self.subTest(type_name=type_name):
                self.assert_violations(
                    True,
                    {"type": type_name},
                    ("", "schema.type"),
                )

        self.assertTrue(is_valid(1, {"type": ["integer", "string"]}))
        self.assert_violations(
            [],
            {"type": ["integer", "string"]},
            ("", "schema.type"),
        )

    def test_scalar_assertions_return_only_pointer_and_stable_code(self):
        cases = (
            ("wrong", {"const": "right"}, "schema.const"),
            ("wrong", {"enum": ["right", None]}, "schema.enum"),
            ("ab", {"minLength": 3}, "schema.min_length"),
            ("abcd", {"maxLength": 3}, "schema.max_length"),
            ("ABC", {"pattern": "^[a-z]+$"}, "schema.pattern"),
            (0, {"minimum": 1}, "schema.minimum"),
            (2, {"maximum": 1}, "schema.maximum"),
            ("not-a-uuid", {"format": "uuid"}, "schema.format.uuid"),
        )
        for instance, schema, code in cases:
            with self.subTest(code=code):
                self.assert_violations(instance, schema, ("", code))

        self.assertTrue(
            is_valid(
                "123e4567-e89b-42d3-a456-426614174000",
                {"format": "uuid"},
            )
        )

    def test_json_equality_keeps_booleans_distinct_from_numbers(self):
        self.assert_violations(True, {"const": 1}, ("", "schema.const"))
        self.assert_violations(False, {"enum": [0]}, ("", "schema.enum"))
        self.assertTrue(is_valid(1.0, {"const": 1}))

    def test_object_contracts_report_redacted_rfc6901_locations(self):
        schema = {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "profile": {
                    "type": "object",
                    "properties": {"enabled": {"type": "boolean"}},
                    "additionalProperties": False,
                },
            },
            "additionalProperties": False,
        }
        self.assert_violations(
            {}, schema, ("/name", "schema.required")
        )
        self.assert_violations(
            {"name": "ok", "profile": {"enabled": 1}},
            schema,
            ("/profile/enabled", "schema.type"),
        )
        self.assert_violations(
            {"name": "ok", "weird~/key": "secret"},
            schema,
            ("/weird~0~1key", "schema.additional_properties"),
        )

    def test_schema_valued_additional_properties_and_dependencies_are_enforced(self):
        schema = {
            "type": "object",
            "properties": {"trigger": {"type": "boolean"}},
            "additionalProperties": {"type": "integer"},
            "dependentRequired": {"trigger": ["confirmation"]},
        }
        self.assert_violations(
            {"trigger": True},
            schema,
            ("/confirmation", "schema.dependent_required"),
        )
        self.assert_violations(
            {"extra": "redacted"},
            schema,
            ("/extra", "schema.type"),
        )

    def test_object_and_array_cardinality_and_items_are_enforced(self):
        self.assert_violations(
            {"a": 1, "b": 2},
            {"type": "object", "maxProperties": 1},
            ("", "schema.max_properties"),
        )
        self.assert_violations(
            {},
            {"type": "object", "minProperties": 1},
            ("", "schema.min_properties"),
        )

        schema = {
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 2,
            "maxItems": 3,
            "uniqueItems": True,
        }
        self.assert_violations([], schema, ("", "schema.min_items"))
        self.assert_violations(
            [1, "redacted"], schema, ("/1", "schema.type")
        )
        self.assert_violations(
            [1, 1.0], schema, ("/1", "schema.unique_items")
        )
        self.assert_violations(
            [1, 2, 3, 4], schema, ("", "schema.max_items")
        )
        self.assertTrue(is_valid([True, 1], {"uniqueItems": True}))

    def test_local_refs_and_json_pointer_unescaping_are_supported(self):
        schema = {
            "$defs": {"name/with~tokens": {"type": "integer"}},
            "$ref": "#/$defs/name~1with~0tokens",
        }
        self.assertTrue(is_valid(3, schema))
        self.assert_violations("redacted", schema, ("", "schema.type"))
        self.assert_violations(
            3, {"$ref": "#/$defs/missing", "$defs": {}}, ("", "schema.ref")
        )

    def test_combinators_apply_exact_json_schema_semantics(self):
        self.assertTrue(
            is_valid("ok", {"oneOf": [{"type": "string"}, {"type": "null"}]})
        )
        self.assert_violations(
            1,
            {"oneOf": [{"type": "number"}, {"type": "integer"}]},
            ("", "schema.one_of"),
        )
        self.assert_violations(
            [],
            {"oneOf": [{"type": "string"}, {"type": "null"}]},
            ("", "schema.one_of"),
        )
        self.assertTrue(
            is_valid(1, {"anyOf": [{"type": "integer"}, {"type": "string"}]})
        )
        self.assert_violations(
            None,
            {"anyOf": [{"type": "integer"}, {"type": "string"}]},
            ("", "schema.any_of"),
        )
        self.assert_violations(
            "ABC",
            {"allOf": [{"type": "string"}, {"pattern": "^[a-z]+$"}]},
            ("", "schema.pattern"),
        )
        self.assert_violations(
            "forbidden", {"not": {"type": "string"}}, ("", "schema.not")
        )
        self.assertTrue(is_valid(4, {"not": {"type": "string"}}))

    def test_conditionals_select_then_or_else_without_leaking_if_failures(self):
        schema = {
            "type": "object",
            "properties": {
                "mode": {"enum": ["manual", "automatic"]},
                "confirmation": {"type": "string"},
                "grant": {"type": "string"},
            },
            "required": ["mode"],
            "if": {
                "properties": {"mode": {"const": "manual"}},
                "required": ["mode"],
            },
            "then": {"required": ["confirmation"]},
            "else": {"required": ["grant"]},
        }
        self.assert_violations(
            {"mode": "manual"},
            schema,
            ("/confirmation", "schema.required"),
        )
        self.assert_violations(
            {"mode": "automatic"}, schema, ("/grant", "schema.required")
        )
        self.assertTrue(
            is_valid({"mode": "manual", "confirmation": "ok"}, schema)
        )
        self.assertTrue(is_valid({"mode": "automatic", "grant": "ok"}, schema))

    def test_boolean_schemas_and_unsupported_assertions_fail_closed(self):
        self.assertTrue(is_valid("anything", True))
        self.assert_violations(
            "anything", False, ("", "schema.false_schema")
        )
        self.assert_violations(
            "anything",
            {"contains": {"const": "anything"}},
            ("", "schema.unsupported_keyword"),
        )
        self.assert_violations(
            "anything",
            {"format": "unsupported"},
            ("", "schema.unsupported_format"),
        )

    def test_all_45_request_branches_accept_valid_and_reject_invalid_examples(self):
        schema = build_request_schema()
        self.assertEqual(len(OPERATION_CONTRACTS), 45)
        for operation in OPERATION_CONTRACTS:
            with self.subTest(operation=operation, case="valid"):
                self.assertTrue(is_valid(request_for(operation), schema))

            invalid = copy.deepcopy(request_for(operation))
            invalid["payload"]["__unexpected__"] = "content-never-returned"
            with self.subTest(operation=operation, case="invalid"):
                self.assertFalse(is_valid(invalid, schema))
                self.assertEqual(
                    validate(invalid, schema),
                    (SchemaViolation("", "schema.one_of"),),
                )

    def test_all_five_validation_outcomes_accept_valid_and_reject_invalid_examples(self):
        schema = build_validation_outcome_schema()
        self.assertEqual(len(VALIDATION_OUTCOME_KINDS), 5)
        for kind in VALIDATION_OUTCOME_KINDS:
            mapping = OUTCOME_MAP[kind]
            valid = (
                _invalid_request_outcome()
                if kind == "request_invalid"
                else _normal_outcome(
                    kind, mapping["status"], mapping["exit_class"]
                )
            )
            with self.subTest(kind=kind, case="valid"):
                self.assertTrue(is_valid(valid, schema))

            invalid = copy.deepcopy(valid)
            invalid["status"] = (
                "failed" if mapping["status"] != "failed" else "succeeded"
            )
            with self.subTest(kind=kind, case="invalid"):
                self.assertFalse(is_valid(invalid, schema))

    def test_representative_decisions_match_jsonschema_reference_implementation(self):
        request_schema = build_request_schema()
        outcome_schema = build_validation_outcome_schema()
        cases = []
        for operation in (
            "project.init",
            "query.status",
            "turn.consult",
            "cleanup.execute",
            "profile.auth.login",
        ):
            valid = request_for(operation)
            invalid = copy.deepcopy(valid)
            invalid["operation_id"] = True
            cases.extend(((valid, request_schema), (invalid, request_schema)))

        for kind in VALIDATION_OUTCOME_KINDS:
            mapping = OUTCOME_MAP[kind]
            valid = (
                _invalid_request_outcome()
                if kind == "request_invalid"
                else _normal_outcome(
                    kind, mapping["status"], mapping["exit_class"]
                )
            )
            invalid = copy.deepcopy(valid)
            invalid["advisory"] = {"herdr": []}
            cases.extend(((valid, outcome_schema), (invalid, outcome_schema)))

        for index, (instance, schema) in enumerate(cases):
            reference = not list(Draft202012Validator(schema).iter_errors(instance))
            with self.subTest(index=index):
                self.assertEqual(is_valid(instance, schema), reference)


if __name__ == "__main__":
    unittest.main()
