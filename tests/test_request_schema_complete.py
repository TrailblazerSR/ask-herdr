#!/usr/bin/env python3
"""Integration tests for the complete, still-unadvertised request schema."""

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
from ask_herdr_operation_contract import OPERATION_CONTRACTS
from ask_herdr_request_schema import (
    REQUEST_SCHEMA_PATH,
    build_request_schema,
)
from tests.test_admin_payload_schemas import VALID_PAYLOADS as ADMIN_PAYLOADS
from tests.test_control_payload_schemas import VALID_PAYLOADS as CONTROL_PAYLOADS
from tests.test_turn_payload_schemas import valid_payloads as turn_payloads


UUID_A = "123e4567-e89b-42d3-a456-426614174000"
UUID_B = "123e4567-e89b-42d3-b456-426614174001"


def all_payloads():
    return {
        **copy.deepcopy(ADMIN_PAYLOADS),
        **copy.deepcopy(CONTROL_PAYLOADS),
        **turn_payloads(),
    }


def request_for(operation):
    contract = OPERATION_CONTRACTS[operation]
    binding = contract.allowed_project_bindings[0]
    project = {
        "schema": "ask_herdr.project_binding.v1",
        "binding": binding,
        "root": "/Users/example/project",
        "authority_id": None if binding == "candidate" else UUID_B,
    }
    reason = {
        "schema": "ask_herdr.reason.v1",
        "action": contract.allowed_action_reasons[0],
    }
    if operation == "turn.consult":
        reason["lane_origin"] = "review"
    mode = contract.allowed_observation_modes[0]
    observation = {
        "schema": "ask_herdr.observation.v1",
        "mode": mode,
        "timeout_ms": 1000 if mode == "wait" else None,
    }
    return {
        "schema": "ask_herdr.request.v1",
        "operation": operation,
        "operation_id": UUID_A,
        "project": project,
        "authority_ref": (
            None
            if contract.authority_class in {"public_read", "bootstrap_human_only"}
            else "grant:opaque-1"
        ),
        "reason": reason,
        "payload": all_payloads()[operation],
        "observation": observation,
    }


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


class CompleteRequestSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = build_request_schema()
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def assert_valid(self, request):
        errors = sorted(
            self.validator.iter_errors(request), key=lambda error: list(error.path)
        )
        self.assertEqual(errors, [], [error.message for error in errors])

    def assert_invalid(self, request):
        self.assertTrue(list(self.validator.iter_errors(request)))

    def test_schema_has_exactly_one_branch_for_every_operation(self):
        self.assertEqual(len(OPERATION_CONTRACTS), 45)
        branches = self.schema["oneOf"]
        self.assertEqual(len(branches), 45)
        self.assertEqual(
            {
                branch["properties"]["operation"]["const"]
                for branch in branches
            },
            set(OPERATION_CONTRACTS),
        )

    def test_one_representative_request_for_every_operation_is_valid(self):
        for operation in OPERATION_CONTRACTS:
            with self.subTest(operation=operation):
                self.assert_valid(request_for(operation))

    def test_payloads_cannot_cross_operation_branches(self):
        operations = list(OPERATION_CONTRACTS)
        for index, operation in enumerate(operations):
            other = operations[(index + 1) % len(operations)]
            request = request_for(operation)
            request["payload"] = all_payloads()[other]
            with self.subTest(operation=operation, other=other):
                self.assert_invalid(request)

    def test_authority_reason_project_and_observation_matrices_are_enforced(self):
        cases = []
        public = request_for("query.status")
        public["authority_ref"] = "grant:forbidden"
        cases.append(public)
        protected = request_for("query.result")
        protected["authority_ref"] = None
        cases.append(protected)
        wrong_reason = request_for("project.init")
        wrong_reason["reason"]["action"] = "inspect"
        cases.append(wrong_reason)
        lane_origin = request_for("query.status")
        lane_origin["reason"]["lane_origin"] = "review"
        cases.append(lane_origin)
        wrong_project = request_for("project.init")
        wrong_project["project"] = request_for("query.status")["project"]
        cases.append(wrong_project)
        wrong_observation = request_for("project.init")
        wrong_observation["observation"] = {
            "schema": "ask_herdr.observation.v1",
            "mode": "wait",
            "timeout_ms": 1000,
        }
        cases.append(wrong_observation)

        for index, request in enumerate(cases):
            with self.subTest(index=index):
                self.assert_invalid(request)

    def test_embedded_payload_documents_have_no_nested_schema_resource_boundary(self):
        for node in walk_dicts(self.schema):
            if node is self.schema:
                continue
            self.assertNotIn("$schema", node)
            self.assertNotIn("$id", node)

    def test_builder_is_deterministic_and_matches_canonical_bundled_document(self):
        first = build_request_schema()
        second = build_request_schema()
        self.assertEqual(canonical_json(first), canonical_json(second))
        on_disk = json.loads(REQUEST_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(on_disk, first)
        self.assertEqual(REQUEST_SCHEMA_PATH.read_bytes(), canonical_json(first) + b"\n")


if __name__ == "__main__":
    unittest.main()
