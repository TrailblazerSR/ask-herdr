#!/usr/bin/env python3
"""Provider-free contract tests for all turn-operation payload schemas."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_turn_payloads import (  # noqa: E402
    TURN_OPERATION_NAMES,
    TURN_PAYLOAD_SCHEMA_IDS,
    build_turn_payload_schemas,
)


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"
UUID_C = "33333333-3333-4333-8333-333333333333"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def normalized(kind: str, text: str = "Review this.\n") -> dict:
    return {
        "schema": f"ask_herdr.normalized_{kind}.v1",
        "text": text,
        "utf8_bytes": len(text.encode("utf-8")),
        "content_digest": DIGEST_A,
    }


def material() -> dict:
    return {
        "schema": "ask_herdr.material_reference.v1",
        "canonical_path": "/Users/example/project/CONTEXT.md",
        "expected_kind": "file",
        "binding": "content",
        "follow_symlink": False,
        "expected_content_digest": DIGEST_B,
        "directory_manifest_ref": None,
    }


def capabilities() -> dict:
    return {
        "schema": "ask_herdr.capability_manifest.v1",
        "read_paths": [
            {
                "schema": "ask_herdr.capability_path.v1",
                "canonical_path": "/Users/example/project/CONTEXT.md",
                "scope": "object",
            }
        ],
        "write_paths": [],
        "network": {
            "schema": "ask_herdr.network_capability.v1",
            "mode": "none",
            "destinations": [],
        },
        "tools": ["read"],
        "connectors": [],
        "limits": {
            "schema": "ask_herdr.transaction_byte_limits.v1",
            "temporary_bytes": 1048576,
            "output_bytes": 262144,
        },
    }


def expansion_ref() -> dict:
    return {
        "schema": "ask_herdr.capability_expansion_ref.v1",
        "expansion_id": UUID_C,
        "expansion_digest": DIGEST_C,
    }


def valid_payloads() -> dict:
    return {
        "turn.consult": {
            "schema": "ask_herdr.turn.consult.payload.v1",
            "prompt": normalized("prompt"),
            "materials": [material()],
            "capabilities": capabilities(),
            "consultants": [
                {
                    "schema": "ask_herdr.consultant_request.v1",
                    "child_operation_id": UUID_A,
                    "consultant_key": "claude-review",
                    "generation_precondition": {
                        "schema": "ask_herdr.generation_precondition.v1",
                        "state": "unused",
                    },
                    "provider": "claude",
                    "launcher_profile": "cc-claude",
                    "requested_model": "claude-fable-5",
                    "requested_effort": "medium",
                    "allowed_auxiliary_models": [],
                    "expected_profile_binding_digest": DIGEST_A,
                    "expected_acceptance_digest": DIGEST_B,
                    "post_final_release": "retain",
                }
            ],
        },
        "turn.answer": {
            "schema": "ask_herdr.turn.answer.payload.v1",
            "clarification": {
                "schema": "ask_herdr.pending_clarification_correlation.v1",
                "consultant_key": "claude-review",
                "lane_id": UUID_A,
                "lane_generation": 1,
                "question_id": UUID_B,
                "question_sequence": 1,
                "originating_turn_id": UUID_C,
                "lineage": {
                    "schema": "ask_herdr.turn_lineage.v1",
                    "kind": "canonical",
                    "review_branch_id": None,
                },
                "expected_head_digest": DIGEST_A,
            },
            "answer": normalized("answer", "Yes.\n"),
            "expected_profile_binding_digest": DIGEST_B,
            "expected_acceptance_digest": DIGEST_C,
            "post_final_release": "lane_workspace",
        },
        "turn.review": {
            "schema": "ask_herdr.turn.review.payload.v1",
            "target": {
                "schema": "ask_herdr.review_target.v1",
                "consultant_key": "claude-review",
                "target_turn_id": UUID_A,
                "lane_id": UUID_B,
                "lane_generation": 2,
                "target_response_digest": DIGEST_A,
                "expected_head_digest": DIGEST_B,
            },
            "instruction": normalized("review_instruction"),
            "materials": [material()],
            "capabilities": capabilities(),
            "expected_profile_binding_digest": DIGEST_B,
            "expected_acceptance_digest": DIGEST_C,
            "post_final_release": "retain",
        },
        "turn.safe_retry": {
            "schema": "ask_herdr.turn.safe_retry.payload.v1",
            "source_operation_id": UUID_A,
            "expected_source_request_digest": DIGEST_A,
            "definite_non_start_state_digest": DIGEST_B,
        },
        "turn.recovery_continue": {
            "schema": "ask_herdr.turn.recovery_continue.payload.v1",
            "source_operation_id": UUID_A,
            "expected_source_request_digest": DIGEST_A,
            "interrupted_state_digest": DIGEST_B,
            "capability_expansion_ref": None,
        },
    }


class TurnPayloadSchemasTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = build_turn_payload_schemas()
        cls.validators = {
            operation: Draft202012Validator(schema)
            for operation, schema in cls.schemas.items()
        }

    def assert_valid(self, operation: str, payload: dict) -> None:
        errors = sorted(
            self.validators[operation].iter_errors(payload),
            key=lambda error: list(error.path),
        )
        self.assertEqual(errors, [], [error.message for error in errors])

    def assert_invalid(self, operation: str, payload: dict) -> None:
        self.assertTrue(list(self.validators[operation].iter_errors(payload)))

    def test_exact_five_operation_mapping_and_fresh_draft_schemas(self):
        expected = (
            "turn.answer",
            "turn.consult",
            "turn.recovery_continue",
            "turn.review",
            "turn.safe_retry",
        )
        self.assertEqual(TURN_OPERATION_NAMES, expected)
        self.assertEqual(tuple(self.schemas), expected)
        self.assertEqual(set(TURN_PAYLOAD_SCHEMA_IDS), set(expected))
        with self.assertRaises(TypeError):
            TURN_PAYLOAD_SCHEMA_IDS["turn.consult"] = "forbidden"  # type: ignore

        second = build_turn_payload_schemas()
        self.assertEqual(second, self.schemas)
        self.assertIsNot(second, self.schemas)
        for operation, schema in self.schemas.items():
            with self.subTest(operation=operation):
                Draft202012Validator.check_schema(schema)
                self.assertEqual(
                    TURN_PAYLOAD_SCHEMA_IDS[operation],
                    f"ask_herdr.{operation}.payload.v1",
                )
                self.assertEqual(
                    schema["properties"]["schema"]["const"],
                    TURN_PAYLOAD_SCHEMA_IDS[operation],
                )
                self.assertFalse(schema["additionalProperties"])
                self.assertNotIn("$ref", repr(schema))

    def test_every_instance_object_schema_is_closed_and_version_tagged(self):
        def walk(node):
            if isinstance(node, dict):
                yield node
                for value in node.values():
                    yield from walk(value)
            elif isinstance(node, list):
                for value in node:
                    yield from walk(value)

        for operation, schema in self.schemas.items():
            objects = [node for node in walk(schema) if node.get("type") == "object"]
            self.assertTrue(objects)
            for object_schema in objects:
                with self.subTest(operation=operation, object_schema=object_schema):
                    self.assertIs(object_schema.get("additionalProperties"), False)
                    self.assertIn("schema", object_schema.get("required", []))
                    schema_const = object_schema["properties"]["schema"]["const"]
                    self.assertTrue(schema_const.endswith(".v1"), schema_const)

    def test_one_valid_fixture_for_every_turn_branch(self):
        for operation, payload in valid_payloads().items():
            with self.subTest(operation=operation):
                self.assert_valid(operation, payload)

    def test_every_branch_rejects_unknown_and_authoritative_derived_fields(self):
        forbidden = {
            "turn.consult": ("lane_id", "workspace_path", "canonical_request_digest"),
            "turn.answer": ("provider", "native_session_id", "workspace_path"),
            "turn.review": ("provider", "native_session_id", "target_response"),
            "turn.safe_retry": ("prompt", "native_session_id", "lane_id"),
            "turn.recovery_continue": ("prompt", "native_session_id", "lane_id"),
        }
        for operation, payload in valid_payloads().items():
            with self.subTest(operation=operation, field="unexpected"):
                candidate = copy.deepcopy(payload)
                candidate["unexpected"] = False
                self.assert_invalid(operation, candidate)
            for field in forbidden[operation]:
                with self.subTest(operation=operation, field=field):
                    candidate = copy.deepcopy(payload)
                    candidate[field] = "caller-forbidden"
                    self.assert_invalid(operation, candidate)

    def test_nested_objects_are_strict_and_schema_tagged(self):
        cases = (
            ("turn.consult", ("prompt",)),
            ("turn.consult", ("materials", 0)),
            ("turn.consult", ("capabilities", "network")),
            ("turn.consult", ("consultants", 0, "generation_precondition")),
            ("turn.answer", ("clarification",)),
            ("turn.answer", ("clarification", "lineage")),
            ("turn.review", ("target",)),
            ("turn.review", ("capabilities", "limits")),
            ("turn.recovery_continue", ("capability_expansion_ref",)),
        )
        payloads = valid_payloads()
        payloads["turn.recovery_continue"]["capability_expansion_ref"] = expansion_ref()
        for operation, path in cases:
            with self.subTest(operation=operation, path=path):
                candidate = copy.deepcopy(payloads[operation])
                nested = candidate
                for component in path:
                    nested = nested[component]
                nested["unexpected"] = "forbidden"
                self.assert_invalid(operation, candidate)

    def test_consultant_provider_profile_pairs_are_exact_and_child_ids_are_semantic(self):
        payload = valid_payloads()["turn.consult"]
        child = payload["consultants"][0]
        valid_pairs = (
            ("claude", "claude"),
            ("claude", "cc-claude"),
            ("deepseek", "cc-deepseek"),
            ("codex", "codex"),
        )
        for provider, profile in valid_pairs:
            with self.subTest(provider=provider, profile=profile):
                candidate = copy.deepcopy(payload)
                candidate["consultants"][0]["provider"] = provider
                candidate["consultants"][0]["launcher_profile"] = profile
                self.assert_valid("turn.consult", candidate)

        invalid = copy.deepcopy(payload)
        invalid["consultants"][0].update(provider="deepseek", launcher_profile="claude")
        self.assert_invalid("turn.consult", invalid)

        duplicate_ids = copy.deepcopy(payload)
        duplicate_ids["consultants"].append(copy.deepcopy(child))
        duplicate_ids["consultants"][1]["consultant_key"] = "claude-second"
        self.assert_valid("turn.consult", duplicate_ids)

    def test_consultant_key_matches_the_exact_lowercase_64_byte_grammar(self):
        payload = valid_payloads()["turn.consult"]
        for valid_key in ("a", "reviewer-", "a" + "-" * 63):
            candidate = copy.deepcopy(payload)
            candidate["consultants"][0]["consultant_key"] = valid_key
            self.assert_valid("turn.consult", candidate)

        for invalid_key in ("Reviewer", "a" + "-" * 64):
            candidate = copy.deepcopy(payload)
            candidate["consultants"][0]["consultant_key"] = invalid_key
            self.assert_invalid("turn.consult", candidate)

    def test_generation_precondition_exact_variants(self):
        payload = valid_payloads()["turn.consult"]
        child = payload["consultants"][0]
        child["generation_precondition"] = {
            "schema": "ask_herdr.generation_precondition.v1",
            "state": "after_release",
            "predecessor_lane_id": UUID_B,
            "predecessor_generation": 4,
            "predecessor_state_digest": DIGEST_C,
        }
        self.assert_valid("turn.consult", payload)

        child["generation_precondition"]["predecessor_generation"] = 0
        self.assert_invalid("turn.consult", payload)

    def test_materials_are_in_place_and_capabilities_are_closed(self):
        payload = valid_payloads()["turn.consult"]
        for forbidden in ("copy_path", "storage_path", "workspace_path"):
            with self.subTest(forbidden=forbidden):
                candidate = copy.deepcopy(payload)
                candidate["materials"][0][forbidden] = "/private/copy"
                self.assert_invalid("turn.consult", candidate)

        web = copy.deepcopy(payload)
        web["capabilities"]["network"] = {
            "schema": "ask_herdr.network_capability.v1",
            "mode": "web",
            "destinations": ["https://docs.example.com"],
        }
        web["capabilities"]["tools"] = ["read", "web.fetch"]
        self.assert_valid("turn.consult", web)

        for mode, destinations in (
            ("none", ["https://docs.example.com"]),
            ("full", ["https://docs.example.com"]),
            ("web", []),
            ("web", ["https://docs.example.com/path"]),
            ("web", ["https://DOCS.example.com"]),
            ("web", ["http://docs.example.com:80"]),
            ("web", ["https://docs.example.com:443"]),
        ):
            with self.subTest(mode=mode, destinations=destinations):
                candidate = copy.deepcopy(payload)
                candidate["capabilities"]["network"] = {
                    "schema": "ask_herdr.network_capability.v1",
                    "mode": mode,
                    "destinations": destinations,
                }
                self.assert_invalid("turn.consult", candidate)

    def test_answer_optional_expansion_is_correlated_and_native_identity_is_forbidden(self):
        baseline = valid_payloads()["turn.answer"]
        self.assert_valid("turn.answer", baseline)

        expanded = copy.deepcopy(baseline)
        expanded["added_materials"] = [material()]
        expanded["capability_expansion_ref"] = expansion_ref()
        self.assert_valid("turn.answer", expanded)

        missing_authority = copy.deepcopy(expanded)
        del missing_authority["capability_expansion_ref"]
        self.assert_invalid("turn.answer", missing_authority)

        native = copy.deepcopy(baseline)
        native["clarification"]["native_session_id"] = "secret-native-id"
        self.assert_invalid("turn.answer", native)

    def test_safe_retry_and_recovery_continuation_stay_minimal(self):
        payloads = valid_payloads()
        expanded = copy.deepcopy(payloads["turn.recovery_continue"])
        expanded["capability_expansion_ref"] = expansion_ref()
        self.assert_valid("turn.recovery_continue", expanded)

        for operation in ("turn.safe_retry", "turn.recovery_continue"):
            for forbidden in ("materials", "capabilities", "consultant_key"):
                with self.subTest(operation=operation, forbidden=forbidden):
                    candidate = copy.deepcopy(payloads[operation])
                    candidate[forbidden] = []
                    self.assert_invalid(operation, candidate)


if __name__ == "__main__":
    unittest.main()
