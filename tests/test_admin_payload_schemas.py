#!/usr/bin/env python3
"""Provider-free contract tests for administration-operation payload schemas."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_admin_payloads import (  # noqa: E402
    ADMIN_PAYLOAD_SCHEMA_BUILDERS,
    ADMIN_PAYLOAD_SCHEMA_IDS,
    build_admin_payload_schema,
)


UUID_A = "123e4567-e89b-42d3-a456-426614174000"
UUID_B = "123e4567-e89b-42d3-b456-426614174001"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64

EXPECTED_OPERATIONS = {
    "profile.list",
    "profile.show",
    "profile.check",
    "profile.auth.status",
    "profile.auth.login",
    "profile.auth.logout",
    "project.init",
    "project.rebind.preview",
    "project.rebind.execute",
    "project.retire.preview",
    "project.retire.execute",
    "cleanup.preview",
    "cleanup.execute",
    "cleanup.resume",
    "cleanup.status",
    "policy.show",
    "policy.status",
    "policy.validate",
    "policy.activate.preview",
    "policy.activate.execute",
    "policy.compact.preview",
    "policy.compact.execute",
}

PROFILE_PAIRS = (
    ("claude", "claude"),
    ("claude", "cc-claude"),
    ("deepseek", "cc-deepseek"),
    ("codex", "codex"),
)


def _payload(operation, **fields):
    return {
        "schema": f"ask_herdr.{operation}.payload.v1",
        **fields,
    }


VALID_PAYLOADS = {
    "profile.list": _payload("profile.list"),
    "profile.show": _payload(
        "profile.show", provider="claude", profile="claude"
    ),
    "profile.check": _payload(
        "profile.check",
        provider="claude",
        profile="claude",
        executable="/opt/homebrew/bin/claude",
    ),
    "profile.auth.status": _payload(
        "profile.auth.status", provider="codex", profile="codex"
    ),
    "profile.auth.login": _payload(
        "profile.auth.login", provider="codex", profile="codex"
    ),
    "profile.auth.logout": _payload(
        "profile.auth.logout", provider="codex", profile="codex"
    ),
    "project.init": _payload("project.init", lifetime="initial"),
    "project.rebind.preview": _payload(
        "project.rebind.preview", proposed_root="/Users/example/moved-project"
    ),
    "project.rebind.execute": _payload(
        "project.rebind.execute",
        manifest_id=UUID_A,
        manifest_digest=DIGEST_A,
        expected_state_digest=DIGEST_B,
    ),
    "project.retire.preview": _payload("project.retire.preview"),
    "project.retire.execute": _payload(
        "project.retire.execute",
        manifest_id=UUID_A,
        manifest_digest=DIGEST_A,
        expected_state_digest=DIGEST_B,
    ),
    "cleanup.preview": _payload(
        "cleanup.preview",
        selection={
            "schema": "ask_herdr.cleanup_selection.v1",
            "scope": "durable_evidence",
            "targets": [
                {
                    "schema": "ask_herdr.cleanup.durable_evidence_target.v1",
                    "target_type": "lane_generation",
                    "lane_id": UUID_A,
                    "generation": 1,
                }
            ],
        },
    ),
    "cleanup.execute": _payload(
        "cleanup.execute",
        manifest_id=UUID_A,
        manifest_digest=DIGEST_A,
        selection_digest=DIGEST_B,
        expected_state_digest=DIGEST_C,
    ),
    "cleanup.resume": _payload(
        "cleanup.resume",
        original_operation_id=UUID_A,
        manifest_id=UUID_B,
        manifest_digest=DIGEST_A,
        expected_reconciliation_state_digest=DIGEST_B,
        completed_step_chain_digest=DIGEST_C,
    ),
    "cleanup.status": _payload("cleanup.status"),
    "policy.show": _payload("policy.show", selection="active"),
    "policy.status": _payload("policy.status"),
    "policy.validate": _payload(
        "policy.validate", candidate_policy="/Users/example/policy.json"
    ),
    "policy.activate.preview": _payload(
        "policy.activate.preview",
        candidate_policy="/Users/example/policy.json",
    ),
    "policy.activate.execute": _payload(
        "policy.activate.execute",
        manifest_id=UUID_A,
        manifest_digest=DIGEST_A,
        expected_ledger_state_digest=DIGEST_B,
    ),
    "policy.compact.preview": _payload("policy.compact.preview"),
    "policy.compact.execute": _payload(
        "policy.compact.execute",
        manifest_id=UUID_A,
        manifest_digest=DIGEST_A,
        expected_ledger_state_digest=DIGEST_B,
    ),
}


def _errors(operation, payload):
    schema = build_admin_payload_schema(operation)
    return list(Draft202012Validator(schema).iter_errors(payload))


def _walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


class AdminPayloadSchemasTest(unittest.TestCase):
    def assert_valid(self, operation, payload):
        self.assertEqual(_errors(operation, payload), [])

    def assert_invalid(self, operation, payload):
        self.assertTrue(_errors(operation, payload))

    def test_builder_mapping_covers_exactly_twenty_two_admin_operations(self):
        self.assertEqual(len(EXPECTED_OPERATIONS), 22)
        self.assertEqual(set(ADMIN_PAYLOAD_SCHEMA_BUILDERS), EXPECTED_OPERATIONS)
        self.assertEqual(
            ADMIN_PAYLOAD_SCHEMA_IDS,
            {
                operation: f"ask_herdr.{operation}.payload.v1"
                for operation in EXPECTED_OPERATIONS
            },
        )
        with self.assertRaises(KeyError):
            build_admin_payload_schema("profile.unknown")

    def test_every_builder_returns_a_fresh_valid_draft_2020_12_schema(self):
        for operation in sorted(EXPECTED_OPERATIONS):
            with self.subTest(operation=operation):
                first = build_admin_payload_schema(operation)
                second = build_admin_payload_schema(operation)
                Draft202012Validator.check_schema(first)
                self.assertEqual(first, second)
                self.assertIsNot(first, second)
                self.assertEqual(
                    first["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertFalse(
                    any(isinstance(node, dict) and "$ref" in node for node in _walk(first)),
                    "payload schemas must be self-contained without references",
                )

    def test_one_valid_fixture_for_every_operation_and_all_payloads_are_closed(self):
        self.assertEqual(set(VALID_PAYLOADS), EXPECTED_OPERATIONS)
        for operation, payload in VALID_PAYLOADS.items():
            with self.subTest(operation=operation):
                self.assert_valid(operation, payload)
                extra = copy.deepcopy(payload)
                extra["unexpected"] = False
                self.assert_invalid(operation, extra)
                wrong_schema = copy.deepcopy(payload)
                wrong_schema["schema"] = "ask_herdr.other.payload.v1"
                self.assert_invalid(operation, wrong_schema)

    def test_profile_pair_union_is_exact_for_show_check_and_auth(self):
        operations = (
            "profile.show",
            "profile.auth.status",
            "profile.auth.login",
            "profile.auth.logout",
        )
        for operation in operations:
            for provider, profile in PROFILE_PAIRS:
                with self.subTest(operation=operation, provider=provider, profile=profile):
                    self.assert_valid(
                        operation,
                        _payload(operation, provider=provider, profile=profile),
                    )
        for operation in operations:
            self.assert_invalid(
                operation,
                _payload(operation, provider="deepseek", profile="claude"),
            )

        for provider, profile in PROFILE_PAIRS:
            self.assert_valid(
                "profile.check",
                _payload(
                    "profile.check",
                    provider=provider,
                    profile=profile,
                    executable="/usr/local/bin/consultant",
                ),
            )
        relative = copy.deepcopy(VALID_PAYLOADS["profile.check"])
        relative["executable"] = "bin/claude"
        self.assert_invalid("profile.check", relative)

        forbidden_override = copy.deepcopy(VALID_PAYLOADS["profile.auth.login"])
        forbidden_override["executable"] = "/usr/bin/claude"
        self.assert_invalid("profile.auth.login", forbidden_override)

    def test_profile_list_filter_is_optional_but_exact_and_not_nullable(self):
        self.assert_valid("profile.list", _payload("profile.list"))
        for provider in ("claude", "deepseek", "codex"):
            self.assert_valid(
                "profile.list", _payload("profile.list", provider=provider)
            )
        for provider in (None, "unknown", "cc-claude"):
            self.assert_invalid(
                "profile.list", _payload("profile.list", provider=provider)
            )

    def test_project_init_lifetimes_and_project_admin_manifests_are_exact(self):
        later = _payload(
            "project.init",
            lifetime="after_tombstone",
            predecessor_tombstone_id=UUID_A,
            predecessor_tombstone_digest=DIGEST_A,
        )
        self.assert_valid("project.init", later)

        invalid_initial = _payload(
            "project.init",
            lifetime="initial",
            predecessor_tombstone_id=UUID_A,
            predecessor_tombstone_digest=DIGEST_A,
        )
        self.assert_invalid("project.init", invalid_initial)

        missing_predecessor = copy.deepcopy(later)
        del missing_predecessor["predecessor_tombstone_digest"]
        self.assert_invalid("project.init", missing_predecessor)

        caller_root = copy.deepcopy(VALID_PAYLOADS["project.init"])
        caller_root["root"] = "/Users/example/project"
        self.assert_invalid("project.init", caller_root)

        for operation in ("project.rebind.execute", "project.retire.execute"):
            for field in ("manifest_id", "manifest_digest", "expected_state_digest"):
                with self.subTest(operation=operation, field=field):
                    missing = copy.deepcopy(VALID_PAYLOADS[operation])
                    del missing[field]
                    self.assert_invalid(operation, missing)

    def test_cleanup_preview_has_four_closed_semantic_selection_variants(self):
        variants = (
            VALID_PAYLOADS["cleanup.preview"],
            _payload(
                "cleanup.preview",
                selection={
                    "schema": "ask_herdr.cleanup_selection.v1",
                    "scope": "durable_evidence",
                    "targets": [
                        {
                            "schema": "ask_herdr.cleanup.durable_evidence_target.v1",
                            "target_type": "review_branch",
                            "review_branch_id": UUID_A,
                        }
                    ],
                },
            ),
            _payload(
                "cleanup.preview",
                selection={
                    "schema": "ask_herdr.cleanup_selection.v1",
                    "scope": "abandonment_evidence",
                    "targets": [
                        {
                            "schema": "ask_herdr.cleanup.abandonment_evidence_target.v1",
                            "lane_id": UUID_A,
                            "generation": 3,
                            "lane_tombstone_digest": DIGEST_A,
                        }
                    ],
                    "acknowledge_loss_of_future_reconciliation": True,
                },
            ),
            _payload(
                "cleanup.preview",
                selection={
                    "schema": "ask_herdr.cleanup_selection.v1",
                    "scope": "provider_native_state",
                    "targets": [
                        {
                            "schema": "ask_herdr.cleanup.provider_native_state_target.v1",
                            "provider": "claude",
                            "profile": "cc-claude",
                            "artifact_kind": "session",
                            "artifact_id": "claude-session-opaque-7",
                            "artifact_binding_digest": DIGEST_A,
                        }
                    ],
                },
            ),
            _payload(
                "cleanup.preview",
                selection={
                    "schema": "ask_herdr.cleanup_selection.v1",
                    "scope": "isolated_authentication",
                    "target": {
                        "schema": "ask_herdr.cleanup.isolated_authentication_target.v1",
                        "provider": "codex",
                        "profile": "codex",
                        "provider_state_root_binding_digest": DIGEST_A,
                    },
                },
            ),
        )
        for index, payload in enumerate(variants):
            with self.subTest(index=index):
                self.assert_valid("cleanup.preview", payload)

        acknowledgement_on_ordinary_evidence = copy.deepcopy(variants[0])
        acknowledgement_on_ordinary_evidence["selection"][
            "acknowledge_loss_of_future_reconciliation"
        ] = True
        self.assert_invalid("cleanup.preview", acknowledgement_on_ordinary_evidence)

        missing_acknowledgement = copy.deepcopy(variants[2])
        del missing_acknowledgement["selection"][
            "acknowledge_loss_of_future_reconciliation"
        ]
        self.assert_invalid("cleanup.preview", missing_acknowledgement)

        caller_path = copy.deepcopy(variants[3])
        caller_path["selection"]["targets"][0]["path"] = "/tmp/native"
        self.assert_invalid("cleanup.preview", caller_path)

        nested_extra = copy.deepcopy(variants[4])
        nested_extra["selection"]["target"]["unexpected"] = False
        self.assert_invalid("cleanup.preview", nested_extra)

    def test_cleanup_execute_and_resume_require_all_correlation_digests(self):
        for operation in ("cleanup.execute", "cleanup.resume"):
            payload = VALID_PAYLOADS[operation]
            for field in tuple(payload)[1:]:
                with self.subTest(operation=operation, field=field):
                    missing = copy.deepcopy(payload)
                    del missing[field]
                    self.assert_invalid(operation, missing)

    def test_policy_show_is_tagged_and_mutations_use_only_exact_sources(self):
        active = _payload("policy.show", selection="active")
        version = _payload(
            "policy.show",
            selection="version",
            policy_profile_id=UUID_A,
            policy_version=7,
        )
        self.assert_valid("policy.show", active)
        self.assert_valid("policy.show", version)

        active_with_version = copy.deepcopy(active)
        active_with_version["policy_version"] = 7
        self.assert_invalid("policy.show", active_with_version)
        version_without_id = copy.deepcopy(version)
        del version_without_id["policy_profile_id"]
        self.assert_invalid("policy.show", version_without_id)

        for operation in ("policy.validate", "policy.activate.preview"):
            relative = copy.deepcopy(VALID_PAYLOADS[operation])
            relative["candidate_policy"] = "policy.json"
            self.assert_invalid(operation, relative)

        caller_prefix = copy.deepcopy(VALID_PAYLOADS["policy.compact.preview"])
        caller_prefix["through_record_id"] = UUID_A
        self.assert_invalid("policy.compact.preview", caller_prefix)

        ledger_range = copy.deepcopy(VALID_PAYLOADS["policy.status"])
        ledger_range["offset"] = 0
        self.assert_invalid("policy.status", ledger_range)

    def test_nested_cleanup_objects_are_closed_and_have_exact_v1_schema(self):
        payloads = [
            VALID_PAYLOADS["cleanup.preview"],
            _payload(
                "cleanup.preview",
                selection={
                    "schema": "ask_herdr.cleanup_selection.v1",
                    "scope": "isolated_authentication",
                    "target": {
                        "schema": "ask_herdr.cleanup.isolated_authentication_target.v1",
                        "provider": "claude",
                        "profile": "claude",
                        "provider_state_root_binding_digest": DIGEST_A,
                    },
                },
            ),
        ]
        for payload in payloads:
            for node in _walk(payload):
                if isinstance(node, dict):
                    self.assertIn("schema", node)
                    self.assertTrue(node["schema"].endswith(".v1"))


if __name__ == "__main__":
    unittest.main()
