#!/usr/bin/env python3
"""Atomic discovery contract for provider-free request validation v1."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_platform import runtime_platform  # noqa: E402


class ValidationDiscoveryActivationTest(unittest.TestCase):
    def invoke(self, *arguments):
        return subprocess.run(
            [sys.executable, str(CLI), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_activated_discovery_advertises_validation_and_machine_run_atomically(self):
        completed = self.invoke("machine", "describe", "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertEqual(result["schema"], "ask_herdr.describe.v3")
        self.assertEqual(result["cli_version"], "0.4.0")
        contract = result["machine_core_contract"]
        self.assertEqual(contract["implementation_version"], "0.4.0")
        self.assertEqual(
            contract["supported_request_versions"],
            ["ask_herdr.request.v1"],
        )
        self.assertEqual(
            contract["supported_outcome_versions"],
            ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
        )
        profile = runtime_platform()
        self.assertEqual(result["runtime_platform"], profile)
        execution_supported = profile["execution_tier"] == "full"
        self.assertEqual(
            result["features"]["machine_validate"],
            execution_supported,
        )
        self.assertEqual(
            result["features"]["machine_run"],
            execution_supported,
        )
        self.assertFalse(result["features"]["human_facade"])
        metadata = {
            item["schema_id"]: item for item in result["schema_documents"]
        }
        self.assertEqual(
            sorted(metadata),
            [
                "ask_herdr.describe.v1",
                "ask_herdr.describe.v2",
                "ask_herdr.describe.v3",
                "ask_herdr.outcome.v1",
                "ask_herdr.outcome.v2",
                "ask_herdr.query.status.result.v1",
                "ask_herdr.request.v1",
                "ask_herdr.schema_document.v1",
                "ask_herdr.schema_document.v2",
                "ask_herdr.schema_document.v3",
            ],
        )
        self.assertEqual(metadata["ask_herdr.request.v1"]["semantic_version"], "1.0.0")
        self.assertEqual(metadata["ask_herdr.outcome.v1"]["semantic_version"], "1.0.0")

    def test_registered_request_and_outcome_documents_are_exact_and_valid(self):
        for schema_id in ("ask_herdr.request.v1", "ask_herdr.outcome.v1"):
            with self.subTest(schema_id=schema_id):
                completed = self.invoke("machine", "schema", "--id", schema_id)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stderr, "")
                self.assertEqual(completed.stdout.count("\n"), 1)
                wrapper = json.loads(completed.stdout)
                self.assertEqual(wrapper["schema_id"], schema_id)
                self.assertEqual(wrapper["semantic_version"], "1.0.0")
                self.assertRegex(wrapper["sha256"], r"\Asha256:[0-9a-f]{64}\Z")
                Draft202012Validator.check_schema(wrapper["document"])

    def test_v3_description_and_wrapper_validate_against_advertised_schemas(self):
        described = self.invoke("machine", "describe", "--json")
        self.assertEqual(described.returncode, 0, described.stderr)
        description = json.loads(described.stdout)

        describe_schema = self.invoke(
            "machine",
            "schema",
            "--id",
            "ask_herdr.describe.v3",
        )
        self.assertEqual(describe_schema.returncode, 0, describe_schema.stderr)
        describe_wrapper = json.loads(describe_schema.stdout)
        self.assertEqual(
            describe_wrapper["schema"],
            "ask_herdr.schema_document.v3",
        )
        self.assertEqual(describe_wrapper["semantic_version"], "3.0.0")
        Draft202012Validator.check_schema(describe_wrapper["document"])
        self.assertEqual(
            list(
                Draft202012Validator(
                    describe_wrapper["document"]
                ).iter_errors(description)
            ),
            [],
        )

        wrapper_schema = self.invoke(
            "machine",
            "schema",
            "--id",
            "ask_herdr.schema_document.v3",
        )
        self.assertEqual(wrapper_schema.returncode, 0, wrapper_schema.stderr)
        wrapper = json.loads(wrapper_schema.stdout)
        self.assertEqual(wrapper["schema"], "ask_herdr.schema_document.v3")
        self.assertEqual(wrapper["semantic_version"], "3.0.0")
        Draft202012Validator.check_schema(wrapper["document"])
        self.assertEqual(
            list(Draft202012Validator(wrapper["document"]).iter_errors(wrapper)),
            [],
        )


if __name__ == "__main__":
    unittest.main()
