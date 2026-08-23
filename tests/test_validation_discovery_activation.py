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
        self.assertEqual(result["schema"], "ask_herdr.describe.v2")
        self.assertEqual(result["cli_version"], "0.3.0")
        contract = result["machine_core_contract"]
        self.assertEqual(contract["implementation_version"], "0.3.0")
        self.assertEqual(
            contract["supported_request_versions"],
            ["ask_herdr.request.v1"],
        )
        self.assertEqual(
            contract["supported_outcome_versions"],
            ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
        )
        self.assertTrue(result["features"]["machine_validate"])
        self.assertTrue(result["features"]["machine_run"])
        self.assertFalse(result["features"]["human_facade"])
        metadata = {
            item["schema_id"]: item for item in result["schema_documents"]
        }
        self.assertEqual(
            sorted(metadata),
            [
                "ask_herdr.describe.v1",
                "ask_herdr.describe.v2",
                "ask_herdr.outcome.v1",
                "ask_herdr.outcome.v2",
                "ask_herdr.query.status.result.v1",
                "ask_herdr.request.v1",
                "ask_herdr.schema_document.v1",
                "ask_herdr.schema_document.v2",
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


if __name__ == "__main__":
    unittest.main()
