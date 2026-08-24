#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_platform import runtime_platform  # noqa: E402

EXPECTED_OPERATIONS = sorted(
    [
        "cleanup.execute",
        "cleanup.preview",
        "cleanup.resume",
        "cleanup.status",
        "policy.activate.execute",
        "policy.activate.preview",
        "policy.compact.execute",
        "policy.compact.preview",
        "policy.show",
        "policy.status",
        "policy.validate",
        "process.interrupt.force",
        "process.interrupt.graceful",
        "profile.auth.login",
        "profile.auth.logout",
        "profile.auth.status",
        "profile.check",
        "profile.list",
        "profile.show",
        "project.init",
        "project.rebind.execute",
        "project.rebind.preview",
        "project.retire.execute",
        "project.retire.preview",
        "query.evidence",
        "query.result",
        "query.status",
        "recovery.rebuild_topology",
        "recovery.reconcile",
        "recovery.retire.lane.execute",
        "recovery.retire.lane.preview",
        "recovery.retire.namespace.execute",
        "recovery.retire.namespace.preview",
        "system.preflight",
        "topology.release.session.execute",
        "topology.release.session.preview",
        "topology.release.session.resume",
        "topology.release.workspace.execute",
        "topology.release.workspace.preview",
        "topology.release.workspace.resume",
        "turn.answer",
        "turn.consult",
        "turn.recovery_continue",
        "turn.review",
        "turn.safe_retry",
    ]
)

EXPECTED_ACTION_REASONS = sorted(
    [
        "authentication",
        "clarification_answer",
        "cleanup",
        "initial",
        "inspect",
        "interrupt",
        "policy_admin",
        "project_admin",
        "recover",
        "recovery_continuation",
        "release",
        "review_clarification_answer",
        "review_fork",
        "safe_retry",
    ]
)


class ContractDiscoveryTest(unittest.TestCase):
    def test_machine_describe_is_static_complete_and_provider_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            fake_bin = sandbox / "bin"
            fake_bin.mkdir()
            herdr_log = sandbox / "herdr-called"
            fake_herdr = fake_bin / "herdr"
            fake_herdr.write_text(
                "#!/bin/sh\nprintf called > \"$ASK_HERDR_DISCOVERY_HERDR_LOG\"\nexit 99\n",
                encoding="utf-8",
            )
            fake_herdr.chmod(0o700)
            environment = dict(os.environ)
            environment["PATH"] = str(fake_bin)
            environment["ASK_HERDR_DISCOVERY_HERDR_LOG"] = str(herdr_log)

            completed = subprocess.run(
                [sys.executable, str(CLI), "machine", "describe", "--json"],
                cwd=sandbox,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stderr, "")
            self.assertEqual(completed.stdout.count("\n"), 1)
            result = json.loads(completed.stdout)
            self.assertEqual(result["schema"], "ask_herdr.describe.v3")
            self.assertEqual(result["cli_version"], "0.4.0")
            self.assertEqual(
                result["machine_core_contract"]["implementation_version"],
                "0.4.0",
            )
            self.assertEqual(
                result["machine_core_contract"]["supported_request_versions"],
                ["ask_herdr.request.v1"],
            )
            self.assertEqual(
                result["machine_core_contract"]["supported_outcome_versions"],
                ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
            )
            self.assertEqual(
                result["machine_core_contract"]["operations"],
                EXPECTED_OPERATIONS,
            )
            self.assertEqual(
                result["machine_core_contract"]["action_reasons"],
                EXPECTED_ACTION_REASONS,
            )
            self.assertEqual(
                result["machine_core_contract"]["lane_origin_reasons"],
                sorted(
                    [
                        "comment",
                        "consult",
                        "diagnose",
                        "other",
                        "plan",
                        "review",
                        "suggest",
                        "verify",
                    ]
                ),
            )
            self.assertEqual(
                result["exit_classes"],
                [
                    {"code": 0, "meaning": "handled"},
                    {"code": 10, "meaning": "human_input_required"},
                    {"code": 20, "meaning": "not_admitted"},
                    {"code": 30, "meaning": "settled_runtime_failure"},
                    {"code": 40, "meaning": "observation_or_reconciliation"},
                    {"code": 50, "meaning": "quarantine_or_ownership_failure"},
                    {"code": 64, "meaning": "usage_or_invalid_request"},
                    {"code": 76, "meaning": "policy_deferral"},
                ],
            )
            self.assertEqual(
                result["limits"],
                {
                    "batch_children_max": 3,
                    "batch_children_min": 2,
                    "clarification_bytes_max": 1048576,
                    "evidence_range_bytes_max": 1048576,
                    "human_evidence_whole_bytes_max": 8388608,
                    "material_files_max": 10000,
                    "material_total_bytes_max": 2147483648,
                    "metadata_page_limit_max": 200,
                    "metadata_page_limit_human_default": 50,
                    "outcome_serialized_bytes_max": 33554432,
                    "provider_terminal_envelope_bytes_max": 16777216,
                    "provider_transaction_temporary_bytes_max": 134217728,
                    "request_envelope_bytes_max": 8388608,
                    "status_read_epoch_attempt_limit": 3,
                    "turn_final_bytes_max": 8388608,
                },
            )
            self.assertEqual(
                result["capability_vocabulary"],
                {
                    "manifest_sources": ["capabilities_file", "review_readonly"],
                    "network_modes": ["full", "none", "web"],
                    "path_scopes": ["object", "subtree"],
                },
            )
            profiles = result["launcher_profile_registry"]["profiles"]
            self.assertEqual(
                [profile["profile"] for profile in profiles],
                [
                    "claude/cc-claude",
                    "claude/claude",
                    "codex/codex",
                    "deepseek/cc-deepseek",
                ],
            )
            self.assertTrue(result["features"]["machine_describe"])
            self.assertTrue(result["features"]["machine_schema"])
            self.assertTrue(result["features"]["machine_validate"])
            self.assertTrue(result["features"]["machine_run"])
            self.assertFalse(result["features"]["human_facade"])
            self.assertEqual(result["runtime_platform"], runtime_platform())
            self.assertEqual(
                [item["schema_id"] for item in result["schema_documents"]],
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
            for schema_document in result["schema_documents"]:
                self.assertRegex(
                    schema_document["sha256"],
                    r"^sha256:[0-9a-f]{64}$",
                )
            self.assertFalse(herdr_log.exists())
            self.assertFalse((sandbox / ".ask-herdr").exists())

    def test_machine_schema_returns_the_exact_bundled_document(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "machine",
                "schema",
                "--id",
                "ask_herdr.describe.v1",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout.count("\n"), 1)
        result = json.loads(completed.stdout)
        self.assertEqual(set(result), {"schema", "schema_id", "semantic_version", "sha256", "document"})
        self.assertEqual(result["schema"], "ask_herdr.schema_document.v1")
        self.assertEqual(result["schema_id"], "ask_herdr.describe.v1")
        self.assertEqual(result["semantic_version"], "1.0.0")
        self.assertEqual(
            result["sha256"],
            "sha256:2360d64451b5e7cca99dc7d842d3c33e8bbdd2545d6b53ec6e581bb3aabc0404",
        )
        self.assertEqual(result["document"]["type"], "object")
        self.assertFalse(result["document"]["additionalProperties"])
        self.assertEqual(
            set(result["document"]["required"]),
            {
                "capability_vocabulary",
                "cli_version",
                "exit_classes",
                "features",
                "launcher_profile_registry",
                "limits",
                "machine_core_contract",
                "schema",
                "schema_documents",
            },
        )


if __name__ == "__main__":
    unittest.main()
