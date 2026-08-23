#!/usr/bin/env python3
"""Provider-free contract tests for the complete operation metadata matrix."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_operation_contract import (  # noqa: E402
    OPERATION_CONTRACTS,
    OPERATION_NAMES,
    get_operation_contract,
)


EXPECTED_OPERATIONS = {
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
}

PUBLIC_READ = {
    "query.status",
    "system.preflight",
    "profile.list",
    "profile.show",
    "profile.check",
    "profile.auth.status",
    "cleanup.status",
    "policy.show",
    "policy.status",
    "policy.validate",
}
EVIDENCE_CONTENT_READ = {"query.result", "query.evidence"}
GRANT_OR_HUMAN = {
    "turn.answer",
    "turn.consult",
    "turn.recovery_continue",
    "turn.review",
    "turn.safe_retry",
    "topology.release.workspace.execute",
    "topology.release.workspace.preview",
    "topology.release.workspace.resume",
}

IMMEDIATE_ONLY = {
    "cleanup.preview",
    "cleanup.status",
    "policy.activate.preview",
    "policy.compact.preview",
    "policy.show",
    "policy.status",
    "policy.validate",
    "profile.auth.status",
    "profile.check",
    "profile.list",
    "profile.show",
    "project.init",
    "project.rebind.preview",
    "project.retire.preview",
    "query.evidence",
    "recovery.retire.lane.preview",
    "recovery.retire.namespace.preview",
    "system.preflight",
    "topology.release.session.preview",
    "topology.release.workspace.preview",
}


class OperationContractMatrixTest(unittest.TestCase):
    def test_matrix_covers_the_exact_advertised_operation_set(self):
        self.assertEqual(len(EXPECTED_OPERATIONS), 45)
        self.assertEqual(set(OPERATION_CONTRACTS), EXPECTED_OPERATIONS)

        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "bin" / "ask-herdr"),
                "machine",
                "describe",
                "--json",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        advertised = json.loads(completed.stdout)["machine_core_contract"][
            "operations"
        ]
        self.assertEqual(tuple(advertised), OPERATION_NAMES)

    def test_every_operation_has_a_deterministic_payload_schema_id(self):
        for operation, contract in OPERATION_CONTRACTS.items():
            self.assertEqual(
                contract.payload_schema_id,
                f"ask_herdr.{operation}.payload.v1",
            )

    def test_authority_classes_are_complete_and_non_overlapping(self):
        expected_by_authority = {
            "public_read": PUBLIC_READ,
            "evidence_content_read": EVIDENCE_CONTENT_READ,
            "grant_or_human": GRANT_OR_HUMAN,
            "bootstrap_human_only": {"project.init"},
            "direct_human_only": EXPECTED_OPERATIONS
            - PUBLIC_READ
            - EVIDENCE_CONTENT_READ
            - GRANT_OR_HUMAN
            - {"project.init"},
        }
        actual_by_authority = {
            authority: {
                operation
                for operation, contract in OPERATION_CONTRACTS.items()
                if contract.authority_class == authority
            }
            for authority in expected_by_authority
        }
        self.assertEqual(actual_by_authority, expected_by_authority)

    def test_action_reasons_follow_the_closed_operation_families(self):
        expected = {}
        expected.update({operation: ("inspect",) for operation in PUBLIC_READ})
        expected.update(
            {operation: ("inspect",) for operation in EVIDENCE_CONTENT_READ}
        )
        expected.update(
            {
                "turn.consult": ("initial",),
                "turn.answer": (
                    "clarification_answer",
                    "review_clarification_answer",
                ),
                "turn.review": ("review_fork",),
                "turn.safe_retry": ("safe_retry",),
                "turn.recovery_continue": ("recovery_continuation",),
            }
        )
        for operation in EXPECTED_OPERATIONS:
            if operation.startswith("topology.release."):
                expected[operation] = ("release",)
            elif operation.startswith("recovery."):
                expected[operation] = ("recover",)
            elif operation.startswith("process.interrupt."):
                expected[operation] = ("interrupt",)
            elif operation.startswith("cleanup.") and operation != "cleanup.status":
                expected[operation] = ("cleanup",)
            elif operation.startswith("project."):
                expected[operation] = ("project_admin",)
            elif operation.startswith("policy.") and operation not in {
                "policy.show",
                "policy.status",
                "policy.validate",
            }:
                expected[operation] = ("policy_admin",)
            elif operation in {"profile.auth.login", "profile.auth.logout"}:
                expected[operation] = ("authentication",)

        self.assertEqual(
            {
                operation: contract.allowed_action_reasons
                for operation, contract in OPERATION_CONTRACTS.items()
            },
            expected,
        )

    def test_project_bindings_are_closed_by_operation(self):
        for operation, contract in OPERATION_CONTRACTS.items():
            if operation == "project.init":
                expected = ("candidate",)
            elif operation == "system.preflight":
                expected = ("bound", "candidate")
            else:
                expected = ("bound",)
            self.assertEqual(contract.allowed_project_bindings, expected)

    def test_observation_modes_are_closed_by_operation(self):
        for operation, contract in OPERATION_CONTRACTS.items():
            if operation in IMMEDIATE_ONLY:
                expected = ("immediate",)
            elif operation in {"query.status", "query.result"}:
                expected = ("immediate", "wait")
            else:
                expected = ("submit_only", "wait")
            self.assertEqual(contract.allowed_observation_modes, expected)

    def test_unknown_operation_is_rejected(self):
        with self.assertRaises(KeyError):
            get_operation_contract("turn.unknown")


if __name__ == "__main__":
    unittest.main()
