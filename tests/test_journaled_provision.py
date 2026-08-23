#!/usr/bin/env python3
"""RED acceptance for journaled, fake-Herdr provisioning."""

from __future__ import annotations

from dataclasses import fields
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

import ask_herdr_journaled_provision as journaled  # noqa: E402
from ask_herdr_journaled_provision import (  # noqa: E402
    JournaledProvisionError,
    JournaledProvisionOutcome,
    JournaledProvisionRequest,
    lane_workspace_binding_digest,
    provision_journaled,
    provision_postcondition_digest,
)
from ask_herdr_herdr_transport import ProvisionIntent  # noqa: E402
from ask_herdr_topology_store import (  # noqa: E402
    TopologyMutationIntent,
    TopologyStoreMutationResult,
    ValidatedTopologyStoreBinding,
    inspect_topology_store,
)
from tests.test_herdr_transport_core import ScriptedHerdr  # noqa: E402


AUTHORITY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
MUTATION_ID = "11111111-1111-4111-8111-111111111111"
OPERATION_ID = "22222222-2222-4222-8222-222222222222"
LANE_ID = "33333333-3333-4333-8333-333333333333"
SESSION_STEP_ID = "44444444-4444-4444-8444-444444444444"
WORKSPACE_STEP_ID = "55555555-5555-4555-8555-555555555555"


def _binding(root: Path) -> ValidatedTopologyStoreBinding:
    metadata = root.stat()
    return ValidatedTopologyStoreBinding(
        canonical_project_root=str(root),
        filesystem_device=metadata.st_dev,
        filesystem_inode=metadata.st_ino,
        owner_uid=metadata.st_uid,
        project_authority_id=AUTHORITY_ID,
        namespace="ask-pipeline",
    )


def _request(root: Path) -> JournaledProvisionRequest:
    workspace = root / "lane-workspaces" / LANE_ID
    provision = ProvisionIntent(
        project_id="project-01",
        lane_id=LANE_ID,
        consultant_key="alpha",
        project_root=str(root),
        topology_nonce="topology-nonce-01",
        lane_workspace_cwd=str(workspace),
    )
    mutation = TopologyMutationIntent(
        mutation_id=MUTATION_ID,
        operation_id=OPERATION_ID,
        canonical_request_digest="sha256:" + "1" * 64,
        policy_record_digest="sha256:" + "2" * 64,
        lane_state_digest="sha256:" + "3" * 64,
        lane_id=LANE_ID,
        lane_generation=1,
        lane_binding_digest="sha256:" + "4" * 64,
        lane_workspace_binding_digest=lane_workspace_binding_digest(
            _binding(root),
            provision,
        ),
        consultant_key="alpha",
        topology_nonce="topology-nonce-01",
        lane_workspace_cwd=str(workspace),
        prior_topology_digest=None,
        intended_action="reconcile_or_provision",
        precondition_digest="sha256:" + "5" * 64,
        expected_postcondition_digest=provision_postcondition_digest(provision),
    )
    return JournaledProvisionRequest(
        store_binding=_binding(root),
        mutation_intent=mutation,
        provision_intent=provision,
        session_start_step_id=SESSION_STEP_ID,
        workspace_create_step_id=WORKSPACE_STEP_ID,
    )


def _event_kinds(root: Path) -> tuple[str, ...]:
    transactions = root / ".ask-herdr-topology" / "transactions"
    return tuple(
        json.loads(path.read_text(encoding="utf-8"))["event_kind"]
        for path in sorted(transactions.glob("event.*.txn/record.json"))
    )


def _is_server_start(argv: tuple[str, ...]) -> bool:
    return argv == ("--session", "ask-pipeline", "server")


def _is_workspace_create(argv: tuple[str, ...]) -> bool:
    return argv[:4] == (
        "--session",
        "ask-pipeline",
        "workspace",
        "create",
    )


class ProjectScriptedHerdr(ScriptedHerdr):
    def __init__(self, project_root: str) -> None:
        super().__init__()
        self.project_root = project_root
        self.before_mutation = None

    def __call__(self, argv):
        argv = tuple(argv)
        if (_is_server_start(argv) or _is_workspace_create(argv)) and self.before_mutation:
            self.before_mutation(argv)
        response = super().__call__(argv)
        if _is_server_start(argv):
            for workspace in self.workspaces.values():
                workspace["cwd"] = self.project_root
            for pane in self.panes.values():
                pane["cwd"] = self.project_root
        return response


class JournaledProvisionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ask-herdr-journaled-provision-",
            dir="/private/tmp",
        )
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        (self.root / "lane-workspaces" / LANE_ID).mkdir(parents=True, mode=0o700)
        self.request = _request(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_happy_path_is_write_ahead_and_settlement_is_last(self):
        runner = ProjectScriptedHerdr(str(self.root))
        boundary_events = []
        runner.before_mutation = lambda argv: boundary_events.append(
            (argv, _event_kinds(self.root))
        )

        result = provision_journaled(self.request, runner=runner)

        self.assertEqual(result.outcome, JournaledProvisionOutcome.CREATED_EPHEMERAL)
        self.assertEqual(result.provision.lane.workspace.cwd, str(self.root / "lane-workspaces" / LANE_ID))
        self.assertEqual(
            boundary_events[0][1],
            ("mutation_intent", "command_intent"),
        )
        self.assertEqual(
            boundary_events[1][1],
            (
                "mutation_intent",
                "command_intent",
                "command_receipt",
                "command_intent",
            ),
        )
        self.assertEqual(
            _event_kinds(self.root),
            (
                "mutation_intent",
                "command_intent",
                "command_receipt",
                "command_intent",
                "command_receipt",
                "mutation_settlement",
            ),
        )
        self.assertEqual(inspect_topology_store(_binding(self.root)).status, "active")

    def test_command_intent_failure_invokes_no_mutating_runner(self):
        runner = ProjectScriptedHerdr(str(self.root))
        failed = TopologyStoreMutationResult(
            "topology_store_reconciliation_required",
            "topology_store.writer_busy",
        )

        with mock.patch.object(journaled, "commit_command_intent", return_value=failed):
            with self.assertRaises(JournaledProvisionError) as caught:
                provision_journaled(self.request, runner=runner)

        self.assertEqual(caught.exception.detail_code, "topology_store.writer_busy")
        self.assertFalse(any(_is_server_start(call) for call in runner.calls))
        self.assertFalse(any(_is_workspace_create(call) for call in runner.calls))

    def test_mutate_then_throw_stops_and_restart_never_resends(self):
        class ThrowAfterStart(ProjectScriptedHerdr):
            def __call__(self, argv):
                response = super().__call__(argv)
                if _is_server_start(tuple(argv)):
                    raise RuntimeError("control lost after possible effect")
                return response

        runner = ThrowAfterStart(str(self.root))
        with self.assertRaises(JournaledProvisionError) as caught:
            provision_journaled(self.request, runner=runner)

        self.assertTrue(caught.exception.reconciliation_required)
        self.assertFalse(caught.exception.resend_allowed)
        self.assertEqual(sum(_is_server_start(call) for call in runner.calls), 1)
        self.assertEqual(sum(_is_workspace_create(call) for call in runner.calls), 0)
        self.assertEqual(inspect_topology_store(_binding(self.root)).status, "reconciliation_required")

        before = tuple(runner.calls)
        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)
        self.assertEqual(tuple(runner.calls), before)

    def test_receipt_store_failure_after_start_forbids_workspace_create(self):
        runner = ProjectScriptedHerdr(str(self.root))
        failed = TopologyStoreMutationResult(
            "topology_store_quarantined",
            "topology_store.publication_unverified",
        )

        with mock.patch.object(journaled, "commit_command_receipt", return_value=failed):
            with self.assertRaises(JournaledProvisionError):
                provision_journaled(self.request, runner=runner)

        self.assertEqual(sum(_is_server_start(call) for call in runner.calls), 1)
        self.assertEqual(sum(_is_workspace_create(call) for call in runner.calls), 0)
        self.assertEqual(inspect_topology_store(_binding(self.root)).status, "reconciliation_required")

    def test_wrong_session_start_result_type_cannot_mint_topology_authority(self):
        class WrongStartType(ProjectScriptedHerdr):
            def __call__(self, argv):
                response = super().__call__(argv)
                if _is_server_start(tuple(argv)):
                    payload = json.loads(response.stdout)
                    payload["result"]["type"] = "not_server_started"
                    return type(response)(
                        exit_code=response.exit_code,
                        stdout=json.dumps(payload),
                        stderr=response.stderr,
                    )
                return response

        runner = WrongStartType(str(self.root))

        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)

        self.assertEqual(sum(_is_server_start(call) for call in runner.calls), 1)
        self.assertEqual(sum(_is_workspace_create(call) for call in runner.calls), 0)
        self.assertNotIn("command_receipt", _event_kinds(self.root))
        self.assertNotIn("mutation_settlement", _event_kinds(self.root))
        self.assertEqual(
            inspect_topology_store(_binding(self.root)).status,
            "reconciliation_required",
        )

    def test_post_start_foreign_session_substitution_cannot_settle(self):
        class SubstitutedSession(ProjectScriptedHerdr):
            def __call__(self, argv):
                argv = tuple(argv)
                if _is_server_start(argv):
                    self.calls.append(argv)
                    foreign = {
                        "default": False,
                        "name": "ask-pipeline",
                        "running": True,
                        "session_dir": "/tmp/foreign/ask-pipeline",
                        "socket_path": "/tmp/foreign/ask-pipeline/herdr.sock",
                        "generation_id": "foreign-generation-01",
                    }
                    self.sessions["ask-pipeline"] = foreign
                    self._create_workspace(self.project_root, "Workspace 1")
                    return self._envelope(
                        {
                            "type": "server_started",
                            "session": {
                                "default": False,
                                "name": "ask-pipeline",
                                "running": True,
                                "session_dir": "/tmp/fake-herdr/ask-pipeline",
                                "socket_path": "/tmp/fake-herdr/ask-pipeline/herdr.sock",
                                "generation_id": "start-generation-01",
                            },
                        }
                    )
                return super().__call__(argv)

        runner = SubstitutedSession(str(self.root))

        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)

        self.assertEqual(sum(_is_server_start(call) for call in runner.calls), 1)
        self.assertEqual(sum(_is_workspace_create(call) for call in runner.calls), 0)
        self.assertNotIn("command_receipt", _event_kinds(self.root))
        self.assertNotIn("mutation_settlement", _event_kinds(self.root))
        self.assertEqual(
            inspect_topology_store(_binding(self.root)).status,
            "reconciliation_required",
        )

    def test_start_receipt_and_live_session_must_both_prove_running_true(self):
        for source, value in (
            ("receipt", False),
            ("receipt", None),
            ("live", False),
            ("live", None),
        ):
            with self.subTest(source=source, value=value), tempfile.TemporaryDirectory(
                prefix="ask-herdr-start-running-",
                dir="/private/tmp",
            ) as temporary:
                root = Path(temporary).resolve()
                os.chmod(root, 0o700)
                (root / "lane-workspaces" / LANE_ID).mkdir(
                    parents=True,
                    mode=0o700,
                )

                class ContradictoryRunning(ProjectScriptedHerdr):
                    def __call__(self, argv):
                        response = super().__call__(argv)
                        if _is_server_start(tuple(argv)):
                            if source == "receipt":
                                payload = json.loads(response.stdout)
                                session = payload["result"]["session"]
                                if value is None:
                                    session.pop("running")
                                else:
                                    session["running"] = value
                                return type(response)(
                                    exit_code=response.exit_code,
                                    stdout=json.dumps(payload),
                                    stderr=response.stderr,
                                )
                            session = self.sessions["ask-pipeline"]
                            if value is None:
                                session.pop("running")
                            else:
                                session["running"] = value
                        return response

                runner = ContradictoryRunning(str(root))
                with self.assertRaises(JournaledProvisionError):
                    provision_journaled(_request(root), runner=runner)

                self.assertEqual(
                    sum(_is_workspace_create(call) for call in runner.calls),
                    0,
                )
                self.assertNotIn("command_receipt", _event_kinds(root))
                self.assertNotIn("mutation_settlement", _event_kinds(root))

    def test_symlink_lane_workspace_is_rejected_before_any_runner_call(self):
        workspace = self.root / "lane-workspaces" / LANE_ID
        workspace.rmdir()
        workspace.symlink_to(self.root, target_is_directory=True)
        runner = ProjectScriptedHerdr(str(self.root))

        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)

        self.assertEqual(runner.calls, [])
        self.assertFalse((self.root / ".ask-herdr-topology").exists())

    def test_lane_authority_and_workspace_identity_are_distinct_durable_fields(self):
        mutation_fields = {
            field.name for field in fields(TopologyMutationIntent)
        }

        self.assertIn("lane_binding_digest", mutation_fields)
        self.assertIn("lane_workspace_binding_digest", mutation_fields)

    def test_workspace_digest_rejects_parent_named_entry_swap(self):
        parent = self.root / "lane-workspaces"
        backup = self.root / "lane-workspaces.original"
        real_stat = journaled.os.stat
        swapped = False

        def racing_stat(path, *args, **kwargs):
            nonlocal swapped
            if (
                not swapped
                and path == "lane-workspaces"
                and kwargs.get("dir_fd") is not None
            ):
                parent.rename(backup)
                parent.mkdir(mode=0o700)
                (parent / LANE_ID).mkdir(mode=0o700)
                swapped = True
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(journaled.os, "stat", side_effect=racing_stat):
            with self.assertRaises(ValueError):
                lane_workspace_binding_digest(
                    self.request.store_binding,
                    self.request.provision_intent,
                )

        self.assertTrue(swapped)

    def test_lane_workspace_swap_during_effect_never_confirms_or_settles(self):
        runner = ProjectScriptedHerdr(str(self.root))
        workspace = self.root / "lane-workspaces" / LANE_ID
        backup = self.root / "lane-workspaces" / (LANE_ID + ".original")

        def swap_before_workspace(argv):
            if _is_workspace_create(argv):
                workspace.rename(backup)
                workspace.symlink_to(self.root, target_is_directory=True)

        runner.before_mutation = swap_before_workspace

        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)

        self.assertEqual(sum(_is_workspace_create(call) for call in runner.calls), 1)
        self.assertNotIn("mutation_settlement", _event_kinds(self.root))
        self.assertEqual(
            inspect_topology_store(_binding(self.root)).status,
            "reconciliation_required",
        )

    def test_lane_workspace_is_revalidated_after_final_proof_before_settlement(self):
        runner = ProjectScriptedHerdr(str(self.root))
        workspace = self.root / "lane-workspaces" / LANE_ID
        backup = self.root / "lane-workspaces" / (LANE_ID + ".original")
        real_digest = journaled.project_topology_digest

        def digest_then_swap(project):
            digest = real_digest(project)
            workspace.rename(backup)
            workspace.symlink_to(self.root, target_is_directory=True)
            return digest

        with mock.patch.object(
            journaled,
            "project_topology_digest",
            side_effect=digest_then_swap,
        ):
            with self.assertRaises(JournaledProvisionError):
                provision_journaled(self.request, runner=runner)

        self.assertNotIn("mutation_settlement", _event_kinds(self.root))
        self.assertEqual(
            inspect_topology_store(_binding(self.root)).status,
            "reconciliation_required",
        )

    def test_final_snapshot_drift_never_settles(self):
        class DriftAfterCreate(ProjectScriptedHerdr):
            def __call__(self, argv):
                response = super().__call__(argv)
                if _is_workspace_create(tuple(argv)):
                    created = max(self.workspaces)
                    self.workspaces[created]["label"] = "foreign-label"
                    self.panes[f"{created}:p1"]["label"] = "foreign-label"
                return response

        runner = DriftAfterCreate(str(self.root))
        with self.assertRaises(JournaledProvisionError):
            provision_journaled(self.request, runner=runner)

        self.assertNotIn("mutation_settlement", _event_kinds(self.root))
        inspection = inspect_topology_store(_binding(self.root))
        self.assertEqual(inspection.status, "reconciliation_required")
        self.assertIsNone(inspection.trust_seed)

    def test_settled_ephemeral_result_is_not_restart_adopted_without_durable_proof(self):
        runner = ProjectScriptedHerdr(str(self.root))
        provision_journaled(self.request, runner=runner)
        before = tuple(runner.calls)

        with self.assertRaises(JournaledProvisionError) as caught:
            provision_journaled(self.request, runner=runner)

        self.assertEqual(
            caught.exception.detail_code,
            "journaled_provision.project_topology_proof_unavailable",
        )
        self.assertTrue(caught.exception.reconciliation_required)
        self.assertFalse(caught.exception.resend_allowed)
        self.assertEqual(tuple(runner.calls), before)


if __name__ == "__main__":
    unittest.main()
