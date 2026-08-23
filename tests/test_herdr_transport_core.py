#!/usr/bin/env python3
import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_herdr_transport import (  # noqa: E402
    CommandResponse,
    DispatchIntent,
    DispatchOutcome,
    HerdrTransport,
    ProvisionIntent,
    ProvisionOutcome,
    ReceiptKind,
    ReleaseIntent,
    ReleaseOutcome,
    ReleaseScope,
    ResponseAuthority,
    RetryDisposition,
    TransportError,
    TransportErrorKind,
)


class ScriptedHerdr:
    def __init__(self, *, bootstrap_workspace=True):
        self.calls = []
        self.sessions = {
            "default": {
                "default": True,
                "name": "default",
                "running": True,
                "session_dir": "/tmp/herdr-user/default",
                "socket_path": "/tmp/herdr-user/default/herdr.sock",
            }
        }
        self.workspaces = {}
        self.tabs = {}
        self.panes = {}
        self.next_workspace = 1
        self.next_request = 1
        self.next_generation = 1
        self.bootstrap_workspace = bootstrap_workspace
        self.pane_run_mode = "accepted"
        self.replacement_on_empty = True

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv == ("session", "list", "--json"):
            return self._response({"sessions": list(self.sessions.values())})
        if argv == ("--session", "ask-pipeline", "server"):
            generation_id = f"generation-{self.next_generation:02d}"
            self.next_generation += 1
            self.sessions["ask-pipeline"] = {
                "default": False,
                "name": "ask-pipeline",
                "running": True,
                "session_dir": "/tmp/fake-herdr/ask-pipeline",
                "socket_path": "/tmp/fake-herdr/ask-pipeline/herdr.sock",
                "generation_id": generation_id,
            }
            if self.bootstrap_workspace:
                self._create_workspace("/work/project", "Workspace 1")
            return self._envelope(
                {
                    "type": "server_started",
                    "session": dict(self.sessions["ask-pipeline"]),
                }
            )
        if argv == (
            "--session",
            "ask-pipeline",
            "api",
            "snapshot",
        ):
            return self._envelope(
                {
                    "type": "snapshot",
                    "snapshot": {
                        "workspaces": list(self.workspaces.values()),
                        "tabs": list(self.tabs.values()),
                        "panes": list(self.panes.values()),
                    },
                }
            )
        if argv[:4] == (
            "--session",
            "ask-pipeline",
            "workspace",
            "create",
        ):
            cwd = argv[argv.index("--cwd") + 1]
            label = argv[argv.index("--label") + 1]
            workspace, tab, pane = self._create_workspace(cwd, label)
            return self._envelope(
                {
                    "type": "workspace_created",
                    "workspace": workspace,
                    "tab": tab,
                    "root_pane": pane,
                }
            )
        if argv[:4] == ("--session", "ask-pipeline", "pane", "run"):
            if argv[4] not in self.panes:
                raise AssertionError(f"unknown pane: {argv[4]!r}")
            if self.pane_run_mode == "unconfirmed":
                return self._response(
                    {
                        "id": f"fake-request-{self.next_request}",
                        "error": {
                            "code": "control_lost",
                            "message": "control lost after possible dispatch",
                        },
                    },
                    exit_code=1,
                )
            return self._envelope(
                {"type": "command_sent", "pane_id": argv[4]}
            )
        if argv[:4] == (
            "--session",
            "ask-pipeline",
            "workspace",
            "close",
        ):
            workspace_id = argv[4]
            if workspace_id not in self.workspaces:
                return self._response(
                    {"error": {"code": "not_found", "message": "missing"}},
                    exit_code=1,
                )
            self.workspaces.pop(workspace_id)
            self.tabs = {
                key: value
                for key, value in self.tabs.items()
                if value["workspace_id"] != workspace_id
            }
            self.panes = {
                key: value
                for key, value in self.panes.items()
                if value["workspace_id"] != workspace_id
            }
            if not self.workspaces and self.replacement_on_empty:
                self._create_workspace("/work/project", "Workspace 1")
            return self._envelope(
                {"type": "workspace_closed", "workspace_id": workspace_id}
            )
        if argv == ("session", "stop", "--json", "ask-pipeline"):
            session = self.sessions.get("ask-pipeline")
            if session is None:
                return self._response(
                    {"error": {"code": "not_found", "message": "missing"}},
                    exit_code=1,
                )
            session["running"] = False
            return self._response(
                {"session": "ask-pipeline", "status": "stopped"}
            )
        if argv == ("session", "delete", "--json", "ask-pipeline"):
            session = self.sessions.get("ask-pipeline")
            if session is None or session["running"]:
                return self._response(
                    {"error": {"code": "still_running", "message": "unsafe"}},
                    exit_code=1,
                )
            self.sessions.pop("ask-pipeline")
            self.workspaces.clear()
            self.tabs.clear()
            self.panes.clear()
            return self._response(
                {"session": "ask-pipeline", "status": "deleted"}
            )
        raise AssertionError(f"unexpected Herdr command: {argv!r}")

    def _create_workspace(self, cwd, label):
        workspace_id = f"w{self.next_workspace}"
        self.next_workspace += 1
        tab_id = f"{workspace_id}:t1"
        pane_id = f"{workspace_id}:p1"
        workspace = {"workspace_id": workspace_id, "label": label, "cwd": cwd}
        tab = {"tab_id": tab_id, "workspace_id": workspace_id}
        pane = {
            "pane_id": pane_id,
            "workspace_id": workspace_id,
            "tab_id": tab_id,
            "label": label,
            "cwd": cwd,
        }
        self.workspaces[workspace_id] = workspace
        self.tabs[tab_id] = tab
        self.panes[pane_id] = pane
        return workspace, tab, pane

    def _envelope(self, result, *, exit_code=0):
        request_id = f"fake-request-{self.next_request}"
        self.next_request += 1
        return self._response(
            {"id": request_id, "result": result}, exit_code=exit_code
        )

    @staticmethod
    def _response(payload, *, exit_code=0):
        return CommandResponse(exit_code=exit_code, stdout=json.dumps(payload))


class HerdrTransportCoreTest(unittest.TestCase):
    def test_provision_records_default_side_effect_and_adopts_only_exact_proof(self):
        runner = ScriptedHerdr()
        transport = HerdrTransport(runner)
        intent = ProvisionIntent(
            project_id="project-01",
            lane_id="lane-01",
            consultant_key="alpha",
            project_root="/work/project",
            topology_nonce="nonce-project-01-lane-01",
        )

        created = transport.provision(intent)

        self.assertEqual(created.outcome, ProvisionOutcome.CREATED)
        self.assertEqual(created.project.namespace, "ask-pipeline")
        self.assertEqual(created.project.project_id, "project-01")
        self.assertEqual(
            tuple(item.workspace_id for item in created.project.side_effects),
            ("w1",),
        )
        self.assertEqual(len(created.project.lanes), 1)
        lane = created.project.lanes[0]
        self.assertEqual(lane.lane_id, "lane-01")
        self.assertEqual(lane.consultant_key, "alpha")
        self.assertEqual(lane.workspace.workspace_id, "w2")
        self.assertEqual(lane.workspace.tab_id, "w2:t1")
        self.assertEqual(lane.workspace.pane_id, "w2:p1")
        self.assertEqual(lane.workspace.cwd, "/work/project")
        self.assertEqual(
            {receipt.kind for receipt in created.receipts},
            {
                ReceiptKind.SESSION_LIST,
                ReceiptKind.SESSION_START,
                ReceiptKind.SNAPSHOT,
                ReceiptKind.WORKSPACE_CREATE,
            },
        )
        self.assertTrue(all(receipt.receipt_digest for receipt in created.receipts))

        adopted = transport.provision(intent, known=created.project)

        self.assertEqual(adopted.outcome, ProvisionOutcome.ADOPTED)
        self.assertEqual(adopted.lane, lane)
        self.assertEqual(
            sum(call[2:4] == ("workspace", "create") for call in runner.calls),
            1,
        )

        second = transport.provision(
            ProvisionIntent(
                project_id="project-01",
                lane_id="lane-02",
                consultant_key="beta",
                project_root="/work/project",
                topology_nonce="nonce-project-01-lane-02",
            ),
            known=adopted.project,
        )
        self.assertEqual(len(second.project.lanes), 2)
        self.assertEqual(
            {item.workspace.workspace_id for item in second.project.lanes},
            {"w2", "w3"},
        )
        self.assertEqual(
            {item.workspace.pane_id for item in second.project.lanes},
            {"w2:p1", "w3:p1"},
        )
        self.assertEqual(
            tuple(item.workspace_id for item in second.project.side_effects),
            ("w1",),
        )

        runner.workspaces["w2"]["label"] = "tampered"
        create_count = sum(
            call[2:4] == ("workspace", "create") for call in runner.calls
        )
        with self.assertRaises(TransportError) as caught:
            transport.provision(intent, known=second.project)
        self.assertEqual(
            caught.exception.kind,
            TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
        )
        self.assertEqual(
            sum(call[2:4] == ("workspace", "create") for call in runner.calls),
            create_count,
        )

    def test_adoption_recomputes_ownership_label_instead_of_trusting_two_matches(self):
        runner = ScriptedHerdr()
        transport = HerdrTransport(runner)
        intent = ProvisionIntent(
            project_id="project-01",
            lane_id="lane-01",
            consultant_key="alpha",
            project_root="/work/project",
            topology_nonce="nonce-project-01-lane-01",
        )
        created = transport.provision(intent)
        forged_workspace = replace(created.lane.workspace, label="forged-match")
        forged_lane = replace(created.lane, workspace=forged_workspace)
        forged_project = replace(created.project, lanes=(forged_lane,))
        runner.workspaces[forged_workspace.workspace_id]["label"] = "forged-match"
        runner.panes[forged_workspace.pane_id]["label"] = "forged-match"

        with self.assertRaises(TransportError) as caught:
            transport.provision(intent, known=forged_project)

        self.assertEqual(
            caught.exception.kind,
            TransportErrorKind.TOPOLOGY_OWNERSHIP_MISMATCH,
        )

    def test_ambiguous_dispatch_is_never_resent_or_treated_as_completion(self):
        runner = ScriptedHerdr()
        transport = HerdrTransport(runner)
        provisioned = transport.provision(
            ProvisionIntent(
                project_id="project-01",
                lane_id="lane-01",
                consultant_key="alpha",
                project_root="/work/project",
                topology_nonce="nonce-project-01-lane-01",
            )
        )
        runner.pane_run_mode = "unconfirmed"

        dispatched = transport.dispatch(
            DispatchIntent(
                project_id="project-01",
                lane_id="lane-01",
                operation_id="operation-01",
                response_evidence_ref="evidence:response:operation-01",
                response_nonce="response-nonce-01",
                launch_command="/bound/adapter --packet evidence:packet:operation-01",
            ),
            project=provisioned.project,
        )

        self.assertEqual(dispatched.outcome, DispatchOutcome.DELIVERY_UNCONFIRMED)
        self.assertEqual(
            dispatched.retry_disposition, RetryDisposition.RECONCILE_FIRST
        )
        self.assertFalse(dispatched.resend_allowed)
        self.assertEqual(
            dispatched.response_expectation.authority,
            ResponseAuthority.DURABLE_RESPONSE_AND_TERMINAL_MARKER,
        )
        self.assertEqual(
            dispatched.response_expectation.terminal_marker,
            "<<<ASK_HERDR_RESPONSE_COMPLETE:operation-01:response-nonce-01>>>",
        )
        self.assertEqual(
            dispatched.response_expectation.response_evidence_ref,
            "evidence:response:operation-01",
        )
        pane_runs = [
            call for call in runner.calls if call[2:4] == ("pane", "run")
        ]
        self.assertEqual(len(pane_runs), 1)
        self.assertEqual(pane_runs[0][4], provisioned.lane.workspace.pane_id)
        self.assertNotIn(
            dispatched.response_expectation.terminal_marker, pane_runs[0][-1]
        )
        self.assertNotIn(
            dispatched.response_expectation.response_evidence_ref,
            pane_runs[0][-1],
        )
        self.assertEqual(runner.calls[-1], pane_runs[0])
        self.assertEqual(dispatched.receipts[-1].kind, ReceiptKind.PANE_RUN)
        self.assertEqual(dispatched.receipts[-1].error_code, "control_lost")
        self.assertEqual(
            dispatched.receipts[-1].authority.value,
            "advisory",
        )

    def test_workspace_release_closes_exact_lane_and_records_default_side_effect(self):
        runner = ScriptedHerdr(bootstrap_workspace=False)
        transport = HerdrTransport(runner)
        provisioned = transport.provision(
            ProvisionIntent(
                project_id="project-01",
                lane_id="lane-01",
                consultant_key="alpha",
                project_root="/work/project",
                topology_nonce="nonce-project-01-lane-01",
            )
        )

        released = transport.release(
            ReleaseIntent(
                project_id="project-01",
                operation_id="release-operation-01",
                scope=ReleaseScope.WORKSPACE,
                lane_ids=("lane-01",),
                side_effect_workspace_ids=(),
            ),
            project=provisioned.project,
        )

        self.assertEqual(released.outcome, ReleaseOutcome.WORKSPACE_RELEASED)
        self.assertEqual(released.released_lane_ids, ("lane-01",))
        self.assertEqual(
            released.released_workspace_ids,
            (provisioned.lane.workspace.workspace_id,),
        )
        self.assertIsNotNone(released.project)
        self.assertEqual(released.project.lanes, ())
        self.assertEqual(len(released.project.side_effects), 1)
        replacement = released.project.side_effects[0]
        self.assertEqual(replacement.workspace_id, "w2")
        self.assertEqual(replacement.label, "Workspace 1")
        self.assertEqual(
            replacement.creation_receipt_digest,
            next(
                item.receipt_digest
                for item in released.receipts
                if item.kind is ReceiptKind.WORKSPACE_CLOSE
            ),
        )
        closes = [
            call for call in runner.calls if call[2:4] == ("workspace", "close")
        ]
        self.assertEqual(
            closes,
            [
                (
                    "--session",
                    "ask-pipeline",
                    "workspace",
                    "close",
                    provisioned.lane.workspace.workspace_id,
                )
            ],
        )
        self.assertNotIn(("session", "stop", "--json", "ask-pipeline"), runner.calls)
        self.assertNotIn(("session", "delete", "--json", "ask-pipeline"), runner.calls)
        self.assertNotIn(("session", "stop", "--json", "default"), runner.calls)

    def test_session_release_requires_complete_project_owned_live_set(self):
        runner = ScriptedHerdr()
        transport = HerdrTransport(runner)
        first = transport.provision(
            ProvisionIntent(
                project_id="project-01",
                lane_id="lane-01",
                consultant_key="alpha",
                project_root="/work/project",
                topology_nonce="nonce-project-01-lane-01",
            )
        )
        second = transport.provision(
            ProvisionIntent(
                project_id="project-01",
                lane_id="lane-02",
                consultant_key="beta",
                project_root="/work/project",
                topology_nonce="nonce-project-01-lane-02",
            ),
            known=first.project,
        )
        side_effect_ids = tuple(
            sorted(item.workspace_id for item in second.project.side_effects)
        )

        released = transport.release(
            ReleaseIntent(
                project_id="project-01",
                operation_id="release-operation-all",
                scope=ReleaseScope.SESSION,
                lane_ids=("lane-01", "lane-02"),
                side_effect_workspace_ids=side_effect_ids,
            ),
            project=second.project,
        )

        self.assertEqual(released.outcome, ReleaseOutcome.SESSION_RELEASED)
        self.assertEqual(released.released_lane_ids, ("lane-01", "lane-02"))
        self.assertEqual(
            set(released.released_workspace_ids),
            {"w1", "w2", "w3"},
        )
        self.assertIsNone(released.project)
        self.assertIn(("session", "stop", "--json", "ask-pipeline"), runner.calls)
        self.assertIn(("session", "delete", "--json", "ask-pipeline"), runner.calls)
        self.assertFalse(
            any(call[2:4] == ("workspace", "close") for call in runner.calls)
        )
        self.assertFalse(any(call[-1:] == ("default",) for call in runner.calls))
        self.assertIn("default", runner.sessions)
        self.assertTrue(runner.sessions["default"]["running"])
        self.assertNotIn("ask-pipeline", runner.sessions)

        guarded_runner = ScriptedHerdr()
        guarded_transport = HerdrTransport(guarded_runner)
        guarded = guarded_transport.provision(
            ProvisionIntent(
                project_id="project-02",
                lane_id="lane-guarded",
                consultant_key="guarded",
                project_root="/work/project",
                topology_nonce="nonce-project-02-lane-guarded",
            )
        )
        guarded_runner._create_workspace("/foreign", "foreign-unowned")
        with self.assertRaises(TransportError) as caught:
            guarded_transport.release(
                ReleaseIntent(
                    project_id="project-02",
                    operation_id="release-operation-guarded",
                    scope=ReleaseScope.SESSION,
                    lane_ids=("lane-guarded",),
                    side_effect_workspace_ids=tuple(
                        item.workspace_id for item in guarded.project.side_effects
                    ),
                ),
                project=guarded.project,
            )
        self.assertEqual(
            caught.exception.kind,
            TransportErrorKind.RELEASE_OWNERSHIP_MISMATCH,
        )
        self.assertNotIn(
            ("session", "stop", "--json", "ask-pipeline"),
            guarded_runner.calls,
        )
        self.assertNotIn(
            ("session", "delete", "--json", "ask-pipeline"),
            guarded_runner.calls,
        )


if __name__ == "__main__":
    unittest.main()
