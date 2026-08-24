#!/usr/bin/env python3
"""Contract tests for Codex and Claude Code Ask-Herdr onboarding."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
AGENT_INSTRUCTIONS = ROOT / "AGENTS.md"
CLAUDE_INSTRUCTIONS = ROOT / "CLAUDE.md"
CANONICAL_SKILL = ROOT / ".agents" / "skills" / "ask-herdr" / "SKILL.md"
CLAUDE_SKILL = ROOT / ".claude" / "skills" / "ask-herdr" / "SKILL.md"
QUICK_START = ROOT / "docs" / "public-beta-getting-started.md"
PUBLIC_CONTRACT = ROOT / "docs" / "public-beta-query-status.md"


class AgentOnboardingTest(unittest.TestCase):
    def test_skill_frontmatter_is_complete_and_bounded(self):
        for skill_path in (CANONICAL_SKILL, CLAUDE_SKILL):
            content = skill_path.read_text(encoding="utf-8")
            match = re.match(r"\A---\n(?P<header>.*?)\n---\n", content, re.DOTALL)
            self.assertIsNotNone(match, skill_path)
            fields = {}
            for line in match.group("header").splitlines():
                key, separator, value = line.partition(":")
                self.assertEqual(separator, ":", line)
                fields[key] = value.strip()

            self.assertEqual(set(fields), {"name", "description"})
            self.assertEqual(fields["name"], "ask-herdr")
            self.assertRegex(fields["name"], r"\A[a-z0-9-]+\Z")
            self.assertLessEqual(len(fields["name"]), 64)
            self.assertTrue(fields["description"])
            self.assertLessEqual(len(fields["description"]), 1024)
            self.assertNotIn("[TODO:", content)

    def test_codex_and_claude_route_to_one_canonical_workflow(self):
        agents = AGENT_INSTRUCTIONS.read_text(encoding="utf-8")
        claude = CLAUDE_INSTRUCTIONS.read_text(encoding="utf-8")
        canonical = CANONICAL_SKILL.read_text(encoding="utf-8")
        adapter = CLAUDE_SKILL.read_text(encoding="utf-8")

        self.assertIn(".agents/skills/ask-herdr/SKILL.md", agents)
        self.assertIn("@AGENTS.md", claude)
        self.assertIn("/ask-herdr", claude)
        self.assertIn(
            "../../../.agents/skills/ask-herdr/SKILL.md",
            adapter,
        )
        self.assertIn("name: ask-herdr", canonical)
        self.assertIn("name: ask-herdr", adapter)

        for cached_grammar in (
            "machine describe --json",
            "machine schema --id",
            "machine run --request",
        ):
            self.assertNotIn(cached_grammar, claude)
            self.assertNotIn(cached_grammar, adapter)

    def test_canonical_skill_is_discovery_first_and_privacy_preserving(self):
        skill = CANONICAL_SKILL.read_text(encoding="utf-8")

        for required_interface in (
            "APPROVED_PYTHON bin/ask-herdr machine describe --json",
            "APPROVED_PYTHON bin/ask-herdr machine schema --id EXACT_ADVERTISED_ID",
            "APPROVED_PYTHON bin/ask-herdr machine run --request",
            "features.machine_run=false",
            "runtime_platform",
            "Native Windows is currently contract-only",
            "schema_documents",
            "exit_classes",
            "do not execute `APPROVED_PYTHON` literally",
            "Pass `bin/ask-herdr` to that interpreter explicitly",
        ):
            self.assertIn(required_interface, skill)

        for privacy_invariant in (
            "owner prepare the request file",
            "without reading, printing, copying, logging, hashing, or",
            "Use a file path, not `--request -`",
            "validation result may contain the private Project root",
            "Do not retry automatically",
        ):
            self.assertIn(privacy_invariant, skill)

        self.assertIn("bin/ask-herdr-pipeline", skill)
        self.assertIn("Herdr command-authority skill", skill)
        self.assertNotIn("cli_version=", skill)
        self.assertNotIn("ask_herdr.describe.v2", skill)
        self.assertNotIn("ask_herdr.describe.v3", skill)
        self.assertNotIn("/usr/local/bin/python3", skill)
        self.assertNotIn("/opt/homebrew/bin/git", skill)
        self.assertNotIn("/usr/bin/python3", skill)
        self.assertNotIn("/usr/bin/git", skill)

    def test_every_relative_skill_reference_resolves(self):
        markdown_link = re.compile(r"\[[^]]+\]\(([^)]+)\)")
        for skill_path in (CANONICAL_SKILL, CLAUDE_SKILL):
            content = skill_path.read_text(encoding="utf-8")
            targets = markdown_link.findall(content)
            self.assertGreater(len(targets), 0)
            for target in targets:
                with self.subTest(skill=skill_path, target=target):
                    self.assertFalse(target.startswith("/"))
                    self.assertTrue(
                        (skill_path.parent / target).resolve().is_file()
                    )

        self.assertTrue(QUICK_START.is_file())
        self.assertTrue(PUBLIC_CONTRACT.is_file())

    def test_live_discovery_supports_the_agent_claim_ceiling(self):
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, str(CLI), "machine", "describe", "--json"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        description = json.loads(completed.stdout)
        runtime = description["runtime_platform"]
        execution_supported = runtime["execution_tier"] == "full"
        self.assertEqual(
            description["features"]["machine_run"],
            execution_supported,
        )
        self.assertFalse(description["features"]["human_facade"])
        self.assertTrue(description["features"]["machine_schema"])
        self.assertEqual(
            description["features"]["machine_validate"],
            execution_supported,
        )

        profiles = description["launcher_profile_registry"]["profiles"]
        self.assertGreater(len(profiles), 0)
        self.assertTrue(all(not profile["default_enabled"] for profile in profiles))

        schema_ids = {
            document["schema_id"] for document in description["schema_documents"]
        }
        self.assertIn("ask_herdr.request.v1", schema_ids)
        self.assertIn("ask_herdr.outcome.v2", schema_ids)
        self.assertIn("ask_herdr.describe.v3", schema_ids)
        self.assertIn("ask_herdr.schema_document.v3", schema_ids)

    def test_synthetic_private_file_flow_returns_one_path_free_typed_outcome(self):
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="ask-herdr-agent-smoke-") as tmp:
            project = Path(tmp) / "synthetic-project"
            project.mkdir()
            request_path = Path(tmp) / "request.json"
            request = {
                "schema": "ask_herdr.request.v1",
                "operation": "query.status",
                "operation_id": "123e4567-e89b-42d3-a456-426614174000",
                "project": {
                    "schema": "ask_herdr.project_binding.v1",
                    "binding": "bound",
                    "root": str(project.resolve()),
                    "authority_id": "123e4567-e89b-42d3-a456-426614174002",
                },
                "authority_ref": None,
                "reason": {
                    "schema": "ask_herdr.reason.v1",
                    "action": "inspect",
                },
                "payload": {
                    "schema": "ask_herdr.query.status.payload.v1",
                    "selector": {
                        "schema": "ask_herdr.query.status.selector.v1",
                        "kind": "project",
                    },
                    "advisory": "none",
                    "limit": 20,
                    "cursor": None,
                },
                "observation": {
                    "schema": "ask_herdr.observation.v1",
                    "mode": "immediate",
                    "timeout_ms": None,
                },
            }
            request_path.write_text(json.dumps(request), encoding="utf-8")
            request_path.chmod(0o600)

            discovered = subprocess.run(
                [sys.executable, str(CLI), "machine", "describe", "--json"],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(discovered.returncode, 0, discovered.stderr)
            execution_supported = (
                json.loads(discovered.stdout)["runtime_platform"][
                    "execution_tier"
                ]
                == "full"
            )

            validation = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "machine",
                    "validate",
                    "--request",
                    str(request_path.resolve()),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if execution_supported:
                self.assertEqual(validation.returncode, 20, validation.stderr)
                self.assertEqual(
                    json.loads(validation.stdout)["outcome_kind"],
                    "request_not_currently_admissible",
                )
            else:
                self.assertEqual(validation.returncode, 20)
                self.assertEqual(validation.stdout, "")
                self.assertEqual(
                    validation.stderr,
                    "ask-herdr machine validate failed: "
                    "runtime.platform_unsupported\n",
                )

            run = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "machine",
                    "run",
                    "--request",
                    str(request_path.resolve()),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if not execution_supported:
                self.assertEqual(run.returncode, 20)
                self.assertEqual(run.stdout, "")
                self.assertEqual(
                    run.stderr,
                    "ask-herdr machine run failed: "
                    "runtime.platform_unsupported\n",
                )
                return
            self.assertEqual(run.returncode, 40, run.stderr)
            self.assertEqual(run.stderr, "")
            self.assertEqual(run.stdout.count("\n"), 1)
            outcome = json.loads(run.stdout)
            self.assertEqual(outcome["schema"], "ask_herdr.outcome.v2")
            self.assertEqual(outcome["operation"], "query.status")
            self.assertEqual(
                outcome["outcome_kind"],
                "request_reconciliation_required",
            )
            self.assertEqual(outcome["status"], "reconciliation_required")
            self.assertIsNone(outcome["result"])
            self.assertEqual(
                set(outcome["project"]),
                {"schema", "authority_id"},
            )
            self.assertNotIn(str(project.resolve()), run.stdout)


if __name__ == "__main__":
    unittest.main()
