#!/usr/bin/env python3
"""Acceptance tests for the public provider-free ``machine validate`` seam."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
sys.path.insert(0, str(ROOT))

from lib.ask_herdr_operation_contract import OPERATION_CONTRACTS
from tests.test_request_schema_complete import request_for as contract_request_for


OUTCOME_SCHEMA = json.loads(
    (ROOT / "schemas" / "ask_herdr.outcome.v1.schema.json").read_text(
        encoding="utf-8"
    )
)
OUTCOME_VALIDATOR = Draft202012Validator(OUTCOME_SCHEMA)
OUTPUT_BYTES_MAX = 33_554_432
OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000"


def project_init_request(project_root: Path) -> dict:
    return {
        "schema": "ask_herdr.request.v1",
        "operation": "project.init",
        "operation_id": OPERATION_ID,
        "project": {
            "schema": "ask_herdr.project_binding.v1",
            "binding": "candidate",
            "root": str(project_root),
            "authority_id": None,
        },
        "authority_ref": None,
        "reason": {
            "schema": "ask_herdr.reason.v1",
            "action": "project_admin",
        },
        "payload": {
            "schema": "ask_herdr.project.init.payload.v1",
            "lifetime": "initial",
        },
        "observation": {
            "schema": "ask_herdr.observation.v1",
            "mode": "immediate",
            "timeout_ms": None,
        },
    }


def canonical_input(request: dict) -> bytes:
    return json.dumps(
        request,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"


def run_validate(
    raw_request: bytes,
    *,
    request_path: Path | None = None,
    environment: dict | None = None,
):
    command = [
        sys.executable,
        str(CLI),
        "machine",
        "validate",
        "--request",
        "-" if request_path is None else str(request_path),
    ]
    child_environment = dict(os.environ if environment is None else environment)
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if request_path is None:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=child_environment,
            input=raw_request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    return subprocess.run(
        command,
        cwd=ROOT,
        env=child_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def parse_outcome(completed: subprocess.CompletedProcess) -> dict:
    if len(completed.stdout) > OUTPUT_BYTES_MAX:
        raise AssertionError("machine outcome exceeded the public 32 MiB bound")
    if not completed.stdout.endswith(b"\n"):
        raise AssertionError("machine outcome must end in exactly one newline")
    if completed.stdout.count(b"\n") != 1:
        raise AssertionError("machine outcome must be one compact JSON line")
    document = json.loads(completed.stdout)
    errors = sorted(
        OUTCOME_VALIDATOR.iter_errors(document),
        key=lambda error: list(error.path),
    )
    if errors:
        raise AssertionError([error.message for error in errors])
    return document


def redacted_process_failure(completed: subprocess.CompletedProcess) -> None:
    if completed.returncode != 64:
        raise AssertionError(f"unexpected exit class: {completed.returncode}")
    if completed.stdout != b"":
        raise AssertionError("pre-envelope failure contaminated stdout")
    lines = completed.stderr.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise AssertionError("pre-envelope failure must be exactly one line")
    if len(completed.stderr) > 512:
        raise AssertionError("pre-envelope diagnostic was not bounded")


def expected_project_init_digest(project_root: Path) -> str:
    metadata = project_root.stat()
    projection = {
        "schema": "ask_herdr.canonical_request_projection.v1",
        "operation": "project.init",
        "project": {
            "binding": "candidate",
            "root": str(project_root),
            "filesystem_identity": {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "owner_uid": os.getuid(),
            },
        },
        "payload": {"lifetime": "initial"},
    }
    # All keys in this frozen projection are ASCII, so Python's sorted compact
    # encoding is independently byte-identical to the contract's canonical JSON.
    canonical_projection = json.dumps(
        projection,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical_projection).hexdigest()


def snapshot_tree(root: Path) -> tuple:
    entries = []
    for entry in [root, *sorted(root.rglob("*"))]:
        metadata = entry.lstat()
        kind = (
            "file"
            if stat.S_ISREG(metadata.st_mode)
            else "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "other"
        )
        digest = (
            hashlib.sha256(entry.read_bytes()).hexdigest()
            if kind == "file"
            else None
        )
        entries.append(
            (
                "." if entry == root else entry.relative_to(root).as_posix(),
                kind,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_size,
                metadata.st_mtime_ns,
                digest,
            )
        )
    return tuple(entries)


def guarded_environment(sandbox: Path) -> tuple[dict, Path, Path]:
    forbidden_process_marker = sandbox / "forbidden-process-called"
    forbidden_network_marker = sandbox / "forbidden-network-called"
    fake_bin = sandbox / "fake-bin"
    fake_bin.mkdir()
    script = (
        "#!/bin/sh\n"
        "printf '%s\\n' \"$0\" > \"$ASK_HERDR_FORBIDDEN_PROCESS_MARKER\"\n"
        "exit 97\n"
    )
    for command in (
        "herdr",
        "claude",
        "cc-claude",
        "cc-deepseek",
        "codex",
        "curl",
        "wget",
        "ssh",
    ):
        executable = fake_bin / command
        executable.write_text(script, encoding="utf-8")
        executable.chmod(0o700)

    guard = sandbox / "python-guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        """\
import os
from pathlib import Path
import socket
import subprocess

PROCESS_NAMES = {
    'herdr', 'claude', 'cc-claude', 'cc-deepseek', 'codex',
    'curl', 'wget', 'ssh',
}

def mark(name):
    Path(os.environ[name]).write_text('called\\n', encoding='utf-8')

class GuardedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        mark('ASK_HERDR_FORBIDDEN_NETWORK_MARKER')
        raise RuntimeError('network is forbidden in machine validate')

    def connect_ex(self, *args, **kwargs):
        mark('ASK_HERDR_FORBIDDEN_NETWORK_MARKER')
        raise RuntimeError('network is forbidden in machine validate')

socket.socket = GuardedSocket

def blocked_create_connection(*args, **kwargs):
    mark('ASK_HERDR_FORBIDDEN_NETWORK_MARKER')
    raise RuntimeError('network is forbidden in machine validate')

socket.create_connection = blocked_create_connection
original_popen = subprocess.Popen

def guarded_popen(*args, **kwargs):
    command = args[0] if args else kwargs.get('args')
    first = command[0] if isinstance(command, (list, tuple)) else command
    if first and os.path.basename(os.fspath(first)) in PROCESS_NAMES:
        mark('ASK_HERDR_FORBIDDEN_PROCESS_MARKER')
        raise RuntimeError('external provider or control process is forbidden')
    return original_popen(*args, **kwargs)

subprocess.Popen = guarded_popen
""",
        encoding="utf-8",
    )

    environment = dict(os.environ)
    environment.update(
        {
            "ASK_HERDR_FORBIDDEN_PROCESS_MARKER": str(forbidden_process_marker),
            "ASK_HERDR_FORBIDDEN_NETWORK_MARKER": str(forbidden_network_marker),
            "PATH": str(fake_bin),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(guard),
        }
    )
    return environment, forbidden_process_marker, forbidden_network_marker


class MachineValidateV1Test(unittest.TestCase):
    def test_cli_disables_bytecode_writes_without_relying_on_caller_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary).resolve()
            cache_root = sandbox / "python-cache"
            environment = dict(os.environ)
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment["PYTHONPYCACHEPREFIX"] = str(cache_root)
            completed = subprocess.run(
                [sys.executable, str(CLI), "machine", "describe", "--json"],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            project_bytecode = [
                path
                for path in cache_root.rglob("*.pyc")
                if path.name.startswith("ask_herdr_")
            ]
            self.assertEqual(project_bytecode, [])

    def test_malformed_or_untrusted_header_is_one_redacted_process_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            project_root = (Path(temporary) / "project").resolve()
            project_root.mkdir()
            untrusted = project_init_request(project_root)
            untrusted["operation"] = "turn.MUST_NOT_LEAK"
            untrusted["reason"]["note"] = "SECOND_SECRET_MUST_NOT_LEAK"
            cases = (
                b'{"schema":"ask_herdr.request.v1","secret":"FIRST_SECRET",',
                canonical_input(untrusted),
            )

            for raw_request in cases:
                with self.subTest(raw_request=raw_request[:32]):
                    completed = run_validate(raw_request)
                    redacted_process_failure(completed)
                    self.assertNotIn(b"FIRST_SECRET", completed.stderr)
                    self.assertNotIn(b"MUST_NOT_LEAK", completed.stderr)
                    self.assertNotIn(str(project_root).encode(), completed.stderr)

    def test_trusted_header_structural_failure_is_one_redacted_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            project_root = (Path(temporary) / "project").resolve()
            project_root.mkdir()
            request = project_init_request(project_root)
            request["payload"]["sensitive_extra"] = "MUST_NOT_LEAK"
            raw_request = canonical_input(request)

            completed = run_validate(raw_request)

        self.assertEqual(completed.returncode, 64)
        self.assertEqual(completed.stderr, b"")
        self.assertNotIn(b"MUST_NOT_LEAK", completed.stdout)
        outcome = parse_outcome(completed)
        self.assertEqual(outcome["outcome_kind"], "request_invalid")
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["exit_class"], 64)
        self.assertEqual(outcome["operation"], "project.init")
        self.assertEqual(outcome["operation_id"], OPERATION_ID)
        self.assertEqual(outcome["project"], request["project"])
        self.assertIsNone(outcome["request_digest"])
        self.assertEqual(outcome["result"]["canonical_bytes"], None)
        self.assertEqual(
            outcome["result"]["captured_sha256"],
            "sha256:" + hashlib.sha256(raw_request).hexdigest(),
        )
        self.assertTrue(outcome["result"]["redacted_field_locations"])

    def test_owned_project_init_is_valid_exact_and_provider_free_with_file_stdin_parity(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary).resolve()
            project_root = sandbox / "project"
            project_root.mkdir()
            self.assertEqual(project_root.stat().st_uid, os.getuid())
            request = project_init_request(project_root)
            raw_request = canonical_input(request)
            request_path = sandbox / "request.json"
            request_path.write_bytes(raw_request)
            request_path.chmod(0o600)
            environment, process_marker, network_marker = guarded_environment(sandbox)

            # A validation-only implementation must succeed even when its target
            # is owner-readable/executable but cannot accept state writes.
            project_root.chmod(0o500)
            try:
                before = snapshot_tree(sandbox)
                file_completed = run_validate(
                    raw_request,
                    request_path=request_path,
                    environment=environment,
                )
                stdin_completed = run_validate(
                    raw_request,
                    environment=environment,
                )
                after = snapshot_tree(sandbox)
                expected_digest = expected_project_init_digest(project_root)
            finally:
                project_root.chmod(0o700)

            self.assertEqual(after, before)
            self.assertFalse((project_root / ".ask-herdr").exists())
            self.assertFalse(process_marker.exists())
            self.assertFalse(network_marker.exists())

            self.assertEqual(file_completed.returncode, 0)
            self.assertEqual(file_completed.stderr, b"")
            self.assertEqual(stdin_completed.returncode, 0)
            self.assertEqual(stdin_completed.stderr, b"")
            outcomes = []
            for source, completed in (
                ("file", file_completed),
                ("stdin", stdin_completed),
            ):
                with self.subTest(source=source):
                    outcome = parse_outcome(completed)
                    outcomes.append(outcome)
                    self.assertEqual(outcome["outcome_kind"], "request_valid")
                    self.assertEqual(outcome["status"], "succeeded")
                    self.assertEqual(outcome["exit_class"], 0)
                    self.assertEqual(outcome["operation"], "project.init")
                    self.assertEqual(outcome["operation_id"], OPERATION_ID)
                    self.assertEqual(outcome["project"], request["project"])
                    self.assertEqual(outcome["request_digest"], expected_digest)
                    self.assertEqual(outcome["diagnostics"], [])
                    self.assertEqual(outcome["evidence_refs"], [])
                    self.assertEqual(outcome["policy"], None)
                    self.assertEqual(outcome["advisory"], {})
                    self.assertEqual(
                        outcome["result"]["captured_bytes"], len(raw_request)
                    )
                    self.assertEqual(
                        outcome["result"]["captured_sha256"],
                        "sha256:" + hashlib.sha256(raw_request).hexdigest(),
                    )
                    self.assertIsInstance(
                        outcome["result"]["canonical_bytes"], int
                    )
                    self.assertEqual(
                        outcome["result"]["redacted_field_locations"], []
                    )

            for outcome in outcomes:
                outcome.pop("timestamps")
            self.assertEqual(outcomes[0], outcomes[1])

    def test_bound_request_without_authority_state_is_typed_not_admissible(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary).resolve()
            project_root = sandbox / "project"
            project_root.mkdir()
            environment, process_marker, network_marker = guarded_environment(sandbox)
            request = contract_request_for("query.status")
            request["project"]["root"] = str(project_root)
            raw_request = canonical_input(request)

            completed = run_validate(raw_request, environment=environment)

            self.assertEqual(completed.returncode, 20)
            self.assertEqual(completed.stderr, b"")
            outcome = parse_outcome(completed)
            self.assertEqual(
                outcome["outcome_kind"], "request_not_currently_admissible"
            )
            self.assertEqual(outcome["status"], "failed")
            self.assertEqual(outcome["exit_class"], 20)
            self.assertEqual(outcome["operation"], "query.status")
            self.assertEqual(outcome["operation_id"], request["operation_id"])
            self.assertEqual(outcome["project"], request["project"])
            self.assertIsNone(outcome["request_digest"])
            self.assertEqual(
                outcome["result"]["captured_sha256"],
                "sha256:" + hashlib.sha256(raw_request).hexdigest(),
            )
            self.assertFalse((project_root / ".ask-herdr").exists())
            self.assertFalse(process_marker.exists())
            self.assertFalse(network_marker.exists())

    def test_every_operation_has_a_structurally_valid_provider_free_path(self):
        self.assertEqual(len(OPERATION_CONTRACTS), 45)
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary).resolve()
            project_root = sandbox / "project"
            project_root.mkdir()
            environment, process_marker, network_marker = guarded_environment(sandbox)

            for operation in OPERATION_CONTRACTS:
                request = copy.deepcopy(contract_request_for(operation))
                request["project"]["root"] = str(project_root)
                raw_request = canonical_input(request)
                with self.subTest(operation=operation):
                    completed = run_validate(raw_request, environment=environment)
                    self.assertEqual(completed.stderr, b"")
                    outcome = parse_outcome(completed)
                    self.assertEqual(outcome["operation"], operation)
                    self.assertEqual(outcome["operation_id"], request["operation_id"])
                    self.assertEqual(outcome["project"], request["project"])
                    if operation == "project.init":
                        self.assertEqual(completed.returncode, 0)
                        self.assertEqual(outcome["outcome_kind"], "request_valid")
                    else:
                        self.assertEqual(completed.returncode, 20)
                        self.assertEqual(
                            outcome["outcome_kind"],
                            "request_not_currently_admissible",
                        )

            self.assertFalse((project_root / ".ask-herdr").exists())
            self.assertFalse(process_marker.exists())
            self.assertFalse(network_marker.exists())


if __name__ == "__main__":
    unittest.main()
