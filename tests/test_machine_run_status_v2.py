#!/usr/bin/env python3
"""Acceptance tests for the activated, provider-free public-beta Machine Run route."""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import importlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_json import canonical_json  # noqa: E402
from ask_herdr_project_status import (  # noqa: E402
    ProjectStatusInspection,
    ProjectStatusLaneHead,
    ProjectStatusOperationMetadata,
)
from ask_herdr_project_read_epoch import ProjectReadEpoch  # noqa: E402
from ask_herdr_project_mutation_lease import (  # noqa: E402
    ValidatedProjectMutationBinding,
)
from tests.test_request_schema_complete import request_for  # noqa: E402


UUID = "123e4567-e89b-42d3-a456-426614174000"
AUTHORITY_ID = "123e4567-e89b-42d3-a456-426614174002"
LANE_ID = "123e4567-e89b-42d3-a456-426614174001"
DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64
OBSERVED_AT = datetime(2026, 8, 22, 1, 2, 3, tzinfo=timezone.utc)


def _cli_module():
    name = "ask_herdr_cli_public_beta_test"
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    loader = SourceFileLoader(name, str(CLI))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load bin/ask-herdr as a test module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _public_module():
    try:
        return importlib.import_module("ask_herdr_public_status")
    except ModuleNotFoundError as error:
        raise AssertionError(
            "RED: ask_herdr_public_status is absent; "
            "the public adapter/route has not been implemented"
        ) from error


def _activation_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except TypeError as error:
        raise AssertionError(
            "RED: the CLI activation injection/ public v2 route seam is absent"
        ) from error


def _status_request(
    selector=None,
    *,
    binding="bound",
    root="/private/tmp/ask-herdr-public-status-project",
    mode="immediate",
    advisory="none",
    limit=2,
    cursor=None,
):
    request = deepcopy(request_for("query.status"))
    request["operation_id"] = UUID
    request["project"] = {
        "schema": "ask_herdr.project_binding.v1",
        "binding": binding,
        "root": root,
        "authority_id": AUTHORITY_ID if binding == "bound" else None,
    }
    request["payload"].update(
        {
            "selector": _selector() if selector is None else selector,
            "advisory": advisory,
            "limit": limit,
            "cursor": cursor,
        }
    )
    request["observation"] = {
        "schema": "ask_herdr.observation.v1",
        "mode": mode,
        "timeout_ms": 1000 if mode == "wait" else None,
    }
    return request


def _selector(kind="project"):
    selector = {
        "schema": "ask_herdr.query.status.selector.v1",
        "kind": kind,
    }
    if kind == "lane":
        selector["lane_id"] = LANE_ID
    elif kind == "key":
        selector["consultant_key"] = "biology"
    elif kind == "operation":
        selector["operation_id"] = UUID
    return selector


def _lane_head():
    return ProjectStatusLaneHead(
        lane_id=LANE_ID,
        lane_generation=1,
        lane_binding_digest=DIGEST,
        event_sequence=7,
        event_digest=REQUEST_DIGEST,
        state_digest=DIGEST,
        response_digest=None,
    )


def _epoch_dict():
    return ProjectReadEpoch(
        schema="ask_herdr.project_read_epoch.v1",
        project_authority_id=AUTHORITY_ID,
        authority_store_head_digest=DIGEST,
        project_state_digest=REQUEST_DIGEST,
        lane_index_digest=DIGEST,
        topology_ledger_head_digest=DIGEST,
        observed_at="2026-08-22T01:02:03Z",
        acquisition_attempt=1,
        epoch_digest=DIGEST,
    )


def _inspection(
    *,
    status="active",
    detail_code="query_status.project_active",
    entries=(),
    next_cursor=None,
    operation_metadata=None,
    normalized_digest=DIGEST,
):
    return ProjectStatusInspection(
        status=status,
        detail_code=detail_code,
        normalized_read_contract_digest=normalized_digest,
        project_read_epoch=_epoch_dict(),
        entries=tuple(entries),
        next_cursor=next_cursor,
        operation_metadata=operation_metadata,
    )


def _operation_metadata(lane_association="bound"):
    return ProjectStatusOperationMetadata(
        operation_id=UUID,
        operation="turn.consult",
        canonical_request_digest=REQUEST_DIGEST,
        authority_record_digest="sha256:" + "p" * 64,
        lane_association=lane_association,
    )


class _Stdout:
    def __init__(self):
        self.buffer = io.BytesIO()

    def write(self, value):
        if isinstance(value, bytes):
            self.buffer.write(value)
        else:
            self.buffer.write(str(value).encode("utf-8"))
        return len(value)

    def flush(self):
        return None


class _Stdin:
    def __init__(self, raw):
        self.buffer = io.BytesIO(raw)


@contextmanager
def _captured_stdio(raw=b""):
    stdout = _Stdout()
    stderr = io.StringIO()
    stdin = _Stdin(raw)
    with mock.patch.object(sys, "stdin", stdin), mock.patch.object(
        sys, "stdout", stdout
    ), mock.patch.object(sys, "stderr", stderr):
        yield stdout, stderr


def _invoke_main(raw, *argv, activation=True):
    module = _cli_module()
    with _captured_stdio(raw) as (stdout, stderr):
        exit_class = _activation_call(
            module.main, list(argv), activation=activation
        )
        return exit_class, stdout.buffer.getvalue(), stderr.getvalue()


def _parse_one_line(raw):
    if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        raise AssertionError("Machine Run output must be one JSON line")
    return json.loads(raw)


def _dispatch(module, request, *, inspector, readers, clock=lambda: OBSERVED_AT):
    dispatch = getattr(module, "dispatch_query_status", None)
    if not callable(dispatch):
        raise AssertionError(
            "ask_herdr_public_status must expose dispatch_query_status"
        )
    return dispatch(
        request,
        project_inspector=inspector,
        status_readers=readers,
        clock=clock,
    )


class MachineRunStatusV2Test(unittest.TestCase):
    def invoke_subprocess(self, *arguments, environment=None, input_bytes=None):
        env = dict(os.environ if environment is None else environment)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, str(CLI), *arguments],
            cwd=ROOT,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_default_discovery_activates_v3_while_legacy_schema_and_validate_remain_v1(self):
        completed = self.invoke_subprocess("machine", "describe", "--json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count(b"\n"), 1)
        description = json.loads(completed.stdout)
        self.assertEqual(description["schema"], "ask_herdr.describe.v3")
        self.assertEqual(description["cli_version"], "0.4.0")
        self.assertEqual(
            description["machine_core_contract"]["implementation_version"],
            "0.4.0",
        )
        self.assertEqual(
            description["machine_core_contract"]["supported_outcome_versions"],
            ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
        )
        self.assertTrue(description["features"]["machine_run"])
        self.assertFalse(description["features"]["human_facade"])
        self.assertEqual(
            [item["schema_id"] for item in description["schema_documents"]],
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

        usage = self.invoke_subprocess(
            "machine", "run", "--request", "-", input_bytes=b"{}\n"
        )
        self.assertEqual(usage.returncode, 64)
        self.assertEqual(usage.stdout, b"")
        self.assertIn(b"machine run failed: request.header_invalid", usage.stderr)

        legacy_hashes = {
            "ask_herdr.describe.v1": "579e548e78ca663cbe4a59c524d167e4320b0f4bcb6a6ac0d7d1c31e1292a838",
            "ask_herdr.outcome.v1": "9cb273d120a83ac0e6f4e58dad6170820c96b29ff0cce883eb7a5f09867c6b47",
            "ask_herdr.request.v1": "92ea2f9e2862543d528650be0c4a4cba61490185eae03f3e36820da57941e3a2",
            "ask_herdr.schema_document.v1": "ab557f81272b9d1762f5ad7debf8ab31b0fb67bba11b693d31f5c7969615ace5",
        }
        for schema_id, expected_hash in legacy_hashes.items():
            with self.subTest(schema_id=schema_id):
                response = self.invoke_subprocess(
                    "machine", "schema", "--id", schema_id
                )
                self.assertEqual(response.returncode, 0, response.stderr)
                self.assertEqual(
                    hashlib.sha256(response.stdout).hexdigest(), expected_hash
                )

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            request = {
                "schema": "ask_herdr.request.v1",
                "operation": "project.init",
                "operation_id": UUID,
                "project": {
                    "schema": "ask_herdr.project_binding.v1",
                    "binding": "candidate",
                    "root": str(project.resolve()),
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
            validation = self.invoke_subprocess(
                "machine",
                "validate",
                "--request",
                "-",
                input_bytes=canonical_json(request) + b"\n",
            )
            self.assertEqual(validation.returncode, 0, validation.stderr)
            self.assertEqual(json.loads(validation.stdout)["schema"], "ask_herdr.outcome.v1")

    def test_default_machine_run_route_is_provider_free_and_path_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            project = sandbox / "private-project"
            project.mkdir()
            fake_bin = sandbox / "bin"
            fake_bin.mkdir()
            provider_log = sandbox / "provider-called"
            fake_herdr = fake_bin / "herdr"
            fake_herdr.write_text(
                "#!/bin/sh\nprintf called > \"$ASK_HERDR_PROVIDER_LOG\"\nexit 99\n",
                encoding="utf-8",
            )
            fake_herdr.chmod(0o700)
            environment = dict(os.environ)
            environment["PATH"] = str(fake_bin)
            environment["ASK_HERDR_PROVIDER_LOG"] = str(provider_log)
            request = _status_request(root=str(project))
            completed = self.invoke_subprocess(
                "machine",
                "run",
                "--request",
                "-",
                environment=environment,
                input_bytes=canonical_json(request) + b"\n",
            )

            self.assertIn(completed.returncode, (0, 20, 40, 50), completed.stderr)
            self.assertEqual(completed.stderr, b"")
            outcome = _parse_one_line(completed.stdout)
            self.assertEqual(outcome["schema"], "ask_herdr.outcome.v2")
            self.assertEqual(outcome["operation"], "query.status")
            self.assertNotIn(str(project), completed.stdout.decode("utf-8"))
            self.assertFalse(provider_log.exists())

    def test_injected_true_discovery_registers_v2_v3_documents_and_exact_route(self):
        module = _cli_module()
        description = _activation_call(module.describe, activation=True)
        self.assertEqual(description["schema"], "ask_herdr.describe.v3")
        self.assertEqual(description["cli_version"], "0.4.0")
        self.assertEqual(
            description["machine_core_contract"]["implementation_version"],
            "0.4.0",
        )
        self.assertTrue(description["features"]["machine_run"])
        self.assertEqual(
            description["machine_core_contract"]["supported_outcome_versions"],
            ["ask_herdr.outcome.v1", "ask_herdr.outcome.v2"],
        )
        self.assertEqual(
            [item["schema_id"] for item in description["schema_documents"]],
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
        for schema_id in (
            "ask_herdr.describe.v1",
            "ask_herdr.outcome.v1",
            "ask_herdr.request.v1",
            "ask_herdr.schema_document.v1",
        ):
            with self.subTest(schema_id=schema_id):
                legacy = _activation_call(
                    module.schema_document, schema_id, activation=True
                )
                self.assertEqual(legacy["schema"], "ask_herdr.schema_document.v1")
                self.assertEqual(legacy["semantic_version"], "1.0.0")
                baseline = json.loads(
                    self.invoke_subprocess(
                        "machine", "schema", "--id", schema_id
                    ).stdout
                )
                self.assertEqual(legacy, baseline)
        for schema_id, version in (
            ("ask_herdr.describe.v2", "2.0.0"),
            ("ask_herdr.outcome.v2", "2.0.0"),
            ("ask_herdr.query.status.result.v1", "1.0.0"),
            ("ask_herdr.schema_document.v2", "2.0.0"),
        ):
            with self.subTest(schema_id=schema_id):
                new = _activation_call(
                    module.schema_document, schema_id, activation=True
                )
                self.assertEqual(new["schema"], "ask_herdr.schema_document.v2")
                self.assertEqual(new["semantic_version"], version)
                Draft202012Validator.check_schema(new["document"])
        for schema_id in (
            "ask_herdr.describe.v3",
            "ask_herdr.schema_document.v3",
        ):
            with self.subTest(schema_id=schema_id):
                new = _activation_call(
                    module.schema_document, schema_id, activation=True
                )
                self.assertEqual(new["schema"], "ask_herdr.schema_document.v3")
                self.assertEqual(new["semantic_version"], "3.0.0")
                Draft202012Validator.check_schema(new["document"])

        describe_errors = list(
            Draft202012Validator(
                _activation_call(
                    module.schema_document,
                    "ask_herdr.describe.v3",
                    activation=True,
                )["document"]
            ).iter_errors(description)
        )
        self.assertEqual(describe_errors, [])
        schema_v3_wrapper = _activation_call(
            module.schema_document,
            "ask_herdr.schema_document.v3",
            activation=True,
        )
        wrapper_errors = list(
            Draft202012Validator(schema_v3_wrapper["document"]).iter_errors(
                schema_v3_wrapper
            )
        )
        self.assertEqual(wrapper_errors, [])

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            request = _status_request(root=str(project))
            exit_class, stdout, stderr = _invoke_main(
                canonical_json(request) + b"\n",
                "machine",
                "run",
                "--request",
                "-",
                activation=True,
            )
            self.assertIn(exit_class, (0, 20, 40, 50))
            self.assertEqual(stderr, "")
            outcome = _parse_one_line(stdout)
            self.assertEqual(outcome["schema"], "ask_herdr.outcome.v2")
            self.assertEqual(outcome["operation"], "query.status")
            self.assertEqual(
                outcome["project"],
                {
                    "schema": "ask_herdr.project_reference.v1",
                    "authority_id": AUTHORITY_ID,
                },
            )

    def test_machine_run_rejects_every_non_exact_route_form(self):
        for argv in (
            ("machine", "run"),
            ("machine", "run", "--json"),
            ("machine", "run", "--request", "relative.json"),
            ("machine", "run", "--request", "-", "extra"),
        ):
            with self.subTest(argv=argv):
                exit_class, stdout, stderr = _invoke_main(
                    b"", *argv, activation=True
                )
                self.assertEqual(exit_class, 64)
                self.assertEqual(stdout, b"")
                self.assertTrue(stderr)
                self.assertLessEqual(len(stderr.encode()), 512)

    def test_strict_stdin_and_file_capture_have_the_same_request_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            request = _status_request(root=str(project))
            raw = canonical_json(request) + b"\n"
            request_path = project / "request.json"
            request_path.write_bytes(raw)
            request_path.chmod(0o600)

            stdin_result = _invoke_main(
                raw,
                "machine",
                "run",
                "--request",
                "-",
                activation=True,
            )
            file_result = _invoke_main(
                b"",
                "machine",
                "run",
                "--request",
                str(request_path),
                activation=True,
            )
            self.assertEqual(stdin_result[0], file_result[0])
            self.assertEqual(stdin_result[2], file_result[2])
            stdin_outcome = _parse_one_line(stdin_result[1])
            file_outcome = _parse_one_line(file_result[1])
            self.assertEqual(stdin_outcome, file_outcome)
            self.assertEqual(
                stdin_outcome["request_digest"],
                "sha256:" + hashlib.sha256(canonical_json(request)).hexdigest(),
            )

    def test_capture_parse_and_trusted_header_failures_are_redacted_no_json(self):
        cases = (
            b"{\"schema\":\"ask_herdr.request.v1\",",
            b"\xff\xfe\xfd",
            b"{}\nprivate-request-secret",
        )
        for raw in cases:
            with self.subTest(raw=raw[:20]):
                exit_class, stdout, stderr = _invoke_main(
                    raw,
                    "machine",
                    "run",
                    "--request",
                    "-",
                    activation=True,
                )
                self.assertEqual(exit_class, 64)
                self.assertEqual(stdout, b"")
                self.assertTrue(stderr)
                self.assertLessEqual(len(stderr.encode()), 512)
                self.assertNotIn(b"private-request-secret", stderr.encode())

    def test_non_query_trusted_route_is_rejected_before_v2_output(self):
        request = deepcopy(request_for("project.init"))
        request["operation_id"] = UUID
        exit_class, stdout, stderr = _invoke_main(
            canonical_json(request) + b"\n",
            "machine",
            "run",
            "--request",
            "-",
            activation=True,
        )
        self.assertEqual(exit_class, 64)
        self.assertEqual(stdout, b"")
        self.assertTrue(stderr)
        self.assertNotIn("project.init", stderr)

    def test_request_invalid_candidate_and_bound_headers_always_use_null_project(self):
        for binding in ("candidate", "bound"):
            with self.subTest(binding=binding):
                request = _status_request(binding=binding)
                request["payload"]["untrusted_extra"] = "CALLER_SECRET"
                exit_class, stdout, stderr = _invoke_main(
                    canonical_json(request) + b"\n",
                    "machine",
                    "run",
                    "--request",
                    "-",
                    activation=True,
                )
                self.assertEqual(exit_class, 64)
                self.assertEqual(stderr, "")
                outcome = _parse_one_line(stdout)
                self.assertEqual(outcome["outcome_kind"], "request_invalid")
                self.assertIsNone(outcome["project"])
                self.assertIsNone(outcome["result"])
                self.assertEqual(len(outcome["diagnostics"]), 1)
                self.assertNotIn("CALLER_SECRET", json.dumps(outcome))

    def test_wait_precedes_advisory_and_neither_inspects_the_project(self):
        module = _public_module()
        request = _status_request(mode="wait", advisory="full")
        inspector = mock.Mock(side_effect=AssertionError("project inspected"))
        readers = {kind: mock.Mock(side_effect=AssertionError(kind)) for kind in (
            "project", "lane", "key", "operation"
        )}
        outcome = _dispatch(module, request, inspector=inspector, readers=readers)
        self.assertEqual(outcome["outcome_kind"], "status_capability_unavailable")
        self.assertEqual(outcome["result"]["detail_code"], "query_status.observation_unavailable")
        inspector.assert_not_called()
        for reader in readers.values():
            reader.assert_not_called()

    def test_advisory_summary_and_full_are_typed_unavailable_without_project_reads(self):
        module = _public_module()
        for advisory in ("summary", "full"):
            with self.subTest(advisory=advisory):
                inspector = mock.Mock(side_effect=AssertionError("project inspected"))
                readers = {kind: mock.Mock() for kind in ("project", "lane", "key", "operation")}
                outcome = _dispatch(
                    module,
                    _status_request(advisory=advisory),
                    inspector=inspector,
                    readers=readers,
                )
                self.assertEqual(outcome["outcome_kind"], "status_capability_unavailable")
                self.assertEqual(outcome["result"]["detail_code"], "query_status.advisory_unavailable")
                inspector.assert_not_called()
                for reader in readers.values():
                    reader.assert_not_called()

    def test_all_four_selectors_call_only_the_matching_private_reader(self):
        module = _public_module()
        for kind in ("project", "lane", "key", "operation"):
            with self.subTest(kind=kind):
                inspection = _inspection()
                readers = {
                    candidate: mock.Mock(return_value=inspection)
                    for candidate in ("project", "lane", "key", "operation")
                }
                inspector = mock.Mock(return_value=True)
                outcome = _dispatch(
                    module,
                    _status_request(_selector(kind)),
                    inspector=inspector,
                    readers=readers,
                )
                self.assertEqual(outcome["operation"], "query.status")
                readers[kind].assert_called_once()
                for other, reader in readers.items():
                    if other != kind:
                        reader.assert_not_called()

    def test_status_mapping_preserves_the_ten_public_outcome_states(self):
        module = _public_module()
        cases = (
            ("active", "query_status.project_active", "status_observed", "succeeded", 0),
            ("absent", "query_status.project_absent", "status_observed", "succeeded", 0),
            ("busy", "query_status.busy", "status_busy", "in_progress", 40),
            (
                "reconciliation_required",
                "query_status.reconciliation_required",
                "status_reconciliation_required",
                "reconciliation_required",
                40,
            ),
            ("cursor_stale", "query_status.cursor_stale", "cursor_stale", "failed", 40),
            ("quarantined", "query_status.quarantined", "status_quarantined", "quarantined", 50),
            (
                "unavailable",
                "query_status.observation_unavailable",
                "status_capability_unavailable",
                "failed",
                20,
            ),
        )
        adapter = getattr(module, "adapt_status", None)
        if not callable(adapter):
            raise AssertionError("ask_herdr_public_status must expose adapt_status")
        for status, detail, kind, outcome_status, exit_class in cases:
            with self.subTest(status=status):
                inspection = _inspection(
                    status=status,
                    detail_code=detail,
                    normalized_digest=None if status == "unavailable" else DIGEST,
                )
                reader = mock.Mock(return_value=inspection)
                readers = {
                    candidate: (reader if candidate == "project" else mock.Mock())
                    for candidate in ("project", "lane", "key", "operation")
                }
                envelope = _dispatch(
                    module,
                    _status_request(),
                    inspector=mock.Mock(return_value=True),
                    readers=readers,
                )
                self.assertEqual(
                    (envelope["outcome_kind"], envelope["status"], envelope["exit_class"]),
                    (kind, outcome_status, exit_class),
                )

    def test_pagination_and_operation_cardinality_are_preserved_at_public_seam(self):
        module = _public_module()
        adapter = getattr(module, "adapt_status", None)
        if not callable(adapter):
            raise AssertionError("ask_herdr_public_status must expose adapt_status")
        page = adapter(
            _inspection(entries=(_lane_head(),), next_cursor="mcv1.next"),
            _selector(),
        )
        self.assertEqual(len(page["entries"]), 1)
        self.assertEqual(page["next_cursor"], "mcv1.next")
        operation = adapter(
            _inspection(
                entries=(_lane_head(),),
                next_cursor=None,
                operation_metadata=_operation_metadata(),
            ),
            _selector("operation"),
        )
        self.assertEqual(operation["next_cursor"], None)
        self.assertEqual(
            list(operation["operation_metadata"]),
            [
                "operation_id",
                "operation",
                "canonical_request_digest",
                "lane_association",
            ],
        )

    def test_real_disposable_project_read_is_provider_free_and_path_free(self):
        from ask_herdr_project_status import read_project_status

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            binding = ValidatedProjectMutationBinding(
                canonical_root=str(root),
                filesystem_device=root.stat().st_dev,
                filesystem_inode=root.stat().st_ino,
                owner_uid=os.getuid(),
                project_authority_id=AUTHORITY_ID,
            )
            inspection = read_project_status(
                binding,
                limit=1,
                cursor=None,
                clock=lambda: OBSERVED_AT,
            )
        self.assertIn(
            inspection.status,
            {"active", "absent", "busy", "reconciliation_required", "quarantined"},
        )
        self.assertNotIn(str(root), repr(inspection))

    def test_bound_root_failure_is_typed_and_does_not_echo_private_exception_text(self):
        module = _public_module()
        secret = "/private/secret/project-root MUST_NOT_LEAK token=abc123"
        request = _status_request()
        inspector = mock.Mock(side_effect=RuntimeError(secret))
        readers = {kind: mock.Mock() for kind in ("project", "lane", "key", "operation")}
        outcome = _dispatch(module, request, inspector=inspector, readers=readers)
        serialized = json.dumps(outcome, sort_keys=True)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("abc123", serialized)
        self.assertIn(
            outcome["outcome_kind"],
            {
                "status_capability_unavailable",
                "request_not_currently_admissible",
                "request_reconciliation_required",
                "request_quarantined",
            },
        )

    def test_source_owned_true_default_cannot_be_disabled_by_environment_or_config(self):
        environment = dict(os.environ)
        environment.update(
            {
                "ASK_HERDR_PUBLIC_BETA": "0",
                "ASK_HERDR_MACHINE_RUN": "0",
                "ASK_HERDR_ACTIVATION": "0",
                "ASK_HERDR_PUBLIC_BETA_ACTIVE": "0",
                "ASK_HERDR_CONFIG": "/private/secret/config.json",
            }
        )
        completed = self.invoke_subprocess(
            "machine", "describe", "--json", environment=environment
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        description = json.loads(completed.stdout)
        self.assertTrue(description["features"]["machine_run"])
        self.assertFalse(description["features"]["human_facade"])
        self.assertEqual(description["schema"], "ask_herdr.describe.v3")
        self.assertEqual(description["cli_version"], "0.4.0")


if __name__ == "__main__":
    unittest.main()
