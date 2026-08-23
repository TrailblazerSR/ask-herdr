#!/usr/bin/env python3
"""Cross-platform acceptance tests for the public Machine Core surface."""

from __future__ import annotations

import builtins
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "bin" / "ask-herdr"
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_platform import (  # noqa: E402
    runtime_execution_supported,
    runtime_platform,
)
from ask_herdr_request_schema import (  # noqa: E402
    CANONICAL_ABSOLUTE_PATH_PATTERN,
)


ACTIVE_SCHEMA_IDS = [
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
]

LEGACY_SCHEMA_HASHES = {
    "ask_herdr.describe.v1.schema.json": (
        "16246349e9c545b715bfbd1c2b91ecd054c7417d717df54c9fca4e6469d52285"
    ),
    "ask_herdr.describe.v2.schema.json": (
        "edb585a608e612556229c35c29c29ad42c765b3f2bdfa6007e048642d196fc7c"
    ),
    "ask_herdr.outcome.v1.schema.json": (
        "7ad13340c0a2ea4be8831f55fdcc38d80de85da7e8eb1c08d30818e76e8b67eb"
    ),
    "ask_herdr.outcome.v2.schema.json": (
        "1162eeb5093f06cbebaec6b823029cf9b711f5bad8f6a36f7723e33eb106dee6"
    ),
    "ask_herdr.query.status.result.v1.schema.json": (
        "091202d0f4acf3b75072160deec8cf30e400647fbedf728a9aba01326703fb23"
    ),
    "ask_herdr.request.v1.schema.json": (
        "cd794d4aa4f02df95322728830ae4bb12d0f67d9b376f86b2f4d6d5610b0c799"
    ),
    "ask_herdr.schema_document.v1.schema.json": (
        "1d3b3abb22a85d81eab6d7cf81eded57d13d318ccaca6e081a0b999eadaa64ae"
    ),
    "ask_herdr.schema_document.v2.schema.json": (
        "7a78c81d9a0c4ee4b9dd858ea1bfc427f15ddc19cd86753b1cc8a4b6d3c351d6"
    ),
}

WINDOWS_PROFILE = {
    "schema": "ask_herdr.runtime_platform.v1",
    "os_family": "windows",
    "path_flavor": "windows",
    "execution_tier": "contract_only",
    "storage_profile": "unavailable",
    "supported_operations": [],
    "limitations": ["native_windows_project_store_unavailable"],
}


@contextmanager
def _load_cli_as_win32():
    """Load the static CLI while making every private storage import fatal."""

    blocked = (
        "fcntl",
        "ask_herdr_authority_store",
        "ask_herdr_capsule",
        "ask_herdr_darwin_capsule",
        "ask_herdr_evidence_registry",
        "ask_herdr_lane_store",
        "ask_herdr_linux_capsule",
        "ask_herdr_machine_validate",
        "ask_herdr_public_status",
        "ask_herdr_recovery_result_store",
        "ask_herdr_topology_store",
    )
    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fcntl" or any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in blocked[1:]
        ):
            raise AssertionError(f"static Windows surface imported {name}")
        return original_import(name, globals, locals, fromlist, level)

    module_name = "ask_herdr_cli_simulated_win32_portability_test"
    loader = SourceFileLoader(module_name, str(CLI))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load bin/ask-herdr")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        with (
            mock.patch.object(sys, "platform", "win32"),
            mock.patch("builtins.__import__", side_effect=guarded_import),
        ):
            spec.loader.exec_module(module)
            yield module
    finally:
        sys.modules.pop(module_name, None)


class PlatformPortabilityTest(unittest.TestCase):
    def test_runtime_profiles_are_closed_and_explicit(self):
        cases = {
            ("darwin", "posix"): {
                "schema": "ask_herdr.runtime_platform.v1",
                "os_family": "macos",
                "path_flavor": "posix",
                "execution_tier": "full",
                "storage_profile": "darwin-exclusive-capsule-v1",
                "supported_operations": ["query.status"],
                "limitations": [],
            },
            ("linux", "posix"): {
                "schema": "ask_herdr.runtime_platform.v1",
                "os_family": "linux",
                "path_flavor": "posix",
                "execution_tier": "full",
                "storage_profile": "linux-exclusive-capsule-v1",
                "supported_operations": ["query.status"],
                "limitations": [],
            },
            ("win32", "nt"): WINDOWS_PROFILE,
            ("plan9", "posix"): {
                "schema": "ask_herdr.runtime_platform.v1",
                "os_family": "other",
                "path_flavor": "posix",
                "execution_tier": "contract_only",
                "storage_profile": "unavailable",
                "supported_operations": [],
                "limitations": ["platform_storage_backend_unavailable"],
            },
        }
        for (platform_name, os_name), expected in cases.items():
            with self.subTest(platform_name=platform_name, os_name=os_name):
                self.assertEqual(
                    runtime_platform(platform_name, os_name),
                    expected,
                )
                self.assertEqual(
                    runtime_execution_supported(platform_name, os_name),
                    expected["execution_tier"] == "full",
                )

    def test_current_runtime_selects_one_explicit_capsule_adapter(self):
        capsule = importlib.import_module("ask_herdr_capsule")
        profile = runtime_platform()
        if profile["os_family"] == "macos":
            self.assertEqual(
                capsule.commit_exclusive.__module__,
                "ask_herdr_darwin_capsule",
            )
        elif profile["os_family"] == "linux":
            self.assertEqual(
                capsule.commit_exclusive.__module__,
                "ask_herdr_linux_capsule",
            )
        else:
            self.assertEqual(capsule.probe_capability(-1), False)
            with self.assertRaises(OSError) as raised:
                capsule.commit_exclusive(-1, "source", "dest")
            self.assertEqual(raised.exception.errno, errno.ENOTSUP)

    def test_win32_static_surface_loads_without_private_storage_imports(self):
        with _load_cli_as_win32() as module:
            description = module.describe(activation=True)
            self.assertEqual(description["schema"], "ask_herdr.describe.v3")
            self.assertEqual(description["cli_version"], "0.4.0")
            self.assertEqual(description["runtime_platform"], WINDOWS_PROFILE)
            self.assertEqual(
                description["features"],
                {
                    "human_facade": False,
                    "machine_describe": True,
                    "machine_run": False,
                    "machine_schema": True,
                    "machine_validate": False,
                },
            )
            self.assertEqual(
                [item["schema_id"] for item in description["schema_documents"]],
                ACTIVE_SCHEMA_IDS,
            )
            wrapper = module.schema_document(
                "ask_herdr.describe.v3",
                activation=True,
            )
            self.assertEqual(wrapper["schema"], "ask_herdr.schema_document.v3")

            for command in ("validate", "run"):
                with self.subTest(command=command):
                    stderr = io.StringIO()
                    stdout = io.StringIO()
                    with (
                        mock.patch.object(
                            module,
                            "capture_request_file",
                            side_effect=AssertionError("request was read"),
                        ) as capture_file,
                        mock.patch.object(
                            module,
                            "capture_request_stdin",
                            side_effect=AssertionError("stdin was read"),
                        ) as capture_stdin,
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                    ):
                        exit_class = module.main(
                            [
                                "machine",
                                command,
                                "--request",
                                r"C:\private\request.json",
                            ],
                            activation=True,
                        )
                    self.assertEqual(exit_class, 20)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(
                        stderr.getvalue(),
                        "ask-herdr machine "
                        f"{command} failed: runtime.platform_unsupported\n",
                    )
                    capture_file.assert_not_called()
                    capture_stdin.assert_not_called()

    def test_native_discovery_reports_the_current_runtime_profile(self):
        completed = subprocess.run(
            [sys.executable, str(CLI), "machine", "describe", "--json"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        description = json.loads(completed.stdout)
        profile = runtime_platform()
        self.assertEqual(description["runtime_platform"], profile)
        full = profile["execution_tier"] == "full"
        self.assertEqual(description["features"]["machine_validate"], full)
        self.assertEqual(description["features"]["machine_run"], full)

    def test_v1_path_grammar_remains_posix_and_legacy_bytes_are_immutable(self):
        self.assertIsNotNone(
            re.fullmatch(CANONICAL_ABSOLUTE_PATH_PATTERN, "/project/request.json")
        )
        self.assertIsNone(
            re.fullmatch(
                CANONICAL_ABSOLUTE_PATH_PATTERN,
                r"C:\project\request.json",
            )
        )
        for filename, expected in LEGACY_SCHEMA_HASHES.items():
            with self.subTest(filename=filename):
                payload = (ROOT / "schemas" / filename).read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)

    def test_contract_files_are_checkout_stable_on_windows(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        for required_rule in (
            "/bin/* text eol=lf",
            "/lib/*.py text eol=lf",
            "/schemas/*.json text eol=lf",
            "/scripts/*.py text eol=lf",
            "/tests/*.py text eol=lf",
            "/.github/workflows/*.yml text eol=lf",
        ):
            self.assertIn(required_rule, attributes)


if __name__ == "__main__":
    unittest.main()
