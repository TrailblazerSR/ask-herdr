#!/usr/bin/env python3
"""Verify the installed console command from outside the source checkout."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMAND = [sys.executable, str(ROOT / "bin" / "ask-herdr")]


def invoke(command: list[str], arguments: list[str], cwd: Path) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [*command, *arguments],
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_parity(
    installed_command: list[str], arguments: list[str], cwd: Path
) -> subprocess.CompletedProcess:
    source = invoke(SOURCE_COMMAND, arguments, cwd)
    installed = invoke(installed_command, arguments, cwd)
    if (
        installed.returncode != source.returncode
        or installed.stdout != source.stdout
        or installed.stderr != source.stderr
    ):
        raise RuntimeError(f"installed command differs for: {' '.join(arguments)}")
    return installed


def main() -> int:
    executable = shutil.which("ask-herdr")
    if executable is None:
        raise RuntimeError("installed ask-herdr command is not on PATH")
    with tempfile.TemporaryDirectory(prefix="ask-herdr-installed-smoke-") as temporary:
        unrelated_cwd = Path(temporary)
        described = require_parity(
            [executable], ["machine", "describe", "--json"], unrelated_cwd
        )
        if described.returncode != 0 or described.stderr != "":
            raise RuntimeError("installed discovery did not succeed cleanly")
        description = json.loads(described.stdout)
        schema_documents = description.get("schema_documents")
        if not isinstance(schema_documents, list) or len(schema_documents) != 10:
            raise RuntimeError("installed discovery did not advertise ten schemas")
        for metadata in schema_documents:
            schema_id = metadata["schema_id"]
            wrapped = require_parity(
                [executable],
                ["machine", "schema", "--id", schema_id],
                unrelated_cwd,
            )
            document = json.loads(wrapped.stdout)
            if document["schema_id"] != schema_id:
                raise RuntimeError(f"installed schema mismatch: {schema_id}")
            if document["sha256"] != metadata["sha256"]:
                raise RuntimeError(f"installed schema digest mismatch: {schema_id}")
        if (unrelated_cwd / ".ask-herdr").exists():
            raise RuntimeError("installed discovery created runtime state")
    print("installed ask-herdr: source parity and 10/10 schemas verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
