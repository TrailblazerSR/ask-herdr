#!/usr/bin/env python3
"""Write or verify deterministic generated Machine Core schema documents."""

from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from ask_herdr_json import canonical_json
from ask_herdr_discovery_contract import (
    DESCRIBE_V3_SCHEMA_PATH,
    SCHEMA_DOCUMENT_V3_SCHEMA_PATH,
    build_describe_v3_schema,
    build_schema_document_v3_schema,
)
from ask_herdr_outcome_contract import (
    OUTCOME_SCHEMA_PATH,
    build_validation_outcome_schema,
)
from ask_herdr_request_schema import REQUEST_SCHEMA_PATH, build_request_schema


def rendered(document):
    return canonical_json(document) + b"\n"


def write_exact(path, payload):
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError(f"stale generated-schema temporary: {temporary}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def main(argv):
    if argv not in (["--write"], ["--check"]):
        print("usage: build_contract_schemas.py --write|--check", file=sys.stderr)
        return 64
    generated = (
        (REQUEST_SCHEMA_PATH, rendered(build_request_schema())),
        (OUTCOME_SCHEMA_PATH, rendered(build_validation_outcome_schema())),
        (DESCRIBE_V3_SCHEMA_PATH, rendered(build_describe_v3_schema())),
        (
            SCHEMA_DOCUMENT_V3_SCHEMA_PATH,
            rendered(build_schema_document_v3_schema()),
        ),
    )
    if argv == ["--write"]:
        for path, payload in generated:
            write_exact(path, payload)
            print(f"written {path.relative_to(ROOT)}")
        return 0
    for path, payload in generated:
        if path.is_symlink() or path.read_bytes() != payload:
            print(f"generated schema drift: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(f"valid {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
