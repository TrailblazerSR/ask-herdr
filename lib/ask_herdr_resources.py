"""Resolve immutable schema resources in a checkout or installed wheel."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


SCHEMA_PACKAGE = "ask_herdr_schemas"
SOURCE_SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas"


def schema_path(filename: str) -> Path:
    """Return one schema as a real filesystem path without changing its bytes."""

    if Path(filename).name != filename or not filename.endswith(".schema.json"):
        raise ValueError("schema filename must be one local .schema.json name")
    if SOURCE_SCHEMA_ROOT.is_dir():
        return SOURCE_SCHEMA_ROOT / filename
    try:
        packaged = resources.files(SCHEMA_PACKAGE).joinpath(filename)
    except ModuleNotFoundError as error:
        raise RuntimeError("bundled schema package is unavailable") from error
    if not isinstance(packaged, Path):
        raise RuntimeError("bundled schemas must be filesystem-backed resources")
    return packaged
