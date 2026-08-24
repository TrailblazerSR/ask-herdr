"""Shared contract for platform-specific exclusive capsule adapters."""

from __future__ import annotations

from enum import Enum


class CommitDisposition(str, Enum):
    """The only non-error outcomes of an exclusive capsule commit."""

    COMMITTED = "committed"
    OCCUPIED = "occupied"


__all__ = ("CommitDisposition",)
