"""Platform selector for the exclusive capsule durability primitives."""

from __future__ import annotations

import errno
from typing import NoReturn

from ask_herdr_capsule_contract import CommitDisposition
from ask_herdr_platform import runtime_platform


_PLATFORM = runtime_platform()
if _PLATFORM["os_family"] == "macos":
    from ask_herdr_darwin_capsule import (
        commit_exclusive,
        fullsync_file,
        probe_capability,
    )
elif _PLATFORM["os_family"] == "linux":
    from ask_herdr_linux_capsule import (
        commit_exclusive,
        fullsync_file,
        probe_capability,
    )
else:
    def probe_capability(anchor_fd: int) -> bool:
        """Report no storage backend on contract-only platforms."""

        return False


    def _unsupported() -> NoReturn:
        raise OSError(
            errno.ENOTSUP,
            "exclusive capsule storage is unavailable on this platform",
            "ask_herdr_capsule",
        )


    def fullsync_file(fd: int) -> None:
        """Reject storage synchronization on contract-only platforms."""

        _unsupported()


    def commit_exclusive(
        parent_fd: int,
        source: str,
        dest: str,
    ) -> CommitDisposition:
        """Reject capsule publication on contract-only platforms."""

        _unsupported()


__all__ = (
    "CommitDisposition",
    "commit_exclusive",
    "fullsync_file",
    "probe_capability",
)
