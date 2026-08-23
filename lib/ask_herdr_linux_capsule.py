"""Linux durability primitives for exclusive capsule publication.

The adapter uses ``renameat2(RENAME_NOREPLACE)`` directly.  It deliberately
offers no check-then-rename or overwriting fallback when that primitive is not
available on the running libc/kernel/filesystem combination.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import stat
from typing import NoReturn

from ask_herdr_capsule_contract import CommitDisposition


RENAME_NOREPLACE = 1
_BASENAME = re.compile(r"[A-Za-z0-9._-]{1,255}")
_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int


def _raise_errno(function_name: str) -> NoReturn:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number), function_name)


def _directory_fd(value: int, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"linux_capsule.{field}_invalid")
    if not stat.S_ISDIR(os.fstat(value).st_mode):
        raise OSError(errno.ENOTDIR, "descriptor is not a directory", field)
    return value


def _basename_bytes(value: str, field: str) -> bytes:
    if (
        type(value) is not str
        or value in {".", ".."}
        or _BASENAME.fullmatch(value) is None
    ):
        raise ValueError(f"linux_capsule.{field}_invalid")
    return value.encode("ascii")


def probe_capability(anchor_fd: int) -> bool:
    """Return whether the runtime exposes the required exclusive rename call."""

    _directory_fd(anchor_fd, "anchor_fd")
    return _RENAMEAT2 is not None


def fullsync_file(fd: int) -> None:
    """Synchronize one regular file through the Linux durability boundary."""

    if type(fd) is not int or fd < 0:
        raise ValueError("linux_capsule.file_fd_invalid")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError(errno.EINVAL, "file descriptor is not regular", "fsync")
    os.fsync(fd)


def commit_exclusive(
    parent_fd: int,
    source: str,
    dest: str,
) -> CommitDisposition:
    """Atomically promote one direct child without overwriting its destination."""

    _directory_fd(parent_fd, "parent_fd")
    source_bytes = _basename_bytes(source, "source_basename")
    dest_bytes = _basename_bytes(dest, "dest_basename")
    if _RENAMEAT2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable", "renameat2")
    ctypes.set_errno(0)
    if (
        _RENAMEAT2(
            parent_fd,
            source_bytes,
            parent_fd,
            dest_bytes,
            RENAME_NOREPLACE,
        )
        == 0
    ):
        return CommitDisposition.COMMITTED
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        return CommitDisposition.OCCUPIED
    _raise_errno("renameat2")


__all__ = (
    "CommitDisposition",
    "commit_exclusive",
    "fullsync_file",
    "probe_capability",
)
