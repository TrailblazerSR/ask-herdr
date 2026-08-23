"""Darwin-only durability primitives for exclusive capsule publication.

This private Adapter owns the native calls required by the Exclusive Capsule
Journal.  It deliberately exposes no weaker rename or sync fallback.
"""

from __future__ import annotations

import ctypes
import errno
from enum import Enum
import fcntl
import os
import re
import stat
from typing import NoReturn


ATTR_BIT_MAP_COUNT = 5
ATTR_VOL_INFO = 0x80000000
ATTR_VOL_CAPABILITIES = 0x00020000
VOL_CAPABILITIES_INTERFACES = 1
VOL_CAP_INT_RENAME_EXCL = 0x00080000
F_FULLFSYNC = 51
RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010
_COMMIT_FLAGS = RENAME_EXCL | RENAME_NOFOLLOW_ANY
_BASENAME = re.compile(r"[A-Za-z0-9._-]{1,255}")


class CommitDisposition(str, Enum):
    """The only non-error outcomes of an exclusive capsule commit."""

    COMMITTED = "committed"
    OCCUPIED = "occupied"


class _AttrList(ctypes.Structure):
    _fields_ = (
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    )


class _VolumeCapabilities(ctypes.Structure):
    _fields_ = (
        ("capabilities", ctypes.c_uint32 * 4),
        ("valid", ctypes.c_uint32 * 4),
    )


class _CapabilityBuffer(ctypes.Structure):
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("volume", _VolumeCapabilities),
    )


_LIBC = ctypes.CDLL(None, use_errno=True)
_FGETATTRLIST = _LIBC.fgetattrlist
_FGETATTRLIST.argtypes = (
    ctypes.c_int,
    ctypes.POINTER(_AttrList),
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_uint,
)
_FGETATTRLIST.restype = ctypes.c_int
_RENAMEATX_NP = _LIBC.renameatx_np
_RENAMEATX_NP.argtypes = (
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
)
_RENAMEATX_NP.restype = ctypes.c_int


def _raise_errno(function_name: str) -> NoReturn:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number), function_name)


def probe_capability(anchor_fd: int) -> bool:
    """Return whether the anchor volume validly advertises exclusive rename."""

    if type(anchor_fd) is not int or anchor_fd < 0:
        raise ValueError("darwin_capsule.anchor_fd_invalid")
    attributes = _AttrList(
        bitmapcount=ATTR_BIT_MAP_COUNT,
        volattr=ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES,
    )
    result = _CapabilityBuffer()
    ctypes.set_errno(0)
    if (
        _FGETATTRLIST(
            anchor_fd,
            ctypes.byref(attributes),
            ctypes.byref(result),
            ctypes.sizeof(result),
            0,
        )
        != 0
    ):
        _raise_errno("fgetattrlist")
    if result.length < ctypes.sizeof(result):
        raise OSError(errno.EIO, "short volume capability response", "fgetattrlist")
    valid = result.volume.valid[VOL_CAPABILITIES_INTERFACES]
    supported = result.volume.capabilities[VOL_CAPABILITIES_INTERFACES]
    return bool(
        valid & VOL_CAP_INT_RENAME_EXCL
        and supported & VOL_CAP_INT_RENAME_EXCL
    )


def fullsync_file(fd: int) -> None:
    """Request Darwin full-media synchronization for one regular file."""

    if type(fd) is not int or fd < 0:
        raise ValueError("darwin_capsule.file_fd_invalid")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise OSError(errno.EINVAL, "file descriptor is not regular", "F_FULLFSYNC")
    fcntl.fcntl(fd, F_FULLFSYNC)


def _basename_bytes(value: str, field: str) -> bytes:
    if (
        type(value) is not str
        or value in {".", ".."}
        or _BASENAME.fullmatch(value) is None
    ):
        raise ValueError(f"darwin_capsule.{field}_invalid")
    return value.encode("ascii")


def commit_exclusive(
    parent_fd: int,
    source: str,
    dest: str,
) -> CommitDisposition:
    """Atomically promote one direct child without following or overwriting."""

    if type(parent_fd) is not int or parent_fd < 0:
        raise ValueError("darwin_capsule.parent_fd_invalid")
    if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
        raise OSError(errno.ENOTDIR, "parent descriptor is not a directory")
    source_bytes = _basename_bytes(source, "source_basename")
    dest_bytes = _basename_bytes(dest, "dest_basename")
    ctypes.set_errno(0)
    if (
        _RENAMEATX_NP(
            parent_fd,
            source_bytes,
            parent_fd,
            dest_bytes,
            _COMMIT_FLAGS,
        )
        == 0
    ):
        return CommitDisposition.COMMITTED
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        return CommitDisposition.OCCUPIED
    raise OSError(error_number, os.strerror(error_number), "renameatx_np")
