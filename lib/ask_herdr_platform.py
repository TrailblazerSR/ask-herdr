"""Pure runtime-platform capability discovery for the Ask-Herdr CLI."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional


RUNTIME_PLATFORM_SCHEMA_ID = "ask_herdr.runtime_platform.v1"


def runtime_platform(
    platform_name: Optional[str] = None,
    os_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the closed, path-free capability projection for this runtime."""

    detected_platform = sys.platform if platform_name is None else platform_name
    detected_os = os.name if os_name is None else os_name
    if detected_platform == "darwin":
        os_family = "macos"
        storage_profile = "darwin-exclusive-capsule-v1"
    elif detected_platform.startswith("linux"):
        os_family = "linux"
        storage_profile = "linux-exclusive-capsule-v1"
    elif detected_platform in {"win32", "cygwin", "msys"} or detected_os == "nt":
        os_family = "windows"
        storage_profile = "unavailable"
    else:
        os_family = "other"
        storage_profile = "unavailable"

    full = os_family in {"macos", "linux"}
    if full:
        limitations = []
    elif os_family == "windows":
        limitations = ["native_windows_project_store_unavailable"]
    else:
        limitations = ["platform_storage_backend_unavailable"]
    return {
        "schema": RUNTIME_PLATFORM_SCHEMA_ID,
        "os_family": os_family,
        "path_flavor": "windows" if os_family == "windows" else "posix",
        "execution_tier": "full" if full else "contract_only",
        "storage_profile": storage_profile,
        "supported_operations": ["query.status"] if full else [],
        "limitations": limitations,
    }


def runtime_execution_supported(
    platform_name: Optional[str] = None,
    os_name: Optional[str] = None,
) -> bool:
    """Return whether validate/run may import the private storage runtime."""

    return runtime_platform(platform_name, os_name)["execution_tier"] == "full"


__all__ = (
    "RUNTIME_PLATFORM_SCHEMA_ID",
    "runtime_execution_supported",
    "runtime_platform",
)
