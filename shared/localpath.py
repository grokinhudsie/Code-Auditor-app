"""Validation for local-directory scan sources.

Local scans copy a directory from the docker HOST into the scan sandbox, so
the path here is a host path. The feature is off unless ALLOW_LOCAL_SCANS is
set, and SCAN_PATH_ROOT can further confine paths to one directory tree. Both
the API and the worker call these (defense in depth, like GIT_URL_RE).
"""

import os
import posixpath

# Never scannable even when local scans are enabled: system trees and, via
# /var, the docker socket. /private/* covers the macOS real locations.
DENY_PREFIXES = (
    "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/opt",
    "/proc", "/sys", "/dev", "/boot", "/root",
    "/private/etc", "/private/var",
)

MAX_PATH_LEN = 4096


def local_scans_enabled() -> bool:
    return os.environ.get("ALLOW_LOCAL_SCANS", "").strip().lower() in ("1", "true", "yes")


def _is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def validate_local_path(path: str) -> str:
    """Return the normalized host path, or raise ValueError with a reason."""
    path = path.strip()
    if not path:
        raise ValueError("local_path is empty")
    if len(path) > MAX_PATH_LEN:
        raise ValueError("local_path is too long")
    # ":" would corrupt the docker bind spec (host:container:mode).
    for bad in ("\0", ":", "\n", "\r"):
        if bad in path:
            raise ValueError("local_path contains forbidden characters")
    if not path.startswith("/"):
        raise ValueError("local_path must be an absolute path")
    if ".." in path.split("/"):
        raise ValueError("local_path must not contain '..'")

    normalized = posixpath.normpath(path)
    if normalized == "/":
        raise ValueError("cannot scan the filesystem root")
    for prefix in DENY_PREFIXES:
        if _is_under(normalized, prefix):
            raise ValueError(f"local_path under {prefix} is not allowed")

    root = os.environ.get("SCAN_PATH_ROOT", "").strip()
    if root and not _is_under(normalized, posixpath.normpath(root)):
        raise ValueError(f"local_path must be under {root}")
    return normalized
