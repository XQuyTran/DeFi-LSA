"""Runtime preflight and restored-output discovery helpers."""

import shutil
import tempfile
from pathlib import Path
from typing import Any


_RESTORED_MARKERS = ("data", "checkpoints", "reports")


def _has_restored_artifacts(path: Path) -> bool:
    return any((path / marker).exists() for marker in _RESTORED_MARKERS)


def resolve_output_root(output: Path, data_dir: Path | None = None) -> Path:
    """Select an explicit, restored, or conventional collection root."""
    if data_dir is not None:
        return data_dir
    if _has_restored_artifacts(output):
        return output
    runs_root = output / "runs"
    if _has_restored_artifacts(runs_root):
        return runs_root
    return output


def _check_writable(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=".defi-lsa-write-test-", dir=path, delete=True):
        pass


def preflight_output_root(
    output_root: Path,
    *,
    minimum_free_bytes: int = 1_000_000_000,
) -> dict[str, Any]:
    """Validate disk space and output-root writability before collection.

    The returned structure is safe to persist: it contains paths and numeric
    measurements only, never source URLs or credential values.
    """
    if minimum_free_bytes < 0:
        raise ValueError("minimum_free_bytes must be non-negative")

    resolved = output_root.expanduser().resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(resolved)
    writable = True
    writable_error = ""
    try:
        _check_writable(resolved)
    except OSError as exc:
        writable = False
        writable_error = type(exc).__name__

    result = {
        "output_root": str(resolved),
        "restored_output": _has_restored_artifacts(resolved),
        "free_bytes": usage.free,
        "minimum_free_bytes": minimum_free_bytes,
        "disk_space_ok": usage.free >= minimum_free_bytes,
        "writable": writable,
    }
    if writable_error:
        result["writable_error"] = writable_error
    result["passed"] = bool(result["disk_space_ok"] and writable)
    return result


def preflight_internet(
    url: str,
    *,
    opener: Any | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Perform a lightweight network reachability check without exposing URLs."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("internet probe URL must be HTTP(S)")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    if opener is None:
        from urllib.request import urlopen

        opener = urlopen
    try:
        with opener(url, timeout=timeout) as response:
            status = getattr(response, "status", None)
            return {"reachable": True, "status": status}
    except Exception as exc:
        return {"reachable": False, "error_type": type(exc).__name__}
