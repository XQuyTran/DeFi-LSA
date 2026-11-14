from pathlib import Path

import pytest

from defi_lsa.runtime import preflight_internet, preflight_output_root, resolve_output_root


def test_resolve_output_root_prefers_restored_output(tmp_path: Path) -> None:
    output = tmp_path / "output"
    (output / "data").mkdir(parents=True)
    (output / "runs" / "checkpoints").mkdir(parents=True)

    assert resolve_output_root(output) == output
    assert resolve_output_root(tmp_path / "fresh") == tmp_path / "fresh"


def test_resolve_output_root_accepts_explicit_root(tmp_path: Path) -> None:
    explicit = tmp_path / "attached"

    assert resolve_output_root(tmp_path / "output", explicit) == explicit


def test_preflight_output_root_reports_success(tmp_path: Path) -> None:
    result = preflight_output_root(tmp_path, minimum_free_bytes=1)

    assert result["passed"] is True
    assert result["disk_space_ok"] is True
    assert result["writable"] is True


def test_preflight_output_root_rejects_insufficient_space(tmp_path: Path) -> None:
    result = preflight_output_root(tmp_path, minimum_free_bytes=10**30)

    assert result["passed"] is False
    assert result["disk_space_ok"] is False


def test_preflight_rejects_negative_space_requirement(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="minimum_free_bytes"):
        preflight_output_root(tmp_path, minimum_free_bytes=-1)


def test_preflight_internet_uses_injected_opener() -> None:
    class Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    result = preflight_internet("https://example.test", opener=lambda *_args, **_kwargs: Response())

    assert result == {"reachable": True, "status": 204}


def test_preflight_internet_redacts_failure_to_exception_type() -> None:
    def opener(*_args, **_kwargs):
        raise RuntimeError("https://secret.example/token")

    result = preflight_internet("https://example.test", opener=opener)

    assert result == {"reachable": False, "error_type": "RuntimeError"}