from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_scanner():
    path = ROOT / "bin" / "scan-release-secrets.py"
    spec = importlib.util.spec_from_file_location("scan_release_secrets_v316", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_current_release_tree_has_no_reportable_secret_literals() -> None:
    scanner = _load_scanner()
    result = scanner.scan_repository(ROOT, include_history=False)

    assert result["status"] == "clean"
    assert result["findings"] == []
    assert result["current_files_scanned"] > 0


def test_history_scan_reports_category_and_oid_without_echoing_secret(
    tmp_path: Path,
) -> None:
    scanner = _load_scanner()
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Secret Scanner Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    synthetic = "github" + "_pat_" + "A" * 48
    (repo / "leak.txt").write_text(synthetic + "\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "commit", "-qm", "fixture")
    (repo / "leak.txt").write_text("removed\n", encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "commit", "-qm", "remove fixture")

    result = scanner.scan_repository(repo, include_history=True)

    encoded = str(result)
    assert result["status"] == "findings"
    assert any(row["category"] == "github-token" for row in result["findings"])
    assert synthetic not in encoded
    assert all("value" not in row for row in result["findings"])


def test_git_output_budget_is_enforced_while_streaming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()

    class Stream:
        def __init__(self, chunks: list[bytes]):
            self._chunks = iter(chunks)

        def read(self, _size: int) -> bytes:
            return next(self._chunks, b"")

    class Process:
        def __init__(self):
            self.stdout = Stream([b"1234", b"5678"])
            self.stderr = Stream([])
            self.returncode = 0
            self.killed = False

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            del timeout
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = Process()
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(scanner.SecretScanError, match="output budget"):
        scanner._run_git(tmp_path, ["status"], maximum=4)

    assert process.killed is True
