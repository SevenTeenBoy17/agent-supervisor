from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
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


def _configure_trusted_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    executable: Path | None = None,
) -> Path:
    if executable is None:
        discovered = shutil.which("git")
        assert discovered is not None
        executable = Path(discovered).resolve(strict=True)
    home = tmp_path / "install-home"
    registry = home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(
        json.dumps(
            {
                "contract": "TrustedExecutableRegistry/v1",
                "entries": {
                    "git": {
                        "kind": "local",
                        "path": str(executable),
                        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    }
                },
                "generated_at": "2000-01-01T00:00:00Z",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(home))
    return executable


def test_current_release_tree_has_no_reportable_secret_literals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    _configure_trusted_git(tmp_path, monkeypatch)
    result = scanner.scan_repository(ROOT, include_history=False)

    assert result["status"] == "clean"
    assert result["findings"] == []
    assert result["current_files_scanned"] > 0


def test_non_git_release_tree_is_scanned_without_git_metadata(
    tmp_path: Path,
) -> None:
    scanner = _load_scanner()
    release = tmp_path / "release"
    runner = release / "bin" / "run-coderabbit-review.py"
    runner.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "bin" / "run-coderabbit-review.py", runner)
    (release / "README.md").write_text("public release\n", encoding="utf-8")

    result = scanner.scan_repository(release, include_history=False)

    assert result["status"] == "clean"
    assert result["current_files_scanned"] == 2


def test_non_git_release_tree_rejects_history_scan(tmp_path: Path) -> None:
    scanner = _load_scanner()
    release = tmp_path / "release"
    runner = release / "bin" / "run-coderabbit-review.py"
    runner.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "bin" / "run-coderabbit-review.py", runner)

    with pytest.raises(scanner.SecretScanError, match="history is unavailable"):
        scanner.scan_repository(release, include_history=True)


@pytest.mark.parametrize("nested", [False, True], ids=["root", "nested"])
def test_non_git_enumeration_errors_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    nested: bool,
) -> None:
    scanner = _load_scanner()
    release = tmp_path / "release"
    runner = release / "bin" / "run-coderabbit-review.py"
    runner.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "bin" / "run-coderabbit-review.py", runner)
    denied = release / "denied"
    denied.mkdir()

    def denied_walk(root, *, followlinks, onerror):
        assert Path(root) == release.resolve(strict=True)
        assert followlinks is False
        if nested:
            yield str(release), ["bin", "denied"], []
        onerror(PermissionError("sensitive host detail"))

    monkeypatch.setattr(scanner.os, "walk", denied_walk)

    assert scanner.main(["--root", str(release)]) == 4
    response = json.loads(capsys.readouterr().out)
    assert response["status"] == "degraded"
    assert response["reason"] == "publishable directory enumeration failed"
    assert response["findings"] == []


def test_stable_file_rejects_same_length_open_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    source = tmp_path / "publishable.txt"
    replacement = tmp_path / "replacement.txt"
    source.write_bytes(b"trusted-content\n")
    replacement.write_bytes(b"hostile-content\n")
    assert source.stat().st_size == replacement.stat().st_size
    real_open = scanner.os.open

    def redirected_open(path, flags, *args):
        target = replacement if Path(path) == source else path
        return real_open(target, flags, *args)

    monkeypatch.setattr(scanner.os, "open", redirected_open)

    with pytest.raises(scanner.SecretScanError, match="changed during scan"):
        scanner._stable_file(source)


def test_history_scan_reports_category_and_oid_without_echoing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    _configure_trusted_git(tmp_path, monkeypatch)
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


def test_history_scan_ignores_same_length_git_replace_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    _configure_trusted_git(tmp_path, monkeypatch)
    repo = tmp_path / "replace-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Secret Scanner Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    synthetic = "github" + "_pat_" + "R" * 48
    (repo / "leak.txt").write_text(synthetic, encoding="utf-8")
    _git(repo, "add", "leak.txt")
    _git(repo, "commit", "-qm", "secret fixture")
    secret_oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD:leak.txt"],
        text=True,
        encoding="ascii",
    ).strip()
    benign = b"x" * len(synthetic.encode("utf-8"))
    benign_oid = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
        input=benign,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.decode("ascii").strip()
    _git(repo, "replace", secret_oid, benign_oid)
    replaced = subprocess.check_output(
        ["git", "-C", str(repo), "cat-file", "blob", secret_oid]
    )
    assert replaced == benign

    result = scanner.scan_repository(repo, include_history=True)

    assert result["status"] == "findings"
    assert any(row["category"] == "github-token" for row in result["findings"])
    assert synthetic not in str(result)


def test_git_output_budget_is_enforced_while_streaming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    _configure_trusted_git(tmp_path, monkeypatch)

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


def test_git_scan_uses_hash_verified_absolute_executable_and_minimal_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = _load_scanner()
    trusted_git = tmp_path / "trusted" / "git"
    trusted_git.parent.mkdir()
    trusted_git.write_bytes(b"trusted git fixture\n")
    _configure_trusted_git(tmp_path, monkeypatch, executable=trusted_git)
    repository = tmp_path / "repo"
    repository.mkdir()
    poisoned = tmp_path / "poisoned"
    poisoned.mkdir()
    (poisoned / ("git.exe" if os.name == "nt" else "git")).write_bytes(
        b"path shim\n"
    )
    monkeypatch.setenv("PATH", str(poisoned))
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-cross-boundary")
    observed: dict[str, object] = {}

    class Process:
        def __init__(self):
            self.stdout = type("Stream", (), {"read": lambda self, _size: b""})()
            self.stderr = type("Stream", (), {"read": lambda self, _size: b""})()
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            del timeout
            return self.returncode

        def kill(self):
            self.returncode = -9

    def popen(command, **kwargs):
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        observed["cwd"] = kwargs["cwd"]
        return Process()

    monkeypatch.setattr(scanner.subprocess, "Popen", popen)

    assert scanner._run_git(repository, ["status"], maximum=1024) == b""
    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert observed["command"][0] == str(trusted_git)
    assert observed["cwd"] == repository
    assert environment["PATH"] == str(trusted_git.parent)
    assert environment["NoDefaultCurrentDirectoryInExePath"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert "UNRELATED_SECRET" not in environment

    trusted_git.write_bytes(b"digest drift\n")
    with pytest.raises(scanner.SecretScanError, match="trusted Git executable"):
        scanner._run_git(repository, ["status"], maximum=1024)


def test_placeholder_suppression_is_whole_value_and_mutations_are_detected() -> None:
    scanner = _load_scanner()
    detector = scanner._credential_detector(ROOT)

    assert detector(b'api_key="process.env.SUPERVISOR_API_KEY"') is None
    assert detector(b'api_key="<SUPERVISOR_API_KEY>"') is None
    assignment = b"api_" + b'key="' + b"Qx9dummyMarker-Z7pLm2N4" + b'"'
    assert (
        detector(assignment)
        == "secret-assignment"
    )
    mutated_token = ("github_pat_" + "A" * 20 + "dummy" + "B" * 24).encode()
    assert detector(mutated_token) == "github-token"
    exact_invalid = (
        b"https://" + b"user:" + b"Qx9-AbCdEf123456" + b"@service.invalid"
    )
    mutated_invalid = exact_invalid + b".evil.example"
    assert detector(exact_invalid) is None
    for quote in (b'"', b"'", b"`"):
        assert detector(quote + exact_invalid + quote) is None
        assert detector(quote + mutated_invalid + quote) == "credentialed-url"
    assert (
        detector(mutated_invalid) == "credentialed-url"
    )
