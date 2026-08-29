from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from supervisor_core import runtime_bundle, workspace as workspace_module


ROOT = Path(__file__).resolve().parents[1]


def _git_fixture_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(name, None)
    return env


def test_git_batch_blob_hashing_transmits_the_complete_request_after_short_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "a" * 40
    payload = b"blob"
    expected_request = object_id.encode("ascii") + b"\n"

    class ShortWriter:
        def __init__(self) -> None:
            self.data = bytearray()
            self.closed = False

        def write(self, value: bytes | memoryview) -> int:
            chunk = bytes(value[:3])
            self.data.extend(chunk)
            return len(chunk)

        def close(self) -> None:
            self.closed = True

    writer = ShortWriter()
    observed_timeout: list[int | None] = []

    class FakeProcess:
        stdin = writer
        stdout = io.BytesIO(
            f"{object_id} blob {len(payload)}\n".encode("ascii")
            + payload
            + b"\n"
        )
        stderr = io.BytesIO()

        def wait(self, timeout: int | None = None) -> int:
            observed_timeout.append(timeout)
            return 0

        def kill(self) -> None:
            pytest.fail("a valid short write must not kill the batch process")

    monkeypatch.setattr(
        workspace_module, "_resolve_git_executable", lambda _workspace: Path("git")
    )
    monkeypatch.setattr(
        workspace_module.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess()
    )

    observed, error = workspace_module._git_batch_blob_sha256(
        tmp_path, [("file.txt", object_id)]
    )

    assert error is None
    assert observed == {"file.txt": hashlib.sha256(payload).hexdigest()}
    assert bytes(writer.data) == expected_request
    assert writer.closed is True
    assert observed_timeout == [workspace_module._git_batch_timeout_seconds(1)]
    assert observed_timeout[0] > workspace_module._GIT_TIMEOUT_SECONDS


def test_git_batch_timeout_scales_with_bounded_object_and_byte_budget() -> None:
    one_object = workspace_module._git_batch_timeout_seconds(1)
    large_batch = workspace_module._git_batch_timeout_seconds(
        workspace_module._MAX_WORKSPACE_FILES
    )

    assert workspace_module._GIT_TIMEOUT_SECONDS < one_object < large_batch
    assert large_batch == workspace_module._GIT_BATCH_TIMEOUT_MAX_SECONDS


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "release_builder_v316_hardening",
        ROOT / "bin" / "build-core-release-manifest.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_review_runner():
    spec = importlib.util.spec_from_file_location(
        "review_runner_v316_release_hardening",
        ROOT / "bin" / "run-coderabbit-review.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _configure_builder_trusted_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    executable: Path,
    *,
    digest: str | None = None,
) -> None:
    install_home = tmp_path / "builder-install-home"
    registry = install_home / ".agent-supervisor" / "trusted-executables.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    observed_digest = digest
    if observed_digest is None:
        observed_digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    registry.write_text(
        json.dumps({
            "contract": "TrustedExecutableRegistry/v1",
            "entries": {
                "git": {
                    "kind": "local",
                    "path": str(executable.resolve()),
                    "sha256": observed_digest,
                }
            },
            "generated_at": "2000-01-01T00:00:00Z",
        }, sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUPERVISOR_INSTALL_HOME", str(install_home))


def _write_runtime_root(root: Path) -> None:
    package = root / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 'trusted'\n", encoding="utf-8")
    (root / "VERSION").write_text("3.1.6\n", encoding="ascii")


def _run_builder(
    builder: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    root: Path,
    output: Path,
    identity_output: Path | None = None,
) -> int:
    arguments = [
        "build-core-release-manifest.py",
        "--root",
        str(root),
        "--version",
        "3.1.6",
        "--output",
        str(output),
    ]
    if identity_output is not None:
        arguments.extend(["--identity-output", str(identity_output)])
    monkeypatch.setattr(sys, "argv", arguments)
    return builder.main()


def test_builder_rejects_version_that_differs_from_repository_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    _write_runtime_root(root)
    output = root / "runtime.zip"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build-core-release-manifest.py",
            "--root",
            str(root),
            "--version",
            "3.1.7",
            "--output",
            str(output),
        ],
    )

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="does-not-match"):
        builder.main()
    assert not output.exists()


def test_builder_rejects_git_ignored_runtime_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    _write_runtime_root(root)
    ignored = root / "supervisor_core" / "ignored-local.py"
    ignored.write_text("TOKEN = 'fixture-only'\n", encoding="utf-8")
    (root / ".gitignore").write_text("supervisor_core/ignored-local.py\n", encoding="utf-8")
    git_env = _git_fixture_env()
    subprocess.run(["git", "init", "-q", str(root)], check=True, env=git_env)
    subprocess.run(
        ["git", "-C", str(root), "add", "VERSION", ".gitignore", "supervisor_core/__init__.py"],
        check=True,
        env=git_env,
    )
    output = root / "runtime.zip"

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="non-publishable"):
        _run_builder(builder, monkeypatch, root=root, output=output)
    assert not output.exists()


def test_builder_rejects_untracked_runtime_member(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    _write_runtime_root(root)
    untracked = root / "supervisor_core" / "local-only.py"
    untracked.write_text("TOKEN = 'fixture-only'\n", encoding="utf-8")
    git_env = _git_fixture_env()
    subprocess.run(["git", "init", "-q", str(root)], check=True, env=git_env)
    subprocess.run(
        ["git", "-C", str(root), "add", "VERSION", "supervisor_core/__init__.py"],
        check=True,
        env=git_env,
    )
    output = root / "runtime.zip"

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="non-publishable"):
        _run_builder(builder, monkeypatch, root=root, output=output)
    assert not output.exists()


@pytest.mark.parametrize("escaped_argument", ["output", "identity"])
def test_builder_rejects_every_output_outside_release_root_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    escaped_argument: str,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    inside_output = root / "runtime" / "core.zip"
    inside_identity = root / "runtime" / "identity.json"
    outside = tmp_path / f"escaped-{escaped_argument}.bin"
    output = outside if escaped_argument == "output" else inside_output
    identity = outside if escaped_argument == "identity" else inside_identity

    def unexpected_build(*_args: Any, **_kwargs: Any) -> bytes:
        pytest.fail("destination validation must precede bundle construction")

    monkeypatch.setattr(builder, "build_runtime_bundle", unexpected_build)

    with pytest.raises(ValueError, match="outside release root"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=output,
            identity_output=identity,
        )
    assert not outside.exists()
    assert not inside_output.exists()
    assert not inside_identity.exists()


def test_builder_rejects_bundle_and_identity_path_alias_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    destination = root / "runtime" / "artifact.bin"

    def unexpected_build(*_args: Any, **_kwargs: Any) -> bytes:
        pytest.fail("destination alias validation must precede bundle construction")

    monkeypatch.setattr(builder, "build_runtime_bundle", unexpected_build)

    with pytest.raises(ValueError, match="distinct"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=destination,
            identity_output=destination.parent / "." / destination.name,
        )
    assert not destination.exists()


def test_builder_rejects_existing_hardlink_aliases_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    output = root / "payload.bin"
    identity_output = root / "identity.json"
    output.write_bytes(b"existing artifact")
    try:
        os.link(output, identity_output)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    def unexpected_build(*_args: Any, **_kwargs: Any) -> bytes:
        pytest.fail("filesystem alias validation must precede bundle construction")

    monkeypatch.setattr(builder, "build_runtime_bundle", unexpected_build)

    with pytest.raises(ValueError, match="distinct"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=output,
            identity_output=identity_output,
        )
    assert output.read_bytes() == b"existing artifact"
    assert identity_output.read_bytes() == b"existing artifact"


def test_builder_rejects_output_through_symlinked_parent(
    tmp_path: Path,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    redirected = root / "redirected"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="outside release root"):
        builder._contained_output(root, redirected / "core.zip")
    assert not (outside / "core.zip").exists()


def test_builder_rejects_reparse_component_even_when_target_stays_inside_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    output_parent = root / "runtime"
    output_parent.mkdir(parents=True)
    real_is_indirection = builder._is_link_or_reparse

    monkeypatch.setattr(
        builder,
        "_is_link_or_reparse",
        lambda path: path == output_parent or real_is_indirection(path),
    )

    with pytest.raises(ValueError, match="symlink or reparse point"):
        builder._contained_output(root, output_parent / "core.zip")


def test_builder_resolves_git_once_and_executes_the_absolute_regular_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    (root / ".git").mkdir()
    git_executable = tmp_path / "trusted" / "git.exe"
    git_executable.parent.mkdir()
    git_executable.write_bytes(b"bounded executable fixture")
    observed: dict[str, Any] = {}

    _configure_builder_trusted_git(tmp_path, monkeypatch, git_executable)
    poison = tmp_path / "poison" / "git.exe"
    poison.parent.mkdir()
    poison.write_bytes(b"must never execute")
    monkeypatch.setenv("PATH", str(poison.parent))

    def run(command, **kwargs):
        observed.setdefault("commands", []).append(command)
        observed["kwargs"] = kwargs
        if command[-2:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(
                returncode=0,
                stdout=str(root.resolve()).encode("utf-8") + b"\n",
                stderr=b"",
            )
        return SimpleNamespace(returncode=0, stdout=b"VERSION\0", stderr=b"")

    monkeypatch.setattr(builder.subprocess, "run", run)

    assert builder._git_publishable_paths(root) == {"VERSION"}
    assert len(observed["commands"]) == 2
    assert all(command[0] == str(git_executable.resolve()) for command in observed["commands"])
    assert Path(observed["commands"][0][0]).is_absolute()
    assert observed["kwargs"]["cwd"] == root
    assert observed["kwargs"]["stdin"] is subprocess.DEVNULL
    assert observed["kwargs"]["env"]["PATH"] == str(git_executable.parent)
    assert observed["kwargs"]["env"]["LANG"] == "C"
    assert observed["kwargs"]["env"]["LC_ALL"] == "C"
    assert str(poison.parent) not in observed["kwargs"]["env"].values()


def test_builder_rejects_nested_git_worktree_as_release_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    checkout = tmp_path / "checkout"
    root = checkout / "nested-release"
    root.mkdir(parents=True)
    git_executable = tmp_path / "trusted" / "git.exe"
    git_executable.parent.mkdir()
    git_executable.write_bytes(b"bounded executable fixture")
    _configure_builder_trusted_git(tmp_path, monkeypatch, git_executable)
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=str(checkout.resolve()).encode("utf-8") + b"\n",
            stderr=b"",
        ),
    )

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="git-publishable-root-mismatch"):
        builder._git_publishable_paths(root)


def test_builder_rejects_non_file_git_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    (root / ".git").mkdir()
    fake_git_directory = tmp_path / "fake-git"
    fake_git_directory.mkdir()
    _configure_builder_trusted_git(
        tmp_path,
        monkeypatch,
        fake_git_directory,
        digest="0" * 64,
    )

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="git-publishable-set-unavailable"):
        builder._git_publishable_paths(root)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (b"fatal: not a git repository (or any parent): .git\n", None),
        (b"fatal: unsafe repository ownership\n", "error"),
    ],
)
def test_builder_distinguishes_non_repository_from_git_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stderr: bytes,
    expected: str | None,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    root.mkdir()
    git_executable = tmp_path / "trusted" / "git.exe"
    git_executable.parent.mkdir()
    git_executable.write_bytes(b"bounded executable fixture")
    _configure_builder_trusted_git(tmp_path, monkeypatch, git_executable)
    monkeypatch.setattr(
        builder.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=128,
            stdout=b"",
            stderr=stderr,
        ),
    )

    if expected is None:
        assert builder._git_publishable_paths(root) is None
    else:
        with pytest.raises(runtime_bundle.RuntimeBundleError, match="git-publishable-set-unavailable"):
            builder._git_publishable_paths(root)


def test_source_checkout_review_uses_only_git_indexed_release_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    source = tmp_path / "source"
    tracked = source / "supervisor_core" / "tracked.py"
    untracked = source / "supervisor_core" / "untracked.py"
    staged = source / "integrations" / "codex" / "staged.py"
    for path, content in (
        (tracked, b"TRACKED = True\n"),
        (untracked, b"UNTRACKED = True\n"),
        (staged, b"STAGED = True\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    observed: dict[str, Any] = {}

    def indexed_paths(command, cwd, *, timeout, env):
        observed.update(command=command, cwd=cwd, timeout=timeout, env=env)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                b"supervisor_core/tracked.py\0"
                b"integrations/codex/staged.py\0"
            ),
        )

    monkeypatch.setattr(runner, "CORE_ROOT", source)
    monkeypatch.setattr(runner, "_SOURCE_CHECKOUT", True)
    monkeypatch.setattr(runner, "_git_environment", lambda: {})
    monkeypatch.setattr(runner, "_run_bytes", indexed_paths)

    destination = tmp_path / "review"
    manifest = runner.prepare_review_tree(destination)
    selected = {row["path"] for row in manifest}

    assert observed["command"][:5] == [
        "git", "ls-files", "--cached", "-z", "--",
    ]
    assert observed["cwd"] == source
    assert "global-core/supervisor_core/tracked.py" in selected
    assert "release-codex/staged.py" in selected
    assert not any("untracked.py" in path for path in selected)


def test_source_checkout_review_rejects_casefold_colliding_index_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    source = tmp_path / "source"
    source.mkdir()

    monkeypatch.setattr(runner, "_git_environment", lambda: {})
    monkeypatch.setattr(
        runner,
        "_run_bytes",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"bin/Release.py\0bin/release.py\0",
        ),
    )

    with pytest.raises(runner.ReviewScopeError, match="case-collision"):
        runner._source_checkout_groups(source)


def test_bound_runtime_review_does_not_require_a_git_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    bound_root = tmp_path / "bound-core"
    source = bound_root / "supervisor_core" / "trusted.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"BOUND = True\n")

    monkeypatch.setattr(runner, "_SOURCE_CHECKOUT", False)
    monkeypatch.setattr(
        runner,
        "source_groups",
        lambda: [("global-core", bound_root, [source])],
    )
    monkeypatch.setattr(
        runner,
        "_source_checkout_groups",
        lambda _root: pytest.fail("bound runtime must not consult a Git index"),
    )

    manifest = runner.prepare_review_tree(tmp_path / "review")

    assert any(row["path"] == "global-core/supervisor_core/trusted.py" for row in manifest)


def test_builder_stages_and_fully_validates_before_ordered_atomic_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    _write_runtime_root(root)
    output = root / "runtime" / "core.zip"
    identity_output = root / "runtime" / "identity.json"
    events: list[str] = []
    real_inspect = builder.inspect_runtime_bundle
    real_atomic_write = builder._atomic_write

    def observed_inspect(blob: bytes, expected_identity: dict[str, str]):
        assert not output.exists()
        assert not identity_output.exists()
        events.append("inspect")
        return real_inspect(blob, expected_identity=expected_identity)

    def observed_atomic_write(path: Path, content: bytes) -> None:
        assert events == ["inspect", "inspect"] or events == [
            "inspect",
            "inspect",
            "payload",
        ]
        if path == output:
            assert not identity_output.exists()
            events.append("payload")
        elif path == identity_output:
            assert output.exists()
            events.append("identity")
        else:
            pytest.fail(f"unexpected publication path: {path}")
        real_atomic_write(path, content)

    monkeypatch.setattr(builder, "inspect_runtime_bundle", observed_inspect)
    monkeypatch.setattr(builder, "_atomic_write", observed_atomic_write)

    assert _run_builder(
        builder,
        monkeypatch,
        root=root,
        output=output,
        identity_output=identity_output,
    ) == 0
    assert events == ["inspect", "inspect", "payload", "identity"]
    identity = json.loads(identity_output.read_text(encoding="utf-8"))
    assert json.loads(capsys.readouterr().out) == identity
    assert runtime_bundle.inspect_runtime_bundle(
        output.read_bytes(),
        expected_identity=identity,
    )["bundle_sha256"] == identity["bundle_sha256"]


def test_builder_preserves_relative_output_and_stdout_only_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    _write_runtime_root(root)
    relative_output = Path("runtime") / "core.zip"

    assert _run_builder(
        builder,
        monkeypatch,
        root=root,
        output=relative_output,
    ) == 0
    output = root / relative_output
    identity = json.loads(capsys.readouterr().out)
    assert identity["bundle_relpath"] == "runtime/core.zip"
    assert runtime_bundle.inspect_runtime_bundle(
        output.read_bytes(),
        expected_identity=identity,
    )["bundle_sha256"] == identity["bundle_sha256"]


def test_identity_staging_failure_leaves_existing_artifacts_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    _write_runtime_root(root)
    output = root / "runtime" / "core.zip"
    identity_output = root / "runtime" / "identity.json"
    output.parent.mkdir()
    output.write_bytes(b"previous payload")
    identity_output.write_bytes(b"previous identity")
    real_stage = builder._stage_bytes
    calls = 0

    def fail_identity_stage(path: Path, content: bytes) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated identity staging failure")
        return real_stage(path, content)

    monkeypatch.setattr(builder, "_stage_bytes", fail_identity_stage)

    with pytest.raises(OSError, match="identity staging failure"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=output,
            identity_output=identity_output,
        )
    assert output.read_bytes() == b"previous payload"
    assert identity_output.read_bytes() == b"previous identity"
    assert not list(output.parent.glob(".*.stage"))


def test_staged_validation_failure_leaves_existing_artifacts_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    _write_runtime_root(root)
    output = root / "runtime" / "core.zip"
    identity_output = root / "runtime" / "identity.json"
    output.parent.mkdir()
    output.write_bytes(b"previous payload")
    identity_output.write_bytes(b"previous identity")

    def reject_staged_artifacts(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise runtime_bundle.RuntimeBundleError("simulated-staged-mismatch")

    monkeypatch.setattr(builder, "inspect_runtime_bundle", reject_staged_artifacts)

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="staged-mismatch"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=output,
            identity_output=identity_output,
        )
    assert output.read_bytes() == b"previous payload"
    assert identity_output.read_bytes() == b"previous identity"
    assert not list(output.parent.glob(".*.stage"))


def test_identity_publication_failure_occurs_only_after_valid_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    builder = _load_builder()
    root = tmp_path / "release"
    _write_runtime_root(root)
    output = root / "runtime" / "core.zip"
    identity_output = root / "runtime" / "identity.json"
    real_atomic_write = builder._atomic_write

    def fail_identity_publication(path: Path, content: bytes) -> None:
        if path == identity_output:
            assert output.exists()
            raise OSError("simulated identity publication failure")
        real_atomic_write(path, content)

    monkeypatch.setattr(builder, "_atomic_write", fail_identity_publication)

    with pytest.raises(OSError, match="identity publication failure"):
        _run_builder(
            builder,
            monkeypatch,
            root=root,
            output=output,
            identity_output=identity_output,
        )
    assert not identity_output.exists()
    assert capsys.readouterr().out == ""
    assert runtime_bundle.inspect_runtime_bundle(output.read_bytes())["manifest"][
        "version"
    ] == "3.1.6"


def test_build_caps_required_archive_members_before_reading_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "release"
    root.mkdir()
    required = [
        PurePosixPath(f"supervisor_core/member_{index}.py")
        for index in range(runtime_bundle.MAX_MEMBERS)
    ]
    monkeypatch.setattr(runtime_bundle, "_runtime_paths", lambda _root: required)

    def unexpected_read(*_args: Any, **_kwargs: Any) -> bytes:
        pytest.fail("member count must be capped before reading source files")

    monkeypatch.setattr(runtime_bundle, "_read_stable_file", unexpected_read)

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="member-count"):
        runtime_bundle.build_runtime_bundle(root, "3.1.6")


def test_runtime_paths_exclude_transient_trees_but_keep_repository_tests(
    tmp_path: Path,
) -> None:
    root = tmp_path / "release"
    _write_runtime_root(root)
    tests_root = root / "tests"
    tests_root.mkdir()
    real_test = tests_root / "test_release_contract.py"
    real_test.write_text("def test_contract(): pass\n", encoding="utf-8")
    transient_directories = (
        "__pycache__",
        ".pytest_cache",
        ".pytest-tmp-worker-1",
        "build",
        "dist",
        "tmp",
        "temp",
    )
    for directory in transient_directories:
        transient = tests_root / directory
        transient.mkdir()
        (transient / "copied_test.py").write_text(
            "def test_transient(): pass\n",
            encoding="utf-8",
        )
    schema_cache = root / "schemas" / ".pytest-tmp-schema"
    schema_cache.mkdir(parents=True)
    (schema_cache / "copied-schema.json").write_text("{}\n", encoding="utf-8")

    selected = {path.as_posix() for path in runtime_bundle._runtime_paths(root)}

    assert "tests/test_release_contract.py" in selected
    assert not any(
        component.casefold() in {
            "__pycache__",
            ".pytest_cache",
            "build",
            "dist",
            "tmp",
            "temp",
        }
        or component.casefold().startswith(".pytest-tmp-")
        for path in selected
        for component in PurePosixPath(path).parts
    )


def test_runtime_paths_include_release_selftest_support_tools() -> None:
    selected = {
        path.as_posix() for path in runtime_bundle._runtime_paths(ROOT)
    }

    assert {
        ".github/workflows/ci.yml",
        "LICENSE",
        "NOTICE",
        "bin/install-agent-supervisor.py",
        "bin/scan-release-secrets.py",
    } <= selected


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("path", "relative-release-root"),
        ("bundle_relpath", "../escaped.zip"),
    ],
)
def test_inspector_rejects_malformed_release_identity_paths(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    root = tmp_path / "release"
    _write_runtime_root(root)
    blob = runtime_bundle.build_runtime_bundle(root, "3.1.6")
    identity = runtime_bundle.release_identity(
        root,
        "3.1.6",
        "runtime/core.zip",
        blob,
    )
    identity[field] = replacement

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="release-identity-mismatch"):
        runtime_bundle.inspect_runtime_bundle(blob, expected_identity=identity)


def test_release_identity_rejects_version_different_from_manifest(tmp_path: Path) -> None:
    root = tmp_path / "release"
    _write_runtime_root(root)
    blob = runtime_bundle.build_runtime_bundle(root, "3.1.6")

    with pytest.raises(runtime_bundle.RuntimeBundleError, match="release-identity-mismatch"):
        runtime_bundle.release_identity(
            root,
            "9.9.9",
            "runtime/core.zip",
            blob,
        )


def _git(repo: Path, *arguments: str, text: bool = True) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=text,
    )


def _review_git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "PATHEXT",
            "TMP",
            "TEMP",
            "TMPDIR",
        )
        if (value := os.environ.get(key))
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_NAME": "Supervisor Review Test",
        "GIT_AUTHOR_EMAIL": "review-test@example.invalid",
        "GIT_COMMITTER_NAME": "Supervisor Review Test",
        "GIT_COMMITTER_EMAIL": "review-test@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    })
    return environment


def test_coderabbit_review_reconstructs_exact_workspace_add_modify_delete_delta(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "review-test@example.invalid")
    _git(source, "config", "user.name", "Review Test")

    original = {
        "tests/test_guard.py": b"def test_guard():\n    assert True\n",
        ".github/workflows/ci.yml": b"name: ci\npermissions: read-all\n",
        "docs/obsolete.md": b"obsolete release note\n",
    }
    for relative, content in original.items():
        path = source.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    _git(source, "add", "-A")
    _git(source, "commit", "-qm", "baseline")

    current = {
        "tests/test_guard.py": b"def test_guard():\n    assert 1 == 1\n",
        ".github/workflows/ci.yml": b"name: ci\npermissions:\n  contents: read\n",
        "docs/new.md": b"new release note\n",
    }
    for relative, content in current.items():
        path = source.joinpath(*PurePosixPath(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (source / "docs" / "obsolete.md").unlink()
    _git(source, "add", "-A")

    delta = {
        "tests/test_guard.py": {
            "before": hashlib.sha256(original["tests/test_guard.py"]).hexdigest(),
            "after": hashlib.sha256(current["tests/test_guard.py"]).hexdigest(),
        },
        ".github/workflows/ci.yml": {
            "before": hashlib.sha256(original[".github/workflows/ci.yml"]).hexdigest(),
            "after": hashlib.sha256(current[".github/workflows/ci.yml"]).hexdigest(),
        },
        "docs/obsolete.md": {
            "before": hashlib.sha256(original["docs/obsolete.md"]).hexdigest(),
            "after": None,
        },
        "docs/new.md": {
            "before": None,
            "after": hashlib.sha256(current["docs/new.md"]).hexdigest(),
        },
    }
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": runner._canonical_sha256(delta),
        "workspace_delta_manifest": delta,
    }
    monkeypatch.setattr(runner, "_resolved_command", lambda command: command)
    monkeypatch.setattr(runner, "_git_environment", _review_git_environment)

    materialized = runner.materialize_workspace_delta(source, binding)
    review = tmp_path / "review"
    review.mkdir()
    context = review / "global-core" / "context.py"
    context.parent.mkdir(parents=True)
    context.write_bytes(b"CONTEXT = True\n")
    context_manifest = [{
        "path": "global-core/context.py",
        "sha256": hashlib.sha256(context.read_bytes()).hexdigest(),
    }]
    manifest = runner.review_manifest_with_workspace_delta(
        context_manifest,
        materialized,
    )
    baseline = runner.prepare_git_repository(review, manifest, materialized)
    head, binary_diff_sha256 = runner.review_revision_binding(review, baseline)

    assert len(binary_diff_sha256) == 64
    observed = {
        line.split("\t", 1)[1]: line.split("\t", 1)[0]
        for line in _git(
            review,
            "diff",
            "--name-status",
            "--no-renames",
            baseline,
            head,
        ).stdout.splitlines()
    }
    assert observed == {
        ".github/workflows/ci.yml": "M",
        "docs/new.md": "A",
        "docs/obsolete.md": "D",
        "tests/test_guard.py": "M",
    }
    assert _git(review, "show", f"{baseline}:tests/test_guard.py", text=False).stdout == original[
        "tests/test_guard.py"
    ]
    assert _git(review, "show", f"{head}:tests/test_guard.py", text=False).stdout == current[
        "tests/test_guard.py"
    ]
    assert _git(review, "show", f"{baseline}:docs/obsolete.md", text=False).stdout == original[
        "docs/obsolete.md"
    ]
    assert _git(review, "show", f"{head}:docs/new.md", text=False).stdout == current[
        "docs/new.md"
    ]
    verified = runner._verified_full_snapshot_manifest(
        review,
        baseline,
        head,
        manifest,
        delta,
    )
    assert verified[".github/workflows/ci.yml"] == delta[
        ".github/workflows/ci.yml"
    ]["after"]


def test_coderabbit_review_fails_closed_when_bound_before_bytes_do_not_match_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    _git(source, "config", "user.email", "review-test@example.invalid")
    _git(source, "config", "user.name", "Review Test")
    target = source / "tests" / "test_guard.py"
    target.parent.mkdir()
    target.write_bytes(b"def test_guard():\n    assert True\n")
    _git(source, "add", "-A")
    _git(source, "commit", "-qm", "baseline")
    target.write_bytes(b"def test_guard():\n    assert 1 == 1\n")
    _git(source, "add", "-A")
    delta = {
        "tests/test_guard.py": {
            "before": "0" * 64,
            "after": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
    }
    binding = {
        "contract": "ReviewArtifactBindingInput/v1",
        "workspace_base_sha256": "a" * 64,
        "workspace_head_sha256": "b" * 64,
        "diff_hash": runner._canonical_sha256(delta),
        "workspace_delta_manifest": delta,
    }
    monkeypatch.setattr(runner, "_resolved_command", lambda command: command)
    monkeypatch.setattr(runner, "_git_environment", _review_git_environment)

    with pytest.raises(runner.ReviewArtifactError, match="before-hash-mismatch"):
        runner.materialize_workspace_delta(source, binding)


def test_review_source_descriptor_identity_rejects_same_size_open_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _load_review_runner()
    expected = tmp_path / "expected.py"
    replacement = tmp_path / "replacement.py"
    expected.write_bytes(b"SAFE = True\n")
    replacement.write_bytes(b"EVIL = True\n")
    assert expected.stat().st_size == replacement.stat().st_size
    real_open = runner.os.open

    def redirected_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path) == expected:
            return real_open(replacement, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runner.os, "open", redirected_open)

    with pytest.raises(runner.ReviewScopeError, match="source-mutated"):
        runner._stable_regular_bytes(expected)
