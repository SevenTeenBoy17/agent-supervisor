from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import sys
from typing import Any

import pytest

from supervisor_core import runtime_bundle


ROOT = Path(__file__).resolve().parents[1]


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "release_builder_v316_hardening",
        ROOT / "bin" / "build-core-release-manifest.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_runtime_root(root: Path) -> None:
    package = root / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 'trusted'\n", encoding="utf-8")


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
        assert events == ["inspect"] or events == ["inspect", "payload"]
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
    assert events == ["inspect", "payload", "identity"]
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
