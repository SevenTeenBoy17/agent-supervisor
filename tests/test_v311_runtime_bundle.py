from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, Callable

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_SCRIPTS = (
    Path(os.environ.get("AGENT_SUPERVISOR_INSTALL_HOME", Path.home()))
    / ".codex"
    / "skills"
    / "dev-supervisor"
    / "scripts"
)
MANIFEST_MEMBER = "SUPERVISOR-RUNTIME-MANIFEST.json"
POINTER_CONTRACT = "ActiveVersionPointer/v4"
IDENTITY_CONTRACT = "SupervisorReleaseIdentity/v1"
MANIFEST_CONTRACT = "SupervisorRuntimeManifest/v1"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _runtime_bundle_module() -> Any:
    return importlib.import_module("supervisor_core.runtime_bundle")


def _write_release(root: Path, *, marker: str = "trusted-old") -> None:
    package = root / "supervisor_core"
    schemas = package / "schemas"
    bin_root = root / "bin"
    schemas.mkdir(parents=True)
    bin_root.mkdir(parents=True)
    (package / "__init__.py").write_text("\n", encoding="utf-8")
    (package / "__main__.py").write_text(
        "from .cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    (package / "snapshot_probe.py").write_text(
        f"VALUE = {marker!r}\n",
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        textwrap.dedent(
            f"""
            import json
            import sys
            from importlib.resources import files
            from .snapshot_probe import VALUE

            def main(argv=None):
                args = list(sys.argv[1:] if argv is None else argv)
                if args == ["--version"]:
                    print(VALUE)
                    return 0
                if args == ["--schema-probe"]:
                    value = files("supervisor_core.schemas").joinpath("probe.json").read_text(encoding="utf-8")
                    print(json.loads(value)["marker"])
                    return 0
                return 64
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (schemas / "__init__.py").write_text("\n", encoding="utf-8")
    (schemas / "probe.json").write_text(
        json.dumps({"marker": marker}, separators=(",", ":")),
        encoding="utf-8",
    )
    (bin_root / "agent-supervisor.py").write_text(
        "from supervisor_core.cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    (bin_root / "run-coderabbit-review.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    (bin_root / "build-core-release-manifest.py").write_text(
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    (root / "VERSION").write_text("3.1.1\n", encoding="utf-8")


def _build(root: Path, version: str = "3.1.1") -> bytes:
    module = _runtime_bundle_module()
    blob = module.build_runtime_bundle(root, version)
    assert type(blob) is bytes
    return blob


def _inspect(blob: bytes, identity: dict[str, str] | None = None) -> dict[str, Any]:
    module = _runtime_bundle_module()
    result = module.inspect_runtime_bundle(blob, expected_identity=identity)
    assert type(result) is dict
    return result


def _manifest(blob: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(BytesIO(blob), "r") as archive:
        names = archive.namelist()
        assert names.count(MANIFEST_MEMBER) == 1
        return json.loads(archive.read(MANIFEST_MEMBER))


def _identity(root: Path, blob: bytes, inspected: dict[str, Any]) -> dict[str, str]:
    return {
        "contract": IDENTITY_CONTRACT,
        "version": inspected["manifest"]["version"],
        "path": str(root.resolve()),
        "bundle_relpath": "supervisor-runtime.zip",
        "bundle_sha256": _sha256(blob),
        "manifest_sha256": inspected["manifest_sha256"],
        "source_tree_sha256": inspected["source_tree_sha256"],
    }


def _rewrite_zip(
    blob: bytes,
    mutate: Callable[[list[tuple[str, bytes]]], list[tuple[str, bytes]]],
) -> bytes:
    with zipfile.ZipFile(BytesIO(blob), "r") as archive:
        members = [(info.filename, archive.read(info)) for info in archive.infolist()]
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in mutate(members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return output.getvalue()


def _run_clean_python(script: str, *args: str, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", script, *args],
        input=stdin,
        capture_output=True,
        check=False,
        env=environment,
    )


def test_runtime_bundle_public_contract_exists() -> None:
    spec = importlib.util.find_spec("supervisor_core.runtime_bundle")
    assert spec is not None, "v3.1.1 requires supervisor_core.runtime_bundle"
    module = _runtime_bundle_module()
    assert callable(module.build_runtime_bundle)
    assert callable(module.inspect_runtime_bundle)


def test_runtime_bundle_is_deterministic_and_manifest_is_canonical(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_release(first)
    _write_release(second)
    for index, path in enumerate(sorted(second.rglob("*"), reverse=True)):
        if path.is_file():
            timestamp = 1_700_000_000 + index
            os.utime(path, (timestamp, timestamp))

    first_blob = _build(first)
    second_blob = _build(second)

    assert first_blob == second_blob
    assert _sha256(first_blob) == _sha256(second_blob)
    inspected = _inspect(first_blob)
    manifest = _manifest(first_blob)
    assert manifest["contract"] == MANIFEST_CONTRACT
    assert manifest["version"] == "3.1.1"
    assert manifest["source_tree_sha256"] == inspected["source_tree_sha256"]
    assert inspected["manifest_sha256"] == _sha256(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    files = manifest["files"]
    assert files == sorted(files, key=lambda item: item["path"])
    assert all(set(item) == {"path", "size", "sha256", "kind", "module"} for item in files)
    assert all("\\" not in item["path"] and not item["path"].startswith("/") for item in files)
    assert "supervisor_core/schemas/probe.json" in {item["path"] for item in files}


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        (
            "exact duplicate",
            lambda members: members + [next(item for item in members if item[0].endswith("snapshot_probe.py"))],
        ),
        (
            "casefold duplicate",
            lambda members: members
            + [
                (
                    next(item for item in members if item[0].endswith("snapshot_probe.py"))[0].upper(),
                    next(item for item in members if item[0].endswith("snapshot_probe.py"))[1],
                )
            ],
        ),
        ("traversal", lambda members: members + [("../escape.py", b"raise SystemExit(99)\n")]),
        ("absolute", lambda members: members + [("/escape.py", b"raise SystemExit(99)\n")]),
        ("extra", lambda members: members + [("unregistered.txt", b"extra")]),
        (
            "duplicate manifest",
            lambda members: members + [next(item for item in members if item[0] == MANIFEST_MEMBER)],
        ),
    ],
)
def test_inspector_rejects_duplicate_casefold_traversal_and_extra_members(
    tmp_path: Path,
    label: str,
    mutate: Callable[[list[tuple[str, bytes]]], list[tuple[str, bytes]]],
) -> None:
    release = tmp_path / "release"
    _write_release(release)
    corrupted = _rewrite_zip(_build(release), mutate)

    with pytest.raises((ValueError, TypeError, OSError), match="(?i)(bundle|manifest|member|path|duplicate|extra)"):
        _inspect(corrupted)


def test_inspector_rejects_oversize_and_truncated_bundles(tmp_path: Path) -> None:
    release = tmp_path / "release"
    _write_release(release)
    blob = _build(release)
    oversized = _rewrite_zip(blob, lambda members: members + [("bomb.bin", b"0" * (65 * 1024 * 1024))])

    with pytest.raises((ValueError, TypeError, OSError), match="(?i)(bundle|size|large|limit|member)"):
        _inspect(oversized)
    with pytest.raises((ValueError, TypeError, OSError, zipfile.BadZipFile), match="(?i)(bundle|zip|trunc|invalid|central)"):
        _inspect(blob[:-19])


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("version", "9.9.9"),
        ("bundle_sha256", "0" * 64),
        ("manifest_sha256", "1" * 64),
        ("source_tree_sha256", "2" * 64),
    ],
)
def test_inspector_rejects_every_release_identity_mismatch(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    release = tmp_path / "release"
    _write_release(release)
    blob = _build(release)
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    identity[field] = replacement

    with pytest.raises((ValueError, TypeError, OSError), match="(?i)(identity|version|hash|mismatch|bundle|manifest|source)"):
        _inspect(blob, identity)


def test_release_identity_and_pointer_v4_have_no_ambient_fields(tmp_path: Path) -> None:
    release = tmp_path / "release"
    _write_release(release)
    blob = _build(release)
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    pointer = {
        "contract": POINTER_CONTRACT,
        "active": identity,
        "previous": {**identity, "version": "3.1.0"},
    }

    assert set(identity) == {
        "contract",
        "version",
        "path",
        "bundle_relpath",
        "bundle_sha256",
        "manifest_sha256",
        "source_tree_sha256",
    }
    assert pointer["contract"] == POINTER_CONTRACT
    assert pointer["active"]["contract"] == IDENTITY_CONTRACT


def _powershell() -> str:
    for candidate in ("pwsh.exe", "powershell.exe", "pwsh", "powershell"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    pytest.fail("PowerShell is required for the native adapter test")


def _stage_native_adapter(home: Path) -> Path:
    scripts = home / ".codex" / "skills" / "dev-supervisor" / "scripts"
    scripts.mkdir(parents=True)
    for name in ("supervisor-core.ps1", "supervisor-process-job.py"):
        shutil.copy2(ADAPTER_SCRIPTS / name, scripts / name)
    return scripts


def _run_staged_version(scripts: Path) -> subprocess.CompletedProcess[str]:
    escaped = str(scripts / "supervisor-core.ps1").replace("'", "''")
    command = (
        f". '{escaped}'; "
        "$runtime = Get-AgentSupervisorPythonCommand; "
        "if ($null -eq $runtime) { exit 125 }; "
        "$core = Get-AgentSupervisorCoreRoot; "
        "$launcher = Resolve-AgentSupervisorTrustedLauncherPath -CoreRoot $core; "
        "if ([string]::IsNullOrWhiteSpace($launcher)) { exit 124 }; "
        "$result = Invoke-AgentSupervisorPython -Command $runtime.Command -PrefixArgs @($runtime.PrefixArgs) "
        "-Arguments @('-I','-S','-B','-X','utf8',$launcher,'--version') "
        "-Operation 'runtime-bundle-probe' -CaptureOutput -SuppressOutput -IsolatedEnvironment -Silent; "
        "[Console]::Out.Write([string]$result.StandardOutput); exit [int]$result.ExitCode"
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [_powershell(), "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env=environment,
    )


def test_bundle_snapshot_ignores_module_schema_and_pyc_swaps_after_build(tmp_path: Path) -> None:
    home = tmp_path / "profile"
    scripts = _stage_native_adapter(home)
    release = home / ".agent-supervisor-releases" / "v-test"
    _write_release(release, marker="trusted-old")
    blob = _build(release)
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    bundle_path = release / identity["bundle_relpath"]
    bundle_path.write_bytes(blob)
    pointer_root = home / ".agent-supervisor"
    pointer_root.mkdir()
    (pointer_root / "active-version.json").write_text(
        json.dumps({"contract": POINTER_CONTRACT, "active": identity, "previous": identity}),
        encoding="utf-8",
    )

    (release / "supervisor_core" / "snapshot_probe.py").write_text(
        "VALUE = 'disk-swapped'\n",
        encoding="utf-8",
    )
    (release / "supervisor_core" / "schemas" / "probe.json").write_text(
        '{"marker":"schema-swapped"}',
        encoding="utf-8",
    )
    pycache = release / "supervisor_core" / "__pycache__"
    pycache.mkdir()
    (pycache / "snapshot_probe.cpython-999.pyc").write_bytes(b"malicious-pyc")

    completed = _run_staged_version(scripts)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "trusted-old"


def test_selected_snapshot_survives_pointer_swap_and_next_build_sees_new_release(tmp_path: Path) -> None:
    old = tmp_path / "old"
    new = tmp_path / "new"
    _write_release(old, marker="old-snapshot")
    _write_release(new, marker="new-snapshot")
    old_blob = _build(old)
    old_inspected = _inspect(old_blob)
    old_identity = _identity(old, old_blob, old_inspected)
    new_blob = _build(new)
    new_inspected = _inspect(new_blob)
    new_identity = _identity(new, new_blob, new_inspected)
    pointer = tmp_path / "active-version.json"
    pointer.write_text(
        json.dumps({"contract": POINTER_CONTRACT, "active": old_identity, "previous": new_identity}),
        encoding="utf-8",
    )

    frozen = json.loads(pointer.read_text(encoding="utf-8"))["active"]
    pointer.write_text(
        json.dumps({"contract": POINTER_CONTRACT, "active": new_identity, "previous": old_identity}),
        encoding="utf-8",
    )

    assert _inspect(old_blob, frozen)["source_tree_sha256"] == old_identity["source_tree_sha256"]
    current = json.loads(pointer.read_text(encoding="utf-8"))["active"]
    assert _inspect(new_blob, current)["source_tree_sha256"] == new_identity["source_tree_sha256"]
    assert frozen["bundle_sha256"] != current["bundle_sha256"]


def test_job_helper_binds_before_dependencies_and_accepts_only_bounded_stdin_frame() -> None:
    source = (ADAPTER_SCRIPTS / "supervisor-process-job.py").read_text(encoding="utf-8")
    job_index = source.index("_enable_kill_on_close()")
    dependency_index = source.index("_enable_dependency_paths()")
    stdin_index = source.index("sys.stdin.buffer")

    assert job_index < dependency_index < stdin_index
    assert "SupervisorRuntimeFrame/v1" in source
    assert "_agent_supervisor_bound_runtime" in source
    assert "MetaPathFinder" in source
    assert "supervisor_core.*" in source or "startswith(\"supervisor_core.\")" in source
    assert "--agent-supervisor-source-b64" not in source


def test_pointer_bundle_and_frame_contracts_are_wired_through_all_native_entrypoints() -> None:
    core_adapter = (ADAPTER_SCRIPTS / "supervisor-core.ps1").read_text(encoding="utf-8")
    job_helper = (ADAPTER_SCRIPTS / "supervisor-process-job.py").read_text(encoding="utf-8")
    launcher = (ROOT / "bin" / "agent-supervisor.py").read_text(encoding="utf-8")
    native_hook = (ADAPTER_SCRIPTS / "codex-supervisor-hook.py").read_text(encoding="utf-8")

    for source in (core_adapter, launcher, native_hook):
        assert POINTER_CONTRACT in source
        assert IDENTITY_CONTRACT in source
        assert "bundle_relpath" in source
        assert "bundle_sha256" in source
        assert "manifest_sha256" in source
        assert "source_tree_sha256" in source
    assert "SupervisorRuntimeFrame/v1" in core_adapter
    assert "RedirectStandardInput" in core_adapter
    assert "SupervisorRuntimeFrame/v1" in job_helper
    assert "sys.stdin.buffer" in job_helper


def test_current_install_pointer_uses_full_v4_release_identity() -> None:
    pointer = json.loads((ROOT / "active-version.json").read_text(encoding="utf-8"))
    assert pointer["contract"] == POINTER_CONTRACT
    assert set(pointer) == {"contract", "active", "previous"}
    for name in ("active", "previous"):
        assert set(pointer[name]) == {
            "contract",
            "version",
            "path",
            "bundle_relpath",
            "bundle_sha256",
            "manifest_sha256",
            "source_tree_sha256",
        }
        assert pointer[name]["contract"] == IDENTITY_CONTRACT
        assert Path(pointer[name]["path"]).is_absolute()


def test_truncated_stdin_frame_fails_closed_without_disk_fallback(tmp_path: Path) -> None:
    helper = ADAPTER_SCRIPTS / "supervisor-process-job.py"
    if os.name != "nt":
        pytest.skip("Windows Job Object framing is Windows-only")
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-X", "utf8", str(helper), "--runtime-frame"],
        input=b"SupervisorRuntimeFrame/v1\x00\x00\x00\x20{}",
        capture_output=True,
        check=False,
        env={
            "SYSTEMROOT": os.environ["SYSTEMROOT"],
            "WINDIR": os.environ["WINDIR"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        },
    )

    assert completed.returncode == 64
    assert completed.stdout == b""
    assert completed.stderr == b""
