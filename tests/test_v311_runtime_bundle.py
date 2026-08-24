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
                if args == ["--identity-probe"]:
                    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
                    print(json.dumps({{
                        "marker": VALUE,
                        "module_file": __file__,
                        "runtime_contract": getattr(runtime, "contract", None),
                        "core_root": getattr(runtime, "core_root", None),
                        "identity_version": getattr(runtime, "identity", {{}}).get("version")
                            if isinstance(getattr(runtime, "identity", None), dict) else None,
                    }}, separators=(",", ":")))
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


def _stage_direct_launcher_release(
    tmp_path: Path, *, marker: str = "bundle-frozen"
) -> tuple[Path, Path, dict[str, str], bytes]:
    release = tmp_path / ".agent-supervisor-releases" / "v3.1.1"
    _write_release(release, marker=marker)
    blob = _build(release)
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    bundle_path = release / identity["bundle_relpath"]
    bundle_path.write_bytes(blob)
    pointer = tmp_path / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True)
    launcher = pointer.parent / "bin" / "agent-supervisor.py"
    launcher.parent.mkdir()
    shutil.copy2(ROOT / "bin" / "agent-supervisor.py", launcher)
    pointer.write_text(
        json.dumps({
            "contract": POINTER_CONTRACT,
            "active": identity,
            "previous": None,
        }, separators=(",", ":")),
        encoding="utf-8",
    )
    return release, pointer, identity, blob


def _run_direct_launcher(
    pointer: Path,
    _release_root: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    })
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            str(pointer.parent / "bin" / "agent-supervisor.py"),
            *arguments,
        ],
        env=environment,
        capture_output=True,
        check=False,
        timeout=15,
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


def _run_non_windows_frozen_dependency_probe(
    tmp_path: Path,
    *,
    dependency_root: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Execute the production POSIX Invoke branch on the Windows CI host.

    Only the cached ``$runningOnWindows`` predicates are rewritten through the
    PowerShell AST.  Runtime-frame construction, stage-zero execution, bundle
    loading, dependency-path enablement, and process cleanup remain production
    code.  This gives the Windows release gate executable coverage of the POSIX
    parent contract without treating a text grep as behavioral evidence.
    """

    home = tmp_path / "posix frozen home"
    scripts = _stage_native_adapter(home)
    release = home / ".agent-supervisor-releases" / "v-posix-stage-zero"
    _write_release(release, marker="bundle-stage-zero")
    dependency = tmp_path / "verified external dependency"
    dependency.mkdir()
    (dependency / "stage_zero_external.py").write_text(
        "VALUE = 'external-dependency-loaded'\n",
        encoding="utf-8",
    )
    (release / "supervisor_core" / "cli.py").write_text(
        textwrap.dedent(
            """
            import json
            import sys
            from stage_zero_external import VALUE as EXTERNAL_VALUE

            def main(argv=None):
                args = list(sys.argv[1:] if argv is None else argv)
                if args != ["--stage-zero-dependency-probe"]:
                    return 64
                runtime = sys.modules.get("_agent_supervisor_bound_runtime")
                print(json.dumps({
                    "external": EXTERNAL_VALUE,
                    "module_file": __file__,
                    "runtime_contract": getattr(runtime, "contract", None),
                    "core_root": getattr(runtime, "core_root", None),
                }, separators=(",", ":")))
                return 0
            """
        ).lstrip(),
        encoding="utf-8",
    )
    blob = _build(release, "v-posix-stage-zero")
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    identity["version"] = "v-posix-stage-zero"
    bundle_path = release / identity["bundle_relpath"]
    bundle_path.write_bytes(blob)
    pointer_root = home / ".agent-supervisor"
    pointer_root.mkdir()
    (pointer_root / "active-version.json").write_text(
        json.dumps(
            {"contract": POINTER_CONTRACT, "active": identity, "previous": None},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    # Both mutable release entrypoints are poisoned *after* the frozen bundle
    # has been built.  A disk launcher/source fallback creates this sentinel.
    sentinel = tmp_path / "mutable-release-was-executed.txt"
    poison = (
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('mutable', encoding='utf-8')\n"
        "raise SystemExit(93)\n"
    )
    (release / "bin" / "agent-supervisor.py").write_text(poison, encoding="utf-8")
    (release / "supervisor_core" / "cli.py").write_text(poison, encoding="utf-8")

    # The bridge derives its trusted install home from ``$PSScriptRoot``.  Keep
    # the transformed copy inside the staged adapter's real scripts directory.
    transformed = scripts / "supervisor-core-posix-stage-zero.ps1"
    harness = tmp_path / "posix-stage-zero-harness.ps1"
    harness.write_text(
        textwrap.dedent(
            r"""
            param(
                [Parameter(Mandatory = $true)][string]$CoreScript,
                [Parameter(Mandatory = $true)][string]$TransformedScript,
                [Parameter(Mandatory = $true)][string]$PythonCommand,
                [Parameter(Mandatory = $true)][string]$DependencyRoot
            )
            $ErrorActionPreference = 'Stop'
            $source = [IO.File]::ReadAllText($CoreScript, [Text.Encoding]::UTF8)
            $tokens = $null
            $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput(
                $source,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if (@($parseErrors).Count -ne 0) { throw 'production bridge parse failed' }
            $assignments = @($ast.FindAll({
                param($node)
                return (
                    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -ceq '$runningOnWindows'
                )
            }, $true))
            if ($assignments.Count -lt 1) { throw 'platform cache assignment missing' }
            foreach ($assignment in @($assignments | Sort-Object {
                $_.Right.Extent.StartOffset
            } -Descending)) {
                $start = $assignment.Right.Extent.StartOffset
                $end = $assignment.Right.Extent.EndOffset
                $source = $source.Substring(0, $start) + '$false' + $source.Substring($end)
            }
            [IO.File]::WriteAllText(
                $TransformedScript,
                $source,
                [Text.UTF8Encoding]::new($false)
            )
            . $TransformedScript
            if (-not (Test-AgentSupervisorProcessTreeKillAvailable)) {
                throw 'host lacks the required tree-aware Kill(bool) primitive'
            }
            $core = Get-AgentSupervisorCoreRoot
            $launcher = Resolve-AgentSupervisorTrustedLauncherPath -CoreRoot $core
            if ([string]::IsNullOrWhiteSpace($launcher)) { throw 'bound launcher unavailable' }
            $script:AgentSupervisorVerifiedDependencyRoots = @($DependencyRoot)
            $result = Invoke-AgentSupervisorPython `
                -Command $PythonCommand `
                -Arguments @(
                    '-I', '-S', '-B', '-X', 'utf8',
                    $launcher,
                    '--stage-zero-dependency-probe'
                ) `
                -Operation 'posix-stage-zero-probe' `
                -TimeoutSeconds 5 `
                -CaptureOutput `
                -SuppressOutput `
                -IsolatedEnvironment `
                -Silent
            [pscustomobject]@{
                ast_rewrite_count = $assignments.Count
                exit_code = [int]$result.ExitCode
                started = [bool]$result.Started
                timed_out = [bool]$result.TimedOut
                output = [string]$result.StandardOutput
            } | ConvertTo-Json -Compress
            """
        ),
        encoding="utf-8",
    )
    selected_dependency = dependency_root if dependency_root is not None else str(dependency)
    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
            "-CoreScript",
            str(scripts / "supervisor-core.ps1"),
            "-TransformedScript",
            str(transformed),
            "-PythonCommand",
            sys.executable,
            "-DependencyRoot",
            selected_dependency,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=20,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return completed, sentinel, release


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


def test_non_windows_invoke_uses_frozen_stage_zero_with_verified_external_dependency(
    tmp_path: Path,
) -> None:
    completed, sentinel, release = _run_non_windows_frozen_dependency_probe(tmp_path)

    assert completed.returncode == 0, completed.stderr
    wrapper = json.loads(completed.stdout)
    assert wrapper["ast_rewrite_count"] >= 1
    assert wrapper["exit_code"] == 0
    assert wrapper["started"] is True
    assert wrapper["timed_out"] is False
    observed = json.loads(wrapper["output"])
    assert observed["external"] == "external-dependency-loaded"
    assert Path(observed["module_file"]) == release / "supervisor_core" / "cli.py"
    assert observed["runtime_contract"] == "SupervisorBoundRuntime/v1"
    assert Path(observed["core_root"]) == release
    assert not sentinel.exists()


def test_non_windows_stage_zero_dependency_path_failure_degrades_without_disk_fallback(
    tmp_path: Path,
) -> None:
    completed, sentinel, _release = _run_non_windows_frozen_dependency_probe(
        tmp_path,
        dependency_root="relative-untrusted-dependency",
    )

    assert completed.returncode == 0, completed.stderr
    wrapper = json.loads(completed.stdout)
    assert wrapper["exit_code"] == 4
    assert isinstance(wrapper["started"], bool)
    assert wrapper["timed_out"] is False
    assert wrapper["output"] == ""
    assert not sentinel.exists()


def test_direct_launcher_executes_frozen_bundle_after_release_cli_is_tampered(
    tmp_path: Path,
) -> None:
    release, pointer, _identity_record, _blob = _stage_direct_launcher_release(
        tmp_path,
        marker="bundle-old-marker",
    )
    (release / "supervisor_core" / "cli.py").write_text(
        "def main(argv=None):\n    print('disk-tampered-marker')\n    return 0\n",
        encoding="utf-8",
    )

    completed = _run_direct_launcher(pointer, tmp_path / "releases", "--version")

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout.strip() == b"bundle-old-marker"


def test_direct_launcher_bundle_modules_keep_logical_release_identity(
    tmp_path: Path,
) -> None:
    release, pointer, identity, _blob = _stage_direct_launcher_release(
        tmp_path,
        marker="bundle-identity-marker",
    )
    (release / "supervisor_core" / "cli.py").write_text(
        "raise SystemExit('disk module must not load')\n",
        encoding="utf-8",
    )

    completed = _run_direct_launcher(pointer, tmp_path / "releases", "--identity-probe")

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    observed = json.loads(completed.stdout)
    assert observed["marker"] == "bundle-identity-marker"
    assert Path(observed["module_file"]) == release / "supervisor_core" / "cli.py"
    assert observed["runtime_contract"] == "SupervisorBoundRuntime/v1"
    assert Path(observed["core_root"]) == release
    assert observed["identity_version"] == identity["version"]


@pytest.mark.parametrize(
    "failure",
    [
        "identity-bundle-hash",
        "identity-manifest-hash",
        "identity-source-hash",
        "bundle-bytes",
        "member-hash",
        "relative-release-path",
        "outside-release-root",
    ],
)
def test_direct_launcher_rejects_untrusted_pointer_bundle_without_disk_fallback(
    tmp_path: Path,
    failure: str,
) -> None:
    release, pointer, identity, blob = _stage_direct_launcher_release(tmp_path)
    payload = json.loads(pointer.read_text(encoding="utf-8"))
    active = payload["active"]
    if failure == "identity-bundle-hash":
        active["bundle_sha256"] = "0" * 64
    elif failure == "identity-manifest-hash":
        active["manifest_sha256"] = "1" * 64
    elif failure == "identity-source-hash":
        active["source_tree_sha256"] = "2" * 64
    elif failure == "bundle-bytes":
        (release / identity["bundle_relpath"]).write_bytes(blob + b"tampered")
    elif failure == "member-hash":
        corrupted = _rewrite_zip(
            blob,
            lambda members: [
                (name, b"VALUE = 'member-tampered'\n" if name == "supervisor_core/snapshot_probe.py" else content)
                for name, content in members
            ],
        )
        (release / identity["bundle_relpath"]).write_bytes(corrupted)
        active["bundle_sha256"] = _sha256(corrupted)
    elif failure == "relative-release-path":
        active["path"] = "relative-release"
    elif failure == "outside-release-root":
        active["path"] = str((tmp_path / "outside").resolve())
    pointer.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")

    completed = _run_direct_launcher(pointer, tmp_path / "releases", "--version")

    assert completed.returncode == 64
    assert completed.stdout == b""


def test_direct_launcher_rejects_partial_pointer_snapshot_without_disk_fallback(
    tmp_path: Path,
) -> None:
    _release, pointer, _identity_record, _blob = _stage_direct_launcher_release(tmp_path)
    valid = pointer.read_bytes()
    pointer.write_bytes(valid[: max(1, len(valid) // 2)])

    completed = _run_direct_launcher(pointer, tmp_path / "releases", "--version")

    assert completed.returncode == 64
    assert completed.stdout == b""


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


def test_powershell_posix_timeout_calls_tree_cleanup_before_parent_exit(tmp_path: Path) -> None:
    """Execute the POSIX timeout branch with a valid frozen runtime frame.

    The production bridge is AST-rewritten only at bounded platform/type AST
    nodes.  A controlled cleanup wrapper records whether the real child was
    already dead when cleanup began.  This catches the P1 regression where
    ``Kill()`` first terminated the parent and then skipped ``Kill(true)`` for
    its descendants, including a root that exits while a descendant owns a pipe.
    """

    home = tmp_path / "posix timeout home"
    scripts = _stage_native_adapter(home)
    release = home / ".agent-supervisor-releases" / "v-posix-timeout"
    _write_release(release)
    (release / "supervisor_core" / "cli.py").write_text(
        textwrap.dedent(
            """
            import time

            def main(argv=None):
                time.sleep(10)
                return 0
            """
        ).lstrip(),
        encoding="utf-8",
    )
    blob = _build(release, "v-posix-timeout")
    inspected = _inspect(blob)
    identity = _identity(release, blob, inspected)
    (release / identity["bundle_relpath"]).write_bytes(blob)
    pointer_root = home / ".agent-supervisor"
    pointer_root.mkdir()
    (pointer_root / "active-version.json").write_text(
        json.dumps(
            {"contract": POINTER_CONTRACT, "active": identity, "previous": None},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

    transformed = scripts / "supervisor-core-posix-timeout.ps1"
    harness = tmp_path / "posix-timeout-harness.ps1"
    harness.write_text(
        textwrap.dedent(
            r"""
            param(
                [Parameter(Mandatory = $true)][string]$CoreScript,
                [Parameter(Mandatory = $true)][string]$TransformedScript,
                [Parameter(Mandatory = $true)][string]$PythonCommand
            )
            $ErrorActionPreference = 'Stop'
            $source = [IO.File]::ReadAllText($CoreScript, [Text.Encoding]::UTF8)
            $tokens = $null
            $parseErrors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput(
                $source,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if (@($parseErrors).Count -ne 0) { throw 'production bridge parse failed' }
            $rewrites = [Collections.Generic.List[object]]::new()
            $assignments = @($ast.FindAll({
                param($node)
                return (
                    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -ceq '$runningOnWindows'
                )
            }, $true))
            foreach ($assignment in $assignments) {
                $rewrites.Add([pscustomobject]@{
                    Start = $assignment.Right.Extent.StartOffset
                    End = $assignment.Right.Extent.EndOffset
                    Value = '$false'
                })
            }
            $nonWindowsPredicates = @($ast.FindAll({
                param($node)
                return (
                    $node -is [Management.Automation.Language.BinaryExpressionAst] -and
                    $node.Extent.Text -ceq '[Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT'
                )
            }, $true))
            foreach ($predicate in $nonWindowsPredicates) {
                $rewrites.Add([pscustomobject]@{
                    Start = $predicate.Extent.StartOffset
                    End = $predicate.Extent.EndOffset
                    Value = '$true'
                })
            }
            $processConstraints = @($ast.FindAll({
                param($node)
                return (
                    $node -is [Management.Automation.Language.TypeConstraintAst] -and
                    $node.Extent.Text -ceq '[Diagnostics.Process]'
                )
            }, $true))
            foreach ($constraint in $processConstraints) {
                $rewrites.Add([pscustomobject]@{
                    Start = $constraint.Extent.StartOffset
                    End = $constraint.Extent.EndOffset
                    Value = '[object]'
                })
            }
            if (
                $assignments.Count -lt 1 -or
                $nonWindowsPredicates.Count -lt 1 -or
                $processConstraints.Count -lt 1
            ) {
                throw 'bounded platform/type AST nodes missing'
            }
            foreach ($rewrite in @($rewrites | Sort-Object Start -Descending)) {
                $source = (
                    $source.Substring(0, $rewrite.Start) +
                    $rewrite.Value +
                    $source.Substring($rewrite.End)
                )
            }
            [IO.File]::WriteAllText(
                $TransformedScript,
                $source,
                [Text.UTF8Encoding]::new($false)
            )
            . $TransformedScript
            $core = Get-AgentSupervisorCoreRoot
            $launcher = Resolve-AgentSupervisorTrustedLauncherPath -CoreRoot $core
            if ([string]::IsNullOrWhiteSpace($launcher)) { throw 'bound launcher unavailable' }

            # Run the production POSIX cleanup helper against an already-exited
            # root facade. It must still attempt Kill(true), because a descendant
            # may retain an inherited stdout/stderr pipe.
            function global:Test-AgentSupervisorProcessTreeKillAvailable { return $true }
            $script:ExitedRootTreeKillCalls = 0
            $script:ExitedRootParentKillCalls = 0
            $exitedRoot = [pscustomobject]@{ Id = 424242; HasExited = $true }
            $exitedRoot | Add-Member -MemberType ScriptMethod -Name Kill -Value {
                param([bool]$EntireProcessTree = $false)
                if ($EntireProcessTree) { $script:ExitedRootTreeKillCalls += 1 }
                else { $script:ExitedRootParentKillCalls += 1 }
            } -Force
            $exitedRoot | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
                param([int]$Milliseconds)
                return $true
            } -Force
            Stop-AgentSupervisorProcessTree -Process $exitedRoot

            function global:Test-AgentSupervisorProcessTreeKillAvailable { return $false }
            $unavailable = Invoke-AgentSupervisorPython `
                -Command $PythonCommand `
                -Arguments @('-I','-S','-B','-X','utf8',$launcher) `
                -Operation 'posix-timeout-probe' `
                -TimeoutSeconds 0.1 `
                -CaptureOutput `
                -SuppressOutput `
                -IsolatedEnvironment `
                -Silent

            function global:Test-AgentSupervisorProcessTreeKillAvailable { return $true }
            $script:StopCalls = 0
            $script:ExitedBeforeStop = $null
            $script:TreeKillCalls = 0
            function global:Stop-AgentSupervisorProcessTree {
                param([Parameter(Mandatory = $true)][object]$Process)
                $script:StopCalls += 1
                $script:ExitedBeforeStop = [bool]$Process.HasExited
                try {
                    if (-not $Process.HasExited) {
                        $Process.Kill($true)
                        $script:TreeKillCalls += 1
                    }
                    $null = $Process.WaitForExit(750)
                } catch { }
            }
            $timed = Invoke-AgentSupervisorPython `
                -Command $PythonCommand `
                -Arguments @('-I','-S','-B','-X','utf8',$launcher) `
                -Operation 'posix-timeout-probe' `
                -TimeoutSeconds 0.1 `
                -CaptureOutput `
                -SuppressOutput `
                -IsolatedEnvironment `
                -Silent
            [pscustomobject]@{
                ast_rewrite_count = $rewrites.Count
                exited_root_tree_kill_calls = $script:ExitedRootTreeKillCalls
                exited_root_parent_kill_calls = $script:ExitedRootParentKillCalls
                unavailable_exit = [int]$unavailable.ExitCode
                unavailable_started = [bool]$unavailable.Started
                timeout_exit = [int]$timed.ExitCode
                timeout_started = [bool]$timed.Started
                timeout_flag = [bool]$timed.TimedOut
                stop_calls = $script:StopCalls
                exited_before_stop = [bool]$script:ExitedBeforeStop
                tree_kill_calls = $script:TreeKillCalls
            } | ConvertTo-Json -Compress
            """
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
            "-CoreScript",
            str(scripts / "supervisor-core.ps1"),
            "-TransformedScript",
            str(transformed),
            "-PythonCommand",
            sys.executable,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["ast_rewrite_count"] >= 3
    assert observed["exited_root_tree_kill_calls"] == 1
    assert observed["exited_root_parent_kill_calls"] == 0
    assert observed["unavailable_exit"] == 4
    assert observed["unavailable_started"] is False
    assert observed["timeout_exit"] == 4
    assert observed["timeout_started"] is True
    assert observed["timeout_flag"] is True
    assert observed["stop_calls"] == 1
    assert observed["exited_before_stop"] is False
    assert observed["tree_kill_calls"] == 1
