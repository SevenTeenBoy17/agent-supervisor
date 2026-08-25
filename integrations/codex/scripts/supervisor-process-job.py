"""Run one bundle-bound Supervisor command through a frozen stage-0.

Windows stage-0 owns a kill-on-close Job Object.  On Linux and macOS the
PowerShell parent is required to provide tree-aware ``Process.Kill(true)``
cleanup before this program is started; this process still owns runtime-frame
validation and the in-memory bundle importer on every supported platform.
"""

from __future__ import annotations

import ctypes
import runpy
import sys
from ctypes import wintypes


_FRAME_MAGIC = b"ASRFv1\x00\x00"
_MAX_IDENTITY_BYTES = 64 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_MEMBER_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_MEMBERS = 512


class _BasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimit),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _enable_kill_on_close() -> bool:
    if sys.platform != "win32":
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        job = kernel32.CreateJobObjectW(None, None)
        limits = _ExtendedLimit()
        limits.BasicLimitInformation.LimitFlags = 0x2000
        ready = bool(
            job
            and kernel32.SetInformationJobObject(
                job,
                9,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            )
            and kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())
        )
        if not ready and job:
            kernel32.CloseHandle(job)
        return ready
    except Exception:
        return False


def _establish_platform_containment() -> bool:
    """Establish or acknowledge the supported platform containment boundary.

    The Windows child must join its own kill-on-close Job before reading any
    caller-supplied frame bytes.  Linux and macOS cannot create that Job; their
    trusted PowerShell parent verifies the tree-aware Kill(bool) primitive and
    is responsible for invoking it on timeout or stream failure.  No other
    platform is implicitly treated as POSIX-compatible.
    """

    if sys.platform == "win32":
        return _enable_kill_on_close()
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        return True
    return False


def _enable_dependency_paths() -> bool:
    """Expose validated package roots only after the process joins the Job."""

    try:
        import os

        raw = os.environ.pop("AGENT_SUPERVISOR_DEPENDENCY_ROOTS", "")
        if not raw:
            return True
        for dependency_path in raw.split(os.pathsep):
            if not dependency_path or not os.path.isabs(dependency_path):
                return False
            if dependency_path not in sys.path:
                sys.path.append(dependency_path)
        return True
    except (OSError, ValueError):
        return False


def _read_exact(stream: object, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise ValueError("truncated-runtime-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate-json-key")
        value[key] = item
    return value


def _safe_member_path(value: object) -> str:
    import pathlib

    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("invalid-member-path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid-member-path")
    return path.as_posix()


def _canonical_json(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_bound_bundle(identity_bytes: bytes, bundle: bytes) -> tuple[dict[str, object], dict[str, bytes], dict[str, object]]:
    import hashlib
    import io
    import json
    import re
    import zipfile

    sha_pattern = re.compile(r"^[0-9a-f]{64}$")
    try:
        identity = json.loads(
            identity_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release-identity-json-invalid") from exc
    required_identity = {
        "contract", "version", "path", "bundle_relpath", "bundle_sha256",
        "manifest_sha256", "source_tree_sha256",
    }
    if (
        not isinstance(identity, dict)
        or set(identity) != required_identity
        or identity.get("contract") != "SupervisorReleaseIdentity/v1"
        or not isinstance(identity.get("version"), str)
        or not identity["version"]
        or not isinstance(identity.get("path"), str)
        or not identity["path"]
        or not __import__("os").path.isabs(identity["path"])
        or _safe_member_path(identity.get("bundle_relpath")) != identity["bundle_relpath"]
        or any(not sha_pattern.fullmatch(str(identity.get(key) or "")) for key in (
            "bundle_sha256", "manifest_sha256", "source_tree_sha256"
        ))
        or hashlib.sha256(bundle).hexdigest() != identity["bundle_sha256"]
    ):
        raise ValueError("release-identity-invalid")

    try:
        archive = zipfile.ZipFile(io.BytesIO(bundle), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("runtime-bundle-invalid") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_MEMBERS:
            raise ValueError("runtime-member-count-invalid")
        names: list[str] = []
        folded: set[str] = set()
        total = 0
        for info in infos:
            name = _safe_member_path(info.filename)
            if name.casefold() in folded or info.is_dir():
                raise ValueError("runtime-member-duplicate")
            folded.add(name.casefold())
            names.append(name)
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                raise ValueError("runtime-member-encoding-invalid")
            if info.file_size < 1 or info.file_size > _MAX_MEMBER_BYTES:
                raise ValueError("runtime-member-size-invalid")
            total += info.file_size
            if total > _MAX_TOTAL_BYTES:
                raise ValueError("runtime-expanded-size-invalid")
        manifest_name = "SUPERVISOR-RUNTIME-MANIFEST.json"
        if manifest_name not in names:
            raise ValueError("runtime-manifest-missing")
        manifest_bytes = archive.read(manifest_name)
        try:
            manifest = json.loads(
                manifest_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("runtime-manifest-json-invalid") from exc
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"contract", "files", "source_tree_sha256", "version"}
            or manifest.get("contract") != "SupervisorRuntimeManifest/v1"
            or manifest_bytes != _canonical_json(manifest)
            or manifest.get("version") != identity["version"]
            or manifest.get("source_tree_sha256") != identity["source_tree_sha256"]
            or hashlib.sha256(manifest_bytes).hexdigest() != identity["manifest_sha256"]
            or not isinstance(manifest.get("files"), list)
        ):
            raise ValueError("runtime-manifest-contract-invalid")
        resources: dict[str, bytes] = {}
        rows: list[dict[str, object]] = []
        row_names: list[str] = []
        modules: set[str] = set()
        for row in manifest["files"]:
            if not isinstance(row, dict) or set(row) != {
                "kind", "module", "path", "sha256", "size",
            }:
                raise ValueError("runtime-manifest-row-invalid")
            name = _safe_member_path(row.get("path"))
            if (
                name == manifest_name
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("size"), int)
                or row["size"] < 1
                or not sha_pattern.fullmatch(str(row.get("sha256") or ""))
            ):
                raise ValueError("runtime-manifest-row-invalid")
            module = row.get("module")
            if module is not None:
                if (
                    not isinstance(module, str)
                    or not (
                        module == "supervisor_core"
                        or module.startswith("supervisor_core.")
                    )
                    or module in modules
                ):
                    raise ValueError("runtime-module-invalid")
                modules.add(module)
            try:
                content = archive.read(name)
            except KeyError as exc:
                raise ValueError("runtime-member-missing") from exc
            if len(content) != row["size"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise ValueError("runtime-member-digest-invalid")
            resources[name] = content
            rows.append(row)
            row_names.append(name)
        if (
            row_names != sorted(row_names)
            or len({name.casefold() for name in row_names}) != len(row_names)
            or set(names) != {manifest_name, *row_names}
            or hashlib.sha256(_canonical_json(rows)).hexdigest() != identity["source_tree_sha256"]
            or "supervisor_core" not in modules
        ):
            raise ValueError("runtime-manifest-members-invalid")
    return identity, resources, manifest


def _install_memory_importer(identity: dict[str, object], resources: dict[str, bytes], manifest: dict[str, object]) -> None:
    import importlib.abc
    import importlib.util
    import types

    module_records: dict[str, tuple[bytes, str, bool]] = {}
    for row in manifest["files"]:
        module = row.get("module")
        if not isinstance(module, str):
            continue
        path = str(row["path"])
        is_package = path.endswith("/__init__.py")
        logical_path = str(identity["path"]).rstrip("\\/") + "/" + path
        module_records[module] = (resources[path], logical_path, is_package)

    class MemoryLoader(importlib.abc.Loader):
        def __init__(self, name: str) -> None:
            self.name = name

        def create_module(self, spec: object) -> object | None:
            return None

        def exec_module(self, module: object) -> None:
            source, logical_path, is_package = module_records[self.name]
            module.__file__ = logical_path
            module.__loader__ = self
            if is_package:
                module.__path__ = [logical_path.rsplit("/", 1)[0]]
            exec(compile(source, logical_path, "exec"), module.__dict__, module.__dict__)

        def get_source(self, fullname: str) -> str:
            return module_records[fullname][0].decode("utf-8")

    class MemoryFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname: str, path: object = None, target: object = None) -> object:
            if fullname == "supervisor_core" or fullname.startswith("supervisor_core."):
                if fullname not in module_records:
                    raise ModuleNotFoundError(f"bound runtime module is not manifested: {fullname}")
                is_package = module_records[fullname][2]
                return importlib.util.spec_from_loader(fullname, MemoryLoader(fullname), is_package=is_package)
            return None

    for name in tuple(sys.modules):
        if name == "supervisor_core" or name.startswith("supervisor_core."):
            sys.modules.pop(name, None)
    runtime = types.ModuleType("_agent_supervisor_bound_runtime")
    runtime.contract = "SupervisorBoundRuntime/v1"
    runtime.core_root = identity["path"]
    runtime.identity = dict(identity)
    runtime.manifest = dict(manifest)
    runtime.resources = dict(resources)
    sys.modules[runtime.__name__] = runtime
    sys.meta_path.insert(0, MemoryFinder())


def _read_and_install_runtime_frame() -> bytes:
    """Read one SupervisorRuntimeFrame/v1 after containment is established."""
    import hashlib
    import io
    import json
    import struct

    stream = sys.stdin.buffer
    header = _read_exact(stream, len(_FRAME_MAGIC) + 12)
    if header[: len(_FRAME_MAGIC)] != _FRAME_MAGIC:
        raise ValueError("runtime-frame-magic-invalid")
    identity_length, bundle_length, payload_length = struct.unpack(
        ">III",
        header[len(_FRAME_MAGIC):],
    )
    if (
        identity_length < 2
        or identity_length > _MAX_IDENTITY_BYTES
        or bundle_length < 1
        or bundle_length > _MAX_BUNDLE_BYTES
        or payload_length > _MAX_PAYLOAD_BYTES
    ):
        raise ValueError("runtime-frame-size-invalid")
    identity_bytes = _read_exact(stream, identity_length)
    bundle = _read_exact(stream, bundle_length)
    payload = _read_exact(stream, payload_length)
    if stream.read(1):
        raise ValueError("runtime-frame-trailing-data")
    identity, resources, manifest = _parse_bound_bundle(identity_bytes, bundle)
    _install_memory_importer(identity, resources, manifest)
    sys.stdin = io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8", errors="strict")
    return resources["bin/agent-supervisor.py"]


def _dispatch(arguments: list[str]) -> int:
    if arguments and arguments[0] == "--runtime-frame":
        try:
            _read_and_install_runtime_frame()
        except (ValueError, TypeError, OSError, SyntaxError, KeyError, ImportError):
            return 64
        return 64

    if arguments and arguments[0] == "--agent-supervisor-bound-bundle":
        if len(arguments) < 2:
            return 64
        try:
            _read_and_install_runtime_frame()
            logical_path = arguments[1]
            from supervisor_core.cli import main as supervisor_main
        except (ValueError, TypeError, OSError, SyntaxError, KeyError, ImportError):
            return 64
        sys.argv = [logical_path, *arguments[2:]]
        return int(supervisor_main())

    while arguments:
        if arguments[0] in {"-E", "-P", "-I", "-s", "-S", "-B", "-u"}:
            arguments = arguments[1:]
            continue
        if arguments[0] == "-X" and len(arguments) >= 2:
            arguments = arguments[2:]
            continue
        if arguments[0].startswith("-X"):
            arguments = arguments[1:]
            continue
        break

    if not arguments:
        return 64
    if arguments[0] == "-c":
        if len(arguments) < 2:
            return 64
        source = arguments[1]
        sys.argv = ["-c", *arguments[2:]]
        globals_ = {"__name__": "__main__", "__package__": None, "__spec__": None}
        exec(compile(source, "<agent-supervisor-command>", "exec"), globals_, globals_)
        return 0
    if arguments[0] == "-m":
        if len(arguments) < 2:
            return 64
        module = arguments[1]
        sys.argv = [module, *arguments[2:]]
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0

    script = arguments[0]
    sys.argv = [script, *arguments[1:]]
    runpy.run_path(script, run_name="__main__")
    return 0


def main() -> int:
    if not _establish_platform_containment():
        return 125
    if not _enable_dependency_paths():
        return 125
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--":
        arguments = arguments[1:]
    return _dispatch(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
