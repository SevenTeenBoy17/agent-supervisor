from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types
import zipfile


_POINTER_CONTRACT = "ActiveVersionPointer/v4"
_IDENTITY_CONTRACT = "SupervisorReleaseIdentity/v1"
_MANIFEST_CONTRACT = "SupervisorRuntimeManifest/v1"
_MANIFEST_MEMBER = "SUPERVISOR-RUNTIME-MANIFEST.json"
_BOUND_RUNTIME_CONTRACT = "SupervisorBoundRuntime/v1"
_POINTER_FIELDS = frozenset({"active", "contract", "previous"})
_IDENTITY_FIELDS = frozenset({
    "bundle_relpath",
    "bundle_sha256",
    "contract",
    "manifest_sha256",
    "path",
    "source_tree_sha256",
    "version",
})
_MANIFEST_FIELDS = frozenset({"contract", "files", "source_tree_sha256", "version"})
_MANIFEST_ROW_FIELDS = frozenset({"kind", "module", "path", "sha256", "size"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_POINTER_BYTES = 1024 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_MEMBER_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024
_MAX_MEMBERS = 512


class _BootstrapError(ValueError):
    """The active immutable runtime could not be established."""


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
    )


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    )


def _reject_path_indirection(path: Path) -> None:
    """Reject every existing link/reparse component without following it."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(absolute.anchor)
    current = anchor
    if not absolute.is_absolute() or _is_link_or_reparse(current):
        raise _BootstrapError("path-indirection")
    try:
        parts = absolute.relative_to(anchor).parts
    except ValueError as exc:
        raise _BootstrapError("path-not-canonical") from exc
    for part in parts:
        current /= part
        if _is_link_or_reparse(current):
            raise _BootstrapError("path-indirection")


def _stable_read(path: Path, maximum: int) -> bytes:
    """Read one regular file through a stable descriptor-bound snapshot."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute():
        raise _BootstrapError("file-path-not-absolute")
    _reject_path_indirection(absolute)
    before = absolute.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > maximum:
        raise _BootstrapError("file-size-invalid")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute, flags)
    try:
        opened_before = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise _BootstrapError("file-size-invalid")
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = absolute.lstat()
    _reject_path_indirection(absolute)
    if not (
        _file_identity(before)
        == _file_identity(opened_before)
        == _file_identity(opened_after)
        == _file_identity(after)
    ):
        raise _BootstrapError("file-changed-during-read")
    value = b"".join(chunks)
    if len(value) != before.st_size:
        raise _BootstrapError("file-read-truncated")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _BootstrapError("duplicate-json-key")
        value[key] = item
    return value


def _json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _BootstrapError(f"{label}-json-invalid") from exc
    if not isinstance(value, dict):
        raise _BootstrapError(f"{label}-object-required")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_member_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise _BootstrapError("member-path-invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise _BootstrapError("member-path-invalid")
    return path.as_posix()


def _install_layout() -> tuple[Path, Path, Path]:
    """Anchor global state in the physical installation, never HOME overrides."""
    launcher = Path(os.path.abspath(__file__))
    _reject_path_indirection(launcher)
    root = launcher.parent.parent
    if root.name.casefold() == ".agent-supervisor":
        install_home = root.parent
    elif root.parent.name.casefold() == ".agent-supervisor-releases":
        install_home = root.parent.parent
    else:
        raise _BootstrapError("launcher-layout-invalid")
    pointer_root = install_home / ".agent-supervisor"
    release_root = install_home / ".agent-supervisor-releases"
    _reject_path_indirection(pointer_root)
    _reject_path_indirection(release_root)
    return pointer_root / "active-version.json", pointer_root, release_root


def _identity_paths(
    identity: object,
    allowed_roots: tuple[Path, Path],
) -> tuple[dict[str, object], Path, Path]:
    if (
        not isinstance(identity, dict)
        or set(identity) != _IDENTITY_FIELDS
        or identity.get("contract") != _IDENTITY_CONTRACT
        or not isinstance(identity.get("version"), str)
        or not str(identity["version"]).strip()
        or any(
            not isinstance(identity.get(name), str)
            or not _SHA256.fullmatch(str(identity[name]))
            for name in ("bundle_sha256", "manifest_sha256", "source_tree_sha256")
        )
    ):
        raise _BootstrapError("release-identity-invalid")
    raw_root = identity.get("path")
    if not isinstance(raw_root, str) or not raw_root or "\x00" in raw_root:
        raise _BootstrapError("release-root-invalid")
    release_root = Path(raw_root)
    if not release_root.is_absolute() or any(part in {".", ".."} for part in release_root.parts):
        raise _BootstrapError("release-root-invalid")
    release_root = Path(os.path.abspath(os.fspath(release_root)))
    _reject_path_indirection(release_root)
    resolved_release = release_root.resolve(strict=True)
    if resolved_release != release_root or not release_root.is_dir():
        raise _BootstrapError("release-root-invalid")
    allowed = False
    for candidate_root in allowed_roots:
        trusted_root = Path(os.path.abspath(os.fspath(candidate_root)))
        _reject_path_indirection(trusted_root)
        resolved_trusted = trusted_root.resolve(strict=True)
        try:
            resolved_release.relative_to(resolved_trusted)
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        raise _BootstrapError("release-root-untrusted")
    relative_bundle = _safe_member_path(identity.get("bundle_relpath"))
    bundle_path = release_root.joinpath(*PurePosixPath(relative_bundle).parts)
    _reject_path_indirection(bundle_path)
    resolved_bundle = bundle_path.resolve(strict=True)
    try:
        resolved_bundle.relative_to(resolved_release)
    except ValueError as exc:
        raise _BootstrapError("bundle-root-escape") from exc
    if resolved_bundle != bundle_path or not bundle_path.is_file():
        raise _BootstrapError("bundle-path-invalid")
    return identity, release_root, bundle_path


def _inspect_bundle(
    identity: dict[str, object],
    bundle: bytes,
) -> tuple[dict[str, bytes], dict[str, object]]:
    if hashlib.sha256(bundle).hexdigest() != identity["bundle_sha256"]:
        raise _BootstrapError("bundle-digest-mismatch")
    try:
        archive = zipfile.ZipFile(io.BytesIO(bundle), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise _BootstrapError("bundle-zip-invalid") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > _MAX_MEMBERS:
            raise _BootstrapError("bundle-member-count-invalid")
        names: list[str] = []
        folded: set[str] = set()
        total = 0
        for info in infos:
            name = _safe_member_path(info.filename)
            if name.casefold() in folded or info.is_dir():
                raise _BootstrapError("bundle-member-duplicate")
            folded.add(name.casefold())
            names.append(name)
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                raise _BootstrapError("bundle-member-encoding-invalid")
            if info.file_size < 1 or info.file_size > _MAX_MEMBER_BYTES:
                raise _BootstrapError("bundle-member-size-invalid")
            total += info.file_size
            if total > _MAX_TOTAL_BYTES:
                raise _BootstrapError("bundle-expanded-size-invalid")
        if _MANIFEST_MEMBER not in names:
            raise _BootstrapError("bundle-manifest-missing")
        manifest_bytes = archive.read(_MANIFEST_MEMBER)
        manifest = _json_object(manifest_bytes, "runtime-manifest")
        if (
            set(manifest) != _MANIFEST_FIELDS
            or manifest.get("contract") != _MANIFEST_CONTRACT
            or manifest_bytes != _canonical_json(manifest)
            or manifest.get("version") != identity["version"]
            or manifest.get("source_tree_sha256") != identity["source_tree_sha256"]
            or hashlib.sha256(manifest_bytes).hexdigest() != identity["manifest_sha256"]
            or not isinstance(manifest.get("files"), list)
        ):
            raise _BootstrapError("runtime-manifest-invalid")

        resources: dict[str, bytes] = {}
        rows: list[dict[str, object]] = []
        row_names: list[str] = []
        modules: set[str] = set()
        for raw_row in manifest["files"]:
            if not isinstance(raw_row, dict) or set(raw_row) != _MANIFEST_ROW_FIELDS:
                raise _BootstrapError("runtime-manifest-row-invalid")
            row = raw_row
            name = _safe_member_path(row.get("path"))
            module = row.get("module")
            if (
                name == _MANIFEST_MEMBER
                or not isinstance(row.get("kind"), str)
                or not isinstance(row.get("size"), int)
                or isinstance(row.get("size"), bool)
                or int(row["size"]) < 1
                or not isinstance(row.get("sha256"), str)
                or not _SHA256.fullmatch(str(row["sha256"]))
                or (
                    module is not None
                    and (
                        not isinstance(module, str)
                        or not (module == "supervisor_core" or module.startswith("supervisor_core."))
                        or module in modules
                    )
                )
            ):
                raise _BootstrapError("runtime-manifest-row-invalid")
            if isinstance(module, str):
                modules.add(module)
            try:
                content = archive.read(name)
            except KeyError as exc:
                raise _BootstrapError("runtime-member-missing") from exc
            if len(content) != row["size"] or hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise _BootstrapError("runtime-member-digest-mismatch")
            resources[name] = content
            rows.append(row)
            row_names.append(name)
        if (
            row_names != sorted(row_names)
            or len({name.casefold() for name in row_names}) != len(row_names)
            or set(names) != {_MANIFEST_MEMBER, *row_names}
            or hashlib.sha256(_canonical_json(rows)).hexdigest() != identity["source_tree_sha256"]
            or "supervisor_core" not in modules
            or "supervisor_core.cli" not in modules
        ):
            raise _BootstrapError("runtime-manifest-members-invalid")
    return resources, manifest


def _install_memory_importer(
    identity: dict[str, object],
    resources: dict[str, bytes],
    manifest: dict[str, object],
) -> None:
    module_records: dict[str, tuple[bytes, str, bool]] = {}
    for row in manifest["files"]:
        module = row.get("module")
        if not isinstance(module, str):
            continue
        path = str(row["path"])
        logical_path = str(identity["path"]).rstrip("\\/") + "/" + path
        module_records[module] = (resources[path], logical_path, path.endswith("/__init__.py"))

    class _MemoryLoader(importlib.abc.Loader):
        def __init__(self, name: str) -> None:
            self.name = name

        def create_module(self, spec: object) -> object | None:
            return None

        def exec_module(self, module: object) -> None:
            source, logical_path, is_package = module_records[self.name]
            module.__file__ = logical_path
            module.__loader__ = self
            module.__cached__ = None
            if is_package:
                module.__path__ = [logical_path.rsplit("/", 1)[0]]
            exec(compile(source, logical_path, "exec"), module.__dict__, module.__dict__)

        def get_source(self, fullname: str) -> str:
            return module_records[fullname][0].decode("utf-8")

        def get_data(self, path: str) -> bytes:
            normalized = path.replace("\\", "/")
            prefix = str(identity["path"]).replace("\\", "/").rstrip("/") + "/"
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
            value = resources.get(_safe_member_path(normalized))
            if not isinstance(value, bytes):
                raise OSError("bound runtime resource is not manifested")
            return value

    class _MemoryFinder(importlib.abc.MetaPathFinder):
        def find_spec(
            self,
            fullname: str,
            path: object = None,
            target: object = None,
        ) -> object:
            if fullname == "supervisor_core" or fullname.startswith("supervisor_core."):
                if fullname not in module_records:
                    raise ModuleNotFoundError(
                        f"bound runtime module is not manifested: {fullname}"
                    )
                is_package = module_records[fullname][2]
                return importlib.util.spec_from_loader(
                    fullname,
                    _MemoryLoader(fullname),
                    is_package=is_package,
                )
            return None

    for name in tuple(sys.modules):
        if name == "supervisor_core" or name.startswith("supervisor_core."):
            sys.modules.pop(name, None)
    finder = _MemoryFinder()
    runtime = types.ModuleType("_agent_supervisor_bound_runtime")
    runtime.contract = _BOUND_RUNTIME_CONTRACT
    runtime.core_root = identity["path"]
    runtime.identity = dict(identity)
    runtime.manifest = dict(manifest)
    runtime.resources = dict(resources)
    runtime.finder = finder
    sys.modules[runtime.__name__] = runtime
    sys.meta_path.insert(0, finder)


def _already_bound() -> bool:
    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
    return bool(
        runtime is not None
        and getattr(runtime, "contract", None) == _BOUND_RUNTIME_CONTRACT
        and isinstance(getattr(runtime, "core_root", None), str)
        and Path(runtime.core_root).is_absolute()
        and isinstance(getattr(runtime, "resources", None), dict)
    )


def _bind_active_runtime() -> None:
    pointer_path, pointer_root, release_root = _install_layout()
    pointer = _json_object(_stable_read(pointer_path, _MAX_POINTER_BYTES), "active-pointer")
    if set(pointer) != _POINTER_FIELDS or pointer.get("contract") != _POINTER_CONTRACT:
        raise _BootstrapError("active-pointer-v4-required")
    active, _, active_bundle_path = _identity_paths(
        pointer.get("active"),
        (pointer_root, release_root),
    )
    active_bundle = _stable_read(active_bundle_path, _MAX_BUNDLE_BYTES)
    resources, manifest = _inspect_bundle(active, active_bundle)

    # A corrupt rollback target invalidates the exact v4 pointer, even though only
    # the active snapshot is installed in this process.
    previous = pointer.get("previous")
    if previous is not None:
        previous_identity, _, previous_bundle_path = _identity_paths(
            previous,
            (pointer_root, release_root),
        )
        previous_bundle = _stable_read(previous_bundle_path, _MAX_BUNDLE_BYTES)
        _inspect_bundle(previous_identity, previous_bundle)
    _install_memory_importer(active, resources, manifest)


def _run() -> int:
    try:
        if not _already_bound():
            _bind_active_runtime()
        from supervisor_core.cli import main

        return int(main())
    except (
        _BootstrapError,
        AttributeError,
        ImportError,
        KeyError,
        OSError,
        RuntimeError,
        SyntaxError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        return 64


raise SystemExit(_run())
