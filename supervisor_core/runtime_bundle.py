from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any
import zipfile


MANIFEST_MEMBER = "SUPERVISOR-RUNTIME-MANIFEST.json"
MANIFEST_CONTRACT = "SupervisorRuntimeManifest/v1"
IDENTITY_CONTRACT = "SupervisorReleaseIdentity/v1"
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 512
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RuntimeBundleError(ValueError):
    """The selected runtime bundle is malformed or does not match its identity."""


def bound_resource_bytes(path: str) -> bytes | None:
    """Return an immutable stage-0 resource, or None in a loose developer run."""
    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
    if runtime is None or getattr(runtime, "contract", None) != "SupervisorBoundRuntime/v1":
        return None
    resources = getattr(runtime, "resources", None)
    if not isinstance(resources, dict):
        raise RuntimeBundleError("bound-resource-map-invalid")
    value = resources.get(_safe_relative_path(path).as_posix())
    if not isinstance(value, bytes):
        raise RuntimeBundleError("bound-resource-missing")
    return value


def bound_resource_map() -> dict[str, bytes] | None:
    """Return a copy of the complete immutable stage-0 resource map."""
    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
    if runtime is None or getattr(runtime, "contract", None) != "SupervisorBoundRuntime/v1":
        return None
    resources = getattr(runtime, "resources", None)
    if (
        not isinstance(resources, dict)
        or not resources
        or any(
            not isinstance(name, str)
            or not isinstance(content, bytes)
            or _safe_relative_path(name).as_posix() != name
            for name, content in resources.items()
        )
    ):
        raise RuntimeBundleError("bound-resource-map-invalid")
    return dict(resources)


def bound_release_identity() -> dict[str, Any] | None:
    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
    if runtime is None or getattr(runtime, "contract", None) != "SupervisorBoundRuntime/v1":
        return None
    identity = getattr(runtime, "identity", None)
    if not isinstance(identity, dict):
        raise RuntimeBundleError("bound-release-identity-invalid")
    return dict(identity)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeBundleError("duplicate-json-key")
        value[key] = item
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RuntimeBundleError("invalid-member-path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeBundleError("invalid-member-path")
    return path


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _read_stable_file(root: Path, relative: PurePosixPath) -> bytes:
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in (None, *relative.parts):
        if part is not None:
            current /= part
        if _is_link_or_reparse(current):
            raise RuntimeBundleError("source-link-or-reparse")
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise RuntimeBundleError("source-root-escape") from exc
    before = resolved.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > MAX_MEMBER_BYTES:
        raise RuntimeBundleError("invalid-source-file")
    with resolved.open("rb") as handle:
        content = handle.read(MAX_MEMBER_BYTES + 1)
    after = resolved.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or len(content) != before.st_size:
        raise RuntimeBundleError("source-changed-during-read")
    return content


def _runtime_paths(root: Path) -> list[PurePosixPath]:
    paths = {
        PurePosixPath(relative)
        for relative in (
            "VERSION",
            ".gitignore",
            "README.md",
            "pyproject.toml",
            "bin/agent-supervisor.py",
            "bin/build-core-release-manifest.py",
            "bin/run-coderabbit-review.py",
        )
        if root.joinpath(*PurePosixPath(relative).parts).is_file()
    }
    package = root / "supervisor_core"
    for candidate in package.rglob("*"):
        if not candidate.is_file() or _is_link_or_reparse(candidate):
            continue
        relative = PurePosixPath(candidate.relative_to(root).as_posix())
        if relative.suffix in {".py", ".json"} and "__pycache__" not in relative.parts:
            paths.add(relative)
    schema_root = root / "schemas"
    if schema_root.is_dir() and not _is_link_or_reparse(schema_root):
        for candidate in schema_root.rglob("*.json"):
            if candidate.is_file() and not _is_link_or_reparse(candidate):
                paths.add(PurePosixPath(candidate.relative_to(root).as_posix()))
    tests_root = root / "tests"
    if tests_root.is_dir() and not _is_link_or_reparse(tests_root):
        for candidate in tests_root.rglob("*.py"):
            if (
                candidate.is_file()
                and not _is_link_or_reparse(candidate)
                and "__pycache__" not in candidate.parts
            ):
                paths.add(PurePosixPath(candidate.relative_to(root).as_posix()))
    return sorted(paths, key=lambda item: item.as_posix())


def _member_kind(path: PurePosixPath) -> tuple[str, str | None]:
    value = path.as_posix()
    if value == "bin/agent-supervisor.py":
        return "launcher", None
    if value == "bin/run-coderabbit-review.py":
        return "review-runner", None
    if value == "VERSION":
        return "version", None
    if path.parts[0] == "supervisor_core" and path.suffix == ".py":
        module_parts = list(path.with_suffix("").parts)
        if module_parts[-1] == "__init__":
            module_parts.pop()
        return "python-module", ".".join(module_parts)
    return "resource", None


def build_runtime_bundle(root: Path, version: str) -> bytes:
    root = Path(root).expanduser()
    if not root.is_absolute() or not version or not isinstance(version, str):
        raise RuntimeBundleError("invalid-build-input")
    root = root.resolve(strict=True)
    if _is_link_or_reparse(root):
        raise RuntimeBundleError("source-root-link-or-reparse")

    files: list[dict[str, Any]] = []
    contents: dict[str, bytes] = {}
    casefolded: set[str] = set()
    total = 0
    for relative in _runtime_paths(root):
        path = _safe_relative_path(relative.as_posix())
        folded = path.as_posix().casefold()
        if folded in casefolded:
            raise RuntimeBundleError("duplicate-casefold-member")
        casefolded.add(folded)
        content = _read_stable_file(root, path)
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise RuntimeBundleError("runtime-source-too-large")
        kind, module = _member_kind(path)
        row: dict[str, Any] = {
            "kind": kind,
            "module": module,
            "path": path.as_posix(),
            "sha256": _sha256(content),
            "size": len(content),
        }
        files.append(row)
        contents[path.as_posix()] = content

    if not files or not any(row.get("module") == "supervisor_core" for row in files):
        raise RuntimeBundleError("runtime-package-missing")
    source_tree_sha256 = _sha256(_canonical_json_bytes(files))
    manifest = {
        "contract": MANIFEST_CONTRACT,
        "files": files,
        "source_tree_sha256": source_tree_sha256,
        "version": version,
    }
    manifest_bytes = _canonical_json_bytes(manifest)

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in [(MANIFEST_MEMBER, manifest_bytes), *sorted(contents.items())]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.flag_bits |= 0x800
            archive.writestr(info, content)
    bundle = output.getvalue()
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise RuntimeBundleError("runtime-bundle-too-large")
    return bundle


def inspect_runtime_bundle(
    blob: bytes,
    expected_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(blob, bytes) or not blob or len(blob) > MAX_BUNDLE_BYTES:
        raise RuntimeBundleError("invalid-bundle-size")
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeBundleError("invalid-zip") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise RuntimeBundleError("invalid-member-count")
        names: list[str] = []
        folded: set[str] = set()
        total = 0
        for info in infos:
            path = _safe_relative_path(info.filename)
            name = path.as_posix()
            lowered = name.casefold()
            if lowered in folded or info.is_dir():
                raise RuntimeBundleError("duplicate-or-directory-member")
            folded.add(lowered)
            names.append(name)
            if info.flag_bits & 0x1 or info.compress_type != zipfile.ZIP_STORED:
                raise RuntimeBundleError("unsupported-member-encoding")
            if info.file_size < 1 or info.file_size > MAX_MEMBER_BYTES:
                raise RuntimeBundleError("invalid-member-size")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise RuntimeBundleError("expanded-bundle-too-large")
        if MANIFEST_MEMBER not in names:
            raise RuntimeBundleError("manifest-missing")
        manifest_bytes = archive.read(MANIFEST_MEMBER)
        try:
            manifest = json.loads(
                manifest_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeBundleError("manifest-json-invalid") from exc
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"contract", "files", "source_tree_sha256", "version"}
            or manifest.get("contract") != MANIFEST_CONTRACT
            or manifest_bytes != _canonical_json_bytes(manifest)
            or not isinstance(manifest.get("version"), str)
            or not manifest["version"]
            or not _SHA256.fullmatch(str(manifest.get("source_tree_sha256") or ""))
            or not isinstance(manifest.get("files"), list)
        ):
            raise RuntimeBundleError("manifest-contract-invalid")

        rows: list[dict[str, Any]] = []
        row_names: list[str] = []
        members: dict[str, bytes] = {}
        modules: set[str] = set()
        for row in manifest["files"]:
            if not isinstance(row, dict) or set(row) != {
                "kind", "module", "path", "sha256", "size",
            }:
                raise RuntimeBundleError("manifest-row-invalid")
            path = _safe_relative_path(row.get("path"))
            name = path.as_posix()
            if name == MANIFEST_MEMBER:
                raise RuntimeBundleError("manifest-self-row-forbidden")
            module = row.get("module")
            if (
                not isinstance(row.get("kind"), str)
                or not isinstance(row.get("size"), int)
                or row["size"] < 1
                or not _SHA256.fullmatch(str(row.get("sha256") or ""))
                or (
                    module is not None
                    and (
                        not isinstance(module, str)
                        or not (
                            module == "supervisor_core"
                            or module.startswith("supervisor_core.")
                        )
                        or module in modules
                    )
                )
            ):
                raise RuntimeBundleError("manifest-row-invalid")
            if isinstance(module, str):
                modules.add(module)
            try:
                content = archive.read(name)
            except KeyError as exc:
                raise RuntimeBundleError("manifest-member-missing") from exc
            if len(content) != row["size"] or _sha256(content) != row["sha256"]:
                raise RuntimeBundleError("member-digest-mismatch")
            rows.append(row)
            row_names.append(name)
            members[name] = content
        if row_names != sorted(row_names) or len({name.casefold() for name in row_names}) != len(row_names):
            raise RuntimeBundleError("manifest-order-or-duplicate-invalid")
        if set(names) != {MANIFEST_MEMBER, *row_names}:
            raise RuntimeBundleError("unmanifested-member")
        if _sha256(_canonical_json_bytes(rows)) != manifest["source_tree_sha256"]:
            raise RuntimeBundleError("source-tree-digest-mismatch")
        if "supervisor_core" not in modules:
            raise RuntimeBundleError("runtime-package-missing")

    manifest_sha256 = _sha256(manifest_bytes)
    bundle_sha256 = _sha256(blob)
    if expected_identity is not None:
        required = {
            "contract", "version", "path", "bundle_relpath", "bundle_sha256",
            "manifest_sha256", "source_tree_sha256",
        }
        if (
            not isinstance(expected_identity, dict)
            or set(expected_identity) != required
            or expected_identity.get("contract") != IDENTITY_CONTRACT
            or expected_identity.get("version") != manifest["version"]
            or expected_identity.get("bundle_sha256") != bundle_sha256
            or expected_identity.get("manifest_sha256") != manifest_sha256
            or expected_identity.get("source_tree_sha256") != manifest["source_tree_sha256"]
        ):
            raise RuntimeBundleError("release-identity-mismatch")
    return {
        "bundle_sha256": bundle_sha256,
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "members": members,
        "source_tree_sha256": manifest["source_tree_sha256"],
    }


def release_identity(root: Path, version: str, bundle_relpath: str, bundle: bytes) -> dict[str, str]:
    inspected = inspect_runtime_bundle(bundle)
    relative = _safe_relative_path(bundle_relpath).as_posix()
    return {
        "bundle_relpath": relative,
        "bundle_sha256": inspected["bundle_sha256"],
        "contract": IDENTITY_CONTRACT,
        "manifest_sha256": inspected["manifest_sha256"],
        "path": str(Path(root).resolve(strict=True)),
        "source_tree_sha256": inspected["source_tree_sha256"],
        "version": version,
    }
