from __future__ import annotations

import importlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_BOUND_IDENTITY_FIELDS = frozenset({
    "bundle_relpath",
    "bundle_sha256",
    "contract",
    "manifest_sha256",
    "path",
    "source_tree_sha256",
    "version",
})


def bound_core_root() -> Path | None:
    """Use only the stage-0 object installed after Job/bundle verification."""
    runtime = sys.modules.get("_agent_supervisor_bound_runtime")
    if (
        runtime is None
        or getattr(runtime, "contract", None) != "SupervisorBoundRuntime/v1"
        or not isinstance(getattr(runtime, "core_root", None), str)
    ):
        return None
    candidate = Path(runtime.core_root)
    return candidate if candidate.is_absolute() else None


def rollout_active_pointer_path(root: Path) -> Path:
    """Call the shared rollout helper without occupying its public package name."""
    package_name = f"_agent_supervisor_bootstrap_{os.getpid()}_{id(root)}"
    package_path = root / "supervisor_core"
    package_spec = importlib.util.spec_from_file_location(
        package_name,
        package_path / "__init__.py",
        submodule_search_locations=[str(package_path)],
    )
    if package_spec is None or package_spec.loader is None:
        raise ImportError("supervisor core bootstrap unavailable")
    package = importlib.util.module_from_spec(package_spec)
    sys.modules[package_name] = package
    try:
        package_spec.loader.exec_module(package)
        rollout = importlib.import_module(f"{package_name}.rollout")
        pointer_path = rollout.active_pointer_path()
        if not isinstance(pointer_path, Path):
            raise TypeError("rollout pointer path must be a Path")
        return pointer_path
    finally:
        for module_name in tuple(sys.modules):
            if module_name == package_name or module_name.startswith(f"{package_name}."):
                sys.modules.pop(module_name, None)


BOUND_ROOT = bound_core_root()
if BOUND_ROOT is None:
    try:
        pointer_path: Path | None = rollout_active_pointer_path(ROOT)
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        pointer_path = None
else:
    ROOT = BOUND_ROOT
    pointer_path = None


def _is_link_or_reparse(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    )


def _has_safe_lexical_path(root: Path, candidate: Path) -> bool:
    if not root.is_absolute() or not candidate.is_absolute():
        return False
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return False
    if any(part in {".", ".."} for part in relative.parts):
        return False
    current = root
    for part in (None, *relative.parts):
        if part is not None:
            current /= part
        if _is_link_or_reparse(current):
            return False
    return True


def trusted_active_root(pointer: object) -> Path | None:
    if not isinstance(pointer, dict) or pointer.get("contract") not in {
        "ActiveVersionPointer/v3",
        "ActiveVersionPointer/v4",
    }:
        return None
    active = pointer.get("active")
    if not isinstance(active, dict):
        return None
    if pointer.get("contract") == "ActiveVersionPointer/v4":
        if active.get("contract") != "SupervisorReleaseIdentity/v1" or set(active) != _BOUND_IDENTITY_FIELDS:
            return None
    version = active.get("version")
    raw_path = active.get("path")
    if not isinstance(version, str) or not version.strip() or not isinstance(raw_path, str) or not raw_path.strip():
        return None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        return None
    configured_release_root = os.environ.get("AGENT_SUPERVISOR_RELEASE_ROOT")
    lexical_roots = [ROOT, ROOT.parent / ".agent-supervisor-releases"]
    if configured_release_root:
        configured = Path(configured_release_root).expanduser()
        if configured.is_absolute():
            lexical_roots.append(configured)
    if not any(_has_safe_lexical_path(root, candidate) for root in lexical_roots):
        return None
    try:
        resolved = candidate.resolve(strict=True)
        allowed_roots = [root.resolve() for root in lexical_roots]
    except (OSError, RuntimeError):
        return None
    if not any(resolved == allowed or resolved.is_relative_to(allowed) for allowed in allowed_roots):
        return None
    if resolved.is_symlink() or not (resolved / "supervisor_core" / "__init__.py").is_file():
        return None
    return resolved


if BOUND_ROOT is None and pointer_path is not None:
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        active = trusted_active_root(pointer)
        if active is not None:
            ROOT = active
    except (OSError, ValueError, TypeError):
        pass
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from supervisor_core.cli import main

raise SystemExit(main())
