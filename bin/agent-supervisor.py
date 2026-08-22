from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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


try:
    pointer_path: Path | None = rollout_active_pointer_path(ROOT)
except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
    pointer_path = None


def trusted_active_root(pointer: object) -> Path | None:
    if not isinstance(pointer, dict) or pointer.get("contract") != "ActiveVersionPointer/v3":
        return None
    active = pointer.get("active")
    if not isinstance(active, dict):
        return None
    version = active.get("version")
    raw_path = active.get("path")
    if not isinstance(version, str) or not version.strip() or not isinstance(raw_path, str) or not raw_path.strip():
        return None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    configured_release_root = os.environ.get("AGENT_SUPERVISOR_RELEASE_ROOT")
    try:
        allowed_roots = [ROOT.resolve(), (ROOT.parent / ".agent-supervisor-releases").resolve()]
    except (OSError, RuntimeError):
        return None
    if configured_release_root:
        configured = Path(configured_release_root).expanduser()
        if configured.is_absolute():
            try:
                allowed_roots.append(configured.resolve())
            except (OSError, RuntimeError):
                return None
    if not any(resolved == allowed or resolved.is_relative_to(allowed) for allowed in allowed_roots):
        return None
    if resolved.is_symlink() or not (resolved / "supervisor_core" / "__init__.py").is_file():
        return None
    return resolved


if pointer_path is not None:
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
