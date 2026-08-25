#!/usr/bin/env python3
"""No-paid Claude adapter + shared Supervisor v3 self-test."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TESTS = ROOT / "tests"
ADAPTER = HERE / "sup-v3-hook.py"
CONFIGURE = HERE / "configure-v3-hooks.py"
DISCOVER = HERE / "sup-discover.py"
HOME = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or Path.home())
SETTINGS = HOME / ".claude" / "settings.json"
EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SubagentStart",
    "SubagentStop",
}
REQUIRED_LEGACY_SUITES = (
    "test_dispatch_ledger.py",
    "test_precision.py",
    "test_retrieval.py",
    "test_verifier.py",
)
FIXED_CHECKS = (
    "active core identity",
    "settings hook registration",
    "sup-discover import",
    "Claude adapter harness",
    "shared core selftest",
    "pytest collection",
)
SELFTEST_TIMEOUT_SECONDS = 600
UNMEASURABLE_EXIT = 77


def _expected_check_count() -> int:
    return len(FIXED_CHECKS) + len(REQUIRED_LEGACY_SUITES)


def _load_adapter_module():
    spec = importlib.util.spec_from_file_location("supervisor_v3_selftest_hook", ADAPTER)
    if spec is None or spec.loader is None:
        raise RuntimeError("adapter_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resolve_test_core() -> tuple[Path, str, dict[str, str]]:
    """Resolve exactly the fully verified pointer-v4 bundle the hook trusts."""
    adapter = _load_adapter_module()
    core, identity = adapter._resolve_active_pointer_selection()
    if identity.get("source") != "active-pointer-v4-bundle":
        raise RuntimeError("active_pointer_not_selected")
    version = identity.get("declared_version", "")
    if not version:
        raise RuntimeError("active_pointer_version_missing")
    declared_path = Path(identity.get("declared_path", ""))
    if not declared_path.is_absolute() or declared_path.resolve(strict=True) != core:
        raise RuntimeError("active_pointer_path_mismatch")
    for name in ("bundle_sha256", "manifest_sha256", "source_tree_sha256"):
        value = identity.get(name, "")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise RuntimeError("active_pointer_identity_incomplete")
    return core, version, identity


def _freeze_test_runtime(expected_identity: dict[str, str]) -> dict[str, Any]:
    """Freeze the verified bundle again and bind it to the resolved identity."""
    adapter = _load_adapter_module()
    frozen = adapter._load_active_runtime()
    identity = frozen["identity"]
    expected = {
        "declared_path": identity["path"],
        "declared_version": identity["version"],
        "bundle_sha256": identity["bundle_sha256"],
        "manifest_sha256": identity["manifest_sha256"],
        "source_tree_sha256": identity["source_tree_sha256"],
    }
    if any(expected_identity.get(key) != value for key, value in expected.items()):
        raise RuntimeError("active_pointer_changed_before_selftest")
    return frozen


def _materialize_test_core(frozen: dict[str, Any], destination: Path) -> Path:
    """Create a private test-only tree solely from the verified frozen bundle bytes."""
    root = destination / "runtime"
    root.mkdir(mode=0o700)
    if os.name == "posix":
        root.chmod(0o700)
    manifest = frozen["manifest"]
    identity = frozen["identity"]
    try:
        archive = zipfile.ZipFile(io.BytesIO(frozen["bundle"]), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError("frozen_bundle_invalid") from exc
    with archive:
        manifest_bytes = archive.read("SUPERVISOR-RUNTIME-MANIFEST.json")
        if hashlib.sha256(manifest_bytes).hexdigest() != identity["manifest_sha256"]:
            raise RuntimeError("frozen_manifest_changed")
        entries: list[tuple[str, bytes]] = [
            ("SUPERVISOR-RUNTIME-MANIFEST.json", manifest_bytes)
        ]
        for row in manifest["files"]:
            name = row["path"]
            relative = PurePosixPath(name)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise RuntimeError("frozen_member_path_invalid")
            content = archive.read(name)
            if (
                len(content) != row["size"]
                or hashlib.sha256(content).hexdigest() != row["sha256"]
            ):
                raise RuntimeError("frozen_member_changed")
            entries.append((name, content))

    for name, content in entries:
        relative = PurePosixPath(name)
        target = root.joinpath(*relative.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix":
            target.parent.chmod(0o700)
        descriptor = os.open(
            target,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return root


def _run(
    label: str,
    command: list[str],
    env: dict[str, str],
    *,
    core: Path,
) -> tuple[bool, str]:
    """Run a child from the already-validated active core, never ambient cwd."""
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=core,
            timeout=SELFTEST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"FAIL {label} — timed out after {SELFTEST_TIMEOUT_SECONDS}s")
        return False, ""
    text = proc.stdout.decode("utf-8", "replace")
    tail = " | ".join(line.strip() for line in text.splitlines()[-4:] if line.strip())
    if proc.returncode == UNMEASURABLE_EXIT:
        print(
            "UNAVAILABLE " + label + f" (exit={UNMEASURABLE_EXIT})"
            + (f" — {tail[:800]}" if tail else "")
        )
        return False, text
    ok = proc.returncode == 0
    print(("PASS " if ok else "FAIL ") + label + f" (exit={proc.returncode})" + (f" — {tail[:800]}" if tail else ""))
    return ok, text


def _normalized_absolute(value: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(value)))


def _supervisor_status(entry: Any, expected_event: str) -> tuple[bool, bool]:
    """Validate the current isolated registration, not merely migration ownership."""
    try:
        spec = importlib.util.spec_from_file_location(
            "supervisor_v3_selftest_configure",
            CONFIGURE,
        )
        if spec is None or spec.loader is None:
            return False
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tokens = module._direct_command_tokens(entry.get("command"))
        owned = bool(module.is_supervisor_hook(entry))
        current = bool(
            owned
            and isinstance(tokens, list)
            and len(tokens) == 6
            and tokens[1:3] == ["-I", "-S"]
            and _normalized_absolute(tokens[0]) == _normalized_absolute(sys.executable)
            and _normalized_absolute(tokens[3]) == _normalized_absolute(str(ADAPTER))
            and tokens[4:] == ["--event", expected_event]
            and entry.get("timeout") == 10
        )
        return owned, current
    except (AttributeError, OSError, TypeError, ValueError):
        return False, False


def _settings_check() -> bool:
    try:
        settings = json.loads(SETTINGS.read_text(encoding="utf-8-sig"))
        if not isinstance(settings, dict) or not isinstance(settings.get("hooks"), dict):
            raise TypeError("invalid_hooks")
        hooks = settings["hooks"]
        counts = {}
        owned_counts = {}
        for event in EVENTS:
            count = 0
            owned_count = 0
            groups = hooks.get(event, [])
            if not isinstance(groups, list):
                raise TypeError("invalid_hooks")
            for group in groups:
                if not isinstance(group, dict):
                    continue
                entries = group.get("hooks", [])
                if not isinstance(entries, list):
                    raise TypeError("invalid_hooks")
                for entry in entries:
                    owned, current = _supervisor_status(entry, event)
                    owned_count += int(owned)
                    count += int(current and group.get("matcher") == "*")
            counts[event] = count
            owned_counts[event] = owned_count
        ok = (
            all(counts[event] == 1 and owned_counts[event] == 1 for event in EVENTS)
            and ADAPTER.exists()
        )
    except (OSError, UnicodeError, KeyError, TypeError, json.JSONDecodeError):
        ok, counts = False, {}
    print(("PASS " if ok else "FAIL ") + "settings hook topology" + f" — events={len(counts)}, exactly_one={ok}")
    return ok


def _discover_import_check() -> bool:
    try:
        spec = importlib.util.spec_from_file_location("supervisor_discover_import_probe", DISCOVER)
        if spec is None or spec.loader is None:
            raise RuntimeError("no_loader")
        module = importlib.util.module_from_spec(spec)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            spec.loader.exec_module(module)
        ok = stdout.getvalue() == "" and stderr.getvalue() == ""
    except Exception:
        ok = False
    print(("PASS " if ok else "FAIL ") + "sup-discover import has no side effects")
    return ok


def _run_checks(
    core: Path,
    core_version: str,
    core_identity: dict[str, str],
) -> int:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(core)
    env["AGENT_SUPERVISOR_CORE"] = str(core)
    env["PYTHONIOENCODING"] = "utf-8"

    checks: list[bool] = []
    checks.append(ADAPTER.exists() and DISCOVER.exists() and core.exists())
    print(
        ("PASS " if checks[-1] else "FAIL ")
        + "active core identity"
        + f" — source={core_identity['source']}, version={core_version}, frozen_bundle=True"
    )
    checks.append(_settings_check())
    checks.append(_discover_import_check())

    ok, _ = _run(
        "Claude adapter harness",
        [sys.executable, "-m", "unittest", "discover", "-s", str(TESTS), "-p", "test_v3_adapter.py", "-v"],
        env,
        core=core,
    )
    checks.append(ok)

    # Legacy suites remain executable historical regressions. Run every one as a
    # child process because importing them calls sys.exit during pytest collection.
    for suite in REQUIRED_LEGACY_SUITES:
        suite_path = TESTS / suite
        if not suite_path.is_file():
            print("FAIL legacy regression " + suite + " — required suite is missing")
            checks.append(False)
            continue
        ok, _ = _run(
            "legacy regression " + suite,
            [sys.executable, str(suite_path)],
            env,
            core=core,
        )
        checks.append(ok)

    ok, _ = _run(
        "shared core selftest",
        [sys.executable, "-m", "supervisor_core", "selftest"],
        env,
        core=core,
    )
    checks.append(ok)

    ok, _ = _run(
        "pytest collection",
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--rootdir",
            str(TESTS),
            str(TESTS),
        ],
        env,
        core=core,
    )
    checks.append(ok)

    passed = sum(checks)
    print(f"RESULT passed={passed} failed={len(checks) - passed}")
    return 0 if all(checks) else 1


def main() -> int:
    print("Supervisor v3 Claude adapter selftest " + datetime.now(timezone.utc).isoformat())
    try:
        _declared_core, core_version, core_identity = _resolve_test_core()
        frozen = _freeze_test_runtime(core_identity)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-frozen-selftest-") as temp:
            core = _materialize_test_core(frozen, Path(temp))
            return _run_checks(core, core_version, core_identity)
    except Exception:
        print("FAIL active core identity — reason_category=active_core_rejected")
        print(f"RESULT passed=0 failed={_expected_check_count()}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
