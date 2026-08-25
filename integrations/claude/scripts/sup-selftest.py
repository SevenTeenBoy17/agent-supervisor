#!/usr/bin/env python3
"""No-paid Claude adapter + shared Supervisor v3 self-test."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TESTS = ROOT / "tests"
ADAPTER = HERE / "sup-v3-hook.py"
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
    """Resolve exactly the active pointer that a non-overridden hook would trust."""
    adapter = _load_adapter_module()
    core, identity = adapter._resolve_active_pointer_selection()
    version_file = adapter._canonical_existing(core / "VERSION", directory=False)
    if version_file is None or not adapter._within(version_file, core):
        raise RuntimeError("core_version_rejected")
    try:
        version = version_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("core_version_unreadable") from exc
    if not version:
        raise RuntimeError("core_version_empty")
    if identity.get("source") != "active-pointer":
        raise RuntimeError("active_pointer_not_selected")
    if identity.get("declared_version") != version:
        raise RuntimeError("active_pointer_version_mismatch")
    declared_path = Path(identity.get("declared_path", ""))
    declared_core = adapter._trusted_core(declared_path, [core]) if declared_path.is_absolute() else None
    if declared_core != core:
        raise RuntimeError("active_pointer_path_mismatch")
    return core, version, identity


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


def _is_supervisor(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    command = str(entry.get("command", "")).replace("\\", "/").lower()
    return "sup-v3-hook.py" in command


def _settings_check() -> bool:
    try:
        settings = json.loads(SETTINGS.read_text(encoding="utf-8-sig"))
        if not isinstance(settings, dict) or not isinstance(settings.get("hooks"), dict):
            raise TypeError("invalid_hooks")
        hooks = settings["hooks"]
        counts = {}
        for event in EVENTS:
            count = 0
            groups = hooks.get(event, [])
            if not isinstance(groups, list):
                raise TypeError("invalid_hooks")
            for group in groups:
                for entry in group.get("hooks", []) if isinstance(group, dict) else []:
                    count += int(_is_supervisor(entry))
            counts[event] = count
        ok = all(counts[event] == 1 for event in EVENTS) and ADAPTER.exists()
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


def main() -> int:
    print("Supervisor v3 Claude adapter selftest " + datetime.now(timezone.utc).isoformat())
    try:
        core, core_version, core_identity = _resolve_test_core()
    except Exception:
        print("FAIL active core identity — reason_category=active_core_rejected")
        print(f"RESULT passed=0 failed={_expected_check_count()}")
        return 1

    env = dict(os.environ)
    old_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(core) + (os.pathsep + old_pythonpath if old_pythonpath else "")
    env["AGENT_SUPERVISOR_CORE"] = str(core)
    env["PYTHONIOENCODING"] = "utf-8"

    checks: list[bool] = []
    checks.append(ADAPTER.exists() and DISCOVER.exists() and core.exists())
    print(
        ("PASS " if checks[-1] else "FAIL ")
        + "active core identity"
        + f" — source={core_identity['source']}, version={core_version}, path={core}"
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


if __name__ == "__main__":
    raise SystemExit(main())
