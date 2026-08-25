from __future__ import annotations

import ast
import contextlib
import io
import json
import hashlib
import importlib.util
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
ADAPTER = HERE.parent / "scripts" / "sup-v3-hook.py"
SELFTEST = HERE.parent / "scripts" / "sup-selftest.py"
DISCOVER = HERE.parent / "scripts" / "sup-discover.py"
CONFIGURE = HERE.parent / "scripts" / "configure-v3-hooks.py"
PLAN = HERE.parent / "scripts" / "sup-plan.py"
LOG = HERE.parent / "scripts" / "sup-log.py"
CLAUDE_SKILL = HERE.parent / "SKILL.md"
PRECISION = HERE / "test_precision.py"
RETRIEVAL = HERE / "test_retrieval.py"
RUNTIME_BUNDLE = HERE.parents[2] / "supervisor_core" / "runtime_bundle.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_core(root: Path, version: str = "9.9.9") -> None:
    package = root / "supervisor_core"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# bundled fixture\n", encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    (package / "__main__.py").write_text(
        "from .cli import main\nraise SystemExit(main())\n",
        encoding="utf-8",
    )
    (package / "nested").mkdir()
    (package / "nested" / "worker.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "VERSION").write_text(version + "\n", encoding="utf-8")


def stage_runtime_pointer(
    home: Path,
    source_root: Path,
    *,
    version: str = "9.9.9",
    pointer_contract: str = "ActiveVersionPointer/v4",
    declared_version: str | None = None,
) -> tuple[Path, Path, dict[str, str]]:
    runtime_bundle = load_module(
        "supervisor_v3_runtime_bundle_" + hashlib.sha256(str(source_root).encode()).hexdigest()[:12],
        RUNTIME_BUNDLE,
    )
    bundle = runtime_bundle.build_runtime_bundle(source_root.resolve(), version)
    release_root = home / ".agent-supervisor-releases"
    release = release_root / ("v" + version)
    bundle_path = release / "runtime" / "supervisor-runtime.zip"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_bytes(bundle)
    identity = runtime_bundle.release_identity(
        release.resolve(),
        version,
        "runtime/supervisor-runtime.zip",
        bundle,
    )
    if declared_version is not None:
        identity["version"] = declared_version
    pointer = home / ".agent-supervisor" / "active-version.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    pointer.write_bytes(
        json.dumps(
            {
                "contract": pointer_contract,
                "active": identity,
                "previous": None,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return pointer, release_root, identity


class CoreTrustResolver(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="supervisor-v3-trust-")
        self.base = Path(self.temp.name)
        self.home = self.base / "home"
        self.default_core = self.home / ".agent-supervisor"
        self.release_root = self.home / ".agent-supervisor-releases"
        self.release_core = self.release_root / "v9.9.9"
        self.adapter = load_module("supervisor_v3_hook_trust_probe", ADAPTER)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_adapter_and_skill_release_metadata_are_3_1_6(self) -> None:
        match = re.search(r"(?m)^\s*version:\s*([^\s]+)\s*$", CLAUDE_SKILL.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        self.assertEqual(self.adapter.ADAPTER_VERSION, "3.1.6")
        self.assertEqual(match.group(1), self.adapter.ADAPTER_VERSION)

    def _pointer(
        self,
        *,
        contract: str = "ActiveVersionPointer/v4",
        version: str = "9.9.9",
    ) -> Path:
        pointer, _release_root, _identity = stage_runtime_pointer(
            self.home,
            self.release_core,
            version="9.9.9",
            pointer_contract=contract,
            declared_version=version,
        )
        return pointer

    def _resolver_env(self, pointer: Path) -> dict[str, str]:
        return {
            "USERPROFILE": str(self.home),
            "HOME": str(self.home),
            "AGENT_SUPERVISOR_ACTIVE_POINTER": str(pointer),
            "AGENT_SUPERVISOR_RELEASE_ROOT": str(self.release_root),
        }

    def test_recursive_python_tree_requires_main_and_rejects_structural_reparse(self) -> None:
        write_core(self.release_core)
        main_entry = self.release_core / "supervisor_core" / "__main__.py"
        main_entry.unlink()
        self.assertIsNone(self.adapter._trusted_core(self.release_core, [self.release_root]))
        env = dict(os.environ)
        env.update(
            {
                "USERPROFILE": str(self.home),
                "HOME": str(self.home),
                "AGENT_SUPERVISOR_CORE": str(self.release_core),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), "--event", "SessionStart"],
            input=json.dumps({"session_id": "trust-structure", "cwd": str(self.base)}).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")

        main_entry.write_text("raise SystemExit(0)\n", encoding="utf-8")
        nested_source = self.release_core / "supervisor_core" / "nested" / "worker.py"
        original_is_reparse = self.adapter._is_reparse

        def structural_reparse(path: Path) -> bool:
            return path == nested_source or original_is_reparse(path)

        with mock.patch.object(self.adapter, "_is_reparse", side_effect=structural_reparse):
            self.assertIsNone(self.adapter._trusted_core(self.release_core, [self.release_root]))

    def test_non_python_package_entry_is_validated_before_extension_filtering(self) -> None:
        write_core(self.release_core)
        package_entry = self.release_core / "supervisor_core" / "payload.data"
        package_entry.write_text("outside-capable fixture\n", encoding="utf-8")
        original_is_reparse = self.adapter._is_reparse

        def structural_reparse(path: Path) -> bool:
            return path == package_entry or original_is_reparse(path)

        with mock.patch.object(self.adapter, "_is_reparse", side_effect=structural_reparse):
            self.assertIsNone(self.adapter._trusted_core(self.release_core, [self.release_root]))

    def test_recursive_python_symlink_escape_is_rejected_and_hook_fails_open(self) -> None:
        write_core(self.release_core)
        outside = self.base / "outside.py"
        outside.write_text("VALUE = 'outside'\n", encoding="utf-8")
        link = self.release_core / "supervisor_core" / "escaped.py"
        try:
            link.symlink_to(outside)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"symlink unavailable: {exc}")

        self.assertIsNone(self.adapter._trusted_core(self.release_core, [self.release_root]))
        env = dict(os.environ)
        env.update(
            {
                "USERPROFILE": str(self.home),
                "HOME": str(self.home),
                "AGENT_SUPERVISOR_CORE": str(self.release_core),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), "--event", "SessionStart"],
            input=json.dumps({"session_id": "trust-symlink", "cwd": str(self.base)}).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")

    def test_strict_active_pointer_selects_declared_release_and_rejects_invalid_pointer(self) -> None:
        write_core(self.default_core, version="3.1.0")
        write_core(self.release_core)
        pointer = self._pointer()
        env = self._resolver_env(pointer)
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("AGENT_SUPERVISOR_HOME", None)
            os.environ.pop("AGENT_SUPERVISOR_CORE", None)
            resolved, identity = self.adapter._resolve_core_selection(require_active_pointer=True)
        self.assertEqual(resolved, self.release_core.resolve())
        self.assertEqual(identity["source"], "active-pointer-v4-bundle")
        self.assertEqual(identity["declared_version"], "9.9.9")

        bad_pointer = self._pointer(contract="ActiveVersionPointer/v3")
        with mock.patch.dict(os.environ, self._resolver_env(bad_pointer), clear=False):
            os.environ.pop("AGENT_SUPERVISOR_HOME", None)
            os.environ.pop("AGENT_SUPERVISOR_CORE", None)
            with self.assertRaises(FileNotFoundError):
                self.adapter._resolve_core_selection(require_active_pointer=True)
            with self.assertRaises(FileNotFoundError):
                self.adapter._core_root()

    def test_v4_requires_complete_identity_and_matching_bundle_bytes(self) -> None:
        write_core(self.release_core)
        pointer = self._pointer()
        env = self._resolver_env(pointer)

        document = json.loads(pointer.read_text(encoding="utf-8"))
        document["active"].pop("manifest_sha256")
        pointer.write_bytes(
            json.dumps(
                document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        with mock.patch.dict(os.environ, env, clear=False):
            with self.assertRaises(FileNotFoundError):
                self.adapter._load_active_runtime()

        pointer = self._pointer()
        document = json.loads(pointer.read_text(encoding="utf-8"))
        bundle = Path(document["active"]["path"]) / document["active"]["bundle_relpath"]
        bundle.write_bytes(bundle.read_bytes() + b"tampered")
        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            with self.assertRaises(FileNotFoundError):
                self.adapter._load_active_runtime()

    def test_v4_pointer_must_be_canonical_json(self) -> None:
        write_core(self.release_core)
        pointer = self._pointer()
        document = json.loads(pointer.read_text(encoding="utf-8"))
        pointer.write_text(json.dumps(document, indent=2), encoding="utf-8")

        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            with self.assertRaises(FileNotFoundError):
                self.adapter._load_active_runtime()

    @unittest.skipUnless(os.name == "posix", "POSIX inode change-time semantics")
    def test_pointer_hardlink_mutation_cannot_hide_behind_restored_mtime(self) -> None:
        write_core(self.release_core)
        pointer = self._pointer()
        hardlink = pointer.with_name("active-version-hardlink.json")
        os.link(pointer, hardlink)
        original_read = self.adapter.os.read
        mutated = False

        def mutate_after_read(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            content = original_read(descriptor, size)
            if content and not mutated:
                mutated = True
                before = pointer.stat()
                replacement = content.replace(b"9.9.9", b"9.9.8", 1)
                self.assertEqual(len(replacement), len(content))
                hardlink.write_bytes(replacement)
                os.utime(hardlink, ns=(before.st_atime_ns, before.st_mtime_ns))
            return content

        with mock.patch.object(self.adapter.os, "read", side_effect=mutate_after_read):
            with self.assertRaises(self.adapter._BootstrapError):
                self.adapter._stable_read(pointer, self.adapter.MAX_POINTER_BYTES)
        self.assertTrue(mutated)

    def test_selftest_identity_uses_hook_resolver_and_version_mismatch_fails_closed(self) -> None:
        write_core(self.default_core, version="3.1.0")
        write_core(self.release_core)
        pointer = self._pointer()
        selftest = load_module("supervisor_v3_selftest_identity_probe", SELFTEST)
        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            os.environ.pop("AGENT_SUPERVISOR_HOME", None)
            os.environ.pop("AGENT_SUPERVISOR_CORE", None)
            core, version, identity = selftest._resolve_test_core()
        self.assertEqual(core, self.release_core.resolve())
        self.assertEqual(version, "9.9.9")
        self.assertEqual(identity["source"], "active-pointer-v4-bundle")

        self._pointer(version="9.9.8")
        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            os.environ.pop("AGENT_SUPERVISOR_HOME", None)
            os.environ.pop("AGENT_SUPERVISOR_CORE", None)
            with self.assertRaises(FileNotFoundError):
                selftest._resolve_test_core()

        self._pointer()
        (self.release_core / "supervisor_core" / "__main__.py").unlink()
        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            os.environ.pop("AGENT_SUPERVISOR_HOME", None)
            os.environ.pop("AGENT_SUPERVISOR_CORE", None)
            core, version, identity = selftest._resolve_test_core()
        self.assertEqual(core, self.release_core.resolve())
        self.assertEqual(version, "9.9.9")
        self.assertEqual(identity["source"], "active-pointer-v4-bundle")

        bad_pointer = self._pointer(contract="ActiveVersionPointer/v3")
        env = dict(os.environ)
        env.update(self._resolver_env(bad_pointer))
        env.pop("AGENT_SUPERVISOR_HOME", None)
        env.pop("AGENT_SUPERVISOR_CORE", None)
        proc = subprocess.run(
            [sys.executable, str(SELFTEST)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        expected_checks = selftest._expected_check_count()
        self.assertIn(f"RESULT passed=0 failed={expected_checks}".encode("ascii"), proc.stdout)
        self.assertEqual(proc.stderr, b"")

    def test_selftest_materializes_only_frozen_bundle_bytes(self) -> None:
        write_core(self.release_core)
        pointer = self._pointer()
        selftest = load_module("supervisor_v3_selftest_frozen_tree_probe", SELFTEST)
        with mock.patch.dict(os.environ, self._resolver_env(pointer), clear=False):
            _core, _version, identity = selftest._resolve_test_core()
            frozen = selftest._freeze_test_runtime(identity)
        original_cli = (self.release_core / "supervisor_core" / "cli.py").read_bytes()
        (self.release_core / "supervisor_core" / "cli.py").write_text(
            "raise RuntimeError('mutable source executed')\n", encoding="utf-8"
        )

        with tempfile.TemporaryDirectory(prefix="supervisor-v3-frozen-tree-") as temp:
            materialized = selftest._materialize_test_core(frozen, Path(temp))
            self.assertEqual(
                (materialized / "supervisor_core" / "cli.py").read_bytes(),
                original_cli,
            )

    def test_selftest_early_failure_count_tracks_required_suite_count(self) -> None:
        selftest = load_module("supervisor_v3_selftest_count_probe", SELFTEST)
        required = ("one.py", "two.py", "three.py", "four.py", "five.py")
        output = io.StringIO()
        with mock.patch.object(selftest, "REQUIRED_LEGACY_SUITES", required):
            calculated_checks = selftest._expected_check_count()
            with mock.patch.object(selftest, "_resolve_test_core", side_effect=RuntimeError("rejected")):
                with contextlib.redirect_stdout(output):
                    rc = selftest.main()

        expected_checks = 6 + len(required)
        self.assertEqual(calculated_checks, expected_checks)
        self.assertEqual(rc, 1)
        self.assertIn(f"RESULT passed=0 failed={expected_checks}", output.getvalue())


class DiscoverySnapshot(unittest.TestCase):
    def test_parse_captures_mtime_from_open_descriptor_without_path_stat(self) -> None:
        discover = load_module("supervisor_v3_discover_snapshot_probe", DISCOVER)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-discover-") as temp:
            skill = Path(temp) / "SKILL.md"
            skill.write_text(
                "---\nname: descriptor-skill\ndescription: descriptor snapshot\n---\n",
                encoding="utf-8",
            )
            with mock.patch.object(Path, "stat", side_effect=AssertionError("path stat is forbidden")):
                record = discover._parse_record(skill)
                parsed = discover.parse(skill)
        self.assertIsNotNone(record)
        self.assertEqual(record[:2], ("descriptor-skill", "descriptor snapshot"))
        self.assertIsInstance(record[2], float)
        self.assertEqual(parsed, ("descriptor-skill", "descriptor snapshot"))

    def test_all_separates_callable_skills_from_uninstalled_marketplace_entries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-discover-all-") as temp:
            home = Path(temp) / "home"
            personal = home / ".claude" / "skills" / "personal-skill" / "SKILL.md"
            installed = (
                home / ".claude" / "plugins" / "cache" / "market" / "enabled-plugin"
                / "1.0" / "skills" / "installed-skill" / "SKILL.md"
            )
            marketplace = (
                home / ".claude" / "plugins" / "marketplaces" / "market" / "plugins"
                / "catalog-only" / "skills" / "market-only" / "SKILL.md"
            )
            for path, name in (
                (personal, "personal-skill"),
                (installed, "installed-skill"),
                (marketplace, "market-only"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f"---\nname: {name}\ndescription: fixture {name}\n---\n",
                    encoding="utf-8",
                )
            settings = home / ".claude" / "settings.json"
            settings.write_text(
                json.dumps({"enabledPlugins": {"enabled-plugin@market": True}}),
                encoding="utf-8",
            )
            with mock.patch.object(Path, "home", return_value=home):
                discover = load_module("supervisor_v3_discover_all_probe", DISCOVER)

            inventory = discover.collect(include_uninstalled=True)
            unavailable = inventory["catalog-only:market-only"]
            self.assertFalse(unavailable["installed"])
            self.assertFalse(unavailable["callable"])
            self.assertFalse(unavailable["routable"])
            self.assertEqual(unavailable["availability_reason"], "marketplace_not_installed")

            output = io.StringIO()
            with mock.patch.object(discover.sys, "argv", [str(DISCOVER), "--all"]):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(discover.main(), 0)
            rendered = output.getvalue()
            self.assertIn("可调用 skill 合计 2 个", rendered)
            self.assertIn("Marketplace 未安装/不可用] 1", rendered)
            self.assertIn("catalog-only:market-only", rendered)
            self.assertIn("marketplace_not_installed", rendered)

            output = io.StringIO()
            with mock.patch.object(
                discover.sys, "argv", [str(DISCOVER), "--all", "market-only"]
            ):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(discover.main(), 0)
            rendered = output.getvalue()
            self.assertIn("可调用匹配 0", rendered)
            self.assertIn("不可用匹配 1", rendered)

    def test_personal_call_uses_directory_name_while_plugin_keeps_declared_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-discover-canonical-") as temp:
            home = Path(temp) / "home"
            personal = home / ".claude" / "skills" / "trusted-directory-name" / "SKILL.md"
            plugin = (
                home / ".claude" / "plugins" / "cache" / "market" / "enabled-plugin"
                / "1.0" / "skills" / "plugin-directory-name" / "SKILL.md"
            )
            personal.parent.mkdir(parents=True, exist_ok=True)
            plugin.parent.mkdir(parents=True, exist_ok=True)
            personal.write_text(
                "---\nname: forged-personal-alias\ndescription: personal fixture\n---\n",
                encoding="utf-8",
            )
            plugin.write_text(
                "---\nname: declared-plugin-name\ndescription: plugin fixture\n---\n",
                encoding="utf-8",
            )
            (home / ".claude" / "settings.json").write_text(
                json.dumps({"enabledPlugins": {"enabled-plugin@market": True}}),
                encoding="utf-8",
            )
            with mock.patch.object(Path, "home", return_value=home):
                discover = load_module("supervisor_v3_discover_canonical_probe", DISCOVER)

            inventory = discover.collect()

            self.assertIn("trusted-directory-name", inventory)
            self.assertNotIn("forged-personal-alias", inventory)
            self.assertEqual(inventory["trusted-directory-name"]["name"], "trusted-directory-name")
            self.assertIn("enabled-plugin:declared-plugin-name", inventory)
            self.assertNotIn("enabled-plugin:plugin-directory-name", inventory)

    def test_every_callable_name_is_byte_exact_in_every_discovery_output_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-discover-names-") as temp:
            home = Path(temp) / "home"
            personal_name = "matrix-personal-" + "x" * 40
            plugin_name = "matrix-plugin-" + "p" * 28
            skill_name = "matrix-skill-" + "s" * 36
            personal = home / ".claude" / "skills" / personal_name / "SKILL.md"
            installed = (
                home / ".claude" / "plugins" / "cache" / "market" / plugin_name
                / "1.0" / "skills" / skill_name / "SKILL.md"
            )
            for path, name in ((personal, personal_name), (installed, skill_name)):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f"---\nname: {name}\ndescription: matrix-marker fixture\n---\n",
                    encoding="utf-8",
                )
            settings = home / ".claude" / "settings.json"
            settings.write_text(
                json.dumps({"enabledPlugins": {plugin_name + "@market": True}}),
                encoding="utf-8",
            )
            with mock.patch.object(Path, "home", return_value=home):
                discover = load_module("supervisor_v3_discover_names_probe", DISCOVER)

            callable_names = sorted(discover.collect().keys())
            self.assertEqual(len(callable_names), 2)
            self.assertTrue(all(len(name) > 34 for name in callable_names))
            modes = (
                [],
                ["--all"],
                ["matrix-marker"],
                ["--new", "1"],
            )
            for mode in modes:
                with self.subTest(mode=mode):
                    output = io.StringIO()
                    with mock.patch.object(discover.sys, "argv", [str(DISCOVER), *mode]):
                        with contextlib.redirect_stdout(output):
                            self.assertEqual(discover.main(), 0)
                    rendered = output.getvalue().encode("utf-8")
                    for name in callable_names:
                        self.assertIn(name.encode("utf-8"), rendered)


class AdapterHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="supervisor-v3-claude-")
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir(parents=True)
        self.missing_core = Path(self.temp.name) / "missing-core"
        self.stub_core = Path(self.temp.name) / "stub-core"
        package = self.stub_core / "supervisor_core"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("# bundled fixture\n", encoding="utf-8")
        (package / "cli.py").write_text(
            """import json, os, pathlib, sys

def main():
    payload = json.loads(sys.stdin.read() or '{}')
    row = {'argv': sys.argv[1:], 'payload': payload}
    with pathlib.Path(os.environ['STUB_LOG']).open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + '\\n')
    adapter = payload.get('_agent_supervisor_adapter') or {}
    if adapter.get('degraded_prior') is True and payload.get('hook_event_name') == 'SessionStart':
        print(json.dumps({'agent_supervisor': {'health': 'degraded', 'durable_ack': True}}))
        return 4
    if os.environ.get('STUB_DEGRADED') == '1':
        print(json.dumps({'agent_supervisor': {'health': 'degraded', 'fail_open': True}}))
        return 0
    if 'Stop' in sys.argv:
        print(json.dumps({'decision': 'block', 'reason': 'fixture incomplete'}))
        return 2
    print(json.dumps({'continue': True, 'suppressOutput': True}))
    return 0
""",
            encoding="utf-8",
        )
        (package / "__main__.py").write_text(
            "from .cli import main\nraise SystemExit(main())\n",
            encoding="utf-8",
        )
        self.stub_log = Path(self.temp.name) / "stub.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def env(self, core: Path) -> dict[str, str]:
        result = dict(os.environ)
        for name in (
            "AGENT_SUPERVISOR_HOME",
            "AGENT_SUPERVISOR_CORE",
            "AGENT_SUPERVISOR_ACTIVE_POINTER",
            "AGENT_SUPERVISOR_RELEASE_ROOT",
            "AGENT_SUPERVISOR_INSTALL_HOME",
        ):
            result.pop(name, None)
        if core.is_dir():
            pointer, release_root, _identity = stage_runtime_pointer(self.home, core)
        else:
            pointer = core / "active-version.json"
            release_root = core / "releases"
        result.update(
            {
                "USERPROFILE": str(self.home),
                "HOME": str(self.home),
                "AGENT_SUPERVISOR_ACTIVE_POINTER": str(pointer),
                "AGENT_SUPERVISOR_RELEASE_ROOT": str(release_root),
                "STUB_LOG": str(self.stub_log),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        return result

    def test_env_scrubs_hostile_parent_core_selection_before_fixture_override(self) -> None:
        hostile = {
            "AGENT_SUPERVISOR_HOME": str(self.missing_core),
            "AGENT_SUPERVISOR_CORE": str(self.missing_core),
            "AGENT_SUPERVISOR_ACTIVE_POINTER": str(self.missing_core / "active-version.json"),
            "AGENT_SUPERVISOR_RELEASE_ROOT": str(self.missing_core / "releases"),
            "AGENT_SUPERVISOR_INSTALL_HOME": str(self.missing_core / "install"),
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            isolated = self.env(self.stub_core)
            proc = self.run_hook(
                "SessionStart",
                {"session_id": "hostile-parent", "cwd": "D:/project"},
                self.stub_core,
            )

        self.assertEqual(
            isolated["AGENT_SUPERVISOR_ACTIVE_POINTER"],
            str(self.home / ".agent-supervisor" / "active-version.json"),
        )
        for name in hostile:
            if name not in {"AGENT_SUPERVISOR_ACTIVE_POINTER", "AGENT_SUPERVISOR_RELEASE_ROOT"}:
                self.assertNotIn(name, isolated)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertTrue(self.stub_log.is_file())
        self.assertEqual(self.rows()[0]["payload"]["session_id"], "hostile-parent")

    def run_hook(self, event: str | None, payload: dict, core: Path) -> subprocess.CompletedProcess[bytes]:
        args = [sys.executable, str(ADAPTER)]
        if event:
            args += ["--event", event]
        return subprocess.run(
            args,
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env(core),
            timeout=30,
            check=False,
        )

    def rows(self) -> list[dict]:
        return [json.loads(line) for line in self.stub_log.read_text(encoding="utf-8").splitlines()]

    def test_missing_core_is_fail_open_and_spool_is_redacted(self) -> None:
        secret = "unit-secret-value"
        proc = self.run_hook(
            "UserPromptSubmit",
            {"session_id": "session-a", "cwd": "D:/project", "user_prompt": f"token={secret}"},
            self.missing_core,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")
        logs = list((self.home / ".agent-supervisor" / "fallback" / "claude").glob("*.jsonl"))
        self.assertEqual(len(logs), 1)
        text = logs[0].read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn("user_prompt\":\"token", text)
        row = json.loads(text)
        self.assertEqual(row["status"], "degraded")
        self.assertEqual(row["reason_category"], "active_pointer_rejected")

    def test_file_not_found_reason_is_actionable_but_path_safe(self) -> None:
        adapter = load_module("supervisor_v3_missing_reason_probe", ADAPTER)
        self.assertEqual(
            adapter._safe_file_not_found_reason(FileNotFoundError("active_pointer_rejected")),
            "active_pointer_rejected",
        )
        self.assertEqual(
            adapter._safe_file_not_found_reason(FileNotFoundError("C:/private/user/path")),
            "core_missing",
        )

    def test_stdin_read_failure_is_fixed_category_fail_open_without_leak(self) -> None:
        adapter = load_module("supervisor_v3_stdin_failure_probe", ADAPTER)
        hidden_detail = "input-read-detail-should-stay-hidden"

        class BrokenBinaryInput:
            def read(self):
                raise OSError(hidden_detail)

        class BrokenInput:
            buffer = BrokenBinaryInput()

        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(adapter.sys, "stdin", BrokenInput()):
            with mock.patch.object(adapter, "_record_degraded") as record:
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    rc = adapter.main(["--event", "SessionStart"])

        self.assertEqual(rc, 0)
        record.assert_called_once_with("SessionStart", {}, "stdin_read_failed")
        self.assertNotIn(hidden_detail, output.getvalue() + errors.getvalue())

    def test_internal_timeout_stays_below_registered_host_ceiling(self) -> None:
        adapter = load_module("supervisor_v3_timeout_probe", ADAPTER)
        configure_tree = ast.parse(CONFIGURE.read_text(encoding="utf-8"))
        registered = [
            value.value
            for node in ast.walk(configure_tree)
            if isinstance(node, ast.Dict)
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant)
            and key.value == "timeout"
            and isinstance(value, ast.Constant)
            and isinstance(value.value, (int, float))
        ]
        self.assertEqual(set(registered), {10})
        self.assertEqual(adapter.REGISTERED_HOOK_TIMEOUT_SECONDS, min(registered))
        for configured in ("9", "10", "30", "inf", "invalid"):
            with self.subTest(configured=configured):
                with mock.patch.dict(
                    os.environ, {"AGENT_SUPERVISOR_HOOK_TIMEOUT": configured}, clear=False
                ):
                    self.assertLess(adapter._hook_timeout(), min(registered))

    def test_forward_ignores_external_pythonpath_and_cwd_module_shadow(self) -> None:
        attacker = Path(self.temp.name) / "attacker"
        package = attacker / "supervisor_core"
        package.mkdir(parents=True)
        marker = Path(self.temp.name) / "shadow-ran.txt"
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "__main__.py").write_text(
            "import os, pathlib\n"
            "pathlib.Path(os.environ['ATTACK_MARKER']).write_text('shadowed', encoding='utf-8')\n",
            encoding="utf-8",
        )
        env = self.env(self.stub_core)
        env["PYTHONPATH"] = str(attacker)
        env["ATTACK_MARKER"] = str(marker)

        proc = subprocess.run(
            [sys.executable, str(ADAPTER), "--event", "SessionStart"],
            input=json.dumps({"session_id": "module-shadow", "cwd": "D:/project"}).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=attacker,
            env=env,
            timeout=30,
            check=False,
        )

        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")
        self.assertFalse(marker.exists())
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["payload"]["hook_event_name"], "SessionStart")

    def test_frozen_runtime_survives_bundle_and_source_swap_after_verification(self) -> None:
        env = self.env(self.stub_core)
        adapter = load_module("supervisor_v3_frozen_runtime_probe", ADAPTER)
        with mock.patch.dict(os.environ, env, clear=False):
            frozen = adapter._load_active_runtime()
            Path(frozen["bundle_path"]).write_bytes(b"replaced-after-freeze")
            (self.stub_core / "supervisor_core" / "cli.py").write_text(
                "raise RuntimeError('mutable source executed')\n",
                encoding="utf-8",
            )
            original_run = subprocess.run
            with mock.patch.object(adapter.subprocess, "run", wraps=original_run) as launch:
                returncode, stdout = adapter._run_frozen_runtime(
                    frozen,
                    "SessionStart",
                    {
                        "session_id": "frozen-session",
                        "cwd": "D:/project",
                        "hook_event_name": "SessionStart",
                        "_agent_supervisor_adapter": {
                            "adapter_version": adapter.ADAPTER_VERSION,
                            "degraded_prior": False,
                        },
                    },
                )

        self.assertEqual(returncode, 0)
        self.assertTrue(json.loads(stdout)["continue"])
        self.assertEqual(self.rows()[0]["payload"]["session_id"], "frozen-session")
        child_args = launch.call_args.args[0]
        child_env = launch.call_args.kwargs["env"]
        self.assertEqual(child_args[1:4], ["-I", "-S", "-c"])
        self.assertNotIn("-m", child_args)
        self.assertNotIn("pythonpath", {name.casefold() for name in child_env})

    def test_mutable_core_environment_has_no_runtime_fallback(self) -> None:
        env = self.env(self.missing_core)
        env["AGENT_SUPERVISOR_CORE"] = str(self.stub_core)
        env["AGENT_SUPERVISOR_HOME"] = str(self.stub_core)
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), "--event", "SessionStart"],
            input=json.dumps({"session_id": "no-core-fallback", "cwd": "D:/project"}).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )

        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")
        self.assertFalse(self.stub_log.exists())

    def test_prompt_and_stop_are_forwarded_even_without_file_changes(self) -> None:
        prompt = self.run_hook(
            "UserPromptSubmit",
            {"session_id": "session-b", "cwd": "D:/project", "user_prompt": "只做分析"},
            self.stub_core,
        )
        stop = self.run_hook(
            "Stop",
            {"session_id": "session-b", "cwd": "D:/project", "stop_hook_active": False},
            self.stub_core,
        )
        self.assertEqual(prompt.returncode, 0)
        self.assertEqual(stop.returncode, 0)
        self.assertEqual(json.loads(stop.stdout)["decision"], "block")
        rows = self.rows()
        self.assertEqual([row["payload"]["hook_event_name"] for row in rows], ["UserPromptSubmit", "Stop"])

    def test_subagent_start_is_forwarded_and_legacy_alias_is_normalized(self) -> None:
        payload = {
            "session_id": "session-subagent-start",
            "cwd": "D:/project",
            "agent_id": "reviewer-fixture",
            "agent_type": "reviewer",
        }
        direct = self.run_hook("SubagentStart", payload, self.stub_core)
        alias = subprocess.run(
            [sys.executable, str(ADAPTER), "subagent-start"],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env(self.stub_core),
            timeout=30,
            check=False,
        )

        for proc in (direct, alias):
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stderr, b"")
        self.assertEqual(
            [row["payload"]["hook_event_name"] for row in self.rows()],
            ["SubagentStart", "SubagentStart"],
        )

    def test_attempt_and_failure_keep_the_same_invocation_id(self) -> None:
        common = {"session_id": "session-c", "cwd": "D:/project", "tool_use_id": "call-42", "tool_name": "Skill"}
        self.run_hook("PreToolUse", {**common, "tool_input": {"skill": "long:skill-name"}}, self.stub_core)
        self.run_hook("PostToolUseFailure", {**common, "error": "rejected"}, self.stub_core)
        rows = self.rows()
        self.assertEqual(rows[0]["payload"]["tool_use_id"], "call-42")
        self.assertEqual(rows[1]["payload"]["tool_use_id"], "call-42")
        self.assertEqual(rows[1]["payload"]["hook_event_name"], "PostToolUseFailure")

    def test_degraded_marker_is_returned_to_core_after_recovery(self) -> None:
        payload = {"session_id": "session-d", "cwd": "D:/project", "hook_event_name": "SessionStart"}
        self.run_hook(None, payload, self.missing_core)
        self.run_hook(None, payload, self.stub_core)
        self.run_hook("UserPromptSubmit", {"session_id": "session-d", "cwd": "D:/project", "user_prompt": "recover"}, self.stub_core)
        self.run_hook(None, payload, self.stub_core)
        forwarded = self.rows()
        self.assertTrue(forwarded[0]["payload"]["_agent_supervisor_adapter"]["degraded_prior"])
        self.assertTrue(forwarded[1]["payload"]["_agent_supervisor_adapter"]["degraded_prior"])
        self.assertFalse(forwarded[2]["payload"]["_agent_supervisor_adapter"]["degraded_prior"])
        self.assertEqual(forwarded[0]["payload"]["_agent_supervisor_adapter"]["adapter_version"], "3.1.6")

    def test_core_degraded_response_creates_marker(self) -> None:
        env = self.env(self.stub_core)
        env["STUB_DEGRADED"] = "1"
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), "--event", "SessionStart"],
            input=json.dumps({"session_id": "session-e", "cwd": "D:/project"}).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout)["agent_supervisor"]["health"], "degraded")
        marker_dir = self.home / ".agent-supervisor" / "fallback" / "claude" / "markers"
        self.assertEqual(len(list(marker_dir.glob("*.json"))), 1)

    def test_degraded_marker_write_and_clear_share_the_session_lock(self) -> None:
        adapter = load_module("supervisor_v3_marker_lock_probe", ADAPTER)
        payload = {"session_id": "session-lock", "cwd": "D:/project"}
        acquired: list[Path] = []
        original_acquire = adapter._acquire_lock

        def tracking_acquire(path: Path, timeout_seconds: float = 1.5):
            acquired.append(path)
            return original_acquire(path, timeout_seconds)

        with mock.patch.dict(os.environ, self.env(self.missing_core), clear=False):
            with mock.patch.object(adapter, "_acquire_lock", side_effect=tracking_acquire):
                adapter._record_degraded("SessionStart", payload, "core_missing")
                marker = adapter._fallback_paths("session-lock")[1]
                session_lock = adapter._degraded_session_lock("session-lock")
                self.assertTrue(marker.is_file())
                adapter._clear_degraded_marker("session-lock")

        self.assertFalse(marker.exists())
        self.assertEqual(sum(path == session_lock for path in acquired), 2)

    def test_degraded_lock_contention_uses_atomic_no_clobber_marker_fallback(self) -> None:
        adapter = load_module("supervisor_v3_marker_contention_probe", ADAPTER)
        secret = "marker-fallback-secret-must-not-persist"
        payload = {
            "session_id": "session-lock-contention",
            "cwd": "D:/project",
            "user_prompt": secret,
        }
        original_acquire = adapter._acquire_lock

        with mock.patch.dict(os.environ, self.env(self.missing_core), clear=False):
            marker = adapter._fallback_paths(payload["session_id"])[1]
            session_lock = adapter._degraded_session_lock(payload["session_id"])
            session_lock.parent.mkdir(parents=True, exist_ok=True)
            session_lock.write_text("held", encoding="ascii")

            def short_acquire(path: Path, timeout_seconds: float = 1.5):
                return original_acquire(path, min(timeout_seconds, 0.02))

            with mock.patch.object(adapter, "_acquire_lock", side_effect=short_acquire):
                adapter._record_degraded("SessionStart", payload, "core_missing")

            self.assertTrue(session_lock.is_file())
            self.assertTrue(marker.is_file())
            first = marker.read_bytes()
            decoded = json.loads(first)
            self.assertTrue(decoded["degraded"])
            self.assertEqual(decoded["reason_category"], "core_missing")
            self.assertNotIn(secret.encode("utf-8"), first)
            self.assertEqual(list(marker.parent.glob("*.fallback-*.tmp")), [])

            with mock.patch.object(adapter, "_acquire_lock", side_effect=short_acquire):
                adapter._record_degraded("Stop", payload, "adapter_exception")

            self.assertEqual(marker.read_bytes(), first)
            self.assertEqual(list(marker.parent.glob("*.fallback-*.tmp")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX owner mode semantics")
    def test_degraded_spool_directories_and_files_are_owner_only(self) -> None:
        adapter = load_module("supervisor_v3_degraded_private_mode_probe", ADAPTER)
        payload = {"session_id": "private-mode-session", "cwd": "D:/project"}

        with mock.patch.dict(os.environ, self.env(self.missing_core), clear=False):
            log_path, marker_path = adapter._fallback_paths(payload["session_id"])
            log_path.parent.mkdir(parents=True, mode=0o755)
            log_path.write_text('{"existing":true}\n', encoding="utf-8")
            log_path.chmod(0o644)
            adapter._record_degraded("SessionStart", payload, "core_missing")

        for directory in (
            self.home / ".agent-supervisor",
            self.home / ".agent-supervisor" / "fallback",
            log_path.parent,
            marker_path.parent,
        ):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in (log_path, marker_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 2)


class RealCoreIntegration(unittest.TestCase):
    def setUp(self) -> None:
        default_core = Path(os.environ.get("USERPROFILE") or Path.home()) / ".agent-supervisor"
        self.core = Path(os.environ.get("AGENT_SUPERVISOR_CORE", default_core))
        if not (self.core / "supervisor_core" / "cli.py").exists():
            self.skipTest("shared Supervisor v3 core is not installed")
        self.temp = tempfile.TemporaryDirectory(prefix="supervisor-v3-real-core-")
        self.home = Path(self.temp.name) / "home"
        self.workspace = Path(self.temp.name) / "workspace with 空格"
        (self.workspace / ".agent-supervisor").mkdir(parents=True)
        schema_source = self.core / "supervisor_core" / "schemas" / "project-config.schema.json"
        (self.workspace / ".agent-supervisor" / "schemas").mkdir()
        (self.workspace / ".agent-supervisor" / "schemas" / "project.schema.json").write_text(
            schema_source.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.workspace / ".agent-supervisor" / "project.json").write_text(
            json.dumps(
                {
                    "$schema": "schemas/project.schema.json",
                    "schema_version": "3.0.0",
                    "project_id": "claude-adapter-fixture",
                    "execution_mode": "enforce",
                    "supervisor_scope": {
                        "allowed_change_globs": [".agent-supervisor/**"],
                        "out_of_scope_globs": ["src/**"],
                    },
                }
            ),
            encoding="utf-8",
        )
        self.session = "claude-adapter-real-core"

    def tearDown(self) -> None:
        if hasattr(self, "temp"):
            self.temp.cleanup()

    def run_hook(self, event: str, extra: dict | None = None) -> subprocess.CompletedProcess[bytes]:
        payload = {
            "session_id": self.session,
            "cwd": str(self.workspace),
            "hook_event_name": event,
            **(extra or {}),
        }
        env = dict(os.environ)
        version = (self.core / "VERSION").read_text(encoding="utf-8").strip()
        pointer, release_root, _identity = stage_runtime_pointer(
            self.home,
            self.core,
            version=version,
        )
        env.pop("AGENT_SUPERVISOR_HOME", None)
        env.pop("AGENT_SUPERVISOR_CORE", None)
        env.update(
            {
                "USERPROFILE": str(self.home),
                "HOME": str(self.home),
                "AGENT_SUPERVISOR_ACTIVE_POINTER": str(pointer),
                "AGENT_SUPERVISOR_RELEASE_ROOT": str(release_root),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        return subprocess.run(
            [sys.executable, str(ADAPTER), "--event", event],
            input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=30,
            check=False,
        )

    def test_real_core_lifecycle_failure_pair_and_direct_enforce_downgrade(self) -> None:
        session_start = self.run_hook("SessionStart")
        prompt = self.run_hook("UserPromptSubmit", {"user_prompt": "只分析目标与风险，不改文件"})
        invocation = {
            "tool_use_id": "real-call-1",
            "tool_name": "Skill",
            "tool_input": {"skill": "plugin:an-extremely-long-capability-name-preserved"},
        }
        pre = self.run_hook("PreToolUse", invocation)
        failed = self.run_hook("PostToolUseFailure", {**invocation, "error": "cancelled"})
        subagent = self.run_hook("SubagentStop", {"agent_id": "reviewer-fixture"})
        stops = [self.run_hook("Stop", {"stop_hook_active": index > 0}) for index in range(3)]

        for proc in (session_start, prompt, pre, failed, subagent, *stops):
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stderr, b"")
        self.assertTrue(all("decision" not in json.loads(stop.stdout) for stop in stops))

        state_files = list((self.home / ".agent-supervisor" / "state").rglob("state.json"))
        self.assertEqual(len(state_files), 1)
        state = json.loads(state_files[0].read_text(encoding="utf-8"))
        self.assertEqual(state["terminal_state"], "incomplete")
        self.assertEqual(state["execution_mode"], "observe")
        self.assertEqual(state["rollout"]["requested_mode"], "enforce")
        self.assertEqual(state["stop_attempts"], 3)
        self.assertTrue(state["host_gate"]["stop_cap_reached"])
        self.assertFalse(state["host_gate"]["should_block"])

        event_file = state_files[0].with_name("events.jsonl")
        events = [json.loads(line) for line in event_file.read_text(encoding="utf-8").splitlines()]
        results = [event for event in events if event.get("invocation_id") == "real-call-1" and event.get("stage") == "result"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"], "failed")
        self.assertEqual(results[0]["capability"], "plugin:an-extremely-long-capability-name-preserved")
        self.assertTrue(any(event.get("event_type") == "subagent_stop_review" for event in events))


class LegacyPlanSafety(unittest.TestCase):
    def test_lexicon_has_no_duplicate_literal_keys(self) -> None:
        tree = ast.parse(PLAN.read_text(encoding="utf-8"))
        lexicon = next(
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "LEXICON" for target in node.targets)
        )
        self.assertIsInstance(lexicon, ast.Dict)
        keys = [key.value for key in lexicon.keys if isinstance(key, ast.Constant)]
        self.assertEqual(len(keys), len(set(keys)))

    def test_unknown_cached_kind_does_not_break_candidate_diversity_count(self) -> None:
        plan = load_module("supervisor_v3_plan_unknown_kind_probe", PLAN)
        result = plan.retrieve(
            "future-debug",
            {
                "items": [
                    {
                        "kind": "future-capability",
                        "call": "future-debug",
                        "blob": "future-debug diagnostic capability",
                        "src": "cached-fixture",
                    }
                ]
            },
            k=1,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1]["call"], "future-debug")

    def test_plugin_cache_requires_a_valid_explicit_enabled_map(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-plan-plugin-") as temp:
            home = Path(temp) / "home"
            settings = home / ".claude" / "settings.json"
            skill = home / ".claude" / "plugins" / "cache" / "market" / "foo" / "1.0" / "skills" / "use-foo" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("---\nname: use-foo\ndescription: Foo capability\n---\n", encoding="utf-8")
            settings.write_text(json.dumps({"enabledPlugins": {"foo@market": True}}), encoding="utf-8")
            with mock.patch.object(Path, "home", return_value=home):
                plan = load_module("supervisor_v3_plan_plugin_probe", PLAN)

            enabled = plan.build_index()
            self.assertIn("foo:use-foo", {item["call"] for item in enabled["items"]})
            self.assertEqual(enabled["plugin_config_status"], "available")

            settings.write_text("{malformed", encoding="utf-8")
            unavailable = plan.build_index()
            self.assertNotIn("foo:use-foo", {item["call"] for item in unavailable["items"]})
            self.assertEqual(unavailable["plugin_config_status"], "unavailable")

            settings.write_text(json.dumps({"enabledPlugins": {}}), encoding="utf-8")
            disabled = plan.build_index()
            self.assertNotIn("foo:use-foo", {item["call"] for item in disabled["items"]})
            self.assertEqual(disabled["plugin_config_status"], "available")

    def test_nested_enabled_plugin_skill_content_invalidates_source_stamp(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-plan-stamp-") as temp:
            home = Path(temp) / "home"
            settings = home / ".claude" / "settings.json"
            skill = (
                home / ".claude" / "plugins" / "cache" / "market" / "foo" / "1.0"
                / "skills" / "use-foo" / "SKILL.md"
            )
            skill.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps({"enabledPlugins": {"foo@market": True}}), encoding="utf-8"
            )
            skill.write_text(
                "---\nname: use-foo\ndescription: Foo capability\n---\n", encoding="utf-8"
            )
            original_stat = skill.stat()
            with mock.patch.object(Path, "home", return_value=home):
                plan = load_module("supervisor_v3_plan_stamp_probe", PLAN)

            before = plan._sources_stamp()
            skill.write_text(
                "---\nname: use-foo\ndescription: Bar capability\n---\n", encoding="utf-8"
            )
            os.utime(skill, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            after = plan._sources_stamp()

            self.assertEqual(before["plugin_skill_count"], 1)
            self.assertEqual(after["plugin_skill_count"], 1)
            self.assertNotEqual(before["plugin_fingerprint"], after["plugin_fingerprint"])

    def test_plugin_fingerprint_is_bounded_but_frontmatter_sensitive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-plan-bounded-") as temp:
            home = Path(temp) / "home"
            settings = home / ".claude" / "settings.json"
            skill = (
                home / ".claude" / "plugins" / "cache" / "market" / "foo" / "1.0"
                / "skills" / "use-foo" / "SKILL.md"
            )
            skill.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps({"enabledPlugins": {"foo@market": True}}), encoding="utf-8"
            )
            prefix = "---\nname: use-foo\ndescription: Frontmatter A\n---\n"
            skill.write_text(prefix + "x" * 5000, encoding="utf-8")
            original_stat = skill.stat()
            with mock.patch.object(Path, "home", return_value=home):
                plan = load_module("supervisor_v3_plan_bounded_probe", PLAN)

            initial = plan._sources_stamp()["plugin_fingerprint"]
            skill.write_text(prefix + "x" * 4999 + "y", encoding="utf-8")
            os.utime(skill, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            suffix_only = plan._sources_stamp()["plugin_fingerprint"]
            skill.write_text(
                prefix.replace("Frontmatter A", "Frontmatter B") + "x" * 5000,
                encoding="utf-8",
            )
            os.utime(skill, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            frontmatter_changed = plan._sources_stamp()["plugin_fingerprint"]

            self.assertEqual(plan.PLUGIN_FINGERPRINT_PREFIX_BYTES, 4096)
            self.assertEqual(initial, suffix_only)
            self.assertNotEqual(initial, frontmatter_changed)

    def test_connector_sources_invalidate_without_persisting_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-plan-connectors-") as temp:
            home = Path(temp) / "home"
            claude = home / ".claude"
            claude.mkdir(parents=True)
            claude_json = home / ".claude.json"
            auth_cache = claude / "mcp-needs-auth-cache.json"
            secret = "credential-must-not-enter-dispatch-stamp"
            claude_json.write_text(
                json.dumps({"mcpServers": {"alpha": {"token": secret}}}), encoding="utf-8"
            )
            auth_cache.write_text(json.dumps({"charlie": {"token": secret}}), encoding="utf-8")

            with mock.patch.object(Path, "home", return_value=home):
                plan = load_module("supervisor_v3_plan_connector_stamp_probe", PLAN)

            before = plan._sources_stamp()
            before_text = json.dumps(before, sort_keys=True)
            self.assertNotIn(secret, before_text)
            self.assertNotIn("alpha", before_text)
            self.assertNotIn("charlie", before_text)

            original = claude_json.stat()
            claude_json.write_text(
                json.dumps({"mcpServers": {"bravo": {"token": secret}}}), encoding="utf-8"
            )
            os.utime(claude_json, ns=(original.st_atime_ns, original.st_mtime_ns))
            changed_name = plan._sources_stamp()
            self.assertNotEqual(
                before["connector_sources"]["claude_json"],
                changed_name["connector_sources"]["claude_json"],
            )

            auth_cache.unlink()
            removed = plan._sources_stamp()
            self.assertFalse(removed["connector_sources"]["auth_cache"]["present"])
            self.assertNotEqual(before, removed)

    def test_render_plan_block_drops_a_trailing_partial_candidate_row(self) -> None:
        plan = load_module("supervisor_v3_plan_truncation_probe", PLAN)
        items = [
            {"kind": "skill", "call": "first-complete-skill", "desc": "first candidate"},
            {"kind": "skill", "call": "second-partial-skill", "desc": "second candidate"},
        ]
        index = {"items": items, "plugin_config_status": "available"}
        groups = [(None, [(2.0, items[0]), (1.0, items[1])])]

        with mock.patch.object(plan, "load_index", return_value=(index, False)):
            with mock.patch.object(plan, "retrieve_by_clause", return_value=groups):
                complete = plan.render_plan_block("fixture", max_chars=10000)
                complete_lines = complete.splitlines()
                second_row_start = complete.index(complete_lines[2])
                truncated = plan.render_plan_block(
                    "fixture",
                    max_chars=second_row_start + len(complete_lines[2]) // 2,
                )

        self.assertEqual(truncated, "\n".join(complete_lines[:2]))
        self.assertIn("first-complete-skill", truncated)
        self.assertNotIn("second-partial", truncated)

    def test_precision_thresholds_reject_empty_measurements(self) -> None:
        precision = load_module("supervisor_v3_precision_guard_probe", PRECISION)
        self.assertFalse(precision.thresholds_pass(0, 0, 0, 0))
        self.assertFalse(precision.thresholds_pass(3, 0, 0, 0))

    def test_precision_requires_an_annotated_must_not_name_in_the_index(self) -> None:
        precision = load_module("supervisor_v3_precision_annotation_probe", PRECISION)
        unrelated = {
            "items": [
                {"kind": "skill", "call": "unrelated-capability", "blob": "unrelated"}
            ]
        }
        output = io.StringIO()
        with mock.patch.object(precision.m, "load_index", return_value=(unrelated, False)):
            with mock.patch.object(precision.m, "retrieve") as retrieve:
                with contextlib.redirect_stdout(output):
                    rc = precision.run()

        self.assertEqual(rc, precision.UNMEASURABLE_EXIT)
        self.assertIn("UNMEASURABLE", output.getvalue())
        retrieve.assert_not_called()

    def test_empty_indexes_are_explicitly_unmeasurable(self) -> None:
        for label, path in (("retrieval", RETRIEVAL), ("precision", PRECISION)):
            with self.subTest(label=label):
                suite = load_module("supervisor_v3_empty_" + label, path)
                output = io.StringIO()
                with mock.patch.object(suite.m, "load_index", return_value=({"items": []}, False)):
                    with contextlib.redirect_stdout(output):
                        rc = suite.run()
                self.assertEqual(rc, 77)
                self.assertIn("UNMEASURABLE", output.getvalue())
                self.assertNotIn("100%", output.getvalue())

    def test_retrieval_rejects_nonempty_index_without_any_expected_candidate(self) -> None:
        suite = load_module("supervisor_v3_retrieval_no_expected_probe", RETRIEVAL)
        unrelated = {
            "items": [
                {"kind": "skill", "call": "unrelated-capability", "blob": "unrelated"}
            ]
        }
        expected_by_prompt = {
            prompt: want[0]
            for prompt, want, _avoid in suite.CASES + suite.HELD_OUT
        }

        def synthetic_retrieve(prompt, _index, _limit):
            call = expected_by_prompt.get(prompt)
            return [(1.0, {"call": call})] if call else []

        output = io.StringIO()
        with mock.patch.object(suite.m, "load_index", return_value=(unrelated, False)):
            with mock.patch.object(suite.m, "retrieve", side_effect=synthetic_retrieve):
                with contextlib.redirect_stdout(output):
                    rc = suite.run()

        self.assertEqual(rc, suite.UNMEASURABLE_EXIT)
        self.assertIn("UNMEASURABLE", output.getvalue())
        self.assertNotIn("Recall@6  : 10/10", output.getvalue())

    def test_retrieval_labels_all_non_skill_entries_as_candidates_not_agents(self) -> None:
        suite = load_module("supervisor_v3_retrieval_label_probe", RETRIEVAL)
        first_expected = suite.CASES[0][1][0]
        index = {
            "items": [
                {"kind": "skill", "call": first_expected},
                {"kind": "agent", "call": "fixture-agent"},
                {"kind": "plugin", "call": "fixture-plugin"},
                {"kind": "connector", "call": "fixture-connector"},
            ]
        }
        expected_by_prompt = {
            prompt: wanted[0]
            for prompt, wanted, _avoid in suite.CASES + suite.HELD_OUT
        }

        def synthetic_retrieve(prompt, _index, _limit):
            call = expected_by_prompt.get(prompt)
            return [(1.0, {"call": call})] if call else []

        output = io.StringIO()
        with mock.patch.object(suite.m, "load_index", return_value=(index, False)):
            with mock.patch.object(suite.m, "retrieve", side_effect=synthetic_retrieve):
                with contextlib.redirect_stdout(output):
                    rc = suite.run()

        self.assertEqual(rc, 0)
        self.assertIn("索引：skill 1 / 非 skill 候选 3", output.getvalue())
        self.assertNotIn("agent 3", output.getvalue())


class LegacyLogSafety(unittest.TestCase):
    def test_decimal_comparisons_are_not_redirects_but_real_paths_are(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-redirect-precision-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_redirect_precision_probe", LOG)

        for command in (
            "python -c \"print(1 > 0.5)\"",
            "awk '$3 > 1.5' report.csv",
            "jq 'select(.score > 2.75)' report.json",
        ):
            with self.subTest(command=command):
                self.assertFalse(log.is_dev_call("Bash", {"command": command}))
        for command in (
            "echo value > report.txt",
            "echo value > .env",
            "echo value > ./nested/output.json",
            r"echo value > C:\temp\output.txt",
        ):
            with self.subTest(command=command):
                self.assertTrue(log.is_dev_call("Bash", {"command": command}))

    def test_dev_turn_requires_successful_post_tool_and_ignores_read_only_work(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-dev-success-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_dev_success_probe", LOG)

            raw_sid = "dev-success-session"
            log.set_session({"session_id": raw_sid})
            log.write_turn_state({
                "turn_started_at": "2000-01-01T00:00:00Z",
                "dev_tool_used": False,
                "session_id": log._session_token(raw_sid),
            })
            edit = {
                "tool_name": "Edit",
                "tool_input": {"file_path": "fixture.txt"},
                "session_id": raw_sid,
                "tool_use_id": "dev-edit",
            }
            with mock.patch.object(log.sys, "argv", [str(LOG), "pre-tool"]):
                log.handle_pre_tool(edit)
            self.assertFalse(log.read_turn_state().get("dev_tool_used"))

            with mock.patch.object(log.sys, "argv", [str(LOG), "post-tool"]):
                log.handle_post_tool(edit)
                for index, status in enumerate(("error", "cancelled", "rejected")):
                    log.handle_post_tool({**edit, "tool_use_id": f"failed-{index}", "status": status})
                log.handle_post_tool({
                    "tool_name": "Read",
                    "tool_input": {"file_path": "research.md"},
                    "session_id": raw_sid,
                    "tool_use_id": "read-only",
                    "status": "ok",
                })
            self.assertFalse(log.read_turn_state().get("dev_tool_used"))

            with mock.patch.object(log.sys, "argv", [str(LOG), "post-tool"]):
                log.handle_post_tool({**edit, "tool_use_id": "successful-edit", "status": "ok"})
            self.assertTrue(log.read_turn_state().get("dev_tool_used"))

    def test_post_tool_rejects_unexpanded_status_templates_and_preserves_failures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-status-template-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_status_template_probe", LOG)

            raw_sid = "status-template-session"
            log.set_session({"session_id": raw_sid})
            log.write_turn_state({
                "turn_started_at": "2000-01-01T00:00:00Z",
                "dev_tool_used": False,
                "session_id": log._session_token(raw_sid),
            })
            base = {
                "tool_name": "Bash",
                "tool_input": {"command": "Set-Content fixture.txt value"},
                "session_id": raw_sid,
            }
            cases = (
                ("%CLAUDE_TOOL_STATUS%", {"status": "FAILED"}, {}, "FAILED"),
                ("$CLAUDE_TOOL_STATUS", {"tool_response": {"status": "error"}}, {}, "error"),
                ("${CLAUDE_TOOL_STATUS}", {}, {"CLAUDE_TOOL_STATUS": "cancelled"}, "cancelled"),
            )
            for index, (template, payload, environment, expected) in enumerate(cases):
                with self.subTest(template_index=index):
                    with mock.patch.object(
                        log.sys, "argv", [str(LOG), "post-tool", "Bash", template]
                    ):
                        with mock.patch.dict(os.environ, environment, clear=False):
                            log.handle_post_tool({**base, **payload, "tool_use_id": f"status-{index}"})

            rows = [
                json.loads(line)
                for line in log._current_log_file().read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([row["status"] for row in rows], ["FAILED", "error", "cancelled"])
            self.assertFalse(log.read_turn_state().get("dev_tool_used"))
            self.assertFalse(any("CLAUDE_TOOL_STATUS" in row["status"] for row in rows))

    def test_context_summary_degrades_when_read_or_stat_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-context-failure-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_context_failure_probe", LOG)

            context_file = log.CONTEXTS_DIR / "fixture.md"
            context_file.write_text("## 🎯 Active Project\nfixture", encoding="utf-8")
            expected = "（[fixture] 上下文读取失败）"
            with mock.patch.object(log, "find_context_file", return_value=(context_file, "fixture")):
                with mock.patch.object(Path, "read_text", side_effect=OSError("read blocked")):
                    self.assertEqual(log.load_context_summary("D:/fixture"), expected)
                with mock.patch.object(Path, "stat", side_effect=OSError("stat blocked")):
                    self.assertEqual(log.load_context_summary("D:/fixture"), expected)

    def test_full_invocation_hash_prevents_same_suffix_call_collision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-uid-collision-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_uid_collision_probe", LOG)

            raw_sid = "uid-collision-session"
            token = log._session_token(raw_sid)
            log.set_session({"session_id": raw_sid})
            log_file = log._current_log_file()
            state = {
                "turn_started_at": "2000-01-01T00:00:00",
                "turn_log_path": str(log_file),
                "turn_log_paths": [str(log_file)],
                "session_id": token,
            }
            first_id = "prefix-a-shared88"
            second_id = "prefix-b-shared88"
            first = {"tool_name": "Skill", "tool_input": {"skill": "first-skill"},
                     "session_id": raw_sid, "tool_use_id": first_id}
            second = {"tool_name": "Skill", "tool_input": {"skill": "second-skill"},
                      "session_id": raw_sid, "tool_use_id": second_id}
            with contextlib.redirect_stdout(io.StringIO()):
                with mock.patch.object(log.sys, "argv", [str(LOG), "pre-tool"]):
                    log.handle_pre_tool(first)
                    log.handle_pre_tool(second)
                with mock.patch.object(log.sys, "argv", [str(LOG), "post-tool"]):
                    log.handle_post_tool({**first, "status": "ok"})
                    log.handle_post_tool({**second, "status": "error"})

            raw_log = log_file.read_text(encoding="utf-8")
            rows = [json.loads(line) for line in raw_log.splitlines()]
            expected_first = hashlib.sha256(first_id.encode("utf-8")).hexdigest()[:16]
            expected_second = hashlib.sha256(second_id.encode("utf-8")).hexdigest()[:16]
            self.assertNotEqual(expected_first, expected_second)
            for row in rows:
                expected_uid = expected_first if row.get("name") == "first-skill" else expected_second
                self.assertEqual(row.get("uid"), expected_uid)
            self.assertNotIn(first_id, raw_log)
            self.assertNotIn(second_id, raw_log)
            self.assertEqual(
                {call["name"]: call["outcome"] for call in log._turn_call_records(state)},
                {"first-skill": "success", "second-skill": "failed"},
            )

    def test_transcript_redacts_complete_prompt_before_bounded_truncation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-transcript-cutoff-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(
                    os.environ,
                    {
                        "SUP_DRYRUN": "0",
                        "SUPERVISOR_LEGACY_PERSIST_PROMPTS": "1",
                    },
                ):
                    log = load_module("supervisor_v3_transcript_cutoff_probe", LOG)

            secret = "sk-" + "A" * 24
            prompt = "x" * 14 + " " + secret + "tail"
            with mock.patch.object(log, "MAX_PROMPT_CHARS", 20):
                transcript = Path(log.append_transcript(prompt, "D:/fixture", 1, True))

            content = transcript.read_text(encoding="utf-8")
            body_match = re.search(r"(`{3,})text\n(.*?)\n\1\n", content, re.S)
            self.assertIsNotNone(body_match)
            body = body_match.group(2)
            visible = body.split("\n…（超长，已截断", 1)[0]
            self.assertLessEqual(len(visible), 20)
            self.assertIn("超长，已截断，原长 " + str(len(prompt)) + " 字", body)
            self.assertIn("已抹除 1 处疑似凭据", content)
            self.assertNotIn(secret, content)
            self.assertNotIn("sk-AA", content)
    def test_briefing_discovery_recognizes_sections_four_and_five(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-brief-marks-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_brief_marks_probe", LOG)

        partial_brief = "④ Karpathy 核查。⑤ 独立门禁。⑥ 待跟进事项。" + "有效说明。" * 30
        with mock.patch.object(log, "_recent_assistant_texts", return_value=[partial_brief]):
            self.assertEqual(log._find_briefing(Path("unused")), partial_brief)

    def test_project_key_is_compatible_deterministic_and_filesystem_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-project-key-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_project_key_probe", LOG)

        compatible = (
            ("", "unknown"),
            ("   ", "unknown"),
            (r"D:\VB\余白改", "D--VB--余白改"),
            ("D:/project", "D--project"),
            ("/opt/项目 alpha", "opt--项目-alpha"),
            (r"\\server\share\项目", "server--share--项目"),
            (".hidden", ".hidden"),
        )
        for raw, expected in compatible:
            with self.subTest(raw=raw, expected=expected):
                self.assertEqual(log.project_key(raw), expected)

        unsafe = (
            ".", "..", "../escape", r"..\escape", "CON", "nul.txt",
            "bad?name", "x" * 400,
        )
        for raw in unsafe:
            with self.subTest(raw=raw):
                key = log.project_key(raw)
                self.assertEqual(log.project_key(raw), key)
                self.assertNotIn(key, ("", ".", ".."))
                self.assertIsNone(re.search(r'[<>:"/\\|?*\x00-\x1f]', key))
                self.assertLessEqual(len(key), log.PROJECT_KEY_MAX_CHARS)

    def test_project_key_callsites_confine_forged_cwd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-project-key-paths-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(
                    os.environ,
                    {
                        "SUP_DRYRUN": "0",
                        "SUPERVISOR_LEGACY_PERSIST_PROMPTS": "1",
                    },
                ):
                    log = load_module("supervisor_v3_project_key_paths_probe", LOG)

            transcript = Path(log.append_transcript("probe", "..", 1, True)).resolve()
            transcript_root = log.TRANSCRIPTS_DIR.resolve()
            self.assertTrue(transcript.is_relative_to(transcript_root))
            self.assertFalse((log.SUP_HOME / transcript.name).exists())

            # Call sites retain their own boundary check even if key generation later
            # regresses or is replaced by an unsafe adapter value.
            escaped_context = log.STATE_DIR / "outside.md"
            escaped_context.write_text("outside", encoding="utf-8")
            with mock.patch.object(log, "project_key", return_value=r"..\outside"):
                context, _key = log.find_context_file("D:/forged")
            self.assertIsNone(context)

            month = log.datetime.now().strftime("%Y-%m") + ".md"
            escaped_transcript = log.TRANSCRIPTS_DIR.parent / month
            with mock.patch.object(log, "project_key", return_value=".."):
                self.assertEqual(log.append_transcript("blocked", "forged", 2, True), "")
            self.assertFalse(escaped_transcript.exists())

            sid = "valid-session_1"
            escaped_session = home / ".claude" / (sid + ".jsonl")
            escaped_session.parent.mkdir(parents=True, exist_ok=True)
            escaped_session.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.object(log, "project_key", return_value=".."):
                    found = log._session_transcript({"session_id": sid, "cwd": "forged"})
            self.assertIsNone(found)

    def test_daily_log_path_is_resolved_for_each_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-daily-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_daily_probe", LOG)

            first = log.LOG_DIR / "sup-20260831.jsonl"
            second = log.LOG_DIR / "sup-20260901.jsonl"
            with mock.patch.object(log, "_current_log_file", side_effect=[first, second]):
                self.assertTrue(log.append_event({"event": "before-midnight"}))
                self.assertTrue(log.append_event({"event": "after-midnight"}))

            self.assertEqual(json.loads(first.read_text(encoding="utf-8"))["event"], "before-midnight")
            self.assertEqual(json.loads(second.read_text(encoding="utf-8"))["event"], "after-midnight")

    def test_transcript_header_exclusive_create_preserves_race_winner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-transcript-race-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(
                    os.environ,
                    {
                        "SUP_DRYRUN": "0",
                        "SUPERVISOR_LEGACY_PERSIST_PROMPTS": "1",
                    },
                ):
                    log = load_module("supervisor_v3_transcript_race_probe", LOG)

            project = "D:/race-project"
            target = (
                log.TRANSCRIPTS_DIR
                / log.project_key(project)
                / (log.datetime.now().strftime("%Y-%m") + ".md")
            )
            target.parent.mkdir(parents=True)
            race_winner = "race-winner-content\n"
            target.write_text(race_winner, encoding="utf-8")
            original_exists = Path.exists

            def stale_exists(path: Path) -> bool:
                return False if path == target else original_exists(path)

            with mock.patch.object(Path, "exists", stale_exists):
                result = log.append_transcript("new prompt", project, 1, True)

            content = target.read_text(encoding="utf-8")
            self.assertEqual(result, str(target))
            self.assertTrue(content.startswith(race_winner))
            self.assertIn("new prompt", content)

    def test_retention_prunes_only_old_valid_noncurrent_state_logs_and_transcripts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-retention-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_retention_probe", LOG)

            log.set_session({"session_id": "active-retention-session"})
            active_state = log._state_file()
            old_state = log.STATE_DIR / ("current-turn-" + "a" * 16 + ".json")
            recent_state = log.STATE_DIR / ("current-turn-" + "b" * 16 + ".json")
            invalid_state = log.STATE_DIR / "current-turn-human-readable.json"

            current_log = log._current_log_file()
            old_log = log.LOG_DIR / "sup-20000101.jsonl"
            recent_log = log.LOG_DIR / "sup-20000102.jsonl"
            invalid_log = log.LOG_DIR / "sup-20000103.jsonl.bak"

            project_transcripts = log.TRANSCRIPTS_DIR / "fixture-project"
            project_transcripts.mkdir(parents=True)
            current_transcript = project_transcripts / (log.datetime.now().strftime("%Y-%m") + ".md")
            old_transcript = project_transcripts / "2000-01.md"
            recent_transcript = project_transcripts / "2000-02.md"
            invalid_transcript = project_transcripts / "2000-03.md.bak"
            misplaced_transcript = log.TRANSCRIPTS_DIR / "2000-04.md"

            files = (
                active_state, old_state, recent_state, invalid_state,
                current_log, old_log, recent_log, invalid_log,
                current_transcript, old_transcript, recent_transcript,
                invalid_transcript, misplaced_transcript,
            )
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")

            old_mtime = time.time() - 10 * 86400
            recent_mtime = time.time() - 86400
            for path in (
                active_state, old_state, invalid_state,
                current_log, old_log, invalid_log,
                current_transcript, old_transcript, invalid_transcript,
                misplaced_transcript,
            ):
                os.utime(path, (old_mtime, old_mtime))
            for path in (recent_state, recent_log, recent_transcript):
                os.utime(path, (recent_mtime, recent_mtime))

            log.prune_state_files(keep_days=-1)
            self.assertTrue(all(path.exists() for path in files))

            log.prune_state_files(keep_days=3)

            self.assertFalse(old_state.exists())
            self.assertFalse(old_log.exists())
            self.assertFalse(old_transcript.exists())
            for path in (
                active_state, recent_state, invalid_state,
                current_log, recent_log, invalid_log,
                current_transcript, recent_transcript,
                invalid_transcript, misplaced_transcript,
            ):
                with self.subTest(path=path):
                    self.assertTrue(path.exists())

    def test_session_start_invokes_retention(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-session-retention-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_session_retention_probe", LOG)

            with mock.patch.object(
                log, "read_stdin_json", return_value={"session_id": "retention-session", "cwd": "D:/project"}
            ), mock.patch.object(log, "_update_turn_state"), mock.patch.object(
                log, "prune_state_files"
            ) as prune, mock.patch.object(log, "append_event"), mock.patch.object(
                log.sys, "argv", [str(LOG), "session-start"]
            ):
                self.assertEqual(log.main(), 0)

            prune.assert_called_once_with()

    def test_turn_state_read_modify_write_is_serialized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-lock-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_lock_probe", LOG)

            log.set_session({"session_id": "concurrent-state"})
            self.assertTrue(log.write_turn_state({"counter": 0}))

            def increment(_index):
                def mutate(state):
                    value = int(state.get("counter", 0))
                    time.sleep(0.005)
                    state["counter"] = value + 1

                return log._update_turn_state(mutate)

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(increment, range(24)))

            self.assertTrue(all(result is not None for result in results))
            self.assertEqual(log.read_turn_state()["counter"], 24)
            self.assertFalse(log._state_lock_file().exists())

    def test_event_jsonl_append_is_serialized_across_sessions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-jsonl-lock-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_jsonl_lock_probe", LOG)

            original_open = Path.open

            class SplitWriter:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    self.handle.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def write(self, value):
                    midpoint = max(1, len(value) // 2)
                    self.handle.write(value[:midpoint])
                    self.handle.flush()
                    time.sleep(0.002)
                    return midpoint + self.handle.write(value[midpoint:])

            def split_open(path, *args, **kwargs):
                handle = original_open(path, *args, **kwargs)
                return SplitWriter(handle) if Path(path) == log._current_log_file() else handle

            def append(index):
                # Session ids deliberately vary: all sessions still share one daily log lock.
                log.set_session({"session_id": f"session-{index}"})
                return log.append_event({"event": "fixture", "index": index})

            with mock.patch.object(Path, "open", split_open):
                with ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(append, range(48)))

            rows = [json.loads(line) for line in log._current_log_file().read_text(
                encoding="utf-8"
            ).splitlines()]
            self.assertTrue(all(results))
            self.assertEqual({row["index"] for row in rows}, set(range(48)))
            self.assertFalse(log._log_lock_file(log._current_log_file()).exists())

    def test_dispatch_results_override_attempts_and_v2_counts_calls_not_names(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-results-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_results_probe", LOG)

            raw_sid = "dispatch-results-session"
            token = log._session_token(raw_sid)
            log.set_session({"session_id": raw_sid})
            log_file = log._current_log_file()
            state = {
                "turn": 1,
                "turn_started_at": "2000-01-01T00:00:00",
                "turn_log_path": str(log_file),
                "turn_log_paths": [str(log_file)],
                "session_id": token,
                "candidates": [],
            }
            self.assertTrue(log.write_turn_state(state))
            rows = [
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "failed-1",
                 "ts": "2099-01-01T00:00:01"},
                {"event": "post-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "failed-1", "status": "error",
                 "ts": "2099-01-01T00:00:02"},
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "success-1",
                 "ts": "2099-01-01T00:00:03"},
                {"event": "post-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "success-1", "status": "ok",
                 "ts": "2099-01-01T00:00:04"},
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "success-2",
                 "ts": "2099-01-01T00:00:05"},
                {"event": "post-tool", "tool": "Skill", "kind": "skill",
                 "name": "same-skill", "sid": token, "uid": "success-2", "status": "success",
                 "ts": "2099-01-01T00:00:06"},
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "pending-skill", "sid": token, "uid": "pending-1",
                 "ts": "2099-01-01T00:00:07"},
                {"event": "pre-tool", "tool": "Agent", "kind": "agent",
                 "name": "unknown-agent", "sid": token, "uid": "unknown-1",
                 "ts": "2099-01-01T00:00:08"},
                {"event": "post-tool", "tool": "Agent", "kind": "agent",
                 "name": "unknown-agent", "sid": token, "uid": "unknown-1", "status": "unknown",
                 "ts": "2099-01-01T00:00:09"},
            ]
            log_file.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )

            rendered = log.render_ledger()
            names, successful_count, saw_visual, saw_shell = log._turn_ledger_facts(state)
            self.assertEqual(names, {"skill:same-skill"})
            self.assertEqual(successful_count, 2)
            self.assertFalse(saw_visual)
            self.assertFalse(saw_shell)
            self.assertIn("skill=2", rendered)
            self.assertNotIn("skill=3", rendered)
            self.assertIn("FAILED=1", rendered)
            self.assertIn("DECLARED=1", rendered)
            self.assertIn("UNVERIFIED=1", rendered)
            self.assertIn("status=failed", rendered)
            self.assertIn("status=declared", rendered)
            self.assertIn("status=unverified", rendered)

            briefing = "①本轮目标：核验调度计数。⑧ FLOOR 要求 2 项，实调 2 项。" + "内部结果说明。" * 20
            with mock.patch.object(log, "_session_transcript", return_value=Path("fixture")):
                with mock.patch.object(log, "_find_briefing", return_value=briefing):
                    exact = log.verify_briefing({}, state)
                with mock.patch.object(log, "_find_briefing", return_value=briefing.replace("实调 2", "实调 3")):
                    overclaimed = log.verify_briefing({}, state)
            self.assertFalse(any(problem.startswith("V-2") for problem in exact))
            self.assertTrue(any(problem.startswith("V-2") for problem in overclaimed))

    def test_v5_reconciles_failed_unverified_declared_and_success_outcomes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-v5-outcomes-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_v5_outcomes_probe", LOG)

            raw_sid = "v5-outcomes-session"
            token = log._session_token(raw_sid)
            log.set_session({"session_id": raw_sid})
            log_file = log._current_log_file()
            state = {
                "turn_started_at": "2000-01-01T00:00:00",
                "turn_log_path": str(log_file),
                "turn_log_paths": [str(log_file)],
                "session_id": token,
                "candidates": [],
            }
            rows = [
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "failed-skill", "sid": token, "uid": "failed-1",
                 "ts": "2099-01-01T00:00:01"},
                {"event": "post-tool", "tool": "Skill", "kind": "skill",
                 "name": "failed-skill", "sid": token, "uid": "failed-1", "status": "error",
                 "ts": "2099-01-01T00:00:02"},
                {"event": "pre-tool", "tool": "Skill", "kind": "skill",
                 "name": "declared-skill", "sid": token, "uid": "declared-1",
                 "ts": "2099-01-01T00:00:03"},
                {"event": "pre-tool", "tool": "Agent", "kind": "agent",
                 "name": "unverified-agent", "sid": token, "uid": "unverified-1",
                 "ts": "2099-01-01T00:00:04"},
                {"event": "post-tool", "tool": "Agent", "kind": "agent",
                 "name": "unverified-agent", "sid": token, "uid": "unverified-1",
                 "status": "unknown", "ts": "2099-01-01T00:00:05"},
                {"event": "pre-tool", "tool": "Workflow", "kind": "workflow",
                 "name": "successful-workflow", "sid": token, "uid": "success-1",
                 "ts": "2099-01-01T00:00:06"},
                {"event": "post-tool", "tool": "Workflow", "kind": "workflow",
                 "name": "successful-workflow", "sid": token, "uid": "success-1",
                 "status": "ok", "ts": "2099-01-01T00:00:07"},
            ]
            log_file.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )

            facts = log._turn_ledger_facts(state, include_outcomes=True)
            self.assertEqual(facts[0], {"workflow:successful-workflow"})
            self.assertEqual(facts[1], 1)
            self.assertEqual(
                facts[4],
                {
                    ("skill", "failed-skill"): {"failed"},
                    ("skill", "declared-skill"): {"declared"},
                    ("agent", "unverified-agent"): {"unverified"},
                    ("workflow", "successful-workflow"): {"success"},
                },
            )

            table = (
                "\n| 12:00 | skill | failed-skill | status=failed |"
                "\n| 12:01 | skill | declared-skill | status=declared |"
                "\n| 12:02 | agent | unverified-agent | status=unverified |"
                "\n| 12:03 | workflow | successful-workflow | status=success |"
            )
            briefing = (
                "① 目标。② 改动。③ 测试。④ 原则。⑤ 门禁。⑥ 无。"
                "⑦ 纯内部改动，不适用。⑧ FLOOR 1 项 / 实调 1 项。⑨ 对表。"
                + "完整审查说明。" * 35 + table
            )
            with mock.patch.object(log, "_session_transcript", return_value=Path("fixture")):
                with mock.patch.object(log, "_find_briefing", return_value=briefing):
                    honest = log.verify_briefing({}, state)
                dishonest_brief = briefing.replace(
                    "failed-skill | status=failed", "failed-skill | status=success"
                )
                with mock.patch.object(log, "_find_briefing", return_value=dishonest_brief):
                    dishonest = log.verify_briefing({}, state)
                forged_brief = briefing.replace("failed-skill", "never-dispatched", 1)
                with mock.patch.object(log, "_find_briefing", return_value=forged_brief):
                    forged = log.verify_briefing({}, state)

            self.assertFalse(any(problem.startswith("V-5") for problem in honest))
            self.assertTrue(any(problem.startswith("V-5") for problem in dishonest))
            self.assertTrue(any(problem.startswith("V-5") for problem in forged))

    def test_shell_details_are_redacted_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-redact-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_redact_probe", LOG)

            secret = "sk-" + "A" * 24
            log.set_session({"session_id": "shell-redaction"})
            with mock.patch.object(log.sys, "argv", [str(LOG), "pre-tool"]):
                for tool in ("Bash", "PowerShell"):
                    log.handle_pre_tool(
                        {
                            "tool_name": tool,
                            "tool_input": {"command": "run --api-key " + secret},
                            "session_id": "shell-redaction",
                        }
                    )

            text = log._current_log_file().read_text(encoding="utf-8")
            rows = [json.loads(line) for line in text.splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertNotIn(secret, text)
            self.assertTrue(all("已抹除" in row.get("detail", "") for row in rows))

    def test_main_fails_open_when_input_or_session_initialization_raises(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-main-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "1"}):
                    log = load_module("supervisor_v3_log_main_probe", LOG)

            for failing_step in ("read", "session"):
                with self.subTest(failing_step=failing_step):
                    output, errors = io.StringIO(), io.StringIO()
                    read_patch = (
                        mock.patch.object(log, "read_stdin_json", side_effect=OSError("private"))
                        if failing_step == "read"
                        else mock.patch.object(
                            log, "read_stdin_json", return_value={"session_id": "fixture"}
                        )
                    )
                    session_patch = (
                        mock.patch.object(log, "set_session", side_effect=OSError("private"))
                        if failing_step == "session"
                        else contextlib.nullcontext()
                    )
                    with read_patch, session_patch, mock.patch.object(
                        log.sys, "argv", [str(LOG), "session-start"]
                    ):
                        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                            rc = log.main()

                    self.assertEqual(rc, 0)
                    self.assertEqual(output.getvalue(), "")
                    self.assertEqual(errors.getvalue(), "")


class LegacyLogRollover(unittest.TestCase):
    def test_session_transcript_rejects_unsafe_sid_before_path_or_glob_use(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-session-path-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_session_path_probe", LOG)

            base = home / ".claude" / "projects"
            base.mkdir(parents=True)
            project_dir = base / log.project_key("D:/project")
            project_dir.mkdir()
            escaped = base / "escape.jsonl"
            escaped.write_text("{}\n", encoding="utf-8")
            unsafe = {"session_id": "../escape", "cwd": "D:/project"}

            self.assertIsNone(log._session_transcript(unsafe))
            log.set_session(unsafe)
            self.assertEqual(log._current_sid, "")

            escaped.unlink()
            with mock.patch.object(Path, "glob", side_effect=AssertionError("broad glob used")) as glob:
                for unsafe_sid in ("../escape", "..\\escape", "wild*card", "range[1]", "colon:id"):
                    with self.subTest(unsafe_sid=unsafe_sid):
                        payload = {"session_id": unsafe_sid, "cwd": "D:/project"}
                        self.assertIsNone(log._session_transcript(payload))
                        log.set_session(payload)
                        self.assertEqual(log._current_sid, "")
            glob.assert_not_called()

            valid_sid = "valid-session_1"
            valid = project_dir / (valid_sid + ".jsonl")
            valid.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(Path, "home", return_value=home):
                self.assertEqual(
                    log._session_transcript({"session_id": valid_sid, "cwd": "D:/project"}),
                    valid,
                )

    def test_turn_reads_start_and_current_logs_without_cross_session_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-rollover-") as temp:
            home = Path(temp) / "home"
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                    log = load_module("supervisor_v3_log_rollover_probe", LOG)

            start_log = log.LOG_DIR / "sup-20260831.jsonl"
            current_log = log.LOG_DIR / "sup-20260901.jsonl"
            raw_sid = "rollover-host"
            log.set_session({"session_id": raw_sid})
            with mock.patch.object(log, "_current_log_file", return_value=start_log):
                with mock.patch.object(log, "append_event"), mock.patch.object(
                    log, "append_transcript", return_value=""
                ), mock.patch.object(log, "emit_full_banner"), mock.patch.object(
                    log, "plan_block", return_value=""
                ):
                    log.handle_prompt_submit(
                        {"prompt": "开发并验证日期切换", "cwd": "D:/project", "session_id": raw_sid}
                    )

            state = log.read_turn_state()
            self.assertEqual(state["turn_log_path"], str(start_log))
            self.assertEqual(state["turn_log_paths"], [str(start_log)])
            token = log._session_token(raw_sid)
            start_rows = [
                {"event": "pre-tool", "kind": "skill", "name": "rollover-skill",
                 "sid": token, "uid": "old-1", "ts": "2099-08-31T23:59:59"},
                {"event": "post-tool", "kind": "skill", "name": "rollover-skill",
                 "sid": token, "uid": "old-1", "status": "ok",
                 "ts": "2099-08-31T23:59:59"},
                {"event": "pre-tool", "kind": "skill", "name": "foreign-skill",
                 "sid": "other-session", "uid": "old-2", "ts": "2099-08-31T23:59:59"},
            ]
            current_rows = [
                {"event": "post-tool", "kind": "shell", "name": "Bash",
                 "sid": token, "uid": "new-1", "status": "ok",
                 "ts": "2099-09-01T00:00:01"},
                {"event": "pre-tool", "kind": "agent", "name": "foreign-agent",
                 "sid": "other-session", "uid": "new-2", "ts": "2099-09-01T00:00:01"},
            ]
            start_log.write_text(
                "\n".join(json.dumps(row) for row in start_rows) + "\n", encoding="utf-8"
            )
            current_log.write_text(
                "\n".join(json.dumps(row) for row in current_rows) + "\n", encoding="utf-8"
            )
            with mock.patch.object(log, "_current_log_file", return_value=current_log):
                rendered = log.render_ledger()
                skills, successful_count, saw_visual, saw_shell = log._turn_ledger_facts(state)
            self.assertIn("rollover-skill", rendered)
            self.assertIn("shell=1", rendered)
            self.assertNotIn("foreign-skill", rendered)
            self.assertNotIn("foreign-agent", rendered)
            self.assertEqual(skills, {"skill:rollover-skill"})
            self.assertEqual(successful_count, 1)
            self.assertFalse(saw_visual)
            self.assertTrue(saw_shell)

            outside = home / "outside" / "sup-20260831.jsonl"
            outside.parent.mkdir(parents=True)
            outside.write_text("{}\n", encoding="utf-8")
            poisoned = {**state, "turn_log_path": str(outside), "turn_log_paths": [str(outside)]}
            with mock.patch.object(log, "_current_log_file", return_value=current_log):
                self.assertNotIn(outside, log._turn_log_files(poisoned))
                self.assertEqual(log._turn_log_files(poisoned), [current_log])


class LegacyLogStorageFailure(unittest.TestCase):
    def test_symlinked_event_log_and_transcript_are_rejected_without_target_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-link-") as temp:
            home = Path(temp) / "home"
            home.mkdir()
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(
                    os.environ,
                    {"SUP_DRYRUN": "0", "SUPERVISOR_LEGACY_PERSIST_PROMPTS": "1"},
                    clear=False,
                ):
                    log = load_module("supervisor_v3_log_link_probe", LOG)

            outside_log = Path(temp) / "outside-log.txt"
            outside_log.write_text("unchanged-log\n", encoding="utf-8")
            log_path = log._current_log_file()
            try:
                log_path.symlink_to(outside_log)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            self.assertFalse(log.append_event({"event": "fixture"}))
            self.assertEqual(outside_log.read_text(encoding="utf-8"), "unchanged-log\n")

            project = "D:/linked-transcript"
            project_dir = log.TRANSCRIPTS_DIR / log.project_key(project)
            log._ensure_private_directory(project_dir)
            transcript = project_dir / (datetime.now().strftime("%Y-%m") + ".md")
            outside_transcript = Path(temp) / "outside-transcript.txt"
            outside_transcript.write_text("unchanged-transcript\n", encoding="utf-8")
            transcript.symlink_to(outside_transcript)
            self.assertEqual(log.append_transcript("private prompt", project, 1, True), "")
            self.assertEqual(
                outside_transcript.read_text(encoding="utf-8"),
                "unchanged-transcript\n",
            )

    def test_default_prompt_handling_persists_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-private-prompt-") as temp:
            home = Path(temp) / "home"
            home.mkdir()
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}, clear=False):
                    os.environ.pop("SUPERVISOR_LEGACY_PERSIST_PROMPTS", None)
                    log = load_module("supervisor_v3_log_private_prompt_probe", LOG)

            prompt = "private fixture words must never be stored"
            log.set_session({"session_id": "private-prompt-session"})
            with contextlib.redirect_stdout(io.StringIO()):
                log.handle_prompt_submit(
                    {"prompt": prompt, "cwd": "D:/project", "session_id": "private-prompt-session"}
                )

            persisted = b"\n".join(
                path.read_bytes()
                for path in log.SUP_HOME.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(prompt.encode("utf-8"), persisted)
            self.assertEqual(list(log.TRANSCRIPTS_DIR.rglob("*.md")), [])
            rows = [
                json.loads(line)
                for line in log._current_log_file().read_text(encoding="utf-8").splitlines()
            ]
            prompt_row = next(row for row in rows if row.get("event") == "prompt-submit")
            self.assertNotIn("prompt_head", prompt_row)
            self.assertEqual(prompt_row["prompt_len"], len(prompt))
            self.assertFalse(prompt_row["transcript"])

    @unittest.skipUnless(os.name == "posix", "POSIX owner mode semantics")
    def test_created_legacy_directories_and_files_are_owner_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-private-mode-") as temp:
            home = Path(temp) / "home"
            home.mkdir()
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}, clear=False):
                    os.environ.pop("SUPERVISOR_LEGACY_PERSIST_PROMPTS", None)
                    log = load_module("supervisor_v3_log_private_mode_probe", LOG)

            log.set_session({"session_id": "private-mode-session"})
            self.assertTrue(log.append_event({"event": "fixture"}))
            self.assertTrue(log.write_turn_state({"turn": 1}))
            for directory in (
                log.SUP_HOME,
                log.LOG_DIR,
                log.STATE_DIR,
                log.CONTEXTS_DIR,
                log.TRANSCRIPTS_DIR,
            ):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for path in (log._current_log_file(), log._state_file()):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_import_and_main_fail_open_without_claiming_failed_writes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-log-storage-") as temp:
            home = Path(temp) / "home"
            home.mkdir()
            original_mkdir = Path.mkdir

            def deny_supervisor_dir(path: Path, *args, **kwargs):
                if ".claude" in path.parts and "supervisor" in path.parts:
                    raise OSError("storage-unavailable")
                return original_mkdir(path, *args, **kwargs)

            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.object(Path, "mkdir", deny_supervisor_dir):
                    with mock.patch.dict(os.environ, {"SUP_DRYRUN": "0"}):
                        log = load_module("supervisor_v3_log_storage_probe", LOG)

            self.assertFalse(log.STORAGE_READY)
            self.assertFalse(log.append_event({"event": "fixture"}))
            self.assertFalse(log.write_turn_state({"turn": 1}))
            self.assertEqual(log.append_transcript("fixture", "D:/project", 1, True), "")

            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(log, "read_stdin_json", return_value={"session_id": "fixture-session"}):
                with mock.patch.object(log.sys, "argv", [str(LOG), "session-start"]):
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                        rc = log.main()

            self.assertEqual(rc, 0)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "")
            self.assertFalse(log.SUP_HOME.exists())


class SettingsMigration(unittest.TestCase):
    def test_only_supervisor_hooks_change_and_output_never_contains_values(self) -> None:
        configure = load_module("supervisor_v3_settings_exact_owner_probe", CONFIGURE)
        self.assertTrue(
            configure.is_supervisor_hook(
                {
                    "type": "command",
                    "command": (
                        '"/opt/python3.12" "/home/user/.claude/skills/supervisor/'
                        'scripts/sup-v3-hook.py" --event SessionStart'
                    ),
                }
            )
        )
        self.assertTrue(
            configure.is_supervisor_hook(
                {
                    "type": "command",
                    "command": (
                        'python -I -S "/home/user/.claude/skills/supervisor/'
                        'scripts/sup-v3-hook.py" --event SessionStart   '
                    ),
                }
            )
        )
        self.assertFalse(
            configure.is_supervisor_hook(
                {
                    "type": "command",
                    "command": (
                        'python"/home/user/.claude/skills/supervisor/'
                        'scripts/sup-v3-hook.py" --event SessionStart'
                    ),
                }
            )
        )
        for command in (
            'python "$(touch>/tmp/x)/.claude/skills/supervisor/scripts/sup-log.py" pre-tool',
            'python "/home/user/.claude/skills/supervisor/scripts/sup-log.py"\npre-tool',
        ):
            with self.subTest(command=command):
                self.assertFalse(
                    configure.is_supervisor_hook(
                        {"type": "command", "command": command}
                    )
                )
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-") as temp:
            home = Path(temp) / "home"
            settings_path = home / ".claude" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            fixture_secret = "fixture-secret-must-not-be-printed"
            original = {
                "opaque_private_setting": fixture_secret,
                "permissions": {"allow": ["Read"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Read", "hooks": [{"type": "command", "command": "python keep-me.py"}]},
                        {"matcher": "*", "hooks": [{"type": "command", "command": "python C:/old/.claude/skills/supervisor/scripts/sup-log.py pre-tool"}]},
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python C:/custom/sup-log.py pre-tool",
                                },
                                {
                                    "type": "command",
                                    "command": (
                                        'python "$(touch>/tmp/x)/.claude/skills/supervisor/'
                                        'scripts/sup-log.py" pre-tool'
                                    ),
                                },
                                {
                                    "type": "command",
                                    "command": (
                                        'python "/home/user/.claude/skills/supervisor/'
                                        'scripts/sup-log.py"\npre-tool'
                                    ),
                                },
                                {
                                    "type": "command",
                                    "command": (
                                        "python C:/old/.claude/skills/supervisor/scripts/"
                                        "sup-log.py pre-tool --user-extra"
                                    ),
                                },
                                {
                                    "type": "command",
                                    "command": (
                                        "python wrapper.py C:/old/.claude/skills/supervisor/"
                                        "scripts/sup-v3-hook.py --event PreToolUse"
                                    ),
                                },
                            ],
                        },
                    ],
                    "Stop": [
                        {"matcher": "Never", "hooks": [], "note": "preserve-empty-user-group"}
                    ],
                    "CustomEmpty": [],
                },
            }
            settings_path.write_text(json.dumps(original), encoding="utf-8")
            if os.name == "posix":
                settings_path.chmod(0o640)
            env = dict(os.environ, USERPROFILE=str(home), HOME=str(home), PYTHONIOENCODING="utf-8")
            first = subprocess.run(
                [sys.executable, str(CONFIGURE)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, timeout=30, check=False
            )
            self.assertEqual(first.returncode, 0)
            self.assertNotIn(fixture_secret.encode(), first.stdout + first.stderr)
            report = json.loads(first.stdout)
            expected_events = {
                "SessionStart",
                "UserPromptSubmit",
                "PreToolUse",
                "PostToolUse",
                "PostToolUseFailure",
                "Stop",
                "SubagentStart",
                "SubagentStop",
            }
            self.assertEqual(set(report["registered_events"]), expected_events)
            self.assertEqual(report["supervisor_hook_count"], len(expected_events))
            migrated = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(migrated["opaque_private_setting"], fixture_secret)
            self.assertEqual(migrated["permissions"], original["permissions"])
            self.assertIn(
                {"matcher": "Never", "hooks": [], "note": "preserve-empty-user-group"},
                migrated["hooks"]["Stop"],
            )
            self.assertEqual(migrated["hooks"]["CustomEmpty"], [])
            kept = [
                entry
                for group in migrated["hooks"]["PreToolUse"]
                for entry in group.get("hooks", [])
                if entry.get("command") == "python keep-me.py"
            ]
            self.assertEqual(len(kept), 1)
            preserved_commands = {
                entry.get("command")
                for group in migrated["hooks"]["PreToolUse"]
                for entry in group.get("hooks", [])
            }
            self.assertIn("python C:/custom/sup-log.py pre-tool", preserved_commands)
            self.assertIn(
                "python C:/old/.claude/skills/supervisor/scripts/sup-log.py pre-tool --user-extra",
                preserved_commands,
            )
            self.assertIn(
                "python wrapper.py C:/old/.claude/skills/supervisor/scripts/sup-v3-hook.py --event PreToolUse",
                preserved_commands,
            )
            self.assertIn(
                'python "$(touch>/tmp/x)/.claude/skills/supervisor/scripts/sup-log.py" pre-tool',
                preserved_commands,
            )
            self.assertIn(
                'python "/home/user/.claude/skills/supervisor/scripts/sup-log.py"\npre-tool',
                preserved_commands,
            )
            for event in expected_events:
                supervisor_entries = [
                    entry
                    for group in migrated["hooks"].get(event, [])
                    for entry in group.get("hooks", [])
                    if configure.is_supervisor_hook(entry)
                ]
                self.assertEqual(len(supervisor_entries), 1, event)
                self.assertIn(" -I -S ", supervisor_entries[0]["command"])
            self.assertNotIn(
                "python C:/old/.claude/skills/supervisor/scripts/sup-log.py pre-tool",
                {
                    command
                    for command in preserved_commands
                    if command and not command.endswith("--user-extra")
                },
            )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(settings_path.stat().st_mode), 0o640)
            first_hash = hashlib.sha256(settings_path.read_bytes()).hexdigest()
            second = subprocess.run(
                [sys.executable, str(CONFIGURE)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, timeout=30, check=False
            )
            self.assertEqual(second.returncode, 0)
            self.assertEqual(first_hash, hashlib.sha256(settings_path.read_bytes()).hexdigest())

    def test_linked_settings_file_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-link-") as temp:
            base = Path(temp)
            home = base / "home"
            settings_path = home / ".claude" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            target = base / "actual-settings.json"
            original = json.dumps({"permissions": {"allow": ["Read"]}}).encode("utf-8")
            target.write_bytes(original)
            if os.name == "posix":
                target.chmod(0o600)
            try:
                settings_path.symlink_to(target)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            env = dict(
                os.environ,
                USERPROFILE=str(home),
                HOME=str(home),
                PYTHONIOENCODING="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(CONFIGURE)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=30,
                check=False,
            )

            self.assertEqual(proc.returncode, 64)
            self.assertEqual(proc.stderr, b"")
            self.assertEqual(
                json.loads(proc.stdout),
                {"updated": False, "error": "settings_read_failed"},
            )
            self.assertTrue(settings_path.is_symlink())
            self.assertEqual(target.read_bytes(), original)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_unreadable_settings_returns_stable_invalid_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-read-") as temp:
            home = Path(temp) / "missing-home"
            env = dict(os.environ, USERPROFILE=str(home), HOME=str(home), PYTHONIOENCODING="utf-8")
            proc = subprocess.run(
                [sys.executable, str(CONFIGURE)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=30,
                check=False,
            )
        self.assertEqual(proc.returncode, 64)
        self.assertEqual(proc.stderr, b"")
        self.assertEqual(
            json.loads(proc.stdout),
            {"updated": False, "error": "settings_read_failed"},
        )

    def test_unrecognizable_emitted_command_is_rejected_before_settings_write(self) -> None:
        configure = load_module("supervisor_v3_configure_emitter_probe", CONFIGURE)
        for case in ("renamed-python", "expanding-path"):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-emitter-") as temp:
                    base = Path(temp)
                    home = base / ("home$expanded" if case == "expanding-path" else "home")
                    settings_path = home / ".claude" / "settings.json"
                    settings_path.parent.mkdir(parents=True)
                    original = json.dumps({"permissions": {"allow": ["Read"]}}).encode("utf-8")
                    settings_path.write_bytes(original)
                    executable = (
                        base / "python-custom.exe" if case == "renamed-python" else Path(sys.executable)
                    )
                    output, errors = io.StringIO(), io.StringIO()
                    with mock.patch.dict(
                        os.environ, {"USERPROFILE": str(home), "HOME": str(home)}, clear=False
                    ), mock.patch.object(configure.sys, "executable", str(executable)):
                        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                            rc = configure.main()

                    self.assertEqual(rc, 64)
                    self.assertEqual(errors.getvalue(), "")
                    self.assertEqual(
                        json.loads(output.getvalue()),
                        {"updated": False, "error": "unsupported_hook_command"},
                    )
                    self.assertEqual(settings_path.read_bytes(), original)
                    self.assertEqual(
                        list(settings_path.parent.glob(".settings.json.*.*.tmp")), []
                    )

    def test_non_list_event_hooks_are_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-shape-") as temp:
            home = Path(temp) / "home"
            settings_path = home / ".claude" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            original = {"private_setting": "keep", "hooks": {"Stop": {"matcher": "*"}}}
            settings_path.write_text(json.dumps(original), encoding="utf-8")
            before = settings_path.read_bytes()
            env = dict(os.environ, USERPROFILE=str(home), HOME=str(home), PYTHONIOENCODING="utf-8")

            proc = subprocess.run(
                [sys.executable, str(CONFIGURE)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=30,
                check=False,
            )

            self.assertEqual(proc.returncode, 64)
            self.assertEqual(proc.stderr, b"")
            self.assertEqual(json.loads(proc.stdout), {"updated": False, "error": "invalid_hooks"})
            self.assertEqual(settings_path.read_bytes(), before)
            self.assertEqual(list(settings_path.parent.glob(".settings.json.*.*.tmp")), [])

    def test_atomic_write_failures_return_stable_invalid_state_without_leak(self) -> None:
        configure = load_module("supervisor_v3_configure_write_probe", CONFIGURE)
        for failure in ("write", "replace"):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory(prefix="supervisor-v3-settings-write-") as temp:
                    home = Path(temp) / "home"
                    settings_path = home / ".claude" / "settings.json"
                    settings_path.parent.mkdir(parents=True)
                    secret = "private-path-must-not-leak"
                    settings_path.write_text(json.dumps({"private": "keep"}), encoding="utf-8")
                    before = settings_path.read_bytes()
                    output, errors = io.StringIO(), io.StringIO()
                    patcher = (
                        mock.patch.object(configure.tempfile, "mkstemp", side_effect=OSError(secret))
                        if failure == "write"
                        else mock.patch.object(configure.os, "replace", side_effect=OSError(secret))
                    )
                    with mock.patch.dict(os.environ, {"USERPROFILE": str(home), "HOME": str(home)}):
                        with patcher, contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                            rc = configure.main()

                    self.assertEqual(rc, 64)
                    self.assertEqual(errors.getvalue(), "")
                    self.assertEqual(
                        json.loads(output.getvalue()),
                        {"updated": False, "error": "settings_write_failed"},
                    )
                    self.assertNotIn(secret, output.getvalue())
                    self.assertEqual(settings_path.read_bytes(), before)
                    # durable_atomic_replace uses a hidden, collision-resistant name:
                    # .settings.json.<pid>.<ns>.tmp. Match that exact family so a
                    # replace failure cannot leave an unobserved settings copy behind.
                    self.assertEqual(
                        list(settings_path.parent.glob(".settings.json.*.*.tmp")), []
                    )


class SecretRedactionOrdering(unittest.TestCase):
    def test_anthropic_key_is_classified_before_the_broader_openai_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-redaction-home-") as temp:
            home = Path(temp) / "isolated home"
            home.mkdir()
            isolated_env = {
                "HOME": str(home),
                "USERPROFILE": str(home),
                "SUP_DRYRUN": "1",
            }
            with mock.patch.object(Path, "home", return_value=home):
                with mock.patch.dict(os.environ, isolated_env, clear=False):
                    module = load_module("supervisor_v3_sup_log_redaction", LOG)
                    # Assemble the synthetic format at runtime so repository-wide
                    # credential scans never see a token-shaped literal in this fixture.
                    token = "".join(("sk", "-", "ant", "-", "fixture" * 5))
                    cleaned, count = module.redact_secrets("credential=" + token)

                    self.assertEqual(token, "sk-" + "ant-" + "fixture" * 5)
                    self.assertEqual(count, 1)
                    self.assertNotIn(token, cleaned)
                    self.assertIn("ANTHROPIC_KEY", cleaned)
                    self.assertNotIn("OPENAI_KEY", cleaned)


class SelftestSettingsValidation(unittest.TestCase):
    def test_all_eight_registered_events_are_required_exactly_once(self) -> None:
        selftest = load_module("supervisor_v3_selftest_eight_events_probe", SELFTEST)
        expected_events = {
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "Stop",
            "SubagentStart",
            "SubagentStop",
        }
        self.assertEqual(selftest.EVENTS, expected_events)

        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-events-") as temp:
            settings = Path(temp) / "settings.json"
            adapter_path = (
                Path(temp) / ".claude" / "skills" / "supervisor" / "scripts" / "sup-v3-hook.py"
            )
            adapter_path.parent.mkdir(parents=True)
            adapter_path.write_text("# fixture\n", encoding="utf-8")
            hooks = {
                event: [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": (
                                    f'"{sys.executable}" -I -S "{adapter_path}" --event {event}'
                                ),
                                "timeout": 10,
                            }
                        ],
                    }
                ]
                for event in expected_events
            }
            settings.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(selftest, "SETTINGS", settings), mock.patch.object(
                selftest, "ADAPTER", adapter_path
            ):
                with contextlib.redirect_stdout(output):
                    ok = selftest._settings_check()

        self.assertTrue(ok)
        self.assertIn("events=8, exactly_one=True", output.getvalue())

    def test_legacy_unisolated_v3_hooks_do_not_pass_current_topology(self) -> None:
        selftest = load_module("supervisor_v3_selftest_legacy_hooks_probe", SELFTEST)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-legacy-") as temp:
            settings = Path(temp) / "settings.json"
            adapter_path = (
                Path(temp) / ".claude" / "skills" / "supervisor" / "scripts" / "sup-v3-hook.py"
            )
            adapter_path.parent.mkdir(parents=True)
            adapter_path.write_text("# fixture\n", encoding="utf-8")
            hooks = {
                event: [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f'"{sys.executable}" "{adapter_path}" --event {event}',
                                "timeout": 10,
                            }
                        ],
                    }
                ]
                for event in selftest.EVENTS
            }
            settings.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(selftest, "SETTINGS", settings):
                with contextlib.redirect_stdout(output):
                    ok = selftest._settings_check()

        self.assertFalse(ok)
        self.assertIn("exactly_one=False", output.getvalue())

    def test_mixed_current_and_legacy_hooks_do_not_pass_current_topology(self) -> None:
        selftest = load_module("supervisor_v3_selftest_mixed_hooks_probe", SELFTEST)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-mixed-") as temp:
            settings = Path(temp) / "settings.json"
            adapter_path = (
                Path(temp) / ".claude" / "skills" / "supervisor" / "scripts" / "sup-v3-hook.py"
            )
            adapter_path.parent.mkdir(parents=True)
            adapter_path.write_text("# fixture\n", encoding="utf-8")
            hooks = {
                event: [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f'"{sys.executable}" -I -S "{adapter_path}" --event {event}',
                                "timeout": 10,
                            }
                        ],
                    },
                    {
                        "matcher": "Never",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f'"{sys.executable}" "{adapter_path}" --event {event}',
                                "timeout": 10,
                            }
                        ],
                    },
                ]
                for event in selftest.EVENTS
            }
            settings.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
            with mock.patch.object(selftest, "SETTINGS", settings), mock.patch.object(
                selftest, "ADAPTER", adapter_path
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    ok = selftest._settings_check()

        self.assertFalse(ok)

    def test_malformed_hooks_type_returns_stable_fail_line(self) -> None:
        selftest = load_module("supervisor_v3_selftest_settings_probe", SELFTEST)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-settings-") as temp:
            settings = Path(temp) / "settings.json"
            settings.write_text(json.dumps({"hooks": []}), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(selftest, "SETTINGS", settings):
                with contextlib.redirect_stdout(output):
                    ok = selftest._settings_check()

        self.assertFalse(ok)
        self.assertIn("FAIL settings hook topology", output.getvalue())

    def test_invalid_utf8_settings_returns_stable_fail_result(self) -> None:
        selftest = load_module("supervisor_v3_selftest_unicode_probe", SELFTEST)
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-unicode-") as temp:
            settings = Path(temp) / "settings.json"
            settings.write_bytes(b"\xff\xfe\xfa")
            output = io.StringIO()
            with mock.patch.object(selftest, "SETTINGS", settings):
                with contextlib.redirect_stdout(output):
                    ok = selftest._settings_check()

        self.assertFalse(ok)
        self.assertIn("FAIL settings hook topology", output.getvalue())
        self.assertIn("events=0, exactly_one=False", output.getvalue())

    def test_unmeasurable_suite_is_reported_unavailable_and_fails_gate(self) -> None:
        selftest = load_module("supervisor_v3_selftest_unavailable_probe", SELFTEST)
        completed = subprocess.CompletedProcess(
            args=["fixture-suite"], returncode=77, stdout=b"UNMEASURABLE fixture\n"
        )
        output = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="supervisor-v3-run-core-") as temp:
            core = Path(temp).resolve()
            with mock.patch.object(selftest.subprocess, "run", return_value=completed):
                with contextlib.redirect_stdout(output):
                    ok, text = selftest._run(
                        "legacy regression fixture", ["fixture-suite"], {}, core=core
                    )

        self.assertFalse(ok)
        self.assertIn("UNMEASURABLE", text)
        self.assertIn("UNAVAILABLE legacy regression fixture (exit=77)", output.getvalue())
        self.assertNotIn("PASS legacy regression fixture", output.getvalue())

    def test_every_child_process_uses_resolved_core_from_external_unicode_cwd(self) -> None:
        selftest = load_module("supervisor_v3_selftest_child_cwd_probe", SELFTEST)
        completed = subprocess.CompletedProcess(args=["fixture"], returncode=0, stdout=b"")

        with tempfile.TemporaryDirectory(prefix="supervisor-v3-selftest-cwd-") as temp:
            base = Path(temp)
            core = (base / "trusted core 中文").resolve()
            ambient = (base / "external cwd 外部").resolve()
            core.mkdir()
            ambient.mkdir()
            resolved = (
                core,
                "9.9.9",
                {
                    "source": "active-pointer-v4-bundle",
                    "declared_version": "9.9.9",
                    "declared_path": str(core),
                },
            )
            original_cwd = Path.cwd()
            calls: list[Path] = []

            def record_run(*args, **kwargs):
                calls.append(Path(kwargs["cwd"]).resolve())
                return completed

            try:
                os.chdir(ambient)
                with mock.patch.object(selftest, "_resolve_test_core", return_value=resolved):
                    with mock.patch.object(selftest, "_freeze_test_runtime", return_value={}):
                        with mock.patch.object(selftest, "_materialize_test_core", return_value=core):
                            with mock.patch.object(selftest, "_settings_check", return_value=True):
                                with mock.patch.object(selftest, "_discover_import_check", return_value=True):
                                    with mock.patch.object(
                                        selftest.subprocess, "run", side_effect=record_run
                                    ):
                                        with contextlib.redirect_stdout(io.StringIO()):
                                            rc = selftest.main()
            finally:
                os.chdir(original_cwd)

        self.assertEqual(rc, 0)
        # Adapter harness + shared-core selftest + pytest collection, plus
        # every required historical regression suite.
        self.assertEqual(len(calls), 3 + len(selftest.REQUIRED_LEGACY_SUITES))
        self.assertTrue(calls)
        self.assertEqual(set(calls), {core})
        self.assertNotIn(ambient, calls)


if __name__ == "__main__":
    unittest.main()
