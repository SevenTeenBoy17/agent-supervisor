from __future__ import annotations

import json
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


HERE = Path(__file__).resolve().parent
GATE = HERE.parent / "scripts" / "supervisor-gate.ps1"
CORE = HERE.parent / "scripts" / "supervisor-core.ps1"
HOOK = HERE.parent / "scripts" / "codex-supervisor-hook.py"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")


@unittest.skipUnless(POWERSHELL, "PowerShell host is required")
class SupervisorGateIsolation(unittest.TestCase):
    def test_event_exit_is_isolated_and_result_streams_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-gate-exit-") as temp:
            root = Path(temp) / "中文 gate fixture"
            root.mkdir()
            gate = root / "supervisor-gate.ps1"
            event = root / "supervisor-event.ps1"
            core = root / "supervisor-core.ps1"
            gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
            core.write_text(
                (HERE.parent / "scripts" / "supervisor-core.ps1").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            event.write_text(
                """param(
    [string]$Workspace, [string]$RoundId, [string]$SessionId,
    [string]$Event, [string]$Actor, [string]$DataJson
)
$payload = $DataJson | ConvertFrom-Json
if ([string]$payload.record.gate_id -ne 'fixture.gate') { exit 64 }
Write-Output '{\"status\":\"incomplete\",\"gate\":\"fixture.gate\"}'
[Console]::Error.WriteLine('{\"audit\":\"degraded-fixture\"}')
exit 2
""",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-File", str(gate), "-GateId", "fixture.gate",
                    "-CriterionId", "criterion-1", "-CollectorGroup", "reviewer",
                    "-Workspace", str(root), "-RoundId", "round-1",
                    "-SessionId", "session-1",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn('"gate":"fixture.gate"', completed.stdout)
            self.assertIn('"audit":"degraded-fixture"', completed.stderr)

    def test_terminating_child_failure_is_redacted_and_normalized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-gate-throw-") as temp:
            root = Path(temp) / "中文 gate failure"
            root.mkdir()
            gate = root / "supervisor-gate.ps1"
            event = root / "supervisor-event.ps1"
            core = root / "supervisor-core.ps1"
            gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
            core.write_text(
                (HERE.parent / "scripts" / "supervisor-core.ps1").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            secret = "R21_SECRET_SENTINEL_MUST_NOT_LEAK"
            event.write_text(
                f"""param(
    [string]$Workspace, [string]$RoundId, [string]$SessionId,
    [string]$Event, [string]$Actor, [string]$DataJson
)
Write-Output '{secret}'
[Console]::Error.WriteLine('{secret}')
throw '{secret}'
""",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-File", str(gate), "-GateId", "fixture.gate",
                    "-CriterionId", "criterion-1", "-CollectorGroup", "reviewer",
                    "-Workspace", str(root), "-RoundId", "round-1",
                    "-SessionId", "session-1",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=30,
                check=False,
            )

            combined = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 4)
            self.assertNotIn(secret, combined)
            self.assertIn('"reason":"gate-adapter-failure"', completed.stderr)
            self.assertFalse(list(Path(temp).glob("agent-supervisor-gate-*.json")))

    def test_gate_source_uses_child_host_and_file_bound_payload(self) -> None:
        source = GATE.read_text(encoding="utf-8")
        self.assertIn("$startInfo.FileName = $hostExecutable", source)
        self.assertIn("$startInfo.RedirectStandardError = $true", source)
        self.assertIn("'-EncodedCommand', $encodedRunner", source)
        self.assertIn("-DataJson $env:AGENT_SUPERVISOR_GATE_DATA", source)
        self.assertNotIn("& $eventScript -Workspace", source)

    def test_windows_event_child_bypasses_policy_for_desktop_and_core_hosts(self) -> None:
        source = GATE.read_text(encoding="utf-8-sig")
        self.assertIn("$env:OS -eq 'Windows_NT'", source)
        self.assertIn("@('-ExecutionPolicy', 'Bypass')", source)
        self.assertNotIn("$PSVersionTable.PSEdition -eq 'Desktop'", source)
        if os.name != "nt":
            return

        hosts = []
        for name in ("powershell.exe", "pwsh.exe", "pwsh"):
            resolved = shutil.which(name)
            if resolved and resolved.casefold() not in {item.casefold() for item in hosts}:
                hosts.append(resolved)
        self.assertTrue(hosts)
        for host in hosts:
            with self.subTest(host=host):
                with tempfile.TemporaryDirectory(prefix="supervisor-gate-policy-") as temp:
                    root = Path(temp) / "policy child"
                    root.mkdir()
                    staged_gate = root / "supervisor-gate.ps1"
                    staged_event = root / "supervisor-event.ps1"
                    capture = root / "child-argv.json"
                    staged_gate.write_text(GATE.read_text(encoding="utf-8-sig"), encoding="utf-8")
                    staged_event.write_text(
                        "param([string]$Workspace,[string]$RoundId,[string]$SessionId,"
                        "[string]$Event,[string]$Actor,[string]$DataJson)\n"
                        "[IO.File]::WriteAllText($env:R25_GATE_CHILD_ARGV,"
                        "([Environment]::GetCommandLineArgs() | ConvertTo-Json -Compress))\n"
                        "exit 0\n",
                        encoding="utf-8",
                    )
                    environment = os.environ.copy()
                    environment["R25_GATE_CHILD_ARGV"] = str(capture)
                    completed = subprocess.run(
                        [
                            host, "-NoLogo", "-NoProfile", "-NonInteractive",
                            "-File", str(staged_gate), "-GateId", "policy.fixture",
                            "-CriterionId", "criterion-1", "-CollectorGroup", "reviewer",
                        ],
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        capture_output=True,
                        env=environment,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    child_argv = [str(value).casefold() for value in json.loads(
                        capture.read_text(encoding="utf-8-sig")
                    )]
                    self.assertIn("-executionpolicy", child_argv)
                    self.assertIn("bypass", child_argv)

    def test_process_tree_termination_and_runtime_revalidation_are_bounded(self) -> None:
        gate_source = GATE.read_text(encoding="utf-8-sig")
        core_source = CORE.read_text(encoding="utf-8-sig")
        self.assertIn("$killer.WaitForExit(5000)", gate_source)
        self.assertIn("$Process.WaitForExit(2000)", gate_source)
        self.assertNotIn("Start-Process", gate_source)
        self.assertIn("-AllowedRoots $allowedRoots", core_source)
        self.assertNotIn("-AllowedRoots @($runtimeRoot)", core_source)
        self.assertIn("Registry::HKEY_LOCAL_MACHINE\\Software\\Python\\PythonCore", core_source)

    def test_python_allowed_roots_exclude_the_profile_but_keep_known_user_install_root(self) -> None:
        if os.name != "nt":
            return
        with tempfile.TemporaryDirectory(prefix="supervisor-python-roots-") as temp:
            profile = Path(temp) / "profile"
            known_install = profile / "AppData" / "Local" / "Programs" / "Python"
            known_install.mkdir(parents=True)
            profile_literal = str(profile).replace("'", "''")
            harness = (
                ". '" + str(CORE).replace("'", "''") + "'\n"
                "$env:USERPROFILE = '" + profile_literal + "'\n"
                "Remove-Item Env:HOME -ErrorAction SilentlyContinue\n"
                "@(Get-AgentSupervisorPythonAllowedRoots) | ConvertTo-Json -Compress\n"
            )
            completed = subprocess.run(
                [
                    str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command", harness,
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            roots = json.loads(completed.stdout)
            if isinstance(roots, str):
                roots = [roots]
            normalized = {str(Path(value)).casefold() for value in roots}
            self.assertNotIn(str(profile).casefold(), normalized)
            self.assertIn(str(known_install).casefold(), normalized)

    def test_python_allowed_roots_reject_system_root_but_keep_system_installs_and_launcher(self) -> None:
        if os.name != "nt":
            return
        with tempfile.TemporaryDirectory(prefix="supervisor-system-root-") as temp:
            fixture = Path(temp)
            fake_system_root = fixture / "Windows"
            malicious_python = fake_system_root / "python.exe"
            legitimate_root = fixture / "Program Files"
            legitimate_python = legitimate_root / "Python" / "python.exe"
            malicious_python.parent.mkdir(parents=True)
            legitimate_python.parent.mkdir(parents=True)
            malicious_python.write_bytes(b"not an interpreter")
            legitimate_python.write_bytes(b"not an interpreter")
            harness = (
                ". '" + str(CORE).replace("'", "''") + "'\n"
                "$previousSystemRoot = $env:SystemRoot\n"
                "$env:SystemRoot = '" + str(fake_system_root).replace("'", "''") + "'\n"
                "$env:ProgramFiles = '" + str(legitimate_root).replace("'", "''") + "'\n"
                "$roots = @(Get-AgentSupervisorPythonAllowedRoots)\n"
                "$malicious = Resolve-AgentSupervisorTrustedPythonPath "
                "-Candidate '" + str(malicious_python).replace("'", "''") + "' "
                "-AllowedRoots $roots -KnownExecutables @()\n"
                "$legitimate = Resolve-AgentSupervisorTrustedPythonPath "
                "-Candidate '" + str(legitimate_python).replace("'", "''") + "' "
                "-AllowedRoots $roots -KnownExecutables @()\n"
                "$env:SystemRoot = $previousSystemRoot\n"
                "[pscustomobject]@{ roots = $roots; malicious = $malicious; "
                "legitimate = $legitimate } | ConvertTo-Json -Compress\n"
            )
            completed = subprocess.run(
                [
                    str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command", harness,
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            normalized = {str(Path(value)).casefold() for value in result["roots"]}
            self.assertNotIn(str(fake_system_root).casefold(), normalized)
            self.assertIsNone(result["malicious"])
            self.assertEqual(
                str(legitimate_python).casefold(),
                str(result["legitimate"]).casefold(),
            )

        launcher_harness = (
            ". '" + str(CORE).replace("'", "''") + "'\n"
            "$resolved = Get-AgentSupervisorPythonCommand\n"
            "if ($null -eq $resolved) { exit 2 }\n"
            "$resolved | ConvertTo-Json -Compress\n"
        )
        launcher = subprocess.run(
            [
                str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-Command", launcher_harness,
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(launcher.returncode, 0, launcher.stderr)
        resolved_launcher = json.loads(launcher.stdout)
        self.assertTrue(Path(resolved_launcher["Command"]).is_file())

    def test_unwritable_degraded_marker_is_observable_and_secret_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="supervisor-marker-failure-") as temp:
            occupied_home = Path(temp) / "not-a-directory"
            occupied_home.write_text("occupied", encoding="ascii")
            environment = os.environ.copy()
            environment.update({
                "USERPROFILE": str(occupied_home),
                "HOME": str(occupied_home),
                "AGENT_SUPERVISOR_HOME": str(occupied_home / "missing-core"),
            })
            secret = "R23_MARKER_SECRET_SENTINEL"
            completed = subprocess.run(
                [sys.executable, str(HOOK), "--event", "PreToolUse"],
                input=json.dumps({"session_id": "marker-failure", "cwd": secret}),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                env=environment,
                timeout=20,
                check=False,
            )
            output = json.loads(completed.stdout)
            combined = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(set(output), {"systemMessage"})
            self.assertIn("could not be persisted", output["systemMessage"])
            self.assertNotIn(secret, combined)

    def test_marker_lock_collision_retries_once_with_full_bounded_budget(self) -> None:
        spec = importlib.util.spec_from_file_location("r23_codex_hook", HOOK)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader if spec is not None else None)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        observed_timeouts = []

        def reject_marker(_path, _record, _recorded_at, lock_timeout_seconds=0.25):
            observed_timeouts.append(lock_timeout_seconds)
            return False

        with tempfile.TemporaryDirectory(prefix="supervisor-marker-retry-") as temp:
            with mock.patch.dict(os.environ, {"USERPROFILE": temp, "HOME": temp}):
                with mock.patch.object(module, "_write_degraded_marker", side_effect=reject_marker):
                    with mock.patch.object(module, "_acquire_lock", return_value=None):
                        recorded = module._record_degraded(
                            "PreToolUse", {"session_id": "retry-fixture"}, "core_timeout", 2
                        )

        self.assertFalse(recorded)
        self.assertEqual(observed_timeouts, [0.25, module.MARKER_LOCK_RETRY_SECONDS])
        self.assertGreaterEqual(module.MARKER_LOCK_RETRY_SECONDS, 1.0)


if __name__ == "__main__":
    unittest.main()
