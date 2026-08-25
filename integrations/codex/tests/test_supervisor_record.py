from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


CODEX_ROOT = Path(__file__).resolve().parents[1]
RECORD_SCRIPT = CODEX_ROOT / "scripts" / "supervisor-record.ps1"


def _powershell() -> str:
    executable = (
        shutil.which("powershell.exe")
        or shutil.which("pwsh.exe")
        or shutil.which("pwsh")
        or shutil.which("powershell")
    )
    if executable is None:
        pytest.skip("PowerShell is required for the Codex adapter regression test")
    return executable


def test_record_adapter_wraps_raw_record_in_event_envelope(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(RECORD_SCRIPT, scripts / RECORD_SCRIPT.name)
    capture_file = tmp_path / "capture.json"
    event_stub = scripts / "supervisor-event.ps1"
    event_stub.write_text(
        """
param(
    [string]$Workspace,
    [string]$RoundId,
    [string]$SessionId,
    [string]$Event,
    [string]$Actor,
    [string]$DataJson,
    [string]$DataFile
)
$capture = [ordered]@{
    workspace = $Workspace
    round_id = $RoundId
    session_id = $SessionId
    event = $Event
    actor = $Actor
    data_json = $DataJson
    data_file = $DataFile
}
[System.IO.File]::WriteAllText(
    $env:SUPERVISOR_RECORD_TEST_CAPTURE,
    ($capture | ConvertTo-Json -Compress),
    (New-Object System.Text.UTF8Encoding($false))
)
exit 0
""".strip()
        + "\n",
        encoding="utf-8",
    )
    raw_record = {
        "task_id": "task-synthetic-1",
        "status": "doing",
        "metadata": {"criterion_ids": ["criterion-synthetic-1"]},
    }
    record_file = tmp_path / "record.json"
    record_file.write_text(json.dumps(raw_record), encoding="utf-8")
    env = dict(__import__("os").environ)
    env["SUPERVISOR_RECORD_TEST_CAPTURE"] = str(capture_file)

    completed = subprocess.run(
        [
            _powershell(),
            "-NoLogo",
            "-NoProfile",
            "-File",
            str(scripts / RECORD_SCRIPT.name),
            "-RecordType",
            "task",
            "-RecordFile",
            str(record_file),
            "-Workspace",
            str(tmp_path),
            "-RoundId",
            "round-synthetic-1",
            "-SessionId",
            "session-synthetic-1",
            "-Actor",
            "codex-test",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    captured = json.loads(capture_file.read_text(encoding="utf-8"))
    assert captured["event"] == "task_record"
    assert captured["data_file"] == ""
    assert json.loads(captured["data_json"]) == {"record": raw_record}

