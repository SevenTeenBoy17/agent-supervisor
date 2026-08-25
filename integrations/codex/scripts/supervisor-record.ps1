#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('task', 'review-finalize', 'waiver', 'changes', 'spec', 'intent', 'evidence-import')]
    [string]$RecordType,
    [Parameter(Mandatory = $true)]
    [string]$RecordFile,
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = 'latest',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$Actor = 'codex'
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"record-adapter-failure","message":"Supervisor record event recording failed; state is degraded."}')
    exit 4
}

$ErrorActionPreference = 'Stop'
$events = @{
    task = 'task_record'
    'review-finalize' = 'review_finalize'
    waiver = 'waiver_record'
    changes = 'changes_record'
    spec = 'spec_record'
    intent = 'intent_disposition'
    'evidence-import' = 'evidence_record'
}
$eventScript = Join-Path $PSScriptRoot 'supervisor-event.ps1'
$recordData = Get-Content -Raw -LiteralPath $RecordFile | ConvertFrom-Json
$recordEnvelope = [ordered]@{ record = $recordData }
$recordEnvelopeJson = $recordEnvelope | ConvertTo-Json -Depth 100 -Compress
$global:LASTEXITCODE = $null
try {
    & $eventScript -Workspace $Workspace -RoundId $RoundId -SessionId $SessionId -Event $events[$RecordType] -Actor $Actor -DataJson $recordEnvelopeJson
    $eventExitCode = $global:LASTEXITCODE
} catch {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"record-adapter-failure","message":"Supervisor record event recording failed; state is degraded."}')
    exit 4
}

[int]$parsedExitCode = 0
if ($null -eq $eventExitCode -or -not [int]::TryParse([string]$eventExitCode, [ref]$parsedExitCode)) {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"record-adapter-failure","message":"Supervisor record event recording failed; exit status is unavailable and state is degraded."}')
    exit 4
}
exit $parsedExitCode
