#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = 'latest',
    [string]$Reason = 'phase-transition',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$Output = ''
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"handoff-adapter-failure"}')
    exit 4
}

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'supervisor-core.ps1')
$workspacePath = Resolve-AgentSupervisorWorkspace -Workspace $Workspace
if ([string]::IsNullOrWhiteSpace($workspacePath)) {
    [Console]::Error.WriteLine('Workspace must resolve to an existing directory.')
    exit 64
}
if ([string]::IsNullOrWhiteSpace($SessionId)) {
    [Console]::Error.WriteLine('A stable SessionId or CODEX_THREAD_ID is required.')
    exit 64
}
if ([string]::IsNullOrWhiteSpace($Output)) {
    $sessionBytes = [Text.Encoding]::UTF8.GetBytes($SessionId)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $sessionHash = ([BitConverter]::ToString($hasher.ComputeHash($sessionBytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
    $handoffRoot = Join-Path (Join-Path $workspacePath '.agent-supervisor') 'handoffs'
    $Output = Join-Path (Join-Path $handoffRoot $sessionHash) 'latest.md'
}
$coreRoot = Get-AgentSupervisorCoreRoot
$launcherPath = Resolve-AgentSupervisorTrustedLauncherPath -CoreRoot $coreRoot
if ([string]::IsNullOrWhiteSpace($launcherPath)) {
    [Console]::Error.WriteLine("Supervisor v3 core is unavailable at $coreRoot")
    exit 4
}
$python = Get-AgentSupervisorPythonCommand
if ($null -eq $python) {
    [Console]::Error.WriteLine('A usable Python 3.11+ interpreter is required; Windows Store aliases are not accepted.')
    exit 4
}
$pythonCommand = [string]$python.Command
$pythonPrefix = @($python.PrefixArgs)
$eventArgs = @('-E', '-P', '-X', 'utf8', $launcherPath, 'event', '--runtime', 'codex', '--workspace', $workspacePath, '--session', $SessionId, '--round', $RoundId, '--event-type', 'handoff_requested', '--phase', 'context-preservation', '--status', 'requested', '--summary', $Reason, '--actor', 'codex-adapter')
$eventInvocation = Invoke-AgentSupervisorPython -Command $pythonCommand -PrefixArgs $pythonPrefix -Arguments $eventArgs -Operation 'handoff-event' -WorkingDirectory $coreRoot -SuppressOutput -IsolatedEnvironment
$eventCode = [int]$eventInvocation.ExitCode
if ($eventCode -ne 0) {
    [Console]::Error.WriteLine('Supervisor handoff reason event could not be recorded.')
    exit $eventCode
}
$queryArgs = @('-E', '-P', '-X', 'utf8', $launcherPath, 'query', '--runtime', 'codex', '--workspace', $workspacePath, '--session', $SessionId, '--round', $RoundId, '--format', 'handoff', '--output', $Output)
$queryInvocation = Invoke-AgentSupervisorPython -Command $pythonCommand -PrefixArgs $pythonPrefix -Arguments $queryArgs -Operation 'handoff-query' -WorkingDirectory $coreRoot -IsolatedEnvironment
$code = [int]$queryInvocation.ExitCode
$global:LASTEXITCODE = 0
exit $code
