#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = 'latest',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$ProjectFile = '',
    [Nullable[int]]$StopAttempt = $null
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"turn-ended-adapter-failure"}')
    exit 4
}

$ErrorActionPreference = 'Stop'
$finalizer = Join-Path $PSScriptRoot 'supervisor-finalize.ps1'
$invoke = @{
    Workspace = $Workspace
    RoundId = $RoundId
    SessionId = $SessionId
}
if (-not [string]::IsNullOrWhiteSpace($ProjectFile)) { $invoke.ProjectFile = $ProjectFile }
if ($null -ne $StopAttempt) { $invoke.StopAttempt = $StopAttempt }
$global:LASTEXITCODE = $null
& $finalizer @invoke
$finalizerExitCode = $global:LASTEXITCODE
[int]$parsedExitCode = 0
if ($null -eq $finalizerExitCode -or -not [int]::TryParse([string]$finalizerExitCode, [ref]$parsedExitCode)) {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"turn-ended-adapter-failure"}')
    exit 4
}
exit $parsedExitCode
