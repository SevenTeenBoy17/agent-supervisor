#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = 'latest',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$ProjectFile = '',
    [switch]$Json
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"validate-adapter-failure"}')
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
$projectResolution = Resolve-AgentSupervisorProjectFile -Workspace $workspacePath -ProjectFile $ProjectFile -Explicit:($PSBoundParameters.ContainsKey('ProjectFile'))
if (-not $projectResolution.Valid) {
    [Console]::Error.WriteLine([string]$projectResolution.Message)
    exit 64
}
$ProjectFile = [string]$projectResolution.Path
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
$argsList = @('validate', '--runtime', 'codex', '--workspace', $workspacePath, '--session', $SessionId, '--round', $RoundId)
if ($projectResolution.Present) { $argsList += @('--project-file', $ProjectFile) }
if ($Json) { $argsList += '--json' }
$invocation = Invoke-AgentSupervisorPython -Command $pythonCommand -PrefixArgs $pythonPrefix -Arguments (@('-E', '-P', '-X', 'utf8', $launcherPath) + $argsList) -Operation 'validate' -WorkingDirectory $coreRoot -IsolatedEnvironment
$code = [int]$invocation.ExitCode
$global:LASTEXITCODE = 0
exit $code
