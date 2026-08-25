#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = "",
    [string]$Message = "Supervisor round bootstrap",
    [Parameter(Mandatory = $true)]
    [ValidateSet('continue', 'extend', 'replace')]
    [string]$ChangeMode,
    [string]$ExecutionMode = '',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$ProjectFile = "",
    [string]$GoalFile = "",
    [string]$CriteriaFile = "",
    [string]$IntentsFile = "",
    [switch]$Shadow
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"bootstrap-adapter-failure"}')
    exit 4
}

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'supervisor-core.ps1')
$workspacePath = Resolve-AgentSupervisorWorkspace -Workspace $Workspace
if ([string]::IsNullOrWhiteSpace($workspacePath)) {
    [Console]::Error.WriteLine('Workspace must resolve to an existing directory.')
    exit 64
}
if ([string]::IsNullOrWhiteSpace($RoundId)) {
    $RoundId = 'round-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmss.fffffffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
}
if ([string]::IsNullOrWhiteSpace($SessionId)) {
    [Console]::Error.WriteLine('A stable SessionId or CODEX_THREAD_ID is required; PID fallbacks split one round across processes.')
    exit 64
}
$projectResolution = Resolve-AgentSupervisorProjectFile -Workspace $workspacePath -ProjectFile $ProjectFile -Explicit:($PSBoundParameters.ContainsKey('ProjectFile'))
if (-not $projectResolution.Valid) {
    [Console]::Error.WriteLine([string]$projectResolution.Message)
    exit 64
}
$ProjectFile = [string]$projectResolution.Path
$executionModeLoadedFromProject = $false
if ([string]::IsNullOrWhiteSpace($ExecutionMode) -and $projectResolution.Present) {
    try {
        $projectConfig = Get-Content -LiteralPath $ProjectFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $ExecutionMode = [string]$projectConfig.execution_mode
        $executionModeLoadedFromProject = $true
    } catch {
        [Console]::Error.WriteLine('ProjectFile must contain valid JSON before Supervisor bootstrap can continue.')
        exit 64
    }
}
if ([string]::IsNullOrWhiteSpace($ExecutionMode)) { $ExecutionMode = 'warn' }
if (@('observe', 'warn', 'enforce') -notcontains $ExecutionMode) {
    if ($executionModeLoadedFromProject) {
        [Console]::Error.WriteLine("ProjectFile execution_mode in project.json must be observe, warn, or enforce: $ProjectFile")
    } else {
        [Console]::Error.WriteLine('ExecutionMode must be observe, warn, or enforce')
    }
    exit 64
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
$argsList = @(
    'start', '--runtime', 'codex', '--workspace', $workspacePath,
    '--session', $SessionId, '--round', $RoundId, '--message', $Message,
    '--change-mode', $ChangeMode, '--execution-mode', $ExecutionMode
)
foreach ($inputFile in @($GoalFile, $CriteriaFile, $IntentsFile)) {
    if (-not [string]::IsNullOrWhiteSpace($inputFile) -and -not (Test-Path -LiteralPath $inputFile -PathType Leaf)) {
        [Console]::Error.WriteLine("Structured Supervisor input file not found: $inputFile")
        exit 64
    }
}
if (-not [string]::IsNullOrWhiteSpace($GoalFile)) { $argsList += @('--goal-json', (Resolve-Path -LiteralPath $GoalFile).Path) }
if (-not [string]::IsNullOrWhiteSpace($CriteriaFile)) { $argsList += @('--criteria-json', (Resolve-Path -LiteralPath $CriteriaFile).Path) }
if (-not [string]::IsNullOrWhiteSpace($IntentsFile)) { $argsList += @('--intents-json', (Resolve-Path -LiteralPath $IntentsFile).Path) }
if ($projectResolution.Present) { $argsList += @('--project-file', $ProjectFile) }
if ($Shadow) { $argsList += '--shadow' }
$invocation = Invoke-AgentSupervisorPython -Command $pythonCommand -PrefixArgs $pythonPrefix -Arguments (@('-E', '-P', '-X', 'utf8', $launcherPath) + $argsList) -Operation 'bootstrap' -WorkingDirectory $coreRoot -IsolatedEnvironment
$code = [int]$invocation.ExitCode
$global:LASTEXITCODE = 0
exit $code
