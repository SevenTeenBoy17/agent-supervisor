#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = "",
    [Alias('Type')][string]$Event = 'note',
    [string]$Phase = '',
    [string]$Status = 'info',
    [string]$Skill = '',
    [string]$Plugin = '',
    [string]$Command = '',
    [string]$Message = '',
    [string]$Actor = 'codex',
    [string]$ResponsibilityGroup = '',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    [string]$InvocationId = '',
    [string]$Result = '',
    [string]$DataJson = '',
    [string]$DataFile = '',
    [string]$ProjectFile = ''
)

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"event-adapter-failure"}')
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
if ([string]::IsNullOrWhiteSpace($RoundId)) { $RoundId = 'latest' }
if (-not [string]::IsNullOrWhiteSpace($DataJson) -and -not [string]::IsNullOrWhiteSpace($DataFile)) {
    [Console]::Error.WriteLine('Use only one of DataJson or DataFile')
    exit 64
}
$isCoreOwnedGateEvent = [string]::Equals($Event, 'gate_run', [StringComparison]::OrdinalIgnoreCase)
if ($isCoreOwnedGateEvent -and
    ($PSBoundParameters.ContainsKey('Actor') -or $PSBoundParameters.ContainsKey('ResponsibilityGroup'))) {
    [Console]::Error.WriteLine('Gate identity is minted by the trusted core and cannot be supplied by the caller.')
    exit 64
}
if (-not [string]::IsNullOrWhiteSpace($DataFile)) {
    if (-not (Test-Path -LiteralPath $DataFile -PathType Leaf)) {
        [Console]::Error.WriteLine('DataFile must resolve to an existing file.')
        exit 64
    }
    $DataFile = (Resolve-Path -LiteralPath $DataFile -ErrorAction Stop).Path
}
$projectResolution = Resolve-AgentSupervisorProjectFile -Workspace $workspacePath -ProjectFile $ProjectFile -Explicit:($PSBoundParameters.ContainsKey('ProjectFile'))
if (-not $projectResolution.Valid) {
    [Console]::Error.WriteLine([string]$projectResolution.Message)
    exit 64
}
$ProjectFile = [string]$projectResolution.Path
$capability = (@($Skill, $Plugin) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ':'
$commandCategory = ConvertTo-AgentSupervisorCommandCategory -Command $Command

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
    'event', '--runtime', 'codex', '--workspace', $workspacePath,
    '--session', $SessionId, '--round', $RoundId, '--event-type', $Event,
    '--phase', $Phase, '--status', $Status, '--capability', $capability,
    '--command-category', $commandCategory, '--summary', $Message
)
if (-not $isCoreOwnedGateEvent) { $argsList += @('--actor', $Actor) }
if ($InvocationId) { $argsList += @('--invocation-id', $InvocationId) }
if (-not $isCoreOwnedGateEvent -and $ResponsibilityGroup) {
    $argsList += @('--responsibility-group', $ResponsibilityGroup)
}
if ($Result) { $argsList += @('--result', $Result) }
if ($DataFile) { $argsList += @('--data-json', $DataFile) }
elseif ($DataJson) { $argsList += @('--data-json', $DataJson) }
if ($projectResolution.Present) { $argsList += @('--project-file', $ProjectFile) }
$invocation = Invoke-AgentSupervisorPython -Command $pythonCommand -PrefixArgs $pythonPrefix -Arguments (@('-E', '-P', '-X', 'utf8', $launcherPath) + $argsList) -Operation 'event' -WorkingDirectory $coreRoot -IsolatedEnvironment
$code = [int]$invocation.ExitCode
$global:LASTEXITCODE = 0
exit $code
