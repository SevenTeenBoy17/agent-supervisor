$ErrorActionPreference = 'Stop'
$coreBridge = Join-Path $PSScriptRoot 'supervisor-core.ps1'
. $coreBridge
$Event = [string][Environment]::GetEnvironmentVariable('AGENT_SUPERVISOR_HOOK_EVENT')
$allowedEvents = @(
    'SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse',
    'PostToolUseFailure', 'PermissionRequest', 'Notification',
    'PreCompact', 'PostCompact', 'SubagentStart', 'SubagentStop', 'Stop', 'SessionEnd'
)
if ($Event -notin $allowedEvents) { exit 4 }
$timeoutRaw = [string][Environment]::GetEnvironmentVariable('AGENT_SUPERVISOR_HOOK_TIMEOUT_SECONDS')
$TimeoutSeconds = [double]20.0
if (-not [double]::TryParse(
    $timeoutRaw,
    [Globalization.NumberStyles]::Float,
    [Globalization.CultureInfo]::InvariantCulture,
    [ref]$TimeoutSeconds
) -or $TimeoutSeconds -lt 1.0 -or $TimeoutSeconds -gt 120.0) { exit 4 }
try {
    $inputStream = [Console]::OpenStandardInput()
    $memory = New-Object IO.MemoryStream
    try {
        $buffer = New-Object byte[] 16384
        while ($true) {
            $read = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $memory.Write($buffer, 0, $read)
            if ($memory.Length -gt 4194304) { throw 'hook input exceeds bounded contract' }
        }
        $payload = $memory.ToArray()
    } finally {
        $memory.Dispose()
        $inputStream.Dispose()
    }
    $runtime = Get-AgentSupervisorPythonCommand
    if ($null -eq $runtime) { exit 4 }
    $core = Get-AgentSupervisorCoreRoot
    $launcher = Resolve-AgentSupervisorTrustedLauncherPath -CoreRoot $core
    if ([string]::IsNullOrWhiteSpace($launcher)) { exit 4 }
    $installHome = Get-AgentSupervisorProfileHome
    if ([string]::IsNullOrWhiteSpace($installHome)) { exit 4 }
    $stateRoot = Join-Path $installHome '.agent-supervisor\state'
    $result = Invoke-AgentSupervisorPython `
        -Command $runtime.Command `
        -PrefixArgs @($runtime.PrefixArgs) `
        -Arguments @(
            '-I', '-S', '-B', '-X', 'utf8', $launcher,
            'hook', '--runtime', 'codex', '--event', $Event,
            '--state-root', $stateRoot
        ) `
        -Operation 'codex-hook' `
        -WorkingDirectory $core `
        -TimeoutSeconds $TimeoutSeconds `
        -InputBytes $payload `
        -CaptureOutput `
        -SuppressOutput `
        -IsolatedEnvironment `
        -Silent
    if (-not [string]::IsNullOrEmpty([string]$result.StandardOutput)) {
        $utf8 = New-Object Text.UTF8Encoding($false)
        $bytes = $utf8.GetBytes([string]$result.StandardOutput)
        $outputStream = [Console]::OpenStandardOutput()
        try {
            $outputStream.Write($bytes, 0, $bytes.Length)
            $outputStream.Flush()
        } finally {
            $outputStream.Dispose()
        }
    }
    exit [int]$result.ExitCode
} catch {
    exit 4
}
