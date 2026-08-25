#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GateId,
    [Parameter(Mandatory = $true)][string]$CriterionId,
    # Deprecated compatibility parameters. They are intentionally accepted and
    # ignored: the trusted core mints collector identity and responsibility data.
    [AllowNull()][object]$CollectorGroup = $null,
    [AllowNull()][object]$CollectorInvocationId = $null,
    [string]$EvidenceId = '',
    # Deprecated and ignored. Gate execution uses the core-owned maximum plus
    # bounded adapter margins below.
    [AllowNull()][object]$TimeoutSeconds = $null,
    [string]$Workspace = (Get-Location).Path,
    [string]$RoundId = 'latest',
    [string]$SessionId = $env:CODEX_THREAD_ID,
    # Deprecated and ignored. Callers cannot select a trusted actor.
    [AllowNull()][object]$Actor = $null
)

$maximumRegisteredGateSeconds = 1800
$coreProcessMarginSeconds = 10
$outerProcessMarginSeconds = 10
$fixedCoreTimeoutSeconds = $maximumRegisteredGateSeconds + $coreProcessMarginSeconds

function Test-SupervisorGateDirectoryChain {
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Directory)

    try {
        if (-not [IO.Path]::IsPathRooted($Directory)) { return $false }
        $fullPath = [IO.Path]::GetFullPath($Directory)
        $pathRoot = [IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrWhiteSpace($pathRoot)) { return $false }
        $current = $pathRoot
        $rootItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $false
        }
        $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        foreach ($component in $fullPath.Substring($pathRoot.Length).Split($separators, [StringSplitOptions]::RemoveEmptyEntries)) {
            $current = Join-Path $current $component
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                return $false
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Resolve-SupervisorGateSystemTaskkillPath {
    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $null }
        $systemDirectory = [Environment]::SystemDirectory
        if ([string]::IsNullOrWhiteSpace($systemDirectory) -or -not [IO.Path]::IsPathRooted($systemDirectory)) {
            return $null
        }
        $systemFull = [IO.Path]::GetFullPath($systemDirectory)
        if (-not (Test-SupervisorGateDirectoryChain -Directory $systemFull)) { return $null }
        $resolvedSystem = (Resolve-Path -LiteralPath $systemFull -ErrorAction Stop).Path
        if ($resolvedSystem -ine $systemFull) { return $null }
        $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedSystem 'taskkill.exe'))
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $null
        }
        $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        if ($resolved -ine $candidate -or (Split-Path -Parent $resolved) -ine $resolvedSystem) { return $null }
        return $resolved
    } catch {
        return $null
    }
}

function ConvertTo-SupervisorGateNativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    $null = $builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $backslashes += 1; continue }
        if ($character -eq [char]34) {
            if ($backslashes -gt 0) { $null = $builder.Append([char]92, (2 * $backslashes)) }
            $null = $builder.Append([char]92)
            $null = $builder.Append([char]34)
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { $null = $builder.Append([char]92, $backslashes) }
        $null = $builder.Append($character)
        $backslashes = 0
    }
    if ($backslashes -gt 0) { $null = $builder.Append([char]92, (2 * $backslashes)) }
    $null = $builder.Append([char]34)
    return $builder.ToString()
}

function Stop-SupervisorGateChild {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    $targetPid = 0
    try { $targetPid = [int]$Process.Id } catch { return }
    $cleanupBudgetMilliseconds = 2500
    $cleanupDeadline = [DateTime]::UtcNow.AddMilliseconds($cleanupBudgetMilliseconds)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $killer = $null
        try {
            $canonicalTaskkill = Resolve-SupervisorGateSystemTaskkillPath
            if ([string]::IsNullOrWhiteSpace($canonicalTaskkill)) {
                throw 'Trusted task termination helper is unavailable.'
            }
            $killerInfo = New-Object Diagnostics.ProcessStartInfo
            $killerInfo.FileName = $canonicalTaskkill
            $killerInfo.Arguments = '/PID ' + [string]$targetPid + ' /T /F'
            $killerInfo.UseShellExecute = $false
            $killerInfo.CreateNoWindow = $true
            $killerInfo.RedirectStandardOutput = $true
            $killerInfo.RedirectStandardError = $true
            $killerInfo.EnvironmentVariables.Clear()
            $trustedWindowsRoot = Split-Path -Parent (Split-Path -Parent $canonicalTaskkill)
            $killerInfo.EnvironmentVariables['SYSTEMROOT'] = $trustedWindowsRoot
            $killerInfo.EnvironmentVariables['WINDIR'] = $trustedWindowsRoot
            $killerInfo.EnvironmentVariables['PATH'] = Split-Path -Parent $canonicalTaskkill
            $killerInfo.EnvironmentVariables['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
            $killerInfo.EnvironmentVariables['NoDefaultCurrentDirectoryInExePath'] = '1'
            $killer = New-Object Diagnostics.Process
            $killer.StartInfo = $killerInfo
            if ($killer.Start()) {
                $killerOut = $killer.StandardOutput.ReadToEndAsync()
                $killerError = $killer.StandardError.ReadToEndAsync()
                $remaining = [Math]::Max(0, [int][Math]::Ceiling(($cleanupDeadline - [DateTime]::UtcNow).TotalMilliseconds))
                if ($remaining -gt 0 -and -not $killer.WaitForExit($remaining)) {
                    try { $killer.Kill() } catch { }
                }
                $remaining = [Math]::Max(0, [int][Math]::Ceiling(($cleanupDeadline - [DateTime]::UtcNow).TotalMilliseconds))
                if ($remaining -gt 0) {
                    try {
                        $null = [Threading.Tasks.Task]::WaitAll(
                            [Threading.Tasks.Task[]]@($killerOut, $killerError),
                            $remaining
                        )
                    } catch { }
                }
            }
        } catch { }
        finally { if ($null -ne $killer) { $killer.Dispose() } }
    }
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
        $remaining = [Math]::Max(0, [int][Math]::Ceiling(($cleanupDeadline - [DateTime]::UtcNow).TotalMilliseconds))
        if ($remaining -gt 0) { $null = $Process.WaitForExit($remaining) }
    } catch { }
}

trap {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"gate-adapter-failure","message":"Supervisor gate event recording failed; state is degraded."}')
    exit 4
}

$ErrorActionPreference = 'Stop'
$record = @{
    record = @{
        gate_id = $GateId
        criterion_id = $CriterionId
    }
}
if (-not [string]::IsNullOrWhiteSpace($EvidenceId)) { $record.record.evidence_id = $EvidenceId }
$json = $record | ConvertTo-Json -Depth 5 -Compress
$eventScript = Join-Path $PSScriptRoot 'supervisor-event.ps1'
$global:LASTEXITCODE = $null
$eventFailure = $null
$eventProcess = $null
$eventStdout = ''
$eventStderr = ''
try {
    try {
        $hostExecutable = (Get-Process -Id $PID -ErrorAction Stop).Path
        if ([string]::IsNullOrWhiteSpace($hostExecutable) -or -not (Test-Path -LiteralPath $hostExecutable -PathType Leaf)) {
            throw 'PowerShell host executable is unavailable.'
        }
$eventRunner = @'
$ErrorActionPreference = 'Stop'
$global:LASTEXITCODE = $null
& $env:AGENT_SUPERVISOR_GATE_EVENT_SCRIPT `
    -Workspace $env:AGENT_SUPERVISOR_GATE_WORKSPACE `
    -RoundId $env:AGENT_SUPERVISOR_GATE_ROUND `
    -SessionId $env:AGENT_SUPERVISOR_GATE_SESSION `
    -Event 'gate_run' `
    -DataJson $env:AGENT_SUPERVISOR_GATE_DATA
# A conforming event adapter sets LASTEXITCODE through exit. A plain return leaves it
# unset; map that case to a private sentinel that the parent converts to degraded 4.
if ($null -eq $global:LASTEXITCODE) { exit 125 }
exit ([int]$global:LASTEXITCODE)
'@
        $encodedRunner = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($eventRunner))
        $eventArguments = @('-NoLogo', '-NoProfile', '-NonInteractive')
        # Both Windows PowerShell and PowerShell Core honor this switch on Windows.
        # Apply it based on the operating system, not the parent host edition, so a
        # restricted policy cannot prevent the isolated event child from starting.
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $eventArguments += @('-ExecutionPolicy', 'Bypass')
        }
        $eventArguments += @('-EncodedCommand', $encodedRunner)
        # Run the event adapter in a redirected child host. supervisor-event.ps1
        # intentionally calls exit, and a terminating child error can write raw
        # details to stderr. Capture both streams so failure output can be replaced
        # with one stable, redacted degraded record before anything reaches the host.
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $hostExecutable
        $startInfo.Arguments = (($eventArguments | ForEach-Object {
            ConvertTo-SupervisorGateNativeArgument -Value ([string]$_)
        }) -join ' ')
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_GATE_EVENT_SCRIPT'] = $eventScript
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_GATE_WORKSPACE'] = $Workspace
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_GATE_ROUND'] = $RoundId
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_GATE_SESSION'] = $SessionId
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_GATE_DATA'] = $json
        $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_PYTHON_TIMEOUT_SECONDS'] =
            $fixedCoreTimeoutSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
        # Do not let inherited legacy identity variables cross the isolation boundary.
        foreach ($legacyIdentityVariable in @(
            'AGENT_SUPERVISOR_GATE_ACTOR',
            'AGENT_SUPERVISOR_GATE_RESPONSIBILITY_GROUP',
            'AGENT_SUPERVISOR_GATE_COLLECTOR_GROUP',
            'AGENT_SUPERVISOR_GATE_COLLECTOR_INVOCATION_ID'
        )) {
            $startInfo.EnvironmentVariables.Remove($legacyIdentityVariable)
        }
        if ($startInfo.PSObject.Properties.Name -contains 'StandardOutputEncoding') {
            $utf8 = New-Object Text.UTF8Encoding($false)
            $startInfo.StandardOutputEncoding = $utf8
            $startInfo.StandardErrorEncoding = $utf8
        }
        $eventProcess = New-Object Diagnostics.Process
        $eventProcess.StartInfo = $startInfo
        if (-not $eventProcess.Start()) { throw 'Event adapter process did not start.' }
        $stdoutTask = $eventProcess.StandardOutput.ReadToEndAsync()
        $stderrTask = $eventProcess.StandardError.ReadToEndAsync()
        $eventWaitMilliseconds = [int][Math]::Ceiling(
            (([double]$fixedCoreTimeoutSeconds + [double]$outerProcessMarginSeconds) * 1000.0)
        )
        if (-not $eventProcess.WaitForExit($eventWaitMilliseconds)) {
            Stop-SupervisorGateChild -Process $eventProcess
            throw 'Event adapter process timed out.'
        }
        $null = $eventProcess.WaitForExit(2000)
        if (-not [Threading.Tasks.Task]::WaitAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 2000
        )) {
            throw 'Event adapter output streams did not close.'
        }
        $eventStdout = [string]$stdoutTask.Result
        $eventStderr = [string]$stderrTask.Result
        $eventExitCode = [int]$eventProcess.ExitCode
    } catch {
        $eventFailure = $_
    }
} catch {
    $eventFailure = $_
} finally {
    if ($null -ne $eventProcess) { $eventProcess.Dispose() }
}
if ($null -ne $eventFailure) {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"gate-adapter-failure","message":"Supervisor gate event recording failed; state is degraded."}')
    exit 4
}

[int]$parsedExitCode = 0
if ($null -eq $eventExitCode -or -not [int]::TryParse([string]$eventExitCode, [ref]$parsedExitCode)) {
    [Console]::Error.WriteLine('{"status":"degraded","reason":"gate-adapter-failure","message":"Supervisor gate event recording failed; exit status is unavailable and state is degraded."}')
    exit 4
}
$structuredExitCodes = @(0, 2, 3, 64)
if ($parsedExitCode -in @(1, 4, 125)) {
    # An unhandled child error exits 1, adapter degradation exits 4, and the private
    # runner sentinel 125 means the script returned without a result. All three are
    # wrapper failures; raw
    # streams may contain secrets or terminating-error details and are never relayed.
    [Console]::Error.WriteLine(
        '{"status":"degraded","reason":"gate-adapter-failure","child_exit_code":' +
        [string]$parsedExitCode +
        ',"message":"Supervisor gate event recording failed; state is degraded."}'
    )
    exit 4
}
if ($parsedExitCode -in $structuredExitCodes) {
    if ($parsedExitCode -eq 0) {
        if (-not [string]::IsNullOrEmpty($eventStdout)) { [Console]::Out.Write($eventStdout) }
        # Even a successful child can emit incidental diagnostics containing local
        # details. The gate event is represented by stdout; captured stderr is never
        # relayed.
        exit 0
    }
    # Never relay raw failure streams. Preserve the core status while emitting only a
    # stable, redacted adapter-level diagnostic.
    $reasonByExitCode = @{
        2 = 'gate-event-incomplete'
        3 = 'gate-event-blocked'
        64 = 'gate-event-invalid-state'
    }
    [Console]::Error.WriteLine(
        '{"status":"degraded","reason":"' +
        [string]$reasonByExitCode[$parsedExitCode] +
        '","child_exit_code":' + [string]$parsedExitCode +
        ',"message":"Supervisor gate event did not complete; captured failure output was suppressed."}'
    )
    exit $parsedExitCode
}
# Any other child status is outside the gate adapter contract. Preserve only the
# numeric diagnostic; captured streams may contain secrets and are never relayed.
[Console]::Error.WriteLine(
    '{"status":"degraded","reason":"gate-adapter-failure","child_exit_code":' +
    [string]$parsedExitCode +
    ',"message":"Supervisor gate event recording failed; state is degraded."}'
)
exit 4
