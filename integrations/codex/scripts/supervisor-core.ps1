#requires -Version 5.1
$script:AgentSupervisorAdapterScriptsRoot = $PSScriptRoot
$script:AgentSupervisorVerifiedExecutableHashes = @{}
$script:AgentSupervisorVerifiedLauncherHashes = @{}
$script:AgentSupervisorVerifiedReleaseBundles = @{}
$script:AgentSupervisorVerifiedDependencyRoots = @()

function Get-AgentSupervisorStreamSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        if (-not $Stream.CanRead -or -not $Stream.CanSeek) { return $null }
        $Stream.Position = 0
        $digest = $hasher.ComputeHash($Stream)
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    } catch {
        return $null
    } finally {
        $hasher.Dispose()
    }
}

function Register-AgentSupervisorVerifiedFileHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Registry
    )

    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $stream = [IO.File]::Open(
            $fullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $sha256 = Get-AgentSupervisorStreamSha256 -Stream $stream
        if ([string]::IsNullOrWhiteSpace($sha256)) { return $false }
        $Registry[$fullPath] = $sha256
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-AgentSupervisorVerifiedFileSourceBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [long]$MaximumBytes = 1048576
    )

    $stream = $null
    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
        $stream = [IO.File]::Open(
            $fullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) { return $null }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { return $null }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) { return $null }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $actualSha256 = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        } finally {
            $hasher.Dispose()
        }
        if ($actualSha256 -cne $ExpectedSha256.ToLowerInvariant()) { return $null }
        return [Convert]::ToBase64String($bytes)
    } catch {
        return $null
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Read-AgentSupervisorStableFileBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [long]$MaximumBytes = 16777216
    )

    $stream = $null
    try {
        if (-not [IO.Path]::IsPathRooted($Path)) { return $null }
        $fullPath = [IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { return $null }
        $itemBefore = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        if ($itemBefore.PSIsContainer -or (($itemBefore.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $null
        }
        $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
        if ($resolved -ine $fullPath) { return $null }
        $stream = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes -or $stream.Length -gt [int]::MaxValue) {
            return $null
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { return $null }
            $offset += $read
        }
        $sha256 = Get-AgentSupervisorStreamSha256 -Stream $stream
        $itemAfter = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if (
            [string]::IsNullOrWhiteSpace($sha256) -or
            $itemBefore.Length -ne $itemAfter.Length -or
            $itemBefore.LastWriteTimeUtc -ne $itemAfter.LastWriteTimeUtc -or
            (($itemAfter.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        ) {
            return $null
        }
        return [pscustomobject]@{
            Bytes = $bytes
            FullPath = $resolved
            Sha256 = $sha256
        }
    } catch {
        return $null
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function New-AgentSupervisorRuntimeFrame {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$IdentityBytes,
        [Parameter(Mandatory = $true)][byte[]]$BundleBytes,
        [byte[]]$PayloadBytes = @()
    )

    if (
        $IdentityBytes.Length -lt 2 -or $IdentityBytes.Length -gt 65536 -or
        $BundleBytes.Length -lt 1 -or $BundleBytes.Length -gt 16777216 -or
        $PayloadBytes.Length -gt 4194304
    ) {
        throw 'SupervisorRuntimeFrame/v1 input exceeds its bounded contract'
    }
    $stream = New-Object IO.MemoryStream
    try {
        $magic = [Text.Encoding]::ASCII.GetBytes("ASRFv1`0`0")
        $stream.Write($magic, 0, $magic.Length)
        foreach ($length in @($IdentityBytes.Length, $BundleBytes.Length, $PayloadBytes.Length)) {
            $network = [Net.IPAddress]::HostToNetworkOrder([int]$length)
            $encoded = [BitConverter]::GetBytes($network)
            $stream.Write($encoded, 0, $encoded.Length)
        }
        $stream.Write($IdentityBytes, 0, $IdentityBytes.Length)
        $stream.Write($BundleBytes, 0, $BundleBytes.Length)
        if ($PayloadBytes.Length -gt 0) { $stream.Write($PayloadBytes, 0, $PayloadBytes.Length) }
        return $stream.ToArray()
    } finally {
        $stream.Dispose()
    }
}

function Resolve-AgentSupervisorWorkspace {
    param([Parameter(Mandatory = $true)][string]$Workspace)
    try {
        if (-not (Test-Path -LiteralPath $Workspace -PathType Container)) {
            return $null
        }
        return (Resolve-Path -LiteralPath $Workspace -ErrorAction Stop).Path
    } catch {
        return $null
    }
}

function Resolve-AgentSupervisorProjectFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Workspace,
        [AllowEmptyString()][string]$ProjectFile = '',
        [switch]$Explicit
    )

    $invalidExplicit = 'ProjectFile must resolve to an existing file.'
    if ($Explicit) {
        if ([string]::IsNullOrWhiteSpace($ProjectFile) -or -not (Test-Path -LiteralPath $ProjectFile -PathType Leaf)) {
            return [pscustomobject]@{ Valid = $false; Present = $false; Path = ''; Message = $invalidExplicit }
        }
        try {
            $resolved = (Resolve-Path -LiteralPath $ProjectFile -ErrorAction Stop).Path
            return [pscustomobject]@{ Valid = $true; Present = $true; Path = $resolved; Message = '' }
        } catch {
            return [pscustomobject]@{ Valid = $false; Present = $false; Path = ''; Message = $invalidExplicit }
        }
    }

    $supervisorDirectory = Join-Path $Workspace '.agent-supervisor'
    if (-not (Test-Path -LiteralPath $supervisorDirectory)) {
        return [pscustomobject]@{ Valid = $true; Present = $false; Path = ''; Message = '' }
    }
    if (-not (Test-Path -LiteralPath $supervisorDirectory -PathType Container)) {
        return [pscustomobject]@{
            Valid = $false
            Present = $false
            Path = ''
            Message = 'Workspace Supervisor configuration is invalid: .agent-supervisor must be a directory.'
        }
    }

    $candidate = Join-Path $supervisorDirectory 'project.json'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return [pscustomobject]@{
            Valid = $false
            Present = $false
            Path = ''
            Message = 'Workspace Supervisor configuration is incomplete: .agent-supervisor/project.json is required.'
        }
    }
    try {
        $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        return [pscustomobject]@{ Valid = $true; Present = $true; Path = $resolved; Message = '' }
    } catch {
        return [pscustomobject]@{
            Valid = $false
            Present = $false
            Path = ''
            Message = 'Workspace Supervisor configuration is incomplete: .agent-supervisor/project.json is required.'
        }
    }
}

function Test-AgentSupervisorDirectoryChain {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Directory)

    try {
        if (-not [IO.Path]::IsPathRooted($Directory)) { return $false }
        $fullPath = [IO.Path]::GetFullPath($Directory)
        $pathRoot = [IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrWhiteSpace($pathRoot)) { return $false }

        $current = $pathRoot
        $rootItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (-not $rootItem.PSIsContainer) { return $false }
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }

        $relative = $fullPath.Substring($pathRoot.Length)
        $separators = [char[]]@(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        foreach ($component in $relative.Split($separators, [StringSplitOptions]::RemoveEmptyEntries)) {
            $current = Join-Path $current $component
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) { return $false }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Resolve-AgentSupervisorTrustedPythonPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [string[]]$AllowedRoots = @(),
        [string[]]$KnownExecutables = @()
    )

    try {
        if (-not [IO.Path]::IsPathRooted($Candidate) -or -not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            return $null
        }
        $candidateFull = [IO.Path]::GetFullPath($Candidate)
        $candidateLeafName = [IO.Path]::GetFileName($candidateFull)
        $validCandidateLeaf = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $candidateLeafName -match '^(?i:python(?:3)?[.]exe)$'
        } else {
            # POSIX launchers commonly expose python3 as one lexical symlink to a
            # versioned regular file such as python3.11.  Accept only the Python
            # executable naming family; suffixes such as -config remain rejected.
            $candidateLeafName -match '^(?:python|python3(?:[.][0-9]+)*)$'
        }
        if (-not $validCandidateLeaf) { return $null }

        # A discovered executable may legitimately be a leaf symbolic link. Keep
        # every lexical parent non-reparse so a directory junction cannot escape a
        # trusted root, then resolve the leaf before validating its real target.
        $candidateParent = Split-Path -Parent $candidateFull
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $candidateParent)) { return $null }
        # Inspect the lexical leaf before Resolve-Path. Resolve-Path follows file
        # links, which would otherwise erase the ReparsePoint identity and let a
        # multi-hop link chain masquerade as its final regular-file target.
        $candidateItem = Get-Item -LiteralPath $candidateFull -Force -ErrorAction Stop
        if ($candidateItem.PSIsContainer) { return $null }

        $resolved = $candidateFull
        if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            # Resolve exactly the candidate leaf. Unknown reparse kinds, broken
            # links, link chains, and links to directories remain fail-closed.
            $linkTargetPath = ''
            $resolveLinkTargetMethod = $candidateItem.PSObject.Methods['ResolveLinkTarget']
            if ($null -ne $resolveLinkTargetMethod) {
                $linkTarget = $candidateItem.ResolveLinkTarget($false)
                if ($null -ne $linkTarget) { $linkTargetPath = [string]$linkTarget.FullName }
            } elseif ($candidateItem.PSObject.Properties.Name -contains 'Target') {
                $rawTargets = @($candidateItem.Target)
                if ($rawTargets.Count -eq 1) { $linkTargetPath = [string]$rawTargets[0] }
            }
            if ([string]::IsNullOrWhiteSpace($linkTargetPath)) { return $null }
            if (-not [IO.Path]::IsPathRooted($linkTargetPath)) {
                $linkTargetPath = Join-Path $candidateParent $linkTargetPath
            }
            $linkTargetFull = [IO.Path]::GetFullPath($linkTargetPath)
            if (-not (Test-Path -LiteralPath $linkTargetFull -PathType Leaf)) { return $null }
            $linkTargetItem = Get-Item -LiteralPath $linkTargetFull -Force -ErrorAction Stop
            if (
                $linkTargetItem.PSIsContainer -or
                (($linkTargetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            ) {
                return $null
            }
            $resolved = (Resolve-Path -LiteralPath $linkTargetFull -ErrorAction Stop).Path
        } else {
            $resolved = (Resolve-Path -LiteralPath $candidateFull -ErrorAction Stop).Path
        }

        $resolvedLeafName = [IO.Path]::GetFileName($resolved)
        $validRuntimeLeaf = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $resolvedLeafName -match '^(?i:python(?:3)?[.]exe)$'
        } else {
            $resolvedLeafName -match '^(?:python|python3(?:[.][0-9]+)*)$'
        }
        if (-not $validRuntimeLeaf) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory (Split-Path -Parent $resolved))) { return $null }
        $resolvedItem = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if ($resolvedItem.PSIsContainer -or (($resolvedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $null
        }

        $withinAllowedRoot = $false
        foreach ($allowedRoot in $AllowedRoots) {
            if ([string]::IsNullOrWhiteSpace($allowedRoot)) { continue }
            try {
                $allowedFull = [IO.Path]::GetFullPath($allowedRoot)
                if (-not (Test-AgentSupervisorDirectoryChain -Directory $allowedFull)) { continue }
                $allowedResolved = (Resolve-Path -LiteralPath $allowedFull -ErrorAction Stop).Path
                $prefix = $allowedResolved.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar
                ) + [IO.Path]::DirectorySeparatorChar
                if ($resolved -ieq $allowedResolved -or $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $withinAllowedRoot = $true
                    break
                }
            } catch { continue }
        }
        if (-not $withinAllowedRoot) { return $null }
        if ($KnownExecutables.Count -eq 0) {
            if (-not (Register-AgentSupervisorVerifiedFileHash -Path $resolved -Registry $script:AgentSupervisorVerifiedExecutableHashes)) {
                return $null
            }
            return $resolved
        }
        foreach ($known in $KnownExecutables) {
            if ([string]::IsNullOrWhiteSpace($known)) { continue }
            try {
                $knownFull = [IO.Path]::GetFullPath($known)
                if ($resolved -ieq $knownFull -or $candidateFull -ieq $knownFull) {
                    if (-not (Register-AgentSupervisorVerifiedFileHash -Path $resolved -Registry $script:AgentSupervisorVerifiedExecutableHashes)) {
                        return $null
                    }
                    return $resolved
                }
            } catch { continue }
        }
        return $null
    } catch {
        return $null
    }
}

function Get-AgentSupervisorPythonAllowedRoots {
    [CmdletBinding()]
    param()

    $roots = @()
    $profileHome = Get-AgentSupervisorProfileHome
    $runningOnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $rawRoots = if ($runningOnWindows) {
        @(
            [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
            [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
        )
    } else { @() }
    if (-not [string]::IsNullOrWhiteSpace($profileHome)) {
        if ($runningOnWindows) {
            # Trust only the conventional per-user Python installation subtree,
            # never the whole writable profile as an executable root.
            $rawRoots += Join-Path $profileHome 'AppData\Local\Programs\Python'
        } else {
            $rawRoots += Join-Path $profileHome '.pyenv/versions'
        }
    }
    if (-not $runningOnWindows) {
        $rawRoots += @('/usr', '/usr/local', '/opt/homebrew', '/opt/local')
    }
    foreach ($rawRoot in $rawRoots) {
        if ([string]::IsNullOrWhiteSpace($rawRoot)) { continue }
        try {
            $fullRoot = [IO.Path]::GetFullPath($rawRoot)
            if (-not (Test-AgentSupervisorDirectoryChain -Directory $fullRoot)) { continue }
            $resolved = (Resolve-Path -LiteralPath $fullRoot -ErrorAction Stop).Path
            if ($roots -notcontains $resolved) { $roots += $resolved }
        } catch { continue }
    }
    # PEP 514 registry entries are an installation-time trust source on Windows.
    # Resolve them before probing a launcher so the later sys.executable identity
    # check can reuse this same fixed root set instead of trusting a path reported
    # by the process being checked.
    if ($runningOnWindows) {
        foreach ($registryRoot in @(
            'Registry::HKEY_LOCAL_MACHINE\Software\Python\PythonCore',
            'Registry::HKEY_CURRENT_USER\Software\Python\PythonCore'
        )) {
            foreach ($versionKey in @(Get-ChildItem -LiteralPath $registryRoot -ErrorAction SilentlyContinue)) {
                try {
                    $install = Get-ItemProperty -LiteralPath (Join-Path $versionKey.PSPath 'InstallPath') -ErrorAction Stop
                    $rawInstall = [string]$install.'(default)'
                    if ([string]::IsNullOrWhiteSpace($rawInstall) -or -not [IO.Path]::IsPathRooted($rawInstall)) { continue }
                    $fullInstall = [IO.Path]::GetFullPath($rawInstall)
                    if (-not (Test-AgentSupervisorDirectoryChain -Directory $fullInstall)) { continue }
                    $resolvedInstall = (Resolve-Path -LiteralPath $fullInstall -ErrorAction Stop).Path
                    if ($roots -notcontains $resolvedInstall) { $roots += $resolvedInstall }
                } catch { continue }
            }
        }
    }
    return @($roots)
}

function Get-AgentSupervisorTrustedRegistryPythonPath {
    [CmdletBinding()]
    param()

    try {
        $profileHome = Get-AgentSupervisorProfileHome
        if ([string]::IsNullOrWhiteSpace($profileHome)) { return $null }
        $registryRoot = Join-Path $profileHome '.agent-supervisor'
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $registryRoot)) { return $null }
        $registryPath = Join-Path $registryRoot 'trusted-executables.json'
        $snapshot = Read-AgentSupervisorStableFileBytes -Path $registryPath -MaximumBytes 1048576
        if ($null -eq $snapshot) { return $null }
        $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
        $registry = $strictUtf8.GetString([byte[]]$snapshot.Bytes) | ConvertFrom-Json -ErrorAction Stop
        $registryNames = @($registry.PSObject.Properties.Name | Sort-Object)
        if (
            ($registryNames -join '|') -cne 'contract|entries|generated_at' -or
            [string]$registry.contract -cne 'TrustedExecutableRegistry/v1' -or
            $null -eq $registry.entries
        ) {
            return $null
        }
        $entry = $registry.entries.python
        $entryNames = @($entry.PSObject.Properties.Name | Sort-Object)
        if (
            $null -eq $entry -or
            ($entryNames -join '|') -cne 'kind|path|sha256' -or
            [string]$entry.kind -cne 'local' -or
            [string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$'
        ) {
            return $null
        }
        $candidate = [string]$entry.path
        if (-not [IO.Path]::IsPathRooted($candidate)) { return $null }
        $candidateFull = [IO.Path]::GetFullPath($candidate)
        $candidateLeaf = [IO.Path]::GetFileName($candidateFull)
        if ($candidateLeaf -notmatch '^(?i:python(?:3)?[.]exe)$') { return $null }
        $candidateRoot = Split-Path -Parent $candidateFull
        $trusted = Resolve-AgentSupervisorTrustedPythonPath `
            -Candidate $candidateFull `
            -AllowedRoots @($candidateRoot) `
            -KnownExecutables @($candidateFull)
        if ([string]::IsNullOrWhiteSpace($trusted)) { return $null }
        $observedSha256 = [string]$script:AgentSupervisorVerifiedExecutableHashes[$trusted]
        if ($observedSha256 -cne [string]$entry.sha256) {
            $script:AgentSupervisorVerifiedExecutableHashes.Remove($trusted)
            return $null
        }
        return $trusted
    } catch {
        return $null
    }
}

function Resolve-AgentSupervisorTrustedCorePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string[]]$AllowedRoots
    )

    try {
        if (-not [IO.Path]::IsPathRooted($Candidate) -or -not (Test-Path -LiteralPath $Candidate -PathType Container)) {
            return $null
        }
        $candidateFull = [IO.Path]::GetFullPath($Candidate)
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $candidateFull)) { return $null }
        $resolved = (Resolve-Path -LiteralPath $Candidate -ErrorAction Stop).Path
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $resolved)) { return $null }
        $trusted = $false
        foreach ($allowedRoot in $AllowedRoots) {
            if ([string]::IsNullOrWhiteSpace($allowedRoot)) { continue }
            try {
                if (-not [IO.Path]::IsPathRooted($allowedRoot)) { continue }
                $allowedFull = [IO.Path]::GetFullPath($allowedRoot)
                if (-not (Test-AgentSupervisorDirectoryChain -Directory $allowedFull)) { continue }
                $resolvedAllowed = (Resolve-Path -LiteralPath $allowedFull -ErrorAction Stop).Path
                if (-not (Test-AgentSupervisorDirectoryChain -Directory $resolvedAllowed)) { continue }
                $prefix = $resolvedAllowed.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
                if ($resolved -ieq $resolvedAllowed -or $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $trusted = $true
                    break
                }
            } catch { continue }
        }
        if (-not $trusted) { return $null }

        $packagePath = Join-Path $resolved 'supervisor_core'
        if (-not (Test-Path -LiteralPath $packagePath -PathType Container)) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $packagePath)) { return $null }
        foreach ($sourceName in @('__init__.py', '__main__.py')) {
            $sourcePath = Join-Path $packagePath $sourceName
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { return $null }
            $sourceItem = Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
            if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $null }
        }
        return $resolved
    } catch {
        return $null
    }
}

function Resolve-AgentSupervisorTrustedLauncherPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$CoreRoot)

    try {
        if (-not [IO.Path]::IsPathRooted($CoreRoot)) { return $null }
        $coreFull = [IO.Path]::GetFullPath($CoreRoot)
        if (-not (Test-Path -LiteralPath $coreFull -PathType Container)) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $coreFull)) { return $null }
        $resolvedCore = (Resolve-Path -LiteralPath $coreFull -ErrorAction Stop).Path
        if ($resolvedCore -ine $coreFull) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $resolvedCore)) { return $null }
        $releaseBinding = $script:AgentSupervisorVerifiedReleaseBundles[$resolvedCore]
        if ($null -eq $releaseBinding) { return $null }

        $binPath = Join-Path $resolvedCore 'bin'
        if (-not (Test-Path -LiteralPath $binPath -PathType Container)) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $binPath)) { return $null }
        $resolvedBin = (Resolve-Path -LiteralPath $binPath -ErrorAction Stop).Path
        if ($resolvedBin -ine [IO.Path]::GetFullPath($binPath)) { return $null }

        $launcherPath = Join-Path $resolvedBin 'agent-supervisor.py'
        if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) { return $null }
        $launcherFull = [IO.Path]::GetFullPath($launcherPath)
        $launcherItem = Get-Item -LiteralPath $launcherFull -Force -ErrorAction Stop
        if (
            $launcherItem.PSIsContainer -or
            (($launcherItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        ) {
            return $null
        }
        $resolvedLauncher = (Resolve-Path -LiteralPath $launcherFull -ErrorAction Stop).Path
        if ($resolvedLauncher -ine $launcherFull) { return $null }
        if ((Split-Path -Parent $resolvedLauncher) -ine $resolvedBin) { return $null }
        $corePrefix = $resolvedCore.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        ) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedLauncher.StartsWith($corePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }
        if (-not (Register-AgentSupervisorVerifiedFileHash -Path $resolvedLauncher -Registry $script:AgentSupervisorVerifiedLauncherHashes)) {
            return $null
        }
        $script:AgentSupervisorVerifiedReleaseBundles[$resolvedLauncher] = $releaseBinding
        return $resolvedLauncher
    } catch {
        return $null
    }
}

function Get-AgentSupervisorProfileHome {
    [CmdletBinding()]
    param()

    # Trust is anchored in the installed adapter itself, never USERPROFILE/HOME.
    # A copied test adapter remains valid when it preserves
    # <install-home>/.codex/skills/dev-supervisor/scripts/.
    try {
        $scriptsRoot = [string]$script:AgentSupervisorAdapterScriptsRoot
        if ([string]::IsNullOrWhiteSpace($scriptsRoot) -or -not [IO.Path]::IsPathRooted($scriptsRoot)) {
            return $null
        }
        $scriptsFull = [IO.Path]::GetFullPath($scriptsRoot)
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $scriptsFull)) { return $null }
        $resolvedScripts = (Resolve-Path -LiteralPath $scriptsFull -ErrorAction Stop).Path
        if ($resolvedScripts -ine $scriptsFull) { return $null }

        $adapterRoot = Split-Path -Parent $resolvedScripts
        $skillsRoot = Split-Path -Parent $adapterRoot
        $codexRoot = Split-Path -Parent $skillsRoot
        $installHome = Split-Path -Parent $codexRoot
        if (
            (Split-Path -Leaf $resolvedScripts) -ine 'scripts' -or
            (Split-Path -Leaf $adapterRoot) -ine 'dev-supervisor' -or
            (Split-Path -Leaf $skillsRoot) -ine 'skills' -or
            (Split-Path -Leaf $codexRoot) -ine '.codex' -or
            [string]::IsNullOrWhiteSpace($installHome)
        ) {
            return $null
        }
        foreach ($directory in @($adapterRoot, $skillsRoot, $codexRoot, $installHome)) {
            if (-not (Test-AgentSupervisorDirectoryChain -Directory $directory)) { return $null }
            if ((Resolve-Path -LiteralPath $directory -ErrorAction Stop).Path -ine [IO.Path]::GetFullPath($directory)) {
                return $null
            }
        }
        return [IO.Path]::GetFullPath($installHome)
    } catch {
        return $null
    }
}

function Get-AgentSupervisorRejectedCorePath {
    [CmdletBinding()]
    param()

    # This OS-derived sentinel is never created. Invalid adapter layouts fail closed.
    return (Join-Path ([Environment]::SystemDirectory) '.agent-supervisor-rejected\.rejected-core')
}

function Get-AgentSupervisorCoreRoot {
    $profileHome = Get-AgentSupervisorProfileHome
    if ([string]::IsNullOrWhiteSpace($profileHome)) {
        return Get-AgentSupervisorRejectedCorePath
    }
    $defaultRoot = Join-Path $profileHome '.agent-supervisor'
    $releaseRoot = Join-Path $profileHome '.agent-supervisor-releases'
    $pointerPath = Join-Path $defaultRoot 'active-version.json'
    try {
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $defaultRoot)) {
            throw 'active pointer root is not trusted'
        }
        $pointerSnapshot = Read-AgentSupervisorStableFileBytes -Path $pointerPath -MaximumBytes 1048576
        if ($null -eq $pointerSnapshot) { throw 'active pointer is unavailable' }
        $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
        $pointer = $strictUtf8.GetString([byte[]]$pointerSnapshot.Bytes) | ConvertFrom-Json -ErrorAction Stop
        $pointerNames = @($pointer.PSObject.Properties.Name | Sort-Object)
        if (
            [string]$pointer.contract -cne 'ActiveVersionPointer/v4' -or
            ($pointerNames -join '|') -cne 'active|contract|previous'
        ) {
            throw 'active pointer v4 contract is required'
        }
        $active = $pointer.active
        $activeNames = @($active.PSObject.Properties.Name | Sort-Object)
        if (
            $null -eq $active -or
            ($activeNames -join '|') -cne 'bundle_relpath|bundle_sha256|contract|manifest_sha256|path|source_tree_sha256|version' -or
            [string]$active.contract -cne 'SupervisorReleaseIdentity/v1'
        ) {
            throw 'active release identity is invalid'
        }
        foreach ($digestName in @('bundle_sha256', 'manifest_sha256', 'source_tree_sha256')) {
            if ([string]$active.$digestName -cnotmatch '^[0-9a-f]{64}$') {
                throw 'active release digest is invalid'
            }
        }
        $activePath = [string]$active.path
        $activeVersion = [string]$active.version
        $bundleRelative = [string]$active.bundle_relpath
        if (
            [string]::IsNullOrWhiteSpace($activeVersion) -or
            -not [IO.Path]::IsPathRooted($activePath) -or
            [string]::IsNullOrWhiteSpace($bundleRelative) -or
            [IO.Path]::IsPathRooted($bundleRelative) -or
            $bundleRelative.Contains('\')
        ) {
            throw 'active release path fields are invalid'
        }
        $bundleParts = @($bundleRelative -split '/')
        if ($bundleParts.Count -lt 1 -or @($bundleParts | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
            throw 'active bundle relative path is invalid'
        }
        $allowedRoots = @(
            [IO.Path]::GetFullPath($defaultRoot),
            [IO.Path]::GetFullPath($releaseRoot)
        )
        $trustedPath = Resolve-AgentSupervisorTrustedCorePath -Candidate $activePath -AllowedRoots $allowedRoots
        if ([string]::IsNullOrWhiteSpace($trustedPath)) { throw 'active core path is untrusted' }
        $bundlePath = [IO.Path]::GetFullPath((Join-Path $trustedPath ($bundleParts -join [IO.Path]::DirectorySeparatorChar)))
        $rootPrefix = $trustedPath.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        ) + [IO.Path]::DirectorySeparatorChar
        if (-not $bundlePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'active bundle escaped the release root'
        }
        $bundleSnapshot = Read-AgentSupervisorStableFileBytes -Path $bundlePath -MaximumBytes 16777216
        if ($null -eq $bundleSnapshot -or [string]$bundleSnapshot.Sha256 -cne [string]$active.bundle_sha256) {
            throw 'active bundle digest mismatch'
        }
        $previous = $pointer.previous
        if ($null -ne $previous) {
            # The rollback target is security-sensitive even when this launch uses
            # only the active release. Validate it with the same strict identity,
            # trusted-root, relative-path, and immutable bundle checks as active.
            $previousNames = @($previous.PSObject.Properties.Name | Sort-Object)
            if (
                ($previousNames -join '|') -cne 'bundle_relpath|bundle_sha256|contract|manifest_sha256|path|source_tree_sha256|version' -or
                [string]$previous.contract -cne 'SupervisorReleaseIdentity/v1'
            ) {
                throw 'previous release identity is invalid'
            }
            foreach ($digestName in @('bundle_sha256', 'manifest_sha256', 'source_tree_sha256')) {
                if ([string]$previous.$digestName -cnotmatch '^[0-9a-f]{64}$') {
                    throw 'previous release digest is invalid'
                }
            }
            $previousPath = [string]$previous.path
            $previousVersion = [string]$previous.version
            $previousBundleRelative = [string]$previous.bundle_relpath
            if (
                [string]::IsNullOrWhiteSpace($previousVersion) -or
                -not [IO.Path]::IsPathRooted($previousPath) -or
                [string]::IsNullOrWhiteSpace($previousBundleRelative) -or
                [IO.Path]::IsPathRooted($previousBundleRelative) -or
                $previousBundleRelative.Contains('\')
            ) {
                throw 'previous release path fields are invalid'
            }
            $previousBundleParts = @($previousBundleRelative -split '/')
            if (
                $previousBundleParts.Count -lt 1 -or
                @($previousBundleParts | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0
            ) {
                throw 'previous bundle relative path is invalid'
            }
            $previousTrustedPath = Resolve-AgentSupervisorTrustedCorePath `
                -Candidate $previousPath `
                -AllowedRoots $allowedRoots
            if ([string]::IsNullOrWhiteSpace($previousTrustedPath)) {
                throw 'previous core path is untrusted'
            }
            $previousBundlePath = [IO.Path]::GetFullPath((Join-Path `
                $previousTrustedPath `
                ($previousBundleParts -join [IO.Path]::DirectorySeparatorChar)
            ))
            $previousRootPrefix = $previousTrustedPath.TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            ) + [IO.Path]::DirectorySeparatorChar
            if (-not $previousBundlePath.StartsWith($previousRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'previous bundle escaped the release root'
            }
            $previousBundleSnapshot = Read-AgentSupervisorStableFileBytes `
                -Path $previousBundlePath `
                -MaximumBytes 16777216
            if (
                $null -eq $previousBundleSnapshot -or
                [string]$previousBundleSnapshot.Sha256 -cne [string]$previous.bundle_sha256
            ) {
                throw 'previous bundle digest mismatch'
            }
        }
        $identityJson = $active | ConvertTo-Json -Compress -Depth 8
        $identityBytes = [Text.Encoding]::UTF8.GetBytes($identityJson)
        $script:AgentSupervisorVerifiedReleaseBundles[$trustedPath] = [pscustomobject]@{
            BundleBytes = [byte[]]$bundleSnapshot.Bytes
            BundlePath = [string]$bundleSnapshot.FullPath
            IdentityBytes = $identityBytes
            PointerSha256 = [string]$pointerSnapshot.Sha256
            Version = $activeVersion
        }
        return $trustedPath
    } catch {
        return (Join-Path $defaultRoot '.rejected-core')
    }
}

function ConvertTo-AgentSupervisorCommandCategory {
    param([AllowEmptyString()][string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $trimmed = $Command.Trim()
    $normalized = $trimmed.ToLowerInvariant()
    $safeCategories = @(
        'bash', 'build', 'cargo', 'cmd', 'curl', 'docker', 'dotnet', 'git', 'go',
        'gradle', 'java', 'lint', 'maven', 'node', 'npm', 'npx', 'playwright',
        'pnpm', 'powershell', 'powershell-syntax', 'pwsh', 'pytest', 'python',
        'shell', 'test', 'typecheck', 'validation', 'verification',
        'windows-powershell-5.1', 'yarn'
    )
    if ($safeCategories -contains $normalized) { return $normalized }

    $firstToken = ''
    if ($trimmed[0] -eq [char]34 -or $trimmed[0] -eq [char]39) {
        $closingIndex = $trimmed.IndexOf($trimmed[0], 1)
        if ($closingIndex -gt 1) { $firstToken = $trimmed.Substring(1, $closingIndex - 1) }
    } else {
        $firstToken = ($trimmed -split '\s+', 2)[0]
    }
    if (-not [string]::IsNullOrWhiteSpace($firstToken)) {
        try {
            $executable = [IO.Path]::GetFileNameWithoutExtension($firstToken).ToLowerInvariant()
        } catch {
            # Tool command text is untrusted host input. Invalid path characters
            # must use the privacy-safe unknown-category hash, not abort the adapter.
            $executable = ''
        }
        if ($executable -match '^python(?:\d+(?:\.\d+)*)?$') { return 'python' }
        if ($safeCategories -contains $executable) { return $executable }
        if ($executable -eq 'powershell') { return 'powershell' }
    }

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($trimmed))
        $hex = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
        return ('other-sha256-' + $hex.Substring(0, 16))
    } finally {
        $hasher.Dispose()
    }
}

function Get-AgentSupervisorPythonTimeoutSeconds {
    $defaultSeconds = [double]120.0
    $minimumSeconds = [double]0.1
    # Registered quality gates are core-owned and may run for as long as 1800
    # seconds.  The thin adapter needs a small process/stream-close margin above
    # that deadline; it must not terminate the trusted core at the old 600-second
    # wrapper limit.  This value is only a process lifetime ceiling and never
    # grants completion or evidence authority.
    $maximumSeconds = [double]1820.0
    $raw = $env:AGENT_SUPERVISOR_PYTHON_TIMEOUT_SECONDS
    if ([string]::IsNullOrWhiteSpace($raw)) { return $defaultSeconds }

    [double]$parsed = 0.0
    $valid = [double]::TryParse(
        $raw,
        [Globalization.NumberStyles]::Float,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsed
    )
    if (-not $valid -or [double]::IsNaN($parsed) -or [double]::IsInfinity($parsed)) {
        return $defaultSeconds
    }
    return [Math]::Max($minimumSeconds, [Math]::Min($maximumSeconds, $parsed))
}

function ConvertTo-AgentSupervisorNativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = New-Object Text.StringBuilder
    $null = $builder.Append([char]34)
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes += 1
            continue
        }
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

function Resolve-AgentSupervisorSystemTaskkillPath {
    [CmdletBinding()]
    param()

    try {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $null }
        $systemDirectory = [Environment]::SystemDirectory
        if ([string]::IsNullOrWhiteSpace($systemDirectory) -or -not [IO.Path]::IsPathRooted($systemDirectory)) {
            return $null
        }
        $systemFull = [IO.Path]::GetFullPath($systemDirectory)
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $systemFull)) { return $null }
        $resolvedSystem = (Resolve-Path -LiteralPath $systemFull -ErrorAction Stop).Path
        if ($resolvedSystem -ine $systemFull) { return $null }

        $candidate = Join-Path $resolvedSystem 'taskkill.exe'
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
        $candidateFull = [IO.Path]::GetFullPath($candidate)
        $item = Get-Item -LiteralPath $candidateFull -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $null
        }
        $resolved = (Resolve-Path -LiteralPath $candidateFull -ErrorAction Stop).Path
        if ($resolved -ine $candidateFull -or (Split-Path -Parent $resolved) -ine $resolvedSystem) {
            return $null
        }
        return $resolved
    } catch {
        return $null
    }
}

function Resolve-AgentSupervisorSafeEnvironmentDirectory {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    try {
        if ([string]::IsNullOrWhiteSpace($Value) -or -not [IO.Path]::IsPathRooted($Value)) {
            return $null
        }
        $fullPath = [IO.Path]::GetFullPath($Value)
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $fullPath)) { return $null }
        $resolved = (Resolve-Path -LiteralPath $fullPath -ErrorAction Stop).Path
        if ($resolved -ine $fullPath) { return $null }
        return $resolved
    } catch {
        return $null
    }
}

function Test-AgentSupervisorSafeEnvironmentScalar {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][ValidateSet('locale', 'session')][string]$Kind
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $maximumLength = if ($Kind -eq 'locale') { 64 } else { 256 }
    if ($Value.Length -gt $maximumLength) { return $false }
    $pattern = if ($Kind -eq 'locale') { '^[A-Za-z0-9_.@-]+$' } else { '^[A-Za-z0-9._:-]+$' }
    return ($Value -cmatch $pattern)
}

function Resolve-AgentSupervisorContainmentLauncherPath {
    $expectedSha256 = '592b9db449b97c57a0934bfbd193763bfed4511afefa7bd1d403d0cc66f87064'
    try {
        $scriptsRoot = [IO.Path]::GetFullPath([string]$script:AgentSupervisorAdapterScriptsRoot)
        if (
            -not [IO.Path]::IsPathRooted($scriptsRoot) -or
            -not (Test-Path -LiteralPath $scriptsRoot -PathType Container) -or
            -not (Test-AgentSupervisorDirectoryChain -Directory $scriptsRoot)
        ) {
            return $null
        }
        $resolvedRoot = (Resolve-Path -LiteralPath $scriptsRoot -ErrorAction Stop).Path
        if ($resolvedRoot -ine $scriptsRoot) { return $null }
        if (-not (Test-AgentSupervisorDirectoryChain -Directory $resolvedRoot)) { return $null }
        $candidate = [IO.Path]::GetFullPath((Join-Path $resolvedRoot 'supervisor-process-job.py'))
        $itemBefore = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if ($itemBefore.PSIsContainer -or (($itemBefore.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            return $null
        }
        $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
        if ($resolved -ine $candidate -or (Split-Path -Parent $resolved) -ine $resolvedRoot) { return $null }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $digest = $hasher.ComputeHash($stream) } finally { $stream.Dispose() }
        } finally {
            $hasher.Dispose()
        }
        $actualSha256 = ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
        $itemAfter = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
        if (
            $actualSha256 -cne $expectedSha256 -or
            $itemBefore.Length -ne $itemAfter.Length -or
            $itemBefore.LastWriteTimeUtc -ne $itemAfter.LastWriteTimeUtc
        ) {
            return $null
        }
        return $resolved
    } catch {
        return $null
    }
}

function Get-AgentSupervisorContainmentLauncherSource {
    $expectedSha256 = '592b9db449b97c57a0934bfbd193763bfed4511afefa7bd1d403d0cc66f87064'
    $expectedLength = [long]17772
    $stream = $null
    $hasher = $null
    try {
        $resolved = Resolve-AgentSupervisorContainmentLauncherPath
        if ([string]::IsNullOrWhiteSpace($resolved)) { return $null }

        # Read the exact validated bytes while denying writes and replacement.
        # Invocation executes this immutable in-memory copy, never the path again,
        # so a same-length/same-mtime swap after validation cannot win a TOCTOU race.
        $stream = [IO.File]::Open(
            $resolved,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        if ($stream.Length -ne $expectedLength) { return $null }
        $bytes = New-Object byte[] ([int]$expectedLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { return $null }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) { return $null }
        $hasher = [Security.Cryptography.SHA256]::Create()
        $actualSha256 = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        if ($actualSha256 -cne $expectedSha256) { return $null }
        return [Convert]::ToBase64String($bytes)
    } catch {
        return $null
    } finally {
        if ($null -ne $hasher) { $hasher.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-AgentSupervisorProcessTreeKillAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $treeKillMethods = @(
            [Diagnostics.Process].GetMethods(
                [Reflection.BindingFlags]'Public,Instance'
            ) | Where-Object {
                if ($_.Name -cne 'Kill') { return $false }
                $parameters = @($_.GetParameters())
                return (
                    $parameters.Count -eq 1 -and
                    $parameters[0].ParameterType -eq [bool]
                )
            }
        )
        return ($treeKillMethods.Count -gt 0)
    } catch {
        return $false
    }
}

function Stop-AgentSupervisorProcessTree {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    $targetPid = 0
    try { $targetPid = [int]$Process.Id } catch { return }
    # Use one cleanup deadline for the trusted taskkill fallback and the direct
    # parent kill. The caller closes the kill-on-close Job Object first, so this
    # path is normally only a bounded compatibility fallback.
    $cleanupBudgetMilliseconds = 750
    $cleanupDeadline = [DateTime]::UtcNow.AddMilliseconds($cleanupBudgetMilliseconds)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        try {
            if (Test-AgentSupervisorProcessTreeKillAvailable) {
                # Always attempt the tree-aware overload, including the output-
                # stream failure case where the root may have just exited while
                # a descendant still owns an inherited pipe. The Process API may
                # reject an already-reaped root, but a HasExited pre-check would
                # guarantee that no descendant cleanup is even attempted.
                $Process.Kill($true)
            } elseif (-not $Process.HasExited) {
                # Fixed interpreter probes cannot spawn descendants, so their
                # compatibility cleanup may terminate only the probe process.
                $Process.Kill()
            }
            $remaining = [Math]::Max(0, [int][Math]::Ceiling(($cleanupDeadline - [DateTime]::UtcNow).TotalMilliseconds))
            if ($remaining -gt 0) { $null = $Process.WaitForExit($remaining) }
        } catch { }
        return
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $killer = $null
        try {
            $taskkillPath = Resolve-AgentSupervisorSystemTaskkillPath
            if ([string]::IsNullOrWhiteSpace($taskkillPath)) { throw 'trusted taskkill unavailable' }
            $killerInfo = New-Object Diagnostics.ProcessStartInfo
            $killerInfo.FileName = $taskkillPath
            $killerInfo.Arguments = '/PID ' + [string]$targetPid + ' /T /F'
            $killerInfo.UseShellExecute = $false
            $killerInfo.CreateNoWindow = $true
            $killerInfo.RedirectStandardOutput = $true
            $killerInfo.RedirectStandardError = $true
            $killerInfo.EnvironmentVariables.Clear()
            $trustedWindowsRoot = Split-Path -Parent (Split-Path -Parent $taskkillPath)
            $killerInfo.EnvironmentVariables['SYSTEMROOT'] = $trustedWindowsRoot
            $killerInfo.EnvironmentVariables['WINDIR'] = $trustedWindowsRoot
            $killerInfo.EnvironmentVariables['PATH'] = Split-Path -Parent $taskkillPath
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

function Test-AgentSupervisorFixedPythonProbe {
    param(
        [string]$Operation,
        [string[]]$PrefixArgs,
        [string[]]$Arguments
    )

    if ($Operation -notin @('python-probe', 'python-identity', 'python-runtime-probe')) { return $false }
    if (@($PrefixArgs).Count -ne 0) { return $false }
    if (@($Arguments).Count -ne 6) { return $false }
    $fixedPrefix = @('-I', '-S', '-X', 'utf8', '-c')
    for ($index = 0; $index -lt $fixedPrefix.Count; $index += 1) {
        if ($Arguments[$index] -cne $fixedPrefix[$index]) { return $false }
    }
    $expectedCode = switch ($Operation) {
        'python-identity' { 'import json,os,site,sys,sysconfig; user_site=site.getusersitepackages(); site_paths=[*getattr(site,"getsitepackages",lambda:[])(),user_site]; dependency_roots=[p for k,p in sysconfig.get_paths().items() if k in ("purelib","platlib","stdlib","platstdlib") and p]+([user_site] if user_site else []); print(json.dumps({"executable":os.path.realpath(sys.executable),"site_paths":[os.path.realpath(p) for p in site_paths if p],"dependency_roots":[os.path.realpath(p) for p in dependency_roots]},separators=(",",":"))); raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' }
        default { 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' }
    }
    return ($Arguments[5] -ceq $expectedCode)
}

function Invoke-AgentSupervisorPython {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$PrefixArgs = @(),
        [string[]]$Arguments = @(),
        [string]$Operation = 'supervisor-operation',
        [AllowEmptyString()][string]$WorkingDirectory = '',
        [Nullable[double]]$TimeoutSeconds = $null,
        [byte[]]$InputBytes = @(),
        [switch]$CaptureOutput,
        [switch]$SuppressOutput,
        [switch]$IsolatedEnvironment,
        [switch]$Silent
    )

    $safeOperation = if ($Operation -match '^[A-Za-z0-9._-]{1,64}$') { $Operation } else { 'supervisor-operation' }
    $effectiveSeconds = if ($null -eq $TimeoutSeconds) {
        Get-AgentSupervisorPythonTimeoutSeconds
    } else {
        $requested = [double]$TimeoutSeconds
        if ([double]::IsNaN($requested) -or [double]::IsInfinity($requested)) { [double]120.0 }
        else { [Math]::Max([double]0.1, [Math]::Min([double]1820.0, $requested)) }
    }
    # Windows process creation on a cold interpreter can exceed sub-second hook
    # budgets. Keep a bounded startup allowance inside the host wall-clock while
    # preserving the configured execution deadline once the contained launcher is
    # running. The outer tests retain a stricter total wall-clock ceiling.
    $runningOnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $fixedProbe = Test-AgentSupervisorFixedPythonProbe `
        -Operation $safeOperation `
        -PrefixArgs $PrefixArgs `
        -Arguments $Arguments
    # Every non-probe operation must execute through the immutable stage-0 and
    # its framed, in-memory release bundle. Windows stage-0 additionally owns a
    # kill-on-close Job Object; Linux/macOS rely on the parent Kill(bool) gate.
    $useContainment = -not $fixedProbe
    $startupGraceSeconds = if ($useContainment) {
        [double]1.5
    } elseif ($runningOnWindows) {
        [double]1.0
    } else {
        [double]0.0
    }
    $timeoutMilliseconds = [int][Math]::Ceiling(($effectiveSeconds + $startupGraceSeconds) * 1000.0)
    $process = $null
    $commandLock = $null
    $runtimeFrame = $null
    try {
        $boundLauncherTarget = ''
        $boundReleaseBinding = $null
        if (-not $fixedProbe) {
            $targetIndex = 0
            $candidateArguments = @($Arguments)
            while ($targetIndex -lt $candidateArguments.Count) {
                $targetArgument = [string]$candidateArguments[$targetIndex]
                if ($targetArgument -in @('-E', '-P', '-I', '-s', '-S', '-B', '-u')) {
                    $targetIndex += 1
                    continue
                }
                if ($targetArgument -ceq '-X' -and ($targetIndex + 1) -lt $candidateArguments.Count) {
                    $targetIndex += 2
                    continue
                }
                if ($targetArgument.StartsWith('-X', [StringComparison]::Ordinal)) {
                    $targetIndex += 1
                    continue
                }
                break
            }
            if ($targetIndex -lt $candidateArguments.Count) {
                $candidateTarget = [string]$candidateArguments[$targetIndex]
                if ([IO.Path]::IsPathRooted($candidateTarget)) {
                    $candidateFull = [IO.Path]::GetFullPath($candidateTarget)
                    if (
                        $script:AgentSupervisorVerifiedLauncherHashes.ContainsKey($candidateFull) -and
                        $script:AgentSupervisorVerifiedReleaseBundles.ContainsKey($candidateFull)
                    ) {
                        $boundLauncherTarget = $candidateFull
                        $boundReleaseBinding = $script:AgentSupervisorVerifiedReleaseBundles[$candidateFull]
                    }
                }
            }
        }
        if (-not $runningOnWindows -and -not $fixedProbe) {
            # POSIX hosts have no Job Object. Refuse stateful Supervisor work
            # before launch unless both the bundle-bound launcher and bounded
            # descendant cleanup are available.
            if (-not (Test-AgentSupervisorProcessTreeKillAvailable)) {
                throw 'tree-aware process cleanup is unavailable'
            }
            if ([string]::IsNullOrWhiteSpace($boundLauncherTarget) -or $null -eq $boundReleaseBinding) {
                throw 'bundle-bound Supervisor launcher is unavailable'
            }
        }
        if ($runningOnWindows) {
            if (-not [IO.Path]::IsPathRooted($Command) -or -not (Test-Path -LiteralPath $Command -PathType Leaf)) {
                throw 'Python command must be an existing absolute file'
            }
            $commandFull = [IO.Path]::GetFullPath($Command)
            if (-not $script:AgentSupervisorVerifiedExecutableHashes.ContainsKey($commandFull)) {
                $validatedCommand = Resolve-AgentSupervisorTrustedPythonPath `
                    -Candidate $commandFull `
                    -AllowedRoots @(Get-AgentSupervisorPythonAllowedRoots) `
                    -KnownExecutables @($commandFull)
                if ([string]::IsNullOrWhiteSpace($validatedCommand) -or $validatedCommand -ine $commandFull) {
                    throw 'Python command trust validation failed'
                }
            }
            $expectedCommandSha256 = [string]$script:AgentSupervisorVerifiedExecutableHashes[$commandFull]
            if ([string]::IsNullOrWhiteSpace($expectedCommandSha256)) {
                throw 'Python command identity is unbound'
            }
        }
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $Command
        $containmentSource = if ($useContainment) {
            Get-AgentSupervisorContainmentLauncherSource
        } else {
            $null
        }
        if ($useContainment -and [string]::IsNullOrWhiteSpace($containmentSource)) {
            throw 'trusted process containment launcher unavailable'
        }
        $containedArguments = @($Arguments)
        if ($useContainment) {
            if ([string]::IsNullOrWhiteSpace($boundLauncherTarget) -or $null -eq $boundReleaseBinding) {
                throw 'trusted core release bundle is unbound'
            }
            $remainingArguments = @()
            if (($targetIndex + 1) -lt $containedArguments.Count) {
                $remainingArguments = @($containedArguments[($targetIndex + 1)..($containedArguments.Count - 1)])
            }
            $runtimeFrame = New-AgentSupervisorRuntimeFrame `
                -IdentityBytes ([byte[]]$boundReleaseBinding.IdentityBytes) `
                -BundleBytes ([byte[]]$boundReleaseBinding.BundleBytes) `
                -PayloadBytes ([byte[]]$InputBytes)
            $containedArguments = @(
                '--agent-supervisor-bound-bundle',
                $boundLauncherTarget
            ) + $remainingArguments
        }
        $allArguments = if ($useContainment) {
            $containmentCommand = "import base64,os;exec(compile(base64.b64decode(os.environ.pop('AGENT_SUPERVISOR_CONTAINMENT_SOURCE_B64'),validate=True),'<agent-supervisor-containment>','exec'))"
            @($PrefixArgs) + @('-I', '-S', '-X', 'utf8', '-c', $containmentCommand, '--') + $containedArguments
        } else {
            @($PrefixArgs) + @($Arguments)
        }
        $startInfo.Arguments = (($allArguments | ForEach-Object { ConvertTo-AgentSupervisorNativeArgument -Value ([string]$_) }) -join ' ')
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = ($null -ne $runtimeFrame)
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            if (
                -not [IO.Path]::IsPathRooted($WorkingDirectory) -or
                -not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)
            ) {
                throw 'working directory must be an existing absolute directory'
            }
            $startInfo.WorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory -ErrorAction Stop).Path
        }
        $startInfo.EnvironmentVariables.Remove('AGENT_SUPERVISOR_CONTAINMENT_SOURCE_B64')
        $startInfo.EnvironmentVariables.Remove('AGENT_SUPERVISOR_DEPENDENCY_ROOTS')
        if ($IsolatedEnvironment) {
            $trustedInstallHome = Get-AgentSupervisorProfileHome
            if ([string]::IsNullOrWhiteSpace($trustedInstallHome)) {
                throw 'adapter install home could not be derived'
            }
            # ProcessStartInfo begins as a full copy of the host environment.
            # Rebuild from an exact allowlist so secrets, profiling hooks,
            # PSModulePath, COR_*, COMPlus_*, and caller-selected trust values
            # cannot cross the isolation boundary.
            $startInfo.EnvironmentVariables.Clear()
            $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_INSTALL_HOME'] = $trustedInstallHome
            $startInfo.EnvironmentVariables['USERPROFILE'] = $trustedInstallHome
            $startInfo.EnvironmentVariables['HOME'] = $trustedInstallHome
            foreach ($directoryVariable in @('TEMP', 'TMP')) {
                $safeDirectory = Resolve-AgentSupervisorSafeEnvironmentDirectory `
                    -Value ([string][Environment]::GetEnvironmentVariable($directoryVariable))
                if (-not [string]::IsNullOrWhiteSpace($safeDirectory)) {
                    $startInfo.EnvironmentVariables[$directoryVariable] = $safeDirectory
                }
            }
            foreach ($knownFolder in @(
                [pscustomobject]@{ Name = 'APPDATA'; Folder = [Environment+SpecialFolder]::ApplicationData },
                [pscustomobject]@{ Name = 'LOCALAPPDATA'; Folder = [Environment+SpecialFolder]::LocalApplicationData }
            )) {
                $knownFolderPath = [Environment]::GetFolderPath($knownFolder.Folder)
                $safeKnownFolder = Resolve-AgentSupervisorSafeEnvironmentDirectory -Value $knownFolderPath
                if (-not [string]::IsNullOrWhiteSpace($safeKnownFolder)) {
                    $startInfo.EnvironmentVariables[[string]$knownFolder.Name] = $safeKnownFolder
                }
            }
            foreach ($localeVariable in @('LANG', 'LC_ALL', 'LC_CTYPE')) {
                $localeValue = [string][Environment]::GetEnvironmentVariable($localeVariable)
                if (Test-AgentSupervisorSafeEnvironmentScalar -Value $localeValue -Kind 'locale') {
                    $startInfo.EnvironmentVariables[$localeVariable] = $localeValue
                }
            }
            $sessionValue = [string][Environment]::GetEnvironmentVariable('CODEX_THREAD_ID')
            if (Test-AgentSupervisorSafeEnvironmentScalar -Value $sessionValue -Kind 'session') {
                $startInfo.EnvironmentVariables['CODEX_THREAD_ID'] = $sessionValue
            }
            if ($runningOnWindows) {
                $taskkillPath = Resolve-AgentSupervisorSystemTaskkillPath
                if ([string]::IsNullOrWhiteSpace($taskkillPath)) {
                    throw 'trusted Windows system directory is unavailable'
                }
                $trustedSystemDirectory = Split-Path -Parent $taskkillPath
                $trustedWindowsRoot = Split-Path -Parent $trustedSystemDirectory
                $trustedCommandProcessor = Join-Path $trustedSystemDirectory 'cmd.exe'
                $commandProcessorItem = Get-Item -LiteralPath $trustedCommandProcessor -Force -ErrorAction Stop
                if (
                    $commandProcessorItem.PSIsContainer -or
                    (($commandProcessorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                    (Resolve-Path -LiteralPath $trustedCommandProcessor -ErrorAction Stop).Path -ine
                        [IO.Path]::GetFullPath($trustedCommandProcessor)
                ) {
                    throw 'trusted Windows command processor is unavailable'
                }
                $startInfo.EnvironmentVariables['SYSTEMROOT'] = $trustedWindowsRoot
                $startInfo.EnvironmentVariables['WINDIR'] = $trustedWindowsRoot
                $startInfo.EnvironmentVariables['PATH'] = (
                    @($trustedSystemDirectory, (Split-Path -Parent $commandFull)) -join [IO.Path]::PathSeparator
                )
                $startInfo.EnvironmentVariables['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
                $startInfo.EnvironmentVariables['COMSPEC'] = $trustedCommandProcessor
                $startInfo.EnvironmentVariables['NoDefaultCurrentDirectoryInExePath'] = '1'
            } else {
                $trustedPathEntries = @()
                if ([IO.Path]::IsPathRooted($Command)) {
                    $trustedPathEntries += Split-Path -Parent ([IO.Path]::GetFullPath($Command))
                }
                foreach ($systemPath in @('/usr/local/bin', '/usr/bin', '/bin')) {
                    $safeSystemPath = Resolve-AgentSupervisorSafeEnvironmentDirectory -Value $systemPath
                    if (-not [string]::IsNullOrWhiteSpace($safeSystemPath)) {
                        $trustedPathEntries += $safeSystemPath
                    }
                }
                if ($trustedPathEntries.Count -gt 0) {
                    $startInfo.EnvironmentVariables['PATH'] = (
                        @($trustedPathEntries | Select-Object -Unique) -join [IO.Path]::PathSeparator
                    )
                }
            }
            if ($useContainment -and @($script:AgentSupervisorVerifiedDependencyRoots).Count -gt 0) {
                $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_DEPENDENCY_ROOTS'] = (
                    @($script:AgentSupervisorVerifiedDependencyRoots) -join [IO.Path]::PathSeparator
                )
            }
        }
        if ($useContainment) {
            $startInfo.EnvironmentVariables['AGENT_SUPERVISOR_CONTAINMENT_SOURCE_B64'] = $containmentSource
        }
        $startInfo.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
        $startInfo.EnvironmentVariables['PYTHONUTF8'] = '1'
        if ($startInfo.PSObject.Properties.Name -contains 'StandardOutputEncoding') {
            $utf8 = New-Object Text.UTF8Encoding($false)
            $startInfo.StandardOutputEncoding = $utf8
            $startInfo.StandardErrorEncoding = $utf8
        }

        if ($runningOnWindows) {
            # Keep the verified executable object non-replaceable until
            # CreateProcess has opened it, and recompute SHA-256 through this same
            # locked handle so a resolve-to-lock path swap fails closed.
            $commandLock = [IO.File]::Open(
                $commandFull,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            $actualCommandSha256 = Get-AgentSupervisorStreamSha256 -Stream $commandLock
            if ($actualCommandSha256 -cne $expectedCommandSha256) {
                throw 'Python command identity changed before process creation'
            }
        }

        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'process start returned false' }
        if ($null -ne $commandLock) {
            $commandLock.Dispose()
            $commandLock = $null
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $runtimeFrame) {
            try {
                $process.StandardInput.BaseStream.Write($runtimeFrame, 0, $runtimeFrame.Length)
                $process.StandardInput.BaseStream.Flush()
            } finally {
                $process.StandardInput.Close()
            }
        }
        if (-not $process.WaitForExit($timeoutMilliseconds)) {
            $containedProcessExited = $false
            if ($runningOnWindows -and $useContainment) {
                try {
                    if (-not $process.HasExited) { $process.Kill() }
                    $containedProcessExited = $process.WaitForExit(750)
                } catch { }
            }
            if (-not $runningOnWindows) {
                # POSIX must use the tree-aware primitive directly. Killing the
                # parent first can make an otherwise-live descendant tree
                # unreachable through Diagnostics.Process.
                Stop-AgentSupervisorProcessTree -Process $process
            } elseif (-not $containedProcessExited) {
                Stop-AgentSupervisorProcessTree -Process $process
            }
            if (-not $Silent) {
                [Console]::Error.WriteLine("Supervisor Python operation '$safeOperation' timed out; state is degraded.")
            }
            return [pscustomobject]@{ ExitCode = 4; TimedOut = $true; Started = $true; StandardOutput = '' }
        }
        $null = $process.WaitForExit(2000)
        $streamsComplete = [Threading.Tasks.Task]::WaitAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask),
            2000
        )
        if (-not $streamsComplete) {
            if (-not $runningOnWindows -or -not $useContainment) {
                Stop-AgentSupervisorProcessTree -Process $process
            }
            if (-not $Silent) {
                [Console]::Error.WriteLine("Supervisor Python operation '$safeOperation' did not close its output streams; state is degraded.")
            }
            return [pscustomobject]@{ ExitCode = 4; TimedOut = $true; Started = $true; StandardOutput = '' }
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $processExitCode = [int]$process.ExitCode
        if ($processExitCode -eq 125) {
            if (-not $Silent) {
                [Console]::Error.WriteLine("Supervisor Python operation '$safeOperation' could not establish process containment; state is degraded.")
            }
            return [pscustomobject]@{ ExitCode = 4; TimedOut = $false; Started = $true; StandardOutput = '' }
        }
        if (-not $SuppressOutput) {
            $previousOutputEncoding = [Console]::OutputEncoding
            try {
                [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
                if (-not [string]::IsNullOrEmpty($stdout)) { [Console]::Out.Write($stdout) }
                if (-not [string]::IsNullOrEmpty($stderr)) { [Console]::Error.Write($stderr) }
            } finally {
                [Console]::OutputEncoding = $previousOutputEncoding
            }
        }
        $capturedOutput = if ($CaptureOutput) { [string]$stdout } else { '' }
        return [pscustomobject]@{ ExitCode = $processExitCode; TimedOut = $false; Started = $true; StandardOutput = $capturedOutput }
    } catch {
        if ($null -ne $process) { Stop-AgentSupervisorProcessTree -Process $process }
        if (-not $Silent) {
            [Console]::Error.WriteLine("Supervisor Python operation '$safeOperation' failed to start or complete; state is degraded.")
        }
        return [pscustomobject]@{ ExitCode = 4; TimedOut = $false; Started = $false; StandardOutput = '' }
    } finally {
        if ($null -ne $commandLock) { $commandLock.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Get-AgentSupervisorPythonCommand {
    <# Resolve and probe a real Python interpreter, excluding Windows Store aliases. #>
    $script:AgentSupervisorVerifiedDependencyRoots = @()
    Remove-Item Env:AGENT_SUPERVISOR_GATE_RUNNER_ROOT -ErrorAction SilentlyContinue
    Remove-Item Env:AGENT_SUPERVISOR_GATE_RUNNER_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:AGENT_SUPERVISOR_GATE_RUNNER_CONTRACT -ErrorAction SilentlyContinue
    $discovered = @()
    $runningOnWindows = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    $pythonCommandNames = if ($runningOnWindows) {
        @('python.exe', 'python3.exe')
    } else {
        @('python', 'python3')
    }
    foreach ($name in $pythonCommandNames) {
        foreach ($python in @(Get-Command $name -CommandType Application -ErrorAction SilentlyContinue)) {
            if ($python.Source -notmatch '\\Microsoft\\WindowsApps\\') {
                $discovered += [pscustomobject]@{ Command = $python.Source; PrefixArgs = @() }
            }
        }
    }

    $allowedRoots = @(Get-AgentSupervisorPythonAllowedRoots)
    $candidates = @()
    $trustedRegistryPython = Get-AgentSupervisorTrustedRegistryPythonPath
    if (-not [string]::IsNullOrWhiteSpace($trustedRegistryPython)) {
        $trustedRegistryRoot = Split-Path -Parent $trustedRegistryPython
        if ($allowedRoots -notcontains $trustedRegistryRoot) { $allowedRoots += $trustedRegistryRoot }
        $candidates += [pscustomobject]@{ Command = $trustedRegistryPython; PrefixArgs = @() }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:AGENT_SUPERVISOR_PYTHON)) {
        $trustedExplicit = Resolve-AgentSupervisorTrustedPythonPath `
            -Candidate $env:AGENT_SUPERVISOR_PYTHON `
            -AllowedRoots $allowedRoots `
            -KnownExecutables @()
        if (-not [string]::IsNullOrWhiteSpace($trustedExplicit)) {
            $candidates += [pscustomobject]@{ Command = $trustedExplicit; PrefixArgs = @() }
        }
    }
    foreach ($candidate in $discovered) {
        $trustedDiscovered = Resolve-AgentSupervisorTrustedPythonPath `
            -Candidate ([string]$candidate.Command) `
            -AllowedRoots $allowedRoots `
            -KnownExecutables @([string]$candidate.Command)
        if (-not [string]::IsNullOrWhiteSpace($trustedDiscovered)) {
            $candidates += [pscustomobject]@{
                Command = $trustedDiscovered
                PrefixArgs = @($candidate.PrefixArgs)
            }
        }
    }

    $seen = @{}
    foreach ($candidate in $candidates) {
        $key = ([string]$candidate.Command).ToLowerInvariant() + '|' + (($candidate.PrefixArgs -join ' '))
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $command = [string]$candidate.Command
        $prefixArgs = @($candidate.PrefixArgs)
        try {
            $probeTimeout = [Math]::Max([double]1.0, [Math]::Min([double](Get-AgentSupervisorPythonTimeoutSeconds), [double]5.0))
            # One fixed probe both enforces the minimum version and reports the
            # exact runtime that executed it. The reported file is then independently
            # revalidated against the original external trust roots; re-executing the
            # same runtime would add latency without adding a new trust assertion.
            $identityArgs = @('-I', '-S', '-X', 'utf8', '-c', 'import json,os,site,sys,sysconfig; user_site=site.getusersitepackages(); site_paths=[*getattr(site,"getsitepackages",lambda:[])(),user_site]; dependency_roots=[p for k,p in sysconfig.get_paths().items() if k in ("purelib","platlib","stdlib","platstdlib") and p]+([user_site] if user_site else []); print(json.dumps({"executable":os.path.realpath(sys.executable),"site_paths":[os.path.realpath(p) for p in site_paths if p],"dependency_roots":[os.path.realpath(p) for p in dependency_roots]},separators=(",",":"))); raise SystemExit(0 if sys.version_info >= (3, 11) else 1)')
            $identity = Invoke-AgentSupervisorPython -Command $command -PrefixArgs $prefixArgs -Arguments $identityArgs -Operation 'python-identity' -TimeoutSeconds $probeTimeout -CaptureOutput -SuppressOutput -IsolatedEnvironment -Silent
            if ($identity.ExitCode -ne 0) { continue }
            $identityLines = @(
                ([string]$identity.StandardOutput -split "`r?`n") |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
            if ($identityLines.Count -ne 1) { continue }
            $identityPayload = $identityLines[0] | ConvertFrom-Json -ErrorAction Stop
            $reportedExecutable = [string]$identityPayload.executable
            $reportedSitePaths = @($identityPayload.site_paths)
            $reportedDependencyRoots = @($identityPayload.dependency_roots)
            if ([string]::IsNullOrWhiteSpace($reportedExecutable) -or -not [IO.Path]::IsPathRooted($reportedExecutable)) {
                continue
            }
            $runtimeCandidate = [IO.Path]::GetFullPath($reportedExecutable)
            # The runtime root is accepted only after a previously trusted
            # launcher identified sys.executable. Revalidate it against the same
            # original trust roots; never promote its reported parent to a root.
            $trustedRuntime = Resolve-AgentSupervisorTrustedPythonPath `
                -Candidate $runtimeCandidate `
                -AllowedRoots $allowedRoots `
                -KnownExecutables @($runtimeCandidate)
            if ([string]::IsNullOrWhiteSpace($trustedRuntime)) { continue }

            # A verified runtime may report its stdlib/purelib roots, but it may
            # not promote an arbitrary path.  Each reported root must first be
            # contained by this fixed trust set derived from the adapter install
            # home and platform installation roots.
            $dependencyTrustRoots = @($allowedRoots)
            $trustedInstallHome = Get-AgentSupervisorProfileHome
            if (-not [string]::IsNullOrWhiteSpace($trustedInstallHome)) {
                $profileDependencyRoots = if ($runningOnWindows) {
                    @((Join-Path $trustedInstallHome 'AppData\Roaming\Python'))
                } else {
                    @(
                        (Join-Path $trustedInstallHome '.local/lib'),
                        (Join-Path $trustedInstallHome 'Library/Python')
                    )
                }
                foreach ($profileDependencyRoot in $profileDependencyRoots) {
                    if (Test-Path -LiteralPath $profileDependencyRoot -PathType Container) {
                        $profileDependencyFull = [IO.Path]::GetFullPath($profileDependencyRoot)
                        if (Test-AgentSupervisorDirectoryChain -Directory $profileDependencyFull) {
                            $resolvedProfileDependency = (
                                Resolve-Path -LiteralPath $profileDependencyFull -ErrorAction Stop
                            ).Path
                            if ($dependencyTrustRoots -notcontains $resolvedProfileDependency) {
                                $dependencyTrustRoots += $resolvedProfileDependency
                            }
                        }
                    }
                }
            }
            $roamingApplicationData = [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::ApplicationData
            )
            if (-not [string]::IsNullOrWhiteSpace($roamingApplicationData)) {
                $runtimeUserPythonRoot = Join-Path $roamingApplicationData 'Python'
                if (Test-Path -LiteralPath $runtimeUserPythonRoot -PathType Container) {
                    $runtimeUserPythonFull = [IO.Path]::GetFullPath($runtimeUserPythonRoot)
                    if (Test-AgentSupervisorDirectoryChain -Directory $runtimeUserPythonFull) {
                        $resolvedRuntimeUserPython = (
                            Resolve-Path -LiteralPath $runtimeUserPythonFull -ErrorAction Stop
                        ).Path
                        if ($dependencyTrustRoots -notcontains $resolvedRuntimeUserPython) {
                            $dependencyTrustRoots += $resolvedRuntimeUserPython
                        }
                    }
                }
            }
            $dependencyAllowedRoots = @()
            foreach ($reportedDependencyRoot in $reportedDependencyRoots) {
                if (
                    -not ($reportedDependencyRoot -is [string]) -or
                    [string]::IsNullOrWhiteSpace($reportedDependencyRoot) -or
                    -not [IO.Path]::IsPathRooted($reportedDependencyRoot)
                ) {
                    continue
                }
                $dependencyFull = [IO.Path]::GetFullPath($reportedDependencyRoot)
                if (-not (Test-Path -LiteralPath $dependencyFull -PathType Container)) { continue }
                if (-not (Test-AgentSupervisorDirectoryChain -Directory $dependencyFull)) { continue }
                $resolvedDependency = (Resolve-Path -LiteralPath $dependencyFull -ErrorAction Stop).Path
                if ($resolvedDependency -ine $dependencyFull) { continue }
                $trustedDependency = $false
                foreach ($dependencyTrustRoot in $dependencyTrustRoots) {
                    if ([string]::IsNullOrWhiteSpace($dependencyTrustRoot)) { continue }
                    $trustFull = [IO.Path]::GetFullPath($dependencyTrustRoot)
                    if (-not (Test-AgentSupervisorDirectoryChain -Directory $trustFull)) { continue }
                    $trustResolved = (Resolve-Path -LiteralPath $trustFull -ErrorAction Stop).Path
                    $trustPrefix = $trustResolved.TrimEnd(
                        [IO.Path]::DirectorySeparatorChar,
                        [IO.Path]::AltDirectorySeparatorChar
                    ) + [IO.Path]::DirectorySeparatorChar
                    if (
                        $resolvedDependency -ieq $trustResolved -or
                        $resolvedDependency.StartsWith($trustPrefix, [StringComparison]::OrdinalIgnoreCase)
                    ) {
                        $trustedDependency = $true
                        break
                    }
                }
                if ($trustedDependency -and $dependencyAllowedRoots -notcontains $resolvedDependency) {
                    $dependencyAllowedRoots += $resolvedDependency
                }
            }
            if ($dependencyAllowedRoots.Count -eq 0) { continue }
            $verifiedDependencyRoots = @()
            foreach ($reportedSitePath in $reportedSitePaths) {
                if (-not ($reportedSitePath -is [string]) -or [string]::IsNullOrWhiteSpace($reportedSitePath)) { continue }
                if (-not [IO.Path]::IsPathRooted($reportedSitePath)) { continue }
                $siteFull = [IO.Path]::GetFullPath($reportedSitePath)
                if ((Split-Path -Leaf $siteFull) -notmatch '^(?i:site-packages|dist-packages)$') { continue }
                if (-not (Test-Path -LiteralPath $siteFull -PathType Container)) { continue }
                if (-not (Test-AgentSupervisorDirectoryChain -Directory $siteFull)) { continue }
                $resolvedSite = (Resolve-Path -LiteralPath $siteFull -ErrorAction Stop).Path
                if ($resolvedSite -ine $siteFull) { continue }
                $allowedDependency = $false
                foreach ($dependencyAllowedRoot in $dependencyAllowedRoots) {
                    if ([string]::IsNullOrWhiteSpace($dependencyAllowedRoot)) { continue }
                    $rootFull = [IO.Path]::GetFullPath($dependencyAllowedRoot)
                    if (-not (Test-AgentSupervisorDirectoryChain -Directory $rootFull)) { continue }
                    $rootPrefix = $rootFull.TrimEnd(
                        [IO.Path]::DirectorySeparatorChar,
                        [IO.Path]::AltDirectorySeparatorChar
                    ) + [IO.Path]::DirectorySeparatorChar
                    if (
                        $resolvedSite -ieq $rootFull -or
                        $resolvedSite.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
                    ) {
                        $allowedDependency = $true
                        break
                    }
                }
                if ($allowedDependency -and $verifiedDependencyRoots -notcontains $resolvedSite) {
                    $verifiedDependencyRoots += $resolvedSite
                }
            }
            if ($verifiedDependencyRoots.Count -eq 0) { continue }
            $script:AgentSupervisorVerifiedDependencyRoots = @($verifiedDependencyRoots)
            $env:AGENT_SUPERVISOR_GATE_RUNNER_ROOT = Split-Path -Parent $trustedRuntime
            $env:AGENT_SUPERVISOR_GATE_RUNNER_NAME = Split-Path -Leaf $trustedRuntime
            $env:AGENT_SUPERVISOR_GATE_RUNNER_CONTRACT = 'verified-active-python-v1'
            return [pscustomobject]@{ Command = $trustedRuntime; PrefixArgs = @() }
        } catch { }
    }
    return $null
}
