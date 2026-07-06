param(
    [string]$Repo,

    [ValidateSet('release', 'action')]
    [string]$Channel = 'release',

    [ValidateSet('list', 'download', 'install', 'uninstall')]
    [string]$Mode = 'list',

    [string]$Version,
    [string]$NamePattern = '*',
    [string]$Workflow,
    [string]$Branch,
    [string]$OutputDir = '.',
    [string]$InstallDir,
    [string]$PackageName,
    [string]$PackagePath,
    [string]$Token = $env:GITHUB_TOKEN,
    [switch]$IncludePrerelease,
    [switch]$Force,

    [Alias('h', '?')]
    [switch]$Help,

    [Alias('-uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$ScriptName = Split-Path -Leaf $ScriptPath
$ScriptDir = Split-Path -Parent $ScriptPath

function Show-Usage {
    Write-Output @"
Usage:
  .\$ScriptName -Repo owner/repo [options]
  .\$ScriptName -Mode uninstall [-InstallDir DIR] [-PackageName NAME]
  .\$ScriptName -Uninstall [-InstallDir DIR] [-PackageName NAME]

Options:
  -Repo VALUE                  GitHub repository: owner/repo, https://github.com/owner/repo, or git@github.com:owner/repo.git
  -Channel release|action      Update channel, default: release
  -Mode list|download|install|uninstall
                               Mode, default: list
  -Uninstall, --uninstall      Alias for -Mode uninstall
  -Version VALUE               Release tag/name or Actions run id/run number/SHA prefix/title
  -NamePattern PATTERN         Asset/artifact wildcard, default: *
  -Workflow VALUE              Workflow file/name/id for Actions
  -Branch VALUE                Branch filter for Actions
  -OutputDir DIR               Download directory, default: .
  -InstallDir DIR              Install root, default for install/uninstall: current directory
  -PackageName NAME            Installed xxx directory name, inferred during install
  -PackagePath FILE            Install an already downloaded release package or action artifact zip
  -Token TOKEN                 GitHub token, default: GITHUB_TOKEN; Actions can also use gh auth
  -IncludePrerelease           Include prerelease releases
  -Force                       Reserved for compatibility; install always supports overwrite
  -Help, -h, -?, --help, --h   Show this help
"@
}

if ($Repo -and (@('--help', '--h') -contains $Repo)) {
    Show-Usage
    return
}

if ($Repo -and (@('--uninstall') -contains $Repo)) {
    $Uninstall = $true
    $Repo = $null
}

if ($PSBoundParameters.Count -eq 0) {
    Show-Usage
    return
}

if ($Help) {
    Show-Usage
    return
}

if ($Uninstall) { $Mode = 'uninstall' }
$RepoWasExplicit = $PSBoundParameters.ContainsKey('Repo')
$ChannelWasExplicit = $PSBoundParameters.ContainsKey('Channel')
$NamePatternWasExplicit = $PSBoundParameters.ContainsKey('NamePattern')
$OutputDirWasExplicit = $PSBoundParameters.ContainsKey('OutputDir')

function Resolve-GitHubToken {
    if ($Token -or $Channel -ne 'action') { return }

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) { return }
    try {
        $resolved = (& gh auth token 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $resolved) {
            Set-Variable -Name Token -Scope Script -Value $resolved
        }
    } catch {
        # Keep unauthenticated mode; the later download warning will explain the token need.
    }
}

function Resolve-GitHubRepo {
    param([string]$Value)

    $text = $Value.Trim()
    if ($text -match '^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?(?:[?#].*)?$') {
        return @{ Owner = $Matches[1]; Name = $Matches[2] }
    }
    if ($text -match '^git@github\.com:([^/]+)/(.+?)(?:\.git)?$') {
        return @{ Owner = $Matches[1]; Name = $Matches[2] }
    }
    if ($text -match '^([^/\s]+)/([^/\s]+)$') {
        return @{ Owner = $Matches[1]; Name = ($Matches[2] -replace '\.git$', '') }
    }
    throw "Invalid GitHub repository address: $Value"
}

function New-GitHubHeaders {
    $headers = @{
        'Accept' = 'application/vnd.github+json'
        'User-Agent' = 'github-updater-ps1'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }
    return $headers
}

function Invoke-GitHubJson {
    param([string]$Uri)

    Invoke-RestMethod -Uri $Uri -Headers (New-GitHubHeaders)
}

function Save-GitHubFile {
    param(
        [string]$Uri,
        [string]$Path
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    Invoke-WebRequest -Uri $Uri -Headers (New-GitHubHeaders) -OutFile $Path
}

function Format-Size {
    param([Int64]$Bytes)

    if ($Bytes -ge 1GB) { return ('{0:n2} GiB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:n2} MiB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:n2} KiB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Get-CurrentPlatform {
    $isWindowsVar = Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue
    if ($isWindowsVar -and $isWindowsVar.Value) { return 'windows' }
    $isLinuxVar = Get-Variable -Name IsLinux -Scope Global -ErrorAction SilentlyContinue
    if ($isLinuxVar -and $isLinuxVar.Value) { return 'linux' }
    $isMacOSVar = Get-Variable -Name IsMacOS -Scope Global -ErrorAction SilentlyContinue
    if ($isMacOSVar -and $isMacOSVar.Value) { return 'macos' }
    if ($env:OS -eq 'Windows_NT') { return 'windows' }
    if ($PSVersionTable.ContainsKey('Platform') -and [string]$PSVersionTable.Platform -eq 'Unix') { return 'linux' }
    return 'windows'
}

function Read-UpdaterInfo {
    param([string]$Root)

    $path = $Root
    if (Test-Path -LiteralPath $Root -PathType Container) {
        $path = Join-Path $Root 'info.Dat'
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    } catch {
        throw "Invalid updater info file: $path"
    }
}

function Get-InfoValue {
    param(
        [object]$Info,
        [string]$Name
    )

    if ($null -eq $Info) { return $null }
    $prop = $Info.PSObject.Properties[$Name]
    if ($prop) { return [string]$prop.Value }
    return $null
}

function Assert-PackageInfoCompatible {
    param(
        [object]$Info,
        [string]$Source
    )

    if ($null -eq $Info) { return }

    $type = (Get-InfoValue -Info $Info -Name 'package_type')
    if ($type) { $type = $type.ToLowerInvariant() }
    if ($type -eq 'apk') {
        throw "Package '$Source' is an Android APK artifact; github-update.ps1 cannot install APK packages. Use an Android installer or choose a Windows package with -NamePattern."
    }
    if ($type -and $type -ne 'archive') {
        throw "Package '$Source' has unsupported package_type '$type'."
    }

    $platform = (Get-InfoValue -Info $Info -Name 'platform')
    if ($platform) { $platform = $platform.ToLowerInvariant() }
    $hostPlatform = Get-CurrentPlatform
    if ($platform -and $platform -ne 'any' -and $platform -ne $hostPlatform) {
        throw "Package '$Source' is for platform '$platform', but this host is '$hostPlatform'. Choose a matching package with -NamePattern."
    }

    $updater = (Get-InfoValue -Info $Info -Name 'updater')
    if ($updater) { $updater = $updater.ToLowerInvariant() }
    if ($updater -and $updater -ne 'ps1') {
        throw "Package '$Source' expects updater '$updater', but this is github-update.ps1. Choose a PowerShell package with -NamePattern."
    }
}

function Resolve-InstallRoot {
    $root = $InstallDir
    if (-not $root) {
        if ((Split-Path -Leaf $ScriptDir) -ne 'ps1') {
            $root = $ScriptDir
        } else {
            $root = '.'
        }
    }
    return (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $root).FullName).Path
}

function Expand-PackageArchive {
    param(
        [string]$ArchivePath,
        [string]$Destination
    )

    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    if ($ArchivePath -match '\.zip$') {
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $Destination -Force
        return
    }
    if ($ArchivePath -match '\.tar\.gz$' -or $ArchivePath -match '\.tgz$') {
        tar -xzf $ArchivePath -C $Destination
        if ($LASTEXITCODE -ne 0) { throw "tar failed to extract $ArchivePath" }
        return
    }
    throw "Unsupported package archive: $ArchivePath"
}

function Get-PackageDirectory {
    param([string]$Root)

    if ($PackageName) {
        $named = Join-Path $Root $PackageName
        if (Test-Path -LiteralPath $named -PathType Container) { return $named }
    }

    $withInstaller = @(Get-ChildItem -LiteralPath $Root -Directory | Where-Object {
        (Test-Path -LiteralPath (Join-Path $_.FullName 'install.ps1')) -or
        (Test-Path -LiteralPath (Join-Path $_.FullName 'install.sh'))
    })
    if ($withInstaller.Count -eq 1) { return $withInstaller[0].FullName }
    if ($withInstaller.Count -gt 1) { throw 'Multiple package directories with install script found. Use -PackageName.' }

    $dirs = @(Get-ChildItem -LiteralPath $Root -Directory | Sort-Object Name)
    if ($dirs.Count -eq 1) { return $dirs[0].FullName }
    throw 'No top-level package directory found in archive.'
}

function Repair-InstallScriptCompatibility {
    param([string]$ScriptPath)

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { return }

    $text = Get-Content -LiteralPath $ScriptPath -Raw
    $fixed = $text -replace "(?m)^[ \t]*\[Alias\('uninstall'\)\]\r?\n(?=[ \t]*\[switch\]\`$Uninstall\b)", ''
    if ($fixed -ne $text) {
        Set-Content -LiteralPath $ScriptPath -Encoding UTF8 -NoNewline -Value $fixed
    }
}

function Invoke-InstallScript {
    param([string]$PackageDir)

    $ps1 = Join-Path $PackageDir 'install.ps1'
    if (Test-Path -LiteralPath $ps1 -PathType Leaf) {
        Repair-InstallScriptCompatibility -ScriptPath $ps1
        & $ps1
        return
    }
    Write-Warning "No install.ps1 found in $(Split-Path -Leaf $PackageDir); skipping project-specific install."
}

function Invoke-UninstallScript {
    param([string]$PackageDir)

    $ps1 = Join-Path $PackageDir 'install.ps1'
    if (Test-Path -LiteralPath $ps1 -PathType Leaf) {
        Repair-InstallScriptCompatibility -ScriptPath $ps1
        & $ps1 -Uninstall
        return
    }
    Write-Warning "No install.ps1 found in $(Split-Path -Leaf $PackageDir); skipping project-specific uninstall."
}

function Write-UpdaterInfo {
    param(
        [string]$PackageDir,
        [object]$Info,
        [string]$SourceChannel,
        [string]$SourceNamePattern,
        [string]$RepoValue
    )

    $map = [ordered]@{}
    if ($Info) {
        foreach ($property in $Info.PSObject.Properties) {
            $map[$property.Name] = $property.Value
        }
    }
    if ($RepoValue) { $map['repo'] = $RepoValue }
    if ($SourceChannel) { $map['channel'] = $SourceChannel }
    if ($SourceNamePattern) { $map['name_pattern'] = $SourceNamePattern }
    if ($map.Count -eq 0) { return }

    $map | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $PackageDir 'info.Dat')
}

function Test-Sha256File {
    param(
        [string]$ShaFile,
        [string]$ArchivePath
    )

    if (-not (Test-Path -LiteralPath $ShaFile -PathType Leaf)) { return }
    $line = (Get-Content -LiteralPath $ShaFile | Select-Object -First 1).Trim()
    if (-not $line) { return }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "Checksum mismatch for $ArchivePath" }
}

function Copy-DirectoryContents {
    param(
        [string]$SourceDir,
        [string]$DestinationDir
    )

    New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $SourceDir -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $DestinationDir -Recurse -Force
    }
}

function Install-ArchivePackage {
    param(
        [string]$ArchivePath,
        [string]$UpdaterRoot,
        [string]$InstallRoot,
        [string]$SourceChannel,
        [string]$SourceNamePattern,
        [string]$RepoValue
    )

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('github-package-' + [guid]::NewGuid().ToString('N'))
    $stage = $null
    $backup = $null
    $updaterStage = $null
    $updaterBackup = $null
    $target = $null
    $installed = $false
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        Expand-PackageArchive -ArchivePath $ArchivePath -Destination $temp
        $packageDir = Get-PackageDirectory -Root $temp
        $packageInfo = Read-UpdaterInfo -Root $packageDir
        Assert-PackageInfoCompatible -Info $packageInfo -Source (Split-Path -Leaf $ArchivePath)
        $archiveUpdater = Join-Path $temp 'github-update.ps1'
        $outerUpdater = Join-Path $UpdaterRoot 'github-update.ps1'
        $updaterSource = $null
        if (Test-Path -LiteralPath $archiveUpdater -PathType Leaf) {
            $updaterSource = $archiveUpdater
        } elseif (Test-Path -LiteralPath $outerUpdater -PathType Leaf) {
            $updaterSource = $outerUpdater
        }
        $name = Split-Path -Leaf $packageDir
        $target = Join-Path $InstallRoot $name
        $suffix = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $InstallRoot (".$name.new-$suffix")
        $backup = Join-Path $InstallRoot (".$name.backup-$suffix")

        Copy-DirectoryContents -SourceDir $packageDir -DestinationDir $stage
        Write-UpdaterInfo -PackageDir $stage -Info $packageInfo -SourceChannel $SourceChannel -SourceNamePattern $SourceNamePattern -RepoValue $RepoValue

        $updaterTarget = Join-Path $InstallRoot 'github-update.ps1'
        if ($updaterSource) {
            $updaterStage = Join-Path $InstallRoot (".github-update.ps1.new-$suffix")
            Copy-Item -LiteralPath $updaterSource -Destination $updaterStage -Force
            if (Test-Path -LiteralPath $updaterTarget -PathType Leaf) {
                $updaterBackup = Join-Path $InstallRoot (".github-update.ps1.backup-$suffix")
                Copy-Item -LiteralPath $updaterTarget -Destination $updaterBackup -Force
            }
        }

        if (Test-Path -LiteralPath $target -PathType Container) {
            try {
                Move-Item -LiteralPath $target -Destination $backup -ErrorAction Stop
            } catch {
                throw "Installed package appears to be in use or cannot be replaced: $target. Stop the running service/process and retry. $($_.Exception.Message)"
            }
        }

        try {
            Move-Item -LiteralPath $stage -Destination $target -ErrorAction Stop
            $stage = $null
        } catch {
            if ($backup -and (Test-Path -LiteralPath $backup -PathType Container) -and -not (Test-Path -LiteralPath $target)) {
                Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue
            }
            throw
        }

        Invoke-InstallScript -PackageDir $target
        if ($updaterStage) {
            Copy-Item -LiteralPath $updaterStage -Destination $updaterTarget -Force
        }
        $installed = $true
        Write-Host "Installed: $target"
    } catch {
        if (-not $installed -and $updaterBackup -and (Test-Path -LiteralPath $updaterBackup -PathType Leaf)) {
            Copy-Item -LiteralPath $updaterBackup -Destination (Join-Path $InstallRoot 'github-update.ps1') -Force -ErrorAction SilentlyContinue
        }
        if (-not $installed -and $target -and $backup -and (Test-Path -LiteralPath $backup -PathType Container)) {
            if (Test-Path -LiteralPath $target -PathType Container) {
                Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
            }
            if (-not (Test-Path -LiteralPath $target -PathType Container)) {
                Move-Item -LiteralPath $backup -Destination $target -ErrorAction SilentlyContinue
            }
        }
        throw
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        if ($stage -and (Test-Path -LiteralPath $stage -PathType Container)) {
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($updaterStage -and (Test-Path -LiteralPath $updaterStage -PathType Leaf)) {
            Remove-Item -LiteralPath $updaterStage -Force -ErrorAction SilentlyContinue
        }
        if ($updaterBackup -and (Test-Path -LiteralPath $updaterBackup -PathType Leaf)) {
            Remove-Item -LiteralPath $updaterBackup -Force -ErrorAction SilentlyContinue
        }
        if ($installed -and $backup -and (Test-Path -LiteralPath $backup -PathType Container)) {
            try {
                Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning "Installed successfully, but old backup could not be removed: $backup"
            }
        }
    }
}

function Install-ActionArtifactPackage {
    param(
        [string]$ArtifactZip,
        [string]$InstallRoot,
        [string]$SourceChannel,
        [string]$SourceNamePattern,
        [string]$RepoValue
    )

    $outer = Join-Path ([System.IO.Path]::GetTempPath()) ('github-artifact-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $outer | Out-Null
    try {
        Expand-Archive -LiteralPath $ArtifactZip -DestinationPath $outer -Force
        $outerInfo = Read-UpdaterInfo -Root $outer
        Assert-PackageInfoCompatible -Info $outerInfo -Source (Split-Path -Leaf $ArtifactZip)
        $inner = @(Get-ChildItem -LiteralPath $outer -File | Where-Object {
            $_.Name -match '\.zip$|\.tar\.gz$|\.tgz$'
        } | Sort-Object Name | Select-Object -First 1)
        if ($inner.Count -eq 0) {
            $apk = @(Get-ChildItem -LiteralPath $outer -File -Filter '*.apk' | Select-Object -First 1)
            if ($apk.Count -gt 0) {
                throw "Action artifact '$ArtifactZip' contains Android APK '$($apk[0].Name)'; github-update.ps1 cannot install APK packages. Use an Android installer or choose a Windows package with -NamePattern."
            }
            throw "No inner package archive found in action artifact: $ArtifactZip"
        }
        $shaPath = Join-Path $outer ($inner[0].Name + '.sha256')
        if (-not (Test-Path -LiteralPath $shaPath -PathType Leaf)) {
            $sha = @(Get-ChildItem -LiteralPath $outer -File -Filter '*.sha256' | Select-Object -First 1)
            if ($sha.Count -gt 0) { $shaPath = $sha[0].FullName }
        }
        if (Test-Path -LiteralPath $shaPath -PathType Leaf) { Test-Sha256File -ShaFile $shaPath -ArchivePath $inner[0].FullName }
        Install-ArchivePackage -ArchivePath $inner[0].FullName -UpdaterRoot $outer -InstallRoot $InstallRoot -SourceChannel $SourceChannel -SourceNamePattern $SourceNamePattern -RepoValue $RepoValue
    } finally {
        Remove-Item -LiteralPath $outer -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Uninstall-Package {
    $root = Resolve-InstallRoot
    if ($PackageName) {
        $packageDir = Join-Path $root $PackageName
    } else {
        $candidates = @(Get-ChildItem -LiteralPath $root -Directory | Where-Object {
            Test-Path -LiteralPath (Join-Path $_.FullName 'install.ps1')
        })
        if ($candidates.Count -ne 1) { throw 'Unable to infer installed package directory. Use -PackageName.' }
        $packageDir = $candidates[0].FullName
    }
    if (-not (Test-Path -LiteralPath $packageDir -PathType Container)) {
        throw "Installed package directory not found: $packageDir"
    }
    Invoke-UninstallScript -PackageDir $packageDir
    Remove-Item -LiteralPath $packageDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Uninstalled: $(Split-Path -Leaf $packageDir)"
}

function Get-ReleaseVersions {
    param([string]$ApiRoot)

    $releases = Invoke-GitHubJson "$ApiRoot/releases?per_page=100"
    @($releases) | Where-Object { -not $_.draft -and ($IncludePrerelease -or -not $_.prerelease) }
}

function Select-ReleaseVersion {
    param(
        [string]$ApiRoot,
        [string]$WantedVersion
    )

    if ($WantedVersion) {
        $encoded = [uri]::EscapeDataString($WantedVersion)
        try {
            return Invoke-GitHubJson "$ApiRoot/releases/tags/$encoded"
        } catch {
            $all = Get-ReleaseVersions $ApiRoot
            $match = @($all | Where-Object { $_.name -eq $WantedVersion -or $_.tag_name -eq $WantedVersion } | Select-Object -First 1)
            if ($match.Count -gt 0) { return $match[0] }
            throw "Release version not found: $WantedVersion"
        }
    }

    $latest = Invoke-GitHubJson "$ApiRoot/releases/latest"
    if (-not $IncludePrerelease -and $latest.prerelease) {
        $latest = @(Get-ReleaseVersions $ApiRoot | Sort-Object published_at -Descending | Select-Object -First 1)[0]
    }
    if (-not $latest) { throw 'No release version found.' }
    return $latest
}

function Get-ActionRuns {
    param([string]$ApiRoot)

    $query = 'per_page=100&status=success'
    if ($Branch) { $query += '&branch=' + [uri]::EscapeDataString($Branch) }
    if ($Workflow) {
        $workflowEscaped = [uri]::EscapeDataString($Workflow)
        $result = Invoke-GitHubJson "$ApiRoot/actions/workflows/$workflowEscaped/runs?$query"
    } else {
        $result = Invoke-GitHubJson "$ApiRoot/actions/runs?$query"
    }
    @($result.workflow_runs)
}

function Select-ActionRun {
    param(
        [string]$ApiRoot,
        [string]$WantedVersion
    )

    if (-not $WantedVersion) {
        $runs = Get-ActionRuns $ApiRoot
        $run = @($runs | Where-Object { $_.conclusion -eq 'success' } | Sort-Object created_at -Descending | Select-Object -First 1)
        if ($run.Count -eq 0) { throw 'No successful action run found.' }
        return $run[0]
    }

    if ($WantedVersion -match '^\d+$') {
        try {
            $direct = Invoke-GitHubJson "$ApiRoot/actions/runs/$WantedVersion"
            if ($direct.conclusion -eq 'success') { return $direct }
        } catch {
            # Fall back to recent runs; the number may be a run_number instead of a run id.
        }
    }

    $runs = Get-ActionRuns $ApiRoot
    $match = @($runs | Where-Object {
        ([string]$_.id -eq $WantedVersion) -or
        ([string]$_.run_number -eq $WantedVersion) -or
        ($_.head_sha -like "$WantedVersion*") -or
        ($_.display_title -eq $WantedVersion) -or
        ($_.name -eq $WantedVersion)
    } | Select-Object -First 1)
    if ($match.Count -eq 0) { throw "Action run version not found: $WantedVersion" }
    return $match[0]
}

function Select-ItemsByPattern {
    param(
        [object[]]$Items,
        [string]$Property,
        [string]$Pattern
    )

    $selected = @($Items | Where-Object { $_.$Property -like $Pattern })
    if ($selected.Count -eq 0) {
        $names = ($Items | ForEach-Object { $_.$Property }) -join ', '
        throw "No item matched pattern '$Pattern'. Available: $names"
    }
    return $selected
}

function Format-ItemNames {
    param(
        [object[]]$Items,
        [string]$Property
    )

    return (($Items | ForEach-Object { $_.$Property }) -join ', ')
}

function Test-InstallCandidateName {
    param(
        [string]$Name,
        [string]$Kind
    )

    if ($Name -match '(?i)\.sha256$') { return $false }
    if ($Name -match '(?i)android|apk') { return $false }
    if ($Kind -eq 'release' -and $Name -notmatch '(?i)(\.zip|\.tar\.gz|\.tgz)$') { return $false }

    $platform = Get-CurrentPlatform
    if ($platform -eq 'windows') { return ($Name -match '(?i)windows|win') }
    if ($platform -eq 'linux') { return ($Name -match '(?i)linux') }
    if ($platform -eq 'macos') { return ($Name -match '(?i)macos|darwin|osx') }
    return $false
}

function Get-InstalledPackageIdentity {
    $root = Resolve-InstallRoot
    $candidateDirs = @()

    if ($PackageName) {
        $candidate = Join-Path $root $PackageName
        if (Test-Path -LiteralPath $candidate -PathType Container) { $candidateDirs = @((Get-Item -LiteralPath $candidate)) }
    } else {
        $candidateDirs = @(Get-ChildItem -LiteralPath $root -Directory | Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName 'info.Dat') -PathType Leaf) -or
            (Test-Path -LiteralPath (Join-Path $_.FullName 'install.ps1') -PathType Leaf)
        })
    }

    if ($candidateDirs.Count -ne 1) { return $null }

    $names = @()
    $names += $candidateDirs[0].Name
    $info = Read-UpdaterInfo -Root $candidateDirs[0].FullName
    foreach ($field in @('artifact', 'package', 'name')) {
        $value = Get-InfoValue -Info $info -Name $field
        if ($value) { $names += $value }
    }

    return [pscustomobject]@{
        Names = @($names | Select-Object -Unique)
        Info = $info
        PackageDir = $candidateDirs[0].FullName
    }
}

function Use-InstalledUpdaterDefaults {
    $identity = Get-InstalledPackageIdentity
    if (-not $identity -or -not $identity.Info) { return }

    if (-not $RepoWasExplicit -and -not $Repo) {
        $repoValue = Get-InfoValue -Info $identity.Info -Name 'repo'
        if ($repoValue) { Set-Variable -Name Repo -Scope Script -Value $repoValue }
    }

    if (-not $ChannelWasExplicit) {
        $channelValue = Get-InfoValue -Info $identity.Info -Name 'channel'
        if (-not $channelValue) { $channelValue = Get-InfoValue -Info $identity.Info -Name 'default_channel' }
        if ($channelValue) { $channelValue = $channelValue.ToLowerInvariant() }
        if ($channelValue -in @('release', 'action')) {
            Set-Variable -Name Channel -Scope Script -Value $channelValue
        } elseif ((Get-InfoValue -Info $identity.Info -Name 'artifact')) {
            Set-Variable -Name Channel -Scope Script -Value 'action'
        }
    }

    if (-not $NamePatternWasExplicit) {
        $pattern = Get-InfoValue -Info $identity.Info -Name 'name_pattern'
        if (-not $pattern) { $pattern = Get-InfoValue -Info $identity.Info -Name 'artifact' }
        if (-not $pattern) { $pattern = Get-InfoValue -Info $identity.Info -Name 'package' }
        if ($pattern) {
            Set-Variable -Name NamePattern -Scope Script -Value $pattern
            Set-Variable -Name NamePatternWasExplicit -Scope Script -Value $true
        }
    }
}

function Select-InstallItems {
    param(
        [object[]]$Items,
        [string]$Property,
        [string]$Kind
    )

    if ($Mode -ne 'install' -or $NamePatternWasExplicit) { return $Items }

    $identity = Get-InstalledPackageIdentity
    if ($identity) {
        $byIdentity = @($Items | Where-Object {
            $itemName = [string]$_.$Property
            $matched = $false
            foreach ($candidate in $identity.Names) {
                if ($candidate -and ($itemName -eq $candidate -or $itemName -like "$candidate*" -or $candidate -like "$itemName*")) {
                    $matched = $true
                }
            }
            $matched
        })
        if ($byIdentity.Count -eq 1) { return $byIdentity }
    }

    $compatible = @($Items | Where-Object { Test-InstallCandidateName -Name ([string]$_.$Property) -Kind $Kind })
    if ($compatible.Count -eq 1) { return $compatible }

    if ($compatible.Count -eq 0) {
        throw "Default -NamePattern '*' did not find an installable $Kind package for $(Get-CurrentPlatform). Available: $(Format-ItemNames -Items $Items -Property $Property). Use -NamePattern to select the exact package."
    }

    throw "Default -NamePattern '*' matched multiple installable $Kind packages: $(Format-ItemNames -Items $compatible -Property $Property). Use -NamePattern to select one package."
}

if ($Mode -eq 'uninstall') {
    Uninstall-Package
    return
}

Use-InstalledUpdaterDefaults

if ($Mode -eq 'install' -and $PackagePath) {
    $packageFull = (Resolve-Path -LiteralPath $PackagePath).Path
    $repoValue = $Repo
    if ($repoValue) {
        try {
            $repoInfoForLocal = Resolve-GitHubRepo $Repo
            $repoValue = "$($repoInfoForLocal.Owner)/$($repoInfoForLocal.Name)"
        } catch {
            # Keep the caller-provided value for info.Dat.
        }
    }
    $sourceNamePattern = $NamePattern
    if (-not $NamePatternWasExplicit -or $sourceNamePattern -eq '*') {
        $sourceNamePattern = Split-Path -Leaf $packageFull
        if ($Channel -eq 'action' -and $sourceNamePattern -match '(?i)\.zip$') {
            $sourceNamePattern = $sourceNamePattern.Substring(0, $sourceNamePattern.Length - 4)
        }
    }
    if ($Channel -eq 'action') {
        Install-ActionArtifactPackage -ArtifactZip $packageFull -InstallRoot (Resolve-InstallRoot) -SourceChannel 'action' -SourceNamePattern $sourceNamePattern -RepoValue $repoValue
    } else {
        Install-ArchivePackage -ArchivePath $packageFull -UpdaterRoot (Split-Path -Parent $packageFull) -InstallRoot (Resolve-InstallRoot) -SourceChannel 'release' -SourceNamePattern $sourceNamePattern -RepoValue $repoValue
    }
    return
}

if (-not $Repo) { throw '-Repo is required unless -Mode uninstall is used.' }
Resolve-GitHubToken

$repoInfo = Resolve-GitHubRepo $Repo
$apiRoot = "https://api.github.com/repos/$($repoInfo.Owner)/$($repoInfo.Name)"
$repoFullName = "$($repoInfo.Owner)/$($repoInfo.Name)"
$downloadTemp = $null
if ($Mode -eq 'install' -and -not $OutputDirWasExplicit) {
    $downloadTemp = Join-Path ([System.IO.Path]::GetTempPath()) ('github-update-download-' + [guid]::NewGuid().ToString('N'))
    $OutputDir = $downloadTemp
}
$outputFull = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $OutputDir).FullName).Path

try {
    if ($Channel -eq 'release') {
        if ($Mode -eq 'list') {
            Get-ReleaseVersions $apiRoot |
                Sort-Object published_at -Descending |
                Select-Object @{n='version';e={$_.tag_name}}, name, prerelease, published_at, @{n='assets';e={$_.assets.Count}} |
                Format-Table -AutoSize
            return
        }

        $release = Select-ReleaseVersion $apiRoot $Version
        $assets = Select-ItemsByPattern -Items @($release.assets) -Property 'name' -Pattern $NamePattern
        $assets = Select-InstallItems -Items $assets -Property 'name' -Kind 'release'
        foreach ($asset in $assets) {
            $target = Join-Path $outputFull $asset.name
            Write-Host "Downloading release $($release.tag_name): $($asset.name) ($(Format-Size $asset.size))"
            Save-GitHubFile -Uri $asset.browser_download_url -Path $target
            Write-Host "Saved: $target"
            if ($Mode -eq 'install') { Install-ArchivePackage -ArchivePath $target -UpdaterRoot $outputFull -InstallRoot (Resolve-InstallRoot) -SourceChannel 'release' -SourceNamePattern $asset.name -RepoValue $repoFullName }
        }
        return
    }

    if ($Channel -eq 'action') {
        if ($Mode -eq 'list') {
            Get-ActionRuns $apiRoot |
                Sort-Object created_at -Descending |
                Select-Object @{n='version';e={$_.id}}, run_number, name, display_title, head_branch, @{n='sha';e={$_.head_sha.Substring(0, 12)}}, created_at |
                Format-Table -AutoSize
            return
        }

        if (-not $Token) {
            Write-Warning 'GitHub Actions artifact downloads usually require a token. Set GITHUB_TOKEN, pass -Token, or run gh auth login.'
        }
        $run = Select-ActionRun $apiRoot $Version
        $artifactResult = Invoke-GitHubJson "$apiRoot/actions/runs/$($run.id)/artifacts?per_page=100"
        $artifacts = Select-ItemsByPattern -Items @($artifactResult.artifacts | Where-Object { -not $_.expired }) -Property 'name' -Pattern $NamePattern
        $artifacts = Select-InstallItems -Items $artifacts -Property 'name' -Kind 'action artifact'
        foreach ($artifact in $artifacts) {
            $artifactZip = Join-Path $outputFull ($artifact.name + '.zip')
            Write-Host "Downloading action run $($run.id) artifact: $($artifact.name) ($(Format-Size $artifact.size_in_bytes))"
            Save-GitHubFile -Uri $artifact.archive_download_url -Path $artifactZip
            Write-Host "Saved: $artifactZip"
            if ($Mode -eq 'install') { Install-ActionArtifactPackage -ArtifactZip $artifactZip -InstallRoot (Resolve-InstallRoot) -SourceChannel 'action' -SourceNamePattern $artifact.name -RepoValue $repoFullName }
        }
        return
    }
} finally {
    if ($downloadTemp -and (Test-Path -LiteralPath $downloadTemp)) {
        Remove-Item -LiteralPath $downloadTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
