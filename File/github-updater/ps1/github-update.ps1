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
    [string]$Token = $env:GITHUB_TOKEN,
    [switch]$IncludePrerelease,
    [switch]$Force,

    [Alias('-uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($Uninstall) { $Mode = 'uninstall' }
$ScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$ScriptDir = Split-Path -Parent $ScriptPath

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

function Resolve-InstallRoot {
    $root = $InstallDir
    if (-not $root) {
        if (($Mode -eq 'install' -or $Mode -eq 'uninstall') -and (Split-Path -Leaf $ScriptDir) -ne 'ps1') {
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

function Invoke-InstallScript {
    param([string]$PackageDir)

    $ps1 = Join-Path $PackageDir 'install.ps1'
    if (Test-Path -LiteralPath $ps1 -PathType Leaf) {
        & $ps1
        return
    }
    Write-Warning "No install.ps1 found in $(Split-Path -Leaf $PackageDir); skipping project-specific install."
}

function Invoke-UninstallScript {
    param([string]$PackageDir)

    $ps1 = Join-Path $PackageDir 'install.ps1'
    if (Test-Path -LiteralPath $ps1 -PathType Leaf) {
        & $ps1 -Uninstall
        return
    }
    Write-Warning "No install.ps1 found in $(Split-Path -Leaf $PackageDir); skipping project-specific uninstall."
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

function Install-ArchivePackage {
    param(
        [string]$ArchivePath,
        [string]$UpdaterRoot,
        [string]$InstallRoot
    )

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('github-package-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    try {
        Expand-PackageArchive -ArchivePath $ArchivePath -Destination $temp
        $archiveUpdater = Join-Path $temp 'github-update.ps1'
        $outerUpdater = Join-Path $UpdaterRoot 'github-update.ps1'
        if (Test-Path -LiteralPath $archiveUpdater -PathType Leaf) {
            Copy-Item -LiteralPath $archiveUpdater -Destination (Join-Path $InstallRoot 'github-update.ps1') -Force
        } elseif (Test-Path -LiteralPath $outerUpdater -PathType Leaf) {
            Copy-Item -LiteralPath $outerUpdater -Destination (Join-Path $InstallRoot 'github-update.ps1') -Force
        }
        $packageDir = Get-PackageDirectory -Root $temp
        $name = Split-Path -Leaf $packageDir
        $target = Join-Path $InstallRoot $name
        Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $packageDir -Destination $InstallRoot -Recurse -Force
        Invoke-InstallScript -PackageDir $target
        Write-Host "Installed: $target"
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-ActionArtifactPackage {
    param(
        [string]$ArtifactZip,
        [string]$InstallRoot
    )

    $outer = Join-Path ([System.IO.Path]::GetTempPath()) ('github-artifact-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $outer | Out-Null
    try {
        Expand-Archive -LiteralPath $ArtifactZip -DestinationPath $outer -Force
        $inner = @(Get-ChildItem -LiteralPath $outer -File | Where-Object {
            $_.Name -match '\.zip$|\.tar\.gz$|\.tgz$'
        } | Sort-Object Name | Select-Object -First 1)
        if ($inner.Count -eq 0) { throw "No inner package archive found in action artifact: $ArtifactZip" }
        $shaPath = Join-Path $outer ($inner[0].Name + '.sha256')
        if (-not (Test-Path -LiteralPath $shaPath -PathType Leaf)) {
            $sha = @(Get-ChildItem -LiteralPath $outer -File -Filter '*.sha256' | Select-Object -First 1)
            if ($sha.Count -gt 0) { $shaPath = $sha[0].FullName }
        }
        if (Test-Path -LiteralPath $shaPath -PathType Leaf) { Test-Sha256File -ShaFile $shaPath -ArchivePath $inner[0].FullName }
        Install-ArchivePackage -ArchivePath $inner[0].FullName -UpdaterRoot $outer -InstallRoot $InstallRoot
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

if ($Mode -eq 'uninstall') {
    Uninstall-Package
    return
}

if (-not $Repo) { throw '-Repo is required unless -Mode uninstall is used.' }
Resolve-GitHubToken

$repoInfo = Resolve-GitHubRepo $Repo
$apiRoot = "https://api.github.com/repos/$($repoInfo.Owner)/$($repoInfo.Name)"
$outputFull = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $OutputDir).FullName).Path

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
    foreach ($asset in $assets) {
        $target = Join-Path $outputFull $asset.name
        Write-Host "Downloading release $($release.tag_name): $($asset.name) ($(Format-Size $asset.size))"
        Save-GitHubFile -Uri $asset.browser_download_url -Path $target
        Write-Host "Saved: $target"
        if ($Mode -eq 'install') { Install-ArchivePackage -ArchivePath $target -UpdaterRoot $outputFull -InstallRoot (Resolve-InstallRoot) }
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
    foreach ($artifact in $artifacts) {
        $artifactZip = Join-Path $outputFull ($artifact.name + '.zip')
        Write-Host "Downloading action run $($run.id) artifact: $($artifact.name) ($(Format-Size $artifact.size_in_bytes))"
        Save-GitHubFile -Uri $artifact.archive_download_url -Path $artifactZip
        Write-Host "Saved: $artifactZip"
        if ($Mode -eq 'install') { Install-ActionArtifactPackage -ArtifactZip $artifactZip -InstallRoot (Resolve-InstallRoot) }
    }
    return
}
